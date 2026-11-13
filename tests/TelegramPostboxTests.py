"""Schema-25 linked messages, real SQLite WAL history, controlled CLR wire data.

The fixture is independent of the parser but is not a real phone capture and
does not substitute for testing upstream Swift's writer on an iPhone.
"""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'helpers/recovery_engine'),str(ROOT/'tests')]
import engine
import telegram_auto
import telegram_postbox
import archive_search
import archive_text
from build_telegram_postbox_fixtures import extract


def inventory(root):return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}


class PostboxTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='controlled-postbox25-');self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.inputs=self.base/'inputs';self.manifest=extract(self.inputs);self.sequence=0

    def analyze(self,relative,fragments=False):
        self.sequence+=1;out=self.base/('archive-'+str(self.sequence));before=inventory(self.inputs)
        with patch.object(engine,'emit'):
            summary=telegram_auto.analyze(dict(protocol=1,operation='telegram_analyze',destination=str(out),
                options=dict(roots=[str(self.inputs/relative)],scan_fragments=fragments)),engine.Importer,lambda *a,**k:None)
        self.assertEqual(before,inventory(self.inputs))
        rows=[json.loads(line) for line in (out/'messages.jsonl').read_text('utf-8').splitlines()]
        return out,summary,rows

    def test_frozen_independent_writer_and_observed_fields(self):
        self.assertIn('not_phone_capture',self.manifest['fixture_kind'])
        writer=ROOT/'tests/postbox_oracle/PostboxWriter.cs'
        self.assertEqual(hashlib.sha256(writer.read_bytes()).hexdigest(),self.manifest['producer_sha256'])
        self.assertNotIn('telegram_postbox',(ROOT/'tests/postbox_oracle/produce.py').read_text('utf-8'))
        output,summary,rows=self.analyze('positive')
        self.assertEqual(len(rows),4)
        self.assertEqual(summary['native_records'],4)
        self.assertEqual(summary['history_messages'],3)
        self.assertEqual(summary['unsent_records'],1)
        for expected in self.manifest['expected']:
            if not expected['text']:continue
            row=next(r for r in rows if r['message_id']==str(expected['namespace'])+':'+str(expected['mid']))
            self.assertEqual((row['chat_id'],row['text'],row['sender_id']),(expected['peer'],expected['text'],expected['sender']))
            self.assertEqual(dt.datetime.fromisoformat(row['timestamp']).timestamp(),expected['date'])
            self.assertTrue(row['application_confirmed']);self.assertIsNone(row['deleted']);self.assertEqual(row['attachments'],[])
            self.assertEqual(len(row['native_postbox_value_sha256']),64)
            self.assertIn('linked:t4',row['source_record']);self.assertIn('not_decoded',row['completeness'])
            self.assertEqual(row['record_kind'],'telegram_ios_postbox_unsent' if expected['unsent'] else 'telegram_ios_postbox_message')
        self.assertEqual(len({r['message_id'] for r in rows}),4,'Different namespaces never merge identical text and numeric IDs')
        for forbidden in ('ATTRIBUTE_NEVER_MESSAGE','OPAQUE_NEVER_MESSAGE','MEDIA_URL_NEVER_FETCH','FORWARD_SIGNATURE_NEVER_MESSAGE','PSA_NEVER_MESSAGE'):
            self.assertEqual(archive_search.search(dict(protocol=1,operation='search',archive=str(output),query=forbidden))['total'],0)

    def test_strict_schema_bounds_index_links_and_unknown_version(self):
        for folder in (self.inputs/'controls').iterdir():
            with self.subTest(control=folder.name):
                _,summary,rows=self.analyze('controls/'+folder.name)
                self.assertEqual((summary['native_records'],rows),(0,[]))
                self.assertEqual(summary['history_messages'],0)

    def test_committed_wal_delete_recovers_previous_record_without_deletion_claim(self):
        _,summary,rows=self.analyze('wal')
        self.assertEqual((summary['native_records'],len(rows)),(1,1))
        row=rows[0]
        self.assertEqual(row['text'],self.manifest['expected'][0]['text'])
        self.assertEqual(row['evidence_kind'],'previous');self.assertEqual(row['wal_proof'],'all_pages_from_validated_wal')
        self.assertIsNone(row['deleted']);self.assertEqual(summary['deleted_supported_records'],0)
        self.assertIn('t7(key=',row['source_record'])

    def test_search_paging_reimport_and_safe_html(self):
        output,summary,rows=self.analyze('positive')
        found=archive_search.search(dict(protocol=1,operation='search',archive=str(output),query='рецепт|Unsent',query_mode='regex',app='Telegram'))
        self.assertEqual(found['total'],3)
        longrow=next(r for r in rows if r['message_id']=='0:8')
        found=archive_search.search(dict(protocol=1,operation='search',archive=str(output),query='Long Postbox',app='Telegram'))['records'][0]
        page=archive_text.read_page(dict(protocol=1,operation='message_page',archive=str(output),record_key=found['archive_record_key'],text_offset=30000,limit=65536))
        self.assertTrue(page['text']);self.assertIn('Я',page['text']);self.assertEqual(longrow['text'].count('Я'),60000)
        self.assertEqual(found['native_postbox_value_sha256'],longrow['native_postbox_value_sha256'])
        html=(output/'Переписки.html').read_text('utf-8')
        self.assertNotIn('<img src=x onerror=alert(1)>',html)
        self.inputs.joinpath('reimport').mkdir()
        for path in output.iterdir():
            if path.is_file():shutil.copyfile(path,self.inputs/'reimport'/path.name)
        _,again,imported=self.analyze('reimport')
        self.assertEqual({r['message_id'] for r in imported},{r['message_id'] for r in rows})
        self.assertTrue(all(r['provenance_verification']=='provided_archive_metadata' for r in imported))

    def test_same_text_changed_record_in_real_wal_preserves_versions(self):
        working=self.base/'working.db';shutil.copyfile(self.inputs/'positive/db_sqlite',working)
        db=sqlite3.connect(working)
        try:
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
            db.execute('VACUUM');db.commit()
            key,value=db.execute('SELECT key,value FROM t7 WHERE length(value)<1000 ORDER BY key LIMIT 1').fetchone()
            changed=bytearray(value);struct.pack_into('<I',changed,5,3)
            db.execute('UPDATE t7 SET value=? WHERE key=?',(bytes(changed),key));db.commit()
            target=self.inputs/'wal-edit/db_sqlite';target.parent.mkdir()
            for suffix in ('','-wal','-shm'):shutil.copyfile(str(working)+suffix,str(target)+suffix)
        finally:db.close()
        _,summary,rows=self.analyze('wal-edit')
        variants=[r for r in rows if 'key='+key.hex() in r['source_record']]
        self.assertEqual(len(variants),2)
        self.assertEqual(len({r['text'] for r in variants}),1)
        self.assertEqual(len({r['native_postbox_value_sha256'] for r in variants}),2)
        self.assertTrue(any(r['evidence_kind']=='previous' for r in variants))
        self.assertTrue(all(r.get('deleted') is None for r in variants))

    def test_decoder_rejects_all_truncations_and_large_counts(self):
        db=sqlite3.connect(self.inputs/'positive/db_sqlite')
        key,value=db.execute('SELECT key,value FROM t7 ORDER BY length(value) LIMIT 1').fetchone()
        index=db.execute('SELECT value FROM t4 WHERE key=?',(key[:12]+key[16:],)).fetchone()[0]
        db.close()
        for size in range(len(value)):
            with self.assertRaises(telegram_postbox.PostboxError):telegram_postbox.decode(key,value[:size],index)
        with self.assertRaises(telegram_postbox.PostboxError):telegram_postbox.decode(key,value+b'\x00',index)
        self.assertEqual(value[9],0)
        malformed=bytearray(value);struct.pack_into('<i',malformed,20,0x7fffffff)
        with self.assertRaises(telegram_postbox.PostboxError):telegram_postbox.decode(key,bytes(malformed),index)


if __name__=='__main__':unittest.main()
