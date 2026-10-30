"""Legacy Android SQL/TL link tests, generated without recovery decoders."""
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'helpers'/'recovery_engine'))
import engine
import archive_search
import telegram_auto
from telegram_tl import parse_message,TelegramTlError
from build_telegram_legacy_fixtures import SCHEMA,DATE,create,message,stored_mid,word


class TelegramLegacyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='owned-telegram-legacy-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.counter=0

    def analyze(self,source,**options):
        self.counter+=1;output=self.root/('out-'+str(self.counter))
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.parent.iterdir() if p.is_file()}
        with patch('engine.emit'):
            summary=telegram_auto.analyze(dict(protocol=1,operation='telegram_analyze',destination=str(output),
                options=dict(roots=[str(source)],**options)),engine.Importer,lambda *a,**kw:None)
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.parent.iterdir() if p.is_file()})
        rows=[json.loads(line) for line in (output/'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        return output,summary,rows

    def test_official_114_wire_text_scalars_and_single_views_value(self):
        raw=message('Рецепт 🥧\n你好',views=11,reply=9,via=42,edit=DATE+1,author='author',grouped=0x123456789)
        value=parse_message(raw)
        self.assertEqual(value['text'],'Рецепт 🥧\n你好');self.assertEqual(value['layer'],114)
        self.assertEqual(value['from_peer'],dict(kind='user',id=77))
        self.assertEqual(value['views'],11);self.assertNotIn('forwards',value)
        self.assertEqual(value['reply']['message_id'],9);self.assertEqual(value['grouped_id'],0x123456789)
        self.assertEqual(value['edit_date'],DATE+1);self.assertEqual(value['via_bot_id'],42)
        other=parse_message(message('118 still reads two counters',profile=118,views=11,forwards=5))
        self.assertEqual((other['views'],other['forwards']),(11,5))

    def test_114_unknown_and_unsupported_nested_flags_fail_closed(self):
        raw=message('Strict text')
        for bit in (1,4,64,128,512,1<<20,1<<22,1<<31):
            with self.subTest(bit=bit):
                with self.assertRaises(TelegramTlError):parse_message(raw[:4]+word(256|bit)+raw[8:])

    def test_114_truncations_unknown_constructor_and_bad_peers_rejected(self):
        raw=message('Truncated wire',tail=False,views=3,author='known')
        for end in range(len(raw)):
            with self.subTest(end=end):
                with self.assertRaises(TelegramTlError):parse_message(raw[:end])
        with self.assertRaises(TelegramTlError):parse_message(word(0x12345678)+raw[4:])
        bad=bytearray(message('bad peer',tail=False));bad[16:20]=word(0x12345678)
        with self.assertRaises(TelegramTlError):parse_message(bad)

    def test_current_legacy_rows_keep_public_id_and_original_packed_key(self):
        for profile in (114,118):
            with self.subTest(profile=profile):
                source,expected=create(self.root/str(profile)/'cache4.db',profile=profile)
                _,_,rows=self.analyze(source)
                native=[row for row in rows if row.get('application_confirmed')]
                self.assertEqual(len(native),len(expected))
                for gold in expected:
                    row=next(r for r in native if r['message_id']==gold['mid'])
                    self.assertEqual(row['chat_id'],gold['uid']);self.assertEqual(row['text'],gold['text'])
                    self.assertEqual(row['sqlite_stored_mid'],gold['stored_mid'])
                    self.assertIn('messages(uid='+str(gold['uid'])+',mid='+str(gold['stored_mid'])+')',row['source_record'])
                    self.assertEqual(row['evidence_kind'],'backup');self.assertIsNone(row.get('deleted'))
                    self.assertEqual(row['sender_id'],'user:77' if gold['sender'] else None)

    def test_real_sql_delete_survives_only_validated_legacy_wal_history(self):
        for profile in (114,118):
            with self.subTest(profile=profile):
                source,_=create(self.root/str(profile)/'cache4.db',profile=profile,wal=True)
                _,_,rows=self.analyze(source)
                old=next(row for row in rows if row.get('message_id')==23)
                self.assertEqual(old['text'],'Channel recipe before real SQL DELETE')
                self.assertEqual(old['evidence_kind'],'previous');self.assertTrue(old['previous_version'])
                self.assertEqual(old['wal_proof'],'all_pages_from_validated_wal')
                self.assertEqual(old['sqlite_stored_mid'],(88<<32)|23)
                self.assertIsNone(old.get('deleted'))
                self.assertNotEqual(old.get('recovery_status'),'deleted_supported_by_evidence')

    def test_mismatched_sql_high_channel_bits_user_key_uid_and_date_are_not_linked(self):
        mutations=[lambda db:db.execute('UPDATE messages SET mid=? WHERE uid=-88 AND mid=?',((99<<32)|23,(88<<32)|23)),
            lambda db:db.execute('UPDATE messages SET mid=23 WHERE mid=?',((88<<32)|23,)),
            lambda db:db.execute('UPDATE messages SET uid=-99 WHERE mid=?',((88<<32)|23,)),
            lambda db:db.execute('UPDATE messages SET date=date+1 WHERE mid=?',((88<<32)|23,)),
            lambda db:db.execute('UPDATE messages SET mid=? WHERE mid=21',((88<<32)|21,))]
        for index,mutate in enumerate(mutations):
            with self.subTest(index=index):
                source,_=create(self.root/str(index)/'cache4.db')
                with sqlite3.connect(source) as db:mutate(db)
                db.close()
                _,_,rows=self.analyze(source)
                forbidden=21 if index==4 else 23
                self.assertFalse(any(row.get('application_confirmed') and row.get('message_id')==forbidden for row in rows))

    def test_generic_or_composite_primary_key_messages_is_not_native_legacy(self):
        for index,schema in enumerate(('mid INTEGER,uid INTEGER,date INTEGER,data BLOB',SCHEMA.replace('mid INTEGER PRIMARY KEY','mid INTEGER')+',PRIMARY KEY(mid,uid)')):
            with self.subTest(index=index):
                source=self.root/('fake-'+str(index)+'.db')
                with sqlite3.connect(source) as db:
                    db.execute('CREATE TABLE messages('+schema+')')
                    db.execute('INSERT INTO messages(mid,uid,date,data) VALUES(?,?,?,?)',(21,77,DATE,message('Not official schema')))
                db.close()
                _,_,rows=self.analyze(source)
                self.assertFalse(any(row.get('application_confirmed') for row in rows))

    def test_negative_local_channel_id_matches_java_signed_or_key(self):
        source,_=create(self.root/'negative'/'cache4.db')
        with sqlite3.connect(source) as db:
            db.execute('INSERT INTO messages(mid,uid,date,data) VALUES(?,?,?,?)',(-7,-88,DATE,message('Local unsent',mid=-7,peer=88,kind='channel',out=True)))
        db.close()
        _,_,rows=self.analyze(source)
        row=next(r for r in rows if r.get('message_id')==-7)
        self.assertEqual(row['sqlite_stored_mid'],-7);self.assertEqual(row['chat_id'],-88)

    def test_same_public_message_id_in_different_channels_does_not_merge(self):
        source,_=create(self.root/'channels'/'cache4.db')
        with sqlite3.connect(source) as db:
            db.execute('INSERT INTO messages(mid,uid,date,data) VALUES(?,?,?,?)',
                (stored_mid(23,'channel',99),-99,DATE,message('Channel recipe before real SQL DELETE',mid=23,peer=99,kind='channel')))
        db.close()
        _,_,rows=self.analyze(source)
        matching=[r for r in rows if r.get('message_id')==23]
        self.assertEqual({r['chat_id'] for r in matching},{-88,-99})
        self.assertEqual({r['sqlite_stored_mid'] for r in matching},{(88<<32)|23,(99<<32)|23})

    def test_maximum_legacy_channel_key_survives_search_and_canonical_reimport(self):
        source,_=create(self.root/'large-key'/'cache4.db')
        maximum=0x7fffffff;key=stored_mid(37,'channel',maximum)
        with sqlite3.connect(source) as db:
            db.execute('INSERT INTO messages(mid,uid,date,data) VALUES(?,?,?,?)',
                (key,-maximum,DATE,message('Maximum packed key keyword',mid=37,peer=maximum,kind='channel')))
        db.close()
        output,_,_=self.analyze(source)
        for mode,query in (('literal','packed key'),('regex',r'packed\s+key')):
            found=archive_search.search(dict(protocol=1,operation='search',archive=str(output),app='Telegram',query=query,query_mode=mode))
            self.assertEqual(found['total'],1)
            self.assertEqual(found['records'][0]['message_id'],37)
            self.assertEqual(found['records'][0]['sqlite_stored_mid'],key)
            self.assertIs(type(found['records'][0]['sqlite_stored_mid']),int)
        _,_,reimported=self.analyze(output/'messages.jsonl')
        again=next(r for r in reimported if r.get('message_id')==37)
        self.assertEqual(again['sqlite_stored_mid'],key)

    def test_canonical_messages_table_does_not_enable_native_or_foreign_app_carving(self):
        source=self.root/'canonical.db'
        with sqlite3.connect(source) as db:
            db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,app TEXT,json TEXT)')
            for index,app,text in ((1,'Telegram','safe export'),(2,'Signal','PRIVATE_CANARY_EXPORT')):
                db.execute('INSERT INTO messages VALUES(?,?,?)',(index,app,json.dumps(dict(app=app,text=text,evidence_kind='export',message_id=index))))
        db.close()
        _,_,rows=self.analyze(source,scan_fragments=True)
        self.assertEqual([r['text'] for r in rows],['safe export'])
        self.assertFalse(any(r.get('native_constructor') for r in rows))

    def test_114_dump_is_only_an_unattributed_structured_fragment(self):
        source=self.root/'provided.mem';source.write_bytes(b'\0'*31+message('Owned legacy dump keyword')+b'\0'*120)
        _,_,rows=self.analyze(source,scan_fragments=True,fragment_query='keyword')
        typed=[row for row in rows if row.get('record_kind')=='typed_tl_fragment']
        self.assertEqual(len(typed),1);row=typed[0]
        self.assertEqual(row['candidate_message_id'],21);self.assertEqual(row['byte_offset'],31)
        self.assertEqual(row['evidence_kind'],'fragment')
        for name in ('message_id','chat_id','sender_id','timestamp'):self.assertIsNone(row.get(name))


if __name__=='__main__':unittest.main(verbosity=2)
