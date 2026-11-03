"""Real collector/import/search tests against independent native artifacts."""
from pathlib import Path
from contextlib import closing
import datetime as dt
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import archive_search
import archive_text
import engine
import telegram_auto
import telegram_platforms
from build_telegram_platform_fixtures import (extract_sources, inventory, load_manifest,
    TEST_KEY, TEST_PASSCODE, ACCOUNT, DRAFT_FILE)


class TelegramPlatformTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-native-platforms-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.inputs = self.base / 'inputs'
        self.oracle = extract_sources(self.inputs)
        self.sequence = 0

    def analyze(self, relative, secrets=None, fragments=False, guard_private=False):
        source = self.inputs / relative
        self.sequence += 1
        output = self.base / f'archive-{self.sequence}'
        before = inventory(self.inputs)
        opening = Path.open
        def checked_open(path, *args, **kwargs):
            if guard_private and path.name in (ACCOUNT+'s', 'maps'):
                self.fail('Native account authorization/map file was opened')
            if secrets is None and path.name == 'key_datas':
                self.fail('Key material was opened without a supplied known passcode/key')
            return opening(path, *args, **kwargs)
        with patch.object(engine, 'emit'), patch.object(Path, 'open', checked_open):
            result = telegram_auto.analyze(dict(protocol=1, operation='telegram_analyze',
                destination=str(output), secrets=secrets or {},
                options=dict(roots=[str(source)], scan_fragments=fragments)), engine.Importer, lambda *a, **k: None)
        self.assertEqual(inventory(self.inputs), before, 'Original DB/WAL/SHM/TDF/key-data source bytes stay unchanged')
        records = [json.loads(s) for s in (output/'messages.jsonl').read_text('utf-8').splitlines()]
        return output, result, records

    def test_independent_native_producer_and_frozen_artifacts(self):
        manifest = load_manifest()
        self.assertEqual(manifest['qt_version'], '5.15.2')
        self.assertEqual(len(manifest['sources']), 63)
        self.assertEqual(len(manifest['expected']['android']), 3)
        self.assertEqual(len(manifest['expected']['ios']), 2)
        self.assertEqual(manifest['expected']['android'][0]['text'],
            'Scheduled native \u043f\u0438\u0440\u043e\u0433 \U0001f967\n\u7b2c\u4e8c\u884c')
        for script in ('telegram_platform_fixture_producer.py', 'telegram_platforms_oracle/NativeScheduledOracle.java'):
            source = (ROOT/'tests'/script).read_text('utf-8')
            self.assertNotIn('import telegram_platforms', source)
            self.assertNotIn('import telegram_auto', source)

    def test_android_scheduled_exact_native_text_and_media_only_are_not_sent_history(self):
        _, summary, records = self.analyze('positive/android')
        self.assertEqual((summary['native_records'],summary['scheduled_records'],summary['history_messages']), (3,3,0))
        self.assertEqual(summary['code'],'LOCAL_DRAFTS_OR_SCHEDULED_AVAILABLE')
        self.assertNotIn('NO_READABLE_TELEGRAM_HISTORY',summary['warnings'])
        self.assertEqual(len(records), 3)
        rows = {r['message_id']:r for r in records}
        for expected in self.oracle['expected']['android']:
            row = rows[expected['mid']]
            self.assertEqual((row['text'],row['chat_id'],row['sender_id']), (expected['text'],909,'user:77'))
            self.assertEqual(dt.datetime.fromisoformat(row['timestamp']).timestamp(), expected['date'])
            self.assertEqual(row['record_kind'], 'telegram_android_scheduled')
            self.assertIn('scheduled_messages_v2', row['source_record'])
            self.assertIn('not_sent_history', row['completeness'])
            self.assertIsNone(row.get('deleted'))
            self.assertNotIn('FILENAME', row['text'])
        self.assertEqual((rows[5103]['text'],rows[5103]['media_id']), ('','0'))

    def test_ios29_versioned_plaintext_native_schema_has_exact_known_identity(self):
        _, summary, records = self.analyze('positive/ios')
        self.assertEqual((summary['native_records'],summary['history_messages']), (2,2))
        rows = {r['message_id']:r for r in records}
        for expected in self.oracle['expected']['ios']:
            row = rows[expected['mid']]
            self.assertEqual((row['text'],row['chat_id'],row['sender_id']), (expected['text'],expected['cid'],'user:77'))
            self.assertEqual(dt.datetime.fromisoformat(row['timestamp']).timestamp(), expected['date'])
            self.assertEqual(row['record_kind'], 'telegram_ios29_message')
            self.assertEqual(row['attachments'], [])
            self.assertIn('legacy_schema29', row['completeness'])
            self.assertIsNone(row.get('deleted'))
            self.assertNotIn('FILENAME', row['text'])

    def test_native_qt_three_draft_layouts_known_passcode_and_correct_unknown_fields(self):
        for expected in self.oracle['expected']['desktop']:
            with self.subTest(tag=expected['tag']):
                output, summary, records = self.analyze('positive/'+expected['case'],
                    dict(telegram_desktop_passcode=TEST_PASSCODE), guard_private=True)
                self.assertEqual((summary['native_records'],summary['draft_records'],summary['history_messages']), (2,2,0))
                self.assertEqual(summary['code'],'LOCAL_DRAFTS_OR_SCHEDULED_AVAILABLE')
                self.assertEqual({r['text'] for r in records}, set(expected['texts']))
                for row in records:
                    self.assertEqual((row['record_kind'],row['chat_id']), ('telegram_desktop_draft','user:909'))
                    self.assertEqual(row['recovery_status'], 'unsent_local_draft')
                    self.assertIn(expected['tag'], row['source_record'])
                    self.assertIn('not_message_history_or_deleted_message', row['completeness'])
                    for name in ('sender_id','sender_name','message_id','timestamp','deleted'):
                        self.assertIsNone(row.get(name), name)
                    self.assertNotIn('NEVER_', row['text'])
                for path in output.rglob('*'):
                    if path.is_file():
                        raw = path.read_bytes()
                        self.assertNotIn(TEST_PASSCODE.encode(), raw, 'No known passcode in published bytes')
                        self.assertNotIn(TEST_KEY.hex().encode(), raw, 'No local key in published bytes')

    def test_raw_key_and_explicit_known_no_passcode_profiles(self):
        for relative, secret in [('positive/desktop-tag6',dict(telegram_desktop_local_key=TEST_KEY.hex())),
                                 ('positive/desktop-empty-passcode',dict(telegram_desktop_passcode=''))]:
            _, summary, rows = self.analyze(relative,secret,guard_private=True)
            self.assertEqual((summary['draft_records'],len(rows)), (2,2))

    def test_no_secret_and_wrong_secret_never_produce_drafts_or_fallback(self):
        _, summary, rows = self.analyze('positive/desktop-tag6',None,guard_private=True)
        self.assertEqual((summary['draft_records'],rows), (0,[]))
        for secret in [dict(telegram_desktop_passcode='wrong-synthetic-passcode'),
                       dict(telegram_desktop_local_key=('00'*256))]:
            _, summary, rows = self.analyze('positive/desktop-tag6',secret,guard_private=True)
            self.assertEqual((summary['native_records'],rows), (0,[]))
            self.assertIn('TELEGRAM_DESKTOP_KEY_OR_INTEGRITY_INVALID', summary['warnings'])

    def test_desktop_corruption_unknown_version_tag_key_duplicate_and_late_failure_are_atomic(self):
        controls = [p for p in (self.inputs/'controls').iterdir() if p.name.startswith('desktop-')]
        self.assertEqual(len(controls),8)
        for source in controls:
            with self.subTest(control=source.name):
                _, summary, rows = self.analyze('controls/'+source.name,dict(telegram_desktop_passcode=TEST_PASSCODE))
                self.assertEqual((summary['native_records'],summary['draft_records'],rows), (0,0,[]))
                self.assertTrue(any(code.startswith('TELEGRAM_DESKTOP_') for code in summary['warnings']))

    def test_sqlite_schema_native_keys_unknown_tl_secret_ids_and_missing_author_controls(self):
        controls = [p for p in (self.inputs/'controls').iterdir() if not p.name.startswith('desktop-') and p.name != 'ios-unconfirmed-author']
        self.assertEqual(len(controls),6)
        for source in controls:
            with self.subTest(control=source.name):
                _, summary, rows = self.analyze('controls/'+source.name)
                self.assertEqual((summary['native_records'],rows), (0,[]))

    def test_confirmed_ios_text_with_missing_author_keeps_unknown_sender(self):
        _, summary, rows = self.analyze('controls/ios-unconfirmed-author')
        self.assertEqual((summary['native_records'],len(rows)),(2,2))
        for row in rows:
            self.assertIsNone(row['sender_id'])
            self.assertIsNone(row['sender_name'])
            self.assertEqual(row['chat_id'],909)

    def test_plain_sqlite_delete_remnants_never_gain_neighbor_ids(self):
        for platform in ('ios','android'):
            original = self.inputs / ('positive/ios/tgdata.db' if platform == 'ios' else 'positive/android/cache4.db')
            target = self.inputs / ('residual-'+platform) / 'native.db'
            target.parent.mkdir()
            shutil.copyfile(original,target)
            table = 'messages_v29' if platform == 'ios' else 'scheduled_messages_v2'
            with closing(sqlite3.connect(target)) as db:
                db.execute('PRAGMA secure_delete=OFF')
                db.execute('DELETE FROM '+table)
                db.commit()
            _, summary, rows = self.analyze('residual-'+platform,fragments=True)
            self.assertEqual((summary['native_records'],rows),(0,[]))

    def test_actual_native_wal_delete_preserves_only_checked_previous_snapshot_not_deleted_claim(self):
        for platform, text in [('android',self.oracle['expected']['android'][0]['text']),('ios','iOS WAL historical surviving text')]:
            with self.subTest(platform=platform):
                _, summary, rows = self.analyze('wal/'+platform)
                self.assertEqual((summary['native_records'],len(rows)), (1,1))
                row = rows[0]
                self.assertEqual((row['text'],row['evidence_kind']), (text,'previous'))
                self.assertEqual(row['wal_proof'], 'all_pages_from_validated_wal')
                self.assertIsNone(row.get('deleted'))
                self.assertEqual(summary['deleted_supported_records'], 0)
                self.assertEqual(summary['history_messages'], int(platform=='ios'))

    def test_new_formats_are_searchable_regex_fulltext_and_reimport_keeps_categories(self):
        secrets = dict(telegram_desktop_passcode=TEST_PASSCODE)
        for relative, phrase, count in [('positive/android','Scheduled',2),('positive/ios','iOS native',2),
                                        ('positive/desktop-tag6','Desktop native',2)]:
            output, _, records = self.analyze(relative,secrets)
            found = archive_search.search(dict(protocol=1,operation='search',archive=str(output),app='Telegram',query=phrase))
            self.assertEqual(found['total'],count)
            regex = archive_search.search(dict(protocol=1,operation='search',archive=str(output),app='Telegram',query='native|alternate',query_mode='regex'))
            self.assertEqual(regex['total'],count)
            row = found['records'][0]
            page = archive_text.read_page(dict(protocol=1,operation='message_page',archive=str(output),
                record_key=row['archive_record_key'],text_offset=0,limit=65536))
            self.assertEqual(page['text'],row['text'])
            for marker in ('FILENAME','NEVER_FETCH','TAGS_NEVER_MESSAGE'):
                self.assertEqual(archive_search.search(dict(protocol=1,operation='search',archive=str(output),app='Telegram',query=marker))['total'],0)
            destination = self.base / f'reimport-{self.sequence}'
            with patch.object(engine,'emit'):
                summary = telegram_auto.analyze(dict(protocol=1,operation='telegram_analyze',destination=str(destination),
                    options=dict(roots=[str(output)])),engine.Importer,lambda *a,**k:None)
            imported = [json.loads(s) for s in (destination/'messages.jsonl').read_text('utf-8').splitlines()]
            self.assertEqual({r['record_kind'] for r in imported},{r['record_kind'] for r in records})
            self.assertEqual({r['text'] for r in imported},{r['text'] for r in records})
            if 'desktop' in relative or 'android' in relative:
                self.assertEqual(summary['history_messages'],0)


if __name__ == '__main__':
    unittest.main()
