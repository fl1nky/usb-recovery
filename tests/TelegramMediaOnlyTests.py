"""Native media-only records against an independently produced Java corpus."""
from pathlib import Path
from contextlib import closing
import datetime as dt
import hashlib
import json
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
from telegram_tl import parse_message, TelegramTlError
from build_telegram_media_only_fixtures import load_cases, extract_sources, load_oracle
from build_telegram_document_empty_fixtures import create, inventory


class TelegramMediaOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = list(load_cases())
        cls.controls = list(load_cases(controls=True))
        cls.by_name = {c['name']: c for c in cls.cases}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-media-only-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = extract_sources(self.root / 'inputs')
        self.sequence = 0

    def analyze(self, source, *, fragments=False):
        self.sequence += 1
        output = self.root / ('archive-' + str(self.sequence))
        folder = source if source.is_dir() else source.parent
        before = inventory(folder)
        with patch.object(engine, 'emit'):
            summary = telegram_auto.analyze(dict(protocol=1, operation='telegram_analyze', destination=str(output),
                options=dict(roots=[str(source)], scan_fragments=fragments)), engine.Importer, lambda *a, **k: None)
        self.assertEqual(before, inventory(folder), 'Original DB/WAL/SHM and source bytes remain unchanged')
        rows = [json.loads(line) for line in (output / 'messages.jsonl').read_text('utf-8').splitlines()]
        native = [r for r in rows if r.get('application_confirmed') is True
                  and r.get('record_kind') in telegram_auto.NATIVE_RECORD_KINDS
                  and r.get('evidence_kind') != 'fragment'
                  and r.get('provenance_verification') != 'provided_archive_metadata']
        return output, summary, rows, native

    def assert_native(self, case, row):
        self.assertEqual(row['text'], case['expected']['text'])
        self.assertEqual(row['text'].encode('utf-8'), case['text'].encode('utf-8'))
        self.assertEqual((row['chat_id'], row['message_id']), (case['exact_sql']['uid'], case['exact_sql']['mid']))
        self.assertEqual(row['sender_id'], 'user:' + str(case['from_user']))
        self.assertEqual(dt.datetime.fromisoformat(row['timestamp']).timestamp(), case['date'])
        self.assertEqual(row['native_tl_body_sha256'], case['tl_body_sha256'])
        self.assertEqual((row['native_layer'], row['native_constructor']), (232, '0x7600b9d3'))
        self.assertEqual((row['media_kind'], row['media_id']), ('document', str(case['document_id'])))
        self.assertIsNone(row.get('deleted'))
        self.assertIsNone(row.get('sender_name'))
        self.assertEqual(row['text_field'], 'message')
        for marker in ('NEVER_OPEN', 'FILENAME_', 'TITLE_', 'PERFORMER_', 'OPAQUE_'):
            self.assertNotIn(marker, row['text'])

    def test_native_framing_and_immutable_zero_text_slots_are_distinct_from_retention(self):
        oracle = load_oracle()
        self.assertEqual((len(self.cases), len(self.controls)), (14, 56))
        self.assertEqual(sum(c['expected_text_slots'] for c in self.cases), 7)
        self.assertEqual(oracle['future_product_retention_policy'], 'UNSPECIFIED; zero text slots does not mean no native message metadata')
        for case in self.cases:
            with self.subTest(case=case['name']):
                value = parse_message(case['blob'])
                for field, expected in case['expected'].items():
                    self.assertEqual(value[field], expected)
                self.assertEqual((value['tl_bytes'], value['consumed_bytes']), (case['tl_bytes'], case['bytes']))
                self.assertEqual(value['media']['document']['id'], case['document_id'])
                self.assertNotIn('attachPath', value)

    def test_all14_native_rows_survive_with_exact_empty_or_nonempty_text(self):
        output, summary, _, native = self.analyze(self.root / 'inputs/positive')
        self.assertEqual((summary['native_records'], len(native)), (14, 14))
        self.assertEqual(sum(r['text'] == '' for r in native), 7)
        by_mid = {r['message_id']: r for r in native}
        for case in self.cases:
            with self.subTest(case=case['name']):
                row = by_mid[case['message_id']]
                self.assert_native(case, row)
                if case['known_valid_png_thumbnail']:
                    self.assertEqual((row['media_status'], row['thumbnail_count'], len(row['attachments'])), ('cached_thumbnail_available', 1, 1))
                    cached = next(s for s in parse_message(case['blob'])['media']['document']['thumbs'] if s.get('kind') == 'cached')
                    self.assertEqual((output / row['attachments'][0]).read_bytes(), cached['content'])
                else:
                    self.assertEqual((row['media_status'], row['thumbnail_count'], row['attachments']), ('document_reference_only', 0, []))
        metadata = json.loads((output / 'attachment-metadata.json').read_text('utf-8'))['attachments']
        self.assertEqual(len(metadata), 1)
        self.assertEqual((metadata[0]['kind'], metadata[0]['size'], len(metadata[0]['sources'])), ('cached_thumbnail', 70, 2))
        self.assertIn('TELEGRAM_CACHED_THUMBNAIL_UNREADABLE', summary['warnings'])

    def test_all56_controls_never_acquire_native_identity(self):
        for case in self.controls:
            if case['name'].endswith('--sql-dialog-mismatch'):
                self.assertEqual(parse_message(case['blob'])['text'], self.by_name[case['parent']]['text'])
            else:
                with self.assertRaises(TelegramTlError):
                    parse_message(case['blob'])
        _, summary, _, native = self.analyze(self.root / 'inputs/controls', fragments=True)
        self.assertEqual((summary['native_records'], native), (0, []))

    def test_empty_document_reference_is_browsable_but_never_matches_metadata_as_text(self):
        output, _, _, native = self.analyze(self.root / 'inputs/positive')
        for query, expected in [('', 14), ('Paired', 7), ('NEVER_OPEN', 0), ('FILENAME_', 0)]:
            result = archive_search.search(dict(protocol=1, operation='search', archive=str(output), app='Telegram', query=query))
            self.assertEqual(result['total'], expected, query)
        listing = archive_search.search(dict(protocol=1, operation='search', archive=str(output), app='Telegram', query=''))
        empty = next(r for r in listing['records'] if r['text'] == '')
        page = archive_text.read_page(dict(protocol=1, operation='message_page', archive=str(output),
            record_key=empty['archive_record_key'], text_offset=0, limit=65536))
        self.assertEqual((page['text'], page['text_length']), ('', 0))
        self.assertEqual(sum(r['text'] == '' for r in native), 7)

    def test_empty_cached_and_reference_messages_replay_from_checked_wal_snapshots(self):
        for name in ('empty-cached-png', 'empty-audio', 'empty-document-empty'):
            case = self.by_name[name]
            for variant in ('history', 'residual'):
                with self.subTest(case=name, variant=variant):
                    source, _ = create(self.root / (name + '-' + variant), case, variant)
                    output, summary, _, native = self.analyze(source)
                    self.assertEqual((summary['native_records'], len(native)), (1, 1))
                    row = native[0]
                    self.assert_native(case, row)
                    self.assertEqual((row['evidence_kind'], row['wal_proof']), ('previous', 'all_pages_from_validated_wal'))
                    self.assertEqual(summary['deleted_supported_records'], int(variant == 'residual'))
                    if row['attachments']:
                        attachment = json.loads((output / 'attachment-metadata.json').read_text('utf-8'))['attachments'][0]
                        for origin in attachment['sources']:
                            self.assertEqual((origin['wal_sha256'], origin['wal_snapshot_sha256']), (row['wal_sha256'], row['wal_snapshot_sha256']))
                            self.assertEqual(origin['offset_kind'], 'sqlite_tl_blob_relative')
                            self.assertEqual(case['blob'][origin['blob_offset']:origin['blob_offset'] + attachment['size']],
                                             (output / attachment['path']).read_bytes())

    def test_missing_reference_is_not_a_message_and_zero_id_is_not_absent(self):
        for document, expected in [({'type': 'empty'}, []), ({'type': 'empty', 'id': 0}, [('', 'message', False)]),
                                   ({'type': 'empty', 'id': -1}, [('', 'message', False)])]:
            value = {'text': '', 'media': {'type': 'document', 'document': document}}
            self.assertEqual(list(telegram_auto._native_text_parts(value, keep_empty_media=True)), expected)
            self.assertEqual(list(telegram_auto._native_text_parts(value)), [])

    def test_actual_sqlite_delete_recovers_empty_media_records_from_owned_freeblocks(self):
        source = self.root / 'actual-delete/cache4.db'
        source.parent.mkdir()
        removed = {self.by_name[name]['message_id'] for name in ('empty-plain', 'empty-video', 'empty-cached-png')}
        with closing(sqlite3.connect(source)) as connection:
            connection.execute('PRAGMA secure_delete=OFF')
            connection.execute(load_oracle()['sql_schema'])
            for case in self.cases:
                connection.execute('INSERT INTO messages_v2(mid,uid,date,data) VALUES(?,?,?,?)',
                    (case['message_id'], case['sql_uid'], case['date'], case['blob']))
            connection.commit()
            connection.executemany('DELETE FROM messages_v2 WHERE mid=?', [(mid,) for mid in removed])
            connection.commit()
        _, summary, _, native = self.analyze(source)
        self.assertEqual((summary['native_records'], len(native), summary['deleted_supported_records']), (14, 14, 3))
        recovered = {r['message_id']: r for r in native if r.get('recovery_status') == 'deleted_supported_by_evidence'}
        self.assertEqual(set(recovered), removed)
        for case in self.cases:
            if case['message_id'] not in removed:
                continue
            row = recovered[case['message_id']]
            self.assert_native(case, row)
            self.assertEqual(row['record_kind'], 'sqlite_deleted_record')
            self.assertEqual(row['deletion_interpretation'], 'row_absent_from_current_table')
            self.assertEqual(row['sqlite_region'], 'freeblock')

    def test_thumbnail_limits_preserve_native_empty_record_and_no_original_byte_claim(self):
        case = self.by_name['empty-cached-png']
        for setting, limit in [('MAX_NATIVE_THUMBNAILS', 0), ('MAX_NATIVE_THUMBNAIL_BYTES', 1)]:
            with self.subTest(setting=setting), patch.object(telegram_auto, setting, limit):
                _, summary, _, native = self.analyze(self.inputs[case['name']])
                self.assertEqual((summary['native_records'], len(native)), (1, 1))
                self.assert_native(case, native[0])
                self.assertEqual((native[0]['attachments'], native[0]['media_status']), ([], 'document_reference_only'))
                self.assertIn('TELEGRAM_THUMBNAIL_LIMIT', summary['warnings'])

    def test_unbound_dump_and_reimport_do_not_promote_claimed_ids(self):
        source = self.root / '.hidden'; source.mkdir()
        case = self.by_name['empty-cached-png']
        (source / 'memory.bin').write_bytes(b'\0' * 513 + case['blob'] + b'\0' * 100)
        _, summary, rows, native = self.analyze(source, fragments=True)
        self.assertEqual((summary['native_records'], native), (0, []))
        for row in rows:
            for field in ('chat_id', 'message_id', 'sender_id', 'timestamp', 'deleted'):
                self.assertIsNone(row.get(field))
        output, _, _, native = self.analyze(self.inputs[case['name']])
        _, _, reimported, attributed = self.analyze(output / 'messages.jsonl')
        self.assertEqual((len(reimported), attributed), (1, []))
        self.assertEqual(reimported[0]['text'], '')
        self.assertEqual(reimported[0]['provenance_verification'], 'provided_archive_metadata')


if __name__ == '__main__':
    unittest.main(verbosity=2)
