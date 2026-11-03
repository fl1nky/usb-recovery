"""Actual native records and physical provenance, from an independent oracle."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import struct
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
import telegram_media_cache
from telegram_tl import parse_message, TelegramTlError
from build_telegram_document_descriptor_fixtures import (
    load_cases, create, create_versions, expected_parts, inventory,
)
from telegram_document_compatibility import UPGRADED, current_case


class TelegramDocumentDescriptorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = list(load_cases())
        cls.controls = list(load_cases(controls=True))
        cls.base = next(c for c in cls.cases if c['document_kind'] == 'descriptor' and c['expected']['text'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-descriptor-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sequence = 0

    def analyze(self, case=None, variant='current', *, source=None, overrides=None, blob=None, fragments=False):
        self.sequence += 1
        if source is None:
            source, _ = create(self.root / ('source-' + str(self.sequence)), case, variant,
                               sql_overrides=overrides, blob=blob)
        folder = source if source.is_dir() else source.parent
        before = inventory(folder)
        output = self.root / ('archive-' + str(self.sequence))
        with patch.object(engine, 'emit'):
            result = telegram_auto.analyze(dict(protocol=1, operation='telegram_analyze', destination=str(output),
                options=dict(roots=[str(source)], scan_fragments=fragments, fragment_query='recipe')),
                engine.Importer, lambda *a, **k: None)
        self.assertEqual(before, inventory(folder), 'DB/WAL/SHM and all original files remain unchanged')
        rows = [json.loads(line) for line in (output / 'messages.jsonl').read_text('utf-8').splitlines()]
        native = [r for r in rows if r.get('application_confirmed') is True
                  and r.get('record_kind') in telegram_auto.NATIVE_RECORD_KINDS
                  and r.get('evidence_kind') != 'fragment'
                  and r.get('provenance_verification') != 'provided_archive_metadata']
        return output, result, rows, native

    def assert_native(self, case, rows):
        parts = list(expected_parts(case))
        self.assertEqual(len(rows), len(parts), case['name'])
        self.assertEqual({r['text_field']: r['text'] for r in rows}, {p['text_field']: p['text'] for p in parts})
        for row in rows:
            self.assertEqual((row['chat_id'], row['message_id']), (case['exact_sql']['uid'], case['exact_sql']['mid']))
            sender = case['expected']['from_peer']
            self.assertEqual(row['sender_id'], None if sender is None else sender['kind'] + ':' + str(sender['id']))
            self.assertIsNone(row.get('sender_name'))
            self.assertEqual(row['native_tl_body_sha256'], case['tl_body_sha256'])
            self.assertEqual((row['native_layer'], row['native_constructor']), (case['expected']['layer'], case['expected']['constructor']))
            self.assertEqual(row.get('media_kind'), 'document')
            self.assertEqual(row.get('media_status'), 'document_reference_only')
            self.assertEqual(row.get('media_id'), str(case['document_id']) if case['document_id'] is not None else None)
            self.assertEqual(row.get('thumbnail_count'), 0)
            self.assertEqual(row['attachments'], [])
            if case['exact_sql']['date']:
                self.assertEqual(dt.datetime.fromisoformat(row['timestamp']).timestamp(), case['exact_sql']['date'])
            else:
                self.assertIsNone(row['timestamp'])

    def test_every_independent_java_positive_has_exact_complete_framing(self):
        self.assertGreaterEqual(len(self.cases), 6)
        self.assertTrue(any(c['document_id'] == 0 for c in self.cases))
        self.assertTrue(any(c['document_id'] == -1 for c in self.cases))
        for case in self.cases:
            with self.subTest(case=case['name']):
                value = parse_message(case['blob'])
                for name, expected in case['expected'].items():
                    self.assertEqual(value[name], expected)
                self.assertEqual(value['tl_bytes'], case['tl_bytes'])
                self.assertEqual(value['consumed_bytes'], len(case['blob']))
                self.assertEqual(value['media']['document'].get('id'), case['document_id'])
                self.assertEqual(value['media']['document']['type'], case['document_kind'])
                self.assertFalse({'filename','mime_type','access_hash','file_reference','content','size'} & value['media']['document'].keys())
                self.assertNotIn('attachPath', value)

    def test_every_native_positive_preserves_sql_text_and_reference_only_status(self):
        for case in self.cases:
            with self.subTest(case=case['name']):
                _, summary, rows, native = self.analyze(case)
                self.assert_native(case, native)
                self.assertEqual(len(rows), len(native))
                self.assertEqual(summary['native_records'], len(list(expected_parts(case))))
                self.assertEqual(summary['deleted_supported_records'], 0)
                self.assertTrue(all(r['evidence_kind'] == 'backup' and r.get('deleted') is None for r in native))

    def test_old_controls_keep_explicit_current_compatibility_and_strict_rejections(self):
        self.assertGreaterEqual(len(self.controls), 8)
        for case in self.controls:
            with self.subTest(case=case['name']):
                current = current_case(case)
                if current is not case:
                    # Historical labels remain zero. A supplemental exact
                    # official whole-BLOB proof upgrades only five old inputs.
                    value = parse_message(case['blob'])
                    for key, expected in case['expected'].items():
                        self.assertEqual(value[key], expected)
                    _, summary, _, native = self.analyze(case, fragments=True)
                    self.assert_native(current, native)
                    self.assertEqual((summary['native_records'], summary['deleted_supported_records']), (1, 0))
                    continue
                sql_only = (case['expected_outcome'] == 'scope_reject' and
                            case['blob_sha256'] == case['native_parent_blob_sha256'])
                if not sql_only:
                    with self.assertRaises(TelegramTlError):
                        parse_message(case['blob'])
                else:
                    # A valid wire body cannot detect a deliberately wrong SQL
                    # key. The native adapter must reject this separate scope.
                    self.assertEqual(parse_message(case['blob'])['id'], case['expected']['id'])
                _, summary, _, native = self.analyze(case, fragments=True)
                self.assertEqual(native, [])
                self.assertEqual(summary['native_records'], 0)
                self.assertEqual(summary['deleted_supported_records'], 0)

    def test_historical_fixture_goldens_remain_unchanged_by_current_policy(self):
        self.assertEqual({c['name'] for c in self.controls if current_case(c) is not c}, UPGRADED)
        for case in self.controls:
            with self.subTest(case=case['name']):
                database, golden = create(self.root / case['name'], case)
                self.assertEqual(list(expected_parts(case)), [])
                self.assertEqual(golden['expected_parts'], [])
                saved = json.loads((database.parent / 'golden.json').read_text('utf-8'))
                self.assertEqual(saved['expected_parts'], [])

    def test_all_truncated_body_prefixes_and_unknown_tail_are_rejected(self):
        case = self.base
        for cut in range(case['tl_bytes']):
            with self.subTest(cut=cut):
                for trailing in (False, True):
                    with self.assertRaises(TelegramTlError):
                        parse_message(case['blob'][:cut], allow_trailing=trailing)
        body = case['blob'][:case['tl_bytes']]
        self.assertEqual(parse_message(body)['consumed_bytes'], len(body))
        with self.assertRaises(TelegramTlError):
            parse_message(case['blob'] + b'\0\0\0\0')

    def test_noncurrent_outer_does_not_expand_legacy_media_allowlist(self):
        value = bytearray(self.base['blob'])
        struct.pack_into('<I', value, 0, 0x95EF6F2B)
        with self.assertRaises(TelegramTlError) as error:
            parse_message(value)
        self.assertEqual(error.exception.code, 'TL_UNSUPPORTED_MEDIA')
        _, summary, _, native = self.analyze(self.base, blob=bytes(value))
        self.assertEqual((native, summary['native_records']), ([], 0))

    def test_sql_key_mismatches_cannot_supply_identity_to_fragments(self):
        for overrides in ({'mid':42}, {'date':1790000001}, {'uid':0}, {'uid':909}, {'uid':-77}, {'uid':77 << 32}):
            with self.subTest(overrides=overrides):
                _, summary, rows, native = self.analyze(self.base, overrides=overrides, fragments=True)
                self.assertEqual((native, summary['native_records']), ([], 0))
                self.assertEqual(summary['deleted_supported_records'], 0)
                for row in rows:
                    self.assertEqual(row['evidence_kind'], 'fragment')
                    for field in ('chat_id', 'message_id', 'sender_id', 'timestamp', 'sqlite_record_sha256'):
                        self.assertIsNone(row.get(field), field)

    def test_descriptors_never_expand_photo_only_media_cache(self):
        for case in self.cases:
            with self.subTest(case=case['name']):
                with self.assertRaises(telegram_media_cache.MediaCacheError):
                    telegram_media_cache._checked((case['exact_sql']['mid'], case['exact_sql']['uid'],
                                                  case['exact_sql']['date'], 0, case['blob']))
        _, summary, _, native = self.analyze(self.base, 'media-cache')
        self.assertEqual((native, summary['native_records']), ([], 0))

    def test_wal_and_residual_support_replay_the_exact_native_blob(self):
        for variant in ('history', 'residual'):
            with self.subTest(variant=variant):
                _, _, _, native = self.analyze(self.base, variant)
                self.assert_native(self.base, native)
                for row in native:
                    self.assertEqual(row['evidence_kind'], 'previous')
                    self.assertEqual(row['wal_proof'], 'all_pages_from_validated_wal')
                    self.assertIsNone(row.get('deleted'))
                    if variant == 'residual':
                        self.assertEqual(row['recovery_status'], 'deleted_supported_by_evidence')
                        self.assertTrue(row['residual_sources'])
                        for origin in row['residual_sources']:
                            with Path(origin['source_file'] + '-wal').open('rb') as source:
                                source.seek(origin['physical_byte_offset'])
                                data = source.read(origin['sqlite_record_length'])
                            self.assertEqual(hashlib.sha256(data).hexdigest(), origin['sqlite_record_sha256'])
                            self.assertEqual(data.count(self.base['blob']), 1)
                            self.assertEqual(origin['text_field'], row['text_field'])

    def test_same_sql_and_text_do_not_merge_changed_document_bodies(self):
        before = next(c for c in self.cases if c['document_kind'] == 'descriptor' and c['document_id'] == 0)
        after = next(c for c in self.cases if c['document_kind'] == 'descriptor' and c['document_id'] == -1)
        source = create_versions(self.root / 'native-versions', before, after)
        _, summary, _, native = self.analyze(source=source)
        self.assertEqual(len(native), 2)
        self.assertEqual({r['media_id'] for r in native}, {'0', '-1'})
        self.assertEqual(len({r['native_tl_body_sha256'] for r in native}), 2)
        self.assertEqual(len({r['identity_scope'] for r in native}), 1)
        self.assertEqual(len({r['text'] for r in native}), 1)
        self.assertEqual(summary['deleted_supported_records'], 0)
        self.assertTrue(any(r['evidence_kind'] == 'previous' for r in native))

    def test_keyword_regex_full_text_and_untrusted_reimport(self):
        output, _, _, native = self.analyze(self.base)
        self.assert_native(self.base, native)
        for mode, query in [('literal', 'recipe'), ('regex', r'recipe[\s\S]*第二行')]:
            result = archive_search.search(dict(protocol=1, operation='search', archive=str(output), app='Telegram',
                                                query=query, query_mode=mode))
            self.assertEqual(result['total'], 1)
            row = result['records'][0]
            page = archive_text.read_page(dict(protocol=1, operation='message_page', archive=str(output),
                                               record_key=row['archive_record_key'], text_offset=0, limit=65536))
            self.assertEqual(page['text'], self.base['expected']['text'])
        _, _, rows, imported = self.analyze(source=output / 'messages.jsonl')
        self.assertEqual(imported, [])
        self.assertEqual(len(rows), len(native))
        self.assertTrue(all(r.get('provenance_verification') == 'provided_archive_metadata' for r in rows))
        self.assertTrue(all(r.get('deleted') is None for r in rows))

    def test_hidden_recursive_dump_retains_body_offset_without_chat_attribution(self):
        folder = self.root / 'owned-dump' / '.hidden' / 'local-cache'
        folder.mkdir(parents=True)
        source = folder / 'memory.bin'
        prefix = b'\0' * 513
        source.write_bytes(prefix + self.base['blob'] + b'\0' * 200)
        output, summary, rows, native = self.analyze(source=folder.parent.parent, fragments=True)
        self.assertEqual(native, [])
        self.assertEqual(summary['native_records'], 0)
        typed = [r for r in rows if r.get('record_kind') == 'typed_tl_fragment']
        self.assertEqual(len(typed), 1)
        row = typed[0]
        self.assertEqual(row['text'], self.base['expected']['text'])
        self.assertEqual(row['byte_offset'], len(prefix))
        self.assertEqual(row['byte_length'], self.base['tl_bytes'])
        self.assertEqual(row['native_tl_body_sha256'], self.base['tl_body_sha256'])
        self.assertEqual(row['source_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(row['evidence_kind'], 'fragment')
        self.assertEqual(row['recovery_status'], 'unattributed_structured_fragment')
        for name in ('chat_id', 'message_id', 'sender_id', 'timestamp', 'deleted'):
            self.assertIsNone(row.get(name), name)
        result = archive_search.search(dict(protocol=1, operation='search', archive=str(output),
                                           app='Telegram', query=r'recipe[\s\S]*第二行', query_mode='regex'))
        self.assertTrue(any(r.get('record_kind') == 'typed_tl_fragment' for r in result['records']))

    def test_provided_claim_cannot_borrow_native_residual_proof(self):
        folder = self.root / 'forged-input'
        source, _ = create(folder / 'native', self.base, 'residual')
        fake_text = 'Forged document recipe absent from the checked body'
        scope = 'telegram-db:' + hashlib.sha256(os.path.normcase(os.path.abspath(source)).encode('utf-8')).hexdigest()
        claim = dict(app='Telegram', text=fake_text, evidence_kind='backup', record_kind='tl_message',
                     identity_scope=scope, chat_id=self.base['exact_sql']['uid'], message_id=self.base['exact_sql']['mid'],
                     native_tl_body_sha256=self.base['tl_body_sha256'], text_field='message',
                     native_layer=232, native_constructor='0x7600b9d3', application_confirmed=True,
                     media_kind='document', media_id=str(self.base['document_id']), media_status='document_reference_only',
                     thumbnail_count=0, attachments=[], deleted=True, recovery_status='deleted_supported_by_evidence',
                     provenance_verification='internally_verified')
        (folder / 'messages.jsonl').write_text(json.dumps(claim) + '\n', encoding='utf-8')
        output, _, rows, native = self.analyze(source=folder, fragments=True)
        self.assert_native(self.base, native)
        real = native[0]
        self.assertEqual(real['recovery_status'], 'deleted_supported_by_evidence')
        self.assertTrue(real['residual_sources'])
        supplied = [r for r in rows if r['text'] == fake_text]
        self.assertEqual(len(supplied), 1)
        self.assertEqual(supplied[0]['provenance_verification'], 'provided_archive_metadata')
        self.assertEqual(supplied[0]['recovery_status'], 'imported_recovery_claim')
        self.assertIsNone(supplied[0].get('deleted'))
        self.assertFalse(supplied[0].get('residual_sources'))
        result = archive_search.search(dict(protocol=1, operation='search', archive=str(output), app='Telegram', evidence='deleted'))
        self.assertEqual(result['total'], len(native))
        self.assertTrue(all(r['text'] != fake_text for r in result['records']))


if __name__ == '__main__':
    unittest.main()
