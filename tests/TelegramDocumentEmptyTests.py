"""Independent official Java/native SQLite cases for surviving document text."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import archive_search
import engine
import telegram_auto
import telegram_media_cache
from telegram_tl import parse_message, TelegramTlError
from build_telegram_document_empty_fixtures import load_cases, expected_parts, create, inventory
from telegram_media_retention_policy import retained_parts_v1


class TelegramDocumentEmptyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {case['name']: case for case in load_cases()}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-document-empty-')
        self.addCleanup(self.temporary.cleanup)
        self.root, self.sequence = Path(self.temporary.name), 0

    def analyze(self, case, variant='current', *, sql_overrides=None, blob=None, source=None, fragments=False):
        self.sequence += 1
        if source is None:
            source, _ = create(self.root / ('source-' + str(self.sequence)), case, variant,
                sql_overrides=sql_overrides, blob=blob)
        folder = source if source.is_dir() else source.parent
        before = inventory(folder)
        output = self.root / ('archive-' + str(self.sequence))
        with patch.object(engine, 'emit'):
            summary = telegram_auto.analyze(dict(protocol=1, operation='telegram_analyze', destination=str(output),
                options=dict(roots=[str(source)], scan_fragments=fragments, fragment_query='recipe')),
                engine.Importer, lambda *a, **k: None)
        self.assertEqual(inventory(folder), before, 'All source DB/WAL/SHM bytes remain unchanged')
        rows = [json.loads(line) for line in (output / 'messages.jsonl').read_text(encoding='utf8').splitlines()]
        native = [row for row in rows if row.get('application_confirmed') is True and
            row.get('record_kind') in telegram_auto.NATIVE_RECORD_KINDS and row.get('evidence_kind') != 'fragment']
        return output, summary, rows, native

    def assert_parts(self, case, rows, *, imported=False):
        expected = {part['text_field']: part['text'] for part in retained_parts_v1(case, expected_parts(case))}
        self.assertEqual(len(rows), len(expected), case['name'])
        self.assertEqual({row['text_field']: row['text'] for row in rows}, expected, case['name'])
        for row in rows:
            self.assertEqual((row['chat_id'], row['message_id']), (case['exact_sql']['uid'], case['exact_sql']['mid']))
            sender = case['expected']['from_peer']
            self.assertEqual(row['sender_id'], None if sender is None else 'user:' + str(sender['id']))
            wanted_date = case['exact_sql']['date']
            if wanted_date:
                self.assertEqual(dt.datetime.fromisoformat(row['timestamp']).timestamp(), wanted_date)
            else:
                self.assertIsNone(row['timestamp'])
            self.assertEqual(row['native_tl_body_sha256'], case['tl_body_sha256'])
            self.assertEqual((row['native_layer'], row['native_constructor']), (case['layer'], case['constructor']))
            self.assertEqual(row['attachments'], [])
            if case['name'] != 'photo-control':
                self.assertEqual(row.get('media_kind'), 'document')
                observed_id = case['document_id']
                self.assertEqual(row.get('media_id'), str(observed_id) if observed_id is not None else None)
                self.assertEqual(row.get('media_status'), 'document_reference_only')
                self.assertEqual(row.get('thumbnail_count'), 0)
            if imported:
                self.assertEqual(row['provenance_verification'], 'provided_archive_metadata')

    def reject(self, raw, code=None, **kwargs):
        with self.assertRaises(TelegramTlError) as caught:
            parse_message(raw, **kwargs)
        if code:
            self.assertEqual(caught.exception.code, code)

    def test_confirmed_false_negative_preserves_both_fields(self):
        case = self.cases['layer118-flags3']
        self.assertEqual(case['blob_sha256'], '1c141ed04a84de2f6d75c18af39d5efca73b4dd6c67b8a3aed9ebfdc7c3edc8d')
        parsed = parse_message(case['blob'])
        self.assertEqual(parsed['text'], case['expected']['text'])
        self.assertEqual(parsed['media']['legacy_caption'], case['expected_legacy_caption'])
        _, summary, _, native = self.analyze(case, fragments=True)
        self.assert_parts(case, native)
        self.assertEqual(summary['native_records'], 2)

    def test_all_167_official_serializations_and_signed_ids(self):
        self.assertEqual(len(self.cases), 167)
        self.assertEqual(len({c['constructor'] for c in self.cases.values()}), 19)
        for case in self.cases.values():
            with self.subTest(case=case['name']):
                value = parse_message(case['blob'])
                for name, wanted in case['expected'].items():
                    self.assertEqual(value[name], wanted)
                self.assertEqual(value['tl_bytes'], case['tl_bytes'])
                self.assertEqual(value['consumed_bytes'], len(case['blob']))
                self.assertTrue(value['local_tail_present'])
                media = value['media']
                self.assertEqual(media['constructor'], case['media_constructor'])
                self.assertEqual(media.get('legacy_caption'), case['expected_legacy_caption'])
                self.assertEqual(media.get('ttl_seconds'), case['ttl_seconds'])
                if case['name'] != 'photo-control':
                    self.assertEqual(media['type'], 'document')
                    self.assertEqual(media['document']['type'], 'empty')
                    self.assertEqual(media['document'].get('id'), case['document_id'])
                    self.assertNotIn('content', media['document'])
                    self.assertNotIn('attachPath', value)
        self.assertEqual(parse_message(self.cases['id0']['blob'])['media']['document']['id'], 0)
        self.assertEqual(parse_message(self.cases['id1']['blob'])['media']['document']['id'], -1)
        self.assertEqual(parse_message(self.cases['id2']['blob'])['media']['document']['id'], -(1 << 63))
        self.assertNotIn('id', parse_message(self.cases['layer118-flags0']['blob'])['media']['document'])

    def test_paired_photo_control_changes_exactly_eight_constructor_bytes(self):
        doc, photo = self.cases['layer118-flags3'], self.cases['photo-control']
        self.assertEqual(len(doc['blob']), len(photo['blob']))
        self.assertEqual([i for i, (a, b) in enumerate(zip(doc['blob'], photo['blob'])) if a != b],
            [80, 81, 82, 83, 88, 89, 90, 91])
        _, summary, _, native = self.analyze(photo)
        self.assert_parts(photo, native)
        self.assertEqual(summary['native_records'], 2)
        self.assertTrue(all(row['media_kind'] == 'photo' for row in native))

    def test_native_sql_body_identity_all_profiles_relations_and_text_roles(self):
        names = [f'layer{layer}-flags{index % 8}' for index, layer in enumerate(
            (232,226,224,222,220,216,205,199,195,180,179,176,175,173,169,135,131,123,118))]
        names += [f'direction{i}' for i in range(1, 5)] + [f'mode{i}' for i in range(1, 5)]
        names += ['date-zero', 'local-negative-mid', 'id0', 'id1']
        for name in names:
            with self.subTest(case=name):
                case = self.cases[name]
                _, summary, rows, native = self.analyze(case)
                self.assert_parts(case, native)
                self.assertEqual(len(rows), len(native))
                self.assertEqual(summary['native_records'], len(retained_parts_v1(case, expected_parts(case))))
                self.assertEqual(summary['deleted_supported_records'], 0)
                for row in native:
                    self.assertEqual(row['evidence_kind'], 'backup')
                    self.assertIsNone(row.get('deleted'))

    def test_unknown_media_flags_and_nested_documents_fail_closed(self):
        original = self.cases['layer118-flags3']['blob']
        for flags in (8, 3 | 256, 3 | (1 << 31), 0xffffffff):
            raw = bytearray(original)
            struct.pack_into('<I', raw, 84, flags)
            self.reject(raw, 'TL_UNSUPPORTED_FLAGS')
        for constructor in (0, 0x8fd4c4d8, 0x55555558, 0x2331b22d, 0xffffffff):
            raw = bytearray(original)
            struct.pack_into('<I', raw, 88, constructor)
            self.reject(raw, 'TL_UNSUPPORTED_DOCUMENT')
        raw = bytearray(original)
        struct.pack_into('<I', raw, 80, 0x52d8ccd9)
        self.reject(raw, 'TL_UNSUPPORTED_MEDIA')

    def test_every_truncated_tl_prefix_rejected_and_exact_body_allowed(self):
        case = self.cases['layer118-flags7']
        for cut in range(case['tl_bytes']):
            with self.subTest(cut=cut):
                self.reject(case['blob'][:cut])
                self.reject(case['blob'][:cut], allow_trailing=True)
        body = case['blob'][:case['tl_bytes']]
        self.assertEqual(parse_message(body)['consumed_bytes'], len(body))
        self.assertFalse(parse_message(body)['local_tail_present'])
        self.reject(case['blob'] + b'\0\0\0\0', 'TL_UNSUPPORTED_TRAILING_BYTES')
        self.reject(case['blob'][:-1])

    def test_caption_utf8_padding_length_and_negative_ttl_are_rejected(self):
        case = self.cases['layer118-flags7']
        cap = case['expected_legacy_caption'].encode('utf8')
        start = case['blob'].index(cap)
        raw = bytearray(case['blob']); raw[start] = 0xff
        self.reject(raw, 'TL_INVALID_UTF8')
        raw = bytearray(case['blob']); raw[start - 1] = 255
        self.reject(raw, 'TL_INVALID_STRING_LENGTH')
        end = start + len(cap)
        self.assertEqual(case['blob'][end], 0, 'Independent caption has a padding byte')
        raw = bytearray(case['blob']); raw[end] = 1
        self.reject(raw, 'TL_INVALID_PADDING')
        raw = bytearray(case['blob']); struct.pack_into('<i', raw, case['tl_bytes'] - 4, -1)
        self.reject(raw, 'TL_INVALID_NUMBER')

    def test_sql_mid_date_uid_and_peer_scope_are_not_inferred(self):
        case = self.cases['layer118-flags3']
        for overrides in ({'mid':42}, {'date':1790000001}, {'uid':0}, {'uid':909}, {'uid':-77},
                          {'uid':77 << 32}, {'mid':(99 << 32) | 41}):
            with self.subTest(sql=overrides):
                _, summary, rows, native = self.analyze(case, sql_overrides=overrides, fragments=True)
                self.assertEqual(native, [])
                self.assertEqual(summary['native_records'], 0)
                for row in rows:
                    self.assertEqual(row['evidence_kind'], 'fragment')
                    for field in ('chat_id','message_id','sender_id','timestamp','sqlite_record_sha256'):
                        self.assertIsNone(row.get(field), field)
                    self.assertNotEqual(row.get('recovery_status'), 'deleted_supported_by_evidence')

    def test_negative_wire_date_does_not_become_native_history(self):
        case = self.cases['layer118-flags3']
        raw = bytearray(case['blob'])
        at = raw.index(struct.pack('<i', case['exact_sql']['date']))
        struct.pack_into('<i', raw, at, -1)
        self.reject(raw, 'TL_INVALID_NUMBER')
        _, summary, _, native = self.analyze(case, blob=bytes(raw), sql_overrides={'date':-1}, fragments=True)
        self.assertEqual(native, [])
        self.assertEqual(summary['native_records'], 0)

    def test_document_cannot_expand_photo_only_media_cache_allowlist(self):
        case = self.cases['layer118-flags3']
        with self.assertRaises(telegram_media_cache.MediaCacheError):
            telegram_media_cache._checked((41,77,1790000000,0,case['blob']))
        _, summary, _, native = self.analyze(case, 'media-cache')
        self.assertEqual(native, [])
        self.assertEqual(summary['native_records'], 0)

    def test_validated_wal_and_residual_proof_keep_exact_both_slots(self):
        case = self.cases['layer118-flags3']
        for variant in ('history', 'residual'):
            with self.subTest(variant=variant):
                _, _, _, native = self.analyze(case, variant)
                self.assert_parts(case, native)
                for row in native:
                    self.assertEqual(row['wal_proof'], 'all_pages_from_validated_wal')
                    self.assertEqual(row['evidence_kind'], 'previous')
                    if variant == 'residual':
                        self.assertEqual(row['recovery_status'], 'deleted_supported_by_evidence')
                        self.assertTrue(row['residual_sources'])
                        for origin in row['residual_sources']:
                            self.assertEqual(origin['text_field'], row['text_field'])
                            with Path(origin['source_file'] + '-wal').open('rb') as file:
                                file.seek(origin['physical_byte_offset'])
                                raw = file.read(origin['sqlite_record_length'])
                            self.assertEqual(hashlib.sha256(raw).hexdigest(), origin['sqlite_record_sha256'])
                            self.assertEqual(raw.count(case['blob']), 1,
                                'The replayed record must contain this exact complete independent BLOB once')

    def test_text_search_regex_and_untrusted_reimport_preserve_slots(self):
        case = self.cases['layer118-flags3']
        output, _, _, native = self.analyze(case)
        self.assert_parts(case, native)
        for query, field in (('second', 'message'), ('caption', 'media.legacy_caption')):
            result = archive_search.search(dict(protocol=1, operation='search', archive=str(output),
                app='Telegram', query=query))
            self.assertEqual(result['total'], 1)
            self.assertEqual(result['records'][0]['text_field'], field)
        result = archive_search.search(dict(protocol=1, operation='search', archive=str(output),
            app='Telegram', query=r'caption[\s\S]*第二行', query_mode='regex'))
        self.assertEqual(result['total'], 1)
        _, _, rows, _ = self.analyze(case, source=output / 'messages.jsonl')
        self.assert_parts(case, rows, imported=True)


if __name__ == '__main__':
    unittest.main()
