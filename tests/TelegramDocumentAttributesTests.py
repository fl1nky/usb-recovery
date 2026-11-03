"""Native document captions/thumbs against an independent pinned Java oracle."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import math
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
from build_telegram_document_attributes_fixtures import load_cases, extract_sources
from build_telegram_document_descriptor_fixtures import create, inventory
from telegram_media_retention_policy import expected_record_count_v1


class TelegramDocumentAttributesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = list(load_cases())
        cls.controls = list(load_cases(controls=True))
        cls.by_name = {c['name']: c for c in cls.cases}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-document-attributes-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = extract_sources(self.root / 'inputs')
        self.sequence = 0

    def analyze(self, source, *, fragments=False):
        self.sequence += 1
        output = self.root / ('archive-' + str(self.sequence))
        before = inventory(self.root / 'inputs')
        with patch.object(engine, 'emit'):
            summary = telegram_auto.analyze(dict(protocol=1, operation='telegram_analyze', destination=str(output),
                options=dict(roots=[str(source)], scan_fragments=fragments, fragment_query='recipe')),
                engine.Importer, lambda *a, **k: None)
        self.assertEqual(before, inventory(self.root / 'inputs'))
        rows = [json.loads(line) for line in (output / 'messages.jsonl').read_text('utf-8').splitlines()]
        native = [r for r in rows if r.get('application_confirmed') is True and r.get('record_kind') in telegram_auto.NATIVE_RECORD_KINDS
                  and r.get('evidence_kind') != 'fragment' and r.get('provenance_verification') != 'provided_archive_metadata']
        return output, summary, rows, native

    def assert_native(self, case, rows):
        self.assertEqual(len(rows), expected_record_count_v1(case), case['name'])
        for row in rows:
            self.assertEqual(row['text'], case['expected']['text'])
            self.assertEqual((row['chat_id'], row['message_id']), (case['exact_sql']['uid'], case['exact_sql']['mid']))
            peer = case['expected']['from_peer']
            self.assertEqual(row['sender_id'], peer['kind'] + ':' + str(peer['id']))
            self.assertEqual(row['native_tl_body_sha256'], case['tl_body_sha256'])
            self.assertEqual((row['native_constructor'], row['native_layer']), ('0x7600b9d3', 232))
            self.assertEqual((row['media_kind'], row['media_id']), ('document', str(case['document_id'])))
            self.assertIsNone(row.get('sender_name'))
            self.assertIsNone(row.get('deleted'))
            self.assertEqual(dt.datetime.fromisoformat(row['timestamp']).timestamp(), case['exact_sql']['date'])
            for marker in ('ATTRIBUTE_FILENAME_', 'ATTRIBUTE_TITLE_', 'ATTRIBUTE_PERFORMER_', 'OPAQUE_THUMB_'):
                self.assertNotIn(marker, row['text'])

    def test_all31_official_serializations_preserve_complete_body(self):
        self.assertEqual((len(self.cases), len(self.controls)), (31, 171))
        self.assertEqual(sum(c['expected_text_slots'] for c in self.cases), 30)
        for case in self.cases:
            with self.subTest(case=case['name']):
                value = parse_message(case['blob'])
                for key, expected in case['expected'].items():
                    self.assertEqual(value[key], expected, key)
                self.assertEqual((value['tl_bytes'], value['consumed_bytes']), (case['tl_bytes'], len(case['blob'])))
                document = value['media']['document']
                self.assertEqual(document['id'], case['document_id'])
                self.assertFalse({'filename', 'size', 'mime_type', 'title', 'performer', 'access_hash', 'file_reference'} & document.keys())
                for size in document.get('thumbs', []):
                    if size.get('kind') == 'cached':
                        self.assertEqual(case['blob'][size['blob_offset']:size['blob_offset'] + len(size['content'])], size['content'])

    def test_all171_controls_keep_wire_validity_separate_from_sql_scope(self):
        for case in self.controls:
            with self.subTest(case=case['name']):
                if case['name'].endswith('--sql-dialog-mismatch'):
                    value = parse_message(case['blob'])
                    self.assertEqual(value['text'], self.by_name[case['parent']]['expected']['text'])
                else:
                    with self.assertRaises(TelegramTlError):
                        parse_message(case['blob'])
        source = self.root / 'controls-only'
        source.mkdir()
        for case in self.controls:
            path = source / case['name']
            path.mkdir()
            (path / 'cache4.db').write_bytes(self.inputs[case['name']].read_bytes())
        _, summary, _, native = self.analyze(source)
        self.assertEqual((summary['native_records'], native), (0, []))

    def test_all_native_sources_publish_only_original_text_and_known_references(self):
        for case in self.cases:
            with self.subTest(case=case['name']):
                output, summary, _, native = self.analyze(self.inputs[case['name']])
                self.assert_native(case, native)
                self.assertEqual(summary['native_records'], expected_record_count_v1(case))
                if case['name'] in ('doc-cached-png', 'doc-two-photo-thumbs'):
                    self.assertEqual((native[0]['thumbnail_count'], native[0]['media_status']), (1, 'cached_thumbnail_available'))
                    self.assertEqual(len(native[0]['attachments']), 1)
                    image = output / native[0]['attachments'][0]
                    value = parse_message(case['blob'])
                    content = next(s['content'] for s in value['media']['document']['thumbs'] if s.get('kind') == 'cached')
                    self.assertEqual(hashlib.sha256(image.read_bytes()).digest(), hashlib.sha256(content).digest())
                else:
                    for row in native:
                        self.assertEqual((row['thumbnail_count'], row['attachments'], row['media_status']), (0, [], 'document_reference_only'))

    def test_video_doubles_audio_ints_and_vector_bounds_fail_closed(self):
        case = self.by_name['video-all-optional']
        attribute = next(a for a in case['attributes'] if a['class'] == 'TL_documentAttributeVideo')
        for number in (math.nan, math.inf, -math.inf, -0.25):
            raw = bytearray(case['blob'])
            struct.pack_into('<d', raw, attribute['offset'] + 8, number)
            with self.assertRaises(TelegramTlError):
                parse_message(raw)
        raw = bytearray(self.by_name['doc-photo-size']['blob'])
        vector = raw.index(struct.pack('<I', 0x1CB5C415), self.by_name['doc-photo-size']['native_offsets']['document'])
        struct.pack_into('<i', raw, vector + 4, 2**31 - 1)
        with self.assertRaises(TelegramTlError):
            parse_message(raw)

    def test_repeated_attribute_kinds_remain_outside_the_supported_profile(self):
        for name in ('baseline-filename', 'video-basic', 'audio-basic', 'image-size', 'animated'):
            with self.subTest(case=name):
                case = self.by_name[name]
                attribute = case['attributes'][-1]
                start, length = attribute['offset'], attribute['bytes']
                copied = case['blob'][start:start + length]
                self.assertEqual(hashlib.sha256(copied).hexdigest(), attribute['sha256'])
                self.assertEqual(start + length, case['tl_bytes'])
                raw = bytearray(case['blob'][:case['tl_bytes']] + copied + case['blob'][case['tl_bytes']:])
                struct.pack_into('<i', raw, case['attributes'][0]['offset'] - 4, len(case['attributes']) + 1)
                with self.assertRaisesRegex(TelegramTlError, 'TL_UNSUPPORTED_DOCUMENT_ATTRIBUTE'):
                    parse_message(raw)

    def test_cached_document_thumbnails_replay_from_previous_wal_snapshots(self):
        for name in ('doc-cached-png', 'doc-two-photo-thumbs'):
            case = self.by_name[name]
            cached = next(s for s in parse_message(case['blob'])['media']['document']['thumbs'] if s.get('kind') == 'cached')
            for variant in ('history', 'residual'):
                with self.subTest(case=name, variant=variant):
                    source, _ = create(self.root / (name + '-' + variant), case, variant)
                    before = inventory(source.parent)
                    output, summary, _, native = self.analyze(source)
                    self.assertEqual(before, inventory(source.parent))
                    self.assert_native(case, native)
                    row = native[0]
                    self.assertEqual((row['evidence_kind'], row['media_status'], row['thumbnail_count']),
                                     ('previous', 'cached_thumbnail_available', 1))
                    self.assertEqual(row['wal_proof'], 'all_pages_from_validated_wal')
                    self.assertEqual(row.get('recovery_status') == 'deleted_supported_by_evidence', variant == 'residual')
                    self.assertEqual(summary['deleted_supported_records'], int(variant == 'residual'))
                    self.assertEqual((output / row['attachments'][0]).read_bytes(), cached['content'])
                    entries = json.loads((output / 'attachment-metadata.json').read_text('utf-8'))['attachments']
                    attachment = next(a for a in entries if a['path'] == row['attachments'][0])
                    self.assertEqual((attachment['kind'], attachment['sha256']),
                                     ('cached_thumbnail', hashlib.sha256(cached['content']).hexdigest()))
                    self.assertTrue(attachment['sources'])
                    for origin in attachment['sources']:
                        self.assertIn('/document.thumbs[', origin['source_record'])
                        self.assertEqual((origin['offset_kind'], origin['blob_offset']),
                                         ('sqlite_tl_blob_relative', cached['blob_offset']))
                        self.assertEqual((origin['wal_sha256'], origin['wal_snapshot_sha256'], origin['wal_commit_frame']),
                                         (row['wal_sha256'], row['wal_snapshot_sha256'], row['wal_commit_frame']))
                        self.assertEqual(case['blob'][origin['blob_offset']:origin['blob_offset'] + attachment['size']],
                                         (output / attachment['path']).read_bytes())

    def test_document_thumbnail_limits_and_wrong_dimensions_do_not_suppress_text(self):
        case = self.by_name['doc-cached-png']
        for setting, limit in (('MAX_NATIVE_THUMBNAILS', 0), ('MAX_NATIVE_THUMBNAIL_BYTES', 1)):
            with self.subTest(setting=setting), patch.object(telegram_auto, setting, limit):
                output, summary, _, native = self.analyze(self.inputs[case['name']])
                self.assert_native(case, native)
                self.assertEqual((native[0]['attachments'], native[0]['thumbnail_count'], native[0]['media_status']),
                                 ([], 0, 'document_reference_only'))
                self.assertEqual(summary['native_records'], 1)
                self.assertIn('TELEGRAM_THUMBNAIL_LIMIT', summary['warnings'])
        raw = bytearray(case['blob'])
        at = raw.index(struct.pack('<I', 0x021E1AD6), case['native_offsets']['document'])
        self.assertEqual(struct.unpack_from('<i', raw, at + 8)[0], 2)
        struct.pack_into('<i', raw, at + 8, 3)
        source, _ = create(self.root / 'wrong-dimensions', case, blob=raw)
        output, summary, _, native = self.analyze(source)
        self.assertEqual((summary['native_records'], native[0]['text']), (1, case['expected']['text']))
        self.assertEqual((native[0]['attachments'], native[0]['thumbnail_count'], native[0]['media_status']),
                         ([], 0, 'document_reference_only'))
        self.assertIn('TELEGRAM_THUMBNAIL_DIMENSIONS_MISMATCH', summary['warnings'])

    def test_new_documents_do_not_expand_photo_only_media_cache_or_other_layers(self):
        for case in self.cases:
            with self.subTest(case=case['name']):
                with self.assertRaises(telegram_media_cache.MediaCacheError):
                    telegram_media_cache._checked((case['exact_sql']['mid'], case['exact_sql']['uid'], case['exact_sql']['date'], 0, case['blob']))
                raw = bytearray(case['blob'])
                struct.pack_into('<I', raw, 0, 0x95EF6F2B)
                with self.assertRaises(TelegramTlError):
                    parse_message(raw)

    def test_wal_residual_versions_and_unattributed_dump_keep_provenance(self):
        case = self.by_name['video-all-optional']
        for variant in ('history', 'residual'):
            with self.subTest(variant=variant):
                source, _ = create(self.root / variant, case, variant)
                before = inventory(source.parent)
                _, _, _, native = self.analyze(source)
                self.assertEqual(before, inventory(source.parent))
                self.assert_native(case, native)
                for row in native:
                    self.assertEqual(row['evidence_kind'], 'previous')
                    self.assertEqual(row['wal_proof'], 'all_pages_from_validated_wal')
                    self.assertIsNone(row.get('deleted'))
                    if variant == 'residual':
                        self.assertTrue(row['residual_sources'])
                        for origin in row['residual_sources']:
                            with Path(origin['source_file'] + '-wal').open('rb') as stream:
                                stream.seek(origin['physical_byte_offset'])
                                raw = stream.read(origin['sqlite_record_length'])
                            self.assertEqual(hashlib.sha256(raw).hexdigest(), origin['sqlite_record_sha256'])
                            self.assertIn(case['blob'], raw)
        hidden = self.root / '.hidden' / 'cache'
        hidden.mkdir(parents=True)
        dump = hidden / 'memory.bin'
        dump.write_bytes(b'\0' * 513 + case['blob'] + b'\0' * 200)
        _, _, rows, native = self.analyze(hidden.parent, fragments=True)
        self.assertEqual(native, [])
        typed = [r for r in rows if r.get('record_kind') == 'typed_tl_fragment']
        self.assertEqual(len(typed), 1)
        self.assertEqual((typed[0]['text'], typed[0]['byte_offset'], typed[0]['byte_length']), (case['expected']['text'], 513, case['tl_bytes']))
        for field in ('chat_id', 'sender_id', 'message_id', 'timestamp', 'deleted'):
            self.assertIsNone(typed[0].get(field))

    def test_keyword_regex_fulltext_and_untrusted_reimport(self):
        case = self.by_name['audio-all-metadata']
        output, _, _, native = self.analyze(self.inputs[case['name']])
        for mode, query in [('literal', 'recipe'), ('regex', r'recipe[\s\S]*第二行')]:
            result = archive_search.search(dict(protocol=1, operation='search', archive=str(output), app='Telegram', query=query, query_mode=mode))
            self.assertEqual(result['total'], 1)
            record = result['records'][0]
            page = archive_text.read_page(dict(protocol=1, operation='message_page', archive=str(output), record_key=record['archive_record_key'], text_offset=0, limit=65536))
            self.assertEqual(page['text'], case['expected']['text'])
        _, _, rows, reimported = self.analyze(output / 'messages.jsonl')
        self.assertEqual((len(rows), reimported), (len(native), []))
        self.assertTrue(all(r.get('provenance_verification') == 'provided_archive_metadata' for r in rows))


if __name__ == '__main__':
    unittest.main(verbosity=2)
