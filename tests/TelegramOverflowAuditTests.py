"""Independent boundary audit of copied, owned SQLite overflow recovery."""
from pathlib import Path
import copy
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
import engine
import sqlite_deleted
import telegram_auto
from build_telegram_overflow_fixtures import create


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TelegramOverflowAudit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-overflow-independent-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.database, self.expected = create(self.folder / 'source')

    def rows(self, **options):
        return [row for row in sqlite_deleted.recover(self.database, **options)
                if row.get('row', {}).get('mid') == 3]

    def test_local_sql_key_does_not_authorize_foreign_tl_identifier(self):
        row = self.rows()[0]
        self.assertGreater(row['sqlite_payload_length'], row['sqlite_record_length'])
        raw = bytearray(self.database.read_bytes())
        blob = (row['sqlite_page'] - 1) * 4096 + row['sqlite_blob_page_offset']
        # The independent layer-232 writer places id after constructor/flags/flags2.
        self.assertEqual(bytes(raw[blob:blob + 16]), self.expected['blob'][:16])
        self.assertEqual(struct.unpack_from('<i', raw, blob + 12)[0], 3)
        struct.pack_into('<i', raw, blob + 12, 999)
        self.database.write_bytes(raw)
        before = digest(self.database)
        self.assertEqual(self.rows(), [])
        self.assertEqual(digest(self.database), before)

    def test_cancel_after_overflow_page_read_preserves_source(self):
        before, report, traversed = digest(self.database), {}, []
        def cancel():
            if report.get('pages_scanned', 0) >= 2:
                traversed.append(report['pages_scanned'])
                return True
            return False
        with self.assertRaisesRegex(sqlite_deleted.DeletedError, '^CANCELLED$'):
            sqlite_deleted.recover(self.database, report=report, cancel=cancel)
        self.assertTrue(traversed, 'Cancellation must occur inside traversal, not at entry')
        self.assertEqual(digest(self.database), before)
        self.assertEqual(sorted(path.name for path in self.database.parent.iterdir()), ['cache4.db'])

    def test_same_size_and_restored_mtime_mutation_is_caught_by_final_hash(self):
        reference = self.rows()[0]
        part = reference['sqlite_payload_ranges'][-1]
        saved = self.database.stat()
        before, report, changed = digest(self.database), {}, []
        def mutate_once():
            if not changed and report.get('pages_scanned', 0) >= 2:
                raw = bytearray(self.database.read_bytes())
                first, last = part['physical_byte_offset'], part['physical_byte_offset'] + part['bytes']
                at = raw.find(b'recipe', first, last)
                self.assertGreaterEqual(at, first)
                raw[at] = ord('R')
                self.database.write_bytes(raw)
                os.utime(self.database, ns=(saved.st_atime_ns, saved.st_mtime_ns))
                changed.append(at)
            return False
        with self.assertRaisesRegex(sqlite_deleted.DeletedError, '^DELETED_SOURCE_CHANGED$'):
            sqlite_deleted.recover(self.database, report=report, cancel=mutate_once)
        self.assertTrue(changed)
        self.assertEqual(self.database.stat().st_size, saved.st_size)
        self.assertEqual(self.database.stat().st_mtime_ns, saved.st_mtime_ns)
        self.assertNotEqual(digest(self.database), before)

    def test_local_archive_search_retains_replayable_complete_range_map(self):
        output = self.folder / 'archive'
        before = digest(self.database)
        with patch('engine.emit'):
            result = telegram_auto.analyze({'protocol': 1, 'operation': 'telegram_analyze',
                'destination': str(output), 'options': {'roots': [str(self.database)],
                'recover_deleted': True}}, engine.Importer, lambda *args, **kwargs: None)
        self.assertIn(result['status'], ('complete', 'partial'))
        rows = [json.loads(line) for line in (output / 'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        recovered = next(row for row in rows if row['text'] == self.expected['text'])
        found = archive_search.search({'protocol': 1, 'operation': 'search',
            'archive': str(output), 'app': 'Telegram', 'query': 'recipe 3', 'evidence': 'deleted'})
        self.assertEqual(found['total'], 1)
        normalized = found['records'][0]
        self.assertEqual(normalized['text'], self.expected['text'])
        for key in archive_search.OVERFLOW_FIELDS:
            self.assertEqual(normalized[key], recovered[key])
        payload, cursor = bytearray(), 0
        for part in normalized['sqlite_payload_ranges']:
            self.assertEqual(part['logical_offset'], cursor)
            self.assertEqual(part['physical_source'], 'db')
            with self.database.open('rb') as source:
                source.seek(part['physical_byte_offset'])
                block = source.read(part['bytes'])
            self.assertEqual(len(block), part['bytes'])
            payload.extend(block)
            cursor += len(block)
        self.assertEqual(cursor, normalized['sqlite_payload_length'])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), normalized['sqlite_payload_sha256'])
        self.assertIn(self.expected['blob'], payload)
        self.assertIsNone(normalized['deleted'])
        self.assertEqual(digest(self.database), before)

    def test_malformed_source_ranges_cannot_survive_display_normalization(self):
        raw = self.rows()[0]
        record = {'app': 'Telegram', 'text': self.expected['text'], 'evidence_kind': 'backup',
                  **{key: raw[key] for key in archive_search.OVERFLOW_FIELDS}}
        self.assertIsNotNone(archive_search._normalized(record))
        for mutation in ('boolean_length', 'gap', 'physical_overlap', 'allocated_origin_alias', 'wal_without_frame'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(record)
                parts = bad['sqlite_payload_ranges']
                if mutation == 'boolean_length':
                    bad['sqlite_payload_length'] = True
                elif mutation == 'gap':
                    parts[1]['logical_offset'] += 1
                elif mutation == 'physical_overlap':
                    parts[1]['physical_byte_offset'] = parts[0]['physical_byte_offset']
                elif mutation == 'allocated_origin_alias':
                    parts[1]['sqlite_page'] = parts[0]['sqlite_page']
                    bad['sqlite_overflow_pages'][0] = parts[0]['sqlite_page']
                else:
                    parts[1]['physical_source'] = 'wal'
                    parts[1]['wal_frame'] = None
                self.assertIsNone(archive_search._normalized(bad))


if __name__ == '__main__':
    unittest.main(verbosity=2)
