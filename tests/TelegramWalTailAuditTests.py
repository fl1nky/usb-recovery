"""Independent source-binding and duplicate-origin audit of owned WAL copies."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import archive_search
import engine
import sqlite_history
import telegram_auto
from build_telegram_wal_tail_fixtures import build, make_database, LATEST


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TelegramWalTailAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='owned-wal-independent-')
        cls.folder = Path(cls.temporary.name)
        cls.manifest = build(cls.folder / 'fixtures')
        cls.cases = {case['name']: case for case in cls.manifest['cases']}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def source(self, name):
        return self.folder / 'fixtures' / self.cases[name]['path']

    def analyze(self, source):
        output = self.folder / (self._testMethodName + '-archive')
        before = {path.name: digest(path) for path in source.parent.iterdir() if path.is_file()}
        with patch('engine.emit'):
            result = telegram_auto.analyze({'protocol': 1, 'operation': 'telegram_analyze',
                'destination': str(output), 'options': {'roots': [str(source)],
                'recover_deleted': True}}, engine.Importer, lambda *args, **kwargs: None)
        self.assertEqual(before, {path.name: digest(path) for path in source.parent.iterdir() if path.is_file()})
        return output, result, [json.loads(line) for line in (output / 'messages.jsonl').read_text(encoding='utf-8').splitlines()]

    def test_checkpointed_duplicate_keeps_uncertain_latest_prefix_origin_in_search(self):
        writer = self.folder / 'writer.db'
        connection, _, _ = make_database(writer)
        try:
            self.assertEqual(connection.execute('PRAGMA wal_checkpoint(FULL)').fetchone()[0], 0)
            main = writer.read_bytes()
            wal = Path(str(writer) + '-wal').read_bytes()
        finally:
            connection.close()
        pair = self.folder / 'checkpointed-pair'
        pair.mkdir()
        source = pair / 'cache4.db'
        source.write_bytes(main)
        Path(str(source) + '-wal').write_bytes(wal + b'\xaa')
        output, result, rows = self.analyze(source)
        self.assertEqual(sum(row['text'] == LATEST for row in rows), 1)
        self.assertIn('TELEGRAM_WAL_HISTORY_INCOMPLETE', result['warnings'])
        found = archive_search.search({'protocol': 1, 'operation': 'search', 'archive': str(output),
            'app': 'Telegram', 'query': 'прабабушки', 'evidence': 'backup'})
        self.assertEqual(found['total'], 1)
        row = found['records'][0]
        self.assertIsNone(row.get('deleted'))
        origins = [origin for origin in row['sources'] if origin.get('wal_snapshot_latest_known_commit')]
        self.assertEqual(len(origins), 1)
        self.assertIs(origins[0]['wal_current_state_confirmed'], False)
        self.assertEqual(origins[0]['wal_tail_reason'], 'torn_frame')
        self.assertEqual(origins[0]['wal_validated_prefix_bytes'], len(wal))
        self.assertEqual(origins[0]['wal_sha256'], hashlib.sha256(wal + b'\xaa').hexdigest())

    def test_full_wal_snapshots_survive_unreadable_base_btree(self):
        original = self.source('torn-after-commit')
        pair = self.folder / 'unreadable-base-pair'
        pair.mkdir()
        source = pair / 'cache4.db'
        damaged = bytearray(original.read_bytes())
        damaged[100] = 255
        source.write_bytes(damaged)
        Path(str(source) + '-wal').write_bytes(Path(str(original) + '-wal').read_bytes())
        _, result, rows = self.analyze(source)
        latest = [row for row in rows if row['text'] == LATEST]
        self.assertEqual(len(latest), 1)
        self.assertEqual(latest[0]['wal_proof'], 'all_pages_from_validated_wal')
        self.assertEqual(latest[0]['recovery_status'], 'committed_wal_prefix_snapshot')
        self.assertIs(latest[0]['wal_current_state_confirmed'], False)
        self.assertIsNone(latest[0]['deleted'])
        self.assertIn('TELEGRAM_SQLITE_CURRENT_UNREADABLE', result['warnings'])

    def test_changed_wal_after_staged_snapshot_cannot_pass_final_source_binding(self):
        original = self.source('torn-after-commit')
        pair = self.folder / 'mutating-pair'
        pair.mkdir()
        source = pair / 'cache4.db'
        wal = Path(str(source) + '-wal')
        source.write_bytes(original.read_bytes())
        wal.write_bytes(Path(str(original) + '-wal').read_bytes())
        saved = wal.stat()
        before = digest(wal)
        report, mutated = {}, []
        work = self.folder / 'mutation-work'
        work.mkdir()
        def change_after_snapshot():
            if not mutated and report.get('snapshots', 0) >= 1:
                raw = bytearray(wal.read_bytes())
                raw[-1] ^= 1
                wal.write_bytes(raw)
                os.utime(wal, ns=(saved.st_atime_ns, saved.st_mtime_ns))
                mutated.append(True)
            return False
        with self.assertRaisesRegex(sqlite_history.HistoryError, '^SOURCE_CHANGED$'):
            list(sqlite_history.iter_committed_snapshots(source, wal, work, report=report,
                cancel=change_after_snapshot, include_latest_on_incomplete_tail=True))
        self.assertTrue(mutated)
        self.assertEqual(wal.stat().st_size, saved.st_size)
        self.assertEqual(wal.stat().st_mtime_ns, saved.st_mtime_ns)
        self.assertNotEqual(digest(wal), before)
        self.assertEqual(list(work.rglob('*.partial')), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
