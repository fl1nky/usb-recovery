"""Independent real-SQLite WAL and format-level historical proof tests."""
from contextlib import closing
import hashlib
from pathlib import Path
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from sqlite_history import iter_committed_snapshots, HistoryError
from build_telegram_native_fixtures import build


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def independent_checksum(raw, little, state=(0, 0)):
    # Literal Appendix WAL recurrence, independent of the production helper.
    numbers = struct.unpack(("<" if little else ">") + "I" * (len(raw) // 4), raw)
    first, second = state
    for index in range(0, len(numbers), 2):
        first = (first + numbers[index] + second) % (1 << 32)
        second = (second + numbers[index + 1] + first) % (1 << 32)
    return first, second


def independent_wal(page_size, records, little=True):
    salts = (0x11223344, 0x55667788)
    raw = struct.pack(">6I", 0x377f0682 if little else 0x377f0683, 3007000, page_size, 0, *salts)
    state = independent_checksum(raw, little)
    raw += struct.pack(">2I", *state)
    for page_number, committed_size, payload in records:
        assert len(payload) == page_size
        begin = struct.pack(">2I", page_number, committed_size)
        state = independent_checksum(begin + payload, little, state)
        raw += begin + struct.pack(">4I", *salts, *state) + payload
    return raw


def rows(path):
    with closing(sqlite3.connect(Path(path).as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
        return connection.execute("SELECT mid FROM messages_v2 ORDER BY mid").fetchall()


class SqliteHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wal-history-tests-")
        self.base = Path(self.temporary.name)
        self.fixtures = self.base / "fixtures"
        build(self.fixtures)
        self.db = self.fixtures / "valid/cache4.db"
        self.wal = Path(str(self.db) + "-wal")
        self.output = self.base / "output"
        self.output.mkdir()
        self.report = {}

    def tearDown(self):
        self.temporary.cleanup()

    def snapshots(self, db=None, wal=None, **options):
        return list(iter_committed_snapshots(db or self.db, wal or self.wal, self.output, report=self.report, **options))

    def test_real_sqlite_commits_deleted_rows_preserved_source_hashes(self):
        before = sha(self.db), sha(self.wal)
        values = self.snapshots()
        self.assertEqual([rows(v["path"]) for v in values], [[], [(1,), (2,)]])
        self.assertEqual(self.report["committed_transactions"], 3)
        self.assertEqual(self.report["status"], "complete")
        for value in values:
            self.assertEqual(value["proof"], "all_pages_from_validated_wal")
            self.assertEqual(sha(value["path"]), value["sha256"])
            self.assertFalse(value["is_latest_known_commit"])
        self.assertEqual((sha(self.db), sha(self.wal)), before)
        # Windows must permit immediate rename: integrity checker closed DB.
        target = Path(values[0]["path"])
        target.rename(target.with_suffix(".renamed"))

    def test_latest_is_explicit_opt_in(self):
        values = self.snapshots(include_latest=True)
        self.assertEqual(rows(values[-1]["path"]), [(1,)])
        self.assertTrue(values[-1]["is_latest_known_commit"])

    def test_missing_preimage_never_uses_current_base(self):
        db = self.fixtures / "missing-preimage/cache4.db"
        self.assertEqual(self.snapshots(db, Path(str(db) + "-wal")), [])
        self.assertTrue(self.report["skipped"])
        self.assertTrue(all(x["reason"] == "historical_page_preimage_missing" for x in self.report["skipped"]))

    def test_invalid_header_checksum_and_unknown_version(self):
        for position, expected in ((24, "WAL_HEADER_CHECKSUM_INVALID"), (4, "WAL_VERSION_UNSUPPORTED")):
            raw = bytearray(self.wal.read_bytes())
            raw[position] ^= 1
            damaged = self.base / (str(position) + ".wal")
            damaged.write_bytes(raw)
            with self.assertRaises(HistoryError) as caught:
                self.snapshots(wal=damaged)
            self.assertEqual(caught.exception.code, expected)

    def test_frame_checksum_stops_at_prior_valid_prefix(self):
        raw = bytearray(self.wal.read_bytes())
        raw[-20] ^= 1
        damaged = self.base / "checksum.wal"
        damaged.write_bytes(raw)
        values = self.snapshots(wal=damaged)
        self.assertEqual(self.report["tail_reason"], "frame_checksum")
        self.assertEqual(self.report["status"], "complete_valid_prefix")
        # Last known good commit is deliberately excluded, even with bad tail.
        self.assertEqual([rows(v["path"]) for v in values], [[]])

    def test_torn_frame_not_a_commit(self):
        raw = self.wal.read_bytes()[:-25]
        damaged = self.base / "torn.wal"
        damaged.write_bytes(raw)
        values = self.snapshots(wal=damaged)
        self.assertEqual(self.report["tail_reason"], "torn_frame")
        self.assertEqual([rows(v["path"]) for v in values], [[]])

    def test_mismatching_frame_salts_are_not_history(self):
        raw = bytearray(self.wal.read_bytes())
        raw[32 + 8] ^= 1
        damaged = self.base / "salt.wal"
        damaged.write_bytes(raw)
        self.assertEqual(self.snapshots(wal=damaged), [])
        self.assertEqual(self.report["tail_reason"], "salt_mismatch")
        self.assertEqual(self.report["committed_transactions"], 0)

    def test_independently_serialized_both_checksum_byte_orders(self):
        # Turn a real final SQLite database into format-level WAL page sets.
        real = self.base / "final.sqlite"
        shutil.copyfile(self.db, real)
        shutil.copyfile(self.wal, Path(str(real) + "-wal"))
        with closing(sqlite3.connect(real)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        content = real.read_bytes()
        size = int.from_bytes(content[16:18], "big")
        pages = len(content) // size
        records = [(number, pages if number == pages else 0, content[(number - 1) * size:number * size])
                   for number in range(1, pages + 1)]
        records.append((1, pages, content[:size]))
        for little in (True, False):
            wal = self.base / ("little.wal" if little else "big.wal")
            wal.write_bytes(independent_wal(size, records, little))
            values = self.snapshots(db=real, wal=wal)
            self.assertEqual(len(values), 1)
            self.assertEqual(rows(values[0]["path"]), [(1,)])

    def test_uncommitted_spill_not_published(self):
        raw = self.wal.read_bytes()
        size = int.from_bytes(raw[8:12], "big")
        records = []
        for at in range(32, len(raw), size + 24):
            number, commit_size = struct.unpack(">2I", raw[at:at + 8])
            records.append((number, commit_size, raw[at + 24:at + 24 + size]))
        number, _, data = records[-1]
        records[-1] = (number, 0, data)
        wal = self.base / "uncommitted.wal"
        wal.write_bytes(independent_wal(size, records))
        values = self.snapshots(wal=wal, include_latest=True)
        self.assertEqual([rows(v["path"]) for v in values], [[], [(1,), (2,)]])
        self.assertGreater(self.report["uncommitted_frames"], 0)

    def test_shrink_then_growth_does_not_resurrect_old_page_incarnations(self):
        db = self.base / "base.sqlite"
        shutil.copyfile(self.db, db)
        shutil.copyfile(self.wal, Path(str(db) + "-wal"))
        with closing(sqlite3.connect(db)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        content = db.read_bytes()
        size = int.from_bytes(content[16:18], "big")
        count = len(content) // size
        first = content[:size]
        shrunk = bytearray(first)
        shrunk[28:32] = (1).to_bytes(4, "big")
        records = [(number, count if number == count else 0, content[(number - 1) * size:number * size])
                   for number in range(1, count + 1)]
        records += [(1, 1, bytes(shrunk)), (1, count, first), (1, count, first)]
        wal = self.base / "shrink.wal"
        wal.write_bytes(independent_wal(size, records))
        values = self.snapshots(db=db, wal=wal)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["commit_frame"], count)
        reason = next(r for r in self.report["skipped"] if r["commit_frame"] == count + 2)
        self.assertEqual(reason["reason"], "historical_page_preimage_missing")
        self.assertIn(2, reason["example_pages"])
        # The same rule survives selection that drops early commit metadata.
        self.assertEqual(self.snapshots(db=db, wal=wal, limits={"max_commits": 2}), [])

    def test_input_output_frame_and_snapshot_limits(self):
        with self.assertRaises(HistoryError) as caught:
            self.snapshots(limits={"max_input_bytes": 100})
        self.assertEqual(caught.exception.code, "INPUT_LIMIT")
        self.assertEqual(self.snapshots(limits={"max_output_bytes": 100}), [])
        self.assertTrue(self.report["output_limited"])
        self.assertEqual(self.snapshots(limits={"max_frames": 1}), [])
        self.assertEqual(self.report["tail_reason"], "frame_limit")
        self.assertEqual(len(self.snapshots(limits={"max_snapshots": 1})), 1)
        self.assertTrue(self.report["snapshot_selection_limited"])

    def test_invalid_limits_and_policy(self):
        for limits in ({"max_frames": 0}, {"unknown": 1}, {"max_snapshots": True}):
            with self.assertRaises(HistoryError) as caught:
                self.snapshots(limits=limits)
            self.assertEqual(caught.exception.code, "INVALID_LIMITS")
        with self.assertRaises(HistoryError) as caught:
            self.snapshots(base_policy="guess_pages")
        self.assertEqual(caught.exception.code, "BASE_POLICY_UNSUPPORTED")

    def test_cancellation_cleans_partial_and_preserves_sources(self):
        before = sha(self.db), sha(self.wal)
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            return calls >= 15
        with self.assertRaises(HistoryError) as caught:
            self.snapshots(cancel=cancel)
        self.assertEqual(caught.exception.code, "CANCELLED")
        self.assertFalse(list(self.output.rglob("*.partial")))
        self.assertEqual((sha(self.db), sha(self.wal)), before)

    def test_immutable_integrity_check_rejects_invalid_structure(self):
        raw = self.wal.read_bytes()
        size = int.from_bytes(raw[8:12], "big")
        records = []
        for at in range(32, len(raw), size + 24):
            number, commit_size = struct.unpack(">2I", raw[at:at + 8])
            payload = bytearray(raw[at + 24:at + 24 + size])
            if number == 2:
                payload[0] = 255  # checksum-valid but invalid btree
            records.append((number, commit_size, bytes(payload)))
        wal = self.base / "bad-structure.wal"
        wal.write_bytes(independent_wal(size, records))
        self.assertEqual(self.snapshots(wal=wal), [])
        self.assertTrue(any(s["reason"] == "snapshot_integrity_invalid" for s in self.report["skipped"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
