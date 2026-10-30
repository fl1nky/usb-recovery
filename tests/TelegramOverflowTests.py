"""Actual deleted SQLite overflow chains; independent SQLite/TL fixtures."""
from pathlib import Path
import hashlib
import json
import sqlite3
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "helpers/recovery_engine"), str(ROOT / "tests")]
import sqlite_deleted
import telegram_auto
import archive_search
import engine
from build_telegram_overflow_fixtures import create


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TelegramOverflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="TelegramOverflow-owned-")
        self.root = Path(self.temp.name)
        self.number = 0

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, **kwargs):
        self.number += 1
        return create(self.root / str(self.number), **kwargs)

    def recover(self, path, **kwargs):
        before = {p: sha(p) for p in (path, Path(str(path) + "-wal")) if p.is_file()}
        report = {}
        rows = sqlite_deleted.recover(path, report=report, **kwargs)
        self.assertEqual(before, {p: sha(p) for p in before})
        return [r for r in rows if r.get("row", {}).get("mid") == 3], report

    def check_ranges(self, path, row):
        chunks, cursor = [], 0
        ranges = row["sqlite_payload_ranges"]
        self.assertLessEqual(len(ranges), 4096)
        for part in ranges:
            self.assertEqual(part["logical_offset"], cursor)
            source = path if part["physical_source"] == "db" else Path(str(path) + "-wal")
            with source.open("rb") as stream:
                stream.seek(part["physical_byte_offset"])
                data = stream.read(part["bytes"])
            self.assertEqual(len(data), part["bytes"])
            chunks.append(data)
            cursor += len(data)
        self.assertEqual(cursor, row["sqlite_payload_length"])
        self.assertEqual(hashlib.sha256(b"".join(chunks)).hexdigest(), row["sqlite_payload_sha256"])
        first = ranges[0]
        self.assertEqual(row["sqlite_record_length"], first["bytes"])
        self.assertEqual(row["sqlite_record_sha256"], hashlib.sha256(chunks[0]).hexdigest())
        self.assertEqual(row["sqlite_overflow_pages"], [p["sqlite_page"] for p in ranges[1:]])
        self.assertTrue(row["sqlite_overflow_chain_verified"])
        self.assertIsNone(row["deleted"])
        self.assertEqual(row["recovery_status"], "deleted_supported_by_evidence")

    def test_real_delete_all_page_sizes_exact_tl_text_and_source_ranges(self):
        for size in (512, 1024, 4096, 65536):
            with self.subTest(page_size=size):
                path, expected = self.fixture(page_size=size)
                rows, report = self.recover(path)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["row"]["data"], expected["blob"])
                self.assertEqual(rows[0]["value"]["text"], expected["text"])
                self.check_ranges(path, rows[0])
                self.assertFalse(report["limited"])

    def test_secure_delete_and_overwritten_first_trunk_do_not_invent_bytes(self):
        for kwargs in ({"secure": True}, {"donor": False}):
            with self.subTest(**kwargs):
                path, _ = self.fixture(**kwargs)
                rows, _ = self.recover(path)
                self.assertEqual(rows, [])

    def test_wal_overlay_ranges_include_actual_db_and_wal_sources(self):
        path, expected = self.fixture(wal=True)
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            rows, _ = self.recover(path, connection=connection)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["row"]["data"], expected["blob"])
            self.check_ranges(path, rows[0])
            self.assertEqual({r["physical_source"] for r in rows[0]["sqlite_payload_ranges"]}, {"db", "wal"})
        finally:
            connection.close()

    def test_broken_cyclic_allocated_and_trunk_pointers_are_rejected(self):
        for mutation in ("zero", "cycle", "allocated", "trunk", "extra_tail", "out_of_bounds"):
            with self.subTest(mutation=mutation):
                path, _ = self.fixture()
                original, _ = self.recover(path)
                row = original[0]
                first = row["sqlite_payload_ranges"][0]
                page_size = 4096
                raw = bytearray(path.read_bytes())
                if mutation == "extra_tail":
                    position = (row["sqlite_overflow_pages"][-1] - 1) * page_size
                    value = row["sqlite_overflow_pages"][0]
                elif mutation == "cycle":
                    position = (row["sqlite_overflow_pages"][0] - 1) * page_size
                    value = row["sqlite_overflow_pages"][0]
                else:
                    position = first["physical_byte_offset"] + first["bytes"]
                    value = {"zero": 0, "allocated": row["sqlite_page"],
                             "trunk": int.from_bytes(raw[32:36], "big"),
                             "out_of_bounds": len(raw) // page_size + 1}[mutation]
                raw[position:position + 4] = struct.pack(">I", value)
                path.write_bytes(raw)
                rows, _ = self.recover(path)
                self.assertEqual(rows, [])

    def test_budget_limit_is_incomplete_and_cancellation_preserves_source(self):
        path, _ = self.fixture()
        for limits in ({"max_scan_bytes": 1000}, {"max_output_bytes": 1000}):
            rows, report = self.recover(path, limits=limits)
            self.assertEqual(rows, [])
            self.assertTrue(report["limited"])
        before = sha(path)
        with self.assertRaisesRegex(sqlite_deleted.DeletedError, "CANCELLED"):
            sqlite_deleted.recover(path, cancel=lambda: True)
        self.assertEqual(sha(path), before)

    def test_valid_modified_text_remains_unauthenticated_source_candidate(self):
        path, expected = self.fixture()
        rows, _ = self.recover(path)
        part = rows[0]["sqlite_payload_ranges"][1]
        raw = bytearray(path.read_bytes())
        start = part["physical_byte_offset"]
        end = start + part["bytes"]
        at = raw.find(b"recipe", start, end)
        self.assertGreaterEqual(at, start)
        raw[at] = ord("R")
        path.write_bytes(raw)
        changed, _ = self.recover(path)
        self.assertEqual(len(changed), 1)
        self.assertNotEqual(changed[0]["row"]["data"], expected["blob"])
        self.assertNotEqual(changed[0]["value"]["text"], expected["text"])
        self.check_ranges(path, changed[0])

    def test_local_import_keyword_search_preserves_complete_overflow_provenance(self):
        path, expected = self.fixture()
        before = sha(path)
        archive = self.root / "archive"
        result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(archive),
            "options": {"roots": [str(path)]}}, engine.Importer, lambda *args, **kwargs: None)
        self.assertIn(result["status"], ("complete", "partial"))
        found = archive_search.search({"protocol": 1, "operation": "search", "archive": str(archive), "app": "Telegram", "query": "recipe 3 яблоки",
            "evidence": "deleted", "offset": 0, "limit": 100})
        self.assertEqual(found["status"], "complete")
        self.assertEqual(found["total"], 1)
        row = found["records"][0]
        self.assertEqual(row["text"], expected["text"])
        self.assertEqual(row["message_id"], 3)
        self.assertEqual(row["recovery_status"], "deleted_supported_by_evidence")
        self.assertIsNone(row["deleted"])
        self.assertTrue(row["sqlite_overflow_chain_verified"])
        self.assertGreater(len(row["sqlite_payload_ranges"]), 1)
        self.assertEqual(sha(path), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
