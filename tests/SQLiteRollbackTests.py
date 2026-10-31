"""Native SQLite before-images plus bounded rollback-reader API checks.

Positive journal bytes come from SQLite's real VFS/COMMIT writer. Expected
database bytes are the independent before-transaction files, not decoder output.
"""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from sqlite_rollback import extract_rollback_journal, iter_validated_pages, RollbackError
from build_telegram_rollback_fixtures import build, OLD


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class SQLiteRollbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix="own-rollback-corpus-")
        cls.addClassCleanup(cls.shared.cleanup)
        cls.fixtures = Path(cls.shared.name) / "fixtures"
        cls.manifest = build(cls.fixtures)
        cls.cases = {case["name"]: case for case in cls.manifest["cases"]}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rollback-reader-test-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "output"
        self.output.mkdir()

    def journal(self, name="full-delete"):
        return self.fixtures / name / "cache4.db-journal"

    def extract(self, name="full-delete", **options):
        return extract_rollback_journal(self.journal(name), self.output, **options)

    def copied_journal(self, name="full-delete"):
        path = Path(self.temporary.name) / "journal-copy"
        shutil.copyfile(self.journal(name), path)
        return path

    def assert_error(self, code, callback):
        with self.assertRaises(RollbackError) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)

    def test_native_full_before_image_is_exact_original_with_old_schema(self):
        original = self.fixtures / "references/full-delete-before.sqlite"
        report = self.extract()
        self.assertEqual(report["status"], "complete")
        self.assertIsNone(report["tail_reason"])
        snapshot = report["snapshot"]
        self.assertIsNotNone(snapshot)
        self.assertEqual(Path(snapshot["path"]).read_bytes(), original.read_bytes())
        self.assertEqual(snapshot["sha256"], self.cases["full-delete"]["before_sha256"])
        with closing(sqlite3.connect(Path(snapshot["path"]).as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertEqual(db.execute("SELECT mid,uid,date FROM messages WHERE mid=21").fetchone()[:2], (21, 77))

    def test_native_standalone_journal_needs_no_current_database(self):
        self.assertFalse((self.fixtures / "full-standalone/cache4.db").exists())
        report = self.extract("full-standalone")
        self.assertEqual(report["snapshot"]["sha256"], self.cases["full-standalone"]["before_sha256"])

    def test_native_partial_delete_and_update_keep_exact_physical_pages(self):
        for name in ("partial-compact-update", "partial-delete", "partial-update", "partial-wide"):
            with self.subTest(case=name):
                report = self.extract(name)
                self.assertIsNone(report["snapshot"])
                self.assertEqual(report["snapshot_skipped_reason"], "initial_pages_missing")
                self.assertEqual(report["initial_pages"], self.cases[name]["initial_pages"])
                rows = list(iter_validated_pages(self.journal(name), report))
                self.assertEqual({item[0]["page"] for item in rows}, set(self.cases[name]["covered_pages"]))
                raw = self.journal(name).read_bytes()
                expected = {item["page"]: item for item in self.cases[name]["journal_records"]}
                for record, data in rows:
                    gold = expected[record["page"]]
                    self.assertEqual(record["data_offset"], gold["data_offset"])
                    self.assertEqual(record["header_offset"], gold["header_offset"])
                    self.assertEqual(data, raw[gold["data_offset"]:gold["data_offset"] + gold["bytes"]])
                    self.assertEqual(record["page_sha256"], gold["sha256"])

    def test_source_and_foreign_current_database_are_untouched(self):
        name = "foreign-paired"
        folder = self.fixtures / name
        before = {path.name: sha(path) for path in folder.iterdir()}
        report = self.extract(name)
        list(iter_validated_pages(self.journal(name), report))
        self.assertIsNone(report["snapshot"])
        self.assertEqual(before, {path.name: sha(path) for path in folder.iterdir()})

    def test_all_original_corpus_bytes_stay_unchanged_after_reading(self):
        for name, case in self.cases.items():
            with self.subTest(case=name):
                self.extract(name)
                for filename, expected in case["source_files"].items():
                    self.assertEqual(sha(self.fixtures / name / filename), expected)

    def test_zero_sentinel_and_persist_never_infer_records_from_eof(self):
        expected = {"zero-count": "zero_record_count", "sentinel-count": "sentinel_record_count",
                    "persist-zero": "zeroed_header"}
        for name, reason in expected.items():
            with self.subTest(case=name):
                report = self.extract(name)
                self.assertEqual(report["status"], "unsupported")
                self.assertEqual(report["tail_reason"], reason)
                self.assertEqual(report["records"], [])
                self.assertIsNone(report["snapshot"])

    def test_invalid_first_magic_and_checksum_publish_no_snapshot(self):
        for name, reason in (("bad-magic", "header_magic"), ("bad-checksum", "page_checksum")):
            with self.subTest(case=name):
                report = self.extract(name)
                self.assertEqual(report["status"], "invalid")
                self.assertEqual(report["tail_reason"], reason)
                self.assertIsNone(report["snapshot"])
                self.assertEqual(list(iter_validated_pages(self.journal(name), report)), [])

    def test_torn_tail_exposes_only_validated_prefix_without_snapshot(self):
        report = self.extract("torn-record")
        self.assertEqual(report["status"], "validated_prefix")
        self.assertEqual(report["tail_reason"], "record_truncated")
        self.assertIsNone(report["snapshot"])
        self.assertEqual(len(list(iter_validated_pages(self.journal("torn-record"), report))), 3)

    def test_super_journal_is_not_followed_and_disables_full_snapshot(self):
        report = self.extract("super-journal")
        self.assertEqual(report["tail_reason"], "super_journal")
        self.assertIsNotNone(report["super_journal"])
        self.assertIsNone(report["snapshot"])
        self.assertEqual(len(list(iter_validated_pages(self.journal("super-journal"), report))), 4)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_report_is_json_safe_and_never_claims_authenticity_or_commit(self):
        report = self.extract()
        json.dumps(report)
        self.assertFalse(report["content_authenticity_verified"])
        self.assertEqual(report["checksum_kind"], "sqlite_sparse_32bit")
        self.assertEqual(report["hot_state"], "unknown")
        self.assertFalse(report["current_state_confirmed"])
        page_map = report["snapshot"]["page_map"]
        self.assertEqual(page_map["journal_sha256"], sha(self.journal()))
        self.assertEqual(page_map["records"], report["records"])
        self.assertNotIn("committed", report)
        self.assertNotIn("deleted", report)

    def test_record_and_header_limits_leave_no_full_snapshot(self):
        for limits, reason, records in (({"max_records": 1}, "record_limit", 1),
                                        ({"max_headers": 1}, "header_limit", 2)):
            with self.subTest(limits=limits):
                report = self.extract(limits=limits)
                self.assertTrue(report["limited"])
                self.assertEqual(report["tail_reason"], reason)
                self.assertEqual(len(report["records"]), records)
                self.assertIsNone(report["snapshot"])
                self.assertEqual(len(list(iter_validated_pages(self.journal(), report))), records)

    def test_output_limit_never_writes_a_partial_or_successful_database(self):
        report = self.extract(limits={"max_output_bytes": 1024})
        self.assertIsNone(report["snapshot"])
        self.assertTrue(report["limited"])
        self.assertEqual(report["snapshot_skipped_reason"], "output_limit")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_input_and_initial_page_limits_are_bounded(self):
        self.assert_error("INPUT_LIMIT", lambda: self.extract(limits={"max_input_bytes": 10}))
        report = self.extract(limits={"max_page_count": 3})
        self.assertTrue(report["limited"])
        self.assertEqual(report["tail_reason"], "initial_pages_bounds")
        self.assertEqual(report["records"], [])

    def test_invalid_limits_reject_bool_unknown_and_unbounded_values(self):
        for limits in ({"max_records": True}, {"unknown": 1}, {"max_records": 65537},
                       {"max_headers": 0}, "wrong"):
            with self.subTest(limits=limits):
                self.assert_error("INVALID_LIMITS", lambda: self.extract(limits=limits))

    def test_cancel_before_access_and_during_snapshot_leaves_no_partial(self):
        self.assert_error("CANCELLED", lambda: self.extract(cancel=lambda: True))
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            return calls == 12
        self.assert_error("CANCELLED", lambda: self.extract(cancel=cancel))
        self.assertFalse(list(self.output.rglob("*.partial")))
        self.assertFalse(list(self.output.rglob("*.sqlite")))

    def test_iterator_rejects_changed_source_before_first_yield(self):
        path = self.copied_journal()
        report = extract_rollback_journal(path, self.output)
        data = bytearray(path.read_bytes()); data[600] ^= 1; path.write_bytes(data)
        self.assert_error("SOURCE_CHANGED", lambda: next(iter_validated_pages(path, report)))

    def test_iterator_final_hash_detects_changes_to_already_yielded_page(self):
        path = self.copied_journal()
        report = extract_rollback_journal(path, self.output)
        iterator = iter_validated_pages(path, report)
        next(iterator)
        data = bytearray(path.read_bytes()); data[600] ^= 1; path.write_bytes(data)
        self.assert_error("SOURCE_CHANGED", lambda: list(iterator))

    def test_iterator_rejects_tampered_physical_provenance_before_yield(self):
        report = self.extract()
        report["records"][0]["data_offset"] += 1
        self.assert_error("REPORT_INVALID", lambda: next(iter_validated_pages(self.journal(), report)))

    def test_raised_cancellation_after_snapshot_rename_removes_private_result(self):
        def cancel():
            if list(self.output.rglob("before-image.sqlite")):
                raise RuntimeError("OWN_CALLBACK_CANCELLATION")
            return False
        with self.assertRaisesRegex(RuntimeError, "OWN_CALLBACK_CANCELLATION"):
            self.extract(cancel=cancel)
        self.assertFalse(list(self.output.rglob("*.sqlite")))
        self.assertFalse(list(self.output.rglob("*.partial")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
