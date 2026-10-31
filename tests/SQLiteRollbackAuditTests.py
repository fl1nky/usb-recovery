"""Independent native-journal mutation and Telegram attribution audit.

Positive journals are emitted by the own SQLite VFS fixture writer. Mutations
below are negative/control cases, never a way to fabricate a positive journal.
No production parser helper is used to calculate expected page checksums/maps.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "helpers" / "recovery_engine"))

from build_telegram_rollback_fixtures import build, OLD
from sqlite_rollback import extract_rollback_journal, iter_validated_pages, RollbackError

MAGIC = bytes.fromhex("d9d505f920a163d7")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def native_records(raw):
    """Independent byte oracle for finite native segments, not recovery code."""
    offset = 0
    records = []
    geometry = None
    while offset + 28 <= len(raw) and raw[offset:offset + 8] == MAGIC:
        count, nonce, total, sector, page = struct.unpack_from(">5I", raw, offset + 8)
        if not 0 < count < 0xffffffff:
            break
        assert geometry in (None, (total, sector, page))
        geometry = total, sector, page
        cursor = offset + sector
        for _ in range(count):
            number = struct.unpack_from(">I", raw, cursor)[0]
            data = raw[cursor + 4:cursor + 4 + page]
            checksum = struct.unpack_from(">I", raw, cursor + 4 + page)[0]
            assert len(data) == page
            expected = nonce
            index = page - 200
            while index > 0:
                expected = (expected + data[index]) & 0xffffffff
                index -= 200
            assert checksum == expected
            records.append({"page": number, "record_offset": cursor,
                "data_offset": cursor + 4, "checksum_offset": cursor + 4 + page,
                "header_offset": offset, "nonce": nonce, "data": data})
            cursor += page + 8
        offset = (cursor + sector - 1) // sector * sector
    return geometry, records


def replace_page_control(raw, record, page):
    """Mutate a negative/control page, retaining its native segment framing."""
    changed = bytearray(raw)
    changed[record["data_offset"]:record["data_offset"] + len(page)] = page
    checksum = record["nonce"]
    for index in range(len(page) - 200, 0, -200):
        checksum = (checksum + page[index]) & 0xffffffff
    struct.pack_into(">I", changed, record["checksum_offset"], checksum)
    return changed


class SQLiteRollbackAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="own-rollback-audit-")
        cls.base = Path(cls.temporary.name)
        cls.fixtures = cls.base / "fixtures"
        cls.manifest = build(cls.fixtures)
        cls.cases = {case["name"]: case for case in cls.manifest["cases"]}
        cls.overflow_fixtures = cls.base / "overflow-fixtures"
        cls.overflow_manifest = build(cls.overflow_fixtures, overflow=True)
        cls.overflow_cases = {case["name"]: case for case in cls.overflow_manifest["cases"]}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.job = Path(tempfile.mkdtemp(prefix="job-", dir=self.base))
        self.output = self.job / "work"
        self.output.mkdir()

    def journal(self, case="full-delete"):
        return self.fixtures / case / "cache4.db-journal"

    def changed(self, raw, name="changed-journal"):
        path = self.job / name
        path.write_bytes(raw)
        return path

    def extract(self, path=None, **kwargs):
        return extract_rollback_journal(path or self.journal(), self.output, **kwargs)

    def assert_no_snapshot(self, report):
        self.assertIsNone(report.get("snapshot"))
        self.assertNotEqual(report.get("status"), "complete_snapshot")

    def test_native_complete_before_image_and_physical_record_oracle(self):
        journal = self.journal()
        original = journal.read_bytes()
        geometry, records = native_records(original)
        report = self.extract(journal)
        self.assertIsNotNone(report["snapshot"])
        expected = (self.fixtures / "references/full-delete-before.sqlite").read_bytes()
        self.assertEqual(Path(report["snapshot"]["path"]).read_bytes(), expected)
        self.assertEqual(report["journal_sha256"], sha(original))
        self.assertEqual((report["initial_pages"], report["page_size"]), (geometry[0], geometry[2]))
        self.assertEqual(len(report["records"]), len(records))
        observed = list(iter_validated_pages(journal, report))
        self.assertEqual(len(observed), len(records))
        for (metadata, payload), oracle in zip(observed, records):
            for field in ("page", "record_offset", "data_offset", "checksum_offset", "header_offset", "nonce"):
                self.assertEqual(metadata[field], oracle[field], field)
            self.assertEqual(metadata["page_sha256"], sha(oracle["data"]))
            self.assertEqual(payload, oracle["data"])
        self.assertEqual(journal.read_bytes(), original)

    def test_normal_partial_update_does_not_fill_missing_present_database_pages(self):
        journal = self.journal("partial-compact-update")
        report = self.extract(journal)
        self.assert_no_snapshot(report)
        self.assertLess(len(report["records"]), report["initial_pages"])
        fragments = [page for _, page in iter_validated_pages(journal, report)]
        self.assertGreater(len(fragments), 0)
        self.assertTrue(any(OLD.encode("utf-8") in page for page in fragments))

    def test_bad_initial_count_never_uses_eof_as_positive_record_count(self):
        original = self.journal().read_bytes()
        for count in (0, 0xffffffff):
            with self.subTest(count=count):
                raw = original[:8] + struct.pack(">I", count) + original[12:]
                report = self.extract(self.changed(raw, "count-" + str(count)))
                self.assert_no_snapshot(report)
                self.assertEqual(report.get("records"), [])
                self.assertIsNotNone(report.get("tail_reason"))

    def test_real_zeroed_persist_header_is_not_recovered_as_valid_journal(self):
        journal = self.journal("persist-zero")
        self.assertEqual(journal.read_bytes()[:28], bytes(28))
        report = self.extract(journal)
        self.assert_no_snapshot(report)
        self.assertEqual(report.get("records"), [])

    def test_repeated_page_number_not_silently_deduplicated(self):
        original = bytearray(self.journal().read_bytes())
        _, records = native_records(original)
        first, second = records[:2]
        struct.pack_into(">I", original, second["record_offset"], first["page"])
        report = self.extract(self.changed(original, "duplicate-page"))
        self.assert_no_snapshot(report)
        self.assertIsNotNone(report.get("tail_reason"))

    def test_identical_duplicate_before_image_is_still_not_complete_history(self):
        original = bytearray(self.journal().read_bytes())
        _, records = native_records(original)
        first, second = records[:2]
        page = len(first["data"])
        struct.pack_into(">I", original, second["record_offset"], first["page"])
        original[second["data_offset"]:second["data_offset"] + page] = first["data"]
        checksum = second["nonce"]
        for index in range(page - 200, 0, -200):
            checksum = (checksum + first["data"][index]) & 0xffffffff
        struct.pack_into(">I", original, second["checksum_offset"], checksum)
        report = self.extract(self.changed(original, "identical-duplicate"))
        self.assert_no_snapshot(report)
        self.assertIsNotNone(report.get("tail_reason"))

    def test_invalid_tail_after_all_original_pages_never_publishes_snapshot(self):
        original = self.journal().read_bytes()
        _, records = native_records(original)
        geometry, _ = native_records(original)
        sector = geometry[1]
        end = records[-1]["checksum_offset"] + 4
        aligned = (end + sector - 1) // sector * sector
        # A complete-looking native prefix cannot vouch for a following segment.
        changed = original[:end] + bytes(aligned - end) + b"BROKEN!!" + bytes(20)
        report = self.extract(self.changed(changed, "bad-trailing-header"))
        self.assert_no_snapshot(report)
        self.assertEqual(len(report["records"]), len(records))
        self.assertIsNotNone(report.get("tail_reason"))

    def test_changed_geometry_in_second_native_header_is_not_a_single_snapshot(self):
        original = bytearray(self.journal().read_bytes())
        _, records = native_records(original)
        headers = sorted({record["header_offset"] for record in records})
        self.assertGreaterEqual(len(headers), 2)
        offset = headers[1]
        struct.pack_into(">I", original, offset + 16, 5)
        report = self.extract(self.changed(original, "geometry-change"))
        self.assert_no_snapshot(report)
        self.assertIsNotNone(report.get("tail_reason"))

    def test_page_size_and_sector_geometry_are_bounded_without_allocation(self):
        original = self.journal().read_bytes()
        for offset, value in ((20, 0), (20, 31), (20, 65537), (20, 0x80000000),
                              (24, 0), (24, 511), (24, 513), (24, 0x80000000)):
            with self.subTest(offset=offset, value=value):
                raw = original[:offset] + struct.pack(">I", value) + original[offset + 4:]
                report = self.extract(self.changed(raw, "geometry-" + str(offset) + "-" + str(value)))
                self.assert_no_snapshot(report)
                self.assertEqual(report.get("records"), [])

    def test_missing_page_one_cannot_borrow_schema_from_adjacent_main_database(self):
        original = bytearray(self.journal().read_bytes())
        _, records = native_records(original)
        page_one = next(record for record in records if record["page"] == 1)
        # Page numbers/counts are outside the checksum. Keep the resulting
        # geometry internally consistent while leaving page one unavailable.
        for offset in {record["header_offset"] for record in records}:
            struct.pack_into(">I", original, offset + 16, 5)
        struct.pack_into(">I", original, page_one["record_offset"], 5)
        report = self.extract(self.changed(original, "missing-page-one"))
        self.assert_no_snapshot(report)
        self.assertEqual(len(report["records"]), len(records))
        self.assertIsNone(report.get("tail_reason"))

    def test_sparse_checksum_does_not_claim_content_authenticity(self):
        original = bytearray(self.journal().read_bytes())
        _, records = native_records(original)
        page_one = next(record for record in records if record["page"] == 1)
        # user_version offset60 is not one of the 512-byte sparse samples.
        original[page_one["data_offset"] + 60] ^= 1
        _, mutated_records = native_records(original)
        self.assertEqual(len(mutated_records), len(records))
        report = self.extract(self.changed(original, "unsampled-mutation"))
        self.assertIsNotNone(report["snapshot"])
        self.assertFalse(report["content_authenticity_verified"])
        self.assertEqual(report["hot_state"], "unknown")
        before = (self.fixtures / "references/full-delete-before.sqlite").read_bytes()
        self.assertNotEqual(Path(report["snapshot"]["path"]).read_bytes(), before)

    def test_sampled_payload_mutation_invalidates_page_checksum(self):
        original = bytearray(self.journal().read_bytes())
        geometry, records = native_records(original)
        original[records[0]["data_offset"] + geometry[2] - 200] ^= 1
        report = self.extract(self.changed(original, "sampled-mutation"))
        self.assert_no_snapshot(report)
        self.assertEqual(report.get("records"), [])

    def test_super_journal_is_unsupported_and_never_followed(self):
        journal = self.journal("super-journal")
        before = journal.read_bytes()
        report = self.extract(journal)
        self.assert_no_snapshot(report)
        self.assertIn(report.get("status"), ("unsupported", "validated_prefix"))
        self.assertIn("super", report.get("tail_reason", ""))
        self.assertEqual(journal.read_bytes(), before)

    def test_iterator_rejects_source_changed_after_report(self):
        journal = self.changed(self.journal().read_bytes(), "changed-after-parse")
        report = self.extract(journal)
        original = bytearray(journal.read_bytes())
        original[12] ^= 1
        journal.write_bytes(original)
        with self.assertRaises(RollbackError):
            list(iter_validated_pages(journal, report))

    def test_iterator_rejects_forged_physical_offset_or_page_hash(self):
        journal = self.journal()
        report = self.extract(journal)
        for field, value in (("data_offset", 0), ("page_sha256", "0" * 64)):
            with self.subTest(field=field):
                forged = json.loads(json.dumps(report))
                forged["records"][0][field] = value
                with self.assertRaises(RollbackError):
                    list(iter_validated_pages(journal, forged))

    def test_iterator_rejects_tampered_authenticity_or_hot_state(self):
        journal = self.journal()
        report = self.extract(journal)
        for field, value in (("content_authenticity_verified", True), ("hot_state", "confirmed"),
                              ("current_state_confirmed", True), ("checksum_kind", "sha256_authenticated")):
            with self.subTest(field=field):
                forged = json.loads(json.dumps(report))
                forged[field] = value
                with self.assertRaises(RollbackError):
                    list(iter_validated_pages(journal, forged))

    def test_iterator_final_source_check_is_required_after_first_yield(self):
        journal = self.changed(self.journal().read_bytes(), "source-changes-mid-iteration")
        report = self.extract(journal)
        iterator = iter_validated_pages(journal, report)
        next(iterator)
        previous = journal.stat()
        os.utime(journal, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1000000))
        with self.assertRaises(RollbackError) as caught:
            list(iterator)
        self.assertEqual(caught.exception.code, "SOURCE_CHANGED")

    def test_cancelled_operation_never_publishes_snapshot(self):
        with self.assertRaises(RollbackError) as caught:
            self.extract(cancel=lambda: True)
        self.assertEqual(caught.exception.code, "CANCELLED")
        self.assertEqual(list(self.output.rglob("*.sqlite")), [])

    def test_native_overflow_payload_reconstruction_maps_only_journal_owned_bytes(self):
        from sqlite_rollback_records import recover_fragments
        for case in ("partial-overflow-delete", "partial-overflow-update"):
            with self.subTest(case=case):
                journal = self.overflow_fixtures / case / "cache4.db-journal"
                before = journal.read_bytes()
                parsed = self.extract(journal)
                self.assert_no_snapshot(parsed)
                fragments = recover_fragments(journal, parsed)
                target = self.overflow_cases[case]["expected_text"]
                self.assertGreater(len(target.encode("utf-8")), parsed["page_size"])
                hits = [row for row in fragments if row["text"] == target]
                self.assertEqual(len(hits), 1)
                row = hits[0]
                for field in ("chat_id", "message_id", "sender_id", "timestamp", "deleted"):
                    self.assertIsNone(row.get(field), field)
                self.assertTrue(row["rollback_payload_chain_verified"])
                ranges = row["rollback_payload_ranges"]
                self.assertGreater(len(ranges), 1)
                oracle = {record["page"]: record for record in parsed["records"]}
                payload = bytearray()
                for item in ranges:
                    self.assertEqual(item["logical_offset"], len(payload))
                    self.assertEqual(item["physical_source"], "rollback_journal")
                    page_record = oracle[item["sqlite_page"]]
                    start = item["physical_byte_offset"]
                    self.assertGreaterEqual(start, page_record["data_offset"])
                    self.assertLessEqual(start + item["bytes"], page_record["data_offset"] + parsed["page_size"])
                    payload.extend(before[start:start + item["bytes"]])
                self.assertEqual(sha(payload), row["rollback_payload_sha256"])
                self.assertEqual(len(payload), row["rollback_payload_length"])
                reference = self.overflow_fixtures / "references" / (case + "-before.sqlite")
                connection = sqlite3.connect(reference.as_uri() + "?mode=ro&immutable=1", uri=True)
                try:
                    blob = connection.execute("SELECT data FROM messages WHERE mid=21").fetchone()[0]
                finally:
                    connection.close()
                self.assertIn(blob, payload)
                self.assertEqual(sha(blob), self.overflow_cases[case]["expected_blob_sha256"])
                self.assertEqual(journal.read_bytes(), before)

    def test_partial_overflow_missing_page_one_cannot_guess_reserved_byte_geometry(self):
        from sqlite_rollback_records import recover_fragments
        case = "partial-overflow-delete"
        journal = self.overflow_fixtures / case / "cache4.db-journal"
        raw = bytearray(journal.read_bytes())
        geometry, records = native_records(raw)
        one = next(record for record in records if record["page"] == 1)
        # Move that record to another unused, in-range page number. Sparse
        # checksums remain valid, but the old database header is unavailable.
        occupied = {record["page"] for record in records}
        replacement = next(page for page in range(2, geometry[0] + 1) if page not in occupied)
        struct.pack_into(">I", raw, one["record_offset"], replacement)
        supplied = self.changed(raw, "overflow-without-page-one")
        parsed = self.extract(supplied)
        self.assert_no_snapshot(parsed)
        values = recover_fragments(supplied, parsed)
        self.assertFalse(any(value["text"] == self.overflow_cases[case]["expected_text"] for value in values))

    def test_partial_overflow_missing_chain_page_is_not_filled_from_current_database(self):
        from sqlite_rollback_records import recover_fragments
        case = "partial-overflow-delete"
        journal = self.overflow_fixtures / case / "cache4.db-journal"
        raw = bytearray(journal.read_bytes())
        geometry, records = native_records(raw)
        # Omit an actual overflow page by moving its record to a new number.
        # The neighbouring current DB still has that page; it is not input.
        occupied = {record["page"] for record in records}
        chain = next(record for record in records if record["page"] == 5)
        replacement = next(page for page in range(2, geometry[0] + 1) if page not in occupied)
        struct.pack_into(">I", raw, chain["record_offset"], replacement)
        supplied = self.changed(raw, "overflow-missing-chain-page")
        parsed = self.extract(supplied)
        self.assert_no_snapshot(parsed)
        values = recover_fragments(supplied, parsed)
        self.assertFalse(any(value["text"] == self.overflow_cases[case]["expected_text"] for value in values))

    def test_structurally_invalid_leaf_does_not_get_verified_overflow_claim(self):
        from sqlite_rollback_records import recover_fragments
        case = "partial-overflow-delete"
        raw = (self.overflow_fixtures / case / "cache4.db-journal").read_bytes()
        _, records = native_records(raw)
        # The independently checked fixture has its target on leaf21 and its
        # overflow on pages3..20. These are native writer outputs, not a parser
        # guess. Its TL constructor prefix is visible on the leaf's local part.
        leaf = next(record for record in records if record["page"] == 21)
        data = leaf["data"]
        self.assertEqual(data[0], 13)
        target = self.overflow_cases[case]["expected_text"]
        reference = self.overflow_fixtures / "references" / (case + "-before.sqlite")
        connection = sqlite3.connect(reference.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            blob = connection.execute("SELECT data FROM messages WHERE mid=21").fetchone()[0]
        finally:
            connection.close()
        tl_start = data.find(blob[:16])
        self.assertGreaterEqual(tl_start, 8)
        mutations = []
        content = bytearray(data)
        content[5:7] = struct.pack(">H", len(data) + 1)
        mutations.append(("content_start_outside_page", content))
        fragments = bytearray(data)
        fragments[7] = 61
        mutations.append(("fragment_byte_count_outside_sqlite_limit", fragments))
        freeblock = bytearray(data)
        # Change only the candidate TL id, leaving the target text and all
        # overflow bytes intact. A well-formed freeblock now overlaps this cell.
        free_start = tl_start + 8
        freeblock[1:3] = struct.pack(">H", free_start)
        freeblock[free_start:free_start + 4] = b"\0\0\0\x04"
        mutations.append(("freeblock_overlaps_live_cell", freeblock))
        for name, page in mutations:
            with self.subTest(name=name):
                supplied = self.changed(replace_page_control(raw, leaf, page), name)
                parsed = self.extract(supplied)
                self.assert_no_snapshot(parsed)
                self.assertIsNone(parsed.get("tail_reason"))
                rows = recover_fragments(supplied, parsed)
                self.assertFalse(any(row["text"] == target and row.get("rollback_payload_chain_verified") for row in rows))
                # Ordinary raw TL fragments are still permitted: they do not
                # claim that the malformed SQLite cell/pointer chain is valid.
                for row in rows:
                    self.assertIsNone(row.get("chat_id"))
                    self.assertIsNone(row.get("message_id"))

    def test_constructor_budget_applies_even_when_query_matches_no_text(self):
        import sqlite_rollback_records
        journal = self.journal()
        raw = journal.read_bytes()
        _, records = native_records(raw)
        constructor = bytes.fromhex("650e2c45")
        self.assertGreaterEqual(sum(record["data"].count(constructor) for record in records), 2)
        parsed = self.extract(journal)
        report = {}
        with patch("sqlite_rollback_records.parse_message", wraps=sqlite_rollback_records.parse_message) as decoder:
            rows = sqlite_rollback_records.recover_fragments(journal, parsed, matcher=lambda text: False,
                limits={"max_candidates": 1}, report=report)
        self.assertEqual(rows, [])
        self.assertEqual(decoder.call_count, 1)
        self.assertEqual(report["candidates_checked"], 1)
        self.assertTrue(report["limited"])
        self.assertEqual(journal.read_bytes(), raw)

    def analyze(self, case, fixture_root=None, as_directory=False, explicit_dump=False, **options):
        import engine
        import telegram_auto
        source = (fixture_root or self.fixtures) / case / ("cache4.db-journal" if case == "full-standalone" else "cache4.db")
        source_root = source.parent
        before = {str(path.relative_to(source_root)): sha(path.read_bytes()) for path in source_root.rglob("*") if path.is_file()}
        if explicit_dump:
            source = source_root / "cache4.db-journal"
        if as_directory:
            source = source_root
        selected = {"path": str(source), "kind": "dump"} if explicit_dump else str(source)
        output = self.job / "archive"
        with patch("engine.emit"):
            telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze",
                "destination": str(output), "options": {"roots": [selected],
                    "scan_fragments": True, **options}}, engine.Importer, lambda *args, **kwargs: None)
        self.assertEqual(before, {str(path.relative_to(source_root)): sha(path.read_bytes()) for path in source_root.rglob("*") if path.is_file()})
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        return output, rows

    def test_partial_delete_update_and_wide_schema_are_useful_unattributed_text(self):
        for case in ("partial-delete", "partial-update", "partial-compact-update", "partial-wide", "foreign-paired"):
            with self.subTest(case=case):
                self.job = Path(tempfile.mkdtemp(prefix="integration-", dir=self.base))
                _, rows = self.analyze(case)
                journal_hash = sha(self.journal(case).read_bytes())
                hits = [row for row in rows if row["text"] == OLD and row.get("rollback_journal_sha256") == journal_hash]
                self.assertGreaterEqual(len(hits), 1)
                for row in hits:
                    self.assertEqual(row["evidence_kind"], "fragment")
                    for field in ("chat_id", "message_id", "sender_id", "timestamp", "deleted"):
                        self.assertIsNone(row.get(field), field)
                    self.assertTrue(str(row["source_file"]).endswith("cache4.db-journal"))
                    self.assertEqual(row["rollback_hot_state"], "unknown")
                    self.assertFalse(row["rollback_current_state_confirmed"])
                    self.assertFalse(row["rollback_content_authenticity_verified"])
                    self.assertIsNone(row.get("wal_commit_frame"))

    def test_complete_journal_keeps_independent_snapshot_and_qualified_chat_links(self):
        for case in ("full-delete", "full-standalone"):
            with self.subTest(case=case):
                self.job = Path(tempfile.mkdtemp(prefix="integration-full-", dir=self.base))
                _, rows = self.analyze(case)
                hits = [row for row in rows if row["text"] == OLD and row.get("rollback_snapshot_sha256")]
                self.assertEqual(len(hits), 1)
                row = hits[0]
                self.assertEqual(row["chat_id"], 77)
                self.assertEqual(row["message_id"], 21)
                self.assertIsNone(row.get("deleted"))
                self.assertEqual(row["rollback_hot_state"], "unknown")
                self.assertFalse(row["rollback_current_state_confirmed"])
                self.assertFalse(row["rollback_content_authenticity_verified"])
                self.assertEqual(row["rollback_snapshot_sha256"], self.cases[case]["before_sha256"])
                self.assertTrue(str(row["source_file"]).endswith("cache4.db-journal"))

    def test_recursive_folder_analysis_does_not_duplicate_database_sidecar_findings(self):
        for case in ("full-delete", "partial-delete", "foreign-paired"):
            with self.subTest(case=case):
                self.job = Path(tempfile.mkdtemp(prefix="recursive-", dir=self.base))
                _, rows = self.analyze(case, as_directory=True)
                journal_hash = sha(self.journal(case).read_bytes())
                hits = [row for row in rows if row["text"] == OLD and row.get("rollback_journal_sha256") == journal_hash]
                self.assertEqual(len(hits), 1)
                if case != "full-delete":
                    self.assertIsNone(hits[0].get("message_id"))
                    self.assertIsNone(hits[0].get("chat_id"))

    def test_explicit_dump_keeps_zero_sentinel_and_persist_text_generic(self):
        for case in ("zero-count", "sentinel-count", "persist-zero"):
            with self.subTest(case=case):
                self.job = Path(tempfile.mkdtemp(prefix="explicit-dump-", dir=self.base))
                _, rows = self.analyze(case, explicit_dump=True)
                hits = [row for row in rows if row["text"] == OLD]
                self.assertTrue(hits)
                for row in hits:
                    self.assertEqual(row["evidence_kind"], "fragment")
                    self.assertEqual(row["record_kind"], "typed_tl_fragment")
                    for field in ("chat_id", "message_id", "sender_id", "timestamp", "deleted",
                                  "rollback_proof", "rollback_journal_sha256", "rollback_snapshot_sha256", "rollback_page_map"):
                        self.assertIsNone(row.get(field), field)
                    self.assertTrue(str(row["source_file"]).endswith("cache4.db-journal"))

    def test_partial_text_keyword_and_regex_search_keep_unknown_identity(self):
        import archive_search
        output, rows = self.analyze("partial-wide")
        hits = [row for row in rows if row["text"] == OLD and row.get("rollback_journal_sha256")]
        self.assertTrue(hits)
        before = {path.name: sha(path.read_bytes()) for path in output.iterdir() if path.is_file()}
        for mode, query in (("literal", "рецепт масла"), ("regex", r"рецепт[\s\S]*две ложки")):
            with self.subTest(mode=mode):
                result = archive_search.search({"protocol": 1, "operation": "search",
                    "archive": str(output), "app": "Telegram", "query": query,
                    "query_mode": mode, "evidence": "fragment", "offset": 0, "limit": 100})
                found = [row for row in result["records"] if row["text"] == OLD]
                self.assertTrue(found)
                self.assertIsNone(found[0].get("chat_id"))
                self.assertIsNone(found[0].get("message_id"))
                self.assertEqual(found[0]["rollback_hot_state"], "unknown")
                self.assertFalse(found[0]["rollback_content_authenticity_verified"])
        self.assertEqual(before, {path.name: sha(path.read_bytes()) for path in output.iterdir() if path.is_file()})

    def test_real_multi_page_partial_text_is_searchable_without_identity_inference(self):
        import archive_search
        output, rows = self.analyze("partial-overflow-delete", fixture_root=self.overflow_fixtures)
        target = self.overflow_cases["partial-overflow-delete"]["expected_text"]
        hits = [row for row in rows if row["text"] == target and row.get("rollback_payload_chain_verified")]
        self.assertEqual(len(hits), 1)
        self.assertIsNone(hits[0].get("chat_id"))
        self.assertIsNone(hits[0].get("message_id"))
        for mode, query in (("literal", "προτυπο"), ("regex", "προτυπο.*🙂")):
            result = archive_search.search({"protocol": 1, "operation": "search", "archive": str(output),
                "app": "Telegram", "evidence": "fragment", "query": query, "query_mode": mode,
                "offset": 0, "limit": 100})
            self.assertTrue(any(row["text"] == target for row in result["records"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
