"""Source-only checks on independent owned SQL/WAL and official TL232 rows."""
from pathlib import Path
import json
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
import engine
import archive_search
import telegram_auto
import telegram_media_cache
from build_telegram_media_cache_fixtures import create, inventory, message, TEXT, DATE, SCHEMA


class TelegramMediaCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="owned-telegram-media-cache-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.counter = 0

    def analyze(self, variant="current", root=None, **options):
        self.counter += 1
        source, golden = create(self.root / ("input-" + str(self.counter)), variant)
        if root is not None:
            source = root
        before = inventory(source.parent)
        output = self.root / ("output-" + str(self.counter))
        with patch("engine.emit"):
            summary = telegram_auto.analyze(
                dict(protocol=1, operation="telegram_analyze", destination=str(output),
                     options=dict(roots=[str(source)], **options)),
                engine.Importer, lambda *a, **k: None)
        self.assertEqual(before, inventory(source.parent), "Every supplied DB/WAL/SHM/golden byte stays unchanged")
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        return output, summary, rows, golden

    def test_current_unicode_caption_and_missing_media(self):
        output, summary, rows, golden = self.analyze()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["text"], row["chat_id"], row["message_id"], row["sender_id"]),
                         (TEXT, 77, 41, "user:77"))
        self.assertEqual(row["record_kind"], "telegram_media_cache")
        self.assertEqual(row["recovery_status"], "current_cache_record")
        self.assertEqual(row["deletion_interpretation"], "unknown")
        self.assertIsNone(row["deleted"])
        self.assertEqual(row["native_layer"], 232)
        self.assertEqual(row["media_status"], "photo_reference_only")
        self.assertEqual(row["attachments"], [])
        self.assertEqual(summary["media"], 0)
        self.assertEqual(summary["native_records"], 1)
        self.assertEqual(summary["deleted_supported_records"], 0)
        self.assertTrue(row["application_confirmed"])
        self.assertIn("type=0", row["source_record"])
        self.assertEqual(golden["secure_delete"], 1)
        normalized = archive_search._normalized(row)
        self.assertEqual(normalized["record_kind"], row["record_kind"])
        self.assertEqual(normalized["recovery_status"], row["recovery_status"])
        self.assertIsNone(normalized["deleted"])
        self.assertEqual(normalized["text"], TEXT)

    def test_committed_wal_before_image_with_secure_delete_on(self):
        output, summary, rows, golden = self.analyze("history")
        self.assertEqual(golden["current_cache_rows"], 0)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["text"], TEXT)
        self.assertEqual(row["record_kind"], "telegram_media_cache")
        self.assertEqual(row["evidence_kind"], "previous")
        self.assertEqual(row["recovery_status"], "historical_cache_record")
        self.assertIsNone(row["deleted"])
        self.assertEqual(row["deletion_interpretation"], "unknown")
        self.assertGreater(row["wal_commit_frame"], 0)
        self.assertEqual(row["wal_proof"], "all_pages_from_validated_wal")
        self.assertEqual(len(row["wal_snapshot_sha256"]), 64)
        self.assertEqual(summary["deleted_supported_records"], 0)

    def test_missing_preimage_does_not_invent_cache_history(self):
        _, summary, rows, _ = self.analyze("missing-preimage")
        self.assertEqual(rows, [])
        self.assertIn("TELEGRAM_WAL_HISTORY_INCOMPLETE", summary["warnings"])

    def test_corrupt_wal_has_no_typed_cache_recovery(self):
        _, summary, rows, _ = self.analyze("corrupt-wal")
        self.assertEqual(rows, [])
        self.assertTrue(any("WAL" in warning for warning in summary["warnings"]))

    def test_wrong_schemas_rows_media_and_unknown_fields_fail_closed(self):
        for variant in ("wrong-schema", "wrong-type", "mid-mismatch",
                        "uid-mismatch", "date-mismatch", "unknown-flags",
                        "missing-media", "secret-uid"):
            with self.subTest(variant=variant):
                _, summary, rows, _ = self.analyze(variant, scan_fragments=False)
                self.assertEqual(rows, [])
                self.assertEqual(summary["native_records"], 0)
                self.assertIn("TELEGRAM_SQLITE_SCHEMA_UNSUPPORTED", summary["warnings"])

    def test_primary_current_keeps_stronger_proof_and_cache_origin(self):
        _, summary, rows, _ = self.analyze("primary-current")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["record_kind"], "tl_message")
        self.assertNotIn("recovery_status", row)
        self.assertEqual(row["evidence_kind"], "backup")
        self.assertEqual(row["text"], TEXT)
        self.assertTrue(any("media_v4" in x["source_record"] for x in row["additional_sources"]))
        self.assertEqual(summary["native_records"], 1)

    def test_historical_primary_promotes_weaker_current_cache(self):
        _, _, rows, _ = self.analyze("primary-historical")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["record_kind"], "tl_message")
        self.assertEqual(row["evidence_kind"], "previous")
        self.assertTrue(any("media_v4" in x["source_record"] for x in row["additional_sources"]))
        self.assertNotIn("recovery_status", row)

    def test_ids_alone_never_replace_different_primary_content(self):
        _, _, rows, _ = self.analyze("primary-different")
        self.assertEqual(len(rows), 2)
        self.assertEqual({x["record_kind"] for x in rows}, {"tl_message", "telegram_media_cache"})
        self.assertEqual({x["text"] for x in rows}, {TEXT, "Другая версия"})

    def test_wrong_database_never_activates_raw_fragment_inference(self):
        _, summary, rows, _ = self.analyze(
            "wrong-schema", scan_fragments=True, fragment_query="Рецепт")
        self.assertEqual(rows, [])
        self.assertEqual(summary["fragment_records"], 0)
        self.assertEqual(summary["native_records"], 0)

    def test_unknown_sender_is_not_invented_from_sql_dialog(self):
        con = sqlite3.connect(":memory:")
        self.addCleanup(con.close)
        con.execute("CREATE TABLE media_v4(" + SCHEMA + ")")
        con.execute("INSERT INTO media_v4 VALUES(?,?,?,?,?)",
                    (41, 909, DATE, 0, message(sender=None)))
        rows = list(telegram_media_cache.photo_captions(con, max_rows=1))
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["value"]["from_peer"])

    def test_extra_generated_columns_and_rowid_alias_schema_rejected(self):
        for schema in (
                SCHEMA.replace(",PRIMARY KEY", ",extra TEXT,PRIMARY KEY"),
                SCHEMA.replace("mid INTEGER", "mid INTEGER PRIMARY KEY").replace(
                    ",PRIMARY KEY(mid,uid,type)", ""),
                SCHEMA.replace(",PRIMARY KEY",
                    ",extra TEXT GENERATED ALWAYS AS (uid),PRIMARY KEY")):
            with self.subTest(schema=schema):
                con = sqlite3.connect(":memory:")
                try:
                    con.execute("CREATE TABLE media_v4(" + schema + ")")
                    self.assertFalse(telegram_media_cache.supported_schema(con))
                finally:
                    con.close()

    def test_exact_schema_composite_type_key_and_row_budget(self):
        con = sqlite3.connect(":memory:")
        self.addCleanup(con.close)
        con.execute("CREATE TABLE media_v4(" + SCHEMA + ")")
        for mid in range(1, 5):
            con.execute("INSERT INTO media_v4 VALUES(?,?,?,?,?)",
                        (mid, 77, DATE, 0, message(mid=mid)))
        con.execute("INSERT INTO media_v4 VALUES(?,?,?,?,?)", (1, 77, DATE, 1, message(mid=1)))
        report = {}
        rows = list(telegram_media_cache.photo_captions(con, max_rows=2, report=report))
        self.assertEqual(len(rows), 2)
        self.assertTrue(report["limited"])
        self.assertEqual(report["checked"], 2)
        self.assertTrue(telegram_media_cache.supported_schema(con))
        with self.assertRaises(telegram_media_cache.MediaCacheError):
            list(telegram_media_cache.photo_captions(con, max_rows=5, cancel=lambda: True))

    def test_same_ids_in_distinct_accounts_stay_separate(self):
        folder = self.root / "accounts"
        create(folder / "account-a")
        create(folder / "account-b")
        before = inventory(folder)
        output = self.root / "two-account-output"
        with patch("engine.emit"):
            telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze",
                destination=str(output), options=dict(roots=[str(folder)])),
                engine.Importer, lambda *a, **k: None)
        rows = [json.loads(x) for x in (output / "messages.jsonl").read_text(encoding="utf8").splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({x["identity_scope"] for x in rows}), 2)
        self.assertEqual(before, inventory(folder))

    def test_repeated_history_has_bounded_cache_provenance(self):
        _, summary, rows, _ = self.analyze("repeated-history")
        self.assertEqual(len(rows), 1)
        self.assertLessEqual(len(rows[0]["additional_sources"]), 10)
        self.assertEqual(rows[0]["recovery_status"], "current_cache_record")
        self.assertIn("TELEGRAM_MEDIA_CACHE_PROVENANCE_LIMIT", summary["warnings"])


if __name__ == "__main__":
    unittest.main()
