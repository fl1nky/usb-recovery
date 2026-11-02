"""Source-only checks on independent owned SQL/WAL and official TL232 rows."""
from pathlib import Path
import json
import datetime as dt
import hashlib
import os
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
from build_telegram_media_cache_fixtures import create, inventory, message, body_digest, TEXT, DATE, SCHEMA


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
        source_root = source if source.is_dir() else source.parent
        before = inventory(source_root)
        output = self.root / ("output-" + str(self.counter))
        with patch("engine.emit"):
            summary = telegram_auto.analyze(
                dict(protocol=1, operation="telegram_analyze", destination=str(output),
                     options=dict(roots=[str(source)], **options)),
                engine.Importer, lambda *a, **k: None)
        self.assertEqual(before, inventory(source_root), "Every supplied DB/WAL/SHM/golden byte stays unchanged")
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

    def test_metadata_only_edit_keeps_both_complete_native_versions(self):
        output, _, rows, golden = self.analyze("metadata-only-edit")
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["text"] for row in rows}, {TEXT})
        self.assertEqual({row["message_id"] for row in rows}, {41})
        self.assertEqual({row["native_tl_body_sha256"] for row in rows},
                         set(golden["body_versions_sha256"]))
        self.assertEqual({row["evidence_kind"] for row in rows}, {"backup", "previous"})
        found = archive_search.search(dict(protocol=1, operation="search",
            archive=str(output), app="Telegram", query="Рецепт"))
        self.assertEqual(found["total"], 2)
        self.assertTrue(all(row["deleted"] is None for row in found["records"]))

    def test_checked_primary_never_adopts_an_imported_archive_claim(self):
        source, _ = create(self.root / "claim-input", "primary-current")
        before = inventory(source.parent)
        output = self.root / "claim-output"
        analyzer = telegram_auto.Analyzer(dict(destination=str(output), options={}),
            engine.Importer, lambda *a, **k: None)
        analyzer.worker = engine.Importer(output, output)
        identity = "telegram-db:" + hashlib.sha256(
            os.path.normcase(os.path.abspath(source)).encode("utf-8")).hexdigest()
        declared = dict(app="Telegram", text=TEXT, evidence_kind="backup",
            source_record="line:1", chat_id=77, message_id=41, sender_id="user:77",
            timestamp=dt.datetime.fromtimestamp(DATE, dt.timezone.utc).isoformat(),
            identity_scope=identity, record_kind="tl_message", application_confirmed=True,
            native_tl_body_sha256=body_digest(message()), native_layer=232,
            native_constructor="0x7600b9d3", completeness="supported_structure_complete",
            media_kind="photo", media_id="987654321", media_status="photo_reference_only",
            thumbnail_count=0, attachments=[], recovery_status="deleted_supported_by_evidence",
            deletion_interpretation="unverified archive claim", deleted=True)
        analyzer.worker.source_label = str(self.root / "provided/messages.jsonl")
        analyzer.canonical_message(archive_search._normalized(declared),
            self.root / "copy/messages.jsonl", self.root / "provided/messages.jsonl", "line:1")
        unverified = analyzer.worker.messages[0]
        self.assertEqual(unverified["recovery_status"], "imported_recovery_claim")
        self.assertEqual(unverified["provenance_verification"], "provided_archive_metadata")
        self.assertIsNone(unverified["deleted"])
        self.assertIs(unverified["archive_claims"]["deleted"], True)
        analyzer.worker.source_label = str(source)
        con = sqlite3.connect(source)
        try:
            analyzer.native_messages(con, {"messages_v2"}, source)
            analyzer.native_media_cache(con, source)
        finally:
            con.close()
        checked = [row for values in analyzer._verified_native_bodies.values() for row in values]
        self.assertEqual(len(checked), 1)
        self.assertIsNot(checked[0], unverified)
        self.assertIsNone(checked[0].get("deleted"))
        self.assertNotEqual(checked[0].get("recovery_status"), "deleted_supported_by_evidence")
        self.assertTrue(checked[0]["source_record"].startswith("messages_v2"))
        self.assertTrue(any(x["record_kind"] == "telegram_media_cache"
                            for x in checked[0]["additional_sources"]))
        self.assertEqual(before, inventory(source.parent))

    def test_imported_deletion_claim_is_not_a_new_deleted_find(self):
        source, _ = create(self.root / "provided-claim", "primary-current")
        declared = dict(app="Telegram", text="Claim-only caption", evidence_kind="backup",
            chat_id=77, message_id=41, record_kind="tl_message", deleted=True,
            recovery_status="deleted_supported_by_evidence",
            deletion_interpretation="claimed by archive writer",
            provenance_verification="internally_verified",
            archive_claims={"secret_key": "owned-test-sentinel", "deleted": {"nested": True}})
        (source.parent / "messages.jsonl").write_text(json.dumps(declared) + "\n", encoding="utf8")
        output, summary, rows, _ = self.analyze(root=source.parent)
        claim = next(row for row in rows if row["text"] == declared["text"])
        self.assertEqual(summary["deleted_supported_records"], 0)
        self.assertEqual(claim["recovery_status"], "imported_recovery_claim")
        self.assertEqual(claim["provenance_verification"], "provided_archive_metadata")
        self.assertIsNone(claim["deleted"])
        self.assertEqual(claim["archive_claims"], {name: declared[name] for name in
            ("recovery_status", "deletion_interpretation", "deleted")})
        found = archive_search.search(dict(protocol=1, operation="search", archive=str(output),
            app="Telegram", query="", evidence="deleted"))
        self.assertEqual(found["total"], 0)
        _, copied_summary, copied_rows, _ = self.analyze(root=output / "messages.jsonl")
        copied_claim = next(row for row in copied_rows if row["text"] == declared["text"])
        self.assertEqual(copied_summary["deleted_supported_records"], 0)
        self.assertEqual(copied_claim["archive_claims"], claim["archive_claims"])
        self.assertEqual(copied_claim["recovery_status"], "imported_recovery_claim")
        self.assertNotIn("owned-test-sentinel", json.dumps(copied_rows))

    def test_archive_claims_accept_only_bounded_display_fields(self):
        value = archive_search._normalized(dict(app="Telegram", text="Owned claim",
            evidence_kind="backup", provenance_verification="internally_verified",
            archive_claims=dict(recovery_status="x" * 5000, deleted=1,
                deletion_interpretation={"nested": "not display text"}, secret_key="owned-sentinel")))
        self.assertEqual(value["archive_claims"], {"recovery_status": "x" * 4096})
        self.assertIsNone(value["provenance_verification"])
        value = archive_search._normalized(dict(app="Telegram", text="Owned claim",
            evidence_kind="backup", archive_claims=dict(deletion_interpretation="🥧" * 4097)))
        self.assertEqual(value["archive_claims"], {"deletion_interpretation": "🥧" * 4096})

    def test_cache_origin_survives_search_fallback_and_archive_reimport(self):
        archive, _, rows, _ = self.analyze("primary-historical")
        fields = ("record_kind", "recovery_status", "deletion_interpretation",
                  "native_tl_body_sha256", "wal_db_sha256")
        expected = next(row for row in rows[0]["additional_sources"]
                        if "media_v4" in row["source_record"])
        self.assertEqual(expected["native_tl_body_sha256"], rows[0]["native_tl_body_sha256"])
        first = archive_search.search(dict(protocol=1, operation="search",
            archive=str(archive), app="Telegram", query="Рецепт"))
        origin = next(row for row in first["records"][0]["sources"] if "media_v4" in row["source_record"])
        self.assertEqual({name: origin.get(name) for name in fields},
                         {name: expected.get(name) for name in fields})
        (archive / "chat-index.sqlite").rename(archive / "original-index.sqlite")
        fallback = archive_search.search(dict(protocol=1, operation="search",
            archive=str(archive), app="Telegram", query="Рецепт"))
        self.assertEqual(fallback["records"][0]["sources"], first["records"][0]["sources"])
        _, _, copied, _ = self.analyze(root=archive / "messages.jsonl")
        normalized = archive_search._normalized(copied[0])
        again = next(row for row in normalized["sources"] if "media_v4" in row["source_record"])
        self.assertEqual({name: again.get(name) for name in fields},
                         {name: expected.get(name) for name in fields})


if __name__ == "__main__":
    unittest.main()
