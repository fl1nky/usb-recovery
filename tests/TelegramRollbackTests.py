"""Journal acquisition, archive transfer and unknown-attribution regressions."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
import archive_search
import engine
import telegram_auto
from rollback_provenance import ROLLBACK_FIELDS
from build_telegram_rollback_fixtures import build, OLD


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TelegramRollbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="owned-rollback-integration-")
        cls.base = Path(cls.temp.name)
        cls.corpus = cls.base / "corpus"
        cls.manifest = build(cls.corpus)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.job = Path(tempfile.mkdtemp(prefix="job-", dir=self.base))
        self.counter = 0

    def analyze(self, source, **options):
        self.counter += 1
        output = self.job / ("out-" + str(self.counter))
        source_root = source if source.is_dir() else source.parent
        before = {str(p.relative_to(source_root)): sha(p) for p in source_root.rglob("*") if p.is_file()}
        with patch("engine.emit"):
            summary = telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze",
                destination=str(output), options=dict(roots=[str(source)], **options)),
                engine.Importer, lambda *a, **k: None)
        self.assertEqual(before, {str(p.relative_to(source_root)): sha(p) for p in source_root.rglob("*") if p.is_file()})
        rows = [json.loads(raw) for raw in (output / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        return output, summary, rows

    def source(self, case):
        return self.corpus / case / ("cache4.db-journal" if case == "full-standalone" else "cache4.db")

    def full_archive(self):
        return self.analyze(self.source("full-standalone"))

    def test_full_and_standalone_publish_all_eight_rows_without_hidden_parser_failure(self):
        for case in ("full-delete", "full-standalone"):
            with self.subTest(case=case):
                out, summary, rows = self.analyze(self.source(case))
                native = [row for row in rows if row.get("rollback_snapshot_sha256")]
                self.assertEqual(len(native), 8)
                self.assertEqual({row["message_id"] for row in native}, {21, *range(100, 107)})
                self.assertEqual(summary["blocked_sources"], 0)
                for row in native:
                    self.assertEqual(row["evidence_kind"], "backup")
                    self.assertIsNone(row.get("deleted"))
                    self.assertEqual(sha(out / row["rollback_page_map"]), row["rollback_page_map_sha256"])

    def test_canonical_reimport_keeps_every_map_including_same_target_reuse(self):
        original, _, _ = self.full_archive()
        output, summary, rows = self.analyze(original / "messages.jsonl")
        native = [row for row in rows if row.get("rollback_snapshot_sha256")]
        self.assertEqual(len(native), 8)
        self.assertNotIn("TELEGRAM_ROLLBACK_MAP_UNAVAILABLE", summary["warnings"])
        for row in native:
            self.assertEqual(sha(output / row["rollback_page_map"]), row["rollback_page_map_sha256"])
            self.assertEqual((output / row["rollback_page_map"]).read_bytes(), (original / row["rollback_page_map"]).read_bytes())

    def test_sqlite_archive_reimport_copies_map_as_well_as_jsonl(self):
        original, _, _ = self.full_archive()
        output, _, rows = self.analyze(original / "chat-index.sqlite")
        self.assertEqual(sum(bool(row.get("rollback_snapshot_sha256")) for row in rows), 8)
        for row in rows:
            self.assertTrue((output / row["rollback_page_map"]).is_file())

    def test_missing_map_keeps_text_and_marks_old_provenance_unavailable(self):
        original, _, original_rows = self.full_archive()
        (original / original_rows[0]["rollback_page_map"]).unlink()
        output, summary, rows = self.analyze(original / "messages.jsonl")
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(row["text"] == OLD for row in rows), 1)
        self.assertIn("TELEGRAM_ROLLBACK_MAP_UNAVAILABLE", summary["warnings"])
        self.assertTrue(all(not row.get("rollback_page_map") for row in rows))
        self.assertTrue(all(row["previous_provenance"]["unavailable_rollback_maps"] for row in rows))
        self.assertFalse((output / "provenance/rollback").exists())

    def test_changed_map_is_not_published_with_stale_success_hash(self):
        original, _, original_rows = self.full_archive()
        (original / original_rows[0]["rollback_page_map"]).write_bytes(b'{"changed_owned_map":true}')
        output, summary, rows = self.analyze(original / "messages.jsonl")
        self.assertEqual(sum(row["text"] == OLD for row in rows), 1)
        self.assertIn("TELEGRAM_ROLLBACK_MAP_UNAVAILABLE", summary["warnings"])
        self.assertTrue(all(not row.get("rollback_journal_sha256") for row in rows))
        self.assertFalse((output / "provenance/rollback").exists())

    def test_additional_journal_sources_survive_reimport(self):
        original, _, rows = self.full_archive()
        first = rows[0]
        extra = {name: first[name] for name in ROLLBACK_FIELDS if first.get(name) is not None}
        extra.update(source_file="OWN_SECOND_JOURNAL_COPY", source_record="own-record", snapshot_id=first["snapshot_id"])
        first["additional_sources"] = [extra]
        (original / "messages.jsonl").write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
        output, _, result = self.analyze(original / "messages.jsonl")
        transferred = next(row for row in result if row["message_id"] == first["message_id"])
        self.assertTrue(any(source.get("source_file") == "OWN_SECOND_JOURNAL_COPY" for source in transferred["additional_sources"]))
        found = archive_search.search(dict(protocol=1, operation="search", archive=str(output), app="Telegram", query=transferred["text"]))
        self.assertTrue(any(source.get("source_file") == "OWN_SECOND_JOURNAL_COPY" for row in found["records"] for source in row["sources"]))

    def test_partial_metadata_cannot_promote_ids_category_date_or_deletion(self):
        _, _, rows = self.analyze(self.source("partial-delete"))
        raw = copy.deepcopy(next(row for row in rows if row["text"] == OLD))
        raw.update(chat_id=99, chat_name="Unproven", sender_id=99, sender_name="Unproven",
                   message_id=999, timestamp="2026-01-01", timestamp_raw="2026-01-01",
                   evidence_kind="backup", deleted=True, previous_version=True)
        normalized = archive_search._normalized(raw)
        self.assertEqual(normalized["evidence_kind"], "fragment")
        for field in ("chat_id", "chat_name", "sender_id", "sender_name", "message_id", "timestamp", "timestamp_raw", "deleted"):
            self.assertIsNone(normalized[field], field)
        self.assertFalse(normalized["previous_version"])

    def test_forged_authentication_and_path_are_not_accepted_as_valid_provenance(self):
        _, _, rows = self.analyze(self.source("partial-delete"))
        raw = next(row for row in rows if row["text"] == OLD)
        for field, value in (("rollback_content_authenticity_verified", True),
                ("rollback_hot_state", "hot"), ("rollback_current_state_confirmed", True),
                ("rollback_page_map", "../../outside.json"), ("rollback_snapshot_sha256", "a" * 64)):
            with self.subTest(field=field):
                self.assertIsNone(archive_search._normalized({**raw, field: value}))

    def test_recover_deleted_off_does_not_publish_journal_text(self):
        _, _, rows = self.analyze(self.source("partial-delete"), recover_deleted=False)
        self.assertFalse(any(row["text"] == OLD for row in rows))
        self.assertFalse(any(row.get("rollback_journal_sha256") for row in rows))

    def test_journal_is_copied_under_non_replay_name_before_sqlite_opens(self):
        connect = sqlite3.connect
        opened = []
        def observe(database, *args, **kwargs):
            opened.append(str(database))
            return connect(database, *args, **kwargs)
        with patch("sqlite3.connect", side_effect=observe):
            _, summary, rows = self.analyze(self.source("full-delete"))
        self.assertEqual(summary["blocked_sources"], 0)
        self.assertTrue(rows)
        self.assertTrue(opened)
        self.assertFalse(any(".rollback-journal" in uri or ".db-journal" in uri for uri in opened))

    def test_global_fragment_cap_is_shared_across_separate_journals(self):
        initialize = telegram_auto.Analyzer.__init__
        def almost_full(instance, *args, **kwargs):
            initialize(instance, *args, **kwargs)
            instance.fragments = 19999
        output = self.job / "budget-output"
        roots = [str(self.source("partial-delete")), str(self.source("partial-update"))]
        with patch.object(telegram_auto.Analyzer, "__init__", almost_full), patch("engine.emit"):
            telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze", destination=str(output),
                options=dict(roots=roots)), engine.Importer, lambda *a, **k: None)
        rows = [json.loads(raw) for raw in (output / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        self.assertEqual(sum(row.get("record_kind") == "sqlite_rollback_fragment" for row in rows), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
