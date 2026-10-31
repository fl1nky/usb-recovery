"""Persistent phone/ZIP origins and untrusted canonical snapshot text."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
import archive_search
import engine
import telegram_auto
from build_telegram_rollback_context_fixtures import build, capture_canonical


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TelegramRollbackContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="owned-rollback-context-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name)
        cls.corpus = cls.base / "corpus"
        cls.manifest = build(cls.corpus)
        cls.cases = {value["name"]: value for value in cls.manifest["cases"]}

    def setUp(self):
        self.job = Path(tempfile.mkdtemp(prefix="job-", dir=self.base))

    def analyze(self, name):
        case = self.cases[name]
        source, destination = self.corpus / case["source_path"], self.job / "output"
        before = {relative: sha(self.corpus / relative) for relative in case["source_files"]}
        with patch("engine.emit"):
            if case["operation"] == "scan":
                worker = engine.Importer(source, destination)
                worker.telegram_only = True
                result = worker.run()
            else:
                result = telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze", destination=str(destination),
                    options=dict(roots=[str(source)])), engine.Importer, lambda *a, **kw: None)
        rows = [json.loads(line) for line in (destination / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        self.assertEqual(before, {relative: sha(self.corpus / relative) for relative in case["source_files"]})
        return destination, result, rows

    def target(self, name):
        output, result, rows = self.analyze(name)
        targets = [row for row in rows if row.get("text") == self.cases[name]["expected_text"]]
        self.assertEqual(len(targets), 1)
        return output, result, targets[0]

    def test_phone_acquisition_preserves_all_logical_origin_fields(self):
        output, _, row = self.target("phone")
        case = self.cases["phone"]
        for field, expected in (("source_file", "expected_origin_path"), ("source_id", "expected_source_id"),
                                ("original_relative_path", "expected_relative_path"), ("source_sha256", "expected_source_sha256")):
            self.assertEqual(row[field], case[expected])
        self.assertNotIn(".work", row["source_file"])
        self.assertTrue(row["application_confirmed"])
        self.assertEqual(row["rollback_proof"], "all_pages_from_validated_rollback_journal")
        self.assertTrue((output / row["rollback_page_map"]).is_file())

    def test_zip_members_have_per_file_hash_and_separate_container_origin(self):
        _, _, row = self.target("zip")
        case = self.cases["zip"]
        for field, expected in (("source_file", "expected_origin_path"), ("source_id", "expected_source_id"),
                                ("source_sha256", "expected_source_sha256"), ("original_relative_path", "expected_relative_path"),
                                ("container_sha256", "container_sha256"), ("container_source_id", "container_source_id"),
                                ("container_source_file", "container_origin_path")):
            self.assertEqual(row[field], case[expected])
        self.assertNotEqual(row["source_sha256"], row["container_sha256"])
        self.assertNotIn(".work", row["source_file"])
        normalized = archive_search._normalized(row)
        self.assertEqual(normalized["container_sha256"], row["container_sha256"])

    def test_generic_json_flags_and_ids_cannot_claim_native_telegram_history(self):
        output, result, row = self.target("generic")
        self.assertEqual(row["rollback_proof"], "archive_text_from_rollback_snapshot")
        self.assertEqual(row["record_kind"], "sqlite_rollback_archive_text")
        self.assertEqual(row["evidence_kind"], "fragment")
        self.assertFalse(row["application_confirmed"])
        self.assertTrue(row["rollback_snapshot_sha256"])
        self.assertEqual(result["history_messages"], 0)
        for field in ("chat_id", "chat_name", "message_id", "sender_id", "sender_name", "timestamp", "timestamp_raw", "deleted"):
            self.assertIsNone(row.get(field))
        for field in ("native_constructor", "native_layer", "native_tl_body_sha256"):
            self.assertIsNone(row.get(field))
        for mode, query in (("literal", "JSON archive text"), ("regex", r"JSON\s+archive\s+text")):
            found = archive_search.search(dict(protocol=1, operation="search", archive=str(output), app="Telegram", query=query, query_mode=mode))
            self.assertEqual(found["total"], 1)
            self.assertEqual(found["records"][0]["rollback_proof"], row["rollback_proof"])
            self.assertFalse(found["records"][0]["application_confirmed"])

    def test_generic_proof_normalization_clears_self_declared_native_claims(self):
        _, _, original = self.target("generic")
        forged = copy.deepcopy(original)
        forged.update(chat_id=77, message_id=21, sender_id="user:77", application_confirmed=True,
                      record_kind="tl_message", native_constructor="0x452c0e65", native_tl_body_sha256="a" * 64)
        value = archive_search._normalized(forged)
        self.assertFalse(value["application_confirmed"])
        self.assertEqual(value["record_kind"], "sqlite_rollback_archive_text")
        for name in ("chat_id", "message_id", "sender_id", "native_constructor", "native_tl_body_sha256"):
            self.assertIsNone(value[name])

    def test_generic_text_survives_invalid_self_declared_provenance(self):
        text = "Owned generic text survives invalid untrusted metadata"
        current, journal, _ = capture_canonical(self.job / "writer.sqlite", dict(app="Telegram", text=text,
            evidence_kind="not-a-real-category", rollback_journal_sha256="not-a-hash", deleted=True))
        source = self.job / "input/cache4.db"
        source.parent.mkdir()
        source.write_bytes(current)
        Path(str(source) + "-journal").write_bytes(journal)
        output = self.job / "result"
        with patch("engine.emit"):
            telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze", destination=str(output),
                options=dict(roots=[str(source)])), engine.Importer, lambda *a, **kw: None)
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        self.assertEqual([row["text"] for row in rows], [text])
        self.assertEqual(rows[0]["rollback_proof"], "archive_text_from_rollback_snapshot")
        self.assertEqual(rows[0]["evidence_kind"], "fragment")
        self.assertFalse(rows[0]["application_confirmed"])

    def test_provided_phone_hash_mismatch_cannot_be_rebound_as_valid(self):
        case = self.cases["phone"]
        source = self.corpus / case["source_path"] / "Telegram/cache4.db"
        output = self.job / "output"
        (output / "media").mkdir(parents=True)
        worker = engine.Importer(source, output)
        worker.work = self.job / "worker"
        worker.work.mkdir()
        worker.telegram_only = True
        worker.origins[str(source.resolve())] = dict(Id="owned-id", OriginalPath="android://OWNED/bad-proof",
            RelativePath="Telegram/cache4.db", Sha256="0" * 64, Size=source.stat().st_size, Status="complete")
        with patch("engine.emit"):
            worker.scan_file(source)
        self.assertEqual(worker.messages, [])
        self.assertTrue(any(value.get("code") in ("ACQUISITION_HASH_MISMATCH", "TELEGRAM_SOURCE_CHANGED") for value in worker.sources))

    def test_description_only_logical_origin_keeps_label_and_actual_file_hash(self):
        case = self.cases["phone"]
        source = self.corpus / case["source_path"] / "Telegram/cache4.db"
        output = self.job / "output"
        (output / "media").mkdir(parents=True)
        worker = engine.Importer(source, output)
        worker.work = self.job / "worker"
        worker.work.mkdir()
        worker.telegram_only = True
        worker.origins[str(source.resolve())] = dict(RelativePath="logical/Telegram/cache4.db")
        with patch("engine.emit"):
            worker.scan_file(source, label="owned-logical://backup/Telegram/cache4.db")
        target = next(row for row in worker.messages if row.get("text") == case["expected_text"])
        self.assertEqual(target["source_file"], "owned-logical://backup/Telegram/cache4.db-journal")
        self.assertEqual(target["source_sha256"], case["expected_journal_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
