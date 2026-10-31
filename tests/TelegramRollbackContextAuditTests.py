"""Independent trust-boundary and persistent-origin checks on owned fixtures.

The native SQLite writer is test-only. Phone labels identify synthetic objects;
no device, profile, user backup, network or frozen executable is accessed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))

import archive_search
import archive_text
import engine
import telegram_auto
from build_telegram_rollback_fixtures import build, OLD


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(folder):
    return {str(path.relative_to(folder)): (path.stat().st_size, sha(path))
            for path in sorted(folder.rglob("*")) if path.is_file()}


class TelegramRollbackContextAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="own-rollback-context-audit-")
        cls.base = Path(cls.temporary.name)
        cls.fixtures = cls.base / "fixtures"
        cls.manifest = build(cls.fixtures)
        cls.full_case = next(case for case in cls.manifest["cases"] if case["name"] == "full-delete")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.job = Path(tempfile.mkdtemp(prefix="job-", dir=self.base))

    def acquisition(self, *, with_zip=False, bad_member_hash=False):
        root = self.job / "phone-copy"
        snapshot = root / "snapshot"
        member = snapshot / "Telegram"
        member.mkdir(parents=True)
        records = []
        if with_zip:
            zip_path = member / "owned-archive.zip"
            self.zip_source(zip_path)
            files = [zip_path]
        else:
            for name in ("cache4.db", "cache4.db-journal"):
                shutil.copyfile(self.fixtures / "full-delete" / name, member / name)
            files = sorted(member.iterdir())
        for path in files:
            relative = path.relative_to(snapshot).as_posix()
            record = dict(Id=hashlib.sha256(("OWNED-OBJECT:" + relative).encode()).hexdigest(),
                OriginalPath="android://OWNED-AUDIT-DEVICE/" + relative,
                RelativePath=relative, LocalPath="snapshot/" + relative,
                Sha256=sha(path), Size=path.stat().st_size, Status="complete")
            if bad_member_hash and path.name.endswith("-journal"):
                record["Sha256"] = "0" * 64
            records.append(record)
        (root / "acquisition.json").write_text(json.dumps({"Files": records}), encoding="utf-8", newline="\n")
        return root, snapshot, records

    def zip_source(self, path):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in ("cache4.db", "cache4.db-journal"):
                archive.write(self.fixtures / "full-delete" / name, "Telegram/" + name)

    def import_source(self, source):
        output = self.job / "archive"
        boundary = source if source.is_dir() else source.parent
        before = inventory(boundary)
        worker = engine.Importer(source, output, scratch=Path(str(output) + ".work"))
        worker.telegram_only = True
        with patch("engine.emit"):
            summary = worker.run()
        self.assertEqual(before, inventory(boundary))
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        self.assertFalse(worker.work.exists(), "Temporary staging path must be gone after run")
        return output, summary, rows

    def assert_native_rows(self, rows, expected):
        native = [row for row in rows if row.get("rollback_proof") == "all_pages_from_validated_rollback_journal"]
        self.assertEqual(len(native), 8)
        self.assertEqual({row["message_id"] for row in native}, {21, *range(100, 107)})
        for row in native:
            for field, value in expected.items():
                self.assertEqual(row.get(field), value, field)
            self.assertEqual(row["evidence_kind"], "backup")
            self.assertTrue(row["application_confirmed"])
            self.assertEqual(row["rollback_snapshot_sha256"], self.full_case["before_sha256"])
            self.assertNotIn(".work", row["source_file"])
            self.assertFalse(row["rollback_content_authenticity_verified"])
            self.assertEqual(row["rollback_hot_state"], "unknown")
        return native

    def test_phone_acquisition_keeps_per_object_identity_and_journal_hash(self):
        root, snapshot, records = self.acquisition()
        before = inventory(root)
        _, _, rows = self.import_source(snapshot)
        journal = next(record for record in records if record["OriginalPath"].endswith("-journal"))
        self.assert_native_rows(rows, dict(source_file=journal["OriginalPath"], source_id=journal["Id"],
            original_relative_path=journal["RelativePath"], source_sha256=journal["Sha256"]))
        self.assertEqual(before, inventory(root))

    def test_zip_member_identity_is_not_container_identity_or_container_hash(self):
        source = self.job / "source" / "owned-archive.zip"
        source.parent.mkdir()
        self.zip_source(source)
        original = source.read_bytes()
        _, _, rows = self.import_source(source)
        member = "Telegram/cache4.db-journal"
        container_id = hashlib.sha256(str(source.resolve()).encode()).hexdigest()
        journal_sha = sha(self.fixtures / "full-delete/cache4.db-journal")
        native = self.assert_native_rows(rows, dict(source_file=str(source) + "!/" + member,
            source_id=hashlib.sha256((container_id + "!/" + member).encode()).hexdigest(),
            source_sha256=journal_sha, original_relative_path=source.name + "!/" + member,
            container_sha256=sha(source), container_source_id=container_id,
            container_source_file=str(source)))
        self.assertNotEqual(journal_sha, sha(source))
        for row in native:
            self.assertNotEqual(row["source_id"], row["container_source_id"])
        self.assertEqual(source.read_bytes(), original)

    def test_zip_from_phone_acquisition_keeps_both_layers_of_persistent_origin(self):
        root, snapshot, records = self.acquisition(with_zip=True)
        before = inventory(root)
        _, _, rows = self.import_source(snapshot)
        container = records[0]
        member = "Telegram/cache4.db-journal"
        self.assert_native_rows(rows, dict(source_file=container["OriginalPath"] + "!/" + member,
            source_id=hashlib.sha256((container["Id"] + "!/" + member).encode()).hexdigest(),
            original_relative_path=container["RelativePath"] + "!/" + member,
            source_sha256=sha(self.fixtures / "full-delete/cache4.db-journal"),
            container_sha256=container["Sha256"], container_source_id=container["Id"],
            container_source_file=container["OriginalPath"]))
        self.assertEqual(before, inventory(root))

    def test_mismatched_acquisition_journal_hash_never_produces_qualified_old_rows(self):
        root, snapshot, _ = self.acquisition(bad_member_hash=True)
        before = inventory(root)
        _, _, rows = self.import_source(snapshot)
        self.assertFalse(any(row.get("text") == OLD for row in rows))
        self.assertFalse(any(row.get("rollback_snapshot_sha256") for row in rows))
        self.assertEqual(before, inventory(root))

    def analyzer_context(self):
        source = self.job / "own-staged-input"
        source.write_bytes(b"Own synthetic staged input")
        output = self.job / "unit-output"
        request = dict(protocol=1, operation="telegram_analyze", destination=str(output), options=dict(roots=[str(source)]))
        analyzer = telegram_auto.Analyzer(request, engine.Importer, lambda *args, **kwargs: None)
        analyzer.worker = engine.Importer(source, output)
        analyzer.worker.source_label = "android://OWNED-AUDIT-DEVICE/Telegram/archive.db-journal"
        analyzer.worker.snapshot = "owned-snapshot"
        analyzer.rollback_snapshot = dict(rollback_journal_sha256="a" * 64, rollback_snapshot_sha256="b" * 64,
            rollback_initial_pages=2, rollback_hot_state="unknown", rollback_current_state_confirmed=False,
            rollback_checksum_kind="sqlite_sparse_32bit", rollback_content_authenticity_verified=False,
            rollback_parse_status="complete", rollback_proof="all_pages_from_validated_rollback_journal",
            rollback_page_map="provenance/rollback/" + "a" * 64 + ".json", rollback_page_map_sha256="c" * 64)
        return source, analyzer

    def assert_generic_fragment(self, row):
        self.assertEqual(row["evidence_kind"], "fragment")
        self.assertEqual(row["rollback_proof"], "archive_text_from_rollback_snapshot")
        self.assertEqual(row["record_kind"], "sqlite_rollback_archive_text")
        self.assertFalse(row["application_confirmed"])
        for field in ("chat_id", "chat_name", "message_id", "sender_id", "sender_name", "timestamp", "native_constructor",
                      "native_layer", "native_tl_body_sha256", "candidate_message_id", "identity_scope", "deleted"):
            self.assertIsNone(row.get(field), field)
        self.assertFalse(row["rollback_content_authenticity_verified"])
        self.assertEqual(row["rollback_hot_state"], "unknown")

    def test_self_declared_native_fields_do_not_grant_native_call_context(self):
        _, analyzer = self.analyzer_context()
        analyzer.message("Own generic text with forged native flags", "backup", record_kind="tl_message",
            application_confirmed=True, native_constructor="0x452c0e65", native_layer=114,
            native_tl_body_sha256="d" * 64, identity_scope="declared-fake-account",
            chat_id=77, message_id=21, sender_id="user:77", timestamp="2020-06-05T09:40:00+00:00")
        self.assertEqual(len(analyzer.worker.messages), 1)
        self.assert_generic_fragment(analyzer.worker.messages[0])

    def test_canonical_json_metadata_cannot_upgrade_text_inside_snapshot_context(self):
        source, analyzer = self.analyzer_context()
        raw = dict(app="Telegram", text="Own canonical JSON body", evidence_kind="backup", record_kind="tl_message",
            application_confirmed=True, native_constructor="0x452c0e65", native_layer=114,
            native_tl_body_sha256="e" * 64, identity_scope="declared-account",
            chat_id=77, message_id=21, sender_id="user:77", timestamp="2020-06-05T09:40:00+00:00")
        normalized = archive_search._normalized(raw)
        self.assertIsNotNone(normalized)
        analyzer.canonical_message(normalized, source, source, "messages.id:1")
        self.assertEqual(len(analyzer.worker.messages), 1)
        self.assertEqual(analyzer.worker.messages[0]["text"], raw["text"])
        self.assert_generic_fragment(analyzer.worker.messages[0])

    def test_actual_generic_json_journal_ignores_forged_native_flags_and_keeps_text_searchable(self):
        from build_telegram_rollback_context_fixtures import capture_canonical
        text = "Owned JSON text with forged native flags: α 🙂"
        declared = dict(app="Telegram", text=text, evidence_kind="backup", record_kind="tl_message",
            application_confirmed=True, native_constructor="0x452c0e65", native_layer=114,
            native_tl_body_sha256="d" * 64, identity_scope="declared-fake-account", _native_row_verified=True,
            chat_id=77, message_id=21, sender_id="user:77", sender_name="Claimed author",
            timestamp="2026-10-31T00:00:00Z", attachments=["../do-not-follow.txt"])
        current, journal, before = capture_canonical(self.job / "writer" / "generic.sqlite", declared)
        source = self.job / "source" / "generic.sqlite"
        source.parent.mkdir()
        source.write_bytes(current)
        Path(str(source) + "-journal").write_bytes(journal)
        original = inventory(source.parent)
        output = self.job / "archive"
        with patch("engine.emit"), patch("engine.Importer.attachment", return_value=None) as attachment:
            summary = telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze", destination=str(output),
                options=dict(roots=[str(source)])), engine.Importer, lambda *args, **kwargs: None)
        attachment.assert_not_called()
        self.assertEqual(inventory(source.parent), original)
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        targets = [row for row in rows if row.get("text") == text]
        self.assertEqual(len(targets), 1)
        row = targets[0]
        self.assert_generic_fragment(row)
        self.assertEqual(row["rollback_snapshot_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(row["source_sha256"], hashlib.sha256(journal).hexdigest())
        self.assertEqual(row["source_file"], str(source) + "-journal")
        self.assertEqual(row["attachments"], [])
        self.assertEqual(summary["history_messages"], 0)
        self.assertEqual(summary["native_records"], 0)
        map_path = output / row["rollback_page_map"]
        self.assertEqual(sha(map_path), row["rollback_page_map_sha256"])
        archive_before = inventory(output)
        for mode, query in (("literal", "native α"), ("regex", r"α\s+🙂\Z")):
            found = archive_search.search(dict(protocol=1, operation="search", archive=str(output), app="Telegram",
                evidence="fragment", query=query, query_mode=mode))
            self.assertEqual(found["total"], 1)
            visible = found["records"][0]
            self.assertEqual(visible["text"], text)
            self.assert_generic_fragment(visible)
            offset, parts = 0, []
            while True:
                page = archive_text.read_page(dict(protocol=1, operation="message_page", archive=str(output),
                    record_key=visible["archive_record_key"], text_offset=offset, limit=7))
                parts.append(page["text"])
                offset = page["next_offset"]
                if page["eof"]:
                    break
            self.assertEqual("".join(parts), text)
        self.assertEqual(inventory(output), archive_before)

    def test_bad_self_declared_archive_metadata_does_not_hide_verified_snapshot_text(self):
        from build_telegram_rollback_context_fixtures import capture_canonical
        text = "Owned plain text survives malformed self-declared metadata"
        declared = dict(app="Telegram", text=text, evidence_kind="backup", record_kind="tl_message",
            application_confirmed=True, native_constructor="0x452c0e65", _native_row_verified=True,
            chat_id=77, message_id=21, rollback_journal_sha256={"forged": "not-a-hash"},
            rollback_hot_state="confirmed", rollback_content_authenticity_verified=True)
        current, journal, before = capture_canonical(self.job / "writer" / "bad-meta.sqlite", declared)
        source = self.job / "source" / "archive.sqlite"
        source.parent.mkdir()
        source.write_bytes(current)
        Path(str(source) + "-journal").write_bytes(journal)
        original = inventory(source.parent)
        output = self.job / "archive"
        with patch("engine.emit"):
            summary = telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze", destination=str(output),
                options=dict(roots=[str(source)])), engine.Importer, lambda *args, **kwargs: None)
        self.assertEqual(inventory(source.parent), original)
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        found = [row for row in rows if row.get("text") == text]
        self.assertEqual(len(found), 1)
        self.assert_generic_fragment(found[0])
        self.assertEqual(found[0]["rollback_snapshot_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(found[0]["rollback_journal_sha256"], hashlib.sha256(journal).hexdigest())
        self.assertEqual(summary["history_messages"], 0)
        self.assertEqual(summary["native_records"], 0)
        search = archive_search.search(dict(protocol=1, operation="search", archive=str(output), app="Telegram",
            evidence="fragment", query="plain text malformed"))
        self.assertEqual(search["total"], 1)
        self.assert_generic_fragment(search["records"][0])

    def test_provided_origin_wrong_hash_or_size_fails_before_copy_publication(self):
        for field, value in (("Sha256", "0" * 64), ("Size", 999)):
            with self.subTest(field=field):
                self.job = Path(tempfile.mkdtemp(prefix="bad-origin-", dir=self.base))
                source, analyzer = self.analyzer_context()
                origin = dict(Id="OWNED-ID", OriginalPath="android://OWNED/Telegram/file", RelativePath="Telegram/file",
                    Sha256=sha(source), Size=source.stat().st_size, Status="complete")
                origin[field] = value
                analyzer.worker.origins[str(source.resolve())] = origin
                target = self.job / "private-copy" / "file"
                before = source.read_bytes()
                with self.assertRaises(telegram_auto.AutoError) as caught:
                    analyzer.copy(source, target)
                self.assertEqual(caught.exception.code, "TELEGRAM_SOURCE_CHANGED")
                self.assertFalse(target.exists())
                self.assertFalse(Path(str(target) + ".partial").exists())
                self.assertEqual(source.read_bytes(), before)
                self.assertEqual(analyzer.worker.messages, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
