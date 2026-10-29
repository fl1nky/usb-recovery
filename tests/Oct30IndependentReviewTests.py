"""Independent regression checks for semantic message-version identity.

Only synthetic messages and temporary local files. These tests focus on
unchanged captions with replaced/removed media, not decoder implementation.
"""
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
sys.path.insert(0, str(ROOT / "tests"))
import engine
import telegram_auto
from TelegramMediaTests import photo_message, photo, size, DATE, create_schema

engine.emit = lambda *args, **kwargs: None


class MessageVersionIdentity(unittest.TestCase):
    def setUp(self):
        self.worker = engine.Importer.__new__(engine.Importer)
        self.worker.snapshot = "current"
        self.worker.source_label = "synthetic/cache4.db"
        self.worker.current_origin = {"Sha256": "a" * 64}
        self.worker.identities = {}
        self.worker.messages = []

    def add(self, *, older=False, caption="Same recipe caption", **fields):
        self.worker.snapshot = "prior" if older else "current"
        self.worker.message("Telegram", caption, "previous" if older else "backup",
            identity_scope="synthetic-account", record_kind="tl_message",
            chat_id=77, message_id=1, sender_id="user:77", timestamp="2026-10-30T00:00:00Z",
            attachments=[], **fields)

    def photo(self, identity="111", **fields):
        return dict(media_kind="photo", media_id=identity,
                    media_status="photo_reference_only", thumbnail_count=0, **fields)

    def test_replaced_photo_same_caption_keeps_previous_reference(self):
        self.add(**self.photo("222"))
        self.add(older=True, **self.photo("111"))
        self.assertEqual([row["media_id"] for row in self.worker.messages], ["222", "111"])
        self.assertEqual(self.worker.messages[1]["evidence_kind"], "previous")

    def test_replaced_photo_without_caption_keeps_both_records(self):
        self.add(caption="", **self.photo("222"))
        self.add(older=True, caption="", **self.photo("111"))
        self.assertEqual(len(self.worker.messages), 2)
        self.assertTrue(all(row["text"] == "" for row in self.worker.messages))

    def test_removed_photo_does_not_collapse_into_same_plain_text(self):
        self.add()
        self.add(older=True, **self.photo())
        self.assertEqual(len(self.worker.messages), 2)
        self.assertNotIn("media_kind", self.worker.messages[0])
        self.assertEqual(self.worker.messages[1]["media_kind"], "photo")

    def test_unchanged_photo_merges_confirmed_record_with_extra_source(self):
        self.add(**self.photo())
        self.add(older=True, **self.photo())
        self.assertEqual(len(self.worker.messages), 1)
        self.assertEqual(self.worker.messages[0]["additional_sources"][0]["snapshot_id"], "prior")

    def test_legacy_plain_message_dedup_stays_compatible(self):
        self.add()
        self.add(older=True)
        self.assertEqual(len(self.worker.messages), 1)
        self.assertEqual(self.worker.messages[0]["text"], "Same recipe caption")

    def test_media_unknown_and_known_are_not_silently_same(self):
        self.add(**self.photo(None))
        self.add(older=True, **self.photo("111"))
        self.assertEqual(len(self.worker.messages), 2)

    def test_thumbnail_availability_metadata_is_retained(self):
        self.add(**self.photo())
        older = self.photo()
        older.update(media_status="cached_thumbnail_available", thumbnail_count=1)
        self.add(older=True, **older)
        self.assertEqual(len(self.worker.messages), 2)


class WalPhotoVersions(unittest.TestCase):
    def verify_replacement(self, caption):
        with tempfile.TemporaryDirectory(prefix="synthetic-photo-version-") as temporary:
            root = Path(temporary)
            source = root / "input"
            source.mkdir()
            db = source / "cache4.db"
            connection = sqlite3.connect(db)
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA wal_autocheckpoint=0")
                create_schema(connection)
                earlier = bytearray(photo([size()]))
                struct.pack_into("<q", earlier, 8, 111)
                connection.execute("INSERT INTO messages_v2 VALUES(1,77,?,?)",
                                   (DATE, photo_message(caption, payload=bytes(earlier))))
                connection.commit()
                current = bytearray(photo([size()]))
                struct.pack_into("<q", current, 8, 222)
                connection.execute("UPDATE messages_v2 SET data=? WHERE mid=1",
                                   (photo_message(caption, payload=bytes(current)),))
                connection.commit()
                paths = (db, Path(str(db) + "-wal"))
                before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
                output = root / "archive"
                result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze",
                    "destination": str(output), "options": {"roots": [str(source)]}},
                    engine.Importer, engine.emit)
                rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(
                    encoding="utf-8").splitlines()]
                self.assertEqual(result["previous_records"], 1)
                self.assertEqual(len(rows), 2)
                self.assertEqual({row["media_id"] for row in rows}, {"111", "222"})
                self.assertEqual(next(row for row in rows if row["media_id"] == "111")["evidence_kind"], "previous")
                self.assertTrue(all(row["text"] == caption and row["attachments"] == [] for row in rows))
                self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
            finally:
                connection.close()

    def test_real_wal_same_caption_replaced_photo(self):
        self.verify_replacement("Same unchanged recipe caption")

    def test_real_wal_empty_caption_replaced_photo(self):
        self.verify_replacement("")


if __name__ == "__main__":
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                               for cls in (MessageVersionIdentity, WalPhotoVersions))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    source_files = [ROOT / "helpers/recovery_engine/engine.py", Path(__file__)]
    report = {
        "status": "passed" if result.wasSuccessful() else "failed",
        "scope": "Synthetic message-version deduplication; no devices, profiles or source-media reads",
        "tests": result.testsRun,
        "regression_fixed": "Photo replacement/removal with unchanged caption retains previous reference",
        "files": [{"path": p.relative_to(ROOT).as_posix(),
                   "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in source_files],
        "real_devices": False,
    }
    (ROOT / "tests/Oct30IndependentReview-validation.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    sys.exit(not result.wasSuccessful())
