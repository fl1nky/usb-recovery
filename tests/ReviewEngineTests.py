"""Independent regression checks found during v3 source review.

All fixtures are generated locally. No user device or personal backup is read.
"""
import importlib.util
import base64
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


engine = module("review_engine", ROOT / "helpers/recovery_engine/engine.py")
engine.emit = lambda *args, **kwargs: None
PHOTO = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j3ioAAAAASUVORK5CYII=")


class ReviewEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="review-engine-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def scan(self, source=None, secrets=None):
        worker = engine.Importer(source or self.source, self.root / "archive", secrets,
                                 tools_dir=ROOT / "tools")
        worker.run()
        return worker

    def test_confirmed_android_media_relation_is_kept_on_message(self):
        con = sqlite3.connect(self.source / "msgstore.db")
        con.executescript("CREATE TABLE jid(_id INTEGER PRIMARY KEY,raw_string TEXT);"
                          "CREATE TABLE chat(_id INTEGER PRIMARY KEY,jid_row_id INTEGER);"
                          "CREATE TABLE message(_id INTEGER PRIMARY KEY,chat_row_id INTEGER,sender_jid_row_id INTEGER,text_data TEXT,timestamp INTEGER,key_id TEXT,from_me INTEGER);"
                          "CREATE TABLE message_media(message_row_id INTEGER,file_path TEXT);")
        con.execute("INSERT INTO jid VALUES(1,'review@example.test')")
        con.execute("INSERT INTO chat VALUES(1,1)")
        con.execute("INSERT INTO message VALUES(101,1,1,'Attached photograph',1700000000000,'review-id',0)")
        con.execute("INSERT INTO message_media VALUES(101,'Media/picture.png')")
        con.commit()
        con.close()
        (self.source / "Media").mkdir()
        (self.source / "Media/picture.png").write_bytes(PHOTO)
        worker = self.scan()
        message = next(m for m in worker.messages if m.get("message_id") == "review-id")
        self.assertEqual(len(message["attachments"]), 1)
        self.assertEqual((worker.output / message["attachments"][0]).read_bytes(), PHOTO)

    def test_valid_sqlite_64k_freelist_yields_separate_unknown_fragments(self):
        con = sqlite3.connect(self.source / "unknown.sqlite")
        con.execute("PRAGMA page_size=65536")
        con.execute("PRAGMA secure_delete=OFF")
        con.execute("CREATE TABLE notes(text)")
        for number in range(80):
            con.execute("INSERT INTO notes VALUES(?)", (f"Review historical text {number}: " + "family recipe " * 700,))
        con.commit()
        con.execute("DELETE FROM notes")
        con.commit()
        con.close()
        self.assertEqual((self.source / "unknown.sqlite").read_bytes()[16:18], b"\x00\x01")
        worker = self.scan()
        fragments = [m for m in worker.messages if m["evidence_kind"] == "fragment"]
        self.assertTrue(fragments)
        self.assertTrue(all(m["chat_id"] is None and m["sender_id"] is None for m in fragments))

    def test_modern_signal_records_point_to_their_own_snapshot(self):
        fixture = ROOT / ".build/SignalHelpers-tests/modern"
        self.assertTrue(fixture.is_dir(), "Run SignalHelpers.Test.py first to generate its independent local-format fixture")
        shutil.copytree(fixture, self.source / "z-signal")
        snapshot = next(p for p in (self.source / "z-signal").iterdir() if p.is_dir() and (p / "main").is_file())
        (self.source / "a-chat.txt").write_text("2026-10-12, 12:00 - Alice: Earlier unrelated file", encoding="utf-8")
        worker = self.scan(secrets={"signal_key": "m" * 64})
        signal_messages = [m for m in worker.messages if m["app"] == "Signal"]
        self.assertEqual(len(signal_messages), 1)
        source_file = signal_messages[0]["source_file"]
        self.assertIsInstance(source_file, str)
        self.assertIn(snapshot.name, source_file)
        self.assertNotIn("a-chat.txt", source_file)

    def test_modern_signal_frame_number_does_not_merge_distinct_snapshots(self):
        from Crypto.Cipher import AES
        fixture = ROOT / ".build/SignalHelpers-tests/modern"
        self.assertTrue(fixture.is_dir(), "Run SignalHelpers.Test.py first")
        shutil.copytree(fixture, self.source / "signals")
        first = next(p for p in (self.source / "signals").iterdir() if p.is_dir() and (p / "main").is_file())
        second = first.parent / "signal-backup-independent-second-snapshot"
        shutil.copytree(first, second)
        def hkdf(secret, context, count):
            prk = hmac.new(bytes(32), secret, hashlib.sha256).digest()
            output, last = b"", b""
            for counter in range(1, (count + 31) // 32 + 1):
                last = hmac.new(prk, last + context + bytes([counter]), hashlib.sha256).digest()
                output += last
            return output[:count]
        backup_key = hkdf(b"m" * 64, b"20240801_SIGNAL_BACKUP_KEY", 32)
        keys = hkdf(backup_key, b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:" + b"B" * 16, 64)
        raw = (first / "main").read_bytes()
        plaintext_padded = AES.new(keys[32:], AES.MODE_CBC, raw[:16]).decrypt(raw[16:-32])
        iv = b"J" * 16
        encrypted = iv + AES.new(keys[32:], AES.MODE_CBC, iv).encrypt(plaintext_padded)
        (second / "main").write_bytes(encrypted + hmac.new(keys[:32], encrypted, hashlib.sha256).digest())
        worker = self.scan(secrets={"signal_key": "m" * 64})
        messages = [m for m in worker.messages if m["app"] == "Signal"]
        self.assertEqual(len(messages), 2)
        self.assertTrue(all(m["message_id"] is None for m in messages))
        self.assertEqual(len({m["snapshot_id"] for m in messages}), 2)

    def test_source_copy_to_worker_native_signal_both_formats_and_nested_ios(self):
        upstream_tests = module("review_engine_fixtures", ROOT / "tests/EngineTests.py")
        fixtures = ROOT / ".build/SignalHelpers-tests"
        # Each protected source gets its own user-provided secret; these are
        # synthetic copies generated by the independent Signal format writer.
        for name, fixture, secret in (
            ("legacy-v0", fixtures / "legacy-v0.backup", "123456789012345678901234567890"),
            ("legacy-v1", fixtures / "legacy-v1.backup", "123456789012345678901234567890"),
            ("modern", fixtures / "modern", "m" * 64),
            ("ios", None, None),
        ):
            with self.subTest(format=name):
                source = self.root / ("source-" + name)
                source.mkdir()
                nested = source / "nested/backups"
                nested.mkdir(parents=True)
                secrets = {"signal_key": secret} if secret else {}
                if name == "ios":
                    db = self.root / "ios-ChatStorage.sqlite"
                    upstream_tests.database(db, message="Nested iPhone backup message", ios=True)
                    upstream_tests.encrypted_iphone(nested / "ios-backup", db)
                    secrets = {"ios_password": "Known test password"}
                elif fixture.is_dir():
                    shutil.copytree(fixture, nested / "signal")
                else:
                    shutil.copyfile(fixture, nested / fixture.name)
                hashes = {str(p): engine.digest(p) for p in source.rglob("*") if p.is_file()}
                copied = self.root / ("copied-" + name)
                copy = subprocess.run([str(ROOT / "tests/ReviewSnapshot.exe"), str(source), str(copied)],
                                      capture_output=True, text=True, encoding="utf-8", timeout=30)
                self.assertEqual(copy.returncode, 0, copy.stdout + copy.stderr)
                manifest = json.loads((copied / "acquisition.json").read_text("utf-8-sig"))
                self.assertTrue(all(r["Status"] == "complete" for r in manifest["Files"]))
                worker = engine.Importer(copied / "snapshot", self.root / ("archive-" + name), secrets,
                                         tools_dir=ROOT / "tools")
                result = worker.run()
                self.assertIn(result["status"], {"complete", "partial"}, worker.sources)
                messages = [m for m in worker.messages if m["evidence_kind"] == "backup"]
                self.assertEqual(len(messages), 1, worker.sources)
                self.assertTrue(messages[0]["source_file"])
                self.assertTrue(messages[0].get("source_id"))
                self.assertEqual(messages[0]["timestamp"], "2001-01-01T00:00:42+00:00" if name == "ios" else "2023-11-14T22:13:20.123000+00:00")
                if name != "ios":
                    self.assertEqual(len(messages[0]["attachments"]), 1)
                    self.assertEqual((worker.output / messages[0]["attachments"][0]).read_bytes(), PHOTO)
                    self.assertTrue(any(p["status"] == "damaged_candidate" for p in worker.photos.values()))
                for value in secrets.values():
                    self.assertTrue(all(value.encode("utf-8") not in p.read_bytes()
                                        for p in worker.output.rglob("*") if p.is_file()))
                self.assertEqual(hashes, {str(p): engine.digest(p) for p in source.rglob("*") if p.is_file()})


if __name__ == "__main__":
    unittest.main(verbosity=2)
