"""Frozen Windows runtime acceptance checks, using only synthetic/public fixtures.

The fixture writer runs under the development Python environment. Every product
invocation runs the supplied EXE, without Python on PATH or Python environment
variables, in a separate working directory. No device or personal source is read.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import plistlib
import shutil
import sqlite3
import struct
import subprocess
import sys
import time
import unittest
import zipfile
import zlib

logging.disable(logging.CRITICAL)

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "tests" / "Portable-fixtures"
EXE = ROOT / "tools" / "recovery-helper" / "recovery-helper.exe"
INVOCATIONS = []
CANARY = "PORTABLE-SECRETS-NEVER-PUBLISH-6C46F0D1"
ALL_SECRETS = {CANARY}
ONLY = "all"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = load_module("portable_engine_fixtures", ROOT / "tests" / "EngineTests.py")
# Only the independent fixture writer needs cryptography. Its old helper test
# target was created for a different Python ABI; keep the 3.12 writer target
# separate from the product bundle and import it before that module's path edit.
sys.path.insert(0, str(ROOT / "tests" / "Portable-fixture-deps"))
from cryptography.hazmat.primitives.ciphers import Cipher
signal = load_module("portable_signal_fixtures", ROOT / "tests" / "SignalHelpers.Test.py")


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def tree_hashes(root):
    return {str(p.relative_to(root)): file_hash(p)
            for p in root.rglob("*") if p.is_file()}


def rows(destination):
    path = destination / "messages.jsonl"
    return [json.loads(line) for line in path.read_text("utf-8").splitlines()] if path.exists() else []


def photos(destination):
    path = destination / "photo-metadata.json"
    return json.loads(path.read_text("utf-8"))["photos"] if path.exists() else []


def codes(destination):
    path = destination / "sources.json"
    return {row.get("code") for row in json.loads(path.read_text("utf-8"))["sources"]
            if row.get("code")} if path.exists() else set()


class PortableFormats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        WORK.mkdir(exist_ok=True)
        cls.run_root = WORK / time.strftime("%Y%m%d-%H%M%S")
        cls.run_root.mkdir()

    def setUp(self):
        self.test_root = self.run_root / self._testMethodName
        self.test_root.mkdir()
        self.source = self.test_root / "source"
        self.source.mkdir()
        self.sequence = 0

    def invoke(self, secrets=None, deep=True, source=None, expected="complete"):
        source = source or self.source
        self.sequence += 1
        destination = self.test_root / ("archive-" + str(self.sequence))
        # This unused additional secret detects accidental full-request logging.
        secret_values = {"unused_canary": CANARY, **(secrets or {})}
        ALL_SECRETS.update(secret_values.values())
        request = {"protocol": 1, "operation": "scan", "source": str(source),
                   "destination": str(destination), "secrets": secret_values,
                   "options": {"deep": deep}}
        before = tree_hashes(self.source)
        env = os.environ.copy()
        env["PATH"] = str(Path(env.get("SystemRoot", r"C:\Windows")) / "System32")
        for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "PYTHONSTARTUP"):
            env.pop(name, None)
        started = time.monotonic()
        proc = subprocess.run([str(EXE)], input=(json.dumps(request) + "\n").encode("utf-8"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                              cwd=self.test_root, timeout=180,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        events = [json.loads(line) for line in proc.stdout.decode("utf-8").splitlines() if line.strip()]
        result = events[-1] if events else {}
        entry = {"test": self._testMethodName, "sequence": self.sequence,
                 "status": result.get("status"), "code": result.get("code"),
                 "messages": result.get("messages"), "photos": result.get("photos"),
                 "media": result.get("media"), "returncode": proc.returncode,
                 "elapsed_seconds": round(time.monotonic() - started, 3),
                 "source_hash_unchanged": tree_hashes(self.source) == before,
                 "stderr_empty": not proc.stderr,
                 "secret_canaries_absent": True}
        INVOCATIONS.append(entry)
        self.assertEqual(result.get("type"), "result", "Expected controlled NDJSON result")
        self.assertEqual(result.get("status"), expected, result)
        self.assertEqual(proc.returncode, 0 if expected != "error" else 2, result)
        self.assertEqual(proc.stderr, b"", "Frozen runtime must not expose upstream stderr")
        self.assertEqual(before, tree_hashes(self.source), "Source bytes changed")
        for value in secret_values.values():
            needle = value.encode("utf-8")
            leaked = needle in proc.stdout + proc.stderr
            leaked = leaked or any(needle in p.read_bytes() for p in destination.rglob("*") if p.is_file())
            entry["secret_canaries_absent"] &= not leaked
            self.assertFalse(leaked, "Secret value leaked into published result")
        if expected == "error":
            self.assertFalse((destination / "messages.jsonl").exists(), "Failed authentication published messages")
            self.assertFalse((destination / "Переписки.html").exists(), "Failed authentication published successful HTML")
            self.assertFalse((destination / "Фотографии.html").exists(), "Failed authentication published photo HTML")
            self.assertFalse(any((destination / "media").iterdir()), "Failed authentication published media")
            self.assertTrue((destination / "job.incomplete").exists())
        else:
            self.assertFalse((destination / "job.incomplete").exists())
            self.assertTrue((destination / "Переписки.html").exists())
            self.assertTrue((destination / "Фотографии.html").exists())
        return destination, result

    def test_telegram_json_html_missing_media_and_unicode(self):
        from PIL import Image
        Image.new("RGB", (48, 40), "green").save(self.source / "photo.png")
        chat = {"id": 9001, "name": "Семья", "messages": [
            {"id": 1, "from_id": "user1", "from": "Прабабушка", "date": "2026-10-12T12:30:00",
             "text": ["Рецепт ", {"type": "bold", "text": "🥧 пирожков"}], "photo": "photo.png"},
            {"id": 2, "text": "одинаковый текст"}, {"id": 3, "text": "одинаковый текст"}]}
        for name in ("result.json", "result-copy.json"):
            (self.source / name).write_text(json.dumps(chat, ensure_ascii=False), encoding="utf-8")
        (self.source / "messages.html").write_text(
            '<div class="message default clearfix" id="message42"><div class="date details" title="12.10.2026 12:30"></div>'
            '<div class="from_name">Fixture</div><div class="text">Один<br>Два<script>EXTERNAL_STEAL()</script></div>'
            '<a href="https://example.test/tracker">media</a></div>', encoding="utf-8")
        destination, result = self.invoke()
        messages = rows(destination)
        self.assertEqual(len(messages), 4)
        self.assertTrue(any(m["text"] == "Один\nДва" for m in messages))
        self.assertEqual(sum(m["text"] == "одинаковый текст" for m in messages), 2)
        self.assertTrue(next(m for m in messages if str(m["message_id"]) == "1")["attachments"])
        con = sqlite3.connect(destination / "chat-index.sqlite")
        self.assertEqual(con.execute("SELECT count(*) FROM search WHERE search MATCH 'пирожков'").fetchone()[0], 1)
        con.close()
        markup = (destination / "Переписки.html").read_text("utf-8")
        self.assertNotIn("EXTERNAL_STEAL", markup)
        self.assertNotIn("example.test/tracker", markup)
        self.assertIn("connect-src 'none'", markup)
        # Missing local media is explicit and does not manufacture an attachment.
        (self.source / "missing.json").write_text(json.dumps({"id": 8001, "type": "personal_chat", "messages": [
            {"id": 4, "text": "Missing attachment", "photo": "missing.png"}]}), encoding="utf-8")
        destination, result = self.invoke(expected="partial")
        self.assertFalse(next(m for m in rows(destination) if m["text"] == "Missing attachment")["attachments"])
        self.assertTrue(any("ATTACHMENT" in code for code in codes(destination)))

    def test_whatsapp_txt_zip_multiline_ambiguous_dates_safe_attachment(self):
        with zipfile.ZipFile(self.source / "chat.zip", "w") as archive:
            archive.writestr("_chat.txt", "01/02/2026, 12:30 - Alice: Первая строка\nвторая 🥧\n"
                             "01/02/2026, 12:31 - Alice: повтор\n01/02/2026, 12:31 - Alice: повтор\n"
                             "2026-10-12, 13:00 - Alice: <attached: attached.html>")
            archive.writestr("attached.html", "<script>DO_NOT_EXECUTE_ATTACHMENT()</script>")
        destination, result = self.invoke()
        messages = rows(destination)
        self.assertEqual(len(messages), 4)
        self.assertIn("вторая 🥧", messages[0]["text"])
        self.assertIsNone(messages[0]["timestamp"])
        self.assertTrue(messages[0]["timestamp_ambiguous"])
        self.assertEqual(sum(m["text"] == "повтор" for m in messages), 2)
        self.assertTrue(messages[-1]["attachments"][0].endswith(".bin"))
        self.assertNotIn("DO_NOT_EXECUTE_ATTACHMENT", (destination / "Переписки.html").read_text("utf-8"))
        with zipfile.ZipFile(self.source / "unsafe.zip", "w") as archive:
            archive.writestr("../escape.txt", "forbidden")
        with zipfile.ZipFile(self.source / "symlink.zip", "w") as archive:
            item = zipfile.ZipInfo("link")
            item.external_attr = 0o120777 << 16
            archive.writestr(item, "/private")
        destination, result = self.invoke(expected="partial")
        self.assertIn("UNSAFE_PATH", codes(destination))
        self.assertIn("UNSAFE_ZIP", codes(destination))
        self.assertFalse((self.test_root / "escape.txt").exists())

    def test_plain_whatsapp_sqlite_schemas_and_confirmed_media(self):
        fixtures.database(self.source / "legacy.db", message="Legacy recipe")
        fixtures.database(self.source / "modern.db", message="Modern recipe", modern=True)
        fixtures.database(self.source / "ChatStorage.sqlite", message="iOS recipe", ios=True)
        (self.source / "Media").mkdir()
        (self.source / "Media" / "picture.png").write_bytes(signal.PHOTO)
        con = sqlite3.connect(self.source / "modern.db")
        con.execute("CREATE TABLE message_media(message_row_id INTEGER,file_path TEXT)")
        con.execute("INSERT INTO message_media VALUES(1,'Media/picture.png')")
        con.commit()
        con.close()
        # Public fixture photo intentionally has a bad CRC; media relation must
        # survive while the image candidate is honestly marked damaged.
        destination, result = self.invoke(deep=False, expected="partial")
        self.assertEqual({m["text"] for m in rows(destination)}, {"Legacy recipe", "Modern recipe", "iOS recipe"})
        attached = next(m for m in rows(destination) if m["text"] == "Modern recipe")["attachments"]
        self.assertEqual(len(attached), 1)
        self.assertEqual((destination / attached[0]).read_bytes(), signal.PHOTO)

    def test_sqlite_wal_and_unknown_free_page_fragments(self):
        database = self.source / "msgstore.db"
        fixtures.database(database, message="base recipe")
        active = self.test_root / "active.db"
        shutil.copyfile(database, active)
        con = sqlite3.connect(active)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("UPDATE messages SET data='previous recipe'")
        con.commit()
        con.execute("UPDATE messages SET data='current recipe'")
        con.commit()
        wal = Path(str(database) + "-wal")
        wal.write_bytes(Path(str(active) + "-wal").read_bytes())
        con.close()
        destination, result = self.invoke()
        messages = rows(destination)
        self.assertTrue(any(m["text"] == "current recipe" and m["evidence_kind"] == "backup" for m in messages))
        self.assertTrue(any(m["text"] == "previous recipe" and m["evidence_kind"] == "previous" for m in messages))
        bad = bytearray(wal.read_bytes())
        bad[-1] ^= 1
        wal.write_bytes(bad)
        con = sqlite3.connect(self.source / "unknown.db")
        con.execute("PRAGMA page_size=65536")
        con.execute("PRAGMA secure_delete=OFF")
        con.execute("CREATE TABLE notes(text)")
        for n in range(60):
            con.execute("INSERT INTO notes VALUES(?)", (f"Historical recipe {n}: " + "прабабушка пирожки " * 500,))
        con.commit()
        con.execute("DELETE FROM notes")
        con.commit()
        con.close()
        destination, result = self.invoke(expected="partial")
        self.assertIn("WAL_CHECKSUM_INVALID", codes(destination))
        fragments = [m for m in rows(destination) if m["evidence_kind"] == "fragment"]
        self.assertTrue(fragments)
        self.assertTrue(all(m["chat_id"] is None and m["sender_id"] is None and m["timestamp"] is None for m in fragments))

    def test_whatsapp_crypt12_crypt14_crypt15_known_key_wrong_key_and_mac(self):
        from wa_crypt_tools.lib.db.db12 import Database12
        from wa_crypt_tools.lib.db.db14 import Database14
        from wa_crypt_tools.lib.db.db15 import Database15
        from wa_crypt_tools.lib.key.key14 import Key14
        from wa_crypt_tools.lib.key.key15 import Key15
        from wa_crypt_tools.lib.props import Props
        plain = self.test_root / "plain.db"
        fixtures.database(plain, message="Authenticated encrypted recipe")
        props = Props(wa_version="2.22.5.13", jid="67", backup_version=0)
        k14 = Key14(key=b"k" * 32, serversalt=b"s" * 32, googleid=b"g" * 16)
        k15 = Key15(keyarray=b"x" * 32)
        for kind, klass, key in ((12, Database12, k14), (14, Database14, k14), (15, Database15, k15)):
            with self.subTest(format=kind):
                directory = self.source / str(kind)
                directory.mkdir()
                obj = klass(key=key) if kind == 12 else klass(iv=bytes(range(16)))
                encrypted = obj.encrypt(key, props, zlib.compress(plain.read_bytes()))
                path = directory / f"msgstore.db.crypt{kind}"
                path.write_bytes(encrypted)
                secret = (key.get_root() if kind == 15 else key.get_cipher_version() + key.get_key_version() + key.get_serversalt()
                          + key.get_googleid() + key._Key14__hashedgoogleid + b"\x00" * 16 + key.get()).hex()
                destination, result = self.invoke({"whatsapp_key": secret}, deep=False, source=directory)
                self.assertEqual([m["text"] for m in rows(destination)], ["Authenticated encrypted recipe"])
                destination, result = self.invoke({"whatsapp_key": "42" * 32}, deep=False, source=directory, expected="error")
                self.assertIn("WHATSAPP_AUTHENTICATION_FAILED", codes(destination))
                bad = bytearray(encrypted)
                bad[-38] ^= 1
                path.write_bytes(bad)
                destination, result = self.invoke({"whatsapp_key": secret}, deep=False, source=directory, expected="error")
                self.assertIn("WHATSAPP_AUTHENTICATION_FAILED", codes(destination))

    def test_whatsapp_upstream_known_samples_match_plain_database(self):
        public = ROOT / "vendor" / "wa-crypt-tools" / "tests" / "res"
        plain_root = self.source / "plain"
        plain_root.mkdir()
        shutil.copyfile(public / "msgstore.db", plain_root / "msgstore.db")
        destination, result = self.invoke(deep=False, source=plain_root)
        baseline = sorted((m["app"], m["text"], str(m["chat_id"]), str(m["message_id"]), str(m["timestamp"])) for m in rows(destination))
        self.assertTrue(baseline, "Published upstream fixture must have known message records")
        for version, keyfile in ((12, "key"), (14, "key"), (15, "encrypted_backup.key")):
            with self.subTest(format=version):
                directory = self.source / str(version)
                directory.mkdir()
                shutil.copyfile(public / f"msgstore.db.crypt{version}", directory / f"msgstore.db.crypt{version}")
                destination, result = self.invoke({"whatsapp_key": (public / keyfile).read_bytes().hex()}, deep=False, source=directory)
                imported = sorted((m["app"], m["text"], str(m["chat_id"]), str(m["message_id"]), str(m["timestamp"])) for m in rows(destination))
                self.assertEqual(imported, baseline)

    def test_iphone_unencrypted_encrypted_good_password_wrong_password_and_digest(self):
        plain = self.test_root / "ChatStorage.sqlite"
        fixtures.database(plain, message="iPhone authenticated recipe", ios=True)
        backup = self.source / "encrypted-ios"
        secret = "Portable known password 7FFB7189"
        encrypted_file = fixtures.encrypted_iphone(backup, plain, password=secret)
        destination, result = self.invoke({"ios_password": secret}, deep=False, source=backup)
        self.assertEqual([m["text"] for m in rows(destination)], ["iPhone authenticated recipe"])
        destination, result = self.invoke({"ios_password": "Wrong password 101E4428"}, deep=False, source=backup, expected="error")
        self.assertIn("IOS_PASSWORD_INCORRECT", codes(destination))
        bad = bytearray(encrypted_file.read_bytes())
        bad[64] ^= 1
        encrypted_file.write_bytes(bad)
        destination, result = self.invoke({"ios_password": secret}, deep=False, source=backup, expected="error")
        self.assertIn("IOS_FILE_DIGEST_MISMATCH", codes(destination))
        unencrypted = self.source / "unencrypted-ios"
        unencrypted.mkdir()
        (unencrypted / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
        fid = hashlib.sha1(b"AppDomain-test-Library/ChatStorage.sqlite").hexdigest()
        (unencrypted / fid[:2]).mkdir()
        (unencrypted / fid[:2] / fid).write_bytes(plain.read_bytes())
        con = sqlite3.connect(unencrypted / "Manifest.db")
        con.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, "AppDomain-test", "Library/ChatStorage.sqlite", 1, b""))
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, "AppDomain-test", "../../escape", 1, b""))
        con.commit()
        con.close()
        destination, result = self.invoke(deep=False, source=unencrypted, expected="partial")
        self.assertEqual([m["text"] for m in rows(destination)], ["iPhone authenticated recipe"])
        self.assertIn("IOS_UNSAFE_PATH", codes(destination))

    def test_images_webp_heif_no_extension_embedded_thumbnail_damaged_duplicates(self):
        from PIL import Image
        import pillow_heif
        pillow_heif.register_heif_opener()
        png = io.BytesIO()
        Image.new("RGB", (48, 40), "blue").save(png, "PNG")
        (self.source / "no-extension").write_bytes(png.getvalue())
        (self.source / "container.cache").write_bytes(b"metadata\x00" + png.getvalue() + b"tail")
        Image.new("RGB", (36, 28), "red").save(self.source / "webp-no-suffix", "WEBP")
        Image.new("RGB", (24, 24), "green").save(self.source / "heif-no-suffix", "HEIF")
        small, large = io.BytesIO(), io.BytesIO()
        Image.new("RGB", (16, 16), "yellow").save(small, "JPEG")
        Image.new("RGB", (400, 360), "red").save(large, "JPEG")
        payload = b"Exif\0\0opaque thumbnail metadata" + small.getvalue()
        photo = large.getvalue()[:2] + b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload + large.getvalue()[2:]
        (self.source / "jpeg-with-thumbnail").write_bytes(photo)
        destination, result = self.invoke()
        catalog = photos(destination)
        self.assertEqual(len(catalog), 5)
        self.assertEqual({p["format"] for p in catalog}, {"PNG", "WEBP", "HEIF", "JPEG"})
        self.assertTrue(all(p["status"] == "decoded" for p in catalog))
        self.assertTrue(any(len(p["sources"]) > 1 for p in catalog))
        self.assertTrue(any(p["kind"] == "embedded" for p in catalog))
        for p in catalog:
            self.assertTrue((destination / p["thumbnail"]).exists())
            self.assertEqual(file_hash(destination / p["path"]), p["sha256"])
        bad = bytearray(png.getvalue())
        bad[-5] ^= 1
        (self.source / "damaged-no-suffix").write_bytes(bad)
        destination, result = self.invoke(expected="partial")
        damaged = [p for p in photos(destination) if p["status"] == "damaged_candidate"]
        self.assertEqual(len(damaged), 1)
        self.assertIsNone(damaged[0]["thumbnail"])

    def test_acquisition_manifest_verified_origin_and_partial_exclusion(self):
        snapshot = self.source / "snapshot"
        snapshot.mkdir()
        good = snapshot / "good.json"
        good.write_text(json.dumps({"id": "chat", "type": "personal_chat", "messages": [{"id": 1, "text": "Verified origin"}]}), encoding="utf-8")
        (snapshot / "stale.json").write_text(json.dumps({"id": "stale", "messages": [{"id": 2, "text": "Not acquired"}]}), encoding="utf-8")
        (snapshot / "partial.json.partial").write_text("incomplete", encoding="utf-8")
        (self.source / "acquisition.json").write_text(json.dumps({"Files": [
            {"Id": "phone-object-42", "RelativePath": "original.json", "OriginalPath": "phone/DCIM/original.json",
             "Status": "complete", "LocalPath": "snapshot/good.json", "Sha256": file_hash(good)},
            {"Id": "unfinished", "OriginalPath": "phone/unfinished", "Status": "copying", "LocalPath": "snapshot/partial.json.partial"}
        ]}), encoding="utf-8")
        destination, result = self.invoke(source=snapshot, expected="partial")
        messages = rows(destination)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["source_id"], "phone-object-42")
        self.assertEqual(messages[0]["source_file"], "phone/DCIM/original.json")

    def test_signal_legacy_v0_v1_good_key_bad_key_and_authentication(self):
        for version in (0, 1):
            with self.subTest(version=version):
                directory = self.source / str(version)
                directory.mkdir()
                backup = directory / f"legacy-v{version}.backup"
                signal.make_legacy(backup, version)
                destination, result = self.invoke({"signal_key": signal.LEGACY_SECRET}, deep=False, source=directory, expected="partial")
                self.assertEqual([m["text"] for m in rows(destination)], [signal.TEXT])
                message = rows(destination)[0]
                self.assertEqual(message["sender_name"], "Fixture Grandmother")
                self.assertEqual((destination / message["attachments"][0]).read_bytes(), signal.PHOTO)
                destination, result = self.invoke({"signal_key": "9" * 30}, deep=False, source=directory, expected="error")
                self.assertIn("SIGNAL_AUTHENTICATION_FAILED", codes(destination))
                damaged = bytearray(backup.read_bytes())
                damaged[-1] ^= 1
                backup.write_bytes(damaged)
                destination, result = self.invoke({"signal_key": signal.LEGACY_SECRET}, deep=False, source=directory, expected="error")
                self.assertIn("SIGNAL_AUTHENTICATION_FAILED", codes(destination))

    def test_signal_modern_multi_snapshot_shared_media_wrong_key_mac_version(self):
        from Crypto.Cipher import AES
        import hmac
        root = self.source / "modern"
        first = signal.make_modern(root)
        second = root / "signal-backup-second-independent-snapshot"
        shutil.copytree(first, second)
        backup_key = signal.hkdf(signal.MODERN_SECRET.encode(), b"20240801_SIGNAL_BACKUP_KEY", 32)
        keys = signal.hkdf(backup_key, b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:" + b"B" * 16, 64)
        raw = (first / "main").read_bytes()
        plaintext = AES.new(keys[32:], AES.MODE_CBC, raw[:16]).decrypt(raw[16:-32])
        iv = b"J" * 16
        encrypted = iv + AES.new(keys[32:], AES.MODE_CBC, iv).encrypt(plaintext)
        (second / "main").write_bytes(encrypted + hmac.new(keys[:32], encrypted, hashlib.sha256).digest())
        destination, result = self.invoke({"signal_key": signal.MODERN_SECRET}, deep=False, source=root, expected="partial")
        messages = rows(destination)
        self.assertEqual(len(messages), 2)
        self.assertEqual(len({m["snapshot_id"] for m in messages}), 2)
        self.assertTrue(all(m["message_id"] is None for m in messages))
        self.assertEqual(len({m["attachments"][0] for m in messages}), 1)
        self.assertTrue(all((destination / m["attachments"][0]).read_bytes() == signal.PHOTO for m in messages))
        destination, result = self.invoke({"signal_key": "n" * 64}, deep=False, source=root, expected="error")
        self.assertIn("SIGNAL_AUTHENTICATION_FAILED", codes(destination))
        badroot = self.source / "bad-main"
        shutil.copytree(root, badroot)
        for snapshot in (p for p in badroot.iterdir() if (p / "main").is_file()):
            bad = bytearray((snapshot / "main").read_bytes())
            bad[-1] ^= 1
            (snapshot / "main").write_bytes(bad)
        destination, result = self.invoke({"signal_key": signal.MODERN_SECRET}, deep=False, source=badroot, expected="error")
        self.assertIn("SIGNAL_AUTHENTICATION_FAILED", codes(destination))
        mediaroot = self.source / "bad-media"
        shutil.copytree(root, mediaroot)
        media = next(p for p in (mediaroot / "files").rglob("*") if p.is_file())
        bad = bytearray(media.read_bytes())
        bad[-1] ^= 1
        media.write_bytes(bad)
        destination, result = self.invoke({"signal_key": signal.MODERN_SECRET}, deep=False, source=mediaroot, expected="partial")
        self.assertEqual(len(rows(destination)), 2)
        self.assertTrue(all(not m["attachments"] for m in rows(destination)))
        self.assertEqual(result["media"], 0)
        future = self.source / "future"
        signal.make_modern(future, metadata_version=2)
        destination, result = self.invoke({"signal_key": signal.MODERN_SECRET}, deep=False, source=future, expected="error")
        self.assertIn("SIGNAL_VERSION_UNSUPPORTED", codes(destination))

    def test_signal_modern_official_crypto_reference_fixture(self):
        import hmac
        upstream = ROOT / "vendor" / "signal-libsignal" / "libsignal-4beb029d8a941f81e7d9c6d8af1ed25a677569a8"
        original = upstream / "rust" / "message-backup" / "tests" / "res" / "test-cases" / "valid-encrypted" / "legacy-account.binproto.encrypted"
        root = self.source / "official"
        snapshot = root / "signal-backup-official-reference"
        snapshot.mkdir(parents=True)
        (root / "files").mkdir()
        backup_key = signal.hkdf(signal.MODERN_SECRET.encode(), b"20240801_SIGNAL_BACKUP_KEY", 32)
        encrypted = original.read_bytes()
        selected = None
        for aci in (b"\x11" * 16, b"\x00" + b"\x11" * 16):
            backup_id = signal.hkdf(backup_key, b"20241024_SIGNAL_BACKUP_ID:" + aci, 16)
            keys = signal.hkdf(backup_key, b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:" + backup_id, 64)
            if hmac.compare_digest(hmac.new(keys[:32], encrypted[:-32], hashlib.sha256).digest(), encrypted[-32:]):
                selected = backup_id
                break
        self.assertIsNotNone(selected, "Official reference must match its independently verified published key vectors")
        metadata_key = signal.hkdf(backup_key, b"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY", 32)
        iv = b"O" * 12
        (snapshot / "metadata").write_bytes(signal.p(1, 1) + signal.p(2, signal.p(1, iv) + signal.p(2, signal.ctr(metadata_key, iv + b"\0" * 4, selected))))
        shutil.copyfile(original, snapshot / "main")
        destination, result = self.invoke({"signal_key": signal.MODERN_SECRET}, deep=False, source=root)
        self.assertEqual(result["messages"], 0)
        self.assertNotIn("SIGNAL_AUTHENTICATION_FAILED", codes(destination))


def main():
    global EXE, ONLY
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, default=EXE)
    parser.add_argument("--only", choices=("all", "without-signal", "signal"), default="all")
    args = parser.parse_args()
    EXE, ONLY = args.exe.resolve(), args.only
    if not EXE.is_file():
        raise SystemExit("Portable executable not found")
    tests = unittest.defaultTestLoader.loadTestsFromTestCase(PortableFormats)
    selected = unittest.TestSuite(t for t in tests if ONLY == "all"
                                 or ("signal_" in t._testMethodName) == (ONLY == "signal"))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(selected)
    text = stream.getvalue()
    for secret in sorted(ALL_SECRETS, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED TEST SECRET]")
    native = EXE.parent.parent / "signal"
    summary = {"protocol": 1, "date": "2026-10-13", "exe": str(EXE), "exe_sha256": file_hash(EXE),
               "native_helpers": {p.name: file_hash(p) for p in native.glob("*.exe")},
               "restricted_path": r"C:\Windows\System32", "python_environment_removed": True,
               "network_policy": "No product network APIs used; external offline enforcement is a separate release check",
               "fixtures": "Synthetic independent Signal/iOS writers and pinned public WhatsApp reference samples",
               "tests_run": result.testsRun, "successful": result.wasSuccessful(),
               "failure_count": len(result.failures), "error_count": len(result.errors),
               "physical_devices_tested": False, "invocations": INVOCATIONS}
    prefix = "PortableFormats" if ONLY == "all" else "PortableFormats-" + ONLY
    (ROOT / "tests" / (prefix + ".result.txt")).write_text(text, encoding="utf-8")
    (ROOT / "tests" / (prefix + ".result.json")).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(text)
    print(f"Frozen invocations: {len(INVOCATIONS)}; results saved to tests/{prefix}.result.json")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
