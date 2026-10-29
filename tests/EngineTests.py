"""Synthetic and independent-format regression tests; no personal source data."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("engine", ROOT / "helpers/recovery_engine/engine.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
engine.emit = lambda *a, **kw: None


def database(path, message="Synthetic family recipe", modern=False, ios=False):
    con = sqlite3.connect(path)
    if ios:
        con.executescript("CREATE TABLE ZWACHATSESSION(Z_PK INTEGER PRIMARY KEY,ZCONTACTJID TEXT);"
                          "CREATE TABLE ZWAMESSAGE(Z_PK INTEGER PRIMARY KEY,ZCHATSESSION INTEGER,ZTEXT TEXT,ZMESSAGEDATE REAL,ZSTANZAID TEXT,ZFROMJID TEXT,ZISFROMME INTEGER);")
        con.execute("INSERT INTO ZWACHATSESSION VALUES(1,'family@example.test')")
        con.execute("INSERT INTO ZWAMESSAGE VALUES(1,1,?,42,'confirmed-key','author@example.test',0)", (message,))
    elif modern:
        con.executescript("CREATE TABLE jid(_id INTEGER PRIMARY KEY,raw_string TEXT);"
                          "CREATE TABLE chat(_id INTEGER PRIMARY KEY,jid_row_id INTEGER);"
                          "CREATE TABLE message(_id INTEGER PRIMARY KEY,chat_row_id INTEGER,sender_jid_row_id INTEGER,text_data TEXT,timestamp INTEGER,key_id TEXT,from_me INTEGER);")
        con.execute("INSERT INTO jid VALUES(1,'family@example.test')")
        con.execute("INSERT INTO chat VALUES(1,1)")
        con.execute("INSERT INTO message VALUES(1,1,1,?,1700000000000,'confirmed-key',0)", (message,))
    else:
        con.execute("CREATE TABLE messages(_id INTEGER PRIMARY KEY,key_remote_jid TEXT,remote_resource TEXT,timestamp INTEGER,data TEXT,key_id TEXT,key_from_me INTEGER)")
        con.execute("INSERT INTO messages VALUES(1,'family@example.test','author@example.test',1700000000000,?,'confirmed-key',0)", (message,))
    con.commit()
    con.close()


def encrypted_iphone(root, message_path, password="Known test password"):
    """Independent RFC3394 + AES-CBC fixture, without the reader's encoder."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    root.mkdir(exist_ok=True)
    salt, dpsl = b"s" * 20, b"d" * 20
    first = hashlib.pbkdf2_hmac("sha256", password.encode(), dpsl, 1, 32)
    outer = hashlib.pbkdf2_hmac("sha1", first, salt, 1, 32)
    class_key, manifest_key, file_key = b"c" * 32, b"m" * 32, b"f" * 32
    def wrap(key, data):
        return AES.new(key, AES.MODE_KW).seal(data)
    def tlv(tag, value):
        if isinstance(value, int):
            value = struct.pack(">I", value)
        return tag.encode() + struct.pack(">I", len(value)) + value
    keybag = b"".join(tlv(tag, value) for tag, value in (
        ("TYPE", 1), ("UUID", b"u" * 16), ("WRAP", 2), ("DPSL", dpsl), ("DPIC", 1),
        ("SALT", salt), ("ITER", 1), ("UUID", b"v" * 16), ("CLAS", 1), ("WRAP", 2),
        ("WPKY", wrap(outer, class_key))))
    content = message_path.read_bytes()
    meta = {"$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": plistlib.UID(1)},
            "$objects": ["$null", {"Size": len(content), "Mode": 0o100600, "ProtectionClass": 1,
                                   "EncryptionKey": plistlib.UID(2), "Digest": plistlib.UID(3)},
                         {"NS.data": struct.pack("<I", 1) + wrap(class_key, file_key)},
                         {"NS.data": hashlib.sha1(content).digest()}]}
    domain, relative = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"
    fileid = hashlib.sha1(f"{domain}-{relative}".encode()).hexdigest()
    (root / fileid[:2]).mkdir(exist_ok=True)
    (root / fileid[:2] / fileid).write_bytes(AES.new(file_key, AES.MODE_CBC, iv=b"\0" * 16).encrypt(pad(content, 16)))
    plain_manifest = root.parent / "fixture-manifest.db"
    con = sqlite3.connect(plain_manifest)
    con.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
    con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fileid, domain, relative, 1, plistlib.dumps(meta, fmt=plistlib.FMT_BINARY)))
    con.commit()
    con.close()
    (root / "Manifest.db").write_bytes(AES.new(manifest_key, AES.MODE_CBC, iv=b"\0" * 16).encrypt(pad(plain_manifest.read_bytes(), 16)))
    plain_manifest.unlink()
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True, "BackupKeyBag": keybag,
                                                         "ManifestKey": struct.pack("<I", 1) + wrap(class_key, manifest_key)}))
    (root / "Info.plist").write_bytes(plistlib.dumps({"Product Version": "17.0"}))
    return root / fileid[:2] / fileid


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="engine-tests-")
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "result"

    def tearDown(self):
        self.tmp.cleanup()

    def run_import(self, secrets=None, deep=True, expected="complete"):
        hashes = {str(p): engine.digest(p) for p in self.source.rglob("*") if p.is_file()}
        worker = engine.Importer(self.source, self.destination, secrets, deep)
        result = worker.run()
        self.assertEqual(result["status"], expected, worker.sources)
        self.assertEqual(hashes, {str(p): engine.digest(p) for p in self.source.rglob("*") if p.is_file()})
        self.assertEqual((self.destination / "job.incomplete").exists(), expected == "error")
        return worker

    def test_telegram_json_unicode_attachments_ids_and_no_text_dedup(self):
        from PIL import Image
        Image.new("RGB", (25, 20), "red").save(self.source / "photo.jpg")
        chat = {"id": 9001, "name": "Семья", "messages": [
            {"id": 1, "from_id": "user1", "from": "Бабушка", "date": "2026-10-11T12:30:00",
             "text": ["Привет ", {"type": "bold", "text": "🥧 пирожки"}], "photo": "photo.jpg"},
            {"id": 2, "text": "повтор"}, {"id": 3, "text": "повтор"}]}
        (self.source / "result.json").write_text(json.dumps(chat, ensure_ascii=False), encoding="utf-8")
        (self.source / "result-copy.json").write_text(json.dumps(chat, ensure_ascii=False), encoding="utf-8")
        worker = self.run_import()
        self.assertEqual(len(worker.messages), 3)
        self.assertEqual(worker.messages[0]["text"], "Привет 🥧 пирожки")
        self.assertTrue(worker.messages[0]["attachments"])
        self.assertEqual(len(worker.photos), 1)
        con = sqlite3.connect(self.destination / "chat-index.sqlite")
        self.assertEqual(con.execute("SELECT count(*) FROM search WHERE search MATCH 'пирожки'").fetchone()[0], 1)
        con.close()

    def test_telegram_html_is_data_and_javascript_is_not_copied(self):
        text = '<div class="message default clearfix" id="message42"><div class="date details" title="11.10.2026 12:30"></div><div class="from_name">Alice</div><div class="text">One<br>Two<script>stealEverything()</script></div><a href="https://example.test/tracker">media</a></div>'
        (self.source / "messages.html").write_text(text, encoding="utf-8")
        worker = self.run_import()
        self.assertEqual(len(worker.messages), 1)
        self.assertEqual(worker.messages[0]["text"], "One\nTwo")
        self.assertEqual(worker.messages[0]["message_id"], "42")
        result = (self.destination / "Переписки.html").read_text(encoding="utf-8")
        self.assertNotIn("stealEverything", result)
        self.assertNotIn("example.test/tracker", result)

    def test_whatsapp_text_multiline_ambiguous_and_known_date(self):
        (self.source / "chat.txt").write_text("01/02/2026, 12:30 - Alice: Первая строка\nвторая 🥧\n01/02/2026, 12:31 - Alice: повтор\n01/02/2026, 12:31 - Alice: повтор", encoding="utf-8")
        worker = self.run_import()
        self.assertEqual(len(worker.messages), 3)
        self.assertIn("вторая 🥧", worker.messages[0]["text"])
        self.assertIsNone(worker.messages[0]["timestamp"])
        self.assertTrue(worker.messages[0]["timestamp_ambiguous"])
        self.assertIsNone(worker.messages[0]["message_id"])
        (self.source / "chat-known.txt").write_text("[31.12.2025, 11:59 PM] Alice: last day\n[01.01.2026, 00:01] Alice: next", encoding="utf-8")
        self.destination = self.root / "result2"
        worker = self.run_import()
        known = [m for m in worker.messages if m.get("chat_name") == "chat-known"]
        self.assertEqual(known[0]["timestamp"], "2025-12-31T23:59:00")

    def test_sqlite_legacy_modern_ios_adapters(self):
        database(self.source / "legacy.db")
        database(self.source / "modern.db", modern=True)
        database(self.source / "ChatStorage.sqlite", ios=True)
        worker = self.run_import(deep=False)
        # Confirmed same Android key deduplicates; distinct iOS timestamp remains.
        self.assertEqual(len(worker.messages), 3)
        self.assertTrue(all(m["app"] == "WhatsApp" for m in worker.messages))
        self.assertTrue(all(m["message_id"] == "confirmed-key" for m in worker.messages))
        self.assertTrue(all(m["evidence_kind"] == "backup" for m in worker.messages))

    def test_wal_committed_previous_version_and_tampered_checksum(self):
        db = self.source / "msgstore.db"
        database(db, "base")
        active = self.root / "active.db"
        active.write_bytes(db.read_bytes())
        con = sqlite3.connect(active)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("UPDATE messages SET data='previous version'")
        con.commit()
        con.execute("UPDATE messages SET data='current version'")
        con.commit()
        Path(str(db) + "-wal").write_bytes(Path(str(active) + "-wal").read_bytes())
        con.close()
        worker = self.run_import()
        self.assertTrue(any(m["text"] == "current version" and m["evidence_kind"] == "backup" for m in worker.messages))
        self.assertTrue(any(m["text"] == "previous version" and m["evidence_kind"] == "previous" for m in worker.messages))
        wal = Path(str(db) + "-wal")
        bad = bytearray(wal.read_bytes())
        bad[-1] ^= 1
        wal.write_bytes(bad)
        self.destination = self.root / "result-bad"
        worker = self.run_import(expected="partial")
        self.assertTrue(any(x.get("code") == "WAL_CHECKSUM_INVALID" for x in worker.sources))

    def test_free_pages_are_fragments_with_unknown_relationships(self):
        db = self.source / "unknown.db"
        con = sqlite3.connect(db)
        con.execute("PRAGMA secure_delete=OFF")
        con.execute("CREATE TABLE notes(text)")
        for n in range(40):
            con.execute("INSERT INTO notes VALUES(?)", (f"Deleted text specimen {n} " + "Бабушкин рецепт " * 300,))
        con.commit()
        con.execute("DELETE FROM notes")
        con.commit()
        con.close()
        worker = self.run_import()
        self.assertTrue(worker.messages)
        self.assertTrue(all(m["evidence_kind"] == "fragment" for m in worker.messages))
        self.assertTrue(all(m["chat_id"] is None and m["sender_id"] is None and m["timestamp"] is None for m in worker.messages))

    def test_images_without_extension_embedded_webp_heif_and_duplicates(self):
        from PIL import Image
        import pillow_heif
        pillow_heif.register_heif_opener()
        png = io.BytesIO()
        Image.new("RGB", (48, 40), "blue").save(png, "PNG")
        (self.source / "unknown-cache").write_bytes(png.getvalue())
        (self.source / "container.bin").write_bytes(b"container metadata\x00" + png.getvalue() + b"tail")
        Image.new("RGB", (36, 28), "red").save(self.source / "webp-cache", "WEBP")
        Image.new("RGB", (24, 24), "green").save(self.source / "heif-cache", "HEIF")
        worker = self.run_import()
        self.assertEqual(len(worker.photos), 3)
        self.assertEqual({p["format"] for p in worker.photos.values()}, {"PNG", "WEBP", "HEIF"})
        self.assertTrue(any(len(p["sources"]) > 1 for p in worker.photos.values()))
        self.assertTrue(all(p["status"] == "decoded" for p in worker.photos.values()))

    def test_zip_traversal_symlink_and_external_attachments_rejected(self):
        with zipfile.ZipFile(self.source / "attack.zip", "w") as z:
            z.writestr("../escape.txt", "not allowed")
        with zipfile.ZipFile(self.source / "symlink.zip", "w") as z:
            item = zipfile.ZipInfo("link")
            item.external_attr = (0o120777 << 16)
            z.writestr(item, "/private")
        worker = self.run_import(expected="partial")
        self.assertTrue(any(x.get("code") == "UNSAFE_PATH" for x in worker.sources))
        self.assertTrue(any(x.get("code") == "UNSAFE_ZIP" for x in worker.sources))
        self.assertFalse((self.root / "escape.txt").exists())

    def test_whatsapp_crypto_all_formats_reject_wrong_key_and_tampering(self):
        from wa_crypt_tools.lib.db.db12 import Database12
        from wa_crypt_tools.lib.db.db14 import Database14
        from wa_crypt_tools.lib.db.db15 import Database15
        from wa_crypt_tools.lib.key.key14 import Key14
        from wa_crypt_tools.lib.key.key15 import Key15
        from wa_crypt_tools.lib.props import Props
        plain = self.root / "plain.db"
        database(plain)
        props = Props(wa_version="2.22.5.13", jid="67", backup_version=0)
        k14 = Key14(key=b"k" * 32, serversalt=b"s" * 32, googleid=b"g" * 16)
        k15 = Key15(keyarray=b"x" * 32)
        # Reference fixture files from pinned upstream tests complement the
        # generated roundtrips below and exercise their independent samples.
        for kind, klass, key in ((12, Database12, k14), (14, Database14, k14), (15, Database15, k15)):
            with self.subTest(format=kind):
                for p in self.source.iterdir():
                    p.unlink()
                obj = klass(key=key) if kind == 12 else klass(iv=bytes(range(16)))
                encrypted = obj.encrypt(key, props, zlib.compress(plain.read_bytes()))
                p = self.source / f"msgstore.db.crypt{kind}"
                p.write_bytes(encrypted)
                secret = (key.get_root() if kind == 15 else key.get_cipher_version() + key.get_key_version() + key.get_serversalt() + key.get_googleid() + key._Key14__hashedgoogleid + b"\x00"*16 + key.get()).hex()
                self.destination = self.root / f"crypto-{kind}"
                worker = self.run_import({"whatsapp_key": secret}, deep=False)
                self.assertEqual(len(worker.messages), 1)
                self.destination = self.root / f"wrong-{kind}"
                worker = self.run_import({"whatsapp_key": "42" * 32}, deep=False, expected="error")
                self.assertEqual(len(worker.messages), 0)
                self.assertFalse((self.destination / "Переписки.html").exists())
                bad = bytearray(encrypted)
                bad[-38] ^= 1
                p.write_bytes(bad)
                self.destination = self.root / f"corrupt-{kind}"
                worker = self.run_import({"whatsapp_key": secret}, deep=False, expected="error")
                self.assertEqual(len(worker.messages), 0)
                self.assertFalse(secret in (self.destination / "sources.json").read_text(encoding="utf-8"))

    def test_unencrypted_iphone_manifest_safe_extraction(self):
        backup = self.source
        (backup / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
        message = self.root / "ChatStorage.sqlite"
        database(message, ios=True)
        fid = hashlib.sha1(b"AppDomain-test-Library/ChatStorage.sqlite").hexdigest()
        (backup / fid[:2]).mkdir()
        (backup / fid[:2] / fid).write_bytes(message.read_bytes())
        con = sqlite3.connect(backup / "Manifest.db")
        con.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, "AppDomain-test", "Library/ChatStorage.sqlite", 1, b""))
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, "AppDomain-test", "../../escape", 1, b""))
        con.commit()
        con.close()
        worker = self.run_import(deep=False, expected="partial")
        self.assertEqual(len(worker.messages), 1)
        self.assertTrue(any(x.get("code") == "IOS_UNSAFE_PATH" for x in worker.sources))

    def test_protocol_no_secret_output_and_nonempty_destination_rejected(self):
        request = {"protocol": 1, "operation": "scan", "source": str(self.source), "destination": str(self.destination),
                   "secrets": {"ios_password": "TEST-SENTINEL-SECRET"}}
        completed = subprocess.run([sys.executable, str(ROOT / "helpers/recovery_engine/engine.py")],
                                   input=json.dumps(request).encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertNotIn(b"TEST-SENTINEL-SECRET", completed.stdout + completed.stderr)
        self.assertEqual(json.loads(completed.stdout.splitlines()[-1])["status"], "complete")
        self.assertEqual(completed.stderr, b"")
        worker = engine.Importer(self.source, self.destination)
        with self.assertRaises(engine.RecoveryError) as ctx:
            worker.run()
        self.assertEqual(ctx.exception.code, "DESTINATION_NOT_EMPTY")

    def test_encrypted_iphone_known_password_wrong_password_and_digest_corruption(self):
        plain = self.root / "ChatStorage.sqlite"
        database(plain, "Encrypted recipe", ios=True)
        encrypted_file = encrypted_iphone(self.source, plain)
        worker = self.run_import({"ios_password": "Known test password"}, deep=False)
        self.assertEqual(len(worker.messages), 1)
        self.assertEqual(worker.messages[0]["text"], "Encrypted recipe")
        self.destination = self.root / "wrong-ios"
        worker = self.run_import({"ios_password": "wrong password sentinel"}, deep=False, expected="error")
        self.assertFalse((self.destination / "Переписки.html").exists())
        bad = bytearray(encrypted_file.read_bytes())
        bad[64] ^= 1
        encrypted_file.write_bytes(bad)
        self.destination = self.root / "corrupt-ios"
        worker = self.run_import({"ios_password": "Known test password"}, deep=False, expected="error")
        self.assertFalse(worker.messages)
        self.assertTrue(any(r.get("code") == "IOS_FILE_DIGEST_MISMATCH" for r in worker.sources))

    def test_pinned_upstream_whatsapp_known_fixtures(self):
        fixtures = ROOT / "vendor/wa-crypt-tools/tests/res"
        for version, key_name in ((12, "key"), (14, "key"), (15, "encrypted_backup.key")):
            with self.subTest(version=version):
                for path in self.source.iterdir():
                    path.unlink()
                original = fixtures / f"msgstore.db.crypt{version}"
                target = self.source / original.name
                target.write_bytes(original.read_bytes())
                worker = engine.Importer(self.source, self.root / f"reference-{version}",
                                         {"whatsapp_key": (fixtures / key_name).read_bytes().hex()}, False)
                with tempfile.TemporaryDirectory() as tmp:
                    worker.work = Path(tmp)
                    decoded = worker.decrypt_whatsapp(target)
                    self.assertEqual(decoded.read_bytes(), (fixtures / "msgstore.db").read_bytes())

    def test_acquisition_manifest_excludes_stale_partial_and_hash_mismatch(self):
        snapshot = self.source / "snapshot"
        snapshot.mkdir()
        chat = {"id": "chat", "messages": [{"id": 1, "text": "verified source"}]}
        good = snapshot / "good.json"
        good.write_text(json.dumps(chat), encoding="utf-8")
        (snapshot / "stale.json").write_text(json.dumps({"id": "stale", "messages": [{"id": 2, "text": "must not import"}]}), encoding="utf-8")
        bad = snapshot / "bad.json"
        bad.write_text(json.dumps(chat), encoding="utf-8")
        (self.source / "acquisition.json").write_text(json.dumps({"Files": [
            {"Id": "source-object-42", "RelativePath": "original.json", "OriginalPath": "phone/DCIM/original.json", "Status": "complete", "LocalPath": "snapshot/good.json", "Sha256": engine.digest(good)},
            {"Id": "bad", "OriginalPath": "bad", "Status": "complete", "LocalPath": "snapshot/bad.json", "Sha256": "0" * 64},
            {"Id": "partial", "OriginalPath": "partial", "Status": "copying", "LocalPath": "snapshot/partial.json"}]}), encoding="utf-8")
        worker = engine.Importer(snapshot, self.destination)
        result = worker.run()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(worker.messages), 1)
        self.assertEqual(worker.messages[0]["source_id"], "source-object-42")
        self.assertEqual(worker.messages[0]["source_file"], "phone/DCIM/original.json")
        self.assertTrue(any(x.get("code") == "ACQUISITION_HASH_MISMATCH" for x in worker.sources))

    def test_damaged_png_is_separate_candidate_and_does_not_abort(self):
        from PIL import Image
        stream = io.BytesIO()
        Image.new("RGB", (30, 20), "blue").save(stream, "PNG")
        bad = bytearray(stream.getvalue())
        bad[-5] ^= 1
        (self.source / "damaged").write_bytes(bad)
        worker = self.run_import(expected="partial")
        self.assertEqual(len(worker.photos), 1)
        candidate = next(iter(worker.photos.values()))
        self.assertEqual(candidate["status"], "damaged_candidate")
        self.assertIsNone(candidate["thumbnail"])

    def test_jpeg_exif_embedded_thumbnail_does_not_truncate_main_candidate(self):
        from PIL import Image
        small, large = io.BytesIO(), io.BytesIO()
        Image.new("RGB", (16, 16), "green").save(small, "JPEG")
        Image.new("RGB", (400, 360), "red").save(large, "JPEG")
        payload = b"Exif\0\0opaque thumbnail metadata" + small.getvalue()
        main = large.getvalue()[:2] + b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload + large.getvalue()[2:]
        (self.source / "photo-with-thumb").write_bytes(main)
        worker = self.run_import()
        self.assertEqual(len(worker.photos), 2)
        self.assertTrue(all(p["status"] == "decoded" for p in worker.photos.values()))
        self.assertTrue(any(p["kind"] == "embedded" for p in worker.photos.values()))

    def test_large_cache_streaming_and_boundary_signature(self):
        from PIL import Image
        photo = io.BytesIO()
        Image.new("RGB", (40, 35), "green").save(photo, "PNG")
        cache = self.source / "large-container.cache"
        with cache.open("wb") as f:
            f.seek(8 * 1024 * 1024 - 4)
            f.write(photo.getvalue())
            f.seek(engine.MAX_IMAGE + 4096)
            f.write(b"\0")
        worker = self.run_import()
        self.assertEqual(len(worker.photos), 1)
        recovered = next(iter(worker.photos.values()))
        self.assertEqual((self.destination / recovered["path"]).read_bytes(), photo.getvalue())
        self.assertEqual(recovered["sources"][0]["offset"], 8 * 1024 * 1024 - 4)

    def test_whatsapp_txt_zip_attachment_and_active_html_stored_as_data(self):
        with zipfile.ZipFile(self.source / "chat.zip", "w") as z:
            z.writestr("_chat.txt", "2026-10-12, 12:30 - Alice: <attached: attached.html>")
            z.writestr("attached.html", "<script>neverExecute()</script>")
        worker = self.run_import()
        self.assertEqual(len(worker.messages), 1)
        item = worker.messages[0]["attachments"][0]
        self.assertTrue(item.endswith(".bin"))
        metadata = json.loads((self.destination / "attachment-metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["attachments"][0]["sources"][0]["source_record"], "attached.html")
        self.assertNotIn("neverExecute", (self.destination / "Переписки.html").read_text(encoding="utf-8"))

    def test_v2_photo_operation_excludes_raw_image_and_artifacts(self):
        from PIL import Image
        (self.source / "filesystem/files").mkdir(parents=True)
        Image.new("RGB", (30, 30), "red").save(self.source / "filesystem/files/photo.png")
        Image.new("RGB", (40, 40), "blue").save(self.source / "usb.dd", "PNG")
        self.destination = self.source / "photo-archive"
        worker = engine.Importer(self.source, self.destination, deep=False)
        worker.run(photos_only=True)
        self.assertEqual(len(worker.photos), 1)
        self.assertEqual(next(iter(worker.photos.values()))["width"], 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)
