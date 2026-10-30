"""Explicit-root synthetic checks; never scan personal profiles or real tdata."""
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
import engine
import telegram_auto as auto
from archive_search import search

engine.emit = lambda *a, **k: None


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def export(path, messages=None, chat=111):
    path.parent.mkdir(parents=True, exist_ok=True)
    if messages is None:
        messages = [{"id": 1, "date": "2026-10-11T10:00:00+03:00", "from": "Бабушка", "from_id": "user77", "text": "секрет пирожков: яблоки"},
                    {"id": 2, "date": "2026-10-13T12:00:00+03:00", "from": "Анна", "from_id": "user88", "text": "Последняя переписка 🥧 рецепт"}]
    path.write_text(json.dumps({"name": "Семья", "type": "personal_chat", "id": chat, "messages": messages}, ensure_ascii=False), encoding="utf-8")
    return path


def canonical(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(v, ensure_ascii=False) + "\n" for v in values), encoding="utf-8")


def message(app="Telegram", text="Ключевые слова яблоки", mid=7, date="2026-10-12T23:00:00+03:00"):
    return {"app": app, "snapshot_id": "known", "chat_id": 555, "sender_id": 23, "sender_name": "Саша", "timestamp": date,
            "text": text, "message_id": mid, "evidence_kind": "export", "source_file": "original-export.json", "source_record": "messages[0]", "attachments": []}


class TelegramAutoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="TelegramAuto-synthetic-")
        self.base = Path(self.temp.name)
        self.input = self.base / "input"
        self.input.mkdir()
        self.sequence = 0

    def tearDown(self):
        self.temp.cleanup()

    def run_analysis(self, roots=None, **options):
        self.sequence += 1
        output = self.base / f"result-{self.sequence}"
        request = {"protocol": 1, "operation": "telegram_analyze", "destination": str(output), "options": {"roots": roots if roots is not None else [str(self.input)], **options}}
        result = auto.analyze(request, engine.Importer, lambda *a, **k: None)
        records = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        return output, result, records

    def test_hidden_extensionless_unicode_exports_latest_keyword_provenance(self):
        path = export(self.input / ".hidden" / "without-extension")
        if os.name == "nt":
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 2)
        before = sha(path)
        output, result, records = self.run_analysis()
        self.assertEqual(result["history_messages"], 2)
        self.assertEqual(records[0]["message_id"], 2)
        self.assertEqual(result["latest_timestamp"], records[0]["timestamp"])
        self.assertEqual(records[0]["source_file"], str(path))
        self.assertEqual(records[0]["source_sha256"], before)
        self.assertEqual(sha(path), before)
        query = search({"protocol": 1, "operation": "search", "archive": str(output), "app": "Telegram", "query": "СЕКРЕТ яблоки", "offset": 0, "limit": 20})
        self.assertEqual(query["total"], 1)
        self.assertFalse(Path(str(output) + ".work").exists())
        self.assertFalse((output / "job.incomplete").exists())

    def test_unknown_dates_last_and_same_text_different_ids_preserved(self):
        export(self.input / "result.json", [
            {"id": 3, "date": "unknown", "from": "Мама", "text": "Одинаковый текст"},
            {"id": 1, "date": "2026-10-11T10:00:00", "from": "Мама", "text": "Одинаковый текст"},
            {"id": 2, "date": "2026-10-13T10:00:00", "from": "Мама", "text": "Одинаковый текст"}])
        _, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 3)
        self.assertEqual([r["message_id"] for r in records], [2, 1, 3])

    def test_mixed_app_archives_only_telegram_no_secret_fields(self):
        values = [message(), message("WhatsApp", "secret-WA", 8), message("Signal", "secret-Signal", 9)]
        values[0]["auth_key"] = "SECRET_CANARY_NOT_A_MESSAGE"
        path = self.input / "old/messages.jsonl"
        canonical(path, values)
        before = sha(path)
        output, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 1)
        self.assertEqual(records[0]["app"], "Telegram")
        self.assertEqual(sha(path), before)
        for item in output.rglob("*"):
            if item.is_file():
                self.assertNotIn(b"SECRET_CANARY_NOT_A_MESSAGE", item.read_bytes())
                self.assertNotIn(b"secret-WA", item.read_bytes())
                self.assertNotIn(b"secret-Signal", item.read_bytes())

    def test_bad_canonical_record_does_not_skip_following_messages(self):
        bad = message(text="damaged record", mid=1)
        bad["evidence_kind"] = []
        canonical(self.input / "messages.jsonl", [bad, message(text="readable after corruption", mid=2)])
        _, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 1)
        self.assertEqual(records[0]["text"], "readable after corruption")

    def test_native_tdata_encrypted_no_key_session_reads_or_copies(self):
        tdata = self.input / "tdata"
        tdata.mkdir()
        private = tdata / "key_datas"
        private.write_bytes(b"PRIVATE_KEY_CANARY")
        account = tdata / "D877F783D5D3EF8Cs"
        account.write_bytes(b"PRIVATE_SESSION_CANARY")
        native = tdata / "user_data.cache"
        native.write_bytes(b"TDF$" + b"CIPHERTEXT" * 10)
        native_before = {x: sha(x) for x in (private, account, native)}
        original_open = Path.open
        def guarded_open(path, *args, **kwargs):
            if path in (private, account):
                raise AssertionError("Private Telegram key/session must not be opened")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", guarded_open):
            output, result, records = self.run_analysis(roots=[{"path": str(tdata), "kind": "desktop_cache"}])
        self.assertEqual(records, [])
        self.assertEqual(result["code"], "NO_READABLE_TELEGRAM_HISTORY")
        self.assertGreater(result["encrypted_sources"], 0)
        self.assertIn("ENCRYPTED_CACHE_UNSUPPORTED", result["warnings"])
        self.assertEqual(native_before, {x: sha(x) for x in native_before})
        for item in output.rglob("*"):
            if item.is_file():
                self.assertNotIn(b"PRIVATE_KEY_CANARY", item.read_bytes())
                self.assertNotIn(b"PRIVATE_SESSION_CANARY", item.read_bytes())
                self.assertNotIn(b"CIPHERTEXT", item.read_bytes())

    def test_safe_html_and_referenced_image(self):
        from PIL import Image
        photo = self.input / "photos/photo.jpg"
        photo.parent.mkdir()
        Image.new("RGB", (15, 17), "red").save(photo)
        path = self.input / "messages.html"
        path.write_text('''<html><script>PRIVATE_SCRIPT_CANARY;fetch("https://bad.example")</script><div class="message default clearfix" id="message42"><div class="date details" title="13.10.2026 12:34:56 UTC+03:00"></div><div class="from_name">Маша</div><div class="text">Рецепт&lt;script&gt;\nЯблоки</div><a href="photos/photo.jpg">Фото</a><a href="https://remote.example/evil.js">Remote</a></div></html>''', encoding="utf-8")
        before = sha(path), sha(photo)
        output, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 1)
        self.assertEqual(records[0]["message_id"], "42")
        self.assertEqual(len(records[0]["attachments"]), 1)
        attachment = output / records[0]["attachments"][0]
        self.assertEqual(sha(attachment), before[1])
        self.assertEqual((sha(path), sha(photo)), before)
        archive = (output / "Переписки.html").read_text(encoding="utf-8")
        self.assertNotIn("PRIVATE_SCRIPT_CANARY", archive)
        self.assertNotIn("remote.example", archive)
        self.assertNotIn("<script>\nЯблоки", archive)

    def test_sqlite_published_archive_telegram_only(self):
        db = self.input / "chat-index.sqlite"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY,app TEXT,json TEXT)")
        for i, app in enumerate(("Telegram", "WhatsApp", "Signal"), 1):
            con.execute("INSERT INTO messages VALUES(?,?,?)", (i, app, json.dumps(message(app, app + " text", i))))
        con.commit()
        con.close()
        before = sha(db)
        _, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 1)
        self.assertEqual(records[0]["app"], "Telegram")
        self.assertEqual(sha(db), before)
        self.assertFalse(Path(str(db) + "-wal").exists())

    def test_android_notification_saved_preview_unknown_author_and_reactions(self):
        db = self.input / "cache4.db"
        con = sqlite3.connect(db)
        con.executescript("CREATE TABLE unread_push_messages(uid INTEGER,mid INTEGER,date INTEGER,fm TEXT,name TEXT,is_reaction INTEGER); CREATE TABLE messages_v2(mid INTEGER,uid INTEGER,date INTEGER,data BLOB);")
        con.executemany("INSERT INTO unread_push_messages VALUES(?,?,?,?,?,?)", [(44, 12, 1_790_000_020, "Уведомление рецепт", "НЕ автор", 0), (44, 10, 1_790_000_000, "Старое уведомление", "НЕ автор", 0), (44, 11, 1_790_000_001, "Реакция", "НЕ автор", 1)])
        con.execute("INSERT INTO messages_v2 VALUES(1,44,1790000000,?)", (b"BINARY fake unrecoverable Telegram history",))
        con.commit()
        con.close()
        before = sha(db)
        output, result, records = self.run_analysis()
        self.assertEqual(result["notification_records"], 2)
        self.assertEqual(result["history_messages"], 0)
        self.assertIsNone(result["latest_timestamp"])
        self.assertTrue(all(r["sender_name"] is None for r in records))
        self.assertEqual([r["message_id"] for r in records], [12, 10])
        self.assertTrue(all(r["record_kind"] == "notification" for r in records))
        self.assertIn("TELEGRAM_TL_HISTORY_UNSUPPORTED", result["warnings"])
        self.assertEqual(sha(db), before)
        found = search({"protocol": 1, "operation": "search", "archive": str(output), "app": "Telegram", "query": "рецепт", "limit": 10})
        self.assertEqual(found["records"][0]["record_kind"], "notification")

    def test_notification_kind_survives_reimport(self):
        raw = message(mid=2)
        raw.update(record_kind="notification", completeness="saved_notification_preview", sender_name=None, sender_id=None, evidence_kind="backup")
        canonical(self.input / "messages.jsonl", [raw])
        _, result, records = self.run_analysis()
        self.assertEqual(result["history_messages"], 0)
        self.assertEqual(result["notification_records"], 1)
        self.assertEqual(records[0]["record_kind"], "notification")

    def test_incomplete_archives_not_published_as_success(self):
        canonical(self.input / "messages.jsonl", [message()])
        (self.input / "job.incomplete").write_text("cancelled", encoding="utf-8")
        _, result, records = self.run_analysis()
        self.assertEqual(records, [])
        self.assertIn("TELEGRAM_ARCHIVE_INCOMPLETE", result["warnings"])

    def test_output_inside_results_never_reimported_self(self):
        archive_root = self.input / "archives"
        export(archive_root / "old/result.json")
        output = archive_root / "Telegram-new"
        result = auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(output), "options": {"roots": [str(archive_root)]}}, engine.Importer, lambda *a, **k: None)
        self.assertEqual(result["messages"], 2)
        sources = (output / "acquisition.json").read_text(encoding="utf-8")
        self.assertNotIn("Telegram-new", sources)

    def test_unsafe_attachment_traversal_and_junction_skipped(self):
        secret = self.base / "private.jpg"
        secret.write_bytes(b"DO_NOT_READ_PRIVATE")
        export(self.input / "result.json", [{"id": 1, "date": "2026-10-12", "from": "User", "text": "safe", "file": "../private.jpg"}])
        output, _, records = self.run_analysis()
        self.assertEqual(records[0]["attachments"], [])
        for item in output.rglob("*"):
            if item.is_file():
                self.assertNotIn(b"DO_NOT_READ_PRIVATE", item.read_bytes())
        if os.name == "nt":
            outside = self.base / "outside"
            outside.mkdir()
            export(outside / "result.json")
            link = self.input / "junction"
            completed = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(outside)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(completed.returncode, 0)
            try:
                _, result, records = self.run_analysis()
                self.assertEqual(result["messages"], 1)
                self.assertIn("TELEGRAM_PATH_UNAVAILABLE", result["warnings"])
            finally:
                os.rmdir(link)

    def test_denied_file_and_mutating_copy_report_partial(self):
        blocked = export(self.input / "blocked.json")
        good = export(self.input / "good.json", chat=222)
        open_orig = Path.open
        def deny(path, *args, **kwargs):
            if path == blocked:
                raise PermissionError()
            return open_orig(path, *args, **kwargs)
        with patch.object(Path, "open", deny):
            _, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 2)
        self.assertGreater(result["blocked_sources"], 0)
        self.assertIn("TELEGRAM_SOURCE_UNAVAILABLE", result["warnings"])
        original_hash = auto._hash
        def mismatch(path):
            return "0" * 64 if Path(path) == good else original_hash(path)
        with patch.object(auto, "_hash", mismatch):
            _, result, _ = self.run_analysis()
        self.assertIn("TELEGRAM_SOURCE_CHANGED", result["warnings"])

    def test_invalid_wal_not_trusted_or_claimed_recent(self):
        db = self.input / "chat-index.sqlite"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY,app TEXT,json TEXT)")
        con.execute("INSERT INTO messages VALUES(1,'Telegram',?)", (json.dumps(message()),))
        con.commit()
        con.close()
        wal = Path(str(db) + "-wal")
        wal.write_bytes(b"corrupt not authenticated WAL recent text")
        before = sha(db), sha(wal)
        _, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 1)
        self.assertIn("TELEGRAM_WAL_INVALID", result["warnings"])
        self.assertEqual((sha(db), sha(wal)), before)
        self.assertNotIn("recent text", records[0]["text"])

    def test_correct_wal_readable_notification_without_source_mutations(self):
        db = self.input / "cache4.db"
        con = sqlite3.connect(db)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("CREATE TABLE unread_push_messages(uid INTEGER,mid INTEGER,date INTEGER,fm TEXT,is_reaction INTEGER)")
        con.commit()
        con.execute("INSERT INTO unread_push_messages VALUES(77,8,1790000000,'WAL recipe',0)")
        con.commit()
        files = [db, Path(str(db) + "-wal"), Path(str(db) + "-shm")]
        before = {p: sha(p) for p in files}
        try:
            _, result, records = self.run_analysis()
            self.assertEqual(result["messages"], 1)
            self.assertEqual(records[0]["text"], "WAL recipe")
            self.assertNotIn("TELEGRAM_WAL_INVALID", result["warnings"])
            self.assertEqual(before, {p: sha(p) for p in files})
        finally:
            con.close()

    def test_wal_validation_streams_pages_and_rejects_corrupted_tail(self):
        source = self.input / "source.db"
        copied = self.base / "copied.db"
        wal = Path(str(copied) + "-wal")
        reads = []
        original_open = Path.open

        class BoundedRead:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def fileno(self):
                return self.stream.fileno()

            def read(self, size=-1):
                if not 0 < size <= 65536:
                    raise AssertionError("WAL validation must read at most one bounded page")
                reads.append(size)
                return self.stream.read(size)

        def bounded_open(path, *args, **kwargs):
            stream = original_open(path, *args, **kwargs)
            return BoundedRead(stream) if path == wal and args == ("rb",) else stream

        con = sqlite3.connect(source)
        try:
            con.execute("PRAGMA page_size=65536")
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("CREATE TABLE messages(text TEXT)")
            con.commit()
            for number in range(4):
                con.execute("INSERT INTO messages VALUES(?)", (f"commit {number}",))
                con.commit()
            shutil.copyfile(source, copied)
            shutil.copyfile(Path(str(source) + "-wal"), wal)
            scanner = auto.Analyzer({"destination": str(self.base / "validation-result")}, engine.Importer, lambda *a, **k: None)
            scanner.worker = Mock()
            before = sha(copied), sha(wal)
            with patch.object(Path, "open", bounded_open):
                scanner.validate_wal(copied, source)
            self.assertEqual((sha(copied), sha(wal)), before)
            self.assertNotIn("TELEGRAM_WAL_INVALID", scanner.warnings)
            self.assertGreater(reads.count(65536), 1)
            scanner.worker.remark.assert_called_once_with("WAL_CHECKED_COMMITS", source)

            with wal.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                value = stream.read(1)
                stream.seek(-1, os.SEEK_END)
                stream.write(bytes([value[0] ^ 1]))
            with patch.object(Path, "open", bounded_open):
                scanner.validate_wal(copied, source)
            self.assertIn("TELEGRAM_WAL_INVALID", scanner.warnings)
            self.assertFalse(wal.exists())
            self.assertEqual(sha(copied), before[0])
        finally:
            con.close()

    def test_repeated_confirmed_id_duplicates_merge_sources(self):
        export(self.input / "first/result.json")
        export(self.input / "second/result.json")
        _, result, records = self.run_analysis()
        self.assertEqual(result["messages"], 2)
        self.assertTrue(all(r.get("additional_sources") for r in records))

    def test_empty_source_honest_no_permanent_destruction_claim(self):
        _, result, records = self.run_analysis()
        self.assertEqual(result["code"], "NO_READABLE_TELEGRAM_HISTORY")
        self.assertEqual(records, [])
        self.assertIsNone(result["latest_timestamp"])

    def test_defaults_only_known_roots_never_developer_tests(self):
        fake_home = self.base / "profile"
        (fake_home / "Documents/ChatExport-2026").mkdir(parents=True)
        app = self.base / "application"
        (app / "tests/ChatExport-dev").mkdir(parents=True)
        with patch.object(Path, "home", return_value=fake_home), patch.dict(os.environ, {"APPDATA": str(fake_home / "AppData/Roaming"), "LOCALAPPDATA": str(fake_home / "AppData/Local")}):
            roots = auto.known_roots(str(app))
        self.assertTrue(any("ChatExport-2026" in str(p) for p, _ in roots))
        self.assertFalse(any("tests" in str(p) for p, _ in roots))
        self.assertFalse(any(p == fake_home for p, _ in roots))
        self.assertFalse(any(p == app / "tdata" for p, _ in roots))

    def test_source_limit_bounded(self):
        export(self.input / "first.json")
        export(self.input / "second.json", chat=222)
        with patch.object(auto, "MAX_FILES", 1):
            _, result, _ = self.run_analysis()
        self.assertIn("TELEGRAM_SCAN_LIMIT", result["warnings"])
        self.assertEqual(result["messages"], 2)

    def test_generic_importer_telegram_only_ignores_whatsapp_and_signal(self):
        export(self.input / "result.json")
        (self.input / "WhatsApp.txt").write_text("13/10/2026, 12:00 - Other: not Telegram", encoding="utf-8")
        (self.input / "Signal.backup").write_bytes(b"do not call Signal")
        whatsapp = self.input / "msgstore.db"
        con = sqlite3.connect(whatsapp)
        con.execute("CREATE TABLE messages(_id INTEGER PRIMARY KEY,key_remote_jid TEXT,timestamp INTEGER,data TEXT,key_id TEXT,key_from_me INTEGER)")
        con.execute("INSERT INTO messages VALUES(1,'other',1790000000,'PRIVATE_WA', 'key',0)")
        con.commit()
        con.close()
        output = self.base / "generic-result"
        worker = engine.Importer(self.input, output, {}, False)
        worker.telegram_only = True
        result = worker.run()
        records = [json.loads(x) for x in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(result["messages"], 2)
        self.assertTrue(all(r["app"] == "Telegram" for r in records))
        self.assertNotIn("PRIVATE_WA", (output / "messages.jsonl").read_text(encoding="utf-8"))

    def test_stdio_dispatch_is_ndjson_and_secretless(self):
        export(self.input / "result.json")
        destination = self.base / "process-result"
        request = {"protocol": 1, "operation": "telegram_analyze", "destination": str(destination), "options": {"roots": [str(self.input)]}}
        response = subprocess.run([sys.executable, str(ROOT / "helpers/recovery_engine/engine.py")], input=json.dumps(request), encoding="utf-8", capture_output=True, timeout=30)
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stderr, "")
        lines = [json.loads(line) for line in response.stdout.splitlines()]
        self.assertEqual(lines[-1]["type"], "result")
        self.assertEqual(lines[-1]["messages"], 2)
        self.assertEqual(lines[-1]["archive"], str(destination))


if __name__ == "__main__":
    unittest.main(verbosity=2)
