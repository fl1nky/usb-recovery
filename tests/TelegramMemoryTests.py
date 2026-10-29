"""Synthetic dump recovery regressions. No personal directories/devices used."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
import engine
import telegram_auto
import memory_fragments as fragments
from archive_search import search, SearchError
from text_match import Matcher, MatchError

engine.emit = lambda *a, **k: None


class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Telegram-memory-synthetic-")
        self.base = Path(self.temp.name)
        self.source = self.base / "input"
        self.source.mkdir()
        self.output = self.base / "archive"

    def tearDown(self):
        self.temp.cleanup()

    def analyze(self, **options):
        request = {"protocol": 1, "operation": "telegram_analyze", "destination": str(self.output),
                   "options": {"roots": [str(self.source)], "scan_fragments": True, **options}}
        result = telegram_auto.analyze(request, engine.Importer, engine.emit)
        records = [json.loads(x) for x in (self.output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        return result, records

    def test_utf8_utf16_offsets_unknown_author_date_and_hash(self):
        text = "Секрет пирожков: яблоки и корица"
        file = self.source / "phone.hprof"
        data = b"\x00\xff\x00" + text.encode() + b"\x00\xff\x00" + text.encode("utf-16-le") + b"\x00\x00\xff\x00" + text.encode("utf-16-be") + b"\x00\x00"
        file.write_bytes(data)
        before = hashlib.sha256(data).hexdigest(), file.stat().st_mtime_ns
        result, records = self.analyze(fragment_query="пирожков")
        self.assertEqual({r["encoding"] for r in records}, {"utf-8", "utf-16-le", "utf-16-be"})
        self.assertEqual(result["history_messages"], 0)
        self.assertEqual(result["fragment_records"], len(records))
        for r in records:
            self.assertEqual(r["evidence_kind"], "fragment")
            self.assertFalse(r["application_confirmed"])
            self.assertIsNone(r["sender_id"])
            self.assertIsNone(r["timestamp"])
            self.assertIsNone(r["message_id"])
            self.assertEqual(r["source_sha256"], before[0])
            self.assertEqual(data[r["byte_offset"]:r["byte_offset"] + r["byte_length"]].decode(r["encoding"]), r["text"])
        self.assertEqual((hashlib.sha256(file.read_bytes()).hexdigest(), file.stat().st_mtime_ns), before)
        self.assertFalse(Path(str(self.output) + ".work").exists())

    def test_block_boundary_and_exact_offset_no_duplicate(self):
        text = "Нужный рецепт бабушки на границе блока"
        file = self.source / "heap.dmp"
        offset = fragments.CHUNK - 11
        file.write_bytes(b"\x00" * offset + text.encode() + b"\x00" * (fragments.CHUNK + 10))
        results = list(fragments.scan(file, Matcher("рецепт")))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["byte_offset"], offset)
        self.assertEqual(results[0]["text"], text)

    def test_hidden_deep_recursive_folder(self):
        directory = self.source / ".hidden"
        for i in range(17): directory /= str(i)
        directory.mkdir(parents=True)
        (directory / "memory.bin").write_bytes(b"\x00" + "Найти важное сообщение".encode() + b"\x00")
        result, records = self.analyze(fragment_query="важное")
        self.assertEqual(result["fragment_records"], 1)
        self.assertIn(".hidden", records[0]["source_file"])

    def test_regex_unicode_alternatives_and_literal_default(self):
        self.assertTrue(Matcher(r"рецепт|пирожк\w+", "regex").matches("ПИРОЖКОВ"))
        self.assertTrue(Matcher(r"яблоки\s+и\s+корица", "regex").matches("Яблоки\nи корица"))
        self.assertFalse(Matcher("яблоки|корица").matches("яблоки"))
        self.assertTrue(Matcher("яблоки корица").matches("Корица и яблоки"))

    def test_bad_regex_is_controlled_before_archive_publication(self):
        with self.assertRaises(telegram_auto.AutoError) as caught:
            self.analyze(fragment_query="[", query_mode="regex")
        self.assertEqual(caught.exception.code, "REGEX_INVALID")
        self.assertFalse(self.output.exists())

    def test_pathological_regex_is_bounded(self):
        matcher = Matcher(r"(a+)+$", "regex")
        start = time.monotonic()
        with self.assertRaises(MatchError) as caught: matcher.matches("a" * 100000 + "!")
        self.assertEqual(caught.exception.code, "REGEX_TIMEOUT")
        self.assertLess(time.monotonic() - start, 2)

    def test_archive_regex_latest_and_provenance(self):
        values = [{"app":"Telegram", "text":text, "evidence_kind":"export", "timestamp":date} for text,date in [("Рецепт старый", "2020-01-01T00:00:00Z"),("Пирожков рецепт", "2026-10-27T00:00:00Z")]]
        self.output.mkdir()
        file = self.output / "messages.jsonl"
        file.write_text("\n".join(json.dumps(v) for v in values), encoding="utf-8")
        request = {"protocol":1, "operation":"search", "archive":str(self.output), "app":"Telegram", "query":r"рецепт|пирожк\w+", "query_mode":"regex", "sort":"latest"}
        result = search(request)
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["records"][0]["text"], "Пирожков рецепт")
        request["query"] = "["
        with self.assertRaises(SearchError) as caught: search(request)
        self.assertEqual(caught.exception.code, "REGEX_INVALID")

    def test_private_session_files_never_opened_even_with_extensions(self):
        files = [self.source / name for name in ("key_datas.dmp", "D877F783D5D3EF8Cs.bin", "settings.dmp")]
        for file in files: file.write_bytes(b"PRIVATE_SESSION_MUST_NOT_BE_READ")
        original = Path.open
        opened = []
        def guarded(path, *args, **kwargs):
            if path in files:
                opened.append(path)
                raise AssertionError("private session opened")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", guarded): result, records = self.analyze()
        self.assertEqual(records, [])
        self.assertGreater(result["encrypted_sources"], 0)
        self.assertEqual(opened, [])

    def test_export_reference_cannot_copy_private_session(self):
        private = self.source / "key_datas.txt"
        private.write_text("PRIVATE_ACCOUNT_CANARY", encoding="utf-8")
        (self.source / "result.json").write_text(json.dumps({"type":"personal_chat","id":1,"messages":[
            {"id":1,"from_id":"user2","date":"2026-10-27T00:00:00Z","text":"safe message","file":"key_datas.txt"}]}), encoding="utf-8")
        result, records = self.analyze()
        self.assertEqual(records[0]["attachments"], [])
        self.assertIn("TELEGRAM_PRIVATE_REFERENCE_SKIPPED", result["warnings"])
        self.assertFalse(any(b"PRIVATE_ACCOUNT_CANARY" in p.read_bytes() for p in self.output.rglob("*") if p.is_file()))

    def test_original_database_free_text_is_separate_not_dated_message(self):
        file = self.source / "cache4.db"
        con = sqlite3.connect(file)
        con.execute("PRAGMA secure_delete=OFF")
        con.execute("CREATE TABLE messages_v2(mid INT,uid INT,date INT,data BLOB)")
        con.execute("INSERT INTO messages_v2 VALUES(1,2,3,?)", (b"\x00" + "Удалённый рецепт пирожков".encode() + b"\x00",))
        con.commit()
        con.execute("DELETE FROM messages_v2")
        con.commit();con.close()
        result, records = self.analyze(fragment_query="пирожков")
        self.assertGreater(result["fragment_records"], 0)
        self.assertEqual(result["history_messages"], 0)
        self.assertTrue(all(r["timestamp"] is None and r["message_id"] is None for r in records))

    def test_mixed_app_published_database_not_carved(self):
        con = sqlite3.connect(self.source / "chat-index.sqlite")
        con.execute("CREATE TABLE messages(id INT,app TEXT,json TEXT)")
        con.execute("INSERT INTO messages VALUES(1,'WhatsApp',?)", (json.dumps({"app":"WhatsApp","text":"PRIVATE_WA_TEXT","evidence_kind":"export"}),))
        con.commit();con.close()
        result, records = self.analyze()
        self.assertEqual(records, [])

    def test_fragment_limit_does_not_invent_history(self):
        file = self.source / "heap.dmp"
        file.write_bytes(b"\x00".join(("Message number %d important" % i).encode() for i in range(30)))
        records = list(fragments.scan(file, Matcher("important"), limit=3))
        self.assertEqual(len(records), 3)

    def test_orphan_wal_has_unattributed_fragments_only(self):
        (self.source / "cache4.db-wal").write_bytes(b"\x00\xff\x00" + "Последний рецепт из журнала".encode() + b"\x00")
        result, records = self.analyze(fragment_query="рецепт")
        self.assertEqual(result["history_messages"], 0)
        self.assertEqual(result["fragment_records"], 1)
        self.assertEqual(records[0]["record_kind"], "memory_fragment")

    def test_damaged_cache_database_retains_only_raw_fragments(self):
        file = self.source / "cache4.db"
        file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100 + "Сохранившийся рецепт в повреждённой базе".encode() + b"\x00")
        result, records = self.analyze(fragment_query="рецепт")
        self.assertEqual(result["history_messages"], 0)
        self.assertEqual(result["fragment_records"], 1)
        self.assertIn("TELEGRAM_SQLITE_INVALID_FRAGMENTS_ONLY", result["warnings"])

    def test_dump_stdin_protocol_no_stdout_leak(self):
        (self.source / "phone.mem").write_bytes(b"\x00" + "секретный рецепт".encode() + b"\x00")
        request = {"protocol":1,"operation":"telegram_analyze","destination":str(self.output),"options":{"roots":[str(self.source)],"scan_fragments":True,"fragment_query":"рецепт"}}
        worker = [str(Path(sys.argv[1]).resolve())] if len(sys.argv) > 1 else [sys.executable,str(ROOT / "helpers/recovery_engine/engine.py")]
        response = subprocess.run(worker,input=json.dumps(request),encoding="utf-8",capture_output=True,timeout=30)
        self.assertEqual(response.returncode,0,response.stderr)
        self.assertNotIn("секретный", response.stdout)
        self.assertEqual(response.stderr, "")
        result=json.loads(response.stdout.splitlines()[-1])
        self.assertEqual(result["fragment_records"],1)
        self.assertEqual(result["history_messages"],0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
