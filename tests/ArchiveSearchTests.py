"""Synthetic read-only archive search regressions; no personal messages."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
import archive_search as search


def message(text, app="Telegram", evidence="export", **extra):
    return {"app": app, "text": text, "evidence_kind": evidence, "chat_id": "chat:1", "sender_id": None,
            "sender_name": None, "timestamp": None, "snapshot_id": "synthetic-snapshot", "message_id": 1,
            "source_file": "synthetic/result.json", "source_record": "messages[0]", "attachments": [], **extra}


def write_archive(folder, values, index=True):
    folder.mkdir(exist_ok=True)
    (folder / "messages.jsonl").write_text("".join(json.dumps(v, ensure_ascii=False) + "\n" for v in values), encoding="utf-8")
    if index:
        con = sqlite3.connect(folder / "chat-index.sqlite")
        con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, json TEXT)")
        con.executemany("INSERT INTO messages(json) VALUES (?)", ((json.dumps(v, ensure_ascii=False),) for v in values))
        con.commit(); con.close()


class ArchiveSearchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="archive-search-")
        self.folder = Path(self.temporary.name)
        self.request = {"protocol": 1, "operation": "search", "archive": str(self.folder), "app": "", "query": "", "offset": 0, "limit": 100}

    def tearDown(self): self.temporary.cleanup()

    def run_search(self, **changes): return search.search({**self.request, **changes})

    def test_unicode_casefold_and_all_words_multiline(self):
        write_archive(self.folder, [message("БАБУШКА\nрецепт пирожков"), message("Только бабушка"), message("Straße apple")])
        found = self.run_search(query="РЕЦЕПТ бабушка")
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["records"][0]["text"], "БАБУШКА\nрецепт пирожков")
        self.assertEqual(self.run_search(query="STRASSE")["total"], 1)

    def test_app_category_and_empty_query(self):
        write_archive(self.folder, [message("recipe"), message("recipe", "WhatsApp", "backup"), message("recipe", "Signal", "fragment")])
        self.assertEqual(self.run_search()["total"], 3)
        self.assertEqual(self.run_search(app="WhatsApp")["total"], 1)
        self.assertEqual(self.run_search(evidence="fragment")["records"][0]["app"], "Signal")

    def test_malformed_evidence_does_not_hide_valid_jsonl_or_index_records(self):
        for indexed in (False, True):
            with self.subTest(indexed=indexed):
                folder = self.folder / str(indexed)
                write_archive(folder, [message("bad list", evidence=[]), message("bad object", evidence={}), message("still readable")], index=indexed)
                result = self.run_search(archive=str(folder))
                self.assertEqual(result["total"], 1)
                self.assertEqual(result["records"][0]["text"], "still readable")
                self.assertIn("RECORD_SKIPPED", result["warnings"])

    def test_literals_sql_fts_are_not_operators(self):
        write_archive(self.folder, [message("' OR 1=1 --"), message("OR hello"), message("ordinary text")])
        self.assertEqual(self.run_search(query="' OR 1=1 --")["total"], 1)
        self.assertEqual(self.run_search(query="recipe OR ordinary")["total"], 0)
        self.assertEqual(self.run_search(query='"unterminated')["total"], 0)

    def test_pagination_and_confirmed_identifiers_preserved(self):
        write_archive(self.folder, [message("row " + str(n), message_id=n) for n in range(237)])
        result = self.run_search(offset=100)
        self.assertEqual(result["total"], 237); self.assertEqual(len(result["records"]), 100)
        self.assertEqual(result["records"][0]["message_id"], 100)
        self.assertEqual(self.run_search(offset=200)["records"][-1]["message_id"], 236)

    def test_no_dedup_by_text_unknown_fields_stay_unknown(self):
        write_archive(self.folder, [message("same", message_id=1), message("same", message_id=2)])
        result = self.run_search()
        self.assertEqual(result["total"], 2)
        self.assertIsNone(result["records"][0]["sender_name"])
        self.assertIsNone(result["records"][0]["timestamp"])

    def test_readonly_hashes_directory_entries_and_times_unchanged(self):
        write_archive(self.folder, [message("hello")])
        before = {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in self.folder.iterdir()}
        self.run_search(query="HELLO")
        after = {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in self.folder.iterdir()}
        self.assertEqual(before, after)
        self.assertFalse((self.folder / "chat-index.sqlite-shm").exists())

    def test_jsonl_fallback_malformed_rows_and_utf8(self):
        write_archive(self.folder, [message("Текст")], index=False)
        with (self.folder / "messages.jsonl").open("ab") as out: out.write(b"{bad}\n\xff\n{}\n")
        result = self.run_search()
        self.assertEqual(result["total"], 1); self.assertEqual(result["status"], "partial")
        self.assertIn("RECORD_SKIPPED", result["warnings"])

    def test_corrupt_sqlite_falls_back_without_modifying_it(self):
        write_archive(self.folder, [message("known")], index=False)
        index = self.folder / "chat-index.sqlite"; index.write_bytes(b"corrupt SQLite")
        self.assertEqual(self.run_search()["total"], 1)
        self.assertIn("INDEX_FALLBACK_JSONL", self.run_search()["warnings"])
        self.assertEqual(index.read_bytes(), b"corrupt SQLite")

    def test_corrupt_index_without_fallback_controlled_error(self):
        (self.folder / "chat-index.sqlite").write_bytes(b"bad")
        with self.assertRaisesRegex(search.SearchError, "ARCHIVE_INDEX_INVALID"): self.run_search()

    def test_view_schema_rejected_and_sensitive_fields_excluded(self):
        write_archive(self.folder, [message("known", key="secret-canary", secret="secret-canary")], index=False)
        con = sqlite3.connect(self.folder / "chat-index.sqlite")
        con.execute("CREATE VIEW messages AS SELECT 1 id, '{}' json"); con.close()
        result = self.run_search(); self.assertEqual(result["total"], 1)
        self.assertNotIn("secret-canary", json.dumps(result))

    def test_query_and_page_limits(self):
        write_archive(self.folder, [message("hello")])
        for request in ({"offset": -1}, {"offset": True}, {"limit": 101}, {"app": "Other"}, {"query": "x" * 1025}, {"query": "x " * 33}):
            with self.assertRaises(search.SearchError): self.run_search(**request)

    def test_unpublished_or_authentication_failed_archive_is_rejected(self):
        write_archive(self.folder, [message("unverified")])
        (self.folder / "job.incomplete").write_text("Import incomplete", encoding="utf-8")
        with self.assertRaisesRegex(search.SearchError, "ARCHIVE_INCOMPLETE"): self.run_search()

    def test_wal_index_uses_published_jsonl_without_side_effects(self):
        write_archive(self.folder, [message("published")])
        wal = self.folder / "chat-index.sqlite-wal"; wal.write_bytes(b"synthetic incomplete WAL")
        result = self.run_search()
        self.assertEqual(result["total"], 1)
        self.assertIn("INDEX_FALLBACK_JSONL", result["warnings"])
        self.assertEqual(wal.read_bytes(), b"synthetic incomplete WAL")

    def test_oversized_jsonl_record_is_skipped_not_split(self):
        write_archive(self.folder, [message("valid")], index=False)
        with (self.folder / "messages.jsonl").open("ab") as out: out.write(json.dumps(message("x" * search.MAX_RECORD)).encode() + b"\n")
        self.assertEqual(self.run_search()["total"], 1)

    def test_large_text_is_searchable_with_explicit_display_truncation(self):
        write_archive(self.folder, [message("x" * (search.MAX_TEXT_RESULT + 100) + " keyword")])
        result = self.run_search(query="keyword")["records"][0]
        self.assertTrue(result["text_truncated"])
        self.assertEqual(len(result["text"]), search.MAX_TEXT_RESULT)

    def test_engine_stdin_operation_has_no_import_or_writes(self):
        write_archive(self.folder, [message("Привет")])
        command = [sys.executable, str(ROOT / "helpers/recovery_engine/engine.py")]
        completed = subprocess.run(command, input=json.dumps({**self.request, "query": "привет"}, ensure_ascii=False), encoding="utf-8", capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual(result["type"], "result"); self.assertEqual(result["total"], 1)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(sorted(p.name for p in self.folder.iterdir()), ["chat-index.sqlite", "messages.jsonl"])


if __name__ == "__main__": unittest.main(verbosity=2)
