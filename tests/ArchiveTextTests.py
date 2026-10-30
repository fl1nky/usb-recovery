"""Read-only paged archive text and true matching snippets on owned fixtures."""
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "helpers/recovery_engine"), str(ROOT / "tests")]
import archive_search
import archive_text
from ArchiveSearchTests import message, write_archive


class ArchiveTextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="archive-text-owned-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def search(self, **values):
        return archive_search.search(dict(protocol=1, operation="search", archive=str(self.root), app="Telegram", **values))

    def page(self, key, offset=0, limit=65536, **extra):
        request = dict(protocol=1, operation="message_page", archive=str(self.root), record_key=key,
                       text_offset=offset, limit=limit)
        request.update(extra)
        return archive_text.read_page(request)

    def test_late_literal_and_regex_matches_are_actually_visible(self):
        text = "x" * 100000 + " бабушка: рецепт ПИРОЖКОВ 🥧 " + "y" * 40000
        write_archive(self.root, [message(text)])
        for mode, query in (("literal", "пирожков"), ("regex", "рецепт.*🥧")):
            with self.subTest(mode=mode):
                row = self.search(query=query, query_mode=mode)["records"][0]
                self.assertIn("ПИРОЖКОВ", row["text"])
                self.assertEqual(row["text"], text[row["text_offset"]:row["text_end"]])
                self.assertEqual(row["text_length"], len(text))
                self.assertLessEqual(row["text_offset"], row["match_offset"])
                self.assertLess(row["match_offset"], row["text_end"])
                self.assertTrue(row["text_truncated"])

    def test_casefold_expansion_positions_refer_to_original_unicode(self):
        text = "ß" * 80000 + " HELLO Straße " + "x" * 80000
        write_archive(self.root, [message(text)])
        row = self.search(query="hello strasse")["records"][0]
        self.assertEqual(row["match_offset"], text.index("HELLO"))
        self.assertIn("HELLO Straße", row["text"])

    def test_sqlite_and_jsonl_pages_replay_complete_unicode_without_loss(self):
        text = ("🧬е\u0301ß\r\n🥧abc" * 4000) + "THE END"
        for indexed in (True, False):
            with self.subTest(indexed=indexed):
                if not indexed:
                    (self.root / "chat-index.sqlite").unlink()
                else:
                    write_archive(self.root, [message(text)])
                row = self.search(query="THE END")["records"][0]
                before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
                offset, chunks = 0, []
                while True:
                    part = self.page(row["archive_record_key"], offset, 997)
                    self.assertEqual(part["text"], text[offset:part["next_offset"]])
                    self.assertEqual(part["text_length"], len(text))
                    self.assertEqual(part["record_key"], row["archive_record_key"])
                    chunks.append(part["text"])
                    offset = part["next_offset"]
                    if part["eof"]:
                        break
                self.assertEqual("".join(chunks), text)
                self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}, before)

    def test_same_size_changed_record_with_restored_timestamp_is_rejected(self):
        write_archive(self.root, [message("recipe OLD")], index=False)
        row = self.search()["records"][0]
        path = self.root / "messages.jsonl"
        state = path.stat()
        path.write_bytes(path.read_bytes().replace(b"recipe OLD", b"recipe NEW"))
        os.utime(path, ns=(state.st_atime_ns, state.st_mtime_ns))
        with self.assertRaisesRegex(archive_search.SearchError, "RECORD_CHANGED"):
            self.page(row["archive_record_key"])

    def test_locator_never_becomes_an_arbitrary_path_or_unbounded_offset(self):
        write_archive(self.root, [message("known text")])
        key = self.search()["records"][0]["archive_record_key"]
        for bad in ("../secrets", "C:\\Windows\\win.ini", "jsonl:0:" + "f" * 64,
                    "sqlite:9223372036854775808:" + "f" * 64, "jsonl:1:" + "f" * 64):
            with self.subTest(key=bad), self.assertRaises(archive_search.SearchError):
                self.page(bad)
        for values in ({"text_offset": True}, {"text_offset": -1}, {"limit": True}, {"limit": 65537}, {"text_offset": 1000}):
            with self.subTest(values=values), self.assertRaises(archive_search.SearchError):
                self.page(key, **values)

    def test_noninteger_index_ids_use_bound_verified_ordinal(self):
        text = "owned message"
        raw = json.dumps(message(text))
        db = sqlite3.connect(self.root / "chat-index.sqlite")
        db.execute("CREATE TABLE messages(id TEXT, json TEXT)")
        db.execute("INSERT INTO messages VALUES(?,?)", ("not SQL';DROP TABLE messages", raw))
        db.commit(); db.close()
        row = self.search()["records"][0]
        self.assertTrue(row["archive_record_key"].startswith("sqlite-ordinal:"))
        self.assertEqual(self.page(row["archive_record_key"])["text"], text)

    def test_unpublished_archive_wal_and_modified_selected_sqlite_record_reject(self):
        write_archive(self.root, [message("before")])
        key = self.search()["records"][0]["archive_record_key"]
        (self.root / "job.incomplete").write_text("partial")
        with self.assertRaisesRegex(archive_search.SearchError, "ARCHIVE_INCOMPLETE"):
            self.page(key)
        (self.root / "job.incomplete").unlink()
        (self.root / "chat-index.sqlite-wal").write_bytes(b"unverified")
        with self.assertRaisesRegex(archive_search.SearchError, "ARCHIVE_INCOMPLETE"):
            self.page(key)
        (self.root / "chat-index.sqlite-wal").unlink()
        db = sqlite3.connect(self.root / "chat-index.sqlite")
        db.execute("UPDATE messages SET json=?", (json.dumps(message("changed")),))
        db.commit(); db.close()
        with self.assertRaisesRegex(archive_search.SearchError, "RECORD_CHANGED"):
            self.page(key)

    def test_blank_queries_zero_width_regex_and_eof_are_bounded(self):
        text = "🧬" * 90000
        write_archive(self.root, [message(text)])
        row = self.search(query="")["records"][0]
        self.assertEqual(row["text_offset"], 0)
        end = self.page(row["archive_record_key"], len(text), 1)
        self.assertTrue(end["eof"])
        self.assertEqual(end["text"], "")
        row = self.search(query="$", query_mode="regex")["records"][0]
        self.assertEqual(row["match_offset"], len(text))
        self.assertEqual(row["text_end"], len(text))


if __name__ == "__main__":
    unittest.main(verbosity=2)
