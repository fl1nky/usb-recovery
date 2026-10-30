"""Search must preserve residual evidence without turning fragments into chats."""
from pathlib import Path
import json
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers/recovery_engine"))
from archive_search import search


class DeletedArchiveSearch(unittest.TestCase):
    def test_jsonl_and_sqlite_filter_provenance_and_unknown_fragment_identity(self):
        for indexed in (False, True):
            with self.subTest(indexed=indexed), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                rows = [dict(app="Telegram", evidence_kind="backup", text="живое сообщение", chat_id=1, message_id=7),
                        dict(app="Telegram", evidence_kind="backup", text="Рецепт\nпирожков", chat_id=1, message_id=8,
                             recovery_status="deleted_supported_by_evidence", deleted=None, sqlite_page=3,
                             physical_byte_offset=8224, native_tl_body_sha256="a" * 64,
                             residual_sources=[dict(sqlite_page=3, physical_source="db", physical_byte_offset=8224,
                                                    proof="reachable table leaf", password="never forward")]),
                        dict(app="Telegram", evidence_kind="fragment", text="пирожков", chat_id=None, sender_id=None,
                             timestamp=None, candidate_message_id=8, record_kind="sqlite_wal_residual")]
                (root / "messages.jsonl").write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows), encoding="utf-8")
                if indexed:
                    with sqlite3.connect(root / "chat-index.sqlite") as connection:
                        connection.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY,json TEXT)")
                        connection.executemany("INSERT INTO messages(json) VALUES(?)", [(json.dumps(row),) for row in rows])
                    connection.close()
                result = search(dict(protocol=1, operation="search", archive=str(root), app="Telegram", query="пирожков", evidence="deleted"))
                self.assertEqual(result["total"], 1)
                row = result["records"][0]
                self.assertEqual(row["physical_byte_offset"], 8224)
                self.assertIsNone(row["deleted"])
                self.assertEqual(row["native_tl_body_sha256"], "a" * 64)
                self.assertNotIn("password", row["residual_sources"][0])
                fragment = search(dict(protocol=1, operation="search", archive=str(root), query="пирожков", evidence="fragment"))["records"][0]
                self.assertIsNone(fragment["chat_id"])
                self.assertIsNone(fragment["sender_id"])
                self.assertIsNone(fragment["timestamp"])
                self.assertEqual(fragment["candidate_message_id"], 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
