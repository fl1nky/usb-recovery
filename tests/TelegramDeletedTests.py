"""Real SQLite DELETE/WAL fixtures plus independent TL wire serialization.

Fixtures are generated with SQLite, not with recovery parser internals. The
20-column Android layouts and secure_delete=ON fact are pinned to official
MessagesStorage.java at 4de548e79fed27f1a66fbdff84223321838fe925. No personal
profile, device, account keys or process memory is accessed by these tests.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "helpers/recovery_engine"), str(ROOT / "tests")]
from build_telegram_native_fixtures import message, DATE
import sqlite_deleted as deleted
import telegram_auto
import engine
from memory_fragments import scan_tl
from text_match import Matcher

engine.emit = lambda *a, **k: None

ACTUAL_COLUMNS = "mid INTEGER,uid INTEGER,read_state INTEGER,send_state INTEGER,date INTEGER,data BLOB,out INTEGER,ttl INTEGER,media INTEGER,replydata BLOB,imp INTEGER,mention INTEGER,forwards INTEGER,replies_data BLOB,thread_reply_id INTEGER,is_channel INTEGER,reply_to_message_id INTEGER,custom_params BLOB,group_id INTEGER,reply_to_story_id INTEGER"
TOPIC_COLUMNS = "mid INTEGER,uid INTEGER,topic_id INTEGER,read_state INTEGER,send_state INTEGER,date INTEGER,data BLOB,out INTEGER,ttl INTEGER,media INTEGER,replydata BLOB,imp INTEGER,mention INTEGER,forwards INTEGER,replies_data BLOB,thread_reply_id INTEGER,is_channel INTEGER,reply_to_message_id INTEGER,custom_params BLOB,reply_to_story_id INTEGER"


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checksum(raw, state=(0, 0)):
    # Independent fixture writer for the specified little-endian WAL variant.
    first, second = state
    words = struct.unpack("<" + "I" * (len(raw) // 4), raw)
    for index in range(0, len(words), 2):
        first = (first + words[index] + second) % (1 << 32)
        second = (second + words[index + 1] + first) % (1 << 32)
    return first, second


def wal_bytes(frames, page_size=4096):
    salt = (0x12345678, 0xAABBCCDD)
    header = struct.pack(">6I", 0x377F0682, 3007000, page_size, 0, *salt)
    state = checksum(header)
    result = header + struct.pack(">2I", *state)
    for page, commit, content in frames:
        if len(content) != page_size:
            raise ValueError("fixture page size")
        first = struct.pack(">2I", page, commit)
        state = checksum(first + content, state)
        result += first + struct.pack(">2I", *salt) + struct.pack(">2I", *state) + content
    return result


class TelegramDeleted(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="TelegramDeleted-synthetic-")
        self.base = Path(self.temp.name)
        self.number = 0

    def tearDown(self):
        self.temp.cleanup()

    def database(self, *, page_size=4096, secure=False, encoding="UTF-8", actual=False, topics=False, note=False, rows=7):
        self.number += 1
        path = self.base / ("db" + str(self.number)) / "cache4.db"
        path.parent.mkdir()
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA page_size=" + str(page_size))
        connection.execute("PRAGMA encoding='" + encoding + "'")
        connection.execute("PRAGMA secure_delete=" + ("ON" if secure else "OFF"))
        table = "messages_topics" if topics else "messages_v2"
        columns = TOPIC_COLUMNS if topics else ACTUAL_COLUMNS if actual else "mid INTEGER,uid INTEGER,date INTEGER,data BLOB"
        if note:
            columns += ",note TEXT"
        primary = "mid,topic_id,uid" if topics else "mid,uid"
        connection.execute("CREATE TABLE " + table + "(" + columns + ",PRIMARY KEY(" + primary + "))")
        for mid in range(1, rows + 1):
            text = "recipe " + str(mid) + " яблоки 🥧 " + "Я" * 60
            uid = -88 if topics else 77
            raw = message(text, mid=mid, dialog=abs(uid), kind="channel" if topics else "user")
            names = ["mid", "uid", "date", "data"]
            values = [mid, uid, DATE, raw]
            if topics:
                names += ["topic_id"]
                values += [7]
            if note:
                names += ["note"]
                values += ["Кириллица 🥧 UTF-16"]
            connection.execute("INSERT INTO " + table + "(" + ",".join(names) + ") VALUES(" + ",".join("?" for value in values) + ")", values)
        connection.commit()
        return path, connection, table

    def delete(self, connection, table, mids=(3, 4, 5)):
        connection.execute("DELETE FROM " + table + " WHERE mid IN (" + ",".join("?" for x in mids) + ")", mids)
        connection.commit()

    def recover(self, path, **kwargs):
        report = {}
        before = sha(path)
        records = deleted.recover(path, report=report, **kwargs)
        self.assertEqual(sha(path), before)
        return records, report

    def analyze(self, path, **options):
        self.number += 1
        output = self.base / ("out" + str(self.number))
        result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(output),
            "options": {"roots": [str(path)], **options}}, engine.Importer, engine.emit)
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        return output, result, rows

    def test_actual_delete_coalesced_freeblocks_recovers_exact_three_rows(self):
        path, connection, table = self.database()
        expected = dict(connection.execute("SELECT mid,data FROM messages_v2 WHERE mid IN (3,4,5)"))
        self.delete(connection, table)
        connection.close()
        records, report = self.recover(path)
        self.assertEqual({r["row"]["mid"]: r["row"]["data"] for r in records}, expected)
        self.assertEqual(report["recovered_records"], 3)
        self.assertTrue(any(r["sqlite_header_length_reconstructed"] for r in records))
        for row in records:
            self.assertEqual(row["recovery_status"], "deleted_supported_by_evidence")
            self.assertEqual(row["deletion_interpretation"], "row_absent_from_current_table")
            self.assertIsNone(row["deleted"])
            with path.open("rb") as source:
                source.seek(row["physical_byte_offset"])
                self.assertEqual(hashlib.sha256(source.read(row["sqlite_record_length"])).hexdigest(), row["sqlite_record_sha256"])

    def test_pinned_android_wide_schema_and_topic_layout(self):
        for topics in (False, True):
            with self.subTest(topics=topics):
                path, connection, table = self.database(actual=True, topics=topics)
                self.delete(connection, table)
                connection.close()
                records, _ = self.recover(path)
                self.assertEqual({r["row"]["mid"] for r in records}, {3, 4, 5})
                self.assertTrue(all(r["table"] == table for r in records))
                if topics:
                    self.assertTrue(all(r["row"]["topic_id"] == 7 and r["row"]["uid"] == -88 for r in records))

    def test_page_sizes_and_database_text_encodings(self):
        for size, encoding in ((512, "UTF-8"), (4096, "UTF-16le"), (4096, "UTF-16be"), (65536, "UTF-8")):
            with self.subTest(size=size, encoding=encoding):
                path, connection, table = self.database(page_size=size, encoding=encoding, note=size != 512)
                expected = {3, 5} if size == 512 else {3, 4, 5}
                self.delete(connection, table, tuple(expected))
                connection.close()
                records, report = self.recover(path)
                self.assertEqual({r["row"]["mid"] for r in records}, expected)
                if size != 512:
                    self.assertTrue(all(r["row"]["note"] == "Кириллица 🥧 UTF-16" for r in records))
                self.assertEqual(report["page_size"], size)

    def test_secure_delete_on_clears_these_rows(self):
        path, connection, table = self.database(secure=True)
        self.delete(connection, table)
        connection.close()
        records, report = self.recover(path, include_unattributed=True)
        self.assertEqual(records, [])
        self.assertEqual(report["recovered_records"], 0)

    def test_vacuum_does_not_invent_destroyed_rows(self):
        path, connection, table = self.database()
        self.delete(connection, table)
        connection.execute("VACUUM")
        connection.close()
        records, _ = self.recover(path, include_unattributed=True)
        self.assertEqual(records, [])

    def test_updated_old_body_is_previous_version_not_deleted_current_key(self):
        path, connection, table = self.database()
        connection.execute("UPDATE messages_v2 SET data=? WHERE mid=4", (message("changed longer text " * 100, mid=4),))
        connection.commit()
        connection.close()
        records, report = self.recover(path)
        previous = [r for r in records if r["row"]["mid"] == 4]
        self.assertEqual(len(previous), 1)
        self.assertEqual(previous[0]["recovery_status"], "previous_version_residual")
        self.assertEqual(report["recovered_records"], 0)

    def test_unrelated_table_does_not_get_telegram_table_attribution(self):
        path, connection, table = self.database()
        connection.execute("ALTER TABLE messages_v2 RENAME TO unrelated_records")
        self.delete(connection, "unrelated_records")
        connection.close()
        records, _ = self.recover(path)
        self.assertEqual(records, [])

    def test_sql_keys_date_dialog_and_secret_chat_mismatch_rejected(self):
        for column, bad in (("mid", 999), ("uid", 888), ("date", DATE + 1), ("uid", 77 << 32)):
            with self.subTest(column=column):
                path, connection, table = self.database()
                connection.execute("UPDATE messages_v2 SET " + column + "=? WHERE mid=4", (bad,))
                connection.commit()
                connection.execute("DELETE FROM messages_v2 WHERE " + column + "=?", (bad,))
                connection.commit()
                connection.close()
                records, _ = self.recover(path)
                self.assertFalse(any(r["row"].get(column) == bad for r in records))

    def test_freelist_pages_only_publish_unattributed_fragments(self):
        path, connection, table = self.database(rows=160)
        connection.execute("DELETE FROM messages_v2 WHERE mid>=5")
        connection.commit()
        self.assertGreater(connection.execute("PRAGMA freelist_count").fetchone()[0], 0)
        connection.close()
        records, report = self.recover(path, include_unattributed=True)
        fragments = [r for r in records if r.get("sqlite_region") == "freelist_leaf"]
        self.assertTrue(fragments)
        self.assertGreater(report["fragments"], 0)
        for value in fragments:
            for field in ("chat_id", "message_id", "sender_id", "timestamp", "deleted", "table"):
                self.assertIsNone(value[field])
            self.assertEqual(value["recovery_status"], "unattributed_structured_fragment")

    def test_freeblock_corruption_does_not_claim_trusted_records(self):
        path, connection, table = self.database()
        root = connection.execute("SELECT rootpage FROM sqlite_master WHERE name='messages_v2'").fetchone()[0]
        self.delete(connection, table)
        connection.close()
        with path.open("r+b") as source:
            source.seek((root - 1) * 4096 + 1)
            offset = int.from_bytes(source.read(2), "big")
            source.seek((root - 1) * 4096 + offset)
            source.write(offset.to_bytes(2, "big"))  # self-linked freeblock
        with self.assertRaises(deleted.DeletedError) as caught:
            self.recover(path)
        self.assertEqual(caught.exception.code, "DELETED_SQLITE_INVALID")

    def test_overwritten_payload_does_not_recover_original_bytes(self):
        path, connection, table = self.database()
        raw = connection.execute("SELECT data FROM messages_v2 WHERE mid=4").fetchone()[0]
        self.delete(connection, table)
        connection.close()
        with path.open("r+b") as source:
            data = source.read()
            at = data.find(raw)
            self.assertGreater(at, 0)
            source.seek(at)
            source.write(b"\0\0\0\0")
        records, _ = self.recover(path)
        self.assertFalse(any(r["row"]["mid"] == 4 for r in records))

    def test_limits_cancellation_and_bounded_reads(self):
        path, connection, table = self.database()
        self.delete(connection, table)
        connection.close()
        for limits in ({"max_scan_bytes": 1}, {"max_candidates": 1}, {"max_records": 1}):
            records, report = self.recover(path, limits=limits)
            self.assertTrue(report["limited"])
            self.assertLessEqual(len(records), 1)
        with self.assertRaises(deleted.DeletedError) as caught:
            deleted.recover(path, cancel=lambda: True)
        self.assertEqual(caught.exception.code, "CANCELLED")
        for limits in ({"max_records": 0}, {"max_pages": -1}, {"max_input_bytes": 1 << 50}, {"max_scan_bytes": True}):
            with self.assertRaises(deleted.DeletedError):
                deleted.recover(path, limits=limits)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read")):
            records, _ = self.recover(path)
            self.assertEqual(len(records), 3)

    def test_changed_source_discards_results(self):
        path, connection, table = self.database()
        self.delete(connection, table)
        connection.close()
        calls = 0
        def mutate():
            nonlocal calls
            calls += 1
            if calls == 9:
                with path.open("ab") as source:
                    source.write(b"x")
            return False
        with self.assertRaises(deleted.DeletedError) as caught:
            deleted.recover(path, cancel=mutate)
        self.assertEqual(caught.exception.code, "DELETED_SOURCE_CHANGED")

    def test_real_wal_secure_delete_on_superseded_body_is_fragment(self):
        path, connection, table = self.database(secure=True)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO messages_v2 VALUES(900,77,?,?)", (DATE, message("WAL-only removed recipe 🥧", mid=900)))
        connection.commit()
        self.delete(connection, table, (900,))
        wal_copy = self.base / "captured-wal"
        shutil.copyfile(Path(str(path) + "-wal"), wal_copy)
        report = {}
        records = deleted.wal_fragments(wal_copy, report=report)
        connection.close()
        target = [r for r in records if r["text"] == "WAL-only removed recipe 🥧"]
        self.assertTrue(target)
        value = target[0]
        self.assertEqual(value["candidate_message_id"], 900)
        self.assertIsNone(value["chat_id"])
        self.assertIsNone(value["timestamp"])
        self.assertIsNone(value["deleted"])
        self.assertEqual(value["sqlite_region"], "superseded_committed_wal_page")
        with wal_copy.open("rb") as source:
            source.seek(value["physical_byte_offset"])
            self.assertEqual(hashlib.sha256(source.read(value["byte_length"])).hexdigest(), value["native_tl_body_sha256"])

    def test_wal_ignores_never_committed_and_transaction_internal_preimages(self):
        def page(text, mid):
            content = message(text, mid=mid)
            return b"\0" * 128 + content + b"\0" * (4096 - 128 - len(content))
        path = self.base / "independent-wal"
        path.write_bytes(wal_bytes([(2, 0, page("never committed", 1)), (2, 2, page("committed recipe", 2)),
                                    (2, 2, page("latest page", 3)), (2, 0, page("uncommitted tail", 4))]))
        report = {}
        values = deleted.wal_fragments(path, report=report)
        self.assertEqual({r["text"] for r in values}, {"committed recipe"})
        self.assertEqual(report["uncommitted_frames"], 1)
        self.assertEqual(values[0]["wal_frame"], 2)
        self.assertEqual(values[0]["wal_commit_frame"], 2)

    def test_corrupt_wal_does_not_make_bad_frames_trusted(self):
        content = message("valid recipe", mid=1)
        page = content + b"\0" * (4096 - len(content))
        raw = bytearray(wal_bytes([(2, 2, page), (2, 2, b"\0" * 4096)]))
        raw[-30] ^= 1
        path = self.base / "corrupt-wal"
        path.write_bytes(raw)
        report = {}
        values = deleted.wal_fragments(path, report=report)
        # A single valid committed page with no verified replacement is not
        # called a superseded committed version.
        self.assertEqual(values, [])
        self.assertEqual(report["status"], "validated_prefix")
        self.assertEqual(report["tail_reason"], "frame_checksum")

    def test_wal_overlay_does_not_misclassify_main_db_freebytes_as_deleted(self):
        path, connection, table = self.database()
        self.delete(connection, table)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        for mid in (3, 4, 5):
            connection.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)", (mid, 77, DATE, message("restored current", mid=mid)))
        connection.commit()
        records, report = self.recover(path, connection=connection)
        self.assertFalse(any(r["recovery_status"] == "deleted_supported_by_evidence" for r in records))
        self.assertEqual(report["current_view"], "validated_committed_wal_overlay")
        connection.close()

    def test_dump_tl_cross_chunk_boundary_keeps_context_unknown(self):
        import memory_fragments
        path = self.base / "provided.mem"
        blob = message("cross-boundary recipe 🥧", mid=321)
        start = memory_fragments.CHUNK - 11
        path.write_bytes(b"\0" * start + blob + b"\0" * 80000)
        values = list(scan_tl(path, Matcher("recipe")))
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["byte_offset"], start)
        self.assertEqual(values[0]["candidate_message_id"], 321)
        self.assertIsNone(values[0]["message_id"])
        self.assertEqual(values[0]["physical_source"], "supplied_dump")
        self.assertEqual(list(scan_tl(path, Matcher("absent words"))), [])

    def test_automatic_analysis_keeps_status_offsets_and_keyword_search(self):
        path, connection, table = self.database(actual=True)
        self.delete(connection, table)
        connection.close()
        before = sha(path)
        output, result, rows = self.analyze(path)
        removed = [r for r in rows if r.get("recovery_status") == "deleted_supported_by_evidence"]
        self.assertEqual({r["message_id"] for r in removed}, {3, 4, 5})
        self.assertEqual(result["deleted_supported_records"], 3)
        self.assertTrue(all(r["record_kind"] == "sqlite_deleted_record" for r in removed))
        self.assertTrue(all(r["source_file"] == str(path) and r["source_sha256"] == before for r in removed))
        self.assertFalse(Path(str(output) + ".work").exists())
        from archive_search import search
        found = search({"protocol": 1, "operation": "search", "archive": str(output), "app": "Telegram",
                        "query": "recipe 4", "offset": 0, "limit": 20})
        self.assertEqual(found["total"], 1)

    def test_automatic_secure_delete_does_not_claim_removed_rows(self):
        path, connection, table = self.database(secure=True)
        self.delete(connection, table)
        connection.close()
        _, result, rows = self.analyze(path)
        self.assertEqual(result["deleted_supported_records"], 0)
        self.assertEqual({r["message_id"] for r in rows}, {1, 2, 6, 7})

    def test_automatic_secure_delete_wal_fallback_is_structured_fragment(self):
        path, connection, table = self.database(secure=True, actual=True)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO messages_v2(mid,uid,date,data) VALUES(900,77,?,?)",
                           (DATE, message("WAL fallback recipe 🥧", mid=900)))
        connection.commit()
        self.delete(connection, table, (900,))
        captured = self.base / "provided-copy" / "cache4.db"
        captured.parent.mkdir()
        for suffix in ("", "-wal"):
            shutil.copyfile(Path(str(path) + suffix), Path(str(captured) + suffix))
        original = {suffix: sha(Path(str(captured) + suffix)) for suffix in ("", "-wal")}
        connection.close()
        _, result, rows = self.analyze(captured)
        target = [r for r in rows if r["text"] == "WAL fallback recipe 🥧"]
        self.assertEqual(len(target), 1)
        record = target[0]
        self.assertEqual(record["record_kind"], "sqlite_wal_residual")
        self.assertEqual(record["evidence_kind"], "fragment")
        self.assertEqual(record["candidate_message_id"], 900)
        for field in ("chat_id", "message_id", "sender_id", "timestamp", "deleted"):
            self.assertIsNone(record[field])
        self.assertEqual(result["deleted_supported_records"], 0)
        self.assertGreater(result["structured_fragment_records"], 0)
        self.assertEqual(original, {suffix: sha(Path(str(captured) + suffix)) for suffix in original})

    def test_declared_encrypted_dialog_is_not_attributed_even_when_tl_matches(self):
        path, connection, table = self.database()
        secret = 77 << 32
        connection.execute("UPDATE messages_v2 SET uid=?,data=? WHERE mid=4",
                           (secret, message("not an attributed secret chat", mid=4, dialog=secret, sender=secret)))
        connection.commit()
        connection.execute("DELETE FROM messages_v2 WHERE uid=?", (secret,))
        connection.commit()
        connection.close()
        records, _ = self.recover(path)
        self.assertFalse(any(r["row"]["uid"] == secret for r in records))

    def test_restore_option_can_disable_new_structured_recovery(self):
        path, connection, table = self.database()
        self.delete(connection, table)
        connection.close()
        _, result, rows = self.analyze(path, recover_deleted=False)
        self.assertEqual(result["deleted_supported_records"], 0)
        self.assertEqual({r["message_id"] for r in rows}, {1, 2, 6, 7})

    def test_dump_analysis_publishes_typed_record_without_claiming_chat(self):
        path = self.base / "provided.mem"
        path.write_bytes(b"\0" * 33 + message("dump recipe keyword 🥧", mid=321) + b"\0" * 150)
        _, result, rows = self.analyze(path, scan_fragments=True, fragment_query="recipe")
        typed = [r for r in rows if r.get("record_kind") == "typed_tl_fragment"]
        self.assertEqual(len(typed), 1)
        self.assertEqual(typed[0]["byte_offset"], 33)
        self.assertEqual(typed[0]["candidate_message_id"], 321)
        self.assertIsNone(typed[0]["message_id"])
        self.assertEqual(result["history_messages"], 0)
        self.assertGreater(result["structured_fragment_records"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
