"""Strict wire parsing + complete synthetic native Telegram import tests."""
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
from telegram_tl import parse_message, TelegramTlError
from build_telegram_native_fixtures import message, peer, word, tl_string, LAYERS, DATE, build, create_schema
import engine
import telegram_auto
from archive_search import search

engine.emit = lambda *a, **k: None


class TelegramTlTests(unittest.TestCase):
    def rejected(self, raw, code):
        with self.assertRaises(TelegramTlError) as caught:
            parse_message(raw)
        self.assertEqual(caught.exception.code, code)

    def test_all_nineteen_official_text_constructors(self):
        for layer, constructor in LAYERS:
            with self.subTest(layer=layer):
                parsed = parse_message(message("Рецепт 🥧\nяблоки", layer=layer))
                self.assertEqual((parsed["text"], parsed["id"], parsed["date"], parsed["layer"]), ("Рецепт 🥧\nяблоки", 1, DATE, layer))
                self.assertEqual(parsed["constructor"], f"0x{constructor:08x}")
                self.assertEqual(parsed["from_peer"], {"kind": "user", "id": 77})
                self.assertTrue(parsed["local_tail_present"])

    def test_wire_record_without_android_tail(self):
        raw = message("surviving wire text", tail=False)
        parsed = parse_message(raw)
        self.assertFalse(parsed["local_tail_present"])
        self.assertEqual(parsed["consumed_bytes"], len(raw))

    def test_unknown_sender_stays_unknown(self):
        self.assertIsNone(parse_message(message("unknown", sender=None))["from_peer"])

    def test_group_channel_peers_and_outgoing(self):
        for kind in ("chat", "channel"):
            parsed = parse_message(message("group", kind=kind, dialog=77777777777, out=True))
            self.assertEqual(parsed["peer"], {"kind": kind, "id": 77777777777})
            self.assertTrue(parsed["out"])

    def test_edited_text_entity_and_empty_media(self):
        entities = word(0x1cb5c415) + word(1) + word(0xbd610bc9) + word(0) + word(2)
        parsed = parse_message(message("🥧 recipe", flags=512 | 128 | (1 << 15),
                    after=word(0x3ded6320) + entities + word(DATE + 20)))
        self.assertEqual(parsed["entities"][0]["length"], 2)
        self.assertEqual(parsed["edit_date"], DATE + 20)
        self.assertEqual(parsed["media"]["type"], "empty")

    def test_long_string_prefix_and_unicode(self):
        text = "Яблоки" * 300
        self.assertEqual(parse_message(message(text))["text"], text)

    def test_negative_id_android_tail_not_followed(self):
        # Path remains opaque, including absolute/URL-looking values.
        raw = message("unsent", mid=-5, out=True, tail=False) + tl_string("https://example.invalid/private")
        parsed = parse_message(raw)
        self.assertEqual(parsed["id"], -5)
        self.assertNotIn("attachPath", parsed)
        self.assertNotIn("private", str(parsed))

    def test_every_truncated_prefix_rejected(self):
        raw = message("important 🥧 recipe", tail=False)
        for length in range(len(raw)):
            with self.subTest(length=length), self.assertRaises(TelegramTlError):
                parse_message(raw[:length])

    def test_unknown_constructor(self):
        self.rejected(word(0x12345678) + b"\0" * 100, "TL_UNSUPPORTED_CONSTRUCTOR")

    def test_unknown_flag(self):
        self.rejected(message("not accepted", flags=1 << 31), "TL_UNSUPPORTED_FLAGS")

    def test_unknown_flags2(self):
        self.rejected(message("not accepted", flags2=1 << 31), "TL_UNSUPPORTED_FLAGS")

    def test_unknown_media_does_not_turn_into_verified_text(self):
        self.rejected(message("looks readable but unsupported", flags=512, after=word(0x12345678)), "TL_UNSUPPORTED_MEDIA")

    def test_complex_reaction_not_blindly_skipped(self):
        self.rejected(message("reaction", flags=1 << 20), "TL_UNSUPPORTED_NESTED")

    def test_unknown_trailer_rejected(self):
        self.rejected(message("text") + b"arbitrary bytes", "TL_UNSUPPORTED_TRAILING_BYTES")

    def test_invalid_utf8_padding_and_noncanonical_length(self):
        base = message("", tail=False)[:-4]
        self.rejected(base + b"\x01\xff\0\0", "TL_INVALID_UTF8")
        self.rejected(base + b"\x01a\1\0", "TL_INVALID_PADDING")
        self.rejected(base + b"\xfe\1\0\0a\0\0\0", "TL_NONCANONICAL_STRING")

    def test_invalid_entity_utf16_range(self):
        entity = word(0x1cb5c415) + word(1) + word(0xbd610bc9) + word(2) + word(1)
        self.rejected(message("🥧", flags=128, after=entity), "TL_INVALID_ENTITY_RANGE")

    def test_input_and_size_limit(self):
        self.rejected("text", "TL_INVALID_INPUT")
        self.rejected(b"", "TL_BLOB_LIMIT")
        self.rejected(b"\0" * (4 * 1024 * 1024 + 1), "TL_BLOB_LIMIT")


class NativeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="Telegram-native-tests-")
        self.base = Path(self.temporary.name)
        self.fixtures = self.base / "fixtures"
        build(self.fixtures)
        self.number = 0

    def tearDown(self):
        self.temporary.cleanup()

    def analyze(self, name, **options):
        self.number += 1
        output = self.base / ("archive-" + str(self.number))
        result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(output),
            "options": {"roots": [str(self.fixtures / name)], **options}}, engine.Importer, engine.emit)
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        return output, result, rows

    def test_current_edited_and_deleted_previous_versions_with_proof(self):
        original = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.fixtures.rglob("*") if p.is_file()}
        output, result, rows = self.analyze("valid")
        self.assertEqual(result["history_messages"], 3)
        self.assertEqual(result["native_records"], 3)
        self.assertEqual(result["previous_records"], 2)
        by_text = {r["text"]: r for r in rows}
        self.assertEqual(by_text["Current recipe"]["evidence_kind"], "backup")
        for text in ("Old recipe before edit", "Deleted recipe before removal"):
            row = by_text[text]
            self.assertEqual(row["evidence_kind"], "previous")
            self.assertEqual(row["wal_proof"], "all_pages_from_validated_wal")
            self.assertGreater(row["wal_commit_frame"], 0)
            self.assertEqual(len(row["wal_sha256"]), 64)
            self.assertEqual(len(row["wal_snapshot_sha256"]), 64)
            self.assertNotIn(".work", row["source_file"])
        self.assertEqual(original, {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.fixtures.rglob("*") if p.is_file()})
        self.assertFalse(Path(str(output) + ".work").exists())
        found = search({"protocol": 1, "operation": "search", "archive": str(output), "query": "Deleted.*removal",
                        "query_mode": "regex", "app": "Telegram", "evidence": "previous", "limit": 10})
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["records"][0]["wal_proof"], "all_pages_from_validated_wal")

    def test_identical_ids_from_independent_databases_do_not_merge(self):
        _, result, rows = self.analyze("cross-account")
        self.assertEqual(result["native_records"], 2)
        self.assertEqual(len({r["identity_scope"] for r in rows}), 2)

    def test_missing_preimages_never_borrow_current_base_pages(self):
        _, result, rows = self.analyze("missing-preimage")
        # An earlier complete snapshot is still unprovable. The new residual
        # reader independently finds this intact SQL/TL record in unused bytes
        # of the latest validated WAL page and current reachable table.
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record_kind"], "sqlite_deleted_record")
        self.assertEqual(rows[0]["recovery_status"], "deleted_supported_by_evidence")
        self.assertEqual(rows[0]["physical_source"], "wal")
        self.assertEqual(rows[0]["evidence_kind"], "backup")
        self.assertNotIn("wal_snapshot_sha256", rows[0])
        self.assertEqual(result["previous_records"], 0)
        self.assertIn("TELEGRAM_WAL_HISTORY_INCOMPLETE", result["warnings"])

    def test_corrupt_last_commit_cannot_publish_current_payload(self):
        _, result, rows = self.analyze("corrupt-wal")
        self.assertNotIn("Current recipe", [row["text"] for row in rows])
        self.assertIn("TELEGRAM_WAL_INVALID", result["warnings"])

    def test_mismatched_mid_uid_date_unknown_constructor_are_not_history(self):
        source = self.fixtures / "wrong/cache4.db"
        source.parent.mkdir()
        con = sqlite3.connect(source)
        try:
            create_schema(con)
            for mid, uid, date, data in ((99, 77, DATE, message("wrong mid")), (3, 88, DATE, message("wrong dialog", mid=3)),
                (4, 77, DATE + 1, message("wrong date", mid=4)), (5, 77, DATE, word(0x12345678) + b"readable"),
                (6, 77, DATE, message("contradicting incoming sender", mid=6, sender=88)),
                (7, 77, DATE, message("wrong outgoing destination", mid=7, out=True, dialog=88))):
                con.execute("INSERT OR REPLACE INTO messages_v2 VALUES(?,?,?,?)", (mid, uid, date, data))
            con.commit()
        finally:
            con.close()
        _, result, rows = self.analyze("wrong")
        self.assertEqual(rows, [])
        self.assertIn("TELEGRAM_TL_HISTORY_UNSUPPORTED", result["warnings"])

    def test_topic_channel_unknown_author_and_notifications_coexist(self):
        source = self.fixtures / "topics/cache4.db"
        source.parent.mkdir()
        con = sqlite3.connect(source)
        try:
            con.executescript("CREATE TABLE messages_topics(mid INTEGER,uid INTEGER,date INTEGER,data BLOB,topic_id INTEGER);"
                "CREATE TABLE unread_push_messages(uid INTEGER,mid INTEGER,date INTEGER,fm TEXT);")
            con.execute("INSERT INTO messages_topics VALUES(3,-88,?,?,7)", (DATE, message("Тема рецепт", mid=3, dialog=88, sender=None, kind="channel")))
            con.execute("INSERT INTO unread_push_messages VALUES(-88,3,?,'Тема рецепт')", (DATE,))
            con.commit()
        finally:
            con.close()
        _, result, rows = self.analyze("topics")
        self.assertEqual(result["native_records"], 1)
        self.assertEqual(result["notification_records"], 1)
        self.assertEqual(result["history_messages"], 1)
        self.assertTrue(all(row["sender_id"] is None for row in rows))
        self.assertIn("topic_id=7", next(r["source_record"] for r in rows if r["record_kind"] == "tl_message"))

    def test_native_reimport_keeps_proof_and_previous_category(self):
        output, _, first = self.analyze("valid")
        self.number += 1
        destination = self.base / ("archive-" + str(self.number))
        result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(destination),
            "options": {"roots": [str(output / "messages.jsonl")]}}, engine.Importer, engine.emit)
        rows = [json.loads(line) for line in (destination / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(result["previous_records"], 2)
        self.assertEqual({r["wal_proof"] for r in rows}, {r["wal_proof"] for r in first})


if __name__ == "__main__":
    unittest.main(verbosity=2)
