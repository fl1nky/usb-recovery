"""Official Java wire oracle + native SQLite/WAL, never personal data."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "helpers/recovery_engine"), str(ROOT / "tests")]
import archive_search
import engine
import telegram_auto
import telegram_media_cache
from telegram_tl import TelegramTlError
from build_telegram_media_cache_profile_fixtures import load_cases, create, expected_parts, inventory, MEDIA_SCHEMA


class TelegramMediaCacheProfiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = list(load_cases())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="owned-official-cache-profiles-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sequence = 0

    def sample(self, layer=118, mode=0, direction=0):
        return next(case for case in self.cases if case["layer"] == layer and case["mode"] == mode
                    and case["direction"] == direction and case["media_constructor"] == "0xb5223b0f")

    def analyze(self, case, variant="current", source=None):
        self.sequence += 1
        if source is None:
            source, golden = create(self.root / ("input-" + str(self.sequence)), case, variant)
        else:
            golden = None
        source_root = source if source.is_dir() else source.parent
        before = inventory(source_root)
        output = self.root / ("archive-" + str(self.sequence))
        with patch.object(engine, "emit"):
            summary = telegram_auto.analyze(dict(protocol=1, operation="telegram_analyze",
                destination=str(output), options=dict(roots=[str(source)])), engine.Importer, lambda *a, **k: None)
        self.assertEqual(before, inventory(source_root), "Every supplied input byte stays unchanged")
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf8").splitlines()]
        return output, summary, rows, golden

    def assert_parts(self, case, rows):
        expected = {part["text_field"]: part["text"] for part in expected_parts(case)}
        self.assertEqual({row["text_field"]: row["text"] for row in rows}, expected)
        self.assertEqual(len(rows), len(expected), "Distinct field slots must neither disappear nor duplicate")
        for row in rows:
            self.assertEqual(row["native_tl_body_sha256"], case["tl_body_sha256"])
            self.assertEqual((row["chat_id"], row["message_id"]), (case["exact_sql"]["uid"], 41))
            self.assertEqual((row["native_layer"], row["native_constructor"]), (case["layer"], case["constructor"]))
            sender = case["expected"]["from_peer"]
            self.assertEqual(row["sender_id"], None if sender is None else "user:" + str(sender["id"]))
            self.assertEqual(dt.datetime.fromisoformat(row["timestamp"]).timestamp(), 1790000000)
            self.assertEqual(row["attachments"], [])
            self.assertEqual(row["media_status"], "photo_reference_only")
            self.assertIsNone(row.get("deleted"))

    def test_all_855_official_bodies_pass_exact_sql_checks(self):
        self.assertEqual(len({case["constructor"] for case in self.cases}), 19)
        self.assertEqual(len({case["media_constructor"] for case in self.cases}), 5)
        con = sqlite3.connect(":memory:")
        self.addCleanup(con.close)
        con.execute("CREATE TABLE media_v4(" + MEDIA_SCHEMA + ")")
        for case in self.cases:
            with self.subTest(case=case["name"]):
                sql = case["exact_sql"]
                con.execute("DELETE FROM media_v4")
                con.execute("INSERT INTO media_v4 VALUES(?,?,?,?,?)", (41, sql["uid"], sql["date"], 0, case["blob"]))
                rows = list(telegram_media_cache.photo_captions(con, max_rows=1))
                self.assertEqual(len(rows), 1)
                value = rows[0]["value"]
                for name, wanted in case["expected"].items():
                    self.assertEqual(value[name], wanted)
                self.assertEqual(value["media"].get("legacy_caption"), case["expected_legacy_caption"])
                self.assertEqual(value["tl_bytes"], case["tl_bytes"])

    def test_rows_flags_and_unregistered_constructors_stay_rejected(self):
        case = self.sample()
        uid, date, blob = case["exact_sql"]["uid"], case["exact_sql"]["date"], case["blob"]
        bad = [(42, uid, date, 0, blob), (41, uid, date + 1, 0, blob),
               (41, 0, date, 0, blob), (41, 77 << 32, date, 0, blob),
               ((99 << 32) | 41, uid, date, 0, blob), (41, uid, date, 1, blob),
               (41, uid, date, 0, b"\xff" * len(blob)), (41, uid, date, 0, blob[:-1])]
        for row in bad:
            with self.subTest(row=row[:4]):
                with self.assertRaises((telegram_media_cache.MediaCacheError, TelegramTlError)):
                    telegram_media_cache._checked(row)
        unsupported = bytearray(blob)
        unsupported[4:8] = (int.from_bytes(unsupported[4:8], "little") | (1 << 20)).to_bytes(4, "little")
        with self.assertRaises(TelegramTlError):
            telegram_media_cache._checked((41, uid, date, 0, bytes(unsupported)))

    def test_actual_analyzer_all_nineteen_profiles_and_five_relations(self):
        layers = sorted({case["layer"] for case in self.cases})
        for number, layer in enumerate(layers):
            with self.subTest(layer=layer):
                case = self.sample(layer, number % 3, number % 5)
                _, summary, rows, _ = self.analyze(case)
                self.assert_parts(case, rows)
                self.assertEqual(summary["native_records"], len(expected_parts(case)))
                self.assertEqual(summary["deleted_supported_records"], 0)

    def test_both_original_text_slots_are_searchable_without_concatenation(self):
        case = self.sample()
        output, _, rows, _ = self.analyze(case)
        self.assert_parts(case, rows)
        self.assertEqual({row["record_kind"] for row in rows}, {"telegram_media_cache", "telegram_media_cache_caption"})
        for needle, field in (("Outer", "message"), ("Legacy", "media.legacy_caption")):
            result = archive_search.search(dict(protocol=1, operation="search", archive=str(output),
                app="Telegram", query=needle))
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["records"][0]["text_field"], field)
            self.assertEqual(result["records"][0]["text"], next(row["text"] for row in rows if row["text_field"] == field))
        regex = archive_search.search(dict(protocol=1, operation="search", archive=str(output),
            app="Telegram", query="Legacy[\\s\\S]*第二行", query_mode="regex"))
        self.assertEqual(regex["total"], 1)
        self.assertEqual(regex["records"][0]["text_field"], "media.legacy_caption")

    def test_legacy_caption_without_outer_text_has_an_explicit_primary_role(self):
        case = self.sample(mode=1, direction=4)
        _, _, rows, _ = self.analyze(case)
        self.assert_parts(case, rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record_kind"], "telegram_media_cache")
        self.assertEqual(rows[0]["text_field"], "media.legacy_caption")

    def test_current_native_primary_keeps_both_distinct_cache_origins(self):
        case = self.sample()
        _, _, rows, _ = self.analyze(case, "primary-current")
        self.assert_parts(case, rows)
        self.assertEqual({row["record_kind"] for row in rows}, {"tl_message", "tl_message_caption"})
        for row in rows:
            origins = row["additional_sources"]
            self.assertTrue(origins)
            self.assertTrue(all(origin["text_field"] == row["text_field"] for origin in origins))
            self.assertTrue(all(origin["record_kind"] in telegram_auto.CACHE_RECORD_KINDS for origin in origins))

    def test_previous_native_primary_promotes_both_weaker_cache_parts(self):
        case = self.sample(direction=3)
        _, _, rows, _ = self.analyze(case, "primary-historical")
        self.assert_parts(case, rows)
        self.assertEqual({row["record_kind"] for row in rows}, {"tl_message", "tl_message_caption"})
        for row in rows:
            self.assertEqual(row["evidence_kind"], "previous")
            self.assertEqual(row["wal_proof"], "all_pages_from_validated_wal")
            self.assertTrue(all(origin["text_field"] == row["text_field"] for origin in row["additional_sources"]))

    def test_native_sqlite_wal_recovers_both_original_cache_fields(self):
        case = self.sample(mode=2)
        _, _, rows, _ = self.analyze(case, "history")
        self.assert_parts(case, rows)
        for row in rows:
            self.assertEqual(row["evidence_kind"], "previous")
            self.assertEqual(row["wal_proof"], "all_pages_from_validated_wal")
            self.assertEqual(row["recovery_status"], "historical_cache_record")

    def test_native_residual_proof_is_bound_to_the_same_checked_field(self):
        case = self.sample()
        output, _, rows, _ = self.analyze(case, "native-residual")
        self.assert_parts(case, rows)
        self.assertEqual({row["record_kind"] for row in rows}, {"tl_message", "tl_message_caption"})
        for row in rows:
            self.assertEqual(row["recovery_status"], "deleted_supported_by_evidence")
            self.assertEqual(row["wal_proof"], "all_pages_from_validated_wal")
            self.assertTrue(row["residual_sources"])
            for origin in row["residual_sources"]:
                self.assertEqual(origin["text_field"], row["text_field"])
                file = Path(origin["source_file"] + "-wal")
                with file.open("rb") as stream:
                    stream.seek(origin["physical_byte_offset"])
                    raw = stream.read(origin["sqlite_record_length"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), origin["sqlite_record_sha256"])
        self.assertTrue((output / "messages.jsonl").is_file())

    def test_field_roles_and_cache_origins_survive_reimport_and_jsonl_fallback(self):
        case = self.sample()
        archive, _, original, _ = self.analyze(case, "primary-current")
        _, _, rows, _ = self.analyze(case, source=archive / "messages.jsonl")
        self.assert_parts(case, rows)
        for row in rows:
            self.assertEqual(row["provenance_verification"], "provided_archive_metadata")
            self.assertTrue(all(origin["text_field"] == row["text_field"] for origin in row["additional_sources"]))
        first = archive_search.search(dict(protocol=1, operation="search", archive=str(archive), app="Telegram", query="Legacy"))
        (archive / "chat-index.sqlite").rename(archive / "retained-original-index.sqlite")
        fallback = archive_search.search(dict(protocol=1, operation="search", archive=str(archive), app="Telegram", query="Legacy"))
        self.assertEqual(first["records"][0]["text_field"], "media.legacy_caption")
        self.assertEqual(first["records"][0]["sources"], fallback["records"][0]["sources"])
        self.assertEqual(fallback["records"][0]["text"], next(row["text"] for row in original if row["text_field"] == "media.legacy_caption"))


if __name__ == "__main__":
    unittest.main()
