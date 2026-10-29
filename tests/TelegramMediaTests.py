"""Independent official-layout photo TL fixtures and end-to-end local imports.

Field order follows pinned Telegram Android TLRPC.java at commit
4de548e79fed27f1a66fbdff84223321838fe925, not the production decoder.
No personal caches/devices, remote URLs or active accounts are accessed.
"""
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from build_telegram_native_fixtures import message, word, tl_string, DATE, create_schema
from telegram_tl import parse_message, TelegramTlError
import engine
import telegram_auto

engine.emit = lambda *args, **kwargs: None


def integer64(value):
    return struct.pack("<q", value)


def vector(values):
    return word(0x1CB5C415) + word(len(values)) + b"".join(values)


def location(constructor=0xBC7FC6CD):
    if constructor == 0xBC7FC6CD:
        return word(constructor) + integer64(-100) + word(77)
    body = integer64(-100) + word(77) + integer64(987654321)
    if constructor in (0x53D69076, 0x091D11EB):
        body = word(2) + body
    if constructor == 0x091D11EB:
        body += tl_string("PRIVATE_REFERENCE_NOT_PUBLISHED")
    return word(constructor) + body


def size(kind="remote", content=b"", width=32, height=24, legacy=False):
    code = {"empty": 0x0E17E23C, "remote": 0x77BFB61B if legacy else 0x75C78E60,
            "cached": 0xE9A734FA if legacy else 0x021E1AD6,
            "progressive": 0x5AA86A51 if legacy else 0xFA3EFB95,
            "stripped": 0xE0B0BC2E, "path": 0xD8214D41}[kind]
    body = word(code) + tl_string("s")
    if kind == "empty":
        return body
    if kind in ("stripped", "path"):
        return body + tl_string(content)
    if legacy:
        body += location()
    body += word(width) + word(height)
    if kind == "cached":
        return body + tl_string(content)
    if kind == "progressive":
        return body + vector([word(100), word(200), word(300)])
    return body + word(1234)


def photo(sizes=(), constructor=0xFB197A65, flags=0):
    if constructor == 0x2331B22D:
        return word(constructor) + integer64(50)
    result = word(constructor)
    if constructor != 0xCDED42FE:
        result += word(flags)
    result += integer64(7777) + integer64(3456789)
    if constructor in (0xFB197A65, 0xD07504A5, 0x9C477DD8):
        result += tl_string("PRIVATE_PHOTO_REFERENCE_NOT_PUBLISHED")
    result += word(DATE) + vector(sizes)
    if constructor in (0xFB197A65, 0xD07504A5):
        result += word(2)
    return result


def media(payload=None, constructor=0xE216EB63, flags=1, caption="legacy caption"):
    result = word(constructor)
    if constructor in (0x3D8CE53D, 0xC8C45A2A):
        result += photo() if payload is None else payload
        if constructor == 0x3D8CE53D:
            result += tl_string(caption)
    else:
        result += word(flags)
        if flags & 1:
            result += photo() if payload is None else payload
        if constructor == 0xB5223B0F and flags & 2:
            result += tl_string(caption)
        if flags & 4:
            result += word(30)
    return result


def image():
    from PIL import Image
    stream = io.BytesIO()
    Image.new("RGB", (32, 24), (129, 71, 33)).save(stream, "JPEG", quality=85)
    return stream.getvalue()


def photo_message(caption="Семейный рецепт 🥧", payload=None, mid=1, tail=True):
    return message(caption, flags=512, after=media(payload), mid=mid, tail=tail)


class TelegramMediaWire(unittest.TestCase):
    def test_current_caption_and_reference_only_photo(self):
        value = parse_message(photo_message(payload=photo([size()])))
        self.assertEqual(value["text"], "Семейный рецепт 🥧")
        self.assertEqual(value["media"]["photo"]["id"], 7777)
        self.assertEqual(value["media"]["photo"]["sizes"][0]["encoded_bytes"], 1234)
        self.assertNotIn("PRIVATE_PHOTO_REFERENCE_NOT_PUBLISHED", repr(value))

    def test_all_five_photo_media_constructors(self):
        for constructor in (0xE216EB63, 0x695150D7, 0xB5223B0F, 0x3D8CE53D, 0xC8C45A2A):
            with self.subTest(constructor=hex(constructor)):
                value = parse_message(message("caption", flags=512, after=media(constructor=constructor)))
                self.assertEqual(value["media"]["type"], "photo")

    def test_supported_photo_objects(self):
        for constructor in (0xFB197A65, 0xD07504A5, 0x9C477DD8, 0x9288DD29, 0xCDED42FE, 0x2331B22D):
            with self.subTest(constructor=hex(constructor)):
                value = parse_message(photo_message(payload=photo(constructor=constructor)))
                self.assertIn(value["media"]["photo"]["type"], ("empty", "photo"))

    def test_all_supported_size_types(self):
        entries = [size(kind, b"data", legacy=legacy) for kind in ("empty", "remote", "cached", "progressive", "stripped", "path")
                   for legacy in ([False, True] if kind in ("remote", "cached", "progressive") else [False])]
        value = parse_message(photo_message(payload=photo(entries)))
        self.assertEqual(len(value["media"]["photo"]["sizes"]), 9)

    def test_cached_image_exact_blob_offset(self):
        content = image()
        raw = photo_message(payload=photo([size("cached", content)]))
        item = parse_message(raw)["media"]["photo"]["sizes"][0]
        self.assertEqual(raw[item["blob_offset"]:item["blob_offset"] + len(content)], content)
        self.assertEqual(item["content"], content)

    def test_stripped_and_vector_path_are_not_complete_images(self):
        value = parse_message(photo_message(payload=photo([size("stripped", b"\1\4\5scan"), size("path", b"<script>never execute</script>")])))
        self.assertTrue(all("content" not in item for item in value["media"]["photo"]["sizes"]))

    def test_legacy_locations_are_consumed_without_exposed_secrets(self):
        for constructor in (0xBC7FC6CD, 0x7C596B46, 0x53D69076, 0x091D11EB):
            entry = word(0x77BFB61B) + tl_string("s") + location(constructor) + word(32) + word(24) + word(1234)
            value = parse_message(photo_message(payload=photo([entry])))
            self.assertNotIn("PRIVATE_REFERENCE", repr(value))
            self.assertNotIn("987654321", repr(value))

    def test_photo_missing_with_ttl_and_spoiler(self):
        value = parse_message(message("caption only", flags=512, after=media(flags=12)))
        self.assertEqual(value["media"]["photo"]["type"], "empty")
        self.assertEqual(value["media"]["ttl_seconds"], 30)
        self.assertTrue(value["media"]["spoiler"])

    def test_legacy_caption_parsed_separately(self):
        for constructor, flags in ((0xB5223B0F, 3), (0x3D8CE53D, 1)):
            value = parse_message(message("", flags=512, after=media(constructor=constructor, flags=flags, caption="Старое фото")))
            self.assertEqual(value["media"]["legacy_caption"], "Старое фото")

    def test_every_truncated_prefix_rejected(self):
        raw = photo_message(payload=photo([size("cached", image())]), tail=False)
        for count in range(len(raw)):
            with self.subTest(count=count), self.assertRaises(TelegramTlError):
                parse_message(raw[:count])

    def test_unknown_nested_constructor_rejected(self):
        for payload in (word(0x12345678), photo([word(0x12345678)])):
            with self.assertRaises(TelegramTlError):
                parse_message(photo_message(payload=payload))

    def test_live_photo_and_animated_photo_are_explicitly_rejected(self):
        for payload in (media(flags=17), media(photo(flags=2))):
            with self.assertRaises(TelegramTlError) as caught:
                parse_message(message("must not guess", flags=512, after=payload))
            self.assertEqual(caught.exception.code, "TL_UNSUPPORTED_FLAGS")

    def test_bad_dimensions_and_vector_limits(self):
        for entry in (size(width=-1), size(height=32769)):
            with self.assertRaises(TelegramTlError) as caught:
                parse_message(photo_message(payload=photo([entry])))
            self.assertEqual(caught.exception.code, "TL_INVALID_PHOTO_DIMENSIONS")
        with self.assertRaises(TelegramTlError) as caught:
            parse_message(photo_message(payload=photo([size("empty")] * 65)))
        self.assertEqual(caught.exception.code, "TL_VECTOR_LIMIT")

    def test_unknown_flags_and_trailing_bytes_rejected(self):
        for raw in (message("bad", flags=512, after=media(flags=32)),
                    photo_message(payload=photo(flags=4)), photo_message() + b"junk"):
            with self.assertRaises(TelegramTlError):
                parse_message(raw)


class TelegramMediaImport(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="Telegram-photo-local-")
        self.root = Path(self.temporary.name)
        self.input = self.root / "input"
        self.input.mkdir()
        self.number = 0

    def tearDown(self):
        self.temporary.cleanup()

    def analyze(self, blobs):
        self.number += 1
        source = self.input / ("source-" + str(self.number))
        source.mkdir()
        db = source / "cache4.db"
        connection = sqlite3.connect(db)
        try:
            create_schema(connection)
            for mid, raw in enumerate(blobs, 1):
                connection.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)", (mid, 77, DATE, raw))
            connection.commit()
        finally:
            connection.close()
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        output = self.root / ("archive-" + str(self.number))
        result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(output),
            "options": {"roots": [str(source)]}}, engine.Importer, engine.emit)
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
        self.assertFalse(Path(str(output) + ".work").exists())
        rows = [json.loads(row) for row in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        return output, result, rows, before

    def test_caption_with_missing_photo_survives_without_fabricated_attachment(self):
        output, result, rows, before = self.analyze([photo_message(payload=photo([size()]))])
        self.assertEqual(result["native_records"], 1)
        self.assertEqual(rows[0]["text"], "Семейный рецепт 🥧")
        self.assertEqual(rows[0]["attachments"], [])
        self.assertEqual(rows[0]["media_status"], "photo_reference_only")
        self.assertEqual(rows[0]["source_sha256"], before)
        self.assertEqual(rows[0]["media_id"], "7777")

    def test_valid_inline_thumbnail_is_exact_and_logically_linked(self):
        content = image()
        output, result, rows, before = self.analyze([photo_message(payload=photo([size("cached", content)]))])
        self.assertEqual(rows[0]["thumbnail_count"], 1)
        self.assertEqual(rows[0]["media_status"], "cached_thumbnail_available")
        target = output / rows[0]["attachments"][0]
        self.assertEqual(target.read_bytes(), content)
        photos = json.loads((output / "photo-metadata.json").read_text(encoding="utf-8"))["photos"]
        linked = next(p for p in photos if p["sha256"] == hashlib.sha256(content).hexdigest())
        origin = next(s for s in linked["sources"] if "photo.sizes[" in s["source_record"])
        self.assertEqual(origin["source_sha256"], before)
        self.assertEqual(origin["offset_kind"], "sqlite_tl_blob_relative")
        self.assertIn("blob_offset", origin)
        self.assertNotIn("offset", origin)

    def test_photo_only_record_with_no_caption_keeps_empty_text(self):
        _, result, rows, _ = self.analyze([photo_message("", payload=photo([size()]))])
        self.assertEqual(result["native_records"], 1)
        self.assertEqual(rows[0]["text"], "")
        self.assertEqual(rows[0]["media_kind"], "photo")

    def test_damaged_thumbnail_does_not_hide_caption_or_become_attachment(self):
        _, result, rows, _ = self.analyze([photo_message(payload=photo([size("cached", b"\xff\xd8\xfftruncated")]))])
        self.assertEqual(result["native_records"], 1)
        self.assertEqual(rows[0]["attachments"], [])
        self.assertEqual(rows[0]["thumbnail_count"], 0)
        self.assertIn("TELEGRAM_CACHED_THUMBNAIL_UNREADABLE", result["warnings"])

    def test_dimensions_mismatch_is_not_a_confirmed_attachment(self):
        _, result, rows, _ = self.analyze([photo_message(payload=photo([size("cached", image(), width=1)]))])
        self.assertEqual(rows[0]["attachments"], [])
        self.assertIn("TELEGRAM_THUMBNAIL_DIMENSIONS_MISMATCH", result["warnings"])

    def test_legacy_caption_retained_and_private_values_not_published(self):
        raw = message("", flags=512, after=media(constructor=0xB5223B0F, flags=3, caption="Старый семейный рецепт"))
        output, _, rows, _ = self.analyze([raw])
        self.assertEqual(rows[0]["text"], "Старый семейный рецепт")
        for name in ("messages.jsonl", "photo-metadata.json", "attachment-metadata.json", "sources.json"):
            self.assertNotIn("PRIVATE_PHOTO_REFERENCE_NOT_PUBLISHED", (output / name).read_text(encoding="utf-8"))

    def test_reused_thumbnail_deduplicates_bytes_and_retains_both_records(self):
        content = image()
        payload = photo([size("cached", content)])
        output, result, rows, _ = self.analyze([photo_message(payload=payload), photo_message("Другой текст", payload=payload, mid=2)])
        self.assertEqual(result["native_records"], 2)
        self.assertEqual(rows[0]["attachments"], rows[1]["attachments"])
        data = json.loads((output / "attachment-metadata.json").read_text(encoding="utf-8"))["attachments"]
        self.assertEqual(len(data), 1)
        self.assertEqual(len(data[0]["sources"]), 2)

    def test_inline_decode_limit_keeps_caption_and_reports_incomplete_media(self):
        with mock.patch.object(telegram_auto, "MAX_NATIVE_THUMBNAILS", 0):
            _, result, rows, _ = self.analyze([photo_message(payload=photo([size("cached", image())]))])
        self.assertEqual(result["native_records"], 1)
        self.assertEqual(rows[0]["text"], "Семейный рецепт 🥧")
        self.assertEqual(rows[0]["attachments"], [])
        self.assertIn("TELEGRAM_THUMBNAIL_LIMIT", result["warnings"])

    def test_inline_byte_limit_keeps_caption_and_reports_incomplete_media(self):
        with mock.patch.object(telegram_auto, "MAX_NATIVE_THUMBNAIL_BYTES", 1):
            _, result, rows, _ = self.analyze([photo_message(payload=photo([size("cached", image())]))])
        self.assertEqual(result["native_records"], 1)
        self.assertEqual(rows[0]["attachments"], [])
        self.assertIn("TELEGRAM_THUMBNAIL_LIMIT", result["warnings"])

    def test_canonical_reimport_retains_photo_fields_and_valid_attachment(self):
        output, _, rows, _ = self.analyze([photo_message(payload=photo([size("cached", image())]))])
        destination = self.root / "reimport"
        result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(destination),
            "options": {"roots": [str(output / "messages.jsonl")]}}, engine.Importer, engine.emit)
        imported = [json.loads(row) for row in (destination / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(result["native_records"], 1)
        self.assertEqual(imported[0]["media_kind"], "photo")
        self.assertEqual(imported[0]["thumbnail_count"], 1)
        self.assertEqual((destination / imported[0]["attachments"][0]).read_bytes(), image())

    def test_historical_thumbnail_links_to_wal_snapshot_not_physical_offset(self):
        source = self.input / "history"
        source.mkdir()
        db = source / "cache4.db"
        connection = sqlite3.connect(db)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            create_schema(connection)
            old = photo_message("Older photo caption", payload=photo([size("cached", image())]))
            connection.execute("INSERT INTO messages_v2 VALUES(1,77,?,?)", (DATE, old))
            connection.commit()
            connection.execute("UPDATE messages_v2 SET data=? WHERE mid=1", (message("Current text"),))
            connection.commit()
            before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (db, Path(str(db) + "-wal"))}
            output = self.root / "history-archive"
            result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(output),
                "options": {"roots": [str(source)]}}, engine.Importer, engine.emit)
            rows = [json.loads(row) for row in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(result["previous_records"], 1)
            older = next(row for row in rows if row["evidence_kind"] == "previous")
            self.assertEqual(older["text"], "Older photo caption")
            metadata = json.loads((output / "attachment-metadata.json").read_text(encoding="utf-8"))["attachments"][0]
            origin = metadata["sources"][0]
            self.assertEqual(origin["wal_sha256"], older["wal_sha256"])
            self.assertEqual(origin["wal_snapshot_sha256"], older["wal_snapshot_sha256"])
            self.assertEqual(origin["snapshot_id"], older["snapshot_id"])
            self.assertIn("@wal_commit:", origin["source_record"])
            self.assertNotIn("offset", origin)
            self.assertEqual(before, {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (db, Path(str(db) + "-wal"))})
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
