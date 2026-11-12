"""Native Android WebPage messages, SQL provenance and bounded negatives."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from telegram_tl import parse_message, TelegramTlError
import engine
import telegram_auto
from archive_search import search

FIXTURES = ROOT / "tests/fixtures/telegram-webpage"
MANIFEST_SHA256 = "4b31f2b3f75aac5360a0b8d5bedfc98942374cbf54ef82f92d9bd15efc0ce575"
engine.emit = lambda *args, **kwargs: None


def word(number):
    return struct.pack("<I", number & 0xffffffff)


def corpus():
    manifest_data = (FIXTURES / "manifest.json").read_bytes()
    if hashlib.sha256(manifest_data).hexdigest() != MANIFEST_SHA256:
        raise ValueError("WebPage manifest changed")
    manifest = json.loads(manifest_data)
    producer = ROOT / "tests/telegram_webpage_oracle/NativeWebPageOracle.java"
    if hashlib.sha256(producer.read_bytes()).hexdigest() != manifest["producer_sha256"]:
        raise ValueError("Native WebPage producer source changed")
    for name, digest in manifest["files"].items():
        if hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() != digest:
            raise ValueError("Native WebPage fixture changed")
    value = json.loads(gzip.decompress((FIXTURES / "oracle.json.gz").read_bytes()))
    if value["commit"] != "4de548e79fed27f1a66fbdff84223321838fe925" or len(value["cases"]) != 8:
        raise ValueError("Unexpected WebPage corpus")
    for case in value["cases"]:
        case["blob"] = base64.b64decode(case["blob_b64"], validate=True)
        if hashlib.sha256(case["blob"]).hexdigest() != case["blob_sha256"]:
            raise ValueError("Native WebPage record changed")
    return value["cases"]


def schema(connection):
    connection.execute("CREATE TABLE messages_v2(mid INTEGER,uid INTEGER,date INTEGER,data BLOB,PRIMARY KEY(mid,uid))")
    connection.commit()


def insert(connection, case):
    connection.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)",
                       (case["id"], case["uid"], case["date"], case["blob"]))


class TelegramWebPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.sources = self.base / "inputs"
        self.sources.mkdir()
        self.sequence = 0

    def tearDown(self):
        self.temporary.cleanup()

    def analyze(self, source, **options):
        self.sequence += 1
        output = self.base / ("output-" + str(self.sequence))
        result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze",
            "destination": str(output), "options": {"roots": [str(source)], **options}},
            engine.Importer, engine.emit)
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        return output, result, rows

    def test_official_current_and_legacy_webpage_serializers(self):
        expected = ["empty", "pending", "empty", "pending", "url_pending", "page", "page", "page"]
        for case, state in zip(self.cases, expected):
            with self.subTest(case=case["name"]):
                value = parse_message(case["blob"])
                self.assertEqual((value["id"], value["date"], value["text"]),
                                 (case["id"], case["date"], case["text"]))
                self.assertEqual(value["from_peer"], {"kind": "user", "id": 77})
                self.assertEqual(value["media"]["type"], "webpage")
                page = value["media"]["webpage"]
                self.assertEqual(page["type"], state)
                if state != "url_pending":
                    self.assertLess(page["id"], 0)  # Opaque signed object ID.
                if state == "pending":
                    self.assertEqual(page["preview_date"], 1794009000)
                    self.assertNotEqual(page["preview_date"], value["date"])
                if state == "page":
                    self.assertEqual(page["page_author"], "PAGE_AUTHOR_IS_NOT_SENDER")
                    self.assertEqual(page["title"], "<script>NEVER_EXECUTE</script>")
                    self.assertEqual(page["embed_url"], "file:///NEVER_OPEN")
                self.assertTrue(value["local_tail_present"])

    def test_truncated_native_object_never_becomes_verified_text(self):
        for case in self.cases:
            end = parse_message(case["blob"])["tl_bytes"]
            for length in range(end):
                with self.subTest(case=case["name"], length=length), self.assertRaises(TelegramTlError):
                    parse_message(case["blob"][:length])

    def test_unsupported_flags_objects_and_invalid_utf8_fail_closed(self):
        current = self.cases[5]["blob"]
        mutations = []
        envelope = current.index(word(0xddf10c3b))
        mutations.append(current[:envelope + 4] + word(4) + current[envelope + 8:])
        page = current.index(word(0xe89c45b2))
        mutations.append(current[:page] + word(0x12345678) + current[page + 4:])
        for bit in (512, 1024, 2048, 4096, 32768):
            flags = struct.unpack_from("<I", current, page + 4)[0] | bit
            mutations.append(current[:page + 4] + word(flags) + current[page + 8:])
        pending = self.cases[1]["blob"]
        offset = pending.index(word(0xb0d13e47)) + 4
        mutations.append(pending[:offset] + word(2) + pending[offset + 4:])
        mutations.append(current.replace(b"https://example.invalid/NEVER_FETCH_5", b"\xffttps://example.invalid/NEVER_FETCH_5"))
        for index, data in enumerate(mutations):
            with self.subTest(control=index), self.assertRaises(TelegramTlError):
                parse_message(data)

    def test_full_native_import_search_and_source_immutability(self):
        source = self.sources / "cache4.db"
        connection = sqlite3.connect(source)
        try:
            schema(connection)
            for case in self.cases:
                insert(connection, case)
            connection.commit()
        finally:
            connection.close()
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        output, result, rows = self.analyze(source, recover_deleted=False)
        self.assertEqual(result["native_records"], 7)
        self.assertEqual(result["history_messages"], 7)
        self.assertEqual(len(rows), 7)
        self.assertEqual({row["text"] for row in rows}, {case["text"] for case in self.cases if case["text"]})
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        for row in rows:
            self.assertEqual(row["record_kind"], "tl_message")
            self.assertEqual(row["media_kind"], "webpage")
            self.assertEqual(row["media_status"], "webpage_metadata_only")
            self.assertEqual(row["attachments"], [])
            self.assertEqual(row["sender_id"], "user:77")
            self.assertEqual(row["evidence_kind"], "backup")
            self.assertIn("messages_v2(uid=77,mid=", row["source_record"])
            self.assertTrue(row["application_confirmed"])
            self.assertIsNot(row.get("deleted"), True)
        found = search({"protocol": 1, "operation": "search", "archive": str(output),
            "query": "variant 0", "query_mode": "regex", "limit": 10})
        self.assertEqual(found["total"], 1)
        metadata = search({"protocol": 1, "operation": "search", "archive": str(output),
            "query": "PAGE_AUTHOR_IS_NOT_SENDER", "query_mode": "literal", "limit": 10})
        self.assertEqual(metadata["total"], 0)
        self.assertNotIn("NEVER_EXECUTE", (output / "messages.jsonl").read_text(encoding="utf-8"))

    def test_sql_key_date_and_sender_controls_are_not_promoted(self):
        for kind in ("mid", "uid", "date", "sender"):
            folder = self.sources / kind
            folder.mkdir()
            source = folder / "cache4.db"
            case = dict(self.cases[0])
            if kind == "sender":
                blob = bytearray(case["blob"])
                # The first peerUser is from_id. A foreign sender contradicts uid.
                offset = blob.index(word(0x59511722)) + 4
                struct.pack_into("<q", blob, offset, 88)
                case["blob"] = bytes(blob)
            else:
                case[kind if kind != "mid" else "id"] += 1
            connection = sqlite3.connect(source)
            try:
                schema(connection)
                insert(connection, case)
                connection.commit()
            finally:
                connection.close()
            _, result, rows = self.analyze(source, recover_deleted=False)
            with self.subTest(control=kind):
                self.assertEqual(result["native_records"], 0)
                self.assertFalse(any(row.get("application_confirmed") for row in rows))
                self.assertIn("TELEGRAM_TL_HISTORY_UNSUPPORTED", result["warnings"])

    def test_native_wal_previous_link_message_keeps_snapshot_proof(self):
        live = self.base / "live.db"
        connection = sqlite3.connect(live)
        try:
            connection.execute("PRAGMA page_size=1024")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            schema(connection)
            insert(connection, self.cases[0])
            connection.commit()
            connection.execute("DELETE FROM messages_v2")
            insert(connection, self.cases[2])
            connection.commit()
            source = self.sources / "cache4.db"
            for suffix in ("", "-wal", "-shm"):
                path = Path(str(live) + suffix)
                if path.exists():
                    shutil.copyfile(path, Path(str(source) + suffix))
        finally:
            connection.close()
        originals = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in self.sources.iterdir()}
        _, result, rows = self.analyze(source)
        old = next(row for row in rows if row["text"] == self.cases[0]["text"])
        self.assertEqual(old["evidence_kind"], "previous")
        self.assertEqual(old["media_status"], "webpage_metadata_only")
        self.assertEqual(old["wal_proof"], "all_pages_from_validated_wal")
        self.assertGreater(old["wal_commit_frame"], 0)
        self.assertEqual(result["previous_records"], 1)
        self.assertEqual(originals, {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in self.sources.iterdir()})


if __name__ == "__main__":
    unittest.main(verbosity=2)
