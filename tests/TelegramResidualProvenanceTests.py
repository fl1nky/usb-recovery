"""Independent regressions for committed-history versus current residual proof.

SQLite creates the tables, deletions and freeblocks. This module writes the
specified WAL envelope/checksums independently and never uses the WAL reader
to build a fixture. No device, account or private data is accessed.
"""
from pathlib import Path
from contextlib import closing
import hashlib
import json
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "helpers/recovery_engine"), str(ROOT / "tests")]
from build_telegram_native_fixtures import message, DATE
import engine
import telegram_auto


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def wal(states, page_size=4096):
    salts = (0x10203040, 0x50607080)
    checksum_state = (0, 0)
    def checksum(data):
        nonlocal checksum_state
        first, second = checksum_state
        for a, b in struct.iter_unpack("<II", data):
            first = (first + a + second) & 0xFFFFFFFF
            second = (second + b + first) & 0xFFFFFFFF
        checksum_state = first, second
        return struct.pack(">II", first, second)
    header = struct.pack(">6I", 0x377F0682, 3007000, page_size, 0, *salts)
    result = header + checksum(header)
    for image in states:
        count = len(image) // page_size
        if count * page_size != len(image):
            raise AssertionError("unaligned synthetic SQLite image")
        for page in range(1, count + 1):
            prefix = struct.pack(">II", page, count if page == count else 0)
            content = image[(page - 1) * page_size:page * page_size]
            result += prefix + struct.pack(">II", *salts) + checksum(prefix + content) + content
    return result


class ResidualProvenance(unittest.TestCase):
    def setUp(self):
        (ROOT / ".build/telegram-independent-audit").mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="provenance-", dir=ROOT / ".build/telegram-independent-audit")
        self.work = Path(self.temporary.name)

    def tearDown(self):
        assert self.work.resolve().is_relative_to((ROOT / ".build/telegram-independent-audit").resolve())
        self.temporary.cleanup()

    def fixture(self, *, deleted_before_history, secure_delete):
        path = self.work / "original.db"
        with closing(sqlite3.connect(path)) as db:
            db.execute("PRAGMA secure_delete=OFF")
            db.execute("CREATE TABLE messages_v2(mid INTEGER,uid INTEGER,date INTEGER,data BLOB,PRIMARY KEY(mid,uid))")
            db.execute("CREATE TABLE unrelated(value TEXT)")
            db.execute("INSERT INTO unrelated VALUES('old')")
            for mid in range(1, 8):
                db.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)", (mid, 77, DATE, message("independent recipe " + str(mid) + " " + "X" * 80, mid=mid)))
            db.commit()
            if deleted_before_history:
                db.execute("DELETE FROM messages_v2 WHERE mid=4")
                db.commit()
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            first = path.read_bytes()
        shadow = self.work / "later.db"
        shadow.write_bytes(first)
        with closing(sqlite3.connect(shadow)) as db:
            db.execute("PRAGMA secure_delete=" + ("ON" if secure_delete else "OFF"))
            if not deleted_before_history:
                db.execute("DELETE FROM messages_v2 WHERE mid=4")
            db.execute("UPDATE unrelated SET value='latest'")
            db.commit()
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            last = shadow.read_bytes()
        captured = self.work / "provided/cache4.db"
        captured.parent.mkdir()
        captured.write_bytes(first)
        sidecar = Path(str(captured) + "-wal")
        sidecar.write_bytes(wal((first, last)))
        before = {name: sha(member) for name, member in (("db", captured), ("wal", sidecar))}
        # This connection reads the synthetic latest committed SQLite view.
        # It does not checkpoint, attach, or modify the supplied pair.
        connection = sqlite3.connect(captured.as_uri() + "?mode=ro", uri=True)
        try:
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertEqual(connection.execute("SELECT value FROM unrelated").fetchone(), ("latest",))
            self.assertIsNone(connection.execute("SELECT mid FROM messages_v2 WHERE mid=4").fetchone())
        finally:
            connection.close()
        self.assertEqual(before, {"db": sha(captured), "wal": sha(sidecar)})
        return captured, sidecar, before, len(first) // 4096

    def analyze(self, captured, sidecar, before):
        output = self.work / "archive"
        with patch.object(engine, "emit", lambda *a, **k: None):
            result = telegram_auto.analyze({"protocol": 1, "operation": "telegram_analyze", "destination": str(output), "options": {"roots": [str(captured)]}}, engine.Importer, lambda *a, **k: None)
        rows = [json.loads(line) for line in (output / "messages.jsonl").read_text(encoding="utf-8").splitlines()]
        target = [row for row in rows if row.get("message_id") == 4]
        self.assertEqual(len(target), 1)
        row = target[0]
        self.assertEqual(row["source_file"], str(captured))
        self.assertEqual(row["source_sha256"], before["db"])
        self.assertEqual(before, {"db": sha(captured), "wal": sha(sidecar)})
        self.assertIsNone(row.get("deleted"))
        self.assertNotIn("TELEGRAM_WAL_HISTORY_INCOMPLETE", result["warnings"])
        return row

    def test_current_residual_never_present_in_history_does_not_borrow_snapshot_proof(self):
        captured, sidecar, before, count = self.fixture(deleted_before_history=True, secure_delete=False)
        row = self.analyze(captured, sidecar, before)
        self.assertEqual(row["record_kind"], "sqlite_deleted_record")
        self.assertEqual(row["recovery_status"], "deleted_supported_by_evidence")
        self.assertEqual(row["evidence_kind"], "backup")
        self.assertFalse(row.get("previous_version"))
        self.assertIsNone(row.get("wal_proof"))
        self.assertIsNone(row.get("wal_snapshot_sha256"))
        self.assertEqual(row["snapshot_id"], before["db"])
        self.assertEqual(row["wal_commit_frame"], count * 2)
        self.assertEqual(row["wal_sha256"], before["wal"])
        self.assertEqual(row["wal_db_sha256"], before["db"])
        self.assertNotIn("@wal_commit:", row["source_record"])
        self.assertEqual(row["physical_source"], "wal")
        with sidecar.open("rb") as source:
            source.seek(row["physical_byte_offset"])
            self.assertEqual(hashlib.sha256(source.read(row["sqlite_record_length"])).hexdigest(), row["sqlite_record_sha256"])

    def test_actual_committed_previous_message_keeps_its_snapshot_proof(self):
        captured, sidecar, before, count = self.fixture(deleted_before_history=False, secure_delete=True)
        row = self.analyze(captured, sidecar, before)
        self.assertEqual(row["record_kind"], "tl_message")
        self.assertEqual(row["evidence_kind"], "previous")
        self.assertTrue(row["previous_version"])
        self.assertEqual(row["wal_proof"], "all_pages_from_validated_wal")
        self.assertEqual(row["wal_commit_frame"], count)
        self.assertEqual(row["wal_sha256"], before["wal"])
        self.assertTrue(row["wal_snapshot_sha256"])
        self.assertIsNone(row.get("recovery_status"))

    def test_matching_previous_body_preserves_stronger_proof_and_adds_residual_source(self):
        captured, sidecar, before, count = self.fixture(deleted_before_history=False, secure_delete=False)
        row = self.analyze(captured, sidecar, before)
        self.assertEqual(row["record_kind"], "tl_message")
        self.assertEqual(row["evidence_kind"], "previous")
        self.assertTrue(row["previous_version"])
        self.assertEqual(row["wal_proof"], "all_pages_from_validated_wal")
        self.assertEqual(row["wal_commit_frame"], count)
        self.assertEqual(row["recovery_status"], "deleted_supported_by_evidence")
        self.assertEqual(len(row["residual_sources"]), 1)
        residual = row["residual_sources"][0]
        self.assertEqual(residual["proof"], "reachable_table_free_space_and_sql_tl_key_agreement")
        self.assertEqual(residual["wal_commit_frame"], count * 2)
        self.assertEqual(residual["source_file"], str(captured))
        self.assertNotIn("@wal_commit:", residual["source_record"])


if __name__ == "__main__":
    unittest.main(verbosity=2)