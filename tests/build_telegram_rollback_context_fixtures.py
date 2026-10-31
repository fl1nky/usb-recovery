"""Owned native SQLite journals, acquisition manifests and ZIP provenance.

All positive journals are captured from SQLite's normal VFS COMMIT callback.
The generic archive deliberately self-declares Telegram IDs/native flags; it has
no Android SQL/TL schema or wire body and must remain unattributed text.
"""
from __future__ import annotations

import argparse
import ctypes as ct
import hashlib
import json
from pathlib import Path
import zipfile

from build_telegram_rollback_fixtures import Capture, OLD, inspect

GENERIC_TEXT = "Owned JSON archive text without independently verified Telegram context"
PHONE_ROOT = "android://OWNED-SYNTHETIC-DEVICE/Telegram/cache4.db"
ZIP_ROOT = "provided-copy://OWNED-SYNTHETIC-ARCHIVE/telegram.zip"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def capture_canonical(path, record=None):
    """Return native current DB/journal and independent original DB bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    writer, db = Capture(), ct.c_void_p()
    try:
        if writer.lib.sqlite3_open_v2(str(path).encode(), ct.byref(db), 6, writer.name):
            raise RuntimeError("OWN_CONTEXT_OPEN_FAILED")
        def sql(value):
            if writer.lib.sqlite3_exec(db, value.encode(), None, None, None):
                raise RuntimeError("OWN_CONTEXT_SQL_FAILED")
        sql("PRAGMA page_size=512;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;"
            "PRAGMA secure_delete=ON;PRAGMA cache_size=1;PRAGMA cache_spill=ON;"
            "CREATE TABLE messages(id INTEGER PRIMARY KEY,app TEXT,json TEXT);BEGIN;")
        if record is None:
            record = dict(app="Telegram", text=GENERIC_TEXT, evidence_kind="backup",
                chat_id=77, message_id=21, sender_id="user:77", timestamp="2026-10-31T00:00:00Z",
                record_kind="tl_message", application_confirmed=True, native_constructor="0x452c0e65")
        encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode()
        sql("INSERT INTO messages VALUES(1,'Telegram',CAST(X'" + encoded.hex() + "' AS TEXT));COMMIT;")
        before = path.read_bytes()
        writer.path, writer.captured = path, []
        sql("BEGIN IMMEDIATE;DELETE FROM messages;PRAGMA user_version=1234;COMMIT;")
        writer.path = None
        if writer.errors or len(writer.captured) != 1:
            raise RuntimeError("OWN_CONTEXT_CAPTURE_FAILED")
        current, journal = writer.captured[0]
        facts = inspect(journal)
        page = int.from_bytes(before[16:18], "big")
        expected = len(before) // page
        if set(facts["pages"]) != set(range(1, expected + 1)):
            raise RuntimeError("OWN_CONTEXT_NOT_FULL_JOURNAL")
        if b"".join(facts["pages"][number] for number in range(1, expected + 1)) != before:
            raise RuntimeError("OWN_CONTEXT_PREIMAGE_MISMATCH")
        return current, journal, before
    finally:
        writer.path = None
        if db.value:
            writer.lib.sqlite3_close(db)
        writer.close()


def build(destination):
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=False)
    writer = Capture()
    try:
        current, journal, before, _, _ = writer.make(root / "reference-native.sqlite", full=True)
    finally:
        writer.close()
    (root / "reference-native-before.sqlite").write_bytes(before)
    journal_sha = digest(journal)
    records = []
    phone = root / "phone/snapshot/Telegram"
    phone.mkdir(parents=True)
    for suffix, raw in (("", current), ("-journal", journal)):
        path = phone / ("cache4.db" + suffix)
        path.write_bytes(raw)
        records.append(dict(Id=digest(("owned-phone" + suffix).encode()),
            OriginalPath=PHONE_ROOT + suffix, RelativePath="Telegram/cache4.db" + suffix,
            LocalPath="snapshot/Telegram/cache4.db" + suffix, Sha256=digest(raw),
            Size=len(raw), Status="complete"))
    write_json(root / "phone/acquisition.json", {"protocol": 1, "Files": records})
    zip_folder = root / "zip/snapshot"
    zip_folder.mkdir(parents=True)
    zip_path = zip_folder / "telegram.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("Telegram/cache4.db", current)
        archive.writestr("Telegram/cache4.db-journal", journal)
    zip_sha, zip_id = digest(zip_path.read_bytes()), digest(b"owned-zip-source")
    zip_origin = dict(Id=zip_id, OriginalPath=ZIP_ROOT, RelativePath="telegram.zip",
        LocalPath="snapshot/telegram.zip", Sha256=zip_sha, Size=zip_path.stat().st_size, Status="complete")
    write_json(root / "zip/acquisition.json", {"protocol": 1, "Files": [zip_origin]})
    generic = root / "generic/cache4.db"
    generic_current, generic_journal, generic_before = capture_canonical(root / "reference-generic.sqlite")
    generic.parent.mkdir()
    generic.write_bytes(generic_current)
    Path(str(generic) + "-journal").write_bytes(generic_journal)
    (root / "reference-generic-before.sqlite").write_bytes(generic_before)
    cases = [
        dict(name="phone", source_path="phone/snapshot", operation="scan", expected_text=OLD,
            expected_origin_path=PHONE_ROOT + "-journal", expected_source_id=records[1]["Id"],
            expected_relative_path="Telegram/cache4.db-journal", expected_source_sha256=journal_sha,
            expected_journal_sha256=journal_sha, expected_proof="all_pages_from_validated_rollback_journal", native_confirmed=True),
        dict(name="zip", source_path="zip/snapshot", operation="scan", expected_text=OLD,
            expected_origin_path=ZIP_ROOT + "!/Telegram/cache4.db-journal",
            expected_source_id=digest((zip_id + "!/Telegram/cache4.db-journal").encode()),
            expected_relative_path="telegram.zip!/Telegram/cache4.db-journal", expected_source_sha256=journal_sha,
            expected_journal_sha256=journal_sha, expected_proof="all_pages_from_validated_rollback_journal", native_confirmed=True,
            container_origin_path=ZIP_ROOT, container_sha256=zip_sha, container_source_id=zip_id,
            member_path="Telegram/cache4.db-journal"),
        dict(name="generic", source_path="generic/cache4.db", operation="analyze", expected_text=GENERIC_TEXT,
            expected_origin_path=str(generic) + "-journal", expected_source_id=digest((str(generic) + "-journal").encode()),
            expected_relative_path="cache4.db-journal", expected_source_sha256=digest(generic_journal),
            expected_journal_sha256=digest(generic_journal), expected_proof="archive_text_from_rollback_snapshot", native_confirmed=False),
    ]
    for case in cases:
        folder = root / case["name"]
        case["source_files"] = {path.relative_to(root).as_posix(): digest(path.read_bytes())
                                for path in sorted(folder.rglob("*")) if path.is_file()}
    manifest = dict(schema=1, scope="Owned native SQLite journals and synthetic acquisition labels; no devices/user data",
                    generator_sha256=digest(Path(__file__).read_bytes()), cases=cases)
    write_json(root / "manifest.json", manifest)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    build(parser.parse_args().destination)
