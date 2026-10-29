"""Synthetic SQLite/WAL + independent TL serialization, never personal data.

Wire field order comes from official Telegram Android commit
4de548e79fed27f1a66fbdff84223321838fe925, TLRPC.java TL_message and
tl/legacy/TL_legacy_message.java. This generator does not call our decoder.
https://github.com/DrKLO/Telegram/tree/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/tgnet
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

DATE = 1790000000
LAYERS = ((232, 0x7600b9d3), (226, 0x95ef6f2b), (224, 0x3ae56482),
          (222, 0x9cb490e9), (220, 0xb92f76cf), (216, 0x9815cec8),
          (205, 0xeabcdd4d), (199, 0x96fdbbe9), (195, 0x94345242),
          (180, 0xbde09c2e), (179, 0x2357bf25), (176, 0xa66c7efc),
          (175, 0x1e4c8a69), (173, 0x76bec211), (169, 0x38116ee0),
          (135, 0x85d6cbe2), (131, 0xbce383d2), (123, 0x58ae39c9),
          (118, 0xf52e6b7f))


def word(value):
    return struct.pack("<I", value & 0xffffffff)


def tl_string(value):
    raw = value.encode("utf-8") if isinstance(value, str) else value
    head = bytes([len(raw)]) if len(raw) < 254 else b"\xfe" + len(raw).to_bytes(3, "little")
    return head + raw + b"\0" * (-(len(head) + len(raw)) % 4)


def peer(kind, number, legacy=False):
    constructor = {"user": (0x59511722, 0x9db1bc6d), "chat": (0x36c6019a, 0xbad0e5bb),
                   "channel": (0xa2a5371e, 0xbddde532)}[kind][bool(legacy)]
    return word(constructor) + struct.pack("<i" if legacy else "<q", number)


def message(text, mid=1, date=DATE, dialog=77, sender=77, layer=232,
            kind="user", out=False, flags=0, flags2=0, after=b"", tail=True):
    constructor = dict(LAYERS)[layer]
    flags |= (256 if sender is not None else 0) | (2 if out else 0)
    result = word(constructor) + word(flags)
    if layer >= 179:
        result += word(flags2)
    result += word(mid)
    if sender is not None:
        result += word(sender) if layer == 118 else peer("user", sender, layer <= 131)
    result += peer(kind, dialog, layer <= 131) + word(date) + tl_string(text) + after
    return result + (tl_string(" ") if tail else b"")


def create_schema(connection):
    connection.execute("CREATE TABLE messages_v2(mid INTEGER,uid INTEGER,date INTEGER,data BLOB,PRIMARY KEY(mid,uid))")
    connection.commit()


def insert(connection, text, mid=1, uid=77):
    connection.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)", (mid, uid, DATE, message(text, mid=mid, dialog=abs(uid), kind="channel" if uid < 0 else "user")))


def copy_pair(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal"):
        path = Path(str(source) + suffix)
        if path.exists():
            shutil.copyfile(path, Path(str(target) + suffix))


def build(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("Fixture destination must be empty")
    with tempfile.TemporaryDirectory(prefix="telegram-wire-fixtures-") as temporary:
        base = Path(temporary)
        db = base / "history.db"
        connection = sqlite3.connect(db)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            create_schema(connection)
            insert(connection, "Old recipe before edit", 1)
            insert(connection, "Deleted recipe before removal", 2)
            connection.commit()
            connection.execute("UPDATE messages_v2 SET data=? WHERE mid=1", (message("Current recipe"),))
            connection.execute("DELETE FROM messages_v2 WHERE mid=2")
            connection.commit()
            copy_pair(db, destination / "valid/cache4.db")
        finally:
            connection.close()
        db = base / "missing.db"
        connection = sqlite3.connect(db)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            create_schema(connection)
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            insert(connection, "Unproved historical recipe", 1)
            connection.commit()
            connection.execute("DELETE FROM messages_v2")
            connection.commit()
            copy_pair(db, destination / "missing-preimage/cache4.db")
        finally:
            connection.close()
        for name in ("account-a", "account-b"):
            db = destination / "cross-account" / name / "cache4.db"
            db.parent.mkdir(parents=True)
            connection = sqlite3.connect(db)
            try:
                create_schema(connection)
                insert(connection, "Same IDs independent account", 5)
                connection.commit()
            finally:
                connection.close()
        corrupt = destination / "corrupt-wal/cache4.db"
        copy_pair(destination / "valid/cache4.db", corrupt)
        wal = Path(str(corrupt) + "-wal")
        raw = bytearray(wal.read_bytes())
        raw[-20] ^= 1
        wal.write_bytes(raw)
    files = [{"path": str(path.relative_to(destination)).replace("\\", "/"), "size": path.stat().st_size,
              "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
             for path in sorted(destination.rglob("*")) if path.is_file()]
    manifest = {"synthetic": True, "telegram_source_commit": "4de548e79fed27f1a66fbdff84223321838fe925",
                "files": files, "valid": {"backup": ["Current recipe"],
                "previous": ["Old recipe before edit", "Deleted recipe before removal"]},
                "missing_preimage_messages": 0, "cross_account_messages": 2}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("TelegramNativeFixtures")
    print(json.dumps(build(output), indent=2))
