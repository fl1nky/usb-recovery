"""Owned SQLite/WAL fixtures; literal official TL wire writer, no recovery imports.

Pinned Android commit4de548e79fed27f1a66fbdff84223321838fe925:
MessagesStorage.java media_v4 schema; TLRPC.java Message/photo-media/photo-empty.
Golden values are queried before deletion; WAL bytes are produced by SQLite.
"""
from pathlib import Path
import hashlib
import json
import shutil
import sqlite3
import struct
import tempfile

DATE = 1790000000
TEXT = "Рецепт 🍰\n第二行 <b>не HTML</b>"
SCHEMA = ("mid INTEGER,uid INTEGER,date INTEGER,type INTEGER,data BLOB,"
          "PRIMARY KEY(mid,uid,type)")
VARIANTS = ("current", "history", "missing-preimage", "corrupt-wal",
            "wrong-schema", "wrong-type", "mid-mismatch", "uid-mismatch",
            "date-mismatch", "unknown-flags", "missing-media", "secret-uid",
            "primary-current", "primary-historical", "primary-different",
            "repeated-history")


def word(value):
    return struct.pack("<I", value & 0xffffffff)


def string(value):
    raw = value.encode("utf-8")
    prefix = bytes([len(raw)]) if len(raw) < 254 else b"\xfe" + len(raw).to_bytes(3, "little")
    return prefix + raw + b"\0" * (-(len(prefix) + len(raw)) % 4)


def peer(kind, value):
    return word({"user": 0x59511722, "channel": 0xa2a5371e,
                 "chat": 0x36c6019a}[kind]) + struct.pack("<q", value)


def message(text=TEXT, *, mid=41, date=DATE, sender=77, dialog=909,
            kind="user", photo=True, extra_flags=0):
    # Official layer232: constructor,flags,flags2,id,from_id?,peer,date,text,media?.
    flags = (256 if sender is not None else 0) | (512 if photo else 0) | extra_flags
    raw = word(0x7600b9d3) + word(flags) + word(0) + word(mid)
    if sender is not None:
        raw += peer("user", sender)
    raw += peer(kind, dialog) + word(date) + string(text)
    if photo:
        raw += word(0xe216eb63) + word(1) + word(0x2331b22d) + struct.pack("<q", 987654321)
    return raw + string("../../never-follow-this-attachment.jpg")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(folder):
    return {p.relative_to(folder).as_posix(): digest(p)
            for p in sorted(Path(folder).rglob("*")) if p.is_file()}


def create(destination, variant="current"):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    require_wal = variant in ("history", "missing-preimage", "corrupt-wal",
                              "primary-historical", "repeated-history")
    with tempfile.TemporaryDirectory(prefix="owned-media-cache-writer-") as temporary:
        source = Path(temporary) / "cache4.db"
        con = sqlite3.connect(source)
        try:
            con.execute("PRAGMA page_size=4096")
            con.execute("PRAGMA secure_delete=ON")
            if require_wal:
                assert con.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
                con.execute("PRAGMA wal_autocheckpoint=0")
            schema = SCHEMA if variant != "wrong-schema" else SCHEMA.replace(
                "PRIMARY KEY(mid,uid,type)", "PRIMARY KEY(mid,uid)")
            con.execute("CREATE TABLE media_v4(" + schema + ")")
            if variant == "repeated-history":
                con.execute("CREATE TABLE fixture_clock(value INTEGER)")
                con.execute("INSERT INTO fixture_clock VALUES(0)")
            if variant.startswith("primary-"):
                con.execute("CREATE TABLE messages_v2(mid INTEGER,uid INTEGER,date INTEGER,data BLOB,PRIMARY KEY(mid,uid))")
            con.execute("PRAGMA user_version=179")
            con.commit()
            if variant == "missing-preimage":
                con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            raw = message(extra_flags=1 << 31 if variant == "unknown-flags" else 0,
                          photo=variant != "missing-media")
            mid = 42 if variant == "mid-mismatch" else 41
            uid = 88 if variant == "uid-mismatch" else 77 << 32 if variant == "secret-uid" else 77
            date = DATE + 1 if variant == "date-mismatch" else DATE
            category = 1 if variant == "wrong-type" else 0
            con.execute("INSERT INTO media_v4 VALUES(?,?,?,?,?)", (mid, uid, date, category, raw))
            if variant.startswith("primary-"):
                primary = message("Другая версия") if variant == "primary-different" else raw
                con.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)", (41, 77, DATE, primary))
            con.commit()
            # Independent SQL oracle while the original complete row is live.
            observed = con.execute("SELECT mid,uid,date,type,data FROM media_v4").fetchone()
            golden = {"variant": variant, "text": TEXT, "mid": observed[0],
                      "uid": observed[1], "date": observed[2], "type": observed[3],
                      "blob_sha256": hashlib.sha256(observed[4]).hexdigest(),
                      "message_constructor": "0x7600b9d3",
                      "media_constructor": "0xe216eb63",
                      "secure_delete": con.execute("PRAGMA secure_delete").fetchone()[0],
                      "scope": "Owned synthetic rows; not an Android profile or proof of user deletion."}
            if variant in ("history", "missing-preimage", "corrupt-wal"):
                con.execute("DELETE FROM media_v4")
                con.commit()
            if variant == "primary-historical":
                con.execute("DELETE FROM messages_v2")
                con.commit()
            golden["current_cache_rows"] = con.execute("SELECT count(*) FROM media_v4").fetchone()[0]
            if variant == "repeated-history":
                for tick in range(24):
                    con.execute("UPDATE fixture_clock SET value=?", (tick + 1,))
                    con.commit()
            # Writer is quiescent and kept open to retain authentic committed WAL.
            target = destination / "cache4.db"
            for suffix in ("", "-wal", "-shm"):
                path = Path(str(source) + suffix)
                if path.is_file():
                    shutil.copyfile(path, Path(str(target) + suffix))
        finally:
            con.close()
    if variant == "corrupt-wal":
        wal = Path(str(target) + "-wal")
        data = bytearray(wal.read_bytes())
        data[24] ^= 1  # Deliberate invalid WAL header checksum, not a fabricated WAL.
        wal.write_bytes(data)
    golden["source_files"] = inventory(destination)
    (destination / "golden.json").write_text(json.dumps(golden, ensure_ascii=False, indent=2) + "\n",
                                           encoding="utf-8")
    return target, golden


def build(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    cases = []
    for variant in VARIANTS:
        path, golden = create(destination / variant, variant)
        cases.append({"variant": variant, "database": path.relative_to(destination).as_posix(),
                      "source_files": golden["source_files"]})
    manifest = {"schema": 1, "source_commit": "4de548e79fed27f1a66fbdff84223321838fe925",
                "independent_sqlite_writer": True, "cases": cases}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    import sys
    print(json.dumps(build(sys.argv[1]), indent=2))
