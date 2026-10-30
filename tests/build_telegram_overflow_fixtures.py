"""Owned real SQLite DELETE fixtures; no recovery implementation imports.

The official Android column order and independent TL writer are shared with
the existing native fixtures. SQLite itself chooses cell/overflow geometry.
"""
from pathlib import Path
import hashlib
import json
import shutil
import sqlite3

from build_telegram_native_fixtures import DATE, message

COLUMNS = ("mid INTEGER,uid INTEGER,read_state INTEGER,send_state INTEGER,date INTEGER,data BLOB,"
           "out INTEGER,ttl INTEGER,media INTEGER,replydata BLOB,imp INTEGER,mention INTEGER,"
           "forwards INTEGER,replies_data BLOB,thread_reply_id INTEGER,is_channel INTEGER,"
           "reply_to_message_id INTEGER,custom_params BLOB,group_id INTEGER,reply_to_story_id INTEGER")


def create(destination, *, page_size=4096, secure=False, donor=True, wal=False):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    path = destination / "cache4.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA page_size=" + str(page_size))
    connection.execute("PRAGMA secure_delete=" + ("ON" if secure else "OFF"))
    connection.execute("CREATE TABLE messages_v2(" + COLUMNS + ",PRIMARY KEY(mid,uid))")
    originals = {}
    repeat = 9000 if page_size == 65536 else 1200 if page_size == 4096 else 600
    for mid in range(1, 8):
        text = ("recipe " + str(mid) + " яблоки ") * repeat
        raw = message(text, mid=mid, dialog=77)
        originals[mid] = {"text": text, "blob": raw}
        connection.execute("INSERT INTO messages_v2(mid,uid,date,data) VALUES(?,?,?,?)", (mid, 77, DATE, raw))
    if donor:
        connection.execute("CREATE TABLE donor(x BLOB)")
        for _ in range(30):
            connection.execute("INSERT INTO donor VALUES(zeroblob(?))", (page_size,))
        connection.commit()
        connection.execute("DROP TABLE donor")
    connection.commit()
    if wal:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("DELETE FROM messages_v2 WHERE mid=3")
    connection.commit()
    if wal:
        copy = destination / "copy"
        copy.mkdir()
        for suffix in ("", "-wal"):
            shutil.copyfile(str(path) + suffix, str(copy / "cache4.db") + suffix)
        connection.close()
        path = copy / "cache4.db"
    else:
        connection.close()
    return path, originals[3]


def build(destination):
    root = Path(destination)
    if root.exists():
        raise FileExistsError("Use a fresh owned fixture directory")
    root.mkdir(parents=True)
    cases = []
    for page in (512, 1024, 4096, 65536):
        path, expected = create(root / ("page-" + str(page)), page_size=page)
        cases.append({"name": path.parent.name, "image": path.relative_to(root).as_posix(),
                      "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "message_id": 3, "expected_text_sha256": hashlib.sha256(expected["text"].encode()).hexdigest(),
                      "expected_tl_sha256": hashlib.sha256(expected["blob"]).hexdigest()})
    (root / "manifest.json").write_text(json.dumps({"schema": 1, "cases": cases}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    import sys
    build(sys.argv[1])
