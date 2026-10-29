"""Build only synthetic portable photo-media DB and expected JPEG bytes.

Independent TL serialization helpers live in TelegramMediaTests.py and use
official pinned Android field order, without calling the production parser.
The generator refuses nonempty output folders; it never finds user profiles.
"""
import hashlib
import json
from pathlib import Path
import sqlite3
import shutil
import sys
import tempfile

from TelegramMediaTests import photo_message, photo, size, image, media, message, create_schema, DATE


def build(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("Synthetic media fixture destination must be empty")
    content = image()
    source = destination / "input"
    source.mkdir()
    db = source / "cache4.db"
    records = [
        photo_message("Photo caption recipe", payload=photo([size()])),
        photo_message("Cached thumbnail recipe", payload=photo([size("cached", content)]), mid=2),
        photo_message("", payload=photo([size()]), mid=3),
        photo_message("Damaged thumbnail caption", payload=photo([size("cached", b"\xff\xd8\xfftruncated")]), mid=4),
        message("Unsupported live photo", flags=512, after=media(flags=17), mid=5),
        message("", flags=512, after=media(constructor=0xB5223B0F, flags=3, caption="Legacy photo caption recipe"), mid=6),
    ]
    connection = sqlite3.connect(db)
    try:
        create_schema(connection)
        for mid, blob in enumerate(records, 1):
            connection.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)", (mid, 77, DATE, blob))
        connection.commit()
    finally:
        connection.close()
    expected = destination / "expected-thumbnail.jpg"
    expected.write_bytes(content)
    with tempfile.TemporaryDirectory(prefix="telegram-photo-wal-fixture-") as temporary:
        original = Path(temporary) / "history.db"
        connection = sqlite3.connect(original)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            create_schema(connection)
            old = photo_message("Prior photo caption", payload=photo([size("cached", content)]))
            connection.execute("INSERT INTO messages_v2 VALUES(1,77,?,?)", (DATE, old))
            connection.commit()
            current = photo_message("Current photo caption", payload=photo([size("cached", content)]))
            connection.execute("UPDATE messages_v2 SET data=? WHERE mid=1", (current,))
            connection.commit()
            history = destination / "history"
            history.mkdir()
            for suffix in ("", "-wal"):
                shutil.copyfile(Path(str(original) + suffix), history / ("cache4.db" + suffix))
        finally:
            connection.close()
    inventory = [{"path": path.relative_to(destination).as_posix(), "size": path.stat().st_size,
                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                 for path in (db, expected, destination / "history/cache4.db", destination / "history/cache4.db-wal")]
    manifest = {"synthetic": True, "files": inventory, "expected_typed_records": 5,
                "thumbnail_sha256": hashlib.sha256(content).hexdigest(),
                "thumbnail_bytes": len(content), "full_original_recovered": False,
                "history_current_text": "Current photo caption", "history_previous_text": "Prior photo caption",
                "history_current_records": 1, "history_previous_records": 1,
                "source_commit": "4de548e79fed27f1a66fbdff84223321838fe925"}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "TelegramMediaFixtures"
    result = build(target)
    print(f"Built synthetic Telegram photo-media fixture: {len(result['files'])} files, {result['expected_typed_records']} supported records")
