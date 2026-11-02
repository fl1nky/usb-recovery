"""Strict caption reader for one official Android media-cache schema.

Format: Telegram Android 13.1.0, commit
4de548e79fed27f1a66fbdff84223321838fe925, MessagesStorage.java:559-561;
MediaDataController.java:4556-4562 deserializes the blob as a full Message.
Only layer232 photo captions are supported. Cache presence/removal says
nothing about user deletion. No attachment paths, decryption or freeblocks.
"""
from __future__ import annotations
import re

from telegram_tl import MAX_BLOB, TelegramTlError, parse_message

SOURCE_COMMIT = "4de548e79fed27f1a66fbdff84223321838fe925"
_COLUMNS = (("mid", "INTEGER", 1), ("uid", "INTEGER", 2),
            ("date", "INTEGER", 0), ("type", "INTEGER", 3),
            ("data", "BLOB", 0))


class MediaCacheError(ValueError):
    pass


def supported_schema(connection):
    """Reject views, virtual/generated/extra fields and different SQL keys."""
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        ("media_v4",)).fetchone()
    if row is None or not isinstance(row[0], str):
        return False
    if not re.match(r"CREATE\s+TABLE\b", row[0], re.I) or re.search(
            r"\bWITHOUT\s+ROWID\b", row[0], re.I):
        return False
    info = connection.execute("PRAGMA table_xinfo(media_v4)").fetchall()
    return (len(info) == len(_COLUMNS) and
            all((column[1], column[2].upper(), column[5]) == expected
                and column[3] == 0 and column[4] is None and column[6] == 0
                for column, expected in zip(info, _COLUMNS)))


def _checked(row):
    mid, uid, date, category, data = row
    if not all(type(value) is int for value in (mid, uid, date, category)):
        raise MediaCacheError("MEDIA_CACHE_ROW_INVALID")
    if category != 0:
        raise MediaCacheError("MEDIA_CACHE_TYPE_UNSUPPORTED")
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BLOB:
        raise MediaCacheError("MEDIA_CACHE_BLOB_INVALID_OR_LIMITED")
    value = parse_message(data)
    if value["layer"] != 232 or value["constructor"] != "0x7600b9d3":
        raise MediaCacheError("MEDIA_CACHE_LAYER_UNSUPPORTED")
    media = value.get("media", {})
    if (media.get("type") != "photo" or
            media.get("constructor") != "0xe216eb63"):
        raise MediaCacheError("MEDIA_CACHE_PHOTO_UNSUPPORTED")
    if mid <= 0 or mid != value["id"] or date != value["date"]:
        raise MediaCacheError("MEDIA_CACHE_KEYS_MISMATCH")
    # Secret dialog IDs live in the high32bits. Never authorize them using
    # the public non-secret peer relations or a neighboring account's IDs.
    if uid == 0 or uid & 0xffffffff == 0 or abs(uid) >= 1 << 52:
        raise MediaCacheError("MEDIA_CACHE_DIALOG_UNSUPPORTED")
    peer, sender = value["peer"], value["from_peer"]
    if peer["kind"] in ("chat", "channel"):
        related = uid == -peer["id"]
    elif value["out"] or sender is None:
        related = uid > 0 and uid == peer["id"]
    else:
        related = uid > 0 and sender["kind"] == "user" and uid == sender["id"]
    if not related:
        raise MediaCacheError("MEDIA_CACHE_DIALOG_MISMATCH")
    return {"mid": mid, "uid": uid, "date": date, "type": category,
            "data": data, "value": value}


def photo_captions(connection, *, max_rows, cancel=None, report=None):
    """Yield complete SQL/TL-checked rows; all budgets are caller bounded."""
    if not supported_schema(connection):
        raise MediaCacheError("MEDIA_CACHE_SCHEMA_UNSUPPORTED")
    if type(max_rows) is not int or max_rows < 1:
        raise MediaCacheError("MEDIA_CACHE_ROW_LIMIT_INVALID")
    report = report if report is not None else {}
    report.update(checked=0, accepted=0, rejected=0, limited=False, reasons={})
    query = ("SELECT mid,uid,date,type,CASE WHEN typeof(data)='blob' AND "
             "length(data)<=? THEN data ELSE NULL END "
             "FROM media_v4 ORDER BY date DESC LIMIT ?")
    for row in connection.execute(query, (MAX_BLOB, max_rows + 1)):
        if cancel is not None and cancel():
            raise MediaCacheError("MEDIA_CACHE_CANCELLED")
        if report["checked"] == max_rows:
            report["limited"] = True
            break
        report["checked"] += 1
        try:
            candidate = _checked(row)
        except (MediaCacheError, TelegramTlError, OverflowError,
                UnicodeError, ValueError) as error:
            code = getattr(error, "code", str(error))
            report["rejected"] += 1
            report["reasons"][code] = report["reasons"].get(code, 0) + 1
            continue
        report["accepted"] += 1
        yield candidate
