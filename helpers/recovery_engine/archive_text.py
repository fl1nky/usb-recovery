"""Bounded read-only pages of one fingerprint-bound archive message.

Locators are emitted by archive_search, never accepted as filesystem paths.
Offsets and lengths are Unicode code points, including astral characters.
"""
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from archive_search import (MAX_INDEX, MAX_RECORD, MAX_TEXT_RESULT, SearchError,
                            _archive_path, _normalized, _plain_path)

_KEY = re.compile(r"\A(jsonl|sqlite|sqlite-ordinal):(-?[0-9]{1,19}):([a-f0-9]{64})\Z")


def _jsonl_record(path, position):
    path = _plain_path(path)
    with path.open("rb") as source:
        before = path.stat()
        if before.st_size > MAX_INDEX:
            raise SearchError("ARCHIVE_TOO_LARGE")
        if not 0 <= position < before.st_size:
            raise SearchError("RECORD_CHANGED")
        if position:
            source.seek(position - 1)
            if source.read(1) != b"\n":
                raise SearchError("RECORD_CHANGED")
        source.seek(position)
        raw = source.readline(MAX_RECORD + 1)
        if len(raw) > MAX_RECORD:
            raise SearchError("RECORD_TOO_LARGE")
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise SearchError("ARCHIVE_CHANGED")
        return raw


def _sqlite_record(path, position, ordinal):
    path = _plain_path(path)
    before = path.stat()
    if before.st_size > MAX_INDEX:
        raise SearchError("ARCHIVE_TOO_LARGE")
    wal = _plain_path(Path(str(path) + "-wal"))
    if wal.is_file() and wal.stat().st_size:
        raise SearchError("ARCHIVE_INCOMPLETE")
    try:
        connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    except sqlite3.Error:
        raise SearchError("ARCHIVE_INDEX_INVALID") from None
    operations = 0
    def budget():
        nonlocal operations
        operations += 1000
        return operations > 10_000_000
    try:
        connection.enable_load_extension(False)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.set_progress_handler(budget, 1000)
        if connection.execute("SELECT type FROM sqlite_master WHERE name='messages'").fetchone() != ("table",):
            raise SearchError("ARCHIVE_SCHEMA_UNSUPPORTED")
        columns = {item[1] for item in connection.execute("PRAGMA table_info(messages)")}
        if not {"id", "json"} <= columns:
            raise SearchError("ARCHIVE_SCHEMA_UNSUPPORTED")
        if ordinal:
            if position < 0:
                raise SearchError("INVALID_REQUEST")
            rows = connection.execute("SELECT CASE WHEN length(json)<=? THEN json ELSE NULL END FROM messages ORDER BY id LIMIT 1 OFFSET ?", (MAX_RECORD, position)).fetchall()
        else:
            rows = connection.execute("SELECT CASE WHEN length(json)<=? THEN json ELSE NULL END FROM messages WHERE id=? LIMIT 2", (MAX_RECORD, position)).fetchall()
        if len(rows) != 1 or not isinstance(rows[0][0], str):
            raise SearchError("RECORD_CHANGED")
        raw = rows[0][0].encode("utf-8")
        if len(raw) > MAX_RECORD:
            raise SearchError("RECORD_TOO_LARGE")
    except sqlite3.Error:
        raise SearchError("ARCHIVE_READ_LIMIT" if operations > 10_000_000 else "ARCHIVE_INDEX_INVALID") from None
    finally:
        connection.close()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise SearchError("ARCHIVE_CHANGED")
    return raw


def read_page(request):
    if request.get("protocol") != 1 or request.get("operation") != "message_page":
        raise SearchError("INVALID_REQUEST")
    root = _archive_path(request.get("archive"))
    key = request.get("record_key")
    match = _KEY.fullmatch(key) if isinstance(key, str) else None
    offset, limit = request.get("text_offset", 0), request.get("limit", MAX_TEXT_RESULT)
    if match is None or type(offset) is not int or offset < 0 or offset > MAX_RECORD or type(limit) is not int or not 1 <= limit <= MAX_TEXT_RESULT:
        raise SearchError("INVALID_REQUEST")
    kind, position, expected = match.groups()
    position = int(position)
    if not -(1 << 63) <= position < (1 << 63):
        raise SearchError("INVALID_REQUEST")
    try:
        raw = (_jsonl_record(root / "messages.jsonl", position) if kind == "jsonl" else
               _sqlite_record(root / "chat-index.sqlite", position, kind == "sqlite-ordinal"))
        if hashlib.sha256(raw).hexdigest() != expected:
            raise SearchError("RECORD_CHANGED")
        value = _normalized(json.loads(raw))
        if value is None or value["app"] != "Telegram":
            raise SearchError("RECORD_UNAVAILABLE")
    except (OSError, UnicodeError, ValueError):
        raise SearchError("RECORD_UNAVAILABLE") from None
    text = value["text"]
    if offset > len(text):
        raise SearchError("INVALID_REQUEST")
    end = min(len(text), offset + limit)
    return {"status": "complete", "code": "OK", "archive": str(root), "record_key": key,
            "text": text[offset:end], "text_offset": offset, "next_offset": end,
            "text_length": len(text), "limit": limit, "eof": end == len(text)}
