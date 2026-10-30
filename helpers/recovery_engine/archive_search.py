"""Literal Unicode keyword search over an existing, immutable local archive.

This module does not run importers, render source HTML, open remote links or write
any file. SQLite is opened immutable/read-only; JSONL is a streaming fallback.
"""
from __future__ import annotations

import json
import datetime as dt
import heapq
import os
from pathlib import Path
import sqlite3
import stat

MAX_RECORD = 4 * 1024 * 1024
MAX_TEXT_RESULT = 64 * 1024
MAX_INDEX = 8 * 1024 * 1024 * 1024
MAX_SORT_WINDOW = 100_000
APPS = {"", "Telegram", "WhatsApp", "Signal"}
EVIDENCE = {"", "export", "backup", "previous", "fragment"}


class SearchError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _plain_path(path):
    """Check each ancestor, including Windows junctions, before opening."""
    path = Path(os.path.abspath(path))
    for item in [path, *path.parents]:
        try:
            st = item.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            raise SearchError("ARCHIVE_PATH_UNSAFE")
    return path


def _archive_path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SearchError("INVALID_REQUEST")
    root = _plain_path(value)
    if root.is_file() and root.name in ("chat-index.sqlite", "messages.jsonl"):
        root = root.parent
    if not root.is_dir():
        raise SearchError("ARCHIVE_NOT_FOUND")
    if (root / "job.incomplete").exists():
        raise SearchError("ARCHIVE_INCOMPLETE")
    if not any((root / name).is_file() for name in ("chat-index.sqlite", "messages.jsonl")):
        raise SearchError("ARCHIVE_NOT_FOUND")
    return root


def _normalized(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("text"), str):
        return None
    # Keep only known display/provenance fields. Never forward app crypto keys.
    names = ("app", "snapshot_id", "chat_id", "chat_name", "sender_id", "sender_name",
             "timestamp", "timestamp_raw", "message_id", "evidence_kind", "source_file",
             "source_record", "text", "timezone_unknown", "date_ambiguous", "previous_version",
             "source_id", "original_relative_path", "source_sha256", "record_kind", "completeness",
             "byte_offset", "byte_length", "encoding", "application_confirmed", "identity_scope",
             "native_constructor", "native_layer", "wal_commit_frame", "wal_proof", "wal_db_sha256",
             "wal_sha256", "wal_snapshot_sha256", "media_kind", "media_id", "media_status", "thumbnail_count")
    result = {name: raw.get(name) for name in names}
    result["date_ambiguous"] = raw.get("date_ambiguous", raw.get("timestamp_ambiguous"))
    if not isinstance(result["app"], str) or result["app"] not in APPS - {""}:
        return None
    if not isinstance(result["evidence_kind"], str) or result["evidence_kind"] not in EVIDENCE - {""}:
        return None
    for name in names:
        if result[name] is not None and not isinstance(result[name], (str, int, float, bool)):
            result[name] = None
        if name != "text" and isinstance(result[name], str):
            result[name] = result[name][:4096]
    refs = raw.get("attachments", [])
    result["attachments"] = [x for x in refs[:100] if isinstance(x, str) and len(x) < 4096] if isinstance(refs, list) else []
    origins = raw.get("additional_sources", raw.get("sources", []))
    result["sources"] = [
        {k: str(item.get(k))[:4096] for k in ("source_file", "source_record", "snapshot_id", "source_sha256",
             "wal_commit_frame", "wal_proof", "wal_sha256", "wal_snapshot_sha256", "media_kind", "media_id", "media_status", "thumbnail_count")
         if isinstance(item.get(k), (str, int))}
        for item in origins[:10] if isinstance(item, dict)
    ] if isinstance(origins, list) else []
    return result


def _jsonl(path, warnings):
    path = _plain_path(path)
    if path.stat().st_size > MAX_INDEX:
        raise SearchError("ARCHIVE_TOO_LARGE")
    with path.open("rb") as source:
        while True:
            line = source.readline(MAX_RECORD + 1)
            if not line:
                break
            if len(line) > MAX_RECORD:
                warnings.add("RECORD_SKIPPED")
                while line and not line.endswith(b"\n"):
                    line = source.readline(MAX_RECORD + 1)
                continue
            try:
                value = _normalized(json.loads(line))
            except (ValueError, UnicodeError):
                value = None
            if value is None:
                warnings.add("RECORD_SKIPPED")
            else:
                yield value


def _sqlite(path, warnings):
    path = _plain_path(path)
    if path.stat().st_size > MAX_INDEX:
        raise SearchError("ARCHIVE_TOO_LARGE")
    # immutable ignores sidecar journals and never creates WAL/SHM on the source.
    uri = path.as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        found = connection.execute("SELECT type FROM sqlite_master WHERE name=?", ("messages",)).fetchone()
        if found != ("table",):
            raise SearchError("ARCHIVE_SCHEMA_UNSUPPORTED")
        columns = {r[1] for r in connection.execute("PRAGMA table_info(messages)")}
        if not {"id", "json"}.issubset(columns):
            raise SearchError("ARCHIVE_SCHEMA_UNSUPPORTED")
        for (raw,) in connection.execute("SELECT CASE WHEN length(json)<=? THEN json ELSE NULL END FROM messages ORDER BY id", (MAX_RECORD,)):
            try:
                value = _normalized(json.loads(raw)) if isinstance(raw, str) else None
            except (ValueError, UnicodeError):
                value = None
            if value is None:
                warnings.add("RECORD_SKIPPED")
            else:
                yield value
    finally:
        connection.close()


def search(request):
    if request.get("protocol") != 1 or request.get("operation") != "search":
        raise SearchError("INVALID_REQUEST")
    root = _archive_path(request.get("archive"))
    app, evidence = request.get("app", ""), request.get("evidence", "")
    query = request.get("query", "")
    offset, limit = request.get("offset", 0), request.get("limit", 100)
    sort = request.get("sort", "")
    if not isinstance(app, str) or not isinstance(evidence, str) or app not in APPS or evidence not in EVIDENCE or not isinstance(query, str) or len(query) > 1024:
        raise SearchError("INVALID_REQUEST")
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise SearchError("INVALID_REQUEST")
    if sort not in ("", "latest"):
        raise SearchError("INVALID_REQUEST")
    if sort == "latest" and offset + limit > MAX_SORT_WINDOW:
        raise SearchError("QUERY_WINDOW_LIMIT")
    from text_match import Matcher, MatchError
    try:
        matcher = Matcher(query, request.get("query_mode", "literal"))
    except MatchError as error:
        raise SearchError(error.code) from None
    warnings = set()

    def matches(value):
        if (app and value["app"] != app) or (evidence and value["evidence_kind"] != evidence):
            return False
        try:
            return matcher.matches(value["text"])
        except MatchError as error:
            raise SearchError(error.code) from None

    def displayed(value):
        if len(value["text"]) > MAX_TEXT_RESULT:
            value["text_length"] = len(value["text"])
            value["text"] = value["text"][:MAX_TEXT_RESULT]
            value["text_truncated"] = True
        return value

    def date_rank(value):
        timestamp = value.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp:
            return 0, 0.0
        try:
            date = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            date = date.replace(tzinfo=date.tzinfo or dt.timezone.utc)
            return 1, date.timestamp()
        except (ValueError, OSError, OverflowError):
            # A recorded HTML timestamp has this explicit day-first form.
            # Ambiguous exported date strings remain unknown, never guessed.
            for fmt in ("%d.%m.%Y %H:%M:%S UTC%z", "%d.%m.%Y %H:%M:%S"):
                try:
                    date = dt.datetime.strptime(timestamp, fmt)
                    date = date.replace(tzinfo=date.tzinfo or dt.timezone.utc)
                    return 1, date.timestamp()
                except (ValueError, OSError, OverflowError):
                    pass
            return 0, 0.0

    def collect(records):
        total, page = 0, []
        for value in records:
            if not matches(value):
                continue
            if offset <= total < offset + limit:
                page.append(displayed(value))
            total += 1
        return total, page

    def ordered(factory, source):
        if not sort:
            return collect(factory())
        # The heap stores only dates and row ordinals, never message bodies.
        # A second read retrieves at most one visible page of bounded text.
        # This keeps keyword searches usable for large pre-existing archives.
        state = source.stat()
        heap, total = [], 0
        window = offset + limit
        for ordinal, value in enumerate(factory()):
            if not matches(value):
                continue
            total += 1
            rank = (*date_rank(value), -ordinal, ordinal)
            if len(heap) < window:
                heapq.heappush(heap, rank)
            elif rank > heap[0]:
                heapq.heapreplace(heap, rank)
        selected = [rank[-1] for rank in sorted(heap, reverse=True)[offset:offset + limit]]
        wanted = set(selected)
        page = {}
        for ordinal, value in enumerate(factory()):
            if ordinal in wanted:
                page[ordinal] = displayed(value)
            if len(page) == len(wanted):
                break
        after = source.stat()
        if (state.st_size, state.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise SearchError("ARCHIVE_CHANGED")
        return total, [page[index] for index in selected]

    index = root / "chat-index.sqlite"
    try:
        if index.is_file():
            journal = root / "chat-index.sqlite-wal"
            if journal.is_file() and journal.stat().st_size > 0:
                # A currently open index is not a published archive snapshot.
                # Do not silently ignore committed messages in its WAL.
                raise SearchError("ARCHIVE_SCHEMA_UNSUPPORTED")
            total, page = ordered(lambda: _sqlite(index, warnings), index)
        else:
            jsonl = root / "messages.jsonl"
            total, page = ordered(lambda: _jsonl(jsonl, warnings), jsonl)
    except (sqlite3.Error, SearchError) as error:
        if isinstance(error, SearchError) and error.code not in ("ARCHIVE_SCHEMA_UNSUPPORTED",):
            raise
        fallback = root / "messages.jsonl"
        if not fallback.is_file():
            raise SearchError("ARCHIVE_INDEX_INVALID")
        warnings.add("INDEX_FALLBACK_JSONL")
        total, page = ordered(lambda: _jsonl(fallback, warnings), fallback)
    return {"status": "partial" if warnings else "complete", "code": "OK", "records": page,
            "total": total, "offset": offset, "limit": limit, "warnings": sorted(warnings),
            "archive": str(root)}
