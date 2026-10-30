"""Literal Unicode keyword search over an existing, immutable local archive.

This module does not run importers, render source HTML, open remote links or write
any file. SQLite is opened immutable/read-only; JSONL is a streaming fallback.
"""
from __future__ import annotations

import json
import datetime as dt
import heapq
import hashlib
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
EVIDENCE_FILTERS = EVIDENCE | {"deleted"}
OVERFLOW_FIELDS = ("sqlite_payload_length", "sqlite_payload_sha256", "sqlite_payload_ranges",
                   "sqlite_overflow_pages", "sqlite_overflow_chain_verified")
WAL_TAIL_FIELDS = ("wal_tail_reason", "wal_validated_prefix_bytes",
                   "wal_snapshot_latest_known_commit", "wal_current_state_confirmed")


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


def _overflow_provenance(raw):
    """Validate bounded display metadata, without claiming source authenticity.

    None means an incomplete/incoherent claimed overflow map, not "no map".
    Range verification here is structural only; search never opens source DBs.
    """
    if not any(raw.get(name) is not None for name in OVERFLOW_FIELDS):
        return {}
    length, digest = raw.get("sqlite_payload_length"), raw.get("sqlite_payload_sha256")
    ranges, pages = raw.get("sqlite_payload_ranges"), raw.get("sqlite_overflow_pages")
    verified = raw.get("sqlite_overflow_chain_verified")
    if (type(length) is not int or not 1 <= length <= 4096 * 65536 or
            not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or
            type(verified) is not bool or not isinstance(ranges, list) or not 2 <= len(ranges) <= 4096 or
            not isinstance(pages, list) or len(pages) != len(ranges) - 1 or
            any(type(page) is not int or not 1 <= page <= 262144 for page in pages) or len(set(pages)) != len(pages)):
        return None
    keys = {"logical_offset", "bytes", "sqlite_page", "physical_source", "physical_byte_offset", "wal_frame"}
    position, cleaned, physical = 0, [], {"db": [], "wal": []}
    for value in ranges:
        if not isinstance(value, dict) or set(value) != keys:
            return None
        logical, size, page, source, offset, frame = (value[name] for name in
            ("logical_offset", "bytes", "sqlite_page", "physical_source", "physical_byte_offset", "wal_frame"))
        if (type(logical) is not int or logical != position or type(size) is not int or not 1 <= size <= 65536 or
                type(page) is not int or not 1 <= page <= 262144 or source not in ("db", "wal") or
                type(offset) is not int or not 0 <= offset <= 4 * 1024**3 - size or
                (frame is not None if source == "db" else type(frame) is not int or not 1 <= frame <= 262144)):
            return None
        position += size
        if position > length:
            return None
        cleaned.append(dict(value))
        physical[source].append((offset, offset + size))
    if position != length or [value["sqlite_page"] for value in cleaned[1:]] != pages or cleaned[0]["sqlite_page"] in pages:
        return None
    for intervals in physical.values():
        intervals.sort()
        if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
            return None
    return dict(zip(OVERFLOW_FIELDS, (length, digest, cleaned, list(pages), verified)))


def _valid_unicode(value):
    try:
        value.encode("utf-8")
        return True
    except UnicodeError:
        return False


def _normalized(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("text"), str) or not _valid_unicode(raw["text"]):
        return None
    # Keep only known display/provenance fields. Never forward app crypto keys.
    names = ("app", "snapshot_id", "chat_id", "chat_name", "sender_id", "sender_name",
             "timestamp", "timestamp_raw", "message_id", "evidence_kind", "source_file",
             "source_record", "text", "timezone_unknown", "date_ambiguous", "previous_version",
             "source_id", "original_relative_path", "source_sha256", "record_kind", "completeness",
             "byte_offset", "byte_length", "encoding", "application_confirmed", "identity_scope",
             "native_constructor", "native_layer", "wal_commit_frame", "wal_proof", "wal_db_sha256",
             "wal_tail_reason", "wal_validated_prefix_bytes", "wal_snapshot_latest_known_commit", "wal_current_state_confirmed",
             "wal_sha256", "wal_snapshot_sha256", "media_kind", "media_id", "media_status", "thumbnail_count",
             "recovery_status", "deletion_interpretation", "deleted", "sqlite_page", "sqlite_region", "sqlite_stored_mid",
             "record_page_offset", "blob_page_offset", "record_length", "record_sha256",
             "header_length_reconstructed", "physical_source", "physical_byte_offset", "wal_frame",
             "proof", "candidate_message_id", "candidate_peer", "candidate_date", "native_tl_body_sha256", "offset_kind", "sqlite_record_page_offset", "sqlite_record_length", "sqlite_blob_page_offset", "sqlite_header_length_reconstructed", "sqlite_record_sha256",
             "candidate_sender", "heap_class", "heap_object_id", "heap_record_sha256", "heap_record_length", "heap_text_sha256", "heap_snapshot_ms", "heap_version", "heap_identifier_bytes")
    overflow = _overflow_provenance(raw)
    if overflow is None:
        return None
    result = {name: raw.get(name) for name in names}
    if result["sqlite_stored_mid"] is not None and (type(result["sqlite_stored_mid"]) is not int or not -(1 << 63) <= result["sqlite_stored_mid"] < (1 << 63)):
        result["sqlite_stored_mid"] = None
    result["date_ambiguous"] = raw.get("date_ambiguous", raw.get("timestamp_ambiguous"))
    if not isinstance(result["app"], str) or result["app"] not in APPS - {""}:
        return None
    if not isinstance(result["evidence_kind"], str) or result["evidence_kind"] not in EVIDENCE - {""}:
        return None
    for name in names:
        if result[name] is not None and not isinstance(result[name], (str, int, float, bool)):
            result[name] = None
        if name != "text" and isinstance(result[name], str):
            result[name] = result[name][:4096] if _valid_unicode(result[name]) else None
    result.update(overflow)
    residuals = raw.get("residual_sources", [])
    provenance_names = ("source_file", "source_record", "source_sha256", "physical_source", "physical_byte_offset", "sqlite_page", "sqlite_region", "record_page_offset", "blob_page_offset", "record_length", "record_sha256", "header_length_reconstructed", "wal_frame", "wal_commit_frame", "proof", "recovery_status", "deletion_interpretation", "native_tl_body_sha256", "offset_kind", "sqlite_record_page_offset", "sqlite_record_length", "sqlite_blob_page_offset", "sqlite_header_length_reconstructed", "sqlite_record_sha256")
    result["residual_sources"] = []
    for item in residuals[:20] if isinstance(residuals, list) else []:
        if not isinstance(item, dict) or (overflow := _overflow_provenance(item)) is None:
            continue
        origin = {k: (v[:4096] if isinstance(v, str) else v) for k, v in item.items()
                  if k in provenance_names and isinstance(v, (str, int, bool)) and (not isinstance(v, str) or _valid_unicode(v))}
        origin.update(overflow)
        stored_mid = item.get("sqlite_stored_mid")
        if type(stored_mid) is int and -(1 << 63) <= stored_mid < (1 << 63):
            origin["sqlite_stored_mid"] = stored_mid
        result["residual_sources"].append(origin)
    refs = raw.get("attachments", [])
    result["attachments"] = [x for x in refs[:100] if isinstance(x, str) and len(x) < 4096 and _valid_unicode(x)] if isinstance(refs, list) else []
    origins = raw.get("additional_sources", raw.get("sources", []))
    result["sources"] = []
    for item in origins[:10] if isinstance(origins, list) else []:
        if not isinstance(item, dict) or (overflow := _overflow_provenance(item)) is None:
            continue
        origin = {k: str(item.get(k))[:4096] for k in ("source_file", "source_record", "snapshot_id", "source_sha256",
             "wal_commit_frame", "wal_proof", "wal_sha256", "wal_snapshot_sha256", "media_kind", "media_id", "media_status", "thumbnail_count")
         if isinstance(item.get(k), (str, int)) and (not isinstance(item[k], str) or _valid_unicode(item[k]))}
        origin.update({name: item[name][:4096] if isinstance(item[name], str) else item[name]
                       for name in WAL_TAIL_FIELDS if isinstance(item.get(name), (str, int, bool)) and (not isinstance(item[name], str) or _valid_unicode(item[name]))})
        origin.update(overflow)
        stored_mid = item.get("sqlite_stored_mid")
        if type(stored_mid) is int and -(1 << 63) <= stored_mid < (1 << 63):
            origin["sqlite_stored_mid"] = stored_mid
        result["sources"].append(origin)
    return result


def _jsonl(path, warnings):
    path = _plain_path(path)
    if path.stat().st_size > MAX_INDEX:
        raise SearchError("ARCHIVE_TOO_LARGE")
    with path.open("rb") as source:
        while True:
            position = source.tell()
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
                value["archive_record_key"] = "jsonl:" + str(position) + ":" + hashlib.sha256(line).hexdigest()
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
        for ordinal, (record_id, raw) in enumerate(connection.execute("SELECT id,CASE WHEN length(json)<=? THEN json ELSE NULL END FROM messages ORDER BY id", (MAX_RECORD,))):
            try:
                encoded = raw.encode("utf-8") if isinstance(raw, str) else None
                value = _normalized(json.loads(raw)) if encoded is not None and len(encoded) <= MAX_RECORD else None
            except (ValueError, UnicodeError):
                value = None
            if value is None:
                warnings.add("RECORD_SKIPPED")
            else:
                kind, position = ("sqlite", record_id) if type(record_id) is int else ("sqlite-ordinal", ordinal)
                value["archive_record_key"] = kind + ":" + str(position) + ":" + hashlib.sha256(encoded).hexdigest()
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
    if not isinstance(app, str) or not isinstance(evidence, str) or app not in APPS or evidence not in EVIDENCE_FILTERS or not isinstance(query, str) or len(query) > 1024:
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
        if (app and value["app"] != app) or (evidence == "deleted" and value.get("recovery_status") != "deleted_supported_by_evidence") or (evidence and evidence != "deleted" and value["evidence_kind"] != evidence):
            return False
        try:
            return matcher.matches(value["text"])
        except MatchError as error:
            raise SearchError(error.code) from None

    def displayed(value):
        if len(value["text"]) > MAX_TEXT_RESULT:
            text = value["text"]
            try:
                span = matcher.first_span(text)
            except MatchError as error:
                raise SearchError(error.code) from None
            start = max(0, min((span[0] if span else 0) - MAX_TEXT_RESULT // 4, len(text) - MAX_TEXT_RESULT))
            value["text_length"] = len(text)
            value["text_offset"] = start
            value["text_end"] = start + min(MAX_TEXT_RESULT, len(text) - start)
            if span is not None:
                value["match_offset"], value["match_end"] = span
            value["text"] = text[start:start + MAX_TEXT_RESULT]
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
