"""Conservative SQLite rollback before-images from static journal copies.

This is not WAL committed history. Static bytes cannot establish whether a
journal was hot, a transaction committed, or a message was deleted. SQLite's
sparse 32-bit checksum samples only some page bytes: it detects some damage,
not authenticity of the page, page number, SQL context or text.

Supported segments have a finite positive record count and an explicit valid
page/sector size. Unsupported or damaged tails may expose their previously
validated prefix for unattributed fragments, but never a complete snapshot.
A snapshot needs every original page, including page 1 and its old schema;
no bytes are taken from a neighbouring current database.

Format/source references (independent implementation):
https://sqlite.org/fileformat2.html#the_rollback_journal
https://github.com/sqlite/sqlite/blob/version-3.53.1/src/pager.c
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import struct
import uuid

from sqlite_history import (HistoryError, _db_header, _quick_check, _safe_path,
                            _sha256, _state)


MAGIC = bytes.fromhex("d9d505f920a163d7")


class RollbackError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RollbackLimits:
    max_input_bytes: int = 256 * 1024 * 1024
    max_output_bytes: int = 512 * 1024 * 1024
    max_records: int = 65536
    max_headers: int = 8192
    max_page_count: int = 131072
    max_sqlite_ops: int = 5_000_000


def _limits(value):
    if value is None:
        value = RollbackLimits()
    elif isinstance(value, dict):
        try:
            value = RollbackLimits(**value)
        except TypeError as error:
            raise RollbackError("INVALID_LIMITS") from error
    if not isinstance(value, RollbackLimits):
        raise RollbackError("INVALID_LIMITS")
    if any(type(getattr(value, key)) is not int or
           not 0 < getattr(value, key) <= cap
           for key, cap in asdict(RollbackLimits()).items()):
        raise RollbackError("INVALID_LIMITS")
    return value


def _cancel(cancel):
    if cancel is not None and cancel():
        raise RollbackError("CANCELLED")


def _opened_state(source):
    info = os.fstat(source.fileno())
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _assert_source(path, source, initial, expected_hash, cancel):
    _cancel(cancel)
    if _state(path) != initial or _opened_state(source) != initial:
        raise RollbackError("SOURCE_CHANGED")
    if _sha256(path, cancel) != expected_hash:
        raise RollbackError("SOURCE_CHANGED")
    if _state(path) != initial or _opened_state(source) != initial:
        raise RollbackError("SOURCE_CHANGED")


def _sparse_checksum(data, nonce):
    # pager_cksum uses i>0, not i>=0. No SQL key/header authentication.
    return (nonce + sum(data[len(data) - 200:0:-200])) & 0xffffffff


def _read_at(source, offset, size):
    source.seek(offset)
    data = source.read(size)
    if len(data) != size:
        raise RollbackError("SOURCE_CHANGED")
    return data


def _same_descriptor(value, expected):
    # bool==1 in Python must not let serialized metadata change its type.
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(
            _same_descriptor(value[key], item) for key, item in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _same_descriptor(one, two) for one, two in zip(value, expected))
    return value == expected


def _footer(source, size, page_size):
    """Detect a bounded super-journal footer, never read/follow its filename."""
    if size < 20 or _read_at(source, size - 8, 8) != MAGIC:
        return None
    length, checksum = struct.unpack(">II", _read_at(source, size - 16, 8))
    if not 1 <= length <= 65536 or length > size - 20:
        return None
    start = size - 20 - length
    sentinel = int.from_bytes(_read_at(source, start, 4), "big")
    if sentinel != 0x40000000 // page_size + 1:
        return None
    name = _read_at(source, start + 4, length)
    return {"offset": start, "bytes": size - start,
            "name_bytes": length,
            "name_checksum_matches": (sum(name) & 0xffffffff) == checksum}


def _parse(source, size, limits, cancel):
    report = {"schema": 1, "status": "validating", "page_size": None,
              "sector_size": None, "initial_pages": None,
              "headers": [], "records": [], "tail_reason": None,
              "snapshot": None, "snapshot_skipped_reason": None,
              "checksum_kind": "sqlite_sparse_32bit",
              "content_authenticity_verified": False,
              "hot_state": "unknown", "current_state_confirmed": False,
              "validated_prefix_bytes": 0, "source_bytes": size,
              "limited": False, "super_journal": None,
              "limits": asdict(limits)}

    def stop(reason, *, unsupported=False, limited=False):
        report["tail_reason"] = reason
        report["limited"] = limited
        report["status"] = ("validated_prefix" if report["records"] else
                            "unsupported" if unsupported else "invalid")
        return report

    if size < 28:
        return stop("header_truncated")
    head = _read_at(source, 0, 28)
    if head[:8] != MAGIC:
        return stop("zeroed_header" if not any(head) else "header_magic",
                    unsupported=not any(head))
    first = struct.unpack(">5I", head[8:])
    first_page = first[4]
    if 512 <= first_page <= 65536 and not first_page & (first_page - 1):
        report["super_journal"] = _footer(source, size, first_page)
    end = report["super_journal"]["offset"] if report["super_journal"] else size
    offset, seen = 0, set()
    while offset < end:
        _cancel(cancel)
        if len(report["headers"]) >= limits.max_headers:
            return stop("header_limit", limited=True)
        if end - offset < 28:
            return stop("header_truncated")
        head = _read_at(source, offset, 28)
        if head[:8] != MAGIC:
            return stop("zeroed_header" if not any(head) else "header_magic",
                        unsupported=not any(head))
        count, nonce, pages, sector, page = struct.unpack(">5I", head[8:])
        if count in (0, 0xffffffff):
            return stop("zero_record_count" if count == 0 else "sentinel_record_count",
                        unsupported=True)
        if not 512 <= page <= 65536 or page & (page - 1):
            return stop("page_size_unsupported", unsupported=True)
        if not 32 <= sector <= 65536 or sector & (sector - 1):
            return stop("sector_size_invalid")
        if not 1 <= pages <= limits.max_page_count:
            return stop("initial_pages_bounds", limited=pages > limits.max_page_count)
        if report["page_size"] is None:
            report.update(page_size=page, sector_size=sector, initial_pages=pages)
        elif (page, sector, pages) != (report["page_size"], report["sector_size"],
                                       report["initial_pages"]):
            return stop("header_geometry_changed")
        if offset % sector or end - offset < sector:
            return stop("header_sector_truncated")
        # Header padding is deliberately not interpreted: pager.c may repeat
        # its header buffer when the assumed sector is larger than a page.
        report["headers"].append({"header_index": len(report["headers"]) + 1,
            "offset": offset, "record_count": count, "nonce": nonce,
            "initial_pages": pages, "sector_size": sector, "page_size": page})
        cursor = offset + sector
        for _ in range(count):
            _cancel(cancel)
            if len(report["records"]) >= limits.max_records:
                return stop("record_limit", limited=True)
            if end - cursor < page + 8:
                return stop("record_truncated")
            raw = _read_at(source, cursor, page + 8)
            number = int.from_bytes(raw[:4], "big")
            if not 1 <= number <= pages or number == 0x40000000 // page + 1:
                return stop("page_number_bounds")
            if number in seen:
                return stop("duplicate_page")
            data = raw[4:4 + page]
            checksum = int.from_bytes(raw[4 + page:], "big")
            if _sparse_checksum(data, nonce) != checksum:
                return stop("page_checksum")
            seen.add(number)
            report["records"].append({"page": number,
                "header_index": len(report["headers"]), "header_offset": offset,
                "record_offset": cursor, "data_offset": cursor + 4,
                "checksum_offset": cursor + 4 + page,
                "page_sha256": hashlib.sha256(data).hexdigest(),
                "sparse_checksum": checksum, "nonce": nonce})
            cursor += page + 8
            report["validated_prefix_bytes"] = cursor
        if cursor == end:
            break
        following = (cursor + sector - 1) // sector * sector
        if end <= following:
            # Only a bounded all-zero alignment tail is accepted as padding.
            # Uncounted/torn bytes never establish a complete snapshot.
            if any(_read_at(source, cursor, end - cursor)):
                return stop("trailing_bytes")
            break
        offset = following
    if report["super_journal"]:
        return stop("super_journal", unsupported=True)
    report["status"] = "complete"
    return report


def _snapshot(source, output, report, limits, cancel):
    records = {record["page"]: record for record in report["records"]}
    pages, page = report["initial_pages"], report["page_size"]
    if report["tail_reason"]:
        report["snapshot_skipped_reason"] = "unsupported_or_invalid_tail"
        return None
    if not pages or len(records) != pages:
        report["snapshot_skipped_reason"] = "initial_pages_missing"
        return None
    amount = page * pages
    if amount > limits.max_output_bytes:
        report["snapshot_skipped_reason"] = "output_limit"
        report["limited"] = True
        return None
    job = output / ("rollback-history-" + uuid.uuid4().hex[:12])
    job.mkdir(exist_ok=False)
    target = job / "before-image.sqlite"
    partial = job / "before-image.partial"
    try:
        with partial.open("xb") as sink:
            for number in range(1, pages + 1):
                _cancel(cancel)
                data = _read_at(source, records[number]["data_offset"], page)
                if hashlib.sha256(data).hexdigest() != records[number]["page_sha256"]:
                    raise RollbackError("SOURCE_CHANGED")
                if number == 1:
                    try:
                        if _db_header(data[:100], amount, snapshot_pages=pages) != page:
                            raise HistoryError("SNAPSHOT_PAGE_SIZE_MISMATCH")
                    except HistoryError:
                        report["snapshot_skipped_reason"] = "snapshot_header_invalid"
                        return None
                sink.write(data)
            sink.flush()
            os.fsync(sink.fileno())
        if not _quick_check(partial, limits, cancel):
            report["snapshot_skipped_reason"] = "snapshot_integrity_invalid"
            return None
        digest = _sha256(partial, cancel)
        _cancel(cancel)
        partial.rename(target)
        return {"path": str(target), "sha256": digest,
            "snapshot_id": "rollback:" + report["journal_sha256"] + ":before-image:" + digest,
            "proof": "all_initial_pages_from_sparse_checksum_validated_journal",
            "page_map": {"journal_sha256": report["journal_sha256"],
                "page_size": page, "initial_pages": pages,
                "records": [dict(record) for record in report["records"]]}}
    finally:
        partial.unlink(missing_ok=True)


def extract_rollback_journal(journal_path, working_dir, *, limits=None, cancel=None):
    """Validate a journal and optionally create its self-contained before-image.

    Format damage/unsupported formats return a report with no snapshot. Only
    validated record prefixes are exposed. Operational errors, source changes,
    invalid options and cancellation raise ``RollbackError(code)``. The caller
    owns completed private output files and must keep journal identity separate
    from any current neighbouring database/account.
    """
    snapshot = None
    try:
        limits = _limits(limits)
        _cancel(cancel)
        path = _safe_path(journal_path, regular=True)
        output = _safe_path(working_dir, directory=True)
        initial = _state(path)
        if initial[2] > limits.max_input_bytes:
            raise RollbackError("INPUT_LIMIT")
        with path.open("rb") as source:
            if _opened_state(source) != initial:
                raise RollbackError("SOURCE_CHANGED")
            digest = _sha256(path, cancel)
            report = _parse(source, initial[2], limits, cancel)
            report["journal_sha256"] = digest
            report["source_state"] = list(initial)
            _assert_source(path, source, initial, digest, cancel)
            snapshot = _snapshot(source, output, report, limits, cancel)
            _assert_source(path, source, initial, digest, cancel)
            report["snapshot"] = snapshot
            return report
    except HistoryError as error:
        if snapshot is not None:
            Path(snapshot["path"]).unlink(missing_ok=True)
        raise RollbackError(error.code) from None
    except (OSError, RollbackError) as error:
        if snapshot is not None:
            Path(snapshot["path"]).unlink(missing_ok=True)
        if isinstance(error, RollbackError):
            raise
        raise RollbackError("ROLLBACK_IO_ERROR") from error
    except BaseException:
        # A caller's cancellation callback may raise instead of returning True.
        # A completed private snapshot still must not survive a failed call.
        if snapshot is not None:
            Path(snapshot["path"]).unlink(missing_ok=True)
        raise


def iter_validated_pages(journal_path, report, *, cancel=None):
    """Yield ``(physical_record_metadata, bytes)`` from the validated prefix.

    The full source hash and canonical parser descriptors are checked before
    the first yield; the source is checked again after exhaustion. Callers
    must stage findings privately and publish only after exhausting this
    iterator successfully. An interrupted/abandoned iterator does not establish
    the final source check. A serialized/tampered descriptor is not trusted.
    """
    try:
        if not isinstance(report, dict):
            raise RollbackError("REPORT_INVALID")
        limits = _limits(report.get("limits"))
        path = _safe_path(journal_path, regular=True)
        initial = _state(path)
        if initial[2] > limits.max_input_bytes:
            raise RollbackError("INPUT_LIMIT")
        with path.open("rb") as source:
            expected = report.get("journal_sha256")
            if (not isinstance(expected, str) or len(expected) != 64 or
                    any(char not in "0123456789abcdef" for char in expected)):
                raise RollbackError("REPORT_INVALID")
            _assert_source(path, source, initial, expected, cancel)
            canonical = _parse(source, initial[2], limits, cancel)
            for field in ("source_bytes", "page_size", "sector_size", "initial_pages",
                          "headers", "records", "tail_reason", "status",
                          "validated_prefix_bytes", "super_journal", "checksum_kind",
                          "content_authenticity_verified", "hot_state",
                          "current_state_confirmed"):
                if not _same_descriptor(report.get(field), canonical[field]):
                    raise RollbackError("REPORT_INVALID")
            if not _same_descriptor(report.get("source_state"), list(initial)):
                raise RollbackError("SOURCE_CHANGED")
            for record in canonical["records"]:
                _cancel(cancel)
                data = _read_at(source, record["data_offset"], canonical["page_size"])
                if hashlib.sha256(data).hexdigest() != record["page_sha256"]:
                    raise RollbackError("SOURCE_CHANGED")
                yield dict(record), data
            _assert_source(path, source, initial, expected, cancel)
    except HistoryError as error:
        raise RollbackError(error.code) from None
    except OSError as error:
        raise RollbackError("ROLLBACK_IO_ERROR") from error
