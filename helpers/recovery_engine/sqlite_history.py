"""Conservative prior committed SQLite WAL snapshots from static working copies.

The default ``wal_only`` policy never fills an older snapshot with present-day
database pages. Every logical page must have a checksum-valid WAL version at or
before the selected commit. Thus checkpointing later transactions into the main
DB cannot silently insert their bytes into a supposed earlier state.

``unchanged_pages`` is an explicit, weaker policy for a known consistent DB/WAL
pair: base pages may be used only if never written in this valid WAL generation.
It is disabled on any invalid/truncated/unscanned tail. Pages whose first WAL
version is later than the target commit always remain unknown. SQL integrity
checking is a further structural check, not proof of historical preimages.

Format references (no third-party implementation copied):
https://sqlite.org/fileformat2.html#wal_file_format
https://sqlite.org/walformat.html

Only regular local files are read. Snapshots are written to a new private job
subdirectory, queried read-only/immutable, and never attach/replay the source WAL.
The caller must provide quiescent, previously copied DB/WAL files, not a live DB.
Checksums detect corruption, not an intentionally forged historical record.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import struct
import uuid


class HistoryError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class HistoryLimits:
    max_input_bytes: int = 256 * 1024 * 1024
    max_output_bytes: int = 512 * 1024 * 1024
    max_frames: int = 65536
    max_commits: int = 256
    max_snapshots: int = 16
    max_page_count: int = 131072
    max_sqlite_ops: int = 5_000_000


@dataclass(frozen=True, slots=True)
class _Frame:
    number: int
    page: int
    data_offset: int
    commit_pages: int


def _cancelled(cancel):
    if cancel is not None and cancel():
        raise HistoryError("CANCELLED")


def _limits(value):
    if value is None:
        value = HistoryLimits()
    elif isinstance(value, dict):
        try:
            value = HistoryLimits(**value)
        except TypeError as exc:
            raise HistoryError("INVALID_LIMITS") from exc
    if not isinstance(value, HistoryLimits):
        raise HistoryError("INVALID_LIMITS")
    caps = HistoryLimits(1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024,
                         262144, 4096, 64, 2097152, 50_000_000)
    if any(type(getattr(value, key)) is not int or not 0 < getattr(value, key) <= cap
           for key, cap in asdict(caps).items()):
        raise HistoryError("INVALID_LIMITS")
    return value


def _safe_path(value, *, regular=False, directory=False):
    path = Path(os.path.abspath(os.fspath(value)))
    name = str(path)
    if os.name == "nt" and (name.startswith("\\\\") or ":" in name[2:]):
        raise HistoryError("NONLOCAL_PATH")
    for entry in (path, *path.parents):
        if not entry.exists() and not entry.is_symlink():
            continue
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise HistoryError("LINK_PATH")
    if regular and (not path.is_file() or not stat.S_ISREG(path.stat().st_mode)):
        raise HistoryError("REGULAR_FILE_REQUIRED")
    if directory and not path.is_dir():
        raise HistoryError("OUTPUT_DIRECTORY_REQUIRED")
    return path


def _state(path):
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _sha256(path, cancel):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            _cancelled(cancel)
            digest.update(block)
    return digest.hexdigest()


def _checksum(data, little, first=0, second=0):
    # SQLite WAL checksum words are endian-dependent; stored checksum fields
    # themselves, like all other WAL header integers, are always big-endian.
    for left, right in struct.iter_unpack("<II" if little else ">II", data):
        first = (first + left + second) & 0xffffffff
        second = (second + right + first) & 0xffffffff
    return first, second


def _db_header(head, physical_size, *, snapshot_pages=None):
    if len(head) != 100 or head[:16] != b"SQLite format 3\0":
        raise HistoryError("SQLITE_HEADER_INVALID")
    raw_page = int.from_bytes(head[16:18], "big")
    page = 65536 if raw_page == 1 else raw_page
    if not 512 <= page <= 65536 or page & (page - 1) or physical_size < page or physical_size % page:
        raise HistoryError("SQLITE_GEOMETRY_INVALID")
    if head[18] not in (1, 2) or head[19] not in (1, 2) or head[20] >= page - 480 or head[21:24] != b"\x40\x20\x20":
        raise HistoryError("SQLITE_HEADER_INVALID")
    schema = int.from_bytes(head[44:48], "big")
    encoding = int.from_bytes(head[56:60], "big")
    if schema not in (0, 1, 2, 3, 4) or encoding not in (0, 1, 2, 3) or any(head[72:92]):
        raise HistoryError("SQLITE_HEADER_INVALID")
    # An empty, newly initialized base DB can have schema/encoding zero. A
    # published snapshot must be a complete, non-empty SQL database instead.
    if snapshot_pages is not None:
        if not schema or not encoding:
            raise HistoryError("SNAPSHOT_SCHEMA_UNINITIALIZED")
        changed = int.from_bytes(head[24:28], "big")
        valid_for = int.from_bytes(head[92:96], "big")
        pages = int.from_bytes(head[28:32], "big")
        if changed == valid_for and pages and pages != snapshot_pages:
            raise HistoryError("SNAPSHOT_HEADER_SIZE_MISMATCH")
    return page


def _parse_wal(source, size, page_size, limits, cancel, report):
    header = source.read(32)
    if len(header) != 32:
        raise HistoryError("WAL_HEADER_TRUNCATED")
    magic, version, page, sequence, salt1, salt2, ca, cb = struct.unpack(">8I", header)
    if magic not in (0x377f0682, 0x377f0683) or version != 3007000:
        raise HistoryError("WAL_VERSION_UNSUPPORTED")
    if page != page_size:
        raise HistoryError("WAL_PAGE_SIZE_MISMATCH")
    little = magic == 0x377f0682
    if _checksum(header[:24], little) != (ca, cb):
        raise HistoryError("WAL_HEADER_CHECKSUM_INVALID")
    report.update(page_size=page, checkpoint_sequence=sequence, salts=[salt1, salt2])
    frames, commits = [], []
    commit_count = 0
    offset = 32
    while offset < size:
        _cancelled(cancel)
        if len(frames) >= limits.max_frames:
            report["tail_reason"] = "frame_limit"
            break
        if size - offset < 24 + page:
            report["tail_reason"] = "torn_frame"
            break
        source.seek(offset)
        frame_head = source.read(24)
        payload = source.read(page)
        if len(frame_head) != 24 or len(payload) != page:
            raise HistoryError("SOURCE_CHANGED")
        number, database_pages, one, two, wanted_a, wanted_b = struct.unpack(">6I", frame_head)
        if not 1 <= number <= limits.max_page_count or database_pages > limits.max_page_count:
            report["tail_reason"] = "page_bounds"
            break
        if (one, two) != (salt1, salt2):
            report["tail_reason"] = "salt_mismatch"
            break
        next_a, next_b = _checksum(frame_head[:8] + payload, little, ca, cb)
        if (next_a, next_b) != (wanted_a, wanted_b):
            report["tail_reason"] = "frame_checksum"
            break
        ca, cb = next_a, next_b
        frames.append(_Frame(len(frames) + 1, number, offset + 24, database_pages))
        if database_pages:
            commit_count += 1
            commits.append({"commit_index": commit_count, "frame": len(frames),
                            "pages": database_pages})
            if len(commits) > limits.max_commits:
                commits.pop(0)
                report["commit_selection_limited"] = True
        offset += 24 + page
    report.update(valid_frames=len(frames), committed_transactions=commit_count,
                  validated_prefix_bytes=offset, latest_commit_frame=commits[-1]["frame"] if commits else None,
                  uncommitted_frames=len(frames) - (commits[-1]["frame"] if commits else 0))
    return frames, commits


def _quick_check(path, limits, cancel):
    calls = 0
    interrupted = False
    def progress():
        nonlocal calls, interrupted
        calls += 1000
        if calls > limits.max_sqlite_ops or cancel is not None and cancel():
            interrupted = True
            return 1
        return 0
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
            connection.enable_load_extension(False)
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.set_progress_handler(progress, 1000)
            result = connection.execute("PRAGMA quick_check(1)").fetchall()
            return result == [("ok",)]
    except sqlite3.DatabaseError:
        if interrupted:
            _cancelled(cancel)
            raise HistoryError("SQLITE_CHECK_LIMIT")
        return False


def iter_committed_snapshots(db_path, wal_path, working_dir, *, limits=None,
                             cancel=None, report=None, base_policy="wal_only",
                             include_latest=False):
    """Yield bounded prior committed snapshots as metadata dictionaries.

    A supplied ``report`` dict records validation, skips, bounds and tail reason.
    No-last-commit default is deliberate: the latest known commit is not itself
    evidence of an earlier version. Cancel callback may return True or raise.
    Completed scratch files belong to the caller. Interrupted partials are
    removed; original DB/WAL bytes are never opened writable or checkpointed.
    """
    if report is None:
        report = {}
    report.clear()
    report.update(status="validating", base_policy=base_policy, snapshots=0,
                  skipped=[], tail_reason=None, commit_selection_limited=False)
    partial = None
    try:
        limits = _limits(limits)
        report["limits"] = asdict(limits)
        if base_policy not in ("wal_only", "unchanged_pages"):
            raise HistoryError("BASE_POLICY_UNSUPPORTED")
        _cancelled(cancel)
        db = _safe_path(db_path, regular=True)
        wal = _safe_path(wal_path, regular=True)
        output = _safe_path(working_dir, directory=True)
        if os.path.samefile(db, wal):
            raise HistoryError("INPUT_ALIAS")
        db_state, wal_state = _state(db), _state(wal)
        if db_state[2] > limits.max_input_bytes or wal_state[2] > limits.max_input_bytes:
            raise HistoryError("INPUT_LIMIT")
        with db.open("rb") as main, wal.open("rb") as log:
            page = _db_header(main.read(100), db_state[2])
            db_sha, wal_sha = _sha256(db, cancel), _sha256(wal, cancel)
            report.update(db_sha256=db_sha, wal_sha256=wal_sha)
            frames, commits = _parse_wal(log, wal_state[2], page, limits, cancel, report)
            if _state(db) != db_state or _state(wal) != wal_state:
                raise HistoryError("SOURCE_CHANGED")
            if not commits:
                report["status"] = "no_committed_transactions"
                return
            if base_policy == "unchanged_pages" and report["tail_reason"]:
                raise HistoryError("BASE_PROOF_INVALID_TAIL")
            last = commits[-1]["frame"]
            selected = [commit for commit in commits if include_latest or commit["frame"] < last]
            if len(selected) > limits.max_snapshots:
                selected = selected[-limits.max_snapshots:]
                report["snapshot_selection_limited"] = True
            # Only pages from committed frames can have been checkpointed to
            # the base. Uncommitted spills cannot establish historical rows.
            ever_committed = {frame.page for frame in frames[:last]}
            job = output / ("wal-history-" + uuid.uuid4().hex[:12])
            job.mkdir(exist_ok=False)
            overlay, next_frame, total_output = {}, 0, 0
            for commit in selected:
                _cancelled(cancel)
                while next_frame < commit["frame"]:
                    frame = frames[next_frame]
                    overlay[frame.page] = frame
                    # A committed truncate invalidates preimages beyond EOF.
                    # They must never reappear in a subsequent database growth.
                    if frame.commit_pages:
                        overlay = {number: value for number, value in overlay.items() if number <= frame.commit_pages}
                    next_frame += 1
                pages, missing = commit["pages"], []
                for number in range(1, pages + 1):
                    if number & 127 == 0:
                        _cancelled(cancel)
                    if number in overlay:
                        continue
                    if base_policy == "unchanged_pages" and number not in ever_committed and number * page <= db_state[2]:
                        continue
                    missing.append(number)
                    if len(missing) >= 8:
                        break
                if missing:
                    report["skipped"].append({"commit_frame": commit["frame"],
                                               "reason": "historical_page_preimage_missing",
                                               "example_pages": missing})
                    continue
                amount = pages * page
                if amount > limits.max_output_bytes - total_output:
                    report["skipped"].append({"commit_frame": commit["frame"], "reason": "output_limit"})
                    report["output_limited"] = True
                    break
                total_output += amount  # attempted writes also consume budget
                target = job / ("commit-" + str(commit["frame"]) + ".sqlite")
                partial = target.with_suffix(".partial")
                with partial.open("xb") as sink:
                    for number in range(1, pages + 1):
                        _cancelled(cancel)
                        if number in overlay:
                            log.seek(overlay[number].data_offset)
                            data = log.read(page)
                        else:
                            main.seek((number - 1) * page)
                            data = main.read(page)
                        if len(data) != page:
                            raise HistoryError("SOURCE_CHANGED")
                        if number == 1:
                            if _db_header(data[:100], amount, snapshot_pages=pages) != page:
                                raise HistoryError("SNAPSHOT_PAGE_SIZE_MISMATCH")
                        sink.write(data)
                    sink.flush()
                    os.fsync(sink.fileno())
                if not _quick_check(partial, limits, cancel):
                    partial.unlink()
                    partial = None
                    report["skipped"].append({"commit_frame": commit["frame"], "reason": "snapshot_integrity_invalid"})
                    continue
                if _state(db) != db_state or _state(wal) != wal_state:
                    raise HistoryError("SOURCE_CHANGED")
                _cancelled(cancel)
                digest = _sha256(partial, cancel)
                partial.rename(target)
                partial = None
                report["snapshots"] += 1
                report["output_bytes"] = total_output
                yield {"path": str(target), "snapshot_id": "wal:" + wal_sha + ":commit:" + str(commit["frame"]),
                       "commit_index": commit["commit_index"], "commit_frame": commit["frame"],
                       "database_pages": pages, "page_size": page, "base_policy": base_policy,
                       "proof": "all_pages_from_validated_wal" if base_policy == "wal_only" else "unchanged_base_pages_from_consistent_pair",
                       "db_sha256": db_sha, "wal_sha256": wal_sha, "sha256": digest,
                       "is_latest_known_commit": commit["frame"] == last,
                       "checkpoint_sequence": report["checkpoint_sequence"], "salts": list(report["salts"])}
            if _state(db) != db_state or _state(wal) != wal_state or _sha256(db, cancel) != db_sha or _sha256(wal, cancel) != wal_sha:
                raise HistoryError("SOURCE_CHANGED")
            report["status"] = "complete_valid_prefix" if report["tail_reason"] else "complete"
    except HistoryError as exc:
        report.update(status="cancelled" if exc.code == "CANCELLED" else "error", code=exc.code)
        raise
    except OSError as exc:
        report.update(status="error", code="HISTORY_IO_ERROR")
        raise HistoryError("HISTORY_IO_ERROR") from exc
    finally:
        if partial is not None:
            partial.unlink(missing_ok=True)
