# SPDX-License-Identifier: AGPL-3.0-or-later
"""Materialize immutable EWF media or a ddrescue-filtered regular image.

All recovery engines receive the same logical RAW bytes. Container offsets
never masquerade as physical source extents. Checkpoints publish no results.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import time
import uuid
import zlib

from recovery_io import (RecoveryIOError as ImageError, plain, digest, writable, atomic_bytes, atomic, writer_lock, read_json, read_only as _read_only)

CHUNK = 1024 * 1024
CHECKPOINT = 8 * CHUNK
MAX_BYTES = 16 * 1024**4
SIGNATURES = (b"EVF\x09\r\n\xff\0", b"EVF2\r\n\x81\0")
VERSION = 1














def validate_sections(stream, signature):
    """Fail closed on damaged descriptors and recorded acquisition errors."""
    stream.seek(0, 2)
    size = stream.tell()
    offset, seen = (13 if signature == SIGNATURES[0] else size - 64), set()
    while True:
        if offset in seen or len(seen) >= 1000000 or offset < (13 if signature == SIGNATURES[0] else 32):
            raise ImageError("INVALID_SOURCE")
        seen.add(offset)
        stream.seek(offset)
        if signature == SIGNATURES[0]:
            raw = stream.read(76)
            if len(raw) != 76 or zlib.adler32(raw[:72]) & 0xffffffff != struct.unpack_from("<I", raw, 72)[0]:
                raise ImageError("SOURCE_CHECKSUM_FAILED")
            kind, next_offset, length = struct.unpack_from("<16sQQ", raw)
            kind = kind.rstrip(b"\0")
            if kind == b"error2" and struct.unpack("<I", stream.read(4))[0]:
                raise ImageError("SOURCE_HAS_RECORDED_ERRORS")
            if kind in (b"done", b"next"):
                break
            if next_offset <= offset or next_offset > size - 76 or length < 76 or length > size - offset:
                raise ImageError("INVALID_SOURCE")
            offset = next_offset
        else:
            raw = stream.read(64)
            if len(raw) != 64 or zlib.adler32(raw[:60]) & 0xffffffff != struct.unpack_from("<I", raw, 60)[0]:
                raise ImageError("SOURCE_CHECKSUM_FAILED")
            kind, flags, previous, length, descriptor_size, padding = struct.unpack_from("<IIQQII", raw)
            if descriptor_size != 64 or flags & 1 or padding > length or length > offset - 32:
                raise ImageError("UNSUPPORTED_FORMAT")
            stream.seek(offset - length)
            if kind == 5 and struct.unpack("<Q", stream.read(8))[0]:
                raise ImageError("SOURCE_HAS_RECORDED_ERRORS")
            if flags & 2:
                stream.seek(offset - length)
                remaining, md5 = length, hashlib.md5()
                while remaining:
                    block = stream.read(min(remaining, CHUNK))
                    if not block:
                        raise ImageError("INVALID_SOURCE")
                    md5.update(block)
                    remaining -= len(block)
                if md5.digest() != raw[32:48]:
                    raise ImageError("SOURCE_CHECKSUM_FAILED")
            if previous == 0:
                break
            if previous >= offset - length:
                raise ImageError("INVALID_SOURCE")
            offset = previous






def map_ranges(path, size):
    if path is None:
        return [(0, size)], []
    if path.stat().st_size > 32 * CHUNK:
        raise ImageError("INVALID_READ_MAP")
    rows, prior, header = [], 0, False
    try:
        with path.open("r", encoding="utf-8-sig") as source:
            for text in source:
                parts = text.split("#", 1)[0].split()
                if not parts:
                    continue
                if not rows and not header and len(parts) in (2, 3) and parts[1] in ("?", "*", "/", "-", "+", "F", "G"):
                    if int(parts[0], 0) < 0 or len(parts) == 3 and int(parts[2], 0) < 0:
                        raise ValueError()
                    header = True
                    continue
                if len(parts) != 3 or parts[2] not in ("?", "*", "/", "-", "+"):
                    raise ValueError()
                start, length = (int(p, 16) if p.lower().startswith("0x") else int(p, 10) for p in parts[:2])
                if start < prior or length <= 0 or start > size - length or len(rows) >= 16000:
                    raise ValueError()
                rows.append((start, start + length, parts[2]))
                prior = start + length
    except (ValueError, UnicodeError):
        raise ImageError("INVALID_READ_MAP") from None
    if not rows:
        raise ImageError("INVALID_READ_MAP")
    good = [(a, b) for a, b, status in rows if status == "+"]
    missing, cursor = [], 0
    for a, b in good:
        if a > cursor:
            missing.append({"Offset": cursor, "Length": a - cursor})
        cursor = b
    if cursor < size:
        missing.append({"Offset": cursor, "Length": size - cursor})
    return good, missing


def missing_ranges(good, size):
    missing, cursor = [], 0
    for start, end in good:
        if start > cursor:
            missing.append({"Offset": cursor, "Length": start-cursor})
        cursor = end
    if cursor < size:
        missing.append({"Offset": cursor, "Length": size-cursor})
    return missing


def inherit_errors(source, identities, size, ewf, good, guards):
    """Keep known acquisition holes when deriving another logical image."""
    sidecar = Path(str(source) + ".read-errors.json")
    if not sidecar.exists():
        capture = source.parent/'capture.json'
        if capture.exists():
            data = read_json(capture)
            if (isinstance(data,dict) and data.get('sha256')==identities[0]['sha256'] and data.get('size')==identities[0]['bytes'] and data.get('unreadBytes',0)):
                raise ImageError('SOURCE_HAS_RECORDED_ERRORS')
        return good, None
    sidecar=plain(str(sidecar),True)
    handle=guards.enter_context(_read_only(sidecar))
    identity={"path":str(sidecar),"bytes":os.fstat(handle.fileno()).st_size,"sha256":digest(handle)}
    data=read_json(sidecar)
    if ewf or not isinstance(data,dict) or data.get('sha256')!=identities[0]['sha256'] or data.get('size')!=size or data.get('copied')!=size or not isinstance(data.get('ranges'),list) or len(data['ranges'])>16000:
        raise ImageError('INVALID_READ_MAP')
    holes,prior=[],0
    for row in data['ranges']:
        a,n=row.get('Offset'),row.get('Length')
        if type(a) is not int or type(n) is not int or a<prior or n<=0 or a>size-n:raise ImageError('INVALID_READ_MAP')
        holes.append((a,a+n));prior=a+n
    unread=sum(b-a for a,b in holes)
    if data.get('unreadBytes')!=unread or data.get('status')!=('complete_with_read_errors' if unread else 'complete'):
        raise ImageError('INVALID_READ_MAP')
    combined, index = [], 0
    for a,b in good:
        cursor=a
        while index<len(holes) and holes[index][1]<=a:index+=1
        scan=index
        while scan<len(holes) and holes[scan][0]<b:
            left,right=holes[scan]
            if cursor<left:combined.append((cursor,min(left,b)))
            cursor=max(cursor,right);scan+=1
        if cursor<b:combined.append((cursor,b))
    return combined, identity


def filtered(stream, offset, count, good):
    # Only rescued intervals are read from the source. Unknown ranges remain
    # explicit zero-filled gaps and propagate to the ordinary evidence map.
    import bisect
    output = bytearray(count)
    index = max(0, bisect.bisect_right(good, (offset, 2**63)) - 1)
    while index < len(good):
        a, b = good[index]
        index += 1
        if a >= offset + count:
            break
        left, right = max(offset, a), min(offset + count, b)
        if left < right:
            stream.seek(left)
            block = stream.read(right - left)
            if len(block) != right - left:
                raise ImageError("INVALID_SOURCE")
            output[left - offset:right - offset] = block
    return bytes(output)


def prepare(request, emit):
    source = plain(request.get("source"), True)
    if str(source).lower().endswith(".partial"):
        raise ImageError("INVALID_SOURCE")
    destination = plain(request.get("destination"))
    if source.is_relative_to(destination):
        raise ImageError("INVALID_REQUEST")
    options = request.get("options") or {}
    resume = options.get("resume") is True
    map_path = plain(options["read_map"], True) if options.get("read_map") else None
    if map_path and map_path.is_relative_to(destination):
        raise ImageError("INVALID_REQUEST")
    limit = options.get("max_output_bytes", MAX_BYTES)
    if type(limit) is not int or not 0 < limit <= MAX_BYTES:
        raise ImageError("INVALID_REQUEST")
    destination.mkdir(parents=True, exist_ok=True)
    with writer_lock(destination / "preparation.lock"), contextlib.ExitStack() as guards:
        first = guards.enter_context(_read_only(source))
        signature = first.read(8)
        import ewf_reader
        ewf = signature in SIGNATURES
        if options.get("require_ewf") and not ewf:
            raise ImageError("UNSUPPORTED_FORMAT")
        paths = ewf_reader.ewf_segments(str(source)) if ewf else [str(source)]
        if not paths or len(paths) > 1024:
            raise ImageError("INVALID_SOURCE")
        identities = []
        for index, value in enumerate(paths):
            path = plain(value, True)
            handle = first if path == source else guards.enter_context(_read_only(path))
            size = os.fstat(handle.fileno()).st_size
            identities.append({"path": str(path), "bytes": size, "sha256": digest(handle, emit)})
            if ewf:
                handle.seek(0)
                if handle.read(8) != signature:
                    raise ImageError("INVALID_SOURCE")
                validate_sections(handle, signature)
            emit("progress", phase="source_hash", completed=index + 1, total=len(paths))
        if map_path:
            map_guard = guards.enter_context(_read_only(map_path))
            map_identity = {"path": str(map_path), "bytes": os.fstat(map_guard.fileno()).st_size, "sha256": digest(map_guard)}
        else:
            map_identity = None
        reader = guards.enter_context(ewf_reader.EwfImage(str(source), segments=[i["path"] for i in identities])) if ewf else first
        size = reader.media_size if ewf else os.fstat(first.fileno()).st_size
        if type(size) is not int or not 0 < size <= limit:
            raise ImageError("INVALID_SOURCE")
        good, _ = map_ranges(map_path, size)
        good, inherited_map = inherit_errors(source, identities, size, ewf, good, guards)
        missing = missing_ranges(good,size)
        binding = {"schema": VERSION, "sources": identities, "read_map": map_identity, "logical_bytes": size,
                   "inherited_read_map": inherited_map,"format": "EWF" if ewf else "RAW", "reader_revision": "ewfprobe-4af1a54a223edbce12693b29fb3838b63a26b4f2"}
        if len(json.dumps(binding).encode())>CHUNK:raise ImageError('INVALID_SOURCE')
        image, partial = destination / "working.dd", destination / "working.dd.partial"
        state, report_path = destination / "preparation-checkpoint.json", destination / "source-preparation.json"
        for path in (image, partial, state, report_path):
            plain(str(path))
        if report_path.exists():
            report = read_json(report_path)
            if not resume or report.get("binding") != binding:
                raise ImageError("SOURCE_PREPARATION_CHANGED")
            if image.is_file():
                with _read_only(image) as verified:
                    if os.fstat(verified.fileno()).st_size != size or digest(verified) != report.get("sha256"):
                        raise ImageError("SOURCE_PREPARATION_CHANGED")
                for suffix in (".read-errors.json", ".sha256"):
                    if not image.with_name(image.name + suffix).is_file():
                        raise ImageError("SOURCE_PREPARATION_CHANGED")
                if read_json(image.with_name(image.name + ".read-errors.json")) != report.get("read_map") or image.with_name(image.name + ".sha256").read_text(encoding="ascii").strip() != report.get("sha256"):
                    raise ImageError("SOURCE_PREPARATION_CHANGED")
                return {"status": "partial" if missing else "complete", "code": "PARTIAL_DATA" if missing else "OK", "image": "working.dd", "bytes": size}
        done, current = 0, hashlib.sha256()
        if partial.exists() or state.exists():
            if not resume or not partial.is_file() or not state.is_file():
                raise ImageError("SOURCE_PREPARATION_EXISTS")
            checkpoint = read_json(state)
            done = checkpoint.get("completed")
            if checkpoint.get("binding") != binding or type(done) is not int or not 0 <= done <= size or partial.stat().st_size < done:
                raise ImageError("SOURCE_PREPARATION_CHANGED")
            with _read_only(partial) as prefix:
                cursor = 0
                while cursor < done:
                    count = min(CHUNK, done - cursor)
                    block = prefix.read(count)
                    if block != filtered(reader, cursor, count, good):
                        raise ImageError("SOURCE_PREPARATION_CHANGED")
                    current.update(block)
                    cursor += count
                    emit("progress", phase="verify_prefix", completed=cursor, total=done)
            if current.hexdigest() != checkpoint.get("prefix_sha256"):
                raise ImageError("SOURCE_PREPARATION_CHANGED")
        elif image.exists():
            raise ImageError("SOURCE_PREPARATION_EXISTS")
        if shutil.disk_usage(destination).free < size - done + 16 * CHUNK:
            raise ImageError("IO_ERROR")
        writable(partial)
        with partial.open("r+b" if partial.exists() else "xb") as output:
            output.truncate(done)
            output.seek(done)
            saved = done
            if not state.exists():
                atomic(state, {"binding": binding, "completed": done, "prefix_sha256": current.hexdigest()})
            while done < size:
                block = filtered(reader, done, min(CHUNK, size - done), good)
                output.write(block)
                current.update(block)
                done += len(block)
                if ewf and (reader.checksum_errors or reader.table_errors or reader.padded_chunks):
                    raise ImageError("SOURCE_CHECKSUM_FAILED")
                if done - saved >= CHECKPOINT or done == size:
                    output.flush()
                    os.fsync(output.fileno())
                    atomic(state, {"binding": binding, "completed": done, "prefix_sha256": current.hexdigest()})
                    saved = done
                emit("progress", phase="materialize", completed=done, total=size)
        # A masked stream cannot be compared to the container's original media
        # digest. Independently read the EWF itself for those digests instead.
        if ewf:
            last_progress = [0.0]
            def verify_progress(done, total):
                now = time.monotonic()
                if now-last_progress[0] >= .2 or done == total:
                    emit("progress", phase="verify_media", completed=done, total=total)
                    last_progress[0] = now
            verified = reader.verify(progress=verify_progress)
            if verified["match"] is False or verified["checksum_errors"] or verified["table_errors"] or verified["padded_chunks"]:
                raise ImageError("SOURCE_CHECKSUM_FAILED")
        sha256 = current.hexdigest()
        read_map = {"status": "complete_with_read_errors" if missing else "complete", "size": size, "copied": size,
                    "sha256": sha256, "unreadBytes": sum(r["Length"] for r in missing), "ranges": missing}
        report = {"binding": binding, "sha256": sha256, "bytes": size, "resumed_bytes": checkpoint["completed"] if resume and 'checkpoint' in locals() else 0,
                  "completeness": "rescued_ranges_only" if missing else "container_logical_bytes", "read_map": read_map,
                  "source_offsets": "Output maps address logical RAW bytes, not compressed container offsets"}
        atomic(image.with_name(image.name + ".read-errors.json"), read_map)
        atomic_bytes(image.with_name(image.name + ".sha256"), (sha256 + "\n").encode("ascii"))
        atomic(report_path, report)
        os.link(partial, image)
        partial.unlink()
        return {"status": "partial" if missing else "complete", "code": "PARTIAL_DATA" if missing else "OK", "image": "working.dd", "bytes": size}


def handle(request, emit):
    try:
        return prepare(request, emit)
    except ImageError as error:
        return {"status": "error", "code": str(error)}
    except Exception:
        return {"status": "error", "code": "INVALID_SOURCE"}
