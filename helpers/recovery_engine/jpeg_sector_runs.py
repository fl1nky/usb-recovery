"""Reassemble baseline JPEGs from sector runs separated by uniformly filled sectors."""

from functools import lru_cache
from heapq import nsmallest
import re

SECTOR = 512
WINDOW_BYTES = 64 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_RUNS = 96
# Match every FF run once, including stuffing (00) and an unfinished run at EOF.
# The trailing FFs are carried to the next physical fragment.
MARKER = re.compile(rb"\xff+([\x00-\xfe]|\Z)")
MAX_JOIN_BYTES = 32 * 1024 * 1024
MAX_ENTROPY_BYTES = 8 * 1024 * 1024


def _ranges(assembler, low, high):
    """Yield physical extents without retaining their payloads."""
    start = None
    for base in range(low, high, 65536):
        count = min(65536, high - base)
        page = assembler.read(base, count)
        if len(page) != count:
            raise OSError("JPEG_SOURCE_TRUNCATED")
        if len(page) % SECTOR == 0 and page.count(page[:1]) == len(page):
            if start is not None:
                yield start, base
                start = None
            continue
        for index in range(0, len(page), SECTOR):
            sector = page[index:index + SECTOR]
            if len(sector) == SECTOR and sector.count(sector[:1]) == SECTOR:
                if start is not None:
                    yield start, base + index
                    start = None
            elif start is None:
                start = base + index
    if start is not None:
        yield start, high


def sector_runs(assembler, anchor, scan_start=None):
    """Search a bounded neighbourhood on the sector grid of this JPEG header."""
    phase = anchor % SECTOR
    low = max(phase, min(anchor - WINDOW_BYTES // 2, assembler.size - WINDOW_BYTES))
    # Round toward the anchor so the final partial sector stays inside an end-clamped window.
    low += (phase - low) % SECTOR
    high = min(assembler.size, low + WINDOW_BYTES)

    def eligible():
        for start, end in _ranges(assembler, low, high):
            if start <= anchor < end:
                start = anchor
            if end - start > MAX_CONTENT:
                # An EOI can precede unrelated allocated data in the very same
                # sector. Only the bounded entropy prefix can belong to a photo.
                if start == anchor and scan_start is None:
                    continue
                prefix = assembler.read(start, MAX_CONTENT)
                if len(prefix) != MAX_CONTENT:
                    raise OSError("JPEG_SOURCE_TRUNCATED")
                footer = prefix.find(b"\xff\xd9", scan_start - start if start == anchor else 0)
                if footer >= 0:
                    end = start + footer + 2
                elif start != anchor and prefix[0] == 0xd9:
                    end = start + 1  # only a preceding FF can establish an EOI
                else:
                    continue
            yield start, end

    # A large unrelated extent cannot be part of a solution under this model.
    # Budget only the selected extents, so such an extent cannot erase prior hits.
    nearest = nsmallest(MAX_RUNS, eligible(), key=lambda span: abs(span[0] - anchor))
    runs = []
    remaining = MAX_CONTENT
    for start, end in nearest:
        length = end - start
        if length <= remaining:
            data = assembler.read(start, length)
            if len(data) != length:
                raise OSError("JPEG_SOURCE_TRUNCATED")
            runs.append((start, data))
            remaining -= length
    return tuple(runs)


def recover(assembler, frame, runs):
    """Return structural candidates only, within the sparse-sector hypothesis."""
    from jpeg_fragments import InvalidJpeg, entropy
    start, header = frame["prefix"]
    by_offset = dict(runs)
    if start not in by_offset or frame["scan"] > start + len(by_offset[start]):
        return []
    blocks, total, interval = frame["blocks"], frame["mcus"], frame["interval"]
    # An interior run need not contain a marker. A marker, a stuffed byte and
    # even the terminating EOI can straddle any physical join.
    solutions = {}
    attempts = joined_bytes = checked_bytes = 0
    exhausted = False

    @lru_cache(maxsize=64)
    def valid(raw, count):
        nonlocal checked_bytes, exhausted
        checked_bytes += len(raw)
        if checked_bytes > MAX_ENTROPY_BYTES:
            exhausted = True
            return False
        try:
            entropy(raw, blocks, count)
            return True
        except InvalidJpeg:
            return False

    def extend(at, path, carry, done):
        nonlocal attempts, joined_bytes, exhausted
        skip = len(header) if at == start else 0
        size = len(carry) + len(by_offset[at]) - skip
        if attempts >= assembler.max_states or joined_bytes + size > MAX_JOIN_BYTES:
            exhausted = True
            return
        if attempts % 64 == 0:
            assembler.read(0, 0)
            assembler.progress(assembler.size, assembler.size)
        attempts += 1
        joined_bytes += size
        scan = carry + by_offset[at][skip:]
        previous = 0
        for match in MARKER.finditer(scan):
            code = match[1]
            if not code or code == b"\0":
                continue
            count = min(interval or total, total - done)
            final = done + count == total
            expected = 0xd9 if final else 0xd0 + (done // interval) % 8
            if code[0] != expected or not valid(scan[previous:match.start()], count):
                return
            done += count
            previous = match.end()
            if final:
                if path:
                    # Only the part of this run up to and including the true EOI.
                    end = skip + previous - len(carry)
                    recipe = [(pos, by_offset[pos]) for pos in path] + [(at, by_offset[at][:end])]
                    payload = b"".join(raw for _, raw in recipe)
                    if payload not in solutions and assembler.decode(payload, "JPEG"):
                        solutions[payload] = recipe
                return
        carry = scan[previous:]
        path += (at,)
        for pos in by_offset:
            if exhausted or len(solutions) == 2:
                break
            if pos not in path:
                extend(pos, path, carry, done)

    extend(start, (), b"", 0)
    if exhausted:
        assembler.skipped["jpeg_sparse_search_incomplete"] += 1
        return []
    return list(solutions.values())
