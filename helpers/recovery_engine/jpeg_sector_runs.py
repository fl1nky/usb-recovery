"""Reassemble baseline JPEGs from sector runs separated by uniformly filled sectors."""

from functools import lru_cache
from heapq import nsmallest
import re

SECTOR = 512
WINDOW_BYTES = 64 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_RUNS = 96
# FF00 is a stuffed data byte. Other marker segments cannot occur inside this scan.
MARKER = re.compile(b"\\xff+(?!\\xff)([\\x01-\\xfe])")


def _ranges(assembler, low, high):
    """Yield physical extents without retaining their payloads."""
    start = None
    for base in range(low, high, 65536):
        page = assembler.read(base, min(65536, high - base))
        if not page:
            return
        if page.count(page[:1]) == len(page):
            if start is not None:
                yield start, base
                start = None
            continue
        for index in range(0, len(page), SECTOR):
            sector = page[index:index + SECTOR]
            if sector.count(sector[:1]) == len(sector):
                if start is not None:
                    yield start, base + index
                    start = None
            elif start is None:
                start = base + index
    if start is not None:
        yield start, high


def sector_runs(assembler, anchor):
    """Search a bounded neighbourhood on the sector grid of this JPEG header."""
    phase = anchor % SECTOR
    low = max(phase, min(anchor - WINDOW_BYTES // 2, assembler.size - WINDOW_BYTES))
    low -= (low - phase) % SECTOR
    high = min(assembler.size, low + WINDOW_BYTES)

    def eligible():
        for start, end in _ranges(assembler, low, high):
            if start <= anchor < end:
                start = anchor
            if end - start <= MAX_CONTENT:
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
            if len(data) == length:
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
    # A restart interval is independently checkable; arbitrary streams without
    # such anchors need a much smaller permutation bound.
    if not interval and len(runs) > 6:
        return []
    pieces = {}
    for at, data in runs:
        scan = data[len(header):] if at == start else data
        markers = list(MARKER.finditer(scan))
        end = next((m.end() for m in markers if m[1] == b"\xd9"), len(scan))
        markers = [m for m in markers if m.start() < end]
        if any(not 0xd0 <= m[1][0] <= 0xd7 and m[1][0] != 0xd9 for m in markers):
            continue
        if interval and not markers:
            continue
        pieces[at] = (scan[:end], markers)
    if start not in pieces:
        return []
    checked_bytes = 0
    exhausted = False

    @lru_cache(maxsize=64)
    def valid(raw, count):
        nonlocal checked_bytes, exhausted
        checked_bytes += len(raw)
        if checked_bytes > 8 * 1024 * 1024:
            exhausted = True
            return False
        try:
            entropy(raw, blocks, count)
            return True
        except InvalidJpeg:
            return False

    solutions = {}
    attempts = 0
    limit = assembler.max_states
    def extend(at, path, carry, done):
        nonlocal attempts
        attempts += 1
        if attempts > limit:
            return
        scan, markers = pieces[at]
        previous = 0
        for marker in markers:
            count = min(interval or total, total - done)
            final = done + count == total
            expected = 0xd9 if final else 0xd0 + (done // interval) % 8
            if marker[1][0] != expected or not valid(carry + scan[previous:marker.start()], count):
                return
            carry = b""
            done += count
            previous = marker.end()
            if final:
                if path:
                    offsets = path + (at,)
                    recipe = [(pos, by_offset[pos] if pos != at else by_offset[pos][:previous])
                              for pos in offsets]
                    payload = b"".join(raw for _, raw in recipe)
                    if assembler.decode(payload, "JPEG"):
                        solutions.setdefault(payload, recipe)
                return
        carry += scan[previous:]
        path += (at,)
        if len(path) < len(pieces):
            for pos in pieces:
                if exhausted or attempts >= limit or len(solutions) >= 2:
                    break
                if pos not in path:
                    extend(pos, path, carry, done)
    extend(start, (), b"", 0)
    if exhausted or attempts >= limit or len(solutions) > 1:
        return []
    return list(solutions.values())
