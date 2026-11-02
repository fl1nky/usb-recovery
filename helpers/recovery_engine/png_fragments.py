"""Bounded one-splice IDAT candidates, retaining original CRC and source bytes.

PNG3 sections5.3/10.2/11.2.3 define logical chunks, not disk allocation units.
Only a surviving eight-byte IDAT header and original trailing CRC are used;
nothing is recompressed, synthesized or repaired. The caller still validates
the entire PNG zlib stream, scanline filters, chunk context and image decode.

CRC concatenation is an independent GF(2) implementation of the documented
zlib checksum operation (https://zlib.net/manual.html#Checksum).
"""
from __future__ import annotations

import re
import struct
import time
import zlib

SECTOR = 512
MAX_SPLIT_CHUNK = 2 * 1024 * 1024
MAX_ANCHORS = 4096
MAX_POOL_BYTES = 64 * 1024 * 1024
MAX_CRC_BYTES = 128 * 1024 * 1024
MAX_TAIL_WINDOW = 65536
MAX_TAIL_HEADERS = 4096
TYPE_TOKEN = re.compile(rb"(?=([A-Za-z]{4}))")


class GapSearchIncomplete(Exception):
    """No result can establish uniqueness after a local search bound."""


def _times(matrix, value):
    result, bit = 0, 0
    while value:
        if value & 1:
            result ^= matrix[bit]
        value >>= 1
        bit += 1
    return result


def _squared(matrix):
    return tuple(_times(matrix, value) for value in matrix)


def _byte_operators():
    # Reflected IEEE CRC32: each basis vector is shifted one bit, with the
    # generator polynomial applied only to the lost low bit. Three squares
    # produce a one-byte linear operator, then powers of two bytes.
    matrix = (0xEDB88320, *(1 << bit for bit in range(31)))
    for _ in range(3):
        matrix = _squared(matrix)
    result = []
    for _ in range((MAX_SPLIT_CHUNK + 12).bit_length()):
        result.append(matrix)
        matrix = _squared(matrix)
    return tuple(result)


_BYTE_OPERATORS = _byte_operators()


def crc32_combine(left, right, right_bytes):
    """CRC(A+B) from CRC(A), CRC(B), len(B), for bounded internal buffers."""
    if type(right_bytes) is not int or not 0 <= right_bytes <= MAX_SPLIT_CHUNK + 12:
        raise ValueError("PNG_CRC_LENGTH_INVALID")
    if not right_bytes:
        return left & 0xFFFFFFFF
    bit = 0
    while right_bytes:
        if right_bytes & 1:
            left = _times(_BYTE_OPERATORS[bit], left)
        right_bytes >>= 1
        bit += 1
    return (left ^ right) & 0xFFFFFFFF


class _Budget:
    def __init__(self, assembler):
        self.assembler = assembler
        self.attempts = self.pairs = self.crc_bytes = 0
        self.last_progress = time.monotonic()

    def poll(self):
        self.assembler.read(0, 0)  # Existing120-second/global read budget.
        now = time.monotonic()
        if now - self.last_progress >= 0.25:
            self.assembler.progress(self.assembler.size, self.assembler.size)
            self.last_progress = now

    def pair(self):
        self.poll()
        self.pairs += 1
        if self.pairs > self.assembler.max_states * 32:
            raise GapSearchIncomplete("png_gap_anchor_pairs_incomplete")

    def attempt(self):
        self.poll()
        self.attempts += 1
        if self.attempts > self.assembler.max_states * 8:
            raise GapSearchIncomplete("png_gap_attempts_incomplete")

    def crc(self, data, initial=0):
        self.poll()
        self.crc_bytes += len(data)
        if self.crc_bytes > MAX_CRC_BYTES:
            raise GapSearchIncomplete("png_gap_crc_work_incomplete")
        return zlib.crc32(data, initial)


def _anchors(assembler, budget):
    """Physical starts of a checked next IDAT/IEND or contiguous tail chain."""
    anchors = set(assembler.iend)
    for at in assembler.idat:
        budget.poll()
        chunk = assembler.chunk(at)
        if chunk and chunk[0] == b"IDAT":
            anchors.add(at)
        if len(anchors) > MAX_ANCHORS:
            raise GapSearchIncomplete("png_gap_anchors_incomplete")
    for ending in assembler.iend:
        base = max(0, ending - MAX_TAIL_WINDOW)
        window = assembler.read(base, ending-base)
        # Collect possible preceding ancillary headers once. Only chains that
        # physically reach this checked IEND become anchors. Logical/context
        # rules are left to the existing PNG walker, never guessed here.
        incoming = {}
        headers = 0
        for match in TYPE_TOKEN.finditer(window):
            budget.poll()
            local = match.start(1) - 4
            kind = match.group(1)
            if local < 0 or not kind[0] & 32 or kind[2] & 32:
                continue
            length = struct.unpack_from(">I", window, local)[0]
            end = local + length + 12
            if end > len(window):
                continue
            headers += 1
            if headers > MAX_TAIL_HEADERS:
                raise GapSearchIncomplete("png_gap_tail_headers_incomplete")
            incoming.setdefault(base+end, []).append((base+local, local, end))
        pending, seen = [(ending, 0)], set()
        while pending:
            end, depth = pending.pop()
            if end in seen:
                continue
            seen.add(end)
            for at, local, stop in incoming.get(end, ()):
                raw = memoryview(window)[local:stop]
                if budget.crc(raw[4:-4]) != struct.unpack_from(">I", raw, len(raw)-4)[0]:
                    continue
                if depth >= 128:
                    raise GapSearchIncomplete("png_gap_tail_chain_incomplete")
                anchors.add(at)
                if len(anchors) > MAX_ANCHORS:
                    raise GapSearchIncomplete("png_gap_anchors_incomplete")
                pending.append((at, depth+1))
    return sorted(anchors)


def _prefix_crcs(prefix, cuts, data_end, budget):
    result, prior, checksum = {}, 4, 0
    for cut in cuts:
        end = min(cut, data_end)
        checksum = budget.crc(memoryview(prefix)[prior:end], checksum)
        result[cut] = checksum
        prior = end
    return result


def _suffix_crcs(window, base, anchor, total, cuts, budget):
    # Cuts are nested suffix windows. Walk right-to-left once in source bytes;
    # checksum concatenation avoids rescanning the entire IDAT for every cut.
    result, prior, checksum, count = {}, anchor-4, 0, 0
    for cut in reversed(cuts):
        start = anchor - (total-cut)
        if start > anchor-4:  # The physical cut is within the four-byte CRC.
            result[cut] = (0, 0)
            continue
        raw = memoryview(window)[start-base:prior-base]
        checksum = crc32_combine(budget.crc(raw), checksum, count)
        count += len(raw)
        prior = start
        result[cut] = (checksum, count)
    return result


def idat_candidates(assembler):
    """Return (head, logical raw, physical parts, physical end, spliced).

    Every absolute512-byte cut is examined in a declared IDAT <=2MiB.
    Bounds stop the entire fallback as incomplete; no early successful cut
    can hide an unvisited content alternative. At most one returned spliced
    chunk may be selected in a PNG path by the caller.
    """
    budget = _Budget(assembler)
    anchors = _anchors(assembler, budget)
    result, pool = [], 0
    for at in assembler.idat:
        header = assembler.read(at, 8)
        if len(header) != 8 or header[4:8] != b"IDAT":
            continue
        length = struct.unpack_from(">I", header)[0]
        if not 0 < length <= MAX_SPLIT_CHUNK:
            continue
        total = length + 12
        prefix = assembler.read(at, min(total-1, assembler.size-at))
        first = ((at + 8 + SECTOR-1)//SECTOR)*SECTOR-at
        cuts = list(range(first, len(prefix)+1, SECTOR))
        if not cuts:
            continue
        prefix_crc = _prefix_crcs(prefix, cuts, total-4, budget)
        for anchor in anchors:
            budget.pair()
            # All cuts share one phase. Most foreign anchors are rejected
            # without reading their potential suffix window at all.
            if (anchor-total+cuts[0]) % SECTOR:
                continue
            valid = [cut for cut in cuts if 0 <= anchor-(total-cut) < anchor and
                     (at+cut <= anchor-(total-cut) or anchor <= at) and
                     anchor-(total-cut) != at+cut]
            if not valid:
                continue
            base = anchor-(total-valid[0])
            window = assembler.read(base, anchor-base)
            if len(window) != anchor-base:
                continue
            suffix_crcs = _suffix_crcs(window, base, anchor, total, valid, budget)
            for cut in valid:
                budget.attempt()
                tail = anchor-(total-cut)
                suffix_crc, amount = suffix_crcs[cut]
                actual = crc32_combine(prefix_crc[cut], suffix_crc, amount)
                if cut <= total-4:
                    stored = struct.unpack_from(">I", window, len(window)-4)[0]
                else:
                    stored = int.from_bytes(prefix[total-4:cut] + window[tail-base:], "big")
                if actual != stored:
                    continue
                raw = prefix[:cut] + window[tail-base:]
                if len(raw) != total or budget.crc(memoryview(raw)[4:-4]) != stored:
                    continue
                pool += len(raw)
                if len(result) >= 128 or pool > MAX_POOL_BYTES:
                    raise GapSearchIncomplete("png_gap_candidate_pool_incomplete")
                # Physical views share the checked immutable logical buffer;
                # no second full copy is retained for each source mapping.
                view = memoryview(raw)
                parts = [(at, view[:cut]), (tail, view[cut:])]
                result.append((at, raw, parts, anchor, True))
    return result
