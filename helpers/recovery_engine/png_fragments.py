"""Bounded IDAT splice candidates, retaining original CRC and source bytes.

PNG3 sections5.3/10.2/11.2.3 define logical chunks, not disk allocation units.
Only a surviving eight-byte IDAT header and original trailing CRC are used;
nothing is recompressed, synthesized or repaired. The caller still validates
the entire PNG zlib stream, scanline filters, chunk context and image decode.

CRC concatenation is an independent GF(2) implementation of the documented
zlib checksum operation (https://zlib.net/manual.html#Checksum).
"""
from __future__ import annotations

from array import array
import hashlib
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
MAX_MIDDLE_INDEX_BYTES = 128 * 1024 * 1024
MAX_JOIN_CELLS = 32 * 1024 * 1024
MAX_PREFIX_DECODE_BYTES = 256 * 1024 * 1024
MAX_PHYSICAL_CANDIDATES = 512
MAX_DISTINCT_CHUNKS = 128
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
        self.join_cells = 0
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

    def cells(self, count):
        self.poll()
        self.join_cells += count
        if self.join_cells > min(MAX_JOIN_CELLS, self.assembler.max_states * 8192):
            raise GapSearchIncomplete("png_two_gap_join_work_incomplete")


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


def _inverse_operator(columns):
    """Invert a32-bit CRC linear operator, retaining zlib's CRC convention."""
    rows = [sum(((column >> row) & 1) << bit for bit, column in enumerate(columns))
            | (1 << (32 + row)) for row in range(32)]
    for bit in range(32):
        pivot = next(row for row in range(bit, 32) if rows[row] & (1 << bit))
        rows[bit], rows[pivot] = rows[pivot], rows[bit]
        for row in range(32):
            if row != bit and rows[row] & (1 << bit):
                rows[row] ^= rows[bit]
    return tuple(sum(((rows[row] >> (32 + bit)) & 1) << row for row in range(32))
                 for bit in range(32))


_INVERSE_BYTE_OPERATORS = tuple(_inverse_operator(matrix) for matrix in _BYTE_OPERATORS)


def _unshift(value, count):
    if type(count) is not int or not 0 <= count <= MAX_SPLIT_CHUNK + 12:
        raise ValueError("PNG_CRC_LENGTH_INVALID")
    bit = 0
    while count:
        if count & 1:
            value = _times(_INVERSE_BYTE_OPERATORS[bit], value)
        count >>= 1
        bit += 1
    return value & 0xFFFFFFFF


def _lookup(table, value):
    return (table[value & 255] ^ table[256 + ((value >> 8) & 255)] ^
            table[512 + ((value >> 16) & 255)] ^ table[768 + ((value >> 24) & 255)])


def _table(columns):
    # Four256-entry uint32 tables bound a shift operation to four lookups.
    result = array("I", [0]) * 1024
    for part in range(4):
        at = part * 256
        for value in range(1, 256):
            low = value & -value
            result[at + value] = result[at + (value ^ low)] ^ columns[part * 8 + low.bit_length() - 1]
    return result


def _inverse_table(count):
    return _table(tuple(_unshift(1 << bit, count) for bit in range(32)))


def _cut_tables(cuts, budget):
    """At most4097 tables (16MiB+4KiB), one per declared sector cut."""
    if not cuts:
        return []
    columns = tuple(_unshift(1 << bit, cuts[0]) for bit in range(32))
    step = _inverse_table(SECTOR)
    result = []
    for _ in cuts:
        budget.poll()
        result.append(_table(columns))
        columns = tuple(_lookup(step, column) for column in columns)
    return result


class _SectorIndex:
    """Streaming CRC prefix states only; never retains the whole source image."""
    def __init__(self, assembler, budget):
        if assembler.size > MAX_MIDDLE_INDEX_BYTES:
            raise GapSearchIncomplete("png_two_gap_source_index_incomplete")
        self.assembler, self.budget = assembler, budget
        self.sectors = assembler.size // SECTOR
        self.crcs = array("I", [0])
        checksum = 0
        for at in range(0, self.sectors * SECTOR, 1024 * 1024):
            block = assembler.read(at, min(1024 * 1024, self.sectors * SECTOR - at))
            if len(block) % SECTOR:
                raise GapSearchIncomplete("png_two_gap_source_index_incomplete")
            view = memoryview(block)
            for local in range(0, len(block), SECTOR):
                checksum = budget.crc(view[local:local + SECTOR], checksum)
                self.crcs.append(checksum)
        if len(self.crcs) != self.sectors + 1:
            raise GapSearchIncomplete("png_two_gap_source_index_incomplete")


def _viable_prefixes(assembler, prefix, cuts, data_end, budget):
    # With multiple IDAT headers this chunk might follow another chunk's
    # DEFLATE state. Standalone inflation must not prune such continuations.
    if len(assembler.idat) != 1:
        return len(cuts) - 1
    decoder, prior, last = zlib.decompressobj(), 8, -1
    for index, cut in enumerate(cuts):
        budget.poll()
        end = min(cut, data_end)
        remaining = MAX_PREFIX_DECODE_BYTES - assembler.decoded
        if remaining < 0:
            raise GapSearchIncomplete("png_two_gap_prefix_decode_incomplete")
        try:
            block = decoder.decompress(memoryview(prefix)[prior:end], remaining + 1)
        except zlib.error:
            break  # No valid prefix extends past the first failing portion.
        assembler.decoded += len(block)
        if assembler.decoded > MAX_PREFIX_DECODE_BYTES or decoder.unconsumed_tail:
            raise GapSearchIncomplete("png_two_gap_prefix_decode_incomplete")
        if decoder.eof or decoder.unused_data:
            break  # At least512 more middle bytes cannot follow a complete zlib stream.
        last, prior = index, end
    return last


def _joined_candidate(assembler, budget, at, prefix, a, b, middle, anchor, total):
    tail = anchor - (total - b)
    ranges = ((at, a), (middle, b - a), (tail, total - b))
    ordered = sorted((start, start + length) for start, length in ranges)
    if (any(start < 0 or length <= 0 or start > assembler.size - length for start, length in ranges) or
            any(left[1] > right[0] for left, right in zip(ordered, ordered[1:]))):
        return None
    budget.attempt()
    mid, end = assembler.read(middle, b - a), assembler.read(tail, total - b)
    if len(mid) != b - a or len(end) != total - b:
        raise GapSearchIncomplete("png_two_gap_candidate_read_incomplete")
    raw = prefix[:a] + mid + end
    stored = struct.unpack_from(">I", raw, total - 4)[0]
    if budget.crc(memoryview(raw)[4:-4]) != stored:
        return None
    view = memoryview(raw)
    return at, raw, [(at, view[:a]), (middle, view[a:b]), (tail, view[b:])], anchor, True


def _three_run_candidates(assembler, budget, heads, anchors):
    """CRC hash join over displacements, never a three-dimensional Cartesian search.

    T is the complete IDAT chunk size. For cuts a<b and middle displacement
    d=m-a, let H(x)=CRC(source[:x]), P(a)=CRC(type+prefix), S(b)=CRC(suffix).
    Exact CRC equality is the hash join
      Unshift(H(d+a),a) xor Unshift(P(a),a)
       == Unshift(H(d+b),b) xor Unshift(storedCRC xor S(b),T-4).
    a/b have the same phase, d=k*512-firstCut, so H indices are k+i/k+j.
    Every original stored CRC is re-read and checked after the algebraic gate.
    The PNG walker still validates whole zlib/Adler, filters/context and decode.
    """
    source_index = None
    for at, total, prefix, cuts, prefix_crc in heads:
        data_end = total - 4
        if len(cuts) < 2:
            continue
        max_a = min(len(cuts) - 2, _viable_prefixes(assembler, prefix, cuts, data_end, budget))
        if max_a < 0:
            continue
        normal_end = min(len(cuts) - 1, (data_end - cuts[0]) // SECTOR)
        split = next((i for i, cut in enumerate(cuts) if data_end < cut < total), None)
        if normal_end < 1 and split is None:
            continue
        tables = _cut_tables(cuts, budget)
        prefix_keys = [_lookup(tables[i], prefix_crc[cuts[i]]) for i in range(max_a + 1)]
        inverse_total = _inverse_table(data_end)
        if source_index is None:
            source_index = _SectorIndex(assembler, budget)
        h, sectors, first = source_index.crcs, source_index.sectors, cuts[0]
        for anchor in anchors:
            budget.pair()
            if (anchor - total + first) % SECTOR:
                continue
            min_gap = max(1, (at + total - anchor + SECTOR - 1) // SECTOR) if anchor > at else 1
            low_b = max(1, (total - anchor - first + SECTOR - 1) // SECTOR)
            suffix_keys = {}
            if low_b <= normal_end:
                values = cuts[low_b:normal_end + 1]
                base = anchor - (total - values[0])
                window = assembler.read(base, anchor - base)
                if len(window) != anchor - base:
                    raise GapSearchIncomplete("png_two_gap_suffix_read_incomplete")
                suffixes = _suffix_crcs(window, base, anchor, total, values, budget)
                stored = struct.unpack_from(">I", window, len(window) - 4)[0]
                suffix_keys = {j: _lookup(inverse_total, stored ^ suffixes[cuts[j]][0])
                               for j in range(low_b, normal_end + 1)}
            for k in range(-max_a, sectors):
                budget.poll()
                d = k * SECTOR - first
                # Adjacent forward pieces are the already-enumerated two-run
                # model; subdividing them must not consume an alias budget.
                if d == at or d == anchor - total:
                    continue
                low_a, high_a = max(0, -k), min(max_a, sectors - k - 1)
                if d > anchor - total:
                    low_a = max(low_a, (anchor + SECTOR - 1) // SECTOR - k)
                high_b = min(normal_end, sectors - k)
                if d < at:
                    high_b = min(high_b, at // SECTOR - k)
                high_a = min(high_a, high_b - min_gap)
                start_b = max(low_b, low_a + min_gap)
                if low_a <= high_a and start_b <= high_b:
                    budget.cells(high_b - start_b + 1 + high_a - low_a + 1)
                    ends = {}
                    for j in range(start_b, high_b + 1):
                        if not j % 1024:
                            budget.poll()
                        key = _lookup(tables[j], h[k + j]) ^ suffix_keys[j]
                        ends.setdefault(key, []).append(j)
                    for i in range(low_a, high_a + 1):
                        if not i % 1024:
                            budget.poll()
                        key = _lookup(tables[i], h[k + i]) ^ prefix_keys[i]
                        for j in ends.get(key, ()):
                            if j - i < min_gap:
                                continue
                            candidate = _joined_candidate(assembler, budget, at, prefix, cuts[i], cuts[j],
                                                          (k + i) * SECTOR, anchor, total)
                            if candidate is not None:
                                yield candidate
                # The sole possible final cut within the four-byte CRC has
                # no suffix payload. Its high CRC bytes belong to the middle;
                # remove those actual bytes from H(end) to obtain H(data_end).
                if (split is None or anchor < total - cuts[split] or
                        not 0 <= k + split <= sectors):
                    continue
                a_low, a_high = max(0, -k), min(max_a, split - min_gap)
                if d > anchor - total:
                    a_low = max(a_low, (anchor + SECTOR - 1) // SECTOR - k)
                if d < at and (k + split) * SECTOR > at:
                    continue
                if a_low > a_high or k + split == 0:
                    continue
                budget.cells(a_high - a_low + 1)
                count = cuts[split] - data_end
                high = assembler.read((k + split) * SECTOR - count, count)
                low = assembler.read(anchor - (4 - count), 4 - count)
                if len(high) != count or len(low) != 4 - count:
                    raise GapSearchIncomplete("png_two_gap_crc_read_incomplete")
                before_crc = _unshift(h[k + split] ^ budget.crc(high), count)
                target = _lookup(inverse_total, int.from_bytes(high + low, "big") ^ before_crc)
                for i in range(a_low, a_high + 1):
                    if not i % 1024:
                        budget.poll()
                    if _lookup(tables[i], h[k + i]) ^ prefix_keys[i] != target:
                        continue
                    candidate = _joined_candidate(assembler, budget, at, prefix, cuts[i], cuts[split],
                                                  (k + i) * SECTOR, anchor, total)
                    if candidate is not None:
                        yield candidate


def idat_candidates(assembler):
    """Return (head, logical raw, physical parts, physical end, spliced).

    Every absolute512-byte cut is examined in a declared IDAT <=2MiB.
    Bounds stop the entire fallback as incomplete; no early successful cut
    can hide an unvisited content alternative. The union includes two-run and
    three-run chunks, with every bounded physical map retained even for equal
    bytes. At most one returned spliced chunk may be selected in a PNG path.
    """
    budget = _Budget(assembler)
    anchors = _anchors(assembler, budget)
    result, pool, heads, interned, physical, distinct = [], 0, [], {}, set(), 0
    def retain(candidate):
        nonlocal pool, distinct
        head, raw, parts, end, spliced = candidate
        mapping = tuple((offset, len(piece)) for offset, piece in parts)
        key = (head, end, mapping)
        if key in physical:
            return
        if len(result) >= MAX_PHYSICAL_CANDIDATES:
            raise GapSearchIncomplete("png_gap_candidate_pool_incomplete")
        checksum = hashlib.sha256(raw).digest()
        bucket = interned.setdefault(checksum, [])
        canonical = next((known for known in bucket if known == raw), None)
        if canonical is None:
            pool += len(raw)
            distinct += 1
            if distinct > MAX_DISTINCT_CHUNKS or pool > MAX_POOL_BYTES:
                raise GapSearchIncomplete("png_gap_candidate_pool_incomplete")
            canonical = raw
            bucket.append(raw)
        # Equality, not merely CRC or SHA, permits sharing immutable bytes.
        view, logical, physical_parts = memoryview(canonical), 0, []
        for offset, piece in parts:
            physical_parts.append((offset, view[logical:logical + len(piece)]))
            logical += len(piece)
        if logical != len(canonical):
            raise GapSearchIncomplete("png_gap_candidate_ranges_incomplete")
        physical.add(key)
        result.append((head, canonical, physical_parts, end, spliced))
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
        heads.append((at, total, prefix, cuts, prefix_crc))
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
                # Physical views share the checked immutable logical buffer;
                # no second full copy is retained for each source mapping.
                view = memoryview(raw)
                parts = [(at, view[:cut]), (tail, view[cut:])]
                retain((at, raw, parts, anchor, True))
    for candidate in _three_run_candidates(assembler, budget, heads, anchors):
        retain(candidate)
    return result
