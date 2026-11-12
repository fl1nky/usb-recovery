"""Bounded JPEG restart-island reconstruction on an existing read-only assembler.

ITU-T T.81 / ISO 10918-1 baseline/progressive Huffman syntax. Every reconstructed
restart interval must decode exactly the required MCU/block count, use legal
Huffman symbols and end with one-bit padding plus the expected marker. Progressive
scans preserve spectral occupancy and validate first/refine/EOBRUN progression.
This is structural evidence, not a checksum or proof of original ownership.

Only minimum-jump paths between maximal physically contiguous valid islands are
considered. A new island may begin at a surviving restart boundary or on a
512-byte source boundary. Different minimum-jump payloads are ambiguous.
Nonrestart baseline also has a bounded one/two-gap sector hypothesis; different
valid results remain unknown-original witnesses, never a selected original.
"""
from __future__ import annotations

import bisect
from array import array
from collections import OrderedDict
import hashlib
import heapq
import math
import re
import struct
import time

MAX_HEADER = 128 * 1024
MAX_INTERVAL = 64 * 1024
MAX_MARKERS = 100_000
MAX_STARTS = 20_000
MAX_ISLANDS = 64
MAX_FILE = 64 * 1024 * 1024
MAX_SINGLE_GAP_FILE = 128 * 1024
MAX_GAP_PIECE = 8 * 1024
MAX_GAP_MEMORY = 32 * 1024 * 1024
MAX_GAP_CACHE_MEMORY = 96 * 1024 * 1024
MAX_PIXELS = 16_000_000
MARKERS = re.compile(rb"\xff[\xd0-\xd7\xd9]")
ALL_MARKERS = re.compile(rb"\xff+[\xc0-\xfe]")
MAX_PROGRESSIVE_SCANS = 64
MAX_PROGRESSIVE_MEMORY = 64 * 1024 * 1024


class InvalidJpeg(Exception):
    pass


def u16(raw, at):
    return struct.unpack_from(">H", raw, at)[0]


def huffman(counts, values):
    if len(counts) != 16 or sum(counts) != len(values) or not values:
        raise InvalidJpeg("jpeg_huffman_table")
    table, code, at = {}, 0, 0
    for length, count in enumerate(counts, 1):
        if code + count > (1 << length):
            raise InvalidJpeg("jpeg_huffman_oversubscribed")
        for _ in range(count):
            if code == (1 << length) - 1:
                raise InvalidJpeg("jpeg_huffman_all_ones")
            table[length, code] = values[at]
            at += 1
            code += 1
        code <<= 1
    fast = [None] * 256
    for (length, code), value in table.items():
        if length <= 8:
            for prefix in range(code << (8-length), (code+1) << (8-length)):
                fast[prefix] = value, length
    table['fast8'] = fast
    return table


def header(assembler, start, allow_progressive=False):
    raw = assembler.read(start, min(MAX_HEADER, assembler.size - start))
    if not raw.startswith(b"\xff\xd8"):
        raise InvalidJpeg("jpeg_soi")
    p, frame, tables, quant, interval = 2, None, {}, set(), 0
    for _ in range(256):
        if p >= len(raw) or raw[p] != 255:
            raise InvalidJpeg("jpeg_header_torn")
        while p < len(raw) and raw[p] == 255:
            p += 1
        if p >= len(raw):
            raise InvalidJpeg("jpeg_header_torn")
        marker = raw[p]
        p += 1
        if marker in {0, 1, 0xd8, 0xd9} or 0xd0 <= marker <= 0xd7 or len(raw) - p < 2:
            raise InvalidJpeg("jpeg_header_marker")
        length = u16(raw, p)
        if length < 2 or length > len(raw) - p:
            raise InvalidJpeg("jpeg_header_bounds")
        body = raw[p + 2:p + length]
        end = p + length
        if marker == 0xc0 or marker == 0xc2 and allow_progressive:
            if frame is not None or len(body) < 6 or body[0] != 8:
                raise InvalidJpeg("jpeg_frame_unsupported")
            height, width, count = u16(body, 1), u16(body, 3), body[5]
            if not width or not height or width * height > MAX_PIXELS or not 1 <= count <= 4 or len(body) != 6 + count * 3:
                raise InvalidJpeg("jpeg_frame_bounds")
            components = {}
            for at in range(6, len(body), 3):
                ident, factors, qt = body[at:at + 3]
                horizontal, vertical = factors >> 4, factors & 15
                if ident in components or not 1 <= horizontal <= 4 or not 1 <= vertical <= 4 or qt > 3:
                    raise InvalidJpeg("jpeg_sampling_unsupported")
                components[ident] = horizontal, vertical, qt
            if sum(h * v for h, v, _ in components.values()) > 10:
                raise InvalidJpeg("jpeg_sampling_unsupported")
            hmax, vmax = max(c[0] for c in components.values()), max(c[1] for c in components.values())
            frame = dict(width=width, height=height, components=components, progressive=marker == 0xc2,
                         mcus=math.ceil(width / (8 * hmax)) * math.ceil(height / (8 * vmax)))
        elif marker in {0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf}:
            raise InvalidJpeg("jpeg_progressive_or_coding_unsupported")
        elif marker == 0xc4:
            at = 0
            while at < len(body):
                if len(body) - at < 17:
                    raise InvalidJpeg("jpeg_huffman_table")
                identifier, counts = body[at], body[at + 1:at + 17]
                at += 17
                count = sum(counts)
                if identifier >> 4 > 1 or identifier & 15 > 3 or count > len(body) - at:
                    raise InvalidJpeg("jpeg_huffman_table")
                tables[identifier >> 4, identifier & 15] = huffman(counts, body[at:at + count])
                at += count
        elif marker == 0xdb:
            at = 0
            while at < len(body):
                identifier = body[at]
                precision, number = identifier >> 4, identifier & 15
                amount = 64 * (precision + 1)
                if precision > 1 or number > 3 or len(body) - at - 1 < amount:
                    raise InvalidJpeg("jpeg_quant_table")
                values = body[at + 1:at + 1 + amount]
                if (not precision and 0 in values) or (precision and any(u16(values, p) == 0 for p in range(0, amount, 2))):
                    raise InvalidJpeg("jpeg_quant_zero")
                quant.add(number)
                at += 1 + amount
        elif marker == 0xdd:
            if len(body) != 2:
                raise InvalidJpeg("jpeg_restart_table")
            interval = u16(body, 0)
        elif marker == 0xda:
            if frame is None or len(body) < 6:
                raise InvalidJpeg("jpeg_scan_header")
            if frame["progressive"]:
                frame.update(prefix=(start, raw[:end]), scan=start + end, tables=tables,
                             quant=quant, interval=interval, scan_header=body)
                return frame
            count = body[0]
            if count != len(frame["components"]) or len(body) != 1 + count * 2 + 3 or body[-3:] != bytes([0, 63, 0]):
                raise InvalidJpeg("jpeg_noninterleaved_or_scan_unsupported")
            blocks, used = [], set()
            for at in range(1, 1 + count * 2, 2):
                ident, selector = body[at:at + 2]
                dc, ac = tables.get((0, selector >> 4)), tables.get((1, selector & 15))
                if ident in used or ident not in frame["components"] or dc is None or ac is None:
                    raise InvalidJpeg("jpeg_scan_tables")
                used.add(ident)
                horizontal, vertical, qt = frame["components"][ident]
                if qt not in quant:
                    raise InvalidJpeg("jpeg_quant_missing")
                blocks.extend([(dc, ac)] * (horizontal * vertical))
            frame.update(prefix=(start, raw[:end]), scan=start + end, blocks=blocks, interval=interval)
            return frame
        elif not (0xe0 <= marker <= 0xef or marker == 0xfe):
            raise InvalidJpeg("jpeg_header_extension_unsupported")
        p = end
    raise InvalidJpeg("jpeg_header_limit")


class Bits:
    def __init__(self, raw):
        self.raw, self.at, self.value, self.remaining = raw, 0, 0, 0

    def get(self, count):
        result = 0
        while count:
            if not self.remaining:
                if self.at >= len(self.raw):
                    raise InvalidJpeg("jpeg_entropy_truncated")
                self.value = self.raw[self.at]
                self.at += 1
                if self.value == 255:
                    if self.at >= len(self.raw):
                        raise InvalidJpeg("jpeg_entropy_truncated")
                    if self.raw[self.at] != 0:
                        raise InvalidJpeg("jpeg_entropy_marker")
                    self.at += 1
                self.remaining = 8
            amount = min(count, self.remaining)
            self.remaining -= amount
            count -= amount
            result = (result << amount) | ((self.value >> self.remaining) & ((1 << amount)-1))
        return result

    def symbol(self, table):
        fast = table.get('fast8')
        if fast is not None:
            saved = self.at,self.value,self.remaining
            try:
                result = fast[self.get(8)]
            except InvalidJpeg:
                result = None
            self.at,self.value,self.remaining = saved
            if result is not None:
                self.get(result[1])
                return result[0]
        code = 0
        for length in range(1, 17):
            code = (code << 1) | self.get(1)
            found = table.get((length, code))
            if found is not None:
                return found
        raise InvalidJpeg("jpeg_huffman_code")

    def finish(self):
        return self.at == len(self.raw) and (self.value & ((1 << self.remaining) - 1)) == (1 << self.remaining) - 1


def block(bits, dc, ac):
    category = bits.symbol(dc)
    if category > 11:
        raise InvalidJpeg("jpeg_dc_category")
    bits.get(category)
    coefficient = 1
    while coefficient < 64:
        symbol = bits.symbol(ac)
        if symbol == 0:
            break
        if symbol == 0xf0:
            coefficient += 16
            if coefficient > 64:
                raise InvalidJpeg("jpeg_ac_run")
            continue
        run, size = symbol >> 4, symbol & 15
        if not size or size > 10:
            raise InvalidJpeg("jpeg_ac_category")
        coefficient += run
        if coefficient >= 64:
            raise InvalidJpeg("jpeg_ac_run")
        bits.get(size)
        coefficient += 1


def entropy(raw, blocks, mcus, checkpoint=None):
    bits = Bits(raw)
    ordinal = 0
    if checkpoint is not None:
        bits.at, bits.value, bits.remaining, ordinal = checkpoint
    for n in range(ordinal, mcus * len(blocks)):
        block(bits, *blocks[n % len(blocks)])
    if not bits.finish():
        raise InvalidJpeg("jpeg_entropy_padding_or_count")


def prefix_checkpoint(raw, blocks, mcus, checkpoint=None):
    """Cache a full-block boundary before the physical cut, not guessed bits."""
    bits = Bits(raw)
    ordinal = 0
    if checkpoint is not None:
        bits.at, bits.value, bits.remaining, ordinal = checkpoint
    for ordinal in range(ordinal, mcus * len(blocks)):
        saved = bits.at, bits.value, bits.remaining, ordinal
        try:
            block(bits, *blocks[ordinal % len(blocks)])
        except InvalidJpeg as error:
            if str(error) == "jpeg_entropy_truncated":
                return saved
            raise
    raise InvalidJpeg("jpeg_gap_after_complete_entropy")


def marker_index(assembler, pattern=MARKERS):
    positions, carry, offset = [], b"", 0
    while offset < assembler.size:
        assembler.read(0, 0)  # shared time/work/cancellation boundary
        assembler.stream.seek(offset)
        block = assembler.stream.read(min(1024 * 1024, assembler.size - offset))
        if not block:
            raise InvalidJpeg("jpeg_source_truncated")
        raw, base = carry + block, offset - len(carry)
        for match in pattern.finditer(raw):
            at = base + match.start()
            if positions and at <= positions[-1][0]:
                continue
            positions.append((at, base + match.end(), match.group()[-1]))
            if len(positions) > MAX_MARKERS:
                assembler.skipped["jpeg_marker_limit"] += 1
                return None
        carry = raw[-4096:]
        offset += len(block)
        assembler.progress(offset, assembler.size)
    return positions


def merge(parts):
    result = []
    for at, raw in parts:
        if result and result[-1][0] + len(result[-1][1]) == at:
            previous, payload = result.pop()
            result.append((previous, payload + raw))
        else:
            result.append((at, raw))
    return result


def overlap(parts, at, length):
    return any(at < start + len(raw) and start < at + length for start, raw in parts)


def restart_paths(assembler, frame, markers):
    positions = [at for at, _, _ in markers]
    cache, decoded, states = {}, 0, 0
    candidate_starts = set(frame["scan"] for _ in range(1))
    for n, (at, end, marker) in enumerate(markers):
        if marker != 0xd9:
            candidate_starts.add(end)
        previous = max(0, at - MAX_INTERVAL)
        candidate_starts.update(range((previous + 511) // 512 * 512, at, 512))
        if len(candidate_starts) > MAX_STARTS:
            assembler.skipped["jpeg_start_limit"] += 1
            return []
    candidate_starts = sorted(candidate_starts)

    def interval(start, count):
        nonlocal decoded
        key = start, count
        if key in cache:
            return cache[key]
        index = bisect.bisect_left(positions, start)
        if index == len(markers):
            cache[key] = None
            return None
        at, end, marker = markers[index]
        if at - start > MAX_INTERVAL or at <= start:
            cache[key] = None
            return None
        decoded += 1
        if decoded > assembler.max_states * 8:
            raise InvalidJpeg("jpeg_entropy_search_incomplete")
        raw = assembler.read(start, end - start)
        try:
            entropy(raw[:-2], frame["blocks"], count)
        except InvalidJpeg:
            cache[key] = None
            return None
        result = raw, end, marker
        cache[key] = result
        return result

    def island(start, completed, number, prefix):
        parts, current = [], start
        while completed < frame["mcus"]:
            count = min(frame["interval"], frame["mcus"] - completed)
            item = interval(current, count)
            if item is None:
                break
            raw, end, marker = item
            final = completed + count == frame["mcus"]
            if marker != (0xd9 if final else 0xd0 + number % 8) or overlap(prefix + parts, current, len(raw)):
                break
            parts.append((current, raw))
            current, completed, number = end, completed + count, number + 1
        return parts, completed, number

    first, completed, number = island(frame["scan"], 0, 0, [frame["prefix"]])
    if not first:
        return []
    initial = [frame["prefix"]] + first
    queue, serial, solutions, minimum = [(0, 0, completed, number, initial)], 0, {}, None
    while queue:
        jumps, _, completed, number, parts = heapq.heappop(queue)
        if minimum is not None and jumps > minimum:
            break
        states += 1
        if states > assembler.max_states:
            assembler.skipped["jpeg_search_incomplete"] += 1
            return []
        if completed == frame["mcus"]:
            payload = b"".join(raw for _, raw in parts)
            if assembler.decode(payload, "JPEG"):
                minimum = jumps
                solutions[hashlib.sha256(payload).hexdigest()] = merge(parts)
                if len(solutions) > 1:
                    assembler.skipped["jpeg_restart_ambiguous"] += 1
                    return []
            continue
        if jumps >= MAX_ISLANDS or len(parts) > 20000:
            assembler.skipped["jpeg_island_limit"] += 1
            return []
        if sum(len(raw) for _, raw in parts) > MAX_FILE:
            assembler.skipped["jpeg_file_limit"] += 1
            return []
        for start in candidate_starts:
            if overlap(parts, start, 1):
                continue
            extra, count, stage = island(start, completed, number, parts)
            if not extra:
                continue
            serial += 1
            heapq.heappush(queue, (jumps + 1, serial, count, stage, parts + extra))
            if len(queue) > assembler.max_states:
                assembler.skipped["jpeg_search_incomplete"] += 1
                return []
    return list(solutions.values())


def has_contiguous_baseline(assembler, frame, markers):
    """Recognize the intact baseline files already owned by ordinary carving."""
    ends = sorted({end for _, end, marker in markers if marker == 0xd9})
    start, prefix = frame["prefix"]
    for end in ends:
        if frame["scan"] < end <= start + MAX_SINGLE_GAP_FILE:
            raw = assembler.read(start, end - start)
            try:
                entropy(raw[len(prefix):-2], frame["blocks"], frame["mcus"])
                if assembler.decode(raw, "JPEG"):
                    return True
            except InvalidJpeg:
                pass
    return False


def baseline_gap_paths(assembler, frame, markers):
    """Minimum one/two-gap paths within an explicit bounded sector hypothesis.

    The header/first cut are in the first 8 KiB. A middle run, if needed, is
    512..8192 bytes. Every jump/cut is sector aligned, an intact EOI terminates
    the last run, and the complete file is at most 128 KiB. Byte-identical
    source windows share parsing work, never assumed original ownership.
    """
    if has_contiguous_baseline(assembler, frame, markers):
        return []
    ends = sorted({end for _, end, marker in markers if marker == 0xd9})
    start, prefix = frame["prefix"]
    total, blocks = frame["mcus"] * len(frame["blocks"]), frame["blocks"]
    prefixes = []
    cuts = range((start // 512 + 1) * 512,
                 min(start + MAX_GAP_PIECE + 1, assembler.size + 1), 512)
    for cut in cuts:
        if cut < frame["scan"]:
            continue
        first = assembler.read(start, cut - start)
        try:
            saved = prefix_checkpoint(first[len(prefix):], blocks, frame["mcus"])
        except InvalidJpeg:
            continue
        prefixes.append((first, saved))
    if not prefixes or not ends:
        return []

    # A tail is deterministic at a full block boundary. Cache the remaining
    # block count with its component/table phase. DC values/predictors do not
    # affect Huffman syntax. No cache key relies on guessed image similarity.
    tails, tail_bytes = [], 0
    for end in ends:
        low = (max(0, end - MAX_SINGLE_GAP_FILE) + 511) // 512 * 512
        if end - low < 3:
            continue
        raw = assembler.read(low, end - low)
        tail_bytes += len(raw)
        if tail_bytes > MAX_GAP_MEMORY:
            raise InvalidJpeg("jpeg_gap_tail_search_incomplete")
        tails.append((low, memoryview(raw)[:-2], raw, OrderedDict()))
    attempts, suffix_work = 0, 0
    cache_limit = max(16, min(assembler.max_states * 64, MAX_GAP_CACHE_MEMORY // 384) // max(1, len(tails)))
    last_progress = time.monotonic()
    transitions = OrderedDict()
    transition_limit = min(assembler.max_states * 8, MAX_GAP_MEMORY // 1024)

    def consume(bits, phase):
        # A baseline block uses at most 27 + 63*26 = 1665 bits, or
        # 418 source bytes even with FF/00 stuffing. Thus this bounded key
        # contains every byte the transition can inspect, including EOF.
        at = bits.at
        key = (bits.raw[at:at + 512], bits.value if bits.remaining else 0,
               bits.remaining, phase)
        if key in transitions:
            result = transitions[key]
            if result is None:
                raise InvalidJpeg("jpeg_entropy_cached_invalid")
            amount, bits.value, bits.remaining = result
            bits.at += amount
            return
        try:
            block(bits, *blocks[phase])
            result = bits.at - at, bits.value, bits.remaining
        except InvalidJpeg:
            result = None
        if len(transitions) >= transition_limit:
            transitions.popitem(last=False)
        transitions[key] = result
        if result is None:
            raise InvalidJpeg("jpeg_entropy_cached_invalid")

    def boundary():
        nonlocal last_progress
        assembler.read(0, 0)
        now = time.monotonic()
        if now - last_progress >= 0.25:
            assembler.progress(assembler.size, assembler.size)
            last_progress = now

    def suffix(raw, cache, at, value, remaining, phase, required):
        nonlocal suffix_work
        bits = Bits(raw)
        bits.at, bits.value, bits.remaining = at, value, remaining
        pending, result = [], None
        while True:
            key = bits.at, bits.value if bits.remaining else 0, bits.remaining, phase
            if key in cache:
                cached = cache[key]
                if cached is None or cached[1] or cached[0] > required - len(pending):
                    result = cached
                    break
            if bits.finish():
                result = (0, True)
                break
            pending.append(key)
            if len(pending) > MAX_GAP_CACHE_MEMORY // 384:
                raise InvalidJpeg("jpeg_gap_suffix_search_incomplete")
            suffix_work += 1
            if suffix_work > assembler.max_states * 16384:
                raise InvalidJpeg("jpeg_gap_entropy_search_incomplete")
            if len(pending) % 128 == 0:
                boundary()
            try:
                consume(bits, phase)
            except InvalidJpeg:
                break
            phase = (phase + 1) % len(blocks)
            if len(pending) > required:
                # Only a lower bound is known. Never poison later suffix
                # states as invalid merely because this prefix needs fewer
                # blocks; a different prefix can need exactly those blocks.
                result = (0, False)
                break
        for key in reversed(pending):
            result = None if result is None else (result[0] + 1, result[1])
            if len(cache) >= cache_limit:
                cache.popitem(last=False)
            cache[key] = result
        return result[0] if result is not None and result[1] else None

    def completes(joined, saved, tail, tail_offset, window, cache):
        nonlocal attempts
        attempts += 1
        if attempts > assembler.max_states * 256:
            raise InvalidJpeg("jpeg_gap_search_incomplete")
        if attempts % 128 == 0:
            boundary()
        at, value, remaining, ordinal = saved
        carry = joined[at:]
        bits = Bits(carry + tail)
        bits.value, bits.remaining = value, remaining
        try:
            consume(bits, ordinal % len(blocks))
        except InvalidJpeg:
            return False
        if bits.at < len(carry):
            raise InvalidJpeg("jpeg_gap_checkpoint_invalid")
        count = suffix(window, cache, tail_offset + bits.at - len(carry),
                       bits.value, bits.remaining, (ordinal + 1) % len(blocks), total - ordinal - 1)
        return count is not None and ordinal + 1 + count == total

    def collect(parts, solutions, aliases=False):
        payload = b"".join(raw for _, raw in parts)
        if not assembler.decode(payload, "JPEG"):
            return
        digest, recipe = hashlib.sha256(payload).digest(), merge(parts)
        if aliases or digest in solutions and solutions[digest] != recipe:
            assembler.skipped["jpeg_gap_source_mapping_ambiguous"] = 1
        solutions.setdefault(digest, recipe)
        if len(solutions) > 1:
            error = InvalidJpeg("jpeg_gap_ambiguous")
            error.recipes = list(solutions.values())
            raise error

    # Minimum-gap scope agrees with the existing restart/progressive policy.
    # Exhaust one-gap alternatives before considering a second discontinuity.
    solutions = {}
    for first, saved in prefixes:
        joined = first[len(prefix):]
        for low, window, raw, cache in tails:
            for offset in range(0, len(window), 512):
                at, tail = low + offset, raw[offset:]
                if at == start + len(first) or overlap([(start, first)], at, len(tail)):
                    continue
                if len(first) + len(tail) > MAX_SINGLE_GAP_FILE:
                    continue
                if completes(joined, saved, tail[:-2], offset, window, cache):
                    collect([(start, first), (at, tail)], solutions)
    if solutions:
        return list(solutions.values())

    # Enumerate actual source bytes without an oracle map or filler heuristic.
    # Preserve every physical occurrence for exact disjoint-range checks.
    windows, window_bytes, starts = {}, 0, 0
    for base in range(0, assembler.size, 1024 * 1024):
        raw = assembler.read(base, min(1024 * 1024 + MAX_GAP_PIECE, assembler.size - base))
        for offset in range(0, min(1024 * 1024, assembler.size - base), 512):
            available = min(MAX_GAP_PIECE, (len(raw) - offset) // 512 * 512)
            if not available:
                continue
            starts += 1
            if starts > MAX_STARTS:
                raise InvalidJpeg("jpeg_gap_start_search_incomplete")
            piece = raw[offset:offset + available]
            if piece not in windows:
                window_bytes += len(piece)
                if len(windows) >= assembler.max_states or window_bytes > MAX_GAP_MEMORY:
                    raise InvalidJpeg("jpeg_gap_window_search_incomplete")
                windows[piece] = []
            windows[piece].append(base + offset)
        assembler.progress(min(base + 1024 * 1024, assembler.size), assembler.size)

    states = 0
    for first, saved in prefixes:
        initial = first[len(prefix):]
        for middle_window, positions in windows.items():
            continued = saved
            for length in range(512, len(middle_window) + 1, 512):
                boundary()
                joined = initial + middle_window[:length]
                try:
                    continued = prefix_checkpoint(joined, blocks, frame["mcus"], continued)
                except InvalidJpeg:
                    break
                states += 1
                if states > assembler.max_states * 8:
                    raise InvalidJpeg("jpeg_gap_middle_search_incomplete")
                middle = middle_window[:length]
                for low, window, raw, cache in tails:
                    for offset in range(0, len(window), 512):
                        at, tail = low + offset, raw[offset:]
                        if len(first) + length + len(tail) > MAX_SINGLE_GAP_FILE:
                            continue
                        fixed = [(start, first), (at, tail)]
                        if overlap(fixed[:1], at, len(tail)):
                            continue
                        possible = (p for p in positions
                            if p != start + len(first) and p + length != at
                            and not overlap(fixed, p, length))
                        physical = next(possible, None)
                        if physical is None:
                            continue
                        if completes(joined, continued, tail[:-2], offset, window, cache):
                            collect([(start, first), (physical, middle), (at, tail)],
                                    solutions, next(possible, None) is not None)
    return list(solutions.values())


class SourceWindow:
    """Bounded view over a source range; entropy never retains the whole image."""
    PAGE = 256 * 1024

    def __init__(self, assembler, start, length, pages=None):
        self.assembler, self.start, self.length = assembler, start, length
        self.pages = pages if pages is not None else OrderedDict()
        self.current_page, self.current_raw = -1, b''

    def __len__(self):
        return self.length

    def __getitem__(self, key):
        if isinstance(key, slice):
            low, high, step = key.indices(self.length)
            if step != 1 or high - low > 1024:
                raise InvalidJpeg("jpeg_stream_slice_bounds")
            return bytes(self[n] for n in range(low, high))
        if not 0 <= key < self.length:
            raise IndexError(key)
        absolute = self.start + key
        page = absolute // self.PAGE * self.PAGE
        if page == self.current_page:
            return self.current_raw[absolute-page]
        if page not in self.pages:
            if len(self.pages) >= 16:
                self.pages.popitem(last=False)
            self.pages[page] = self.assembler.read(page, min(self.PAGE, self.assembler.size - page))
        self.pages.move_to_end(page)
        self.current_page, self.current_raw = page, self.pages[page]
        return self.current_raw[absolute - page]


class JoinedWindow:
    def __init__(self, carry, tail):
        self.carry, self.tail = carry, tail

    def __len__(self):
        return len(self.carry) + len(self.tail)

    def __getitem__(self, key):
        if isinstance(key, slice):
            low, high, step = key.indices(len(self))
            if step != 1 or high - low > 1024:
                raise InvalidJpeg("jpeg_stream_slice_bounds")
            return bytes(self[n] for n in range(low, high))
        return self.carry[key] if key < len(self.carry) else self.tail[key - len(self.carry)]


def minimum_block_bits(blocks):
    """A grammar lower bound, independent of pixels or observed filler bytes."""
    result = 1 << 30
    for dc, ac in blocks:
        dc_cost = min(key[0] + value for key,value in dc.items()
                      if isinstance(key,tuple) and value <= 11)
        costs = [1 << 30] * 65
        costs[64] = 0
        for coefficient in range(63, 0, -1):
            for key, symbol in ac.items():
                if not isinstance(key, tuple):
                    continue
                length, _ = key
                if symbol == 0:
                    costs[coefficient] = min(costs[coefficient], length)
                elif symbol == 0xf0 and coefficient + 16 <= 64:
                    costs[coefficient] = min(costs[coefficient], length + costs[coefficient+16])
                else:
                    run, size = symbol >> 4, symbol & 15
                    if 0 < size <= 10 and coefficient + run < 64:
                        costs[coefficient] = min(costs[coefficient], length+size+costs[coefficient+run+1])
        result = min(result, dc_cost + costs[1])
    return result


def snapshot_stream_state(assembler):
    import copy
    state = copy.deepcopy(assembler.jpeg_stream_state)
    if state is not None and assembler.jpeg_stream_cache is not None:
        # A bounded suffix cache avoids redecoding the same surviving tail on
        # every short retry. It is anchored by the ordinary source/code journal.
        state['Memo'] = [list(key)+[value] for key,value in
                         list(assembler.jpeg_stream_cache.items())[-20000:]]
    return state


def validate_stream_state(state, assembler):
    """An anchored journal still needs bounded, typed source/entropy cursors."""
    if state is None:
        return
    from recovery_checkpoint import CheckpointError
    try:
        required = {'Start','Phase','Prefixes','NextCut','Saved','End','Prefix','Physical','Active','Solutions'}
        if set(state) - {'Memo','MemoEnd','Aliases'} != required:
            raise ValueError()
        if state['Phase'] not in {'prefix','join','complete'}:
            raise ValueError()
        for name in ('Start','NextCut','End','Prefix','Physical'):
            if type(state[name]) is not int or not 0 <= state[name] <= max(assembler.size, MAX_MARKERS):
                raise ValueError()
        def checkpoint(value):
            return (isinstance(value, list) and len(value) == 4 and
                    all(type(n) is int and 0 <= n <= MAX_FILE * 8 for n in value) and
                    value[1] <= 255 and value[2] <= 8)
        if state['Saved'] is not None and not checkpoint(state['Saved']):
            raise ValueError()
        if not isinstance(state['Prefixes'], list) or len(state['Prefixes']) > assembler.max_states * 8:
            raise ValueError()
        previous = state['Start']
        for cut, saved in state['Prefixes']:
            if type(cut) is not int or not previous < cut <= assembler.size or cut % 512 or not checkpoint(saved):
                raise ValueError()
            previous = cut
        active = state['Active']
        if active is not None and (not isinstance(active, list) or len(active) != 6 or
                                  not checkpoint(active[:3] + [active[5]]) or
                                  any(type(n) is not int or not 0 <= n <= MAX_FILE * 8 for n in active)):
            raise ValueError()
        if not isinstance(state['Solutions'], list) or len(state['Solutions']) > 2:
            raise ValueError()
        aliases = state.get('Aliases',[])
        if not isinstance(aliases,list) or len(aliases)>511:
            raise ValueError()
        for solution in state['Solutions']+aliases:
            if len(solution) != 3 or not re.fullmatch('[0-9a-f]{64}', solution[2]):
                raise ValueError()
            for at, length in solution[:2]:
                if type(at) is not int or type(length) is not int or not 0 < length <= MAX_FILE or not 0 <= at <= assembler.size-length:
                    raise ValueError()
        memo = state.get('Memo', [])
        if (not isinstance(memo,list) or len(memo)>20000 or
                type(state.get('MemoEnd',0)) is not int or not 0<=state.get('MemoEnd',0)<=MAX_MARKERS):
            raise ValueError()
        for row in memo:
            if (not isinstance(row,list) or len(row)!=5 or
                    any(type(n) is not int or not 0<=n<=MAX_FILE*8 for n in row[:4]) or
                    row[1]>255 or row[2]>8 or row[3]>10 or
                    row[4] is not None and (type(row[4]) is not int or not 0<=row[4]<=MAX_FILE*8)):
                raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise CheckpointError('PHOTO_CHECKPOINT_JPEG_SEARCH_STATE_INVALID') from None


def baseline_stream_paths(assembler, frame, markers):
    """Exhaust a one-gap hypothesis up to the ordinary 64 MiB file bound.

    Prefix checkpoints advance once through the source, sector by sector.
    Suffix states share a bounded LRU entropy index. Reads use a 4 MiB page
    cache, rather than a buffer per tail or a prefix/tail Cartesian byte copy.
    Work exhaustion publishes nothing and leaves the durable JPEG cursor at
    its previous candidate boundary. This is deliberately not a two-gap claim.
    """
    start, prefix = frame["prefix"]
    scan, blocks = frame["scan"], frame["blocks"]
    total = frame["mcus"] * len(blocks)
    ends = sorted({end for _, end, marker in markers if marker == 0xd9})
    if not ends:
        return []
    block_minimum = minimum_block_bits(blocks)
    pages = OrderedDict()
    state = assembler.jpeg_stream_state
    if state is None or state['Start'] != start:
        state = dict(Start=start, Phase='prefix', Prefixes=[], NextCut=(scan + 511)//512*512,
                     Saved=None, End=0, Prefix=0, Physical=0, Active=None, Solutions=[],Aliases=[])
        assembler.jpeg_stream_state = state
        assembler.jpeg_stream_cache = None
    assembler.jpeg_stream_aliases = state.setdefault('Aliases',[])
    prefixes, saved = state['Prefixes'], state['Saved']
    last, persisted = time.monotonic(), time.monotonic()

    def boundary():
        nonlocal last, persisted
        assembler.read(0, 0)
        if time.monotonic() - last >= .25:
            assembler.progress(assembler.size, assembler.size)
            last = time.monotonic()
        if assembler.jpeg_checkpoint and time.monotonic() - persisted >= 10:
            assembler.jpeg_checkpoint()
            persisted = time.monotonic()

    # Invalid syntax cannot become valid by appending later physical bytes.
    if state['Phase'] == 'prefix':
        for cut in range(state['NextCut'], min(start + MAX_FILE, assembler.size) + 1, 512):
            boundary()
            window = SourceWindow(assembler, scan, cut - scan, pages)
            try:
                saved = prefix_checkpoint(window, blocks, frame["mcus"], saved)
            except InvalidJpeg:
                break
            prefixes.append([cut, list(saved)])
            state.update(NextCut=cut+512, Saved=list(saved))
            if len(prefixes) >= assembler.max_states * 8:
                raise InvalidJpeg("jpeg_stream_prefix_search_incomplete")
        state['Phase'] = 'join'
    if not prefixes:
        return []

    work, attempts, solutions = 0, 0, {}
    for first, tail, expected in state['Solutions']:
        parts = [(at, assembler.read(at, length)) for at, length in (first, tail)]
        if hashlib.sha256(parts[0][1]+parts[1][1]).hexdigest() != expected:
            raise InvalidJpeg('jpeg_stream_retained_candidate_invalid')
        solutions[bytes.fromhex(expected)] = parts
    if len(solutions) > 1:
        error = InvalidJpeg('jpeg_gap_ambiguous')
        error.recipes = list(solutions.values())
        raise error
    cache_limit = min(200000, assembler.max_states * 64)
    for end_index in range(state['End'], len(ends)):
        end = ends[end_index]
        low = (max(0, end - MAX_FILE) + 511) // 512 * 512
        if end - low < 3:
            continue
        window = SourceWindow(assembler, low, end - low - 2, pages)
        cache = OrderedDict((tuple(row[:4]),row[4]) for row in state.get('Memo',[])) if state.get('MemoEnd')==end_index else OrderedDict()
        assembler.jpeg_stream_cache = cache
        state['MemoEnd'] = end_index

        def suffix(at, value, remaining, phase, required):
            nonlocal work
            bits = Bits(window)
            bits.at, bits.value, bits.remaining = at, value, remaining
            prior_count = 0
            if state['Active'] is not None:
                bits.at,bits.value,bits.remaining,phase,prior_count,_ = state['Active']
            pending, result = [], None
            while True:
                key = bits.at, bits.value if bits.remaining else 0, bits.remaining, phase
                if key in cache:
                    result = cache[key]
                    cache.move_to_end(key)
                    break
                if bits.finish():
                    result = 0
                    break
                pending.append(key)
                work += 1
                if len(pending) > cache_limit or work > assembler.max_states * 16384:
                    raise InvalidJpeg("jpeg_stream_entropy_search_incomplete")
                if work % 128 == 0:
                    # No speculative candidate: this is only a parser cursor.
                    state['Active'] = [bits.at,bits.value,bits.remaining,phase,prior_count+len(pending)-1,0]
                    boundary()
                try:
                    block(bits, *blocks[phase])
                except InvalidJpeg:
                    break
                phase = (phase + 1) % len(blocks)
            for key in reversed(pending):
                result = None if result is None else result + 1
                if len(cache) >= cache_limit:
                    cache.popitem(last=False)
                cache[key] = result
            return None if result is None else prior_count + result

        for prefix_index in range(state['Prefix'], len(prefixes)):
            cut, checkpoint = prefixes[prefix_index]
            first_length = cut - start
            saved_at, value, remaining, ordinal = checkpoint
            carry = assembler.read(scan + saved_at, cut - scan - saved_at)
            for physical in range(max(low, state['Physical']), end - 2, 512):
                tail_length = end - physical
                if (physical == cut or first_length + tail_length > MAX_FILE or
                        physical < cut and start < end or
                        (total-ordinal)*block_minimum > (len(carry)+tail_length-2)*8+remaining):
                    continue
                attempts += 1
                if attempts > assembler.max_states * 256:
                    raise InvalidJpeg("jpeg_stream_join_search_incomplete")
                state.update(End=end_index, Prefix=prefix_index, Physical=physical)
                if attempts % 128 == 0:
                    boundary()
                tail = SourceWindow(assembler, physical, tail_length - 2, pages)
                bits = Bits(JoinedWindow(carry, tail))
                bits.value, bits.remaining = value, remaining
                try:
                    block(bits, *blocks[ordinal % len(blocks)])
                except InvalidJpeg:
                    state.update(Physical=physical+512, Active=None)
                    continue
                if bits.at < len(carry):
                    raise InvalidJpeg("jpeg_stream_checkpoint_invalid")
                count = suffix(physical - low + bits.at - len(carry), bits.value,
                               bits.remaining, (ordinal + 1) % len(blocks), total - ordinal - 1)
                if count is None or ordinal + count + 1 != total:
                    state.update(Physical=physical+512, Active=None)
                    continue
                # Materialize only a fully grammar-verified bounded candidate.
                parts = [(start, assembler.read(start, first_length)),
                         (physical, assembler.read(physical, tail_length))]
                payload = parts[0][1] + parts[1][1]
                if not assembler.decode(payload, "JPEG"):
                    state.update(Physical=physical+512, Active=None)
                    continue
                digest = hashlib.sha256(payload).digest()
                if digest in solutions and solutions[digest] != parts:
                    assembler.skipped["jpeg_gap_source_mapping_ambiguous"] = 1
                    alias = [[at,len(raw)] for at,raw in parts]+[digest.hex()]
                    if alias not in state['Aliases']:
                        if len(state['Aliases'])>=511:
                            raise InvalidJpeg('jpeg_stream_alias_search_incomplete')
                        state['Aliases'].append(alias)
                solutions.setdefault(digest, parts)
                state['Solutions'] = [[[at,len(raw)] for at,raw in recipe]+[key.hex()]
                                      for key,recipe in solutions.items()]
                state.update(Physical=physical+512, Active=None)
                if len(solutions) > 1:
                    error = InvalidJpeg("jpeg_gap_ambiguous")
                    error.recipes = list(solutions.values())
                    raise error
            state.update(Prefix=prefix_index+1, Physical=0, Active=None)
        state.update(End=end_index+1, Prefix=0, Physical=0, Active=None)
    state['Phase'] = 'complete'
    return list(solutions.values())


class ProgressiveState:
    """Spectral occupancy, not guessed image coefficients or synthesized bytes.

    T.81 Annex G first/refine/EOBRUN grammar needs the nonzero positions from
    preceding scans. A 64-bit occupancy mask per padded block is sufficient for
    consuming refinement bits. DC prediction is preserved separately per restart
    interval. We deliberately reject the bogus progression warnings that tolerant
    JPEG viewers can accept (see the official libjpeg-turbo src/jdphuff.c).
    """
    def __init__(self, frame):
        self.frame, self.tables = frame, dict(frame["tables"])
        self.interval, self.quant = frame["interval"], set(frame["quant"])
        hmax = max(c[0] for c in frame["components"].values())
        vmax = max(c[1] for c in frame["components"].values())
        self.cols = math.ceil(frame["width"] / (8 * hmax))
        self.rows = math.ceil(frame["height"] / (8 * vmax))
        self.shapes, self.masks, self.levels = {}, {}, {}
        for ident, (h, v, _) in frame["components"].items():
            width = math.ceil(frame["width"] * h / (8 * hmax))
            height = math.ceil(frame["height"] * v / (8 * vmax))
            self.shapes[ident] = width, height, self.cols * h
            self.masks[ident] = array("Q", [0]) * (self.cols * h * self.rows * v)
            self.levels[ident] = [-1] * 64
        self.scan, self.scans, self.completed, self.number = None, 0, 0, 0
        self.mode, self.finished = "entropy", False
        self.footer_adjacent, self.partial_precision, self.allow_partial = False, False, False
        self.blocked_script = False
        self.new_scan(frame["scan_header"])

    def clone(self):
        other = object.__new__(ProgressiveState)
        other.__dict__ = self.__dict__.copy()
        other.tables, other.quant = dict(self.tables), set(self.quant)
        other.masks = {ident: array("Q", masks) for ident, masks in self.masks.items()}
        other.levels = {ident: levels[:] for ident, levels in self.levels.items()}
        return other

    def memory(self):
        # Count shared immutable Huffman tables per state too. This deliberately
        # overestimates sharing, preventing tiny images with many table branches
        # from hiding a large queue behind a small coefficient buffer.
        return (sum(len(masks) * masks.itemsize for masks in self.masks.values()) + 8192 +
                sum(256 + len(table) * 192 for table in self.tables.values()))

    def new_scan(self, body):
        if not body or not 1 <= body[0] <= 4 or len(body) != 4 + 2 * body[0]:
            raise InvalidJpeg("jpeg_progressive_scan_header")
        ss, se, approximation = body[-3:]
        ah, al = approximation >> 4, approximation & 15
        if ss > se or se > 63 or (ss == 0 and se != 0) or (ss != 0 and body[0] != 1) or al > 13 or (ah and al != ah - 1):
            raise InvalidJpeg("jpeg_progressive_scan_parameters")
        selected, used = [], set()
        for at in range(1, len(body) - 3, 2):
            ident, selector = body[at:at + 2]
            if ident in used or ident not in self.masks or selector >> 4 > 3 or selector & 15 > 3:
                raise InvalidJpeg("jpeg_progressive_scan_components")
            if self.frame["components"][ident][2] not in self.quant:
                raise InvalidJpeg("jpeg_quant_missing")
            used.add(ident)
            dc, ac = self.tables.get((0, selector >> 4)), self.tables.get((1, selector & 15))
            if (ss == 0 and ah == 0 and dc is None) or (ss != 0 and ac is None):
                raise InvalidJpeg("jpeg_progressive_scan_tables")
            if ss and self.levels[ident][0] < 0:
                raise InvalidJpeg("jpeg_progressive_ac_before_dc")
            for coefficient in range(ss, se + 1):
                previous = self.levels[ident][coefficient]
                if (not ah and previous != -1) or (ah and previous != ah):
                    raise InvalidJpeg("jpeg_progressive_scan_order")
            selected.append((ident, dc, ac))
        for ident, _, _ in selected:
            for coefficient in range(ss, se + 1):
                self.levels[ident][coefficient] = al
        total = self.cols * self.rows if len(selected) > 1 else math.prod(self.shapes[selected[0][0]][:2])
        self.scan = dict(ss=ss, se=se, ah=ah, al=al, selected=selected, total=total)
        self.completed, self.number, self.mode = 0, 0, "entropy"
        self.scans += 1
        if self.scans > MAX_PROGRESSIVE_SCANS:
            raise InvalidJpeg("jpeg_progressive_scan_limit")

    def blocks(self, mcu):
        selected = self.scan["selected"]
        if len(selected) == 1:
            ident, dc, ac = selected[0]
            width, _, stride = self.shapes[ident]
            yield ident, (mcu // width) * stride + mcu % width, dc, ac
        else:
            for ident, dc, ac in selected:
                h, v, _ = self.frame["components"][ident]
                stride = self.shapes[ident][2]
                x, y = (mcu % self.cols) * h, (mcu // self.cols) * v
                for row in range(v):
                    for column in range(h):
                        yield ident, (y + row) * stride + x + column, dc, ac


def progressive_block(bits, mask, dc, ac, ss, se, ah, eobrun, predictor):
    if not ss:
        if ah:
            bits.get(1)
        else:
            category = bits.symbol(dc)
            if category > 11:
                raise InvalidJpeg("jpeg_dc_category")
            value = bits.get(category)
            if category and value < 1 << (category - 1):
                value -= (1 << category) - 1
            predictor += value
            if not -(1 << 31) <= predictor < 1 << 31:
                raise InvalidJpeg("jpeg_progressive_dc_overflow")
        return mask, eobrun, predictor
    coefficient = ss
    if not ah:
        if eobrun:
            return mask, eobrun - 1, predictor
        while coefficient <= se:
            symbol = bits.symbol(ac)
            run, size = symbol >> 4, symbol & 15
            if size:
                if size > 10:
                    raise InvalidJpeg("jpeg_ac_category")
                coefficient += run
                if coefficient > se:
                    raise InvalidJpeg("jpeg_ac_run")
                bits.get(size)
                if mask & (1 << coefficient):
                    raise InvalidJpeg("jpeg_progressive_duplicate_coefficient")
                mask |= 1 << coefficient
                coefficient += 1
            elif run == 15:
                coefficient += 16
                if coefficient > se + 1:
                    raise InvalidJpeg("jpeg_ac_run")
            else:
                return mask, (1 << run) + bits.get(run) - 1, predictor
        return mask, 0, predictor
    # AC refinement: each previously nonzero coefficient consumes a correction
    # bit even during EOBRUN. Only newly nonzero coefficients carry sign bits.
    if not eobrun:
        while coefficient <= se:
            symbol = bits.symbol(ac)
            run, size = symbol >> 4, symbol & 15
            if size:
                if size != 1:
                    raise InvalidJpeg("jpeg_progressive_refine_size")
                bits.get(1)
            elif run != 15:
                eobrun = (1 << run) + bits.get(run)
                break
            while coefficient <= se:
                if mask & (1 << coefficient):
                    bits.get(1)
                else:
                    run -= 1
                    if run < 0:
                        break
                coefficient += 1
            if coefficient > se:
                raise InvalidJpeg("jpeg_progressive_refine_run")
            if size:
                mask |= 1 << coefficient
            coefficient += 1
    if eobrun:
        while coefficient <= se:
            if mask & (1 << coefficient):
                bits.get(1)
            coefficient += 1
        eobrun -= 1
    return mask, eobrun, predictor


def progressive_entropy(raw, state, count, assembler=None, checkpoint=None):
    """Consume an exact restart interval, with transactional block checkpoints."""
    bits, eobrun, predictors = Bits(raw), 0, {}
    first = state.completed
    if checkpoint is not None:
        bits.at, bits.value, bits.remaining, first, eobrun, predictors = checkpoint
        predictors = dict(predictors)
    for ordinal in range(first, state.completed + count):
        if assembler is not None and ordinal % 128 == 0:
            assembler.read(0, 0)
        for ident, index, dc, ac in state.blocks(ordinal):
            mask, eobrun, predictor = progressive_block(bits, state.masks[ident][index], dc, ac,
                                                       state.scan["ss"], state.scan["se"], state.scan["ah"],
                                                       eobrun, predictors.get(ident, 0))
            state.masks[ident][index] = mask
            predictors[ident] = predictor
        if eobrun > state.completed + count - ordinal - 1:
            raise InvalidJpeg("jpeg_progressive_eobrun_bounds")
    if eobrun or not bits.finish():
        raise InvalidJpeg("jpeg_progressive_padding_or_count")


def progressive_checkpoint(raw, state, count, assembler=None):
    """Last complete MCU before a physical cut, including pending bit/DC/EOB.

    Coefficient occupancy changes from an interrupted MCU are rolled back. The
    returned state belongs to the caller and may be cloned for candidate tails.
    Bytes preceding the cut are retained verbatim, including a split FF/00 pair.
    """
    bits, eobrun, predictors = Bits(raw), 0, {}
    for ordinal in range(state.completed, state.completed + count):
        if assembler is not None and ordinal % 128 == 0:
            assembler.read(0, 0)
        saved = bits.at, bits.value, bits.remaining, ordinal, eobrun, dict(predictors)
        blocks = list(state.blocks(ordinal))
        old = [(ident, index, state.masks[ident][index]) for ident, index, _, _ in blocks]
        try:
            for ident, index, dc, ac in blocks:
                mask, eobrun, predictor = progressive_block(bits, state.masks[ident][index], dc, ac,
                                                           state.scan["ss"], state.scan["se"], state.scan["ah"],
                                                           eobrun, predictors.get(ident, 0))
                state.masks[ident][index] = mask
                predictors[ident] = predictor
            if eobrun > state.completed + count - ordinal - 1:
                raise InvalidJpeg("jpeg_progressive_eobrun_bounds")
        except InvalidJpeg as error:
            for ident, index, mask in old:
                state.masks[ident][index] = mask
            if str(error) == "jpeg_entropy_truncated":
                return saved
            raise
    raise InvalidJpeg("jpeg_progressive_cut_after_complete_entropy")


def progressive_metadata(assembler, position, state):
    raw = assembler.read(position, 2)
    if len(raw) != 2 or raw[0] != 255:
        raise InvalidJpeg("jpeg_progressive_marker_missing")
    fill = 0
    while raw[1] == 255:
        fill += 1
        if fill > 4096:
            raise InvalidJpeg("jpeg_progressive_marker_fill_limit")
        raw = assembler.read(position + fill, 2)
        if len(raw) != 2:
            raise InvalidJpeg("jpeg_progressive_metadata_torn")
    marker = raw[1]
    if marker == 0xd9:
        if any(levels[0] < 0 for levels in state.levels.values()):
            raise InvalidJpeg("jpeg_progressive_missing_dc")
        state.partial_precision = any(level != 0 for levels in state.levels.values() for level in levels)
        if state.partial_precision and not state.allow_partial:
            raise InvalidJpeg("jpeg_progressive_partial_precision")
        if state.partial_precision and not state.footer_adjacent:
            raise InvalidJpeg("jpeg_progressive_unlinked_partial_eoi")
        state.finished = True
        return assembler.read(position, fill + 2)
    raw = assembler.read(position + fill, 4)
    if len(raw) != 4:
        raise InvalidJpeg("jpeg_progressive_metadata_torn")
    length = u16(raw, 2)
    if length < 2 or length > MAX_HEADER - 2:
        raise InvalidJpeg("jpeg_progressive_metadata_bounds")
    raw = assembler.read(position, fill + length + 2)
    if len(raw) != fill + length + 2:
        raise InvalidJpeg("jpeg_progressive_metadata_torn")
    body = raw[fill + 4:]
    if marker == 0xc4:
        at = 0
        while at < len(body):
            if len(body) - at < 17:
                raise InvalidJpeg("jpeg_huffman_table")
            identifier, counts = body[at], body[at + 1:at + 17]
            amount = sum(counts)
            at += 17
            if identifier >> 4 > 1 or identifier & 15 > 3 or amount > len(body) - at:
                raise InvalidJpeg("jpeg_huffman_table")
            state.tables[identifier >> 4, identifier & 15] = huffman(counts, body[at:at + amount])
            at += amount
    elif marker == 0xdd:
        if len(body) != 2:
            raise InvalidJpeg("jpeg_restart_table")
        state.interval = u16(body, 0)
    elif marker == 0xda:
        state.new_scan(body)
    elif not (0xe0 <= marker <= 0xef or marker == 0xfe):
        raise InvalidJpeg("jpeg_progressive_metadata_unsupported")
    return raw


def progressive_paths(assembler, frame, markers, allow_gaps=False, allow_partial=False):
    """Bounded minimum-discontinuity search; no missing bytes are fabricated."""
    positions = [at for at, _, _ in markers]
    starts = {frame["scan"]}
    metadata_starts = set()
    for at, end, marker in markers:
        if 0xd0 <= marker <= 0xd7:
            starts.add(end)
        else:
            metadata_starts.add(at)
        low = max(0, at - MAX_INTERVAL)
        starts.update(range((low + 511) // 512 * 512, at, 512))
        if len(starts) > MAX_STARTS:
            raise InvalidJpeg("jpeg_progressive_start_limit")
    starts, metadata_starts = sorted(starts), sorted(metadata_starts)
    attempts = 0

    def decode_range(state, position, length, count, final, checkpoint=None, prefix=b"", marker_bytes=2):
        # Reject incompatible prefixes before reading a potentially long span
        # of unrelated disk padding. A truncated prefix is the sole condition
        # that more bytes can repair; complete count/padding/code errors cannot.
        entropy_length = length if final else length - marker_bytes
        if entropy_length > 512:
            preview = prefix + assembler.read(position, 512)
            try:
                progressive_entropy(preview, state.clone(), count, assembler, checkpoint)
            except InvalidJpeg as error:
                if str(error) != "jpeg_entropy_truncated":
                    raise
            else:
                raise InvalidJpeg("jpeg_progressive_extra_entropy")
        raw = assembler.read(position, length)
        trial = state.clone()
        progressive_entropy(prefix + (raw if final else raw[:-marker_bytes]), trial, count, assembler, checkpoint)
        return raw, trial

    def gap_extensions(state, position, parts):
        nonlocal attempts
        # One split inside an interval, with source boundaries determined by the
        # medium rather than encoded marker offsets. Additional intervals can
        # each have a split; no one interval is arbitrarily permuted bytewise.
        index = bisect.bisect_left(positions, position)
        if index == len(markers):
            return
        maximum_cut = min(markers[index][0], position + MAX_INTERVAL, assembler.size)
        count = min(state.interval or state.scan["total"], state.scan["total"] - state.completed)
        final = state.completed + count == state.scan["total"]
        cuts = range((position // 512 + 1) * 512, maximum_cut + 1, 512)
        for cut in cuts:
            prefix = assembler.read(position, cut - position)
            partial = state.clone()
            try:
                checkpoint = progressive_checkpoint(prefix, partial, count, assembler)
            except InvalidJpeg:
                continue
            for start in starts:
                if start % 512 or start == cut or overlap(parts + [(position, prefix)], start, 1):
                    continue
                marker_index = bisect.bisect_left(positions, start)
                if marker_index == len(markers):
                    continue
                at, end, marker = markers[marker_index]
                if at <= start or cut - position + at - start > MAX_INTERVAL:
                    continue
                if (not final and marker != 0xd0 + state.number % 8) or (final and 0xd0 <= marker <= 0xd7):
                    continue
                length = (at if final else end) - start
                if overlap(parts + [(position, prefix)], start, length):
                    continue
                attempts += 1
                if attempts > assembler.max_states * 8:
                    raise InvalidJpeg("jpeg_progressive_entropy_gap_search_incomplete")
                try:
                    tail, trial = decode_range(partial, start, length, count, final, checkpoint, prefix, end - at)
                except InvalidJpeg:
                    continue
                trial.completed += count
                trial.number += 1
                if final:
                    trial.mode = "metadata"
                    trial.footer_adjacent = True
                yield trial, start + length, [(position, prefix), (start, tail)]

    def walk(state, position, parts):
        nonlocal attempts
        extra = []
        while not state.finished:
            assembler.read(0, 0)
            if state.mode == "metadata":
                trial = state.clone()
                try:
                    raw = progressive_metadata(assembler, position, trial)
                except InvalidJpeg as error:
                    # A complete surviving SOS with an impossible progression
                    # is corruption, not permission to skip that scan and turn
                    # a later EOI into a deliberately low-precision image.
                    if str(error) in {"jpeg_progressive_scan_order", "jpeg_progressive_scan_parameters",
                                      "jpeg_progressive_scan_components", "jpeg_progressive_ac_before_dc"}:
                        state.blocked_script = True
                    break
            else:
                index = bisect.bisect_left(positions, position)
                if index == len(markers):
                    break
                at, end, marker = markers[index]
                if not 0 <= at - position <= MAX_INTERVAL:
                    break
                count = min(state.interval or state.scan["total"], state.scan["total"] - state.completed)
                final = state.completed + count == state.scan["total"]
                if (not final and marker != 0xd0 + state.number % 8) or (final and 0xd0 <= marker <= 0xd7):
                    break
                attempts += 1
                if attempts > assembler.max_states * 8:
                    raise InvalidJpeg("jpeg_progressive_entropy_search_incomplete")
                try:
                    raw, trial = decode_range(state, position, end - position if not final else at - position, count, final, marker_bytes=end - at)
                except InvalidJpeg:
                    break
                trial.completed += count
                trial.number += 1
                if final:
                    trial.mode = "metadata"
                    trial.footer_adjacent = True
            if not raw or overlap(parts + extra, position, len(raw)):
                break
            extra.append((position, raw))
            position += len(raw)
            state = trial
            if len(parts) + len(extra) > MAX_MARKERS or sum(len(value) for _, value in extra) > MAX_FILE:
                raise InvalidJpeg("jpeg_progressive_file_limit")
        return state, position, extra

    initial_state = ProgressiveState(frame)
    initial_state.allow_partial = allow_partial
    state, position, extra = walk(initial_state, frame["scan"], [frame["prefix"]])
    initial = [frame["prefix"]] + extra
    if state.finished:
        return []  # intact originals belong to ordinary carving
    queue = [(0, 0, state, position, initial)]
    serial, states, solutions, minimum = 0, 0, {}, None
    queued_bytes = state.memory() + sum(len(raw) for _, raw in initial)
    while queue:
        jumps, _, state, position, parts = heapq.heappop(queue)
        queued_bytes -= state.memory() + sum(len(raw) for _, raw in parts)
        if minimum is not None and jumps > minimum:
            break
        states += 1
        if states > assembler.max_states:
            raise InvalidJpeg("jpeg_progressive_search_incomplete")
        if state.finished:
            payload = b"".join(raw for _, raw in parts)
            if assembler.decode(payload, "JPEG"):
                minimum = jumps
                solutions[hashlib.sha256(payload).hexdigest()] = (merge(parts), state.partial_precision)
                if len(solutions) > 1:
                    raise InvalidJpeg("jpeg_progressive_ambiguous")
            continue
        if state.blocked_script:
            continue
        if jumps >= MAX_ISLANDS:
            raise InvalidJpeg("jpeg_progressive_island_limit")
        if minimum is not None and jumps >= minimum:
            continue
        for start in metadata_starts if state.mode == "metadata" else starts:
            if start == position or overlap(parts, start, 1):
                continue
            branch = state.clone()
            if branch.mode == "metadata":
                branch.footer_adjacent = False
            result, end, extra = walk(branch, start, parts)
            if not extra:
                continue
            joined = parts + extra
            size = result.memory() + sum(len(raw) for _, raw in joined)
            if size > MAX_FILE or queued_bytes + size > MAX_PROGRESSIVE_MEMORY or len(queue) >= assembler.max_states:
                raise InvalidJpeg("jpeg_progressive_memory_search_incomplete")
            serial += 1
            queued_bytes += size
            heapq.heappush(queue, (jumps + 1, serial, result, end, joined))
        if allow_gaps and state.mode == "entropy":
            for continued, end, gap_parts in gap_extensions(state, position, parts):
                result, end, extra = walk(continued, end, parts + gap_parts)
                joined = parts + gap_parts + extra
                size = result.memory() + sum(len(raw) for _, raw in joined)
                if size > MAX_FILE or queued_bytes + size > MAX_PROGRESSIVE_MEMORY or len(queue) >= assembler.max_states:
                    raise InvalidJpeg("jpeg_progressive_memory_search_incomplete")
                serial += 1
                queued_bytes += size
                heapq.heappush(queue, (jumps + 1, serial, result, end, joined))
    return list(solutions.values())


def recover_jpegs(assembler):
    """Yield (recipe, status, note); publication remains with the caller."""
    if not assembler.jpeg_starts:
        return
    markers = marker_index(assembler, ALL_MARKERS)
    if markers is None:
        return
    for start in assembler.jpeg_starts:
        try:
            frame = header(assembler, start, allow_progressive=True)
            if frame["progressive"]:
                recipes = progressive_paths(assembler, frame, markers)
                if not recipes:
                    recipes = progressive_paths(assembler, frame, markers, allow_gaps=True)
                if not recipes:
                    recipes = progressive_paths(assembler, frame, markers, allow_partial=True)
                if not recipes:
                    recipes = progressive_paths(assembler, frame, markers, allow_gaps=True, allow_partial=True)
                for recipe, partial in recipes:
                    yield (recipe, "progressive_partial_precision_candidate" if partial else "jpeg_progressive_structural_candidate",
                           ("A surviving EOI is physically adjacent to the last verified scan/metadata island. Spectral coverage or successive precision is partial; absent scans are not synthesized and this is not a complete-precision image. " if partial else "") +
                           "Progressive Huffman DC/AC first/refine scans, spectral progression, exact MCU/EOBRUN counts, RST sequence, padding and decoding agree for a unique minimum-jump path in the bounded scan/restart search or one sector split per interval fallback. Original bytes and physical extents are preserved; ownership, integrity and deletion are not authenticated.")
                continue
            baseline_markers = [marker for marker in markers if marker[2] == 0xd9 or 0xd0 <= marker[2] <= 0xd7]
            if not frame["interval"]:
                if has_contiguous_baseline(assembler, frame, baseline_markers):
                    continue
                recipes = baseline_stream_paths(assembler, frame, baseline_markers)
                if not recipes:
                    recipes = baseline_gap_paths(assembler, frame, baseline_markers)
                for recipe in recipes:
                    yield (recipe, "jpeg_gap_structural_candidate",
                           "Exact baseline Huffman MCU count, one-bit padding, EOI and JPEG decoding agree for a unique minimum-gap byte result within a bounded search. The paged one-gap search supports files up to 64 MiB with no 8 KiB first-run restriction; the additional two-gap hypothesis remains bounded to 128 KiB with first/middle runs up to 8 KiB. Source jumps and cuts are 512-byte aligned. Reported extents are one replayable mapping; jpeg_gap_source_mapping_ambiguous means original physical placement is unknown. Structural candidate only: original ownership, payload integrity and deletion are not authenticated.")
                if recipes and assembler.jpeg_stream_aliases:
                    for first,tail,digest in assembler.jpeg_stream_aliases:
                        recipe = [(at,assembler.read(at,length)) for at,length in (first,tail)]
                        if hashlib.sha256(b''.join(raw for _,raw in recipe)).hexdigest()!=digest:
                            raise InvalidJpeg('jpeg_stream_retained_candidate_invalid')
                        yield (recipe,'jpeg_gap_structural_candidate',
                               'Byte-identical source alias from the complete bounded one-gap search; physical placement and original ownership are unknown and not authenticated.')
                continue
            recipes = restart_paths(assembler, frame, baseline_markers)
            for recipe in recipes:
                if len(recipe) < 2:
                    continue
                yield (recipe, "jpeg_restart_structural_candidate",
                       "Baseline Huffman MCU counts, RST sequence, padding and JPEG decoding agree for a unique minimum-jump island path. This is structural evidence only; payload ownership, original integrity and deletion are not authenticated. New islands start at known restart or 512-byte boundaries.")
        except InvalidJpeg as error:
            assembler.skipped[str(error)] += 1
            if str(error) == "jpeg_gap_ambiguous":
                for recipe in error.recipes:
                    yield (recipe, "jpeg_gap_ambiguous_candidate",
                           "Ambiguous baseline JPEG: two distinct complete Huffman/MCU/padding/EOI and decoder-valid byte results survive the bounded minimum-gap hypothesis. At most two content witnesses are retained; search stopped after proving ambiguity, so alternative content and physical aliases are not exhaustively enumerated. Original bytes, order and physical placement are unknown. Listed extents are one replayable source mapping, not proof of original placement or ownership.")
