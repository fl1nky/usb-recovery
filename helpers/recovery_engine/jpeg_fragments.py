"""Bounded JPEG restart-island reconstruction on an existing read-only assembler.

ITU-T T.81 / ISO 10918-1 baseline sequential Huffman syntax. Every reconstructed
restart interval must decode exactly the required MCU/block count, use legal
Huffman symbols and end with one-bit padding plus the expected RST/EOI marker.
This is structural evidence, not a checksum or proof of original ownership.

Only minimum-jump paths between maximal physically contiguous valid islands are
considered. A new island may begin at a surviving restart boundary or on a
512-byte source boundary. Different minimum-jump payloads are ambiguous.
"""
from __future__ import annotations

import bisect
import hashlib
import heapq
import math
import re
import struct

MAX_HEADER = 128 * 1024
MAX_INTERVAL = 64 * 1024
MAX_MARKERS = 100_000
MAX_STARTS = 20_000
MAX_ISLANDS = 64
MAX_FILE = 64 * 1024 * 1024
MAX_SINGLE_GAP_FILE = 128 * 1024
MAX_PIXELS = 16_000_000
MARKERS = re.compile(rb"\xff[\xd0-\xd7\xd9]")


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
    return table


def header(assembler, start):
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
        if marker == 0xc0:
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
            frame = dict(width=width, height=height, components=components,
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
                quant.add(number)
                at += 1 + amount
        elif marker == 0xdd:
            if len(body) != 2:
                raise InvalidJpeg("jpeg_restart_table")
            interval = u16(body, 0)
        elif marker == 0xda:
            if frame is None or len(body) < 6:
                raise InvalidJpeg("jpeg_scan_header")
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
        for _ in range(count):
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
            self.remaining -= 1
            result = (result << 1) | ((self.value >> self.remaining) & 1)
        return result

    def symbol(self, table):
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


def prefix_checkpoint(raw, blocks, mcus):
    """Cache a full-block boundary before the physical cut, not guessed bits."""
    bits = Bits(raw)
    for ordinal in range(mcus * len(blocks)):
        saved = bits.at, bits.value, bits.remaining, ordinal
        try:
            block(bits, *blocks[ordinal % len(blocks)])
        except InvalidJpeg as error:
            if str(error) == "jpeg_entropy_truncated":
                return saved
            raise
    raise InvalidJpeg("jpeg_gap_after_complete_entropy")


def marker_index(assembler):
    positions, carry, offset = [], b"", 0
    while offset < assembler.size:
        assembler.read(0, 0)  # shared time/work/cancellation boundary
        assembler.stream.seek(offset)
        block = assembler.stream.read(min(1024 * 1024, assembler.size - offset))
        if not block:
            raise InvalidJpeg("jpeg_source_truncated")
        raw, base = carry + block, offset - len(carry)
        for match in MARKERS.finditer(raw):
            at = base + match.start()
            if positions and at <= positions[-1][0]:
                continue
            positions.append((at, at + 2, match.group()[1]))
            if len(positions) > MAX_MARKERS:
                assembler.skipped["jpeg_marker_limit"] += 1
                return None
        carry = raw[-1:]
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


def single_gap_paths(assembler, frame, markers):
    """One missing physical adjacency, never missing/synthesized bytes.

    The first piece must end at one of the first sixteen 512-byte source
    boundaries. The tail starts at a 512-byte boundary and ends at an intact
    EOI. This deliberately bounded fallback is not a general JPEG fragmenter.
    """
    ends = [end for _, end, marker in markers if marker == 0xd9]
    start, prefix = frame["prefix"]
    # A physically contiguous, strictly valid JPEG belongs to normal carving.
    for end in ends:
        if frame["scan"] < end <= start + MAX_SINGLE_GAP_FILE:
            raw = assembler.read(start, end - start)
            try:
                entropy(raw[len(prefix):-2], frame["blocks"], frame["mcus"])
                if assembler.decode(raw, "JPEG"):
                    return []
            except InvalidJpeg:
                pass
    cuts = [at for at in range((start // 512 + 1) * 512, min(start + 8193, assembler.size + 1), 512) if at >= frame["scan"]]
    prefixes = {}
    for cut in cuts:
        first = assembler.read(start, cut - start)
        try:
            saved = prefix_checkpoint(first[len(prefix):], frame["blocks"], frame["mcus"])
        except InvalidJpeg:
            continue
        prefixes[cut] = first, saved
    states, solutions = 0, {}
    for end in ends:
        # Tail starts farther away than 128 KiB cannot fit this fallback.
        low = max(0, end - MAX_SINGLE_GAP_FILE)
        tails = range((low + 511) // 512 * 512, end - 1, 512)
        for at in tails:
            tail = None
            for cut, (first, saved) in prefixes.items():
                if at == cut or at < cut and start < end or cut - start + end - at > MAX_SINGLE_GAP_FILE:
                    continue
                states += 1
                if states > assembler.max_states:
                    assembler.skipped["jpeg_gap_search_incomplete"] += 1
                    return []
                if tail is None:
                    tail = assembler.read(at, end - at)
                payload = first + tail
                try:
                    entropy(payload[len(prefix):-2], frame["blocks"], frame["mcus"], saved)
                except InvalidJpeg:
                    continue
                if assembler.decode(payload, "JPEG"):
                    solutions[hashlib.sha256(payload).hexdigest()] = [(start, first), (at, tail)]
                    if len(solutions) > 1:
                        assembler.skipped["jpeg_gap_ambiguous"] += 1
                        return []
    return list(solutions.values())


def recover_jpegs(assembler):
    """Yield (recipe, status, note); publication remains with the caller."""
    if not assembler.jpeg_starts:
        return
    markers = marker_index(assembler)
    if markers is None:
        return
    for start in assembler.jpeg_starts:
        try:
            frame = header(assembler, start)
            if not frame["interval"]:
                for recipe in single_gap_paths(assembler, frame, markers):
                    yield (recipe, "jpeg_gap_structural_candidate",
                           "One physical gap, exact baseline Huffman MCU count, one-bit padding and JPEG decoding agree. Prefix cut and tail start are 512-byte source boundaries; bounded to a 128 KiB file and a cut in the first 8 KiB. Structural candidate only: original ownership, payload integrity and deletion are not authenticated.")
                continue
            recipes = restart_paths(assembler, frame, markers)
            for recipe in recipes:
                if len(recipe) < 2:
                    continue
                yield (recipe, "jpeg_restart_structural_candidate",
                       "Baseline Huffman MCU counts, RST sequence, padding and JPEG decoding agree for a unique minimum-jump island path. This is structural evidence only; payload ownership, original integrity and deletion are not authenticated. New islands start at known restart or 512-byte boundaries.")
        except InvalidJpeg as error:
            assembler.skipped[str(error)] += 1
