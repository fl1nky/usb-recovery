"""Bounded JPEG restart-island reconstruction on an existing read-only assembler.

ITU-T T.81 / ISO 10918-1 baseline/progressive Huffman syntax. Every reconstructed
restart interval must decode exactly the required MCU/block count, use legal
Huffman symbols and end with one-bit padding plus the expected marker. Progressive
scans preserve spectral occupancy and validate first/refine/EOBRUN progression.
This is structural evidence, not a checksum or proof of original ownership.

Only minimum-jump paths between maximal physically contiguous valid islands are
considered. A new island may begin at a surviving restart boundary or on a
512-byte source boundary. Different minimum-jump payloads are ambiguous.
"""
from __future__ import annotations

import bisect
from array import array
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
                for recipe in single_gap_paths(assembler, frame, baseline_markers):
                    yield (recipe, "jpeg_gap_structural_candidate",
                           "One physical gap, exact baseline Huffman MCU count, one-bit padding and JPEG decoding agree. Prefix cut and tail start are 512-byte source boundaries; bounded to a 128 KiB file and a cut in the first 8 KiB. Structural candidate only: original ownership, payload integrity and deletion are not authenticated.")
                continue
            recipes = restart_paths(assembler, frame, baseline_markers)
            for recipe in recipes:
                if len(recipe) < 2:
                    continue
                yield (recipe, "jpeg_restart_structural_candidate",
                       "Baseline Huffman MCU counts, RST sequence, padding and JPEG decoding agree for a unique minimum-jump island path. This is structural evidence only; payload ownership, original integrity and deletion are not authenticated. New islands start at known restart or 512-byte boundaries.")
        except InvalidJpeg as error:
            assembler.skipped[str(error)] += 1
