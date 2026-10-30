"""Bounded photo reassembly from read-only raw images.

PNG chunks are linked by their CRC and the complete zlib/Adler stream. This is
structural evidence, not authentication of an original file or proof of deletion.
JPEG restart-interval support is implemented in a separate module.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
import warnings
import zlib

PNG = b"\x89PNG\r\n\x1a\n"
TOKENS = re.compile(rb"\x89PNG\r\n\x1a\n|IHDR|PLTE|IDAT|IEND|\xff\xd8\xff")
MAX_CHUNK = 8 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_PIXELS = 16_000_000
MAX_STARTS = 2000
MAX_CHUNKS = 4096
MAX_STATES = 4096
MAX_VERIFY_BYTES = 512 * 1024 * 1024


class LimitReached(Exception):
    pass


def disjoint(recipe):
    ranges = sorted((at, at + len(raw)) for at, raw in recipe)
    return all(start >= 0 and end > start and (not index or ranges[index - 1][1] <= start)
               for index, (start, end) in enumerate(ranges))


class PhotoAssembler:
    def __init__(self, stream, options=None, progress=None):
        self.stream = stream
        self.size = os.fstat(stream.fileno()).st_size
        self.options = options or {}
        self.progress = progress or (lambda done, total: None)
        self.verified = 0
        self.decoded = 0
        self.started = time.monotonic()
        self.skipped = Counter()
        self.starts, self.jpeg_starts, self.idat, self.iend = [], [], [], []
        self.ihdr, self.plte = [], []
        self.max_states = min(MAX_STATES, max(1, int(self.options.get("max_states", MAX_STATES))))
        self.index_position, self.index_tokens, self.index_last_match = 0, 0, -1

    def read(self, offset, length):
        if time.monotonic() - self.started > 120:
            raise LimitReached("time_budget")
        if offset < 0 or length < 0 or length > MAX_FILE or offset > self.size - length:
            return b""
        self.verified += length
        if self.verified > MAX_VERIFY_BYTES:
            raise LimitReached("verification_budget")
        self.stream.seek(offset)
        return self.stream.read(length)

    def chunk(self, offset):
        head = self.read(offset, 8)
        if len(head) != 8:
            return None
        length, kind = struct.unpack(">I4s", head)
        if length > MAX_CHUNK or not re.fullmatch(rb"[A-Za-z]{4}", kind):
            return None
        raw = self.read(offset, length + 12)
        if len(raw) != length + 12 or zlib.crc32(raw[4:-4]) != struct.unpack(">I", raw[-4:])[0]:
            return None
        return kind, raw

    def index(self, commit=None):
        position, last_match, tokens = self.index_position, self.index_last_match, self.index_tokens
        self.stream.seek(max(0, position - 11))
        carry = self.stream.read(min(position, 11))
        interval = max(32 * 1024 * 1024, ((self.size + 63) // 64 + 1048575) // 1048576 * 1048576)
        saved, saved_at = position, time.monotonic()
        lists = [self.starts,self.jpeg_starts,self.ihdr,self.plte,self.idat,self.iend]
        def checkpoint_prefix():
            nonlocal saved, saved_at
            if commit and position > saved:
                commit(); saved, saved_at = position,time.monotonic()
        while True:
            if time.monotonic() - self.started > 120:
                checkpoint_prefix()
                raise LimitReached("index_time_budget")
            counts = [len(values) for values in lists]
            try:
                self.stream.seek(position)
                block = self.stream.read(1024 * 1024)
                if block:
                    data, base = carry + block, position - len(carry)
                    next_match, next_tokens = self.index_data(data,base,last_match,tokens)
            except BaseException:
                # An exception inside CRC/header validation must not combine a
                # previous block position with partially appended next-block
                # entries. Only the last complete block may become durable.
                for values,count in zip(lists,counts):
                    del values[count:]
                checkpoint_prefix()
                raise
            if not block:
                checkpoint_prefix()
                break
            last_match,tokens = next_match,next_tokens
            position += len(block)
            carry = data[-11:]
            self.index_position, self.index_tokens, self.index_last_match = position, tokens, last_match
            if position == self.size or position - saved >= interval or time.monotonic()-saved_at >= 10:
                checkpoint_prefix()
            try:
                self.progress(position, self.size)
            except BaseException:
                checkpoint_prefix()
                raise

    def index_data(self,data,base,last_match,tokens):
        for match in TOKENS.finditer(data):
            at, token = base + match.start(), match.group()
            if at <= last_match:
                continue
            last_match = at
            tokens += 1
            if tokens > 2_000_000:
                raise LimitReached("index_token_budget")
            if token == PNG:
                if len(self.starts) >= MAX_STARTS:
                    raise LimitReached("photo_headers")
                self.starts.append(at)
            elif token == b"\xff\xd8\xff":
                if len(self.jpeg_starts) < MAX_STARTS:
                    self.jpeg_starts.append(at)
            else:
                # Fixed-size headers, trailers and small palettes do not
                # justify reading a forged multi-megabyte chunk body.
                declared = self.read(at - 4, 4)
                if len(declared) != 4:
                    continue
                length = struct.unpack(">I", declared)[0]
                if ((token == b"IHDR" and length != 13) or
                        (token == b"PLTE" and (not 0 < length <= 768 or length % 3)) or
                        (token == b"IEND" and length != 0)):
                    continue
                chunk = self.chunk(at - 4)
                if chunk and chunk[0] == token:
                    target = {b"IHDR": self.ihdr, b"PLTE": self.plte,
                              b"IDAT": self.idat, b"IEND": self.iend}[token]
                    if len(target) >= MAX_CHUNKS:
                        raise LimitReached("png_chunks")
                    target.append(at - 4)
        return last_match,tokens

    def header(self, raw):
        # PNG critical-chunk layout: https://www.w3.org/TR/png-3/#11IHDR
        if raw[4:8] != b"IHDR" or len(raw) != 25:
            return None
        width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", raw[8:-4])
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color)
        legal = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
        if (not channels or depth not in legal[color] or not width or not height or
                width * height > MAX_PIXELS or compression or filtering or interlace):
            self.skipped["png_unsupported_header"] += 1
            return None
        row_bytes = 1 + (width * channels * depth + 7) // 8
        expected = height * row_bytes
        if expected > MAX_FILE:
            return None
        return dict(expected=expected, row_bytes=row_bytes, color=color, depth=depth)

    @staticmethod
    def palette_size(raw, header):
        size = len(raw) - 12
        if header["color"] not in {2, 3, 6} or not 0 < size <= 768 or size % 3:
            return None
        entries = size // 3
        if header["color"] == 3 and entries > 1 << header["depth"]:
            return None
        return entries

    def ancillary_valid(self, kind, raw, header, palette, seen, after_idat=False):
        # PNG 3 table 7: tolerant decoders do not validate chunk context.
        before_palette = {b"cHRM", b"cICP", b"gAMA", b"iCCP", b"mDCV", b"cLLI", b"sBIT", b"sRGB"}
        before_data = before_palette | {b"bKGD", b"hIST", b"tRNS", b"eXIf", b"pHYs", b"sPLT"}
        singletons = (before_data - {b"sPLT"}) | {b"tIME"}
        valid = not (kind[2] & 32 or kind in {b"acTL", b"fcTL", b"fdAT"})
        valid = valid and not (kind in singletons and kind in seen)
        valid = valid and not (after_idat and kind in before_data)
        valid = valid and not (palette is not None and kind in before_palette)
        data, color, maximum = raw[8:-4], header["color"], (1 << header["depth"]) - 1
        if kind in {b"tRNS", b"bKGD"}:
            if color == 3:
                valid = valid and palette is not None
                if kind == b"tRNS":
                    valid = valid and palette is not None and 1 <= len(data) <= palette
                else:
                    valid = valid and len(data) == 1 and palette is not None and data[0] < palette
            else:
                count = 1 if color in {0, 4} else 3
                valid = valid and len(data) == count * 2
                valid = valid and not (kind == b"tRNS" and color in {4, 6})
                if len(data) == count * 2:
                    valid = valid and all(value[0] <= maximum for value in struct.iter_unpack(">H", data))
        elif kind == b"hIST":
            valid = valid and palette is not None and len(data) == palette * 2
        elif kind == b"sBIT":
            count = {0: 1, 2: 3, 3: 3, 4: 2, 6: 4}[color]
            valid = valid and len(data) == count and all(0 < value <= (8 if color == 3 else header["depth"]) for value in data)
        elif kind == b"gAMA":
            valid = valid and len(data) == 4 and int.from_bytes(data, "big") > 0
        elif kind == b"cHRM":
            valid = valid and len(data) == 32
        elif kind == b"sRGB":
            valid = valid and len(data) == 1 and data[0] <= 3
        elif kind == b"pHYs":
            valid = valid and len(data) == 9 and data[-1] <= 1
        if not valid:
            self.skipped["png_invalid_chunk_context"] += 1
        return valid

    def prefix_tail(self, parts, at, header, palette):
        parts = list(parts)
        seen = {raw[4:8] for _, raw in parts if raw != PNG}
        for _ in range(128):
            chunk = self.chunk(at)
            if not chunk:
                return parts, palette
            kind, raw = chunk
            if kind == b"IDAT":
                return parts, palette
            if kind in {b"IHDR", b"IEND"} or not (kind[0] & 32) and kind != b"PLTE":
                return None
            if kind == b"PLTE":
                if palette is not None or seen & {b"tRNS", b"bKGD", b"hIST"}:
                    return None
                palette = self.palette_size(raw, header)
                if palette is None:
                    return None
            elif header["color"] == 3 and palette is None and kind in {b"tRNS", b"bKGD", b"hIST"}:
                return None  # These indexed-color chunks must follow the palette.
            elif not self.ancillary_valid(kind, raw, header, palette, seen):
                return None
            seen.add(kind)
            parts.append((at, raw))
            if sum(len(raw) for _, raw in parts) > MAX_CHUNK or not disjoint(parts):
                return None
            at += len(raw)
        return None

    def prefixes(self, start):
        adjacent = self.chunk(start + len(PNG))
        # A surviving signature/IHDR adjacency is stronger than a global search.
        # A detached signature contains no dimensions or image identity: every
        # surviving compatible header must be considered before publication.
        headers = [start + len(PNG)] if adjacent and adjacent[0] == b"IHDR" else self.ihdr
        for at in headers:
            chunk = self.chunk(at)
            header = self.header(chunk[1]) if chunk else None
            if header is None:
                continue
            parts = [(start, PNG), (at, chunk[1])]
            if not disjoint(parts):
                continue
            prefix = self.prefix_tail(parts, at + len(chunk[1]), header, None)
            if prefix is None:
                continue
            parts, palette = prefix
            if header["color"] != 3 or palette is not None:
                yield parts, header, palette
                continue
            # Only a mandatory indexed-color palette is searched without a
            # surviving adjacency. Optional truecolor palettes cannot be linked
            # to a stream merely because they decode successfully.
            for palette_at in self.plte:
                prefix = self.prefix_tail(parts, palette_at, header, None)
                if prefix is not None and prefix[1] is not None:
                    yield prefix[0], header, prefix[1]

    def png(self, start):
        if not self.iend:
            return []
        solutions, states = {}, 0
        for parts, header, palette in self.prefixes(start):
            expected = header["expected"]
            candidates, candidate_bytes = [], 0
            for at in self.idat:
                chunk = self.chunk(at)
                if not chunk:
                    continue
                raw = chunk[1]
                if not disjoint(parts + [(at, raw)]):
                    continue
                # Equal IDAT bytes can have different surviving ancillary
                # tails. Only complete payloads establish equivalence.
                candidates.append((at, raw))
                candidate_bytes += len(raw)
                if len(candidates) > 128 or candidate_bytes > MAX_FILE:
                    self.skipped["png_branch_limit"] += 1
                    return []
            stack = [(parts, zlib.decompressobj(), 0, frozenset(), sum(len(raw) for _, raw in parts))]
            while stack:
                chain, decoder, decoded, used, output_bytes = stack.pop()
                for at, raw in candidates:
                    if at in used or output_bytes + len(raw) > MAX_FILE or len(used) >= 64 or not disjoint(chain + [(at, raw)]):
                        continue
                    states += 1
                    if states > self.max_states:
                        self.skipped["png_search_incomplete"] += 1
                        return []  # Unvisited alternatives cannot establish uniqueness.
                    trial = decoder.copy()
                    try:
                        block = trial.decompress(raw[8:-4], expected - decoded + 1)
                    except zlib.error:
                        continue
                    count = decoded + len(block)
                    self.decoded += len(block)
                    if self.decoded > 256 * 1024 * 1024:
                        raise LimitReached("decode_budget")
                    if count > expected or trial.unconsumed_tail or trial.unused_data:
                        continue
                    # Every non-interlaced scanline starts with a filter byte
                    # 0..4. Checking it as soon as it survives inflation rejects
                    # permutations of stored/weakly compressed IDAT fragments
                    # before waiting for the final zlib Adler checksum.
                    first_filter = (-decoded) % header["row_bytes"]
                    if any(value > 4 for value in block[first_filter::header["row_bytes"]]):
                        continue
                    next_chain = chain + [(at, raw)]
                    if trial.eof:
                        if count != expected:
                            continue
                        # Preserve surviving ancillary chunks after the last IDAT.
                        tail, cursor, tail_bytes = [], at + len(raw), 0
                        tail_seen = {piece[4:8] for _, piece in next_chain if piece != PNG}
                        invalid_tail = False
                        for _ in range(128):
                            following = self.chunk(cursor)
                            if following is None:
                                break
                            kind, body = following
                            tail_bytes += len(body)
                            if output_bytes + len(raw) + tail_bytes > MAX_FILE:
                                break
                            if kind == b"IEND" and len(body) == 12:
                                tail.append((cursor, body))
                                break
                            if not kind[0] & 32:
                                break
                            if not self.ancillary_valid(kind, body, header, palette, tail_seen, after_idat=True):
                                invalid_tail = True
                                break
                            tail_seen.add(kind)
                            tail.append((cursor, body)); cursor += len(body)
                        if invalid_tail:
                            continue
                        if not tail or tail[-1][1][4:8] != b"IEND":
                            ending = next(((end_at, self.chunk(end_at)) for end_at in self.iend
                                           if disjoint(next_chain + tail + [(end_at, b"x" * 12)])), None)
                            if not ending or not ending[1] or len(ending[1][1]) != 12:
                                continue
                            tail.append((ending[0], ending[1][1]))
                        recipe = next_chain + tail
                        if not disjoint(recipe):
                            self.skipped["png_overlapping_ranges"] += 1
                            continue
                        if sum(len(piece) for _, piece in recipe) > MAX_FILE:
                            continue
                        payload = b"".join(piece for _, piece in recipe)
                        if self.decode(payload, "PNG", palette if header["color"] == 3 else None):
                            solutions[hashlib.sha256(payload).hexdigest()] = recipe
                            if len(solutions) > 1:
                                self.skipped["png_ambiguous"] += 1
                                return []
                    else:
                        stack.append((next_chain, trial, count, used | {at}, output_bytes + len(raw)))
        return list(solutions.values())

    def recipes(self, completed=None, png_start=0, jpeg_start=0):
        for index, start in enumerate(self.starts[png_start:], png_start):
            for recipe in self.png(start):
                yield recipe, "png_crc_zlib_reassembled_candidate", "Chunk CRC, full zlib Adler stream and image decoding agree; original ownership and deletion are not authenticated."
            if completed:
                completed("Png", index + 1)
        from jpeg_fragments import recover_jpegs
        original = self.jpeg_starts
        self.jpeg_starts = _CompletedStarts(original[jpeg_start:], completed, jpeg_start)
        try:
            yield from recover_jpegs(self)
        finally:
            self.jpeg_starts = original

    @staticmethod
    def decode(payload, kind, palette_entries=None):
        from PIL import Image, ImageFile
        # Do not enable Pillow's truncated-image recovery globally.
        if ImageFile.LOAD_TRUNCATED_IMAGES:
            return False
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(payload)) as image:
                    if image.format != kind or image.width * image.height > MAX_PIXELS:
                        return False
                    image.load()
                    if palette_entries is not None and (image.mode != "P" or image.getextrema()[1] >= palette_entries):
                        return False
            return True
        except (OSError, ValueError, SyntaxError, Image.DecompressionBombError, Image.DecompressionBombWarning):
            return False


class _CompletedStarts(list):
    def __init__(self, values, completed, first):
        super().__init__(values)
        self.completed, self.first = completed, first

    def __iter__(self):
        for index, value in enumerate(super().__iter__(), self.first):
            yield value
            if self.completed:
                self.completed("Jpeg", index + 1)


def _snapshot(assembler):
    return dict(Position=assembler.index_position, Tokens=assembler.index_tokens,
                LastMatch=assembler.index_last_match,
                **{name: list(getattr(assembler, name)) for name in ('starts', 'jpeg_starts', 'ihdr', 'plte', 'idat', 'iend')})


def _restore(assembler, journal):
    from recovery_checkpoint import CheckpointError
    index, cursor, records, skipped = None, dict(Png=0, Jpeg=0), [], {}
    verified = decoded = 0
    phase = 'index'
    keys = {'Schema','Binding','Sequence','Previous','Phase','Index','Cursor','Files','Skipped','VerifiedBytes','DecodedBytes'}
    for state in journal.chain:
        if set(state) != keys or not isinstance(state['Phase'],str) or state['Phase'] not in {'index','candidates','complete'}:
            raise CheckpointError('PHOTO_CHECKPOINT_STRUCTURE_INVALID')
        incoming = state['Index']
        if incoming is not None:
            names = {'Position','Tokens','LastMatch','starts','jpeg_starts','ihdr','plte','idat','iend'}
            if not isinstance(incoming, dict) or set(incoming) != names:
                raise CheckpointError('PHOTO_CHECKPOINT_INDEX_INVALID')
            position, tokens, last = incoming['Position'], incoming['Tokens'], incoming['LastMatch']
            if (type(position) is not int or not 0 <= position <= assembler.size or
                    position != assembler.size and position % 1048576 or
                    type(tokens) is not int or not 0 <= tokens <= 2_000_000 or
                    type(last) is not int or not -1 <= last < max(1, position)):
                raise CheckpointError('PHOTO_CHECKPOINT_INDEX_INVALID')
            for name in names - {'Position','Tokens','LastMatch'}:
                values, maximum = incoming[name], MAX_STARTS if name in {'starts','jpeg_starts'} else MAX_CHUNKS
                if (not isinstance(values, list) or len(values) > maximum or
                        any(type(at) is not int or not 0 <= at < position for at in values) or
                        any(a >= b for a, b in zip(values, values[1:])) or
                        index is not None and values[:len(index[name])] != index[name]):
                    raise CheckpointError('PHOTO_CHECKPOINT_INDEX_INVALID')
            if index is not None and (position < index['Position'] or tokens < index['Tokens'] or last < index['LastMatch']):
                raise CheckpointError('PHOTO_CHECKPOINT_INDEX_INVALID')
            index = incoming
        if index is None:
            raise CheckpointError('PHOTO_CHECKPOINT_INDEX_INVALID')
        next_cursor = state['Cursor']
        if not isinstance(next_cursor, dict) or set(next_cursor) != {'Png','Jpeg'}:
            raise CheckpointError('PHOTO_CHECKPOINT_CURSOR_INVALID')
        for key, name in (('Png','starts'),('Jpeg','jpeg_starts')):
            value = next_cursor[key]
            if type(value) is not int or not cursor[key] <= value <= len(index[name]):
                raise CheckpointError('PHOTO_CHECKPOINT_CURSOR_INVALID')
        if (phase == 'complete' and state['Phase'] != 'complete' or
                next_cursor['Jpeg'] and next_cursor['Png'] != len(index['starts']) or
                state['Phase'] == 'index' and (phase != 'index' or next_cursor != dict(Png=0,Jpeg=0)) or
                state['Phase'] != 'index' and index['Position'] != assembler.size or
                state['Phase'] == 'complete' and next_cursor != dict(Png=len(index['starts']),Jpeg=len(index['jpeg_starts']))):
            raise CheckpointError('PHOTO_CHECKPOINT_CURSOR_INVALID')
        if not isinstance(state['Files'], list) or len(state['Files']) > 1000 or len(records)+len(state['Files']) > 1000:
            raise CheckpointError('PHOTO_CHECKPOINT_OUTPUT_INVALID')
        records.extend(state['Files'])
        if not isinstance(state['Skipped'], dict) or len(state['Skipped']) > 256 or any(
                not re.fullmatch(r'[a-z0-9_]{1,100}', key) or type(value) is not int or not 0 <= value <= 2_000_000
                for key, value in state['Skipped'].items()):
            raise CheckpointError('PHOTO_CHECKPOINT_STRUCTURE_INVALID')
        for key, prior in skipped.items():
            if state['Skipped'].get(key, 0) < prior:
                raise CheckpointError('PHOTO_CHECKPOINT_STRUCTURE_INVALID')
        for key, prior in (('VerifiedBytes',verified),('DecodedBytes',decoded)):
            if type(state[key]) is not int or not prior <= state[key] < 2**63:
                raise CheckpointError('PHOTO_CHECKPOINT_STRUCTURE_INVALID')
        verified, decoded, skipped, cursor, phase = state['VerifiedBytes'], state['DecodedBytes'], state['Skipped'], next_cursor, state['Phase']
    assembler.index_position, assembler.index_tokens, assembler.index_last_match = index['Position'], index['Tokens'], index['LastMatch']
    for name in ('starts','jpeg_starts','ihdr','plte','idat','iend'):
        setattr(assembler, name, list(index[name]))
    assembler.skipped.update(skipped)
    return records, cursor, verified, decoded, phase


def _validate_outputs(stream, destination, records):
    from recovery_checkpoint import CheckpointError, plain
    hashes, total = set(), 0
    statuses = {'png_crc_zlib_reassembled_candidate','jpeg_gap_structural_candidate','jpeg_restart_structural_candidate',
                'jpeg_progressive_structural_candidate','progressive_partial_precision_candidate'}
    known = set()
    size = os.fstat(stream.fileno()).st_size
    for record in records:
        if not isinstance(record, dict) or set(record) != {'Path','Sha256','Bytes','Status','Extents','Note'}:
            raise CheckpointError('PHOTO_CHECKPOINT_OUTPUT_INVALID')
        name, sha, amount = record['Path'], record['Sha256'], record['Bytes']
        if (not isinstance(name, str) or not re.fullmatch(r'(?:png-[a-f0-9]{64}\.png|jpeg-[a-f0-9]{64}\.jpg)', name) or
                not isinstance(sha,str) or not re.fullmatch(r'[a-f0-9]{64}',sha) or sha in hashes or sha not in name or type(amount) is not int or not 0 < amount <= MAX_FILE or
                not isinstance(record['Status'],str) or record['Status'] not in statuses or not isinstance(record['Note'], str) or len(record['Note']) > 16384 or
                not isinstance(record['Extents'], list) or not 1 <= len(record['Extents']) <= 100000):
            raise CheckpointError('PHOTO_CHECKPOINT_OUTPUT_INVALID')
        files = [plain(destination / name, hardlinks=True), plain(destination / (name+'.partial'), hardlinks=True)]
        existing = [path for path in files if path.is_file()]
        if len(existing) != 1 or existing[0].stat().st_size != amount:
            raise CheckpointError('PHOTO_CHECKPOINT_OUTPUT_MISSING')
        output = existing[0]; known.add(output.name)
        logical, ranges, digest, pieces = 0, [], hashlib.sha256(),[]
        with output.open('rb') as candidate:
            for extent in record['Extents']:
                if not isinstance(extent, dict) or set(extent) != {'ImageOffset','LogicalOffset','Length'}:
                    raise CheckpointError('PHOTO_CHECKPOINT_MAPPING_INVALID')
                at, position, length = extent['ImageOffset'], extent['LogicalOffset'], extent['Length']
                if any(type(value) is not int for value in (at, position, length)) or position != logical or at < 0 or length <= 0 or length > amount-logical or at > size-length:
                    raise CheckpointError('PHOTO_CHECKPOINT_MAPPING_INVALID')
                ranges.append((at, at+length)); logical += length
                stream.seek(at)
                remaining = length
                while remaining:
                    raw = stream.read(min(1048576, remaining))
                    other = candidate.read(len(raw))
                    if not raw or raw != other:
                        raise CheckpointError('PHOTO_CHECKPOINT_OUTPUT_CHANGED')
                    digest.update(raw);pieces.append(raw); remaining -= len(raw)
        ranges.sort()
        if logical != amount or any(a[1] > b[0] for a,b in zip(ranges, ranges[1:])) or digest.hexdigest() != sha:
            raise CheckpointError('PHOTO_CHECKPOINT_MAPPING_INVALID')
        if not _cached_image_valid(b''.join(pieces),name,record['Status']):
            raise CheckpointError('PHOTO_CHECKPOINT_IMAGE_INVALID')
        hashes.add(sha); total += amount
        if total > 512 * 1024 * 1024:
            raise CheckpointError('PHOTO_CHECKPOINT_OUTPUT_INVALID')
    return hashes, total, known


def _cached_image_valid(payload,name,status):
    """Validate cached format/CRC/decodability, without re-running the search.

    This does not authenticate an external anchor or re-establish historical
    ownership/uniqueness. Those remain separate from cache integrity checks.
    """
    if status == 'png_crc_zlib_reassembled_candidate':
        if not name.startswith('png-') or not name.endswith('.png') or not payload.startswith(PNG):
            return False
        position,seen_data = len(PNG),False
        while position < len(payload):
            if position > len(payload)-12:
                return False
            length,kind = struct.unpack_from('>I4s',payload,position)
            end = position+length+12
            if length > MAX_CHUNK or end > len(payload) or not re.fullmatch(rb'[A-Za-z]{4}',kind):
                return False
            if position == len(PNG) and (kind != b'IHDR' or length != 13):
                return False
            if zlib.crc32(payload[position+4:end-4]) != struct.unpack_from('>I',payload,end-4)[0]:
                return False
            seen_data |= kind == b'IDAT'
            if kind == b'IEND':
                return length == 0 and end == len(payload) and seen_data and PhotoAssembler.decode(payload,'PNG')
            position = end
        return False
    if not name.startswith('jpeg-') or not name.endswith('.jpg') or not payload.startswith(b'\xff\xd8') or not payload.endswith(b'\xff\xd9'):
        return False
    return PhotoAssembler.decode(payload,'JPEG')


def recover(image, destination, options=None, progress=None, checkpoint_progress=None):
    import jpeg_fragments
    import recovery_checkpoint as checkpoint
    from PIL import __version__ as pillow_version
    image, destination = checkpoint.plain(image), checkpoint.plain(destination)
    options = dict(options or {})
    anchor = options.pop('resume_checkpoint', None)
    if any(key != 'max_states' for key in options):
        raise ValueError('PHOTO_OPTIONS_INVALID')
    normalized = dict(max_states=min(MAX_STATES,max(1,int(options.get('max_states',MAX_STATES)))))
    state_directory = checkpoint.plain(destination.parent / (destination.name+'.state'))
    if (not image.is_file() or image == destination or
            image.is_relative_to(destination) or image.is_relative_to(state_directory) or
            anchor is None and (destination.exists() or state_directory.exists())):
        raise ValueError('PHOTO_SOURCE_OR_DESTINATION_INVALID')
    if anchor is not None and (not destination.is_dir() or not state_directory.is_dir()):
        raise checkpoint.CheckpointError('PHOTO_CHECKPOINT_JOB_MISSING')
    records, hashes, status, output_bytes = [], set(), 'complete', 0
    resumed_index_bytes = reused_candidates = 0
    if anchor is None:
        destination.mkdir(parents=True, exist_ok=False)
        state_directory.mkdir(parents=True, exist_ok=False)
        (destination/'job.incomplete').touch()
    job_open = anchor is None
    try:
        with checkpoint.locked(state_directory), image.open("rb") as stream:
            identity = os.fstat(stream.fileno())
            input_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            stream.seek(0)
            assembler = PhotoAssembler(stream, normalized, progress)
            binding = dict(SourceSha256=input_sha256,SourceBytes=identity.st_size,Options=normalized,
                           CodeSha256=checkpoint.fingerprint([sys.modules[__name__],jpeg_fragments,checkpoint]),
                           Runtime=dict(Python=list(sys.version_info[:3]),Pillow=pillow_version,Zlib=zlib.ZLIB_RUNTIME_VERSION))
            journal = checkpoint.Journal(state_directory,binding,anchor,checkpoint_progress)
            cursor, verified_prior, decoded_prior, phase = dict(Png=0,Jpeg=0),0,0,'index'
            if anchor is not None:
                records,cursor,verified_prior,decoded_prior,phase = _restore(assembler,journal)
                hashes,output_bytes,known = _validate_outputs(stream,destination,records)
                resumed_index_bytes,reused_candidates = assembler.index_position,len(records)
                orphans = []
                for file in destination.iterdir():
                    checkpoint.plain(file,hardlinks=True)
                    if file.name in known or file.name == 'job.incomplete':
                        continue
                    if not file.is_file() or not (file.name in {'report.json','report.json.partial'} or re.fullmatch(r'(?:png-[a-f0-9]{64}\.png|jpeg-[a-f0-9]{64}\.jpg)(?:\.partial)?',file.name)):
                        raise checkpoint.CheckpointError('PHOTO_CHECKPOINT_UNEXPECTED_OUTPUT')
                    orphans.append(file)
                for file in state_directory.iterdir():
                    match = checkpoint.NAME.fullmatch(file.name)
                    if match and int(match[1]) > journal.sequence or file.name.endswith('.json.partial'):
                        orphans.append(file)
                journal.quarantine(orphans)
            marker = destination/'job.incomplete'
            with marker.open('ab') as pending:
                pending.flush(); os.fsync(pending.fileno())
            job_open = True
            # Cache/chain validation has its own byte/count bounds. Give the
            # continued search a fresh work interval after that verification,
            # so many valid cached photos cannot consume every retry's search
            # budget before the first uncompleted candidate is visited.
            assembler.started = time.monotonic()
            committed_records = len(records)
            def save(phase_name, include_index=False):
                nonlocal committed_records
                value = dict(Phase=phase_name,Index=_snapshot(assembler) if include_index else None,
                    Cursor=dict(cursor),Files=records[committed_records:],Skipped=dict(assembler.skipped),
                    VerifiedBytes=verified_prior+assembler.verified,DecodedBytes=decoded_prior+assembler.decoded)
                try:
                    journal.commit(value)
                except checkpoint.CheckpointError as error:
                    if str(error) == 'PHOTO_CHECKPOINT_STORAGE_LIMIT':
                        raise LimitReached('checkpoint_storage_limit') from None
                    raise
                committed_records = len(records)
            if anchor is None:
                save('index',True)
            def completed(kind, value):
                if any(key.endswith(('_limit','_incomplete')) for key in assembler.skipped):
                    raise LimitReached('candidate_search_incomplete')
                cursor[kind] = value
                save('candidates')
            try:
                if phase == 'index':
                    assembler.index(lambda:save('index',True))
                    save('candidates',True)
                for recipe, candidate_status, note in assembler.recipes(completed,cursor['Png'],cursor['Jpeg']):
                    if not disjoint(recipe) or any(at > assembler.size - len(part) for at, part in recipe):
                        assembler.skipped["overlapping_or_invalid_ranges"] += 1
                        continue
                    payload = b"".join(part for _, part in recipe)
                    sha = hashlib.sha256(payload).hexdigest()
                    if sha in hashes:
                        continue
                    fragmented = any(at + len(part) != recipe[index + 1][0]
                                     for index, (at, part) in enumerate(recipe[:-1]))
                    if not fragmented:
                        continue
                    if len(records) >= 1000 or output_bytes + len(payload) > 512 * 1024 * 1024:
                        raise LimitReached("output_budget")
                    filename = ("png-" if candidate_status.startswith("png_") else "jpeg-") + sha + (".png" if candidate_status.startswith("png_") else ".jpg")
                    partial = destination / (filename + ".partial")
                    with partial.open("xb") as target:
                        target.write(payload); target.flush(); os.fsync(target.fileno())
                    logical, extents = 0, []
                    for at, part in recipe:
                        extents.append(dict(ImageOffset=at, LogicalOffset=logical, Length=len(part)))
                        logical += len(part)
                    records.append(dict(Path=filename, Sha256=sha, Bytes=len(payload),
                                        Status=candidate_status, Extents=extents,
                                        Note=note))
                    hashes.add(sha); output_bytes += len(payload)
                after = os.fstat(stream.fileno())
                if (identity.st_size, identity.st_mtime_ns, identity.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                    raise ValueError("PHOTO_SOURCE_CHANGED")
            except LimitReached as error:
                status = "limited"
                assembler.skipped[str(error)] += 1
            after = os.fstat(stream.fileno())
            stream.seek(0)
            final_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            path_state = image.stat()
            if ((identity.st_size, identity.st_mtime_ns, identity.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino) or
                    identity.st_ino != path_state.st_ino or input_sha256 != final_sha256):
                raise ValueError("PHOTO_SOURCE_CHANGED")
            if any(key.endswith(("_limit", "_incomplete")) for key in assembler.skipped):
                status = 'limited'
            if status == 'complete':
                try:
                    save('complete')
                except LimitReached as error:
                    status = 'limited';assembler.skipped[str(error)] += 1
            for row in records:
                partial, final = destination / (row['Path']+'.partial'),destination / row['Path']
                # The complete source digest has now been checked. A finished
                # candidate remains useful even when another search is limited;
                # the job marker and incomplete stage stay separate.
                if partial.exists():
                    if final.exists():
                        raise checkpoint.CheckpointError('PHOTO_CHECKPOINT_OUTPUT_EXISTS')
                    partial.rename(final)
            published = [dict(row,Path=row['Path']+'.partial') if (destination/(row['Path']+'.partial')).exists() else dict(row) for row in records]
            report = dict(Schema=1, Status=status, Candidates=len(records), OutputBytes=output_bytes,
                          VerifiedBytes=verified_prior+assembler.verified, SourceSha256=input_sha256,
                          SourceUnchanged=True, Skipped=dict(assembler.skipped), Files=published,
                          ResumedFromCheckpoint=anchor is not None,ResumedIndexBytes=resumed_index_bytes,
                          ReusedCandidates=reused_candidates)
            temporary = destination/'report.json.partial'
            with temporary.open('xb') as target:
                target.write(json.dumps(report,ensure_ascii=False,indent=2).encode('utf-8'));target.flush();os.fsync(target.fileno())
            temporary.replace(destination/'report.json')
            if status == 'complete':
                (destination/'job.incomplete').unlink()
            return report
    except BaseException:
        if job_open:
            (destination / "job.incomplete").touch()
        raise
