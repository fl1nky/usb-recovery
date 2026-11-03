"""Resumable global IDAT search over one job-shared sector-prefix index.

Only a completed global pool reaches the PNG validator. A candidate discovered
in an early source range cannot suppress a different payload or alias later in
the image. Checkpoints contain physical ranges and hashes, never image payloads.
"""
import copy
import hashlib
import struct
import time

import png_fragments as gap
from recovery_checkpoint import CheckpointError, SHA

MAX_REPLAY_BYTES = gap.MAX_PHYSICAL_CANDIDATES * (gap.MAX_SPLIT_CHUNK + 12)


class GlobalPngSearch:
    def __init__(self, assembler, state=None):
        self.assembler = assembler
        self.result, self.physical, self.interned = [], set(), {}
        self.pool_bytes = self.distinct = 0
        self.last_save = time.monotonic()
        self.save_failed = False
        self.replay_bytes = 0
        if state is None:
            self.state = dict(Schema=1, Phase='anchors', Head=0, Anchor=0, Unit=None,
                              Anchors=None, Candidates=[], Rows=0,
                              StartedAtPng=getattr(assembler, 'png_cursor', 0))
        else:
            self.validate_state(state, assembler)
            self.state = copy.deepcopy(state)
            for record in state['Candidates']:
                self._restore_candidate(record)
        assembler.png_search = self

    @staticmethod
    def validate_state(state, assembler):
        if (not isinstance(state, dict) or set(state) != {'Schema', 'Phase', 'Head', 'Anchor', 'Unit', 'Anchors', 'Candidates', 'Rows', 'StartedAtPng'} or type(state['Schema']) is not int or state['Schema'] != 1 or
                not isinstance(state['Phase'], str) or state['Phase'] not in {'anchors', 'two', 'three', 'complete'} or
                type(state['Head']) is not int or not 0 <= state['Head'] <= len(assembler.idat) or
                type(state['Anchor']) is not int or not 0 <= state['Anchor'] <= gap.MAX_ANCHORS or
                state['Unit'] is not None and (type(state['Unit']) is not int or not -4096 <= state['Unit'] <= assembler.size // gap.SECTOR + 4096) or
                type(state['Rows']) is not int or not 0 <= state['Rows'] < 2**63 or
                type(state['StartedAtPng']) is not int or not 0 <= state['StartedAtPng'] <= len(assembler.starts) or
                not isinstance(state['Candidates'], list) or len(state['Candidates']) > gap.MAX_PHYSICAL_CANDIDATES):
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_STATE_INVALID')
        anchors = state['Anchors']
        if state['Phase'] == 'anchors':
            if anchors is not None or state['Head'] or state['Anchor'] or state['Unit'] is not None or state['Candidates']:
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_STATE_INVALID')
        elif (not isinstance(anchors, list) or len(anchors) > gap.MAX_ANCHORS or
                any(type(at) is not int or not 0 <= at <= assembler.size - 12 for at in anchors) or
                any(a >= b for a, b in zip(anchors, anchors[1:])) or state['Anchor'] > len(anchors)):
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_STATE_INVALID')
        if state['Phase'] == 'complete' and (state['Head'] != len(assembler.idat) or state['Anchor'] or state['Unit'] is not None):
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_STATE_INVALID')
        for record in state['Candidates']:
            if (not isinstance(record, dict) or set(record) != {'Head', 'End', 'Ranges', 'Bytes', 'Sha256'} or
                    type(record['Head']) is not int or record['Head'] not in assembler.idat or
                    type(record['End']) is not int or anchors is None or record['End'] not in anchors or
                    type(record['Bytes']) is not int or not 12 < record['Bytes'] <= gap.MAX_SPLIT_CHUNK + 12 or
                    not isinstance(record['Sha256'], str) or not SHA.fullmatch(record['Sha256']) or
                    not isinstance(record['Ranges'], list) or not 2 <= len(record['Ranges']) <= 3):
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_POOL_INVALID')
            amount, ordered = 0, []
            for pair in record['Ranges']:
                if (not isinstance(pair, list) or len(pair) != 2 or any(type(v) is not int for v in pair) or
                        pair[0] < 0 or pair[1] <= 0 or pair[0] > assembler.size - pair[1]):
                    raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_POOL_INVALID')
                amount += pair[1]
                ordered.append((pair[0], pair[0] + pair[1]))
            ordered.sort()
            if (amount != record['Bytes'] or record['Ranges'][0][0] != record['Head'] or
                    sum(record['Ranges'][-1]) != record['End'] or
                    any(a[1] > b[0] for a, b in zip(ordered, ordered[1:]))):
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_POOL_INVALID')

    def _restore_candidate(self, record):
        # Cache replay has its own finite byte bound. It cannot consume each
        # continued interval's verification budget before any new row is read.
        self.replay_bytes += record['Bytes']
        if self.replay_bytes > MAX_REPLAY_BYTES:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_POOL_INVALID')
        raw_parts = []
        for at, count in record['Ranges']:
            self.assembler.stream.seek(at)
            raw = self.assembler.stream.read(count)
            if len(raw) != count:
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_POOL_SOURCE_MISMATCH')
            raw_parts.append(raw)
        raw = b''.join(raw_parts)
        if (hashlib.sha256(raw).hexdigest() != record['Sha256'] or raw[4:8] != b'IDAT' or
                int.from_bytes(raw[:4], 'big') + 12 != len(raw) or
                gap.zlib.crc32(raw[4:-4]) != int.from_bytes(raw[-4:], 'big')):
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_POOL_SOURCE_MISMATCH')
        self.retain((record['Head'], raw, [(at, part) for (at, _), part in zip(record['Ranges'], raw_parts)], record['End'], True), restoring=True)

    def snapshot(self):
        return copy.deepcopy(self.state)

    def retain(self, candidate, *, restoring=False):
        head, raw, parts, end, spliced = candidate
        mapping = tuple((offset, len(piece)) for offset, piece in parts)
        key = (head, end, mapping)
        if key in self.physical:
            if restoring:
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_POOL_INVALID')
            return
        if len(self.result) >= gap.MAX_PHYSICAL_CANDIDATES:
            raise gap.GapSearchIncomplete('png_gap_candidate_pool_incomplete')
        checksum = hashlib.sha256(raw).digest()
        bucket = self.interned.setdefault(checksum, [])
        canonical = next((known for known in bucket if known == raw), None)
        if canonical is None:
            if self.distinct + 1 > gap.MAX_DISTINCT_CHUNKS or self.pool_bytes + len(raw) > gap.MAX_POOL_BYTES:
                raise gap.GapSearchIncomplete('png_gap_candidate_pool_incomplete')
            self.distinct += 1
            self.pool_bytes += len(raw)
            canonical = raw
            bucket.append(raw)
        physical_parts, logical = [], 0
        view = memoryview(canonical)
        for at, piece in parts:
            physical_parts.append((at, view[logical:logical + len(piece)]))
            logical += len(piece)
        if logical != len(canonical):
            raise gap.GapSearchIncomplete('png_gap_candidate_ranges_incomplete')
        self.physical.add(key)
        self.result.append((head, canonical, physical_parts, end, spliced))
        if not restoring:
            self.state['Candidates'].append(dict(Head=head, End=end, Ranges=[list(pair) for pair in mapping],
                                                 Bytes=len(canonical), Sha256=checksum.hex()))

    def _save(self, force=False):
        now = time.monotonic()
        if force or now - self.last_save >= 5:
            callback = getattr(self.assembler, 'png_checkpoint', None)
            if callback:
                try:
                    callback()
                except BaseException:
                    self.save_failed = True
                    raise
            self.last_save = now

    def progress(self):
        state = self.state
        heads, anchors = max(1, len(self.assembler.idat)), max(1, len(state['Anchors'] or []))
        pair = state['Head'] * anchors + state['Anchor']
        if state['Phase'] == 'anchors':
            return 'png_two', 0, 1
        if state['Phase'] == 'two':
            return 'png_two', min(pair, heads * anchors), heads * anchors
        if state['Phase'] == 'complete':
            return 'png_join', 1, 1
        span = self.assembler.size // gap.SECTOR + 4097
        unit = state['Unit'] if state['Unit'] is not None else -4096
        return 'png_join', min(heads * anchors * span, pair * span + unit + 4096), heads * anchors * span

    def _head(self, at, budget):
        header = self.assembler.read(at, 8)
        if len(header) != 8 or header[4:8] != b'IDAT':
            return None
        length = struct.unpack_from('>I', header)[0]
        if length > gap.MAX_SPLIT_CHUNK:
            raise gap.GapSearchIncomplete('png_idat_size_incomplete')
        if not length:
            return None
        total = length + 12
        prefix = self.assembler.read(at, min(total - 1, self.assembler.size - at))
        first = ((at + 8 + gap.SECTOR - 1) // gap.SECTOR) * gap.SECTOR - at
        cuts = list(range(first, len(prefix) + 1, gap.SECTOR))
        if not cuts:
            return None
        return at, total, prefix, cuts, gap._prefix_crcs(prefix, cuts, total - 4, budget)

    def _advance_head(self):
        self.state['Head'] += 1
        self.state['Anchor'], self.state['Unit'] = 0, None

    def _advance_anchor(self):
        self.state['Anchor'] += 1
        self.state['Unit'] = None

    def _two(self, budget):
        state, assembler = self.state, self.assembler
        anchors = state['Anchors']
        while state['Head'] < len(assembler.idat):
            prepared = self._head(assembler.idat[state['Head']], budget)
            if prepared is None:
                self._advance_head(); continue
            at, total, prefix, cuts, prefix_crc = prepared
            while state['Anchor'] < len(anchors):
                anchor = anchors[state['Anchor']]
                if state['Unit'] is None:
                    budget.pair()
                    state['Unit'] = 0
                if (anchor - total + cuts[0]) % gap.SECTOR:
                    self._advance_anchor(); continue
                valid = [cut for cut in cuts if 0 <= anchor - (total - cut) < anchor and
                         (at + cut <= anchor - (total - cut) or anchor <= at) and
                         anchor - (total - cut) != at + cut]
                if not valid:
                    self._advance_anchor(); continue
                if not 0 <= state['Unit'] <= len(valid):
                    raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_CURSOR_INVALID')
                base = anchor - (total - valid[0])
                window = assembler.read(base, anchor - base)
                if len(window) != anchor - base:
                    raise gap.GapSearchIncomplete('png_gap_suffix_read_incomplete')
                suffixes = gap._suffix_crcs(window, base, anchor, total, valid, budget)
                while state['Unit'] < len(valid):
                    cut = valid[state['Unit']]
                    budget.attempt()
                    tail = anchor - (total - cut)
                    suffix_crc, amount = suffixes[cut]
                    actual = gap.crc32_combine(prefix_crc[cut], suffix_crc, amount)
                    stored = (struct.unpack_from('>I', window, len(window) - 4)[0] if cut <= total - 4 else
                              int.from_bytes(prefix[total - 4:cut] + window[tail - base:], 'big'))
                    if actual == stored:
                        raw = prefix[:cut] + window[tail - base:]
                        if len(raw) == total and budget.crc(memoryview(raw)[4:-4]) == stored:
                            view = memoryview(raw)
                            self.retain((at, raw, [(at, view[:cut]), (tail, view[cut:])], anchor, True))
                    state['Unit'] += 1
                    state['Rows'] += 1
                    self._save()
                self._advance_anchor()
            self._advance_head()
        state.update(Phase='three', Head=0, Anchor=0, Unit=None)
        self._save(force=True)

    def _three(self, budget):
        state, assembler = self.state, self.assembler
        anchors, source_index = state['Anchors'], assembler.sector_index
        if source_index is None or source_index.source_position != assembler.size:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_NOT_COMPLETE')
        h, sectors = source_index, assembler.size // gap.SECTOR
        while state['Head'] < len(assembler.idat):
            prepared = self._head(assembler.idat[state['Head']], budget)
            if prepared is None or len(prepared[3]) < 2:
                self._advance_head(); continue
            at, total, prefix, cuts, prefix_crc = prepared
            data_end = total - 4
            max_a = min(len(cuts) - 2, gap._viable_prefixes(assembler, prefix, cuts, data_end, budget))
            normal_end = min(len(cuts) - 1, (data_end - cuts[0]) // gap.SECTOR)
            split = next((i for i, cut in enumerate(cuts) if data_end < cut < total), None)
            if max_a < 0 or normal_end < 1 and split is None:
                self._advance_head(); continue
            tables = gap._cut_tables(cuts, budget)
            prefix_keys = [gap._lookup(tables[i], prefix_crc[cuts[i]]) for i in range(max_a + 1)]
            inverse_total = gap._inverse_table(data_end)
            first = cuts[0]
            while state['Anchor'] < len(anchors):
                anchor = anchors[state['Anchor']]
                if state['Unit'] is None:
                    budget.pair()
                    state['Unit'] = -max_a
                if (anchor - total + first) % gap.SECTOR:
                    self._advance_anchor(); continue
                if not -max_a <= state['Unit'] <= sectors:
                    raise CheckpointError('PHOTO_CHECKPOINT_PNG_SEARCH_CURSOR_INVALID')
                min_gap = max(1, (at + total - anchor + gap.SECTOR - 1) // gap.SECTOR) if anchor > at else 1
                low_b = max(1, (total - anchor - first + gap.SECTOR - 1) // gap.SECTOR)
                suffix_keys = {}
                if low_b <= normal_end:
                    values = cuts[low_b:normal_end + 1]
                    base = anchor - (total - values[0])
                    window = assembler.read(base, anchor - base)
                    if len(window) != anchor - base:
                        raise gap.GapSearchIncomplete('png_two_gap_suffix_read_incomplete')
                    suffixes = gap._suffix_crcs(window, base, anchor, total, values, budget)
                    stored = struct.unpack_from('>I', window, len(window) - 4)[0]
                    suffix_keys = {j: gap._lookup(inverse_total, stored ^ suffixes[cuts[j]][0]) for j in range(low_b, normal_end + 1)}
                while state['Unit'] < sectors:
                    k = state['Unit']
                    budget.poll()
                    self._row(budget, prepared, max_a, normal_end, split, tables, prefix_keys,
                              inverse_total, suffix_keys, k, sectors, h, anchor, min_gap, low_b)
                    state['Unit'] = k + 1
                    state['Rows'] += 1
                    self._save()
                self._advance_anchor()
            self._advance_head()
        state.update(Phase='complete', Head=len(assembler.idat), Anchor=0, Unit=None)
        self._save(force=True)

    def _row(self, budget, prepared, max_a, normal_end, split, tables, prefix_keys,
             inverse_total, suffix_keys, k, sectors, h, anchor, min_gap, low_b):
        assembler = self.assembler
        at, total, prefix, cuts, _ = prepared
        data_end, first = total - 4, cuts[0]
        d = k * gap.SECTOR - first
        if d == at or d == anchor - total:
            return
        low_a, high_a = max(0, -k), min(max_a, sectors - k - 1)
        if d > anchor - total:
            low_a = max(low_a, (anchor + gap.SECTOR - 1) // gap.SECTOR - k)
        high_b = min(normal_end, sectors - k)
        if d < at:
            high_b = min(high_b, at // gap.SECTOR - k)
        high_a = min(high_a, high_b - min_gap)
        start_b = max(low_b, low_a + min_gap)
        # Charge the complete k row before changing state. A stopped row is
        # replayed, and retained matches deduplicate by exact physical map.
        cells = (high_b - start_b + 1 + high_a - low_a + 1) if low_a <= high_a and start_b <= high_b else 0
        a_low, a_high = max(0, -k), min(max_a, (split or 0) - min_gap)
        has_split = split is not None and anchor >= total - cuts[split] and 0 < k + split <= sectors
        if d > anchor - total:
            a_low = max(a_low, (anchor + gap.SECTOR - 1) // gap.SECTOR - k)
        if has_split and d < at and (k + split) * gap.SECTOR > at:
            has_split = False
        if has_split and a_low <= a_high:
            cells += a_high - a_low + 1
        if cells:
            budget.cells(cells)
        if low_a <= high_a and start_b <= high_b:
            ends = {}
            for j in range(start_b, high_b + 1):
                if not j % 1024:
                    budget.poll()
                key = gap._lookup(tables[j], h[k + j]) ^ suffix_keys[j]
                ends.setdefault(key, []).append(j)
            for i in range(low_a, high_a + 1):
                if not i % 1024:
                    budget.poll()
                key = gap._lookup(tables[i], h[k + i]) ^ prefix_keys[i]
                for j in ends.get(key, ()):
                    if j - i >= min_gap:
                        candidate = gap._joined_candidate(assembler, budget, at, prefix, cuts[i], cuts[j],
                                                          (k + i) * gap.SECTOR, anchor, total)
                        if candidate is not None:
                            self.retain(candidate)
        if not has_split or a_low > a_high:
            return
        count = cuts[split] - data_end
        high = assembler.read((k + split) * gap.SECTOR - count, count)
        low = assembler.read(anchor - (4 - count), 4 - count)
        if len(high) != count or len(low) != 4 - count:
            raise gap.GapSearchIncomplete('png_two_gap_crc_read_incomplete')
        before_crc = gap._unshift(h[k + split] ^ budget.crc(high), count)
        target = gap._lookup(inverse_total, int.from_bytes(high + low, 'big') ^ before_crc)
        for i in range(a_low, a_high + 1):
            if not i % 1024:
                budget.poll()
            if gap._lookup(tables[i], h[k + i]) ^ prefix_keys[i] == target:
                candidate = gap._joined_candidate(assembler, budget, at, prefix, cuts[i], cuts[split],
                                                  (k + i) * gap.SECTOR, anchor, total)
                if candidate is not None:
                    self.retain(candidate)

    def run(self):
        if self.assembler.unsupported_idat:
            raise gap.GapSearchIncomplete('png_idat_size_incomplete')
        if self.state['Phase'] == 'complete':
            return self.result
        budget = gap._Budget(self.assembler)
        self.save_failed = False
        try:
            if self.state['Phase'] == 'anchors':
                self.state.update(Anchors=gap._anchors(self.assembler, budget), Phase='two')
                self._save(force=True)
            if self.state['Phase'] == 'two':
                self._two(budget)
            if self.state['Phase'] == 'three':
                self._three(budget)
        except BaseException:
            if not self.save_failed:
                self._save(force=True)
            raise
        return self.result
