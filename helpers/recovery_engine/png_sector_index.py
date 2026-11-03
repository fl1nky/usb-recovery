"""Bounded disk-backed CRC(source[:sector*512]) states for photo jobs.

Page hashes are carried by the externally acknowledged checkpoint, not trusted
from an adjacent manifest. The append-only working file may contain an
unacknowledged tail after interruption; only the parent-pinned prefix is used.
No source bytes are written, and this index is not file authentication.
"""
from array import array
from collections import OrderedDict
import hashlib
import os
from pathlib import Path
import re
import struct
import sys
import uuid
import zlib

from recovery_checkpoint import CheckpointError, SHA, plain

SECTOR_BYTES = 512
PAGE_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 2 * 1024 * 1024 * 1024
MAX_DIRECTORY_BYTES = 3 * 1024 * 1024 * 1024
MAX_ORPHANS = 256
INDEX_NAME = 'sector-crcs.bin'
FORMAT = 'u32le-sector-prefix-v1'
ORPHAN = re.compile(r'uncommitted-[a-f0-9]{32}\.partial\Z')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class SectorPrefixIndex:
    """One job's sequential writer, then at most two verified resident pages."""
    def __init__(self, directory, source_bytes, *, create=False):
        self.directory = plain(directory)
        self.path = plain(self.directory / INDEX_NAME, hardlinks=True)
        self.source_bytes = source_bytes
        self.stream = None
        self.states, self.source_position, self.checksum = 1, 0, 0
        self.hashes, self.cache = [], OrderedDict()
        self.dirty_page = 0
        self.expected = None
        if type(source_bytes) is not int or source_bytes < 0 or (source_bytes // SECTOR_BYTES + 1) * 4 > MAX_INDEX_BYTES:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_STORAGE_LIMIT')
        if create:
            self.directory.mkdir(parents=True, exist_ok=False)
            self.stream = self.path.open('x+b', buffering=0)
            self.stream.write(b'\0\0\0\0')
        else:
            if not self.directory.is_dir() or not self.path.is_file():
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_MISSING')
            self.stream = self.path.open('r+b', buffering=0)
        try:
            self.orphan_bytes = self._inventory() - self.path.stat().st_size
        except BaseException:
            self.close()
            raise

    def _inventory(self):
        amount, orphans = 0, 0
        for path in self.directory.iterdir():
            plain(path, hardlinks=True)
            if not path.is_file() or path.name != INDEX_NAME and not ORPHAN.fullmatch(path.name):
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_UNEXPECTED_FILE')
            amount += path.stat().st_size
            orphans += path.name != INDEX_NAME
        if amount > MAX_DIRECTORY_BYTES or orphans > MAX_ORPHANS:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_STORAGE_LIMIT')
        self.orphan_count = orphans
        return amount

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        self.cache.clear()

    def append(self, position, block):
        """Commit a whole scanner block in memory, or keep the prior boundary."""
        if (type(position) is not int or position != self.source_position or position % SECTOR_BYTES or
                not isinstance(block, bytes) or position > self.source_bytes - len(block) or
                len(block) % SECTOR_BYTES and position + len(block) != self.source_bytes):
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_POSITION_INVALID')
        old_states, old_crc, old_position = self.states, self.checksum, self.source_position
        raw = array('I')
        view = memoryview(block)
        checksum = self.checksum
        for at in range(0, len(block) - len(block) % SECTOR_BYTES, SECTOR_BYTES):
            checksum = zlib.crc32(view[at:at + SECTOR_BYTES], checksum)
            raw.append(checksum)
        if sys.byteorder != 'little':
            raw.byteswap()
        payload = raw.tobytes()
        if (self.states * 4 + len(payload) > MAX_INDEX_BYTES or
                self.orphan_bytes + self.states * 4 + len(payload) > MAX_DIRECTORY_BYTES):
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_STORAGE_LIMIT')
        plain(self.path, hardlinks=True)
        self.stream.seek(0, 2)
        if self.stream.tell() != old_states * 4:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_UNCOMMITTED_TAIL')
        try:
            if self.stream.write(payload) != len(payload):
                raise OSError('Short CRC-index write')
        except BaseException:
            self.stream.truncate(old_states * 4)
            self.stream.seek(old_states * 4)
            self.states, self.checksum, self.source_position = old_states, old_crc, old_position
            raise
        self.dirty_page = min(self.dirty_page, old_states * 4 // PAGE_BYTES)
        self.states += len(payload) // 4
        self.checksum, self.source_position = checksum, position + len(block)
        self.expected = None
        self.cache.clear()

    @staticmethod
    def validate_metadata(meta, source_bytes, position=None):
        if (not isinstance(meta, dict) or set(meta) != {'Format', 'Name', 'SourcePosition', 'States', 'Bytes', 'PageBytes', 'Pages', 'LastCrc'} or meta['Format'] != FORMAT or
                meta['Name'] != INDEX_NAME or type(meta['PageBytes']) is not int or meta['PageBytes'] != PAGE_BYTES or
                type(meta['SourcePosition']) is not int or not 0 <= meta['SourcePosition'] <= source_bytes or
                meta['SourcePosition'] != source_bytes and meta['SourcePosition'] % 1048576 or
                position is not None and meta['SourcePosition'] != position or
                type(meta['States']) is not int or meta['States'] != meta['SourcePosition'] // SECTOR_BYTES + 1 or
                type(meta['Bytes']) is not int or meta['Bytes'] != meta['States'] * 4 or meta['Bytes'] > MAX_INDEX_BYTES or
                type(meta['LastCrc']) is not int or not 0 <= meta['LastCrc'] < 2**32 or
                not isinstance(meta['Pages'], list) or len(meta['Pages']) != (meta['Bytes'] + PAGE_BYTES - 1) // PAGE_BYTES or
                any(not isinstance(value, str) or not SHA.fullmatch(value) for value in meta['Pages'])):
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_METADATA_INVALID')

    def extension(self, before, after):
        """Previous complete pages are immutable; verify its former tail too."""
        self.validate_metadata(before, self.source_bytes)
        self.validate_metadata(after, self.source_bytes)
        if after['SourcePosition'] < before['SourcePosition'] or after['Bytes'] < before['Bytes']:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_METADATA_INVALID')
        complete, tail = divmod(before['Bytes'], PAGE_BYTES)
        if after['Pages'][:complete] != before['Pages'][:complete]:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_METADATA_INVALID')
        if tail:
            self.stream.seek(complete * PAGE_BYTES)
            raw = self.stream.read(tail)
            if len(raw) != tail or _sha(raw) != before['Pages'][complete]:
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_HASH_MISMATCH')

    def snapshot(self):
        self.stream.flush()
        os.fsync(self.stream.fileno())
        count = self.states * 4
        plain(self.path, hardlinks=True)
        if os.fstat(self.stream.fileno()).st_size != count:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_LENGTH_INVALID')
        pages = (count + PAGE_BYTES - 1) // PAGE_BYTES
        hashes = self.hashes[:min(self.dirty_page, pages)]
        for page in range(len(hashes), pages):
            self.stream.seek(page * PAGE_BYTES)
            raw = self.stream.read(min(PAGE_BYTES, count - page * PAGE_BYTES))
            if len(raw) != min(PAGE_BYTES, count - page * PAGE_BYTES):
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_LENGTH_INVALID')
            hashes.append(_sha(raw))
        self.hashes = hashes
        self.dirty_page = count // PAGE_BYTES
        self.expected = dict(Format=FORMAT, Name=INDEX_NAME, SourcePosition=self.source_position,
                             States=self.states, Bytes=count, PageBytes=PAGE_BYTES,
                             Pages=list(hashes), LastCrc=self.checksum)
        return dict(self.expected, Pages=list(hashes))

    def restore(self, meta):
        self.validate_metadata(meta, self.source_bytes)
        plain(self.path, hardlinks=True)
        actual = os.fstat(self.stream.fileno()).st_size
        if actual < meta['Bytes'] or actual > MAX_INDEX_BYTES:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_LENGTH_INVALID')
        for page, expected in enumerate(meta['Pages']):
            self.stream.seek(page * PAGE_BYTES)
            raw = self.stream.read(min(PAGE_BYTES, meta['Bytes'] - page * PAGE_BYTES))
            if _sha(raw) != expected:
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_HASH_MISMATCH')
        self.stream.seek(0)
        if self.stream.read(4) != b'\0\0\0\0':
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_METADATA_INVALID')
        self.stream.seek(meta['Bytes'] - 4)
        if struct.unpack('<I', self.stream.read(4))[0] != meta['LastCrc']:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_METADATA_INVALID')
        if actual > meta['Bytes']:
            # Retain only the unacknowledged tail as evidence before returning
            # the owned working file to the exact parent-pinned boundary.
            if (self._inventory() + actual - meta['Bytes'] > MAX_DIRECTORY_BYTES or
                    self.orphan_count >= MAX_ORPHANS):
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_STORAGE_LIMIT')
            orphan = plain(self.directory / ('uncommitted-' + uuid.uuid4().hex + '.partial'))
            self.stream.seek(meta['Bytes'])
            with orphan.open('xb') as output:
                while block := self.stream.read(65536):
                    output.write(block)
                output.flush(); os.fsync(output.fileno())
            self.stream.truncate(meta['Bytes'])
            self.stream.flush(); os.fsync(self.stream.fileno())
            self.orphan_bytes += actual - meta['Bytes']
            self.orphan_count += 1
        self.source_position, self.states, self.checksum = meta['SourcePosition'], meta['States'], meta['LastCrc']
        self.hashes = list(meta['Pages'])
        self.dirty_page = meta['Bytes'] // PAGE_BYTES
        self.expected = dict(meta, Pages=list(meta['Pages']))
        self.cache.clear()

    def __getitem__(self, index):
        if type(index) is not int or not 0 <= index < self.states or self.expected is None:
            raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_ACCESS_INVALID')
        at = index * 4
        page = at // PAGE_BYTES
        raw = self.cache.get(page)
        if raw is None:
            plain(self.path, hardlinks=True)
            length = min(PAGE_BYTES, self.expected['Bytes'] - page * PAGE_BYTES)
            self.stream.seek(page * PAGE_BYTES)
            raw = self.stream.read(length)
            if len(raw) != length or _sha(raw) != self.expected['Pages'][page]:
                raise CheckpointError('PHOTO_CHECKPOINT_PNG_INDEX_HASH_MISMATCH')
            self.cache[page] = raw
            if len(self.cache) > 2:
                self.cache.popitem(last=False)
        else:
            self.cache.move_to_end(page)
        return struct.unpack_from('<I', raw, at - page * PAGE_BYTES)[0]
