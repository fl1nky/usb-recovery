# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded read-only access to a logical NTFS MFT, including fragmented tables.

This module supplies metadata and logical streams to a recovery controller. It
does not publish files, acknowledge checkpoints, or turn free records into proof
of intact deleted contents. The independent physical-record scanner is separate.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import struct
from typing import BinaryIO, Callable


class NtfsVolumeError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    max_records: int = 2_000_000
    max_runs: int = 100_000
    max_attributes: int = 4096
    max_name_chars: int = 2048
    max_stream_bytes: int = 1024**4
    max_read_bytes: int = 8 * 1024**2
    max_io_bytes: int = 4 * 1024**3

    def validate(self) -> None:
        for value in vars(self).values():
            if type(value) is not int or value < 1:
                raise NtfsVolumeError("NTFS_INVALID_LIMITS")
        if self.max_read_bytes > 64 * 1024**2 or self.max_io_bytes > 1024**4:
            raise NtfsVolumeError("NTFS_INVALID_LIMITS")


@dataclass(frozen=True)
class Geometry:
    sector_bytes: int
    cluster_bytes: int
    record_bytes: int
    volume_bytes: int
    mft_lcn: int
    mirror_lcn: int
    serial: int

    @classmethod
    def parse(cls, boot: bytes, available: int) -> Geometry:
        if len(boot) != 512 or boot[3:11] != b"NTFS    " or boot[510:512] != b"\x55\xaa":
            raise NtfsVolumeError("NTFS_BOOT_INVALID")
        sector = struct.unpack_from("<H", boot, 11)[0]
        code = boot[13]
        if code > 128:
            exponent = 256 - code
            if not 1 <= exponent <= 16:
                raise NtfsVolumeError("NTFS_GEOMETRY_INVALID")
            sectors_per_cluster = 1 << exponent
        else:
            sectors_per_cluster = code
        if (sector not in (512, 1024, 2048, 4096) or sectors_per_cluster == 0
                or sectors_per_cluster & (sectors_per_cluster - 1)):
            raise NtfsVolumeError("NTFS_GEOMETRY_INVALID")
        cluster = sector * sectors_per_cluster
        if cluster > 2 * 1024**2:
            raise NtfsVolumeError("NTFS_GEOMETRY_INVALID")
        sectors, mft, mirror = struct.unpack_from("<QQQ", boot, 40)
        volume = sectors * sector
        code = struct.unpack_from("<b", boot, 64)[0]
        record = (1 << -code) if -16 <= code < 0 else code * cluster
        if (volume < cluster or volume > available or record < 512 or record > 65536
                or record & (record - 1) or mft < 1 or mirror < 1
                or mft * cluster > volume - record or mirror * cluster > volume - record):
            raise NtfsVolumeError("NTFS_GEOMETRY_INVALID")
        return cls(sector, cluster, record, volume, mft, mirror,
                   struct.unpack_from("<Q", boot, 72)[0])


class VolumeWindow(io.RawIOBase):
    """A seekable window; the caller retains ownership of the read-only image.

    Bounds apply before calling the underlying stream. A guard can check
    cancellation/identity on each physical read without exposing device access.
    """

    def __init__(self, source: BinaryIO, offset: int, length: int, *,
                 limits: Limits = Limits(), guard: Callable[[], None] | None = None):
        super().__init__()
        limits.validate()
        if (type(offset) is not int or type(length) is not int or offset < 0 or length < 512
                or not source.readable() or not source.seekable() or source.writable()):
            raise NtfsVolumeError("NTFS_SOURCE_INVALID")
        previous = source.tell()
        source.seek(0, io.SEEK_END)
        available = source.tell()
        source.seek(previous)
        if offset > available - length:
            raise NtfsVolumeError("NTFS_VOLUME_OUTSIDE_IMAGE")
        self.source, self.offset, self.length = source, offset, length
        self.limits, self.guard = limits, guard
        self.position = self.io_bytes = 0

    def _check(self) -> None:
        if self.closed:
            raise ValueError("Closed NTFS volume window")
        if self.guard is not None:
            self.guard()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        self._check()
        return self.position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._check()
        if type(offset) is not int or whence not in (io.SEEK_SET, io.SEEK_CUR, io.SEEK_END):
            raise NtfsVolumeError("NTFS_SEEK_INVALID")
        target = offset + (self.position if whence == io.SEEK_CUR else self.length if whence == io.SEEK_END else 0)
        if target < 0 or target > self.length:
            raise NtfsVolumeError("NTFS_SEEK_OUTSIDE_VOLUME")
        self.position = target
        return target

    def read(self, count: int = -1) -> bytes:
        self._check()
        if type(count) is not int or count < -1:
            raise NtfsVolumeError("NTFS_READ_INVALID")
        count = self.length - self.position if count == -1 else min(count, self.length - self.position)
        if count > self.limits.max_read_bytes or count > self.limits.max_io_bytes - self.io_bytes:
            raise NtfsVolumeError("NTFS_READ_BUDGET_EXCEEDED")
        chunks, remaining = [], count
        while remaining:
            self._check()
            self.source.seek(self.offset + self.position)
            data = self.source.read(remaining)
            if not isinstance(data, bytes) or not data or len(data) > remaining:
                raise NtfsVolumeError("NTFS_SOURCE_SHORT_READ")
            chunks.append(data)
            self.position += len(data)
            self.io_bytes += len(data)
            remaining -= len(data)
        self._check()
        return b"".join(chunks)

    def readinto(self, destination) -> int:
        data = self.read(len(destination))
        destination[:len(data)] = data
        return len(data)


@dataclass(frozen=True)
class Record:
    ordinal: int
    sequence: int
    decoded_record_sha256: str
    in_use: bool
    bitmap_in_use: bool | None
    directory: bool
    extension: bool

    @property
    def deletion_evidence(self) -> str | None:
        if not self.in_use and self.bitmap_in_use is False and not self.extension:
            return "mft_bitmap_free_and_record_not_in_use"
        return None


@dataclass(frozen=True)
class StreamRun:
    logical_offset: int
    image_offset: int | None
    length: int


@dataclass(frozen=True)
class Stream:
    name: str
    size: int
    initialized_size: int
    resident: bool
    compressed: bool
    encrypted: bool
    runs: tuple[StreamRun, ...]

    @property
    def direct_mapping(self) -> bool:
        # Compressed physical spans do not map byte-for-byte to decoded output.
        return not self.resident and not self.compressed and not self.encrypted


class LogicalMft:
    """Read ordinals through the MFT stream, never by a physical signature scan.

    Library initialization resolves the MFT's own runs and attribute lists.
    The controller must persist the next ordinal separately from stream copies.
    """

    def __init__(self, volume: VolumeWindow):
        from dissect.ntfs import NTFS
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE

        self.volume = volume
        volume.seek(0)
        self.geometry = Geometry.parse(volume.read(512), volume.length)
        # Ignore trailing bytes outside this filesystem even within a larger view.
        volume.length = self.geometry.volume_bytes
        volume.seek(0)
        self.ntfs = NTFS(volume)
        if (self.ntfs.sector_size != self.geometry.sector_bytes
                or self.ntfs.cluster_size != self.geometry.cluster_bytes
                or self.ntfs._record_size != self.geometry.record_bytes):
            raise NtfsVolumeError("NTFS_PARSER_GEOMETRY_DISAGREES")
        mft = self.ntfs.mft.get(0)
        size = mft.size()
        if size < self.geometry.record_bytes or size % self.geometry.record_bytes:
            raise NtfsVolumeError("NTFS_MFT_SIZE_INVALID")
        self.record_count = size // self.geometry.record_bytes
        if self.record_count > volume.limits.max_records:
            raise NtfsVolumeError("NTFS_MFT_RECORD_LIMIT")
        self.bitmap = mft.open(attr_type=ATTRIBUTE_TYPE_CODE.BITMAP)
        if mft.size(attr_type=ATTRIBUTE_TYPE_CODE.BITMAP) * 8 < self.record_count:
            raise NtfsVolumeError("NTFS_MFT_BITMAP_SHORT")

    def record(self, ordinal: int) -> tuple[Record, object]:
        from dissect.ntfs.util import segment_reference

        if type(ordinal) is not int or not 0 <= ordinal < self.record_count:
            raise NtfsVolumeError("NTFS_MFT_ORDINAL_INVALID")
        self.volume._check()
        value = self.ntfs.mft.get(ordinal)
        self.bitmap.seek(ordinal // 8)
        byte = self.bitmap.read(1)
        if len(byte) != 1:
            raise NtfsVolumeError("NTFS_MFT_BITMAP_SHORT")
        header = value.header
        result = Record(ordinal, header.SequenceNumber, hashlib.sha256(value.data).hexdigest(),
                        bool(header.Flags & 1), bool(byte[0] & (1 << (ordinal % 8))),
                        bool(header.Flags & 2), bool(segment_reference(header.BaseFileRecordSegment)))
        return result, value

    def streams(self, parsed: object) -> tuple[Stream, ...]:
        """Validate every DATA attribute, preserving named streams separately.

        Uncompressed sparse ranges are explicit logical zeroes, not recovered
        missing bytes. A hole in a compressed unit may instead describe padding;
        compressed runs must never be exported as a direct output map.
        """
        from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE

        self.volume._check()
        if parsed.ntfs is not self.ntfs:
            raise NtfsVolumeError("NTFS_RECORD_OWNER_CHANGED")
        attributes = parsed.attributes.get(ATTRIBUTE_TYPE_CODE.DATA, ())
        limits = self.volume.limits
        if len(attributes) > limits.max_attributes:
            raise NtfsVolumeError("NTFS_ATTRIBUTE_LIMIT")
        groups = {}
        for attr in attributes:
            self.volume._check()
            name = attr.header.name
            if len(name) > limits.max_name_chars or "\x00" in name:
                raise NtfsVolumeError("NTFS_STREAM_NAME_INVALID")
            groups.setdefault(name, []).append(attr)
        streams = []
        for name, parts in groups.items():
            resident = parts[0].header.resident
            if any(part.header.resident != resident for part in parts):
                raise NtfsVolumeError("NTFS_STREAM_STORAGE_CONFLICT")
            if resident:
                if len(parts) != 1:
                    raise NtfsVolumeError("NTFS_DUPLICATE_RESIDENT_STREAM")
                size = parts[0].header.size
                if not 0 <= size <= limits.max_stream_bytes:
                    raise NtfsVolumeError("NTFS_STREAM_SIZE_INVALID")
                streams.append(Stream(name, size, size, True, False,
                                      bool(parts[0].header.flags & 0x4000), ()))
                continue
            parts.sort(key=lambda part: part.header.lowest_vcn)
            first = parts[0].header
            size = first.size
            initialized = first.header.Form.Nonresident.ValidDataLength
            if not 0 <= initialized <= size <= limits.max_stream_bytes:
                raise NtfsVolumeError("NTFS_STREAM_SIZE_INVALID")
            next_vcn, runs = 0, []
            for part in parts:
                header = part.header
                if header.lowest_vcn != next_vcn or header.highest_vcn < header.lowest_vcn:
                    raise NtfsVolumeError("NTFS_STREAM_VCN_GAP_OR_OVERLAP")
                if header.flags != first.flags:
                    raise NtfsVolumeError("NTFS_STREAM_FLAGS_CONFLICT")
                for lcn, clusters in header.dataruns():
                    self.volume._check()
                    if (len(runs) >= limits.max_runs or type(clusters) is not int or clusters <= 0
                            or lcn is not None and (type(lcn) is not int or lcn < 0)):
                        raise NtfsVolumeError("NTFS_STREAM_RUN_INVALID")
                    length = clusters * self.geometry.cluster_bytes
                    physical = None if lcn is None else lcn * self.geometry.cluster_bytes
                    if physical is not None and physical > self.geometry.volume_bytes - length:
                        raise NtfsVolumeError("NTFS_STREAM_RUN_OUTSIDE_VOLUME")
                    runs.append(StreamRun(next_vcn * self.geometry.cluster_bytes,
                                          None if physical is None else self.volume.offset + physical, length))
                    next_vcn += clusters
                if next_vcn != header.highest_vcn + 1:
                    raise NtfsVolumeError("NTFS_STREAM_RUN_COVERAGE_INVALID")
            if next_vcn * self.geometry.cluster_bytes < size:
                raise NtfsVolumeError("NTFS_STREAM_RUN_COVERAGE_INVALID")
            streams.append(Stream(name, size, initialized, False, bool(first.flags & 0xFF),
                                  bool(first.flags & 0x4000), tuple(runs)))
        return tuple(streams)

    def open_stream(self, parsed: object, descriptor: Stream) -> BinaryIO:
        """Return the parser's read-only logical stream after revalidating its plan.

        The controller owns chunk-copy checkpoints and must guard each read.
        EFS-encrypted content is never silently exported as readable plaintext.
        """
        if descriptor not in self.streams(parsed):
            raise NtfsVolumeError("NTFS_STREAM_PLAN_CHANGED")
        if descriptor.encrypted:
            raise NtfsVolumeError("NTFS_EFS_PLAINTEXT_UNAVAILABLE")
        return parsed.open(descriptor.name)
