# SPDX-License-Identifier: AGPL-3.0-or-later
"""Source adapter checks; no NTFS controller/portable/device completion claim."""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import io
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from ntfs_volume import Geometry, Limits, LogicalMft, NtfsVolumeError, VolumeWindow

checks = 0


def check(value, why):
    global checks
    checks += 1
    if not value:
        raise AssertionError(why)


def rejects(function, code):
    try:
        function()
    except NtfsVolumeError as error:
        check(str(error) == code, f"expected {code}, received {error}")
    else:
        raise AssertionError(f"missing rejection {code}")


class ReadOnly(io.BytesIO):
    def writable(self):
        return False


def boundaries():
    data = bytes(range(256)) * 32
    source = ReadOnly(data)
    window = VolumeWindow(source, 512, 4096)
    check(window.read(17) == data[512:529], "volume offset maps exact bytes")
    check(window.seek(-8, io.SEEK_END) == 4088, "end seek stays in volume")
    check(window.read(80) == data[4600:4608], "read clips to volume end")
    check(window.read(1) == b"", "EOF does not leak adjacent source bytes")
    rejects(lambda: window.seek(-1), "NTFS_SEEK_OUTSIDE_VOLUME")
    rejects(lambda: window.seek(4097), "NTFS_SEEK_OUTSIDE_VOLUME")
    rejects(lambda: window.seek(0, 99), "NTFS_SEEK_INVALID")
    rejects(lambda: window.read(-2), "NTFS_READ_INVALID")
    rejects(lambda: window.read(True), "NTFS_READ_INVALID")
    rejects(lambda: VolumeWindow(source, 8191, 512), "NTFS_VOLUME_OUTSIDE_IMAGE")
    rejects(lambda: VolumeWindow(io.BytesIO(data), 0, len(data)), "NTFS_SOURCE_INVALID")
    rejects(lambda: VolumeWindow(source, -1, 512), "NTFS_SOURCE_INVALID")
    rejects(lambda: VolumeWindow(source, 0, True), "NTFS_SOURCE_INVALID")
    rejects(lambda: Limits(max_io_bytes=0).validate(), "NTFS_INVALID_LIMITS")
    rejects(lambda: Limits(max_read_bytes=128 * 1024**2).validate(), "NTFS_INVALID_LIMITS")
    tiny = VolumeWindow(source, 0, 4096, limits=Limits(max_read_bytes=8, max_io_bytes=12))
    rejects(lambda: tiny.read(9), "NTFS_READ_BUDGET_EXCEEDED")
    check(tiny.tell() == 0 and tiny.io_bytes == 0, "rejected read consumes no position or I/O budget")
    check(tiny.read(8) == data[:8], "accepted bounded read")
    rejects(lambda: tiny.read(5), "NTFS_READ_BUDGET_EXCEEDED")
    check(tiny.read(4) == data[8:12], "exact remaining budget")
    window.close()
    check(not source.closed, "closing a volume view does not close the caller's image")

    class Short(ReadOnly):
        def read(self, count=-1):
            return super().read(min(7, count))
    short = VolumeWindow(Short(data), 0, len(data))
    check(short.read(40) == data[:40] and short.io_bytes == 40, "short physical reads are completed exactly")
    class Gone(ReadOnly):
        def read(self, count=-1):
            return b""
    rejects(lambda: VolumeWindow(Gone(data), 0, len(data)).read(1), "NTFS_SOURCE_SHORT_READ")
    def cancelled():
        raise InterruptedError("owned cancellation")
    cancelled_view = VolumeWindow(source, 0, len(data), guard=cancelled)
    try:
        cancelled_view.read(5)
    except InterruptedError:
        check(cancelled_view.io_bytes == 0, "cancellation runs before source reads")
    else:
        raise AssertionError("missing guard cancellation")


def native(root):
    image = root / "ntfs.bin"
    expected = "3cf887ae87b7f44f1faee71838b3d79b811097a0a1a4962e8e0fd132bc8dfbc7"
    check(hashlib.sha256(image.read_bytes()).hexdigest() == expected, "pinned independent NTFS fixture")
    with image.open("rb") as source:
        window = VolumeWindow(source, 0, image.stat().st_size)
        mft = LogicalMft(window)
        check(mft.geometry.sector_bytes == 512 and mft.geometry.cluster_bytes == 4096
              and mft.geometry.record_bytes == 1024, "independent Windows NTFS geometry")
        check(mft.record_count == 2304, "logical table covers all declared MFT records")
        runs = mft.ntfs.mft.get(0).dataruns()
        check(len(runs) == 3, "actual MFT spans three physical runs")
        for ordinal, name, body in [(41, "File.txt", b"Contents here"), (44, "Large.txt", b"A" * 2097152)]:
            record, parsed = mft.record(ordinal)
            check(parsed.filename == name and parsed.open().read() == body,
                  "resident/nonresident payload equals upstream independent known bytes")
            check(record.in_use and record.bitmap_in_use and record.deletion_evidence is None,
                  "live records never become deleted messages/files")
            check(hashlib.sha256(parsed.data).hexdigest() == record.decoded_record_sha256,
                  "record digest labels fixed-up parser bytes, not on-disk sector checksums")
            streams = mft.streams(parsed)
            check(len(streams) == 1 and streams[0].size == len(body), "complete named-stream plan")
            with mft.open_stream(parsed, streams[0]) as opened:
                chunks = []
                while data := opened.read(4093):
                    chunks.append(data)
                check(b"".join(chunks) == body, "logical stream supports chunk reads without remux or synthesized payload")
            check(streams[0].resident == (ordinal == 41) and streams[0].compressed == (ordinal == 44)
                  and not streams[0].direct_mapping, "resident and compressed bodies are never falsely mapped as direct image bytes")
            rejects(lambda: mft.open_stream(parsed, replace(streams[0], size=streams[0].size + 1)),
                    "NTFS_STREAM_PLAN_CHANGED")
            check(replace(record, in_use=False, bitmap_in_use=None).deletion_evidence is None
                  and replace(record, bitmap_in_use=False).deletion_evidence is None,
                  "unknown allocation or conflicting live flag cannot confirm deletion")
            check(replace(record, in_use=False, bitmap_in_use=False).deletion_evidence
                  == "mft_bitmap_free_and_record_not_in_use", "deletion marker requires agreement of both retained metadata facts")
        record, parsed = mft.record(2200)
        logical = 2200 * mft.geometry.record_bytes
        for lcn, clusters in runs:
            span = clusters * mft.geometry.cluster_bytes
            if logical >= span:
                logical -= span
                continue
            source.seek(lcn * mft.geometry.cluster_bytes + logical)
            raw = source.read(mft.geometry.record_bytes)
            break
        check(raw[:4] == b"FILE" and raw[:48] == parsed.data[:48],
              "ordinal in the third run maps back to its actual physical record")
        check(record.ordinal == 2200 and record.sequence == parsed.header.SequenceNumber,
              "logical ordinal and sequence survive fragmented table lookup")
        rejects(lambda: mft.record(-1), "NTFS_MFT_ORDINAL_INVALID")
        rejects(lambda: mft.record(mft.record_count), "NTFS_MFT_ORDINAL_INVALID")
        rejects(lambda: mft.record(True), "NTFS_MFT_ORDINAL_INVALID")
        stream_corruption(mft)

    with image.open("rb") as source:
        rejects(lambda: LogicalMft(VolumeWindow(source, 0, image.stat().st_size,
                                               limits=Limits(max_records=1))), "NTFS_MFT_RECORD_LIMIT")
    boot = image.read_bytes()[:512]
    for offset, value in [(11, b"\x00\x00"), (13, b"\x03"), (40, b"\xff" * 8),
                          (48, b"\xff" * 8), (56, b"\xff" * 8), (64, b"\x80")]:
        invalid = bytearray(boot)
        invalid[offset:offset + len(value)] = value
        rejects(lambda: Geometry.parse(bytes(invalid), image.stat().st_size), "NTFS_GEOMETRY_INVALID")
    invalid = bytearray(boot); invalid[510] = 0
    rejects(lambda: Geometry.parse(bytes(invalid), image.stat().st_size), "NTFS_BOOT_INVALID")
    large_clusters = bytearray(boot)
    struct.pack_into("<H", large_clusters, 11, 4096)
    large_clusters[13] = 247  # Signed exponent -9: 512 sectors per cluster.
    struct.pack_into("<QQQ", large_clusters, 40, 2048, 1, 2)
    check(Geometry.parse(bytes(large_clusters), 8 * 1024**2).cluster_bytes == 2 * 1024**2,
          "large-cluster geometry is bounded before any filesystem parser allocation; not a native format test")
    large_clusters[13] = 246
    rejects(lambda: Geometry.parse(bytes(large_clusters), 8 * 1024**2), "NTFS_GEOMETRY_INVALID")
    check(hashlib.sha256(image.read_bytes()).hexdigest() == expected, "native image remains unchanged")


def stream_corruption(mft):
    from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    def parsed(*, name="", size=4096, initialized=4096, first=0, last=0, flags=0, runs=((1, 1),)):
        header = SimpleNamespace(name=name, size=size, resident=False, lowest_vcn=first,
                                 highest_vcn=last, flags=flags, dataruns=lambda: list(runs),
                                 header=SimpleNamespace(Form=SimpleNamespace(Nonresident=SimpleNamespace(ValidDataLength=initialized))))
        return SimpleNamespace(ntfs=mft.ntfs, attributes={ATTRIBUTE_TYPE_CODE.DATA: [SimpleNamespace(header=header)]})
    for fields, code in [({"name": "x\x00y"}, "NTFS_STREAM_NAME_INVALID"),
                         ({"name": "я" * 2049}, "NTFS_STREAM_NAME_INVALID"),
                         ({"size": -1}, "NTFS_STREAM_SIZE_INVALID"),
                         ({"initialized": 4097}, "NTFS_STREAM_SIZE_INVALID"),
                         ({"first": 1}, "NTFS_STREAM_VCN_GAP_OR_OVERLAP"),
                         ({"last": 1}, "NTFS_STREAM_RUN_COVERAGE_INVALID"),
                         ({"runs": ((-1, 1),)}, "NTFS_STREAM_RUN_INVALID"),
                         ({"runs": ((1, 0),)}, "NTFS_STREAM_RUN_INVALID"),
                         ({"runs": ((10**12, 1),)}, "NTFS_STREAM_RUN_OUTSIDE_VOLUME")]:
        rejects(lambda fields=fields: mft.streams(parsed(**fields)), code)
    sparse = mft.streams(parsed(runs=((None, 1),)))[0]
    check(sparse.direct_mapping and sparse.runs[0].image_offset is None,
          "uncompressed sparse extent remains an explicit zero range")
    encrypted = parsed(flags=0x4000)
    plan = mft.streams(encrypted)[0]
    check(plan.encrypted and not plan.direct_mapping, "EFS state remains explicit")
    rejects(lambda: mft.open_stream(encrypted, plan), "NTFS_EFS_PLAINTEXT_UNAVAILABLE")
    foreign = parsed(); foreign.ntfs = object()
    rejects(lambda: mft.streams(foreign), "NTFS_RECORD_OWNER_CHANGED")
    first = parsed()
    other = parsed(first=0)
    first.attributes[ATTRIBUTE_TYPE_CODE.DATA] += other.attributes[ATTRIBUTE_TYPE_CODE.DATA]
    rejects(lambda: mft.streams(first), "NTFS_STREAM_VCN_GAP_OR_OVERLAP")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependency-root", type=Path, required=True)
    parser.add_argument("--native-root", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.dependency_root.absolute()))
    boundaries()
    native(args.native_root.absolute())
    print(f"PASS NtfsVolumeReader: {checks} checks; bounded read-only logical MFT adapter, "
          "independent three-run NTFS fixture and known resident/nonresident bytes; "
          "no controller/continuation/portable/device claim")


if __name__ == "__main__":
    main()
