# SPDX-License-Identifier: AGPL-3.0-or-later
"""Create an explicit, authored large-file deletion derivative, never a device.

The input is the pinned Dissect native NTFS sample. Its original filesystem is
retained; this derivative expands its geometry, extends $Bitmap, and replaces
record 41's resident DATA with a known nonresident stream in the added area.
This is neither an operating-system deletion nor an independent deleted sample.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).absolute().parents[1]
ORIGINAL_SHA256 = "3cf887ae87b7f44f1faee71838b3d79b811097a0a1a4962e8e0fd132bc8dfbc7"


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--dependency-directory", type=Path)
    args = parser.parse_args()
    if args.destination.exists():
        raise ValueError("A fresh fixture directory is required")
    if args.dependency_directory:
        sys.path.insert(0, str(args.dependency_directory.resolve()))
    sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
    from ntfs_volume import LogicalMft, VolumeWindow
    from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE as A

    original = args.original.read_bytes()
    if sha(original) != ORIGINAL_SHA256:
        raise ValueError("Independent source fixture hash mismatch")
    with args.original.open("rb") as source:
        reader = LogicalMft(VolumeWindow(source, 0, len(original)))
        geometry = reader.geometry
        if geometry.sector_bytes != 512 or geometry.cluster_bytes != 4096 or geometry.record_bytes != 1024:
            raise ValueError("Unexpected pinned source geometry")
        mft = reader.ntfs.mft.get(0)
        mft_data_at = mft.attributes[A.DATA][0].header.offset

        def physical(runs, logical):
            for lcn, count in runs:
                size = count * geometry.cluster_bytes
                if logical < size:
                    if lcn is None:
                        raise ValueError("Missing source fixture segment")
                    return lcn * geometry.cluster_bytes + logical
                logical -= size
            raise ValueError("Source fixture mapping exceeded")

        record_at = physical(mft.dataruns(), 41 * geometry.record_bytes)
        mft_record_at = physical(mft.dataruns(), 0)
        bitmap_record_at = physical(mft.dataruns(), 6 * geometry.record_bytes)
        mft_bitmap_at = physical(mft.dataruns(attr_type=A.BITMAP), 41 // 8)
        record = reader.ntfs.mft.get(41)
        bitmap_record = reader.ntfs.mft.get(6)
        data_attribute = record.attributes[A.DATA][0]
        bitmap_attribute = bitmap_record.attributes[A.DATA][0]
        if not data_attribute.resident or bitmap_attribute.resident:
            raise ValueError("Unexpected pinned source attributes")
        data_at = data_attribute.header.offset
        bitmap_data_at = bitmap_attribute.header.offset
        bitmap_at = physical(bitmap_record.dataruns(), 0)

    expanded = 16 * 1024**2
    raw = bytearray(original)
    raw.extend(bytes(expanded - len(raw)))
    volume_bytes = expanded - 512
    payload = bytes((i * 29 + i // 4096) & 255 for i in range(3 * 1024**2 + 123))
    clusters = (len(payload) + 4095) // 4096
    lcn = 2048

    def decode(at):
        data = bytearray(raw[at:at + 1024])
        usa, count = struct.unpack_from("<HH", data, 4)
        if count != 3 or data[:4] != b"FILE":
            raise ValueError("Invalid pinned MFT fixups")
        for index in range(1, count):
            end = index * 512
            if data[end - 2:end] != data[usa:usa + 2]:
                raise ValueError("Pinned MFT fixup mismatch")
            data[end - 2:end] = data[usa + 2 * index:usa + 2 * index + 2]
        return data

    def encode(at, data):
        usa, count = struct.unpack_from("<HH", data, 4)
        sequence = (struct.unpack_from("<H", data, usa)[0] + 1) & 0xFFFF or 1
        struct.pack_into("<H", data, usa, sequence)
        for index in range(1, count):
            end = index * 512
            data[usa + 2 * index:usa + 2 * index + 2] = data[end - 2:end]
            struct.pack_into("<H", data, end - 2, sequence)
        raw[at:at + 1024] = data

    data = decode(record_at)
    old_length = struct.unpack_from("<I", data, data_at + 4)[0]
    instance = struct.unpack_from("<H", data, data_at + 14)[0]
    attribute = bytearray(72)
    struct.pack_into("<IIBBHHH", attribute, 0, 0x80, len(attribute), 1, 0, 0, 0, instance)
    struct.pack_into("<QQHHIQQQ", attribute, 16, 0, clusters - 1, 64, 0, 0, clusters * 4096, len(payload), len(payload))
    attribute[64:70] = bytes([0x22]) + struct.pack("<HH", clusters, lcn) + b"\0"
    used = struct.unpack_from("<I", data, 24)[0]
    tail = data[data_at + old_length:used]
    replacement = attribute + tail
    if data_at + len(replacement) > len(data):
        raise ValueError("Replacement attribute exceeds MFT record")
    data[data_at:used] = bytes(used - data_at)
    data[data_at:data_at + len(replacement)] = replacement
    struct.pack_into("<I", data, 24, data_at + len(replacement))
    struct.pack_into("<H", data, 22, struct.unpack_from("<H", data, 22)[0] & ~1)
    encode(record_at, data)
    raw[mft_bitmap_at] &= ~(1 << (41 % 8))

    data = decode(bitmap_record_at)
    bitmap_bytes = ((volume_bytes // 4096) + 7) // 8
    if bitmap_bytes > struct.unpack_from("<Q", data, bitmap_data_at + 40)[0]:
        raise ValueError("Expanded bitmap exceeds original allocation")
    struct.pack_into("<QQ", data, bitmap_data_at + 48, bitmap_bytes, bitmap_bytes)
    encode(bitmap_record_at, data)
    for cluster in range(geometry.volume_bytes // 4096, volume_bytes // 4096):
        raw[bitmap_at + cluster // 8] &= ~(1 << (cluster % 8))
    raw[lcn * 4096:lcn * 4096 + len(payload)] = payload
    struct.pack_into("<Q", raw, 40, volume_bytes // 512)
    raw[-512:] = raw[:512]

    args.destination.mkdir(parents=True)
    resident = bytearray(original)
    struct.pack_into("<H", resident, record_at + 22, struct.unpack_from("<H", resident, record_at + 22)[0] & ~1)
    resident[mft_bitmap_at] &= ~(1 << (41 % 8))
    struct.pack_into("<H", resident, record_at + data_at + 12, 0)
    with (args.destination / "deleted-resident-derived.dd").open("xb") as output:
        output.write(resident)
    image = args.destination / "deleted-large-derived.dd"
    with image.open("xb") as output:
        output.write(raw)
    with image.open("rb") as source:
        independent = LogicalMft(VolumeWindow(source, 0, len(raw)))
        descriptor, parsed = independent.record(41)
        streams = independent.streams(parsed)
        if descriptor.deletion_evidence is None or len(streams) != 1 or independent.open_stream(parsed, streams[0]).read() != payload:
            raise ValueError("Independent logical NTFS parser rejected authored fixture")
    (args.destination / "expected.bin").write_bytes(payload)
    receipt = dict(
        scope="Authored expansion and metadata deletion derivative; independently parsed, not an OS deletion or device sample",
        original_sha256=ORIGINAL_SHA256, image_sha256=sha(raw), expected_sha256=sha(payload),
        record=41, file_bytes=len(payload), volume_bytes=volume_bytes, cluster_bytes=4096,
        data_lcn=lcn, allocated_clusters=clusters,
        resident_image_sha256=sha(resident),
    )
    # Integration cases use a separate 64-record MFT derivative so exercising
    # session/partition/report transitions does not repeat thousands of unrelated
    # record checkpoints. The full 2304-record fixtures remain mandatory above.
    data = decode(mft_record_at)
    struct.pack_into("<QQ", data, mft_data_at + 48, 64 * 1024, 64 * 1024)
    encode(mft_record_at, data)
    mirror_at = geometry.mirror_lcn * geometry.cluster_bytes
    raw[mirror_at:mirror_at + 1024] = raw[mft_record_at:mft_record_at + 1024]
    small = args.destination / "deleted-small-mft-derived.dd"
    with small.open("xb") as output:
        output.write(raw)
    with small.open("rb") as source:
        independent = LogicalMft(VolumeWindow(source, 0, len(raw)))
        descriptor, parsed = independent.record(41)
        streams = independent.streams(parsed)
        if independent.record_count != 64 or descriptor.deletion_evidence is None or independent.open_stream(parsed, streams[0]).read() != payload:
            raise ValueError("Independent parser rejected integration fixture")
    receipt["integration_image_sha256"] = sha(raw)
    receipt["integration_mft_records"] = 64
    (args.destination / "fixture.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    if sha(args.original.read_bytes()) != ORIGINAL_SHA256:
        raise ValueError("Original source changed")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
