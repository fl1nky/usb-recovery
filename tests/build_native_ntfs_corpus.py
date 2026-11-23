# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authored NTFS stream layouts over the pinned, independently parsed sample.

These are explicit metadata edits, not operating-system deletions or device
evidence. Expected content comes from the authoring inputs, never recovery output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "2492f587dae8284adc3c1fccadb687c0aa55b932281c5e07bc8ae004c4c3b563"
CLUSTER = 4096


def digest(data):
    return hashlib.sha256(data).hexdigest()


def align(value):
    return (value + 7) & ~7


def resident(name, value, instance):
    text = name.encode("utf-16le")
    start = align(24 + len(text))
    result = bytearray(align(start + len(value)))
    struct.pack_into("<IIBBHHH", result, 0, 0x80, len(result), 0, len(text) // 2, 24 if text else 0, 0, instance)
    struct.pack_into("<IHBB", result, 16, len(value), start, 0, 0)
    result[24:24 + len(text)] = text
    result[start:start + len(value)] = value
    return result


def nonresident(runs, size, initialized, instance=4):
    pairs = bytearray()
    previous = 0
    for lcn, count in runs:
        if lcn is None:
            pairs += b"\x02" + struct.pack("<H", count)
        else:
            pairs += b"\x22" + struct.pack("<Hh", count, lcn - previous)
            previous = lcn
    pairs += b"\0"
    flags = 0x8000 if any(lcn is None for lcn, _ in runs) else 0
    mapping_at = 72 if flags else 64
    result = bytearray(align(mapping_at + len(pairs)))
    struct.pack_into("<IIBBHHH", result, 0, 0x80, len(result), 1, 0, 0, flags, instance)
    struct.pack_into("<QQHHIQQQ", result, 16, 0, sum(count for _, count in runs) - 1, mapping_at, 0, 0,
                     sum(count for _, count in runs) * CLUSTER, size, initialized)
    if flags:
        struct.pack_into("<Q", result, 64, sum(count for lcn, count in runs if lcn is not None) * CLUSTER)
    result[mapping_at:mapping_at + len(pairs)] = pairs
    return result


def decode_record(raw, position):
    record = bytearray(raw[position:position + 1024])
    usa, count = struct.unpack_from("<HH", record, 4)
    if record[:4] != b"FILE" or count != 3:
        raise ValueError("Unexpected source MFT geometry")
    for index in range(1, count):
        end = index * 512
        if record[end - 2:end] != record[usa:usa + 2]:
            raise ValueError("Invalid source MFT fixup")
        record[end - 2:end] = record[usa + 2 * index:usa + 2 * index + 2]
    return record


def encode_record(raw, position, record):
    usa, count = struct.unpack_from("<HH", record, 4)
    sequence = (struct.unpack_from("<H", record, usa)[0] + 1) & 0xffff or 1
    struct.pack_into("<H", record, usa, sequence)
    for index in range(1, count):
        end = index * 512
        record[usa + 2 * index:usa + 2 * index + 2] = record[end - 2:end]
        struct.pack_into("<H", record, end - 2, sequence)
    raw[position:position + len(record)] = record


def physical(runs, logical):
    for lcn, count in runs:
        length = count * CLUSTER
        if logical < length:
            if lcn is None:
                raise ValueError("Source metadata is sparse")
            return lcn * CLUSTER + logical
        logical -= length
    raise ValueError("Source metadata mapping exceeded")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--dependency-directory", type=Path)
    args = parser.parse_args()
    if args.dependency_directory:
        sys.path.insert(0, str(args.dependency_directory.resolve()))
    sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
    from ntfs_volume import LogicalMft, VolumeWindow
    from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE

    original = args.base.read_bytes()
    if digest(original) != BASE_SHA:
        raise ValueError("Pinned small integration derivative changed")
    destination = args.destination.resolve()
    if destination.exists() or not destination.is_relative_to((ROOT / ".build").resolve()):
        raise ValueError("Fresh corpus directory under project .build required")
    with args.base.open("rb") as source:
        reader = LogicalMft(VolumeWindow(source, 0, len(original)))
        mft = reader.ntfs.mft.get(0)
        mft_runs = list(mft.dataruns())
        mft_bitmap_at = physical(mft.dataruns(attr_type=ATTRIBUTE_TYPE_CODE.BITMAP), 41 // 8)
        bitmap = reader.ntfs.mft.get(6)
        bitmap_at = physical(bitmap.dataruns(), 0)
    record_at = physical(mft_runs, 41 * 1024)
    template = decode_record(original, record_at)
    first = struct.unpack_from("<H", template, 20)[0]
    kept = []
    at = first
    while struct.unpack_from("<I", template, at)[0] != 0xffffffff:
        kind, length = struct.unpack_from("<II", template, at)
        if length < 24 or at + length > 1024:
            raise ValueError("Invalid source attribute boundary")
        if kind != 0x80:
            kept.append(bytes(template[at:at + length]))
        at += length
    destination.mkdir(parents=True)
    payload = bytes((i * 53 + i // CLUSTER) & 255 for i in range(3 * 1024**2 + 123))
    note = "Важная заметка: рецепт пирожков\nстрока два 🍰".encode("utf-8")
    split = [(2048, 256), (3072, 256), (2560, 257)]
    sparse = [(2048, 256), (None, 16), (3072, 256)]
    sparse_size = 528 * CLUSTER - 37
    cases = [
        ("fragmented", split, len(payload), len(payload), [("", payload)]),
        ("fragmented-ads", split, len(payload), len(payload), [("", payload), ("заметка", note)]),
        ("sparse", sparse, sparse_size, sparse_size, None),
        ("sparse-uninitialized", sparse, sparse_size, 300 * CLUSTER + 19, None),
        ("resident-ads", [], 0, 0, [("", b"primary resident contents"), ("заметка", note)]),
    ]
    facts = []
    for name, runs, size, initialized, streams in cases:
        raw = bytearray(original)
        logical = 0
        expected = bytearray()
        for lcn, count in runs:
            amount = min(count * CLUSTER, max(0, size - logical))
            content = bytes((i * 53 + i // CLUSTER) & 255 for i in range(logical, logical + amount))
            if lcn is not None:
                raw[lcn * CLUSTER:lcn * CLUSTER + amount] = content
                for cluster in range(lcn, lcn + count):
                    raw[bitmap_at + cluster // 8] &= ~(1 << (cluster % 8))
            expected += bytes(amount) if lcn is None else content
            logical += amount
        if runs:
            expected[initialized:] = bytes(size - initialized)
            if streams is None:
                streams = [("", bytes(expected))]
            attributes = [nonresident(runs, size, initialized)]
            attributes.extend(resident(label, content, 5 + index) for index, (label, content) in enumerate(streams[1:]))
        else:
            attributes = [resident(label, content, 4 + index) for index, (label, content) in enumerate(streams)]
        record = bytearray(template)
        contents = b"".join(kept + attributes) + b"\xff\xff\xff\xff\0\0\0\0"
        if first + len(contents) > len(record):
            raise ValueError("Authored attributes exceed MFT record")
        record[first:] = bytes(len(record) - first)
        record[first:first + len(contents)] = contents
        struct.pack_into("<I", record, 24, first + len(contents))
        encode_record(raw, record_at, record)
        case = destination / name
        case.mkdir()
        image = case / "image.dd"
        image.write_bytes(raw)
        with image.open("rb") as source:
            reader = LogicalMft(VolumeWindow(source, 0, len(raw)))
            descriptor, parsed = reader.record(41)
            parsed_streams = {row.name: row for row in reader.streams(parsed)}
            if descriptor.deletion_evidence is None or set(parsed_streams) != {label for label, _ in streams}:
                raise ValueError("Independent parser disagrees with authored stream inventory")
            for index, (label, content) in enumerate(streams):
                plan = parsed_streams[label]
                observed = reader.open_stream(parsed, plan).read()
                # Dissect exposes allocated bytes past ValidDataLength. Check
                # that prefix independently; the recovery must zero the tail.
                if observed[:plan.initialized_size] != content[:plan.initialized_size] or plan.size != len(content):
                    raise ValueError("Independent parser disagrees with authored content")
                (case / (str(index) + ".bin")).write_bytes(content)
        facts.append(dict(name=name, image=str(image.relative_to(destination)), image_sha256=digest(raw),
                          initialized=initialized, runs=runs,
                          streams=[dict(name=label, file=name + "/" + str(index) + ".bin", sha256=digest(content), bytes=len(content))
                                   for index, (label, content) in enumerate(streams)]))
    # Allocation and update-sequence controls must not become recoverable
    # messages/files merely because they contain a plausible FILE signature.
    for name in ("bitmap-in-use", "record-in-use", "bad-fixup"):
        raw = bytearray(original)
        if name == "bitmap-in-use":
            raw[mft_bitmap_at] |= 1 << (41 % 8)
        elif name == "record-in-use":
            record = bytearray(template)
            struct.pack_into("<H", record, 22, struct.unpack_from("<H", record, 22)[0] | 1)
            encode_record(raw, record_at, record)
        else:
            raw[record_at + 1022] ^= 1
        case = destination / name
        case.mkdir()
        image = case / "image.dd"
        image.write_bytes(raw)
        with image.open("rb") as source:
            reader = LogicalMft(VolumeWindow(source, 0, len(raw)))
            if name == "bad-fixup":
                try:
                    reader.record(41)
                except ValueError as error:
                    if str(error) != "Fixup mismatch":
                        raise
                else:
                    raise ValueError("Independent parser accepted the corrupt update sequence")
            elif reader.record(41)[0].deletion_evidence is not None:
                raise ValueError("Independent parser accepted contradictory allocation flags")
        facts.append(dict(name=name, image=str(image.relative_to(destination)), image_sha256=digest(raw),
                          initialized=0, runs=[], streams=[]))
    receipt = dict(status="authored_and_independently_parsed", base_sha256=BASE_SHA, cases=facts,
                   source_sha256={name: digest((ROOT / name).read_bytes()) for name in
                                  ("tests/build_native_ntfs_corpus.py", "helpers/recovery_engine/ntfs_volume.py")},
                   authored_deletion_not_os_deletion=True, real_devices_tested=False)
    (destination / "corpus.json").write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    if digest(args.base.read_bytes()) != BASE_SHA:
        raise ValueError("Original input changed")
    print(json.dumps(dict(status=receipt["status"], cases=len(facts))))


if __name__ == "__main__":
    main()
