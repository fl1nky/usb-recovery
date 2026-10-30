"""Offline Linux MD fixtures from pinned independent upstream component images.

No md device, loop device, system service or private drive is used. The gzip
archives are checked against their pinned SHA256 before bounded extraction.
Derived cases explicitly alter geometry/state; they are not mdadm executions.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import shutil
import struct
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/raid-md"
PIN = "d2da189112cae3a627f96d9de78341193eb6dc52"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checksum_v1(raw, at):
    count = 256 + struct.unpack_from("<I", raw, at + 220)[0] * 2
    struct.pack_into("<I", raw, at + 216, 0)
    words = count // 4
    total = sum(struct.unpack_from("<" + "I" * words, raw, at))
    if count % 4:
        total += struct.unpack_from("<H", raw, at + words * 4)[0]
    struct.pack_into("<I", raw, at + 216, ((total & 0xffffffff) + (total >> 32)) & 0xffffffff)


def build(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("Fixture destination must be empty")
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8-sig"))
    if manifest["commit"] != PIN or len(manifest["files"]) != 23:
        raise ValueError("Unexpected pinned upstream inventory")
    rows = []
    originals = destination / "upstream"
    originals.mkdir()
    for item in manifest["files"]:
        path = FIXTURES / item["name"]
        if path.name != item["name"]:
            raise ValueError("Unsafe upstream fixture name")
        data = path.read_bytes()
        if len(data) != item["bytes"] or sha(data) != item["sha256"]:
            raise ValueError("Upstream compressed fixture checksum mismatch")
        with gzip.open(path, "rb") as source:
            plain = source.read(128 * 1024 * 1024 + 1)
        if len(plain) != item["raw_bytes"] or len(plain) > 128 * 1024 * 1024 or sha(plain) != item["raw_sha256"]:
            raise ValueError("Upstream raw fixture checksum mismatch")
        name = item["name"][:-3]
        (originals / name).write_bytes(plain)
        rows.append(dict(name="upstream/" + name, sha256=sha(plain), bytes=len(plain), origin="independent_published_upstream", source=item["url"]))

    def save(family, number, data, origin):
        directory = destination / family
        directory.mkdir(exist_ok=True)
        name = family + "/member" + str(number) + ".bin"
        (destination / name).write_bytes(data)
        rows.append(dict(name=name, sha256=sha(data), bytes=len(data), origin="derived_geometry_or_state", source=origin))

    for minor in (0, 1):
        for number in (1, 2):
            source = originals / f"md-raid1-{number}.bin"
            original = source.read_bytes()
            metadata = bytearray(original[4096:8192])
            old_offset = struct.unpack_from("<Q", metadata, 128)[0] * 512
            count = struct.unpack_from("<Q", metadata, 80)[0] * 512
            new_offset = 0 if minor == 0 else 8192
            data = bytearray(count + 8192)
            data[new_offset:new_offset + count] = original[old_offset:old_offset + count]
            super_offset = count if minor == 0 else 0
            struct.pack_into("<Q", metadata, 128, new_offset // 512)
            struct.pack_into("<Q", metadata, 136, count // 512)
            struct.pack_into("<Q", metadata, 144, super_offset // 512)
            data[super_offset:super_offset + 4096] = metadata
            checksum_v1(data, super_offset)
            save("version1-" + str(minor), number, data, source.name + "; explicit relocation, self-contained data copied exactly")

    # Retain exactly the first uniform striping zone of the independent RAID0.
    for number in (1, 2, 3):
        source = originals / f"md-raid0-{number}.bin"
        data = bytearray(source.read_bytes()[:3 * 1024 * 1024])
        struct.pack_into("<Q", data, 4096 + 136, 2048)
        checksum_v1(data, 4096)
        save("raid0-uniform-zone", number, data, source.name + "; first one-MiB data zone retained, MD data_size cropped")

    # The original published RAID6 is not fully synchronized. This variant
    # changes only the state field to exercise candidate mapping, not to claim
    # successful independent data/parity recovery.
    for number in (1, 2, 3, 4):
        source = originals / f"md-raid6-{number}.bin"
        data = bytearray(source.read_bytes())
        struct.pack_into("<Q", data, 4096 + 208, 0xffffffffffffffff)
        checksum_v1(data, 4096)
        save("raid6-synced-state", number, data, source.name + "; synthetic resync state only; data integrity unproved")

    # Four-member adjacent near=2 RAID10 metadata is derived from the
    # independent two-member sample. This checks parser geometry only.
    for number in range(4):
        source = originals / f"md-raid10-{number % 2 + 1}.bin"
        data = bytearray(source.read_bytes())
        struct.pack_into("<I", data, 4096 + 92, 4)
        struct.pack_into("<I", data, 4096 + 160, number)
        data[4096 + 168:4096 + 184] = uuid.uuid5(uuid.NAMESPACE_URL, "recovery-owned-raid10-" + str(number)).bytes_le
        struct.pack_into("<Q", data, 4096 + 208, 0xffffffffffffffff)
        for slot in range(128):
            struct.pack_into("<H", data, 4096 + 256 + slot * 2, slot if slot < 4 else 0xffff)
        checksum_v1(data, 4096)
        save("raid10-four-member", number, data, source.name + "; synthetic member/role count and clean state, not an mdadm run")

    # Byte-swapping legacy records follows the explicitly documented host-
    # endian field layout, including the special events hi/lo placement.
    for number in (1, 2):
        source = originals / f"md-90-{number}.bin"
        data = bytearray(source.read_bytes())
        at = (len(data) // 65536 - 1) * 65536
        words = list(struct.unpack_from("<1024I", data, at))
        for first, second in ((39, 40), (41, 42)):
            words[first], words[second] = words[second], words[first]
        words[38] = 0
        total = sum(words)
        words[38] = ((total & 0xffffffff) + (total >> 32)) & 0xffffffff
        struct.pack_into(">1024I", data, at, *words)
        save("legacy-big-endian", number, data, source.name + "; explicit legacy host-endian field conversion")

    result = dict(schema=1, upstream_commit=PIN, scope="Published independent upstream images plus separately labeled derived geometry/state fixtures; no local mdadm/real device run", files=rows)
    (destination / "manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    result = build(parser.parse_args().destination)
    print("Prepared", len(result["files"]), "owned/published Linux MD fixture files")