"""Owned derived MD RAID10 fixtures, not native mdadm/device evidence.

Payload placement uses the inverse (physical -> virtual) mapping in Linux
raid10_find_virt, independently of the product's forward mapping. Metadata is
explicitly derived from a pinned public MD1.2 header. No devices are opened.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import struct
import uuid

from build_raid_md_fixtures import checksum_v1

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "tests/fixtures/raid-md"
CHUNK = 4096
CASES = [("near", 2, n) for n in (2, 3, 5)] + [
    ("near", 3, n) for n in (3, 4, 5)] + [
    ("far", 2, n) for n in (3, 5)] + [("far", 3, 5)] + [
    ("offset", 2, n) for n in (3, 5)] + [("offset", 3, 5)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def block(index):
    return hashlib.shake_256(b"USB Recovery owned RAID10 inverse oracle\0" +
                            struct.pack("<I", index)).digest(CHUNK)


def template_bytes():
    inventory = json.loads((UPSTREAM / "manifest.json").read_text(encoding="utf-8-sig"))
    item = next(v for v in inventory["files"] if v["name"] == "md-raid10-1.bin.gz")
    compressed = (UPSTREAM / item["name"]).read_bytes()
    if digest(compressed) != item["sha256"]:
        raise ValueError("Pinned upstream compressed hash mismatch")
    original = gzip.decompress(compressed)
    if len(original) != item["raw_bytes"] or digest(original) != item["raw_sha256"]:
        raise ValueError("Pinned upstream raw hash mismatch")
    return original[4096:8192], inventory["commit"]


def build(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("Fixture destination must be empty")
    template, commit = template_bytes()
    result = {"schema": 1, "origin": "owned_derived_inverse_mapping_not_native",
              "upstream_commit": commit, "template_sha256": digest(template),
              "mapping_reference": "https://github.com/torvalds/linux/blob/v6.12/drivers/md/raid10.c",
              "cases": []}
    for kind, copies, members in CASES:
        name = f"md-{kind}-{copies}-{members}"
        directory = destination / name
        directory.mkdir()
        near, far = (copies, 1) if kind == "near" else (1, copies)
        component_chunks = 17
        stride = component_chunks // far
        logical_chunks = component_chunks // far * members // near
        logical = b"".join(block(i) for i in range(logical_chunks))
        (directory / "expected.bin").write_bytes(logical)
        coverage = [0] * logical_chunks
        entry = {"name": name, "layout": f"md-{kind}-{copies}", "members": members,
                 "copies": copies, "chunk": CHUNK, "component": component_chunks * CHUNK,
                 "bytes": len(logical), "sha256": digest(logical), "files": []}
        for disk in range(members):
            offset = 16384 + disk * 4096
            data = bytearray(offset + component_chunks * CHUNK + (disk + 1) * 4096)
            for physical in range(component_chunks):
                # Kernel inverse mapping, with original far_set_size=raid_disks.
                if kind == "offset":
                    base, copy = divmod(physical, far)
                else:
                    copy, base = divmod(physical, stride)
                device = (disk - copy * near) % members
                index = (base * members + device) // near
                if copy < far and index < logical_chunks:
                    data[offset + physical * CHUNK:offset + (physical + 1) * CHUNK] = block(index)
                    coverage[index] += 1
            metadata = bytearray(template)
            metadata[16:32] = uuid.uuid5(uuid.NAMESPACE_URL, "owned:" + name).bytes_le
            metadata[32:64] = name.encode().ljust(32, b"\0")
            struct.pack_into("<I", metadata, 8, 0)
            layout = near | (far << 8) | ((kind == "offset") << 16)
            for at, value in ((72, 10), (76, layout), (88, CHUNK // 512),
                              (92, members), (160, disk)):
                struct.pack_into("<I", metadata, at, value)
            for at, value in ((80, component_chunks * CHUNK // 512), (128, offset // 512),
                              (136, component_chunks * CHUNK // 512), (144, 8),
                              (200, 100), (208, 0xffffffffffffffff)):
                struct.pack_into("<Q", metadata, at, value)
            metadata[168:184] = uuid.uuid5(uuid.NAMESPACE_URL, f"owned:{name}:{disk}").bytes_le
            maximum = struct.unpack_from("<I", metadata, 220)[0]
            for role in range(maximum):
                struct.pack_into("<H", metadata, 256 + role * 2, role if role < members else 0xffff)
            data[4096:8192] = metadata
            checksum_v1(data, 4096)
            filename = f"member-{disk}.bin"
            (directory / filename).write_bytes(data)
            entry["files"].append({"name": filename, "offset": offset,
                                   "bytes": len(data), "sha256": digest(data)})
        if any(value != copies for value in coverage):
            raise ValueError("Inverse oracle did not produce exactly all copies")
        result["cases"].append(entry)
    pinned = ROOT / "tests/fixtures/raid10/manifest.json"
    if result != json.loads(pinned.read_text(encoding="utf-8-sig")):
        raise ValueError("Derived bytes differ from pinned source inventory")
    (destination / "manifest.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def verify(destination):
    destination = Path(destination).absolute()
    for parent in (destination, *destination.parents):
        info = parent.lstat()
        if parent.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Fixture links are not accepted")
    template, commit = template_bytes()
    pinned_text = (ROOT / "tests/fixtures/raid10/manifest.json").read_text(encoding="utf-8-sig")
    pinned = json.loads(pinned_text)
    if pinned["upstream_commit"] != commit or pinned["template_sha256"] != digest(template):
        raise ValueError("Native header source changed")
    if (destination / "manifest.json").read_text(encoding="utf-8-sig") != pinned_text:
        raise ValueError("Fixture inventory differs from pinned bytes")
    expected_files = {"manifest.json"}
    expected_directories = set()
    for entry in pinned["cases"]:
        expected_directories.add(entry["name"])
        for row in entry["files"] + [{"name": "expected.bin", "bytes": entry["bytes"], "sha256": entry["sha256"]}]:
            relative = entry["name"] + "/" + row["name"]
            path = destination / relative
            info = path.lstat()
            if not path.is_file() or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Fixture is not a regular file")
            if info.st_size != row["bytes"] or digest(path.read_bytes()) != row["sha256"]:
                raise ValueError("Fixture data differs from pinned bytes: " + relative)
            expected_files.add(relative)
    actual_files, actual_directories = set(), set()
    for path in destination.rglob("*"):
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Fixture links are not accepted")
        relative = path.relative_to(destination).as_posix()
        (actual_directories if path.is_dir() else actual_files).add(relative)
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ValueError("Fixture inventory has missing or extra entries")
    return pinned


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--destination", type=Path)
    mode.add_argument("--verify", type=Path)
    args = parser.parse_args()
    report = verify(args.verify) if args.verify else build(args.destination)
    print("Verified" if args.verify else "Prepared", len(report["cases"]), "owned inverse-mapped RAID10 cases; no native device evidence")
