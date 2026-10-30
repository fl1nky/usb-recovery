"""Independent ext4 fixtures made by real e2fsprogs, never by recovery code.

Windows: python tests/ext4_fixture_generator.py --destination .build/ext4-fixtures-01
Requires an existing WSL distribution with mke2fs/debugfs (no mount/install).
Sources: kernel.org/doc/html/latest/filesystems/ext4/ and e2fsprogs debugfs.
Only newly created synthetic image files are opened for writing.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

TIME = "1700000000"
UUID = "11111111-2222-3333-4444-555555555555"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def crc32c(seed, data):
    for value in data:
        seed ^= value
        for _ in range(8):
            seed = (seed >> 1) ^ (0x82F63B78 if seed & 1 else 0)
    return seed


def geometry(image, inode):
    data = image.read_bytes()
    sb = data[1024:2048]
    block = 1024 << u32(sb, 24)
    inode_size = u16(sb, 88)
    descriptor_size = u16(sb, 254) if u32(sb, 96) & 0x80 else 32
    group, index = divmod(inode - 1, u32(sb, 40))
    descriptor = (u32(sb, 20) + 1) * block + group * descriptor_size
    inode_table = u32(data, descriptor + 8)
    inode_offset = inode_table * block + index * inode_size
    record = data[inode_offset:inode_offset + inode_size]
    seed = u32(sb, 0x270) if u32(sb, 96) & 0x2000 else crc32c(0xFFFFFFFF, sb[0x68:0x78])
    return {"data": data, "block": block, "inode_size": inode_size, "descriptor": descriptor,
            "inode_offset": inode_offset, "record": record, "seed": seed, "blocks": u32(sb, 4)}


def repair_inode(data, details, inode):
    offset, size = details["inode_offset"], details["inode_size"]
    record = bytearray(data[offset:offset + size])
    record[124:126] = b"\0\0"
    high = size >= 132 and u16(record, 128) >= 4
    if high:
        record[130:132] = b"\0\0"
    checksum = crc32c(crc32c(crc32c(details["seed"], struct.pack("<I", inode)), record[100:104]), record)
    struct.pack_into("<H", record, 124, checksum & 65535)
    if high:
        struct.pack_into("<H", record, 130, checksum >> 16)
    data[offset:offset + size] = record


def repair_super(data):
    struct.pack_into("<I", data, 1024 + 0x3FC, crc32c(0xFFFFFFFF, data[1024:1024 + 0x3FC]))


def repair_group(data, details, group=0):
    size = u16(data, 1024 + 254)
    offset = details["descriptor"] + group * size
    record = bytearray(data[offset:offset + size]); record[30:32] = b"\0\0"
    checksum = crc32c(crc32c(details["seed"], struct.pack("<I", group)), record)
    struct.pack_into("<H", record, 30, checksum & 65535)
    data[offset:offset + size] = record


def package_fixtures(source, destination):
    """Preserve real-tool images in a small, deterministic, offline bundle."""
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=False)
    manifest.pop("commands", None)
    manifest.pop("distribution", None)
    manifest["compressed_images"] = {}
    for name in sorted({case["image"] for case in manifest["cases"]}):
        data = (source / name).read_bytes()
        if sha(data) != next(case["sha256"] for case in manifest["cases"] if case["image"] == name):
            raise ValueError("Source fixture changed before packaging")
        target = destination / (name + ".gz")
        with target.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
                compressed.write(data)
        manifest["compressed_images"][name] = {"archive": target.name, "archive_sha256": sha(target.read_bytes()), "bytes": len(data)}
    manifest["provenance"] = "Images generated from synthetic regular files by e2fsprogs 1.47.3; no mounted/personal device. Header hints deliberately include damaged synthetic content and are not decoded-image controls."
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "PROVENANCE.txt").write_text("Synthetic test images and fixture manifest were created for the USB-Recovery project from programmatically defined data. No personal data, third-party authored documents or third-party program binaries are embedded. This provenance file does not define or grant a separate license.\n", encoding="utf-8")
    print(json.dumps({"bundle": str(destination.resolve()), "files": len(manifest["compressed_images"]), "bytes": sum(p.stat().st_size for p in destination.iterdir())}))


def extract_fixtures(source, destination):
    """Expand only manifest-listed bounded regular files; never invoke WSL."""
    document = source / "manifest.json"
    if document.stat().st_size > 1024 * 1024:
        raise ValueError("Fixture manifest too large")
    manifest = json.loads(document.read_text(encoding="utf-8"))
    images = manifest["compressed_images"]
    if len(images) > 128:
        raise ValueError("Too many fixture images")
    destination.mkdir(parents=True, exist_ok=False)
    total = 0
    for name, details in images.items():
        archive = details["archive"]
        if Path(name).name != name or Path(archive).name != archive or not re.fullmatch(r"[a-z0-9-]+\.dd", name) or archive != name + ".gz":
            raise ValueError("Unsafe fixture filename")
        expected = int(details["bytes"]); total += expected
        if expected < 2048 or expected > 64 * 1024 * 1024 or total > 2 * 1024 * 1024 * 1024:
            raise ValueError("Fixture expansion limit")
        packed = source / archive
        if packed.stat().st_size > 64 * 1024 * 1024 or sha(packed.read_bytes()) != details["archive_sha256"]:
            raise ValueError("Fixture archive hash mismatch")
        target, partial = destination / name, destination / (name + ".partial")
        count = 0; digest = hashlib.sha256()
        try:
            with gzip.open(packed, "rb") as compressed, partial.open("xb") as output:
                while True:
                    block = compressed.read(min(1024 * 1024, expected - count + 1))
                    if not block:
                        break
                    count += len(block)
                    if count > expected:
                        raise ValueError("Fixture exceeds declared bytes")
                    output.write(block); digest.update(block)
            reference = next(case["sha256"] for case in manifest["cases"] if case["image"] == name)
            if count != expected or digest.hexdigest() != reference:
                raise ValueError("Fixture image hash/length mismatch")
            partial.rename(target)
        finally:
            partial.unlink(missing_ok=True)
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"destination": str(destination.resolve()), "cases": len(manifest["cases"]), "offline": True}))


class Generator:
    def __init__(self, destination, distribution):
        destination.mkdir(parents=True, exist_ok=False)
        self.root, self.distribution = destination.resolve(), distribution
        self.calls, self.cases, self.counter = [], [], 0
        (self.root / "commands").mkdir()
        self.payload = self.root / "payload.bin"
        self.payload.write_bytes(bytes((i * 29 + 7) % 256 for i in range(70001)))

    def linux(self, path):
        text = str(path.resolve())
        if len(text) < 3 or text[1:3] != ":\\":
            raise ValueError("Expected ordinary Windows file path")
        return "/mnt/host/" + text[0].lower() + "/" + text[3:].replace("\\", "/")

    def run(self, args):
        result = subprocess.run(["wsl.exe", "-d", self.distribution, "--exec", "/usr/bin/env",
            "LC_ALL=C", "E2FSPROGS_FAKE_TIME=" + TIME] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
        self.calls.append({"arguments": args, "returncode": result.returncode,
                           "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)})
        self.last_stderr = result.stderr.decode("utf-8", errors="replace").replace("\0", "")
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace")[-2000:])
        return result.stdout.decode("utf-8", errors="replace")

    def debug(self, image, commands):
        self.counter += 1
        script = self.root / "commands" / ("%04d.txt" % self.counter)
        script.write_text("set_current_time " + TIME + "\n" + "\n".join(commands) + "\n", encoding="utf-8")
        return self.run(["/usr/sbin/debugfs", "-w", "-f", self.linux(script), self.linux(image)])

    def filesystem(self, name, legacy=False, block_size=1024, features=None):
        image = self.root / (name + ".dd")
        with image.open("xb") as stream:
            stream.truncate(32 * 1024 * 1024)
        args = ["/sbin/mke2fs", "-q", "-F", "-t", "ext4", "-b", str(block_size), "-I", "256", "-N", "256", "-U", UUID,
                "-E", "lazy_itable_init=0,lazy_journal_init=0,hash_seed=" + UUID]
        if legacy:
            args += ["-O", "^extent,^64bit,^flex_bg,^metadata_csum_seed"]
        elif features:
            args += ["-O", features]
        self.run(args + [self.linux(image)])
        return image

    def write(self, image, payload=None, target="/old.bin"):
        output = self.debug(image, ["write " + self.linux(payload or self.payload) + " " + target])
        return int(re.search(r"Allocated inode:\s*(\d+)", output).group(1))

    def add(self, name, image, inode, outcome, payload=None, **extra):
        self.cases.append({"name": name, "image": image.name, "target_inode": inode,
                           "sha256": sha(image.read_bytes()), "outcome": outcome,
                           "payload_sha256": sha((payload or self.payload).read_bytes()), **extra})

    def clone(self, source, name):
        destination = self.root / (name + ".dd")
        shutil.copyfile(source, destination)
        return destination

    def build(self):
        base = self.filesystem("extent-deleted")
        inode = self.write(base)
        live = self.clone(base, "live-control")
        self.add("live-control", live, inode, "live")
        self.debug(base, ["rm /old.bin"])
        self.add("extent-deleted", base, inode, "recover")
        g = geometry(base, inode)
        first = u32(g["record"], 60)
        for name, offset in [("bad-super-checksum", 1024 + 0x68), ("bad-group-checksum", g["descriptor"] + 8),
                             ("bad-inode-checksum", g["inode_offset"] + 100),
                             ("bad-inode-bitmap-checksum", u32(g["data"], g["descriptor"] + 4) * g["block"] + 5),
                             ("bad-block-bitmap-checksum", u32(g["data"], g["descriptor"]) * g["block"] + 5)]:
            image = self.clone(base, name)
            data = bytearray(image.read_bytes()); data[offset] ^= 1; image.write_bytes(data)
            self.add(name, image, inode, "reject")
        image = self.clone(base, "allocated-data-conflict")
        self.debug(image, ["setb " + str(first)])
        self.add("allocated-data-conflict", image, inode, "reject")
        image = self.clone(base, "free-data-overwritten")
        with image.open("r+b") as stream:
            stream.seek(first * g["block"] + 19); stream.write(b"OVERWRITTEN-UNKNOWN-HISTORY")
        self.add("free-data-overwritten", image, inode, "candidate_current_bytes")
        image = self.clone(base, "extent-bounds-valid-inode-crc")
        data = bytearray(image.read_bytes()); struct.pack_into("<I", data, g["inode_offset"] + 60, g["blocks"] + 100)
        repair_inode(data, g, inode); image.write_bytes(data)
        self.add("extent-bounds-valid-inode-crc", image, inode, "reject")
        for name, physical in [("data-primary-superblock-valid-crc", 1), ("data-backup-superblock-valid-crc", 8193)]:
            image = self.clone(base, name); data = bytearray(image.read_bytes())
            struct.pack_into("<I", data, g["inode_offset"] + 60, physical)
            repair_inode(data, g, inode); image.write_bytes(data)
            self.add(name, image, inode, "reject", reason="data_block_bounds_or_reserved")
        for name, relative, value, reason in [
            ("inode-table-overlaps-gdt-valid-crc", 8, 2, "group_metadata_overlaps_super_or_gdt"),
            ("bitmap-overlaps-super-valid-crc", 0, 1, "group_metadata_overlaps_super_or_gdt"),
            ("unsupported-group-flags-valid-crc", 0x12, 0x8000, "group_flags_unsupported")]:
            image = self.clone(base, name); data = bytearray(image.read_bytes())
            struct.pack_into("<H" if relative == 0x12 else "<I", data, g["descriptor"] + relative, value)
            repair_group(data, g); image.write_bytes(data)
            self.add(name, image, inode, "reject", skipped=reason)
        image = self.clone(base, "cross-group-metadata-overlap-valid-crc"); data = bytearray(image.read_bytes())
        second_descriptor = g["descriptor"] + u16(data, 1024 + 254)
        struct.pack_into("<I", data, second_descriptor + 8, u32(data, g["descriptor"] + 8))
        repair_group(data, g, 1); image.write_bytes(data)
        self.add("cross-group-metadata-overlap-valid-crc", image, inode, "reject", skipped="cross_group_metadata_overlap")
        for name, offset, value, reason in [
            ("unknown-ro-feature-valid-crc", 0x64, u32(g["data"], 1024 + 0x64) | 0x80000000, "unsupported_features_or_journal_replay_required"),
            ("unknown-revision-valid-crc", 0x4C, 2, "superblock_geometry_invalid")]:
            image = self.clone(base, name); data = bytearray(image.read_bytes())
            struct.pack_into("<I", data, 1024 + offset, value); repair_super(data); image.write_bytes(data)
            self.add(name, image, inode, "reject", volume_reason=reason)
        image = self.clone(base, "unaligned-extra-isize-valid-crc"); data = bytearray(image.read_bytes())
        struct.pack_into("<H", data, g["inode_offset"] + 128, 1); repair_inode(data, g, inode); image.write_bytes(data)
        self.add("unaligned-extra-isize-valid-crc", image, inode, "reject", skipped="inode_checksum_invalid")
        wrapped = self.root / "partition-offset.dd"
        with wrapped.open("xb") as stream:
            mbr = bytearray(512); mbr[446 + 4] = 0x83
            struct.pack_into("<II", mbr, 446 + 8, 2048, base.stat().st_size // 512); mbr[510:] = b"\x55\xaa"
            stream.write(mbr); stream.truncate(1024 * 1024); stream.seek(1024 * 1024); stream.write(base.read_bytes())
        self.add("partition-offset", wrapped, inode, "recover", partition_offset=1024 * 1024)

        signatures = [("jpeg", b"\xff\xd8\xff\xe1", ".jpg"), ("png", b"\x89PNG\r\n\x1a\n", ".png"),
                      ("gif", b"GIF89a", ".gif"), ("webp", b"RIFF\0\0\0\0WEBP", ".webp"),
                      ("pdf", b"%PDF-1.7", ".pdf"), ("zip", b"PK\x03\x04", ".zip")]
        for kind, signature, extension in signatures:
            image = self.clone(base, "signature-hint-" + kind)
            with image.open("r+b") as stream:
                stream.seek(first * g["block"]); stream.write(signature)
            self.add("signature-hint-" + kind, image, inode, "candidate_current_bytes", extension=extension)

        unicode_image = self.filesystem("unicode-retained-link")
        self.debug(unicode_image, ["mkdir /архив"])
        unicode_inode = self.write(unicode_image, target="/архив/прабабушка.txt")
        self.debug(unicode_image, ["sif /архив/прабабушка.txt links_count 0", "kill_file /архив/прабабушка.txt"])
        self.add("unicode-retained-link", unicode_image, unicode_inode, "recover", expected_name="прабабушка.txt")
        directory_inode = int(re.search(r"Inode:\s*(\d+)", self.debug(unicode_image, ["stat /архив"])).group(1))
        directory = geometry(unicode_image, directory_inode)
        image = self.clone(unicode_image, "bad-directory-checksum")
        data = bytearray(image.read_bytes()); data[u32(directory["record"], 60) * directory["block"] + 30] ^= 1; image.write_bytes(data)
        self.add("bad-directory-checksum", image, unicode_inode, "recover", names_must_be_absent=True)

        small = self.root / "fragmented-payload.bin"
        small.write_bytes(bytes((i * 17 + 23) % 256 for i in range(12 * 1024 - 9)))
        tree = self.filesystem("extent-tree-fragmented")
        tree_inode = self.write(tree, small)
        content = small.read_bytes()
        for logical in range((len(content) + 1023) // 1024):
            old = int(self.debug(tree, ["bmap /old.bin " + str(logical)]).strip().splitlines()[-1])
            physical = 5000 + logical * 17
            self.debug(tree, ["setb " + str(physical), "bmap /old.bin %d %d" % (logical, physical), "freeb " + str(old)])
            with tree.open("r+b") as stream:
                stream.seek(physical * 1024); stream.write(content[logical * 1024:(logical + 1) * 1024])
        self.debug(tree, ["rm /old.bin"])
        tg = geometry(tree, tree_inode)
        if u16(tg["record"], 46) < 1:
            raise ValueError("Real e2fsprogs did not create an external extent node")
        self.add("extent-tree-fragmented", tree, tree_inode, "recover", small, minimum_extents=12)
        node = u32(tg["record"], 56)
        image = self.clone(tree, "bad-extent-node-checksum")
        data = bytearray(image.read_bytes()); data[node * 1024 + 15] ^= 1; image.write_bytes(data)
        self.add("bad-extent-node-checksum", image, tree_inode, "reject", small)
        image = self.clone(tree, "cyclic-extent-tree-valid-crc")
        data = bytearray(image.read_bytes()); struct.pack_into("<H", data, tg["inode_offset"] + 46, 2)
        repair_inode(data, tg, tree_inode)
        node_offset = node * tg["block"]
        struct.pack_into("<H", data, node_offset + 2, 1); struct.pack_into("<H", data, node_offset + 6, 1)
        struct.pack_into("<IIHH", data, node_offset + 12, 0, node, 0, 0)
        tail = node_offset + 12 + u16(data, node_offset + 4) * 12
        node_seed = crc32c(crc32c(tg["seed"], struct.pack("<I", tree_inode)), tg["record"][100:104])
        struct.pack_into("<I", data, tail, crc32c(node_seed, data[node_offset:tail])); image.write_bytes(data)
        self.add("cyclic-extent-tree-valid-crc", image, tree_inode, "reject", small)

        legacy_payload = self.root / "legacy-payload.bin"
        legacy_payload.write_bytes(bytes((i * 37 + 13) % 256 for i in range(350123)))
        legacy = self.filesystem("legacy-indirect-deleted", legacy=True)
        legacy_inode = self.write(legacy, legacy_payload)
        self.debug(legacy, ["rm /old.bin"])
        self.add("legacy-indirect-deleted", legacy, legacy_inode, "recover", legacy_payload, mapping="direct_indirect")
        for name, options in [("extent-4k-deleted", {"block_size": 4096}),
                              ("gdt-crc16-deleted", {"features": "^metadata_csum,^metadata_csum_seed,^orphan_file,uninit_bg"})]:
            image = self.filesystem(name, **options)
            target = self.write(image); self.debug(image, ["rm /old.bin"])
            self.add(name, image, target, "recover")

        for name, operation in [("sparse-deleted", "punch /old.bin 1 1"), ("unwritten-deleted", "fallocate /old.bin 0 3")]:
            image = self.filesystem(name)
            if name.startswith("unwritten"):
                empty = self.root / "empty.bin"; empty.write_bytes(b"")
                target = self.write(image, empty)
                self.debug(image, [operation, "sif /old.bin size 4096", "rm /old.bin"])
            else:
                target = self.write(image)
                self.debug(image, [operation, "rm /old.bin"])
            self.add(name, image, target, "reject")
        self.run(["/usr/sbin/debugfs", "-V"])
        debugfs_version = re.search(r"debugfs [0-9.]+[^\r\n]*", self.last_stderr).group(0)
        self.run(["/sbin/mke2fs", "-V"])
        mke2fs_version = re.search(r"mke2fs [0-9.]+[^\r\n]*", self.last_stderr).group(0)
        manifest = {"schema": 1, "scope": "Synthetic regular image files only; real e2fsprogs metadata; no mounted filesystem or personal data.",
                    "generator_sha256": sha(Path(__file__).read_bytes()), "distribution": self.distribution, "fake_time": TIME,
                    "tool_versions": {"debugfs": debugfs_version, "mke2fs": mke2fs_version}, "cases": self.cases, "commands": self.calls,
                    "limits": "debugfs deletion preserves inode maps; normal kernel deletion may clear them. Retained directory link case intentionally uses kill_file without unlink. No journal history recovery claim."}
        (self.root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"destination": str(self.root), "cases": len(self.cases)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--distribution", default="docker-desktop")
    parser.add_argument("--extract", type=Path, help="Expand a maintained compressed fixture bundle without WSL")
    parser.add_argument("--package", type=Path, help="Package freshly generated fixtures for offline use")
    args = parser.parse_args()
    if args.extract:
        if args.package:
            parser.error("--extract and --package cannot be combined")
        extract_fixtures(args.extract, args.destination)
    else:
        Generator(args.destination, args.distribution).build()
        if args.package:
            package_fixtures(args.destination, args.package)
