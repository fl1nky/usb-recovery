"""Real APFS reader tests; generated structures plus independent upstream images.

Usage: python ApfsRecoveryTests.py [--fixtures PATH]
PATH can be dissect_apfs-1.1.tar.gz or its tests/_data directory.  Tests never
download data, mount filesystems, touch devices or use user profiles.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import tracemalloc
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers" / "recovery_engine"))
from storage_apfs import handle_apfs

CHECKS = 0
FIXTURES = None
FIXTURE_PINS = {
    "case_sensitive": ("0c2cf324cf6cd8d7b8e1f75e3c1c0f70a107479f30cfc601ebe0d4e357f7d019", "8e7ae7cb2b6d27c48f465635d000aa4a5004cbc21cf5777b681f7369c414ccc2"),
    "encrypted": ("9780647470fd4a818c0c7ae86f70f2b7d39c48a5ccf2f89f0f2bd47d35915f1d", "fbf5c6854f37b7f8b9170aef5aaaba60cd91c4ecb80e121479370c486a68d21f"),
    "snapshot": ("63dedb8142c17e6ab6709c9fe2c37c695f1caa617946bc8d499087c5299dcf2b", "21fc98a4708ed18542b20177d1c6bae3a6dc07bdf742a747fceecfe284d33019"),
    "corrupt": ("672c556cb370c4ae547e69b822d1896a2327fcb392eeba19f3d73414382cc80f", "a11d94826610518f797d51b2a8838cdb9fdf101eec8d4a132c60a0735d977e08"),
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _header(obj, oid, kind, subtype=0):
    obj.o_cksum = bytes(8)
    obj.o_oid, obj.o_xid, obj.o_type, obj.o_subtype = oid, 1, kind, subtype


def _block(data):
    from dissect.apfs.util import fletcher64
    value = bytearray(4096)
    value[:len(data)] = data
    struct.pack_into("<Q", value, 0, fletcher64(value[8:]))
    return value


def _btree(address, rows, physical, fixed=False, oid=None, subtype=11):
    from dissect.apfs.c_apfs import c_apfs as c
    node = c.btree_node_phys()
    _header(node.btn_o, oid or address, 2 | (0x40000000 if physical else 0), subtype)
    node.btn_flags, node.btn_level, node.btn_nkeys = 3 | (4 if fixed else 0), 0, len(rows)
    node.btn_table_space.off, node.btn_table_space.len = 0, len(rows) * (4 if fixed else 8)
    block = bytearray(4096)
    block[:len(node)] = node.dumps()
    key_start = len(node) + node.btn_table_space.len
    key_used, value_used = 0, 0
    for index, (key, value) in enumerate(rows):
        value_used += len(value)
        block[key_start + key_used:key_start + key_used + len(key)] = key
        start = 4096 - 40 - value_used
        block[start:start + len(value)] = value
        toc = struct.pack("<HH", key_used, value_used) if fixed else struct.pack("<HHHH", key_used, len(key), value_used, len(value))
        block[len(node) + index * len(toc):len(node) + (index + 1) * len(toc)] = toc
        key_used += len(key)
    info = c.btree_info()
    info.bt_fixed.bt_flags, info.bt_fixed.bt_node_size = 16 if physical else 0, 4096
    info.bt_fixed.bt_key_size = len(rows[0][0]) if fixed else 0
    info.bt_fixed.bt_val_size = len(rows[0][1]) if fixed else 0
    info.bt_longest_key, info.bt_longest_val = max(map(lambda p: len(p[0]), rows)), max(map(lambda p: len(p[1]), rows))
    info.bt_key_count, info.bt_node_count = len(rows), 1
    block[-40:] = info.dumps()
    return _block(block)


def _xfields(fields):
    data = bytearray(struct.pack("<HH", len(fields), 0))
    for kind, value in fields:
        data.extend(struct.pack("<BBH", kind, 0, len(value)))
    values = bytearray()
    for _, value in fields:
        values.extend(value)
        values.extend(bytes((-len(values)) % 8))
    struct.pack_into("<H", data, 2, len(values))
    return bytes(data + values)


def synthetic_apfs(payload):
    """Build a real tiny NX/OMAP/FS/B-tree graph, two extents and a clone."""
    from dissect.apfs.c_apfs import c_apfs as c
    image = bytearray(16 * 4096)
    nx = c.nx_superblock()
    _header(nx.nx_o, 1, 1 | 0x80000000)
    nx.nx_magic, nx.nx_block_size, nx.nx_block_count = int.from_bytes(b"NXSB", "little"), 4096, 16
    nx.nx_uuid = bytes.fromhex("1234567890abcdef1234567890abcdef")
    nx.nx_next_oid, nx.nx_next_xid = 300, 2
    nx.nx_xp_desc_base, nx.nx_xp_desc_blocks = 1, 1
    nx.nx_omap_oid, nx.nx_max_file_systems, nx.nx_fs_oid[0] = 2, 100, 100
    for index in (0, 1):
        image[index * 4096:(index + 1) * 4096] = _block(nx.dumps())
    for address, child in ((2, 3), (5, 6)):
        omap = c.omap_phys()
        _header(omap.om_o, address, 11 | 0x40000000)
        omap.om_tree_type, omap.om_tree_oid = 2 | 0x40000000, child
        image[address * 4096:(address + 1) * 4096] = _block(omap.dumps())
    for address, oid, target in ((3, 100, 4), (6, 200, 7)):
        row = (struct.pack("<QQ", oid, 1), struct.pack("<IIQ", 0, 4096, target))
        image[address * 4096:(address + 1) * 4096] = _btree(address, [row], True, True)
    fs = c.apfs_superblock()
    _header(fs.apfs_o, 100, 13)
    fs.apfs_magic = int.from_bytes(b"APSB", "little")
    fs.apfs_omap_oid, fs.apfs_root_tree_oid = 5, 200
    fs.apfs_root_tree_type, fs.apfs_fs_flags = 14, int(c.APFS_FS.UNENCRYPTED)
    fs.apfs_vol_uuid = bytes.fromhex("abcdef1234567890abcdef1234567890")
    fs.apfs_volname = b"Synthetic APFS"
    fs.apfs_num_files, fs.apfs_num_directories = 2, 1
    image[4 * 4096:5 * 4096] = _block(fs.dumps())

    def inode(oid, private_id, name, directory=False):
        value = c.j_inode_val()
        value.parent_id, value.private_id = 1 if directory else 2, private_id
        value.mode = (stat.S_IFDIR if directory else stat.S_IFREG) | 0o600
        value.nchildren = 2 if directory else 1
        fields = [(int(c.INO_EXT_TYPE.NAME), name.encode() + b"\0")]
        if not directory:
            stream = c.j_dstream(size=len(payload), alloced_size=8192)
            fields.append((int(c.INO_EXT_TYPE.DSTREAM), stream.dumps()))
        return struct.pack("<Q", (3 << 60) | oid), value.dumps() + _xfields(fields)

    # APFS's private root directory entry precedes inode 2, as required by
    # predecessor-based record searches for (inode, APFS_TYPE_ANY).
    root_name = b"root\0"
    rows = [(struct.pack("<QH", (9 << 60) | 1, len(root_name)) + root_name,
             struct.pack("<QQH", 2, 0, 4)), inode(2, 2, "root", True)]
    for name, oid in (("clone.txt", 12), ("recipe.txt", 10)):
        name_bytes = name.encode() + b"\0"
        key = struct.pack("<QH", (9 << 60) | 2, len(name_bytes)) + name_bytes
        rows.append((key, struct.pack("<QQH", oid, 0, 8)))
    rows += [inode(10, 10, "recipe.txt")]
    for logical, physical in ((0, 8), (4096, 10)):
        rows.append((struct.pack("<QQ", (8 << 60) | 10, logical), struct.pack("<QQQ", 4096, physical, 0)))
    rows.append(inode(12, 10, "clone.txt"))
    image[7 * 4096:8 * 4096] = _btree(7, rows, False, oid=200, subtype=14)
    image[8 * 4096:9 * 4096] = payload[:4096].ljust(4096, b"\0")
    image[10 * 4096:11 * 4096] = payload[4096:].ljust(4096, b"\0")
    return bytes(image)


def compressed_apfs(encoded, algorithm=3, declared=64, resource=None):
    """Real checksummed APFS graph carrying deliberately inconsistent decmpfs."""
    from dissect.apfs import APFS
    data = bytearray(synthetic_apfs(b"a" * 6000))
    with io.BytesIO(data) as stream:
        tree = APFS(stream).volumes[0].root_tree
        rows = [(tree._read_key(tree.root, i), tree._read_value(tree.root, i)) for i in range(tree.root.nkeys)]
    for index, (key, value) in enumerate(rows):
        if struct.unpack_from("<Q", key)[0] == (3 << 60) | 10:
            value = bytearray(value)
            struct.pack_into("<I", value, 68, 0x20)
            rows[index] = key, bytes(value)
    blob = struct.pack("<IIQ", int.from_bytes(b"cmpf", "big"), algorithm, declared) + encoded
    attributes = {"com.apple.decmpfs": blob}
    if resource is not None:
        attributes["com.apple.ResourceFork"] = resource
    for name, blob in attributes.items():
        name_bytes = name.encode() + b"\0"
        key = struct.pack("<QH", (4 << 60) | 10, len(name_bytes)) + name_bytes
        rows.append((key, struct.pack("<HH", 2, len(blob)) + blob))
    def order(row):
        raw = struct.unpack_from("<Q", row[0])[0]
        kind = raw >> 60
        return raw & ((1 << 60) - 1), kind, row[0][10:] if kind in (4, 9) else row[0][8:]
    rows.sort(key=order)
    data[7 * 4096:8 * 4096] = _btree(7, rows, False, oid=200, subtype=14)
    return bytes(data)


class ApfsRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="recovery-apfs-test-")
        cls.root = Path(cls.temporary.name)
        cls.count = 0
        cls.payload = ("Прабабушка: рецепт пирожков 🥧\n" * 100).encode("utf-8")[:6000]
        cls.small = cls.root / "tiny.dd"
        cls.small.write_bytes(synthetic_apfs(cls.payload))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def check(self, value, text):
        global CHECKS
        CHECKS += 1
        self.assertTrue(value, text)

    def run_image(self, source, options=None, secrets=None, emit=None):
        type(self).count += 1
        destination = self.root / ("result-" + str(self.count))
        result = handle_apfs({"source": str(source), "destination": str(destination), "options": options or {}, "secrets": secrets or {}}, emit)
        records = json.loads((destination / "storage-candidates.json").read_text("utf-8")) if (destination / "storage-candidates.json").exists() else []
        return result, destination, records

    def fixture(self, name):
        if FIXTURES is None:
            self.fail("Independent fixtures required: pass --fixtures dissect_apfs-1.1.tar.gz or tests/_data")
        source = self.root / (name + ".dd")
        if not source.exists():
            if FIXTURES.is_file():
                with tarfile.open(FIXTURES) as archive:
                    member = archive.getmember("dissect_apfs-1.1/tests/_data/" + name + ".bin.gz")
                    compressed = archive.extractfile(member).read()
            else:
                compressed = (FIXTURES / (name + ".bin.gz")).read_bytes()
            if hashlib.sha256(compressed).hexdigest() != FIXTURE_PINS[name][0]:
                raise ValueError("Independent compressed fixture checksum differs")
            with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as data, source.open("wb") as target:
                shutil.copyfileobj(data, target)
            if sha(source) != FIXTURE_PINS[name][1]:
                raise ValueError("Independent raw fixture checksum differs")
        return source

    def assert_records(self, source, destination, records):
        digest = sha(source)
        for record in records:
            output = destination / record["path"]
            self.check(output.is_file() and not output.is_symlink(), "ordinary owned output")
            self.check(output.stat().st_size == record["bytes"] and sha(output) == record["sha256"], "all output hashes and lengths exact")
            self.check(record["source_sha256"] == digest and record["validation"] == "metadata-checksum-and-readable-stream", "known source, careful validation label")
        self.check(not list(destination.rglob("*.partial")), "no incomplete output advertised")

    def test_tiny_real_structures_fragmented_file_and_clone(self):
        before = sha(self.small)
        result, destination, records = self.run_image(self.small)
        self.check(result["status"] == "complete" and len(records) == 2, "tiny real APFS graph reads")
        self.check({r["original_path"] for r in records} == {"/clone.txt", "/recipe.txt"}, "real directory records retained")
        self.check(all((destination / r["path"]).read_bytes() == self.payload for r in records), "two noncontiguous extents and private-id clone exact")
        self.check({r["inode"] for r in records} == {10, 12} and len({r["sha256"] for r in records}) == 1, "different identities share exact content")
        self.check(all(r["origin"] == "existing" and r["deleted"] is False and r["physical_ranges"] is None for r in records), "live files never claimed undeleted")
        self.check(sha(self.small) == before, "synthetic source unchanged")
        self.assert_records(self.small, destination, records)

    def test_independent_plaintext_unicode_compression_hardlinks_and_symlinks(self):
        source = self.fixture("case_sensitive")
        before = sha(source)
        result, destination, records = self.run_image(source)
        self.check(result["status"] == "complete" and len(records) == 20, "upstream real macOS fixture")
        paths = {r["original_path"]: r for r in records}
        self.check((destination / paths["/dir/file"]["path"]).read_bytes() == " File System\n".encode(), "independent exact UTF8 content")
        self.check(paths["/dir/file"]["sha256"] == paths["/hardlink"]["sha256"], "hardlink aliases retained")
        self.check(not any("symlink" in p for p in paths), "no APFS symlink followed")
        self.check(paths["/dir/compressed-lzfse-fork"]["sha256"] == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f", "official independent LZFSE checksum")
        self.check(sha(source) == before, "official source unchanged")
        self.assert_records(source, destination, records)

    def test_independent_encrypted_and_secret_handling(self):
        source = self.fixture("encrypted")
        result, destination, records = self.run_image(source, secrets={"apfs_password": "password"})
        self.check(result["status"] == "complete" and len(records) == 20, "official encrypted image unlocks with supplied password")
        self.check(any((destination / r["path"]).read_bytes() == " File System\n".encode() for r in records), "decrypted bytes equal independently known plaintext")
        self.check(any(r["original_path"] == "/dir/compressed-lzfse-fork" and r["sha256"] == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f" for r in records), "encrypted large fork exact across XTS sector offsets")
        reports = (destination / "apfs-report.json").read_text() + (destination / "storage-candidates.json").read_text()
        self.check('"password"' not in reports and '"apfs_password"' not in reports, "no secret in metadata")
        self.assert_records(source, destination, records)
        for secret, expected in (({}, "SECRET_REQUIRED"), ({"apfs_password": "DO-NOT-LOG-incorrect-ключ"}, "AUTH_FAILED")):
            result, destination, records = self.run_image(source, secrets=secret)
            self.check(result["status"] == "error" and result["code"] == expected, "missing/incorrect secret rejected")
            self.check(not records and not destination.exists(), "authentication failure publishes no result")
            self.check("DO-NOT-LOG" not in json.dumps(result), "error is sanitized")

    def test_independent_snapshots_recover_absent_live_file(self):
        source = self.fixture("snapshot")
        result, destination, records = self.run_image(source, options={"max_snapshots": 3})
        self.check(result["status"] == "partial" and "APFS_SNAPSHOT_LIMIT_REACHED" in result["warnings"], "bounded snapshot pass explicitly partial")
        previous = [r for r in records if r["original_path"] == "/file"]
        self.check(len(previous) == 3 and all(r["origin"] == "previous-version" and r["deleted"] is None for r in previous), "three referenced past versions, no guessed deletion")
        self.check({r["snapshot_name"] for r in previous} == {"Snapshot 0", "Snapshot 1", "Snapshot 2"}, "snapshot identity retained")
        self.check(all((destination / r["path"]).read_bytes() == (r["snapshot_name"] + "\n").encode() for r in previous), "independent historical exact payloads")
        self.check(all(r["snapshot_xid"] is not None and r["record_id"] is not None for r in previous), "record and transaction provenance")
        self.check(not any(r["original_path"] == "/file" and r["origin"] == "existing" for r in records), "live file really absent")
        self.assert_records(source, destination, previous)
        result, destination, records = self.run_image(source, options={"include_snapshots": False})
        self.check(result["status"] == "complete" and all(r["snapshot_id"] is None for r in records), "explicit current-only mode avoids history")

    def test_recent_snapshot_priority(self):
        source = self.fixture("snapshot")
        result, destination, records = self.run_image(source, options={"max_snapshots": 3, "prefer_recent_snapshots": True, "max_files": 5000})
        previous = [r for r in records if r["original_path"] == "/file"]
        self.check(result["status"] == "partial" and {r["snapshot_name"] for r in previous} == {"Snapshot 509", "Snapshot 510", "Snapshot 511"}, "bounded UI prioritizes the newest three referenced snapshots")
        self.check(all((destination / r["path"]).read_bytes() == (r["snapshot_name"] + "\n").encode() for r in previous), "newest snapshot bytes exactly match independent fixture")

    def test_independent_corrupt_checkpoint_fallback(self):
        source = self.fixture("corrupt")
        result, destination, records = self.run_image(source, options={"include_snapshots": False, "max_files": 1000})
        self.check(result["status"] in ("complete", "partial") and bool(records), "valid older checkpoint remains readable")
        report = json.loads((destination / "apfs-report.json").read_text())
        self.check(report["checkpoint_xid"] == 302 and report["checkpoint_fallback"], "independent expected checkpoint selected")
        self.check(all(r["checkpoint_fallback"] and r["origin"] == "previous-version" and r["deleted"] is None for r in records), "fallback never misrepresented as the latest live state")

    def test_offsets_truncation_checksums_and_bounds(self):
        padded = self.root / "partition.dd"
        padded.write_bytes(bytes(1024 * 1024) + self.small.read_bytes() + bytes(4096))
        result, destination, records = self.run_image(padded, options={"offset_bytes": 1024 * 1024, "length_bytes": self.small.stat().st_size})
        self.check(result["status"] == "complete" and all(r["source_offset_bytes"] == 1024 * 1024 for r in records), "explicit partition range")
        self.check(all((destination / r["path"]).read_bytes() == self.payload for r in records), "offset reading exact")
        truncated = self.root / "truncated.dd"
        truncated.write_bytes(self.small.read_bytes()[:8 * 4096])
        bad = self.root / "bad-tree.dd"
        data = bytearray(self.small.read_bytes());data[7 * 4096 + 100] ^= 1;bad.write_bytes(data)
        for source, options in ((truncated, {}), (bad, {}), (self.small, {"offset_bytes": -1}), (self.small, {"length_bytes": 4096}), (self.small, {"offset_bytes": 1})):
            result, destination, records = self.run_image(source, options=options)
            self.check(result["status"] == "error" and not records, "truncation/checksum/invalid range cannot succeed")
            self.check(not (destination / "storage-candidates.json").exists(), "no trusted candidate list after validation failure")

    def test_budgets_existing_output_and_invalid_requests(self):
        for options in ({"max_files": 1}, {"max_file_bytes": 10}, {"max_output_bytes": 10}):
            result, destination, records = self.run_image(self.small, options=options)
            self.check(result["status"] == "partial" and result["warnings"], "resource limit explicit")
            self.check(len(records) <= 1, "budget enforced")
        for options in ({"include_snapshots": 1}, {"max_files": True}, {"max_file_bytes": -1}, {"offset_bytes": "0"}):
            result, destination, records = self.run_image(self.small, options=options)
            self.check(result["status"] == "error" and result["code"] == "INVALID_REQUEST", "malformed options rejected")
        existing = self.root / "existing";existing.mkdir();keep = existing / "keep.txt";keep.write_text("untouched")
        result = handle_apfs({"source": str(self.small), "destination": str(existing)}, None)
        self.check(result["status"] == "error" and keep.read_text() == "untouched", "existing output not modified")
        result = handle_apfs({"source": str(self.small), "destination": str(self.root)}, None)
        self.check(result["status"] == "error" and self.small.is_file(), "source/destination ancestry rejected")
        self.check(handle_apfs(None, None)["code"] == "INVALID_REQUEST", "invalid request sanitized")
        result, destination, records = self.run_image(self.fixture("case_sensitive"), options={"max_metadata_bytes": 4096})
        self.check(result["status"] == "partial" and "APFS_RESOURCE_LIMIT_REACHED" in result["warnings"], "metadata manifest memory budget explicit")
        self.check(len(list((destination / "apfs-files").iterdir())) == len(records), "metadata limit leaves no orphan output")

    def test_sparse_extent_and_damaged_extent_bounds(self):
        data = bytearray(self.small.read_bytes())
        # The generated second file-extent record is row 6 in the root leaf.
        value_offset = struct.unpack_from("<HHHH", data, 7 * 4096 + 56 + 6 * 8)[2]
        physical_field = 7 * 4096 + 4096 - 40 - value_offset + 8
        struct.pack_into("<Q", data, physical_field, 0)
        data[7 * 4096:8 * 4096] = _block(data[7 * 4096:8 * 4096])
        sparse = self.root / "sparse.dd";sparse.write_bytes(data)
        result, destination, records = self.run_image(sparse)
        self.check(result["status"] == "complete" and len(records) == 2, "referenced sparse extent readable")
        self.check(all((destination / r["path"]).read_bytes() == self.payload[:4096] + bytes(len(self.payload) - 4096) for r in records), "sparse hole is zeros, never block-zero metadata")
        struct.pack_into("<QQ", data, physical_field - 8, 8192, 15)
        data[7 * 4096:8 * 4096] = _block(data[7 * 4096:8 * 4096])
        damaged = self.root / "bad-extent.dd";damaged.write_bytes(data)
        result, destination, records = self.run_image(damaged)
        self.check(result["status"] == "partial" and not records, "extent beyond container cannot be published")
        self.check(not list((destination / "apfs-files").iterdir()), "damaged stream leaves no file/partial success")

    def test_unknown_container_feature_rejected(self):
        data = bytearray(self.small.read_bytes())
        struct.pack_into("<Q", data, 64, 1 << 63)
        data[:4096] = _block(data[:4096])
        unknown = self.root / "future.dd";unknown.write_bytes(data)
        result, destination, records = self.run_image(unknown)
        self.check(result["status"] == "error" and result["code"] == "UNSUPPORTED_VERSION", "unknown incompatible format rejected explicitly")
        self.check(not destination.exists() and not records, "future format never successful empty archive")

    def test_compressed_expansion_is_bounded_before_allocation(self):
        encoded = zlib.compress(b"A" * (2 * 1024 * 1024), 9)
        source = self.root / "small-compressed.dd"
        source.write_bytes(compressed_apfs(encoded))
        before = sha(source)
        result, destination, records = self.run_image(source, options={"max_file_bytes": 64, "max_output_bytes": 128})
        self.check(result["status"] == "partial" and not records, "oversized decoded stream is not a successful file")
        self.check("APFS_COMPRESSED_DATA_INVALID" in result["warnings"], "bounded decompression failure explicit")
        self.check(not list((destination / "apfs-files").iterdir()), "no failed compressed candidate or partial file published")
        self.check(sha(source) == before, "compressed malformed source unchanged")
        decoder = handle_apfs.__globals__["_decode_chunk"]
        failed = False
        tracemalloc.start()
        try:
            decoder(3, encoded, 64)
        except Exception:
            failed = True
        finally:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        self.check(failed and peak < 256 * 1024, "2MiB zlib expansion rejected below256KiB allocation")

    def test_compressed_fork_table_count_and_lzfse_header_bounded(self):
        # A declared one-block file cannot supply a UINT32_MAX-entry fork table.
        resource = struct.pack(">IIII", 16, 0, 0, 0) + struct.pack("<II", 0, 0xFFFFFFFF)
        source = self.root / "bad-fork-table.dd"
        source.write_bytes(compressed_apfs(b"", algorithm=4, resource=resource))
        result, destination, records = self.run_image(source, options={"max_file_bytes": 64, "max_output_bytes": 128})
        self.check(result["status"] == "partial" and not records and "APFS_COMPRESSED_DATA_INVALID" in result["warnings"], "huge fork table count rejected before iteration")
        self.check(not list((destination / "apfs-files").iterdir()), "bad fork does not publish a candidate")
        decoder = handle_apfs.__globals__["_decode_chunk"]
        for algorithm, data in ((11, b"bvx-" + struct.pack("<I", 2 * 1024 * 1024) + b"short"),
                                (7, b"\xe1A\x00\x01" + b"\xf0\xff" * 8192 + b"\x06" + bytes(7))):
            failed = False
            tracemalloc.start()
            try:
                decoder(algorithm, data, 64)
            except Exception:
                failed = True
            finally:
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
            self.check(failed and peak < 1024 * 1024, "codec header/output ceiling rejects expansion before1MiB allocation")

    def test_source_write_denied_throughout_operation_on_windows(self):
        if os.name != "nt":
            self.skipTest("Windows sharing protection")
        attempts = []
        def emit(*_args, **_kwargs):
            try:
                with self.small.open("r+b"):
                    attempts.append(False)
            except PermissionError:
                attempts.append(True)
        result, _, _ = self.run_image(self.small, emit=emit)
        self.check(result["status"] == "complete" and attempts and all(attempts), "source write handle denied during real progress callbacks")
        with self.small.open("r+b"):
            result, destination, records = self.run_image(self.small)
        self.check(result["status"] == "error" and result["code"] == "IO_ERROR" and not records, "preexisting writer prevents forensic read lock")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path)
    args, remaining = parser.parse_known_args()
    FIXTURES = args.fixtures
    if FIXTURES is None:
        for path in (ROOT / "tests/StorageFixtures/apfs", ROOT / "helpers/recovery_engine/dependency-sources/dissect_apfs-1.1.tar.gz", ROOT / ".build/apfs-research/dissect_apfs-1.1.tar.gz"):
            if path.is_file() or (path.is_dir() and all((path / (name + ".bin.gz")).is_file() for name in ("case_sensitive", "encrypted", "snapshot", "corrupt"))):
                FIXTURES = path
                break
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ApfsRecovery))
    if result.wasSuccessful():
        print(f"PASS APFS: {CHECKS} checks; generated real metadata graph, fragmented extents/private-id clone, independent macOS plaintext/encrypted/snapshot/corrupt-checkpoint fixtures, strict source bounds and no secret publication. Ordinary files only; no devices.")
    sys.exit(0 if result.wasSuccessful() else 1)
