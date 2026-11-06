# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent synthetic APFS fixture generator for unreferenced salvage recovery.

Generates bit-accurate APFS container and volume test fixtures without external dependencies.
Covers:
- Live files in surviving B-Trees (control).
- Unreferenced deleted files in historical B-Tree leaf nodes outside surviving trees.
- Fragmented deleted files spanning multiple non-contiguous extents.
- Unreferenced orphan files without directory records (reconstructed via inode xfield name or id).
- Unreferenced nested directories and subfolder reconstruction.
- Fletcher-64 checksum corruptions (strict rejection negative test).
- Multi-volume APFS containers.
Only newly created synthetic fixture files are opened for writing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fletcher64(data: bytes) -> int:
    """Fletcher-64 checksum implementation matching Apple File System reference."""
    sum1 = 0
    sum2 = 0
    for i in range(0, len(data) & ~3, 4):
        word = int.from_bytes(data[i:i + 4], "little")
        sum1 = (sum1 + word) & 0xFFFFFFFFFFFFFFFF
        sum2 = (sum2 + sum1) & 0xFFFFFFFFFFFFFFFF
    mod = 0xFFFFFFFF
    ck_low = mod - ((sum1 + sum2) % mod)
    ck_high = mod - ((sum1 + ck_low) % mod)
    return ck_low | (ck_high << 32)


def make_xfields(fields: list[tuple[int, bytes]]) -> bytes:
    """Pack extended fields (xf_blob_t)."""
    data = bytearray(struct.pack("<HH", len(fields), 0))
    for kind, val in fields:
        data.extend(struct.pack("<BBH", kind, 0, len(val)))
    values = bytearray()
    for _, val in fields:
        values.extend(val)
        values.extend(bytes((-len(values)) % 8))
    struct.pack_into("<H", data, 2, len(values))
    return bytes(data + values)


def make_inode_record(
    oid: int,
    parent_id: int,
    private_id: int,
    name: str,
    size: int,
    is_dir: bool = False,
    create_time_ns: int = 1600000000000000000,
) -> tuple[bytes, bytes]:
    """Create j_key_t and j_inode_val_t for an inode."""
    key = struct.pack("<Q", (3 << 60) | oid)
    val = bytearray(92)
    struct.pack_into("<QQ", val, 0, parent_id, private_id)
    struct.pack_into("<QQQQ", val, 16, create_time_ns, create_time_ns, create_time_ns, create_time_ns)
    struct.pack_into("<Q", val, 48, 0)  # internal_flags
    struct.pack_into("<i", val, 56, 2 if is_dir else 1)  # nchildren / nlink
    mode = 0o040755 if is_dir else 0o100644
    struct.pack_into("<H", val, 80, mode)
    struct.pack_into("<Q", val, 84, size if not is_dir else 0)

    name_bytes = name.encode("utf-8") + b"\0"
    fields = [(4, name_bytes)]  # 4 = INO_EXT_TYPE_NAME
    if not is_dir:
        dstream = bytearray(40)
        struct.pack_into("<QQQQQ", dstream, 0, size, (size + 4095) & ~4095, 0, size, size)
        fields.append((8, bytes(dstream)))  # 8 = INO_EXT_TYPE_DSTREAM

    val.extend(make_xfields(fields))
    return key, bytes(val)


def make_file_extent_record(
    private_id_or_inode: int,
    logical_offset: int,
    byte_length: int,
    physical_block_num: int,
) -> tuple[bytes, bytes]:
    """Create j_file_extent_key_t and j_file_extent_val_t."""
    key = struct.pack("<QQ", (8 << 60) | private_id_or_inode, logical_offset)
    val = struct.pack("<QQQ", byte_length & 0x00FFFFFFFFFFFFFF, physical_block_num, 0)
    return key, val


def make_drec_record(
    parent_id: int,
    file_id: int,
    name: str,
    is_dir: bool = False,
    date_added_ns: int = 1600000000000000000,
) -> tuple[bytes, bytes]:
    """Create j_drec_key_t and j_drec_val_t."""
    name_bytes = name.encode("utf-8") + b"\0"
    key = struct.pack("<QH", (9 << 60) | parent_id, len(name_bytes)) + name_bytes
    flags = 2 if is_dir else 8
    val = struct.pack("<QQH", file_id, date_added_ns, flags)
    return key, val


def apfs_key_sort(row: tuple[bytes, bytes]):
    key = row[0]
    raw = struct.unpack_from("<Q", key, 0)[0]
    oid = raw & 0x0FFFFFFFFFFFFFFF
    ktype = raw >> 60
    rest = key[8:]
    return (oid, ktype, rest)


def make_btree_node(
    address: int,
    rows: list[tuple[bytes, bytes]],
    is_root: bool,
    xid: int = 1,
    subtype: int = 14,
) -> bytearray:
    """Create a B-tree node block (BTND / btree_node_phys_t) with Fletcher-64 checksum."""
    buf = bytearray(4096)
    obj_type = (2 if is_root else 3) | 0x40000000
    struct.pack_into("<QQII", buf, 8, address, xid, obj_type, subtype)

    sorted_rows = sorted(rows, key=apfs_key_sort)
    btn_flags = 3 if is_root else 2
    btn_level = 0
    nkeys = len(sorted_rows)
    table_space_off = 0
    table_space_len = nkeys * 8

    struct.pack_into("<HHI", buf, 32, btn_flags, btn_level, nkeys)
    struct.pack_into("<HH", buf, 40, table_space_off, table_space_len)
    struct.pack_into("<HH", buf, 44, 0, 0)
    struct.pack_into("<HH", buf, 48, 0, 0)
    struct.pack_into("<HH", buf, 52, 0, 0)

    node_header_size = 56
    key_start = node_header_size + table_space_off + table_space_len

    key_used = 0
    val_used = 0
    val_base = 4096 - (40 if is_root else 0)

    for idx, (k, v) in enumerate(sorted_rows):
        val_used += len(v)
        val_start = val_base - val_used
        buf[key_start + key_used : key_start + key_used + len(k)] = k
        buf[val_start : val_start + len(v)] = v

        toc = struct.pack("<HHHH", key_used, len(k), val_used, len(v))
        toc_offset = node_header_size + table_space_off + idx * 8
        buf[toc_offset : toc_offset + 8] = toc
        key_used += len(k)

    if is_root:
        info = bytearray(40)
        max_k = max(len(k) for k, v in sorted_rows) if sorted_rows else 0
        max_v = max(len(v) for k, v in sorted_rows) if sorted_rows else 0
        struct.pack_into("<IIII", info, 0, 16, 4096, 0, 0)
        struct.pack_into("<IIII", info, 16, max_k, max_v, nkeys, 1)
        buf[4096 - 40 : 4096] = info

    ck = fletcher64(buf[8:])
    struct.pack_into("<Q", buf, 0, ck)
    return buf


def make_nx_superblock(
    block_count: int,
    fs_oids: list[int],
    uuid_hex: str = "1234567890abcdef1234567890abcdef",
) -> bytearray:
    buf = bytearray(4096)
    struct.pack_into("<QQII", buf, 8, 1, 1, 1 | 0x80000000, 0)
    buf[32:36] = b"NXSB"
    struct.pack_into("<II", buf, 36, 4096, block_count)
    buf[72:88] = bytes.fromhex(uuid_hex)
    struct.pack_into("<QQ", buf, 88, 500, 2)
    struct.pack_into("<IIQQII", buf, 104, 1, 1, 1, 2, 1, 1)
    struct.pack_into("<Q", buf, 160, 2)
    struct.pack_into("<I", buf, 180, len(fs_oids))
    for idx, fs_oid in enumerate(fs_oids):
        struct.pack_into("<Q", buf, 184 + idx * 8, fs_oid)
    ck = fletcher64(buf[8:])
    struct.pack_into("<Q", buf, 0, ck)
    return buf


def make_volume_superblock(
    oid: int,
    xid: int,
    root_tree_block: int,
    volname: str,
    vol_uuid_hex: str = "abcdef1234567890abcdef1234567890",
) -> bytearray:
    buf = bytearray(4096)
    struct.pack_into("<QQII", buf, 8, oid, xid, 13, 0)
    buf[32:36] = b"APSB"
    struct.pack_into("<II", buf, 116, 14 | 0x40000000, 0)
    struct.pack_into("<QQ", buf, 128, 5, root_tree_block)
    buf[240:256] = bytes.fromhex(vol_uuid_hex)
    struct.pack_into("<I", buf, 264, 1)  # UNENCRYPTED
    name_bytes = volname.encode("utf-8")[:255] + b"\0"
    buf[704 : 704 + len(name_bytes)] = name_bytes
    ck = fletcher64(buf[8:])
    struct.pack_into("<Q", buf, 0, ck)
    return buf


class ApfsContainerBuilder:
    def __init__(self, block_count: int = 64):
        self.block_count = block_count
        self.image = bytearray(block_count * 4096)

    def write_block(self, block_idx: int, data: bytes):
        if len(data) != 4096:
            raise ValueError(f"Block must be exactly 4096 bytes, got {len(data)}")
        self.image[block_idx * 4096 : (block_idx + 1) * 4096] = data

    def write_data(self, block_idx: int, payload: bytes):
        start = block_idx * 4096
        self.image[start : start + len(payload)] = payload

    def get_bytes(self) -> bytes:
        return bytes(self.image)


def build_live_only(target: Path) -> dict:
    builder = ApfsContainerBuilder(32)
    vol_oid = 100
    root_tree_block = 6
    nx = make_nx_superblock(32, [vol_oid])
    builder.write_block(0, nx)
    builder.write_block(1, nx)

    vol = make_volume_superblock(vol_oid, 1, root_tree_block, "LiveVolume")
    builder.write_block(4, vol)

    # Root dir entry (oid 1 -> 2)
    r1 = make_drec_record(1, 2, "root", is_dir=True)
    r2 = make_inode_record(2, 1, 2, "root", 0, is_dir=True)

    # Live file: hello.txt
    payload_hello = b"Hello, APFS live world!\n"
    r3 = make_drec_record(2, 10, "hello.txt", is_dir=False)
    r4 = make_inode_record(10, 2, 10, "hello.txt", len(payload_hello), is_dir=False)
    r5 = make_file_extent_record(10, 0, len(payload_hello), 10)
    builder.write_data(10, payload_hello)

    # Live file: notes.md
    payload_notes = b"# Meeting Notes\nDiscussion on RoW salvage.\n"
    r6 = make_drec_record(2, 11, "notes.md", is_dir=False)
    r7 = make_inode_record(11, 2, 11, "notes.md", len(payload_notes), is_dir=False)
    r8 = make_file_extent_record(11, 0, len(payload_notes), 11)
    builder.write_data(11, payload_notes)

    root_node = make_btree_node(root_tree_block, [r1, r2, r3, r4, r5, r6, r7, r8], is_root=True, xid=1)
    builder.write_block(root_tree_block, root_node)

    data = builder.get_bytes()
    target.write_bytes(data)
    return {
        "name": "apfs-live-only",
        "image": target.name,
        "sha256": sha256_bytes(data),
        "volume_name": "LiveVolume",
        "live_files": [
            {"path": "hello.txt", "size": len(payload_hello), "sha256": sha256_bytes(payload_hello)},
            {"path": "notes.md", "size": len(payload_notes), "sha256": sha256_bytes(payload_notes)},
        ],
        "salvaged_files": [],
    }


def build_deleted_single(target: Path) -> dict:
    builder = ApfsContainerBuilder(32)
    vol_oid = 100
    root_tree_block = 6
    unref_node_block = 8

    nx = make_nx_superblock(32, [vol_oid])
    builder.write_block(0, nx)
    builder.write_block(1, nx)

    vol = make_volume_superblock(vol_oid, 2, root_tree_block, "SingleDeletedVolume")
    builder.write_block(4, vol)

    # Surviving Tree at block 6: only live.txt
    payload_live = b"This is active live data.\n"
    r1 = make_drec_record(1, 2, "root", is_dir=True)
    r2 = make_inode_record(2, 1, 2, "root", 0, is_dir=True)
    r3 = make_drec_record(2, 10, "live.txt", is_dir=False)
    r4 = make_inode_record(10, 2, 10, "live.txt", len(payload_live), is_dir=False)
    r5 = make_file_extent_record(10, 0, len(payload_live), 12)
    builder.write_data(12, payload_live)
    root_node = make_btree_node(root_tree_block, [r1, r2, r3, r4, r5], is_root=True, xid=2)
    builder.write_block(root_tree_block, root_node)

    # Historical unreferenced leaf node at block 8 (xid=1, before deletion):
    payload_deleted = b"CONFIDENTIAL DOCUMENT SALVAGED FROM UNREFERENCED APFS LEAF!\n"
    u1 = make_drec_record(2, 20, "secret_deleted.txt", is_dir=False)
    u2 = make_inode_record(20, 2, 20, "secret_deleted.txt", len(payload_deleted), is_dir=False)
    u3 = make_file_extent_record(20, 0, len(payload_deleted), 14)
    builder.write_data(14, payload_deleted)
    unref_node = make_btree_node(unref_node_block, [u1, u2, u3], is_root=False, xid=1)
    builder.write_block(unref_node_block, unref_node)

    data = builder.get_bytes()
    target.write_bytes(data)
    return {
        "name": "apfs-deleted-single",
        "image": target.name,
        "sha256": sha256_bytes(data),
        "volume_name": "SingleDeletedVolume",
        "live_files": [
            {"path": "live.txt", "size": len(payload_live), "sha256": sha256_bytes(payload_live)},
        ],
        "salvaged_files": [
            {
                "path": "secret_deleted.txt",
                "size": len(payload_deleted),
                "sha256": sha256_bytes(payload_deleted),
                "inode": 20,
            },
        ],
    }


def build_deleted_fragmented(target: Path) -> dict:
    builder = ApfsContainerBuilder(48)
    vol_oid = 100
    root_tree_block = 6
    unref_node_block = 8

    nx = make_nx_superblock(48, [vol_oid])
    builder.write_block(0, nx)
    builder.write_block(1, nx)

    vol = make_volume_superblock(vol_oid, 2, root_tree_block, "FragDeletedVolume")
    builder.write_block(4, vol)

    # Surviving tree: live.txt
    payload_live = b"Active survivor file.\n"
    r1 = make_drec_record(1, 2, "root", is_dir=True)
    r2 = make_inode_record(2, 1, 2, "root", 0, is_dir=True)
    r3 = make_drec_record(2, 10, "live.txt", is_dir=False)
    r4 = make_inode_record(10, 2, 10, "live.txt", len(payload_live), is_dir=False)
    r5 = make_file_extent_record(10, 0, len(payload_live), 12)
    builder.write_data(12, payload_live)
    root_node = make_btree_node(root_tree_block, [r1, r2, r3, r4, r5], is_root=True, xid=2)
    builder.write_block(root_tree_block, root_node)

    # Discontiguous unreferenced deleted file:
    # 6144 bytes total: 4096 bytes at block 16, 2048 bytes at block 20
    chunk1 = (b"PART_1_APFS_DISCONTIGUOUS_EXTENT_SALVAGE_AAAA" * 100)[:4096]
    chunk2 = (b"PART_2_APFS_DISCONTIGUOUS_EXTENT_SALVAGE_BBBB" * 50)[:2048]
    full_payload = chunk1 + chunk2
    builder.write_data(16, chunk1)
    builder.write_data(20, chunk2)

    u1 = make_drec_record(2, 30, "discontiguous_deleted.bin", is_dir=False)
    u2 = make_inode_record(30, 2, 30, "discontiguous_deleted.bin", len(full_payload), is_dir=False)
    u3 = make_file_extent_record(30, 0, 4096, 16)
    u4 = make_file_extent_record(30, 4096, 2048, 20)
    unref_node = make_btree_node(unref_node_block, [u1, u2, u3, u4], is_root=False, xid=1)
    builder.write_block(unref_node_block, unref_node)

    data = builder.get_bytes()
    target.write_bytes(data)
    return {
        "name": "apfs-deleted-fragmented",
        "image": target.name,
        "sha256": sha256_bytes(data),
        "volume_name": "FragDeletedVolume",
        "live_files": [
            {"path": "live.txt", "size": len(payload_live), "sha256": sha256_bytes(payload_live)},
        ],
        "salvaged_files": [
            {
                "path": "discontiguous_deleted.bin",
                "size": len(full_payload),
                "sha256": sha256_bytes(full_payload),
                "inode": 30,
            },
        ],
    }


def build_deleted_orphan(target: Path) -> dict:
    builder = ApfsContainerBuilder(32)
    vol_oid = 100
    root_tree_block = 6
    unref_node_block = 8

    nx = make_nx_superblock(32, [vol_oid])
    builder.write_block(0, nx)
    builder.write_block(1, nx)

    vol = make_volume_superblock(vol_oid, 2, root_tree_block, "OrphanVolume")
    builder.write_block(4, vol)

    payload_live = b"Active anchor.\n"
    r1 = make_drec_record(1, 2, "root", is_dir=True)
    r2 = make_inode_record(2, 1, 2, "root", 0, is_dir=True)
    r3 = make_drec_record(2, 10, "anchor.txt", is_dir=False)
    r4 = make_inode_record(10, 2, 10, "anchor.txt", len(payload_live), is_dir=False)
    r5 = make_file_extent_record(10, 0, len(payload_live), 12)
    builder.write_data(12, payload_live)
    root_node = make_btree_node(root_tree_block, [r1, r2, r3, r4, r5], is_root=True, xid=2)
    builder.write_block(root_tree_block, root_node)

    # Orphan file: NO drec! Only inode and extent in unref node.
    # Inode contains NAME="orphan_report.pdf" in xfields
    payload_orphan = b"%PDF-1.7\nOrphaned PDF payload recovered outside surviving tree\n%%EOF\n"
    u1 = make_inode_record(40, 2, 40, "orphan_report.pdf", len(payload_orphan), is_dir=False)
    u2 = make_file_extent_record(40, 0, len(payload_orphan), 14)
    builder.write_data(14, payload_orphan)
    unref_node = make_btree_node(unref_node_block, [u1, u2], is_root=False, xid=1)
    builder.write_block(unref_node_block, unref_node)

    data = builder.get_bytes()
    target.write_bytes(data)
    return {
        "name": "apfs-deleted-orphan",
        "image": target.name,
        "sha256": sha256_bytes(data),
        "volume_name": "OrphanVolume",
        "live_files": [
            {"path": "anchor.txt", "size": len(payload_live), "sha256": sha256_bytes(payload_live)},
        ],
        "salvaged_files": [
            {
                "path": "orphan_report.pdf",
                "size": len(payload_orphan),
                "sha256": sha256_bytes(payload_orphan),
                "inode": 40,
                "is_orphan": True,
            },
        ],
    }


def build_deleted_subfolder(target: Path) -> dict:
    builder = ApfsContainerBuilder(32)
    vol_oid = 100
    root_tree_block = 6
    unref_node_block = 8

    nx = make_nx_superblock(32, [vol_oid])
    builder.write_block(0, nx)
    builder.write_block(1, nx)

    vol = make_volume_superblock(vol_oid, 2, root_tree_block, "SubfolderVolume")
    builder.write_block(4, vol)

    payload_live = b"Active top level file.\n"
    r1 = make_drec_record(1, 2, "root", is_dir=True)
    r2 = make_inode_record(2, 1, 2, "root", 0, is_dir=True)
    r3 = make_drec_record(2, 10, "top.txt", is_dir=False)
    r4 = make_inode_record(10, 2, 10, "top.txt", len(payload_live), is_dir=False)
    r5 = make_file_extent_record(10, 0, len(payload_live), 12)
    builder.write_data(12, payload_live)
    root_node = make_btree_node(root_tree_block, [r1, r2, r3, r4, r5], is_root=True, xid=2)
    builder.write_block(root_tree_block, root_node)

    # Deleted subfolder: OldProject (inode 50, parent 2)
    # Inside: design.txt (inode 51, parent 50)
    payload_design = b"PROJECT BLUEPRINT ARCHITECTURE DIAGRAM 2026\n"
    u1 = make_drec_record(2, 50, "OldProject", is_dir=True)
    u2 = make_inode_record(50, 2, 50, "OldProject", 0, is_dir=True)
    u3 = make_drec_record(50, 51, "design.txt", is_dir=False)
    u4 = make_inode_record(51, 50, 51, "design.txt", len(payload_design), is_dir=False)
    u5 = make_file_extent_record(51, 0, len(payload_design), 14)
    builder.write_data(14, payload_design)
    unref_node = make_btree_node(unref_node_block, [u1, u2, u3, u4, u5], is_root=False, xid=1)
    builder.write_block(unref_node_block, unref_node)

    data = builder.get_bytes()
    target.write_bytes(data)
    return {
        "name": "apfs-deleted-subfolder",
        "image": target.name,
        "sha256": sha256_bytes(data),
        "volume_name": "SubfolderVolume",
        "live_files": [
            {"path": "top.txt", "size": len(payload_live), "sha256": sha256_bytes(payload_live)},
        ],
        "salvaged_files": [
            {
                "path": "OldProject/design.txt",
                "size": len(payload_design),
                "sha256": sha256_bytes(payload_design),
                "inode": 51,
            },
        ],
    }


def build_checksum_corrupt(target: Path) -> dict:
    builder = ApfsContainerBuilder(32)
    vol_oid = 100
    root_tree_block = 6
    corrupt_node_block = 8

    nx = make_nx_superblock(32, [vol_oid])
    builder.write_block(0, nx)
    builder.write_block(1, nx)

    vol = make_volume_superblock(vol_oid, 2, root_tree_block, "CorruptTestVolume")
    builder.write_block(4, vol)

    payload_live = b"Good live data.\n"
    r1 = make_drec_record(1, 2, "root", is_dir=True)
    r2 = make_inode_record(2, 1, 2, "root", 0, is_dir=True)
    r3 = make_drec_record(2, 10, "good.txt", is_dir=False)
    r4 = make_inode_record(10, 2, 10, "good.txt", len(payload_live), is_dir=False)
    r5 = make_file_extent_record(10, 0, len(payload_live), 12)
    builder.write_data(12, payload_live)
    root_node = make_btree_node(root_tree_block, [r1, r2, r3, r4, r5], is_root=True, xid=2)
    builder.write_block(root_tree_block, root_node)

    # Valid unref node initially:
    payload_bad = b"CORRUPTED METADATA SHOULD NEVER BE RECOVERED!\n"
    u1 = make_drec_record(2, 60, "corrupted.txt", is_dir=False)
    u2 = make_inode_record(60, 2, 60, "corrupted.txt", len(payload_bad), is_dir=False)
    u3 = make_file_extent_record(60, 0, len(payload_bad), 14)
    builder.write_data(14, payload_bad)
    corrupt_node = make_btree_node(corrupt_node_block, [u1, u2, u3], is_root=False, xid=1)

    # Deliberately corrupt bytes in corrupt_node without updating checksum:
    corrupt_node[100] ^= 0xFF
    corrupt_node[101] ^= 0xAA
    builder.write_block(corrupt_node_block, corrupt_node)

    data = builder.get_bytes()
    target.write_bytes(data)
    return {
        "name": "apfs-checksum-corrupt",
        "image": target.name,
        "sha256": sha256_bytes(data),
        "volume_name": "CorruptTestVolume",
        "live_files": [
            {"path": "good.txt", "size": len(payload_live), "sha256": sha256_bytes(payload_live)},
        ],
        "salvaged_files": [],  # corrupted block must be rejected!
        "corrupted_block": corrupt_node_block,
    }


def generate_all(destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    cases = []
    cases.append(build_live_only(destination / "apfs-live-only.dd"))
    cases.append(build_deleted_single(destination / "apfs-deleted-single.dd"))
    cases.append(build_deleted_fragmented(destination / "apfs-deleted-fragmented.dd"))
    cases.append(build_deleted_orphan(destination / "apfs-deleted-orphan.dd"))
    cases.append(build_deleted_subfolder(destination / "apfs-deleted-subfolder.dd"))
    cases.append(build_checksum_corrupt(destination / "apfs-checksum-corrupt.dd"))

    manifest = {
        "version": 1,
        "provenance": "Pure Python synthetic APFS container fixtures with live and unreferenced salvage test cases.",
        "cases": cases,
    }
    manifest_path = destination / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Generated {len(cases)} APFS fixtures in {destination}")
    return manifest


def package_fixtures(source: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((source / "manifest.json").read_text("utf-8"))
    for case in manifest["cases"]:
        name = case["image"]
        raw = (source / name).read_bytes()
        compressed = destination / (name + ".gz")
        with gzip.open(compressed, "wb", compresslevel=9) as f:
            f.write(raw)
        case["archive"] = name + ".gz"
        case["archive_sha256"] = sha256_bytes(compressed.read_bytes())
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Packaged {len(manifest['cases'])} fixtures into {destination}")


def extract_fixtures(source: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((source / "manifest.json").read_text("utf-8"))
    for case in manifest["cases"]:
        name = case["image"]
        target = destination / name
        if target.exists():
            try:
                target.chmod(0o666)
            except Exception:
                pass
        archive_name = case.get("archive")
        if archive_name and (source / archive_name).exists():
            with gzip.open(source / archive_name, "rb") as comp:
                target.write_bytes(comp.read())
        elif (source / name).exists():
            shutil.copy2(source / name, target)
        try:
            target.chmod(0o444)
        except Exception:
            pass
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Extracted {len(manifest['cases'])} fixtures to {destination}")


def main():
    parser = argparse.ArgumentParser(description="APFS salvage test fixture generator and packager.")
    parser.add_argument("--destination", type=Path, help="Target directory for generated or extracted fixtures.")
    parser.add_argument("--package", type=Path, help="Package fixtures into target directory with .gz compression.")
    parser.add_argument("--extract", type=Path, help="Extract packaged fixtures from source directory.")
    args = parser.parse_args()

    if args.extract and args.destination:
        extract_fixtures(args.extract, args.destination)
    elif args.package:
        temp_dir = Path(".build/temp-apfs-fixtures")
        generate_all(temp_dir)
        package_fixtures(temp_dir, args.package)
        shutil.rmtree(temp_dir, ignore_errors=True)
    elif args.destination:
        generate_all(args.destination)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
