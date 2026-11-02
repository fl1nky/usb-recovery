# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent synthetic ReFS fixture generator.

Generates bit-accurate ReFS v1.2 and v3.4 test volumes without external dependencies.
Sources: libfsrefs (Joachim Metz), Ballenthin (2012), Green (2013), Prade et al. (2019).
Only newly created synthetic image files are opened for writing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def crc32c(data: bytes, seed: int = 0xFFFFFFFF) -> int:
    """Castagnoli CRC32-C (polynomial 0x1EDC6F41, reflected 0x82F63B78)."""
    for byte in data:
        seed ^= byte
        for _ in range(8):
            seed = (seed >> 1) ^ (0x82F63B78 if seed & 1 else 0)
    return seed ^ 0xFFFFFFFF


def crc64_ecma(data: bytes, seed: int = 0xFFFFFFFFFFFFFFFF) -> int:
    """CRC64-ECMA-182 (polynomial 0x42F0E1EBA9EA3693, reflected 0xC96C5795D7870F42)."""
    poly = 0xC96C5795D7870F42
    for b in data:
        seed ^= b
        for _ in range(8):
            seed = (seed >> 1) ^ poly if (seed & 1) else (seed >> 1)
    return seed ^ 0xFFFFFFFFFFFFFFFF


class ReFSVolumeBuilder:
    def __init__(
        self,
        major: int = 3,
        minor: int = 4,
        cluster_size: int = 4096,
        total_clusters: int = 1024,
        sector_size: int = 512,
        container_size: int = 0x4000,
    ):
        self.major = major
        self.minor = minor
        self.cluster_size = cluster_size
        self.sector_size = sector_size
        self.total_clusters = total_clusters
        self.meta_block_size = 16384 if major == 1 else cluster_size
        self.header_size = 48 if major == 1 else 80
        self.ref_size = 24 if major == 1 else 48
        self.container_size = container_size if major >= 3 else 0
        self.image = bytearray(total_clusters * cluster_size)

    def write_vbr(self, sector_offset: int = 0, backup: bool = False):
        vbr = bytearray(self.sector_size)
        vbr[0:3] = b"\xeb\x52\x90"
        vbr[3:11] = b"ReFS\0\0\0\0"
        vbr[16:20] = b"FSRS"
        struct.pack_into("<I", vbr, 20, 32)  # Header size
        total_sectors = (len(self.image)) // self.sector_size
        struct.pack_into("<Q", vbr, 24, total_sectors)
        struct.pack_into("<I", vbr, 32, self.sector_size)
        struct.pack_into("<I", vbr, 36, self.cluster_size // self.sector_size)
        vbr[40] = self.major
        vbr[41] = self.minor
        struct.pack_into("<Q", vbr, 56, 0x1234567890ABCDEF)
        if self.major >= 3:
            struct.pack_into("<Q", vbr, 64, self.container_size)
        vbr[510:512] = b"\x55\xaa"
        self.image[sector_offset : sector_offset + self.sector_size] = vbr

    def write_block_ref(self, target: bytearray, offset: int, block_num: int, expected_crc: int = 0, crc_type: int = 1):
        if expected_crc == 0:
            crc_type = 0
        if self.major == 1:
            struct.pack_into("<Q", target, offset, block_num)
            target[offset + 8] = 0   # checksum offset
            target[offset + 9] = 4 if crc_type == 1 else 8
            target[offset + 10] = crc_type
            target[offset + 11] = 0
            if crc_type == 1:
                struct.pack_into("<I", target, offset + 12, expected_crc & 0xFFFFFFFF)
            else:
                struct.pack_into("<Q", target, offset + 16, expected_crc)
        else:
            struct.pack_into("<QQQQ", target, offset, block_num, 0, 0, 0)
            target[offset + 32] = 0  # checksum offset
            target[offset + 33] = 4 if crc_type == 1 else 8
            target[offset + 34] = crc_type
            target[offset + 35] = 0
            struct.pack_into("<I", target, offset + 36, 0)
            if crc_type == 1:
                struct.pack_into("<Q", target, offset + 40, expected_crc & 0xFFFFFFFF)
            else:
                struct.pack_into("<Q", target, offset + 40, expected_crc)

    def write_superblock(self, primary_chkp: int = 31, secondary_chkp: int = 32, seq: int = 1):
        sb_offset = 30 * self.meta_block_size
        sb = bytearray(self.meta_block_size)
        chkp_offset = 128 if self.major == 1 else 160
        num_checkpoints = 2

        if self.major == 1:
            struct.pack_into("<QQ", sb, 0, 30, seq)
            # Body at 48:
            guid = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
            sb[48:64] = guid
            struct.pack_into("<Q", sb, 72, seq)
            struct.pack_into("<II", sb, 80, chkp_offset, num_checkpoints)
            self.write_block_ref(sb, chkp_offset, primary_chkp)
            self.write_block_ref(sb, chkp_offset + self.ref_size, secondary_chkp)
        else:
            sb[0:4] = b"SUPB"
            struct.pack_into("<II", sb, 4, 1, 0)
            struct.pack_into("<QQ", sb, 16, seq, 0)
            # Body at 80:
            guid = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
            sb[80:96] = guid
            struct.pack_into("<Q", sb, 104, seq)
            struct.pack_into("<II", sb, 112, chkp_offset, num_checkpoints)
            self.write_block_ref(sb, chkp_offset, primary_chkp)
            self.write_block_ref(sb, chkp_offset + self.ref_size, secondary_chkp)

        self.image[sb_offset : sb_offset + self.meta_block_size] = sb

    def write_checkpoint(
        self,
        block_num: int,
        seq: int,
        tree0_block: int,
        tree0_crc: int = 0,
        tree7_block: int = 0,
        tree7_crc: int = 0,
        crc_type: int = 1,
        corrupt: bool = False,
    ):
        chkp_offset = block_num * self.meta_block_size
        chkp = bytearray(self.meta_block_size)
        table_start = 256 if self.major >= 3 else 128

        if self.major >= 3:
            chkp[0:4] = b"CHKP"
            struct.pack_into("<II", chkp, 4, 1, 0)
            struct.pack_into("<QQ", chkp, 16, seq, seq)
            # Checkpoint header (16B at 80):
            struct.pack_into("<HH", chkp, 84, self.major, self.minor)
            # Trailer at 96:
            struct.pack_into("<QQ", chkp, 96, seq, seq)
            # Tree table offsets at 144:
            struct.pack_into("<I", chkp, 144, 8)  # 8 trees
            # Tree 0 at table_start, Tree 7 at table_start + 7 * 48
            for i in range(8):
                off = table_start + i * self.ref_size
                struct.pack_into("<I", chkp, 148 + i * 4, off)
            self.write_block_ref(chkp, table_start, tree0_block, tree0_crc)
            if tree7_block:
                self.write_block_ref(chkp, table_start + 7 * self.ref_size, tree7_block, tree7_crc)
        else:
            struct.pack_into("<QQ", chkp, 0, block_num, seq)
            struct.pack_into("<HH", chkp, 48 + 4, self.major, self.minor)
            # Trailer at 64:
            struct.pack_into("<Q", chkp, 64, seq)
            struct.pack_into("<I", chkp, 64 + 24, 7)
            for i in range(7):
                off = table_start + i * self.ref_size
                struct.pack_into("<I", chkp, 64 + 28 + i * 4, off)
            self.write_block_ref(chkp, table_start, tree0_block, tree0_crc)

        # Update self checksum in superblock pointer or block itself
        calc_crc = crc32c(chkp) if crc_type == 1 else crc64_ecma(chkp)
        if corrupt:
            calc_crc ^= 0xDEADBEEF
        sb_offset = 30 * self.meta_block_size
        chkp_slot = 128 if self.major == 1 else 160
        # Determine whether this is primary (index 0) or secondary (index 1)
        if block_num == 31:
            self.write_block_ref(self.image, sb_offset + chkp_slot, block_num, calc_crc, crc_type)
        elif block_num == 32:
            self.write_block_ref(self.image, sb_offset + chkp_slot + self.ref_size, block_num, calc_crc, crc_type)

        self.image[chkp_offset : chkp_offset + self.meta_block_size] = chkp

    def write_btree_leaf(
        self,
        block_num: int,
        records: list[tuple[bytes, bytes]],
        corrupt: bool = False,
    ) -> int:
        offset = block_num * self.meta_block_size
        page = bytearray(self.meta_block_size)
        node_hdr_start = self.header_size

        if self.major >= 3:
            page[0:4] = b"MSB+"
            struct.pack_into("<II", page, 4, 1, 0)
            struct.pack_into("<QQ", page, 16, 1, 1)

        # 32-byte NodeHeader at node_hdr_start:
        record_offsets_start = 32
        struct.pack_into(
            "<IIIBBHIII",
            page,
            node_hdr_start,
            0,
            0,
            0,
            0,  # NodeLevel = 0 (Leaf)
            2,  # NodeTypeFlags = 2 (Root/Leaf)
            0,  # Reserved = 0
            record_offsets_start,
            len(records),
            0,  # RecordOffsetsEnd
        )

        tail = self.meta_block_size
        rec_rel_offsets = []

        for key, val in records:
            # Record header: size(4), key_off(2), key_size(2), flags(2), val_off(2), val_size(2) = 14 bytes
            rec_hdr_size = 14
            rec_len = rec_hdr_size + len(key) + len(val)
            tail -= rec_len
            rel_key = rec_hdr_size
            rel_val = rec_hdr_size + len(key)
            struct.pack_into(
                "<IHHHHH",
                page,
                tail,
                rec_len,
                rel_key,
                len(key),
                0,
                rel_val,
                len(val),
            )
            page[tail + rel_key : tail + rel_key + len(key)] = key
            page[tail + rel_val : tail + rel_val + len(val)] = val
            rec_rel_offsets.append(tail - node_hdr_start)

        # Write record offsets array
        off_pos = node_hdr_start + record_offsets_start
        for roff in rec_rel_offsets:
            if self.major >= 3:
                # Mask high word with 0xFFFF
                val32 = 0xFFFF0000 | (roff & 0xFFFF)
                struct.pack_into("<I", page, off_pos, val32)
                off_pos += 4
            else:
                struct.pack_into("<H", page, off_pos, roff & 0xFFFF)
                off_pos += 2

        computed_crc = crc32c(page)
        if corrupt:
            # Flip a bit in the node header or records so stored block does not match expected CRC
            page[node_hdr_start + 12] ^= 0x01

        self.image[offset : offset + self.meta_block_size] = page
        return computed_crc

    def build_object_record_key(self, object_id: int) -> bytes:
        return struct.pack("<QQ", 0, object_id)

    def build_object_record_value(self, target_block: int, expected_crc: int = 0) -> bytes:
        val = bytearray(self.ref_size)
        self.write_block_ref(val, 0, target_block, expected_crc)
        return bytes(val)

    def build_container_record(self, container_id: int, physical_start_cluster: int, cluster_count: int = 0x4000) -> tuple[bytes, bytes]:
        key = struct.pack("<Q", container_id)
        val = bytearray(160)
        struct.pack_into("<Q", val, 0, container_id)
        struct.pack_into("<Q", val, 144, physical_start_cluster)
        struct.pack_into("<Q", val, 152, cluster_count)
        return key, bytes(val)

    def build_dir_entry_record(
        self,
        name: str,
        entry_type: int,  # 1 = File, 2 = Directory
        child_object_id: int = 0,
        payload: bytes = b"",
        is_resident: bool = True,
        cluster_extents: list[tuple[int, int, int]] | None = None,  # (logical_offset, block_count, physical_block)
        compressed: bool = False,
    ) -> tuple[bytes, bytes]:
        name_utf16 = name.encode("utf-16le")
        key = struct.pack("<HH", 0x0030, entry_type) + name_utf16

        # Standard Windows FILETIME timestamp: 1700000000 epoch -> 133443264000000000
        ft = 133443264000000000

        if entry_type == 2:
            # Directory value: 72 bytes
            val = bytearray(72)
            struct.pack_into("<Q", val, 0, child_object_id)
            struct.pack_into("<QQQQ", val, 16, ft, ft, ft, ft)
            struct.pack_into("<I", val, 64, 0x10)  # FILE_ATTRIBUTE_DIRECTORY
            return key, bytes(val)

        # File value: 128-byte file header + Attribute 0x80 ($DATA)
        attr_flags = 0x20  # FILE_ATTRIBUTE_ARCHIVE
        if compressed:
            attr_flags |= 0x800  # FILE_ATTRIBUTE_COMPRESSED

        val = bytearray(128)
        struct.pack_into("<QQQQ", val, 0, ft, ft, ft, ft)
        struct.pack_into("<I", val, 32, attr_flags)
        file_len = len(payload) if (is_resident or not cluster_extents) else sum(cnt * self.cluster_size for _, cnt, _ in cluster_extents)
        if not is_resident and payload:
            file_len = len(payload)
        struct.pack_into("<QQ", val, 64, file_len, file_len)

        # Attribute 0x80 ($DATA)
        attr = bytearray()
        if is_resident:
            # Resident Attribute header: 16 bytes
            # attr_type(4) = 0x80, attr_flags(2) = 0 (bit 3 is 0), inline_off(4), inline_size(4)
            inline_off = 16
            attr_hdr = struct.pack("<IIII", 0x80, 0, inline_off, len(payload))
            attr = attr_hdr + payload
        else:
            # Non-resident Attribute header: 16 bytes
            # attr_type(4) = 0x80, attr_flags(2) = 0x08 (bit 3 is 1: embedded data runs)
            runs_data = bytearray()
            if cluster_extents:
                for log_off, blk_cnt, phys_blk in cluster_extents:
                    runs_data += struct.pack("<QQQ", log_off, blk_cnt, phys_blk)
            attr_hdr = struct.pack("<IIII", 0x80, 0x08, 16, len(runs_data))
            attr = attr_hdr + runs_data

        return key, bytes(val + attr)

    def write_raw_data(self, cluster: int, data: bytes):
        offset = cluster * self.cluster_size
        self.image[offset : offset + len(data)] = data

    def finalize(self) -> bytes:
        return bytes(self.image)


# ---------------------------------------------------------------------------
# Generator Cases: 10 Synthetic Test Images
# ---------------------------------------------------------------------------

def generate_fixtures(destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": 1,
        "provenance": "Pure Python synthetic ReFS v1.2 and v3.4 fixtures without external dependencies.",
        "cases": [],
    }

    # Case 1: refs-v12-minimal (v1.2, 16K meta blocks, 4K clusters, resident + non-resident)
    print("Generating refs-v12-minimal...")
    b1 = ReFSVolumeBuilder(major=1, minor=2, cluster_size=4096, total_clusters=2048)
    b1.write_vbr(0)
    p1_resident = b"Hello, ReFS v1.2 resident payload!"
    p1_nonres = bytes((i % 256 for i in range(8192)))
    b1.write_raw_data(200, p1_nonres)

    rec_res = b1.build_dir_entry_record("hello.txt", 1, payload=p1_resident, is_resident=True)
    rec_nonres = b1.build_dir_entry_record("data.bin", 1, payload=p1_nonres, is_resident=False, cluster_extents=[(0, 2, 200)])
    crc_root = b1.write_btree_leaf(34, [rec_res, rec_nonres])

    rec_obj600 = (b1.build_object_record_key(0x600), b1.build_object_record_value(34, crc_root))
    crc_tree0 = b1.write_btree_leaf(33, [rec_obj600])

    b1.write_superblock(31, 32, seq=1)
    b1.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc_tree0)
    b1.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc_tree0)

    img1 = b1.finalize()
    p1 = destination / "refs-v12-minimal.dd"
    p1.write_bytes(img1)
    manifest["cases"].append({
        "name": "refs-v12-minimal",
        "image": "refs-v12-minimal.dd",
        "sha256": sha256_bytes(img1),
        "outcome": "recover",
        "expected_version": "1.2",
        "target_name": "hello.txt",
        "payload_sha256": sha256_bytes(p1_resident),
    })

    # Case 2: refs-v34-minimal (v3.4, 4K meta blocks, 4K clusters, Tree 7 containers)
    print("Generating refs-v34-minimal...")
    b2 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    b2.write_vbr(0)
    p2_resident = b"Welcome to ReFS v3.4 structured recovery!"
    p2_nonres = bytes(((i * 7) % 256 for i in range(4096)))
    b2.write_raw_data(100, p2_nonres)

    rec2_res = b2.build_dir_entry_record("welcome.txt", 1, payload=p2_resident, is_resident=True)
    rec2_nonres = b2.build_dir_entry_record("sample.dat", 1, payload=p2_nonres, is_resident=False, cluster_extents=[(0, 1, 100)])
    crc2_root = b2.write_btree_leaf(34, [rec2_res, rec2_nonres])

    rec2_obj600 = (b2.build_object_record_key(0x600), b2.build_object_record_value(34, crc2_root))
    crc2_tree0 = b2.write_btree_leaf(33, [rec2_obj600])

    c0_rec = b2.build_container_record(0, physical_start_cluster=0)
    crc2_tree7 = b2.write_btree_leaf(35, [c0_rec])

    b2.write_superblock(31, 32, seq=1)
    b2.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc2_tree0, tree7_block=35, tree7_crc=crc2_tree7)
    b2.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc2_tree0, tree7_block=35, tree7_crc=crc2_tree7)

    img2 = b2.finalize()
    p2 = destination / "refs-v34-minimal.dd"
    p2.write_bytes(img2)
    manifest["cases"].append({
        "name": "refs-v34-minimal",
        "image": "refs-v34-minimal.dd",
        "sha256": sha256_bytes(img2),
        "outcome": "recover",
        "expected_version": "3.4",
        "target_name": "welcome.txt",
        "payload_sha256": sha256_bytes(p2_resident),
    })

    # Case 3: refs-v34-nested-dirs (/Documents/Work/report.pdf)
    print("Generating refs-v34-nested-dirs...")
    b3 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    b3.write_vbr(0)
    p3_pdf = b"%PDF-1.5 Synthetic ReFS nested document payload in /Documents/Work/report.pdf\n%%EOF"
    rec3_pdf = b3.build_dir_entry_record("report.pdf", 1, payload=p3_pdf, is_resident=True)
    crc3_work = b3.write_btree_leaf(38, [rec3_pdf])

    rec3_work_dir = b3.build_dir_entry_record("Work", 2, child_object_id=0x702)
    crc3_docs = b3.write_btree_leaf(37, [rec3_work_dir])

    rec3_docs_dir = b3.build_dir_entry_record("Documents", 2, child_object_id=0x701)
    crc3_root = b3.write_btree_leaf(34, [rec3_docs_dir])

    rec3_obj600 = (b3.build_object_record_key(0x600), b3.build_object_record_value(34, crc3_root))
    rec3_obj701 = (b3.build_object_record_key(0x701), b3.build_object_record_value(37, crc3_docs))
    rec3_obj702 = (b3.build_object_record_key(0x702), b3.build_object_record_value(38, crc3_work))
    crc3_tree0 = b3.write_btree_leaf(33, [rec3_obj600, rec3_obj701, rec3_obj702])

    crc3_tree7 = b3.write_btree_leaf(35, [b3.build_container_record(0, 0)])

    b3.write_superblock(31, 32, seq=1)
    b3.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc3_tree0, tree7_block=35, tree7_crc=crc3_tree7)
    b3.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc3_tree0, tree7_block=35, tree7_crc=crc3_tree7)

    img3 = b3.finalize()
    p3 = destination / "refs-v34-nested-dirs.dd"
    p3.write_bytes(img3)
    manifest["cases"].append({
        "name": "refs-v34-nested-dirs",
        "image": "refs-v34-nested-dirs.dd",
        "sha256": sha256_bytes(img3),
        "outcome": "recover",
        "expected_version": "3.4",
        "target_name": "report.pdf",
        "expected_path": "Documents/Work/report.pdf",
        "payload_sha256": sha256_bytes(p3_pdf),
    })

    # Case 4: refs-v34-discontiguous (4 extents across separate bands, Tree 7 container mapping)
    print("Generating refs-v34-discontiguous...")
    b4 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024, container_size=0x4000)
    b4.write_vbr(0)

    # 4 extents:
    # Extent 1: logical 0, 1 cluster (4096B) at physical 100
    # Extent 2: logical 4096, 2 clusters (8192B) at physical 120
    # Extent 3: logical 12288, 1 cluster (4096B) at physical 150
    # Extent 4: logical 16384, 1 cluster (4096B) at container 1 (virtual block 0x4000 + 10 -> physical 300 + 10 = 310)
    chunk1 = b"PART_1_AAAA" * 372 + b"1111"  # 4096
    chunk2 = b"PART_2_BBBB" * 744 + b"22222222"  # 8192
    chunk3 = b"PART_3_CCCC" * 372 + b"3333"  # 4096
    chunk4 = b"PART_4_DDDD" * 372 + b"4444"  # 4096
    full_frag_payload = chunk1 + chunk2 + chunk3 + chunk4  # 20480 bytes

    b4.write_raw_data(100, chunk1)
    b4.write_raw_data(120, chunk2)
    b4.write_raw_data(150, chunk3)
    b4.write_raw_data(310, chunk4)

    runs = [
        (0, 1, 100),
        (4096, 2, 120),
        (12288, 1, 150),
        (16384, 1, 0x4000 + 10),
    ]
    rec4 = b4.build_dir_entry_record("fragmented.bin", 1, payload=full_frag_payload, is_resident=False, cluster_extents=runs)
    crc4_root = b4.write_btree_leaf(34, [rec4])

    rec4_obj600 = (b4.build_object_record_key(0x600), b4.build_object_record_value(34, crc4_root))
    crc4_tree0 = b4.write_btree_leaf(33, [rec4_obj600])

    c0 = b4.build_container_record(0, physical_start_cluster=0)
    c1 = b4.build_container_record(1, physical_start_cluster=300)
    crc4_tree7 = b4.write_btree_leaf(35, [c0, c1])

    b4.write_superblock(31, 32, seq=1)
    b4.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc4_tree0, tree7_block=35, tree7_crc=crc4_tree7)
    b4.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc4_tree0, tree7_block=35, tree7_crc=crc4_tree7)

    img4 = b4.finalize()
    p4 = destination / "refs-v34-discontiguous.dd"
    p4.write_bytes(img4)
    manifest["cases"].append({
        "name": "refs-v34-discontiguous",
        "image": "refs-v34-discontiguous.dd",
        "sha256": sha256_bytes(img4),
        "outcome": "recover",
        "expected_version": "3.4",
        "target_name": "fragmented.bin",
        "payload_sha256": sha256_bytes(full_frag_payload),
    })

    # Case 5: refs-backup-vbr (Sector 0 zeroed; backup VBR at volume end)
    print("Generating refs-backup-vbr...")
    b5 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    # Write backup VBR at last sector: len(image) - 512
    last_sector_off = len(b5.image) - 512
    b5.write_vbr(last_sector_off, backup=True)
    # Sector 0 remains zeroes!

    p5_survivor = b"Recovered via Backup VBR at volume end!"
    rec5 = b5.build_dir_entry_record("survivor.txt", 1, payload=p5_survivor, is_resident=True)
    crc5_root = b5.write_btree_leaf(34, [rec5])

    rec5_obj600 = (b5.build_object_record_key(0x600), b5.build_object_record_value(34, crc5_root))
    crc5_tree0 = b5.write_btree_leaf(33, [rec5_obj600])

    crc5_tree7 = b5.write_btree_leaf(35, [b5.build_container_record(0, 0)])

    b5.write_superblock(31, 32, seq=1)
    b5.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc5_tree0, tree7_block=35, tree7_crc=crc5_tree7)
    b5.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc5_tree0, tree7_block=35, tree7_crc=crc5_tree7)

    img5 = b5.finalize()
    p5 = destination / "refs-backup-vbr.dd"
    p5.write_bytes(img5)
    manifest["cases"].append({
        "name": "refs-backup-vbr",
        "image": "refs-backup-vbr.dd",
        "sha256": sha256_bytes(img5),
        "outcome": "recover",
        "expected_version": "3.4",
        "target_name": "survivor.txt",
        "payload_sha256": sha256_bytes(p5_survivor),
    })

    # Case 6: refs-checkpoint-pingpong (Primary seq 42, Secondary seq 43 arbitrated)
    print("Generating refs-checkpoint-pingpong...")
    b6 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    b6.write_vbr(0)

    # Checkpoint 0 (block 31) has old file
    p6_old = b"Old file from sequence 42."
    rec6_old = b6.build_dir_entry_record("old_file.txt", 1, payload=p6_old, is_resident=True)
    crc6_root_old = b6.write_btree_leaf(34, [rec6_old])
    rec6_obj600_old = (b6.build_object_record_key(0x600), b6.build_object_record_value(34, crc6_root_old))
    crc6_tree0_old = b6.write_btree_leaf(33, [rec6_obj600_old])

    # Checkpoint 1 (block 32) has active file
    p6_active = b"Arbitrated latest checkpoint clock sequence 43."
    rec6_active = b6.build_dir_entry_record("active_version.txt", 1, payload=p6_active, is_resident=True)
    crc6_root_new = b6.write_btree_leaf(37, [rec6_active])
    rec6_obj600_new = (b6.build_object_record_key(0x600), b6.build_object_record_value(37, crc6_root_new))
    crc6_tree0_new = b6.write_btree_leaf(36, [rec6_obj600_new])

    crc6_tree7 = b6.write_btree_leaf(35, [b6.build_container_record(0, 0)])

    b6.write_superblock(31, 32, seq=1)
    b6.write_checkpoint(31, seq=42, tree0_block=33, tree0_crc=crc6_tree0_old, tree7_block=35, tree7_crc=crc6_tree7)
    b6.write_checkpoint(32, seq=43, tree0_block=36, tree0_crc=crc6_tree0_new, tree7_block=35, tree7_crc=crc6_tree7)

    img6 = b6.finalize()
    p6 = destination / "refs-checkpoint-pingpong.dd"
    p6.write_bytes(img6)
    manifest["cases"].append({
        "name": "refs-checkpoint-pingpong",
        "image": "refs-checkpoint-pingpong.dd",
        "sha256": sha256_bytes(img6),
        "outcome": "recover",
        "expected_version": "3.4",
        "target_name": "active_version.txt",
        "payload_sha256": sha256_bytes(p6_active),
    })

    # Case 7: refs-corrupted-crc (Leaf node bit flipped -> rejected with metadata_checksum_mismatch)
    print("Generating refs-corrupted-crc...")
    b7 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    b7.write_vbr(0)
    p7 = b"Payload that should not be extracted due to corrupt CRC."
    rec7 = b7.build_dir_entry_record("corrupted_node.txt", 1, payload=p7, is_resident=True)
    # Write corrupted leaf
    crc7_root = b7.write_btree_leaf(34, [rec7], corrupt=True)

    # Point to it with the uncorrupted CRC in Tree 0
    rec7_obj600 = (b7.build_object_record_key(0x600), b7.build_object_record_value(34, crc7_root))
    crc7_tree0 = b7.write_btree_leaf(33, [rec7_obj600])

    crc7_tree7 = b7.write_btree_leaf(35, [b7.build_container_record(0, 0)])

    b7.write_superblock(31, 32, seq=1)
    b7.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc7_tree0, tree7_block=35, tree7_crc=crc7_tree7)
    b7.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc7_tree0, tree7_block=35, tree7_crc=crc7_tree7)

    img7 = b7.finalize()
    p7_path = destination / "refs-corrupted-crc.dd"
    p7_path.write_bytes(img7)
    manifest["cases"].append({
        "name": "refs-corrupted-crc",
        "image": "refs-corrupted-crc.dd",
        "sha256": sha256_bytes(img7),
        "outcome": "reject",
        "target_name": "corrupted_node.txt",
    })

    # Case 8: refs-unsupported-compression (FILE_ATTRIBUTE_COMPRESSED 0x800)
    print("Generating refs-unsupported-compression...")
    b8 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    b8.write_vbr(0)
    p8 = b"Raw compressed cluster payload."
    rec8 = b8.build_dir_entry_record("compressed_file.bin", 1, payload=p8, is_resident=True, compressed=True)
    crc8_root = b8.write_btree_leaf(34, [rec8])

    rec8_obj600 = (b8.build_object_record_key(0x600), b8.build_object_record_value(34, crc8_root))
    crc8_tree0 = b8.write_btree_leaf(33, [rec8_obj600])

    crc8_tree7 = b8.write_btree_leaf(35, [b8.build_container_record(0, 0)])

    b8.write_superblock(31, 32, seq=1)
    b8.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc8_tree0, tree7_block=35, tree7_crc=crc8_tree7)
    b8.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc8_tree0, tree7_block=35, tree7_crc=crc8_tree7)

    img8 = b8.finalize()
    p8_path = destination / "refs-unsupported-compression.dd"
    p8_path.write_bytes(img8)
    manifest["cases"].append({
        "name": "refs-unsupported-compression",
        "image": "refs-unsupported-compression.dd",
        "sha256": sha256_bytes(img8),
        "outcome": "reject",
        "target_name": "compressed_file.bin",
    })

    # Case 9: refs-unicode-surrogates (Cyrillic, Chinese, spaces, and emoji surrogate pair)
    print("Generating refs-unicode-surrogates...")
    b9 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    b9.write_vbr(0)
    p9_cyrillic = "Тестовый документ ReFS на русском языке.".encode("utf-8")
    p9_chinese = "财务报告 ReFS 简体中文测试数据。".encode("utf-8")
    p9_space = b"File with spaces in filename test."
    p9_emoji = b"Emoji surrogate pair \xf0\x9f\x9a\x80 in ReFS filename."

    rec9_1 = b9.build_dir_entry_record("Документ_2026.docx", 1, payload=p9_cyrillic, is_resident=True)
    rec9_2 = b9.build_dir_entry_record("财务报告.xlsx", 1, payload=p9_chinese, is_resident=True)
    rec9_3 = b9.build_dir_entry_record("My Special Document.txt", 1, payload=p9_space, is_resident=True)
    rec9_4 = b9.build_dir_entry_record("Project🚀Plan.txt", 1, payload=p9_emoji, is_resident=True)
    crc9_root = b9.write_btree_leaf(34, [rec9_1, rec9_2, rec9_3, rec9_4])

    rec9_obj600 = (b9.build_object_record_key(0x600), b9.build_object_record_value(34, crc9_root))
    crc9_tree0 = b9.write_btree_leaf(33, [rec9_obj600])

    crc9_tree7 = b9.write_btree_leaf(35, [b9.build_container_record(0, 0)])

    b9.write_superblock(31, 32, seq=1)
    b9.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc9_tree0, tree7_block=35, tree7_crc=crc9_tree7)
    b9.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc9_tree0, tree7_block=35, tree7_crc=crc9_tree7)

    img9 = b9.finalize()
    p9_path = destination / "refs-unicode-surrogates.dd"
    p9_path.write_bytes(img9)
    manifest["cases"].append({
        "name": "refs-unicode-surrogates",
        "image": "refs-unicode-surrogates.dd",
        "sha256": sha256_bytes(img9),
        "outcome": "recover",
        "expected_version": "3.4",
        "target_name": "Project🚀Plan.txt",
        "payload_sha256": sha256_bytes(p9_emoji),
    })

    # Case 10: refs-deleted-salvage (Unreferenced B+ tree page in free space)
    print("Generating refs-deleted-salvage...")
    b10 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=1024)
    b10.write_vbr(0)

    # Active root directory has only 1 normal file
    p10_live = b"Active mounted file in root directory."
    rec10_live = b10.build_dir_entry_record("active.txt", 1, payload=p10_live, is_resident=True)
    crc10_root = b10.write_btree_leaf(34, [rec10_live])

    rec10_obj600 = (b10.build_object_record_key(0x600), b10.build_object_record_value(34, crc10_root))
    crc10_tree0 = b10.write_btree_leaf(33, [rec10_obj600])

    crc10_tree7 = b10.write_btree_leaf(35, [b10.build_container_record(0, 0)])

    # Write deleted file in free space at metadata block 80
    p10_deleted = b"Confidential financial statement 2026. Salvaged from free space ReFS page."
    b10.write_raw_data(250, p10_deleted)
    rec10_del = b10.build_dir_entry_record(
        "deleted_secret.doc",
        1,
        payload=p10_deleted,
        is_resident=False,
        cluster_extents=[(0, 1, 250)],
    )
    b10.write_btree_leaf(80, [rec10_del])

    b10.write_superblock(31, 32, seq=1)
    b10.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc10_tree0, tree7_block=35, tree7_crc=crc10_tree7)
    b10.write_checkpoint(32, seq=9, tree0_block=33, tree0_crc=crc10_tree0, tree7_block=35, tree7_crc=crc10_tree7)

    img10 = b10.finalize()
    p10_path = destination / "refs-deleted-salvage.dd"
    p10_path.write_bytes(img10)
    manifest["cases"].append({
        "name": "refs-deleted-salvage",
        "image": "refs-deleted-salvage.dd",
        "sha256": sha256_bytes(img10),
        "outcome": "salvage",
        "expected_version": "3.4",
        "target_name": "deleted_secret.doc",
        "payload_sha256": sha256_bytes(p10_deleted),
    })

    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "PROVENANCE.txt").write_text(
        "Synthetic test images and fixture manifest created for the USB-Recovery project from programmatically defined data. "
        "No personal data or third-party program binaries are embedded.\n",
        encoding="utf-8",
    )
    print(f"Generated 10 ReFS fixtures in {destination}")
    return manifest


def package_fixtures(source: Path, destination: Path):
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=True)
    manifest["compressed_images"] = {}
    for case in manifest["cases"]:
        name = case["image"]
        data = (source / name).read_bytes()
        target = destination / (name + ".gz")
        with target.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as comp:
                comp.write(data)
        manifest["compressed_images"][name] = {
            "archive": target.name,
            "archive_sha256": sha256_bytes(target.read_bytes()),
            "bytes": len(data),
        }
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "PROVENANCE.txt").write_text(
        "Packaged synthetic ReFS fixtures for offline regression verification.\n",
        encoding="utf-8",
    )
    print(f"Packaged {len(manifest['compressed_images'])} fixtures to {destination}")


def extract_fixtures(source: Path, destination: Path):
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=True)
    images = manifest.get("compressed_images", {})
    if images:
        for name, details in images.items():
            archive = source / details["archive"]
            target = destination / name
            if target.exists():
                try:
                    target.chmod(0o666)
                except Exception:
                    pass
            with gzip.open(archive, "rb") as comp:
                target.write_bytes(comp.read())
    else:
        # If not compressed, copy .dd files
        for case in manifest["cases"]:
            name = case["image"]
            target = destination / name
            if target.exists():
                try:
                    target.chmod(0o666)
                except Exception:
                    pass
            shutil.copy2(source / name, target)
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Extracted {len(manifest['cases'])} fixtures to {destination}")


def main():
    parser = argparse.ArgumentParser(description="ReFS test fixture generator and packager.")
    parser.add_argument("--destination", type=Path, help="Target directory for generated or extracted fixtures.")
    parser.add_argument("--package", type=Path, help="Package fixtures into target directory with .gz compression.")
    parser.add_argument("--extract", type=Path, help="Extract packaged fixtures from source directory.")
    args = parser.parse_args()

    if args.extract and args.destination:
        extract_fixtures(args.extract, args.destination)
    elif args.package:
        temp_dir = Path(".build/temp-refs-fixtures")
        generate_fixtures(temp_dir)
        package_fixtures(temp_dir, args.package)
        shutil.rmtree(temp_dir, ignore_errors=True)
    elif args.destination:
        generate_fixtures(args.destination)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
