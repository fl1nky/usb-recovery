# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adversarial ReFS fixture generator for challenger_m3_1.

Generates corrupted, mutated, boundary, and edge-case ReFS v1.2 and v3.4 synthetic images
to stress test RefsRecovery against structural corruption, invalid clocks, OOB pointers,
container translation, and checksum rejection.
"""
from __future__ import annotations

import struct
from pathlib import Path
import sys
sys.path.insert(0, ".")
from tests.refs_fixture_generator import ReFSVolumeBuilder, crc32c, crc64_ecma


def make_adv_fixtures(dest: Path) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    manifest = {}

    # Case 1: Corrupted VBR: Both primary and backup VBR destroyed
    b_vbr_both = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    # Don't write VBR, image remains zeroes
    path = dest / "adv-vbr-both-corrupt.dd"
    path.write_bytes(b_vbr_both.finalize())
    manifest["adv-vbr-both-corrupt"] = {"file": path.name, "expect": "reject_volume"}

    # Case 2: VBR invalid geometry: BytesPerSector=0, SectorsPerCluster=0, ContainerSize=0
    b_vbr_geom = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_vbr_geom.write_vbr(0)
    # Zero out BytesPerSector (offset 32) and SectorsPerCluster (offset 36)
    vbr_ba = bytearray(b_vbr_geom.image[0:512])
    struct.pack_into("<I", vbr_ba, 32, 0)
    struct.pack_into("<I", vbr_ba, 36, 0)
    b_vbr_geom.image[0:512] = vbr_ba
    path = dest / "adv-vbr-invalid-geom.dd"
    path.write_bytes(b_vbr_geom.finalize())
    manifest["adv-vbr-invalid-geom"] = {"file": path.name, "expect": "fallback_geom"}

    # Case 3: Unsupported Major Version: ReFS v2.0
    b_v2 = ReFSVolumeBuilder(major=2, minor=0, cluster_size=4096, total_clusters=128)
    b_v2.write_vbr(0)
    path = dest / "adv-vbr-unsupported-v2.dd"
    path.write_bytes(b_v2.finalize())
    manifest["adv-vbr-unsupported-v2"] = {"file": path.name, "expect": "unsupported_version"}

    # Case 4: Superblock signature corrupted (not "SUPB")
    b_sb_sig = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_sb_sig.write_vbr(0)
    b_sb_sig.write_superblock(31, 32, seq=1)
    sb_off = 30 * b_sb_sig.meta_block_size
    b_sb_sig.image[sb_off : sb_off + 4] = b"XXXX"
    path = dest / "adv-sb-invalid-sig.dd"
    path.write_bytes(b_sb_sig.finalize())
    manifest["adv-sb-invalid-sig"] = {"file": path.name, "expect": "sb_corrupt"}

    # Case 5: Dual Checkpoint Ping-Pong with Checkpoint 0 sequence higher than Checkpoint 1
    # Checkpoint 0 (block 31) seq=200, Checkpoint 1 (block 32) seq=100
    b_pp0 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_pp0.write_vbr(0)
    rec_res0 = b_pp0.build_dir_entry_record("file_from_chkp0.txt", 1, payload=b"chkp0_payload", is_resident=True)
    rec_res1 = b_pp0.build_dir_entry_record("file_from_chkp1.txt", 1, payload=b"chkp1_payload", is_resident=True)
    crc_root0 = b_pp0.write_btree_leaf(36, [rec_res0])
    crc_root1 = b_pp0.write_btree_leaf(38, [rec_res1])
    crc_t0_0 = b_pp0.write_btree_leaf(35, [(b_pp0.build_object_record_key(0x600), b_pp0.build_object_record_value(36, crc_root0))])
    crc_t0_1 = b_pp0.write_btree_leaf(37, [(b_pp0.build_object_record_key(0x600), b_pp0.build_object_record_value(38, crc_root1))])
    b_pp0.write_superblock(31, 32, seq=1)
    b_pp0.write_checkpoint(31, seq=200, tree0_block=35, tree0_crc=crc_t0_0)
    b_pp0.write_checkpoint(32, seq=100, tree0_block=37, tree0_crc=crc_t0_1)
    path = dest / "adv-chkp-pingpong-chkp0-higher.dd"
    path.write_bytes(b_pp0.finalize())
    manifest["adv-chkp-pingpong-chkp0-higher"] = {"file": path.name, "expect": "chkp0_selected"}

    # Case 6: Dual Checkpoint with Checkpoint 1 corrupted CRC (fallback to Checkpoint 0)
    b_pp_c1 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_pp_c1.write_vbr(0)
    crc_root_c = b_pp_c1.write_btree_leaf(36, [rec_res0])
    crc_t0_c = b_pp_c1.write_btree_leaf(35, [(b_pp_c1.build_object_record_key(0x600), b_pp_c1.build_object_record_value(36, crc_root_c))])
    b_pp_c1.write_superblock(31, 32, seq=1)
    b_pp_c1.write_checkpoint(31, seq=50, tree0_block=35, tree0_crc=crc_t0_c)
    b_pp_c1.write_checkpoint(32, seq=100, tree0_block=35, tree0_crc=crc_t0_c, corrupt=True)
    path = dest / "adv-chkp-pingpong-chkp1-corrupt.dd"
    path.write_bytes(b_pp_c1.finalize())
    manifest["adv-chkp-pingpong-chkp1-corrupt"] = {"file": path.name, "expect": "chkp0_fallback"}

    # Case 7: Both Checkpoints corrupted CRC (all_checkpoints_corrupt)
    b_pp_both = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_pp_both.write_vbr(0)
    b_pp_both.write_superblock(31, 32, seq=1)
    b_pp_both.write_checkpoint(31, seq=50, tree0_block=35, corrupt=True)
    b_pp_both.write_checkpoint(32, seq=100, tree0_block=35, corrupt=True)
    path = dest / "adv-chkp-both-corrupt.dd"
    path.write_bytes(b_pp_both.finalize())
    manifest["adv-chkp-both-corrupt"] = {"file": path.name, "expect": "all_checkpoints_corrupt"}

    # Case 8: Tree Node Cycle (Branch A -> Branch B -> Branch A)
    b_cycle = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_cycle.write_vbr(0)
    # Tree 0 at block 33 is branch pointing to 34. Block 34 is branch pointing to 33!
    # Write branch 34 pointing to 33
    def write_branch(block_num: int, child_block: int) -> int:
        offset = block_num * b_cycle.meta_block_size
        page = bytearray(b_cycle.meta_block_size)
        page[0:4] = b"MSB+"
        struct.pack_into("<II", page, 4, 1, 0)
        struct.pack_into("<QQ", page, 16, 1, 1)
        node_hdr_start = 80
        # NodeLevel = 1 (Branch), NodeTypeFlags = 1 (Branch)
        struct.pack_into("<IIIBBHIII", page, node_hdr_start, 0, 0, 0, 1, 1, 0, 32, 1, 0)
        tail = b_cycle.meta_block_size - (14 + 8 + 48)
        key = struct.pack("<Q", 0)
        val = bytearray(48)
        b_cycle.write_block_ref(val, 0, child_block)
        struct.pack_into("<IHHHHH", page, tail, 14 + len(key) + len(val), 14, len(key), 0, 14 + len(key), len(val))
        page[tail + 14 : tail + 14 + len(key)] = key
        page[tail + 14 + len(key) : tail + 14 + len(key) + len(val)] = val
        struct.pack_into("<I", page, node_hdr_start + 32, 0xFFFF0000 | ((tail - node_hdr_start) & 0xFFFF))
        crc = crc32c(page)
        b_cycle.image[offset : offset + b_cycle.meta_block_size] = page
        return crc

    crc34 = write_branch(34, 33)
    crc33 = write_branch(33, 34)
    # Re-write 34 with correct crc33 in pointer if needed, or with crc_type=0
    b_cycle.write_superblock(31, 32, seq=1)
    b_cycle.write_checkpoint(31, seq=10, tree0_block=33, crc_type=0)
    path = dest / "adv-tree-cycle.dd"
    path.write_bytes(b_cycle.finalize())
    manifest["adv-tree-cycle"] = {"file": path.name, "expect": "cycle_detected"}

    # Case 9: Circular Directories (Dir 0x600 contains Subdir 0x701, Subdir 0x701 contains 0x600)
    b_circ_dir = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_circ_dir.write_vbr(0)
    rec_d1 = b_circ_dir.build_dir_entry_record("sub", 2, child_object_id=0x701)
    rec_d2 = b_circ_dir.build_dir_entry_record("loop_back", 2, child_object_id=0x600)
    crc_d1 = b_circ_dir.write_btree_leaf(35, [rec_d1])
    crc_d2 = b_circ_dir.write_btree_leaf(36, [rec_d2])
    rec_obj600 = (b_circ_dir.build_object_record_key(0x600), b_circ_dir.build_object_record_value(35, crc_d1))
    rec_obj701 = (b_circ_dir.build_object_record_key(0x701), b_circ_dir.build_object_record_value(36, crc_d2))
    crc_t0_circ = b_circ_dir.write_btree_leaf(34, [rec_obj600, rec_obj701])
    b_circ_dir.write_superblock(31, 32, seq=1)
    b_circ_dir.write_checkpoint(31, seq=10, tree0_block=34, tree0_crc=crc_t0_circ)
    path = dest / "adv-dir-circular.dd"
    path.write_bytes(b_circ_dir.finalize())
    manifest["adv-dir-circular"] = {"file": path.name, "expect": "circular_dir_detected"}

    # Case 10: Unicode string decoding stress: emojis, lone surrogates, path separators
    b_uni = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_uni.write_vbr(0)
    # File with emoji: "test_\uD83D\uDE00.txt" and slashes "a/b\\c.txt"
    rec_u1 = b_uni.build_dir_entry_record("test_\U0001F600.txt", 1, payload=b"emoji_content", is_resident=True)
    rec_u2 = b_uni.build_dir_entry_record("bad/name\\test.txt", 1, payload=b"slash_content", is_resident=True)
    crc_u_root = b_uni.write_btree_leaf(34, [rec_u1, rec_u2])
    crc_u_t0 = b_uni.write_btree_leaf(33, [(b_uni.build_object_record_key(0x600), b_uni.build_object_record_value(34, crc_u_root))])
    b_uni.write_superblock(31, 32, seq=1)
    b_uni.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc_u_t0)
    path = dest / "adv-unicode-stress.dd"
    path.write_bytes(b_uni.finalize())
    manifest["adv-unicode-stress"] = {"file": path.name, "expect": "unicode_sanitized"}

    # Case 11: Container translation verification:
    # Container 0 (cluster 100), Container 1 (virtual 0x4010 -> physical cluster 150)
    b_cont = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=512, container_size=0x4000)
    b_cont.write_vbr(0)
    p_cont = b"PAYLOAD_CONTAINER_TRANSLATION_VERIFIED_7777777"
    b_cont.write_raw_data(150, p_cont)
    # Virtual cluster 0x4000 + 10 = 0x400A (16394)
    # Container 1 mapped to physical start 140 -> 140 + 10 = 150
    rec_cont_file = b_cont.build_dir_entry_record(
        "container_file.dat",
        1,
        payload=p_cont,
        is_resident=False,
        cluster_extents=[(0, 1, 0x400A)],
    )
    crc_cont_root = b_cont.write_btree_leaf(36, [rec_cont_file])
    rec_c0 = b_cont.build_container_record(0, 0)
    rec_c1 = b_cont.build_container_record(1, 140)
    crc_t7 = b_cont.write_btree_leaf(35, [rec_c0, rec_c1])
    crc_t0_cont = b_cont.write_btree_leaf(34, [(b_cont.build_object_record_key(0x600), b_cont.build_object_record_value(36, crc_cont_root))])
    b_cont.write_superblock(31, 32, seq=1)
    b_cont.write_checkpoint(31, seq=10, tree0_block=34, tree0_crc=crc_t0_cont, tree7_block=35, tree7_crc=crc_t7)
    path = dest / "adv-container-trans.dd"
    path.write_bytes(b_cont.finalize())
    manifest["adv-container-trans"] = {"file": path.name, "expect": "container_recovered"}

    # Case 12: Extent pointing beyond image EOF (Out-of-bounds extent)
    b_oob = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_oob.write_vbr(0)
    # Declared size 100 bytes, but extent points to physical cluster 999999 (far beyond image EOF of 128 clusters)
    rec_oob = b_oob.build_dir_entry_record(
        "oob_file.bin",
        1,
        payload=b"A" * 100,
        is_resident=False,
        cluster_extents=[(0, 1, 999999)],
    )
    crc_oob_root = b_oob.write_btree_leaf(34, [rec_oob])
    crc_oob_t0 = b_oob.write_btree_leaf(33, [(b_oob.build_object_record_key(0x600), b_oob.build_object_record_value(34, crc_oob_root))])
    b_oob.write_superblock(31, 32, seq=1)
    b_oob.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc_oob_t0)
    path = dest / "adv-extent-oob.dd"
    path.write_bytes(b_oob.finalize())
    manifest["adv-extent-oob"] = {"file": path.name, "expect": "oob_extent_behavior"}

    # Case 13: Extent with declaredSize = 0 but non-resident extents present
    b_zero_size = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_zero_size.write_vbr(0)
    # We craft record with declaredSize = 0 (offset 64 in value = 0)
    rec_zs_key, rec_zs_val = b_zero_size.build_dir_entry_record(
        "zerosize_file.bin",
        1,
        payload=b"",
        is_resident=False,
        cluster_extents=[(0, 2, 50)],
    )
    # Explicitly set declared size at 64 to 0
    zs_val_ba = bytearray(rec_zs_val)
    struct.pack_into("<QQ", zs_val_ba, 64, 0, 0)
    b_zero_size.write_raw_data(50, b"DATA_IN_CLUSTER_50" * 100)
    crc_zs_root = b_zero_size.write_btree_leaf(34, [(rec_zs_key, bytes(zs_val_ba))])
    crc_zs_t0 = b_zero_size.write_btree_leaf(33, [(b_zero_size.build_object_record_key(0x600), b_zero_size.build_object_record_value(34, crc_zs_root))])
    b_zero_size.write_superblock(31, 32, seq=1)
    b_zero_size.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc_zs_t0)
    path = dest / "adv-zero-declared-size.dd"
    path.write_bytes(b_zero_size.finalize())
    manifest["adv-zero-declared-size"] = {"file": path.name, "expect": "zero_size_extent_behavior"}

    # Case 14: Extent with huge block count / negative wraparound (physBlk = 0xFFFFFFFFFFFFFFFF)
    b_huge_blk = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_huge_blk.write_vbr(0)
    rec_huge = b_huge_blk.build_dir_entry_record(
        "huge_blk_file.bin",
        1,
        payload=b"A" * 100,
        is_resident=False,
        cluster_extents=[(0, 1, 0xFFFFFFFFFFFFFFFF)],
    )
    crc_huge_root = b_huge_blk.write_btree_leaf(34, [rec_huge])
    crc_huge_t0 = b_huge_blk.write_btree_leaf(33, [(b_huge_blk.build_object_record_key(0x600), b_huge_blk.build_object_record_value(34, crc_huge_root))])
    b_huge_blk.write_superblock(31, 32, seq=1)
    b_huge_blk.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc_huge_t0)
    path = dest / "adv-physblk-negative-wrap.dd"
    path.write_bytes(b_huge_blk.finalize())
    manifest["adv-physblk-negative-wrap"] = {"file": path.name, "expect": "negative_wrap_behavior"}

    # Case 15: CRC64 Checkpoint and Tree Reference Single-Bit Corruption
    b_crc64 = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_crc64.write_vbr(0)
    rec_c64 = b_crc64.build_dir_entry_record("crc64_test.txt", 1, payload=b"valid_payload", is_resident=True)
    crc32_root = b_crc64.write_btree_leaf(34, [rec_c64])
    # Build Tree 0 record with CRC64 type 2
    # First compute CRC64 of block 34
    block34_data = b_crc64.image[34 * 4096 : 35 * 4096]
    crc64_root = crc64_ecma(block34_data)
    val_tree0 = bytearray(48)
    b_crc64.write_block_ref(val_tree0, 0, 34, expected_crc=crc64_root, crc_type=2)
    crc32_t0 = b_crc64.write_btree_leaf(33, [(b_crc64.build_object_record_key(0x600), bytes(val_tree0))])
    b_crc64.write_superblock(31, 32, seq=1)
    b_crc64.write_checkpoint(31, seq=10, tree0_block=33, tree0_crc=crc32_t0)
    path = dest / "adv-crc64-valid.dd"
    path.write_bytes(b_crc64.finalize())
    manifest["adv-crc64-valid"] = {"file": path.name, "expect": "crc64_valid"}

    # Corrupt 1 bit in block 34 for CRC64 rejection test
    b_crc64_corrupt = ReFSVolumeBuilder(major=3, minor=4, cluster_size=4096, total_clusters=128)
    b_crc64_corrupt.image[:] = b_crc64.image[:]
    b_crc64_corrupt.image[34 * 4096 + 100] ^= 0x01  # Flip 1 bit
    path = dest / "adv-crc64-corrupt-bit.dd"
    path.write_bytes(b_crc64_corrupt.finalize())
    manifest["adv-crc64-corrupt-bit"] = {"file": path.name, "expect": "crc64_rejected"}

    return manifest


if __name__ == "__main__":
    dest = Path(".build/refs-adversarial-fixtures")
    manifest = make_adv_fixtures(dest)
    print(f"Generated {len(manifest)} adversarial fixtures in {dest}")
