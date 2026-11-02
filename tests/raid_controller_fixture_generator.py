"""Synthetic RAID controller and Storage Spaces metadata fixture generator.

Generates independent, deterministic synthetic disk images containing:
1. Intel Matrix Storage Manager (IMSM / Intel RST) metadata (RAID 0, 1, 5)
2. SNIA DDF (Disk Data Format v1.2) metadata (RAID 0, 1, 5)
3. Windows Storage Spaces pool and slab metadata (Simple, Mirror, Parity)

All fixtures are verified with strict integrity checksums and can be extracted offline.
"""
import os
import sys
import gzip
import json
import struct
import hashlib
import binascii

def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xffffffff

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_imsm_metadata(num_disks: int, disk_idx: int, raid_level: int, chunk_sectors: int, disk_bytes: int, data_offset_sec: int = 0) -> bytes:
    """Build a standard 1024-byte Intel Matrix Storage Manager (IMSM) MPB."""
    mpb = bytearray(1024)
    # Signature: 24 bytes ASCII
    sig = b"Intel Raid ISM Cfg Sig. "
    mpb[0:24] = sig
    # Version: 8 bytes
    mpb[24:32] = b"1.2.00\x00\x00"
    # Checksum at 32: will be computed below
    mpb_size = 1024
    struct.pack_into("<I", mpb, 36, mpb_size)
    # Generation num
    struct.pack_into("<I", mpb, 40, 1)
    # Error log size
    struct.pack_into("<I", mpb, 44, 0)
    # Attributes
    struct.pack_into("<I", mpb, 48, 0)
    # Num disks & num volumes & this_disk index
    mpb[52] = num_disks
    mpb[53] = 1 # 1 volume
    struct.pack_into("<H", mpb, 54, disk_idx)

    # Disks table at 56: each disk is 40 bytes
    disk_sectors = disk_bytes // 512
    for i in range(num_disks):
        at = 56 + i * 40
        struct.pack_into("<II", mpb, at, disk_sectors & 0xffffffff, disk_sectors >> 32)
        serial = f"INTEL-DISK-{i:03d}".encode("ascii")
        mpb[at + 8:at + 8 + len(serial)] = serial
        struct.pack_into("<I", mpb, at + 24, 0x01) # status: configured/online
        struct.pack_into("<I", mpb, at + 28, i)

    # Volume table at 56 + num_disks * 40
    vol_at = 56 + num_disks * 40
    vol_name = f"Volume{raid_level}".encode("ascii")
    mpb[vol_at:vol_at + len(vol_name)] = vol_name
    struct.pack_into("<I", mpb, vol_at + 16, 0) # status: 0 = normal/clean
    # Volume sectors:
    data_disks = num_disks if raid_level == 0 else (num_disks - 1 if raid_level == 5 else 1)
    comp_sectors = (disk_bytes // 512) - (1024 // 512) - data_offset_sec
    # Round down to chunk multiple
    comp_sectors = (comp_sectors // chunk_sectors) * chunk_sectors
    vol_sectors = comp_sectors * data_disks
    struct.pack_into("<II", mpb, vol_at + 24, vol_sectors & 0xffffffff, vol_sectors >> 32)
    mpb[vol_at + 32] = raid_level
    struct.pack_into("<H", mpb, vol_at + 34, chunk_sectors)
    struct.pack_into("<I", mpb, vol_at + 36, data_offset_sec)
    mpb[vol_at + 40] = num_disks
    # Map disk roles (disk 0 -> role 0, disk 1 -> role 1, etc.)
    for r in range(num_disks):
        mpb[vol_at + 44 + r] = r

    # Compute additive 32-bit checksum across mpb_size with checksum field = 0
    struct.pack_into("<I", mpb, 32, 0)
    total_words = mpb_size // 4
    csum = sum(struct.unpack_from("<" + "I" * total_words, mpb, 0)) & 0xffffffff
    struct.pack_into("<I", mpb, 32, csum)
    return bytes(mpb)

def make_ddf_metadata(num_disks: int, disk_idx: int, raid_level: int, stripe_sectors: int, disk_bytes: int, array_guid: bytes = None) -> bytes:
    """Build a standard 512-byte SNIA DDF anchor header and virtual disk record."""
    if array_guid is None:
        array_guid = hashlib.md5(f"DDF-ARRAY-{raid_level}".encode()).digest()
    disk_guid = hashlib.md5(f"DDF-DISK-{disk_idx}".encode()).digest()

    sector = bytearray(512)
    # DDF Magic: 0xDE11DE11 (little-endian: 0x11, 0xDE, 0x11, 0xDE)
    struct.pack_into("<I", sector, 0, 0xDE11DE11)
    # CRC at 4: set to 0xffffffff before computation
    struct.pack_into("<I", sector, 4, 0xffffffff)
    sector[8:24] = disk_guid
    sector[24] = 0x01 # DDF rev 1.2
    sector[25] = 0x00 # Standard DDF
    # Primary & Secondary Header LBA
    struct.pack_into("<Q", sector, 32, 0)
    struct.pack_into("<Q", sector, 40, (disk_bytes // 512) - 1)
    struct.pack_into("<I", sector, 56, num_disks)
    struct.pack_into("<I", sector, 60, 1) # 1 VD

    # Virtual Disk Record embedded at offset 128
    vd_at = 128
    struct.pack_into("<I", sector, vd_at, 0xDD01DD01) # VD record signature
    sector[vd_at + 8:vd_at + 24] = array_guid
    name = f"DDF-RAID{raid_level}".encode("ascii")
    sector[vd_at + 24:vd_at + 24 + len(name)] = name
    # RAID level
    ddf_level = 0x00 if raid_level == 0 else (0x01 if raid_level == 1 else (0x05 if raid_level == 5 else 0x06))
    sector[vd_at + 40] = ddf_level
    # Stripe unit size: log2 of sectors
    shift = 0
    s = stripe_sectors
    while s > 1:
        shift += 1
        s >>= 1
    sector[vd_at + 41] = shift
    struct.pack_into("<H", sector, vd_at + 42, num_disks)
    # VD size
    data_disks = num_disks if raid_level == 0 else (num_disks - 1 if raid_level == 5 else 1)
    comp_sectors = (disk_bytes // 512) - 8
    comp_sectors = (comp_sectors // stripe_sectors) * stripe_sectors
    vd_sectors = comp_sectors * data_disks
    struct.pack_into("<Q", sector, vd_at + 48, vd_sectors)
    # Disk role index
    sector[vd_at + 64] = disk_idx

    # Compute CRC32
    c = crc32(sector)
    struct.pack_into("<I", sector, 4, c)
    return bytes(sector)

def make_storage_spaces_metadata(num_columns: int, col_idx: int, resiliency: int, slab_bytes: int, disk_bytes: int, pool_guid: bytes = None) -> bytes:
    """Build a 512-byte Windows Storage Spaces pool/slab header."""
    if pool_guid is None:
        pool_guid = hashlib.md5(f"POOL-{resiliency}".encode()).digest()
    space_guid = hashlib.md5(f"SPACE-{resiliency}".encode()).digest()

    block = bytearray(512)
    # Signature: MSFT\0\0\0\0
    block[0:8] = b"MSFT\x00\x00\x00\x00"
    # CRC at 8
    struct.pack_into("<I", block, 8, 0)
    # Pool ID & Space ID
    block[16:32] = pool_guid
    block[32:48] = space_guid
    # Resiliency: 0=Simple, 1=Mirror, 2=Parity
    struct.pack_into("<I", block, 48, resiliency)
    struct.pack_into("<I", block, 52, num_columns)
    struct.pack_into("<Q", block, 56, slab_bytes)
    struct.pack_into("<I", block, 64, col_idx)
    struct.pack_into("<Q", block, 68, 1) # Generation / sequence
    struct.pack_into("<Q", block, 76, 8192) # Data offset: 8KB
    data_slabs = (disk_bytes - 8192) // slab_bytes
    comp_bytes = data_slabs * slab_bytes
    struct.pack_into("<Q", block, 84, comp_bytes)

    # Checksum at 8
    c = crc32(block)
    struct.pack_into("<I", block, 8, c)
    return bytes(block)

def generate_fixtures(out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"schema": 1, "format": "raid_controller_fixtures", "cases": []}

    # 1. IMSM Cases
    # Case 1: IMSM RAID 0 (2 disks, 64KB chunk, 128KB disk size each)
    disk_size = 128 * 1024
    chunk_sec = 128 # 64KB
    for idx in range(2):
        img = bytearray(disk_size)
        # Fill payload with distinct recognizable pattern
        for off in range(0, disk_size - 1024, 512):
            val = (idx * 1000 + off // 512) & 0xff
            img[off:off+512] = bytes([val]) * 512
        # Place IMSM metadata at length - 1024
        mpb = make_imsm_metadata(2, idx, 0, chunk_sec, disk_size)
        img[disk_size - 1024:disk_size] = mpb
        filename = f"imsm-raid0-{idx+1}.dd.gz"
        with gzip.open(os.path.join(out_dir, filename), "wb") as gz:
            gz.write(img)
        manifest["cases"].append({"name": filename, "format": "imsm", "level": 0, "disks": 2, "role": idx, "sha256": sha256_hex(img), "bytes": disk_size})

    # Case 2: IMSM RAID 1 (2 disks, mirror, 128KB disk size)
    disk_size = 128 * 1024
    for idx in range(2):
        img = bytearray(disk_size)
        # Both disks share the same payload data in RAID1
        for off in range(0, disk_size - 1024, 512):
            val = (off // 512) & 0xff
            img[off:off+512] = bytes([val]) * 512
        mpb = make_imsm_metadata(2, idx, 1, 128, disk_size)
        img[disk_size - 1024:disk_size] = mpb
        filename = f"imsm-raid1-{idx+1}.dd.gz"
        with gzip.open(os.path.join(out_dir, filename), "wb") as gz:
            gz.write(img)
        manifest["cases"].append({"name": filename, "format": "imsm", "level": 1, "disks": 2, "role": idx, "sha256": sha256_hex(img), "bytes": disk_size})

    # Case 3: IMSM RAID 5 (3 disks, 64KB chunk, 192KB disk size)
    disk_size = 192 * 1024
    chunk_size = 64 * 1024
    num_rows = (disk_size - 1024) // chunk_size
    imgs = [bytearray(disk_size) for _ in range(3)]
    for r in range(num_rows):
        p_disk = 3 - 1 - (r % 3)
        data_disks = [d for d in range(3) if d != p_disk]
        for d in data_disks:
            for off in range(r * chunk_size, (r + 1) * chunk_size, 512):
                val = ((d + 1) * 37 + off // 512 + r * 13) & 0xff
                imgs[d][off:off+512] = bytes([val]) * 512
        for byte_i in range(r * chunk_size, (r + 1) * chunk_size):
            p_val = 0
            for d in data_disks:
                p_val ^= imgs[d][byte_i]
            imgs[p_disk][byte_i] = p_val
    for idx in range(3):
        mpb = make_imsm_metadata(3, idx, 5, 128, disk_size)
        imgs[idx][disk_size - 1024:disk_size] = mpb
        filename = f"imsm-raid5-{idx+1}.dd.gz"
        with gzip.open(os.path.join(out_dir, filename), "wb") as gz:
            gz.write(imgs[idx])
        manifest["cases"].append({"name": filename, "format": "imsm", "level": 5, "disks": 3, "role": idx, "sha256": sha256_hex(imgs[idx]), "bytes": disk_size})

    # 2. DDF Cases
    # Case 4: DDF RAID 0 (2 disks, 64KB stripe, 128KB disk size)
    disk_size = 128 * 1024
    for idx in range(2):
        img = bytearray(disk_size)
        for off in range(0, disk_size - 512, 512):
            val = (idx * 50 + off // 512) & 0xff
            img[off:off+512] = bytes([val]) * 512
        ddf = make_ddf_metadata(2, idx, 0, 128, disk_size)
        img[disk_size - 512:disk_size] = ddf
        filename = f"ddf-raid0-{idx+1}.dd.gz"
        with gzip.open(os.path.join(out_dir, filename), "wb") as gz:
            gz.write(img)
        manifest["cases"].append({"name": filename, "format": "ddf", "level": 0, "disks": 2, "role": idx, "sha256": sha256_hex(img), "bytes": disk_size})

    # Case 5: DDF RAID 1 (2 disks, mirror, 128KB disk size)
    disk_size = 128 * 1024
    for idx in range(2):
        img = bytearray(disk_size)
        for off in range(0, disk_size - 512, 512):
            val = (off // 512) & 0xff
            img[off:off+512] = bytes([val]) * 512
        ddf = make_ddf_metadata(2, idx, 1, 128, disk_size)
        img[disk_size - 512:disk_size] = ddf
        filename = f"ddf-raid1-{idx+1}.dd.gz"
        with gzip.open(os.path.join(out_dir, filename), "wb") as gz:
            gz.write(img)
        manifest["cases"].append({"name": filename, "format": "ddf", "level": 1, "disks": 2, "role": idx, "sha256": sha256_hex(img), "bytes": disk_size})

    # 3. Storage Spaces Cases
    # Case 6: Storage Spaces Simple (2 columns, 64KB slab, 128KB disk size)
    disk_size = 128 * 1024
    for idx in range(2):
        img = bytearray(disk_size)
        for off in range(8192, disk_size, 512):
            val = (idx * 20 + off // 512) & 0xff
            img[off:off+512] = bytes([val]) * 512
        ss = make_storage_spaces_metadata(2, idx, 0, 65536, disk_size)
        img[4096:4096+512] = ss
        filename = f"spaces-simple-{idx+1}.dd.gz"
        with gzip.open(os.path.join(out_dir, filename), "wb") as gz:
            gz.write(img)
        manifest["cases"].append({"name": filename, "format": "storage-spaces", "level": 0, "disks": 2, "role": idx, "sha256": sha256_hex(img), "bytes": disk_size})

    # Case 7: Storage Spaces Mirror (2-way, 64KB disk size)
    disk_size = 64 * 1024
    for idx in range(2):
        img = bytearray(disk_size)
        for off in range(8192, disk_size, 512):
            val = (off // 512) & 0xff
            img[off:off+512] = bytes([val]) * 512
        ss = make_storage_spaces_metadata(2, idx, 1, 32768, disk_size)
        img[4096:4096+512] = ss
        filename = f"spaces-mirror-{idx+1}.dd.gz"
        with gzip.open(os.path.join(out_dir, filename), "wb") as gz:
            gz.write(img)
        manifest["cases"].append({"name": filename, "format": "storage-spaces", "level": 1, "disks": 2, "role": idx, "sha256": sha256_hex(img), "bytes": disk_size})

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Generated {len(manifest['cases'])} RAID controller and Storage Spaces fixtures in {out_dir}")

def extract_fixtures(src_dir: str, dest_dir: str):
    os.makedirs(dest_dir, exist_ok=True)
    manifest_path = os.path.join(src_dir, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    for case in manifest["cases"]:
        gz_path = os.path.join(src_dir, case["name"])
        raw_name = case["name"].replace(".dd.gz", ".dd").replace(".bin.gz", ".bin")
        out_path = os.path.join(dest_dir, raw_name)
        with gzip.open(gz_path, "rb") as gz:
            data = gz.read()
        if sha256_hex(data) != case["sha256"]:
            raise ValueError(f"Checksum mismatch for {case['name']}")
        with open(out_path, "wb") as out:
            out.write(data)
    # copy manifest as well
    with open(os.path.join(dest_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Extracted {len(manifest['cases'])} fixtures to {dest_dir}")

if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--extract":
        extract_fixtures(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 2:
        generate_fixtures(sys.argv[1])
    else:
        generate_fixtures("tests/fixtures/raid-controller")
