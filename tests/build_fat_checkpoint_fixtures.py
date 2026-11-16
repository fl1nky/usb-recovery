"""Owned FAT16 directory/ownership controls, independent of recovery code.

These structural fixtures supplement mkfs.fat/mtools native corpus checks;
they are not presented as native-formatted images or physical devices.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys


def large_mapping(root):
    count, size, fat_sectors, data_sector = 100001, 128 * 1024 * 1024, 2048, 32 + 4096
    image = bytearray(size)
    image[:3] = b'\xeb\x58\x90'; image[3:11] = b'OWNEDFS '
    struct.pack_into('<HBHBHHBHHHII', image, 11, 512, 1, 32, 2, 0, 0, 0xf8, 0, 32, 64, 0, size // 512)
    struct.pack_into('<IHHIHH', image, 36, fat_sectors, 0, 0, 2, 1, 6)
    image[64:67] = b'\x80\x00\x29'; image[71:82] = b'OWNED TEST '; image[82:90] = b'FAT32   '; image[510:512] = b'\x55\xaa'
    fat = bytearray(fat_sectors * 512)
    for cluster, value in ((0, 0x0ffffff8), (1, 0x0fffffff), (2, 0x0fffffff)):
        struct.pack_into('<I', fat, cluster * 4, value)
    original = bytearray(count * 512)
    for n in range(count):
        cluster = 1000 + n * 2
        struct.pack_into('<I', fat, cluster * 4, 0x0fffffff if n == count - 1 else cluster + 2)
        payload = struct.pack('<I', n) * 128
        original[n * 512:(n + 1) * 512] = payload
        offset = (data_sector + cluster - 2) * 512
        image[offset:offset + 512] = payload
    image[32 * 512:(32 + fat_sectors) * 512] = fat
    image[(32 + fat_sectors) * 512:(32 + 2 * fat_sectors) * 512] = fat
    directory = data_sector * 512
    image[directory:directory + 11] = b'\xe5UGE    BIN'; image[directory + 11] = 0x20
    struct.pack_into('<H', image, directory + 26, 1000)
    struct.pack_into('<I', image, directory + 28, len(original))
    path = root / 'map-limit.dd'; path.write_bytes(image)
    (root / 'map-limit.dd.sha256').write_text(hashlib.sha256(image).hexdigest() + '\n', encoding='ascii')
    (root / 'map-limit-original.bin').write_bytes(original)
    (root / 'map-limit.json').write_text(json.dumps({'sha256': hashlib.sha256(original).hexdigest(), 'bytes': len(original),
        'ranges': count, 'scope': 'structural FAT32 retained chain with more source ranges than the evidence cap'}) + '\n', encoding='utf-8')


def build(destination):
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=False)
    image = bytearray(16 * 1024 * 1024)
    sectors, fat_sectors, root_entries = len(image) // 512, 128, 512
    data_sector = 1 + fat_sectors * 2 + root_entries // 16
    image[:3] = b'\xeb\x3c\x90'; image[3:11] = b'OWNEDFS '
    struct.pack_into('<HBHBHHBHHHII', image, 11, 512, 1, 1, 2, root_entries, sectors, 0xf8, fat_sectors, 32, 64, 0, 0)
    image[36:39] = b'\x80\x00\x29'; image[43:54] = b'OWNED TEST '; image[54:62] = b'FAT16   '; image[510:512] = b'\x55\xaa'
    fat_offsets = [512, 512 + fat_sectors * 512]
    root_offset = (1 + fat_sectors * 2) * 512

    def cluster(number):
        return (data_sector + number - 2) * 512

    def fat(number, value):
        for offset in fat_offsets:
            struct.pack_into('<H', image, offset + number * 2, value)

    def entry(offset, name, start, size, deleted=False, directory=False):
        assert len(name) == 11
        image[offset:offset + 11] = name
        if deleted: image[offset] = 0xe5
        image[offset + 11] = 0x10 if directory else 0x20
        struct.pack_into('<H', image, offset + 26, start)
        struct.pack_into('<I', image, offset + 28, size)

    fat(0, 0xfff8); fat(1, 0xffff)
    expected = []
    for directory in range(10):
        number = 2 + directory
        fat(number, 0xffff)
        entry(root_offset + directory * 32, f'DIR{directory:05d}   '.encode(), number, 0, directory=True)
        at = cluster(number)
        entry(at, b'.          ', number, 0, directory=True)
        entry(at + 32, b'..         ', 0, 0, directory=True)
        for member in range(8):
            target = 100 + directory * 8 + member
            if directory == 0 and member == 0:
                target = 10000  # outside directory-reader buffers for a real read-lock fault
            payload = (f'owned FAT record {directory}:{member}\n'.encode() * 13)[:400]
            image[cluster(target):cluster(target) + len(payload)] = payload
            name = f'F{directory:02d}{member:05d}BIN'.encode()
            entry(at + 64 + member * 32, name, target, len(payload), deleted=True)
            expected.append({'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                             'offset': cluster(target), 'directory': directory, 'member': member})
    # A live owner encountered late protects an otherwise identical deleted entry.
    live = 300; fat(live, 0xffff)
    entry(cluster(11) + 64 + 8 * 32, b'LIVE    BIN', live, 100)
    entry(cluster(2) + 64 + 8 * 32, b'CLAIM   BIN', live, 100, deleted=True)
    image[cluster(live):cluster(live) + 100] = b'L' * 100
    # Unlinked directory: no parent identity/deletion inference is possible.
    orphan = 500; fat(orphan, 0xffff)
    entry(cluster(orphan), b'.          ', orphan, 0, directory=True)
    entry(cluster(orphan) + 32, b'..         ', 0, 0, directory=True)
    lost = b'owned unlinked directory payload\n' * 29
    entry(cluster(orphan) + 64, b'LOST    BIN', 600, len(lost))
    image[cluster(600):cluster(600) + len(lost)] = lost
    (root / 'orphan-original.bin').write_bytes(lost)
    path = root / 'directories.dd'; path.write_bytes(image)
    digest = hashlib.sha256(image).hexdigest()
    (root / 'directories.dd.sha256').write_text(digest + '\n', encoding='ascii')
    (root / 'directories.json').write_text(json.dumps({'image_sha256': digest, 'files': expected,
        'scope': 'structural FAT16 checkpoint and late live-owner controls; native formatting tested separately'}, indent=2) + '\n', encoding='utf-8')
    large_mapping(root)
    print(root)


if __name__ == '__main__':
    build(sys.argv[1])
