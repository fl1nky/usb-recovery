"""Produce owned NTFS record controls independently of the recovery parser."""
from __future__ import annotations
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resident(kind: int, value: bytes) -> bytes:
    data = bytearray((24 + len(value) + 7) & ~7)
    struct.pack_into('<II', data, 0, kind, len(data))
    struct.pack_into('<IH', data, 16, len(value), 24)
    data[24:24 + len(value)] = value
    return bytes(data)


def file_record(number: int, name: str, payload: bytes, *, flags: int = 0,
                parent: int = 5, data_attribute: bytes | None = None, record_bytes: int = 1024) -> bytes:
    encoded = name.encode('utf-16le')
    filename = bytearray(66 + len(encoded))
    struct.pack_into('<Q', filename, 0, parent | (1 << 48))
    filename[64:66] = bytes([len(encoded) // 2, 1])
    filename[66:] = encoded
    attributes = resident(0x30, filename) + (resident(0x80, payload) if data_attribute is None else data_attribute)
    sectors = record_bytes // 512
    first = (48 + (sectors + 1) * 2 + 7) & ~7
    data = bytearray(record_bytes)
    data[:4] = b'FILE'
    struct.pack_into('<HH', data, 4, 48, sectors + 1)
    struct.pack_into('<HHHH', data, 16, 1, 1, first, flags)
    struct.pack_into('<II', data, 24, first + len(attributes) + 8, record_bytes)
    struct.pack_into('<I', data, 44, number)
    assert first + len(attributes) + 8 <= record_bytes
    data[first:first + len(attributes)] = attributes
    struct.pack_into('<I', data, first + len(attributes), 0xffffffff)
    struct.pack_into('<H', data, 48, 0xb7a1)
    for sector in range(1, sectors + 1):
        tail = sector * 512 - 2
        data[48 + sector * 2:50 + sector * 2] = data[tail:tail + 2]
        struct.pack_into('<H', data, tail, 0xb7a1)
    return bytes(data)


def budget_images(destination: Path) -> dict:
    image = bytearray(24 * 1024 * 1024)
    for index in range(20001):
        offset = 1024 * 1024 + index * 1024
        image[offset:offset + 1024] = file_record(42 + index, 'limit.bin', b'owned-limit')
    (destination / 'candidate-limit.dd').write_bytes(image)
    candidates_hash = digest(image)
    image = bytearray(4 * 1024 * 1024)
    mapping = b'\x11\x01\x01' * 2000 + b'\x00'
    attribute = bytearray((64 + len(mapping) + 7) & ~7)
    struct.pack_into('<II', attribute, 0, 0x80, len(attribute))
    attribute[8] = 1
    struct.pack_into('<QQH', attribute, 16, 0, 1999, 64)
    struct.pack_into('<QQQ', attribute, 40, 2000 * 512, 1024, 1024)
    attribute[64:64 + len(mapping)] = mapping
    for index in range(126):
        offset = 1024 * 1024 + index * 8192
        image[offset:offset + 8192] = file_record(42 + index, 'runs.bin', b'', data_attribute=attribute, record_bytes=8192)
    (destination / 'run-limit.dd').write_bytes(image)
    return {'candidate_sha256': candidates_hash, 'run_sha256': digest(image),
            'scope': '20001 records and 126 records with 2000 mapping runs; no output quality claim'}


def path_image(destination: Path) -> dict:
    image = bytearray(2 * 1024 * 1024)
    image[0:3] = b'\xeb\x52\x90'
    image[3:11] = b'NTFS    '
    struct.pack_into('<H', image, 11, 512)
    image[13] = 8
    struct.pack_into('<QQ', image, 40, len(image) // 512 - 1, 4)
    image[64] = 246  # -10: a 1024-byte FILE record
    image[510:512] = b'\x55\xaa'
    stream = bytearray(72)
    struct.pack_into('<II', stream, 0, 0x80, len(stream))
    stream[8] = 1
    struct.pack_into('<QQH', stream, 16, 0, 15, 64)
    struct.pack_into('<QQQ', stream, 40, 65536, 65536, 65536)
    stream[64:68] = b'\x11\x10\x04\x00'
    bitmap = bytearray(64)
    bitmap[0:3] = b'\xff\xff\x0f'
    records = {0: file_record(0, '$MFT', b'', flags=1, data_attribute=stream),
               5: file_record(5, '.', b'', flags=3),
               6: file_record(6, '$Bitmap', bitmap, flags=1),
               20: file_record(20, 'Архив', b'', flags=3),
               21: file_record(21, 'Предки', b'', flags=2, parent=20)}
    expected = []
    for index in range(5):
        name = f'recipe{index}.txt'
        payload = (f'path original {index}\n'.encode('ascii') + b'p' * 450)[:450]
        records[42 + index] = file_record(42 + index, name, payload, parent=21 if index < 3 else 26)
        expected.append({'sha256': digest(payload), 'original_path': f'/Архив/Предки/{name}' if index < 3 else None})
    for number, record in records.items():
        offset = 4 * 4096 + number * 1024
        image[offset:offset + 1024] = record
    (destination / 'paths.dd').write_bytes(image)
    return {'image_sha256': digest(image), 'files': expected,
            'scope': 'structural current MFT, valid and invalid shared parent-cache controls'}


def produce(destination: Path) -> None:
    destination = destination.absolute()
    if destination.exists() or any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError('Choose a fresh destination without links')
    source = Path(__file__).resolve().parent / 'fixtures/ntfs-records'
    manifest = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
    packed = source / 'legacy-usa-torn.dd.gz'
    expected = source / 'legacy-expected.jpg'
    if (manifest['schema'] != 1 or packed.is_symlink() or expected.is_symlink()
            or digest(packed.read_bytes()) != manifest['image']['compressed_sha256']
            or digest(expected.read_bytes()) != manifest['expected']['sha256']):
        raise ValueError('Pinned NTFS controls changed')
    with gzip.open(packed, 'rb') as stream:
        legacy = stream.read(64 * 1024 * 1024 + 1)
    if len(legacy) != 64 * 1024 * 1024 or digest(legacy) != manifest['image']['sha256']:
        raise ValueError('Pinned image failed size or SHA256 validation')
    destination.mkdir(parents=True)
    (destination / 'legacy-usa-torn.dd').write_bytes(legacy)
    (destination / 'legacy-expected.jpg').write_bytes(expected.read_bytes())
    fixed = bytearray(legacy)
    at = manifest['record_offset']
    sequence = fixed[at + 48:at + 50]
    for tail in (510, 1022):
        fixed[at + tail:at + tail + 2] = sequence
    (destination / 'legacy-usa-fixed.dd').write_bytes(fixed)
    image = bytearray(16 * 1024 * 1024)
    (destination / 'originals').mkdir()
    files = []
    for index in range(80):
        offset = 2 * 1024 * 1024 if index == 0 else (
            4 * 1024 * 1024 - 512 if index == 1 else 6 * 1024 * 1024 + (index - 2) * 2048)
        payload = (f'owned record {index}: прабабушка, пирожки\n'.encode('utf-8') + b'x' * 500)[:450]
        name = f'удалённое-🧁-{index:02d}.txt' if index != 79 else 'private.partial'
        image[offset:offset + 1024] = file_record(42 + index, name, payload)
        original = f'originals/owned-{index:03d}.bin'
        (destination / original).write_bytes(payload)
        files.append({'record_offset': offset, 'name': name, 'original': original,
                      'bytes': len(payload), 'sha256': digest(payload)})
    (destination / 'records.dd').write_bytes(image)
    (destination / 'records.dd.sha256').write_text(digest(image), encoding='ascii')
    control = {'schema': 1, 'scope': 'owned structural resident records, not a native-formatted volume',
               'image_sha256': digest(image), 'files': files,
               'native_control': {'source_sha256': digest(legacy), 'fixed_sha256': digest(fixed),
                                  'expected_sha256': manifest['expected']['sha256'],
                                  'scope': 'historical native-format image with four controlled USA repairs'}}
    control['paths'] = path_image(destination)
    control['budgets'] = budget_images(destination)
    for name in ('legacy-usa-torn.dd', 'legacy-usa-fixed.dd', 'paths.dd', 'candidate-limit.dd', 'run-limit.dd'):
        (destination / (name + '.sha256')).write_text(digest((destination / name).read_bytes()), encoding='ascii')
    (destination / 'manifest.json').write_text(json.dumps(control, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'Produced {len(files)} independent resident originals and pinned historical NTFS controls')


if __name__ == '__main__':
    produce(Path(sys.argv[1]))
