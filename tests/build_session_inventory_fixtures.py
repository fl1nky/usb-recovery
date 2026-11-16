"""Own 100,000 tiny files for inventory durability, not photo recovery quality."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import zlib


def write_mapping(root):
    # Independent PNG producer for the actual public pipeline/source-map case.
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    pixels = bytes([0, 200, 10, 70, 255, 20, 220, 90, 255])
    png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 2, 1, 8, 6, 0, 0, 0)) +
           chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))
    mapped = bytearray(b'\xa5' * (256 * 1024))
    mapped[8192:8192 + len(png)] = png
    (root / 'original.png').write_bytes(png)
    (root / 'mapping.dd').write_bytes(mapped)
    (root / 'mapping.dd.sha256').write_text(hashlib.sha256(mapped).hexdigest() + '\n', encoding='ascii')


def build(destination):
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=False)
    image = bytes(range(256)) * 16
    (root / 'source.dd').write_bytes(image)
    write_mapping(root)
    job = root / 'prepared'
    photos = job / 'extra-photos'
    state = job / 'photos.state'
    photos.mkdir(parents=True)
    state.mkdir()
    for ordinal in range(100000):
        (photos / f'owned-{ordinal:06d}.bin').write_bytes(struct.pack('<I', ordinal))
        if ordinal % 25000 == 24999:
            print(f'Prepared {ordinal + 1} owned inventory files', flush=True)
    for ordinal in range(17):
        (state / f'bookkeeping-{ordinal:06d}.json').write_text(json.dumps({'owned': ordinal}), encoding='utf-8')
    (job / 'extra-photo-search.json').write_text(json.dumps({'status': 'complete', 'test_scope': 'inventory_only'}), encoding='utf-8')
    manifest = {'scope': 'Inventory of 100000 owned binary placeholders plus 18 bookkeeping artifacts; not recovered photographs',
                'outputs': 100000, 'bookkeeping': 18, 'total_artifacts': 100018,
                'source_sha256': hashlib.sha256(image).hexdigest(), 'source_bytes': len(image)}
    (root / 'inventory-fixture.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(root, flush=True)


if __name__ == '__main__':
    build(sys.argv[1])
