"""Owned zipfile originals; physical records are placed independently of recovery."""
from pathlib import Path
import hashlib
import io
import json
import random
import struct
import sys
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def original(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, data, method in entries:
            info = zipfile.ZipInfo(name, (2024, 1, 2, 3, 4, 6))
            info.compress_type = method
            archive.writestr(info, data)
    data = stream.getvalue()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.testzip() is None
        for info, (_, wanted, _) in zip(archive.infolist(), entries):
            assert archive.read(info) == wanted
        offsets = [info.header_offset for info in archive.infolist()]
        directory = archive.start_dir
    boundaries = offsets + [directory]
    return data, [data[a:b] for a, b in zip(boundaries, boundaries[1:])], data[directory:]


def build(destination):
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=False)
    for label in ('normal', 'long-names', 'work-budget', 'report-budget'):
        image = bytearray(b'\xa5' * (40 * 1024 * 1024))
        files = []
        next_early = 1024 * 1024 + 9
        for ordinal in range(3 if label == 'normal' else 6 if label == 'report-budget' else 1):
            if label in ('long-names', 'report-budget'):
                entries = [('<' * 980 + f'{ordinal:02d}-{n:04d}.txt', f'long name {ordinal}:{n}'.encode(), zipfile.ZIP_STORED)
                           for n in range(1024 if label == 'report-budget' else 150)]
            elif label == 'work-budget':
                rng = random.Random(197)
                block = rng.randbytes(4096)
                entries = [('budget.bin', block * 2048, zipfile.ZIP_DEFLATED)]
            else:
                entries = [('message.txt', ('Привет из архива ' + str(ordinal)).encode() * 64, zipfile.ZIP_DEFLATED),
                           ('<img src=x>.html', b'<script>owned text only</script>' + str(ordinal).encode(), zipfile.ZIP_STORED),
                           ('folder/end.bin', bytes(range(256)) * (ordinal + 1), zipfile.ZIP_DEFLATED)]
            data, records, tail = original(entries)
            original_name = f'{label}-{ordinal}.original.zip'
            (root / original_name).write_bytes(data)
            if label == 'work-budget':
                # Keep every local/central key equal, but require a wrong CRC.
                # Each candidate expands to 8 MiB. Resume must retain this work.
                bad = bytearray(records[0])
                crc = struct.unpack_from('<I', bad, 14)[0] ^ 1
                struct.pack_into('<I', bad, 14, crc)
                bad_tail = bytearray(tail)
                struct.pack_into('<I', bad_tail, 16, crc)
                for n in range(65):
                    offset = next_early + n * (len(bad) + 31)
                    image[offset:offset + len(bad)] = bad
                image[30 * 1024 * 1024:30 * 1024 * 1024 + len(bad_tail)] = bad_tail
                continue
            extents = []
            logical = 0
            for n, record in enumerate(records):
                offset = (30 + ordinal) * 1024 * 1024 + 17 if n == len(records) - 1 else next_early
                if label == 'normal' and ordinal == 0 and n == 0:
                    offset = 4 * 1024 * 1024 - 2  # signature straddles an index block
                image[offset:offset + len(record)] = record
                extents.append({'ImageOffset': offset, 'LogicalOffset': logical, 'Length': len(record)})
                logical += len(record)
                next_early += len(record) + 71
            central_offset = (5 + ordinal * 3) * 1024 * 1024 + 3
            if label == 'report-budget':
                central_offset = (10 + ordinal * 3) * 1024 * 1024 + 3
            if label == 'normal' and ordinal == 1:
                central_offset = 12 * 1024 * 1024 - (len(tail) - 22) - 2
            image[central_offset:central_offset + len(tail)] = tail
            extents.append({'ImageOffset': central_offset, 'LogicalOffset': logical, 'Length': len(tail)})
            files.append({'sha256': sha(data), 'bytes': len(data), 'original': original_name,
                          'extents': extents, 'members': len(records)})
        path = root / (label + '.dd')
        path.write_bytes(image)
        digest = sha(image)
        (root / (label + '.dd.sha256')).write_text(digest + '\n', encoding='ascii')
        (root / (label + '.json')).write_text(json.dumps({'image_sha256': digest, 'files': files},
                                                       ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(root)


if __name__ == '__main__':
    build(sys.argv[1])
