"""Independent ZIP32 fixtures built with Python zipfile, then scattered as records."""
import hashlib
import io
import json
from pathlib import Path
import random
import struct
import sys
import zipfile

root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
cases = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(entries, comment=b'', extra=b''):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as zipped:
        for name, data, method in entries:
            info = zipfile.ZipInfo(name, date_time=(2024, 5, 6, 7, 8, 10))
            info.compress_type = method
            info.extra = extra
            zipped.writestr(info, data)
        zipped.comment = comment
    raw = stream.getvalue()
    with zipfile.ZipFile(io.BytesIO(raw)) as reader:
        offsets = [info.header_offset for info in reader.infolist()]
        directory = reader.start_dir
        assert reader.testzip() is None
    records = [raw[a:b] for a, b in zip(offsets, offsets[1:] + [directory])]
    return dict(raw=raw, records=records, tail=raw[directory:], logical=offsets,
                directory=directory, names=[entry[0] for entry in entries])


def image_case(name, zipped, *, records=None, tail=None, order=None, prefix=53,
               expected=True, reason=None, duplicate=None, extension='.zip'):
    records = zipped['records'] if records is None else records
    tail = zipped['tail'] if tail is None else tail
    order = list(reversed(range(len(records)))) if order is None else order
    image = bytearray(b'\xa5' * prefix)
    alternatives = {}
    if duplicate is not None:
        index, copy = duplicate
        alternatives.setdefault(index, []).append(len(image))
        image.extend(copy)
        image.extend(b'\xa5' * 37)
    central_offset = None
    for number, index in enumerate(order):
        alternatives.setdefault(index, []).append(len(image))
        image.extend(records[index])
        image.extend(b'\xa5' * (43 + number * 11))
        if number == 0:
            central_offset = len(image)
            image.extend(tail)
            image.extend(b'\xa5' * 71)
    if central_offset is None:
        central_offset = len(image)
        image.extend(tail)
    image.extend(b'\xa5' * 31)
    path = root / (name + '.dd')
    path.write_bytes(image)
    wanted = []
    if expected:
        expected_extents = []
        for index, record in enumerate(zipped['records']):
            expected_extents.append(dict(ImageOffset=min(alternatives[index]),
                                         LogicalOffset=zipped['logical'][index],
                                         Length=len(record)))
        expected_extents.append(dict(ImageOffset=central_offset,
                                     LogicalOffset=zipped['directory'],
                                     Length=len(zipped['tail'])))
        wanted.append(dict(sha256=sha(zipped['raw']), size=len(zipped['raw']),
                           members=len(zipped['records']), names=zipped['names'],
                           extents=expected_extents, extension=extension,
                           alternatives={str(i): value for i, value in alternatives.items()}))
        (root / (name + '.original.zip')).write_bytes(zipped['raw'])
    cases.append(dict(case=name, file=path.name, image_sha256=sha(image),
                      expected=wanted, reason=reason))


text = 'Рецепт прабабушки: пирожки с капустой 🥧\n'.encode()
stored = archive([('recipe.txt', text, 0), ('photo.bin', bytes(range(256)) * 5, 0)])
deflated = archive([('recipe.txt', text * 9, 8), ('media/photo.dat', bytes(range(256)) * 13, 8)])
mixed = archive([('данные/рецепт.txt', text, 8), ('фото без расширения', bytes(range(97)) * 21, 0), ('empty.txt', b'', 0)])
for name, value in [('stored', stored), ('deflated', deflated), ('unicode-mixed-empty', mixed)]:
    image_case(name, value)
image_case('duplicate-identical-record', deflated, duplicate=(0, deflated['records'][0]))
image_case('local-header-block-boundary', deflated, order=[0, 1], prefix=4*1024*1024-2)
image_case('eocd-block-boundary', deflated, prefix=4*1024*1024-2-len(deflated['records'][1])-43-len(deflated['tail'])+22)
image_case('archive-comment', archive([('a.txt', text, 8), ('b.txt', b'more data', 0)], comment='Пирожки'.encode()))
image_case('unknown-extra-preserved', archive([('a.txt', text, 0), ('b.txt', b'more data', 8)], extra=struct.pack('<HH4s', 0xcafe, 4, b'abcd')))
image_case('directory-member', archive([('folder/', b'', 0), ('folder/recipe.txt', text, 8)]))
for extension, document in [('.docx', 'word/document.xml'), ('.xlsx', 'xl/workbook.xml'), ('.pptx', 'ppt/presentation.xml')]:
    zipped = archive([('[Content_Types].xml', b'<Types/>', 8), (document, b'<document>recipe</document>', 8)])
    image_case(extension[1:], zipped, extension=extension)
image_case('hostile-member-names', archive([('../outside.exe', b'not an executable', 0), ('C:/escape.html', b'<script>bad()</script>', 8)]))


def changed_record(zipped, index, mutate):
    records = [bytearray(record) for record in zipped['records']]
    mutate(records[index])
    return records


image_case('corrupt-stored-body', stored, records=changed_record(stored, 0, lambda b: b.__setitem__(-1, b[-1] ^ 0x11)), expected=False, reason='member_crc_or_length')
image_case('corrupt-deflated-body', deflated, records=changed_record(deflated, 0, lambda b: b.__setitem__(30+len('recipe.txt'), 0xff)), expected=False, reason='member_crc_or_length')
image_case('missing-local', deflated, order=[1], expected=False, reason='member_missing')
image_case('truncated-local', stored, records=[stored['records'][0][:-6], stored['records'][1]], expected=False, reason='member_crc_or_length')
split_records = list(deflated['records'])
cut = 30+len('recipe.txt')+12
split_records[0] = split_records[0][:cut] + b'\xa5'*43 + split_records[0][cut:]
image_case('compressed-member-split', deflated, records=split_records, expected=False, reason='member_crc_or_length')
image_case('truncated-tail', deflated, tail=deflated['tail'][:-16], expected=False)
image_case('broken-central', deflated, tail=b'NOPE'+deflated['tail'][4:], expected=False, reason='central_signature')
for name, local_at, central_at, value, width, reason in [
    ('encrypted', 6, 8, 1, 'H', 'flags_or_descriptor_unsupported'),
    ('descriptor', 6, 8, 8, 'H', 'flags_or_descriptor_unsupported'),
    ('unknown-flags', 6, 8, 0x4000, 'H', 'flags_or_descriptor_unsupported'),
    ('unsupported-compression', 8, 10, 99, 'H', 'compression_unsupported'),
    ('zip64-sizes', 18, 20, 0xffffffff, 'I', 'zip64_unsupported'),
    ('oversized-member', 22, 24, 64*1024*1024+1, 'I', 'member_limit'),
    ('unknown-version', 4, 6, 63, 'H', 'version_unsupported'),
]:
    records = [bytearray(record) for record in deflated['records']]
    tail = bytearray(deflated['tail'])
    struct.pack_into('<'+width, records[0], local_at, value)
    struct.pack_into('<'+width, tail, central_at, value)
    image_case(name, deflated, records=records, tail=tail, expected=False, reason=reason)
tail = bytearray(deflated['tail'])
struct.pack_into('<H', tail, len(tail)-22+4, 1)
image_case('multivolume', deflated, tail=tail, expected=False, reason='multivolume_unsupported')
tail = bytearray(deflated['tail'])
struct.pack_into('<I', tail, 42, 1)
image_case('logical-prefix-gap', deflated, tail=tail, expected=False, reason='logical_gaps_or_overlap_unsupported')
tail = bytearray(deflated['tail'])
second = 46+len('recipe.txt')
struct.pack_into('<I', tail, second+42, 0)
image_case('logical-overlap', deflated, tail=tail, expected=False, reason='logical_record_bounds')
tail = bytearray(deflated['tail'])
struct.pack_into('<I', tail, len(tail)-22+16, deflated['directory']+1)
image_case('logical-directory-gap', deflated, tail=tail, expected=False, reason='member_crc_or_length')
extra_zip = archive([('a.txt', text, 0), ('b.txt', b'other', 0)], extra=struct.pack('<HH4s', 0xcafe, 4, b'abcd'))
different = bytearray(extra_zip['records'][0])
different[30+len('a.txt')+4] ^= 0x22
image_case('ambiguous-record-extra', extra_zip, duplicate=(0, different), expected=False, reason='member_ambiguous_raw_versions')
invalid_name_zip = archive([('a.txt', text, 8), ('b.txt', text, 8)])
records = [bytearray(record) for record in invalid_name_zip['records']]
tail = bytearray(invalid_name_zip['tail'])
struct.pack_into('<H', records[0], 6, 0x800)
records[0][30] = 0xff
struct.pack_into('<H', tail, 8, 0x800)
tail[46] = 0xff
image_case('invalid-utf8', invalid_name_zip, records=records, tail=tail, expected=False, reason='name_encoding')
zip64extra = archive([('a.txt', text, 8), ('b.txt', text, 8)], extra=struct.pack('<HH4s', 1, 4, b'abcd'))
image_case('zip64-extra', zip64extra, expected=False, reason='zip64_unsupported')
image_case('all-empty', archive([('a.txt', b'', 0), ('b.txt', b'', 0)]), expected=False, reason='empty_archive')
path = root / 'already-contiguous.dd'
path.write_bytes(b'\xa5'*57 + deflated['raw'] + b'\xa5'*81)
cases.append(dict(case='already-contiguous', file=path.name, image_sha256=sha(path.read_bytes()), expected=[], reason='already_contiguous'))

# Different archives survive in one image and exact duplicate archive bytes are
# emitted once, even when more than one directory copy survives
first = next(row for row in cases if row['case'] == 'stored')
second = next(row for row in cases if row['case'] == 'deflated')
for name, other, deduplicate in [('multiple-archives', second, False), ('duplicate-archives', first, True)]:
    image1, image2 = (root/first['file']).read_bytes(), (root/other['file']).read_bytes()
    shift = len(image1)+113
    image = image1+b'\xa5'*113+image2
    expected = [dict(first['expected'][0], original_file='stored.original.zip')]
    if not deduplicate:
        row = json.loads(json.dumps(other['expected'][0]))
        row['original_file'] = other['case']+'.original.zip'
        for extent in row['extents']:
            extent['ImageOffset'] += shift
        expected.append(row)
    path = root/(name+'.dd')
    path.write_bytes(image)
    cases.append(dict(case=name, file=path.name, image_sha256=sha(image), expected=expected,
                      reason='duplicate_archive_bytes' if deduplicate else None))

# Deliberately exceeds only the total decompression work limit, while every
# individual member is within size and compression-ratio limits
payload = random.Random(771).randbytes(4096) * (64*1024*1024//4096)
budget_zip = archive([(f'part-{i}.bin', payload, 8) for i in range(9)])
image_case('expanded-work-limit', budget_zip, expected=False)
cases.pop()
del payload, budget_zip

(root/'fixtures.json').write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding='utf-8')
(root/'header-limit.dd').write_bytes(b'PK\x03\x04' * 30001 + bytes(30))
(root/'directory-limit.dd').write_bytes(b'PK\x05\x06' * 5001 + bytes(30))
empty_record = archive([('x', b'', 0)])['records'][0]
(root/'local-limit.dd').write_bytes(empty_record * 20001)
print(f'{len(cases)} fragmented ZIP fixtures created')
