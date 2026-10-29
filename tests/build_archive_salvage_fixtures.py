"""Independent fixtures made with Python's ZIP implementation, never production code."""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile

root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
cases = []

def local(name, data, method=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=method) as z:
        z.writestr(name, data)
    archive = buf.getvalue()
    central = archive.index(b'PK\x01\x02')
    return bytearray(archive[:central])

def save(name, bodies, expected, offset=53):
    image = b'\xa5' * offset + b''.join(bodies)
    path = root / (name + '.dd')
    path.write_bytes(image)
    wanted = []
    for member_name, data, at in expected:
        wanted.append(dict(name=member_name, sha256=hashlib.sha256(data).hexdigest(), size=len(data), offset=offset+at))
    cases.append(dict(case=name, file=path.name, image_sha256=hashlib.sha256(image).hexdigest(), expected=wanted))

text = 'Любимый рецепт пирожков\nUnicode \U0001f967\n'.encode()
stored = local('photo-without-extension', bytes(range(256)) * 9, zipfile.ZIP_STORED)
xml = b'<?xml version="1.0"?><document><text>recipe</text></document>'
deflated = local('word/document.xml', xml)
unicode_member = local('данные/пирожки.txt', text)
empty = local('empty.txt', b'', zipfile.ZIP_STORED)
save('mixed-no-central', [stored, deflated, unicode_member, empty], [('photo-without-extension', bytes(range(256))*9, 0), ('word/document.xml', xml, len(stored)), ('данные/пирожки.txt', text, len(stored)+len(deflated)), ('empty.txt', b'', len(stored)+len(deflated)+len(unicode_member))])
save('block-boundary', [deflated], [('word/document.xml', xml, 0)], 1024*1024+1)
save('duplicates', [deflated, deflated], [('word/document.xml', xml, 0), ('word/document.xml', xml, len(deflated))])
bad_middle = bytearray(deflated)
struct.pack_into('<I', bad_middle, 14, 0x12345678)
save('continue-after-corrupt', [deflated, bad_middle, unicode_member], [('word/document.xml', xml, 0), ('данные/пирожки.txt', text, len(deflated)+len(bad_middle))])
html = b'<script>fetch("https://example.invalid")</script>'
save('neutralize-active', [local('hostile.html', html), local('CON.exe', b'not executable')], [('hostile.html', html, 0), ('CON.exe', b'not executable', len(local('hostile.html', html)))])

for name, transform in [
    ('bad-crc', lambda b: struct.pack_into('<I', b, 14, 0x12345678)),
    ('encrypted', lambda b: struct.pack_into('<H', b, 6, 1)),
    ('descriptor', lambda b: struct.pack_into('<H', b, 6, 8)),
    ('unsupported-method', lambda b: struct.pack_into('<H', b, 8, 99)),
    ('zip64-size', lambda b: struct.pack_into('<I', b, 22, 0xffffffff)),
    ('oversize', lambda b: struct.pack_into('<I', b, 22, 64*1024*1024+1)),
    ('lying-expansion', lambda b: struct.pack_into('<I', b, 22, 2)),
    ('truncated-body', lambda b: b.__delitem__(slice(-10, None))),
    ('invalid-utf8', lambda b: (struct.pack_into('<H', b, 6, 0x800), b.__setitem__(30, 0xff))),
]:
    value = bytearray(deflated)
    transform(value)
    save(name, [value], [])
for name, member in [('traversal', '../outside.txt'), ('absolute', '/outside.txt'), ('windows-path', 'C:/outside.txt'), ('backslash-traversal', '..\\outside.txt'), ('directory', 'folder/')]:
    save(name, [local(member, b'unsafe')], [])
value = bytearray(deflated)
struct.pack_into('<H', value, 28, 4)
value[30+len('word/document.xml'):30+len('word/document.xml')] = struct.pack('<HH', 1, 0)
save('zip64-extra', [value], [])
value = bytearray(deflated)
value[30+len('word/document.xml')] = 0xff
save('bad-deflate', [value], [])
(root / 'fixtures.json').write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding='utf-8')
bad_header = bytearray(deflated)
struct.pack_into('<H', bad_header, 8, 99)
(root / 'candidate-limit.dd').write_bytes(bad_header * 20001)
print(f'{len(cases)} ZIP salvage fixtures created')
