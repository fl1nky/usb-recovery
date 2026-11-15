"""Independent, bounded ZIP32 checkpoint inputs; no recovery imports/devices."""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile

root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=False)


def local(name, payload, method):
    memory = io.BytesIO()
    info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = method
    with zipfile.ZipFile(memory, "w") as archive:
        archive.writestr(info, payload)
    raw = memory.getvalue()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.read(name) == payload
        compressed = archive.getinfo(name).compress_size
    name_bytes, extra = struct.unpack_from("<HH", raw, 26)
    return bytearray(raw[:30 + name_bytes + extra + compressed])


def payload(index):
    return ("Сохранённый рецепт %d 🥧\n" % index).encode() + hashlib.sha256(str(index).encode()).digest() * 32


def image(label, many):
    raw = bytearray(40 * 1024 * 1024)
    originals = root / (label + "-originals")
    originals.mkdir()
    positions = [(1024 * 1024 + 9, "recipe.txt", payload(0), zipfile.ZIP_STORED),
                 (4 * 1024 * 1024 - 3, "данные/пирожки.txt", payload(1), zipfile.ZIP_DEFLATED)]
    if many:
        # '<' is escaped by the .NET JSON serializer, so count-only pagination
        # would overrun the page byte budget on these valid original names.
        positions = [(1024 * 1024 + 9 + index * 4096,
                      "<" * 990 + "/m%04d.txt" % index, payload(index), zipfile.ZIP_STORED)
                     for index in range(130)]
    positions.append((30 * 1024 * 1024 + 17, "hostile.html", payload(2), zipfile.ZIP_DEFLATED))
    expected = []
    for offset, name, data, method in positions:
        record = local(name, data, method)
        assert len(record) < 4096
        raw[offset:offset + len(record)] = record
        original = originals / (str(offset) + ".bin")
        original.write_bytes(data)
        expected.append({"offset": offset, "name": name, "bytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest(), "method": method,
                         "original": original.relative_to(root).as_posix()})
    bad_data = payload(99)
    bad = local("bad-crc.txt", bad_data, zipfile.ZIP_DEFLATED)
    crc, = struct.unpack_from("<I", bad, 14)
    struct.pack_into("<I", bad, 14, crc ^ 1)
    offset = 5 * 1024 * 1024 + 99
    raw[offset:offset + len(bad)] = bad
    assert raw.count(b"PK\x03\x04") == len(expected) + 1
    source = root / (label + ".dd")
    source.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    (root / (label + ".dd.sha256")).write_text(digest.upper(), encoding="ascii")
    (root / (label + ".json")).write_text(json.dumps({
        "image_sha256": digest, "source_bytes": len(raw), "files": expected,
        "expected_headers": len(expected) + 1, "bad_crc_bytes": len(bad_data),
        "expected_decoded_work": sum(row["bytes"] for row in expected) + len(bad_data),
        "scope": "Python zipfile originals; missing central directories and one controlled bad local CRC"
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


image("normal", False)
image("long-names", True)

# Failed CRC candidates still consume real decoding work. A cancellation must
# preserve that charge instead of granting a fresh 512-MiB search budget.
block = b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(128))
body = block * 2048
record = local("work-budget.txt", body, zipfile.ZIP_DEFLATED)
assert len(record) < 128 * 1024 and len(body) <= len(record) * 1000
crc, = struct.unpack_from("<I", record, 14)
struct.pack_into("<I", record, 14, crc ^ 1)
raw = bytearray(40 * 1024 * 1024)
for index in range(65):
    offset = 1024 * 1024 + index * 128 * 1024 + 9
    raw[offset:offset + len(record)] = record
(root / "work-budget.dd").write_bytes(raw)
(root / "work-budget.dd.sha256").write_text(hashlib.sha256(raw).hexdigest(), encoding="ascii")
print("Created 3 owned 40-MiB archive checkpoint images, exact manifests and failed-candidate work controls")
