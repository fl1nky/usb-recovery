"""Independent standard-library ZIP fixtures, never user files/devices."""
from pathlib import Path
import io, json, struct, zipfile

root = Path(__file__).resolve().parent / "QualityFixtures"
root.mkdir(exist_ok=True)
cases = []
def save(name, data, expected):
    (root / name).write_bytes(data)
    cases.append({"path": name, "expected": expected})
def archive(method=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=method) as out:
        out.writestr("word/document.xml", "<document>Секрет пирожков — яблоки</document>".encode())
        out.writestr("folder/", b"")
        out.writestr("Unicode/прабабушка.txt", "Сохранившийся текст\nВторая строка".encode())
        out.comment = b"Known independent Python zipfile fixture"
    return stream.getvalue()

save("stored.zip", archive(zipfile.ZIP_STORED), "container_crc")
data = archive()
save("deflate.docx", data, "container_crc")
truncated = data[:data.index(b"PK\x01\x02")]
save("no-central.zip", truncated, "partial")
bad = bytearray(archive(zipfile.ZIP_STORED)); name_size, extra_size = struct.unpack_from("<HH", bad, 26)
bad[30+name_size+extra_size+5] ^= 0x44
save("crc-error.zip", bad, "damaged")
zip64 = io.BytesIO()
with zipfile.ZipFile(zip64, "w") as out:
    with out.open("small.txt", "w", force_zip64=True) as file:
        file.write(b"Small, but deliberately ZIP64 local header")
save("force-zip64.zip", zip64.getvalue(), "unverified")
save("unknown.zip", b"not a ZIP header", "unverified")
save("prefix.zip", b"additional prefix"+data, "unverified")
empty = io.BytesIO()
with zipfile.ZipFile(empty, "w"): pass
save("empty.zip", empty.getvalue(), "container_crc")
# A legal digital-signature structure is not an authenticated signature.
signed = bytearray(data)
end = signed.rfind(b"PK\x05\x06"); central_size = struct.unpack_from("<I", signed, end+12)[0]
signature = b"PK\x05\x05\x03\x00abc"
signed[end:end] = signature
struct.pack_into("<I", signed, end+len(signature)+12, central_size+len(signature))
save("signed-catalog.zip", signed, "unverified")
multipart = bytearray(data); central = multipart.index(b"PK\x01\x02"); struct.pack_into("<H", multipart, central+34, 1)
save("part-of-volume.zip", multipart, "unverified")
encrypted = bytearray(data); central = encrypted.index(b"PK\x01\x02"); struct.pack_into("<H", encrypted, central+8, struct.unpack_from("<H", encrypted, central+8)[0]|1)
save("encrypted.zip", encrypted, "encrypted")
unknown_method = bytearray(data); central = unknown_method.index(b"PK\x01\x02"); struct.pack_into("<H", unknown_method, central+10, 99)
save("unsupported-method.zip", unknown_method, "unverified")
save("partial.pdf", b"%PDF-1.7\n1 0 obj<<>>endobj\n", "partial")
save("structured.pdf", b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n", "structure")
save("structured.wav", b"RIFF"+struct.pack("<I", 12)+b"WAVEdata"+struct.pack("<I", 0), "structure")
save("truncated.wav", b"RIFF"+struct.pack("<I", 40)+b"WAVEdata"+struct.pack("<I", 0), "partial")
save("plain.txt", "Просто текст; не восстановленный документ".encode(), "unverified")
(root / "cases.json").write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
print(f"Created {len(cases)} independent content fixtures")
