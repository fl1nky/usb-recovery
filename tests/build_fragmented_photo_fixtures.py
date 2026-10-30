"""Portable photo fixtures: independent PNG/zlib writer and real Pillow JPEG."""
from pathlib import Path
import hashlib
import io
import json
import random
import struct
import sys
import zlib

from PIL import Image

PNG = b"\x89PNG\r\n\x1a\n"


def chunk(kind, payload):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))


def png(parts):
    rng = random.Random(130 + parts)
    rows = b"".join(b"\0" + rng.randbytes(39 * 3) for _ in range(31))
    packed = zlib.compress(rows)
    cuts = [len(packed) * i // parts for i in range(parts + 1)]
    prefix = PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", 39, 31, 8, 2, 0, 0, 0)) + chunk(b"tEXt", b"Comment\0independent portable fixture")
    pieces = [prefix + chunk(b"IDAT", packed[cuts[0]:cuts[1]])]
    pieces += [chunk(b"IDAT", packed[cuts[i]:cuts[i + 1]]) for i in range(1, parts)]
    pieces[-1] += chunk(b"tEXt", b"Tail\0keep original bytes") + chunk(b"IEND", b"")
    payload = b"".join(pieces)
    with Image.open(io.BytesIO(payload)) as image:
        image.load()
    return payload, pieces


def jpeg():
    rng = random.Random(199)
    image = Image.new("RGB", (83, 61))
    image.putdata([tuple(rng.randrange(256) for _ in range(3)) for _ in range(image.width * image.height)])
    output = io.BytesIO()
    image.save(output, "JPEG", quality=85, subsampling=0, restart_marker_blocks=8)
    raw = output.getvalue()
    markers = [p + 2 for p in range(len(raw) - 1) if raw[p] == 255 and 0xd0 <= raw[p + 1] <= 0xd7]
    assert len(markers) > 3
    cuts = [0, markers[len(markers) // 3], markers[len(markers) * 2 // 3], len(raw)]
    return raw, [raw[a:b] for a, b in zip(cuts, cuts[1:])]


def main(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    for name, (payload, pieces), extension, status in (
        ("png-two", png(2), ".png", "png_crc_zlib_reassembled_candidate"),
        ("png-three", png(3), ".png", "png_crc_zlib_reassembled_candidate"),
        ("jpeg-restart", jpeg(), ".jpg", "jpeg_restart_structural_candidate"),
    ):
        image = bytearray(b"\xa5" * 131072)
        slots = [4096, 49152, 16384]
        extents, logical = [], 0
        for position, part in zip(slots, pieces):
            image[position:position + len(part)] = part
            extents.append(dict(ImageOffset=position, LogicalOffset=logical, Length=len(part)))
            logical += len(part)
        source, original = name + ".dd", name + extension
        (output / source).write_bytes(image)
        (output / (source + ".sha256")).write_text(hashlib.sha256(image).hexdigest() + "  " + source + "\n", encoding="ascii")
        (output / original).write_bytes(payload)
        cases.append(dict(Name=name, Image=source, Original=original, Sha256=hashlib.sha256(payload).hexdigest(), Bytes=len(payload), Status=status, Extents=extents))
    # Index budget, not an invented corrupt-recovery result.
    limited = (PNG + bytes(8)) * 2001
    (output / "header-limit.dd").write_bytes(limited)
    (output / "header-limit.dd.sha256").write_text(hashlib.sha256(limited).hexdigest() + "  header-limit.dd\n", encoding="ascii")
    manifest = dict(Schema=1, Cases=cases, LimitedImage="header-limit.dd")
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Independent portable photo fixtures:", len(cases))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
