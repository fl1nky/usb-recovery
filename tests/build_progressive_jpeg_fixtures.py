"""Independent Pillow encodings/scattering; no recovery-module imports.

Fixtures are newly generated regular files. Physical offsets, encoder seeds and
split points are chosen here; the recovery receives only the resulting image.
"""
from pathlib import Path
import hashlib
import io
import json
import random
import struct
from PIL import Image


def specimen(seed=409, *, restart=8, gray=False, subsampling=0, size=(113, 81)):
    rng = random.Random(seed)
    image = Image.new("L" if gray else "RGB", size)
    image.putdata([rng.randrange(256) if gray else tuple(rng.randrange(256) for _ in range(3))
                   for _ in range(image.width * image.height)])
    out = io.BytesIO()
    image.save(out, "JPEG", quality=84, progressive=True, subsampling=subsampling,
               restart_marker_blocks=restart)
    return out.getvalue()


def markers(raw):
    """Read physical markers without interpreting any Huffman/progressive data."""
    result, at = [], 0
    while at < len(raw):
        if raw[at] != 255:
            at += 1
            continue
        start = at
        while at < len(raw) and raw[at] == 255:
            at += 1
        if at >= len(raw):
            raise ValueError("torn marker in independent reference")
        marker = raw[at]
        at += 1
        if marker == 0:
            continue
        if marker in {0xd8, 0xd9} or 0xd0 <= marker <= 0xd7:
            end = at
        else:
            end = at + struct.unpack_from(">H", raw, at)[0]
            if end > len(raw):
                raise ValueError("marker length in independent reference")
        result.append((start, end, marker))
        at = end
    return result


def scans(raw):
    all_markers = markers(raw)
    result = []
    for index, (start, end, marker) in enumerate(all_markers):
        if marker == 0xda:
            stop = next(at for at, _, code in all_markers[index + 1:] if not 0xd0 <= code <= 0xd7)
            result.append(dict(header=start, start=end, end=stop, script=list(raw[end - 3:end])))
    return result


def scatter(raw, cuts, *, duplicate=False, alternate=False, damage=None):
    points = [0, *sorted(cuts), len(raw)]
    pieces = [raw[a:b] for a, b in zip(points, points[1:])]
    slots = random.Random(991).sample(range(64, 1024, 16), len(pieces))
    data = bytearray(b"\xcc" * (1024 * 1024))
    extents = []
    for logical, piece, slot in zip(points, pieces, slots):
        physical = slot * 512
        data[physical:physical + len(piece)] = piece
        extents.append(dict(logical=logical, physical=physical, length=len(piece)))
    if duplicate or alternate:
        tail = bytearray(pieces[-1])
        if alternate:
            marker = tail.index(b"original-A")
            tail[marker:marker + 10] = b"original-B"
        data[900 * 512:900 * 512 + len(tail)] = tail
    if damage == "eoi":
        last = extents[-1]
        end = last["physical"] + last["length"]
        data[end - 2:end] = b"\x00\x00"
    elif damage == "restart":
        first = extents[0]
        at = first["physical"] + first["length"] - 1
        data[at] = 0xd7 if data[at] != 0xd7 else 0xd6
    return bytes(data), extents


def write(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    cases = []

    def emit(name, raw, cuts, status="jpeg_progressive_structural_candidate"):
        reference = root / (name + ".jpg")
        reference.write_bytes(raw)
        image, extents = scatter(raw, cuts)
        (root / (name + ".dd")).write_bytes(image)
        with Image.open(io.BytesIO(raw)) as decoded:
            decoded.load()
            rgb_sha = hashlib.sha256(decoded.convert("RGB").tobytes()).hexdigest()
        cases.append(dict(name=name, original=reference.name, image=name + ".dd", extents=extents,
                          status=status, sha256=hashlib.sha256(raw).hexdigest(), decoded_rgb_sha256=rgb_sha,
                          source_sha256=hashlib.sha256(image).hexdigest(), scans=scans(raw)))

    for name, options in (("rgb-rst", {}), ("gray-rst", dict(gray=True, restart=7)),
                          ("subsample-rst", dict(subsampling=2, restart=3)), ("rgb-no-rst", dict(restart=0))):
        raw = specimen(**options)
        restart_cuts = [end for _, end, code in markers(raw) if 0xd0 <= code <= 0xd7]
        metadata_cuts = [row["header"] for row in scans(raw)][1:]
        choices = restart_cuts or metadata_cuts
        cuts = [choices[len(choices) // 3], choices[len(choices) * 2 // 3]]
        emit(name, raw, cuts)
    raw = specimen(restart=0, size=(256, 128))
    emit("nonrst-entropy-4k", raw, [4096])
    refine = next(scan for scan in scans(raw) if scan["script"][2] >> 4 and scan["end"] - scan["start"] > 1024)
    emit("nonrst-two-entropy-gaps", raw, [4096, (refine["start"] // 512 + 1) * 512])
    raw = specimen()
    stop = scans(raw)[0]["end"]
    raw = raw[:stop] + b"\xff\xd9"
    cuts = [end for _, end, code in markers(raw) if 0xd0 <= code <= 0xd7]
    emit("dc-only-rst", raw, [cuts[len(cuts) // 3], cuts[len(cuts) * 2 // 3]], "progressive_partial_precision_candidate")
    (root / "manifest.json").write_text(json.dumps(dict(schema=1, cases=cases), ensure_ascii=False, indent=2), encoding="utf-8")
    return cases


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    write(parser.parse_args().output)
