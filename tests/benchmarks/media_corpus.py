"""Independent, reproducible recovery corpus. Never opens a device or user file.

Ground truth is outside each image. Generated ISO-BMFF files are muxed by FFmpeg,
JPEGs by Pillow. The scatterer knows byte extents, not any recovery implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
from pathlib import Path
import random
import struct
import subprocess
import zlib
from PIL import Image, ImageDraw

SEED = 20261030
SECTOR = 512


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command):
    result = subprocess.run([str(x) for x in command], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace")[-6000:])
    return result.stdout


def jpeg(seed, *, progressive=False, restart=False):
    rng = random.Random(seed)
    image = Image.new("RGB", (320, 192))
    pixels = image.load()
    for y in range(image.height):
        for x in range(image.width):
            pixels[x, y] = ((x * 3 + y * 2 + rng.randrange(17)) % 256,
                            (y * 5 + rng.randrange(17)) % 256,
                            ((x ^ y) * 3 + rng.randrange(17)) % 256)
    ImageDraw.Draw(image).text((12, 12), "RECOVERY BENCH %d" % seed, fill="white")
    output = io.BytesIO()
    options = {"quality": 88, "subsampling": 0, "progressive": progressive}
    if restart:
        options["restart_marker_blocks"] = 8
    image.save(output, "JPEG", **options)
    data = output.getvalue()
    with Image.open(io.BytesIO(data)) as check:
        check.load()
    return data


def png_asset(source):
    stream = io.BytesIO()
    with Image.open(io.BytesIO(source)) as image:
        image.save(stream, "PNG", compress_level=6)
    original = stream.getvalue()
    result = bytearray(original[:8])
    position = 8
    while position < len(original):
        size = struct.unpack_from(">I", original, position)[0]
        kind = original[position + 4:position + 8]
        payload = original[position + 8:position + 8 + size]
        pieces = [payload[i:i + 4096] for i in range(0, size, 4096)] if kind == b"IDAT" else [payload]
        for piece in pieces:
            result += struct.pack(">I", len(piece)) + kind + piece + struct.pack(">I", zlib.crc32(kind + piece))
        position += size + 12
    with Image.open(io.BytesIO(result)) as image:
        image.load()
    return bytes(result)


def png_boundaries(data):
    result = [8]
    position = 8
    while position < len(data):
        size = struct.unpack_from(">I", data, position)[0]
        position += size + 12
        result.append(position)
    return result


def boxes(data, start=0, end=None):
    end = len(data) if end is None else end
    while start < end:
        if start + 8 > end:
            raise ValueError("truncated ISO-BMFF atom")
        length, kind = struct.unpack_from(">I4s", data, start)
        header = 8
        if length == 1:
            length = struct.unpack_from(">Q", data, start + 8)[0]
            header = 16
        elif length == 0:
            length = end - start
        if length < header or start + length > end:
            raise ValueError("invalid ISO-BMFF atom")
        yield kind, start, start + length, header
        start += length


def bmff_chunk_boundaries(data):
    """Read encoder tables only to select genuine boundaries for the experiment."""
    offsets = set()
    top = list(boxes(data))
    mdats = [(a + h, b) for k, a, b, h in top if k == b"mdat"]
    def descend(start, end):
        for kind, a, b, header in boxes(data, start, end):
            if kind in (b"moov", b"trak", b"mdia", b"minf", b"stbl"):
                descend(a + header, b)
            if kind in (b"stco", b"co64"):
                count = struct.unpack_from(">I", data, a + header + 4)[0]
                width, token = (4, ">I") if kind == b"stco" else (8, ">Q")
                for n in range(count):
                    offsets.add(struct.unpack_from(token, data, a + header + 8 + n * width)[0])
    descend(0, len(data))
    return sorted(offsets), mdats


def frame_digest(ffmpeg, path):
    result = run([ffmpeg, "-v", "error", "-i", path, "-map", "0:v", "-an",
                  "-f", "framemd5", "-"])
    # Compare actual decoded frames/stream identity, not muxer version comments.
    return sha(b"\n".join(line for line in result.splitlines() if line and not line.startswith(b"#")))


def make_videos(output, ffmpeg):
    assets = {}
    common = [ffmpeg, "-v", "error", "-nostdin", "-y", "-f", "lavfi",
              "-i", "testsrc2=size=160x96:rate=6", "-t", "2",
              "-map_metadata", "-1", "-fflags", "+bitexact", "-flags:v", "+bitexact"]
    for name, codec in (("avc-single.mp4", "libx264"), ("mjpeg-single.mov", "mjpeg")):
        path = output / name
        options = ["-c:v", codec]
        options += ["-preset", "medium", "-crf", "24", "-g", "6", "-bf", "0"] if codec == "libx264" else ["-q:v", "5"]
        run(common + options + ["-movflags", "+faststart", path])
        assets[name] = path.read_bytes()
    for name, codec in (("avc-dual.mp4", "libx264"), ("mjpeg-dual.mov", "mjpeg")):
        path = output / name
        command = [ffmpeg, "-v", "error", "-nostdin", "-y", "-f", "lavfi",
                   "-i", "testsrc2=size=160x96:rate=6", "-f", "lavfi",
                   "-i", "testsrc=size=160x96:rate=6", "-t", "2",
                   "-map", "0:v", "-map", "1:v", "-map_metadata", "-1",
                   "-c:v", codec, "-pix_fmt", "yuv420p", "-fflags", "+bitexact",
                   "-flags:v", "+bitexact", "-max_interleave_delta", "1"]
        command += ["-preset", "medium", "-crf", "24", "-g", "6", "-bf", "0"] if codec == "libx264" else ["-q:v", "5"]
        run(command + ["-movflags", "+faststart", path])
        assets[name] = path.read_bytes()
    return assets


def split_at(data, positions):
    points = [0] + sorted(set(p for p in positions if 0 < p < len(data))) + [len(data)]
    return [(a, data[a:b]) for a, b in zip(points, points[1:])]


def raw_image(parts, seed, *, overwrite=None, duplicate=None, contiguous=False):
    rng = random.Random(seed)
    image = bytearray(b"\xcc" * (8 * 1024 * 1024))
    extents = []
    cursor = 131072
    slots = rng.sample(range(64, 7680, 64), len(parts))
    if any(len(payload) > 32768 for logical, payload in parts):
        slots = rng.sample(range(128, 15360, 128), len(parts))
    if contiguous:
        slots = []
    for i, (logical, payload) in enumerate(parts):
        physical = cursor if contiguous else slots[i] * SECTOR
        image[physical:physical + len(payload)] = payload
        extents.append({"logical_offset": logical, "image_offset": physical, "length": len(payload)})
        cursor += len(payload)
    if overwrite is not None:
        item = extents[overwrite]
        count = min(64, item["length"])
        image[item["image_offset"]:item["image_offset"] + count] = b"\x00" * count
    if duplicate is not None:
        logical, payload = parts[duplicate]
        physical = 7 * 1024 * 1024
        image[physical:physical + len(payload)] = payload
    return image, extents


def fat16_image(data, seed, *, deleted=False, clear_chain=False):
    """Independent superfloppy writer, FAT16 BPB and 2 FAT copies, 1KiB clusters."""
    image = bytearray(32 * 1024 * 1024)
    image[:3] = b"\xeb\x3c\x90"
    image[3:11] = b"BENCHV4 "
    struct.pack_into("<HBHBHHBHHHII", image, 11, 512, 2, 1, 2, 512, 0, 0xF8, 128, 32, 64, 0, 65536)
    image[36:39] = b"\x80\x00\x29"
    struct.pack_into("<I", image, 39, seed)
    image[43:54] = b"BENCHMARK  "
    image[54:62] = b"FAT16   "
    image[510:512] = b"\x55\xaa"
    fat = bytearray(128 * SECTOR)
    struct.pack_into("<HH", fat, 0, 0xFFF8, 0xFFFF)
    rng = random.Random(seed)
    chain = rng.sample(range(8, 24000), math.ceil(len(data) / 1024))
    extents = []
    for i, cluster in enumerate(chain):
        logical = i * 1024
        block = data[logical:logical + 1024]
        physical = (289 + (cluster - 2) * 2) * SECTOR
        image[physical:physical + len(block)] = block
        extents.append({"logical_offset": logical, "image_offset": physical, "length": len(block)})
        if not clear_chain:
            struct.pack_into("<H", fat, cluster * 2, chain[i + 1] if i + 1 < len(chain) else 0xFFFF)
    image[SECTOR:129 * SECTOR] = fat
    image[129 * SECTOR:257 * SECTOR] = fat
    entry = 257 * SECTOR
    image[entry:entry + 11] = b"PAYLOAD JPG"
    if deleted:
        image[entry] = 0xE5
    image[entry + 11] = 0x20
    struct.pack_into("<H", image, entry + 26, chain[0])
    struct.pack_into("<I", image, entry + 28, len(data))
    return image, extents


def attribute(kind, value, ident):
    total = (24 + len(value) + 7) & ~7
    result = bytearray(total)
    struct.pack_into("<IIBBHHH", result, 0, kind, total, 0, 0, 0, 0, ident)
    struct.pack_into("<IH", result, 16, len(value), 24)
    result[24:24 + len(value)] = value
    return result


def record(number, attrs, *, used=True, directory=False):
    result = bytearray(1024)
    result[:4] = b"FILE"
    struct.pack_into("<HH", result, 4, 48, 3)
    struct.pack_into("<HHHH", result, 16, 1, 1, 56, (1 if used else 0) | (2 if directory else 0))
    end = 56
    for attr in attrs:
        result[end:end + len(attr)] = attr
        end += len(attr)
    struct.pack_into("<I", result, end, 0xFFFFFFFF)
    struct.pack_into("<II", result, 24, end + 8, 1024)
    struct.pack_into("<H", result, 40, len(attrs))
    struct.pack_into("<I", result, 44, number)
    struct.pack_into("<HHH", result, 48, 0xAA55, struct.unpack_from("<H", result, 510)[0], struct.unpack_from("<H", result, 1022)[0])
    result[510:512] = result[1022:1024] = b"\x55\xaa"
    return result


def nonresident(data_size, cluster_runs, ident=2):
    runs = bytearray()
    previous = 0
    total_clusters = 0
    for lcn, length in cluster_runs:
        delta = lcn - previous
        width = next(n for n in range(1, 9) if -(1 << (8 * n - 1)) <= delta < (1 << (8 * n - 1)))
        count_width = max(1, (length.bit_length() + 7) // 8)
        runs += bytes([(width << 4) | count_width]) + length.to_bytes(count_width, "little") + delta.to_bytes(width, "little", signed=True)
        total_clusters += length
        previous = lcn
    runs += b"\x00"
    result = bytearray((64 + len(runs) + 7) & ~7)
    struct.pack_into("<IIBBHHH", result, 0, 0x80, len(result), 1, 0, 0, 0, ident)
    struct.pack_into("<QQHHIQQQ", result, 16, 0, total_clusters - 1, 64, 0, 0, total_clusters * 4096, data_size, data_size)
    result[64:64 + len(runs)] = runs
    return result


def ntfs_image(data, seed):
    image = bytearray(64 * 1024 * 1024)
    image[:3] = b"\xeb\x52\x90"
    image[3:11] = b"NTFS    "
    struct.pack_into("<HB", image, 11, 512, 8)
    image[21] = 0xF8
    struct.pack_into("<Q", image, 40, len(image) // SECTOR)
    struct.pack_into("<QQ", image, 48, 4, 8192)
    image[64] = 0xF6
    image[68] = 1
    struct.pack_into("<Q", image, 72, seed)
    image[510:512] = b"\x55\xaa"
    image[-512:] = image[:512]
    mft = 4 * 4096
    image[mft:mft + 1024] = record(0, [nonresident(64 * 1024, [(4, 16)])])
    root_name = bytearray(68)
    struct.pack_into("<Q", root_name, 0, 5 | (1 << 48))
    root_name[64:66] = b"\x01\x01"
    root_name[66:68] = b".\x00"
    image[mft + 5 * 1024:mft + 6 * 1024] = record(5, [attribute(0x30, root_name, 1)], directory=True)
    rng = random.Random(seed)
    clusters = rng.sample(range(100, 7500), math.ceil(len(data) / 4096))
    extents = []
    for i, cluster in enumerate(clusters):
        logical = i * 4096
        block = data[logical:logical + 4096]
        image[cluster * 4096:cluster * 4096 + len(block)] = block
        extents.append({"logical_offset": logical, "image_offset": cluster * 4096, "length": len(block)})
    name = "grandma-benchmark.jpg".encode("utf-16le")
    fn = bytearray(66 + len(name))
    struct.pack_into("<Q", fn, 0, 5 | (1 << 48))
    struct.pack_into("<QQI", fn, 40, math.ceil(len(data) / 4096) * 4096, len(data), 0x20)
    fn[64:66] = bytes([len(name) // 2, 1])
    fn[66:] = name
    image[mft + 42 * 1024:mft + 43 * 1024] = record(42, [attribute(0x30, fn, 1), nonresident(len(data), [(c, 1) for c in clusters])], used=False)
    image[8192 * 4096:8192 * 4096 + 4096] = image[mft:mft + 4096]
    return image, extents


def build(destination, ffmpeg):
    destination.mkdir(parents=True, exist_ok=False)
    originals = destination / "originals"
    images = destination / "images"
    originals.mkdir()
    images.mkdir()
    assets = {"baseline.jpg": jpeg(SEED), "restart.jpg": jpeg(SEED + 1, restart=True),
              "progressive.jpg": jpeg(SEED + 2, progressive=True, restart=True)}
    assets.update(make_videos(originals, ffmpeg))
    assets["chunked.png"] = png_asset(assets["restart.jpg"])
    for name, data in assets.items():
        (originals / name).write_bytes(data)
    reference = []
    for name, data in assets.items():
        item = {"name": name, "path": "originals/" + name, "bytes": len(data), "sha256": sha(data)}
        if name.endswith((".mp4", ".mov")):
            offsets, mdats = bmff_chunk_boundaries(data)
            item.update(chunks=len(offsets), chunk_offsets=offsets, mdat_ranges=mdats,
                        decoded_frames_sha256=frame_digest(ffmpeg, originals / name))
        else:
            with Image.open(io.BytesIO(data)) as image:
                item["decoded_rgb_sha256"] = sha(image.convert("RGB").tobytes())
        reference.append(item)
    cases = []
    def add(name, asset, image, extents, expected=True, note=""):
        path = images / (name + ".dd")
        path.write_bytes(image)
        cases.append({"name": name, "image": "images/" + path.name, "bytes": len(image), "sha256": sha(image),
                      "expected": [{"asset": asset, "all_original_bytes_present": expected,
                                    "extents": extents}], "note": note})
    for i, name in enumerate(("baseline.jpg", "avc-single.mp4", "mjpeg-single.mov")):
        image, extents = raw_image([(0, assets[name])], SEED + 10 + i, contiguous=True)
        add("raw-contiguous-" + Path(name).stem, name, image, extents)
    for i, name in enumerate(("restart.jpg", "progressive.jpg", "baseline.jpg")):
        data = assets[name]
        markers = [p + 2 for p in range(len(data) - 1) if data[p] == 255 and 208 <= data[p + 1] <= 215]
        # Restart boundaries and arbitrary cluster boundaries are distinct cases.
        cuts = [markers[len(markers) // 3], markers[len(markers) * 2 // 3]] if len(markers) >= 3 else [4096, 8192]
        parts = split_at(data, cuts)
        image, extents = raw_image(parts, SEED + 30 + i)
        add("raw-scattered-" + Path(name).stem, name, image, extents,
            note="JPEG split at encoder restart boundaries" if markers else "JPEG split at arbitrary 4KiB boundaries")
    for i, name in enumerate(("avc-dual.mp4", "mjpeg-dual.mov")):
        data = assets[name]
        offsets, mdats = bmff_chunk_boundaries(data)
        cuts = offsets + [point for pair in mdats for point in pair]
        parts = split_at(data, cuts)
        image, extents = raw_image(parts, SEED + 50 + i)
        add("raw-scattered-" + Path(name).stem, name, image, extents,
            note="Original FFmpeg chunks reordered physically; original moov retained; no ground-truth map in image")
        image, extents = raw_image(parts, SEED + 50 + i, overwrite=2)
        add("raw-overwritten-" + Path(name).stem, name, image, extents, False,
            "64 source bytes were overwritten. Whole original recovery must not be claimed")
    for i, (deleted, clear) in enumerate(((False, False), (True, False), (True, True))):
        image, extents = fat16_image(assets["restart.jpg"], SEED + 70 + i, deleted=deleted, clear_chain=clear)
        add(("fat16-live-chain", "fat16-deleted-retained-chain", "fat16-deleted-cleared-chain")[i], "restart.jpg", image, extents,
            note="Scatter at ordinary 1KiB allocation units; BPB/FAT/root directory independently constructed")
    image, extents = ntfs_image(assets["baseline.jpg"], SEED + 80)
    add("ntfs-deleted-data-runs", "baseline.jpg", image, extents,
        note="Deleted FILE record42 retains nonresident signed-delta data runs; independently written USA fixups")
    # Intentionally malformed headers are decoys, not expected recovered files.
    image = bytearray(b"\xcc" * (8 * 1024 * 1024))
    image[65536:65536 + 32] = b"\xff\xd8\xff\xe0" + b"x" * 26 + b"\xff\xd9"
    image[131072:131088] = struct.pack(">I4s", 0x7FFFFFFF, b"ftyp") + b"isom0000"
    image[262144:262160] = struct.pack(">I4s", 16, b"moov") + b"garbage!"
    path = images / "raw-malformed-decoys.dd"
    path.write_bytes(image)
    cases.append({"name": "raw-malformed-decoys", "image": "images/" + path.name,
                  "bytes": len(image), "sha256": sha(image), "expected": [],
                  "note": "JPEG/ISO-BMFF headers with invalid structure; no recoverable original"})
    png = assets["chunked.png"]
    image, extents = raw_image([(0, png)], SEED + 90, contiguous=True)
    add("raw-contiguous-png", "chunked.png", image, extents)
    parts = split_at(png, png_boundaries(png))
    image, extents = raw_image(parts, SEED + 91)
    add("raw-scattered-png-chunks", "chunked.png", image, extents, note="Each complete PNG chunk is physically scattered; CRC and zlib unchanged")
    image, extents = raw_image(parts, SEED + 91, overwrite=3)
    add("raw-overwritten-png-crc", "chunked.png", image, extents, False, "IDAT bytes overwritten; CRC and whole zlib verification must fail")
    # A valid but different IDAT is an extra candidate, not permission to invent
    # the original image. Its incompatible zlib stream cannot complete this PNG.
    image, extents = raw_image(parts, SEED + 92)
    wrong = zlib.compress(b"wrong stream, not pixels" * 70)
    decoy = struct.pack(">I", len(wrong)) + b"IDAT" + wrong + struct.pack(">I", zlib.crc32(b"IDAT" + wrong))
    image[7 * 1024 * 1024:7 * 1024 * 1024 + len(decoy)] = decoy
    add("raw-scattered-png-crc-decoy", "chunked.png", image, extents, note="Additional CRC-valid but incompatible IDAT stream")
    manifest = {"schema": 1, "seed": SEED, "scope": "Synthetic regular image files only. No device access.",
                "generator_sha256": file_sha(Path(__file__)), "ffmpeg_sha256": file_sha(ffmpeg),
                "ffmpeg_version": run([ffmpeg, "-version"]).decode().splitlines()[0],
                "assets": reference, "cases": cases}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"manifest": str(destination / "manifest.json"), "cases": len(cases),
                      "assets": len(assets), "largest_asset": max(len(x) for x in assets.values())}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    args = parser.parse_args()
    build(args.destination.resolve(), args.ffmpeg.resolve())
