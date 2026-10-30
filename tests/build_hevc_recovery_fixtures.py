"""Scatter genuine independently encoded HEVC MP4 chunks into owned RAW files."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import random
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(command):
    return subprocess.run([str(value) for value in command], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=90)


def build(destination, samples, ffmpeg):
    destination = destination.resolve()
    if destination.exists():
        raise ValueError("A new fixture directory is required")
    ffmpeg = ffmpeg.resolve()
    manifest = json.loads((samples / "manifest.json").read_text(encoding="utf-8-sig"))
    if manifest["ffmpeg_sha256"] != sha(ffmpeg.read_bytes()):
        raise ValueError("Independent encoder differs from sample fixture provenance")
    spec = importlib.util.spec_from_file_location("owned_media_corpus", ROOT / "tests/benchmarks/media_corpus.py")
    corpus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(corpus)
    destination.mkdir(parents=True)
    rows = []
    originals = {}
    for item in manifest["files"]:
        if item["name"] not in {"main-hvc1", "main10-hev1", "two-slices-hvc1"}:
            continue
        data = (samples / item["original"]).read_bytes()
        if sha(data) != item["original_sha256"]:
            raise ValueError("Independent encoded original changed")
        originals[item["name"]] = data
    dual = destination / "dual-independent.mp4"
    command = [ffmpeg, "-v", "error", "-nostdin", "-f", "lavfi", "-i", "testsrc2=size=160x96:rate=6",
               "-f", "lavfi", "-i", "testsrc=size=192x128:rate=6", "-t", "2", "-map", "0:v", "-map", "1:v",
               "-c:v", "libx265", "-pix_fmt", "yuv420p", "-threads", "1", "-preset", "fast", "-x265-params",
               "log-level=error:pools=1:frame-threads=1:keyint=6:min-keyint=6:scenecut=0:bframes=2:repeat-headers=0",
               "-tag:v", "hvc1", "-max_interleave_delta", "1", "-movflags", "+faststart", dual]
    run(command)
    originals["dual-hvc1"] = dual.read_bytes()

    def parts_of(data):
        boundaries, mdats = corpus.bmff_chunk_boundaries(data)
        if len(mdats) != 1 or not boundaries or boundaries[0] != mdats[0][0]:
            raise ValueError("Expected one densely packed real mdat")
        parts = []
        for kind, start, end, header in corpus.boxes(data):
            if kind == b"mdat":
                parts.append((start, data[start:start + header], "mdat_header"))
            else:
                parts.append((start, data[start:end], kind.decode("ascii")))
        for start, end in zip(boundaries, boundaries[1:] + [mdats[0][1]]):
            parts.append((start, data[start:end], "sample_chunk"))
        parts.sort()
        if b"".join(payload for _, payload, _ in parts) != data:
            raise ValueError("Independent parts do not cover original exactly")
        return parts

    def scatter(name, data, expected=1, exact=True, mutate=None, duplicate=False):
        parts = parts_of(data)
        positions = random.Random(814003 + len(rows)).sample(range(131072, 7340032, 131072), len(parts))
        image = bytearray(b"\xcc" * (8 * 1024 * 1024))
        extents = []
        for (logical, payload, kind), physical in zip(parts, positions):
            if len(payload) >= 131072:
                raise ValueError("Owned scatter slot is too small")
            image[physical:physical + len(payload)] = payload
            extents.append(dict(LogicalOffset=logical, ImageOffset=physical, Length=len(payload), Kind=kind))
        chunks = [(i, item) for i, item in enumerate(parts) if item[2] == "sample_chunk"]
        if mutate is not None:
            mutate(image, parts, extents, chunks)
        if duplicate:
            index, (_, payload, _) = chunks[0]
            image[7864320:7864320 + len(payload)] = payload
        original = name + ".original.mp4"
        (destination / original).write_bytes(data)
        output = name + ".dd"
        (destination / output).write_bytes(image)
        original_path = destination / original
        decoded = run([ffmpeg, "-v", "error", "-nostdin", "-i", original_path, "-map", "0:v", "-an", "-f", "framemd5", "-"])
        if decoded.stderr.strip():
            raise ValueError("Independent original is not cleanly decoded")
        frames = [line for line in decoded.stdout.splitlines() if line and not line.startswith(b"#")]
        rows.append(dict(Name=name, Image=output, ImageSha256=sha(image), Original=original, Sha256=sha(data),
                         Bytes=len(data), Expected=expected, Exact=exact, Chunks=len(chunks),
                         Tracks=2 if name.startswith("dual-") else 1, DecodedSha256=sha(b"\n".join(frames)),
                         Extents=extents, Scope="Owned full original chunks, independent encoder tables; no recovery implementation imported"))

    for name, data in originals.items():
        scatter(name + "-scattered", data)
    base = originals["main-hvc1"]

    def invalid_length(image, parts, extents, chunks):
        index, _ = chunks[0]
        at = extents[index]["ImageOffset"]
        image[at:at + 4] = b"\x00" * 4

    scatter("nal-prefix-overwritten", base, 0, False, invalid_length)

    def incompatible_config(image, parts, extents, chunks):
        for index, (_, payload, kind) in enumerate(parts):
            if kind == "moov":
                marker = payload.index(b"hvcC") + 4
                image[extents[index]["ImageOffset"] + marker + 6] |= 0x40
                return
        raise ValueError("Missing independent hvcC")

    scatter("foreign-configuration-constraint", base, 0, False, incompatible_config)

    def replace_inband_set(image, parts, extents, chunks):
        for index, (_, payload, _) in chunks:
            at = 0
            while at + 6 <= len(payload):
                count = struct.unpack_from(">I", payload, at)[0]
                if count < 3 or count > len(payload) - at - 4:
                    break
                if ((payload[at + 4] >> 1) & 63) == 33:
                    image[extents[index]["ImageOffset"] + at + 4 + count - 3] ^= 1
                    return
                at += 4 + count
        raise ValueError("Independent hev1 did not contain the expected SPS")

    scatter("foreign-inband-set", originals["main10-hev1"], 0, False, replace_inband_set)

    def alter_entropy(payload):
        changed = bytearray(payload)
        count = struct.unpack_from(">I", changed)[0]
        if not 3 <= count <= len(changed) - 4 or ((changed[4] >> 1) & 63) >= 32:
            raise ValueError("Expected independent first VCL")
        position = 4 + count - 5
        while position > 24 and (changed[position] < 16 or 0 in changed[position - 2:position]):
            position -= 1
        if position <= 24:
            raise ValueError("No opaque CABAC byte in owned first picture")
        changed[position] ^= 1
        return changed

    def ambiguous(image, parts, extents, chunks):
        _, (_, payload, _) = chunks[0]
        alternative = alter_entropy(payload)
        image[7864320:7864320 + len(alternative)] = alternative

    scatter("distinct-syntax-assignments", base, 0, True, ambiguous)
    scatter("identical-chunk-duplicate", base, duplicate=True)

    def entropy_overwrite(image, parts, extents, chunks):
        index, (_, payload, _) = chunks[0]
        altered = alter_entropy(payload)
        at = extents[index]["ImageOffset"]
        image[at:at + len(altered)] = altered

    scatter("opaque-cabac-overwrite-candidate", base, 1, False, entropy_overwrite)
    result = dict(Schema=1, FfmpegSha256=sha(ffmpeg.read_bytes()), Cases=rows,
                  Scope="Actual independent FFmpeg/libx265 complete HEVC containers and chunk scattering; includes conservative ambiguity and explicit opaque-CABAC limits; no devices")
    (destination / "manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"cases": len(rows), "destination": str(destination)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    args = parser.parse_args()
    build(args.destination, args.samples.resolve(), args.ffmpeg)
