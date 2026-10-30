"""Pin independent real-FFmpeg audio-island corpus and adversarial controls.

Inputs are the output of tests/benchmarks/audio_corpus.py. Manifest extents are
used here only to construct ground truth, never passed to recovery code.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args):
    result = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
    if result.returncode or result.stderr:
        raise RuntimeError("Independent decoder rejected synthetic mutation: " + result.stderr.decode(errors="replace")[-1000:])
    return result.stdout


class Bits:
    def __init__(self, data):
        self.data, self.at = data, 0

    def get(self, count):
        value = 0
        for _ in range(count):
            value = value * 2 + ((self.data[self.at // 8] >> (7 - self.at % 8)) & 1)
            self.at += 1
        return value


def change_gain(raw):
    """Change only global_gain, leaving sizes and entropy codewords intact."""
    data = bytearray(raw); bits = Bits(data)
    for _ in range(32):
        element = bits.get(3)
        if element == 6:
            count = bits.get(4)
            if count == 15:
                count = 14 + bits.get(8)
            bits.at += count * 8
            continue
        if element not in (0, 1):
            raise ValueError("Expected independently encoded SCE/CPE")
        bits.get(4)
        if element == 1 and bits.get(1):
            if bits.get(1):
                raise ValueError("Reserved ICS bit")
            sequence = bits.get(2); bits.get(1)
            bands = bits.get(4 if sequence == 2 else 6)
            groups = 1
            if sequence == 2:
                groups += sum(bits.get(1) == 0 for _ in range(7))
            elif bits.get(1):
                raise ValueError("LC prediction forbidden")
            mask = bits.get(2)
            if mask == 1:
                bits.at += groups * bands
            elif mask == 3:
                raise ValueError("Reserved stereo mask")
        start = bits.at; gain = bits.get(8)
        if gain > 250:
            raise ValueError("Synthetic gain mutation would clip")
        for i in range(8):
            at = start + i; data[at // 8] &= ~(1 << (7 - at % 8)); data[at // 8] |= ((gain + 1) >> (7 - i) & 1) << (7 - at % 8)
        return bytes(data)
    raise ValueError("No encoded audio element")


def package(corpus, destination, ffmpeg):
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=False)
    assets = {a["name"]: a for a in manifest["assets"]}
    cases = []

    def save(name, image, asset, expected, output_sha=None, exact=True, reason=None, note=None):
        archive = name + ".dd.gz"
        packed = gzip.compress(bytes(image), compresslevel=9, mtime=0)
        (destination / archive).write_bytes(packed)
        cases.append({"name": name, "archive": archive, "archive_sha256": sha(packed), "image": name + ".dd",
                      "image_bytes": len(image), "image_sha256": sha(image), "expected": expected,
                      "expected_output_sha256": output_sha or asset["sha256"], "exact_original": exact,
                      "expected_video_sha256": asset["decoded_frames_sha256"], "expected_audio_sha256": asset["decoded_audio_sha256"],
                      "reason": reason, "note": note})

    for case in manifest["cases"]:
        asset = assets[case["expected"][0]["asset"]]; image = (corpus / case["image"]).read_bytes()
        if sha(image) != case["sha256"]:
            raise ValueError("Independent corpus image changed")
        expected = 1 if case["name"].endswith(("chunk-islands", "all-chunks")) else 0
        save(case["name"], image, asset, expected, note=case["note"])

    # FFprobe independently supplies exact AAC access-unit positions and sizes.
    base = next(c for c in manifest["cases"] if c["name"] == "avc-aac-faststart-all-chunks")
    asset = assets[base["expected"][0]["asset"]]; original = corpus / asset["path"]; raw = original.read_bytes()
    packets = json.loads(run([ffmpeg.with_name("ffprobe.exe"), "-v", "error", "-select_streams", "a:0", "-show_packets",
                              "-show_entries", "packet=pos,size", "-of", "json", original]))["packets"]
    packet_map = {int(p["pos"]): p for p in packets}
    chunk_start = next(x for x in asset["chunk_offsets"][3:] if x in packet_map)
    media_end = next(end for start, end in asset["mdat_ranges"] if start <= chunk_start < end)
    chunk_end = min([x for x in asset["chunk_offsets"] if x > chunk_start] + [media_end])
    chunk = raw[chunk_start:chunk_end]; packet_size = int(packet_map[chunk_start]["size"])
    changed = change_gain(chunk[:packet_size]) + chunk[packet_size:]
    altered = raw[:chunk_start] + changed + raw[chunk_end:]
    temp = destination / "gain-control.mp4"; temp.write_bytes(altered)
    altered_audio = sha(run([ffmpeg, "-v", "error", "-nostdin", "-i", temp, "-map", "0:a", "-c:a", "pcm_s16le", "-f", "s16le", "-"]))
    temp.unlink()
    if altered_audio == asset["decoded_audio_sha256"]:
        raise ValueError("Global gain mutation did not produce independently different decoded PCM")
    extent = next(e for e in base["expected"][0]["extents"] if e["logical_offset"] == chunk_start)
    if extent["length"] != len(chunk):
        raise ValueError("AAC chunk is not independently isolated in source corpus")
    physical = extent["image_offset"]; spare = 7_700_480  # 512-byte aligned, verified unused below
    image = bytearray((corpus / base["image"]).read_bytes())
    if spare % 512 or image[spare:spare + len(chunk)] != b"\xcc" * len(chunk):
        raise ValueError("Test duplicate region is not unused aligned space")
    identical = image.copy(); identical[spare:spare + len(chunk)] = chunk
    save("aac-identical-duplicate", identical, asset, 1, note="Equal bytes at two physical locations are equivalent provenance")
    ambiguous = image.copy(); ambiguous[spare:spare + len(chunk)] = changed
    save("aac-distinct-valid-duplicate", ambiguous, asset, 0, reason="chunk_payload_ambiguous", note="Two complete syntax-valid AAC chunks have identical declared sample sizes but independently different decoded PCM")
    altered_image = image.copy(); altered_image[physical:physical + len(chunk)] = changed
    save("aac-valid-history-unknown", altered_image, asset, 1, output_sha=sha(altered), exact=False, note="Syntax has no checksum: valid changed audio remains a candidate, never authenticated original")
    cases[-1]["expected_audio_sha256"] = altered_audio
    missing = image.copy(); missing[physical:physical + len(chunk)] = b"\0" * len(chunk)
    save("aac-missing-chunk", missing, asset, 0, reason="aac_chunk_missing_or_invalid")
    split = image.copy(); split[physical:physical + len(chunk)] = b"\xcc" * len(chunk)
    cut = max(3, packet_size // 2); split[physical:physical + cut] = chunk[:cut]; split[spare:spare + len(chunk) - cut] = chunk[cut:]
    save("aac-split-access-unit", split, asset, 0, reason="aac_chunk_missing_or_invalid", note="No synthesized AAC bytes when an access unit itself is split")
    unaligned = image.copy(); unaligned[physical:physical + len(chunk)] = b"\xcc" * len(chunk); unaligned[spare + 37:spare + 37 + len(chunk)] = chunk
    save("aac-unaligned-unsupported", unaligned, asset, 0, reason="aac_chunk_missing_or_invalid", note="An isolated unaligned audio chunk without affine anchors is outside the explicitly bounded search")
    result = {"schema": 1, "source_manifest_sha256": sha((corpus / "manifest.json").read_bytes()), "ffmpeg_sha256": sha(ffmpeg.read_bytes()),
              "generator_sha256": sha(Path(__file__).read_bytes()), "scope": "Independent real FFmpeg AVC/AAC regular images plus explicitly described adversarial derivatives; no production recovery imports or device access", "cases": cases}
    (destination / "manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (destination / "PROVENANCE.txt").write_text("Synthetic media generated for USB-Recovery using FFmpeg, plus documented byte mutations and source-layout changes. No personal data, third-party authored media or program binaries. No separate license grant is defined by this file.\n", encoding="utf-8")
    print(json.dumps({"bundle": str(destination.resolve()), "cases": len(cases), "bytes": sum(p.stat().st_size for p in destination.iterdir())}))


def extract(source, destination):
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    if len(manifest["cases"]) > 64:
        raise ValueError("Too many fixture cases")
    destination.mkdir(parents=True, exist_ok=False)
    for case in manifest["cases"]:
        name, archive = case["image"], case["archive"]
        if Path(name).name != name or Path(archive).name != archive or not name.endswith(".dd") or archive != name + ".gz":
            raise ValueError("Unsafe fixture path")
        expected = int(case["image_bytes"])
        if expected < 1 or expected > 16 * 1024 * 1024:
            raise ValueError("Fixture expansion bound")
        packed = (source / archive).read_bytes()
        if len(packed) > 16 * 1024 * 1024 or sha(packed) != case["archive_sha256"]:
            raise ValueError("Compressed fixture hash/bounds")
        with gzip.open(source / archive, "rb") as stream:
            raw = stream.read(expected + 1)
        if len(raw) != expected or sha(raw) != case["image_sha256"]:
            raise ValueError("Fixture image hash/bounds")
        (destination / name).write_bytes(raw)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"destination": str(destination.resolve()), "cases": len(manifest["cases"]), "offline": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--ffmpeg", type=Path)
    parser.add_argument("--extract", type=Path)
    args = parser.parse_args()
    if args.extract:
        extract(args.extract.resolve(), args.destination.resolve())
    elif args.corpus and args.ffmpeg:
        package(args.corpus.resolve(), args.destination.resolve(), args.ffmpeg.resolve())
    else:
        parser.error("Use --extract BUNDLE, or --corpus CORPUS --ffmpeg EXE")
