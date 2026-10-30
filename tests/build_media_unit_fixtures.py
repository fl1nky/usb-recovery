"""Independent real-FFmpeg allocation-unit layouts and ambiguity controls.

The recovery API receives only the image path. Reference extents below are
ground truth for fixture construction/verification, never production input.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).parent / "benchmarks"))
from media_corpus import run, sha, file_sha, boxes, split_at, frame_digest
from audio_corpus import audio_digest
from build_aac_recovery_fixtures import change_gain


def build(destination: Path, ffmpeg: Path):
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "originals").mkdir()
    (destination / "images").mkdir()
    assets = {}
    for name, size, rate, seconds, frequency, channels, front in (
        ("small-front", "192x128", 10, 3, 44100, 1, True),
        ("small-tail", "192x128", 10, 3, 44100, 1, False),
        ("large-front", "320x192", 12, 4, 48000, 2, True),
        ("dual-front", "192x128", 8, 3, 44100, 1, True),
    ):
        path = destination / "originals" / (name + ".mp4")
        command = [ffmpeg, "-v", "error", "-nostdin", "-y", "-f", "lavfi",
                   "-i", "testsrc2=size=" + size + ":rate=" + str(rate), "-f", "lavfi",
                   "-i", "sine=frequency=1249:sample_rate=" + str(frequency), "-t", str(seconds),
                   *(["-map", "0:v", "-map", "0:v", "-map", "1:a"] if name == "dual-front" else ["-map", "0:v", "-map", "1:a"]), "-c:v", "libx264", "-preset", "medium",
                   "-crf", "23", "-g", str(rate), "-bf", "2", "-threads", "1",
                   "-c:a", "aac", "-b:a", "64k", "-ac", str(channels), "-map_metadata", "-1",
                   "-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact"]
        if front:
            command += ["-movflags", "+faststart"]
        run(command + [path])
        packets = json.loads(run([ffmpeg.with_name("ffprobe.exe"), "-v", "error", "-show_packets",
                                  "-show_entries", "packet=codec_type,pos,size", "-of", "json", path]))["packets"]
        assets[name] = {"path": path, "data": path.read_bytes(), "packets": packets,
                        "frames": frame_digest(ffmpeg, path), "pcm": audio_digest(ffmpeg, path)}

    # Independently ask the muxer for ordinary metadata, placing a real sample's
    # four-byte NAL length across a 4096-byte boundary. No payload is rewritten.
    source = assets["small-front"]
    packet = min((p for p in source["packets"] if p["codec_type"] == "video" and int(p["pos"]) > 4096), key=lambda p: (4094 - int(p["pos"])) % 4096)
    target_packet = [p for p in source["packets"] if p["codec_type"] == "video"].index(packet)
    comment_length = 1
    prefix_path = destination / "originals" / "nal-prefix-split.mp4"
    for attempt in range(3):
        run([ffmpeg, "-v", "error", "-nostdin", "-y", "-i", source["path"], "-map", "0", "-c", "copy", "-metadata", "comment=" + "V" * comment_length, "-movflags", "+faststart", "-fflags", "+bitexact", prefix_path])
        packets = json.loads(run([ffmpeg.with_name("ffprobe.exe"), "-v", "error", "-show_packets", "-show_entries", "packet=codec_type,pos,size", "-of", "json", prefix_path]))["packets"]
        position = int([p for p in packets if p["codec_type"] == "video"][target_packet]["pos"])
        if position % 4096 == 4094:
            break
        comment_length += (4094 - position) % 4096
    else:
        raise ValueError("Muxer did not create the independently targeted NAL prefix split")
    assets["prefix-split"] = {"path": prefix_path, "data": prefix_path.read_bytes(), "packets": packets,
                              "frames": frame_digest(ffmpeg, prefix_path), "pcm": audio_digest(ffmpeg, prefix_path)}

    cases = []
    def emit(name, asset_name, unit, background="zero", action=None, expected=1):
        asset = assets[asset_name]
        data = asset["data"]
        cuts = list(range(unit, len(data), unit))
        if action == "nonaligned":
            cuts = list(range(unit + 37, len(data), unit + 37))
        pieces = split_at(data, cuts)
        rng = random.Random(20261108 + len(cases))
        image_size = 2 * 1024 * 1024
        image = bytearray(rng.randbytes(image_size) if background == "random" else bytes([0 if background == "zero" else 204]) * image_size)
        slots = rng.sample(range(1, 24), len(pieces))
        extents = []
        for n, (logical, payload) in enumerate(pieces):
            # Allocation units need not start at an address divisible by their
            # size. Vary the 512-byte-aligned physical origins independently.
            physical = slots[n] * 65536 + rng.randrange(1, 15) * 512
            image[physical:physical + len(payload)] = payload
            extents.append({"logical_offset": logical, "image_offset": physical, "length": len(payload)})
        expected_data = data
        original_present = True
        expected_pcm = asset["pcm"]
        decode = True
        reason = None
        if action == "duplicate":
            for n, (logical, payload) in enumerate(pieces):
                physical = 1600000 + n * 16384
                physical = (physical + 511) // 512 * 512
                image[physical:physical + len(payload)] = payload
        if action in ("foreign", "foreign-only", "audio-overwrite"):
            packets = [p for p in asset["packets"] if p["codec_type"] == "audio" and int(p["pos"]) // unit == (int(p["pos"]) + int(p["size"]) - 1) // unit]
            packet = packets[len(packets) // 2]
            logical, length = int(packet["pos"]), int(packet["size"])
            original = data[logical:logical + length]
            changed = change_gain(original)
            mutated = data[:logical] + changed + data[logical + length:]
            mutated_path = destination / "originals" / (name + "-current.mp4")
            mutated_path.write_bytes(mutated)
            changed_pcm = audio_digest(ffmpeg, mutated_path)
            if changed_pcm == asset["pcm"] or frame_digest(ffmpeg, mutated_path) != asset["frames"]:
                raise ValueError("Independent known same-config AAC mutation must change PCM only")
            index = logical // unit
            extent = extents[index]
            if action == "foreign":
                physical = 1900032
                logical_start, payload = pieces[index]
                foreign = mutated[logical_start:logical_start + len(payload)]
                image[physical:physical + len(foreign)] = foreign
                reason = "unit_mapping_ambiguous"
            elif action == "foreign-only":
                physical = extent["image_offset"] + logical - extent["logical_offset"]
                image[physical:physical + length] = changed
                original_present = False
                expected_data, expected_pcm = mutated, changed_pcm
            else:
                physical = extent["image_offset"] + logical - extent["logical_offset"]
                image[physical:physical + min(length, 32)] = bytes(min(length, 32))
                original_present = False
        if action == "metadata-ambiguous":
            where = data.index(b"SoundHandler")
            index = where // unit
            logical, payload = pieces[index]
            changed = bytearray(payload)
            changed[where - logical] = ord("T")
            physical = 1900032
            image[physical:physical + len(changed)] = changed
            reason = "moov_unit_ambiguous"
        if action == "missing":
            extent = extents[len(extents) // 2]
            physical = extent["image_offset"]
            image[physical:physical + extent["length"]] = bytes(extent["length"])
            original_present = False
        if action == "opaque":
            packet = next(p for p in asset["packets"] if p["codec_type"] == "video" and int(p["size"]) > 1000 and int(p["pos"]) > unit)
            logical = int(packet["pos"]) + int(packet["size"]) // 2
            extent = next(e for e in extents if e["logical_offset"] <= logical < e["logical_offset"] + e["length"])
            physical = extent["image_offset"] + logical - extent["logical_offset"]
            image[physical] ^= 1
            changed = bytearray(data)
            changed[logical] ^= 1
            expected_data, original_present, decode = bytes(changed), False, False
        if action == "metadata-overlap":
            continuation_extent = extents[-1]
            continuation = data[continuation_extent["logical_offset"]:]
            if not any(k == b"moov" and a < continuation_extent["logical_offset"] < b for k, a, b, h in boxes(data)):
                raise ValueError("Regression requires a split tail moov")
            previous = continuation_extent["image_offset"]
            image[previous:previous + len(continuation)] = bytes(len(continuation))
            continuation_extent["image_offset"] = image_size - 32768 + 512
            image[continuation_extent["image_offset"]:continuation_extent["image_offset"] + len(continuation)] = continuation
            selected = None
            for packet in asset["packets"]:
                if packet["codec_type"] != "video":
                    continue
                at, stop = int(packet["pos"]), int(packet["pos"]) + int(packet["size"])
                while at < stop:
                    length = int.from_bytes(data[at:at + 4], "big")
                    if length < 1 or at + 4 + length > stop:
                        raise ValueError("Independent AVC framing invalid")
                    if data[at + 4] & 31 in (1, 5):
                        for logical in range((at + 4 + 128 + 511) // 512 * 512, at + 4 + length - len(continuation) + 1, 512):
                            owner = next(e for e in extents if e["logical_offset"] <= logical < e["logical_offset"] + e["length"])
                            if logical + len(continuation) <= owner["logical_offset"] + owner["length"]:
                                selected = logical, owner["image_offset"] + logical - owner["logical_offset"]
                                break
                    if selected:
                        break
                    at += 4 + length
                if selected:
                    break
            if selected is None:
                raise ValueError("Need opaque AVC region for the physical-overlap regression")
            logical, physical = selected
            image[physical:physical + len(continuation)] = continuation
            current = bytearray(data)
            current[logical:logical + len(continuation)] = continuation
            expected_data, original_present, decode = bytes(current), False, False
        path = destination / "images" / (name + ".dd")
        path.write_bytes(image)
        cases.append({"name": name, "image": "images/" + path.name, "sha256": sha(image), "bytes": len(image),
                      "expected": expected, "expected_output_sha256": sha(expected_data), "original_sha256": sha(data),
                      "all_original_bytes_present": original_present, "expected_video_sha256": asset["frames"],
                      "expected_audio_sha256": expected_pcm, "decode": decode, "reason": reason,
                      "unit": unit, "background": background, "action": action, "truth_extents": extents})

    emit("front-4k-zero", "small-front", 4096)
    emit("front-8k-random", "small-front", 8192, "random")
    emit("tail-4k-zero", "small-tail", 4096)
    emit("tail-8k-cc", "small-tail", 8192, "cc")
    emit("larger-8k-zero", "large-front", 8192)
    emit("larger-16k-random", "large-front", 16384, "random")
    emit("two-video-tracks-8k", "dual-front", 8192)
    emit("nal-length-prefix-split", "prefix-split", 4096)
    emit("identical-all-units", "small-front", 4096, action="duplicate")
    emit("same-config-foreign-choice", "small-front", 4096, action="foreign", expected=0)
    emit("same-config-foreign-current", "small-front", 4096, action="foreign-only")
    emit("metadata-choice", "small-tail", 4096, action="metadata-ambiguous", expected=0)
    emit("audio-overwrite", "small-front", 4096, action="audio-overwrite", expected=0)
    emit("missing-unit", "small-front", 4096, action="missing", expected=0)
    emit("nonaligned-cuts", "small-front", 4096, action="nonaligned", expected=0)
    emit("opaque-entropy-candidate", "small-front", 4096, action="opaque")
    emit("equal-metadata-different-overlap", "small-tail", 4096, action="metadata-overlap")
    manifest = {"schema": 1, "generator_sha256": file_sha(Path(__file__)), "ffmpeg_sha256": file_sha(ffmpeg),
                "support_sha256": {name: file_sha(Path(__file__).parent / name) for name in ("benchmarks/media_corpus.py", "benchmarks/audio_corpus.py", "build_aac_recovery_fixtures.py")},
                "scope": "Synthetic real FFmpeg AVC+B-frames/AAC, 192x128/320x192, 44.1kHz mono/48kHz stereo; no user data",
                "assets": [{"name": n, "path": "originals/" + a["path"].name, "bytes": len(a["data"]), "sha256": sha(a["data"]), "frames": a["frames"], "pcm": a["pcm"]} for n, a in assets.items()], "cases": cases}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"destination": str(destination), "cases": len(cases), "assets": len(assets)}))


def package(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    for case in manifest["cases"]:
        raw = (source / case["image"]).read_bytes()
        if sha(raw) != case["sha256"]:
            raise ValueError("Fixture hash mismatch")
        name = case["name"] + ".dd.gz"
        packed = gzip.compress(raw, compresslevel=9, mtime=0)
        (destination / name).write_bytes(packed)
        case["archive"], case["archive_sha256"] = name, sha(packed)
        case["image"] = case["name"] + ".dd"
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (destination / "PROVENANCE.txt").write_text("Synthetic images generated for this project using real FFmpeg encoders. No personal or third-party program data. No separate license grant is defined. The included manifest records generator, decoder, input and expected-content hashes. Recovery receives only an image path.\n", encoding="utf-8")


def extract(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    for case in manifest["cases"]:
        for key in ("archive", "image"):
            if Path(case[key]).name != case[key]:
                raise ValueError("Invalid fixture path")
        packed = (source / case["archive"]).read_bytes()
        if sha(packed) != case["archive_sha256"]:
            raise ValueError("Compressed fixture hash mismatch")
        raw = gzip.decompress(packed)
        if len(raw) != case["bytes"] or sha(raw) != case["sha256"]:
            raise ValueError("Expanded fixture hash mismatch")
        (destination / case["image"]).write_bytes(raw)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--extract", type=Path)
    args = parser.parse_args()
    if args.package:
        package(args.package.resolve(), args.destination.resolve())
    elif args.extract:
        extract(args.extract.resolve(), args.destination.resolve())
    elif args.ffmpeg:
        build(args.destination.resolve(), args.ffmpeg.resolve())
    else:
        parser.error("Supply --ffmpeg, --package or --extract")
