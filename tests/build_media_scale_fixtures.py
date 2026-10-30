"""Reproducible large real-encoder images; generated payloads stay outside Git.

Only image paths are passed to recovery. Reference maps construct/verify the
experiment, never guide production reconstruction. Requires the pinned local
FFmpeg on the developer machine; the application does not require FFmpeg.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent / "benchmarks"))
from media_corpus import boxes, split_at, frame_digest, run
from audio_corpus import audio_digest
from build_aac_recovery_fixtures import change_gain

FFMPEG_SHA = "3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec"
INDEPENDENT_SHA = "98f7743659209631f1942e0b2c6c8b356d48aa6c208c5585134cfa673cb675a0"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encode(ffmpeg, path, seconds, independent=False):
    command = [ffmpeg, "-v", "error", "-nostdin", "-n", "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=30",
               "-f", "lavfi", "-i", "sine=frequency=" + ("1249" if independent else "1117") + ":sample_rate=48000",
               "-t", str(seconds), "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-preset", "medium" if independent else "ultrafast",
               "-b:v", "4M", "-minrate", "4M", "-maxrate", "4M", "-bufsize", "8M" if independent else "4M",
               "-x264-params", "nal-hrd=cbr:force-cfr=1", "-g", "15" if independent else "30", "-bf", "2",
               "-threads", "1" if independent else "2", "-c:a", "aac", "-b:a", "96k", "-ac", "1" if independent else "2",
               "-map_metadata", "-1", "-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact", "-movflags", "+faststart", path]
    run(command)
    return ["ffmpeg.exe", *[str(value) for value in command[1:-1]], path.name]


def build(destination, ffmpeg, independent_asset):
    if digest(ffmpeg) != FFMPEG_SHA:
        raise ValueError("Pinned FFmpeg differs")
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "originals").mkdir()
    (destination / "images").mkdir()
    assets = {}
    for name, seconds, independent in (("front40", 40, False), ("front80", 80, False), ("independent48", 48, True)):
        path = destination / "originals" / (name + ".mp4")
        if independent and independent_asset:
            if digest(independent_asset) != INDEPENDENT_SHA:
                raise ValueError("Independent calibration asset changed")
            shutil.copyfile(independent_asset, path)
            command = "Independently supplied calibration; reproducible command is encode(...,48,True)"
        else:
            command = encode(ffmpeg, path, seconds, independent)
        if independent and digest(path) != INDEPENDENT_SHA:
            raise ValueError("Independent fixed encoder output differs")
        assets[name] = dict(path=path, command=command)
    tail = destination / "originals" / "tail40.mp4"
    run([ffmpeg, "-v", "error", "-nostdin", "-n", "-i", assets["front40"]["path"], "-map", "0", "-c", "copy", "-fflags", "+bitexact", tail])
    assets["tail40"] = dict(path=tail, command="FFmpeg stream copy of front40 without faststart; no payload rewriting")
    for asset in assets.values():
        path = asset["path"]
        asset["raw"] = path.read_bytes()
        asset["packets"] = json.loads(run([ffmpeg.with_name("ffprobe.exe"), "-v", "error", "-show_packets", "-show_entries", "packet=codec_type,pos,size", "-of", "json", path]))["packets"]
        asset["frames"], asset["pcm"] = frame_digest(ffmpeg, path), audio_digest(ffmpeg, path)
    cases = []
    def emit(name, source, image_mib=128, phase=0, background="zero", action=None, expected=1):
        asset = assets[source]
        data = asset["raw"]
        unit = 65536
        mdat = next((a + header for kind, a, b, header in boxes(data) if kind == b"mdat"))
        # Preserve a large front moov using a genuine contiguous prefix. Body
        # allocation units remain 64KiB and are independently scattered.
        first = (mdat + unit - 1) // unit * unit
        parts = split_at(data, range(first, len(data), unit))
        image_size = image_mib * 1024 * 1024
        rng = random.Random(20261123 + len(cases))
        slots = rng.sample(range(16, (image_size - 8 * 1024 * 1024) // unit - 4, 4), len(parts))
        image = destination / "images" / (name + ".dd")
        extents = []
        with image.open("xb") as output:
            output.truncate(image_size)
            if background == "random":
                filler = random.Random(20261130)
                for _ in range(image_size // (1024 * 1024)):
                    output.write(filler.randbytes(1024 * 1024))
            for n, ((logical, payload), slot) in enumerate(zip(parts, slots)):
                physical = slot * unit + rng.randrange(1, 16) * 512 + phase + (n % 2 if action == "mixed-phase" else 0)
                output.seek(physical)
                output.write(payload)
                extents.append(dict(logical_offset=logical, image_offset=physical, length=len(payload)))
            if action == "duplicate":
                index = len(parts) // 2
                physical = image_size - 4 * unit + phase
                output.seek(physical)
                output.write(parts[index][1])
            if action == "foreign-choice":
                packet = next(p for p in asset["packets"][len(asset["packets"]) // 2:] if p["codec_type"] == "audio" and int(p["pos"]) // unit == (int(p["pos"]) + int(p["size"]) - 1) // unit)
                at, length = int(packet["pos"]), int(packet["size"])
                index = next(n for n, (start, payload) in enumerate(parts) if start <= at < start + len(payload))
                logical, payload = parts[index]
                foreign = bytearray(payload)
                foreign[at - logical:at - logical + length] = change_gain(data[at:at + length])
                output.seek(image_size - 4 * unit + phase)
                output.write(foreign)
            if action == "missing":
                extent = extents[len(extents) // 2]
                output.seek(extent["image_offset"])
                output.write(bytes(extent["length"]))
        cases.append(dict(name=name, image="images/" + image.name, bytes=image_size, sha256=digest(image), expected=expected,
                          expected_output_sha256=digest(asset["path"]), expected_video_sha256=asset["frames"], expected_audio_sha256=asset["pcm"],
                          all_original_bytes_present=action != "missing", phase=phase, background=background, action=action, truth_extents=extents))
    emit("front20m-zero128", "front40")
    emit("tail20m-zero128", "tail40")
    emit("front40m-zero256", "front80", 256)
    emit("independent24m-phase17", "independent48", phase=17)
    emit("independent24m-random-phase511", "independent48", phase=511, background="random")
    emit("identical-unit-copy", "independent48", phase=17, action="duplicate")
    emit("foreign-unit-choice", "independent48", phase=17, action="foreign-choice", expected=0)
    emit("missing-unit", "independent48", action="missing", expected=0)
    emit("independent-fragment-phases", "front40", phase=17, action="mixed-phase", expected=0)
    public_assets = [dict(name=name, path="originals/" + asset["path"].name, bytes=len(asset["raw"]), sha256=digest(asset["path"]),
                          command=asset["command"], decoded_frames_sha256=asset["frames"], decoded_audio_sha256=asset["pcm"],
                          packet_count=len(asset["packets"]), max_video_packet=max(int(p["size"]) for p in asset["packets"] if p["codec_type"] == "video")) for name, asset in assets.items()]
    manifest = dict(schema=1, generator_sha256=digest(Path(__file__)), ffmpeg_sha256=FFMPEG_SHA,
                    scope="Owned reproducible real encoder clips/images only; no devices/user data. The image map is never passed to recovery. Payloads generated outside Git.", assets=public_assets, cases=cases)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"destination": str(destination), "cases": len(cases), "assets": len(assets)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--independent-asset", type=Path)
    args = parser.parse_args()
    build(args.destination.resolve(), args.ffmpeg.resolve(), args.independent_asset.resolve() if args.independent_asset else None)
