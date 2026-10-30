"""Independent owned libx265/FFmpeg HEVC samples, never recovery-code output."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    return subprocess.run([str(item) for item in command], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=90)


def hex_dump(text):
    value = bytearray()
    for line in text.splitlines():
        if ":" not in line:
            continue
        value.extend(bytes.fromhex(line.partition(":")[2].split("  ", 1)[0].strip().replace(" ", "")))
    return bytes(value)


def build(destination, ffmpeg):
    destination = destination.resolve()
    if destination.exists():
        raise ValueError("A new fixture directory is required")
    ffmpeg = ffmpeg.resolve()
    ffprobe = ffmpeg.with_name("ffprobe.exe")
    encoders = run([ffmpeg, "-hide_banner", "-encoders"]).stdout
    if b"libx265" not in encoders:
        raise ValueError("Installed independent FFmpeg lacks libx265")
    destination.mkdir(parents=True)
    files = []
    variants = [("main-hvc1", "hvc1", "yuv420p", "160x96", "repeat-headers=0"),
                ("main10-hev1", "hev1", "yuv420p10le", "160x96", "repeat-headers=1"),
                ("two-slices-hvc1", "hvc1", "yuv420p", "256x192", "repeat-headers=0:slices=2:wpp=1"),
                ("foreign-parameters-hev1", "hev1", "yuv420p", "192x128", "repeat-headers=1"),
                ("hrd-aud-wpp-hvc1", "hvc1", "yuv420p", "320x256", "repeat-headers=0:hrd=1:vbv-maxrate=180:vbv-bufsize=360:aud=1:wpp=1"),
                ("temporal-layers-hvc1", "hvc1", "yuv420p", "320x192", "repeat-headers=0:temporal-layers=1:b-adapt=0"),
                ("tiny-hvc1", "hvc1", "yuv420p", "64x64", "repeat-headers=0")]
    for name, tag, pixels, size, extra in variants:
        folder = destination / name
        folder.mkdir()
        movie = folder / "original.mp4"
        source = ("color=c=blue:size=" if name == "tiny-hvc1" else "testsrc2=size=") + size + ":rate=6"
        command = [ffmpeg, "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i",
                   source, "-frames:v", "12", "-an", "-c:v", "libx265",
                   "-pix_fmt", pixels, "-preset", "fast", "-threads", "1", "-x265-params",
                   "log-level=error:pools=1:frame-threads=1:keyint=6:min-keyint=6:scenecut=0:bframes=2:" + extra,
                   "-tag:v", tag, "-movflags", "+faststart", str(movie)]
        run(command)
        probe = json.loads(run([ffprobe, "-v", "error", "-show_streams", "-show_packets", "-show_data", "-of", "json", movie]).stdout)
        if len(probe["streams"]) != 1 or probe["streams"][0]["codec_name"] != "hevc":
            raise ValueError("Unexpected encoded stream")
        stream = probe["streams"][0]
        config = hex_dump(stream["extradata"])
        if len(config) != stream["extradata_size"]:
            raise ValueError("FFprobe hvcC extraction length mismatch")
        (folder / "hvcc.bin").write_bytes(config)
        original = movie.read_bytes()
        packets = []
        for number, packet in enumerate(probe["packets"]):
            start, length = int(packet["pos"]), int(packet["size"])
            sample = original[start:start + length]
            if len(sample) != length or sample != hex_dump(packet["data"]):
                raise ValueError("Independent packet bytes do not match container offsets")
            path = folder / ("sample-" + str(number).zfill(3) + ".bin")
            path.write_bytes(sample)
            packets.append(dict(path=path.relative_to(destination).as_posix(), bytes=length, sha256=digest(path),
                                position=start, dts=packet.get("dts"), pts=packet.get("pts"), flags=packet.get("flags")))
        decoded = run([ffmpeg, "-v", "error", "-nostdin", "-i", movie, "-map", "0:v", "-an", "-f", "framemd5", "-"])
        frame_lines = [line for line in decoded.stdout.splitlines() if line and not line.startswith(b"#")]
        if len(frame_lines) != 12 or decoded.stderr.strip():
            raise ValueError("Independent original did not decode cleanly to all frames")
        files.append(dict(name=name, tag=tag, width=int(stream["width"]), height=int(stream["height"]),
                          pixels=pixels, original=movie.relative_to(destination).as_posix(), original_sha256=digest(movie),
                          hvcc=(folder / "hvcc.bin").relative_to(destination).as_posix(), hvcc_sha256=digest(folder / "hvcc.bin"),
                          decoded_frames=len(frame_lines), decoded_frames_sha256=hashlib.sha256(b"\n".join(frame_lines)).hexdigest(),
                          command=[str(item) for item in command[:-1]] + ["<fixture>/original.mp4"], samples=packets))
    result = dict(schema=1, scope="Owned independently encoded valid HEVC samples; not real devices or recovered-media evidence",
                  ffmpeg_sha256=digest(ffmpeg), ffprobe_sha256=digest(ffprobe),
                  ffmpeg_version=run([ffmpeg, "-version"]).stdout.decode("utf-8", errors="strict").splitlines()[0],
                  files=files)
    (destination / "manifest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"files": len(files), "samples": sum(len(item["samples"]) for item in files), "destination": str(destination)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    args = parser.parse_args()
    build(args.destination, args.ffmpeg)
