"""Create independent AAC-LC raw access units using real FFmpeg/ffprobe only.

No recovery code, device access, downloaded media or application data is used.
The destination must be new. Only synthetic audio and small raw packets remain.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args):
    result = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace")[-2000:])
    return result.stdout


def build(destination, ffmpeg):
    destination.mkdir(parents=True, exist_ok=False)
    ffprobe = ffmpeg.with_name("ffprobe.exe")
    manifest = {"schema": 1, "scope": "Synthetic audio, real FFmpeg AAC-LC packets. No recovery implementation used to create references.",
                "ffmpeg_sha256": sha(ffmpeg.read_bytes()), "ffprobe_sha256": sha(ffprobe.read_bytes()),
                "generator_sha256": sha(Path(__file__).read_bytes()), "ffmpeg_version": run([ffmpeg, "-version"]).decode().splitlines()[0], "cases": []}
    rates = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350]
    for frequency, rate in enumerate(rates):
        for channels in (1, 2):
            name = "aac-lc-%d-%dch" % (rate, channels)
            container = destination / (name + ".m4a")
            # Noise and a loud/quiet envelope exercise different band/window
            # patterns. The reference remains the actual encoder's own output.
            source = "anoisesrc=color=white:amplitude=0.3:seed=74291:sample_rate=%d:duration=0.18" % rate
            run([ffmpeg, "-v", "error", "-nostdin", "-y", "-f", "lavfi", "-i", source,
                 "-af", "volume=if(lt(t\\,0.07)\\,0.01\\,1):eval=frame", "-ac", channels,
                 "-c:a", "aac", "-profile:a", "aac_low", "-b:a", min(96000, rate * channels * 2),
                 "-map_metadata", "-1", "-fflags", "+bitexact", "-flags:a", "+bitexact", container])
            info = json.loads(run([ffprobe, "-v", "error", "-select_streams", "a:0", "-show_streams", "-show_packets",
                                   "-show_entries", "stream=codec_name,profile,sample_rate,channels:packet=pos,size", "-of", "json", container]))
            stream = info["streams"][0]
            if stream["codec_name"] != "aac" or stream["profile"] != "LC" or int(stream["sample_rate"]) != rate or stream["channels"] != channels:
                raise ValueError("Encoder changed requested AAC-LC format")
            data = container.read_bytes()
            for index, packet in enumerate(info["packets"]):
                start, size = int(packet["pos"]), int(packet["size"])
                raw = data[start:start + size]
                target = destination / (name + "-%03d.rawaac" % index)
                target.write_bytes(raw)
                manifest["cases"].append({"path": target.name, "bytes": len(raw), "sha256": sha(raw), "channels": channels, "frequency_index": frequency})
            container.unlink()
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (destination / "PROVENANCE.txt").write_text("Synthetic audio packets generated for USB-Recovery using FFmpeg. No personal data, third-party authored media or program binaries are embedded. This file does not define a separate license.\n", encoding="utf-8")
    print(json.dumps({"destination": str(destination.resolve()), "packets": len(manifest["cases"]), "bytes": sum(p.stat().st_size for p in destination.iterdir())}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    args = parser.parse_args()
    build(args.destination.resolve(), args.ffmpeg.resolve())
