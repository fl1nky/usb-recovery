"""Real FFmpeg AVC/AAC references; independently scatter whole container atoms.

This is a useful supported geometry control, not evidence that isolated raw AAC
chunks can be identified. The separate benchmark/audio_corpus deliberately tests
harder interleaved islands and arbitrary 4 KiB physical cuts as well.
"""
from pathlib import Path
import hashlib
import json
import random
import struct
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(args):
    process = subprocess.run([str(x) for x in args], capture_output=True, timeout=60)
    if process.returncode:
        raise RuntimeError(process.stderr.decode("utf-8", "replace")[-2000:])
    return process.stdout


def atoms(raw):
    result, at = [], 0
    while at < len(raw):
        size, kind = struct.unpack_from(">I4s", raw, at)
        if size == 1:
            size = struct.unpack_from(">Q", raw, at + 8)[0]
        assert 8 <= size <= len(raw) - at
        result.append((at, raw[at:at + size], kind.decode("ascii")))
        at += size
    return result


def decoded(ffmpeg, path, audio):
    common = [ffmpeg, "-hide_banner", "-v", "error", "-xerror", "-protocol_whitelist", "file,pipe", "-i", path]
    if audio:
        return sha(run([*common, "-map", "0:a:0", "-c:a", "pcm_s16le", "-f", "s16le", "-"]))
    result = run([*common, "-map", "0:v:0", "-f", "framemd5", "-"])
    return sha(b"\n".join(row for row in result.splitlines() if not row.startswith(b"#")))


def main(output, ffmpeg):
    output.mkdir(parents=True, exist_ok=True)
    ffprobe = ffmpeg.with_name("ffprobe.exe")
    cases = []
    for fast in (False, True):
        label = "fast" if fast else "tail"
        original = output / ("phone-" + label + ".mp4")
        command = [ffmpeg, "-hide_banner", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=96x64:rate=6:duration=2",
                   "-f", "lavfi", "-i", "sine=frequency=880:sample_rate=48000:duration=2", "-map", "0:v:0", "-map", "1:a:0",
                   "-c:v", "libx264", "-preset", "ultrafast", "-g", "6", "-c:a", "aac", "-b:a", "64k", "-shortest"]
        if fast:
            command += ["-movflags", "+faststart"]
        run([*command, original])
        raw = original.read_bytes()
        video_hash, audio_hash = decoded(ffmpeg, original, False), decoded(ffmpeg, original, True)
        packets = json.loads(run([ffprobe, "-v", "error", "-select_streams", "a:0", "-show_packets", "-show_entries", "packet=pos,size", "-of", "json", original]))["packets"]
        packet = packets[len(packets) // 2]
        packet_at, packet_size = int(packet["pos"]), int(packet["size"])
        assert packet_size > 24
        sections = atoms(raw)
        for mode, expected, exact in (("scattered-boxes", 1, True), ("contiguous", 0, True),
                                      ("audio-payload-unknown", 1, False), ("audio-boundary-damaged", 0, False),
                                      ("detached-audio", 0, False)):
            name = "aac-" + label + "-" + mode
            image = bytearray(b"\xa5" * (2 * 1024 * 1024))
            extents = []
            source_sections = [(0, raw, "all")] if mode == "contiguous" else sections
            positions = random.Random(941).sample(range(2, 12), len(source_sections))
            damaged_at = None
            for index, (logical, payload, kind) in enumerate(source_sections):
                physical = positions[index] * 131072
                image[physical:physical + len(payload)] = payload
                extents.append(dict(ImageOffset=physical, LogicalOffset=logical, Length=len(payload), Kind=kind))
                if logical <= packet_at < logical + len(payload):
                    damaged_at = physical + packet_at - logical
            assert damaged_at is not None
            if mode == "audio-payload-unknown":
                image[damaged_at + 8:damaged_at + 20] = bytes(12)
            elif mode == "audio-boundary-damaged":
                image[damaged_at + packet_size - 2:damaged_at + packet_size] = bytes(2)
            elif mode == "detached-audio":
                image[1800000:1800000 + packet_size] = image[damaged_at:damaged_at + packet_size]
                image[damaged_at:damaged_at + packet_size] = bytes(packet_size)
            source = name + ".dd"
            (output / source).write_bytes(image)
            cases.append(dict(Name=name, Image=source, Original=original.name, Sha256=sha(raw), Bytes=len(raw),
                              Expected=expected, Exact=exact, VideoDecodedSha256=video_hash, AudioDecodedSha256=audio_hash,
                              Extents=extents))
    manifest = dict(Schema=1, Scope="Real AVC/AAC, intact mdat body; container atoms moved independently. No general isolated AAC reconstruction claim.",
                    FfmpegSha256=sha(ffmpeg.read_bytes()), FfmpegVersion=run([ffmpeg, "-version"]).splitlines()[0].decode("ascii", "replace"), Cases=cases)
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Real AVC/AAC geometry fixtures:", len(cases))


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
