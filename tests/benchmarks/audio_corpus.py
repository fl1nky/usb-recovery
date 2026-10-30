"""Separate FFmpeg AVC/AAC corpus, including layouts that cannot be inferred.

Uses real muxer output. No recovery code or secret per-chunk markers are used.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
from media_corpus import run, sha, file_sha, boxes, bmff_chunk_boundaries, split_at, raw_image, frame_digest


def audio_digest(ffmpeg, path):
    return sha(run([ffmpeg, "-v", "error", "-nostdin", "-i", path,
                    "-map", "0:a", "-c:a", "pcm_s16le", "-f", "s16le", "-"]))


def build(output, ffmpeg):
    output.mkdir(parents=True, exist_ok=False)
    (output / "originals").mkdir()
    (output / "images").mkdir()
    assets = []
    cases = []
    for variant in ("faststart", "tailmoov"):
        name = "avc-aac-" + variant + ".mp4"
        path = output / "originals" / name
        command = [ffmpeg, "-v", "error", "-nostdin", "-y", "-f", "lavfi",
                   "-i", "testsrc2=size=160x96:rate=6", "-f", "lavfi",
                   "-i", "sine=frequency=997:sample_rate=48000", "-t", "2",
                   "-map", "0:v", "-map", "1:a", "-c:v", "libx264",
                   "-preset", "medium", "-crf", "24", "-g", "6", "-bf", "0",
                   "-c:a", "aac", "-b:a", "48k", "-ac", "2", "-map_metadata", "-1",
                   "-fflags", "+bitexact", "-flags:v", "+bitexact", "-flags:a", "+bitexact"]
        if variant == "faststart":
            command += ["-movflags", "+faststart"]
        run(command + [path])
        data = path.read_bytes()
        chunks, mdats = bmff_chunk_boundaries(data)
        top = list(boxes(data))
        assets.append({"name": name, "path": "originals/" + name, "bytes": len(data), "sha256": sha(data),
                       "decoded_frames_sha256": frame_digest(ffmpeg, path),
                       "decoded_audio_sha256": audio_digest(ffmpeg, path),
                       "chunk_offsets": chunks, "mdat_ranges": mdats,
                       "top_atoms": [{"type": k.decode("ascii"), "offset": a, "length": b - a} for k, a, b, h in top]})
        for layout in ("contiguous", "chunk-islands", "4k-islands", "all-chunks", "audio-overwrite"):
            if layout == "contiguous":
                parts = [(0, data)]
            elif layout == "4k-islands":
                parts = split_at(data, range(4096, len(data), 4096))
            elif layout == "all-chunks":
                parts = split_at(data, chunks + [x for r in mdats for x in r] + [a for k, a, b, h in top if k == b"moov"])
            else:
                # Group four adjacent muxer chunks, independent of codec type.
                # These islands preserve real audio/video interleave geometry.
                parts = split_at(data, chunks[::4])
            image, extents = raw_image(parts, 20261101 + len(cases), contiguous=layout == "contiguous")
            complete = True
            if layout == "audio-overwrite":
                probe = json.loads(run([ffmpeg.with_name("ffprobe.exe"), "-v", "error", "-show_packets",
                                        "-select_streams", "a:0", "-show_entries", "packet=pos,size", "-of", "json", path]))
                packet = probe["packets"][len(probe["packets"]) // 2]
                logical = int(packet["pos"])
                length = min(32, int(packet["size"]))
                extent = next(e for e in extents if e["logical_offset"] <= logical < e["logical_offset"] + e["length"])
                physical = extent["image_offset"] + logical - extent["logical_offset"]
                image[physical:physical + length] = b"\x00" * length
                complete = False
            image_name = "avc-aac-" + variant + "-" + layout
            image_path = output / "images" / (image_name + ".dd")
            image_path.write_bytes(image)
            cases.append({"name": image_name, "image": "images/" + image_path.name,
                          "bytes": len(image), "sha256": sha(image),
                          "expected": [{"asset": name, "all_original_bytes_present": complete, "extents": extents}],
                          "note": "Real muxed AVC/AAC. No map in image. All-chunks/4K layouts are deliberately difficult; do not assume their geometry is recoverable."})
    manifest = {"schema": 1, "seed": 20261101, "scope": "Synthetic real-muxer AVC/AAC regular images, no device access",
                "generator_sha256": file_sha(Path(__file__)), "support_generator_sha256": file_sha(Path(__file__).with_name("media_corpus.py")),
                "ffmpeg_sha256": file_sha(ffmpeg), "ffmpeg_version": run([ffmpeg, "-version"]).decode().splitlines()[0],
                "assets": assets, "cases": cases}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"manifest": str(output / "manifest.json"), "cases": len(cases), "assets": len(assets)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    args = parser.parse_args()
    build(args.destination.resolve(), args.ffmpeg.resolve())
