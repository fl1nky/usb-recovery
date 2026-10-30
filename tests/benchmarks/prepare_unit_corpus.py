"""Adapt owned allocation-unit fixtures for public RecoveryPipeline scoring.

Reference extents and originals are benchmark ground truth only. Production
receives the raw image path and its independent checksum, never those maps.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(source, destination):
    if destination.exists():
        raise FileExistsError("Preserve existing benchmark corpus")
    manifest_path = source / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    (destination / "originals").mkdir(parents=True)
    (destination / "images").mkdir()
    assets, by_hash = [], {}
    for row in manifest["assets"]:
        path = source / row["path"]
        if digest(path) != row["sha256"]:
            raise ValueError("Independent original changed")
        relative = "originals/" + path.name
        shutil.copyfile(path, destination / relative)
        asset = dict(name=row["name"], path=relative, bytes=row["bytes"], sha256=row["sha256"],
                     decoded_frames_sha256=row["frames"], decoded_audio_sha256=row["pcm"])
        assets.append(asset)
        by_hash[row["sha256"]] = asset
    cases = []
    for row in manifest["cases"]:
        image = source / row["image"]
        if digest(image) != row["sha256"]:
            raise ValueError("Independent image changed")
        relative = "images/" + image.name
        shutil.copyfile(image, destination / relative)
        original = by_hash[row["original_sha256"]]
        data = image.read_bytes()
        rebuilt = bytearray()
        for extent in sorted(row["truth_extents"], key=lambda value: value["logical_offset"]):
            logical, at, length = (extent[key] for key in ("logical_offset", "image_offset", "length"))
            if logical != len(rebuilt) or at < 0 or length <= 0 or at + length > len(data):
                raise ValueError("Ground truth source map invalid")
            rebuilt.extend(data[at:at + length])
        if (hashlib.sha256(rebuilt).hexdigest() == original["sha256"]) != row["all_original_bytes_present"]:
            raise ValueError("Ground truth survival flag is inconsistent")
        cases.append(dict(name=row["name"], image=relative, bytes=row["bytes"], sha256=row["sha256"],
                          expected=[dict(asset=original["name"], all_original_bytes_present=row["all_original_bytes_present"], extents=row["truth_extents"])],
                          engine_expected_candidates=row["expected"], engine_expected_current_sha256=row["expected_output_sha256"],
                          note="Owned real-muxer input; exact-original scoring is separate from intentionally changed current structural candidates. "
                               "Strict media-stage expectation does not prescribe results of other selected pipeline methods."))
    document = dict(schema=1, source_manifest_sha256=digest(manifest_path), adapter_sha256=digest(Path(__file__)),
                    ffmpeg_sha256=manifest["ffmpeg_sha256"], scope="Seventeen owned real-FFmpeg allocation-unit regular images; public Pipeline benchmark, original-byte and complete-frame/PCM scoring. No devices.",
                    assets=assets, cases=cases)
    (destination / "manifest.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(json.dumps({"corpus": str(destination), "cases": len(cases), "manifest_sha256": digest(destination / "manifest.json")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.source.resolve(), args.destination.resolve())
