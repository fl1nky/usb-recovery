"""Adapt independent HEVC fixtures to the public pipeline benchmark schema.

Only benchmark ground truth uses the supplied extent map. The production
scanner receives the raw image and no reference metadata.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(source, destination):
    if destination.exists():
        raise FileExistsError("Preserve existing corpus")
    manifest_path = source / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    (destination / "images").mkdir(parents=True)
    (destination / "originals").mkdir()
    assets, cases = [], []
    for row in manifest["Cases"]:
        image, original = source / row["Image"], source / row["Original"]
        if sha(image) != row["ImageSha256"] or sha(original) != row["Sha256"]:
            raise ValueError("Independent fixture changed")
        image_relative, original_relative = "images/" + image.name, "originals/" + original.name
        shutil.copyfile(image, destination / image_relative)
        shutil.copyfile(original, destination / original_relative)
        assets.append(dict(name=original.name, path=original_relative, bytes=original.stat().st_size,
                           sha256=row["Sha256"], decoded_frames_sha256=row["DecodedSha256"]))
        data, rebuilt = image.read_bytes(), bytearray()
        extents = []
        for extent in sorted(row["Extents"], key=lambda value: value["LogicalOffset"]):
            logical, physical, length = (extent[key] for key in ("LogicalOffset", "ImageOffset", "Length"))
            if logical != len(rebuilt) or physical < 0 or length <= 0 or physical + length > len(data):
                raise ValueError("Ground truth coverage/bounds invalid")
            rebuilt.extend(data[physical:physical + length])
            extents.append(dict(logical_offset=logical, image_offset=physical, length=length))
        if len(rebuilt) != original.stat().st_size:
            raise ValueError("Ground truth length invalid")
        cases.append(dict(name=row["Name"], image=image_relative, bytes=len(data), sha256=row["ImageSha256"],
                          expected=[dict(asset=original.name, all_original_bytes_present=bytes(rebuilt) == original.read_bytes(), extents=extents)],
                          engine_expected_candidates=row["Expected"], engine_expected_exact=row["Exact"],
                          note=row["Scope"] + "; candidate counts refer to strict media assembly; other pipeline methods may emit unrelated/nonmatching candidates."))
    output = dict(schema=1, scope="Ten independent real-FFmpeg/libx265 HEVC owned regular images; adapted solely for public RecoveryPipeline benchmark and external scoring.",
                  source_manifest_sha256=sha(manifest_path), adapter_sha256=sha(Path(__file__)), ffmpeg_sha256=manifest["FfmpegSha256"], assets=assets, cases=cases)
    (destination / "manifest.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({"corpus": str(destination), "cases": len(cases), "manifest_sha256": sha(destination / "manifest.json")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.source.resolve(), args.destination.resolve())
