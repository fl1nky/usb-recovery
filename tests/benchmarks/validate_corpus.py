"""Validate external ground truth without importing recovery implementation."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular_file(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("Corpus path is outside corpus or not a regular file")
    return path


def validate(root):
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8-sig"))
    assets = {}
    for record in manifest["assets"]:
        data = regular_file(root, record["path"]).read_bytes()
        if len(data) != record["bytes"] or sha(data) != record["sha256"]:
            raise ValueError("Original asset differs from manifest")
        if record["name"] in assets:
            raise ValueError("Duplicate original asset")
        assets[record["name"]] = data
    names = set()
    for case in manifest["cases"]:
        if case["name"] in names:
            raise ValueError("Duplicate corpus case")
        names.add(case["name"])
        image = regular_file(root, case["image"]).read_bytes()
        if len(image) != case["bytes"] or sha(image) != case["sha256"]:
            raise ValueError("Corpus image differs from manifest")
        physical_ranges = []
        for expected in case["expected"]:
            original = assets[expected["asset"]]
            rebuilt = bytearray()
            for extent in sorted(expected["extents"], key=lambda item: item["logical_offset"]):
                logical, physical, size = (extent[key] for key in ("logical_offset", "image_offset", "length"))
                if logical != len(rebuilt) or min(logical, physical) < 0 or size <= 0 or physical + size > len(image):
                    raise ValueError("Gap, overlap or out-of-bounds ground truth extent")
                physical_ranges.append((physical, physical + size))
                rebuilt.extend(image[physical:physical + size])
            if len(rebuilt) != len(original):
                raise ValueError("Ground truth extent coverage differs from original length")
            if (bytes(rebuilt) == original) != expected["all_original_bytes_present"]:
                raise ValueError("Ground truth survival flag contradicts image bytes")
        ordered = sorted(physical_ranges)
        if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
            raise ValueError("Ground truth physical extents overlap")
    return {"cases": len(names), "assets": len(assets), "manifest_sha256": sha((root / "manifest.json").read_bytes()),
            "validation": "all hashes, extent bounds/non-overlap and survival flags verified"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.corpus.resolve())))
