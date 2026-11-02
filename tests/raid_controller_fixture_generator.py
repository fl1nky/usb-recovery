"""Offline extractor for pinned native DDF and rejected prototype fixtures.

Native images originate in fox-it/dissect.volume and are preserved byte-for-byte.
The old local IMSM/DDF/MSFT layouts are negative controls, not format examples.
This module never generates supposedly native controller metadata.
"""
from __future__ import annotations
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys


def extract_fixtures(src_dir: str, dest_dir: str) -> None:
    source, destination = Path(src_dir), Path(dest_dir)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8-sig"))
    destination.mkdir(parents=True, exist_ok=True)
    for case in manifest["cases"]:
        name = case["name"]
        if Path(name).name != name or not name.endswith(".dd.gz"):
            raise ValueError("Unsafe fixture name")
        packed = (source / name).read_bytes()
        if case.get("gzip_sha256") and hashlib.sha256(packed).hexdigest() != case["gzip_sha256"]:
            raise ValueError(f"Compressed fixture checksum mismatch: {name}")
        with gzip.open(source / name, "rb") as handle:
            data = handle.read(case["bytes"] + 1)
        if len(data) != case["bytes"] or hashlib.sha256(data).hexdigest() != case["sha256"]:
            raise ValueError(f"Raw fixture checksum mismatch: {name}")
        (destination / name.removesuffix(".gz")).write_bytes(data)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Extracted {len(manifest['cases'])} pinned fixtures; native DDF and rejected prototypes")


def verify_oracles(src_dir: str) -> None:
    """Recheck fixed expectations through the independent external decoder."""
    from dissect.volume.ddf.ddf import DDF

    source = Path(src_dir)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8-sig"))
    for oracle in manifest["arrays"]:
        cases = [c for c in manifest["cases"] if c["kind"] == "native_upstream" and c["level"] == oracle["level"]]
        images = [gzip.decompress((source / c["name"]).read_bytes()) for c in cases]
        for case, data in zip(cases, images, strict=True):
            if len(data) != case["bytes"] or hashlib.sha256(data).hexdigest() != case["sha256"]:
                raise ValueError("Source fixture mismatch")
        volume = DDF([io.BytesIO(data) for data in images]).configurations[0].virtual_disks[0]
        if volume.size != oracle["logical_bytes"]:
            raise ValueError("Independent size differs")
        stream, digest, remaining = volume.open(), hashlib.sha256(), volume.size
        step = min(volume.stripe_size, volume.size)
        # dissect.volume 3.18 RAID456Stream._read over-reads multi-stripe
        # requests. One-stripe requests exercise its intended mapping exactly.
        while remaining:
            data = stream.read(min(step, remaining))
            if not data or len(data) > min(step, remaining):
                raise ValueError("Independent decoder length mismatch")
            digest.update(data)
            remaining -= len(data)
        if digest.hexdigest() != oracle["logical_sha256"]:
            raise ValueError("Independent payload hash differs")
        stream.seek(0)
        for number in range(1, (3072 if oracle["level"] == 0 else 512) + 1):
            if stream.read(4096) != number.to_bytes(2, "little") * 2048:
                raise ValueError("Upstream numbered payload differs")
        print(f"PASS independent DDF{oracle['level']} oracle: {digest.hexdigest()}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-oracles":
        verify_oracles(sys.argv[2])
        raise SystemExit(0)
    if len(sys.argv) != 4 or sys.argv[1] != "--extract":
        raise SystemExit("Usage: raid_controller_fixture_generator.py --extract SOURCE DESTINATION")
    extract_fixtures(sys.argv[2], sys.argv[3])
