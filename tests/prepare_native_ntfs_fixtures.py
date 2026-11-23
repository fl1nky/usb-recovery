# SPDX-License-Identifier: AGPL-3.0-or-later
"""Restore one public, hash-pinned NTFS sample and create authored derivatives.

No local disks or user profiles are searched. The full upstream sample remains
the 2304-record control; the smaller derivative tests integration transitions.
Install scripts/native-ntfs-test-requirements.txt for the independent parser.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).absolute().parents[1]
COMMIT = "83f71a87e173613580eb31f64c600789f4259c20"
URL = f"https://media.githubusercontent.com/media/fox-it/dissect.ntfs/{COMMIT}/tests/_data/ntfs.bin.gz"
PACKED_SHA = "cc1b5c665a80befed008b3db817325aac1555e1efe511de63203f421c2250080"
RAW_SHA = "3cf887ae87b7f44f1faee71838b3d79b811097a0a1a4962e8e0fd132bc8dfbc7"
PACKED_BYTES, RAW_BYTES = 908628, 10420736


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--packed", type=Path, help="Use an existing verified gzip instead of downloading")
    parser.add_argument("--dependency-directory", type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination.exists() or not destination.is_relative_to((ROOT / ".build").resolve()):
        raise ValueError("A fresh fixture directory under project .build is required")
    destination.mkdir(parents=True)
    packed = args.packed.resolve() if args.packed else destination / "ntfs.bin.gz"
    if not args.packed:
        pending = packed.with_name(packed.name + ".partial")
        count = 0
        with urllib.request.urlopen(URL, timeout=60) as source, pending.open("xb") as output:
            if not source.geturl().startswith("https://"):
                raise ValueError("HTTPS redirect required")
            while block := source.read(1024**2):
                count += len(block)
                if count > PACKED_BYTES:
                    raise ValueError("NTFS fixture download size exceeded")
                output.write(block)
        if count != PACKED_BYTES or sha(pending) != PACKED_SHA:
            raise ValueError("Pinned NTFS gzip hash mismatch")
        pending.rename(packed)
    if packed.stat().st_size != PACKED_BYTES or sha(packed) != PACKED_SHA:
        raise ValueError("Existing NTFS gzip differs from public sample")
    raw = destination / "ntfs.bin"
    pending = raw.with_name(raw.name + ".partial")
    count = 0
    with gzip.open(packed, "rb") as source, pending.open("xb") as output:
        while block := source.read(1024**2):
            count += len(block)
            if count > RAW_BYTES:
                raise ValueError("NTFS fixture decompression size exceeded")
            output.write(block)
    if count != RAW_BYTES or sha(pending) != RAW_SHA:
        raise ValueError("Pinned decompressed NTFS image mismatch")
    pending.rename(raw)
    command = [sys.executable, str(ROOT / "tests/build_native_ntfs_checkpoint_fixture.py"), str(raw), str(destination / "derived")]
    if args.dependency_directory:
        command.extend(["--dependency-directory", str(args.dependency_directory.resolve())])
    subprocess.run(command, check=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    receipt = dict(status="prepared_public_ntfs_sample_and_authored_derivatives", origin=URL, commit=COMMIT,
                   upstream_license="AGPL-3.0; fox-it/dissect.ntfs", packed_sha256=PACKED_SHA, image_sha256=RAW_SHA,
                   raw_bytes=RAW_BYTES, full_fixture_mft_records=2304, integration_fixture_mft_records=64,
                   authored_deletion_not_os_deletion=True, real_devices_tested=False)
    (destination / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
