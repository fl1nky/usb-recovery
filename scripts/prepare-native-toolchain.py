# SPDX-License-Identifier: AGPL-3.0-or-later
"""Restore SHA512-pinned Cygwin build inputs in a fresh local directory.

Build/development tool only: Python 3.14+ is needed for compression.zstd.
Does not run installers, postinstall scripts, compilers, or registry changes.
The end-user recovery runtime uses the compiled tools, not this script.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import tarfile
import urllib.request

PROJECT = Path(__file__).absolute().parents[1]
MIRROR = "https://mirrors.kernel.org/sourceware/cygwin/"


def digest(path: Path, algorithm: str = "sha256") -> str:
    result = hashlib.new(algorithm)
    with path.open("rb") as source:
        while block := source.read(1024**2):
            result.update(block)
    return result.hexdigest()


def relative(name: str) -> PurePosixPath:
    parts = PurePosixPath(name)
    if (parts.is_absolute() or "\\" in name or ":" in name
            or any(part in ("", ".", "..") for part in parts.parts)):
        raise ValueError("Unsafe package path")
    return parts


def restore(row: dict, cache: Path, offline: bool) -> Path:
    name = relative(row["path"])
    if (not str(name).startswith(("x86_64/release/", "noarch/release/", "src/release/"))
            or not re.fullmatch("[a-f0-9]{128}", row["sha512"])
            or type(row["bytes"]) is not int or not 0 < row["bytes"] < 256 * 1024**2):
        raise ValueError("Invalid pinned package")
    target = cache / name
    if target.exists():
        if target.stat().st_size != row["bytes"] or digest(target, "sha512") != row["sha512"]:
            raise ValueError("Cached package changed: " + target.name)
        return target
    if offline:
        raise FileNotFoundError("Missing pinned archive: " + target.name)
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = target.with_name(target.name + ".partial")
    count, checksum = 0, hashlib.sha512()
    with urllib.request.urlopen(MIRROR + name.as_posix(), timeout=60) as source, pending.open("xb") as output:
        if not source.geturl().startswith("https://"):
            raise ValueError("HTTPS redirect required")
        while block := source.read(1024**2):
            count += len(block)
            if count > row["bytes"]:
                raise ValueError("Package size exceeded")
            output.write(block)
            checksum.update(block)
    if count != row["bytes"] or checksum.hexdigest() != row["sha512"]:
        raise ValueError("Downloaded package hash mismatch")
    pending.rename(target)
    return target


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--archive-cache", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--runtime-sources", action="store_true", help="Also restore the redistributable runtime's matching source archives")
    args = parser.parse_args()
    from compression import zstd

    destination, cache = args.destination.resolve(), args.archive_cache.resolve()
    if destination.exists() or not destination.is_relative_to((PROJECT / ".build").resolve()):
        raise ValueError("A fresh toolchain directory under project .build is required")
    lock_path = PROJECT / "scripts/native-recovery-packages.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock["packages"]
    if lock["schema"] != 1 or not 1 <= len(packages) <= 100:
        raise ValueError("Invalid package lock")
    rows = list(packages.values()) + (list(lock["runtime_sources"].values()) if args.runtime_sources else [])
    if sum(row["bytes"] for row in rows) > 512 * 1024**2:
        raise ValueError("Package download limit exceeded")
    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(lambda row: restore(row, cache, args.offline), rows))
    destination.mkdir(parents=True)
    files, links, skipped = {}, [], []
    total = 0

    def target(name):
        parts = relative(name).parts
        # Cygwin mounts /usr/bin and /usr/lib onto /bin and /lib.
        if len(parts) >= 2 and parts[:2] in (("usr", "bin"), ("usr", "lib")):
            parts = parts[1:]
        out = destination.joinpath(*parts).resolve()
        if not out.is_relative_to(destination):
            raise ValueError("Package extraction escaped destination")
        return out

    for package, row in sorted(packages.items()):
        archive = cache / row["path"]
        stream = zstd.open(archive, "rb") if archive.name.endswith(".zst") else archive.open("rb")
        with stream, tarfile.open(fileobj=stream, mode="r|*") as source:
            for member in source:
                if member.name in (".", "./"):
                    continue
                if ":" in member.name and member.name.startswith("usr/share/man/"):
                    skipped.append(dict(path=member.name, reason="Cygwin-encoded manual filename; not a build/runtime file"))
                    continue
                out = target(member.name)
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                elif member.issym() or member.islnk():
                    name = member.linkname
                    if member.issym():
                        name = posixpath.normpath(name.lstrip("/") if name.startswith("/") else posixpath.join(posixpath.dirname(member.name), name))
                    links.append((member.name, out, target(name), package))
                elif member.isfile():
                    if not 0 <= member.size <= 128 * 1024**2 or total > 2 * 1024**3 - member.size:
                        raise ValueError("Package extraction limit exceeded")
                    total += member.size
                    data = source.extractfile(member).read(member.size + 1)
                    if len(data) != member.size:
                        raise ValueError("Short archive member")
                    checksum = hashlib.sha256(data).hexdigest()
                    out.parent.mkdir(parents=True, exist_ok=True)
                    if out.exists():
                        if not out.is_file() or digest(out) != checksum:
                            raise ValueError("Conflicting package members")
                    else:
                        with out.open("xb") as file:
                            file.write(data)
                    files[out.relative_to(destination).as_posix()] = dict(bytes=len(data), sha256=checksum, package=package)
                else:
                    skipped.append(dict(path=member.name, reason="Special file; no postinstall is executed"))
    while links:
        remaining, progress = [], False
        for original, out, source, package in links:
            if source.is_file():
                out.parent.mkdir(parents=True, exist_ok=True)
                checksum = digest(source)
                if out.exists():
                    if not out.is_file() or digest(out) != checksum:
                        raise ValueError("Conflicting package alias")
                else:
                    shutil.copyfile(source, out)
                files[out.relative_to(destination).as_posix()] = dict(bytes=source.stat().st_size, sha256=checksum, package=package, alias=original)
                progress = True
            else:
                remaining.append((original, out, source, package))
        if not progress:
            skipped.extend(dict(path=name, reason="Absent or directory alias; no postinstall") for name, _, _, _ in remaining)
            break
        links = remaining
    for name in ("bash.exe", "gcc.exe", "make.exe", "cygwin1.dll"):
        if not (destination / "bin" / name).is_file():
            raise ValueError("Missing required compiler/runtime file")
    (destination / "tmp").mkdir(exist_ok=True)
    receipt = dict(schema=1, status="restored_verified_build_toolchain", files=files, skipped=skipped,
                   package_lock_sha256=digest(lock_path), packages=len(packages), extracted_bytes=total,
                   runtime_sources_restored=args.runtime_sources, executables_run=False, system_installation=False)
    (destination / "toolchain-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(dict(status=receipt["status"], packages=len(packages), files=len(files), bytes=total)))


if __name__ == "__main__":
    main()
