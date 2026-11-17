# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build the read-only NTFS worker from pinned archives in an isolated workspace.

Requires a toolchain restored by prepare-native-toolchain.py, both upstream
source archives, and the matching Cygwin runtime sources in --archive-cache.
Never executes the upstream TestDisk executable or requests administrator rights.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import tarfile

PROJECT = Path(__file__).absolute().parents[1]
SOURCES = {
    "testdisk": ("f8343be20cb4001c5d91a2e3bcd918398f00ae6d8310894a5a9f2feb813c283f", "testdisk-7.2"),
    "ntfs": ("350d9415c59f7c3fa74e23985ad2d56423c6a168337368f672e2e362d8f295c8", "ntfs-3g-2026.9.28"),
}
DLLS = ("cygwin1.dll", "cygz.dll", "cygiconv-2.dll", "cygcharset-1.dll")


def digest(path: Path, algorithm="sha256") -> str:
    result = hashlib.new(algorithm)
    with path.open("rb") as source:
        while block := source.read(1024**2):
            result.update(block)
    return result.hexdigest()


def safe(root: Path, name: str) -> Path:
    parts = PurePosixPath(name)
    if parts.is_absolute() or "\\" in name or ":" in name or any(p in ("", ".", "..") for p in parts.parts):
        raise ValueError("Unsafe build input path")
    result = (root / parts).resolve()
    if not result.is_relative_to(root.resolve()):
        raise ValueError("Build input escaped root")
    return result


def extract(archive: Path, destination: Path, expected: str) -> None:
    if digest(archive) != expected:
        raise ValueError("Upstream source archive SHA256 mismatch")
    destination.mkdir()
    count = total = 0
    with tarfile.open(archive) as source:
        for member in source:
            if member.isdir():
                continue
            if not member.isfile() or member.size > 64 * 1024**2:
                raise ValueError("Unexpected source archive member")
            count += 1
            total += member.size
            if count > 10000 or total > 128 * 1024**2:
                raise ValueError("Source archive extraction limit")
            path = safe(destination, member.name)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = source.extractfile(member).read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("Short source archive member")
            with path.open("xb") as output:
                output.write(data)
            # Preserve generated configure/Makefile timestamps. No autoreconf
            # or third-party postinstall is needed for the pinned release.
            os.utime(path, (member.mtime, member.mtime))


def apply_patch(root: Path, patch: Path) -> None:
    """Strict unified patch: exact context only, no fuzzy or offset matching."""
    lines = patch.read_text(encoding="utf-8").splitlines(keepends=True)
    if len(lines) < 3 or not lines[0].startswith("--- a/") or not lines[1].startswith("+++ b/"):
        raise ValueError("Unsupported patch header")
    name = lines[1][6:].strip()
    if lines[0][6:].strip() != name:
        raise ValueError("Patch rename is not supported")
    path = safe(root, name)
    original = path.read_text(encoding="utf-8").splitlines(keepends=True)
    output, cursor, at = [], 0, 2
    while at < len(lines):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?", lines[at])
        if not match:
            raise ValueError("Unsupported patch hunk")
        start, old_count, new_count = int(match[1]) - 1, int(match[2] or 1), int(match[4] or 1)
        if not cursor <= start <= len(original):
            raise ValueError("Patch hunk order invalid")
        output.extend(original[cursor:start])
        cursor, removed, added, at = start, 0, 0, at + 1
        while at < len(lines) and not lines[at].startswith("@@ "):
            line = lines[at]
            if not line or line[0] not in " +-":
                raise ValueError("Unsupported patch line")
            if line[0] in " -":
                if cursor >= len(original) or original[cursor] != line[1:]:
                    raise ValueError("Patch context differs from pinned source")
                cursor += 1
                removed += 1
            if line[0] in " +":
                output.append(line[1:])
                added += 1
            at += 1
        if removed != old_count or added != new_count:
            raise ValueError("Patch hunk length mismatch")
    output.extend(original[cursor:])
    path.write_text("".join(output), encoding="utf-8", newline="\n")


def unix(path: Path) -> str:
    text = path.resolve().as_posix()
    if len(text) < 3 or text[1:3] != ":/" or not text[0].isalpha():
        raise ValueError("A local Windows drive path is required")
    return "/cygdrive/" + text[0].lower() + text[2:]


def command(parts) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def source_notice(archive: Path, suffix: str) -> bytes:
    """Read one notice from a verified Cygwin source package's upstream tar."""
    from compression import zstd
    stream = zstd.open(archive, "rb") if archive.name.endswith(".zst") else archive.open("rb")
    with stream, tarfile.open(fileobj=stream, mode="r|*") as package:
        for member in package:
            if not member.isfile() or not member.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
                continue
            if member.size > 64 * 1024**2:
                raise ValueError("Runtime source member limit")
            data = package.extractfile(member).read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("Short runtime source member")
            with tarfile.open(fileobj=io.BytesIO(data)) as upstream:
                matches = sorted((row for row in upstream if row.isfile() and row.name.endswith(suffix)), key=lambda row: len(row.name))
                if matches:
                    if matches[0].size > 1024**2:
                        raise ValueError("Runtime notice limit")
                    return upstream.extractfile(matches[0]).read()
    raise ValueError("Expected notice missing from pinned runtime sources")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--archive-cache", type=Path, required=True)
    parser.add_argument("--testdisk-archive", type=Path, required=True)
    parser.add_argument("--ntfs-archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    destination, toolchain, cache = args.destination.resolve(), args.toolchain.resolve(), args.archive_cache.resolve()
    if (os.name != "nt" or destination.exists() or not destination.is_relative_to((PROJECT / ".build").resolve())
            or not 1 <= args.jobs <= 16):
        raise ValueError("A fresh Windows build directory under project .build is required")
    lock_path = PROJECT / "scripts/native-recovery-packages.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    inventory_path = toolchain / "toolchain-receipt.json"
    if inventory_path.stat().st_size > 4 * 1024**2:
        raise ValueError("Toolchain inventory limit")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    if inventory.get("schema") != 1 or inventory.get("package_lock_sha256") != digest(lock_path) or not 1 <= len(inventory["files"]) <= 20000:
        raise ValueError("Toolchain lock mismatch")
    for name, row in inventory["files"].items():
        file = safe(toolchain, name)
        if file.stat().st_size != row["bytes"] or digest(file) != row["sha256"]:
            raise ValueError("Toolchain file changed: " + name)
    runtime_sources = []
    for row in lock["runtime_sources"].values():
        path = safe(cache, row["path"])
        if path.stat().st_size != row["bytes"] or digest(path, "sha512") != row["sha512"]:
            raise ValueError("Matching runtime source archive missing or changed")
        runtime_sources.append(path)
    destination.mkdir(parents=True)
    for name, archive in (("testdisk", args.testdisk_archive), ("ntfs", args.ntfs_archive)):
        extract(archive, destination / name, SOURCES[name][0])
    td, ntfs = destination / "testdisk" / SOURCES["testdisk"][1], destination / "ntfs" / SOURCES["ntfs"][1]
    patches = PROJECT / "src/Recovery.Native/Patches"
    apply_patch(td, patches / "testdisk-7.2-compat.patch")
    apply_patch(td, patches / "testdisk-7.2-ntfs-record-validation.patch")
    apply_patch(ntfs, patches / "ntfs3g-2026.9.28-gcc-packing.patch")
    runtime = destination / "runtime"
    runtime.mkdir()
    logs = destination / "logs"
    logs.mkdir()
    environment = os.environ.copy()
    for name in ("BASH_ENV", "ENV", "CONFIG_SITE", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "LIBS"):
        environment.pop(name, None)
    flags = "-O2 -g0 -ffile-prefix-map=" + unix(destination) + "=/usb-recovery/native-build"

    def run(label, cwd, statements):
        script = destination / (label + ".sh")
        script.write_text("set -eu\nPATH=/usr/bin:/bin\nexport PATH\ncd " + shlex.quote(unix(cwd)) + "\n" + "\n".join(statements) + "\n", encoding="utf-8", newline="\n")
        with (logs / (label + ".log")).open("wb") as log:
            result = subprocess.run([str(toolchain / "bin/bash.exe"), "--noprofile", "--norc", unix(script)], env=environment, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError("Native build failed at " + label + "; original log preserved")

    run("01-ntfs-library", ntfs, [command(["/bin/sh", "./configure", "--disable-ntfs-3g", "--disable-ntfsprogs",
        "--disable-device-default-io-ops", "--disable-crypto", "--disable-nfconv", "--disable-shared", "--enable-static",
        "CC=gcc -std=gnu23", "CFLAGS=" + flags]), command(["make", "-j" + str(args.jobs), "-C", "libntfs-3g"])])
    run("02-testdisk-objects", td, [command(["/bin/sh", "./configure", "--without-ncurses", "--without-ewf", "--without-ext2fs",
        "--without-reiserfs", "--disable-qt", "--with-ntfs3g-lib=" + unix(ntfs / "libntfs-3g/.libs"),
        "--with-ntfs3g-includes=" + unix(ntfs / "include"), "CC=gcc -std=gnu11", "CFLAGS=" + flags]),
        command(["make", "-j" + str(args.jobs), "-C", "src", "testdisk.exe"])])
    variables = {}
    for line in re.sub(r"\\\n", " ", (td / "src/Makefile").read_text()).splitlines():
        match = re.match(r"^([A-Za-z0-9_]+)\s*=\s*(.*)$", line)
        if match:
            variables[match[1]] = match[2]

    def expand(name, seen=()):
        if name in seen or len(seen) > 50:
            raise ValueError("Invalid native object list")
        return re.sub(r"\$\(([A-Za-z0-9_]+)\)", lambda m: expand(m[1], seen + (name,)), variables[name])

    objects = list(dict.fromkeys(expand("testdisk_OBJECTS").split()))
    if not {"testdisk.o", "ntfs_udl.o", "icon_tst.o"}.issubset(objects):
        raise ValueError("Upstream object profile changed")
    objects = [name for name in objects if name not in ("testdisk.o", "ntfs_udl.o", "icon_tst.o")]
    if not 1 <= len(objects) <= 512 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+\.o", name) for name in objects):
        raise ValueError("Invalid native object list")
    owned = PROJECT / "src/Recovery.Native"
    include = ["-I" + unix(td / "src"), "-I" + unix(td), "-I" + unix(ntfs / "include"), "-DHAVE_CONFIG_H"]
    lines = [command(["windres", "--include-dir", unix(owned), "-i", unix(owned / "worker.rc"), "-o", unix(destination / "worker-resource.o")])]
    for name, path in (("protocol", owned / "Bridge/protocol.c"), ("bridge", owned / "Ntfs/testdisk_ntfs_bridge.c"), ("main", owned / "Ntfs/main.c")):
        lines.append(command(["gcc", "-std=gnu11", "-O2", "-g0", "-ffile-prefix-map=" + unix(PROJECT) + "=/usb-recovery",
            "-Wall", "-Wextra", *include, "-c", unix(path), "-o", unix(destination / (name + ".o"))]))
    lines.append(command(["gcc", "-Wl,--no-insert-timestamp", "-o", unix(runtime / "ntfs_worker.exe"),
        *(unix(td / "src" / name) for name in objects), *(unix(destination / (name + ".o")) for name in ("protocol", "bridge", "main", "worker-resource")),
        unix(ntfs / "libntfs-3g/.libs/libntfs-3g.a"), "-lz"]))
    run("03-worker", destination, lines)
    for name in DLLS:
        shutil.copyfile(toolchain / "bin" / name, runtime / name)
    files = [dict(Name=name, Sha256=digest(runtime / name)) for name in ("ntfs_worker.exe", *DLLS)]
    (runtime / "runtime.json").write_text(json.dumps(dict(Schema=1, Profile="ntfs-plan-v1", Files=files), indent=2), encoding="utf-8")
    licenses = runtime / "licenses"
    licenses.mkdir()
    shutil.copyfile(td / "COPYING", licenses / "TestDisk-COPYING.txt")
    shutil.copyfile(ntfs / "COPYING", licenses / "NTFS-3G-COPYING.txt")
    shutil.copyfile(ntfs / "COPYING.LIB", licenses / "NTFS-3G-COPYING.LIB.txt")
    shutil.copyfile(PROJECT / "LICENSE", licenses / "USB-Recovery-AGPL-3.0.txt")
    shutil.copyfile(toolchain / "usr/share/doc/Cygwin/CYGWIN_LICENSE", licenses / "Cygwin-CYGWIN_LICENSE.txt")
    shutil.copyfile(toolchain / "usr/share/doc/Cygwin/COPYING", licenses / "Cygwin-GPL-3.0.txt")
    for name, suffix, output in (("cygwin", "/winsup/COPYING.LIB", "Cygwin-LGPL-3.0.txt"),
                                ("libiconv2", "/COPYING.LIB", "libiconv-libcharset-LGPL.txt"),
                                ("zlib0", "/LICENSE", "zlib-LICENSE.txt")):
        archive = safe(cache, lock["runtime_sources"][name]["path"])
        (licenses / output).write_bytes(source_notice(archive, suffix))
    sources = runtime / "sources"
    sources.mkdir()
    for archive in (args.testdisk_archive, args.ntfs_archive, *runtime_sources):
        shutil.copyfile(archive, sources / archive.name)
    shutil.copytree(owned, sources / "Recovery.Native")
    for path in (Path(__file__), PROJECT / "scripts/prepare-native-toolchain.py", lock_path):
        shutil.copyfile(path, sources / path.name)
    receipt = dict(schema=1, status="native_ntfs_worker_built_from_pinned_sources", profile="ntfs-plan-v1", files=files,
        toolchain_lock_sha256=digest(lock_path), toolchain_inventory_sha256=digest(inventory_path), object_count=len(objects),
        sources={file.name: digest(file) for file in sources.iterdir() if file.is_file()},
        owned_sources={file.relative_to(owned).as_posix(): digest(file) for file in owned.rglob("*") if file.is_file()},
        flags=flags.split()[0:2], gui_used=False, system_installation=False, upstream_executables_run=False,
        recovery_tests_run=False, packaged_acceptance=False)
    (runtime / "build-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(dict(status=receipt["status"], worker_sha256=files[0]["Sha256"], object_count=len(objects))))


if __name__ == "__main__":
    main()
