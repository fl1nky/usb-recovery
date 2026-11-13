"""Restore pinned build inputs from an immutable public release, never its EXEs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TAG = "v2026.11.13-images-postbox-lvm"
ARCHIVE_SHA256 = "6fe5b3e19559191386c1bff8f66d6f3fd142f00df1328ac8bdbb600d37252039"
URL = f"https://github.com/fl1nky/usb-recovery/releases/download/{TAG}/USB-Recovery-Windows-x64-{TAG}.zip"
PREFIX = "tools/recovery-helper/rebuild/"
PREFIXES = ("helpers/recovery_engine/wheels/", "helpers/recovery_engine/dependency-sources/",
            "vendor/iphone-backup-decrypt/")
WHEEL_REGISTRY = "helpers/recovery_engine/wheels/SHA256.json"
SOURCE_REGISTRY = "helpers/recovery_engine/storage-dependencies.json"
LOCK = "helpers/recovery_engine/requirements-wheel-lock.txt"
VENDOR = "vendor/iphone-backup-decrypt/"
VENDOR_FILES = frozenset((".github/workflows/release.yml", ".gitignore", "Dockerfile", "LICENSE.txt",
    "README.md", "SECURITY.md", "pyproject.toml", "src/iphone_backup_decrypt/__init__.py",
    "src/iphone_backup_decrypt/exceptions.py", "src/iphone_backup_decrypt/google_iphone_dataprotection.py",
    "src/iphone_backup_decrypt/iphone_backup.py", "src/iphone_backup_decrypt/utils.py", "tests/__init__.py",
    "tests/test_file_id_security.py", "tests/test_kdf_resource_limits.py", "tests/test_manifest_memory.py",
    "tests/test_output_path_security.py"))

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def plain(path):
    for node in (path, *path.parents):
        if node.is_symlink() or node.is_junction():
            raise ValueError("Linked build path")
    return path

def safe_name(name):
    parts = PurePosixPath(name).parts
    reserved = {"con", "prn", "aux", "nul", *("com" + str(i) for i in range(1, 10)), *("lpt" + str(i) for i in range(1, 10))}
    if (not parts or len(name) > 512 or name.startswith("/") or "\\" in name or
            any(ord(char) < 32 or char in ':<>"|?*' for char in name) or
            any(part in ("", ".", "..") or part.endswith((".", " ")) or part.split(".", 1)[0].casefold() in reserved for part in name.split("/"))):
        raise ValueError("Unsafe bootstrap member")
    return name

def source_registry(root):
    expected, folded = {}, set()
    registry_hashes = {}
    for registry, key, prefix, extension in ((WHEEL_REGISTRY, "name", PREFIXES[0], ".whl"),
                                           (SOURCE_REGISTRY, "source", PREFIXES[1], ".tar.gz")):
        path = plain(root / registry)
        records = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(records, list) or not records:
            raise ValueError("Empty or invalid checkout dependency registry")
        registry_hashes[registry] = digest(path)
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid checkout dependency record")
            name, sha = record.get(key), record.get("sha256")
            if not isinstance(name, str) or "/" in name or not name.endswith(extension):
                raise ValueError("Invalid checkout dependency name")
            safe_name(name)
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise ValueError("Invalid checkout dependency checksum")
            target = prefix + name
            if target.casefold() in folded:
                raise ValueError("Duplicate checkout dependency record")
            folded.add(target.casefold())
            expected[target] = sha
    lock_path = plain(root / LOCK)
    hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})(?=\s|$)", lock_path.read_text(encoding="utf-8-sig")))
    if {sha for name, sha in expected.items() if name.startswith(PREFIXES[0])} != hashes:
        raise ValueError("Checkout wheel registry differs from requirements lock")
    registry_hashes[LOCK] = digest(lock_path)
    expected.update((VENDOR + name, None) for name in VENDOR_FILES)
    return expected, registry_hashes

def restore(archive, root=ROOT, expected=ARCHIVE_SHA256):
    root = plain(root.absolute())
    plain(archive)
    if digest(archive) != expected:
        raise ValueError("Bootstrap archive checksum mismatch")
    required, registries = source_registry(root)
    rows, names, total = [], set(), 0
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            if not entry.filename.startswith(PREFIX) or entry.is_dir():
                continue
            name = entry.filename[len(PREFIX):]
            if not name.startswith(PREFIXES):
                continue
            safe_name(name)
            if (name.casefold() in names or (entry.external_attr >> 16) & 0o170000 == 0o120000 or entry.flag_bits & 1):
                raise ValueError("Unsafe bootstrap member")
            names.add(name.casefold())
            if name == WHEEL_REGISTRY:
                # This file belongs to the checkout; never replace it from a release.
                continue
            if name not in required:
                raise ValueError("Unregistered bootstrap dependency: " + name)
            total += entry.file_size
            if entry.file_size > 128 * 1024**2 or total > 512 * 1024**2:
                raise ValueError("Bootstrap expansion limit")
            target = plain(root / name)
            if target.exists() and not target.is_file():
                raise ValueError("Bootstrap target is not a file")
            rows.append((entry, name, target))
        if {name for _, name, _ in rows} != set(required):
            raise ValueError("Bootstrap is missing checkout-pinned build inputs")
        build = plain(root / ".build")
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="bootstrap-", dir=build) as stage:
            checked = []
            for entry, name, target in rows:
                temporary = Path(stage) / name
                temporary.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(entry) as source, temporary.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024**2)
                if temporary.stat().st_size != entry.file_size:
                    raise ValueError("Truncated bootstrap member")
                sha = digest(temporary)
                if required[name] is not None and sha != required[name]:
                    raise ValueError("Bootstrap dependency differs from checkout registry: " + name)
                if target.exists() and digest(target) != sha:
                    raise ValueError("Existing build input differs: " + name)
                checked.append((temporary, target, name, sha))
            # Validate the entire selection before publishing any dependency.
            for temporary, target, name, sha in checked:
                plain(target).parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    os.link(temporary, target)
            result = {"status": "passed", "archive_sha256": expected, "checkout_registries": registries, "files": [
                {"path": name, "sha256": sha, "bytes": target.stat().st_size}
                for _, target, name, sha in checked]}
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Use the already verified release ZIP without downloading")
    options = parser.parse_args()
    root = plain(ROOT)
    if options.archive is None:
        directory = plain(root / ".build/ci-download")
        directory.mkdir(parents=True, exist_ok=True)
        archive = directory / (TAG + ".zip")
        if not archive.exists():
            pending = directory / (TAG + "-" + str(time.time_ns()) + ".partial")
            started = time.monotonic()
            with urllib.request.urlopen(URL, timeout=90) as source, pending.open("xb") as output:
                if not source.geturl().startswith("https://"):
                    raise ValueError("Insecure bootstrap redirect")
                count = 0
                while data := source.read(1024**2):
                    count += len(data)
                    if count > 250 * 1024**2 or time.monotonic() - started > 300:
                        raise ValueError("Bootstrap download limit")
                    output.write(data)
            if pending.stat().st_size > 250 * 1024**2 or digest(pending) != ARCHIVE_SHA256:
                raise ValueError("Downloaded bootstrap archive mismatch")
            os.link(pending, archive)
            pending.unlink()
    else:
        archive = options.archive
    result = restore(archive)
    (root / ".build/bootstrap-build.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"PASS pinned build inputs: {len(result['files'])} files; no previous runtime copied")

if __name__ == "__main__":
    main()
