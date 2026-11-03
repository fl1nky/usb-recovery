"""Own ZIP inputs: immutable caches and fresh legacy-suite working copies.

--verify reads ONLY immutable caches. Existing unknown/stale/input-mutated
working roots are rejected; complete owned runs are archived, never deleted.
This developer-only preparer executes only two fixed maintained generators.
"""
from pathlib import Path, PurePosixPath
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import uuid

ROOT = Path(__file__).absolute().parents[1]
JOBS = (("build_archive_salvage_fixtures.py", "archive-salvage-inputs-current", "archive-salvage-tests"),
        ("build_fragmented_zip_fixtures.py", "fragmented-zip-inputs-current", "fragmented-zip-tests"))
CACHE_MARKER = ".archive-fixture-cache.json"
RUN_MARKER = ".archive-fixture-run.json"
MAX_INPUT_FILES = 256
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_RUN_FILES = 4096
MAX_RUN_BYTES = 1024 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def plain(path):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink() or parent.is_junction():
            info = parent.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not
                    getattr(info, "st_file_attributes", 0) & 0x400,
                    "Linked archive fixture path rejected")
    return path


def inside_build(path):
    build = plain(ROOT / ".build").resolve()
    path = plain(path).resolve()
    require(path != build and path.is_relative_to(build), "Archive path must remain inside resolved .build")
    return path


def relative(name):
    require(isinstance(name, str) and ":" not in name and "\\" not in name,
            "Invalid archive inventory path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name and
            all(p not in ("", ".", "..") for p in path.parts), "Unsafe archive inventory path")
    return name


def sha(path):
    with plain(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n"); stream.flush(); os.fsync(stream.fileno())


def inventory(target, skip=None, run=False):
    result, total = {}, 0
    for parent, directories, files in os.walk(plain(target), followlinks=False):
        require(len(Path(parent).relative_to(target).parts) <= 32, "Archive inventory depth bound")
        for name in directories:
            plain(Path(parent) / name)
        for name in files:
            path = plain(Path(parent) / name)
            if skip and path == target / skip:
                continue
            require(path.is_file(), "Regular archive fixture files required")
            size = path.stat().st_size; total += size
            require(len(result) < (MAX_RUN_FILES if run else MAX_INPUT_FILES) and
                    total <= (MAX_RUN_BYTES if run else MAX_INPUT_BYTES), "Archive inventory bound")
            result[path.relative_to(target).as_posix()] = {"bytes": size, "sha256": sha(path)}
    return result


def binding(generator):
    return {"schema": 1, "generator": generator.name, "generator_sha256": sha(generator),
            "preparer_sha256": sha(Path(__file__)), "python_version": list(sys.version_info[:3]),
            "python_executable_sha256": sha(Path(sys.executable))}


def read_cache(job, expected):
    target = inside_build(ROOT / ".build" / job[1])
    require(target.is_dir() and (target / CACHE_MARKER).is_file(), "Missing/unrecorded immutable archive cache")
    receipt = json.loads(plain(target / CACHE_MARKER).read_text("utf-8"))
    require(set(receipt) == {"kind", "binding", "files"} and
            receipt["kind"] == "owned-archive-input-cache-v2" and receipt["binding"] == expected,
            "Stale immutable archive cache preserved")
    actual = inventory(target, CACHE_MARKER)
    require(actual == receipt["files"] and "fixtures.json" in actual,
            "Changed/incomplete immutable archive cache preserved")
    return target, receipt


def ensure_cache(job, expected):
    target = inside_build(ROOT / ".build" / job[1])
    if target.exists():
        return read_cache(job, expected)
    stage = inside_build(ROOT / ".build" / (".archive-input-" + job[1] + "-" + uuid.uuid4().hex + ".partial"))
    require(not stage.exists(), "Fresh archive cache stage required")
    generator = plain(ROOT / "tests" / job[0])
    result = subprocess.run([sys.executable, "-B", str(generator), str(stage)], cwd=ROOT,
                            capture_output=True, timeout=120, check=False)
    require(result.returncode == 0, "Archive generator failed; staged inputs preserved")
    files = inventory(stage)
    require("fixtures.json" in files and isinstance(json.loads((stage / "fixtures.json").read_text("utf-8")), list),
            "Archive generator did not publish its fixture list")
    require(binding(generator) == expected, "Archive source/Python changed during generation")
    write_json(stage / CACHE_MARKER, {"kind": "owned-archive-input-cache-v2", "binding": expected, "files": files})
    # Both paths are checked immediately before same-volume rename. On Windows
    # os.rename refuses an existing destination; no replacement/deletion occurs.
    require(not inside_build(target).exists(), "Immutable cache appeared concurrently; stage preserved")
    os.rename(inside_build(stage), inside_build(target))
    return read_cache(job, expected)


def run_header(job, expected):
    current = inside_build(ROOT / ".build" / job[2])
    if not current.exists():
        return None
    require(current.is_dir() and (current / RUN_MARKER).is_file(), "Unknown legacy working root preserved")
    marker = json.loads(plain(current / RUN_MARKER).read_text("utf-8"))
    require(set(marker) == {"schema", "kind", "run_id", "working_path", "binding", "cache_fingerprint", "input_files"} and
            marker["schema"] == 1 and marker["kind"] == "owned-archive-working-run-v2" and
            re.fullmatch(r"[0-9a-f]{32}", marker["run_id"]) and
            marker["working_path"] == str(current).casefold() and marker["binding"] == expected,
            "Stale/foreign archive working root preserved")
    return marker


def inspect_run(job, expected, cache):
    marker = run_header(job, expected)
    if marker is None:
        return None
    require(marker["cache_fingerprint"] == digest(cache) and marker["input_files"] == cache["files"],
            "Archive working root belongs to another input cache; preserved")
    current = inside_build(ROOT / ".build" / job[2])
    files = inventory(current, run=True)
    for name, proof in cache["files"].items():
        require(files.get(relative(name)) == proof, "Mutated/missing original archive input; entire run preserved")
    return {"marker": marker, "files": files}


def stage_working(job, expected, cache_path, cache):
    current = inside_build(ROOT / ".build" / job[2])
    run_id = uuid.uuid4().hex
    stage = inside_build(ROOT / ".build" / (".archive-working-" + job[2] + "-" + run_id + ".partial"))
    stage.mkdir()
    for name, proof in cache["files"].items():
        src, dst = plain(cache_path / relative(name)), plain(stage / relative(name))
        dst.parent.mkdir(parents=True, exist_ok=True)
        with src.open("rb") as source, dst.open("xb") as target:
            shutil.copyfileobj(source, target, 128 * 1024)
    require(inventory(stage) == cache["files"], "Incomplete working copy; stage preserved")
    write_json(stage / RUN_MARKER, {"schema": 1, "kind": "owned-archive-working-run-v2", "run_id": run_id,
               "working_path": str(current).casefold(), "binding": expected,
               "cache_fingerprint": digest(cache), "input_files": cache["files"]})
    return stage


def archive_run(job, expected, cache, prior):
    if prior is None:
        return None
    current = inside_build(ROOT / ".build" / job[2])
    require(inspect_run(job, expected, cache) == prior, "Archive run changed since preflight; preserved")
    history = inside_build(ROOT / ".build/archive-regression-history")
    history.mkdir(exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = inside_build(history / (job[2] + "-" + stamp + "-" + prior["marker"]["run_id"]))
    receipt = inside_build(history / (target.name + ".receipt.json"))
    require(not target.exists() and not receipt.exists(), "Fresh archive history destination required")
    os.rename(inside_build(current), inside_build(target))
    require(inventory(target, run=True) == prior["files"], "Archived run verification failed; all artifacts preserved")
    write_json(receipt, {"schema": 1, "kind": "preserved-archive-regression-run", "from": str(current),
                        "to": str(target), "run_id": prior["marker"]["run_id"], "files": prior["files"]})
    return str(target.relative_to(ROOT).as_posix())


def prepare(verify_only=False):
    plain(ROOT)
    expected = [binding(plain(ROOT / "tests" / job[0])) for job in JOBS]
    if verify_only:
        caches = [read_cache(job, proof) for job, proof in zip(JOBS, expected)]
        return {"status": "verified", "mode": "immutable-caches-read-only", "recovery_executed": False,
                "caches": [{"directory": job[1], "files": len(cache[1]["files"])} for job, cache in zip(JOBS, caches)]}
    # Refuse unknown/stale working roots before creating or moving anything.
    for job, proof in zip(JOBS, expected):
        run_header(job, proof)
    plain(ROOT / ".build").mkdir(exist_ok=True)
    caches = [ensure_cache(job, proof) for job, proof in zip(JOBS, expected)]
    priors = [inspect_run(job, proof, cache[1]) for job, proof, cache in zip(JOBS, expected, caches)]
    stages = [stage_working(job, proof, cache[0], cache[1]) for job, proof, cache in zip(JOBS, expected, caches)]
    for job, proof in zip(JOBS, expected):
        require(binding(plain(ROOT / "tests" / job[0])) == proof, "Archive source changed before rotation")
    for job, proof, cache in zip(JOBS, expected, caches):
        read_cache(job, proof)
    histories = [archive_run(job, proof, cache[1], prior)
                 for job, proof, cache, prior in zip(JOBS, expected, caches, priors)]
    for job, stage in zip(JOBS, stages):
        target = inside_build(ROOT / ".build" / job[2])
        require(not target.exists(), "Working root appeared concurrently; stage/history preserved")
        os.rename(inside_build(stage), inside_build(target))
    for job, proof, cache in zip(JOBS, expected, caches):
        require(inspect_run(job, proof, cache[1]) is not None, "Published working-copy verification failed")
    return {"status": "prepared", "mode": "fresh-owned-working-copies", "recovery_executed": False,
            "caches": [{"directory": job[1], "files": len(cache[1]["files"])} for job, cache in zip(JOBS, caches)],
            "working_directories": [job[2] for job in JOBS], "preserved_history": histories}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Read ONLY immutable caches; never rotate/create working copies")
    args = parser.parse_args()
    print(json.dumps(prepare(args.verify)))
