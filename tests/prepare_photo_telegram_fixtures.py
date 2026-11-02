"""Prepare immutable, SHA-bound owned PNG and Telegram offline fixtures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".build"
PNG_NAMES = {
    "contiguous", "whole-idat", "cut-512", "cut-4k", "cut-32k", "cut-128k", "cut-1280k",
    "unaligned-head", "reversed", "zero-padding", "random-padding", "ancillary-prefix",
    "ancillary-tail", "indexed-palette", "multi-idat-middle", "crc-split", "duplicate-tail",
    "false-anchor", "corrupt-crc", "invalid-adler", "missing-payload", "overlap",
    "forbidden-tail-context", "invalid-filter", "ambiguous-tail", "mixed-intact-gap-ambiguous",
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def plain(path):
    require(path.absolute().is_relative_to(ROOT.absolute()), "Fixture path outside project")
    for parent in (path, *path.parents):
        require(not parent.is_symlink() and not parent.is_junction(), "Linked fixture path")
    return path


def sha(path):
    with plain(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(folder):
    result = {}
    pending = [plain(folder)]
    while pending:
        current = plain(pending.pop())
        for path in sorted(current.iterdir()):
            plain(path)
            if path.is_dir():
                pending.append(path)
            elif path.is_file():
                result[path.relative_to(folder).as_posix()] = {"bytes": path.stat().st_size, "sha256": sha(path)}
    return result


def prepare(kind):
    telegram = kind == "telegram-media-cache-profile"
    generator = ROOT / "tests" / ("build_telegram_media_cache_profile_fixtures.py" if telegram else "build_png_idat_gap_fixtures.py")
    target = plain(BUILD / (kind + "-fixtures-current"))
    marker = plain(BUILD / (kind + "-fixtures-current.prepared.json"))
    sources = {generator.relative_to(ROOT).as_posix(): sha(generator)}
    if telegram:
        source_dir = ROOT / "tests/fixtures/telegram-cache-profiles"
        sources.update({"tests/fixtures/telegram-cache-profiles/" + name: row["sha256"]
                        for name, row in inventory(source_dir).items()})
    if target.exists():
        require(marker.is_file(), "Unrecorded fixture cache; preserve it and prepare a fresh destination: " + str(target))
        receipt = json.loads(marker.read_text(encoding="utf-8"))
        require(receipt.get("schema") == 1 and receipt.get("sources") == sources,
                "Stale fixture sources; preserve the old corpus before preparing a new one")
        require(receipt.get("files") == inventory(target), "Changed fixture bytes; existing evidence was preserved")
    else:
        require(not marker.exists(), "Orphaned fixture receipt; preserve existing evidence")
        subprocess.run([sys.executable, str(generator), str(target)], check=True)
        require(all(sha(ROOT / name) == digest for name, digest in sources.items()), "Source changed during fixture preparation")

    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    if telegram:
        cases, snapshots = manifest["cases"], manifest["snapshot_cases"]
        require(manifest["schema"] == 1 and manifest["generator_sha256"] == sha(generator) and
                manifest["source_commit"] == "4de548e79fed27f1a66fbdff84223321838fe925" and
                manifest["oracle_manifest_sha256"] == sha(ROOT / "tests/fixtures/telegram-cache-profiles/manifest.json"),
                "Telegram source/oracle fingerprint mismatch")
        require(len(cases) == len({row["name"] for row in cases}) == 855 and
                sum(len(row["text_parts"]) for row in cases) == 1235 and
                len(snapshots) == 6 and {row["name"] for row in snapshots} == {
                    "cache-history", "primary-current", "primary-historical", "native-history", "native-residual", "caption-only"},
                "Incomplete independent Telegram corpus")
    else:
        cases = manifest["Cases"]
        require(manifest["Schema"] == 1 and manifest["IndependentEncoder"] is True and
                manifest["GeneratorSha256"] == sha(generator) and len(cases) == 26 and
                {row["Name"] for row in cases} == PNG_NAMES and
                sum(row["ExpectedCandidates"] == 1 for row in cases) == 17,
                "Incomplete independent PNG corpus or generator mismatch")
    if not marker.exists():
        with marker.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump({"schema": 1, "sources": sources, "files": inventory(target)}, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"fixture": kind, "status": "verified", "cases": len(cases)}))


if __name__ == "__main__":
    BUILD.mkdir(exist_ok=True)
    prepare("telegram-media-cache-profile")
    prepare("png-idat-gap")
