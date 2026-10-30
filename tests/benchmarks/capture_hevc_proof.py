"""Capture actual HEVC engine tests against a specified frozen application.

This executes owned regular-file fixtures only. It is a direct engine test,
not a whole-pipeline, commercial-product or physical-device comparison.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture(project, runtime, fixtures, ffmpeg, output, expected_app):
    if output.exists():
        raise FileExistsError("Preserve existing benchmark proof")
    app, harness = runtime / "USB-Recovery.exe", runtime / "HevcRecoveryTests.exe"
    manifest_path = fixtures / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if len(manifest["Cases"]) != 10 or digest(app) != expected_app or digest(ffmpeg) != manifest["FfmpegSha256"]:
        raise ValueError("Frozen binary or fixture binding mismatch")
    paths = []
    for row in manifest["Cases"]:
        for key, hash_key in (("Image", "ImageSha256"), ("Original", "Sha256")):
            path = (fixtures / row[key]).resolve()
            if not path.is_relative_to(fixtures.resolve()) or not path.is_file() or digest(path) != row[hash_key]:
                raise ValueError("HEVC source/original inventory mismatch")
            paths.append(path)
    def inventory():
        return {path.relative_to(project).as_posix(): digest(path) for path in (app, harness, manifest_path, ffmpeg, *paths)}
    app_key, harness_key, manifest_key, ffmpeg_key = (path.relative_to(project).as_posix() for path in (app, harness, manifest_path, ffmpeg))
    before = inventory()
    started = time.monotonic()
    result = subprocess.run([str(harness), str(project), str(fixtures), str(ffmpeg)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    stdout = result.stdout.decode("utf-8", errors="replace")
    after = inventory()
    match = re.search(r"PASS HevcRecovery: (\d+) checks;", stdout)
    if result.returncode or result.stderr.strip() or not match or before != after:
        raise ValueError("Frozen HEVC proof failed, was incomplete or changed its inputs")
    for row in manifest["Cases"]:
        if row["Expected"] == 1 and not any(line.startswith(row["Name"] + ":") for line in stdout.splitlines()):
            raise ValueError("Missing positive/uncertain case observation")
    document = {
        "schema": 1, "status": "passed", "checks": int(match[1]), "cases": len(manifest["Cases"]),
        "application_sha256_before": before[app_key], "application_sha256_after": after[app_key],
        "harness_sha256": before[harness_key], "harness_source_sha256": digest(project / "tests/HevcRecoveryTests.cs"),
        "collector_sha256": digest(Path(__file__)), "manifest_sha256": before[manifest_key],
        "ffmpeg_sha256": before[ffmpeg_key], "source_and_originals_unchanged": True,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "exact_original_cases": sum(row["Expected"] == 1 and row["Exact"] for row in manifest["Cases"]),
        "uncertain_structural_cases": sum(row["Expected"] == 1 and not row["Exact"] for row in manifest["Cases"]),
        "rejected_cases": sum(row["Expected"] == 0 for row in manifest["Cases"]),
        "observed_stdout": stdout.splitlines(), "fixture_manifest": manifest,
        "input_hashes_before": before, "input_hashes_after": after,
        "pipeline_used": False, "helper_used": False, "commercial_tools_tested": False,
        "scope": "Actual direct engine invocation from the frozen application assembly on ten independent real-FFmpeg owned regular-file fixtures. Five exact originals plus all decoded frames; one deliberately opaque CABAC overwrite remains unauthenticated; four negative cases produce no output. No physical devices or new commercial-product tests.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(json.dumps({"proof": str(output), "checks": document["checks"], "exact_original_cases": document["exact_original_cases"], "rejected_cases": document["rejected_cases"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project", "runtime", "fixtures", "ffmpeg", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-app", required=True)
    args = parser.parse_args()
    capture(args.project.resolve(), args.runtime.resolve(), args.fixtures.resolve(), args.ffmpeg.resolve(), args.output.resolve(), args.expected_app)
