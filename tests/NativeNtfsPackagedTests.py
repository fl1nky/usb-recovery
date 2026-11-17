# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the actual packaged CLI on an owned image with no Python on child PATH."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    package, image = args.package.resolve(), args.image.resolve()
    evidence = args.evidence.resolve()
    if evidence.exists():
        raise ValueError("Fresh packaged-test evidence directory required")
    evidence.mkdir(parents=True)
    executable = package / "USB-Recovery.exe"
    worker = package / "tools/native-recovery/ntfs_worker.exe"
    bound = {str(path): sha(path) for path in (executable, worker, image, args.expected)}
    environment = os.environ.copy()
    environment["PATH"] = str(Path(os.environ["WINDIR"]) / "System32")
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["__COMPAT_LAYER"] = "RunAsInvoker"
    # Keep image-only CLI tests at the existing privilege level; no shell/UAC,
    # device access, browser command or interaction with a running app.
    if shutil.which("python", path=environment["PATH"]) or shutil.which("py", path=environment["PATH"]):
        raise ValueError("Child PATH unexpectedly resolves a Python interpreter")
    command = [str(executable), "scan", str(image), "-o", str(evidence / "result"),
               "--mode", "fast", "--fs", "ntfs", "--json"]
    with (evidence / "stdout.log").open("wb") as output, (evidence / "stderr.log").open("wb") as errors:
        child = subprocess.Popen(command, cwd=package, env=environment, stdout=output, stderr=errors,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            status = child.wait(timeout=180)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)
            raise
    if status != 0:
        raise ValueError(f"Packaged scan exit {status}; preserved stdout/stderr")
    session = json.loads((evidence / "result/recovery-session.json").read_text(encoding="utf-8-sig"))
    stages = {row["Key"]: row for row in session["Stages"]}
    if stages["ntfs"]["Status"] != "complete" or stages["ntfs"]["Candidates"] != 1 or stages["ntfs"]["CheckpointSequence"] < 1:
        raise ValueError("Actual packaged NTFS session is not complete and anchored")
    catalog = json.loads((evidence / "result/files-index.json").read_text(encoding="utf-8-sig"))
    if len(catalog["Items"]) != 1:
        raise ValueError("Packaged catalog contains missing or unexpected payloads")
    item = catalog["Items"][0]
    payload = evidence / "result" / item["Path"]
    if sha(payload) != bound[str(args.expected)] or item["Sha256"] != bound[str(args.expected)] or not item["SourceMapGroups"]:
        raise ValueError("Packaged candidate differs from expected bytes or lacks provenance")
    for path, digest in bound.items():
        if sha(Path(path)) != digest:
            raise ValueError("Packaged input or executable changed during validation")
    receipt = dict(status="passed", scope="Actual packaged NTFS CLI and catalog with child PATH without Python; synthetic image only",
                   files=1, bytes=payload.stat().st_size, output_sha256=sha(payload), inputs=bound,
                   child_python_on_path=False, interpreter_still_installed_on_host=True, network_isolated=False,
                   gui_tests_run=False, real_devices_tested=False, full_portable_acceptance=False)
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
