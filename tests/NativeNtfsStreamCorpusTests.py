# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare actual packaged NTFS outputs, names and maps with authored inputs."""
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


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--case", action="append", dest="selected_cases", help="Run selected cases; omitted means full corpus")
    args = parser.parse_args()
    package, corpus, evidence = args.package.resolve(), args.corpus.resolve(), args.evidence.resolve()
    if evidence.exists():
        raise ValueError("Fresh stream-corpus evidence required")
    evidence.mkdir(parents=True)
    inventory = load(corpus / "corpus.json")
    executable = package / "USB-Recovery.exe"
    worker = package / "tools/native-recovery/ntfs_worker.exe"
    bound = {str(path): sha(path) for path in (executable, worker, corpus / "corpus.json")}
    bound[str(Path(__file__).resolve())] = sha(Path(__file__).resolve())
    environment = os.environ.copy()
    environment["PATH"] = str(Path(os.environ["WINDIR"]) / "System32")
    environment["__COMPAT_LAYER"] = "RunAsInvoker"
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    if shutil.which("python", path=environment["PATH"]) or shutil.which("py", path=environment["PATH"]):
        raise ValueError("Child PATH contains Python")
    receipts = []
    selected = set(args.selected_cases or [case["name"] for case in inventory["cases"]])
    if not selected or not selected.issubset({case["name"] for case in inventory["cases"]}):
        raise ValueError("Unknown or empty stream corpus selection")
    for case in inventory["cases"]:
        if case["name"] not in selected:
            continue
        image = corpus / case["image"]
        if sha(image) != case["image_sha256"]:
            raise ValueError("Authored corpus image changed")
        bound[str(image)] = case["image_sha256"]
        folder = evidence / case["name"]
        folder.mkdir()
        result = folder / "result"
        command = [str(executable), "scan", str(image), "-o", str(result), "--mode", "fast", "--fs", "ntfs", "--json"]
        with (folder / "stdout.log").open("wb") as output, (folder / "stderr.log").open("wb") as errors:
            child = subprocess.Popen(command, cwd=package, env=environment, stdout=output, stderr=errors,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                status = child.wait(timeout=180)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
        if status != 0:
            raise ValueError(f"Corpus case {case['name']} scan failed: {status}")
        session = load(result / "recovery-session.json")
        ntfs = next(row for row in session["Stages"] if row["Key"] == "ntfs")
        if ntfs["Status"] != "complete" or ntfs["CheckpointSequence"] < 1:
            raise ValueError("NTFS corpus session not complete/anchored")
        report = load(result / "ntfs/partition-0/ntfs-volume.json")
        catalog = load(result / "files-index.json")
        expected = {row["name"]: row for row in case["streams"]}
        candidates = {row["stream_name"]: row for row in report["candidates"]}
        if set(candidates) != set(expected) or len(report["outputs"]) != len(expected) or len(catalog["Items"]) != len(expected):
            raise ValueError(f"Corpus stream inventory differs: {case['name']}")
        outputs = {row["index"]: row for row in report["outputs"]}
        for name, item in expected.items():
            oracle = corpus / item["file"]
            if sha(oracle) != item["sha256"]:
                raise ValueError("Authored expected bytes changed")
            bound[str(oracle)] = item["sha256"]
            candidate = candidates[name]
            if candidate["status"] != "candidate" or candidate["missing_bytes"] != 0 or candidate["files"] != 1:
                raise ValueError("Complete authored stream classified incorrectly")
            output = outputs[candidate["first_file"]]
            recovered = result / "ntfs/partition-0/data" / output["file"]
            if sha(recovered) != item["sha256"] or output["sha256"] != item["sha256"]:
                raise ValueError(f"Recovered stream differs: {case['name']} / {name}")
            catalog_item = next(row for row in catalog["Items"] if row["Sha256"] == item["sha256"])
            if catalog_item["OriginalPathStatus"] != "metadata_hint":
                raise ValueError("Authored parent path incorrectly promoted to verified path")
            if name == "" and case["runs"]:
                actual = [(row["lcn"], row["clusters"]) for row in candidate["runs"]]
                if actual != [(lcn if lcn is not None else -1, count) for lcn, count in case["runs"]]:
                    raise ValueError("Actual native run list differs from independent fixture mapping")
                if candidate["initialized_bytes"] != case["initialized"]:
                    raise ValueError("Native initialized size differs from fixture")
        receipts.append(dict(name=case["name"], streams=len(expected), exact_content=True, names_and_runs_preserved=True))
        print("PASS NTFS stream corpus:", case["name"], flush=True)
    for path, checksum in bound.items():
        if sha(Path(path)) != checksum:
            raise ValueError("Source or runtime changed during corpus validation")
    receipt = dict(status="passed", cases=receipts, full_corpus=not args.selected_cases, inputs=bound, child_python_on_path=False,
                   authored_deletion_not_os_deletion=True, real_devices_tested=False, gui_tests_run=False,
                   network_isolated=False, full_portable_acceptance=False)
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(dict(status="passed", cases=len(receipts))))


if __name__ == "__main__":
    main()
