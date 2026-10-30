"""Bind manually observed competitor scans/exports to the shared corpus.

An empty pre-created directory is NEVER treated as a failed recovery. Every
scored case needs an explicit operator observation with an outcome and notes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def collect(corpus, directory, observations, executable, output, tool, edition):
    manifest_file = corpus / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8-sig"))
    cases = {x["name"]: x for x in manifest["cases"]}
    observed = json.loads(observations.read_text(encoding="utf-8-sig"))
    rows = []
    names = set()
    for record in observed["cases"]:
        name = record["name"]
        if name in names or name not in cases:
            raise ValueError("Unknown or duplicate observed corpus case")
        names.add(name)
        if record["status"] not in {"completed", "no_findings", "trial_not_exported", "inconclusive"}:
            raise ValueError("Unsupported observed outcome")
        if not record.get("note") or not record.get("configuration"):
            raise ValueError("Observation needs actual parameters and notes")
        sample = cases[name]
        image = corpus / sample["image"]
        if digest(image) != sample["sha256"]:
            raise ValueError("Corpus source checksum differs")
        exported = directory / name
        files = []
        if exported.exists():
            for path in sorted(exported.rglob("*")):
                if path.is_symlink() or path.is_junction():
                    raise ValueError("Linked exported candidate")
                if path.is_file():
                    files.append({"path": str(path.resolve()), "bytes": path.stat().st_size,
                                  "sha256": digest(path), "method": "competitor_export",
                                  "status": "exported_candidate", "original_path": str(path.relative_to(exported))})
        if record["status"] == "completed" and not files:
            raise ValueError("Successful export requires an actual file")
        if record["status"] == "no_findings" and files:
            raise ValueError("No-findings observation contradicts exports")
        rows.append({"name": name, "image": sample["image"], "image_sha256": sample["sha256"],
                     "source_unchanged": True, "elapsed_ms": record.get("elapsed_ms"),
                     "status": record["status"], "trial_not_exported": record["status"] == "trial_not_exported",
                     "configuration": record["configuration"], "operator_note": record["note"], "files": files})
    if not rows:
        raise ValueError("No actually observed competitor cases")
    report = {"schema": 1, "tool": tool, "edition": edition, "label": "actual observed exports",
              "application_sha256": digest(executable), "observations_sha256": digest(observations),
              "manifest_sha256": digest(manifest_file), "cases_not_tested": sorted(set(cases) - names),
              "paid_edition_activated": False, "results": rows}
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"run": str(output), "observed_cases": len(rows),
                      "untested_cases": len(report["cases_not_tested"])}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("corpus", "directory", "observations", "executable", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--edition", required=True)
    args = parser.parse_args()
    collect(args.corpus.resolve(), args.directory.resolve(), args.observations.resolve(),
            args.executable.resolve(), args.output.resolve(), args.tool, args.edition)
