"""Append verified progressive-stage evidence without changing historical files."""
from pathlib import Path
import argparse
import hashlib
import json
import re


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def publish(repository, build, destination, run_directory, score_path, application_sha256, helper_sha256):
    historical = repository / ".build/benchmarks-v4"
    corpus = historical / "corpus-02"
    manifest = load(corpus / "manifest.json")
    manifest_sha = digest(corpus / "manifest.json")
    names = [case["name"] for case in manifest["cases"]]
    if len(names) != 19 or len(set(names)) != 19:
        raise ValueError("Expected the unchanged independent nineteen-case corpus")
    pending = {}
    historical_inventory = destination / "sha256.json"
    if historical_inventory.is_file():
        for name, expected in load(historical_inventory).items():
            if Path(name).name != name or digest(destination / name) != expected:
                raise ValueError("Historical published evidence changed")

    def relative(path):
        return path.resolve().relative_to(repository).as_posix()

    def sanitize(value, key=""):
        if isinstance(value, dict):
            return {k: sanitize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [sanitize(item, key) for item in value]
        if isinstance(value, str):
            for prefix in (str(repository), repository.as_posix()):
                value = re.sub(re.escape(prefix), ".", value, flags=re.IGNORECASE)
            if key.startswith("decoder_error"):
                value = re.sub(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\r\n]*", "<local path removed>", value)
            if key in {"path", "original_path", "source", "image", "runtime", "executable"}:
                value = value.replace("\\", "/")
                if value.startswith("./"):
                    value = value[2:]
            if re.search(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]", value):
                raise ValueError("Unexpected absolute path in derived evidence")
        return value

    def stage_details(row, directory):
        session_path = directory / row["name"] / "recovery-session.json"
        if not session_path.is_file():
            raise ValueError("Missing per-case pipeline evidence")
        session = load(session_path)
        row = dict(row)
        row["pipeline_status"] = session.get("Status")
        row["session_evidence"] = {"source": relative(session_path), "sha256": digest(session_path)}
        row["stages"] = [{key: value for key, value in stage.items()
                          if key in {"Key", "Status", "Candidates", "Message", "Warnings"}}
                         for stage in session.get("Stages", [])]
        row["bounded_search_evidence"] = []
        for filename in ("fragmented-photo-search.json", "fragmented-media.json"):
            path = session_path.parent / filename
            if path.is_file():
                report = load(path)
                row["bounded_search_evidence"].append({"source": relative(path), "sha256": digest(path),
                    "data": {key: value for key, value in report.items()
                             if key in {"Schema", "Status", "Candidates", "Recovered", "Skipped", "SourceUnchanged", "SourceSha256"}}})
        return row

    def document(name, source, data):
        pending[name] = (json.dumps({"derived_evidence_schema": 1,
            "provenance": {"source": relative(source), "source_sha256": digest(source),
                "transformation": "Append-only derived metadata; paths sanitized; per-case pipeline state preserved. Historical evidence is unchanged."},
            "data": sanitize(data)}, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    run_path = run_directory / "run.json"
    run, scored = load(run_path), load(score_path)
    if run["manifest_sha256"] != manifest_sha or scored["manifest_sha256"] != manifest_sha:
        raise ValueError("Corpus differs from executed benchmark")
    if scored["run_sha256"] != digest(run_path):
        raise ValueError("Score does not bind current run")
    for component in ("application", "helper", "carver", "manifest"):
        before, after = run.get(component + "_sha256_before"), run.get(component + "_sha256_after")
        if not before or before != after:
            raise ValueError("Missing immutable runtime/corpus pairing")
    if run["application_sha256_after"] != application_sha256 or run["helper_sha256_after"] != helper_sha256:
        raise ValueError("Run is not bound to the selected release application/helper")
    if [row["name"] for row in run["results"]] != names or [row["name"] for row in scored["cases"]] != names:
        raise ValueError("Benchmark must contain all original cases, in original order")
    if any(not row.get("source_unchanged") for row in run["results"]):
        raise ValueError("Source preservation is not established")
    for case, row in zip(manifest["cases"], run["results"]):
        if row["image_sha256"] != case["sha256"] or digest(corpus / case["image"]) != case["sha256"]:
            raise ValueError("Benchmark image changed")
        for candidate in row.get("files", []):
            if digest(Path(candidate["path"])) != candidate["sha256"]:
                raise ValueError("Exported candidate changed after scoring")
    rows = [stage_details(row, run_path.parent) for row in run["results"]]
    document("progressive-media-run.json", run_path, {**run, "results": rows, "runtime_pairing": "before_after"})
    derived_run_sha = hashlib.sha256(pending["progressive-media-run.json"]).hexdigest()
    document("progressive-media-score.json", score_path, {**scored, "derived_run_sha256": derived_run_sha,
        "run_sha256_is_original_source": True})

    def metric(score, chosen=None):
        selected = [row for row in score["cases"] if chosen is None or row["name"] in chosen]
        return {"cases_tested": len(selected), "exact_originals": sum(item["exact"] for row in selected for item in row["expected"]),
            "decoded_equivalent_originals": sum(item["decoded_equivalent"] for row in selected for item in row["expected"])}

    references = {}
    for label, filename, original_run in (("baseline", "baseline-score-02-revalidated.json", "baseline-results-02/run.json"),
            ("previous_release", "final-score-01.json", "final-results-01/run.json")):
        path = historical / filename
        reference = load(path)
        if reference["manifest_sha256"] != manifest_sha or reference["run_sha256"] != digest(historical / original_run):
            raise ValueError("Historical reference binding changed")
        references[label] = {**metric(reference), "source": relative(path), "sha256": digest(path)}
    previous = load(historical / "final-score-01.json")
    current_by_name = {row["name"]: row for row in scored["cases"]}
    previous_by_name = {row["name"]: row for row in previous["cases"]}
    improved = [name for name in names if metric({"cases": [current_by_name[name]]})["exact_originals"] > metric({"cases": [previous_by_name[name]]})["exact_originals"]]
    regressed = [name for name in names if metric({"cases": [current_by_name[name]]})["exact_originals"] < metric({"cases": [previous_by_name[name]]})["exact_originals"]]
    comparisons = []
    for label in ("rstudio", "dmde"):
        path = build / ("trial-" + label + "-rescore.json")
        trial_run = historical / (label + "-run.json")
        trial = load(path)
        original_trial = load(trial_run)
        if trial["manifest_sha256"] != manifest_sha or trial["run_sha256"] != digest(trial_run):
            raise ValueError("Trial rescore is not bound to unchanged real exports")
        if trial["scorer_sha256"] != scored["scorer_sha256"] or trial["ffmpeg_sha256"] != scored["ffmpeg_sha256"]:
            raise ValueError("Trial and current exports were scored by different validators")
        observed = [row["name"] for row in trial["cases"]]
        if len(observed) != len(set(observed)) or not set(observed).issubset(names):
            raise ValueError("Unexpected trial case list")
        if observed != [row["name"] for row in original_trial["results"]]:
            raise ValueError("Trial rescore changed the observed case set")
        for row in original_trial["results"]:
            if not row.get("source_unchanged"):
                raise ValueError("Prior trial source preservation is not established")
            for candidate in row.get("files", []):
                if digest(Path(candidate["path"])) != candidate["sha256"]:
                    raise ValueError("A prior real trial export changed")
        comparisons.append({"tool": trial["tool"], "edition": trial["edition"], "comparison_kind": "new Recovery run versus prior observed trial exports, freshly rescored; no new trial scan",
            "shared_cases": observed, "not_tested": [name for name in names if name not in observed],
            "current": metric(scored, observed), "trial": metric(trial), "source_run": relative(trial_run), "source_run_sha256": digest(trial_run),
            "source_rescore": relative(path), "source_rescore_sha256": digest(path)})
        trial_by_name = {row["name"]: row for row in trial["cases"]}
        public_trial = {**trial, "cases": [trial_by_name.get(name, {"name": name, "status": "not_tested", "expected": [], "candidates": []}) for name in names],
            "not_tested_explicit": True, "scope_note": "Fresh validation of previously observed real exports; no new commercial scan or export."}
        document("progressive-trial-" + label + "-rescore.json", path, public_trial)
    summary = {"schema": 1, "manifest_sha256": manifest_sha, "current": {**metric(scored),
        "application_sha256": run["application_sha256_after"], "helper_sha256": run["helper_sha256_after"],
        "incomplete_search_cases": [row["name"] for row in rows if any(stage.get("Status") == "incomplete" for stage in row["stages"])],
        "failed_cases": [row["name"] for row in rows if row["status"] != "completed"],
        "source_run_sha256": digest(run_path), "source_score_sha256": digest(score_path)},
        "references": references, "new_exact_cases": improved, "lost_exact_cases": regressed,
        "shared_case_comparisons": comparisons, "counts_are_not_percentages": True,
        "historical_evidence_inventory_sha256": digest(historical_inventory) if historical_inventory.is_file() else None,
        "limits": "Same small synthetic nineteen-case corpus. Previous trial exports only; progressive case not scanned in either commercial trial. No hardware, personal data, full competitor ranking or universal replacement claim.",
        "exporter_sha256": digest(Path(__file__))}
    pending["progressive-summary.json"] = (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    pending["progressive-sha256.json"] = (json.dumps({name: hashlib.sha256(data).hexdigest() for name, data in sorted(pending.items())}, indent=2) + "\n").encode("utf-8")
    destination.mkdir(parents=True, exist_ok=True)
    for name in pending:
        if (destination / name).exists():
            raise ValueError("Evidence already exists; historical files are never overwritten")
    for name, data in pending.items():
        (destination / name).write_bytes(data)
    print(json.dumps({"destination": str(destination), "files": len(pending), "current": summary["current"], "new_exact_cases": improved, "lost_exact_cases": regressed}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--build", type=Path, default=Path(".build/benchmarks-v5"))
    parser.add_argument("--destination", type=Path, default=Path("tests/benchmarks/evidence"))
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--application-sha256", required=True)
    parser.add_argument("--helper-sha256", required=True)
    args = parser.parse_args()
    publish(args.repository.resolve(), args.build.resolve(), args.destination.resolve(),
            args.run_directory.resolve(), args.score.resolve(), args.application_sha256.lower(), args.helper_sha256.lower())
