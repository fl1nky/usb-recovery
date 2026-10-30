"""Publish byte-exact synthetic paired media evidence; never run a recovery tool.

Restore with --restore ENVELOPE... --out FRESH_DIRECTORY. Rescore existing bytes
with --rescore RESTORED_DIRECTORY --out FRESH_DIRECTORY --ffmpeg PINNED_FFMPEG.
"""
from __future__ import annotations

import argparse
import base64
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re

from export_telegram_legacy import check_ancestors, restore, validate_name

FFMPEG_SHA256 = "3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def inventory(folder):
    return {p.relative_to(folder).as_posix(): digest(p)
            for p in sorted(folder.rglob("*")) if p.is_file()}


def score_core(value):
    """Relocation changes paths/run hashes; decoder diagnostics contain addresses."""
    if isinstance(value, dict):
        return {k: score_core(v) for k, v in value.items()
                if k not in ("path", "run_sha256", "decoder_error")}
    if isinstance(value, list):
        return [score_core(v) for v in value]
    return value


def rescore(restored, destination, ffmpeg):
    # Archives are data. Never execute Python supplied by a restored envelope.
    # Validate every code/tool binding before importing even the trusted scorer.
    check_ancestors(restored)
    if digest(ffmpeg) != FFMPEG_SHA256:
        raise ValueError("FFMPEG_BINDING_CHANGED")
    source = Path(__file__).with_name("score_media_results.py")
    source_sha = digest(source)
    check_ancestors(restored / "sources/score_media_results.py")
    if digest(restored / "sources/score_media_results.py") != source_sha:
        raise ValueError("SCORER_BINDING_CHANGED")
    collection = read(restored / "runs/v8/collection.json")
    names = [r["name"] for r in collection["results"]]
    if len(names) != 5 or len(set(names)) != 5 or any(
            not isinstance(n, str) or not re.fullmatch(r"[a-z0-9-]{1,80}", n) for n in names):
        raise ValueError("COLLECTION_NAMES_INVALID")
    for name in names:
        if len(validate_name(name)) != 1:
            raise ValueError("COLLECTION_NAMES_INVALID")
    expected_reports = {}
    for name in names + ["rstudio", "dmde"]:
        expected = read(restored / "scores" / (name + ".json"))
        if expected["ffmpeg_sha256"] != FFMPEG_SHA256:
            raise ValueError("FFMPEG_BINDING_CHANGED")
        if expected["scorer_sha256"] != source_sha:
            raise ValueError("SCORER_BINDING_CHANGED")
        expected_reports[name] = expected
    check_ancestors(destination)
    destination.mkdir(parents=True, exist_ok=False)
    paths = read(restored / "provenance/path-map.json")
    spec = importlib.util.spec_from_file_location("trusted_media_scorer", source)
    scorer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scorer)
    results = []
    for name in names + ["rstudio", "dmde"]:
        original = (restored / "historical" / (name + "-run.json")
                    if name in ("rstudio", "dmde")
                    else restored / "runs/v8" / name / "run.json")
        expected = expected_reports[name]
        if digest(original) != expected["run_sha256"]:
            raise ValueError("RAW_RUN_BINDING_CHANGED")
        projected = copy.deepcopy(read(original))
        for row in projected["results"]:
            for item in row.get("files", []):
                target = restored.joinpath(*validate_name(paths[item["path"]]))
                check_ancestors(target)
                if digest(target) != item["sha256"]:
                    raise ValueError("RESTORED_CANDIDATE_CHANGED")
                item["path"] = str(target.resolve())
        projected_path = destination / (name + "-relocated-run.json")
        write(projected_path, projected)
        output = destination / (name + "-score.json")
        scorer.score(restored / "inputs/corpus-02", projected_path, ffmpeg, output)
        actual = read(output)
        if score_core(actual) != score_core(expected):
            raise ValueError("RESCORE_SEMANTICS_DIFFER: " + name)
        results.append({"name": name, "equivalent": True,
                        "original_score_sha256": digest(restored / "scores" / (name + ".json")),
                        "relocated_score_sha256": digest(output),
                        "cases": len(actual["cases"])})
    receipt = {"schema": 1, "status": "passed", "scope":
               "Only public scoring/decoding of restored files; no recovery program rerun. "
               "All score fields compare equal except relocated candidate paths, projected "
               "run-file SHA256 and volatile decoder diagnostic text.",
               "ffmpeg_sha256": digest(ffmpeg), "scorer_sha256": digest(source),
               "results": results}
    write(destination / "rescore-equivalence.json", receipt)
    return receipt


def privacy_scan(path, raw, project):
    problems = []
    if path.suffix.lower() in {".exe", ".dll", ".pyd", ".sys", ".scr", ".msi"}:
        problems.append("EXECUTABLE_EXCLUDED")
    if any(word in path.name.casefold() for word in ("screenshot", "clipboard", "capture_screen")):
        problems.append("SCREENSHOT_EXCLUDED")
    if path.suffix.lower() not in {".json", ".txt", ".log", ".csv", ".xml", ".cs", ".py", ".lock", ".sha256"}:
        return problems
    text = raw.decode("utf-8-sig", errors="replace").replace("\\\\", "\\")
    if re.search(r"(?i)[a-z]:[\\/]Users[\\/][^\r\n\"<>]*[\\/]AppData[\\/]", text):
        problems.append("PERSONAL_APPDATA_PATH")
    if re.search(r"(?i)(?:bearer\s+[a-z0-9._-]{20,}|gh[pousr]_[a-z0-9]{20,}|sk-[a-z0-9_-]{25,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)", text):
        problems.append("POSSIBLE_SECRET")
    for match in re.finditer(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\r\n\"<>|]*", text):
        value = match.group().replace("/", "\\").casefold()
        own = str(project).replace("/", "\\").casefold()
        if value.rstrip() != own and not value.startswith(own + "\\"):
            problems.append("OUTSIDE_OWN_PROJECT_PATH")
            break
    return sorted(set(problems))


def publish(project, destination, restore_check, ffmpeg):
    base = project / ".build/benchmarks-v8-comparison"
    corpus = project / ".build/benchmarks-v4/corpus-02"
    before = read(base / "paired-five-01/binding-before.json")
    after = read(base / "paired-five-01/binding-after.json")
    if before != after or inventory(base / "runtime") != before["runtime"]:
        raise ValueError("RUNTIME_BINDING_CHANGED")
    if inventory(corpus) != before["corpus"]:
        raise ValueError("CORPUS_BINDING_CHANGED")
    collection = read(base / "paired-five-01/collection.json")
    names = [r["name"] for r in collection["results"]]
    if collection["status"] != "complete" or len(set(names)) != 5:
        raise ValueError("COLLECTION_INCOMPLETE")
    manifest = read(corpus / "manifest.json")
    paid = {tool: read(project / ".build/benchmarks-v4" / (tool + "-run.json"))
            for tool in ("rstudio", "dmde")}
    if names != [r["name"] for r in paid["rstudio"]["results"]]:
        raise ValueError("PAIRED_INPUTS_DIFFER")
    source_files = {}
    path_map = {}

    def add(path, relative):
        check_ancestors(path)
        validate_name(relative)
        if not path.is_file() or path.is_symlink():
            raise ValueError("SOURCE_NOT_REGULAR")
        key = str(path.resolve())
        if relative in source_files and source_files[relative] != path:
            raise ValueError("DUPLICATE_PUBLIC_PATH")
        source_files[relative] = path
        path_map[key] = relative

    def tree(folder, prefix):
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                add(path, prefix + "/" + path.relative_to(folder).as_posix())

    add(corpus / "manifest.json", "inputs/corpus-02/manifest.json")
    for case in manifest["cases"]:
        if case["name"] in names:
            add(corpus / case["image"], "inputs/corpus-02/" + case["image"])
    for asset in manifest["assets"]:
        add(corpus / asset["path"], "inputs/corpus-02/" + asset["path"])
    tree(base / "paired-five-01", "runs/v8")
    tree(base / "scores-01", "scores")
    for name in ("collection.log", "scoring.log"):
        add(base / name, "runs/" + name)
    add(base / "independent-review-01.json", "provenance/independent-review-01.json")
    for name in ("run_existing_five.py", "score_current_five.py"):
        add(base / name, "sources/" + name)
    for name in ("MediaBenchmark.cs", "score_media_results.py", "export_telegram_legacy.py"):
        add(project / "tests/benchmarks" / name, "sources/" + name)
    add(Path(__file__).resolve(), "sources/export_media_comparison.py")
    paid_count = 0
    for tool, run in paid.items():
        add(project / ".build/benchmarks-v4" / (tool + "-run.json"), "historical/" + tool + "-run.json")
        folder = project / ".build/benchmarks-v4" / (tool + "-results")
        for row in run["results"]:
            for item in row.get("files", []):
                path = Path(item["path"])
                if digest(path) != item["sha256"] or before["paid_exports"][str(path)] != item["sha256"]:
                    raise ValueError("PAID_EXPORT_CHANGED")
                add(path, "historical/" + tool + "-results/" + path.relative_to(folder).as_posix())
                paid_count += 1
    if paid_count != 20:
        raise ValueError("PAID_EXPORT_COUNT_CHANGED")
    if digest(base / "run_existing_five.py") != before["collector_source_sha256"]:
        raise ValueError("COLLECTOR_CHANGED")
    if digest(project / "tests/benchmarks/MediaBenchmark.cs") != before["public_harness_source_sha256"]:
        raise ValueError("HARNESS_SOURCE_CHANGED")
    scanned = []; entries = []
    for relative, path in sorted(source_files.items()):
        raw = path.read_bytes()
        problems = privacy_scan(path, raw, project)
        if problems:
            raise ValueError("PRIVACY_REVIEW_REQUIRED: " + relative + " " + ",".join(problems))
        if len(raw) > 64 * 1024**2:
            raise ValueError("RESTORE_PER_FILE_LIMIT")
        record = {"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        scanned.append(record)
        entries.append({**record, "gzip_base64": base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii")})
    map_raw = (json.dumps(path_map, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    map_record = {"path": "provenance/path-map.json", "bytes": len(map_raw),
                  "sha256": hashlib.sha256(map_raw).hexdigest()}
    scanned.append(map_record)
    entries.append({**map_record, "gzip_base64": base64.b64encode(gzip.compress(map_raw, mtime=0)).decode("ascii")})
    destination.mkdir(parents=True, exist_ok=False)
    envelope = {"schema": 1, "encoding": "gzip+base64", "directories": [],
                "scope": "Owned synthetic project fixtures, historical trial exports and actual published V8 Pipeline outputs. "
                "Original workspace paths are provenance. No personal devices/profiles were scanned; executables/screenshots excluded.",
                "files": entries}
    write(destination / "complete-proof.json", envelope)
    restored_receipt = restore([destination / "complete-proof.json"], restore_check)
    for row in scanned:
        if digest(restore_check.joinpath(*validate_name(row["path"]))) != row["sha256"]:
            raise ValueError("RESTORE_SOURCE_DIFFERENCE")
    write(destination / "path-map.json", path_map)
    write(destination / "restoration-check.json", restored_receipt)
    receipt = rescore(restore_check, restore_check.parent / (restore_check.name + "-rescore"), ffmpeg)
    write(destination / "rescore-equivalence.json", receipt)
    scores = {name: read(base / "scores-01" / (name + ".json")) for name in names + ["rstudio", "dmde"]}
    def metric(reports):
        cases = [row for report in reports for row in report["cases"]]
        return {"cases": len(cases), "exact_targets": sum(x["exact"] for c in cases for x in c["expected"]),
                "equivalent_only_targets": sum(x["decoded_equivalent"] and not x["exact"] for c in cases for x in c["expected"]),
                "exported_candidates": sum(c["candidate_count"] for c in cases)}
    stages = [read(base / "paired-five-01" / name / name / "scan-stages.json") for name in names]
    write(destination / "comparison.json", {"schema": 1, "scope": envelope["scope"],
          "published_application_sha256": before["runtime"]["USB-Recovery.exe"],
          "published_helper_sha256": before["runtime"]["tools/recovery-helper/recovery-helper.exe"],
          "v8": metric([scores[n] for n in names]), "rstudio_historical_trial": metric([scores["rstudio"]]),
          "dmde_historical_free": metric([scores["dmde"]]), "paid_tools_rerun": False,
          "source_runtime_paid_exports_unchanged": True, "selected_cases": names,
          "completion": {"overall_states": [x["status"] for x in stages],
                         "selected_stages_per_case": [len(x["stages"]) for x in stages],
                         "no_incomplete_selected_stages_recorded": all(s["status"] == "complete" for x in stages for s in x["stages"]),
                         "ext4_selected": False},
          "limits": ["Five small synthetic regular-file inputs; no recovery-rate estimate for real damaged devices.",
                     "R-Studio 5 cases and DMDE 2-case subset reuse captured trial/free exports and original settings, not exhaustive current paid-product testing.",
                     "Overall sessions finished_with_warnings despite all selected stages recorded complete; unselected methods were not tested.",
                     "Extra decodable embedded frames are not automatically false positives; false-positive rate is unknown.",
                     "DMDE equivalent-only baseline export contains the complete original JPEG prefix plus trailing bytes; byte-exact result remains false."],
          "restoration": restored_receipt, "rescore_status": receipt["status"],
          "binding_counts": {"runtime_files": len(before["runtime"]), "full_original_corpus_files": len(before["corpus"]), "paid_export_files": paid_count}})
    write(destination / "source-inventory.json", {"schema": 1, "files": scanned, "privacy": {"scanned_files": len(scanned), "omitted_files": 0}})
    write(destination / "inventory.json", {"schema": 1, "files": inventory(destination)})
    print(json.dumps({"status": "passed", "out": str(destination), "inventory_sha256": digest(destination / "inventory.json"), "restoration": restored_receipt}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--restore", type=Path, nargs="+")
    parser.add_argument("--restore-check", type=Path)
    parser.add_argument("--rescore", type=Path)
    parser.add_argument("--ffmpeg", type=Path)
    args = parser.parse_args()
    if args.restore:
        print(json.dumps(restore(args.restore, args.out)))
    elif args.rescore:
        print(json.dumps(rescore(args.rescore, args.out, args.ffmpeg)))
    else:
        if args.restore_check is None or args.ffmpeg is None:
            parser.error("--restore-check and --ffmpeg are required for publication")
        publish(Path.cwd(), args.out, args.restore_check, args.ffmpeg)
