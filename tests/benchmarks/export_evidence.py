"""Publish small derived benchmark metadata, never images, executables or logs."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def publish(repository, build, destination):
    if destination.exists():
        raise ValueError("Evidence destination already exists; preserve previous evidence")
    pending = {}
    prefixes = (str(repository), repository.as_posix())

    def sanitize(value, key=""):
        if isinstance(value, dict):
            return {k: sanitize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [sanitize(v, key) for v in value]
        if isinstance(value, str):
            for prefix in prefixes:
                value = re.sub(re.escape(prefix), ".", value, flags=re.IGNORECASE)
            if key.startswith("decoder_error"):
                # The raw scorer may truncate diagnostics midway through a path.
                # Do not expose the remaining partial personal directory prefix.
                value = re.sub(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\r\n]*", "<local path removed>", value)
            if key in {"path", "original_path", "image", "source", "executable", "SourcePath"}:
                value = value.replace("\\", "/")
                if value.startswith("./"):
                    value = value[2:]
            if re.search(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]", value):
                raise ValueError("Unexpected absolute path in public evidence")
        return value

    def relative(path):
        return path.resolve().relative_to(repository).as_posix()

    def write(name, source, data):
        document = {"derived_evidence_schema": 1,
                    "provenance": {"source": relative(source), "source_sha256": digest(source),
                                   "transformation": "Paths sanitized; explicit not_tested rows and summarized stage evidence added; original source is unchanged."},
                    "data": sanitize(data)}
        file = destination / name
        pending[name] = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        return file

    manifests = {"media": load(build / "corpus-02/manifest.json"), "audio": load(build / "audio-corpus-01/manifest.json")}
    for kind, folder in (("media", "corpus-02"), ("audio", "audio-corpus-01")):
        data = {**manifests[kind], "independent_scope_limits": [
            "Procedural small media; mostly 0xCC image filler; no personal device or production data.",
            "ntfs-deleted-data-runs is a damaged incomplete MFT probe, not normally formatted NTFS.",
            "All original bytes present describes survival; it does not promise recoverability."]}
        write(kind + "-manifest.json", build / folder / "manifest.json", data)

    definitions = [
        ("baseline-media", "media", "baseline-results-02/run.json", "baseline-score-02-revalidated.json"),
        ("final-media", "media", "final-results-01/run.json", "final-score-01.json"),
        ("final-audio", "audio", "final-audio-results-01/run.json", "final-audio-score-01.json"),
        ("trial-rstudio", "media", "rstudio-run.json", "rstudio-score.json"),
        ("trial-dmde", "media", "dmde-run.json", "dmde-score.json")]
    summaries = {}
    scores = {}
    for label, kind, run_name, score_name in definitions:
        run_path, score_path = build / run_name, build / score_name
        run, scored = load(run_path), load(score_path)
        if label.startswith("final-"):
            for component in ("application", "helper", "carver", "manifest"):
                if not run.get(component + "_sha256_before") or run[component + "_sha256_before"] != run.get(component + "_sha256_after"):
                    raise ValueError("Final evidence requires matching before/after runtime and corpus bindings")
        if any(not row.get("source_unchanged") for row in run["results"]):
            raise ValueError("Source preservation is not established")
        if scored["run_sha256"] != digest(run_path):
            raise ValueError("Score does not bind current original run")
        if scored["manifest_sha256"] != digest(build / ("corpus-02" if kind == "media" else "audio-corpus-01") / "manifest.json"):
            raise ValueError("Score does not bind current corpus")
        observed = {x["name"]: x for x in run["results"]}
        rows = []
        for case in manifests[kind]["cases"]:
            row = observed.get(case["name"])
            if row is None:
                rows.append({"name": case["name"], "status": "not_tested", "image_sha256": case["sha256"], "files": []})
                continue
            row = dict(row)
            session_path = run_path.parent / case["name"] / "recovery-session.json"
            if session_path.is_file():
                session = load(session_path)
                row["pipeline_status"] = session.get("Status")
                row["session_evidence"] = {"source": relative(session_path), "sha256": digest(session_path)}
                row["stages"] = [{k: v for k, v in stage.items() if k in {"Key", "Status", "Candidates", "Message", "Warnings"}}
                                 for stage in session.get("Stages", [])]
                searches = []
                for filename in ("fragmented-photo-search.json", "fragmented-media.json"):
                    path = session_path.parent / filename
                    if path.is_file():
                        report = load(path)
                        searches.append({"source": relative(path), "sha256": digest(path),
                                         "data": {k: v for k, v in report.items() if k in {"Schema", "Status", "Candidates", "Recovered", "Skipped", "SourceUnchanged", "SourceSha256"}}})
                row["bounded_search_evidence"] = searches
            rows.append(row)
        run_data = {**run, "results": rows, "not_tested_explicit": True,
                    "runtime_pairing": "before_after" if "application_sha256_before" in run else "legacy_end_only"}
        derived_run = write(label + "-run.json", run_path, run_data)
        cases = {x["name"]: x for x in scored["cases"]}
        score_rows = []
        for case in manifests[kind]["cases"]:
            if case["name"] not in cases:
                score_rows.append({"name": case["name"], "status": "not_tested", "expected": [], "candidates": []})
                continue
            row = dict(cases[case["name"]])
            candidates = []
            for original in row["candidates"]:
                candidate = dict(original)
                message = candidate.pop("decoder_error", None)
                if message:
                    candidate["decoder_error_prefix"] = sanitize(message, "decoder_error")[:200]
                    candidate["decoder_error_sha256"] = hashlib.sha256(message.encode("utf-8")).hexdigest()
                candidates.append(candidate)
            row["candidates"] = candidates
            score_rows.append(row)
        data = {**scored, "cases": score_rows, "derived_run_sha256": hashlib.sha256(pending[derived_run.name]).hexdigest(),
                "run_sha256_is_original_source": True, "not_tested_explicit": True}
        write(label + "-score.json", score_path, data)
        scores[label] = {x["name"]: x for x in score_rows}
        summaries[label] = {"cases_tested": len(observed), "cases_not_tested": len(rows) - len(observed),
                            "exact_originals": sum(x["exact"] for row in scored["cases"] for x in row["expected"]),
                            "decoded_equivalent_originals": sum(x["decoded_equivalent"] for row in scored["cases"] for x in row["expected"]),
                            "incomplete_search_cases": [row["name"] for row in rows if any(stage.get("Status") == "incomplete" for stage in row.get("stages", []))],
                            "source_run_sha256": digest(run_path), "source_score_sha256": digest(score_path)}

    inventory_path = build / "tool-inventory.json"
    inventory = load(inventory_path)
    for tool in inventory["tools"]:
        tool["evaluation_status"] = "not_tested" if tool["edition"] == "Not evaluated" else "generator_and_validator" if tool["name"] == "FFmpeg" else "tested_subset"
    write("tool-inventory.json", inventory_path, inventory)
    environment_path = build / "generator-environment.json"
    environment = load(environment_path)
    environment.pop("executable", None)
    write("generator-environment.json", environment_path, environment)
    write("corpus-validation.json", build / "corpus-validation.json", load(build / "corpus-validation.json"))
    comparisons = []
    for trial in ("trial-rstudio", "trial-dmde"):
        names = [name for name, row in scores[trial].items() if row["status"] != "not_tested"]
        comparisons.append({"trial": trial, "shared_cases": names, "results": {
            label: {"exact": sum(item["exact"] for name in names for item in scores[label][name]["expected"]),
                    "decoded_equivalent": sum(item["decoded_equivalent"] for name in names for item in scores[label][name]["expected"])}
            for label in ("baseline-media", "final-media", trial)}})
    summary = {"schema": 1, "runs": summaries, "shared_case_comparisons": comparisons,
               "ufs": {"status": "not_tested", "cases": [{"name": x["name"], "status": "not_tested"} for x in manifests["media"]["cases"]]},
               "limits": "Synthetic small files and subsets only; no real-device recovery rate, overall competitor ranking or universal replacement claim.",
               "exporter_sha256": digest(Path(__file__)), "counts_are_not_percentages": True}
    pending["summary.json"] = (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    readme = """# Синтетический benchmark: опубликованные доказательства

Только метаданные, SHA256 и разметка синтетических образов. Здесь нет программ, образов дисков, фотографий, переписок или личных файлов

Начать с [summary.json](summary.json). Полный протокол и ограничения: [fragmented-media-benchmark.md](../../../docs/development/fragmented-media-benchmark.md)

Файлы `*-run.json`, `*-score.json` и manifest — производные копии. `provenance.source_sha256` относится к неизменённому локальному исходнику; `data.run_sha256` внутри score также относится к исходному run. `derived_run_sha256` привязывает опубликованную копию. Абсолютные пути заменены относительными, ошибки декодера сокращены с сохранением SHA текста. Данные стадий дополнительно взяты из отдельно хешированных recovery-session/report файлов

`not_tested` означает, что сравнение не выполнено. `trial_not_exported` означает ограничение пробной версии. `incomplete_search_cases` сохраняет случаи с исчерпанным бюджетом поиска. Равные декодированные пиксели учитываются отдельно от полного SHA файла. Декодируемые встроенные кадры не объявляются ложными находками

Все программы анализировали одинаковые байты соответствующего manifest. Генераторы и проверки находятся в родительском каталоге. Конкретные результаты не устанавливают общий рейтинг платных программ и не проверяют настоящие устройства
"""
    pending["README.md"] = readme.encode("utf-8")
    checksums = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(pending.items())}
    pending["sha256.json"] = (json.dumps(checksums, indent=2) + "\n").encode("utf-8")
    destination.mkdir(parents=True)
    for name, data in pending.items():
        (destination / name).write_bytes(data)
    print(json.dumps({"destination": str(destination), "files": len(checksums) + 1,
                      "bytes": sum(file.stat().st_size for file in destination.iterdir()), "summary": summaries}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--build", type=Path, default=Path(".build/benchmarks-v4"))
    parser.add_argument("--destination", type=Path, default=Path("tests/benchmarks/evidence"))
    args = parser.parse_args()
    publish(args.repository.resolve(), args.build.resolve(), args.destination.resolve())
