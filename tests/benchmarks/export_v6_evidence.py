"""Publish append-only, path-sanitized receipts for the verified release binary.

Existing v4/v5 evidence is never rewritten. Engineering snapshots cannot be
mistaken for release receipts because every new run must match explicit hashes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metrics(score, selected=None):
    rows = [row for row in score["cases"] if selected is None or row["name"] in selected]
    expected = [target for row in rows for target in row["expected"]]
    return dict(cases=len(rows), expected_targets=len(expected), exact=sum(row["exact"] for row in expected),
                decoded_equivalent=sum(row["decoded_equivalent"] for row in expected),
                all_original_bytes_present=sum(row["all_original_bytes_present"] for row in expected),
                complete_cases=sum(bool(row["expected"]) and all(target["decoded_equivalent"] for target in row["expected"]) for row in rows))


def publish(repository, build, destination, app, helper, suffix):
    if destination.exists():
        raise FileExistsError("Preserve existing published evidence")
    sources = {
        "media-run.json": build / ("final-media-results-" + suffix) / "run.json",
        "media-score.json": build / ("final-media-score-" + suffix + ".json"),
        "audio-run.json": build / ("final-audio-results-" + suffix) / "run.json",
        "audio-score.json": build / ("final-audio-score-" + suffix + ".json"),
        "hevc-pipeline-run.json": build / ("final-hevc-pipeline-results-" + suffix) / "run.json",
        "hevc-pipeline-score.json": build / ("final-hevc-pipeline-score-" + suffix + ".json"),
        "hevc-pipeline-provenance.json": build / ("final-hevc-pipeline-provenance-" + suffix + ".json"),
        "audio-pipeline-provenance.json": build / ("final-audio-pipeline-provenance-" + suffix + ".json"),
        "hevc-engine-proof.json": build / ("final-hevc-proof-" + suffix + ".json"),
        "hevc-pipeline-manifest.json": build / "hevc-corpus-final-02/manifest.json",
        "v5-audio-run.json": build / "v5-audio-baseline/run.json",
        "v5-audio-score.json": build / "v5-audio-score.json",
        "trial-rstudio-rescore.json": build / "trial-rstudio-rescore.json",
        "trial-dmde-rescore.json": build / "trial-dmde-rescore.json",
        "runtime-before.json": build / ("final-freeze-before-" + suffix + ".json"),
        "runtime-after.json": build / ("final-freeze-after-" + suffix + ".json"),
    }
    documents = {name: load(path) for name, path in sources.items()}
    for name in ("media-run.json", "audio-run.json", "hevc-pipeline-run.json"):
        run = documents[name]
        if any(run[key] != app for key in ("application_sha256", "application_sha256_before", "application_sha256_after")):
            raise ValueError("Release application binding differs: " + name)
        if any(run[key] != helper for key in ("helper_sha256", "helper_sha256_before", "helper_sha256_after")):
            raise ValueError("Release helper binding differs: " + name)
        if run["manifest_sha256_before"] != run["manifest_sha256_after"] or run["carver_sha256_before"] != run["carver_sha256_after"]:
            raise ValueError("Benchmark input/runtime changed")
        if any(row["status"] != "completed" or not row["source_unchanged"] for row in run["results"]):
            raise ValueError("Incomplete pipeline benchmark cannot become final release evidence")
    for label in ("media", "audio", "hevc-pipeline", "v5-audio"):
        run, score = documents[label + "-run.json"], documents[label + "-score.json"]
        if score["run_sha256"] != digest(sources[label + "-run.json"]) or score["manifest_sha256"] != run["manifest_sha256"]:
            raise ValueError("Score is not bound to executed run")
    engine, provenance = documents["hevc-engine-proof.json"], documents["hevc-pipeline-provenance.json"]
    if engine["application_sha256_before"] != app or engine["application_sha256_after"] != app or engine["pipeline_used"] or not provenance["pipeline_used"] or provenance["application_sha256"] != app:
        raise ValueError("HEVC engine/pipeline scopes or binaries differ")
    for label, name in (("audio", "audio-pipeline-provenance.json"), ("hevc-pipeline", "hevc-pipeline-provenance.json")):
        proof = documents[name]
        if proof["application_sha256"] != app or proof["helper_sha256"] != helper or proof["run_sha256"] != digest(sources[label + "-run.json"]):
            raise ValueError("Pipeline provenance proof binding differs")
    if digest(sources["hevc-pipeline-manifest.json"]) != documents["hevc-pipeline-score.json"]["manifest_sha256"]:
        raise ValueError("HEVC adapted ground truth differs")
    before, after = documents["runtime-before.json"]["files"], documents["runtime-after.json"]["files"]
    if {row["path"]: (row["sha256"], row["bytes"]) for row in before} != {row["path"]: (row["sha256"], row["bytes"]) for row in after}:
        raise ValueError("Frozen runtime inventory changed")
    paid = []
    media_names = {row["name"] for row in documents["media-score.json"]["cases"]}
    for label in ("rstudio", "dmde"):
        score = documents["trial-" + label + "-rescore.json"]
        if score["manifest_sha256"] != documents["media-score.json"]["manifest_sha256"]:
            raise ValueError("Commercial export belongs to a different corpus")
        tested = {row["name"] for row in score["cases"]}
        if not tested <= media_names:
            raise ValueError("Commercial export is outside shared corpus")
        paid.append(dict(tool=score["tool"], previously_tested_cases=sorted(tested), old_exports_rescored=True,
                         fresh_gui_run=False, commercial=metrics(score), recovery_on_same_cases=metrics(documents["media-score.json"], tested),
                         media_not_tested_cases=sorted(media_names - tested), audio_status="not_tested", hevc_status="not_tested"))
    summary = dict(schema=1, application_sha256=app, helper_sha256=helper, exporter_sha256=digest(Path(__file__)),
                   media=metrics(documents["media-score.json"]), audio=metrics(documents["audio-score.json"]),
                   actual_v5_audio=metrics(documents["v5-audio-score.json"]),
                   actual_v5_application_sha256=documents["v5-audio-run.json"]["application_sha256"],
                   actual_v5_helper_sha256=documents["v5-audio-run.json"]["helper_sha256"],
                   hevc_pipeline=metrics(documents["hevc-pipeline-score.json"]),
                   hevc_engine_checks=engine["checks"], hevc_engine_scope="direct application engine, not the public pipeline",
                   hevc_pipeline_scope="actual public pipeline plus persisted catalog and byte-for-byte source maps",
                   commercial_subsets=paid, runtime_files_unchanged=len(before),
                   limits=["Owned synthetic regular files only; mostly 0xCC filler and short encoder clips.",
                           "Surviving original bytes do not imply uniquely recoverable geometry.",
                           "AAC search: 512-byte aligned starts and surviving video/container affine offsets; no arbitrary within-sample reconstruction.",
                           "Opaque syntactically valid AAC/CABAC changes cannot be authenticated without an independent original/hash.",
                           "Commercial values are existing limited demo exports rescored on shared cases; new AAC/HEVC commercial comparisons were not executed.",
                           "No physical-device recovery rate, speed superiority or universal replacement claim."])
    stage_rows = []
    for kind in ("media", "audio", "hevc-pipeline"):
        run_path = sources[kind + "-run.json"]
        for result in documents[kind + "-run.json"]["results"]:
            session_path = run_path.parent / result["name"] / "recovery-session.json"
            session = load(session_path)
            if session["SourceSha256"] != result["image_sha256"]:
                raise ValueError("Saved stage source binding differs")
            stage_rows.append(dict(corpus=kind, case=result["name"], session_status=session["Status"],
                                   session_sha256=digest(session_path),
                                   stages=[dict(key=row["Key"], status=row["Status"], candidates=row["Candidates"],
                                                warnings=row["Warnings"], checkpoint_sequence=row.get("CheckpointSequence", 0))
                                           for row in session["Stages"]]))
    summary["pipeline_cases_with_incomplete_methods"] = [dict(corpus=row["corpus"], case=row["case"],
                                                              methods=[stage["key"] for stage in row["stages"] if stage["status"] != "complete"])
                                                          for row in stage_rows if any(stage["status"] != "complete" for stage in row["stages"])]
    prefixes = (str(repository), repository.as_posix())

    def sanitize(value, key=""):
        if isinstance(value, dict):
            return {sanitize(k): sanitize(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [sanitize(v, key) for v in value]
        if not isinstance(value, str):
            return value
        for prefix in prefixes:
            value = re.sub(re.escape(prefix), ".", value, flags=re.IGNORECASE)
        if key.startswith("decoder_error"):
            value = re.sub(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\r\n]*", "<local path removed>", value)
        if re.search(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]", value):
            raise ValueError("Unexpected absolute path in public evidence")
        return value

    pending = {}
    for name, document in documents.items():
        source = sources[name]
        envelope = dict(derived_evidence_schema=1, provenance=dict(source=source.relative_to(repository).as_posix(), source_sha256=digest(source),
                                                                  transformation="Paths sanitized only; original benchmark receipt preserved"), data=sanitize(document))
        pending[name] = (json.dumps(envelope, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    pending["pipeline-stages.json"] = (json.dumps(dict(schema=1, application_sha256=app, cases=stage_rows,
                                                     scope="Actual persisted method states. A completed outer pipeline does not mean every selected recovery method completed."),
                                                ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    pending["summary.json"] = (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    pending["sha256.json"] = (json.dumps({name: hashlib.sha256(raw).hexdigest() for name, raw in pending.items()}, indent=2) + "\n").encode("utf-8")
    destination.mkdir(parents=True)
    for name, raw in pending.items():
        (destination / name).write_bytes(raw)
    print(json.dumps({"destination": str(destination), "files": len(pending), "media_exact": summary["media"]["exact"], "audio_exact": summary["audio"]["exact"], "hevc_pipeline_exact": summary["hevc_pipeline"]["exact"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "build", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-app", required=True)
    parser.add_argument("--expected-helper", required=True)
    parser.add_argument("--suffix", default="03")
    args = parser.parse_args()
    publish(args.repository.resolve(), args.build.resolve(), args.destination.resolve(), args.expected_app, args.expected_helper, args.suffix)
