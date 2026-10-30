"""Publish append-only V7 media receipts bound to the actually tested runtime."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from export_v6_evidence import metrics


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export(repository, build, destination, app, helper, v6_run, v6_score):
    if destination.exists():
        raise FileExistsError("Preserve published receipts")
    sources = {}
    for kind in ("media", "audio", "hevc-pipeline", "unit-pipeline"):
        sources[kind + "-run.json"] = build / ("final-" + kind + "-results-01/run.json")
        sources[kind + "-score.json"] = build / ("final-" + kind + "-score-01.json")
        sources[kind + "-provenance.json"] = build / ("final-" + kind + "-provenance-01.json")
    sources.update({"v6-unit-run.json": v6_run, "v6-unit-score.json": v6_score,
                    "unit-engine-proof.json": build / "unit-engine-proof.json",
                    "runtime-before.json": build / "runtime-before.json", "runtime-after.json": build / "runtime-after.json",
                    "unit-manifest.json": build / "unit-corpus-final-01/manifest.json"})
    sources.update({"media-manifest.json": repository / ".build/benchmarks-v4/corpus-02/manifest.json",
                    "audio-manifest.json": repository / ".build/benchmarks-v4/audio-corpus-01/manifest.json",
                    "hevc-pipeline-manifest.json": repository / ".build/benchmarks-v6/hevc-corpus-final-02/manifest.json"})
    documents = {name: load(path) for name, path in sources.items()}
    stages = []
    for kind in ("media", "audio", "hevc-pipeline", "unit-pipeline"):
        run, score, proof = (documents[kind + suffix] for suffix in ("-run.json", "-score.json", "-provenance.json"))
        if any(run[key] != app for key in ("application_sha256", "application_sha256_before", "application_sha256_after")):
            raise ValueError("Wrong release app: " + kind)
        if any(run[key] != helper for key in ("helper_sha256", "helper_sha256_before", "helper_sha256_after")):
            raise ValueError("Wrong release helper: " + kind)
        if run["manifest_sha256_before"] != run["manifest_sha256_after"] or run["carver_sha256_before"] != run["carver_sha256_after"]:
            raise ValueError("Input/carver changed: " + kind)
        if any(row["status"] != "completed" or not row["source_unchanged"] for row in run["results"]):
            raise ValueError("Incomplete outer pipeline cannot become final evidence: " + kind)
        if score["run_sha256"] != digest(sources[kind + "-run.json"]) or score["manifest_sha256"] != run["manifest_sha256"]:
            raise ValueError("Score binding differs: " + kind)
        if not proof["pipeline_used"] or proof["status"] != "passed" or proof["application_sha256"] != app or proof["helper_sha256"] != helper or proof["run_sha256"] != score["run_sha256"]:
            raise ValueError("Catalog/source proof differs: " + kind)
        for row in run["results"]:
            path = sources[kind + "-run.json"].parent / row["name"] / "recovery-session.json"
            session = load(path)
            if session["SourceSha256"] != row["image_sha256"]:
                raise ValueError("Stage/session source differs")
            stages.append(dict(corpus=kind, case=row["name"], session_status=session["Status"], session_sha256=digest(path),
                               stages=[dict(key=s["Key"], status=s["Status"], candidates=s["Candidates"], warnings=s["Warnings"]) for s in session["Stages"]]))
    v6, old_score = documents["v6-unit-run.json"], documents["v6-unit-score.json"]
    if v6["application_sha256"] != "77ce273fc758ca8095e3c24ff8b9bb6c6475ed3cab8fb08b25a45eb332127c51" or v6["helper_sha256"] != "253ea81928b28e007d9f1ec60c51830c8cc89d897d04430e4684d9ff8c1966e6":
        raise ValueError("V6 baseline is not the pinned released runtime")
    if any(row["status"] != "completed" or not row["source_unchanged"] for row in v6["results"]) or old_score["run_sha256"] != digest(v6_run) or old_score["manifest_sha256"] != documents["unit-pipeline-run.json"]["manifest_sha256"]:
        raise ValueError("V6 actual comparison is incomplete/unbound")
    for key, expected in (("application_sha256_before", v6["application_sha256"]), ("application_sha256_after", v6["application_sha256"]), ("helper_sha256_before", v6["helper_sha256"]), ("helper_sha256_after", v6["helper_sha256"])):
        if v6[key] != expected:
            raise ValueError("V6 actual runtime changed")
    for row in v6["results"]:
        path = v6_run.parent / row["name"] / "recovery-session.json"
        session = load(path)
        if session["SourceSha256"] != row["image_sha256"]:
            raise ValueError("V6 stage/session source differs")
        stages.append(dict(corpus="actual-v6-units", case=row["name"], session_status=session["Status"], session_sha256=digest(path),
                           stages=[dict(key=s["Key"], status=s["Status"], candidates=s["Candidates"], warnings=s["Warnings"]) for s in session["Stages"]]))
    before, after = documents["runtime-before.json"]["files"], documents["runtime-after.json"]["files"]
    if {r["path"]: (r["sha256"], r["bytes"]) for r in before} != {r["path"]: (r["sha256"], r["bytes"]) for r in after}:
        raise ValueError("Frozen runtime files changed")
    engine = documents["unit-engine-proof.json"]
    if engine["application_sha256"] != app or engine["pipeline_used"] or engine["helper_used"] or engine["checks"] != 826:
        raise ValueError("Engine-only proof binding/scope differs")
    baseline = repository / "tests/benchmarks/evidence-v6"
    baseline_hashes = load(baseline / "sha256.json")
    previous = {}
    for kind in ("media", "audio", "hevc-pipeline"):
        filename = kind + "-score.json"
        if digest(baseline / filename) != baseline_hashes[filename]:
            raise ValueError("Historical V6 evidence changed")
        previous[kind] = metrics(load(baseline / filename)["data"])
    incomplete = [dict(corpus=row["corpus"], case=row["case"], methods=[s["key"] for s in row["stages"] if s["status"] != "complete"])
                  for row in stages if any(s["status"] != "complete" for s in row["stages"])]
    decoded_counts = {}
    for kind in ("media", "audio", "hevc-pipeline", "unit-pipeline"):
        name = "unit-manifest.json" if kind == "unit-pipeline" else kind + "-manifest.json"
        if digest(sources[name]) != documents[kind + "-run.json"]["manifest_sha256"]:
            raise ValueError("Published manifest differs: " + kind)
        assets = {row["name"]: row for row in documents[name]["assets"]}
        decoded_counts[kind] = 0
        for row in documents[kind + "-score.json"]["cases"]:
            for target in row["expected"]:
                asset = assets[target["asset"]]
                matches = [candidate for candidate in row["candidates"]
                           if candidate["valid"] is True
                           and candidate["decoded_sha256"] == asset.get("decoded_rgb_sha256", asset.get("decoded_frames_sha256"))
                           and (asset.get("decoded_audio_sha256") is None or candidate.get("decoded_audio_sha256") == asset["decoded_audio_sha256"])]
                decoded_counts[kind] += bool(matches)
    summary = dict(schema=1, application_sha256=app, helper_sha256=helper, exporter_sha256=digest(Path(__file__)),
                   scope="Actual public RecoveryPipeline on 56 owned synthetic regular images; separate actual V6 comparison on 17. No physical devices or fresh commercial-tool run.",
                   results={kind: metrics(documents[kind + "-score.json"]) for kind in ("media", "audio", "hevc-pipeline", "unit-pipeline")},
                   independently_validated_complete_frame_pcm_targets=decoded_counts,
                   actual_v6_shared=previous, actual_v6_new_units=metrics(old_score),
                   actual_v6_application_sha256=v6["application_sha256"], actual_v6_helper_sha256=v6["helper_sha256"],
                   unit_engine_checks=826, unit_engine_scope="Actual released app engine; not UI or public pipeline", runtime_files_unchanged=len(before),
                   pipeline_cases_with_incomplete_methods=incomplete,
                   commercial_status="not_tested for new unit/AAC/HEVC corpus; historical limited demo evidence remains separately scoped in evidence-v6",
                   limits=["Every reported exact result is bound to an independent full original hash; decoded equivalence uses all frames/PCM.",
                           "Changed current candidates and unrelated embedded media are not silently counted as recovered originals.",
                           "A completed outer pipeline can include incomplete selected methods; their exact ledger is included.",
                           "Allocation-unit fallback has explicit 16MiB/cell/state/metadata limits and cannot infer unanchored opaque interiors or arbitrary missing bytes.",
                           "Independent tail-moov 64MiB padded control reached its search limit; no universal disk-size recovery guarantee.",
                           "Syntax, decoder acceptance, source maps and synthetic tests do not prove historical ownership/deletion or authenticate opaque entropy.",
                           "No universal paid-tool replacement, physical-device recovery rate or speed-superiority claim."])
    def sanitize(value):
        if isinstance(value, dict):
            return {key: sanitize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if isinstance(value, str):
            for prefix in (str(repository), repository.as_posix()):
                value = re.sub(re.escape(prefix), ".", value, flags=re.I)
            if re.search(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]", value):
                raise ValueError("Unexpected absolute path in public evidence")
        return value
    pending = {}
    for name, data in documents.items():
        source = sources[name]
        envelope = dict(derived_evidence_schema=1, provenance=dict(source=source.relative_to(repository).as_posix(), source_sha256=digest(source), transformation="Local paths sanitized only; original receipt preserved"), data=sanitize(data))
        pending[name] = (json.dumps(envelope, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    pending["pipeline-stages.json"] = (json.dumps(dict(schema=1, application_sha256=app, cases=stages), indent=2) + "\n").encode()
    pending["summary.json"] = (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    pending["sha256.json"] = (json.dumps({name: hashlib.sha256(raw).hexdigest() for name, raw in pending.items()}, indent=2) + "\n").encode()
    destination.mkdir(parents=True)
    for name, raw in pending.items():
        (destination / name).write_bytes(raw)
    print(json.dumps({"destination": str(destination), "files": len(pending), "results": summary["results"], "actual_v6_new_units": summary["actual_v6_new_units"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "build", "destination", "v6-unit-run", "v6-unit-score"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-app", required=True)
    parser.add_argument("--expected-helper", required=True)
    args = parser.parse_args()
    export(args.repository.resolve(), args.build.resolve(), args.destination.resolve(), args.expected_app, args.expected_helper, args.v6_unit_run.resolve(), args.v6_unit_score.resolve())
