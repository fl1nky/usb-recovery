"""Export compact, explicitly scoped large-media test receipts without payloads."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export(repository, fixtures, verification, destination, expected_runtime, scope):
    if destination.exists():
        raise FileExistsError("Preserve existing evidence")
    data = json.loads(verification.read_text(encoding="utf-8-sig"))
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8-sig"))
    if data["application_sha256"] != expected_runtime or data["manifest_sha256"] != digest(fixtures / "manifest.json") or data["pipeline_used"]:
        raise ValueError("Runtime/input/scope binding differs")
    cases = {case["name"]: case for case in manifest["cases"]}
    if len(data["cases"]) != len(cases):
        raise ValueError("Incomplete scale gate")
    rows = []
    for row in data["cases"]:
        case = cases[row["name"]]
        report_path = verification.parent / row["name"] / "fragmented-media.json"
        report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        if not row["source_unchanged"] or row["candidates"] != case["expected"] or report["Status"] != row["status"]:
            raise ValueError("Observed candidate/status binding differs")
        outputs = []
        for candidate in report["Files"]:
            if candidate["Sha256"] != case["expected_output_sha256"] or candidate["PayloadAuthenticated"] or candidate["DeletionConfirmed"]:
                raise ValueError("Full original/authentication claim differs")
            if data["independent_decode"] and (row["frame_sha256"] != case["expected_video_sha256"] or row["pcm_sha256"] != case["expected_audio_sha256"]):
                raise ValueError("Complete decoder comparison differs")
            outputs.append(dict(sha256=candidate["Sha256"], bytes=candidate["Bytes"], status=candidate["Status"],
                                payload_authenticated=False, deletion_confirmed=False, source_map_ranges=len(candidate["Extents"]),
                                source_map_sha256=hashlib.sha256(json.dumps(candidate["Extents"], sort_keys=True).encode()).hexdigest()))
        rows.append(dict(**row, input_sha256=case["sha256"], input_bytes=case["bytes"], original_sha256=case["expected_output_sha256"],
                         all_original_bytes_present=case["all_original_bytes_present"], outputs=outputs, source_report_sha256=digest(report_path)))
    sources = ["src/Recovery/Recovery/Engines/FragmentedMediaRecovery.cs", "src/Recovery/Recovery/Engines/FragmentedMediaRecovery.Units.cs", "src/Recovery/Recovery/Engines/FragmentedMediaRecovery.Ranges.cs", "tests/FragmentedMediaScaleTests.cs", "tests/build_media_scale_fixtures.py"]
    document = dict(schema=1, scope=scope, pipeline_used=False, helper_used=False, application_sha256=expected_runtime,
                    checks=data["checks"], independent_decode=data["independent_decode"], manifest_sha256=data["manifest_sha256"],
                    verification_sha256=digest(verification), exporter_sha256=digest(Path(__file__)),
                    source_sha256={name: digest(repository / name) for name in sources}, ffmpeg_sha256=manifest["ffmpeg_sha256"],
                    assets=manifest["assets"], cases=rows,
                    limits=["Source-compiled engine and released-application engine are distinct receipts; neither is the public UI/Pipeline.",
                            "Source maps/full hashes are exact synthetic reference comparisons, not payload authenticity/deletion proof.",
                            "Peak working-set values are process cumulative peaks, not isolated per-case measurements.",
                            "Limited negative cases are not complete missing-data determinations.",
                            "No real devices or new commercial-tool comparison; large HEVC/JPEG unmeasured."])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"receipt": str(destination), "cases": len(rows), "exact_originals": sum(bool(row["outputs"]) for row in rows), "checks": data["checks"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "fixtures", "verification", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-runtime", required=True)
    parser.add_argument("--scope", required=True)
    args = parser.parse_args()
    export(args.repository.resolve(), args.fixtures.resolve(), args.verification.resolve(), args.destination.resolve(), args.expected_runtime, args.scope)
