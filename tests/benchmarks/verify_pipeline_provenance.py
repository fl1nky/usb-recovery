"""Verify actual catalog media maps from a completed public pipeline benchmark."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def verify(corpus, run_file, output):
    if output.exists():
        raise FileExistsError("Preserve existing proof")
    manifest, run = load(corpus / "manifest.json"), load(run_file)
    if digest(corpus / "manifest.json") != run["manifest_sha256"]:
        raise ValueError("Executed manifest changed")
    cases = {row["name"]: row for row in manifest["cases"]}
    observed = []
    for result in run["results"]:
        case = cases[result["name"]]
        image = corpus / case["image"]
        if result["status"] != "completed" or not result["source_unchanged"] or digest(image) != case["sha256"]:
            raise ValueError("Pipeline case was incomplete or its source changed")
        root = run_file.parent / case["name"]
        session, catalog, media = load(root / "recovery-session.json"), load(root / "files-index.json"), load(root / "fragmented-media.json")
        if session["SourceSha256"] != case["sha256"] or session["SourceBytes"] != image.stat().st_size:
            raise ValueError("Saved session source binding differs")
        if "engine_expected_candidates" in case and media["Candidates"] != case["engine_expected_candidates"]:
            raise ValueError("Strict media stage differs from independent expectation")
        records = []
        for candidate in media["Files"]:
            if candidate["PayloadAuthenticated"] or candidate["DeletionConfirmed"]:
                raise ValueError("Structural candidate falsely authenticated")
            item = next(row for row in catalog["Items"] if row["Sha256"] == candidate["Sha256"])
            relative = item["SourceCandidatePath"]
            path = (root / relative).resolve()
            if not path.is_relative_to(root.resolve()) or digest(path) != item["Sha256"]:
                raise ValueError("Catalog provenance candidate differs")
            logical = 0
            with image.open("rb") as source, path.open("rb") as payload:
                for extent in item["SourceRanges"]:
                    start, remaining = extent["Offset"], extent["Length"]
                    if start < 0 or remaining <= 0 or start + remaining > image.stat().st_size:
                        raise ValueError("Catalog range bounds invalid")
                    source.seek(start)
                    while remaining:
                        count = min(65536, remaining)
                        if source.read(count) != payload.read(count):
                            raise ValueError("Catalog source range does not reproduce candidate bytes")
                        logical += count; remaining -= count
                if payload.read(1):
                    raise ValueError("Catalog map does not cover full payload")
            if logical != item["Bytes"] or logical != candidate["Bytes"] or not relative.startswith("fragmented-media/"):
                raise ValueError("Catalog length/origin mismatch")
            records.append(dict(sha256=item["Sha256"], bytes=item["Bytes"], source_candidate=relative,
                                source_ranges=item["SourceRanges"], source_ranges_match_current_image=True,
                                method=item["Method"], status=item["Status"], quality=item["Quality"],
                                payload_authenticated=False, deletion_confirmed=False))
        observed.append(dict(name=case["name"], pipeline_status=session["Status"], source_unchanged=True,
                             catalog_candidates=catalog["Candidates"], unique_catalog_items=len(catalog["Items"]),
                             media_candidates=len(records), verified_media_maps=records))
    document = dict(schema=1, status="passed", application_sha256=run["application_sha256"], helper_sha256=run["helper_sha256"],
                    run_sha256=digest(run_file), manifest_sha256=digest(corpus / "manifest.json"), verifier_sha256=digest(Path(__file__)),
                    pipeline_used=True, cases=observed,
                    scope="Actual public RecoveryPipeline results and persisted catalog/session. Every strict media candidate is rebound to its current image ranges byte for byte. This verifies provenance and observed candidate classification, not historical ownership or CABAC authenticity.")
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"proof": str(output), "cases": len(observed), "media_maps": sum(row["media_candidates"] for row in observed)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("corpus", "run", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    verify(args.corpus.resolve(), args.run.resolve(), args.output.resolve())
