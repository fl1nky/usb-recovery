"""Score exported candidates against independent originals, without assuming names.

Exact original SHA, decoded equivalence, partial/damaged output, decodable nonmatching
media, and files not exported because of a trial limit are separate outcomes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from PIL import Image, __version__ as pillow_version


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def decode(path, ffmpeg):
    try:
        with Image.open(path) as image:
            image.load()
            return {"kind": "image", "decoded_sha256": sha(image.convert("RGB").tobytes()), "valid": True}
    except Exception:
        pass
    try:
        result = subprocess.run([str(ffmpeg), "-v", "error", "-nostdin", "-i", str(path), "-map", "0:v", "-an", "-f", "framemd5", "-"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    except subprocess.TimeoutExpired:
        return {"kind": "decoder_timeout", "decoded_sha256": None, "valid": None,
                "decoder_error": "Video validation exceeded 20 seconds; recovery outcome is unvalidated."}
    lines = [line for line in result.stdout.splitlines() if line and not line.startswith(b"#")]
    if result.returncode == 0 and lines and not result.stderr.strip():
        try:
            audio = subprocess.run([str(ffmpeg), "-v", "error", "-nostdin", "-i", str(path), "-map", "0:a", "-c:a", "pcm_s16le", "-f", "s16le", "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        except subprocess.TimeoutExpired:
            return {"kind": "video", "decoded_sha256": sha(b"\n".join(lines)), "valid": True,
                    "decoded_audio_sha256": None, "audio_validation": "decoder_timeout"}
        return {"kind": "video", "decoded_sha256": sha(b"\n".join(lines)), "valid": True,
                "decoded_audio_sha256": sha(audio.stdout) if audio.returncode == 0 and audio.stdout else None}
    return {"kind": "unknown_or_damaged", "decoded_sha256": None, "valid": False,
            "decoder_error": result.stderr.decode("utf-8", errors="replace")[:1000]}


def score(corpus, run_file, ffmpeg, output):
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8-sig"))
    run = json.loads(run_file.read_text(encoding="utf-8-sig"))
    if run["manifest_sha256"] != digest(corpus / "manifest.json"):
        raise ValueError("Benchmark corpus differs from executed manifest")
    assets = {x["name"]: x for x in manifest["assets"]}
    cases = {x["name"]: x for x in manifest["cases"]}
    rows = []
    for result in run["results"]:
        sample = cases[result["name"]]
        image = corpus / sample["image"]
        if digest(image) != sample["sha256"] or result["image_sha256"] != sample["sha256"]:
            raise ValueError("Benchmark source changed")
        expected = [assets[x["asset"]] for x in sample["expected"]]
        candidates = []
        for item in result.get("files", []):
            path = Path(item["path"])
            if digest(path) != item["sha256"]:
                raise ValueError("Exported candidate changed")
            decoded = decode(path, ffmpeg)
            exact = [x["name"] for x in expected if x["sha256"] == item["sha256"]]
            equivalent = [x["name"] for x in expected if decoded["decoded_sha256"] is not None and
                          decoded["decoded_sha256"] == x.get("decoded_rgb_sha256", x.get("decoded_frames_sha256")) and
                          (x.get("decoded_audio_sha256") is None or x["decoded_audio_sha256"] == decoded.get("decoded_audio_sha256"))]
            category = "exact_original" if exact else "decoded_equivalent" if equivalent else "decodable_nonmatching" if decoded["valid"] else "unvalidated_candidate" if decoded["valid"] is None else "damaged_or_nonmedia"
            candidates.append({**item, **decoded, "benchmark_class": category, "matches": exact or equivalent})
        recovered = []
        for item in sample["expected"]:
            asset = assets[item["asset"]]
            matching = [x for x in candidates if asset["name"] in x["matches"]]
            recovered.append({"asset": asset["name"], "all_original_bytes_present": item["all_original_bytes_present"],
                              "exact": any(x["benchmark_class"] == "exact_original" for x in matching),
                              "decoded_equivalent": bool(matching),
                              "trial_not_exported": bool(result.get("trial_not_exported", False))})
        rows.append({"name": sample["name"], "status": result["status"], "elapsed_ms": result.get("elapsed_ms"),
                     "source_unchanged": result["source_unchanged"], "expected": recovered,
                     "candidate_count": len(candidates), "decodable_nonmatching": sum(x["benchmark_class"] == "decodable_nonmatching" for x in candidates),
                     "damaged_or_nonmedia": sum(x["benchmark_class"] == "damaged_or_nonmedia" for x in candidates),
                     "unvalidated_candidates": sum(x["benchmark_class"] == "unvalidated_candidate" for x in candidates),
                     "false_positive_rate": None, "false_positive_note": "Extra media may be valid embedded frames; they are not automatically false positives.", "candidates": candidates})
    report = {"schema": 1, "tool": run["tool"], "edition": run["edition"], "label": run["label"],
              "manifest_sha256": digest(corpus / "manifest.json"), "run_sha256": digest(run_file),
              "ffmpeg_sha256": digest(ffmpeg), "cases": rows,
              "scorer_sha256": digest(Path(__file__)), "python_version": sys.version, "pillow_version": pillow_version,
              "scope": "Generated regular files only; decode/exact hashes do not establish real-device recovery rate."}
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"report": str(output), "cases": len(rows),
                      "exact": sum(x["exact"] for row in rows for x in row["expected"]),
                      "decoded_equivalent": sum(x["decoded_equivalent"] for row in rows for x in row["expected"])}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    score(args.corpus.resolve(), args.run.resolve(), args.ffmpeg.resolve(), args.output.resolve())
