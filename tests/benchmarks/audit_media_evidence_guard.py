"""Targeted untrusted-envelope guard probes; no recovery program is executed."""
import argparse
import json
from pathlib import Path
import shutil
from unittest.mock import patch

import export_media_comparison as exporter


def audit(restored, ffmpeg, destination):
    destination.mkdir(parents=True, exist_ok=False)
    before = exporter.inventory(restored)
    results = []
    cases = ["restored_scorer_canary", "wrong_ffmpeg", "last_scorer_hash", "last_ffmpeg_hash",
             "parent_name", "slash_name", "backslash_name", "drive_name", "reserved_name", "duplicate_name"]
    bad_names = {"parent_name": "../escape", "slash_name": "one/two", "backslash_name": "one\\two",
                 "drive_name": "c:escape", "reserved_name": "con"}
    for number, case in enumerate(cases):
        root = destination / case
        (root / "sources").mkdir(parents=True)
        (root / "runs/v8").mkdir(parents=True)
        shutil.copy2(restored / "sources/score_media_results.py", root / "sources/score_media_results.py")
        shutil.copytree(restored / "scores", root / "scores")
        collection = exporter.read(restored / "runs/v8/collection.json")
        marker = root / "CODE_EXECUTED"
        if case == "restored_scorer_canary":
            (root / "sources/score_media_results.py").write_text(
                "from pathlib import Path\nPath(" + repr(str(marker.resolve())) + ").write_text('executed')\n", encoding="utf-8")
        selected_ffmpeg = ffmpeg
        if case == "wrong_ffmpeg":
            selected_ffmpeg = root / "not-a-tool.txt"
            selected_ffmpeg.write_text("untrusted executable stand-in", encoding="utf-8")
        if case in ("last_scorer_hash", "last_ffmpeg_hash"):
            report_path = root / "scores/dmde.json"
            report = exporter.read(report_path)
            report["scorer_sha256" if case == "last_scorer_hash" else "ffmpeg_sha256"] = "0" * 64
            report_path.write_text(json.dumps(report), encoding="utf-8")
        if case in bad_names:
            collection["results"][0]["name"] = bad_names[case]
        if case == "duplicate_name":
            collection["results"][1]["name"] = collection["results"][0]["name"]
        exporter.write(root / "runs/v8/collection.json", collection)
        real_spec = exporter.importlib.util.spec_from_file_location
        with patch.object(exporter.importlib.util, "spec_from_file_location", wraps=real_spec) as loading:
            with patch("subprocess.run", side_effect=AssertionError("SUBPROCESS_BEFORE_GUARD")) as child:
                try:
                    exporter.rescore(root, root / "must-not-create", selected_ffmpeg)
                except ValueError as exc:
                    code = str(exc)
                else:
                    raise AssertionError("UNTRUSTED_INPUT_ACCEPTED: " + case)
        assert not marker.exists(), "ARCHIVED_PYTHON_EXECUTED"
        assert loading.call_count == child.call_count == 0, "CODE_LOADED_BEFORE_ALL_BINDINGS"
        assert not (root / "must-not-create").exists(), "WRITE_BEFORE_GUARD"
        results.append({"name": case, "status": "passed", "error": code,
                        "module_loads": loading.call_count, "subprocesses": child.call_count,
                        "canary_executed": False})

    # Exercise the real post-restoration filesystem boundary when this account
    # may create Windows symbolic links. Never touch an original recovered file.
    root = destination / "post_restore_link"
    root.mkdir()
    owned_target = destination / "owned-target.jpg"
    owned_target.write_bytes(b"owned guard fixture")
    link = root / "candidate.jpg"
    try:
        link.symlink_to(owned_target.resolve())
    except OSError as exc:
        results.append({"name": "post_restore_link", "status": "not_tested",
                        "reason": "Account cannot create symbolic links", "winerror": getattr(exc, "winerror", None)})
    else:
        try:
            exporter.check_ancestors(link)
        except ValueError as exc:
            assert str(exc) == "RESTORE_PATH_LINK"
        else:
            raise AssertionError("POST_RESTORE_LINK_ACCEPTED")
        results.append({"name": "post_restore_link", "status": "passed", "error": "RESTORE_PATH_LINK"})
    assert before == exporter.inventory(restored), "ORIGINAL_RESTORED_PROOF_CHANGED"
    report = {"schema": 1, "scope": "Publication/scoring guard only; no application/helper/paid-program run.",
              "exporter_sha256": exporter.digest(Path(exporter.__file__)),
              "audit_sha256": exporter.digest(Path(__file__)),
              "passed": sum(x["status"] == "passed" for x in results),
              "not_tested": sum(x["status"] == "not_tested" for x in results), "results": results,
              "original_restored_files_unchanged": True}
    exporter.write(destination / "guard-check.json", report)
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restored", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    audit(args.restored, args.ffmpeg, args.out)
