"""Bind portable checks to the exact delivered bytes, without device access.

This validates captured evidence; it does not rerun recovery tests. Historical
green reports with no matching binary/source/log hashes are rejected.
"""
from pathlib import Path
import datetime as dt
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
READY_NAME = "\u0413\u043e\u0442\u043e\u0432\u0430\u044f \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u0430"
COUNT = re.compile(r"\b(\d+)\s+(?:[A-Za-z-]+\s+){0,4}(?:assertions|checks)\b", re.I)
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
DEPENDENCIES = {"USB-Recovery.exe", "tools/recovery-helper/recovery-helper.exe",
                "tools/testdisk-7.2/photorec_win.exe", "tools/testdisk-7.2/testdisk_win.exe",
                "package-sha256.json", "tools/recovery-helper/runtime-SHA256.json"}


class ValidationError(ValueError):
    pass


def require(condition, description):
    if not condition:
        raise ValidationError(description)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def safe(base, relative):
    require(isinstance(relative, str) and relative and not relative.startswith(("/", "\\")), "absolute evidence path")
    require("\\" not in relative and ":" not in relative and ".." not in relative.split("/"), "unsafe evidence path")
    base = Path(base).resolve()
    result = base / relative
    require(result.resolve().is_relative_to(base), "evidence path escapes artifact")
    require(not result.is_symlink(), "evidence symlink")
    return result


def stamp(value):
    require(isinstance(value, str), "missing timestamp")
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "timestamp has no timezone")
    return result


def actual_count(summary):
    require(isinstance(summary, str) and "FAIL " not in summary, "invalid test summary")
    match = COUNT.search(summary)
    require(match is not None and int(match[1]) > 0, "missing actual assertion count")
    return int(match[1])


def verify_offline(report_name, root, ready):
    tests = Path(root) / "tests"
    report = read(tests / report_name)
    require(report.get("evidence_schema") == 2, "unbound historical offline report: " + report_name)
    require(report.get("status") == "passed", "offline test did not pass: " + report_name)
    require(report.get("rules_removed") is True and report.get("python_on_path") is False,
            "offline environment/cleanup not confirmed: " + report_name)
    require(type(report.get("outbound_rules")) is int and report["outbound_rules"] > 0, "missing outbound block")
    require(Path(report.get("application", "")).resolve() == Path(ready).resolve(), "report tested another artifact")
    started, completed = stamp(report.get("started_utc")), stamp(report.get("completed_utc"))
    require(started <= completed, "reversed run timestamps")
    runner = report.get("runner", {})
    require(sha(safe(tests, runner.get("path"))) == runner.get("sha256"), "runner changed since execution")
    require(sha(tests / "OfflineEvidence.ps1") == report.get("evidence_helper_sha256"), "evidence helper changed")
    dependencies = report.get("dependencies", [])
    require({row.get("path") for row in dependencies} == DEPENDENCIES and len(dependencies) == len(DEPENDENCIES),
            "tested dependency inventory incomplete")
    for dependency in dependencies:
        before, after = dependency.get("sha256_before"), dependency.get("sha256_after")
        require(isinstance(before, str) and DIGEST.fullmatch(before) is not None and before == after,
                "tested binary changed during execution")
        require(sha(safe(ready, dependency["path"])) == before, "stale tested binary: " + dependency["path"])
    suites, names = [], set()
    for suite in report.get("tests", []):
        name = suite.get("name")
        require(isinstance(name, str) and name and name not in names and suite.get("status") == "passed", "invalid suite")
        names.add(name)
        require(started <= stamp(suite.get("started_utc")) <= stamp(suite.get("completed_utc")) <= completed,
                "suite outside captured run")
        log = safe(tests, suite.get("log"))
        require(sha(log) == suite.get("log_sha256"), "test log changed: " + name)
        lines = log.read_text(encoding="utf-8-sig").splitlines()
        require(bool(lines) and lines[-1] == suite.get("summary"), "summary does not match actual log: " + name)
        require(type(suite.get("assertions")) is int and suite["assertions"] == actual_count(lines[-1]), "stored count does not match log: " + name)
        require(isinstance(suite.get("harness_sha256"), str) and DIGEST.fullmatch(suite["harness_sha256"]) is not None,
                "missing tested harness digest")
        sources = suite.get("sources", [])
        require(bool(sources), "missing test sources: " + name)
        for source in sources:
            require(sha(safe(tests, source.get("path"))) == source.get("sha256"), "test source changed: " + name)
        suites.append({"name": name, "assertions": suite["assertions"], "log": suite["log"], "log_sha256": suite["log_sha256"]})
    require(bool(suites), "no executed suites")
    return {"report": report_name, "run_id": report["run_id"], "started_utc": report["started_utc"],
            "completed_utc": report["completed_utc"], "python_on_path": False, "rules_removed": True,
            "outbound_rules": report["outbound_rules"], "tests": suites}


def verify(root=ROOT):
    root = Path(root).resolve()
    ready, tests = root / READY_NAME, root / "tests"
    inventory = read(ready / "package-sha256.json")
    require(isinstance(inventory, list) and bool(inventory), "missing package inventory")
    names = set()
    for entry in inventory:
        relative = entry.get("path")
        require(relative not in names, "duplicate package entry")
        names.add(relative)
        path = safe(ready, relative)
        require(path.stat().st_size == entry.get("bytes") and sha(path) == entry.get("sha256"), "package checksum: " + relative)
    actual = {path.relative_to(ready).as_posix() for path in ready.rglob("*")
              if path.is_file() and path.suffix.lower() in (".exe", ".dll", ".pyd")}
    require(actual == names, "unlisted runtime binary or missing packaged binary")
    application = sha(ready / "USB-Recovery.exe")
    require(application == sha(root / "USB-Recovery.exe"), "root executable differs from delivery")
    sources = list(root.glob("*.cs"))
    require(all(sha(path) == sha(ready / path.name) for path in sources), "delivered C# source mismatch")
    helper = ready / "tools/recovery-helper"
    helper_inventory = read(helper / "runtime-SHA256.json")
    for entry in helper_inventory:
        path = safe(helper, entry.get("path"))
        require(path.stat().st_size == entry.get("size") and sha(path) == entry.get("sha256"), "helper inventory mismatch")
    reports = {name: verify_offline(name + "Offline-validation.json", root, ready) for name in ("Quality", "Telegram", "Usb")}
    required = {"ContentQualityTests", "ArchiveSalvageTests", "MetadataRescueTests", "NewEngineIntegrationTests",
                "ResumableCaptureTests", "RecoverySessionTests", "FolderProvenanceTests", "FolderExportTests",
                "FragmentedZipRecoveryTests", "UserSignatureRecoveryTests", "SignatureUiIntegrationTests",
                "RecoveryMotionTests", "RecoveryResultsVisualTests", "RecoveryStageProgressTests",
                "RaidRecoveryTests", "StorageUiTests", "StoragePipelineTests", "HelperMemoryTests", "AtomicJsonSaveTests"}
    require({row["name"] for row in reports["Quality"]["tests"]} == required, "expected current quality suites missing")
    require({row["name"] for row in reports["Telegram"]["tests"]} == {"TelegramPortable", "TelegramNativePortable", "TelegramMediaPortable"}, "Telegram suites missing")
    require({row["name"] for row in reports["Usb"]["tests"]} == {"UsbPackaged"}, "USB suite missing")
    comparison = read(tests / "CommercialComparison-after.json")
    require(comparison.get("status") == "complete" and comparison.get("application_sha256") == application, "comparison regression is stale")
    require(all(row["exact"] == row["expected"] and row["source_unchanged"] for row in comparison["results"]), "comparison payload regression")
    return {
        "evidence_schema": 2, "status": "passed", "checked_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "application_sha256": application, "helper_sha256": sha(helper / "recovery-helper.exe"),
        "runtime_files_verified": len(inventory), "cs_sources_verified": len(sources),
        "helper_inventory_entries_verified": len(helper_inventory),
        "bound_offline_runs": reports,
        "packaged_quality_assertions_total": sum(row["assertions"] for row in reports["Quality"]["tests"]),
        "packaged_telegram_assertions_total": sum(row["assertions"] for row in reports["Telegram"]["tests"]),
        "packaged_usb_assertions_total": sum(row["assertions"] for row in reports["Usb"]["tests"]),
        "comparison_regression": {"fixtures": len(comparison["results"]), "expected_payloads": sum(r["expected"] for r in comparison["results"]),
                                  "all_expected_hashes_exact": True, "paid_full_editions_tested": False},
        "historical_counts_reused": False,
        "runtime_inventory_bound": True,
        "limits": {"real_usb_tested": False, "android_tested": False, "iphone_tested": False,
                   "universal_deleted_chat_recovery": False},
        "scope": "Synthetic regular files and images only; logs, test sources and before/after binary hashes bind every counted offline suite to this package. This verifies captured evidence, not real hardware recovery."
    }


if __name__ == "__main__":
    result = verify()
    (ROOT / "tests/RecoveryOctober30-validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("PASS bound package evidence: " + str(result["packaged_quality_assertions_total"]) + " quality assertions, "
          + str(result["packaged_telegram_assertions_total"]) + " Telegram assertions, "
          + str(result["packaged_usb_assertions_total"]) + " USB assertions; historical counts not reused")
