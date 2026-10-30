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
READY_NAME = "dist/USB-Recovery"
COUNT = re.compile(r"\b(\d+)\s+(?:[A-Za-z-]+\s+){0,4}(?:assertions|checks)\b", re.I)
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
DEPENDENCIES = {"USB-Recovery.exe", "tools/recovery-helper/recovery-helper.exe",
                "tools/testdisk-7.2/photorec_win.exe", "tools/testdisk-7.2/testdisk_win.exe",
                "package-sha256.json", "tools/recovery-helper/runtime-SHA256.json"}
SOURCE_TREES = ("src", "scripts", "helpers/recovery_engine", "vendor/iphone-backup-decrypt", "docs")
SOURCE_FIXTURES = ("fixtures/hevc-recovery", "fixtures/hevc-validation", "fixtures/aac-islands", "fixtures/aac-lc", "fixtures/ext4", "fixtures/raid-md", "benchmarks", "TelegramNativeFixtures", "TelegramMediaFixtures", "StorageFixtures",
                   "photorec-20261011T231546120952Z/fixtures")
EXCLUDED_SOURCE_DIRECTORIES = {".git", "__pycache__", ".pytest_cache", "bin", "obj"}
GENERATED_TEST_REPORTS = {"CommercialComparison-after.json", "CommercialComparison-baseline.json",
                          "October30-package-audit.json"}


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


def repository_runtime(root, relative):
    """Map package names to their actual build/source counterpart."""
    if relative == "USB-Recovery.exe":
        return safe(root, ".build/app/USB-Recovery.exe")
    if relative.startswith("source/"):
        return safe(root, relative[len("source/"):])
    return safe(root, relative)


def source_tree(root, relative):
    directory = safe(root, relative)
    require(directory.is_dir(), "missing source directory: " + relative)
    result = {}
    for path in directory.rglob("*"):
        if EXCLUDED_SOURCE_DIRECTORIES.intersection(path.relative_to(directory).parts[:-1]):
            continue
        require(not path.is_symlink() and not path.is_junction(), "linked source: " + str(path))
        if path.is_file():
            result[path.relative_to(root).as_posix()] = path
    require(bool(result), "empty source directory: " + relative)
    return result


def generated_test_report(relative):
    path = Path(relative)
    return (len(path.parts) == 2 and path.parts[0] == "tests" and
            (path.name.endswith(("result.txt", "-validation.json")) or
             path.name in GENERATED_TEST_REPORTS))


def verify_sources(root, ready):
    """Check the complete packaged source selection, not just top-level C#."""
    root, ready = Path(root), Path(ready)
    expected = {}
    for relative in SOURCE_TREES:
        expected.update(source_tree(root, relative))
    for relative in ("build.ps1", "README.md"):
        path = safe(root, relative)
        require(path.is_file(), "missing package source: " + relative)
        expected[relative] = path
    tests = root / "tests"
    test_sources = {path.relative_to(root).as_posix(): path for path in tests.iterdir()
                    if path.is_file() and path.suffix.lower() in (".cs", ".py", ".ps1")}
    require(bool(test_sources), "empty test source set")
    expected.update(test_sources)
    for relative in SOURCE_FIXTURES:
        expected.update(source_tree(root, "tests/" + relative))

    csharp = sorted(name for name in expected if name.startswith("src/Recovery/") and name.endswith(".cs"))
    require(bool(csharp), "empty C# source set")
    for relative in ("src/Recovery/Recovery.csproj", "src/Recovery/app.manifest",
                     "scripts/build-app.ps1", "scripts/build-helper.ps1", "scripts/ProjectPaths.ps1"):
        require(relative in expected, "required application/build source missing: " + relative)

    delivered_root = ready / "source"
    require(delivered_root.is_dir(), "missing packaged source tree")
    delivered = {}
    for path in delivered_root.rglob("*"):
        require(not path.is_symlink() and not path.is_junction(), "linked delivered source")
        if path.is_file():
            relative = path.relative_to(delivered_root).as_posix()
            # Reports bind their own changing bytes through verify_offline; an
            # audit must not include its own newly written report in source hashes.
            if not generated_test_report(relative):
                delivered[relative] = path
    require(set(delivered) == set(expected),
            "packaged source inventory mismatch: " + str(sorted(set(delivered) ^ set(expected))))
    for relative, source in expected.items():
        require(sha(source) == sha(delivered[relative]), "delivered source mismatch: " + relative)

    documents = source_tree(root, "docs")
    for relative in ("docs/guides", "docs/images"):
        source_tree(root, relative)
    require("docs/third-party.md" in documents, "missing third-party document")
    delivered_documents = source_tree(ready, "docs")
    require(set(documents) == set(delivered_documents), "runtime document inventory mismatch")
    for relative, source in documents.items():
        require(sha(source) == sha(delivered_documents[relative]), "runtime document mismatch: " + relative)
    return {"sources_verified": len(expected), "runtime_documents_verified": len(documents),
            "cs_sources": [{"path": name, "sha256": sha(expected[name]), "matched": True} for name in csharp],
            "application_metadata": [{"path": name, "sha256": sha(expected[name]), "matched": True}
                                     for name in ("src/Recovery/Recovery.csproj", "src/Recovery/app.manifest")]}


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
        require(sha(repository_runtime(root, relative)) == entry.get("sha256"), "build/runtime differs: " + relative)
    actual = {path.relative_to(ready).as_posix() for path in ready.rglob("*")
              if path.is_file() and path.suffix.lower() in (".exe", ".dll", ".pyd")}
    require(actual == names, "unlisted runtime binary or missing packaged binary")
    application = sha(ready / "USB-Recovery.exe")
    require(application == sha(root / ".build/app/USB-Recovery.exe"), "built executable differs from delivery")
    sources = verify_sources(root, ready)
    helper = ready / "tools/recovery-helper"
    helper_inventory = read(helper / "runtime-SHA256.json")
    require(isinstance(helper_inventory, list) and bool(helper_inventory), "missing helper inventory")
    helper_names = set()
    for entry in helper_inventory:
        relative = entry.get("path")
        require(relative not in helper_names, "duplicate helper inventory entry")
        helper_names.add(relative)
        path = safe(helper, relative)
        require(path.stat().st_size == entry.get("size") and sha(path) == entry.get("sha256"), "helper inventory mismatch")
    actual_helper = {path.relative_to(helper).as_posix() for path in helper.rglob("*") if path.is_file()}
    require(actual_helper == helper_names | {"runtime-SHA256.json"}, "unlisted helper files")
    reports = {name: verify_offline(name + "Offline-validation.json", root, ready) for name in ("Quality", "Telegram", "Usb")}
    required = {"ContentQualityTests", "ArchiveSalvageTests", "MetadataRescueTests", "NewEngineIntegrationTests",
                "ResumableCaptureTests", "RecoverySessionTests", "FolderProvenanceTests", "FolderExportTests",
                "FragmentedZipRecoveryTests", "UserSignatureRecoveryTests", "SignatureUiIntegrationTests",
                "RecoveryMotionTests", "RecoveryResultsVisualTests", "RecoveryStageProgressTests",
                "RaidRecoveryTests", "StorageUiTests", "StoragePipelineTests", "HelperMemoryTests", "AtomicJsonSaveTests",
                "ExportTempCollisionTests", "StorageWorkflowTests", "CaptureProvenanceTests", "ApplicationPathsTests", "FragmentedMediaRecoveryTests", "MediaWorkflowTests", "FragmentedPhotoPortableTests", "ProgressivePhotoPortableTests", "AndroidHeapPortableTests", "Ext4RecoveryTests", "Ext4WorkflowTests", "RaidMetadataProbeTests", "RaidMetadataAuditTests", "RaidMetadataUiAuditTests", "Ext4IntegrationAuditTests", "PhotoCheckpointSessionTests", "CandidateIntegrityPreservationTests", "HelperCheckpointProtocolTests", "RecoveryRunLockTests", "AacLcValidatorTests", "AacSyntaxAuditTests", "FragmentedAacRecoveryTests", "HevcSampleValidatorTests", "HevcRecoveryTests", "PhotoCheckpointPortableTests", "PhotoCheckpointParentAuditTests"}
    require({row["name"] for row in reports["Quality"]["tests"]} == required, "expected current quality suites missing")
    require({row["name"] for row in reports["Telegram"]["tests"]} == {"TelegramPortable", "TelegramNativePortable", "TelegramMediaPortable", "TelegramDeletedPortable"}, "Telegram suites missing")
    require({row["name"] for row in reports["Usb"]["tests"]} == {"UsbPackaged"}, "USB suite missing")
    comparison = read(tests / "CommercialComparison-after.json")
    require(comparison.get("status") == "complete" and comparison.get("application_sha256") == application, "comparison regression is stale")
    require(all(row["exact"] == row["expected"] and row["source_unchanged"] for row in comparison["results"]), "comparison payload regression")
    return {
        "evidence_schema": 2, "status": "passed", "checked_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "application_sha256": application, "helper_sha256": sha(helper / "recovery-helper.exe"),
        "runtime_files_verified": len(inventory), "cs_sources_verified": len(sources["cs_sources"]),
        "packaged_sources_verified": sources["sources_verified"],
        "runtime_documents_verified": sources["runtime_documents_verified"],
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
