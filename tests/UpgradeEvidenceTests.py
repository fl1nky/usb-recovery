"""Tamper/staleness tests for captured evidence, no processes/devices/network."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from verify_upgrade_package import actual_count, DEPENDENCIES, sha, ValidationError, verify_offline


class EvidenceBinding(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="recovery-evidence-")
        self.root = Path(self.temporary.name)
        self.tests = self.root / "tests"
        self.ready = self.root / "ready"
        self.tests.mkdir()
        self.ready.mkdir()
        for name in DEPENDENCIES:
            path = self.ready / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("Synthetic fixture: " + name).encode())
        for name in ("runner.ps1", "OfflineEvidence.ps1", "Suite.cs"):
            (self.tests / name).write_text("Synthetic source " + name, encoding="utf-8")
        self.log = self.tests / "suite.result.txt"
        self.log.write_text("PASS example: 8 checks; synthetic only.\n", encoding="utf-8")
        self.report = {
            "evidence_schema": 2, "status": "passed", "run_id": "synthetic-only",
            "application": str(self.ready), "started_utc": "2026-10-30T01:00:00Z", "completed_utc": "2026-10-30T01:00:05Z",
            "python_on_path": False, "rules_removed": True, "outbound_rules": 1,
            "runner": {"path": "runner.ps1", "sha256": sha(self.tests / "runner.ps1")},
            "evidence_helper_sha256": sha(self.tests / "OfflineEvidence.ps1"),
            "dependencies": [{"path": name, "sha256_before": sha(self.ready / name), "sha256_after": sha(self.ready / name)} for name in sorted(DEPENDENCIES)],
            "tests": [{"name": "Suite", "status": "passed", "assertions": 8, "summary": "PASS example: 8 checks; synthetic only.",
                       "log": self.log.name, "log_sha256": sha(self.log), "harness_sha256": "a" * 64,
                       "sources": [{"path": "Suite.cs", "sha256": sha(self.tests / "Suite.cs")}],
                       "started_utc": "2026-10-30T01:00:01Z", "completed_utc": "2026-10-30T01:00:03Z"}]
        }

    def tearDown(self):
        self.temporary.cleanup()

    def verify(self, report=None):
        (self.tests / "Synthetic-validation.json").write_text(json.dumps(self.report if report is None else report), encoding="utf-8")
        return verify_offline("Synthetic-validation.json", self.root, self.ready)

    def rejected(self, report=None):
        with self.assertRaises(ValidationError):
            self.verify(report)

    def test_exact_binary_source_log_binding(self):
        self.assertEqual(self.verify()["tests"][0]["assertions"], 8)

    def test_old_unbound_green_report_rejected(self):
        old = copy.deepcopy(self.report)
        old.pop("evidence_schema")
        self.rejected(old)

    def test_binary_changed_since_test_rejected(self):
        (self.ready / "USB-Recovery.exe").write_bytes(b"different executable fixture")
        self.rejected()

    def test_binary_changed_during_test_rejected(self):
        changed = copy.deepcopy(self.report)
        changed["dependencies"][0]["sha256_after"] = "0" * 64
        self.rejected(changed)

    def test_package_inventory_regenerated_after_test_rejected(self):
        (self.ready / "package-sha256.json").write_text('[{"path":"new.dll"}]', encoding="utf-8")
        self.rejected()

    def test_helper_inventory_regenerated_after_dependency_change_rejected(self):
        (self.ready / "tools/recovery-helper/runtime-SHA256.json").write_text(
            '[{"path":"_internal/_sqlite3.pyd","sha256":"new-dependency"}]', encoding="utf-8")
        self.rejected()

    def test_dependency_inventory_changed_during_run_rejected(self):
        changed = copy.deepcopy(self.report)
        item = next(row for row in changed["dependencies"] if row["path"] == "package-sha256.json")
        item["sha256_after"] = "0" * 64
        self.rejected(changed)

    def test_binary_only_binding_rejected(self):
        changed = copy.deepcopy(self.report)
        changed["dependencies"] = [row for row in changed["dependencies"] if row["path"].endswith(".exe")]
        self.rejected(changed)

    def test_changed_log_rejected(self):
        self.log.write_text("PASS example: 8000 checks; fabricated edit.\n", encoding="utf-8")
        self.rejected()

    def test_changed_count_even_with_intact_log_rejected(self):
        changed = copy.deepcopy(self.report)
        changed["tests"][0]["assertions"] = 8000
        self.rejected(changed)

    def test_changed_test_or_runner_source_rejected(self):
        (self.tests / "Suite.cs").write_text("changed", encoding="utf-8")
        self.rejected()
        (self.tests / "Suite.cs").write_text("Synthetic source Suite.cs", encoding="utf-8")
        (self.tests / "runner.ps1").write_text("changed", encoding="utf-8")
        self.rejected()

    def test_suite_outside_run_rejected(self):
        changed = copy.deepcopy(self.report)
        changed["tests"][0]["started_utc"] = "2026-10-29T01:00:00Z"
        self.rejected(changed)

    def test_changed_common_evidence_helper_rejected(self):
        (self.tests / "OfflineEvidence.ps1").write_text("changed", encoding="utf-8")
        self.rejected()

    def test_missing_dependency_or_log_traversal_rejected(self):
        changed = copy.deepcopy(self.report)
        changed["dependencies"].pop()
        self.rejected(changed)
        changed = copy.deepcopy(self.report)
        changed["tests"][0]["log"] = "../outside.result.txt"
        self.rejected(changed)

    def test_duplicate_suite_and_missing_sources_rejected(self):
        changed = copy.deepcopy(self.report)
        changed["tests"].append(copy.deepcopy(changed["tests"][0]))
        self.rejected(changed)
        changed = copy.deepcopy(self.report)
        changed["tests"][0]["sources"] = []
        self.rejected(changed)

    def test_actual_count_formats_and_failures(self):
        for text, expected in (("Content quality: 69 checks passed", 69), ("PASS 16 packaged USB assertions;", 16), ("PASS TelegramNativePortable: 39 checks", 39)):
            self.assertEqual(actual_count(text), expected)
        for text in ("passed", "PASS 0 checks", "FAIL 3 assertions"):
            with self.assertRaises(ValidationError):
                actual_count(text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
