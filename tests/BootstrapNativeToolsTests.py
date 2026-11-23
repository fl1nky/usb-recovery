"""Native input integrity on owned tiny ZIPs; fake executables are never run."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bootstrap_build", ROOT / "scripts/bootstrap-build.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class NativeToolInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="owned-native-inputs-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "checkout"
        (self.root / "scripts").mkdir(parents=True)
        self.data = {"tools/testdisk-7.2/photorec_win.exe": b"owned fake PE, never executed",
                     "tools/testdisk-7.2/COPYING.txt": b"owned license control",
                     "tools/platform-tools/NOTICE.txt": b"owned second component control"}
        self.rows = [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                     for name, data in self.data.items()]
        self.registry()

    def registry(self):
        (self.root / bootstrap.NATIVE_REGISTRY).write_text(json.dumps(self.rows), encoding="utf-8")

    def archive(self, change=None, missing=None, extra=(), symlink=False):
        archive = self.base / ("input-%d.zip" % len(list(self.base.glob("*.zip"))))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive, "w") as output:
                for name, data in self.data.items():
                    if name == missing:
                        continue
                    if symlink and name.endswith("photorec_win.exe"):
                        info = zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = 0o120777 << 16
                        output.writestr(info, data)
                    else:
                        output.writestr(name, (change or {}).get(name, data))
                output.writestr("USB-Recovery.exe", b"old app must not be copied")
                output.writestr("tools/recovery-helper/recovery-helper.exe", b"old helper must not be copied")
                for name, data in extra:
                    output.writestr(name, data)
        return archive

    def restore(self, archive):
        return bootstrap.restore_native_tools(archive, self.root, bootstrap.digest(archive))

    def no_publication(self):
        self.assertFalse((self.root / "tools").exists())
        self.assertFalse((self.root / "USB-Recovery.exe").exists())

    def test_exact_inputs_licenses_and_idempotence_without_old_app_helper(self):
        archive = self.archive()
        result = self.restore(archive)
        self.assertFalse(result["application_or_helper_restored"])
        self.assertEqual({row["path"] for row in result["files"]}, set(self.data))
        for name, data in self.data.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.assertFalse((self.root / "USB-Recovery.exe").exists())
        self.assertFalse((self.root / "tools/recovery-helper").exists())
        self.assertEqual(self.restore(archive), result)

    def test_outer_checksum_required(self):
        with self.assertRaisesRegex(ValueError, "archive checksum"):
            bootstrap.restore_native_tools(self.archive(), self.root, "0" * 64)
        self.no_publication()

    def test_changed_content_rejected_before_any_publication(self):
        name = self.rows[-1]["path"]
        changed = b"x" * len(self.data[name])
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.restore(self.archive(change={name: changed}))
        self.no_publication()

    def test_missing_file_and_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing"):
            self.restore(self.archive(missing=self.rows[0]["path"]))
        self.no_publication()
        with self.assertRaisesRegex(ValueError, "size"):
            self.restore(self.archive(change={self.rows[0]["path"]: b"short"}))
        self.no_publication()

    def test_duplicate_symlink_and_unregistered_native_entries_rejected(self):
        for archive in (self.archive(extra=[(self.rows[0]["path"], self.data[self.rows[0]["path"]])]),
                        self.archive(symlink=True),
                        self.archive(extra=[("tools/testdisk-7.2/unknown.exe", b"unregistered")])):
            with self.subTest(archive=archive.name), self.assertRaisesRegex(ValueError, "Unsafe"):
                self.restore(archive)
            self.no_publication()

    def test_registry_cannot_select_old_application_or_traversal(self):
        for name in ("USB-Recovery.exe", "tools/recovery-helper/recovery-helper.exe",
                     "tools/testdisk-7.2/../../outside.exe"):
            self.rows[0]["path"] = name
            self.registry()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.restore(self.archive())
            self.no_publication()

    def test_invalid_registry_counts_and_hashes_rejected(self):
        original = self.rows[0].copy()
        for field, value in (("bytes", True), ("bytes", 0), ("bytes", 64 * 1024**2 + 1),
                             ("sha256", "A" * 64)):
            self.rows[0] = {**original, field: value}
            self.registry()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.restore(self.archive())
            self.no_publication()

    def test_existing_mismatch_preserved_without_installing_other_files(self):
        target = self.root / self.rows[-1]["path"]
        target.parent.mkdir(parents=True)
        target.write_bytes(b"owned preexisting content")
        with self.assertRaisesRegex(ValueError, "Existing native tool differs"):
            self.restore(self.archive())
        self.assertEqual(target.read_bytes(), b"owned preexisting content")
        self.assertFalse((self.root / self.rows[0]["path"]).exists())

    def test_native_only_cli_does_not_restore_old_application_or_helper_inputs(self):
        archive = self.archive()
        (self.root / ".build").mkdir()
        with patch.object(bootstrap, "ROOT", self.root), \
             patch("sys.argv", ["bootstrap-build.py", "--native-only", "--archive", str(archive)]), \
             patch.object(bootstrap, "restore", side_effect=AssertionError("Helper restore must not run")), \
             patch.object(bootstrap, "restore_native_tools", return_value={"files": [], "status": "passed"}) as native:
            bootstrap.main()
            native.assert_called_once_with(archive)
        report = json.loads((self.root / ".build/bootstrap-build.json").read_text(encoding="utf-8"))
        self.assertEqual(report["files"], [])
        self.assertEqual(report["native_tools"]["status"], "passed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
