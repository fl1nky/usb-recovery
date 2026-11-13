"""Bootstrap integrity and publication controls on small owned ZIPs; no network."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import struct
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bootstrap_build", ROOT / "scripts/bootstrap-build.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="owned-bootstrap-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "checkout"
        self.root.mkdir()
        self.wheel = bootstrap.PREFIXES[0] + "owned-1-py3-none-any.whl"
        self.source = bootstrap.PREFIXES[1] + "owned-1.tar.gz"
        self.payloads = {self.wheel: b"owned wheel bytes", self.source: b"owned source bytes"}
        self.payloads.update((bootstrap.VENDOR + name, ("owned source " + name).encode()) for name in sorted(bootstrap.VENDOR_FILES))
        wheels = [{"name": Path(self.wheel).name, "sha256": hashlib.sha256(self.payloads[self.wheel]).hexdigest()}]
        sources = [{"name": "owned", "version": "1", "source": Path(self.source).name, "sha256": hashlib.sha256(self.payloads[self.source]).hexdigest()}]
        for relative, content in ((bootstrap.WHEEL_REGISTRY, json.dumps(wheels)), (bootstrap.SOURCE_REGISTRY, json.dumps(sources)), (bootstrap.LOCK, "owned==1 --hash=sha256:" + wheels[0]["sha256"] + "\n")):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.registries = {name: (self.root / name).read_bytes() for name in (bootstrap.WHEEL_REGISTRY, bootstrap.SOURCE_REGISTRY, bootstrap.LOCK)}

    def archive(self, extra=(), remove=(), change=None):
        path = self.base / ("input-" + str(len(list(self.base.glob("*.zip")))) + ".zip")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as output:
            for name, data in self.payloads.items():
                if name not in remove:
                    output.writestr(bootstrap.PREFIX + name, (change or {}).get(name, data))
            # A release may carry stale registry metadata; the checkout owns its pins.
            output.writestr(bootstrap.PREFIX + bootstrap.WHEEL_REGISTRY, b"untrusted release registry never installed")
            output.writestr("tools/recovery-helper/recovery-helper.exe", b"old runtime must never be copied")
            output.writestr("USB-Recovery.exe", b"old application must never be copied")
            for name, data in extra:
                output.writestr(name, data)
        return path

    def restore(self, archive):
        return bootstrap.restore(archive, self.root, bootstrap.digest(archive))

    def no_dependencies_published(self):
        self.assertFalse((self.root / self.wheel).exists())
        self.assertFalse((self.root / self.source).exists())
        for name, before in self.registries.items():
            self.assertEqual((self.root / name).read_bytes(), before)

    def test_exact_dependency_inputs_and_idempotent_no_runtime_restore(self):
        archive = self.archive()
        result = self.restore(archive)
        self.assertEqual(result["status"], "passed")
        self.assertEqual({row["path"] for row in result["files"]}, set(self.payloads))
        for name, expected in self.payloads.items():
            self.assertEqual((self.root / name).read_bytes(), expected)
        self.assertFalse((self.root / "tools").exists())
        self.assertFalse((self.root / "USB-Recovery.exe").exists())
        for name, before in self.registries.items():
            self.assertEqual((self.root / name).read_bytes(), before)
        self.assertEqual(self.restore(archive), result)

    def test_outer_archive_checksum_is_required(self):
        with self.assertRaisesRegex(ValueError, "archive checksum"):
            bootstrap.restore(self.archive(), self.root, "0" * 64)
        self.no_dependencies_published()

    def test_zip_crc_failure_prevents_all_dependency_publication(self):
        archive = self.archive()
        with zipfile.ZipFile(archive) as bundle:
            entry = bundle.getinfo(bootstrap.PREFIX + self.source)
            offset = entry.header_offset
        with archive.open("r+b") as stream:
            stream.seek(offset)
            header = stream.read(30)
            name_len, extra_len = struct.unpack_from("<HH", header, 26)
            stream.seek(offset + 30 + name_len + extra_len)
            first = stream.read(1)
            stream.seek(-1, 1)
            stream.write(bytes([first[0] ^ 255]))
        with self.assertRaises(zipfile.BadZipFile):
            self.restore(archive)
        self.no_dependencies_published()

    def test_traversal_windows_aliases_and_special_names_are_rejected(self):
        for suffix in ("../escape.whl", "nested/../../escape.whl", "nested\\escape.whl", "C:escape.whl", "NUL.whl", "name./test.whl", "name /test.whl", "a:stream.whl", "bad\nname.whl"):
            with self.subTest(suffix=suffix):
                archive = self.archive(extra=[(bootstrap.PREFIX + bootstrap.PREFIXES[0] + suffix, b"bad")])
                with self.assertRaises(ValueError):
                    self.restore(archive)
                self.no_dependencies_published()
        self.assertFalse((self.root / "escape.whl").exists())

    def test_selected_case_collision_and_duplicate_fail_before_publication(self):
        for name in (self.wheel, self.wheel.upper().replace("HELPERS/RECOVERY_ENGINE/WHEELS/", bootstrap.PREFIXES[0])):
            with self.subTest(name=name):
                archive = self.archive(extra=[(bootstrap.PREFIX + name, b"duplicate")])
                with self.assertRaises(ValueError):
                    self.restore(archive)
                self.no_dependencies_published()

    def test_zip_symlink_is_rejected(self):
        archive = self.archive(remove=[self.wheel])
        link = zipfile.ZipInfo(bootstrap.PREFIX + self.wheel)
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        with zipfile.ZipFile(archive, "a") as output:
            output.writestr(link, "../../outside")
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            self.restore(archive)
        self.no_dependencies_published()

    def test_declared_zip_expansion_limit_precedes_extraction(self):
        archive = self.archive()
        data = bytearray(archive.read_bytes())
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<I", data, central + 24, 129 * 1024**2)
        archive.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "expansion limit"):
            self.restore(archive)
        self.no_dependencies_published()

    def test_existing_directory_is_never_replaced_with_a_file(self):
        path = self.root / self.wheel
        path.mkdir()
        with self.assertRaisesRegex(ValueError, "not a file"):
            self.restore(self.archive())
        self.assertTrue(path.is_dir())
        self.assertFalse((self.root / self.source).exists())

    def test_existing_different_file_is_never_overwritten_or_partially_published(self):
        name = bootstrap.VENDOR + "README.md"
        path = self.root / name
        path.parent.mkdir(parents=True)
        path.write_bytes(b"existing checkout change")
        with self.assertRaisesRegex(ValueError, "Existing build input differs"):
            self.restore(self.archive())
        self.assertEqual(path.read_bytes(), b"existing checkout change")
        self.no_dependencies_published()

    def test_source_archive_must_match_checkout_registry(self):
        with self.assertRaisesRegex(ValueError, "checkout registry"):
            self.restore(self.archive(change={self.source: b"different dependency"}))
        self.no_dependencies_published()

    def test_wheel_must_match_checkout_registry(self):
        with self.assertRaisesRegex(ValueError, "checkout registry"):
            self.restore(self.archive(change={self.wheel: b"different wheel"}))
        self.no_dependencies_published()

    def test_missing_required_wheel_source_or_vendor_fails(self):
        for name in (self.wheel, self.source, bootstrap.VENDOR + "pyproject.toml"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "missing checkout-pinned"):
                    self.restore(self.archive(remove=[name]))
                self.no_dependencies_published()

    def test_unregistered_executable_in_dependency_directory_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unregistered"):
            self.restore(self.archive(extra=[(bootstrap.PREFIX + bootstrap.PREFIXES[0] + "old-runtime.exe", b"old runtime")]))
        self.no_dependencies_published()

    def test_checkout_wheel_registry_must_match_requirements_lock(self):
        (self.root / bootstrap.LOCK).write_text("owned==1 --hash=sha256:" + "0" * 64 + "\n")
        with self.assertRaisesRegex(ValueError, "requirements lock"):
            self.restore(self.archive())
        self.assertFalse((self.root / self.wheel).exists())

    def test_checkout_registry_duplicate_or_traversal_is_rejected(self):
        registry = self.root / bootstrap.SOURCE_REGISTRY
        valid = json.loads(registry.read_text())
        for value in ([valid[0], valid[0]], [{**valid[0], "source": "../escape.tar.gz"}]):
            registry.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                self.restore(self.archive())
            self.assertFalse((self.root / self.wheel).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
