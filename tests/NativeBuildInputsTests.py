# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build-input boundaries: no compiler, network, installer or device access."""
from __future__ import annotations
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).absolute().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


build = module("native_build", "build-native-recovery.py")
prepare = module("native_inputs", "prepare-native-toolchain.py")


class Inputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="usb-native-inputs-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def archive(self, name, members):
        path = self.root / name
        with tarfile.open(path, "w:gz") as output:
            for member, body in members:
                output.addfile(member, io.BytesIO(body) if member.isfile() else None)
        return path

    def patch(self, source="alpha\nbeta\ngamma\n", patch=None):
        (self.root / "file.c").write_text(source, encoding="utf-8")
        path = self.root / "fix.patch"
        path.write_text(patch or "--- a/file.c\n+++ b/file.c\n@@ -1,3 +1,3 @@\n alpha\n-beta\n+fixed\n gamma\n", encoding="utf-8")
        return path

    def test_safe_relative_input(self):
        self.assertEqual(build.safe(self.root, "dir/file.c"), self.root / "dir/file.c")

    def test_unsafe_paths(self):
        for name in ("../file", "/file", "C:/file", "dir\\file", "dir/../../file"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                build.safe(self.root, name)

    def test_exact_patch(self):
        build.apply_patch(self.root, self.patch())
        self.assertEqual((self.root / "file.c").read_text(), "alpha\nfixed\ngamma\n")

    def test_patch_context_refuses_fuzzy_match(self):
        patch = self.patch("alpha\nchanged\ngamma\n")
        with self.assertRaises(ValueError):
            build.apply_patch(self.root, patch)
        self.assertEqual((self.root / "file.c").read_text(), "alpha\nchanged\ngamma\n")

    def test_patch_count_mismatch(self):
        patch = self.patch(patch="--- a/file.c\n+++ b/file.c\n@@ -1,4 +1,3 @@\n alpha\n-beta\n+fixed\n gamma\n")
        with self.assertRaises(ValueError):
            build.apply_patch(self.root, patch)
        self.assertEqual((self.root / "file.c").read_text(), "alpha\nbeta\ngamma\n")

    def test_patch_path_escape(self):
        patch = self.patch(patch="--- a/../outside.c\n+++ b/../outside.c\n@@ -1 +1 @@\n-old\n+new\n")
        with self.assertRaises(ValueError):
            build.apply_patch(self.root, patch)

    def test_extract_verified_member(self):
        member = tarfile.TarInfo("source/file.c")
        member.size = 3
        archive = self.archive("good.tgz", [(member, b"abc")])
        build.extract(archive, self.root / "out", build.digest(archive))
        self.assertEqual((self.root / "out/source/file.c").read_bytes(), b"abc")

    def test_extract_wrong_digest_creates_no_destination(self):
        archive = self.archive("bad.tgz", [])
        with self.assertRaises(ValueError):
            build.extract(archive, self.root / "out", "0" * 64)
        self.assertFalse((self.root / "out").exists())

    def test_extract_traversal(self):
        member = tarfile.TarInfo("../outside.c")
        member.size = 3
        archive = self.archive("escape.tgz", [(member, b"abc")])
        with self.assertRaises(ValueError):
            build.extract(archive, self.root / "out", build.digest(archive))
        self.assertFalse((self.root / "outside.c").exists())

    def test_extract_symlink_refused(self):
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside"
        archive = self.archive("link.tgz", [(member, b"")])
        with self.assertRaises(ValueError):
            build.extract(archive, self.root / "out", build.digest(archive))

    def test_cache_verified_offline(self):
        path = self.root / "x86_64/release/owned/input.tar.xz"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"abc")
        row = dict(path=path.relative_to(self.root).as_posix(), bytes=3, sha512=hashlib.sha512(b"abc").hexdigest())
        self.assertEqual(prepare.restore(row, self.root, True), path)
        path.write_bytes(b"abd")
        with self.assertRaises(ValueError):
            prepare.restore(row, self.root, True)

    def test_offline_missing_archive_not_downloaded(self):
        row = dict(path="src/release/owned/input.tar.xz", bytes=3, sha512=hashlib.sha512(b"abc").hexdigest())
        with self.assertRaises(FileNotFoundError):
            prepare.restore(row, self.root, True)
        self.assertFalse((self.root / "src").exists())


if __name__ == "__main__":
    unittest.main()
