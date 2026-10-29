"""BitLocker adapter tests using upstream Dissect 4.6 fixtures, no real devices.

Fixture origin: https://github.com/fox-it/dissect.fve/tree/4.6/tests/_data/bde
Pinned upstream commit: c03d2dc5ece7a53cb6ef76c3567d63e6c9ab12ee
Upstream LICENSE: AGPL-3.0-or-later. Published credentials below are test data.
Use --fixtures DIR when upstream sources are unpacked elsewhere. No downloads.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import tarfile
import unittest
import zlib

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "helpers/recovery_engine"))
from storage_bitlocker import handle_bitlocker
from dissect.fve.bde import BDE

FIXTURES = PROJECT / ".build/storage-bitlocker/dissect-fve/tests/_data/bde"
PASSWORD = "password12!@"
RECOVERY = "284867-596541-514998-422114-660297-261613-215424-199408"
checks = 0


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class BitLockerRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (FIXTURES / "aes_128.bin.gz").is_file():
            raise RuntimeError("Missing pinned upstream fixtures; pass --fixtures DIR")
        parent = PROJECT / ".build"
        parent.mkdir(exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(prefix="bitlocker-tests-", dir=parent))
        cls.aes = cls.image("aes_128")

    @classmethod
    def image(cls, name):
        target = cls.work / (name + ".dd")
        if not target.exists():
            with gzip.open(FIXTURES / (name + ".bin.gz"), "rb") as source, target.open("xb") as out:
                shutil.copyfileobj(source, out)
        return target

    @classmethod
    def tearDownClass(cls):
        if cls.work.resolve().is_relative_to((PROJECT / ".build").resolve()):
            shutil.rmtree(cls.work)

    def verify(self, value, description):
        global checks
        checks += 1
        self.assertTrue(value, description)

    def request(self, source=None, secret=None, **options):
        destination = self.work / ("out-" + next(tempfile._get_candidate_names()))
        return {"source": str(source or self.aes), "destination": str(destination),
                "secrets": secret if secret is not None else {"password": PASSWORD},
                "options": options}

    def fail(self, request, expected):
        result = handle_bitlocker(request, lambda *args, **kwargs: None)
        self.verify(result["status"] == "error" and result["code"] == expected, result)
        self.verify(not Path(request["destination"]).exists() or not any(Path(request["destination"]).glob("*.dd")), "no published image after failure")
        return result

    def valid(self, request, cipher, expected_status="partial"):
        # The library's XTS implementation is per-sector Python. Exercise its
        # independent known boot/MFT sectors through an explicit bounded prefix;
        # ordinary CBC is also checked over the entire available source.
        if cipher.startswith("AES_XTS"):
            request["options"].setdefault("output_length_bytes", 65536)
        before = sha(request["source"])
        events = []
        result = handle_bitlocker(request, lambda kind, **fields: events.append((kind, fields)))
        self.verify(result["status"] == expected_status, result)
        self.verify(result["image"] == ("decrypted-prefix.dd" if expected_status == "partial" else "decrypted.dd"), "explicit prefix filename")
        destination = Path(request["destination"])
        image = destination / result["image"]
        with image.open("rb") as plaintext:
            boot = plaintext.read(512)
            plaintext.seek(0x2000)
            mft = plaintext.read(8)
        # Independent known plaintext documented by upstream test_bde.py.
        self.verify(boot[3:11] == b"NTFS    " and boot[510:512] == b"\x55\xaa", "known NTFS boot plaintext")
        self.verify(mft == b"FILE0\0\x03\0", "known MFT plaintext beyond virtualized boot")
        self.verify(image.stat().st_size == result["bytes"], "measured length")
        self.verify(sha(image) == result["image_sha256"], "actual output SHA256")
        self.verify((destination / (result["image"] + ".sha256")).read_text().strip() == result["image_sha256"], "sidecar matches image")
        report = json.loads((destination / result["report"]).read_text(encoding="utf-8"))
        self.verify(report["cipher"] == cipher and report["source"]["unchanged"], "actual cipher and preserved source")
        self.verify(report["source"]["sha256"] == before == sha(request["source"]), "input hash unchanged")
        self.verify(report["authentication"]["data_sectors"] == "not_authenticated_by_bitlocker", "no whole-volume integrity claim")
        serialized = json.dumps(report) + json.dumps(result) + json.dumps(events)
        for secret in request["secrets"].values():
            self.verify(secret not in serialized, "provided secret absent from protocol and report")
        for phase in ("source_hash", "decrypt", "verify_source"):
            rows = [fields for kind, fields in events if kind == "progress" and fields["phase"] == phase]
            self.verify(bool(rows) and rows[-1]["completed"] == rows[-1]["total"], "real finished byte count " + phase)
            self.verify(all(0 <= row["completed"] <= row["total"] for row in rows), "no invented byte count " + phase)
            self.verify([row["completed"] for row in rows] == sorted(row["completed"] for row in rows), "monotonic observed bytes " + phase)
        self.verify(not list(destination.glob("*.partial")), "no partial remains after publication")
        return result, report

    def test_six_official_ciphers(self):
        for name, cipher in (("aes_128", "AES_128"), ("aes_256", "AES_256"),
                             ("aes_128_diffuser", "AES_128_DIFFUSER"), ("aes_256_diffuser", "AES_256_DIFFUSER"),
                             ("aes-xts_128", "AES_XTS_128"), ("aes-xts_256", "AES_XTS_256")):
            with self.subTest(cipher=cipher):
                # Diffuser is sector-by-sector Python; its independent known
                # boot/MFT plaintext fits the explicit64KiB bounded extraction.
                options = {"output_length_bytes": 65536} if "diffuser" in name else {}
                result, report = self.valid(self.request(self.image(name), **options), cipher)
                self.verify(report["declared_logical_bytes"] > result["bytes"] and "TRUNCATED_SOURCE" in result["warnings"], "truncated official fixture remains partial")

    def test_recovery_password(self):
        self.valid(self.request(self.image("recovery_password"), {"recovery_password": RECOVERY}), "AES_XTS_128")

    def test_recovery_password_without_separators(self):
        self.valid(self.request(self.image("recovery_password"), {"recovery_password": RECOVERY.replace("-", "")}), "AES_XTS_128")

    def test_bek(self):
        for name in ("startup_key", "recovery_key"):
            with self.subTest(key=name):
                key = base64.b64encode((FIXTURES / (name + ".bek")).read_bytes()).decode("ascii")
                self.valid(self.request(self.image(name), {"bek_base64": key}), "AES_XTS_128")

    def test_eow_bitmap_volume_bounded_prefix(self):
        source = self.image("eow_partial")
        before = sha(source)
        request = self.request(source, output_length_bytes=65536)
        result = handle_bitlocker(request, lambda *args, **fields: None)
        self.verify(result["status"] == "partial" and result["image"] == "decrypted-prefix.dd", "EOW bounded output remains partial")
        output = Path(request["destination"])
        report = json.loads((output / result["report"]).read_text())
        self.verify(report["eow"] and report["sector_size"] == 512, "actual EOW metadata recognized")
        self.verify((output / result["image"]).read_bytes()[3:11] == b"NTFS    ", "independent known EOW boot plaintext")
        self.verify(before == sha(source), "EOW input unchanged")

    def test_vista_recovery_and_virtualized_boot(self):
        source = self.image("vista")
        request = self.request(source, {"recovery_password": "517506-503998-044583-576191-587004-635965-501270-087802"}, output_length_bytes=65536)
        result = handle_bitlocker(request, lambda *args, **fields: None)
        self.verify(result["status"] == "partial" and result["image"] == "decrypted-prefix.dd", "Vista bounded prefix")
        with source.open("rb") as original:
            bde = BDE(original)
            original.seek(0)
            expected = bytearray(original.read(512))
            expected[3:11] = b"NTFS    "
            expected[0x38:0x40] = struct.pack("<Q", bde.information.header.Mft2StartLcn)
        output = Path(request["destination"])
        self.verify((output / result["image"]).read_bytes()[:512] == expected, "independently specified Vista boot restoration")
        report = json.loads((output / result["report"]).read_text())
        self.verify(report["bitlocker_version"] == 1 and report["source"]["sha256"] == sha(source), "Vista source preserved and version reported")

    def test_offset_and_length_view(self):
        source = self.work / "partitioned.dd"
        data = self.aes.read_bytes()
        source.write_bytes(b"prefix".ljust(1024 * 1024, b"\0") + data + b"suffix".ljust(4096, b"\0"))
        result, report = self.valid(self.request(source, offset_bytes=1024 * 1024, length_bytes=len(data)), "AES_128")
        self.verify(result["bytes"] == len(data) and report["source"]["offset_bytes"] == 1024 * 1024, "partition offsets preserved")

    def test_full_length_generated_ciphertext_tail(self):
        # A generated derivative, not an independent complete-device fixture.
        # Fill unavailable tail with our encrypted zero sectors and backup boot.
        source = self.work / "generated-complete.dd"
        shutil.copyfile(self.aes, source)
        with source.open("rb") as encrypted:
            from dissect.fve.crypto import create_cipher
            from dissect.fve.bde.c_bde import CIPHER_MAP
            bde = BDE(encrypted)
            bde.unlock_with_passphrase(PASSWORD)
            stream = bde.open()
            boot = stream.read(512)
            cipher = create_cipher(CIPHER_MAP[bde._fvek_type], bde._fvek,
                                   sector_size=bde.sector_size, iv_sector_size=bde.sector_size)
            total, current = bde.information.state_offset, source.stat().st_size
            with source.open("ab") as output:
                while current < total:
                    count = min(1024 * 1024, total - current)
                    block = bytearray(count)
                    if current + count == total:
                        block[-512:] = boot
                    output.write(cipher.encrypt(bytes(block), sector=current // bde.sector_size))
                    current += count
        result, report = self.valid(self.request(source), "AES_128", "complete")
        self.verify(result["bytes"] == report["declared_logical_bytes"], "generated complete source copies declared extent")

    def test_wrong_credentials_no_plaintext(self):
        self.fail(self.request(secret={"password": "wrong-test-password-do-not-persist"}), "AUTH_FAILED")
        self.fail(self.request(self.image("recovery_password"), {"recovery_password": "-".join(["000000"] * 8)}), "AUTH_FAILED")
        wrong = base64.b64encode((FIXTURES / "startup_key.bek").read_bytes()).decode("ascii")
        self.fail(self.request(self.image("recovery_key"), {"bek_base64": wrong}), "AUTH_FAILED")

    def test_missing_or_ambiguous_credentials(self):
        self.fail(self.request(secret={}), "SECRET_REQUIRED")
        self.fail(self.request(secret={"fvek": "not-accepted"}), "SECRET_REQUIRED")
        self.fail(self.request(secret={"password": PASSWORD, "recovery_password": RECOVERY}), "INVALID_REQUEST")
        for secret in ({"password": 123}, {"recovery_password": "not-a-key"}, {"bek_base64": "bad!"}):
            self.fail(self.request(secret=secret), "INVALID_REQUEST")

    def test_corrupt_crc_no_plaintext(self):
        source = self.work / "corrupt-crc.dd"
        data = bytearray(self.aes.read_bytes())
        bde = BDE(io.BytesIO(data))
        for information in bde._valid_information:
            data[information.offset + 16] ^= 1
        source.write_bytes(data)
        self.fail(self.request(source), "INVALID_SOURCE")

    def test_crc_repaired_but_authenticated_metadata_changed(self):
        source = self.work / "corrupt-auth.dd"
        data = bytearray(self.aes.read_bytes())
        bde = BDE(io.BytesIO(data))
        for information in bde._valid_information:
            data[information.offset + 17] ^= 2
            crc = zlib.crc32(data[information.offset:information.offset + information.size])
            struct.pack_into("<I", data, information.offset + information.size + 4, crc)
        source.write_bytes(data)
        # Library4.6 ignores False from metadata SHA check; our adapter enforces it.
        parsed = BDE(io.BytesIO(data))
        self.verify(len(parsed._valid_information) == 3, "tampered metadata passes plain CRC")
        self.fail(self.request(source), "AUTH_FAILED")

    def test_paused_state_is_explicitly_unsupported(self):
        source = self.work / "paused.dd"
        data = bytearray(self.aes.read_bytes())
        for information in BDE(io.BytesIO(data))._valid_information:
            struct.pack_into("<HH", data, information.offset + 12, 3, 1)
            struct.pack_into("<I", data, information.offset + information.size + 4,
                             zlib.crc32(data[information.offset:information.offset + information.size]))
        source.write_bytes(data)
        self.fail(self.request(source), "UNSUPPORTED_FORMAT")

    def test_bounds_limits_and_existing_destination(self):
        for options in ({"offset_bytes": 1}, {"offset_bytes": -512}, {"offset_bytes": 2**63},
                        {"offset_bytes": True}, {"length_bytes": 1}, {"length_bytes": self.aes.stat().st_size + 512},
                        {"max_output_bytes": 512}, {"output_length_bytes": 513},
                        {"output_length_bytes": self.aes.stat().st_size + 512}):
            self.fail(self.request(**options), "INVALID_REQUEST")
        request = self.request()
        destination = Path(request["destination"])
        destination.mkdir()
        sentinel = destination / "existing.txt"
        sentinel.write_text("keep", encoding="ascii")
        self.fail(request, "INVALID_REQUEST")
        self.verify(sentinel.read_text() == "keep", "existing output remains unchanged")
        request = self.request()
        request["destination"] = str(self.aes)
        self.fail(request, "INVALID_SOURCE")

    def test_interruption_leaves_only_partial(self):
        request = self.request()
        before = sha(self.aes)
        def stop(kind, **fields):
            if fields.get("phase") == "decrypt":
                raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            handle_bitlocker(request, stop)
        destination = Path(request["destination"])
        self.verify(not list(destination.glob("*.dd")), "interrupted image never published")
        self.verify(any(path.stat().st_size > 0 for path in destination.glob("*.partial")), "partial bytes retained for diagnosis")
        self.verify(before == sha(self.aes), "interrupted source unchanged")

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics")
    def test_source_handle_prevents_writes(self):
        request = self.request()
        blocked = []
        def probe(kind, **fields):
            if fields.get("phase") == "source_hash" and not blocked:
                try:
                    fd = os.open(self.aes, os.O_WRONLY)
                except PermissionError:
                    blocked.append(True)
                else:
                    os.close(fd)
                    blocked.append(False)
        result = handle_bitlocker(request, probe)
        self.verify(result["status"] == "partial" and blocked == [True], "source cannot be opened for writing during read")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    args = parser.parse_args()
    FIXTURES = args.fixtures.resolve()
    archive = PROJECT / "helpers/recovery_engine/dependency-sources/dissect_fve-4.6.tar.gz"
    if FIXTURES.is_file():
        archive = FIXTURES
    if FIXTURES.is_file() or not FIXTURES.is_dir():
        pins = json.loads((PROJECT / "helpers/recovery_engine/storage-dependencies.json").read_text(encoding="utf-8-sig"))
        pin = next(item for item in pins if item["name"] == "dissect.fve")
        if archive.name != pin["source"] or hashlib.sha256(archive.read_bytes()).hexdigest() != pin["sha256"]:
            raise RuntimeError("Pinned source archive mismatch")
        temporary_fixtures = tempfile.TemporaryDirectory(prefix="recovery-bde-upstream-")
        import atexit
        atexit.register(temporary_fixtures.cleanup)
        FIXTURES = Path(temporary_fixtures.name)
        with tarfile.open(archive, "r:gz") as source_archive:
            for member in source_archive.getmembers():
                token = "/tests/_data/bde/"
                if token not in member.name or not member.isfile():
                    continue
                name = member.name.split(token, 1)[1]
                if Path(name).name != name or not (name.endswith(".bin.gz") or name.endswith(".bek")) or member.size > 16 * 1024 * 1024:
                    continue
                with source_archive.extractfile(member) as source_file, (FIXTURES / name).open("xb") as output_file:
                    shutil.copyfileobj(source_file, output_file)

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BitLockerRecovery))
    if result.wasSuccessful():
        print(f"PASS BitLockerRecovery: {checks} checks; upstream known encrypted fixtures, six ciphers, recovery/BEK, authenticated metadata, prefix completeness, bounded views, cancellation and Windows read locks; no physical devices")
    sys.exit(0 if result.wasSuccessful() else 1)
