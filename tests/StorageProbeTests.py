"""Signature/partition discovery tests; no filesystem or crypto is simulated."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers" / "recovery_engine"))
from storage_probe import probe


class StorageProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="storage-probe-generated-")
        self.root = Path(self.temporary.name)
        self.counter = 0

    def tearDown(self):
        self.temporary.cleanup()

    def image(self, data, suffix=".dd"):
        self.counter += 1
        path = self.root / (str(self.counter) + suffix)
        path.write_bytes(data)
        return path

    @staticmethod
    def magic(data, offset, kind):
        if kind == "APFS":
            data[offset + 32:offset + 36] = b"NXSB"
        else:
            data[offset + 3:offset + 11] = b"-FVE-FS-"

    def inspect(self, data):
        path = self.image(data)
        original = hashlib.sha256(path.read_bytes()).hexdigest()
        emitted = []
        result = probe({"source": str(path)}, emitted.append)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), original)
        self.assertEqual(emitted, [])
        return result

    def detected(self, result, expected):
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["code"], "OK")
        self.assertTrue(result["detection_only"])
        self.assertEqual([(v["kind"], v["offset_bytes"]) for v in result["volumes"]], expected)
        self.assertNotIn("files", result)
        self.assertNotIn("recovered", result)

    @staticmethod
    def refresh_header(data, sector):
        size = struct.unpack_from("<I", data, sector + 12)[0]
        struct.pack_into("<I", data, sector + 16, 0)
        struct.pack_into("<I", data, sector + 16, zlib.crc32(data[sector:sector + size]))

    def gpt(self, sector=512, entries=None):
        # Proper GPT disk/header/table geometry. Only the volume magic is
        # generated: probe must explicitly report detection, not successful read.
        data = bytearray(128 * sector)
        data[510:512] = b"\x55\xaa"
        data[450] = 0xEE
        struct.pack_into("<II", data, 454, 1, 127)
        records = entries or [(8, 23, "APFS"), (32, 47, "BitLocker")]
        table = bytearray(4 * 128)
        for index, (first, last, kind) in enumerate(records):
            record = index * 128
            table[record:record + 16] = uuid.UUID("7c3457ef-0000-11aa-aa11-00306543ecac").bytes_le
            table[record + 16:record + 32] = uuid.UUID(int=index + 1).bytes_le
            struct.pack_into("<QQ", table, record + 32, first, last)
            if 0 <= first * sector < len(data) - 4096:
                self.magic(data, first * sector, kind)
        data[2 * sector:2 * sector + len(table)] = table
        header = sector
        data[header:header + 8] = b"EFI PART"
        struct.pack_into("<III", data, header + 8, 0x10000, 92, 0)
        struct.pack_into("<QQQQ", data, header + 24, 1, 127, 4, 126)
        data[header + 56:header + 72] = uuid.UUID(int=9244).bytes_le
        struct.pack_into("<QIII", data, header + 72, 2, 4, 128, zlib.crc32(table))
        self.refresh_header(data, sector)
        return data

    def test_raw_apfs_magic_is_only_detection(self):
        data = bytearray(8192)
        self.magic(data, 0, "APFS")
        self.detected(self.inspect(data), [("APFS", 0)])

    def test_raw_bitlocker_magic_does_not_attempt_authentication(self):
        data = bytearray(8192)
        self.magic(data, 0, "BitLocker")
        self.detected(self.inspect(data), [("BitLocker", 0)])

    def test_unknown_data_and_short_image_have_no_claimed_volume(self):
        for size in (0, 35, 511, 8192):
            self.detected(self.inspect(bytes(size)), [])

    def test_missing_extension_is_accepted(self):
        data = bytearray(4096)
        self.magic(data, 0, "APFS")
        path = self.image(data, "")
        self.detected(probe({"source": str(path)}), [("APFS", 0)])

    def test_gpt_512_two_volume_candidates(self):
        self.detected(self.inspect(self.gpt()), [("APFS", 8 * 512), ("BitLocker", 32 * 512)])

    def test_gpt_4096_sector_geometry(self):
        self.detected(self.inspect(self.gpt(4096)), [("APFS", 8 * 4096), ("BitLocker", 32 * 4096)])

    def test_gpt_header_crc_mismatch_is_not_treated_as_valid_mbr(self):
        data = self.gpt()
        data[512 + 56] ^= 0x10
        result = self.inspect(data)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["volumes"], [])
        self.assertIn("GPT_HEADER_INVALID", result["warnings"])
        self.assertTrue(result["detection_only"])

    def test_gpt_table_crc_mismatch(self):
        data = self.gpt()
        data[1024 + 56] ^= 0x08
        result = self.inspect(data)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["volumes"], [])
        self.assertIn("GPT_TABLE_INVALID", result["warnings"])

    def test_gpt_out_of_bounds_table_is_rejected_before_read(self):
        data = self.gpt()
        struct.pack_into("<Q", data, 512 + 72, 0xFFFFFFFFFFFFFFFF)
        self.refresh_header(data, 512)
        result = self.inspect(data)
        self.assertEqual(result["volumes"], [])
        self.assertIn("GPT_TABLE_INVALID", result["warnings"])

    def test_gpt_candidate_count_and_entry_size_are_bounded(self):
        for count, width in ((4097, 128), (0xFFFFFFFF, 128), (4, 127), (4, 4097)):
            data = self.gpt()
            struct.pack_into("<II", data, 512 + 80, count, width)
            self.refresh_header(data, 512)
            result = self.inspect(data)
            self.assertEqual(result["volumes"], [])
            self.assertIn("GPT_HEADER_INVALID", result["warnings"])

    def test_gpt_header_size_is_bounded(self):
        for size in (91, 513, 0xFFFFFFFF):
            data = self.gpt()
            struct.pack_into("<I", data, 512 + 12, size)
            result = self.inspect(data)
            self.assertEqual(result["volumes"], [])
            self.assertIn("GPT_HEADER_INVALID", result["warnings"])

    def test_gpt_partition_range_failures_do_not_hide_other_candidates(self):
        for first, last in ((24, 8), (1, 16), (8, 1000)):
            data = self.gpt(entries=[(first, last, "APFS"), (32, 47, "BitLocker")])
            result = self.inspect(data)
            self.assertEqual([(v["kind"], v["offset_bytes"]) for v in result["volumes"]], [("BitLocker", 32 * 512)])
            self.assertIn("PARTITION_RANGE_INVALID", result["warnings"])
            self.assertEqual(result["status"], "partial")

    def mbr(self, records):
        data = bytearray(128 * 512)
        data[510:512] = b"\x55\xaa"
        for index, (first, count, kind) in enumerate(records):
            at = 446 + 16 * index
            data[at + 4] = 7
            struct.pack_into("<II", data, at + 8, first, count)
            if first * 512 <= len(data) - 4096:
                self.magic(data, first * 512, kind)
        return data

    def test_mbr_primary_volume_candidates(self):
        self.detected(self.inspect(self.mbr([(8, 16, "APFS"), (32, 16, "BitLocker")])), [("APFS", 8 * 512), ("BitLocker", 32 * 512)])

    def test_mbr_signature_and_bounds_are_required(self):
        data = self.mbr([(8, 16, "APFS")])
        data[510:512] = b"\0\0"
        self.detected(self.inspect(data), [])
        self.detected(self.inspect(self.mbr([(8, 1000, "APFS")])), [])

    def test_duplicate_volume_offsets_are_not_duplicated(self):
        result = self.inspect(self.mbr([(8, 16, "APFS"), (8, 16, "APFS")]))
        self.detected(result, [("APFS", 8 * 512)])
        self.assertEqual(result["volumes"][0]["identifier"], "4096:8192")

    def test_partial_missing_and_nonregular_sources_fail(self):
        paths = [self.image(bytes(4096), ".partial"), self.image(bytes(4096), ".PARTIAL"), self.root, self.root / "not-there.dd"]
        for path in paths:
            result = probe({"source": str(path)})
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["code"], "INVALID_SOURCE")
            self.assertEqual(result["volumes"], [])

    def test_malformed_requests_have_no_success_result(self):
        for request in ({}, {"source": None}, {"source": 391}, {"source": []}):
            result = probe(request)
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["volumes"], [])

    def test_file_and_ancestor_symbolic_links_are_rejected(self):
        directory = self.root / "real"
        directory.mkdir()
        target = directory / "image.dd"
        target.write_bytes(bytes(4096))
        file_link, folder_link = self.root / "alias.dd", self.root / "alias-folder"
        try:
            file_link.symlink_to(target)
            folder_link.symlink_to(directory, target_is_directory=True)
        except OSError as error:
            self.skipTest("Symlink creation unavailable: " + str(error.winerror))
        for path in (file_link, folder_link / "image.dd"):
            result = probe({"source": str(path)})
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["code"], "INVALID_SOURCE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
