"""Independent PNG context/ancillary regressions, synthetic regular images only.

The writer below implements PNG chunk framing/CRC without assembler internals.
A decoded pixel stream alone cannot resolve contradictory metadata or legalize
an invalid surviving ancillary chunk. No device or user image is accessed.
"""
from pathlib import Path
import hashlib
import io
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from fragmented_photos import recover

SIGNATURE = b"\x89PNG\r\n\x1a\n"
PALETTE = b"\x00\x00\x00\xff\xff\xff"


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def header(color):
    return SIGNATURE + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, color, 0, 0, 0))


def pixels(color):
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    raw = b"\x00" + (b"\x00\x01" if color == 3 else bytes(range(1, channels * 2 + 1)))
    return chunk(b"IDAT", zlib.compress(raw))


class PngContextAudit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="png-context-audit-")
        self.work = Path(self.temporary.name)
        self.number = 0

    def tearDown(self):
        self.temporary.cleanup()

    def recover_parts(self, parts):
        self.number += 1
        source = self.work / (str(self.number) + ".dd")
        output = self.work / (str(self.number) + "-out")
        data = bytearray(b"\xa5" * 262144)
        for offset, part in zip((4096, 65536, 131072, 196608), parts):
            data[offset:offset + len(part)] = part
        source.write_bytes(data)
        before = hashlib.sha256(data).hexdigest()
        result = recover(source, output)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertFalse((output / "job.incomplete").exists())
        return result, output

    def reject(self, color, prefix=b"", tail=b""):
        result, output = self.recover_parts([header(color) + prefix, pixels(color) + tail + chunk(b"IEND", b"")])
        self.assertEqual(result["Candidates"], 0, result)
        self.assertFalse(list(output.glob("*.png")))

    def exact(self, color, prefix):
        parts = [header(color) + prefix, pixels(color) + chunk(b"IEND", b"")]
        expected = b"".join(parts)
        from PIL import Image
        with Image.open(io.BytesIO(expected)) as image:
            image.load()
        result, output = self.recover_parts(parts)
        self.assertEqual(result["Candidates"], 1, result)
        row = result["Files"][0]
        self.assertEqual((output / row["Path"]).read_bytes(), expected)
        self.assertEqual(row["Sha256"], hashlib.sha256(expected).hexdigest())

    def test_valid_grayscale_truecolor_and_indexed_transparency_preserved(self):
        for color, prefix in ((0, chunk(b"tRNS", b"\x00\x01")),
                              (2, chunk(b"tRNS", b"\x00\x01\x00\x02\x00\x03")),
                              (3, chunk(b"PLTE", PALETTE) + chunk(b"tRNS", b"\x00\xff"))):
            with self.subTest(color=color):
                self.exact(color, prefix)

    def test_transparency_for_alpha_color_types_is_rejected(self):
        for color in (4, 6):
            with self.subTest(color=color):
                self.reject(color, chunk(b"tRNS", b"\x00" * 6))

    def test_transparency_lengths_are_checked(self):
        for color, data in ((0, b"x"), (0, b"xxx"), (2, b"xxxxx"), (2, b"xxxxxxx")):
            with self.subTest(color=color, length=len(data)):
                self.reject(color, chunk(b"tRNS", data))

    def test_indexed_alpha_count_cannot_exceed_palette(self):
        self.reject(3, chunk(b"PLTE", PALETTE) + chunk(b"tRNS", b"\x00\x10\x20"))

    def test_duplicate_transparency_rejected(self):
        self.reject(2, chunk(b"tRNS", b"\x00\x01\x00\x02\x00\x03") * 2)

    def test_transparency_after_idat_is_not_ignored_or_preserved_as_valid(self):
        self.reject(2, tail=chunk(b"tRNS", b"\x00\x01\x00\x02\x00\x03"))
        self.reject(3, chunk(b"PLTE", PALETTE), chunk(b"tRNS", b"\x00\xff"))

    def test_truecolor_palette_must_precede_transparency_if_present(self):
        self.reject(2, chunk(b"tRNS", b"\x00\x01\x00\x02\x00\x03") + chunk(b"PLTE", PALETTE))

    def test_palette_must_precede_background_if_present(self):
        self.reject(2, chunk(b"bKGD", b"\x00\x01\x00\x02\x00\x03") + chunk(b"PLTE", PALETTE))

    def test_histogram_requires_preceding_palette(self):
        self.reject(2, chunk(b"hIST", b"\x00\x01\x00\x02"))
        self.reject(2, chunk(b"hIST", b"\x00\x01\x00\x02") + chunk(b"PLTE", PALETTE))
        self.reject(3, chunk(b"hIST", b"\x00\x01\x00\x02") + chunk(b"PLTE", PALETTE))

    def test_valid_palette_transparency_background_histogram_preserved(self):
        self.exact(3, chunk(b"PLTE", PALETTE) + chunk(b"tRNS", b"\x00\xff") + chunk(b"bKGD", b"\x01") + chunk(b"hIST", b"\x00\x01\x00\x02"))
        self.exact(2, chunk(b"PLTE", PALETTE) + chunk(b"tRNS", b"\x00\x01\x00\x02\x00\x03"))

    def test_identical_idat_with_different_surviving_tails_is_ambiguous(self):
        data = pixels(2)
        first = data + chunk(b"tEXt", b"Owner\x00candidate A") + chunk(b"IEND", b"")
        second = data + chunk(b"tEXt", b"Owner\x00candidate B") + chunk(b"IEND", b"")
        result, output = self.recover_parts([header(2), first, second])
        self.assertEqual(result["Candidates"], 0, result)
        self.assertGreater(result["Skipped"].get("png_ambiguous", 0), 0)
        self.assertFalse(list(output.glob("*.png")))

    def test_identical_idat_and_identical_context_are_one_result(self):
        tail = pixels(2) + chunk(b"tEXt", b"Owner\x00same candidate") + chunk(b"IEND", b"")
        result, output = self.recover_parts([header(2), tail, tail])
        self.assertEqual(result["Candidates"], 1, result)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), header(2) + tail)


    def test_detached_iend_preserves_already_linked_ancillary_tail(self):
        tail = pixels(2) + chunk(b"tEXt", b"Owner\x00preserved tail")
        parts = [header(2), tail, chunk(b"IEND", b"")]
        result, output = self.recover_parts(parts)
        self.assertEqual(result["Candidates"], 1, result)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), b"".join(parts))

    def test_detached_iend_does_not_erase_tail_ambiguity(self):
        data = pixels(2)
        first = data + chunk(b"tEXt", b"Owner\x00candidate A")
        second = data + chunk(b"tEXt", b"Owner\x00candidate B")
        result, output = self.recover_parts([header(2), first, second, chunk(b"IEND", b"")])
        self.assertEqual(result["Candidates"], 0, result)
        self.assertGreater(result["Skipped"].get("png_ambiguous", 0), 0)
        self.assertFalse(list(output.glob("*.png")))


if __name__ == "__main__":
    unittest.main(verbosity=2)