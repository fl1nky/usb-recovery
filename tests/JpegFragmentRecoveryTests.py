"""Real Pillow JPEGs, independent scattering and strict entropy-negative tests."""
from pathlib import Path
import hashlib
import io
import random
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers/recovery_engine"))
from fragmented_photos import LimitReached, PhotoAssembler
from jpeg_fragments import InvalidJpeg, entropy, header, huffman, recover_jpegs
from PIL import Image


def jpeg(seed=71, *, gray=False, progressive=False, restart=8, subsampling=0):
    rng = random.Random(seed)
    image = Image.new("L" if gray else "RGB", (83, 61))
    image.putdata([rng.randrange(256) if gray else tuple(rng.randrange(256) for _ in range(3))
                   for _ in range(image.width * image.height)])
    out = io.BytesIO()
    image.save(out, "JPEG", quality=85, progressive=progressive,
               subsampling=subsampling, restart_marker_blocks=restart)
    return out.getvalue()


def rst_cuts(raw):
    return [p + 2 for p in range(len(raw) - 1) if raw[p] == 255 and 0xd0 <= raw[p + 1] <= 0xd7]


def pixels(raw):
    with Image.open(io.BytesIO(raw)) as image:
        image.load()
        return hashlib.sha256(image.tobytes()).hexdigest()


class JpegFragments(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jpeg-fragments-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def source(self, raw, *, two=False, alternate=None, duplicate=False, damage=None):
        cuts = rst_cuts(raw)
        self.assertGreaterEqual(len(cuts), 3)
        cuts = [cuts[len(cuts) // 3]] if two else [cuts[len(cuts) // 3], cuts[len(cuts) * 2 // 3]]
        boundaries = [0, *cuts, len(raw)]
        pieces = [raw[a:b] for a, b in zip(boundaries, boundaries[1:])]
        positions = [700 * 512, 2500 * 512, 1300 * 512]
        data = bytearray(b"\xcc" * (2 * 1024 * 1024))
        for physical, piece in zip(positions, pieces):
            data[physical:physical + len(piece)] = piece
        if alternate is not None:
            alt_cuts = rst_cuts(alternate)
            # Match restart stage by ordinal, not by byte position/length.
            stage = rst_cuts(raw).index(cuts[0])
            tail = alternate[alt_cuts[stage]:]
            data[3300 * 512:3300 * 512 + len(tail)] = tail
        if duplicate:
            tail = pieces[-1]
            data[3500 * 512:3500 * 512 + len(tail)] = tail
        if damage == "eoi":
            last = positions[len(pieces) - 1] + len(pieces[-1])
            data[last - 2:last] = b"\x00\x00"
        if damage == "restart":
            at = positions[0] + cuts[0] - 1
            data[at] = 0xd7 if data[at] != 0xd7 else 0xd6
        if damage == "padding":
            at = positions[0] + cuts[0] - 3
            data[at] &= 0xfe
        path = self.root / "image.dd"
        path.write_bytes(data)
        return path, positions[:len(pieces)], pieces

    def run_recovery(self, path, options=None):
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open("rb") as stream:
            assembler = PhotoAssembler(stream, options)
            assembler.index()
            found = list(recover_jpegs(assembler))
        self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())
        return found, assembler

    def test_three_islands_exact_bytes_pixels_and_extents(self):
        raw = jpeg()
        path, positions, pieces = self.source(raw)
        found, assembler = self.run_recovery(path)
        self.assertEqual(len(found), 1, assembler.skipped)
        recipe, status, note = found[0]
        result = b"".join(part for _, part in recipe)
        self.assertEqual(result, raw)
        self.assertEqual(pixels(result), pixels(raw))
        self.assertEqual([at for at, _ in recipe], positions)
        self.assertEqual([part for _, part in recipe], pieces)
        self.assertEqual(status, "jpeg_restart_structural_candidate")
        self.assertIn("not authenticated", note)

    def test_grayscale_and_partial_final_interval(self):
        raw = jpeg(gray=True, restart=7)
        path, _, _ = self.source(raw)
        found, assembler = self.run_recovery(path)
        self.assertEqual(len(found), 1, assembler.skipped)
        self.assertEqual(b"".join(part for _, part in found[0][0]), raw)

    def test_subsampled_color(self):
        raw = jpeg(subsampling=2, restart=3)
        path, _, _ = self.source(raw)
        found, assembler = self.run_recovery(path)
        self.assertEqual(len(found), 1, assembler.skipped)
        self.assertEqual(b"".join(part for _, part in found[0][0]), raw)

    def test_distinct_equal_stage_tails_are_ambiguous(self):
        path, _, _ = self.source(jpeg(71), two=True, alternate=jpeg(72))
        found, assembler = self.run_recovery(path)
        self.assertEqual(found, [])
        self.assertGreater(assembler.skipped["jpeg_restart_ambiguous"], 0)

    def test_identical_duplicate_does_not_create_two_files(self):
        raw = jpeg()
        path, _, _ = self.source(raw, duplicate=True)
        found, assembler = self.run_recovery(path)
        self.assertEqual(len(found), 1, assembler.skipped)
        self.assertEqual(b"".join(part for _, part in found[0][0]), raw)

    def test_missing_eoi_rejected(self):
        path, _, _ = self.source(jpeg(), damage="eoi")
        found, _ = self.run_recovery(path)
        self.assertEqual(found, [])

    def test_wrong_restart_sequence_rejected(self):
        path, _, _ = self.source(jpeg(), damage="restart")
        found, _ = self.run_recovery(path)
        self.assertEqual(found, [])

    def test_arithmetic_coding_is_explicitly_unsupported(self):
        raw = jpeg(progressive=True).replace(b"\xff\xc2", b"\xff\xc9", 1)
        path, _, _ = self.source(raw)
        found, assembler = self.run_recovery(path)
        self.assertEqual(found, [])
        self.assertGreater(assembler.skipped["jpeg_progressive_or_coding_unsupported"], 0)

    def test_search_budget_is_not_success(self):
        path, _, _ = self.source(jpeg())
        found, assembler = self.run_recovery(path, {"max_states": 1})
        self.assertEqual(found, [])
        self.assertTrue(any(name.endswith("_incomplete") for name in assembler.skipped))

    def test_existing_time_budget_propagates(self):
        path, _, _ = self.source(jpeg())
        with path.open("rb") as stream:
            assembler = PhotoAssembler(stream)
            assembler.index()
            assembler.started = time.monotonic() - 121
            with self.assertRaises(LimitReached):
                list(recover_jpegs(assembler))

    def test_entropy_requires_exact_mcu_count_and_one_padding(self):
        dc, ac = {(1, 0): 0}, {(1, 0): 0}
        entropy(b"\x3f", [(dc, ac)], 1)
        entropy(b"\x0f", [(dc, ac)], 2)
        for raw, count in ((b"\x3e", 1), (b"\x0f", 1), (b"\x3f", 2), (b"\x3f\x00", 1)):
            with self.subTest(raw=raw, count=count), self.assertRaises(InvalidJpeg):
                entropy(raw, [(dc, ac)], count)

    def test_entropy_rejects_invalid_categories_and_runs(self):
        with self.assertRaises(InvalidJpeg):
            entropy(b"\x7f", [({(1, 0): 12}, {(1, 0): 0})], 1)
        with self.assertRaises(InvalidJpeg):
            entropy(b"\x00\x00", [({(1, 0): 0}, {(1, 0): 0x10})], 1)
        with self.assertRaises(InvalidJpeg):
            entropy(b"\x00\x00", [({(1, 0): 0}, {(1, 0): 0xf1})], 1)

    def test_huffman_table_bounds(self):
        with self.assertRaises(InvalidJpeg):
            huffman([3] + [0] * 15, [0, 1, 2])
        with self.assertRaises(InvalidJpeg):
            huffman([2] + [0] * 15, [0, 1])
        with self.assertRaises(InvalidJpeg):
            huffman([1] + [0] * 15, [])

    def test_corrupt_header_does_not_become_candidate(self):
        raw = bytearray(jpeg())
        at = raw.index(b"\xff\xc4")
        raw[at + 2:at + 4] = b"\xff\xff"
        path, _, _ = self.source(bytes(raw))
        found, assembler = self.run_recovery(path)
        self.assertEqual(found, [])
        self.assertTrue(assembler.skipped)

    def test_contiguous_jpeg_is_left_to_normal_carving(self):
        path = self.root / "contiguous.dd"
        path.write_bytes(b"\xcc" * 4096 + jpeg() + b"\xcc" * 4096)
        found, _ = self.run_recovery(path)
        self.assertEqual(found, [])

    def test_single_sector_aligned_gap_without_restart(self):
        rng = random.Random(17)
        image = Image.new("L", (47, 31))
        image.putdata([rng.randrange(256) for _ in range(image.width * image.height)])
        data = io.BytesIO(); image.save(data, "JPEG", quality=55)
        raw = data.getvalue()
        self.assertGreater(len(raw), 512)
        image = bytearray(b"\xcc" * (2 * 1024 * 1024))
        first, second = 2500 * 512, 500 * 512
        image[first:first + 512] = raw[:512]
        image[second:second + len(raw) - 512] = raw[512:]
        path = self.root / "single-gap.dd"
        path.write_bytes(image)
        found, assembler = self.run_recovery(path)
        self.assertEqual(len(found), 1, assembler.skipped)
        recipe, status, note = found[0]
        self.assertEqual(status, "jpeg_gap_structural_candidate")
        self.assertEqual([at for at, _ in recipe], [first, second])
        self.assertEqual(b"".join(part for _, part in recipe), raw)
        self.assertEqual(pixels(b"".join(part for _, part in recipe)), pixels(raw))
        self.assertIn("128 KiB", note)


if __name__ == "__main__":
    unittest.main(verbosity=2)
