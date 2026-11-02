"""Independent Pillow encodings and physical two-gap/source-checkpoint controls."""
from pathlib import Path
import hashlib
import io
import itertools
import json
import random
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from fragmented_photos import PhotoAssembler, recover
from jpeg_fragments import recover_jpegs
from PIL import Image


def encoded(seed=71, last=None):
    rng = random.Random(seed)
    image = Image.new("L", (83, 61))
    image.putdata([rng.randrange(256) for _ in range(image.width * image.height)])
    if last is not None:
        image.putpixel((82, 60), last)
    data = io.BytesIO()
    image.save(data, "JPEG", quality=85)
    return data.getvalue()


def scattered(raw, *, alternate=None, duplicate=False, overwritten=False):
    # The independent scatterer never reads the Huffman parser/checkpoints.
    positions, points = [32 * 512, 300 * 512, 150 * 512], [0, 512, 1024, len(raw)]
    image = bytearray(b"\xcc" * (256 * 1024))
    for at, a, b in zip(positions, points, points[1:]):
        image[at:at + b - a] = raw[a:b]
    if alternate is not None:
        at = 400 * 512
        image[at:at + len(alternate) - 1024] = alternate[1024:]
    if duplicate:
        image[420 * 512:421 * 512] = raw[512:1024]
    if overwritten:
        image[positions[2]:positions[2] + 64] = b"\x00" * 64
    return bytes(image), positions


class TwoGapJpegs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jpeg-two-gap-")
        self.root = Path(self.temp.name)
        self.source, self.output = self.root / "image.dd", self.root / "output"
        self.raw = encoded()

    def tearDown(self):
        self.temp.cleanup()

    def search(self, image, options=None):
        self.source.write_bytes(image)
        before = hashlib.sha256(image).hexdigest()
        with self.source.open("rb") as stream:
            assembler = PhotoAssembler(stream, options)
            assembler.index()
            found = list(recover_jpegs(assembler))
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), before)
        return found, assembler

    def test_two_gaps_exact_bytes_pixels_and_disjoint_source_extents(self):
        image, positions = scattered(self.raw)
        found, assembler = self.search(image)
        self.assertEqual(len(found), 1, assembler.skipped)
        recipe, status, note = found[0]
        self.assertEqual(b"".join(raw for _, raw in recipe), self.raw)
        self.assertEqual([at for at, _ in recipe], positions)
        self.assertEqual([len(raw) for _, raw in recipe], [512, 512, len(self.raw) - 1024])
        for at, raw in recipe:
            self.assertEqual(image[at:at + len(raw)], raw)
        with Image.open(io.BytesIO(self.raw)) as expected, Image.open(io.BytesIO(b"".join(raw for _, raw in recipe))) as actual:
            self.assertEqual(expected.tobytes(), actual.tobytes())
        self.assertEqual(status, "jpeg_gap_structural_candidate")
        self.assertIn("minimum-gap", note)
        self.assertIn("not authenticated", note)

    def test_equal_length_independently_encoded_distinct_valid_tails_are_ambiguous(self):
        alternate = next((other for value in range(256)
                          if (other := encoded(last=value)) != self.raw
                          and len(other) == len(self.raw) and other[:1024] == self.raw[:1024]), None)
        self.assertIsNotNone(alternate, "Independent encoder did not produce the control")
        with Image.open(io.BytesIO(alternate)) as check:
            check.load()
        image, _ = scattered(self.raw, alternate=alternate)
        found, assembler = self.search(image)
        self.assertEqual(len(found), 2)
        self.assertEqual(assembler.skipped["jpeg_gap_ambiguous"], 1)
        self.assertEqual(len({hashlib.sha256(b"".join(raw for _, raw in row[0])).digest() for row in found}), 2)
        for recipe, status, note in found:
            self.assertEqual(status, "jpeg_gap_ambiguous_candidate")
            self.assertIn("not exhaustively enumerated", note)
            self.assertIn("placement are unknown", note)
            for at, raw in recipe:
                self.assertEqual(image[at:at + len(raw)], raw)

    def test_overwritten_tail_is_not_synthesized(self):
        found, assembler = self.search(scattered(self.raw, overwritten=True)[0])
        self.assertEqual(found, [], assembler.skipped)

    def test_identical_middle_alias_preserves_unknown_original_mapping(self):
        image, _ = scattered(self.raw, duplicate=True)
        found, assembler = self.search(image)
        self.assertEqual(len(found), 1, assembler.skipped)
        self.assertEqual(b"".join(raw for _, raw in found[0][0]), self.raw)
        self.assertEqual(assembler.skipped["jpeg_gap_source_mapping_ambiguous"], 1)
        self.assertIn("physical placement is unknown", found[0][2])

    def test_search_budget_is_incomplete_without_advancing_candidate(self):
        self.source.write_bytes(scattered(self.raw)[0])
        anchors = []
        report = recover(self.source, self.output, {"max_states": 1}, checkpoint_progress=anchors.append)
        self.assertEqual(report["Status"], "limited")
        self.assertEqual(report["Candidates"], 0)
        self.assertTrue(any(key.endswith("_incomplete") for key in report["Skipped"]))
        state = json.loads(Path(anchors[-1]["Path"]).read_text(encoding="utf-8"))
        self.assertEqual(state["Cursor"]["Jpeg"], 0)
        self.assertTrue((self.output / "job.incomplete").exists())

    def test_cancel_inside_entropy_search_resumes_from_durable_candidate_boundary(self):
        self.source.write_bytes(scattered(self.raw)[0])
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        anchors, polls, phase = [], 0, None
        def acknowledged(row):
            nonlocal phase
            anchors.append(row)
            phase = json.loads(Path(row["Path"]).read_text(encoding="utf-8"))["Phase"]
        def cancelled(done, total):
            nonlocal polls
            if phase == "candidates":
                polls += 1
                if polls == 2:
                    raise InterruptedError("owned entropy cancellation")
        ticks = itertools.count()
        with patch("jpeg_fragments.time", SimpleNamespace(monotonic=lambda: next(ticks))), self.assertRaisesRegex(InterruptedError, "owned entropy"):
            recover(self.source, self.output, progress=cancelled, checkpoint_progress=acknowledged)
        state = json.loads(Path(anchors[-1]["Path"]).read_text(encoding="utf-8"))
        self.assertEqual(state["Cursor"]["Jpeg"], 0)
        self.assertFalse(list(self.output.glob("*.jpg")))
        report = recover(self.source, self.output, {"resume_checkpoint": anchors[-1]})
        self.assertEqual(report["Status"], "complete")
        self.assertTrue(report["ResumedFromCheckpoint"])
        self.assertEqual(report["Candidates"], 1)
        self.assertEqual((self.output / report["Files"][0]["Path"]).read_bytes(), self.raw)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), before)
        self.assertFalse((self.output / "job.incomplete").exists())

    def test_completed_ambiguous_witnesses_resume_with_unknown_status_intact(self):
        alternate = next(other for value in range(256)
                         if (other := encoded(last=value)) != self.raw
                         and len(other) == len(self.raw) and other[:1024] == self.raw[:1024])
        self.source.write_bytes(scattered(self.raw, alternate=alternate)[0])
        anchors = []
        def stop(row):
            anchors.append(row)
            state = json.loads(Path(row["Path"]).read_text(encoding="utf-8"))
            if state["Cursor"]["Jpeg"] == 1:
                raise InterruptedError("owned acknowledged ambiguity")
        with self.assertRaisesRegex(InterruptedError, "acknowledged ambiguity"):
            recover(self.source, self.output, checkpoint_progress=stop)
        # A completed JPEG start is reused, rather than selecting one witness
        # or attempting to re-establish uniqueness from decoder success.
        report = recover(self.source, self.output, {"resume_checkpoint": anchors[-1]})
        self.assertEqual(report["ReusedCandidates"], 2)
        self.assertEqual({row["Status"] for row in report["Files"]}, {"jpeg_gap_ambiguous_candidate"})
        self.assertEqual(report["Skipped"]["jpeg_gap_ambiguous"], 1)
        self.assertEqual(len(list(self.output.glob("*.jpg"))), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
