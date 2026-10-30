"""Real progressive JPEG first/refine, restart/scan and entropy-cut evidence."""
from pathlib import Path
from collections import Counter
import hashlib
import io
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers/recovery_engine"))
from fragmented_photos import PhotoAssembler, LimitReached, disjoint
from jpeg_fragments import (Bits, InvalidJpeg, ProgressiveState, header, progressive_block,
                            progressive_entropy, progressive_checkpoint, progressive_metadata, recover_jpegs)
from build_progressive_jpeg_fixtures import markers, scans, scatter, specimen
from PIL import Image
EXTERNAL = False


def pixels(raw):
    with Image.open(io.BytesIO(raw)) as image:
        image.load()
        return hashlib.sha256(image.tobytes()).hexdigest()


class ProgressiveRecovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="jpeg-progressive-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_image(self, data, options=None):
        path = self.root / (str(len(list(self.root.iterdir()))) + ".dd")
        path.write_bytes(data)
        before = hashlib.sha256(data).hexdigest()
        with path.open("rb") as stream:
            assembler = PhotoAssembler(stream, options)
            assembler.index()
            results = list(recover_jpegs(assembler))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
        return results, assembler

    def split(self, raw):
        cuts = [end for _, end, code in markers(raw) if 0xd0 <= code <= 0xd7]
        if not cuts:
            cuts = [scan["header"] for scan in scans(raw)][1:]
        return [cuts[len(cuts) // 3], cuts[len(cuts) * 2 // 3]]

    def assert_exact(self, raw, data, expected_status="jpeg_progressive_structural_candidate"):
        results, assembler = self.run_image(data)
        self.assertEqual(len(results), 1, assembler.skipped)
        recipe, status, note = results[0]
        self.assertTrue(disjoint(recipe))
        self.assertGreaterEqual(len(recipe), 2)
        rebuilt = b"".join(part for _, part in recipe)
        self.assertEqual(rebuilt, raw)
        self.assertEqual(pixels(rebuilt), pixels(raw))
        self.assertEqual(status, expected_status)
        self.assertIn("not authenticated", note)
        for position, part in recipe:
            self.assertEqual(data[position:position + len(part)], part)
        return results

    def test_real_ten_scan_rgb_restart_islands(self):
        raw = specimen()
        script = [scan["script"] for scan in scans(raw)]
        self.assertGreaterEqual(len(script), 10)
        self.assertTrue(any(ss == 0 and ah_al >> 4 for ss, _, ah_al in script))
        self.assertTrue(any(ss > 0 and ah_al >> 4 for ss, _, ah_al in script))
        self.assert_exact(raw, scatter(raw, self.split(raw))[0])

    def test_grayscale_partial_final_restart(self):
        raw = specimen(gray=True, restart=7)
        self.assert_exact(raw, scatter(raw, self.split(raw))[0])

    def test_subsampled_padded_dc_blocks_match_ac_grid(self):
        raw = specimen(subsampling=2, restart=3)
        self.assert_exact(raw, scatter(raw, self.split(raw))[0])

    def test_scan_islands_without_restart(self):
        raw = specimen(restart=0)
        self.assert_exact(raw, scatter(raw, self.split(raw))[0])

    def test_ambiguous_distinct_metadata_tail_is_rejected(self):
        raw = specimen()
        comment = b"original-A"
        raw = raw[:-2] + b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment + raw[-2:]
        data, _ = scatter(raw, self.split(raw), alternate=True)
        results, assembler = self.run_image(data)
        self.assertEqual(results, [])
        self.assertGreater(assembler.skipped["jpeg_progressive_ambiguous"], 0)

    def test_identical_duplicate_does_not_create_ambiguity(self):
        raw = specimen()
        self.assert_exact(raw, scatter(raw, self.split(raw), duplicate=True)[0])

    def test_missing_eoi_and_bad_restart_do_not_publish(self):
        raw = specimen()
        for damage in ("eoi", "restart"):
            with self.subTest(damage=damage):
                results, _ = self.run_image(scatter(raw, self.split(raw), damage=damage)[0])
                self.assertEqual(results, [])

    def test_refinement_script_wrong_predecessor_rejected(self):
        raw = bytearray(specimen())
        refine = next(scan for scan in scans(raw) if scan["script"][0] > 0 and scan["script"][2] >> 4)
        raw[refine["start"] - 1] = 0x31
        results, _ = self.run_image(scatter(bytes(raw), self.split(raw))[0])
        self.assertEqual(results, [])

    def test_ac_first_invalid_category_and_refine_invalid_size(self):
        for ah, symbol in ((0, 0x0b), (1, 0x02), (0, 0xf1), (1, 0xf1), (1, 0xf0)):
            with self.subTest(ah=ah, symbol=symbol), self.assertRaises(InvalidJpeg):
                progressive_block(Bits(b"\x00\x00"), 0, {}, {(1, 0): symbol}, 1, 2, ah, 0, 0)

    def test_refine_consumes_existing_nonzero_correction_bits(self):
        mask = (1 << 1) | (1 << 3)
        new_mask, remaining, _ = progressive_block(Bits(b"\x3f"), mask, {}, {(1, 0): 0}, 1, 3, 1, 0, 0)
        self.assertEqual((new_mask, remaining), (mask, 0))
        with self.assertRaises(InvalidJpeg):
            progressive_block(Bits(b""), mask, {}, {}, 1, 3, 1, 1, 0)

    def test_existing_global_time_and_search_budget(self):
        raw = specimen()
        data, _ = scatter(raw, self.split(raw))
        results, assembler = self.run_image(data, {"max_states": 1})
        self.assertEqual(results, [])
        self.assertTrue(any(key.endswith("incomplete") for key in assembler.skipped))
        path = self.root / "late.dd"
        path.write_bytes(data)
        with path.open("rb") as stream:
            assembler = PhotoAssembler(stream)
            assembler.index()
            assembler.started = time.monotonic() - 121
            with self.assertRaises(LimitReached):
                list(recover_jpegs(assembler))

    def test_coefficient_queue_memory_budget_cannot_publish(self):
        raw = specimen()
        with patch("jpeg_fragments.MAX_PROGRESSIVE_MEMORY", 1):
            results, assembler = self.run_image(scatter(raw, self.split(raw))[0])
        self.assertEqual(results, [])
        self.assertGreater(assembler.skipped["jpeg_progressive_memory_search_incomplete"], 0)

    def test_contiguous_is_left_to_normal_carving(self):
        results, _ = self.run_image(b"\xcc" * 1024 + specimen() + b"\xcc" * 1024)
        self.assertEqual(results, [])

    def test_nonrestart_single_4k_boundary_inside_entropy(self):
        raw = specimen(restart=0, size=(256, 128))
        self.assertTrue(any(scan["start"] < 4096 < scan["end"] for scan in scans(raw)))
        self.assert_exact(raw, scatter(raw, [4096])[0])

    def test_restart_single_sector_boundary_inside_entropy(self):
        raw = specimen(restart=64, size=(256, 128))
        # The split is a medium boundary, not a JPEG restart or scan boundary.
        self.assertNotIn(4096, {end for _, end, _ in markers(raw)})
        self.assert_exact(raw, scatter(raw, [4096])[0])

    def test_checkpoint_preserves_dc_eobrun_masks_and_partial_byte(self):
        raw = specimen(restart=16, subsampling=2)
        path = self.root / "reference.jpg"
        path.write_bytes(raw)
        with path.open("rb") as stream:
            assembler = PhotoAssembler(stream)
            frame = header(assembler, 0, allow_progressive=True)
            state, position, modes = ProgressiveState(frame), frame["scan"], set()
            all_markers = markers(raw)
            while not state.finished:
                if state.mode == "metadata":
                    payload = progressive_metadata(assembler, position, state)
                    position += len(payload)
                    continue
                at, end, code = next(item for item in all_markers if item[0] >= position)
                count = min(state.interval or state.scan["total"], state.scan["total"] - state.completed)
                data = raw[position:at]
                mode = state.scan["ss"] == 0, state.scan["ah"] != 0
                reference = state.clone()
                progressive_entropy(data, reference, count)
                if mode not in modes and len(data) > 3:
                    cuts = [len(data) // 2]
                    if b"\xff\x00" in data:
                        cuts.append(data.index(b"\xff\x00") + 1)
                    for cut in cuts:
                        partial = state.clone()
                        checkpoint = progressive_checkpoint(data[:cut], partial, count)
                        progressive_entropy(data, partial, count, checkpoint=checkpoint)
                        self.assertEqual(partial.masks, reference.masks)
                    modes.add(mode)
                state = reference
                state.completed += count
                state.number += 1
                if state.completed == state.scan["total"]:
                    state.mode, position = "metadata", at
                else:
                    position = end
            self.assertEqual(modes, {(True, False), (True, True), (False, False), (False, True)})

    def test_eobrun_may_not_cross_restart_interval(self):
        raw = specimen()
        path = self.root / "eob.jpg"
        path.write_bytes(raw)
        with path.open("rb") as stream:
            assembler = PhotoAssembler(stream)
            state = ProgressiveState(header(assembler, 0, allow_progressive=True))
            ident = next(iter(state.masks))
            state.scan = dict(ss=1, se=1, ah=0, al=0, selected=[(ident, {}, {(1, 0): 0x10})], total=1)
            with self.assertRaisesRegex(InvalidJpeg, "eobrun_bounds"):
                progressive_entropy(b"\x3f", state, 1)

    def test_two_nonrestart_entropy_gaps_in_different_scans(self):
        raw = specimen(restart=0, size=(256, 128))
        first = next(scan for scan in scans(raw) if scan["start"] < 4096 < scan["end"])
        second = next(scan for scan in scans(raw) if scan["script"][2] >> 4 and scan["end"] - scan["start"] > 1024)
        cut = (second["start"] // 512 + 1) * 512
        self.assertGreater(cut, first["end"])
        self.assertLess(cut, second["end"])
        self.assert_exact(raw, scatter(raw, [4096, cut])[0])

    def test_gap_with_distinct_equal_stage_tails_is_ambiguous(self):
        raw = specimen(restart=0, size=(256, 128))
        comment = b"original-A"
        raw = raw[:-2] + b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment + raw[-2:]
        results, assembler = self.run_image(scatter(raw, [4096], alternate=True)[0])
        self.assertEqual(results, [])
        self.assertGreater(assembler.skipped["jpeg_progressive_ambiguous"], 0)

    def test_low_precision_scans_have_separate_candidate_status(self):
        raw = specimen()
        stop = next(scan["header"] for scan in scans(raw) if scan["script"][2] >> 4)
        truncated = raw[:stop] + b"\xff\xd9"
        results = self.assert_exact(truncated, scatter(truncated, self.split(truncated))[0], "progressive_partial_precision_candidate")
        self.assertIn("not a complete-precision image", results[0][2])

    def test_dc_only_valid_partial_image_with_surviving_eoi(self):
        raw = specimen()
        stop = scans(raw)[0]["end"]
        dc_only = raw[:stop] + b"\xff\xd9"
        self.assert_exact(dc_only, scatter(dc_only, self.split(dc_only))[0], "progressive_partial_precision_candidate")

    def test_legal_marker_fill_bytes_are_preserved_exactly(self):
        raw = specimen()
        # JPEG permits FF fill before a marker. Entropy padding is separate.
        for at, _, code in reversed(markers(raw)):
            if code in {0xda, 0xc4, 0xd9} or 0xd0 <= code <= 0xd7:
                raw = raw[:at] + b"\xff\xff" + raw[at:]
        self.assert_exact(raw, scatter(raw, self.split(raw))[0])

    def test_independent_corpus02_if_explicitly_requested(self):
        if not EXTERNAL:
            self.skipTest("explicit --external required for the independent benchmark image")
        root = Path(__file__).resolve().parents[1] / ".build/benchmarks-v4/corpus-02"
        source = root / "images/raw-scattered-progressive.dd"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        with source.open("rb") as stream:
            assembler = PhotoAssembler(stream)
            assembler.index()
            results = list(recover_jpegs(assembler))
        self.assertEqual(len(results), 1, assembler.skipped)
        recipe = results[0][0]
        rebuilt = b"".join(part for _, part in recipe)
        self.assertEqual(hashlib.sha256(rebuilt).hexdigest(), "ca760a47df30584b0bfd485577249488eb14dde429f6ae8396f806d73c387385")
        self.assertEqual(pixels(rebuilt), "365c151db1d5100ec9330022628785cc0cbe6d4c43cbd32217cf3c0f2904c083")
        self.assertTrue(disjoint(recipe))
        self.assertEqual(len(recipe), 3)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    EXTERNAL = "--external" in sys.argv
    if EXTERNAL:
        sys.argv.remove("--external")
    unittest.main(verbosity=2)
