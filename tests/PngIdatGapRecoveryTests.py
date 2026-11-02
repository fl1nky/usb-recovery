"""Independent allocation-unit PNG gaps, strict validation and durable resume."""
from pathlib import Path
import hashlib
import json
import random
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / "helpers/recovery_engine"))
import fragmented_photos
import png_fragments
from recovery_checkpoint import CheckpointError
from build_png_idat_gap_fixtures import CASE_NAMES, create, oracle


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(folder):
    return {path.relative_to(folder).as_posix():sha(path) for path in folder.rglob("*") if path.is_file()}


class OwnedCancellation(Exception):
    pass


class PngIdatGapRecoveryTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / ".build/png-idat-source-tests"
        base.mkdir(parents=True,exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="owned-",dir=base)
        self.root = Path(self.temporary.name)
        self.assertTrue(self.root.resolve().is_relative_to(base.resolve()))
        self.addCleanup(self.temporary.cleanup)
        self.counter = 0

    def fixture(self,name):
        self.counter += 1
        source,golden = create(self.root / ("input-"+str(self.counter)),name)
        return source,golden,self.root / ("result-"+str(self.counter))

    def run_case(self,name,options=None,**callbacks):
        source,golden,output = self.fixture(name)
        before = inventory(source.parent)
        result = fragmented_photos.recover(source,output,options,**callbacks)
        self.assertEqual(inventory(source.parent),before,"Supplied PNG/image/golden bytes stay unchanged")
        self.assertEqual((output / "job.incomplete").exists(),result["Status"] != "complete")
        return source,golden,output,result

    def check_file(self,source,golden,output,result):
        self.assertEqual(result["Status"],"complete")
        self.assertEqual(result["Candidates"],1)
        item = result["Files"][0]
        actual = output / item["Path"]
        self.assertEqual((sha(actual),item["Sha256"],actual.stat().st_size),(golden["Sha256"],golden["Sha256"],golden["Bytes"]))
        self.assertEqual(item["Status"],"png_crc_zlib_reassembled_candidate")
        self.assertEqual(oracle(actual.read_bytes())["PixelsSha256"],golden["Oracle"]["PixelsSha256"])
        disk,logical,physical = source.read_bytes(),0,[]
        body = bytearray()
        for extent in item["Extents"]:
            at,size = extent["ImageOffset"],extent["Length"]
            self.assertEqual(extent["LogicalOffset"],logical)
            self.assertGreaterEqual(at,0)
            self.assertLessEqual(at+size,len(disk))
            physical.append((at,at+size))
            body.extend(disk[at:at+size]);logical += size
        physical.sort()
        self.assertTrue(all(left[1] <= right[0] for left,right in zip(physical,physical[1:])))
        self.assertEqual(bytes(body),actual.read_bytes(),"Only exact disjoint original-source bytes form output")
        self.assertEqual(logical,golden["Bytes"])

    def test_crc_concatenation_matches_native_zlib_without_data_rescans(self):
        rng = random.Random(20261103)
        lengths = [(0,0),(1,1),(511,512),(512,513),(65536,131073),(65537,2*1024*1024)]
        lengths += [(rng.randrange(8193),rng.randrange(65537)) for _ in range(80)]
        for left_size,right_size in lengths:
            with self.subTest(left=left_size,right=right_size):
                left,right = rng.randbytes(left_size),rng.randbytes(right_size)
                self.assertEqual(png_fragments.crc32_combine(zlib.crc32(left),zlib.crc32(right),len(right)),zlib.crc32(left+right))
        for bad in (-1,2*1024*1024+13,True,1.5):
            with self.assertRaises(ValueError):
                png_fragments.crc32_combine(0,0,bad)

    def test_independent_gap_layouts_have_exact_bytes_pixels_and_source_maps(self):
        positive = ("whole-idat","cut-512","cut-4k","cut-32k","cut-128k","cut-1280k","unaligned-head",
            "reversed","zero-padding","random-padding","ancillary-prefix","ancillary-tail","indexed-palette",
            "multi-idat-middle","crc-split","duplicate-tail","false-anchor")
        for name in positive:
            with self.subTest(name=name):
                source,golden,output,result = self.run_case(name)
                self.check_file(source,golden,output,result)
                if name.startswith("cut-"):
                    self.assertTrue(golden["SourceCutIsAbsolute512"])
                if name == "cut-1280k":
                    self.assertGreaterEqual(golden["LogicalCut"],1280*1024)

    def test_corruption_loss_context_and_overlap_never_become_success(self):
        for name in ("corrupt-crc","invalid-adler","missing-payload","overlap","forbidden-tail-context","invalid-filter"):
            with self.subTest(name=name):
                _,_,output,result = self.run_case(name)
                self.assertEqual(result["Candidates"],0)
                self.assertFalse(list(output.glob("*.png")))

    def test_ambiguous_native_tails_do_not_publish_the_first_valid_image(self):
        source,golden,output,result = self.run_case("ambiguous-tail")
        self.assertNotEqual(sha(source.parent / "alternative.png"),golden["Sha256"])
        self.assertEqual(result["Candidates"],0)
        self.assertGreater(result["Skipped"].get("png_ambiguous",0),0)
        self.assertFalse(list(output.glob("*.png")))

    def test_contiguous_native_png_remains_normal_carving_not_reassembly(self):
        _,_,_,result = self.run_case("contiguous")
        self.assertEqual(result["Status"],"complete")
        self.assertEqual(result["Candidates"],0)

    def test_intact_foreign_idat_does_not_hide_a_valid_gap_alternative(self):
        source,golden,output,result = self.run_case("mixed-intact-gap-ambiguous")
        self.assertTrue(golden["AllOriginalBytesPresent"])
        self.assertNotEqual(sha(source.parent / "alternative.png"),golden["Sha256"])
        self.assertEqual(result["Candidates"],0,"A valid intact-IDAT solution cannot hide a different valid fragmented solution")
        self.assertGreater(result["Skipped"].get("png_ambiguous",0),0)
        self.assertFalse(list(output.glob("*.png")))

    def test_late_alternatives_and_search_limits_do_not_claim_uniqueness(self):
        for name in ("cut-512","cut-4k","mixed-intact-gap-ambiguous"):
            with self.subTest(name=name):
                checkpoints = []
                _,_,output,result = self.run_case(name,{"max_states":1},checkpoint_progress=checkpoints.append)
                self.assertEqual(result["Status"],"limited")
                self.assertEqual(result["Candidates"],0)
                self.assertGreater(result["Skipped"].get("png_gap_attempts_incomplete",0),0)
                last = json.loads(Path(checkpoints[-1]["Path"]).read_text(encoding="utf8"))
                self.assertEqual(last["Cursor"]["Png"],0,"Unexplored alternatives do not advance the durable PNG cursor")
                self.assertTrue((output / "job.incomplete").exists())

    def test_crc_work_limit_is_incomplete_not_an_empty_success(self):
        with patch.object(png_fragments,"MAX_CRC_BYTES",1):
            _,_,_,result = self.run_case("cut-4k")
        self.assertEqual((result["Status"],result["Candidates"]),("limited",0))
        self.assertGreater(result["Skipped"].get("png_gap_crc_work_incomplete",0),0)

    def test_cancellation_inside_gap_search_resumes_from_checked_index(self):
        source,golden,output = self.fixture("cut-128k")
        before = inventory(source.parent)
        captured,search_phase = [],False
        base,elapsed = time.monotonic(),0
        def checkpoint(value):
            nonlocal search_phase
            captured.append(value)
            state = json.loads(Path(value["Path"]).read_text(encoding="utf8"))
            search_phase |= state["Phase"] == "candidates"
        def clock():
            nonlocal elapsed
            if search_phase:
                elapsed += 0.5
            return base+elapsed
        def cancel(done,total):
            if search_phase:
                raise OwnedCancellation("owned progress cancellation inside new search")
        with patch("png_fragments.time.monotonic",side_effect=clock):
            with self.assertRaises(OwnedCancellation):
                fragmented_photos.recover(source,output,progress=cancel,checkpoint_progress=checkpoint)
        self.assertTrue(captured)
        self.assertTrue((output / "job.incomplete").exists())
        self.assertEqual(inventory(source.parent),before)
        result = fragmented_photos.recover(source,output,{"resume_checkpoint":captured[-1]})
        self.check_file(source,golden,output,result)
        self.assertTrue(result["ResumedFromCheckpoint"])
        self.assertEqual(result["ResumedIndexBytes"],source.stat().st_size)
        self.assertEqual(inventory(source.parent),before)

    def test_new_png_module_participates_in_checkpoint_code_binding(self):
        captured = []
        source,golden,output,result = self.run_case("cut-4k",checkpoint_progress=captured.append)
        self.check_file(source,golden,output,result)
        before = inventory(output)
        with patch.object(png_fragments,"MAX_CRC_BYTES",png_fragments.MAX_CRC_BYTES+1):
            with self.assertRaisesRegex(CheckpointError,"PHOTO_CHECKPOINT_BINDING_MISMATCH"):
                fragmented_photos.recover(source,output,{"resume_checkpoint":captured[-1]})
        self.assertEqual(inventory(output),before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
