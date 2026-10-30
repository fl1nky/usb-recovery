"""Checks that benchmark evidence cannot silently become a recovery claim."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from PIL import Image
from collect_exports import collect, digest
from score_media_results import decode, score, sha
from validate_corpus import validate


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.exports = self.root / "exports"
        self.exports.mkdir()
        original = self.corpus / "original.png"
        Image.new("RGB", (4, 4), "red").save(original)
        self.data = original.read_bytes()
        (self.corpus / "image.dd").write_bytes(b"prefix" + self.data + b"padding")
        self.asset = {"name": "original", "path": "original.png", "bytes": len(self.data), "sha256": sha(self.data),
                      "decoded_rgb_sha256": sha(Image.new("RGB", (4, 4), "red").tobytes())}
        self.case = {"name": "control", "image": "image.dd", "bytes": (self.corpus / "image.dd").stat().st_size,
                     "sha256": digest(self.corpus / "image.dd"), "expected": [{"asset": "original", "all_original_bytes_present": True,
                     "extents": [{"logical_offset": 0, "image_offset": 6, "length": len(self.data)}]}]}
        self.manifest = {"assets": [self.asset], "cases": [self.case]}
        self.write_manifest()
        self.observations = self.root / "observations.json"
        self.executable = self.root / "tool.exe"
        self.executable.write_bytes(b"inert-version-binding-only")
        self.run = self.root / "run.json"
        self.report = self.root / "score.json"

    def tearDown(self):
        self.temporary.cleanup()

    def write_manifest(self):
        (self.corpus / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def collect(self, status):
        self.observations.write_text(json.dumps({"cases": [{"name": "control", "status": status,
            "configuration": "inert test", "note": "explicit test observation"}]}), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            collect(self.corpus, self.exports, self.observations, self.executable, self.run, "test", "inert")

    def candidate(self, data):
        folder = self.exports / "control"
        folder.mkdir()
        file = folder / "candidate"
        file.write_bytes(data)
        return file

    def score(self):
        with contextlib.redirect_stdout(io.StringIO()):
            score(self.corpus, self.run, self.executable, self.report)
        return json.loads(self.report.read_text(encoding="utf-8"))

    def test_empty_directory_is_not_a_successful_export(self):
        (self.exports / "control").mkdir()
        with self.assertRaises(ValueError):
            self.collect("completed")

    def test_trial_restriction_is_preserved(self):
        self.collect("trial_not_exported")
        self.assertTrue(self.score()["cases"][0]["expected"][0]["trial_not_exported"])

    def test_no_findings_cannot_hide_an_export(self):
        self.candidate(self.data)
        with self.assertRaises(ValueError):
            self.collect("no_findings")

    def test_padding_can_be_decoded_equivalent_without_exact_sha(self):
        self.candidate(self.data + b"image padding")
        self.collect("completed")
        result = self.score()["cases"][0]["expected"][0]
        self.assertFalse(result["exact"])
        self.assertTrue(result["decoded_equivalent"])

    def test_modified_export_is_rejected(self):
        file = self.candidate(self.data)
        self.collect("completed")
        file.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.score()

    def test_modified_source_is_rejected(self):
        self.collect("no_findings")
        (self.corpus / "image.dd").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.score()

    def test_decoder_timeout_is_unknown(self):
        file = self.candidate(b"non-image")
        with patch("score_media_results.subprocess.run", side_effect=subprocess.TimeoutExpired("decoder", 20)):
            self.assertIsNone(decode(file, self.executable)["valid"])

    def test_matching_video_without_matching_audio_is_not_equivalent(self):
        self.asset["decoded_frames_sha256"] = "video-hash"
        self.asset["decoded_audio_sha256"] = "audio-hash"
        del self.asset["decoded_rgb_sha256"]
        self.write_manifest()
        self.candidate(b"different-container")
        self.collect("completed")
        with patch("score_media_results.decode", return_value={"kind": "video", "valid": True,
                "decoded_sha256": "video-hash", "decoded_audio_sha256": "wrong-audio"}):
            self.assertFalse(self.score()["cases"][0]["expected"][0]["decoded_equivalent"])

    def test_extent_truth_is_checked_against_actual_image(self):
        self.assertEqual(validate(self.corpus)["cases"], 1)
        self.case["expected"][0]["all_original_bytes_present"] = False
        self.write_manifest()
        with self.assertRaises(ValueError):
            validate(self.corpus)


if __name__ == "__main__":
    unittest.main()
