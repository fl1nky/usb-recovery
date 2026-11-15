"""Ground-truth and path boundaries; no recovery or competitor is mocked."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / 'benchmarks'))
import native_storage as benchmark


class NativeBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = self.root / 'owned.dd'
        self.image.write_bytes(b'owned image' * 100)
        self.case = {'name': 'owned-control', 'image': self.image.name, 'bytes': self.image.stat().st_size,
                     'sha256': benchmark.digest(self.image), 'engine': 'fat', 'expected_sha256': [],
                     'truth_scope': 'complete_negative', 'provenance': {'kind': 'owned_control'}}

    def manifest(self, cases=None):
        (self.root / 'manifest.json').write_text(json.dumps({'schema': 1, 'cases': cases or [self.case]}), encoding='utf-8')

    def test_valid_owned_corpus(self):
        self.manifest()
        self.assertEqual(benchmark.validate(self.root)['cases'][0], self.case)

    def test_modified_image_rejected(self):
        self.manifest()
        self.image.write_bytes(b'x' * self.case['bytes'])
        with self.assertRaisesRegex(ValueError, 'IMAGE_HASH_MISMATCH'):
            benchmark.validate(self.root)

    def test_outside_and_ambiguous_paths_rejected(self):
        for path in ('../owned.dd', '/owned.dd', 'C:/owned.dd', './owned.dd', 'x//owned.dd', 'x\\owned.dd'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                benchmark.regular(self.root, path)

    def test_hardlinked_image_rejected(self):
        alias = self.root / 'alias.dd'
        os.link(self.image, alias)
        with self.assertRaisesRegex(ValueError, 'INVALID_CORPUS_FILE'):
            benchmark.regular(self.root, alias.name)

    def test_duplicate_ids_and_invalid_sizes_rejected(self):
        self.manifest([self.case, self.case])
        with self.assertRaisesRegex(ValueError, 'INVALID_CASE_ID'):
            benchmark.validate(self.root)
        for size in (True, -1, 0, benchmark.MAX_IMAGE_BYTES + 1):
            with self.subTest(size=size):
                self.case['bytes'] = size
                self.manifest()
                with self.assertRaisesRegex(ValueError, 'INVALID_IMAGE_SIZE'):
                    benchmark.validate(self.root)

    def test_conflicting_negative_truth_rejected(self):
        self.case['expected_sha256'] = ['a' * 64]
        self.manifest()
        with self.assertRaisesRegex(ValueError, 'CONFLICTING_GROUND_TRUTH'):
            benchmark.validate(self.root)

    def test_unmatched_positive_candidate_is_unclassified(self):
        expected = hashlib.sha256(b'original').hexdigest()
        other = hashlib.sha256(b'not-in-incomplete-truth').hexdigest()
        self.case.update(expected_sha256=[expected], truth_scope='target_contents_only')
        score = benchmark.score(self.case, [{'sha256': expected}, {'sha256': expected}, {'sha256': other}])
        self.assertEqual(score['exact_unique_contents'], 1)
        self.assertEqual(score['unclassified_candidate_contents'], 1)
        self.assertIsNone(score['negative_control_candidates'])
        self.assertEqual(score['exact_recall'], 1)

    def test_negative_candidates_are_counted_only_in_complete_negative_control(self):
        score = benchmark.score(self.case, [{'sha256': 'a' * 64}, {'sha256': 'a' * 64}])
        self.assertEqual(score['negative_control_candidates'], 1)
        self.assertIsNone(score['exact_recall'])
        self.assertEqual(score['unclassified_candidate_contents'], 0)


if __name__ == '__main__':
    unittest.main()
