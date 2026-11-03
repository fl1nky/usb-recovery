"""All20 accepted independent native PNG variants in the new disk-index mode."""
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import fragmented_photos as photos
from build_png_two_gap_fixtures import CASE_NAMES, create, inventory
from build_png_idat_gap_fixtures import oracle


def canonical(extents):
    result = []
    logical = 0
    for extent in extents:
        at, count = extent['ImageOffset'], extent['Length']
        if extent['LogicalOffset'] != logical or count <= 0:
            raise AssertionError('Invalid logical map')
        logical += count
        if result and sum(result[-1]) == at:
            result[-1][1] += count
        else:
            result.append([at, count])
    return result


class PngStreamingNativeTests(unittest.TestCase):
    def test_all20_independent_native_variants_keep_exact_bytes_maps_and_ambiguity(self):
        with tempfile.TemporaryDirectory(prefix='owned-png-native-streaming-') as temporary:
            root = Path(temporary)
            self.assertEqual(len(CASE_NAMES), 20)
            for name in CASE_NAMES:
                with self.subTest(name=name):
                    source, golden = create(root / name / 'input', name)
                    output, anchors = root / name / 'output', []
                    before = inventory(source.parent)
                    for attempt in range(16):
                        options = dict(streaming_png=True)
                        if anchors:
                            options['resume_checkpoint'] = anchors[-1]
                        report = photos.recover(source, output, options, checkpoint_progress=anchors.append)
                        if report['Status'] == 'complete':
                            break
                    self.assertEqual((report['Status'], report['Candidates']), ('complete', golden['ExpectedCandidates']))
                    self.assertEqual(inventory(source.parent), before)
                    self.assertFalse((output / 'job.incomplete').exists())
                    if not golden['ExpectedCandidates']:
                        self.assertGreater(report['Skipped'].get('png_ambiguous', 0), 0)
                        self.assertFalse(list(output.glob('*.png')))
                        continue
                    item = report['Files'][0]
                    raw = (output / item['Path']).read_bytes()
                    self.assertEqual(raw, (source.parent / 'original.png').read_bytes())
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), golden['Sha256'])
                    self.assertEqual(oracle(raw)['PixelsSha256'], golden['Oracle']['PixelsSha256'])
                    maps = [item['Extents'], *item.get('AlternateExtents', [])]
                    normalized = [canonical(mapping) for mapping in maps]
                    self.assertEqual(len({repr(mapping) for mapping in normalized}), len(maps))
                    for known in golden['KnownMaps']:
                        if known['Sha256'] == golden['Sha256']:
                            self.assertIn(canonical(known['Extents']), normalized)
                    with source.open('rb') as stream:
                        for mapping in maps:
                            ordered = sorted((extent['ImageOffset'], extent['ImageOffset'] + extent['Length']) for extent in mapping)
                            self.assertTrue(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])))
                            parts = []
                            for extent in mapping:
                                stream.seek(extent['ImageOffset']); parts.append(stream.read(extent['Length']))
                            self.assertEqual(b''.join(parts), raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
