"""One content, multiple replayable placements and durable alias checkpoints.

The controlled producer tests isolate alias plumbing from the gap search.
The final test exercises the real PNG chunk walker on independent PNG bytes.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import fragmented_photos as photos
import recovery_checkpoint as checkpoint
from FragmentedPhotoTests import specimen, disk


class PhotoSourceAliases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-photo-aliases-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source, self.output = self.root / 'image.dd', self.root / 'out'
        self.payload, _ = specimen()
        cut = 97
        self.recipes = [[(4096, self.payload[:cut]), (8192, self.payload[cut:])],
                        [(16384, self.payload[:cut]), (24576, self.payload[cut:])]]
        raw = bytearray(b'\xa5' * 65536)
        for recipe in self.recipes:
            for at, content in recipe:
                raw[at:at + len(content)] = content
        self.source.write_bytes(raw)
        self.source_hash = hashlib.sha256(raw).hexdigest()
        self.anchors = []
        self.visits = []

    def producer(self, recipes):
        def controlled(assembler, completed=None, png_start=0, jpeg_start=0):
            self.assertEqual(len(assembler.starts), 2)
            self.assertEqual(assembler.jpeg_starts, [])
            for index in range(png_start, 2):
                self.visits.append(index)
                for recipe in recipes[index]:
                    yield recipe, 'png_crc_zlib_reassembled_candidate', 'Owned alias plumbing fixture.'
                if completed:
                    completed('Png', index + 1)
        return controlled

    def run_search(self, anchor=None, producer=None, notify=None):
        options = {} if anchor is None else dict(resume_checkpoint=anchor)
        with patch.object(photos.PhotoAssembler, 'recipes', producer or self.producer([[self.recipes[0]], [self.recipes[1]]])):
            report = photos.recover(self.source, self.output, options,
                checkpoint_progress=notify or self.anchors.append)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.source_hash)
        return report

    def validate(self, records):
        with self.source.open('rb') as stream:
            return photos._validate_outputs(stream, self.output, records)

    def test_resume_binding_captures_critical_status_policy(self):
        modules = [photos, checkpoint]
        original = checkpoint.fingerprint(modules)
        for name in ('PARTIAL_PRECISION_STATUS_RANK', 'AMBIGUOUS_JPEG_STATUS_RANK'):
            with self.subTest(name=name), patch.object(photos, name, getattr(photos, name) + 10):
                self.assertNotEqual(checkpoint.fingerprint(modules), original)
        self.assertEqual(checkpoint.fingerprint(modules), original)

    def jpeg_fixture(self):
        from PIL import Image
        saved = io.BytesIO()
        Image.new('RGB', (12, 8), (30, 70, 90)).save(saved, 'JPEG', quality=90)
        self.payload = saved.getvalue()
        self.recipes = [[(4096, self.payload[:97]), (8192, self.payload[97:])],
                        [(16384, self.payload[:97]), (24576, self.payload[97:])]]
        raw = bytearray(b'\xa5' * 65536)
        for recipe in self.recipes:
            for at, content in recipe:
                raw[at:at + len(content)] = content
        self.source.write_bytes(raw)
        self.source_hash = hashlib.sha256(raw).hexdigest()

    def jpeg_producer(self, incoming, same_map=False, first='jpeg_gap_structural_candidate', limit=None):
        def controlled(assembler, completed=None, png_start=0, jpeg_start=0):
            self.assertEqual(assembler.starts, [])
            self.assertEqual(len(assembler.jpeg_starts), 2)
            for index in range(jpeg_start, 2):
                recipe = self.recipes[0 if same_map else index]
                status = first if not index else incoming
                yield recipe, status, ('Initial evidence: ' if not index else 'Later evidence: ') + status
                if index and limit and limit[0]:
                    raise photos.LimitReached('owned_status_limit')
                if completed:
                    completed('Jpeg', index + 1)
        return controlled

    def test_one_file_retains_both_exact_source_maps(self):
        result = self.run_search()
        self.assertEqual((result['Status'], result['Candidates'], result['OutputBytes']),
                         ('complete', 1, len(self.payload)))
        record = result['Files'][0]
        self.assertEqual((self.output / record['Path']).read_bytes(), self.payload)
        self.assertEqual(record['Extents'], photos._recipe_extents(self.recipes[0]))
        self.assertEqual(record['AlternateExtents'], [photos._recipe_extents(self.recipes[1])])
        self.assertEqual(self.validate(result['Files'])[1], len(self.payload))
        states = [json.loads(Path(row['Path']).read_text(encoding="utf-8-sig")) for row in self.anchors]
        updates = [update for state in states for update in state.get('AliasUpdates', [])]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]['AddedExtents'], record['AlternateExtents'])

    def test_resume_adds_alias_to_previously_committed_output(self):
        def stop(row):
            self.anchors.append(row)
            if json.loads(Path(row['Path']).read_text(encoding="utf-8-sig"))['Cursor']['Png'] == 1:
                raise InterruptedError('owned checkpoint interruption')
        producer = self.producer([[self.recipes[0]], [self.recipes[1]]])
        with self.assertRaises(InterruptedError):
            self.run_search(producer=producer, notify=stop)
        result = self.run_search(self.anchors[-1], producer)
        self.assertTrue(result['ResumedFromCheckpoint'])
        self.assertEqual(result['ReusedCandidates'], 1)
        self.assertEqual(len(result['Files'][0]['AlternateExtents']), 1)
        # A complete anchor restores the alias delta without running search.
        visited = list(self.visits)
        restored = self.run_search(self.anchors[-1], producer)
        self.assertEqual(self.visits, visited)
        self.assertEqual(restored['Files'], result['Files'])

    def test_aliases_found_before_first_commit_are_in_the_file_record(self):
        producer = self.producer([self.recipes, []])
        result = self.run_search(producer=producer)
        states = [json.loads(Path(row['Path']).read_text(encoding="utf-8-sig")) for row in self.anchors]
        stored = [record for state in states for record in state['Files']]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['AlternateExtents'], result['Files'][0]['AlternateExtents'])
        self.assertFalse(any(state.get('AliasUpdates') for state in states))

    def test_duplicate_placement_partitions_are_not_new_aliases(self):
        first = self.recipes[0]
        partitioned = [(first[0][0], first[0][1][:31]),
                       (first[0][0] + 31, first[0][1][31:]), first[1]]
        result = self.run_search(producer=self.producer([[first], [partitioned]]))
        self.assertEqual(result['Candidates'], 1)
        self.assertNotIn('AlternateExtents', result['Files'][0])

    def test_alias_byte_budget_limits_search_without_a_false_complete(self):
        with patch.object(photos, 'MAX_ALIAS_BYTES', len(self.payload) - 1):
            result = self.run_search()
        self.assertEqual(result['Status'], 'limited')
        self.assertEqual(result['Candidates'], 1)
        self.assertEqual(result['Skipped']['source_aliases_limit'], 1)
        self.assertTrue((self.output / 'job.incomplete').exists())
        self.assertEqual((self.output / result['Files'][0]['Path']).read_bytes(), self.payload)

    def test_cross_start_updates_store_only_added_maps(self):
        hybrid = [self.recipes[0][0], self.recipes[1][1]]
        result = self.run_search(producer=self.producer([self.recipes, [hybrid]]))
        self.assertEqual(len(result['Files'][0]['AlternateExtents']), 2)
        states = [json.loads(Path(row['Path']).read_text(encoding="utf-8-sig")) for row in self.anchors]
        initial = [record for state in states for record in state['Files']]
        updates = [update for state in states for update in state.get('AliasUpdates', [])]
        self.assertEqual(len(initial), 1)
        self.assertEqual(len(initial[0]['AlternateExtents']), 1)
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]['AddedExtents'], [photos._recipe_extents(hybrid)])
        self.assertEqual(self.validate(result['Files'])[1], len(self.payload))

    def test_physical_map_count_limit_preserves_already_verified_maps(self):
        hybrid = [self.recipes[0][0], self.recipes[1][1]]
        with patch.object(photos, 'MAX_SOURCE_MAPS', 2):
            result = self.run_search(producer=self.producer([self.recipes, [hybrid]]))
        self.assertEqual(result['Status'], 'limited')
        self.assertEqual(len(result['Files'][0]['AlternateExtents']), 1)
        self.assertTrue((self.output / 'job.incomplete').exists())
        self.assertEqual((self.output / result['Files'][0]['Path']).read_bytes(), self.payload)

    def test_cached_alternate_replay_is_bounded_independently(self):
        record = self.run_search()['Files'][0]
        for limit in ('MAX_ALIAS_BYTES', 'MAX_ALIAS_EXTENTS'):
            with self.subTest(limit=limit), patch.object(photos, limit, 1):
                with self.assertRaisesRegex(checkpoint.CheckpointError, 'ALIASES_INVALID'):
                    self.validate([record])

    def test_later_jpeg_uncertainty_survives_known_map_and_resume(self):
        self.jpeg_fixture()
        for index, (status, same_map) in enumerate([
                ('jpeg_gap_ambiguous_candidate', False),
                ('jpeg_gap_ambiguous_candidate', True),
                ('progressive_partial_precision_candidate', False)]):
            with self.subTest(status=status, same_map=same_map):
                self.output = self.root / ('jpeg-status-' + str(index))
                self.anchors.clear()
                producer = self.jpeg_producer(status, same_map)
                def stop(row):
                    self.anchors.append(row)
                    if json.loads(Path(row['Path']).read_text(encoding="utf-8-sig"))['Cursor']['Jpeg'] == 1:
                        raise InterruptedError('owned JPEG checkpoint interruption')
                with self.assertRaises(InterruptedError):
                    self.run_search(producer=producer, notify=stop)
                result = self.run_search(self.anchors[-1], producer)
                record = result['Files'][0]
                self.assertEqual((result['Candidates'], record['Status']), (1, status))
                self.assertIn('Later evidence: ' + status, record['Note'])
                self.assertEqual(len(record.get('AlternateExtents', [])), 0 if same_map else 1)
                restored = self.run_search(self.anchors[-1], producer)
                self.assertEqual(restored['Files'], result['Files'])
                self.validate(restored['Files'])

    def test_later_stronger_label_cannot_erase_existing_jpeg_uncertainty(self):
        self.jpeg_fixture()
        result = self.run_search(producer=self.jpeg_producer(
            'jpeg_gap_structural_candidate', first='jpeg_gap_ambiguous_candidate'))
        self.assertEqual(result['Files'][0]['Status'], 'jpeg_gap_ambiguous_candidate')
        self.assertIn('Initial evidence: jpeg_gap_ambiguous_candidate', result['Files'][0]['Note'])
        self.validate(result['Files'])

    def test_limited_branch_saves_weaker_evidence_without_advancing_cursor(self):
        self.jpeg_fixture()
        limited = [True]
        producer = self.jpeg_producer('jpeg_gap_ambiguous_candidate', True, limit=limited)
        result = self.run_search(producer=producer)
        self.assertEqual(result['Status'], 'limited')
        self.assertEqual(result['Files'][0]['Status'], 'jpeg_gap_ambiguous_candidate')
        last = json.loads(Path(self.anchors[-1]['Path']).read_text(encoding="utf-8-sig"))
        self.assertEqual(last['Cursor']['Jpeg'], 1)
        self.assertEqual(last['Phase'], 'candidates')
        self.assertEqual(last['AliasUpdates'][0]['AddedExtents'], [])
        self.assertEqual(last['AliasUpdates'][0]['Status'], 'jpeg_gap_ambiguous_candidate')
        limited[0] = False
        resumed = self.run_search(self.anchors[-1], producer)
        self.assertEqual(resumed['Files'][0]['Status'], 'jpeg_gap_ambiguous_candidate')
        self.validate(resumed['Files'])

    def test_changed_alias_bytes_fail_replay_even_with_valid_primary(self):
        result = self.run_search()
        source = bytearray(self.source.read_bytes())
        source[self.recipes[1][0][0] + 10] ^= 1
        self.source.write_bytes(source)
        with self.assertRaisesRegex(checkpoint.CheckpointError, 'OUTPUT_CHANGED'):
            self.validate(result['Files'])

    def test_invalid_alternate_shape_bounds_overlap_and_length_rejected(self):
        record = self.run_search()['Files'][0]
        invalid = [None, {}, [], [{'ImageOffset': 0, 'LogicalOffset': 0, 'Length': len(self.payload)}],
                   [{'ImageOffset': 65536, 'LogicalOffset': 0, 'Length': len(self.payload)}],
                   [{'ImageOffset': True, 'LogicalOffset': 0, 'Length': len(self.payload)}],
                   [{'ImageOffset': 4096, 'LogicalOffset': 1, 'Length': len(self.payload)}],
                   [{'ImageOffset': 16384, 'LogicalOffset': 0, 'Length': 0}]]
        for mapping in invalid:
            with self.subTest(mapping=mapping):
                changed = copy.deepcopy(record)
                changed['AlternateExtents'] = [mapping]
                with self.assertRaises(checkpoint.CheckpointError):
                    self.validate([changed])
        changed = copy.deepcopy(record)
        changed['AlternateExtents'] = None
        with self.assertRaises(checkpoint.CheckpointError):
            self.validate([changed])

    def test_duplicate_primary_and_duplicate_alias_rejected_on_restore(self):
        record = self.run_search()['Files'][0]
        for maps in ([record['Extents']], record['AlternateExtents'] * 2):
            with self.subTest(count=len(maps)):
                changed = copy.deepcopy(record)
                changed['AlternateExtents'] = maps
                with self.assertRaisesRegex(checkpoint.CheckpointError, 'MAPPING_INVALID'):
                    self.validate([changed])

    def test_alias_update_cannot_refer_to_another_content_or_drop_maps(self):
        self.run_search()
        states = [json.loads(Path(row['Path']).read_text(encoding="utf-8-sig")) for row in self.anchors]
        original = next(index for index, state in enumerate(states) if state.get('AliasUpdates'))
        for mutation in ('unknown-hash', 'empty', 'duplicate-update', 'rollback'):
            chain = copy.deepcopy(states)
            update = chain[original]['AliasUpdates'][0]
            if mutation == 'unknown-hash':
                update['Sha256'] = '0' * 64
            elif mutation == 'empty':
                update['AddedExtents'] = []
            elif mutation == 'duplicate-update':
                chain[original]['AliasUpdates'].append(copy.deepcopy(update))
            else:
                chain[-1]['AliasUpdates'] = [copy.deepcopy(update)]
            with self.subTest(mutation=mutation), self.source.open('rb') as stream:
                assembler = photos.PhotoAssembler(stream)
                with self.assertRaisesRegex(checkpoint.CheckpointError, 'ALIASES_INVALID'):
                    photos._restore(assembler, SimpleNamespace(chain=chain))

    def test_invalid_alias_validation_preserves_saved_content(self):
        record = self.run_search()['Files'][0]
        before = (self.output / record['Path']).read_bytes()
        # Malformed secondary provenance may never be trusted because the
        # already verified primary still decodes successfully.
        changed = copy.deepcopy(record)
        changed['AlternateExtents'][0][0]['Length'] += 1
        with self.assertRaises(checkpoint.CheckpointError):
            self.validate([changed])
        self.assertEqual((self.output / record['Path']).read_bytes(), before)

    def test_real_png_walker_keeps_equal_content_at_distinct_placements(self):
        payload, pieces = specimen(parts=2)
        raw = disk([pieces[0], pieces[1], pieces[1]], [4096, 16384, 49152])
        self.source.write_bytes(raw)
        with self.source.open('rb') as stream:
            assembler = photos.PhotoAssembler(stream)
            assembler.index()
            recipes = assembler._png(4096)
        self.assertGreaterEqual(len(recipes), 2)
        self.assertEqual({b''.join(content for _, content in recipe) for recipe in recipes}, {payload})
        self.assertEqual(len(recipes), len({photos._extent_key(photos._recipe_extents(recipe)) for recipe in recipes}))


if __name__ == '__main__':
    unittest.main()
