"""Disk CRC pages, trusted checkpoint boundaries and resumable global search."""
from pathlib import Path
from unittest.mock import patch
import copy
import hashlib
import json
import os
import random
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import fragmented_photos as photos
import png_fragments as gap
import png_sector_index as index
import png_streaming
from recovery_checkpoint import CheckpointError
from build_png_two_gap_fixtures import create


class PngStreamingIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-png-streaming-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def data(self):
        return random.Random(2718).randbytes(2 * 1048576 + 37)

    def index_data(self, data):
        store = index.SectorPrefixIndex(self.root / 'index', len(data), create=True)
        self.addCleanup(store.close)
        for at in range(0, len(data), 1048576):
            store.append(at, data[at:at + 1048576])
        return store, store.snapshot()

    def test_every_sector_prefix_and_page_seam_matches_independent_zlib(self):
        data = self.data()
        with patch.object(index, 'PAGE_BYTES', 4096):
            store, meta = self.index_data(data)
            self.assertEqual((meta['States'], meta['Bytes']), (len(data) // 512 + 1, (len(data) // 512 + 1) * 4))
            self.assertEqual(meta['SourcePosition'], len(data))
            checksum = 0
            self.assertEqual(store[0], 0)
            for sector in range(1, len(data) // 512 + 1):
                checksum = zlib.crc32(data[(sector - 1) * 512:sector * 512], checksum)
                self.assertEqual(store[sector], checksum)
            self.assertLessEqual(len(store.cache), 2)
            self.assertEqual(store.path.read_bytes(), b''.join(struct.pack('<I', zlib.crc32(data[:at]))
                                                             for at in range(0, len(data) - len(data) % 512 + 1, 512)))

    def test_parent_pinned_prefix_survives_unacknowledged_append(self):
        data = self.data()
        with patch.object(index, 'PAGE_BYTES', 4096):
            store = index.SectorPrefixIndex(self.root / 'index', len(data), create=True)
            store.append(0, data[:1048576])
            first = store.snapshot()
            store.append(1048576, data[1048576:2097152])
            extra = store.path.read_bytes()[first['Bytes']:]
            store.close()
            restored = index.SectorPrefixIndex(self.root / 'index', len(data))
            self.addCleanup(restored.close)
            restored.restore(first)
            self.assertEqual(restored.path.stat().st_size, first['Bytes'])
            orphans = list(restored.directory.glob('uncommitted-*.partial'))
            self.assertEqual(len(orphans), 1)
            self.assertEqual(orphans[0].read_bytes(), extra)
            restored.append(1048576, data[1048576:2097152])
            restored.append(2097152, data[2097152:])
            final = restored.snapshot()
            restored.extension(first, final)
            self.assertEqual(restored[restored.states - 1], zlib.crc32(data[:len(data) - len(data) % 512]))

    def test_reissued_sibling_metadata_cannot_bless_changed_page(self):
        data = self.data()
        with patch.object(index, 'PAGE_BYTES', 4096):
            store, meta = self.index_data(data)
            store.close()
            raw = bytearray(store.path.read_bytes()); raw[512] ^= 1; store.path.write_bytes(raw)
            fake = copy.deepcopy(meta)
            fake['Pages'][0] = hashlib.sha256(raw[:4096]).hexdigest()
            (store.directory / ('uncommitted-' + '1' * 32 + '.partial')).write_text(json.dumps(fake), encoding='utf-8')
            restored = index.SectorPrefixIndex(store.directory, len(data))
            self.addCleanup(restored.close)
            with self.assertRaisesRegex(CheckpointError, 'HASH_MISMATCH'):
                restored.restore(meta)

    def test_loaded_page_is_verified_on_first_use_and_resident_window_bounded(self):
        data = self.data()
        with patch.object(index, 'PAGE_BYTES', 4096):
            store, _ = self.index_data(data)
            with store.path.open('r+b') as output:
                output.seek(4096); value = output.read(1); output.seek(4096); output.write(bytes([value[0] ^ 1]))
            with self.assertRaisesRegex(CheckpointError, 'HASH_MISMATCH'):
                store[1024]

    def test_metadata_type_geometry_and_hardlink_guards(self):
        data = self.data()
        store, meta = self.index_data(data)
        for key, value in (('SourcePosition', True), ('States', True), ('Bytes', True), ('LastCrc', -1),
                           ('PageBytes', float(index.PAGE_BYTES)), ('Name', '../index.bin'), ('Pages', [])):
            bad = copy.deepcopy(meta); bad[key] = value
            with self.subTest(key=key), self.assertRaises(CheckpointError):
                index.SectorPrefixIndex.validate_metadata(bad, len(data))
        store.close()
        os.link(store.path, self.root / 'linked-index.bin')
        with self.assertRaisesRegex(CheckpointError, 'UNSAFE_PATH'):
            index.SectorPrefixIndex(store.directory, len(data))

    def test_append_rejects_wrong_boundary_without_changing_committed_bytes(self):
        data = self.data()
        store = index.SectorPrefixIndex(self.root / 'index', len(data), create=True)
        self.addCleanup(store.close)
        store.append(0, data[:1048576]); meta = store.snapshot(); before = store.path.read_bytes()
        with self.assertRaises(CheckpointError):
            store.append(0, b'\0' * 512)
        self.assertEqual(store.path.read_bytes(), before)
        self.assertEqual(store.snapshot(), meta)

    def test_unacknowledged_tail_quarantine_count_cannot_exceed_its_own_budget(self):
        data = self.data()
        with patch.object(index, 'MAX_ORPHANS', 1):
            store = index.SectorPrefixIndex(self.root / 'index', len(data), create=True)
            first = store.snapshot()
            store.append(0, data[:1048576]); store.close()
            restored = index.SectorPrefixIndex(store.directory, len(data))
            restored.restore(first)
            restored.append(0, data[:1048576]); restored.close()
            final = index.SectorPrefixIndex(store.directory, len(data))
            self.addCleanup(final.close)
            with self.assertRaisesRegex(CheckpointError, 'STORAGE_LIMIT'):
                final.restore(first)
            self.assertEqual(len(list(final.directory.glob('uncommitted-*.partial'))), 1)
            self.assertGreater(final.path.stat().st_size, first['Bytes'])

    def test_budget_resume_advances_global_rows_without_publishing_early_match(self):
        source, golden = create(self.root / 'source', 'two-gap-duplicate-middle')
        output = self.root / 'output'
        anchors, reports, rows = [], [], []
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        with patch.object(gap, 'MAX_JOIN_CELLS', 10000):
            for _ in range(32):
                options = dict(streaming_png=True)
                if anchors:
                    options['resume_checkpoint'] = anchors[-1]
                report = photos.recover(source, output, options, checkpoint_progress=anchors.append)
                reports.append(report)
                rows.append(report['PngSearchCoverage']['Rows'])
                if report['Status'] == 'complete':
                    break
                self.assertEqual(report['Candidates'], 0)
                self.assertFalse(list(output.glob('*.png')))
                self.assertTrue(report['ActiveIncomplete'])
            else:
                self.fail('Bounded resume did not finish')
        self.assertEqual(reports[0]['Status'], 'limited')
        self.assertTrue(all(a < b for a, b in zip(rows, rows[1:])))
        self.assertEqual(report['Files'][0]['Sha256'], golden['Sha256'])
        self.assertEqual(len(report['Files'][0]['AlternateExtents']), 1)
        self.assertEqual(report['ActiveIncomplete'], [])
        self.assertGreater(report['Skipped']['png_two_gap_join_work_incomplete'], 0)
        self.assertFalse((output / 'job.incomplete').exists())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

    def test_cancelled_signature_block_commits_matching_crc_boundary_then_resumes(self):
        source, golden = create(self.root / 'source', 'physical-order-012')
        with source.open('r+b') as output:
            output.seek(3 * 1048576 - 1); output.write(b'\0')
        output, anchors = self.root / 'output', []
        class OwnedCancel(Exception):
            pass
        def stop(done, total):
            if 0 < done < 400000:
                raise OwnedCancel()
        with self.assertRaises(OwnedCancel):
            photos.recover(source, output, dict(streaming_png=True), progress=stop, checkpoint_progress=anchors.append)
        state = json.loads(Path(anchors[-1]['Path']).read_text('utf-8'))
        self.assertEqual(state['Index']['Position'], 1048576)
        self.assertEqual(state['Index']['SectorCrc']['SourcePosition'], state['Index']['Position'])
        result = photos.recover(source, output, dict(streaming_png=True, resume_checkpoint=anchors[-1]))
        self.assertEqual((result['Status'], result['Files'][0]['Sha256']), ('complete', golden['Sha256']))
        self.assertEqual(result['ResumedIndexBytes'], 1048576)

    def test_cancelled_join_row_replays_retained_candidate_without_early_publication(self):
        source, golden = create(self.root / 'source', 'two-gap-duplicate-middle')
        output, anchors = self.root / 'output', []
        original = png_streaming.GlobalPngSearch._row
        cancel = [True]
        class OwnedCancel(Exception):
            pass
        def stop(search, *args):
            original(search, *args)
            if search.state['Candidates'] and cancel[0]:
                cancel[0] = False
                raise OwnedCancel()
        with patch.object(png_streaming.GlobalPngSearch, '_row', stop):
            with self.assertRaises(OwnedCancel):
                photos.recover(source, output, dict(streaming_png=True), checkpoint_progress=anchors.append)
            state = json.loads(Path(anchors[-1]['Path']).read_text('utf-8'))
            self.assertTrue(state['PngSearch']['Candidates'])
            self.assertEqual(state['PngSearch']['Phase'], 'three')
            self.assertFalse(list(output.glob('*.png')))
            self.assertTrue((output / 'job.incomplete').is_file())
            # Keep the same executing code version; only the external
            # cancellation request changes between these two invocations.
            result = photos.recover(source, output, dict(streaming_png=True, resume_checkpoint=anchors[-1]))
            self.assertEqual((result['Status'], result['Files'][0]['Sha256']), ('complete', golden['Sha256']))
            self.assertEqual(len(result['Files'][0]['AlternateExtents']), 1)
            self.assertFalse((output / 'job.incomplete').exists())

    def test_changed_source_or_index_or_mode_cannot_resume(self):
        source, _ = create(self.root / 'source', 'physical-order-012')
        output, anchors = self.root / 'output', []
        photos.recover(source, output, dict(streaming_png=True), checkpoint_progress=anchors.append)
        with self.assertRaisesRegex(CheckpointError, 'BINDING_MISMATCH'):
            photos.recover(source, output, dict(resume_checkpoint=anchors[-1]))
        index_file = output.parent / (output.name + '.index') / index.INDEX_NAME
        raw = bytearray(index_file.read_bytes()); raw[8] ^= 1; index_file.write_bytes(raw)
        with self.assertRaisesRegex(CheckpointError, 'HASH_MISMATCH'):
            photos.recover(source, output, dict(streaming_png=True, resume_checkpoint=anchors[-1]))

    def test_changed_source_with_restored_size_and_mtime_cannot_resume(self):
        source, _ = create(self.root / 'source', 'physical-order-012')
        output, anchors = self.root / 'output', []
        photos.recover(source, output, dict(streaming_png=True), checkpoint_progress=anchors.append)
        original = source.stat()
        with source.open('r+b') as target:
            target.seek(0); target.write(b'changed!')
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertEqual(source.stat().st_size, original.st_size)
        self.assertEqual(source.stat().st_mtime_ns, original.st_mtime_ns)
        with self.assertRaisesRegex(CheckpointError, 'BINDING_MISMATCH'):
            photos.recover(source, output, dict(streaming_png=True, resume_checkpoint=anchors[-1]))

    def test_oversized_idat_is_a_persistent_coverage_gap_and_blocks_publication(self):
        for length in (gap.MAX_SPLIT_CHUNK + 1, photos.MAX_CHUNK + 1):
            with self.subTest(length=length):
                folder = self.root / str(length)
                source, _ = create(folder / 'source', 'physical-order-012')
                with source.open('r+b') as target:
                    target.seek(1048576)
                    target.write(struct.pack('>I', length) + b'IDAT')
                    target.seek(2 * 1048576 - 1); target.write(b'\0')
                output, anchors = folder / 'output', []
                for attempt in range(2):
                    options = dict(streaming_png=True)
                    if attempt:
                        options['resume_checkpoint'] = anchors[-1]
                    result = photos.recover(source, output, options, checkpoint_progress=anchors.append)
                    self.assertEqual(result['Status'], 'limited')
                    self.assertIn('png_idat_size_incomplete', result['ActiveIncomplete'])
                    self.assertEqual(result['Candidates'], 0)
                    self.assertFalse(list(output.glob('*.png')))
                    self.assertTrue((output / 'job.incomplete').is_file())


if __name__ == '__main__':
    unittest.main(verbosity=2)
