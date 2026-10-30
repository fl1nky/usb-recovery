"""Independent adversarial checkpoint validation using owned synthetic files."""
from pathlib import Path
import hashlib
import io
import json
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import fragmented_photos as photos
import jpeg_fragments as jpeg
import recovery_checkpoint as checkpoint
from FragmentedPhotoTests import specimen, disk


class PhotoCheckpointAudit(unittest.TestCase):
    def setUp(self):
        self.base = (ROOT / '.build/checkpoint-independent-audit').resolve()
        self.base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=self.base)
        self.root = Path(self.temp.name)
        self.source, self.output = self.root / 'source.dd', self.root / 'output'
        self.payload, parts = specimen()
        self.source.write_bytes(disk(parts))
        self.source_hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.anchors = []

    def tearDown(self):
        self.assertTrue(self.root.resolve().is_relative_to(self.base))
        self.temp.cleanup()

    def stop(self, *, first=False):
        def acknowledge(anchor):
            self.anchors.append(anchor)
            state = json.loads(Path(anchor['Path']).read_text(encoding='utf-8'))
            if first or state['Cursor']['Png'] == 1:
                raise InterruptedError('owned test interruption')
        with self.assertRaises(InterruptedError):
            photos.recover(self.source, self.output, checkpoint_progress=acknowledge)
        return dict(self.anchors[-1])

    def resume(self, anchor):
        result = photos.recover(self.source, self.output, {'resume_checkpoint': anchor})
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.source_hash)
        return result

    def rewrite(self, anchor, modify):
        path = Path(anchor['Path'])
        state = json.loads(path.read_text(encoding='utf-8'))
        modify(state)
        raw = checkpoint.encoded(state)
        path.write_bytes(raw)
        return dict(anchor, Sha256=hashlib.sha256(raw).hexdigest())

    def test_boolean_schema_is_not_integer_schema(self):
        anchor = self.stop(first=True)
        anchor = self.rewrite(anchor, lambda state: state.update(Schema=True))
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_boolean_checkpoint_sequence_is_not_integer_sequence(self):
        anchor = self.stop(first=True)
        anchor = self.rewrite(anchor, lambda state: state.update(Sequence=True))
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_boolean_external_anchor_sequence_is_rejected(self):
        anchor = self.stop(first=True)
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(dict(anchor, Sequence=True))

    def test_binding_equality_cannot_alias_boolean_and_integer(self):
        directory = self.root / 'journal'
        directory.mkdir()
        binding = dict(SourceBytes=1, Options=dict(max_states=1))
        journal = checkpoint.Journal(directory, binding)
        journal.commit(dict(Phase='index'))
        path = next(directory.glob('checkpoint-*.json'))
        state = json.loads(path.read_text(encoding='utf-8'))
        state['Binding']['SourceBytes'] = True
        state['Binding']['Options']['max_states'] = True
        raw = checkpoint.encoded(state)
        path.write_bytes(raw)
        with self.assertRaises(checkpoint.CheckpointError):
            checkpoint.Journal(directory, binding, dict(Path=str(path), Sha256=hashlib.sha256(raw).hexdigest(), Sequence=1))

    def test_executing_positional_defaults_are_bound(self):
        before = checkpoint.fingerprint([photos, jpeg, checkpoint])
        original = jpeg.header.__defaults__
        try:
            jpeg.header.__defaults__ = (not original[0],)
            self.assertNotEqual(checkpoint.fingerprint([photos, jpeg, checkpoint]), before)
        finally:
            jpeg.header.__defaults__ = original

    def test_executing_keyword_defaults_are_bound(self):
        before = checkpoint.fingerprint([photos, jpeg, checkpoint])
        original = checkpoint.plain.__kwdefaults__
        try:
            checkpoint.plain.__kwdefaults__ = dict(hardlinks=not original['hardlinks'])
            self.assertNotEqual(checkpoint.fingerprint([photos, jpeg, checkpoint]), before)
        finally:
            checkpoint.plain.__kwdefaults__ = original

    def test_static_method_defaults_are_bound(self):
        before = checkpoint.fingerprint([photos, jpeg, checkpoint])
        original = photos.PhotoAssembler.decode.__defaults__
        try:
            photos.PhotoAssembler.decode.__defaults__ = (3,)
            self.assertNotEqual(checkpoint.fingerprint([photos, jpeg, checkpoint]), before)
        finally:
            photos.PhotoAssembler.decode.__defaults__ = original

    def test_cached_crc_is_checked_even_when_pixels_decode(self):
        from PIL import Image
        damaged = bytearray(self.payload)
        at = len(photos.PNG)
        while at < len(damaged):
            size, kind = struct.unpack_from('>I4s', damaged, at)
            if kind == b'IDAT':
                damaged[at + 8 + size] ^= 1
                break
            at += size + 12
        self.assertEqual(kind, b'IDAT')
        with Image.open(io.BytesIO(damaged)) as picture:
            picture.load()
        digest = hashlib.sha256(damaged).hexdigest()
        self.assertFalse(photos._cached_image_valid(bytes(damaged), 'png-' + digest + '.png', 'png_crc_zlib_reassembled_candidate'))

    def test_duplicate_json_fields_rejected_even_with_matching_anchor_hash(self):
        anchor = self.stop(first=True)
        path = Path(anchor['Path'])
        raw = path.read_bytes()[:-1] + b',"Schema":1}'
        path.write_bytes(raw)
        anchor = dict(anchor, Sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_nonstandard_json_nan_gets_own_checkpoint_error(self):
        anchor = self.stop(first=True)
        path = Path(anchor['Path'])
        value = json.loads(path.read_text(encoding='utf-8'))
        value['Binding']['SourceBytes'] = float('nan')
        raw = json.dumps(value, allow_nan=True).encode('utf-8')
        path.write_bytes(raw)
        anchor = dict(anchor, Sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_self_referencing_generation_does_not_replay_forever(self):
        anchor = self.stop()
        anchor = self.rewrite(anchor, lambda value: value.update(Previous=dict(Name=Path(anchor['Path']).name, Sha256=anchor['Sha256'])))
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_rehashed_source_bound_nonimage_cannot_become_verified_png(self):
        anchor = self.stop()
        state = json.loads(Path(anchor['Path']).read_text(encoding='utf-8'))
        record = state['Files'][0]
        old = self.output / (record['Path'] + '.partial')
        junk = self.source.read_bytes()[:64]
        self.assertFalse(junk.startswith(photos.PNG))
        digest = hashlib.sha256(junk).hexdigest()
        forged = 'png-' + digest + '.png'
        old.rename(self.output / (forged + '.partial'))
        (self.output / (forged + '.partial')).write_bytes(junk)

        def change(value):
            value['Files'][0].update(Path=forged, Sha256=digest, Bytes=len(junk),
                                    Extents=[dict(ImageOffset=0, LogicalOffset=0, Length=len(junk))])
        anchor = self.rewrite(anchor, change)
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)
        self.assertFalse((self.output / forged).exists())

    def test_rehashed_format_status_disagreement_is_rejected(self):
        anchor = self.stop()
        state = json.loads(Path(anchor['Path']).read_text(encoding='utf-8'))
        record = state['Files'][0]
        old = self.output / (record['Path'] + '.partial')
        renamed = 'jpeg-' + record['Sha256'] + '.jpg'
        old.rename(self.output / (renamed + '.partial'))
        anchor = self.rewrite(anchor, lambda value: value['Files'][0].update(Path=renamed, Status='jpeg_gap_structural_candidate'))
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_overlap_rehashed_mapping_is_rejected(self):
        anchor = self.stop()
        def overlap(value):
            record = value['Files'][0]
            record['Extents'][1]['ImageOffset'] = record['Extents'][0]['ImageOffset']
        anchor = self.rewrite(anchor, overlap)
        with self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_actual_runtime_dependency_change_prevents_resume(self):
        anchor = self.stop()
        import PIL
        with patch.object(PIL, '__version__', PIL.__version__ + '.owned-change'), self.assertRaises(checkpoint.CheckpointError):
            self.resume(anchor)

    def test_torn_generation_is_not_adopted_as_parent_anchor(self):
        anchor = self.stop()
        path = Path(anchor['Path'])
        next_path = path.parent / ('checkpoint-%012d.json.partial' % (anchor['Sequence'] + 1))
        next_path.write_bytes(b'{"Schema":1,"unfinished":')
        result = self.resume(anchor)
        self.assertEqual(result['Status'], 'complete')
        self.assertEqual((self.output / result['Files'][0]['Path']).read_bytes(), self.payload)
        self.assertTrue(list(path.parent.glob('orphan-*')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
