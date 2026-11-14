import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'helpers/recovery_engine'))
import resumable_copy as c
import recovery_io
from apfs_journal import FileJournal
from stream_faults import limited_open


class ShortReader(io.BytesIO):
    def read(self, count=-1):
        return super().read(min(count, 65535) if count >= 0 else count)


class CopyTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'copy.dd';self.raw=b'abcde'*(3*c.CHUNK);self.binding={'source_sha256':hashlib.sha256(self.raw).hexdigest()}
    def tearDown(self):self.temp.cleanup()
    def test_resume_exact_and_uncommitted_tail(self):
        def stop(event,**row):
            if row['phase']=='copy' and row['completed']>=10*c.CHUNK:raise InterruptedError()
        with self.assertRaises(InterruptedError):c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,False,stop)
        self.assertFalse(self.path.exists())
        state=json.loads(Path(str(self.path)+'.resume.json').read_text(encoding="utf-8-sig"));self.assertEqual(state['completed'],8*c.CHUNK)
        staged=c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,True)
        self.assertEqual(staged['resumed_bytes'],8*c.CHUNK);c.publish(staged,self.path)
        self.assertEqual(self.path.read_bytes(),self.raw)
        self.assertTrue(c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,True)['published'])
    def test_tampered_prefix_or_binding_rejected(self):
        def stop(event,**row):
            if row['completed']>=8*c.CHUNK:raise InterruptedError()
        with self.assertRaises(InterruptedError):c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,False,stop)
        with self.assertRaises(c.RecoveryIOError):c.stage(io.BytesIO(self.raw),len(self.raw),self.path,{'source_sha256':'changed'},True)
        with Path(str(self.path)+'.partial').open('r+b') as stream:stream.write(b'x')
        with self.assertRaises(c.RecoveryIOError):c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,True)
        self.assertFalse(self.path.exists())
    def test_secret_binding_rejected_before_writes(self):
        with self.assertRaises(c.RecoveryIOError):c.stage(io.BytesIO(self.raw),len(self.raw),self.path,{'nested':{'password':'not-to-save'}},False)
        self.assertFalse(list(self.path.parent.iterdir()))
    def test_hardlinked_partial_not_modified(self):
        original=self.path.parent/'source.dd';original.write_bytes(self.raw);os.link(original,Path(str(self.path)+'.partial'))
        with self.assertRaises(c.RecoveryIOError):c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,True)
        self.assertEqual(original.read_bytes(),self.raw)

    def test_empty_stream_checkpoint_and_publication(self):
        staged=c.stage(io.BytesIO(),0,self.path,self.binding,False)
        c.publish(staged,self.path)
        self.assertEqual(self.path.read_bytes(),b'')
        self.assertTrue(c.stage(io.BytesIO(),0,self.path,self.binding,True)['published'])

    def test_crash_between_publish_link_and_private_alias_removal(self):
        staged=c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,False)
        os.link(staged['partial'],self.path)
        resumed=c.stage(io.BytesIO(self.raw),len(self.raw),self.path,self.binding,True)
        self.assertTrue(resumed['published'])
        self.assertFalse(staged['partial'].exists())
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_durable_apfs_row_before_publication(self):
        template={'volume_id':'synthetic-volume','snapshot_xid':None,'original_path':'/recipe.txt','inode':42,'bytes':len(self.raw)}
        journal=FileJournal(self.path.parent,self.binding,False,65536)
        with patch('apfs_journal.publish',side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):journal.export(template,'.txt',lambda:io.BytesIO(self.raw))
        self.assertEqual(len(journal.records),1)
        self.assertFalse((self.path.parent/journal.records[0]['path']).exists())
        resumed=FileJournal(self.path.parent,self.binding,True,65536)
        self.assertTrue(resumed.export(template,'.txt',lambda:io.BytesIO(self.raw)))
        resumed.finish()
        self.assertEqual((self.path.parent/resumed.records[0]['path']).read_bytes(),self.raw)
        self.assertFalse(list((self.path.parent/'apfs-resume').iterdir()))
        with (self.path.parent/resumed.records[0]['path']).open('r+b') as stream:stream.write(b'tampered')
        with self.assertRaises(c.RecoveryIOError):resumed.export(template,'.txt',lambda:io.BytesIO(self.raw))

    def test_torn_apfs_journal_append_and_source_change(self):
        journal=FileJournal(self.path.parent,self.binding,False,65536)
        template={'volume_id':'v','snapshot_xid':1,'original_path':'/empty','inode':1,'bytes':0}
        journal.export(template,'.bin',lambda:io.BytesIO())
        with journal.path.open('ab') as stream:stream.write(b'{"torn":')
        with self.assertRaises(c.RecoveryIOError):FileJournal(self.path.parent,{'source_sha256':'changed'},True,65536)
        self.assertTrue(journal.path.read_bytes().endswith(b'{"torn":'))
        resumed=FileJournal(self.path.parent,self.binding,True,65536)
        self.assertEqual(len(resumed.records),1)
        resumed.export(template,'.bin',lambda:io.BytesIO())
        resumed.finish()
        self.assertTrue(journal.path.read_bytes().endswith(b'\n'))

    def test_short_reads_and_resume_verification(self):
        def stop(event, **row):
            if row['phase'] == 'copy' and row['completed'] >= 10*c.CHUNK:
                raise InterruptedError()
        with self.assertRaises(InterruptedError):
            c.stage(ShortReader(self.raw), len(self.raw), self.path, self.binding, False, stop)
        staged = c.stage(ShortReader(self.raw), len(self.raw), self.path, self.binding, True)
        self.assertEqual(staged['resumed_bytes'], 8*c.CHUNK)
        c.publish(staged, self.path)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_short_writes_are_completed_before_checkpoint(self):
        with limited_open(lambda path, mode: path.name.endswith('.partial') and mode == 'xb'):
            staged = c.stage(io.BytesIO(self.raw), len(self.raw), self.path, self.binding, False)
        c.publish(staged, self.path)
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertTrue(c.stage(io.BytesIO(self.raw), len(self.raw), self.path, self.binding, True)['published'])

    def test_invalid_write_never_publishes_and_can_resume(self):
        for index, invalid in enumerate((0, None, True, -1, c.CHUNK + 1)):
            with self.subTest(invalid=invalid):
                output = self.path.with_name('invalid-%d.dd' % index)
                with limited_open(lambda path, mode: path.name.endswith('.partial') and mode == 'xb', (invalid,)):
                    with self.assertRaisesRegex(c.RecoveryIOError, '^IO_ERROR$'):
                        c.stage(io.BytesIO(self.raw), len(self.raw), output, self.binding, False)
                self.assertFalse(output.exists())
                state = json.loads(Path(str(output)+'.resume.json').read_text())
                self.assertEqual(state['completed'], 0)
                staged = c.stage(io.BytesIO(self.raw), len(self.raw), output, self.binding, True)
                c.publish(staged, output)
                self.assertEqual(output.read_bytes(), self.raw)

    def test_atomic_short_write_preserves_full_metadata(self):
        state = self.path.with_name('state.json')
        state.write_bytes(b'previous durable metadata')
        expected = b'next metadata' * 100000
        with limited_open(lambda path, mode: path.name.endswith('.tmp') and mode == 'xb'):
            recovery_io.atomic_bytes(state, expected)
        self.assertEqual(state.read_bytes(), expected)

    def test_atomic_failed_write_preserves_previous_and_cleans_own_temp(self):
        state = self.path.with_name('state.json')
        state.write_bytes(b'previous durable metadata')
        for invalid in (0, None, True, -1, 100):
            with self.subTest(invalid=invalid):
                with limited_open(lambda path, mode: path.name.endswith('.tmp') and mode == 'xb', (invalid,)):
                    with self.assertRaisesRegex(c.RecoveryIOError, '^IO_ERROR$'):
                        recovery_io.atomic_bytes(state, b'new metadata')
                self.assertEqual(state.read_bytes(), b'previous durable metadata')
                self.assertFalse(list(state.parent.glob('*.tmp')))

    def test_tuple_secret_binding_rejected_before_writes(self):
        with self.assertRaisesRegex(c.RecoveryIOError, '^INVALID_CHECKPOINT_BINDING$'):
            c.stage(io.BytesIO(self.raw), len(self.raw), self.path, {'nested': ({'key': 'owned sentinel'},)}, False)
        self.assertFalse(list(self.path.parent.iterdir()))

    def test_source_failure_after_checkpoint_can_resume(self):
        class Disconnected(io.BytesIO):
            def read(self, count=-1):
                if self.tell() >= 10*c.CHUNK:
                    raise OSError('owned simulated disconnect')
                return super().read(count)
        with self.assertRaises(OSError):
            c.stage(Disconnected(self.raw), len(self.raw), self.path, self.binding, False)
        self.assertFalse(self.path.exists())
        staged = c.stage(io.BytesIO(self.raw), len(self.raw), self.path, self.binding, True)
        self.assertEqual(staged['resumed_bytes'], 8*c.CHUNK)
        c.publish(staged, self.path)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_failed_checkpoint_keeps_last_durable_prefix(self):
        original = c.atomic
        def fail_final(path, state):
            if state['completed'] == len(self.raw):
                raise OSError('owned simulated full destination')
            original(path, state)
        with patch.object(c, 'atomic', fail_final):
            with self.assertRaises(OSError):
                c.stage(io.BytesIO(self.raw), len(self.raw), self.path, self.binding, False)
        self.assertFalse(self.path.exists())
        staged = c.stage(io.BytesIO(self.raw), len(self.raw), self.path, self.binding, True)
        self.assertEqual(staged['resumed_bytes'], 8*c.CHUNK)
        c.publish(staged, self.path)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_atomic_failed_replace_keeps_previous_and_cleans_own_temp(self):
        state = self.path.with_name('state.json')
        state.write_bytes(b'previous durable metadata')
        with patch.object(recovery_io.os, 'replace', side_effect=OSError('owned rename failure')):
            with self.assertRaises(OSError):
                recovery_io.atomic_bytes(state, b'next metadata')
        self.assertEqual(state.read_bytes(), b'previous durable metadata')
        self.assertFalse(list(state.parent.glob('*.tmp')))

    def test_real_eof_does_not_publish_truncated_source(self):
        with self.assertRaisesRegex(c.RecoveryIOError, '^SOURCE_TRUNCATED$'):
            c.stage(io.BytesIO(self.raw[:-1]), len(self.raw), self.path, self.binding, False)
        self.assertFalse(self.path.exists())
        staged = c.stage(io.BytesIO(self.raw), len(self.raw), self.path, self.binding, True)
        self.assertEqual(staged['resumed_bytes'], 8*c.CHUNK)
        c.publish(staged, self.path)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_process_termination_retains_last_durable_checkpoint(self):
        ready = self.path.parent / 'child.ready'
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--crash-child', str(self.path)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, creationflags=flags)
        try:
            deadline = time.monotonic() + 20
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(ready.exists(), 'owned child reached an uncommitted tail')
            child.kill()
            child.wait(timeout=10)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
        state = json.loads(Path(str(self.path)+'.resume.json').read_text())
        self.assertEqual(state['completed'], 8*c.CHUNK)
        staged = c.stage(io.BytesIO(self.raw), len(self.raw), self.path, self.binding, True)
        self.assertEqual(staged['resumed_bytes'], 8*c.CHUNK)
        c.publish(staged, self.path)
        self.assertEqual(self.path.read_bytes(), self.raw)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--crash-child':
        import threading
        output = Path(sys.argv[2])
        raw = b'abcde' * (3*c.CHUNK)
        binding = {'source_sha256': hashlib.sha256(raw).hexdigest()}
        def pause(event, **row):
            if row['phase'] == 'copy' and row['completed'] >= 10*c.CHUNK:
                (output.parent / 'child.ready').write_bytes(b'ready')
                threading.Event().wait(40)
                raise InterruptedError('owned child timeout')
        c.stage(io.BytesIO(raw), len(raw), output, binding, False, pause)
    else:
        unittest.main()
