import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'helpers/recovery_engine'))
import resumable_copy as c
from apfs_journal import FileJournal


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


if __name__=='__main__':unittest.main()
