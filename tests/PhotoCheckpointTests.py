"""Owned photo fixtures, acknowledged immutable checkpoints and real crashes."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'helpers/recovery_engine'),str(ROOT/'tests')]
import fragmented_photos as photos
import recovery_checkpoint as checkpoint
from FragmentedPhotoTests import specimen,disk


class PhotoCheckpoints(unittest.TestCase):
    def setUp(self):
        base = ROOT/'.build/photo-checkpoint-tests';base.mkdir(parents=True,exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.temp.name)
        self.source,self.output = self.root/'image.dd',self.root/'out'
        self.payload,self.parts = specimen()
        self.source.write_bytes(disk(self.parts))
        self.before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.anchors = []

    def tearDown(self):
        self.temp.cleanup()

    def collect(self,row):
        self.anchors.append(row)

    def run_recovery(self,anchor=None,**kwargs):
        options = kwargs.pop('options',{})
        if anchor is not None:
            options = dict(options,resume_checkpoint=anchor)
        result=photos.recover(self.source,self.output,options,checkpoint_progress=kwargs.pop('checkpoint_progress',self.collect),**kwargs)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.before)
        return result

    def stopped(self,condition):
        def stop(row):
            self.collect(row)
            state=json.loads(Path(row['Path']).read_text(encoding='utf-8'))
            if condition(state):
                raise InterruptedError('owned cancellation')
        with self.assertRaises(InterruptedError):
            self.run_recovery(checkpoint_progress=stop)
        return self.anchors[-1]

    def test_index_continues_after_acknowledged_block_without_replaying_prefix(self):
        with self.source.open('r+b') as stream:
            stream.seek(70*1024*1024-1);stream.write(b'\xa5')
        self.before=hashlib.sha256(self.source.read_bytes()).hexdigest()
        anchor=self.stopped(lambda state:state['Phase']=='index' and state['Index']['Position']>=32*1024*1024)
        position=json.loads(Path(anchor['Path']).read_text())['Index']['Position']
        self.assertEqual(position,32*1024*1024)
        progress=[]
        result=self.run_recovery(anchor,progress=lambda done,total:progress.append(done))
        self.assertGreater(min(progress),position)
        self.assertEqual(result['Status'],'complete')
        self.assertEqual((self.output/result['Files'][0]['Path']).read_bytes(),self.payload)

    def test_completed_candidate_is_not_searched_again(self):
        calls=[];original=photos.PhotoAssembler.png
        def tracked(assembler,start):
            calls.append(start)
            return original(assembler,start)
        with patch.object(photos.PhotoAssembler,'png',tracked):
            anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
            first=calls.copy();self.assertEqual(len(first),1)
            self.assertTrue(list(self.output.glob('*.partial')))
            self.assertFalse(list(self.output.glob('*.png')))
            result=self.run_recovery(anchor)
            self.assertEqual(calls,first)
        self.assertEqual(result['Candidates'],1)
        self.assertTrue(result['ResumedFromCheckpoint'])
        self.assertEqual(result['ResumedIndexBytes'],len(disk(self.parts)))
        self.assertEqual(result['ReusedCandidates'],1)
        self.assertFalse((self.output/'job.incomplete').exists())

    def index_source(self):
        raw=bytearray(b'\xa5'*(2*1024*1024));raw[64:72]=photos.PNG;raw[1048640:1048648]=photos.PNG
        self.source.write_bytes(raw)

    @staticmethod
    def index_state(reader):
        return dict(Phase='index',Index=photos._snapshot(reader),Cursor=dict(Png=0,Jpeg=0),
                    Files=[],Skipped=dict(reader.skipped),VerifiedBytes=reader.verified,DecodedBytes=reader.decoded)

    def test_slow_limit_commits_completed_prefix_and_repeated_resume_advances(self):
        self.index_source();binding=dict(SourceBytes=self.source.stat().st_size,SourceSha256=hashlib.sha256(self.source.read_bytes()).hexdigest())
        state_dir=self.root/'slow.state';state_dir.mkdir();anchor=None
        for expected in (1048576,2097152):
            clock=[0.0]
            with patch.object(photos.time,'monotonic',lambda:clock[0]),self.source.open('rb') as stream:
                reader=photos.PhotoAssembler(stream,progress=lambda done,total:clock.__setitem__(0,121.0))
                reader.size=8*1024**3  # Test the large-device byte interval without creating/hash-reading 8 GiB.
                journal=checkpoint.Journal(state_dir,binding,anchor,lambda row:self.anchors.append(row))
                if anchor is None:
                    journal.commit(self.index_state(reader))
                else:
                    photos._restore(reader,journal)
                with self.assertRaisesRegex(photos.LimitReached,'index_time_budget'):
                    reader.index(lambda:journal.commit(self.index_state(reader)))
                anchor=self.anchors[-1]
                state=json.loads(Path(anchor['Path']).read_text())
                self.assertEqual(state['Index']['Position'],expected)
                self.assertEqual(state['Index']['starts'],[64] if expected==1048576 else [64,1048640])
                self.assertEqual(state['Index']['Tokens'],expected//1048576)

    def test_time_interval_checkpoints_before_large_byte_interval(self):
        self.index_source();clock=[0.0];saved=[]
        with patch.object(photos.time,'monotonic',lambda:clock[0]),self.source.open('rb') as stream:
            reader=photos.PhotoAssembler(stream,progress=lambda done,total:clock.__setitem__(0,15.0))
            reader.size=8*1024**3
            reader.index(lambda:saved.append(photos._snapshot(reader)))
        self.assertEqual([state['Position'] for state in saved],[2097152])

    def test_midblock_limit_rolls_back_lists_and_preserves_complete_prefix(self):
        self.index_source();raw=bytearray(self.source.read_bytes());at=1048700
        raw[at:at+4]=(0).to_bytes(4,'big');raw[at+4:at+8]=b'IDAT';self.source.write_bytes(raw)
        clock=[0.0];saved=[];original=photos.PhotoAssembler.read
        def stop_in_chunk(reader,offset,length):
            if offset>=1048576:
                clock[0]=121.0
            return original(reader,offset,length)
        with patch.object(photos.time,'monotonic',lambda:clock[0]),patch.object(photos.PhotoAssembler,'read',stop_in_chunk),self.source.open('rb') as stream:
            reader=photos.PhotoAssembler(stream);reader.size=8*1024**3
            with self.assertRaisesRegex(photos.LimitReached,'time_budget'):
                reader.index(lambda:saved.append(photos._snapshot(reader)))
            self.assertEqual(len(saved),1)
            self.assertEqual(saved[0]['Position'],1048576)
            self.assertEqual(saved[0]['starts'],[64])
            self.assertEqual((saved[0]['Tokens'],saved[0]['LastMatch']),(1,64))
            # Normal restore validation must accept the persisted prefix and
            # contain no token from the interrupted second block.
            state=dict(self.index_state(reader),Schema=1,Binding={},Sequence=1,Previous=None)
            replay=photos.PhotoAssembler(stream);replay.size=8*1024**3
            photos._restore(replay,SimpleNamespace(chain=[state]))
            self.assertEqual(replay.starts,[64])

    def test_completed_jpeg_start_is_not_parsed_again(self):
        from JpegFragmentRecoveryTests import jpeg,rst_cuts
        import jpeg_fragments
        self.payload=jpeg();cuts=rst_cuts(self.payload)
        points=[0,cuts[len(cuts)//3],cuts[len(cuts)*2//3],len(self.payload)]
        data=bytearray(b'\xcc'*(2*1024*1024))
        for physical,a,b in zip((700*512,2500*512,1300*512),points,points[1:]):
            data[physical:physical+b-a]=self.payload[a:b]
        self.source.write_bytes(data);self.before=hashlib.sha256(data).hexdigest()
        calls=[];original=jpeg_fragments.header
        def tracked(*args,**kwargs):
            calls.append(args[1]);return original(*args,**kwargs)
        with patch.object(jpeg_fragments,'header',tracked):
            anchor=self.stopped(lambda state:state['Cursor']['Jpeg']==1)
            first=calls.copy();self.assertEqual(len(first),1)
            result=self.run_recovery(anchor)
            self.assertEqual(calls,first)
        self.assertEqual(result['Candidates'],1)
        self.assertEqual((self.output/result['Files'][0]['Path']).read_bytes(),self.payload)

    def test_crash_after_complete_checkpoint_before_publication_is_idempotent(self):
        anchor=self.stopped(lambda state:state['Phase']=='complete')
        self.assertTrue(list(self.output.glob('*.partial')))
        self.assertFalse(list(self.output.glob('*.png')))
        result=self.run_recovery(anchor)
        self.assertEqual(result['Status'],'complete')
        self.assertEqual(len(list(self.output.glob('*.png'))),1)

    def test_limited_job_still_publishes_source_verified_completed_candidate(self):
        raw=bytearray(self.source.read_bytes());raw[100000:100008]=photos.PNG
        self.source.write_bytes(raw);self.before=hashlib.sha256(raw).hexdigest()
        original=photos.PhotoAssembler.png;limited=True
        def fail_later(assembler,start):
            if start==100000 and limited:
                raise photos.LimitReached('time_budget')
            return original(assembler,start)
        with patch.object(photos.PhotoAssembler,'png',fail_later):
            result=self.run_recovery()
            self.assertEqual(result['Status'],'limited')
            self.assertEqual(result['Candidates'],1)
            self.assertEqual((self.output/result['Files'][0]['Path']).read_bytes(),self.payload)
            self.assertTrue((self.output/'job.incomplete').exists())
            anchor=self.anchors[-1];limited=False
            resumed=self.run_recovery(anchor)
        self.assertEqual(resumed['Status'],'complete')
        self.assertEqual(resumed['Candidates'],1)

    def test_rehashed_malformed_map_is_rejected_by_structural_validation(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        path=Path(anchor['Path']);state=json.loads(path.read_text())
        state['Files'][0]['Extents'][0]['LogicalOffset']=1
        raw=checkpoint.encoded(state);path.write_bytes(raw)
        altered=dict(anchor,Sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(checkpoint.CheckpointError,'MAPPING_INVALID'):
            self.run_recovery(altered)

    def test_real_process_crash_resumes_cross_process_code_fingerprint(self):
        runner=self.root/'crash.py';anchor_file=self.root/'ack.json'
        runner.write_text('''import json,os,sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\nfrom fragmented_photos import recover\ndef ack(row):\n p=Path(row['Path']);s=json.loads(p.read_text(encoding='utf-8'))\n if s['Cursor']['Png']==1:\n  with open(sys.argv[4],'w',encoding='utf-8') as f:\n   json.dump(row,f);f.flush();os.fsync(f.fileno())\n  os._exit(77)\nrecover(sys.argv[2],sys.argv[3],checkpoint_progress=ack)\n''',encoding='utf-8')
        process=subprocess.run([sys.executable,str(runner),str(ROOT/'helpers/recovery_engine'),str(self.source),str(self.output),str(anchor_file)],capture_output=True,timeout=30)
        self.assertEqual(process.returncode,77,process.stderr.decode(errors='replace'))
        self.assertTrue((self.output/'job.incomplete').exists())
        anchor=json.loads(anchor_file.read_text(encoding='utf-8'))
        result=self.run_recovery(anchor)
        self.assertEqual(result['Status'],'complete')
        self.assertEqual((self.output/result['Files'][0]['Path']).read_bytes(),self.payload)

    def test_state_hash_tampering_rejected_without_rewriting_owned_outputs(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        path=Path(anchor['Path']);path.write_bytes(path.read_bytes()+b' ')
        before={file.name:file.read_bytes() for file in self.output.iterdir()}
        with self.assertRaisesRegex(checkpoint.CheckpointError,'HASH_MISMATCH'):
            self.run_recovery(anchor)
        self.assertEqual(before,{file.name:file.read_bytes() for file in self.output.iterdir()})

    def test_changed_source_and_options_rejected(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        with self.assertRaisesRegex(checkpoint.CheckpointError,'BINDING_MISMATCH'):
            self.run_recovery(anchor,options={'max_states':17})
        with self.source.open('r+b') as stream:
            stream.seek(0);stream.write(b'X')
        with self.assertRaisesRegex(checkpoint.CheckpointError,'BINDING_MISMATCH'):
            self.run_recovery(anchor)

    def test_changed_code_rejected(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        with patch.object(photos,'MAX_PIXELS',photos.MAX_PIXELS-1),self.assertRaisesRegex(checkpoint.CheckpointError,'BINDING_MISMATCH'):
            self.run_recovery(anchor)

    def test_changed_or_missing_completed_payload_rejected(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        output=next(self.output.glob('*.partial'));original=output.read_bytes()
        altered=bytearray(original);altered[-1]^=1;output.write_bytes(altered)
        with self.assertRaisesRegex(checkpoint.CheckpointError,'OUTPUT_CHANGED'):
            self.run_recovery(anchor)
        output.write_bytes(original);output.unlink()
        with self.assertRaisesRegex(checkpoint.CheckpointError,'OUTPUT_MISSING'):
            self.run_recovery(anchor)

    def test_existing_job_without_external_anchor_remains_untouched(self):
        self.stopped(lambda state:state['Cursor']['Png']==1)
        before={file.name:file.read_bytes() for file in self.output.iterdir()}
        with self.assertRaisesRegex(ValueError,'SOURCE_OR_DESTINATION'):
            self.run_recovery()
        self.assertEqual(before,{file.name:file.read_bytes() for file in self.output.iterdir()})

    def test_completed_old_anchor_quarantines_unacknowledged_outputs_and_generations(self):
        self.run_recovery()
        anchor=next(row for row in self.anchors if json.loads(Path(row['Path']).read_text())['Phase']=='candidates')
        result=self.run_recovery(anchor)
        self.assertEqual(result['Candidates'],1)
        self.assertEqual((self.output/result['Files'][0]['Path']).read_bytes(),self.payload)
        state=self.output.parent/(self.output.name+'.state')
        self.assertTrue(list(state.glob('orphan-*')))
        self.assertEqual(len(list(self.output.glob('*.png'))),1)

    def test_relocated_source_and_job_with_same_bytes_resume(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        old=self.output.parent/(self.output.name+'.state')
        relocated=self.root/'moved';relocated.mkdir()
        self.source.rename(relocated/'copy.dd');self.source=relocated/'copy.dd'
        self.output.rename(relocated/'out');self.output=relocated/'out'
        old.rename(relocated/'out.state')
        anchor=dict(anchor,Path=str(relocated/'out.state'/Path(anchor['Path']).name))
        self.assertEqual(self.run_recovery(anchor)['Status'],'complete')

    def test_anchor_outside_job_and_wrong_sequence_rejected(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        foreign=self.root/'outside.json';foreign.write_bytes(Path(anchor['Path']).read_bytes())
        for changed in (dict(anchor,Path=str(foreign)),dict(anchor,Sequence=anchor['Sequence']+1)):
            with self.assertRaisesRegex(checkpoint.CheckpointError,'ANCHOR_INVALID'):
                self.run_recovery(changed)

    def test_hardlink_checkpoint_and_output_rejected(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        path=Path(anchor['Path']);other=self.root/'linked-state';os.link(path,other)
        with self.assertRaisesRegex(checkpoint.CheckpointError,'UNSAFE_PATH'):
            self.run_recovery(anchor)
        other.unlink()
        path=next(self.output.glob('*.partial'));os.link(path,self.root/'linked-output')
        with self.assertRaisesRegex(checkpoint.CheckpointError,'UNSAFE_PATH'):
            self.run_recovery(anchor)

    def test_real_directory_junction_checkpoint_path_rejected(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        state=self.root/'out.state';actual=self.root/'actual-state'
        state.rename(actual)
        try:
            if os.name=='nt':
                result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(state),str(actual)],capture_output=True,timeout=10)
                self.assertEqual(result.returncode,0,'Unable to create owned NTFS junction')
            else:
                state.symlink_to(actual,target_is_directory=True)
            with self.assertRaisesRegex(checkpoint.CheckpointError,'UNSAFE_PATH'):
                self.run_recovery(anchor)
        finally:
            if state.is_junction() if os.name=='nt' else state.is_symlink():
                self.assertEqual(state.parent.resolve(),self.root.resolve())
                os.rmdir(state) if os.name=='nt' else state.unlink()
            actual.rename(state)

    def test_limits_leave_partial_files_and_incomplete_marker(self):
        result=self.run_recovery(options={'max_states':1})
        self.assertEqual(result['Status'],'limited')
        self.assertTrue((self.output/'job.incomplete').exists())
        self.assertFalse(list(self.output.glob('*.png')))

    def test_generation_storage_limit_explicit_and_existing_anchor_retained(self):
        anchor=self.stopped(lambda state:state['Cursor']['Png']==1)
        before=Path(anchor['Path']).read_bytes()
        with patch.object(checkpoint,'MAX_TOTAL_BYTES',1),self.assertRaisesRegex(checkpoint.CheckpointError,'STORAGE_LIMIT'):
            self.run_recovery(anchor)
        self.assertEqual(Path(anchor['Path']).read_bytes(),before)

    def test_checkpoint_budget_reports_partial_without_dropping_acknowledged_state(self):
        with patch.object(checkpoint,'MAX_GENERATIONS',4):
            result=self.run_recovery()
        self.assertEqual(result['Status'],'limited')
        self.assertEqual(result['Candidates'],1)
        self.assertGreater(result['Skipped']['checkpoint_storage_limit'],0)
        self.assertTrue((self.output/'job.incomplete').exists())
        self.assertEqual((self.output/result['Files'][0]['Path']).read_bytes(),self.payload)
        self.assertEqual(len(self.anchors),4)
        for anchor in self.anchors:
            self.assertEqual(hashlib.sha256(Path(anchor['Path']).read_bytes()).hexdigest(),anchor['Sha256'])


if __name__=='__main__':
    unittest.main(verbosity=2)
