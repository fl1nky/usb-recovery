"""Atomic candidate publication and complete byte-identical source aliases."""
from pathlib import Path
import io
import json
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'helpers/recovery_engine'))
from fragmented_photos import PhotoAssembler,LimitReached,recover
from PIL import Image
import jpeg_fragments as jpeg


class StreamingCheckpoints(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='jpeg-stream-state-')
        self.root=Path(self.temp.name)
        image=Image.frombytes('L',(83,61),random.Random(731).randbytes(83*61))
        out=io.BytesIO();image.save(out,'JPEG',quality=85)
        self.raw=out.getvalue();self.cut=1024;self.start=32768;self.tail=16384
        self.image=bytearray(b'\xcc'*(128*1024))
        self.image[self.start:self.start+self.cut]=self.raw[:self.cut]
        self.image[self.tail:self.tail+len(self.raw)-self.cut]=self.raw[self.cut:]
        self.source,self.output=self.root/'source.dd',self.root/'output'

    def tearDown(self):
        self.temp.cleanup()

    def test_disconnect_after_entropy_match_retries_same_uncommitted_mapping(self):
        self.source.write_bytes(self.image)
        read=PhotoAssembler.read
        anchors=[]
        armed=True
        def fail(self,at,length):
            if armed and at==32768 and length==1024:
                raise LimitReached('owned_candidate_read_disconnection')
            return read(self,at,length)
        with patch.object(PhotoAssembler,'read',fail):
            report=recover(self.source,self.output,checkpoint_progress=anchors.append)
            self.assertEqual((report['Status'],report['Candidates']),('limited',0))
            state=json.loads(Path(anchors[-1]['Path']).read_text())
            self.assertEqual(state['JpegSearch']['Physical'],self.tail)
            self.assertEqual(state['JpegSearch']['Solutions'],[])
            armed=False
            resumed=recover(self.source,self.output,dict(resume_checkpoint=anchors[-1]))
        self.assertEqual((resumed['Status'],resumed['Candidates']),('complete',1))
        self.assertEqual((self.output/resumed['Files'][0]['Path']).read_bytes(),self.raw)
        self.assertEqual(self.source.read_bytes(),self.image)

    def test_byte_identical_tail_aliases_retain_both_complete_maps(self):
        alias=65536
        self.image[alias:alias+len(self.raw)-self.cut]=self.raw[self.cut:]
        self.source.write_bytes(self.image)
        report=recover(self.source,self.output)
        self.assertEqual((report['Status'],report['Candidates']),('complete',1))
        row=report['Files'][0]
        maps=[row['Extents'],*row.get('AlternateExtents',[])]
        self.assertEqual(len(maps),2)
        self.assertEqual({m[1]['ImageOffset'] for m in maps},{self.tail,alias})
        for mapping in maps:
            payload=b''.join(self.image[e['ImageOffset']:e['ImageOffset']+e['Length']] for e in mapping)
            self.assertEqual(payload,self.raw)
        self.assertEqual(report['Skipped']['jpeg_gap_source_mapping_ambiguous'],1)

    def test_batched_grammar_matches_scalar_decoder_across_paged_and_joined_bytes(self):
        pixels=random.Random(2091).randbytes(324*259)
        output=io.BytesIO();Image.frombytes('L',(324,259),pixels).save(output,'JPEG',quality=91)
        raw=output.getvalue();start=jpeg.SourceWindow.PAGE-1024
        self.source.write_bytes(b'\xcc'*start+raw)
        with self.source.open('rb') as stream:
            assembler=PhotoAssembler(stream);frame=jpeg.header(assembler,start)
            entropy=raw[len(frame['prefix'][1]):-2]
            self.assertIn(b'\xff\x00',entropy)
            paged=jpeg.SourceWindow(assembler,frame['scan'],len(entropy))
            for low,high in ((0,32768),(311,511),(len(entropy)-100,len(entropy))):
                self.assertEqual(paged[low:high],entropy[low:high])
            joined=jpeg.JoinedWindow(entropy[:311],jpeg.SourceWindow(assembler,frame['scan']+311,len(entropy)-311))
            self.assertEqual(joined[21:32768],entropy[21:32768])
            for window in (paged,joined):
                scalar,batched=jpeg.Bits(entropy),jpeg.Bits(window)
                transitions=jpeg.BlockTransitions(frame['blocks'],128)
                ordinal=0;total=frame['mcus']*len(frame['blocks'])
                while ordinal<total:
                    count=transitions(batched,ordinal%len(frame['blocks']),min(64,total-ordinal))
                    self.assertTrue(0<count<=64)
                    for n in range(count):jpeg.block(scalar,*frame['blocks'][(ordinal+n)%len(frame['blocks'])])
                    self.assertEqual((batched.at,batched.value,batched.remaining),(scalar.at,scalar.value,scalar.remaining))
                    ordinal+=count
                self.assertTrue(scalar.finish() and batched.finish())

    def test_identical_window_batch_cache_proves_work_reuse_within_memory_bound(self):
        table=jpeg.huffman(bytes([1]+[0]*15),bytes([0]))
        transitions=jpeg.BlockTransitions([(table,table)],128)
        bits=jpeg.Bits(bytes(65536))
        with patch.object(jpeg,'block',wraps=jpeg.block) as measured:
            for _ in range(100):self.assertEqual(transitions(bits,0,64),64)
        self.assertEqual(bits.at,1600)
        self.assertEqual(measured.call_count,64,'Identical bytes reuse a checked syntax transition, not repeated decoding')
        self.assertLessEqual(transitions.bytes,jpeg.MAX_GAP_MEMORY//2)

    def test_cached_proof_requires_matching_lookahead_and_eof(self):
        table=jpeg.huffman(bytes([1]+[0]*15),bytes([0]))
        transitions=jpeg.BlockTransitions([(table,table)],128)
        first=jpeg.Bits(bytes(100));self.assertEqual(transitions(first,0,64),64)
        short=jpeg.Bits(bytes(8));self.assertEqual(transitions(short,0,64),32)
        # Same first sixteen bytes, different speculative lookahead. Both
        # paths must agree with scalar parsing; no near-EOF result is reused.
        for raw in (bytes(16),bytes(16)+b'\xff\xd9',bytes(17)+b'\x00\xff\x00'):
            slow,fast=jpeg.Bits(raw),jpeg.Bits(raw)
            count=transitions(fast,0,64)
            for _ in range(count):jpeg.block(slow,table,table)
            self.assertEqual((fast.at,fast.value,fast.remaining),(slow.at,slow.value,slow.remaining))

    def test_active_suffix_cursor_survives_interruption_and_replays_same_candidate(self):
        output=io.BytesIO();Image.frombytes('L',(320,256),random.Random(558).randbytes(320*256)).save(output,'JPEG',quality=88)
        original=output.getvalue();start,tail,cut=131072,16384,1024
        image=bytearray(b'\xcc'*(256*1024));image[start:start+cut]=original[:cut];image[tail:tail+len(original)-cut]=original[cut:]
        self.source.write_bytes(image)
        expected=recover(self.source,self.root/'uninterrupted')
        read=PhotoAssembler.read;anchors=[];armed=True
        def interrupt(assembler,at,length):
            current=assembler.jpeg_stream_state
            caller=sys._getframe(1).f_code.co_name
            if armed and current and current.get('Active') and caller=='boundary':
                raise LimitReached('jpeg_stream_owned_active_suffix_incomplete')
            return read(assembler,at,length)
        with patch.object(PhotoAssembler,'read',interrupt):
            partial=recover(self.source,self.output,checkpoint_progress=anchors.append)
            self.assertEqual(partial['Status'],'limited')
            state=json.loads(Path(anchors[-1]['Path']).read_text())
            self.assertIsNotNone(state['JpegSearch']['Active'])
            self.assertFalse(list(self.output.glob('*.jpg')))
            armed=False
            resumed=recover(self.source,self.output,dict(resume_checkpoint=anchors[-1]))
        self.assertEqual((resumed['Status'],resumed['Candidates']),(expected['Status'],expected['Candidates']),
                         {'expected_skipped':expected['Skipped'],'resumed_skipped':resumed['Skipped']})
        self.assertEqual({(r['Sha256'],r['Status']) for r in resumed['Files']},{(r['Sha256'],r['Status']) for r in expected['Files']})
        for row in resumed['Files']:
            replay=b''.join(image[e['ImageOffset']:e['ImageOffset']+e['Length']] for e in row['Extents'])
            self.assertEqual((self.output/row['Path']).read_bytes(),replay)
        self.assertEqual(self.source.read_bytes(),image)


if __name__=='__main__':
    unittest.main(verbosity=2)
