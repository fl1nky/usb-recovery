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


if __name__=='__main__':
    unittest.main(verbosity=2)
