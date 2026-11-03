"""Independent native PNG oracles and exact three-run reconstruction guards."""
from pathlib import Path
from unittest.mock import patch
import hashlib
import json
import random
import struct
import sys
import tempfile
import time
import unittest
import zlib

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'helpers/recovery_engine'),str(ROOT/'tests')]
import fragmented_photos as photos
import png_fragments as gaps
from recovery_checkpoint import CheckpointError
from build_png_two_gap_fixtures import BASE_CASES,ORDERS,create,inventory
from build_png_idat_gap_fixtures import oracle,packets,chunk


class OwnedCancel(Exception):pass


class PngTwoGapRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='owned-png-three-run-')
  self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.number=0

 def fixture(self,name):
  self.number+=1
  source,golden=create(self.root/('input-'+str(self.number)),name)
  return source,golden,self.root/('output-'+str(self.number))

 def run_case(self,name,options=None,**callbacks):
  source,golden,out=self.fixture(name);before=inventory(source.parent)
  result=photos.recover(source,out,options,**callbacks)
  self.assertEqual(before,inventory(source.parent))
  self.assertEqual((out/'job.incomplete').exists(),result['Status']!='complete')
  return source,golden,out,result

 def mapping(self,source,raw,ranges):
  logical=0;spans=[];pieces=[]
  with source.open('rb') as stream:
   for r in ranges:
    at,length=r['ImageOffset'],r['Length']
    self.assertEqual(r['LogicalOffset'],logical)
    self.assertTrue(0<=at<=source.stat().st_size-length and length>0)
    stream.seek(at);pieces.append(stream.read(length));logical+=length;spans.append((at,at+length))
  spans.sort();self.assertTrue(all(a[1]<=b[0] for a,b in zip(spans,spans[1:])))
  self.assertEqual(logical,len(raw));self.assertEqual(b''.join(pieces),raw)

 def exact(self,source,golden,out,result):
  self.assertEqual((result['Status'],result['Candidates']),('complete',1))
  item=result['Files'][0];raw=(out/item['Path']).read_bytes()
  self.assertEqual(hashlib.sha256(raw).hexdigest(),golden['Sha256'])
  self.assertEqual(raw,(source.parent/'original.png').read_bytes())
  self.assertEqual(oracle(raw)['PixelsSha256'],golden['Oracle']['PixelsSha256'])
  self.assertEqual(item['Status'],'png_crc_zlib_reassembled_candidate')
  self.assertIn('not authenticated',item['Note'])
  maps=[item['Extents'],*item.get('AlternateExtents',[])]
  for mapping in maps:self.mapping(source,raw,mapping)
  for known in golden['KnownMaps']:
   if known['Sha256']==golden['Sha256']:
    self.assertTrue(any(photos._extent_key(mapping)==photos._extent_key(known['Extents']) for mapping in maps),
     'Every independently planted physical map must survive, even for identical content')
  self.assertEqual(len({photos._extent_key(mapping) for mapping in maps}),len(maps))
  return item

 def test_all_four_independent_baseline_cases_and_duplicate_source_aliases(self):
  for name in BASE_CASES:
   with self.subTest(name=name):
    source,golden,out,result=self.run_case(name)
    if name=='two-gap-ambiguous':
     self.assertEqual((result['Status'],result['Candidates']),('complete',0))
     self.assertGreater(result['Skipped'].get('png_ambiguous',0),0)
     self.assertNotEqual(hashlib.sha256((source.parent/'alternative.png').read_bytes()).hexdigest(),golden['Sha256'])
    else:
     item=self.exact(source,golden,out,result)
     if name=='two-gap-duplicate-middle':self.assertEqual(len(item.get('AlternateExtents',[])),1)

 def test_all_six_physical_orders_and_unaligned_head(self):
  for name in ORDERS+('unaligned-head',):
   with self.subTest(name=name):self.exact(*self.run_case(name))

 def test_intact_foreign_idat_cannot_hide_valid_three_run_alternative(self):
  source,golden,out,result=self.run_case('mixed-intact-three-run-ambiguous')
  self.assertEqual(sorted(len(m['Extents']) for m in golden['KnownMaps']),[2,3])
  self.assertEqual(len({m['Sha256'] for m in golden['KnownMaps']}),2)
  self.assertNotEqual(oracle((source.parent/'original.png').read_bytes())['PixelsSha256'],
                      oracle((source.parent/'alternative.png').read_bytes())['PixelsSha256'])
  self.assertEqual((result['Status'],result['Candidates']),('complete',0))
  self.assertGreater(result['Skipped'].get('png_ambiguous',0),0)
  self.assertFalse(list(out.glob('*.png')))

 def test_second_cut_at_crc_start_or_inside_each_crc_byte(self):
  for count in range(4):
   with self.subTest(crc_bytes_in_middle=count):self.exact(*self.run_case('crc-split-'+str(count)))

 def test_multiple_idat_continuation_palette_and_ancillary_context(self):
  for name in ('multi-idat-middle','indexed-palette','ancillary-prefix','ancillary-tail'):
   with self.subTest(name=name):self.exact(*self.run_case(name))

 def test_inverse_crc_shifts_and_fast_cut_tables_match_native_zlib(self):
  rng=random.Random(20261103)
  for count in (0,1,3,8,479,512,65537,131072,2*1024*1024):
   left,right=rng.randbytes(701),rng.randbytes(count)
   crc=zlib.crc32(left+right)^zlib.crc32(right)
   self.assertEqual(gaps._unshift(crc,count),zlib.crc32(left))
   table=gaps._inverse_table(count)
   self.assertEqual(gaps._lookup(table,crc),zlib.crc32(left))
  for bad in (-1,2*1024*1024+13,True,1.5):
   with self.assertRaises(ValueError):gaps._unshift(0,bad)
  source,_,_=self.fixture('unaligned-head')
  with source.open('rb') as stream:
   assembler=photos.PhotoAssembler(stream);budget=gaps._Budget(assembler)
   cuts=[8+i*512 for i in range(7)];tables=gaps._cut_tables(cuts,budget)
   for cut,table in zip(cuts,tables):
    for _ in range(8):
     value=rng.getrandbits(32);self.assertEqual(gaps._lookup(table,value),gaps._unshift(value,cut))

 def test_multiple_headers_never_use_standalone_zlib_prefix_pruning(self):
  class Probe:
   idat=[1,2]
  self.assertEqual(gaps._viable_prefixes(Probe(),b'not a zlib header',[8,520,1032],1032,None),2)

 def test_corrupt_or_missing_middle_and_original_crc_never_become_success(self):
  for kind in ('middle','crc','header'):
   with self.subTest(kind=kind):
    source,golden,out=self.fixture('physical-order-012');raw=bytearray(source.read_bytes())
    if kind=='middle':
     at=golden['PhysicalExtents'][1]['ImageOffset'];raw[at:at+512]=b'\xcc'*512
    elif kind=='crc':
     last=golden['PhysicalExtents'][2];raw[last['ImageOffset']+last['Length']-13]^=1
    else:
     packet=next(p for p in packets((source.parent/'original.png').read_bytes()) if p[0]==b'IDAT')
     raw[golden['PhysicalExtents'][0]['ImageOffset']+packet[2]+4]^=0x20
    source.write_bytes(raw);before=inventory(source.parent);result=photos.recover(source,out)
    self.assertEqual(result['Candidates'],0);self.assertFalse(list(out.glob('*.png')))
    self.assertEqual(inventory(source.parent),before)

 def test_valid_chunk_crc_cannot_hide_invalid_adler_or_filter(self):
  for kind in ('adler','filter'):
   source,golden,out=self.fixture('physical-order-012')
   original=(source.parent/'original.png').read_bytes();packet=next(p for p in packets(original) if p[0]==b'IDAT')
   payload=bytearray(packet[1])
   if kind=='adler':payload[-1]^=1
   else:
    inflated=bytearray(zlib.decompress(payload));inflated[0]=5
    payload=bytearray(zlib.compress(inflated,0))
   corrupted=original[:packet[2]]+chunk(b'IDAT',payload)+original[packet[3]:]
   # Negative input is independently written with valid chunk CRC; recovery
   # must still refuse its invalid full stream/row-filter semantics.
   a,b=golden['LogicalCuts'];positions=[r['ImageOffset'] for r in golden['PhysicalExtents']]
   image=bytearray(b'\xa5'*golden['SourceBytes'])
   for start,end,at in zip((0,a,b),(a,b,len(corrupted)),positions):image[at:at+end-start]=corrupted[start:end]
   source.write_bytes(image);result=photos.recover(source,out)
   self.assertEqual(result['Candidates'],0);self.assertFalse(list(out.glob('*.png')))

 def test_join_source_and_crc_bounds_report_incomplete_not_unique(self):
  for constant in ('MAX_JOIN_CELLS','MAX_MIDDLE_INDEX_BYTES','MAX_CRC_BYTES'):
   with self.subTest(bound=constant):
    anchors=[]
    with patch.object(gaps,constant,1):
     _,_,out,result=self.run_case('physical-order-012',checkpoint_progress=anchors.append)
    self.assertEqual((result['Status'],result['Candidates']),('limited',0))
    self.assertTrue(any(k.endswith('_incomplete') for k in result['Skipped']))
    state=json.loads(Path(anchors[-1]['Path']).read_text(encoding='utf8'))
    self.assertEqual(state['Cursor']['Png'],0)

 def test_max_states_one_never_claims_completed_uniqueness(self):
  _,_,_,result=self.run_case('two-gap-rgb',{'max_states':1})
  self.assertEqual((result['Status'],result['Candidates']),('limited',0))
  self.assertTrue(any(k.endswith('_incomplete') for k in result['Skipped']))

 def test_cancellation_inside_new_index_or_join_resumes_exact_maps(self):
  source,golden,out=self.fixture('two-gap-duplicate-middle');before=inventory(source.parent)
  anchors=[];active=False;base=time.monotonic();elapsed=0
  def clock():
   nonlocal elapsed,active
   frame=sys._getframe().f_back
   while frame:
    if frame.f_code.co_name=='_three_run_candidates':active=True;break
    frame=frame.f_back
   if active:elapsed+=0.5
   return base+elapsed
  def cancel(done,total):
   if active:raise OwnedCancel('owned three-run cancellation')
  with patch('png_fragments.time.monotonic',side_effect=clock):
   with self.assertRaises(OwnedCancel):photos.recover(source,out,progress=cancel,checkpoint_progress=anchors.append)
  self.assertTrue(anchors);self.assertTrue((out/'job.incomplete').exists())
  result=photos.recover(source,out,{'resume_checkpoint':anchors[-1]})
  self.exact(source,golden,out,result)
  self.assertTrue(result['ResumedFromCheckpoint'])
  self.assertEqual(result['ResumedIndexBytes'],source.stat().st_size)
  self.assertEqual(inventory(source.parent),before)

 def test_new_join_constants_are_part_of_checkpoint_code_binding(self):
  anchors=[];source,golden,out,result=self.run_case('physical-order-012',checkpoint_progress=anchors.append)
  self.exact(source,golden,out,result);before=inventory(out)
  with patch.object(gaps,'MAX_JOIN_CELLS',gaps.MAX_JOIN_CELLS+1):
   with self.assertRaisesRegex(CheckpointError,'PHOTO_CHECKPOINT_BINDING_MISMATCH'):
    photos.recover(source,out,{'resume_checkpoint':anchors[-1]})
  self.assertEqual(inventory(out),before)


if __name__=='__main__':unittest.main()
