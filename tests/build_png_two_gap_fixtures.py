"""Independent native-PNG three-run sources; no recovery imports or oracle hints.

The native encoder and PNG/zlib/filter oracle come from the accepted independent
one-gap fixture writer. This factory only changes allocation, preserving bytes.
"""
from pathlib import Path
import itertools
import json
import tempfile

from build_png_idat_gap_fixtures import create as native_fixture, digest, oracle, packets

BASE_CASES=('two-gap-rgb','two-gap-large','two-gap-ambiguous','two-gap-duplicate-middle')
ORDERS=tuple('physical-order-'+''.join(map(str,p)) for p in itertools.permutations(range(3)))
CASE_NAMES=BASE_CASES+ORDERS+('unaligned-head','crc-split-0','crc-split-1','crc-split-2','crc-split-3',
 'multi-idat-middle','ancillary-prefix','ancillary-tail','indexed-palette','mixed-intact-three-run-ambiguous')
BASE_ORIGINAL_SHA={
 'two-gap-rgb':'29caa93faa24cd91f0b88dab2d81722441a217d5796e9a3d559a7e15ef77bcdc',
 'two-gap-large':'d5c5b65bc5054878002c8771f7318b502e0c23d68701947d382b4cfe1b5a7766',
 'two-gap-ambiguous':'09ac1c5e93fc58963f03aae880296f70b30006c263453fe08aa938b4336a3c9d',
 'two-gap-duplicate-middle':'7a57430fd9dfb8c5aaaa44c8c6b8b5e26d05d0352fce6cb4ea3f003fd5a2122f'}


def inventory(folder):
 return {p.relative_to(folder).as_posix():digest(p.read_bytes()) for p in sorted(Path(folder).rglob('*')) if p.is_file()}


def create(destination,name):
 if name not in CASE_NAMES:raise ValueError('Unknown independent three-run PNG case')
 destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
 native_name={'two-gap-rgb':'cut-128k','two-gap-large':'cut-1280k',
  'two-gap-ambiguous':'ambiguous-tail','two-gap-duplicate-middle':'cut-4k',
  'multi-idat-middle':'multi-idat-middle','ancillary-prefix':'ancillary-prefix',
  'ancillary-tail':'ancillary-tail','indexed-palette':'indexed-palette',
  'mixed-intact-three-run-ambiguous':'mixed-intact-gap-ambiguous'}.get(name,'cut-4k')
 with tempfile.TemporaryDirectory(prefix='owned-native-three-run-png-') as temporary:
  folder=Path(temporary)/'native';native_fixture(folder,native_name)
  original=(folder/'original.png').read_bytes()
  alternative=(folder/'alternative.png').read_bytes() if name in ('two-gap-ambiguous','mixed-intact-three-run-ambiguous') else None
 if name in BASE_ORIGINAL_SHA and digest(original)!=BASE_ORIGINAL_SHA[name]:
  raise ValueError('Native original changed from the independently approved baseline')
 known=oracle(original);idats=[p for p in packets(original) if p[0]==b'IDAT']
 index=1 if name=='multi-idat-middle' else 0
 packet=idats[index]
 head=8192;cuts=(4096,32768);locations=(head,65536,131072);size=256*1024
 if name=='two-gap-rgb':cuts=(32768,131072);locations=(8192,262144,65536);size=512*1024
 if name=='two-gap-large':cuts=(131072,1310720);locations=(8192,2097152,1048576);size=4*1024*1024
 if name=='two-gap-duplicate-middle':locations=(8192,65536,196608)
 if name in ORDERS:
  slots=(8192,65536,131072);locations=tuple(slots[int(c)] for c in name[-3:]);head=locations[0]
 if name=='unaligned-head':head+=73;locations=(head,65536,131072)
 if name=='indexed-palette':cuts=(4096,8192)
 if name=='multi-idat-middle':cuts=(packet[2]+4096,packet[2]+8192)
 if name.startswith('crc-split-'):
  count=int(name[-1]);last=packet[3]-4+count
  head=8192+(-last)%512;locations=(head,65536,131072);cuts=(4096,last)
 a=((head+cuts[0]+511)//512)*512-head
 b=cuts[1] if name.startswith('crc-split-') else ((head+cuts[1]+511)//512)*512-head
 assert packet[2]+8<a<b<packet[3]
 assert b-a>=512 and (head+a)%512==(head+b)%512==0
 image=bytearray(b'\xa5'*size)
 def mapping(data,positions):
  result=[]
  for begin,end,physical in zip((0,a,b),(a,b,len(data)),positions):
   image[physical:physical+end-begin]=data[begin:end]
   result.append(dict(ImageOffset=physical,LogicalOffset=begin,Length=end-begin))
  return result
 maps=[dict(Sha256=digest(original),Extents=mapping(original,locations))]
 if name=='mixed-intact-three-run-ambiguous':
  foreign_start=next(p[2] for p in packets(alternative) if p[0]==b'IDAT')
  assert alternative[:foreign_start]==original[:foreign_start]
  image[196608:196608+len(alternative)-foreign_start]=alternative[foreign_start:]
  maps.append(dict(Sha256=digest(alternative),Extents=[
   dict(ImageOffset=locations[0],LogicalOffset=0,Length=foreign_start),
   dict(ImageOffset=196608,LogicalOffset=foreign_start,Length=len(alternative)-foreign_start)]))
 elif alternative is not None:
  assert original[:b]==alternative[:b] and len(original)==len(alternative)
  assert oracle(alternative)['PixelsSha256']!=known['PixelsSha256']
  maps.append(dict(Sha256=digest(alternative),Extents=mapping(alternative,locations[:2]+(196608,))))
 if name=='two-gap-duplicate-middle':
  image[98304:98304+b-a]=original[a:b]
  extra=[dict(r) for r in maps[0]['Extents']];extra[1]['ImageOffset']=98304
  maps.append(dict(Sha256=digest(original),Extents=extra))
 for item in maps:
  ranges=item['Extents'];ordered=sorted((r['ImageOffset'],r['ImageOffset']+r['Length']) for r in ranges)
  assert all(left[1]<=right[0] for left,right in zip(ordered,ordered[1:]))
  raw=b''.join(image[r['ImageOffset']:r['ImageOffset']+r['Length']] for r in ranges)
  assert digest(raw)==item['Sha256']
  oracle(raw)
 source=destination/'image.dd';source.write_bytes(image)
 (destination/'original.png').write_bytes(original)
 if alternative is not None:(destination/'alternative.png').write_bytes(alternative)
 golden=dict(Name=name,Image='image.dd',Original='original.png',Sha256=digest(original),Bytes=len(original),
  SourceSha256=digest(image),SourceBytes=len(image),LogicalCuts=[a,b],PhysicalExtents=maps[0]['Extents'],
  KnownMaps=maps,AllOriginalBytesPresent=True,ExpectedCandidates=0 if alternative is not None else 1,
  Oracle=known,IdatIndex=index,IndependentEncoder=True,NoRecoveryImports=True)
 (destination/'golden.json').write_text(json.dumps(golden,indent=2)+'\n',encoding='utf8')
 return source,golden


def build(destination):
 destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
 cases=[]
 for name in CASE_NAMES:
  source,golden=create(destination/name,name)
  cases.append(dict(golden,Image=source.relative_to(destination).as_posix()))
 result=dict(Schema=1,Cases=cases,GeneratorSha256=digest(Path(__file__).read_bytes()),IndependentEncoder=True)
 (destination/'manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
 return result


if __name__=='__main__':
 import sys
 print(json.dumps(dict(cases=len(build(sys.argv[1])['Cases']))))
