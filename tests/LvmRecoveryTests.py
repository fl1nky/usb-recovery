"""Independent native LVM2 PVs plus explicit damaged/synthetic edge controls."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'helpers/recovery_engine'))
import storage_lvm as lvm
from storage_lvm_thin import ThinMapping,crc32c_raw

PINS={
 'lvm':('35759d311d34a51c3b911ebfc518e48c2d5ce8c7bc8ee0b11dea6d5f713667b4','3f43cf87e6b97a6ae541703e98a1535e481f1b30a2653fcf51fcf73cae45fde1'),
 'lvm-mirror-1':('a031b1d83c9f69eae37fce849ab553ec18c58b09f9a05f2c0e4263b98790357d','72b614c72f655bf63fa5eb19d695fa332387ea380bdd41486e06314d11ba0f14'),
 'lvm-mirror-2':('c67254aa86288b97496160a08802e12fcbd417caf3fa279024f93bd1fcdb65ed','34fa132513ac74a51515ae99f3b240649b9c580f3f282ae19199e661246e332e'),
 'lvm-thin':('bf1fa447d43f768e04b93ef60774424f5bec5e138179f967e5269c7343ecd08b','3839cc5bcc7791ca602915994590348b0f9f2f96b907de85e778181df809af3f')}
THIN_ID='J8nR1S-tcbL-1Mbb-Yrhe-STD8-oZ5N-ULSFWr'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def independent_crc32c(data):
    value=0xffffffff
    for byte in data:
        value^=byte
        for _ in range(8):value=(value>>1)^(0x82f63b78 if value&1 else 0)
    return value


class LvmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='native-lvm2-fixtures-');cls.root=Path(cls.temporary.name);cls.sources={}
        for name,pins in PINS.items():
            encoded=(ROOT/'tests/StorageFixtures/lvm'/(name+'.bin.gz')).read_bytes()
            assert hashlib.sha256(encoded).hexdigest()==pins[0]
            with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as source:raw=source.read(32*1024*1024)
            assert hashlib.sha256(raw).hexdigest()==pins[1]
            path=cls.root/(name+'.dd');path.write_bytes(raw);cls.sources[name]=path
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def setUp(self):self.work=tempfile.TemporaryDirectory(prefix='lvm-results-');self.addCleanup(self.work.cleanup);self.output=Path(self.work.name)/'result'
    def request(self,names,identifier=None):
        paths=[str(self.sources.get(n,n)) for n in names]
        if identifier is None:
            probe=lvm.handle_lvm({'operation':'lvm_probe','sources':paths});self.assertEqual(probe['code'],'OK',probe);identifier=probe['volumes'][0]['identifier']
        return {'operation':'lvm','sources':paths,'destination':str(self.output),'options':{'volume_id':identifier}}
    def run_request(self,request):
        before={p:sha(p) for p in request['sources']}
        result=lvm.handle_lvm(request)
        self.assertEqual(before,{p:sha(p) for p in request['sources']})
        return result
    def rejected(self,request,code):
        result=self.run_request(request);self.assertEqual(result['status'],'error',result);self.assertEqual(result['code'],code,result)
        self.assertFalse((Path(request['destination'])/'lvm.dd').exists())
    def test_native_linear_exact_pv_range_and_upstream_known_payload(self):
        request=self.request(['lvm']);result=self.run_request(request);self.assertEqual(result['status'],'complete',result)
        raw=(self.output/'lvm.dd').read_bytes();self.assertEqual(raw,self.sources['lvm'].read_bytes()[1048576:])
        self.assertEqual(raw[:1024],b'\xde\xad\xbe\xef'*256);self.assertEqual(raw[1024:2048],bytes(1024))
        self.assertEqual(hashlib.sha256(raw).hexdigest(),result['image_sha256'])
        self.assertFalse(list(self.output.glob('*.partial')))
    def test_native_mirror_and_thin_known_full_pattern_and_holes(self):
        expected=b''.join(n.to_bytes(2,'little')*2048 for n in range(1,513))+bytes(2*1024*1024)
        cases=[['lvm-mirror-1','lvm-mirror-2'],['lvm-thin']]
        for n,names in enumerate(cases):
            request=self.request(names);request['destination']=str(self.output.parent/str(n))
            result=self.run_request(request);self.assertEqual(result['status'],'complete',result)
            self.assertEqual((Path(request['destination'])/'lvm.dd').read_bytes(),expected)
        probe=lvm.handle_lvm({'operation':'lvm_probe','sources':[str(self.sources['lvm-thin'])]})
        self.assertEqual(len(probe['volumes']),2)
        second=self.request(['lvm-thin'],probe['volumes'][1]['identifier']);self.assertEqual(self.run_request(second)['status'],'complete')
        self.assertEqual((self.output/'lvm.dd').read_bytes(),expected)
    def test_missing_duplicate_and_unequal_mirror_members(self):
        known='34ucWJ-rUDE-A10l-DXcY-oEC7-ZU3D-RGHQhT'
        self.rejected(self.request(['lvm-mirror-1'],known),'LVM_MEMBERS_MISSING')
        self.rejected(self.request(['lvm','lvm'],'TnYdWo-zRE9-wf2T-5nt0-M1aD-vtoP-fASCxK'),'LVM_DUPLICATE_MEMBER')
        changed=self.output.parent/'changed.dd';data=bytearray(self.sources['lvm-mirror-2'].read_bytes());data[1048576+11]^=1;changed.write_bytes(data)
        self.rejected(self.request(['lvm-mirror-1',changed],known),'LVM_MIRRORS_DISAGREE')
    def test_metadata_crc_bounds_and_future_version(self):
        identifier='TnYdWo-zRE9-wf2T-5nt0-M1aD-vtoP-fASCxK'
        for index,(at,code) in enumerate(((612,'LVM_LABEL_CHECKSUM_FAILED'),(4096+13,'LVM_METADATA_CHECKSUM_FAILED'))):
            changed=self.output.parent/('bad-'+str(index)+'.dd');data=bytearray(self.sources['lvm'].read_bytes());data[at]^=1;changed.write_bytes(data)
            self.rejected(self.request([changed],identifier),code)
        truncated=self.output.parent/'short.dd';truncated.write_bytes(self.sources['lvm'].read_bytes()[:2048])
        self.rejected(self.request([truncated],identifier),'LVM_SOURCE_TRUNCATED')
    def test_cancel_resume_and_changed_plaintext_rejected(self):
        request=self.request(['lvm'])
        def cancel(event,**fields):
            if fields.get('phase')=='lvm-copy' and fields['completed']==fields['total']:raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):lvm.handle_lvm(request,cancel)
        self.assertFalse((self.output/'lvm.dd').exists());self.assertTrue((self.output/'lvm.dd.partial').exists())
        request['options']['resume']=True
        result=self.run_request(request);self.assertEqual(result['status'],'complete',result)
        self.assertEqual(json.loads((self.output/'lvm-report.json').read_text())['resumed_bytes'],4*1024*1024)
        with (self.output/'lvm.dd').open('r+b') as changed:changed.write(b'tampered')
        result=self.run_request(request);self.assertEqual(result['code'],'RESUME_OUTPUT_CHANGED')
    def test_thin_crc_dirty_version_and_repaired_cycle_controls(self):
        base=1048576+3*4194304
        original=self.sources['lvm-thin'].read_bytes()
        for case in ('crc','dirty','version','cycle'):
            data=bytearray(original)
            if case=='crc':data[base+77]^=1;code='LVM_THIN_CHECKSUM_FAILED'
            elif case in ('dirty','version'):
                struct.pack_into('<I',data,base+(4 if case=='dirty' else 40),1 if case=='dirty' else 3)
                struct.pack_into('<I',data,base,independent_crc32c(data[base+4:base+4096])^160774)
                code='LVM_THIN_STATE_UNSUPPORTED' if case=='dirty' else 'LVM_THIN_VERSION_UNSUPPORTED'
            else:
                root=struct.unpack_from('<Q',data,base+320)[0];root_at=base+root*4096
                maximum=struct.unpack_from('<I',data,root_at+20)[0]
                child=struct.unpack_from('<Q',data,root_at+32+maximum*8)[0];child_at=base+child*4096
                maximum=struct.unpack_from('<I',data,child_at+20)[0]
                struct.pack_into('<I',data,child_at+4,1);struct.pack_into('<I',data,child_at+16,1)
                struct.pack_into('<Q',data,child_at+32+maximum*8,child)
                struct.pack_into('<I',data,child_at,independent_crc32c(data[child_at+4:child_at+4096])^121107)
                code='LVM_THIN_METADATA_CYCLE'
            path=self.output.parent/(case+'.dd');path.write_bytes(data)
            self.rejected(self.request([path],THIN_ID),code)
    def test_sparse_hole_does_not_hide_a_later_mapped_block(self):
        mapping=ThinMapping.__new__(ThinMapping);mapping.block_size=4096;mapping.mapping={1:3}
        mapping.data=lvm.Logical(16384,lambda at,count:bytes([at//4096])*count)
        self.assertEqual(mapping.read_at(0,8192),bytes(4096)+b'\x03'*4096)
        self.assertEqual(crc32c_raw(b'123456789')^0xffffffff,0xe3069283)
        self.assertEqual(crc32c_raw(b'123456789'),independent_crc32c(b'123456789'))
    def test_stripe_mapping_uses_sectors_and_round_robin_not_concatenation(self):
        # Numerical edge control, separate from native-producer acceptance.
        group=lvm.VolumeGroup.__new__(lvm.VolumeGroup);group.extent=4096;group.opened={}
        sources=[]
        for value in (b'A',b'B'):
            raw=value*4096;sources.append({'handle':io.BytesIO(raw),'bytes':len(raw)})
        group.physical={'p0':(sources[0],0,1),'p1':(sources[1],0,1)}
        group.lvs={'striped':{'id':'generated','flags':[],'status':['READ'],'segment_count':1,
                            'segment1':{'start_extent':0,'extent_count':2,'type':'striped','stripe_count':2,'stripe_size':1,'stripes':['p0',0,'p1',0]}}}
        volume=group.open('striped')
        self.assertEqual(volume.read(8192),(b'A'*512+b'B'*512)*8)
    def test_invalid_requests_and_output_limit(self):
        self.assertEqual(lvm.handle_lvm(None)['code'],'INVALID_REQUEST')
        request=self.request(['lvm']);request['options']['max_output_bytes']=1
        self.rejected(request,'LVM_OUTPUT_LIMIT')


if __name__=='__main__':unittest.main(verbosity=2)
