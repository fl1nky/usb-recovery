from pathlib import Path
import gzip
import json
import tempfile
import unittest
from unittest.mock import patch
import fixture_bundle as bundle


class Bundles(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.source=self.root/'source';self.source.mkdir()
        (self.source/'nested').mkdir()
        (self.source/'nested'/'owned.bin').write_bytes(bytes(range(256))*16)
        (self.source/'manifest.json').write_text('{"synthetic":true}',encoding='utf-8')
        self.packed=self.root/'packed';bundle.pack(self.source,self.packed)
        self.output=self.root/'out'

    def tearDown(self):
        self.temp.cleanup()

    def inventory(self):
        return json.loads((self.packed/'bundle.json').read_text(encoding='utf-8'))

    def save(self,value):
        (self.packed/'bundle.json').write_text(json.dumps(value),encoding='utf-8')

    def test_real_round_trip_all_bytes(self):
        result=bundle.extract(self.packed,self.output)
        self.assertTrue(result['offline'])
        for original in self.source.rglob('*'):
            if original.is_file():
                self.assertEqual(original.read_bytes(),(self.output/original.relative_to(self.source)).read_bytes())

    def test_namespace_traversal_and_devices_rejected_before_creation(self):
        for name in ('../outside','/absolute','C:/drive','x\\outside','x:stream','NUL','NUL.bin','COM1','LPT9.txt','COM\u00b9','LPT\u00b2.dat','CONIN$','CONOUT$','CLOCK$','nested/..','nested/./file','nested//file','.','nested/trailing.','nested/trailing ','bad\x00name'):
            with self.subTest(name=repr(name)),self.assertRaises(ValueError):
                bundle.relative(name)
        self.assertFalse(self.output.exists())

    def test_duplicate_and_case_alias_inventory_rejected(self):
        value=self.inventory();second=dict(value['files'][0]);second['path']=second['path'].upper();value['files'].append(second);self.save(value)
        with self.assertRaises(ValueError):bundle.extract(self.packed,self.output)
        self.assertFalse(self.output.exists())

    def test_nonintegral_limits_and_unknown_schema_rejected(self):
        original=self.inventory()
        for key,value in (('bytes',True),('bytes',-1),('bytes',bundle.MAX_FILE+1),('packed_bytes',True),('sha256','not-a-digest')):
            changed=json.loads(json.dumps(original));changed['files'][0][key]=value;self.save(changed)
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):bundle.extract(self.packed,self.output)
            self.assertFalse(self.output.exists())
        changed=original;changed['schema']=True;self.save(changed)
        with self.assertRaises(ValueError):bundle.extract(self.packed,self.output)

    def test_packed_tamper_detected_source_unchanged(self):
        row=self.inventory()['files'][0];path=self.packed/(row['path']+'.gz');path.write_bytes(b'corrupt')
        before=(self.source/'nested'/'owned.bin').read_bytes()
        with self.assertRaises(ValueError):bundle.extract(self.packed,self.output)
        self.assertEqual((self.source/'nested'/'owned.bin').read_bytes(),before)

    def test_expansion_is_bounded_even_with_rehashed_archive(self):
        value=self.inventory();row=value['files'][0];raw=gzip.compress(b'A'*1024*1024,mtime=0);(self.packed/(row['path']+'.gz')).write_bytes(raw)
        row.update(packed_bytes=len(raw),packed_sha256=bundle.sha(raw),bytes=8,sha256=bundle.sha(b'A'*8));self.save(value)
        with self.assertRaises(ValueError):bundle.extract(self.packed,self.output)
        self.assertFalse((self.output/row['path']).exists())

    def test_existing_destination_preserved(self):
        self.output.mkdir();marker=self.output/'keep.txt';marker.write_text('owned existing data',encoding='utf-8')
        with self.assertRaises(FileExistsError):bundle.extract(self.packed,self.output)
        self.assertEqual(marker.read_text(encoding='utf-8'),'owned existing data')

    def test_file_budget_before_output(self):
        with patch.object(bundle,'MAX_FILES',1),self.assertRaises(ValueError):bundle.extract(self.packed,self.output)
        self.assertFalse(self.output.exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
