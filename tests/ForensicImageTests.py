"""Independent libewf media plus deterministic interruption/error controls."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'helpers/recovery_engine'))
import forensic_image as f


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class ForensicImages(unittest.TestCase):
    def test_pinned_vendor_bytes(self):
        vendor=ROOT/'vendor/ewfprobe'
        data=json.loads((vendor/'UPSTREAM.json').read_text())
        self.assertEqual(sha(vendor/'ewfprobe.py'),data['sha256'])
        self.assertEqual(data['commit'],'4af1a54a223edbce12693b29fb3838b63a26b4f2')
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='recovery-ewf-')
        cls.root = Path(cls.temp.name)
        cls.fixtures = cls.root / 'native'
        cls.fixtures.mkdir()
        folder = ROOT / 'tests/fixtures/forensic-images'
        cls.manifest = json.loads((folder/'manifest.json').read_text())
        archive = folder/'native-ewf.tar.gz'
        assert sha(archive) == cls.manifest['archive_sha256']
        with tarfile.open(archive) as inputs:
            members = inputs.getmembers()
            assert {m.name for m in members} == set(cls.manifest['files'])
            for member in members:
                assert member.isfile() and '/' not in member.name and '\\' not in member.name
                expected = cls.manifest['files'][member.name]
                assert member.size == expected['bytes']
                with inputs.extractfile(member) as src, (cls.fixtures/member.name).open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                assert sha(cls.fixtures/member.name) == expected['sha256']

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def request(self, source, folder, **options):
        return {'source': str(source), 'destination': str(folder), 'options': options}

    def test_native_ewf1_and_ex01(self):
        for name, row in self.manifest['variants'].items():
            with self.subTest(name=name):
                source = self.fixtures/row['files'][0]
                out = self.root/name
                request = self.request(source, out)
                result = f.prepare(request, lambda *a, **k: None)
                self.assertEqual(result['status'], 'complete')
                self.assertEqual((out/'working.dd').stat().st_size, self.manifest['size'])
                self.assertEqual(sha(out/'working.dd'), self.manifest['sha256'])
                report = f.read_json(out/'source-preparation.json')
                self.assertEqual(len(report['binding']['sources']), len(row['files']))
                self.assertEqual(len(report['read_map']['ranges']), 0)
                self.assertTrue((out/'working.dd.sha256').read_text().startswith(sha(out/'working.dd')))
                request['options']['resume'] = True
                self.assertEqual(f.prepare(request, lambda *a, **k: None)['status'], 'complete')
                for member in row['files']:
                    self.assertEqual(sha(self.fixtures/member), self.manifest['files'][member]['sha256'])

    def test_ddrescue_masks_unknown_bytes(self):
        source = self.root/'raw-map.dd'
        original = bytes(range(256))*64
        source.write_bytes(original)
        mapping = self.root/'raw-map.map'
        mapping.write_text('# map\n0x0 + 1\n0x0 0x1000 +\n0x1000 0x1000 -\n0x2000 0x1000 ?\n0x3000 0x1000 +\n')
        out = self.root/'mapped'
        result = f.prepare(self.request(source, out, read_map=str(mapping)), lambda *a, **k: None)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual((out/'working.dd').read_bytes(), original[:4096]+bytes(8192)+original[12288:])
        report = f.read_json(out/'working.dd.read-errors.json')
        self.assertEqual(report['unreadBytes'], 8192)
        self.assertEqual(report['ranges'], [{'Offset':4096, 'Length':8192}])
        self.assertEqual(source.read_bytes(), original)

    def test_malformed_map_does_not_publish(self):
        source = self.root/'bad-map-source.dd';source.write_bytes(b'x'*4096)
        for index, text in enumerate(('0 100 +\n50 50 -', '0 5000 +', '0 -1 +', '0 1 X', '', 'junk', '0 0 +')):
            with self.subTest(text=text):
                mapping=self.root/f'bad-{index}.map';mapping.write_text(text)
                out=self.root/f'bad-{index}'
                with self.assertRaises(f.ImageError):
                    f.prepare(self.request(source,out,read_map=str(mapping)),lambda *a,**k:None)
                self.assertFalse((out/'working.dd').exists())

    def test_cancel_and_resume_verified_prefix(self):
        source=self.root/'resume-source.dd';source.write_bytes(bytes(range(251))*(20*1024*1024//251))
        out=self.root/'resumed'; request=self.request(source,out)
        def interrupt(event,**fields):
            if fields.get('phase')=='materialize' and fields['completed']>=10*f.CHUNK:
                raise InterruptedError('controlled stop')
        with self.assertRaises(InterruptedError):f.prepare(request,interrupt)
        checkpoint=f.read_json(out/'preparation-checkpoint.json')
        self.assertEqual(checkpoint['completed'],8*f.CHUNK)
        self.assertFalse((out/'working.dd').exists())
        request['options']['resume']=True
        self.assertEqual(f.prepare(request,lambda *a,**k:None)['status'],'complete')
        self.assertEqual(sha(out/'working.dd'),sha(source))
        self.assertEqual(f.read_json(out/'source-preparation.json')['resumed_bytes'],8*f.CHUNK)

    def test_modified_prefix_rejected(self):
        source=self.root/'tamper-source.dd';source.write_bytes(b'abcd'*(3*f.CHUNK))
        out=self.root/'tamper'
        def stop(event,**fields):
            if fields.get('phase')=='materialize' and fields['completed']>=8*f.CHUNK:raise InterruptedError()
        request=self.request(source,out)
        with self.assertRaises(InterruptedError):f.prepare(request,stop)
        with (out/'working.dd.partial').open('r+b') as target:target.write(b'changed')
        request['options']['resume']=True
        with self.assertRaises(f.ImageError):f.prepare(request,lambda *a,**k:None)
        self.assertFalse((out/'working.dd').exists())

    def test_changed_source_or_map_rejected(self):
        source=self.root/'changed-source.dd';source.write_bytes(b'cd'*(6*f.CHUNK))
        out=self.root/'changed'
        def stop(event,**fields):
            if fields.get('phase')=='materialize' and fields['completed']>=8*f.CHUNK:raise InterruptedError()
        request=self.request(source,out)
        with self.assertRaises(InterruptedError):f.prepare(request,stop)
        with source.open('r+b') as target:target.write(b'changed')
        request['options']['resume']=True
        with self.assertRaises(f.ImageError):f.prepare(request,lambda *a,**k:None)
        self.assertFalse((out/'working.dd').exists())

    def test_ewf_descriptor_checksum_rejected(self):
        source=self.root/'bad-descriptor.Ex01';shutil.copyfile(self.fixtures/'ex01-fast.Ex01',source)
        with source.open('r+b') as target:target.seek(-1,os.SEEK_END);target.write(b'\0')
        out=self.root/'bad-descriptor'
        result=f.handle(self.request(source,out),lambda *a,**k:None)
        self.assertEqual(result['status'],'error')
        self.assertFalse((out/'working.dd').exists())

    def test_hardlinked_partial_never_modified(self):
        source=self.root/'hardlink-source.dd';source.write_bytes(b'source'*2*f.CHUNK)
        out=self.root/'hardlink';out.mkdir()
        os.link(source,out/'working.dd.partial')
        before=sha(source)
        self.assertEqual(f.handle(self.request(source,out,resume=True),lambda *a,**k:None)['status'],'error')
        self.assertEqual(sha(source),before)

    def test_read_map_sidecar_tamper_rejected(self):
        source=self.root/'sidecar-source.dd';source.write_bytes(b'x'*4096)
        out=self.root/'sidecar';request=self.request(source,out)
        f.prepare(request,lambda *a,**k:None)
        (out/'working.dd.read-errors.json').write_text('{}')
        request['options']['resume']=True
        self.assertEqual(f.handle(request,lambda *a,**k:None)['status'],'error')

    def test_concurrent_writer_rejected(self):
        source=self.root/'concurrent-source.dd';source.write_bytes(b'abc'*(4*f.CHUNK))
        out=self.root/'concurrent';request=self.request(source,out)
        entered,release=threading.Event(),threading.Event()
        failures=[]
        def pause(event,**fields):
            if fields.get('phase')=='materialize':
                entered.set();release.wait(10);raise InterruptedError()
        def worker():
            try:f.prepare(request,pause)
            except InterruptedError:pass
            except Exception as error:failures.append(str(error))
        thread=threading.Thread(target=worker);thread.start()
        try:
            self.assertTrue(entered.wait(10))
            result=f.handle(request,lambda *a,**k:None)
            self.assertEqual(result['code'],'SOURCE_PREPARATION_BUSY')
        finally:release.set();thread.join(10)
        self.assertFalse(thread.is_alive());self.assertEqual(failures,[])

    def test_original_acquisition_errors_cannot_be_erased(self):
        source=self.root/'old-acquisition.dd';source.write_bytes(b'x'*4096)
        health={'sha256':sha(source),'size':4096,'copied':4096,'unreadBytes':512,'status':'complete_with_read_errors','ranges':[{'Offset':512,'Length':512}]}
        Path(str(source)+'.read-errors.json').write_text(json.dumps(health))
        mapping=self.root/'all-rescued.map';mapping.write_text('0x0 + 1\n0 4096 +\n')
        out=self.root/'old-acquisition'
        result=f.prepare(self.request(source,out,read_map=str(mapping)),lambda *a,**k:None)
        self.assertEqual(result['status'],'partial')
        self.assertEqual((out/'working.dd').read_bytes(),b'x'*512+bytes(512)+b'x'*3072)
        report=f.read_json(out/'working.dd.read-errors.json')
        self.assertEqual(report['ranges'],health['ranges'])


if __name__=='__main__':unittest.main()
