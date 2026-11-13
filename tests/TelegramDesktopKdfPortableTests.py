"""Actual frozen helper acceptance for owned Desktop KD2/v2 native inputs.

Only fixture restoration uses development Python. Every product operation runs
the supplied Windows EXE through stdin, with System32-only PATH and no Python
environment. No product module, source bridge, client profile or device is used.
Results and synthetic inputs remain in a fresh private .build evidence folder.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
import uuid
import zipfile

from build_telegram_platform_fixtures import extract_sources, inventory, TEST_KEY, TEST_PASSCODE

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT/'tools/recovery-helper/recovery-helper.exe'
EVIDENCE = None
INVOCATIONS = []
CANARY = 'OWNED-KD2-PORTABLE-REQUEST-NEVER-PUBLISH-2E17F04C'
WRONG_PASSCODE = 'wrong-synthetic-passcode'
MANIFEST_SHA256 = '9c9711965739f03ab3d85d813d21408f0e9fbad27d8e0ef3769776e56a94510a'
PRIVATE_MARKERS = (b'AUTH_MATERIAL_NEVER_READ', b'MAP_MATERIAL_NEVER_READ',
                   b'OPAQUE_ACCOUNT_INFO_NEVER_DECRYPT_KD2')
SECRET_NEEDLES = (TEST_PASSCODE.encode(), WRONG_PASSCODE.encode(), CANARY.encode(),
                  TEST_KEY, TEST_KEY.hex().encode())


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            result.update(block)
    return result.hexdigest()


class TelegramDesktopKdfPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != 'nt' or EXE.suffix.lower() != '.exe' or not EXE.is_file():
            raise RuntimeError('An actual built Windows recovery-helper.exe is required')
        with EXE.open('rb') as stream:
            if stream.read(2) != b'MZ':
                raise RuntimeError('The helper must be a native Windows executable')
        EVIDENCE.mkdir(parents=True, exist_ok=False)
        cls.helper_sha256 = digest(EXE)
        cls.inputs = EVIDENCE/'native-inputs'
        cls.oracle = extract_sources(cls.inputs)
        cls.expected_texts = set(next(row for row in cls.oracle['expected']['desktop']
            if row['case']=='desktop-tag6')['texts'])
        folder = ROOT/'tests/fixtures/telegram-desktop-kdf'
        raw_manifest = (folder/'manifest.json').read_bytes()
        if hashlib.sha256(raw_manifest).hexdigest() != MANIFEST_SHA256:
            raise RuntimeError('The frozen independent KD2 manifest changed')
        cls.manifest = json.loads(raw_manifest)
        if digest(folder/'native-cases.zip') != cls.manifest['archive_sha256']:
            raise RuntimeError('The frozen independent KD2 archive changed')
        cls.cases = {}
        with zipfile.ZipFile(folder/'native-cases.zip') as archive:
            if len(archive.namelist()) != 35 or set(archive.namelist()) != {
                    row['path'] for row in cls.manifest['cases']}:
                raise RuntimeError('The native KD2 archive membership changed')
            for row in cls.manifest['cases']:
                raw = archive.read(row['path'])
                if len(raw) != row['size'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                    raise RuntimeError('A native KD2 fixture changed')
                cls.cases[Path(row['path']).stem] = (raw, row)
        cls.sequence = 0

    @classmethod
    def tearDownClass(cls):
        if digest(EXE) != cls.helper_sha256:
            raise AssertionError('The tested helper executable changed during acceptance')

    def invoke(self, name, passcode, label=None):
        type(self).sequence += 1
        token = str(self.sequence).zfill(3)+'-'+(label or name)
        source = EVIDENCE/'profiles'/token
        source.parent.mkdir(exist_ok=True)
        shutil.copytree(self.inputs/'positive/desktop-tag6',source)
        (source/'key_datas').write_bytes(self.cases[name][0])
        before = inventory(source)
        destination = EVIDENCE/'archives'/token
        secrets = dict(unused_canary=CANARY)
        if passcode is not None:
            secrets['telegram_desktop_passcode'] = passcode
        request = dict(protocol=1,operation='telegram_analyze',destination=str(destination),
            secrets=secrets,options=dict(roots=[str(source)],scan_fragments=False))
        environment = os.environ.copy()
        environment['PATH'] = str(Path(environment.get('SystemRoot',r'C:\Windows'))/'System32')
        for variable in ('PYTHONHOME','PYTHONPATH','PYTHONSTARTUP','VIRTUAL_ENV'):
            environment.pop(variable,None)
        environment['PYTHONNOUSERSITE'] = '1'
        started = time.monotonic()
        completed = subprocess.run([str(EXE)],input=(json.dumps(request)+'\n').encode('utf-8'),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,cwd=EVIDENCE,
            timeout=60,creationflags=subprocess.CREATE_NO_WINDOW)
        # Check before retaining protocol output; failed receipts never log secrets.
        for needle in SECRET_NEEDLES:
            self.assertFalse(needle in completed.stdout+completed.stderr,'Secret canary in helper protocol')
        self.assertEqual(completed.stderr,b'','Frozen helper stderr must stay empty')
        events = [json.loads(line) for line in completed.stdout.decode('utf-8').splitlines() if line.strip()]
        self.assertTrue(events,'Actual helper emitted no protocol events')
        self.assertTrue(all(row.get('protocol')==1 for row in events),'Unknown helper protocol version')
        self.assertEqual(events[-1].get('event'),'result','Expected a final controlled NDJSON result')
        self.assertEqual(sum(row.get('event')=='result' for row in events),1)
        result = events[-1]
        entry = dict(case=token,wrapper=name if name in self.cases else token,operation='telegram_analyze',
            returncode=completed.returncode,status=result.get('status'),code=result.get('code'),
            native_records=result.get('native_records'),draft_records=result.get('draft_records'),
            source_hashes_unchanged=inventory(source)==before,stderr_empty=not completed.stderr,
            elapsed_seconds=round(time.monotonic()-started,3),secret_canaries_absent=True)
        # Do not preserve a request or any of its supplied secret values.
        INVOCATIONS.append(entry)
        self.assertEqual(completed.returncode,0,'Frozen helper returned failure')
        self.assertNotEqual(result.get('status'),'error','Expected a controlled analysis result')
        self.assertTrue(entry['source_hashes_unchanged'],'Original native input bytes changed')
        self.assertFalse(Path(str(destination)+'.work').exists(),'Private work directory survived publication')
        self.assertFalse((destination/'job.incomplete').exists(),'Incomplete archive was published')
        records = [json.loads(line) for line in (destination/'messages.jsonl').read_text('utf-8').splitlines()]
        self.assertEqual(result['history_messages'],0)
        self.assertEqual(result['deleted_supported_records'],0)
        for path in destination.rglob('*'):
            if path.is_file():
                raw = path.read_bytes()
                for needle in SECRET_NEEDLES+PRIVATE_MARKERS:
                    self.assertFalse(needle in raw,'Secret/private canary in published archive')
        protocol = EVIDENCE/'protocol'
        protocol.mkdir(exist_ok=True)
        (protocol/(token+'.ndjson')).write_bytes(completed.stdout)
        return result,records

    def assert_drafts(self,result,records):
        self.assertEqual((result['native_records'],result['draft_records'],len(records)),(2,2,2))
        self.assertEqual({row['text'] for row in records},self.expected_texts)
        for row in records:
            self.assertEqual(row['record_kind'],'telegram_desktop_draft')
            self.assertEqual(row['recovery_status'],'unsent_local_draft')
            self.assertEqual(row['chat_id'],'user:909')
            self.assertIn('not_message_history_or_deleted_message',row['completeness'])
            for field in ('sender_id','sender_name','message_id','timestamp','deleted'):
                self.assertIsNone(row.get(field))

    def test_all_35_native_wrapper_outcomes_on_actual_frozen_collector(self):
        self.assertEqual(len(self.cases),35)
        self.assertEqual(sum(row['accepted'] for _,row in self.cases.values()),9)
        for name,(data,row) in sorted(self.cases.items()):
            with self.subTest(native_wrapper=name):
                result,records = self.invoke(name,'' if row['secret']=='empty' else TEST_PASSCODE)
                if row['accepted']:
                    self.assert_drafts(result,records)
                else:
                    self.assertEqual((result['native_records'],result['draft_records'],records),(0,0,[]))
                    self.assertTrue(any(code.startswith('TELEGRAM_DESKTOP_') for code in result['warnings']))

    def test_wrong_known_code_has_no_open_wrapper_fallback(self):
        for name in ('scrypt-default','passcode-and-open'):
            with self.subTest(native_wrapper=name):
                result,records = self.invoke(name,WRONG_PASSCODE,label='wrong-code-'+name)
                self.assertEqual((result['native_records'],result['draft_records'],records),(0,0,[]))
                self.assertIn('TELEGRAM_DESKTOP_KEY_OR_INTEGRITY_INVALID',result['warnings'])

    def test_no_supplied_code_and_explicit_known_empty_state_are_distinct(self):
        for name in ('scrypt-default','passcode-and-open'):
            with self.subTest(native_wrapper=name):
                result,records = self.invoke(name,None,label='no-code-'+name)
                self.assertEqual((result['native_records'],result['draft_records'],records),(0,0,[]))
                self.assertIn('ENCRYPTED_CACHE_UNSUPPORTED',result['warnings'])
                self.assertIn('NO_READABLE_TELEGRAM_HISTORY',result['warnings'])
        result,records = self.invoke('passcode-and-open','',label='explicit-known-open')
        self.assert_drafts(result,records)


def main():
    global EXE,EVIDENCE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe',type=Path,default=EXE)
    parser.add_argument('--evidence',type=Path)
    args = parser.parse_args()
    EXE = args.exe.resolve()
    EVIDENCE = (args.evidence or ROOT/'.build'/('telegram-desktop-kdf-portable-'+uuid.uuid4().hex)).resolve()
    if EVIDENCE.exists():
        raise SystemExit('Preserve existing evidence; select a fresh --evidence folder')
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TelegramDesktopKdfPortableTests)
    result = unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    log = stream.getvalue()
    for value in (TEST_PASSCODE,WRONG_PASSCODE,CANARY,TEST_KEY.hex()):
        log = log.replace(value,'[REDACTED TEST SECRET]')
    if EVIDENCE.exists():
        summary = dict(protocol=1,helper=str(EXE),helper_sha256=digest(EXE) if EXE.is_file() else None,
            tests_run=result.testsRun,successful=result.wasSuccessful(),failures=len(result.failures),errors=len(result.errors),
            independent_wrapper_inputs=35,expected_supported_wrappers=9,expected_rejected_wrappers=26,
            restricted_path='System32 only',python_environment_removed=True,product_source_modules_imported=False,
            physical_devices_tested=False,real_profiles_tested=False,network_isolation=False,
            boundary='Actual frozen helper stdin/collector on owned Qt5 inputs; repeated drafts are the same two unsent records',
            fixture_manifest_sha256=MANIFEST_SHA256,invocations=INVOCATIONS)
        (EVIDENCE/'acceptance.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (EVIDENCE/'tests.log').write_text(log,encoding='utf-8')
    print(log)
    print('Frozen helper invocations:',len(INVOCATIONS))
    print('Evidence:',EVIDENCE)
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':
    raise SystemExit(main())
