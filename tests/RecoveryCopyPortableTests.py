"""Source-seeded durable checkpoints resumed by the actual frozen helper.

Child PATH contains System32 only. Sources are owned RAW bytes and a pinned
independent LVM2 fixture; these are ordinary files, not physical device tests.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'helpers/recovery_engine'))
import forensic_image
import resumable_copy
import storage_lvm


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(executable):
    executable = executable.resolve(strict=True)
    evidence = ROOT / '.build' / ('frozen-copy-' + uuid.uuid4().hex)
    evidence.mkdir(parents=True)
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith('PYTHON')}
    environment['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32')
    assert shutil.which('python.exe', path=environment['PATH']) is None
    calls = []

    def invoke(request, code='OK'):
        request = {'protocol': 1, **request}
        process = subprocess.run([str(executable)], input=json.dumps(request),
                                 capture_output=True, encoding='utf-8', env=environment,
                                 timeout=120, cwd=executable.parent,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        index = len(calls)
        (evidence / ('process-%d.stdout.jsonl' % index)).write_text(process.stdout, encoding='utf-8')
        (evidence / ('process-%d.stderr.txt' % index)).write_text(process.stderr, encoding='utf-8')
        assert process.returncode == (0 if code == 'OK' else 2), (index, process.returncode)
        assert not process.stderr.strip(), index
        results = [row for line in process.stdout.splitlines() if line.strip()
                   and (row := json.loads(line)).get('type') == 'result']
        assert len(results) == 1 and results[0]['code'] == code, results
        calls.append({'operation': request['operation'], 'exit': process.returncode, 'code': code})
        return results[0]

    raw = evidence / 'источник.dd'
    raw.write_bytes(bytes(range(251)) * 50000)
    raw_hash = sha(raw)
    raw_output = evidence / 'копия RAW'
    request = {'operation': 'prepare_image', 'source': str(raw), 'destination': str(raw_output), 'options': {}}

    def stop_raw(event, **fields):
        if fields.get('phase') == 'materialize' and fields['completed'] >= 10*resumable_copy.CHUNK:
            raise InterruptedError('owned checkpoint fixture')
    try:
        forensic_image.prepare(request, stop_raw)
        raise AssertionError('source seed did not stop')
    except InterruptedError:
        pass
    assert not (raw_output / 'working.dd').exists()
    request['options']['resume'] = True
    invoke(request)
    assert sha(raw_output / 'working.dd') == raw_hash == sha(raw)
    assert json.loads((raw_output / 'source-preparation.json').read_text(encoding='utf-8'))['resumed_bytes'] == 8*resumable_copy.CHUNK
    invoke(request)
    with (raw_output / 'working.dd').open('r+b') as stream:
        stream.write(b'changed')
    invoke(request, 'SOURCE_PREPARATION_CHANGED')

    packed = ROOT / 'tests/StorageFixtures/lvm/lvm.bin.gz'
    assert sha(packed) == '35759d311d34a51c3b911ebfc518e48c2d5ce8c7bc8ee0b11dea6d5f713667b4'
    pv = evidence / 'native-lvm.dd'
    with gzip.open(packed, 'rb') as stream:
        pv.write_bytes(stream.read(32*1024*1024))
    pv_hash = sha(pv)
    assert pv_hash == '3f43cf87e6b97a6ae541703e98a1535e481f1b30a2653fcf51fcf73cae45fde1'
    probe = invoke({'operation': 'lvm_probe', 'sources': [str(pv)]})
    lvm_output = evidence / 'копия LVM'
    request = {'operation': 'lvm', 'sources': [str(pv)], 'destination': str(lvm_output),
               'options': {'volume_id': probe['volumes'][0]['identifier']}}

    def stop_lvm(event, **fields):
        if fields.get('phase') == 'lvm-copy' and fields['completed'] >= resumable_copy.CHUNK:
            raise InterruptedError('owned checkpoint fixture')
    # Seed schema-1 at 1 MiB; the helper uses its production 8 MiB interval.
    # The checkpoint boundary must remain compatible with either interval.
    with patch.object(resumable_copy, 'INTERVAL', resumable_copy.CHUNK):
        assert storage_lvm.handle_lvm(request, stop_lvm)['code'] == 'IO_ERROR'
    assert not (lvm_output / 'lvm.dd').exists()
    request['options']['resume'] = True
    invoke(request)
    assert (lvm_output / 'lvm.dd').read_bytes() == pv.read_bytes()[1024*1024:]
    assert json.loads((lvm_output / 'lvm-report.json').read_text(encoding='utf-8'))['resumed_bytes'] == resumable_copy.CHUNK
    before = sha(lvm_output / 'lvm.dd')
    invoke(request)
    assert sha(lvm_output / 'lvm.dd') == before
    with (lvm_output / 'lvm.dd').open('r+b') as stream:
        stream.write(b'changed')
    invoke(request, 'RESUME_OUTPUT_CHANGED')
    assert sha(pv) == pv_hash and sha(raw) == raw_hash
    receipt = {'status': 'passed', 'helper_sha256': sha(executable), 'invocations': calls,
               'python_on_child_path': False, 'network_blocked_locally': False,
               'gui_tests_run': False, 'real_devices_tested': False,
               'fixtures': 'owned RAW; checksum-pinned upstream LVM2; source-seeded checkpoints'}
    (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print('PASS frozen recovery copy: %d invocations; %s' % (len(calls), evidence))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', required=True, type=Path)
    run(parser.parse_args().exe)
