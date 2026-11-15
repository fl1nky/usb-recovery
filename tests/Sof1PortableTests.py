"""Native libjpeg SOF1 controls against real packaged helpers, no GUI/Python PATH."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import uuid
from PIL import Image
from JpegFragmentRecoveryTests import extended_sequential_jpeg, rst_cuts

ROOT = Path(__file__).resolve().parents[1]
BASELINE_SHA256 = 'bd18710aee4ccc8ad580d9a1bf9f3e0bf0a15babb7fd7bbfeabfc8ec3225c0a5'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(executable, baseline=None):
    executable = executable.resolve(strict=True)
    if baseline:
        baseline = baseline.resolve(strict=True)
        assert sha(baseline) == BASELINE_SHA256
    evidence = ROOT/'.build'/('sof1-frozen-'+uuid.uuid4().hex)
    evidence.mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('PYTHON')}
    env['PATH'] = str(Path(os.environ['SystemRoot'])/'System32')
    rows = []
    configurations = [(False, 0, 8), (False, 1, 4), (False, 2, 2), (True, 0, 8), (True, 0, 0), (False, 0, 8)]
    for index, (gray, subsampling, restart) in enumerate(configurations):
        raw = extended_sequential_jpeg(gray=gray, subsampling=subsampling, restart=restart)
        positive = index != 5
        if not positive:
            changed = bytearray(raw)
            changed[changed.index(b'\xff\xc1')+4] = 12
            raw = bytes(changed)
        cuts = rst_cuts(raw)
        cuts = [cuts[len(cuts)//3], cuts[2*len(cuts)//3]] if restart else [512]
        points = [0, *cuts, len(raw)]
        pieces = [raw[a:b] for a, b in zip(points, points[1:])]
        positions = [700*512, 2500*512, 1300*512] if restart else [2500*512, 500*512]
        storage = bytearray(b'\xcc'*(2*1024*1024))
        for position, piece in zip(positions, pieces):
            storage[position:position+len(piece)] = piece
        image = evidence/('case-%d.dd' % index)
        image.write_bytes(storage)
        before = sha(image)
        versions = [('current', executable, int(positive))]
        if baseline:
            versions.insert(0, ('baseline', baseline, 0))
        for label, binary, expected in versions:
            destination = evidence/('case-%d-%s' % (index, label))
            request = {'protocol': 1, 'operation': 'fragmented_photos', 'source': str(image),
                       'destination': str(destination), 'options': {}}
            process = subprocess.run([str(binary)], input=json.dumps(request), encoding='utf-8',
                                     capture_output=True, env=env, cwd=binary.parent, timeout=180,
                                     creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            (evidence/('case-%d-%s.stdout.jsonl' % (index, label))).write_text(process.stdout, encoding='utf-8')
            (evidence/('case-%d-%s.stderr.txt' % (index, label))).write_text(process.stderr, encoding='utf-8')
            assert process.returncode == 0 and not process.stderr.strip(), (index, label, process.returncode)
            report = json.loads((destination/'report.json').read_text(encoding='utf-8'))
            assert report['Status'] == 'complete' and report['Candidates'] == expected, (index, label, report)
            assert report['SourceUnchanged'] and report['SourceSha256'] == before == sha(image)
            if expected:
                record, = report['Files']
                recovered = destination/record['Path']
                assert recovered.resolve().is_relative_to(destination.resolve())
                assert recovered.read_bytes() == raw
                assert [(e['ImageOffset'], e['Length']) for e in record['Extents']] == list(zip(positions, map(len, pieces)))
                with Image.open(recovered) as restored, Image.open(io.BytesIO(raw)) as original:
                    restored.load(); original.load()
                    assert restored.tobytes() == original.tobytes()
            rows.append({'case': index, 'label': label, 'helper_sha256': sha(binary), 'candidates': expected,
                         'source_sha256': before, 'original_sha256': hashlib.sha256(raw).hexdigest(),
                         'input': 'libjpeg-generated SOF1' if positive else 'controlled unsupported precision',
                         'source_unchanged': True})
    receipt = {'status': 'passed', 'invocations': rows, 'no_gui': True, 'real_devices_tested': False,
               'python_on_child_path': False, 'network_blocked_locally': False,
               'limits': 'Five owned positive SOF1 cases plus a precision rejection, not a general recovery percentage.'}
    (evidence/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
    print('PASS SOF1 portable: %d invocations; %s' % (len(rows), evidence))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    arguments = parser.parse_args()
    run(arguments.exe, arguments.baseline)
