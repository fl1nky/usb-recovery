"""Owned before/after inputs against real helpers, without GUI or Python on PATH."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import random
import shutil
import subprocess
import uuid
from PIL import Image
ROOT = Path(__file__).resolve().parents[1]

def run(executable, baseline=None):
    EVIDENCE = ROOT / '.build' / ('frozen-readability-' + uuid.uuid4().hex)
    EVIDENCE.mkdir(parents=True)
    EXE = executable.resolve(strict=True)
    OLD_EXE = baseline.resolve(strict=True) if baseline else None

    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith('PYTHON')}
    environment['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32')
    assert shutil.which('python.exe', path=environment['PATH']) is None
    if OLD_EXE is not None:
        assert digest(OLD_EXE) == '75d0feb6f47fbd21ccb8319e32e8e1c2ef9578d5619bdf1c9d0a687ceeedfdc4'
    invocations = []

    def invoke(executable, request, expected_exit=0):
        completed = subprocess.run([str(executable)], input=json.dumps(request, ensure_ascii=False), encoding='utf-8', capture_output=True, env=environment, cwd=executable.parent, timeout=180, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        index = len(invocations)
        (EVIDENCE / f'process-{index}.stdout.jsonl').write_text(completed.stdout, encoding='utf-8')
        (EVIDENCE / f'process-{index}.stderr.txt').write_text(completed.stderr, encoding='utf-8')
        assert completed.returncode == expected_exit, (index, completed.returncode, completed.stderr[:300])
        assert not completed.stderr.strip(), (index, 'Unexpected diagnostics')
        events = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        results = [event for event in events if event.get('type') == 'result']
        assert len(results) == 1, (index, events)
        invocations.append({'exe_sha256': digest(executable), 'operation': request['operation'], 'exit': completed.returncode, 'status': results[0].get('status'), 'code': results[0].get('code')})
        return results[0]
    source = EVIDENCE / 'источник HTML'
    source.mkdir()
    markup = '<div class="message default" id="message42"><div class="from_name">Alice</div><div class="text">Рецепт<br/>начинка<BR />🥧</div></div>'
    html_file = source / 'messages.html'
    html_file.write_text(markup, encoding='utf-8')
    html_sha = digest(html_file)
    archives = {}
    html_counts = {}
    runs = ([('baseline', OLD_EXE, 0)] if OLD_EXE else []) + [('current', EXE, 1)]
    for label, executable, expected_count in runs:
        archive = EVIDENCE / ('archive-' + label)
        result = invoke(executable, {'protocol': 1, 'operation': 'scan', 'source': str(source), 'destination': str(archive), 'options': {'deep': False}})
        assert result['status'] == 'complete', result
        rows = [json.loads(line) for line in (archive / 'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        assert len(rows) == expected_count, (label, len(rows))
        if label == 'current':
            assert rows[0]['text'] == 'Рецепт\nначинка\n🥧'
            assert rows[0]['message_id'] == '42'
            assert rows[0]['evidence_kind'] == 'export'
        archives[label] = archive
        html_counts[label] = len(rows)
    assert digest(html_file) == html_sha
    for query, mode in [('начинка', 'literal'), ('Рецепт\\s+начинка', 'regex')]:
        result = invoke(EXE, {'protocol': 1, 'operation': 'search', 'archive': str(archives['current']), 'app': 'Telegram', 'query': query, 'query_mode': mode, 'offset': 0, 'limit': 100, 'sort': 'latest'})
        assert result['status'] == 'complete' and result['total'] == 1, result
        record = result['records'][0]
        page = invoke(EXE, {'protocol': 1, 'operation': 'message_page', 'archive': str(archives['current']), 'record_key': record['archive_record_key'], 'text_offset': 0, 'limit': 65536})
        assert page['text'] == 'Рецепт\nначинка\n🥧' and page['eof']
    rng = random.Random(71)
    image = Image.new('RGB', (83, 61))
    image.putdata([tuple((rng.randrange(256) for _ in range(3))) for _ in range(image.width * image.height)])
    encoded = io.BytesIO()
    image.save(encoded, 'JPEG', quality=85, subsampling=0, restart_marker_blocks=8)
    original = encoded.getvalue()
    app = b'\xff\xef\xff\xff' + b'A' * 65533
    raw = original[:2] + app * 4 + original[2:]
    cuts = [p + 2 for p in range(len(raw) - 1) if raw[p] == 255 and 208 <= raw[p + 1] <= 215]
    cuts = [0, cuts[len(cuts) // 3], cuts[len(cuts) * 2 // 3], len(raw)]
    positions = [700 * 512, 2500 * 512, 1300 * 512]
    pieces = [raw[a:b] for a, b in zip(cuts, cuts[1:])]
    storage = bytearray(b'\xcc' * (2 * 1024 * 1024))
    for position, piece in zip(positions, pieces):
        storage[position:position + len(piece)] = piece
    disk = EVIDENCE / 'owned-fragmented-jpeg.dd'
    disk.write_bytes(storage)
    source_sha = digest(disk)
    expected_sha = hashlib.sha256(raw).hexdigest()
    jpeg_outcomes = {}
    for label, executable, expected_count in runs:
        destination = EVIDENCE / ('photos-' + label)
        result = invoke(executable, {'protocol': 1, 'operation': 'fragmented_photos', 'source': str(disk), 'destination': str(destination), 'options': {}})
        report = json.loads((destination / 'report.json').read_text(encoding='utf-8'))
        assert report['Status'] == 'complete' and report['Candidates'] == expected_count, (label, report)
        assert report['SourceUnchanged'] and report['SourceSha256'] == source_sha
        if label == 'current':
            row, = report['Files']
            assert row['Sha256'] == expected_sha
            recovered = destination / row['Path']
            assert recovered.resolve().is_relative_to(destination.resolve())
            assert recovered.read_bytes() == raw
            assert [(extent['ImageOffset'], extent['Length']) for extent in row['Extents']] == list(zip(positions, map(len, pieces)))
            with Image.open(recovered) as decoded, Image.open(io.BytesIO(original)) as reference:
                decoded.load()
                reference.load()
                assert decoded.tobytes() == reference.tobytes()
        jpeg_outcomes[label] = {'candidates': report['Candidates'], 'skipped': report['Skipped']}
    assert digest(disk) == source_sha
    bad = EVIDENCE / 'invalid-protocol-output'
    result = invoke(EXE, {'protocol': 999, 'operation': 'scan', 'source': str(source), 'destination': str(bad)}, 2)
    assert result['status'] == 'error' and result['code'] == 'PROTOCOL_UNSUPPORTED' and (not bad.exists())
    receipt = {'status': 'passed', 'owned_inputs_only': True, 'python_on_product_path': False, 'network_blocking_checked': False, 'no_gui': True, 'acceptance_scope': 'helper operations only', 'old_helper_sha256': digest(OLD_EXE) if OLD_EXE else None, 'new_helper_sha256': digest(EXE), 'html_source_sha256': html_sha, 'html_messages': html_counts, 'jpeg_source_sha256': source_sha, 'jpeg_original_sha256': expected_sha, 'jpeg': jpeg_outcomes, 'invocations': invocations, 'limits': 'Two owned examples, not a general quality percentage or real-device test.'}
    (EVIDENCE / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'status': 'passed', 'processes': len(invocations), 'evidence': str(EVIDENCE)}, ensure_ascii=False))
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, default=ROOT / 'tools/recovery-helper/recovery-helper.exe')
    parser.add_argument('--baseline-exe', type=Path, help='Optional exact accepted 5fa286b helper for before/after evidence')
    arguments = parser.parse_args()
    run(arguments.exe, arguments.baseline_exe)
