"""External ground truth and measurements for regular-file storage corpora.

No recovery module is imported. Unmatched candidates in an incomplete truth set
are unclassified, never automatically labelled false positives.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
MAX_IMAGE_BYTES = 128 * 1024 * 1024
MAX_CASES = 100


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('METADATA_LIMIT')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def regular(root, relative):
    if not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative:
        raise ValueError('INVALID_CORPUS_PATH')
    parts = PurePosixPath(relative).parts
    if PurePosixPath(relative).is_absolute() or any(p in ('', '.', '..') for p in relative.split('/')):
        raise ValueError('INVALID_CORPUS_PATH')
    path = root.joinpath(*parts)
    for node in (path, *path.parents):
        if node.is_symlink() or getattr(node, 'is_junction', lambda: False)():
            raise ValueError('LINKED_CORPUS_PATH')
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('INVALID_CORPUS_FILE')
    return path


def validate(root):
    manifest = read_json(regular(root, 'manifest.json'))
    cases = manifest.get('cases')
    if manifest.get('schema') != 1 or not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError('INVALID_CORPUS')
    seen = set()
    for case in cases:
        name = case.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}', name) or name in seen:
            raise ValueError('INVALID_CASE_ID')
        seen.add(name)
        if case.get('engine') not in ('fat', 'ntfs', 'ext4'):
            raise ValueError('INVALID_ENGINE')
        image = regular(root, case['image'])
        size = case.get('bytes')
        if type(size) is not int or not 0 < size <= MAX_IMAGE_BYTES or image.stat().st_size != size:
            raise ValueError('INVALID_IMAGE_SIZE')
        if digest(image) != case.get('sha256'):
            raise ValueError('IMAGE_HASH_MISMATCH')
        expected = case.get('expected_sha256')
        if not isinstance(expected, list) or len(expected) != len(set(expected)) or any(
                not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for value in expected):
            raise ValueError('INVALID_GROUND_TRUTH')
        if case.get('truth_scope') not in ('complete_negative', 'target_contents_only'):
            raise ValueError('INVALID_TRUTH_SCOPE')
        if case['truth_scope'] == 'complete_negative' and expected:
            raise ValueError('CONFLICTING_GROUND_TRUTH')
        if not isinstance(case.get('provenance'), dict) or not case['provenance'].get('kind'):
            raise ValueError('MISSING_PROVENANCE')
    return manifest


def score(case, files):
    expected = set(case['expected_sha256'])
    actual = {row['sha256'] for row in files}
    matched = expected & actual
    unmatched = actual - expected
    negative = case['truth_scope'] == 'complete_negative'
    return {
        'expected_unique_contents': len(expected), 'exact_unique_contents': len(matched),
        'missing_sha256': sorted(expected - actual), 'candidate_unique_contents': len(actual),
        'negative_control_candidates': len(actual) if negative else None,
        'unclassified_candidate_contents': len(unmatched) if not negative else 0,
        'exact_recall': len(matched) / len(expected) if expected else None,
    }


def run(root, destination, driver, require_exact=False):
    manifest_path = regular(root, 'manifest.json')
    manifest_hash = digest(manifest_path)
    manifest = validate(root)
    if destination.exists() or destination.resolve().is_relative_to(root.resolve()):
        raise ValueError('INVALID_OUTPUT_DIRECTORY')
    destination.mkdir(parents=True)
    driver = driver.resolve(strict=True)
    driver_hash = digest(driver)
    application = regular(driver.parent, 'USB-Recovery.exe')
    application_hash = digest(application)
    rows = []
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('PYTHON')}
    env['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32')
    for case in manifest['cases']:
        image = regular(root, case['image'])
        output = destination / case['name']
        request = {'image': str(image.resolve()), 'destination': str(output.resolve()),
                   'engine': case['engine'], 'source_sha256': case['sha256'], 'timeout_seconds': 120}
        started = time.perf_counter()
        process = subprocess.run([str(driver)], input=json.dumps(request), encoding='utf-8',
                                 capture_output=True, env=env, timeout=150,
                                 creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        (destination / (case['name'] + '.stdout.json')).write_text(process.stdout, encoding='utf-8')
        (destination / (case['name'] + '.stderr.txt')).write_text(process.stderr, encoding='utf-8')
        result = json.loads(process.stdout)
        if process.stderr.strip() or result.get('schema') != 1:
            raise ValueError('INVALID_DRIVER_PROTOCOL')
        if result.get('application_sha256') != application_hash or result.get('driver_sha256') != driver_hash:
            raise ValueError('DRIVER_RUNTIME_CHANGED')
        unchanged = digest(image) == case['sha256']
        if not unchanged:
            raise ValueError('SOURCE_CHANGED')
        files = result.get('files', [])
        for item in files:
            path = Path(item['path'])
            path = regular(output, path.relative_to(output.resolve()).as_posix())
            if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
                raise ValueError('OUTPUT_BINDING_MISMATCH')
        rows.append({'name': case['name'], 'engine': case['engine'],
                     'provenance': case['provenance'], 'status': result['status'], 'exit': process.returncode,
                     'source_unchanged': unchanged, 'score': score(case, files),
                     'wall_seconds': time.perf_counter() - started,
                     'engine_elapsed_ms': result.get('elapsed_ms'),
                     'peak_working_set_bytes': result.get('peak_working_set_bytes'),
                     'memory_scope': result.get('memory_scope'),
                     'application_sha256': result.get('application_sha256'),
                     'files': files, 'code': result.get('code')})
    if digest(manifest_path) != manifest_hash or digest(driver) != driver_hash or digest(application) != application_hash:
        raise ValueError('BENCHMARK_INPUT_CHANGED')
    result = {'schema': 1, 'scope': 'owned regular images; single-process filesystem engines only',
              'manifest_sha256': manifest_hash, 'driver_sha256': driver_hash, 'cases': rows,
              'totals': {'cases': len(rows), 'errors': sum(r['status'] != 'complete' for r in rows),
                         'expected_unique_contents': sum(r['score']['expected_unique_contents'] for r in rows),
                         'exact_unique_contents': sum(r['score']['exact_unique_contents'] for r in rows),
                         'negative_control_candidates': sum(r['score']['negative_control_candidates'] or 0 for r in rows)},
              'real_devices_tested': False, 'gui_tests_run': False,
              'performance_comparison_supported': False, 'paid_competitors_run': False}
    (destination / 'run.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'native_storage_benchmark': result['totals']}, sort_keys=True))
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        print('::notice title=Native storage benchmark::' + json.dumps(
            [{'case': r['name'], 'exact': r['score']['exact_unique_contents'],
              'expected': r['score']['expected_unique_contents'], 'negative_candidates': r['score']['negative_control_candidates'],
              'status': r['status']} for r in rows], separators=(',', ':')))
    totals = result['totals']
    if totals['errors']:
        raise ValueError('BENCHMARK_ENGINE_ERRORS')
    if require_exact and (totals['negative_control_candidates'] or
                          totals['expected_unique_contents'] != totals['exact_unique_contents']):
        raise ValueError('BENCHMARK_EXPECTATION_FAILED')
    return result


def prepare_ext4(destination):
    """Reuse hash-pinned e2fsprogs images; corruption controls remain labelled."""
    if destination.exists():
        raise ValueError('OUTPUT_EXISTS')
    destination.mkdir(parents=True)
    fixtures = ROOT / 'tests/fixtures/ext4'
    original = read_json(fixtures / 'manifest.json')
    selected = ('extent-deleted', 'extent-tree-fragmented', 'bad-super-checksum',
                'bad-inode-checksum', 'bad-block-bitmap-checksum', 'allocated-data-conflict')
    cases = []
    for name in selected:
        row = next(c for c in original['cases'] if c['name'] == name)
        archive = original['compressed_images'][row['image']]
        packed = regular(fixtures, archive['archive'])
        if digest(packed) != archive['archive_sha256']:
            raise ValueError('FIXTURE_ARCHIVE_CHANGED')
        image = destination / row['image']
        with gzip.open(packed, 'rb') as source, image.open('xb') as output:
            done = 0
            while block := source.read(1024 * 1024):
                done += len(block)
                if done > archive['bytes'] or done > MAX_IMAGE_BYTES:
                    raise ValueError('FIXTURE_EXPANSION_LIMIT')
                output.write(block)
        if done != archive['bytes'] or digest(image) != row['sha256']:
            raise ValueError('FIXTURE_IMAGE_CHANGED')
        positive = row['outcome'] == 'recover'
        cases.append({'name': name, 'engine': 'ext4', 'image': image.name, 'bytes': done,
                      'sha256': row['sha256'], 'expected_sha256': [row['payload_sha256']] if positive else [],
                      'truth_scope': 'target_contents_only' if positive else 'complete_negative',
                      'provenance': {'kind': 'native_metadata_with_controlled_deletion' if positive else 'synthetic_integrity_control',
                                     'tools': original['tool_versions'], 'fixture_manifest_sha256': digest(fixtures / 'manifest.json'),
                                     'note': original['provenance']}})
    (destination / 'manifest.json').write_text(json.dumps({'schema': 1, 'cases': cases}, indent=2) + '\n', encoding='utf-8')
    validate(destination)
    return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    command = parser.add_subparsers(dest='command', required=True)
    prepare = command.add_parser('prepare-ext4')
    prepare.add_argument('--destination', required=True, type=Path)
    execute = command.add_parser('run')
    execute.add_argument('--corpus', required=True, type=Path)
    execute.add_argument('--destination', required=True, type=Path)
    execute.add_argument('--driver', required=True, type=Path)
    execute.add_argument('--require-exact', action='store_true')
    arguments = parser.parse_args()
    if arguments.command == 'prepare-ext4':
        prepare_ext4(arguments.destination)
    else:
        run(arguments.corpus.resolve(strict=True), arguments.destination.resolve(), arguments.driver, arguments.require_exact)
