"""Extract pinned own MP4/stz2 fixtures; existing mismatches are never repaired.

--verify only reads an existing complete cache. No codecs/recovery/network run.
"""
from pathlib import Path, PurePosixPath
import argparse
import gzip
import hashlib
import json
import os
import stat

ROOT = Path(__file__).absolute().parents[1]
CORPUS = ROOT / 'tests/fixtures/video-stz2'
DEFAULT = ROOT / '.build/video-stz2-fixtures-current'
MANIFEST_CANONICAL_SHA256 = '98d23d8bd8cc39dd7f4aa7959d59e415b73e0622983565e82519d26a88fef396'
CASE_NAMES = ('avc-stsz-control', 'avc-stz2-16', 'hevc-stsz-control', 'hevc-stz2-16')

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def plain(path):
    path = Path(path).absolute()
    require(not str(path).startswith('\\\\'), 'Local fixture paths required')
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            attrs = item.lstat()
            require(not stat.S_ISLNK(attrs.st_mode) and not
                    getattr(attrs, 'st_file_attributes', 0) & 0x400, 'Linked fixture path rejected')
    return path

def relative(name):
    require(isinstance(name, str) and ':' not in name and '\x00' not in name, 'Invalid fixture path')
    name = name.replace('\\', '/')
    path = PurePosixPath(name)
    require(not path.is_absolute() and name == path.as_posix() and
            all(part not in ('', '.', '..') for part in path.parts), 'Unsafe fixture path')
    return path.as_posix()

def inventory(folder):
    folder = plain(folder)
    result = {}
    for parent, directories, files in os.walk(folder, followlinks=False):
        for name in directories:
            plain(Path(parent) / name)
        for name in files:
            path = plain(Path(parent) / name)
            require(path.is_file(), 'Regular fixture files required')
            result[path.relative_to(folder).as_posix()] = (path.stat().st_size, sha(path.read_bytes()))
    return result

def source():
    raw = plain(CORPUS / 'manifest.json').read_bytes()
    manifest = json.loads(raw.decode('utf-8-sig'))
    require(sha(canonical(manifest)) == MANIFEST_CANONICAL_SHA256, 'Changed compact-video source oracle')
    require(manifest['schema'] == 1 and tuple(c['name'] for c in manifest['cases']) == CASE_NAMES,
            'Unexpected compact-video cases')
    require(len(manifest['files']) == 41, 'Incomplete compact-video payload set')
    sources, outputs = {}, {}
    for row in manifest['files']:
        src, dst = relative(row['source']), relative(row['path'])
        require(src not in sources and dst not in outputs and dst not in ('manifest.json', 'prepared.json'),
                'Duplicate/reserved compact-video paths')
        require(row['compression'] in ('none', 'gzip') and
                0 <= row['bytes'] <= 2 * 1024 * 1024 and 0 <= row['source_bytes'] <= 2 * 1024 * 1024,
                'Compact-video payload bound')
        sources[src] = (row['source_bytes'], row['source_sha256'])
        outputs[dst] = (row['bytes'], row['sha256'])
    require(sum(size for size, digest in outputs.values()) <= 8 * 1024 * 1024, 'Compact-video total bound')
    sources['manifest.json'] = (len(raw), sha(raw))
    require(inventory(CORPUS) == sources, 'Changed/missing/extra compact-video source files')
    outputs['manifest.json'] = (len(raw), sha(raw))
    return manifest, raw, sources, outputs

def verify_semantics(target, manifest):
    for case in manifest['cases']:
        image = (target / relative(case['image'])).read_bytes()
        original = (target / relative(case['original'])).read_bytes()
        require(sha(image) == case['image_sha256'] and sha(original) == case['original_sha256'],
                'Compact-video case/oracle disagreement')
        position, used, pieces = 0, [], []
        for extent in case['physical_extents']:
            at, length = extent['source_offset'], extent['length']
            require(extent['logical_offset'] == position and 0 <= at <= len(image) and
                    0 < length <= len(image) - at, 'Compact-video source-range bounds/gap')
            require(all(at + length <= left or right <= at for left, right in used),
                    'Overlapping compact-video source ranges')
            piece = image[at:at + length]
            require(sha(piece) == extent['sha256'], 'Changed compact-video source range')
            pieces.append(piece); used.append((at, at + length)); position += length
        require(b''.join(pieces) == original, 'Compact-video complete replay mismatch')
        codec, sizes = case['codec'], case['table']['sample_sizes']
        packets = json.loads((target / 'originals' / (codec + '-packets.json')).read_text('utf-8'))['packets']
        require([int(p['size']) for p in packets] == sizes and
                len(packets) == case['table']['sample_count'] == case['decoded_frame_count'] == 12,
                'Independent packet-size oracle disagreement')
        require([int(p['pos']) for p in packets] ==
                [case['table']['first_sample'] + sum(sizes[:i]) for i in range(len(sizes))],
                'Independent packet-offset oracle disagreement')
        suffix = 'stsz' if case['table']['box'] == 'stsz' else 'stz2-16'
        lines = (target / 'originals' / (codec + '-' + suffix + '.framemd5')).read_bytes().splitlines()
        frames = [line for line in lines if line and not line.startswith(b'#')]
        require(len(frames) == 12 and sha(b'\n'.join(frames)) == case['decoded_frames_sha256'],
                'Independent decoded-frame oracle disagreement')
    tables = json.loads((target / 'table-oracles.json').read_text('utf-8'))
    require((tables['positive_packing_controls'], tables['negative_policy_controls'],
             tables['native_video_cases_added']) == (7, 12, 0), 'Table controls misclassified as native videos')
    for row in tables['controls']:
        raw = (target / relative(row['path'])).read_bytes()
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'Changed table-only oracle')

def prepare(target=DEFAULT, verify_only=False):
    target = plain(target)
    require(target != CORPUS and CORPUS not in target.parents and target not in CORPUS.parents,
            'Fixture cache/source overlap')
    manifest, manifest_raw, sources, outputs = source()
    factory_sha = sha(Path(__file__).read_bytes())
    marker = {'schema': 1, 'kind': 'owned-video-stz2-cache-v1', 'preparer_sha256': factory_sha,
              'manifest_canonical_sha256': MANIFEST_CANONICAL_SHA256,
              'source_files': {k: {'bytes': n, 'sha256': h} for k, (n, h) in sources.items()},
              'payload_files': {k: {'bytes': n, 'sha256': h} for k, (n, h) in outputs.items()}}
    marker_path = target / 'prepared.json'
    if target.exists():
        require(target.is_dir() and marker_path.is_file(), 'Existing unrecorded compact-video cache; preserved')
        require(json.loads(marker_path.read_text('utf-8')) == marker, 'Changed/stale compact-video cache; preserved')
        actual = inventory(target); actual.pop('prepared.json', None)
        require(actual == outputs, 'Changed/missing/extra compact-video cache payload; preserved')
    else:
        require(not verify_only, 'Compact-video cache absent in read-only verification')
        target.mkdir(parents=True)
        for row in manifest['files']:
            src = plain(CORPUS / relative(row['source']))
            if row['compression'] == 'gzip':
                with gzip.open(src, 'rb') as stream:
                    payload = stream.read(row['bytes'] + 1)
            else:
                payload = src.read_bytes()
            require(len(payload) == row['bytes'] and sha(payload) == row['sha256'], 'Compact-video extraction disagreement')
            dst = plain(target / relative(row['path'])); dst.parent.mkdir(parents=True, exist_ok=True)
            with dst.open('xb') as stream:
                stream.write(payload)
        with (target / 'manifest.json').open('xb') as stream:
            stream.write(manifest_raw)
        require(inventory(target) == outputs, 'Incomplete compact-video extraction')
        verify_semantics(target, manifest)
        require(inventory(CORPUS) == sources and sha(Path(__file__).read_bytes()) == factory_sha,
                'Compact-video source changed during extraction')
        with marker_path.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(marker, stream, indent=2, sort_keys=True); stream.write('\n')
    verify_semantics(target, manifest)
    require(inventory(CORPUS) == sources and sha(Path(__file__).read_bytes()) == factory_sha,
            'Compact-video source changed during verification')
    return {'fixture': 'video-stz2', 'status': 'verified', 'native_cases': 4,
            'table_only_positive': 7, 'table_only_negative_policy': 12, 'payload_files': len(outputs),
            'manifest_canonical_sha256': MANIFEST_CANONICAL_SHA256, 'actual_recovery': 'NOT_RUN_BY_PREPARER'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', type=Path, default=DEFAULT)
    parser.add_argument('--verify', action='store_true', help='Read-only; require an exact existing cache')
    args = parser.parse_args()
    print(json.dumps(prepare(args.target, args.verify)))
