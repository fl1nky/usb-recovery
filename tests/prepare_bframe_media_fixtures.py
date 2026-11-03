"""Expand and verify the small pinned native B-frame corpus without FFmpeg."""
from pathlib import Path
import gzip
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
CORPUS=ROOT/'tests/fixtures/video-bframes'
MANIFEST_SHA='a8407ca1d2faf1b877f6cf27c49721e4fa99880a0c493903bb7c7e3a0d1db1f0'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare(destination,verify=False):
    manifest_raw=(CORPUS/'manifest.json').read_bytes()
    assert sha(manifest_raw)==MANIFEST_SHA
    manifest=json.loads(manifest_raw)
    expected={'manifest.json':manifest_raw}
    for row in manifest['Files']:
        assert Path(row['Path']).name==row['Path']
        raw=(CORPUS/row['Path']).read_bytes()
        assert len(raw)==row['Bytes'] and sha(raw)==row['Sha256']
        if not row['Path'].endswith('.gz'):
            expected[row['Path']]=raw
    for case in manifest['Cases']:
        assert case['SourceBytes']==2*1024*1024
        # Compressed bytes are independently pinned before the decoder sees them.
        raw=gzip.decompress((CORPUS/case['Image']).read_bytes())
        assert len(raw)==case['SourceBytes'] and sha(raw)==case['SourceSha256']
        expected[case['ExpandedImage']]=raw
    if verify:
        assert destination.is_dir()
    else:
        destination.mkdir(parents=True,exist_ok=False)
        for name,raw in expected.items():
            (destination/name).write_bytes(raw)
    assert {p.name for p in destination.iterdir()}==set(expected)
    for name,raw in expected.items():
        assert (destination/name).is_file() and (destination/name).read_bytes()==raw
    print('PASS: two pinned native B-frame image/original/frame/map fixtures')


if __name__=='__main__':
    args=sys.argv[1:]
    verify='--verify' in args
    args=[x for x in args if x!='--verify']
    prepare(Path(args[0]).resolve(),verify)
