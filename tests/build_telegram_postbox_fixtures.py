"""Extract immutable controlled CLR/SQLite inputs. No producer runs in tests."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

FIXTURES=Path(__file__).resolve().parent/'fixtures/telegram-postbox'
MANIFEST_SHA256='02414383b71356e59ea4fa11c5f744ff02d770b60aecff1e44a666660d19583a'


def extract(destination):
    destination=Path(destination)
    if destination.exists():raise ValueError('Preserve existing fixtures')
    raw=(FIXTURES/'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=MANIFEST_SHA256:raise ValueError('Changed fixture manifest')
    manifest=json.loads(raw)
    archive=FIXTURES/'controlled-layout.zip'
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=manifest['archive_sha256']:raise ValueError('Changed fixture archive')
    expected={row['path']:row for row in manifest['sources']}
    if len(expected)!=14 or sum(row['bytes'] for row in expected.values())>8*1024*1024:raise ValueError('Fixture budget')
    verified=[]
    with zipfile.ZipFile(archive) as source:
        if len(source.namelist())!=len(expected) or set(source.namelist())!=set(expected):raise ValueError('Fixture members differ')
        for item in source.infolist():
            name=item.filename;parts=PurePosixPath(name).parts
            if not parts or name.startswith('/') or '\\' in name or ':' in name or '..' in parts or item.flag_bits&1 or (item.external_attr>>16)&0o170000==0o120000:raise ValueError('Unsafe fixture')
            row=expected[name]
            if item.file_size!=row['bytes']:raise ValueError('Fixture size differs')
            data=source.read(item)
            if hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('Changed fixture')
            verified.append((name,data))
    for name,data in verified:
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    return manifest


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--destination',required=True)
    extract(parser.parse_args().destination)
