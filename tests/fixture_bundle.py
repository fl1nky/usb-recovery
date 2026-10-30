"""Bounded offline bundles of owned fixtures; never opens a device or network."""
from pathlib import Path, PurePosixPath
import argparse
import gzip
import hashlib
import json
import re

MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILES = 4096


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def relative(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('Unsafe fixture path')
    parts = PurePosixPath(name)
    if parts.is_absolute() or parts.as_posix() != name or not parts.parts or len(parts.parts) > 32:
        raise ValueError('Unsafe fixture path')
    for part in parts.parts:
        if (part in {'.', '..'} or part.endswith((' ', '.')) or
                any(ord(c) < 32 or c in '<>"|?*' for c in part) or
                re.fullmatch(r'(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\..*)?', part)):
            raise ValueError('Unsafe fixture path')
    return name


def plain(path):
    path = Path(path).absolute()
    for entry in (path, *path.parents):
        if entry.is_symlink() or entry.is_junction():
            raise ValueError('Linked fixture path')
    return path


def empty(path):
    path = plain(path)
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise FileExistsError('Use a new empty fixture directory')
    path.mkdir(parents=True, exist_ok=True)
    return path


def pack(source, destination):
    source, destination = plain(source), plain(destination)
    if destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError('Fixture source and destination must be separate')
    files = sorted(path for path in source.rglob('*') if path.is_file())
    if not 0 < len(files) <= MAX_FILES:
        raise ValueError('Fixture count limit')
    destination = empty(destination)
    records, total = [], 0
    for path in files:
        plain(path)
        name = relative(path.relative_to(source).as_posix())
        amount = path.stat().st_size
        total += amount
        if amount > MAX_FILE or total > MAX_TOTAL:
            raise ValueError('Fixture size limit')
        raw = path.read_bytes()
        compressed = gzip.compress(raw, compresslevel=9, mtime=0)
        target = destination / (name + '.gz')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(compressed)
        records.append(dict(path=name, bytes=len(raw), sha256=sha(raw),
                            packed_bytes=len(compressed), packed_sha256=sha(compressed)))
    manifest = dict(schema=1, scope='Owned synthetic fixture files; no user data or third-party binaries', files=records)
    (destination / 'bundle.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (destination / 'PROVENANCE.txt').write_text('Synthetic data generated for USB-Recovery with independently pinned encoders. Original generator manifests are included in the bundle. No personal data or third-party program binaries. This file grants no separate license.\n', encoding='utf-8')
    return dict(files=len(records), raw_bytes=total, packed_bytes=sum(row['packed_bytes'] for row in records))


def extract(source, destination):
    source, destination = plain(source), plain(destination)
    if destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError('Fixture source and destination must be separate')
    inventory = plain(source / 'bundle.json')
    if inventory.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Fixture inventory limit')
    manifest = json.loads(inventory.read_text(encoding='utf-8-sig'))
    files = manifest.get('files')
    if type(manifest.get('schema')) is not int or manifest['schema'] != 1 or not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        raise ValueError('Invalid fixture inventory')
    seen, total = set(), 0
    for row in files:
        if not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256', 'packed_bytes', 'packed_sha256'}:
            raise ValueError('Invalid fixture record')
        name = relative(row['path'])
        if name.casefold() in seen or type(row['bytes']) is not int or not 0 <= row['bytes'] <= MAX_FILE or type(row['packed_bytes']) is not int or not 0 < row['packed_bytes'] <= MAX_FILE + 65536:
            raise ValueError('Invalid fixture bounds')
        if not all(isinstance(row[key], str) and re.fullmatch('[a-f0-9]{64}', row[key]) for key in ('sha256','packed_sha256')):
            raise ValueError('Invalid fixture checksum')
        seen.add(name.casefold()); total += row['bytes']
    if total > MAX_TOTAL:
        raise ValueError('Fixture total limit')
    destination = empty(destination)
    for row in files:
        path = plain(source / (row['path'] + '.gz'))
        if path.stat().st_size != row['packed_bytes']:
            raise ValueError('Packed fixture changed')
        packed = path.read_bytes()
        if sha(packed) != row['packed_sha256']:
            raise ValueError('Packed fixture changed')
        with gzip.open(path, 'rb') as stream:
            raw = stream.read(row['bytes'] + 1)
        if len(raw) != row['bytes'] or sha(raw) != row['sha256']:
            raise ValueError('Raw fixture changed')
        target = plain(destination / row['path'])
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output:
            output.write(raw)
    return dict(files=len(files), bytes=total, offline=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('pack','extract'))
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(json.dumps((pack if args.action == 'pack' else extract)(args.source, args.destination)))
