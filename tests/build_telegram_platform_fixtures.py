"""Restore frozen independent native Qt/Java/SQLite inputs; no regeneration."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import zipfile

FIXTURES = Path(__file__).resolve().parent / "fixtures/telegram-platforms"
MANIFEST_SHA256 = "f802063b5b9de84f314fa3c700478174b63f01e5171850c601e2ff63f612074e"
SOURCE_ARCHIVE_SHA256 = "58249417c988cdd77dc5f310e05c1e5b3129d40ab526ffa1e4ba93598a03f025"
TEST_PASSCODE = "synthetic-known-passcode"  # Public artificial fixture value.
TEST_KEY = bytes((i * 37 + 11) % 256 for i in range(256))
ACCOUNT = "0123456789ABCDEF"
DRAFT_FILE = "ABCDEF0123456789s"


def load_manifest():
    raw = (FIXTURES / "manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("Native platform manifest changed")
    manifest = json.loads(raw)
    if hashlib.sha256((FIXTURES / "native-cases.zip").read_bytes()).hexdigest() != manifest['archive_sha256']:
        raise ValueError("Native platform source archive changed")
    if hashlib.sha256((FIXTURES / "oracle-sources.tar.gz").read_bytes()).hexdigest() != SOURCE_ARCHIVE_SHA256:
        raise ValueError("Independent producer source archive changed")
    return manifest


def extract_sources(destination):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("Preserve existing native platform inputs")
    manifest = load_manifest()
    expected = {row['path']: row for row in manifest['sources']}
    if len(expected) != 63 or sum(row['bytes'] for row in expected.values()) > 4 * 1024 * 1024:
        raise ValueError("Native platform inventory differs")
    verified = []
    with zipfile.ZipFile(FIXTURES / 'native-cases.zip') as archive:
        if len(archive.namelist()) != len(expected) or set(archive.namelist()) != set(expected):
            raise ValueError("Native platform archive membership differs")
        for member in archive.infolist():
            name = member.filename
            parts = PurePosixPath(name).parts
            if ('\\' in name or ':' in name or name.startswith('/') or '..' in parts or
                    member.flag_bits & 1 or member.file_size > 4 * 1024 * 1024 or
                    (member.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("Unsafe native platform member")
            row = expected[name]
            raw = archive.read(member)
            if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError("Native platform member changed")
            verified.append((name, raw))
    destination.mkdir(parents=True)
    for name, raw in verified:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return manifest


def inventory(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(root).rglob('*')) if p.is_file()}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--out',required=True)
    args = parser.parse_args()
    manifest = extract_sources(args.out)
    print(json.dumps(dict(files=len(manifest['sources']), fixture_manifest_sha256=MANIFEST_SHA256)))
