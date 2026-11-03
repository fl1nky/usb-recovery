"""Load independent Java/SQLite inputs without importing the recovery reader."""
from pathlib import Path, PurePosixPath
import base64
import gzip
import hashlib
import io
import json
import zipfile

FIXTURES = Path(__file__).resolve().parent / 'fixtures/telegram-document-attributes'
MANIFEST_SHA = '73e02a818c974582952ee3b07c3b0c8db37d8d2abb105644bb4a893714711fee'


def load_oracle():
    manifest_bytes = (FIXTURES / 'manifest.json').read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != MANIFEST_SHA:
        raise ValueError('Independent attributes manifest changed')
    manifest = json.loads(manifest_bytes)
    for row in manifest['files']:
        raw = (FIXTURES / row['path']).read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('Independent attributes payload changed')
    with gzip.GzipFile(fileobj=io.BytesIO((FIXTURES / 'oracle.json.gz').read_bytes())) as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) != manifest['uncompressed_json_bytes'] or hashlib.sha256(raw).hexdigest() != manifest['uncompressed_json_sha256']:
        raise ValueError('Independent attributes JSON changed or exceeded limit')
    return json.loads(raw)


def load_cases(*, controls=False):
    oracle = load_oracle()
    for original in oracle['mutation_controls' if controls else 'positive_cases']:
        row = dict(original)
        row['sql_schema'] = oracle['sql_schema']
        row['blob'] = base64.b64decode(row['blob_base64'], validate=True)
        if len(row['blob']) != row['bytes'] or hashlib.sha256(row['blob']).hexdigest() != row['blob_sha256']:
            raise ValueError('Independent native BLOB changed')
        if not controls:
            row['document_id'] = int(row['document_id'])
            row['document_kind'] = 'descriptor'
            row['expected_legacy_caption'] = ''
            row['expected'] = dict(row['expected'], layer=232, constructor='0x7600b9d3')
        yield row


def extract_sources(target):
    """Copy exactly 202 declared native DBs, preserving existing destinations."""
    target = Path(target)
    if target.exists():
        raise ValueError('Preserve existing source inputs')
    oracle = load_oracle()
    expected = {row['path']: row for row in oracle['sqlite_sources']}
    if len(expected) != 202 or sum(row['bytes'] for row in expected.values()) > 16 * 1024 * 1024:
        raise ValueError('Unexpected native source inventory')
    with zipfile.ZipFile(FIXTURES / 'native-sqlite-cases.zip') as archive:
        names = archive.namelist()
        if len(names) != len(expected) or set(names) != set(expected):
            raise ValueError('Native source archive membership differs')
        verified = []
        for entry in archive.infolist():
            name = entry.filename
            parts = PurePosixPath(name).parts
            if '\\' in name or ':' in name or name.startswith('/') or len(parts) != 2 or '..' in parts or parts[-1] != 'cache4.db':
                raise ValueError('Unsafe native source member')
            row = expected[name]
            if entry.flag_bits & 1 or entry.file_size != row['bytes'] or entry.file_size > 4 * 1024 * 1024 or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Unsafe native source size or type')
            raw = archive.read(entry)
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('Native source member SHA differs')
            verified.append((row, raw))
    target.mkdir(parents=True)
    result = {}
    for row, raw in verified:
        path = target / row['path']
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
        result[row['case']] = path
    return result
