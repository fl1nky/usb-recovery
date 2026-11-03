"""Load independently serialized native media-only inputs; no reader imports.

The frozen oracle records zero/nonzero text slots, not a product retention
policy. Product expectations live separately in telegram_media_retention_policy.
"""
from pathlib import Path, PurePosixPath
import base64
import gzip
import hashlib
import io
import json
import zipfile

FIXTURES = Path(__file__).resolve().parent / 'fixtures/telegram-media-only'
MANIFEST_SHA256 = '947bde089ecc7187f66e511cc907fa101f91c8b7c5dd2488fe16aeb05cdfe26c'


def load_oracle():
    raw_manifest = (FIXTURES / 'manifest.json').read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != MANIFEST_SHA256:
        raise ValueError('Independent media-only manifest changed')
    manifest = json.loads(raw_manifest)
    for row in manifest['files']:
        raw = (FIXTURES / row['path']).read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('Independent media-only payload changed')
    with gzip.GzipFile(fileobj=io.BytesIO((FIXTURES / 'oracle.json.gz').read_bytes())) as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) != manifest['uncompressed_json_bytes'] or hashlib.sha256(raw).hexdigest() != manifest['uncompressed_json_sha256']:
        raise ValueError('Independent media-only JSON changed or exceeded limit')
    return json.loads(raw)


def load_cases(*, controls=False):
    oracle = load_oracle()
    for original in oracle['mutation_controls' if controls else 'positive_cases']:
        row = dict(original)
        row['sql_schema'] = oracle['sql_schema']
        row['blob'] = base64.b64decode(row['blob_base64'], validate=True)
        if len(row['blob']) != row['bytes'] or hashlib.sha256(row['blob']).hexdigest() != row['blob_sha256']:
            raise ValueError('Independent native media-only BLOB changed')
        if not controls:
            row['document_id'] = int(row['document_id'])
            row['expected_legacy_caption'] = ''
        yield row


def extract_sources(target):
    """Copy exactly 70 declared native DBs without replacing destinations."""
    target = Path(target)
    if target.exists():
        raise ValueError('Preserve existing source inputs')
    expected = {row['path']: row for row in load_oracle()['sqlite_sources']}
    if len(expected) != 70 or sum(row['bytes'] for row in expected.values()) > 16 * 1024 * 1024:
        raise ValueError('Unexpected native media-only source inventory')
    with zipfile.ZipFile(FIXTURES / 'native-sqlite-cases.zip') as archive:
        names = archive.namelist()
        if len(names) != len(expected) or set(names) != set(expected):
            raise ValueError('Native media-only archive membership differs')
        verified = []
        for entry in archive.infolist():
            name = entry.filename
            parts = PurePosixPath(name).parts
            if '\\' in name or ':' in name or name.startswith('/') or len(parts) != 3 or '..' in parts or parts[-1] != 'cache4.db':
                raise ValueError('Unsafe native media-only source member')
            row = expected[name]
            if entry.flag_bits & 1 or entry.file_size != row['bytes'] or entry.file_size > 4 * 1024 * 1024 or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Unsafe native media-only source size or type')
            raw = archive.read(entry)
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('Native media-only source member SHA differs')
            verified.append((row, raw))
    target.mkdir(parents=True)
    result = {}
    for row, raw in verified:
        path = target / row['path']
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
        result[row['case']] = path
    return result
