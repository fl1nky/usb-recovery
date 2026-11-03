"""Load independent official Java BLOBs and make fresh native SQLite copies.

No recovery module is imported. The existing source factory writes SQLite using
the supplied exact SQL schema and complete oracle BLOB; it never serializes TL.
"""
from pathlib import Path
import base64
import gzip
import hashlib
import json
import re
import shutil
import sqlite3
import tempfile

from build_telegram_document_empty_fixtures import create as _create, inventory, expected_parts as _parts

BUNDLE = Path(__file__).resolve().parent / 'fixtures/telegram-document-descriptor'
COMMIT = '4de548e79fed27f1a66fbdff84223321838fe925'
MANIFEST_SHA256 = '8b2d3c7b6fe1f259607ef18987bcd51625412aad9a59c747f72980b212f712f7'
FACTORY_SHA256 = '3936357e1a2dee4e4fe9bd7d7c422b35f6cea0724dc7a0df7da93b396b2da205'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def expected_parts(case):
    if case.get('expected_native_parts') == 0:
        return
    yield from _parts(case)


def create(destination, case, variant='current', *, sql_overrides=None, blob=None):
    # The pinned writer always creates a fresh directory and never serializes
    # TL. Its legacy golden format predates explicit invalid-case outcomes.
    database, golden = _create(destination, case, variant, sql_overrides=sql_overrides, blob=blob)
    golden['expected_parts'] = list(expected_parts(case))
    (Path(destination) / 'golden.json').write_text(
        json.dumps(golden, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return database, golden


def payload(bundle=BUNDLE):
    bundle = Path(bundle)
    if not MANIFEST_SHA256 or digest(bundle / 'manifest.json') != MANIFEST_SHA256:
        raise ValueError('Changed/unaccepted native document descriptor oracle')
    factory = Path(__file__).with_name('build_telegram_document_empty_fixtures.py')
    if digest(factory) != FACTORY_SHA256:
        raise ValueError('Changed native SQLite source factory')
    manifest = json.loads((bundle / 'manifest.json').read_text('utf-8-sig'))
    if (manifest['schema'], manifest['telegram_commit'], manifest['positive_cases'], manifest['mutation_controls']) != (1, COMMIT, 21, 42):
        raise ValueError('Unexpected independent oracle profile')
    if {item['path'] for item in manifest['files']} != {'oracle.json.gz', 'oracle-sources.tar.gz', 'LICENSE'}:
        raise ValueError('Incomplete native oracle payload')
    for item in manifest['files']:
        if item['path'] not in {'oracle.json.gz', 'oracle-sources.tar.gz', 'LICENSE'}:
            raise ValueError('Unexpected native oracle payload')
        path = bundle / item['path']
        if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Changed native oracle bytes')
    with gzip.open(bundle / 'oracle.json.gz', 'rb') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if (len(raw) > 2 * 1024 * 1024 or len(raw) != manifest['uncompressed_json_bytes'] or
            hashlib.sha256(raw).hexdigest() != manifest['uncompressed_json_sha256']):
        raise ValueError('Native oracle payload limit')
    result = json.loads(raw)
    if (result['commit'] != COMMIT or len(result['positive_cases']) != 21 or len(result['mutation_controls']) != 42 or
            hashlib.sha256(result['sql_schema'].encode('utf-8')).hexdigest() != manifest['native_sql_schema_sha256']):
        raise ValueError('Unexpected official source commit')
    return result


def load_cases(*, controls=False, bundle=BUNDLE):
    data = payload(bundle)
    rows = data['mutation_controls'] if controls else data['positive_cases']
    parents = {row['name']: row for row in data['positive_cases']}
    names = set()
    for row in rows:
        if controls:
            parent = parents[row['parent']]
            if row['native_parent_blob_sha256'] != parent['blob_sha256']:
                raise ValueError('Changed mutation-parent binding')
            case = {**parent, **row}
        else:
            case = dict(row)
        name = case['name']
        if not re.fullmatch(r'[a-z0-9-]{1,80}', name) or name in names:
            raise ValueError('Invalid oracle case name')
        names.add(name)
        blob = base64.b64decode(case.pop('blob_base64'), validate=True)
        boundary = case['tl_bytes']
        if (len(blob) != case['bytes'] or hashlib.sha256(blob).hexdigest() != case['blob_sha256'] or
                type(boundary) is not int or not 0 < boundary <= len(blob) or
                hashlib.sha256(blob[:boundary]).hexdigest() != case['tl_body_sha256']):
            raise ValueError('Changed independent document BLOB')
        case.update(blob=blob, sql_schema=data['sql_schema'])
        if case['document_id'] is not None:
            case['document_id'] = int(case['document_id'])
        yield case


def create_versions(destination, before, after):
    """Write two real SQLite commits with distinct independently made BLOBs."""
    if before['exact_sql'] != after['exact_sql'] or before['expected'] != after['expected']:
        raise ValueError('Version controls need equal exact SQL and message fields')
    if before['tl_body_sha256'] == after['tl_body_sha256']:
        raise ValueError('Version controls must differ in the complete native body')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    values = before['exact_sql']
    with tempfile.TemporaryDirectory(prefix='owned-descriptor-version-writer-') as tmp:
        source = Path(tmp) / 'cache4.db'
        con = sqlite3.connect(source)
        try:
            con.execute('PRAGMA page_size=4096')
            con.execute('PRAGMA secure_delete=ON')
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('PRAGMA wal_autocheckpoint=0')
            con.execute(before['sql_schema'])
            con.execute('INSERT INTO messages_v2(mid,uid,date,data) VALUES(?,?,?,?)',
                        (values['mid'], values['uid'], values['date'], before['blob']))
            con.commit()
            con.execute('UPDATE messages_v2 SET data=? WHERE mid=? AND uid=?',
                        (after['blob'], values['mid'], values['uid']))
            con.commit()
            if con.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ValueError('Native WAL control is invalid')
            for suffix in ('', '-wal', '-shm'):
                shutil.copyfile(Path(str(source) + suffix), destination / ('cache4.db' + suffix))
        finally:
            con.close()
    return destination / 'cache4.db'
