"""Pinned independent Java wire bytes in own native SQLite test sources.

No recovery implementation is imported. No golden TL serialization is synthesized.
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

BUNDLE = Path(__file__).resolve().parent / 'fixtures/telegram-document-descriptor'
COMMIT = '4de548e79fed27f1a66fbdff84223321838fe925'
MANIFEST_SHA256 = '8b2d3c7b6fe1f259607ef18987bcd51625412aad9a59c747f72980b212f712f7'
CANONICAL = {'oracle.json.gz', 'oracle-sources.tar.gz', 'LICENSE'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(folder):
    return {p.relative_to(folder).as_posix(): digest(p)
            for p in sorted(Path(folder).rglob('*')) if p.is_file()}


def load_oracle(bundle=BUNDLE):
    """Verify frozen oracle; never extract or execute its source archive."""
    bundle = Path(bundle)
    if digest(bundle / 'manifest.json') != MANIFEST_SHA256:
        raise ValueError('Changed independent descriptor manifest')
    manifest = json.loads((bundle / 'manifest.json').read_text(encoding='utf8'))
    if (manifest['schema'], manifest['telegram_commit'], manifest['positive_cases'],
            manifest['mutation_controls']) != (1, COMMIT, 21, 42):
        raise ValueError('Unsupported independent descriptor oracle')
    if {item['path'] for item in manifest['files']} != CANONICAL or len(manifest['files']) != 3:
        raise ValueError('Unexpected independent descriptor payload inventory')
    for item in manifest['files']:
        path = bundle / item['path']
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Changed independent descriptor payload')
    with gzip.open(bundle / 'oracle.json.gz', 'rb') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if (len(raw) > 2 * 1024 * 1024 or len(raw) != manifest['uncompressed_json_bytes'] or
            hashlib.sha256(raw).hexdigest() != manifest['uncompressed_json_sha256']):
        raise ValueError('Invalid independent descriptor payload size/hash')
    oracle = json.loads(raw)
    if (oracle['schema'], oracle['commit'], len(oracle['positive_cases']),
            len(oracle['mutation_controls'])) != (1, COMMIT, 21, 42):
        raise ValueError('Incomplete independent descriptor payload')
    if hashlib.sha256(oracle['sql_schema'].encode('utf8')).hexdigest() != manifest['native_sql_schema_sha256']:
        raise ValueError('Changed official native SQLite schema')
    names = set()
    for case in oracle['positive_cases'] + oracle['mutation_controls']:
        if not re.fullmatch(r'[a-z0-9-]{1,80}', case['name']) or case['name'] in names:
            raise ValueError('Invalid or duplicate independent descriptor name')
        names.add(case['name'])
        blob = base64.b64decode(case['blob_base64'], validate=True)
        boundary = case['tl_bytes']
        if (len(blob) != case['bytes'] or hashlib.sha256(blob).hexdigest() != case['blob_sha256'] or
                not 0 < boundary <= len(blob) or hashlib.sha256(blob[:boundary]).hexdigest() != case['tl_body_sha256']):
            raise ValueError('Changed independent native descriptor body')
    return oracle


def load_cases(bundle=BUNDLE):
    oracle = load_oracle(bundle)
    for row in oracle['positive_cases']:
        case = dict(row)
        case['blob'] = base64.b64decode(case['blob_base64'], validate=True)
        case['sql_schema'] = oracle['sql_schema']
        yield case


def load_controls(bundle=BUNDLE):
    oracle = load_oracle(bundle)
    parents = {row['name']: row for row in oracle['positive_cases']}
    for row in oracle['mutation_controls']:
        case = dict(parents[row['parent']])
        case.update(row)
        case['blob'] = base64.b64decode(case['blob_base64'], validate=True)
        case['sql_schema'] = oracle['sql_schema']
        yield case


def expected_parts(case):
    if case.get('expected_native_parts') == 0:
        return
    text, caption = case['expected']['text'], case['expected_legacy_caption']
    if text:
        yield dict(text=text, text_field='message', supplemental=False)
    if caption and caption != text:
        yield dict(text=caption, text_field='media.legacy_caption', supplemental=bool(text))


def create(destination, case, variant='current', *, sql_overrides=None, blob=None):
    """Create own new DB/WAL/SHM source; refuse existing destinations.

    history/residual preserve committed-before-delete native SQLite bytes. A body
    surviving physically is not itself authenticated history or a deletion claim.
    media-cache creates photo-type=0 as a negative document attribution control.
    """
    if variant not in {'current', 'history', 'residual', 'media-cache'}:
        raise ValueError('Unknown descriptor source variant')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    target = destination / 'cache4.db'
    values = dict(case['exact_sql'])
    values.update(sql_overrides or {})
    historical = variant in {'history', 'residual'}
    with tempfile.TemporaryDirectory(prefix='owned-descriptor-sqlite-', dir=destination.parent) as tmp:
        source = Path(tmp) / 'cache4.db'
        con = sqlite3.connect(source)
        try:
            con.execute('PRAGMA page_size=4096')
            con.execute('PRAGMA secure_delete=' + ('OFF' if variant == 'residual' else 'ON'))
            if historical:
                con.execute('PRAGMA journal_mode=WAL')
                con.execute('PRAGMA wal_autocheckpoint=0')
            data = case['blob'] if blob is None else blob
            if variant == 'media-cache':
                con.execute('CREATE TABLE media_v4(mid INTEGER,uid INTEGER,date INTEGER,type INTEGER,data BLOB,PRIMARY KEY(mid,uid,type))')
                con.execute('INSERT INTO media_v4 VALUES(?,?,?,?,?)',
                            (values['mid'], values['uid'], values['date'], 0, data))
            else:
                con.execute(case['sql_schema'])
                if variant == 'residual':
                    for mid in (39, 40, 42, 43):
                        con.execute('INSERT INTO messages_v2(mid,uid,date,data) VALUES(?,?,?,?)',
                                    (mid, values['uid'], values['date'], b'owned non-TL descriptor filler ' * 20))
                out = int(case.get('expected', {}).get('out', False))
                con.execute('INSERT INTO messages_v2(mid,uid,read_state,send_state,date,data,out,ttl,media) VALUES(?,?,?,?,?,?,?,?,?)',
                            (values['mid'], values['uid'], 0, 0, values['date'], data, out, 0, 0))
            con.commit()
            if historical:
                con.execute('DELETE FROM messages_v2 WHERE mid=? AND uid=?', (values['mid'], values['uid']))
                con.commit()
            if con.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ValueError('Native SQLite writer structural check failed')
            for suffix in ('', '-wal', '-shm'):
                file = Path(str(source) + suffix)
                if file.is_file():
                    shutil.copyfile(file, Path(str(target) + suffix))
        finally:
            con.close()
    golden = {k: v for k, v in case.items() if k not in {'blob', 'sql_schema'}}
    golden.update(variant=variant, source_files=inventory(destination), native_sqlite_writer=True,
                  sqlite_version=sqlite3.sqlite_version, expected_parts=list(expected_parts(case)), sql=values,
                  native_blob_sha256=hashlib.sha256(data).hexdigest() if isinstance(data, bytes) else None,
                  data_storage_type='blob' if isinstance(data, bytes) else 'text' if isinstance(data, str) else 'other')
    (destination / 'golden.json').write_text(json.dumps(golden, ensure_ascii=False, indent=2) + '\n', encoding='utf8', newline='\n')
    return target, golden
