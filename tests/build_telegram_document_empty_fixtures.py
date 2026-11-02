"""Pinned official-Java wire bytes, copied into native SQLite test sources.

No recovery parser is imported and no TL body is synthesized by this factory.
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

BUNDLE = Path(__file__).resolve().parent / 'fixtures/telegram-document-empty'
COMMIT = '4de548e79fed27f1a66fbdff84223321838fe925'
MANIFEST_SHA256 = 'd73a082ea9484dc168fe55d8e9b2db5ad4f31c696ccd4d44b96838ac8fcbbf1f'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(folder):
    return {p.relative_to(folder).as_posix(): digest(p) for p in sorted(Path(folder).rglob('*')) if p.is_file()}


def load_cases(bundle=BUNDLE):
    bundle = Path(bundle)
    if digest(bundle / 'manifest.json') != MANIFEST_SHA256:
        raise ValueError('Changed independent document fixture manifest')
    manifest = json.loads((bundle / 'manifest.json').read_text(encoding='utf8'))
    if (manifest['schema'], manifest['cases'], manifest['telegram_commit']) != (1, 167, COMMIT):
        raise ValueError('Unsupported independent document fixture')
    for item in manifest['files']:
        if item['path'] not in {'oracle.json.gz', 'oracle-sources.tar.gz', 'LICENSE'}:
            raise ValueError('Invalid independent fixture file')
        path = bundle / item['path']
        if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Changed independent document fixture bytes')
    with gzip.open(bundle / 'oracle.json.gz', 'rb') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024 or len(raw) != manifest['uncompressed_json_bytes']:
        raise ValueError('Invalid independent fixture size')
    payload = json.loads(raw)
    if payload['commit'] != COMMIT or len(payload['cases']) != 167:
        raise ValueError('Incomplete independent document fixture')
    names = set()
    for row in payload['cases']:
        case = dict(row)
        if not re.fullmatch(r'[a-z0-9-]{1,80}', case['name']) or case['name'] in names:
            raise ValueError('Invalid independent fixture name')
        names.add(case['name'])
        blob = base64.b64decode(case.pop('blob_base64'), validate=True)
        boundary = case['tl_bytes']
        if (len(blob) != case['bytes'] or hashlib.sha256(blob).hexdigest() != case['blob_sha256'] or
                not 0 < boundary <= len(blob) or hashlib.sha256(blob[:boundary]).hexdigest() != case['tl_body_sha256']):
            raise ValueError('Changed independent serialized document')
        case.update(blob=blob, sql_schema=payload['sql_schema'])
        yield case


def expected_parts(case):
    text, caption = case['expected']['text'], case['expected_legacy_caption']
    if text:
        yield dict(text=text, text_field='message', supplemental=False)
    if caption and caption != text:
        yield dict(text=caption, text_field='media.legacy_caption', supplemental=bool(text))


def create(destination, case, variant='current', *, sql_overrides=None, blob=None):
    """Create a new source; do not update or replay any existing evidence."""
    if variant not in {'current', 'history', 'residual', 'media-cache'}:
        raise ValueError('Unknown document source variant')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    target = destination / 'cache4.db'
    values = dict(case['exact_sql'])
    values.update(sql_overrides or {})
    historical = variant in {'history', 'residual'}
    with tempfile.TemporaryDirectory(prefix='owned-document-sqlite-writer-') as tmp:
        source = Path(tmp) / 'cache4.db'
        con = sqlite3.connect(source)
        try:
            con.execute('PRAGMA page_size=4096')
            con.execute('PRAGMA secure_delete=' + ('OFF' if variant == 'residual' else 'ON'))
            if historical:
                con.execute('PRAGMA journal_mode=WAL')
                con.execute('PRAGMA wal_autocheckpoint=0')
            if variant == 'media-cache':
                con.execute('CREATE TABLE media_v4(mid INTEGER,uid INTEGER,date INTEGER,type INTEGER,data BLOB,PRIMARY KEY(mid,uid,type))')
                con.execute('INSERT INTO media_v4 VALUES(?,?,?,?,?)',
                    (values['mid'], values['uid'], values['date'], 0, case['blob'] if blob is None else blob))
            else:
                con.execute(case['sql_schema'])
                if variant == 'residual':
                    for mid in (39, 40, 42, 43):
                        con.execute('INSERT INTO messages_v2(mid,uid,date,data) VALUES(?,?,?,?)',
                            (mid, values['uid'], values['date'], b'owned non-TL document filler ' * 20))
                con.execute('INSERT INTO messages_v2(mid,uid,read_state,send_state,date,data,out,ttl,media) VALUES(?,?,?,?,?,?,?,?,?)',
                    (values['mid'], values['uid'], 0, 0, values['date'], case['blob'] if blob is None else blob,
                     int(case['expected']['out']), 0, 0))
            con.commit()
            if historical:
                con.execute('DELETE FROM messages_v2 WHERE mid=? AND uid=?', (values['mid'], values['uid']))
                con.commit()
            assert con.execute('PRAGMA quick_check').fetchall() == [('ok',)]
            for suffix in ('', '-wal', '-shm'):
                file = Path(str(source) + suffix)
                if file.is_file():
                    shutil.copyfile(file, Path(str(target) + suffix))
        finally:
            con.close()
    golden = {k: v for k, v in case.items() if k not in {'blob', 'sql_schema'}}
    golden.update(variant=variant, source_files=inventory(destination), native_sqlite_writer=True,
        sqlite_version=sqlite3.sqlite_version, expected_parts=list(expected_parts(case)), sql=values)
    (destination / 'golden.json').write_text(json.dumps(golden, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    return target, golden
