"""Fresh native SQLite inputs for the packaged DocumentEmpty acceptance test.

Wire bytes and expected fields are loaded from the pinned official Java oracle.
No recovery module is imported and no TL body is synthesized here.
"""
from pathlib import Path
import json
import shutil
import sqlite3
import tempfile

from build_telegram_document_empty_fixtures import (
    BUNDLE, COMMIT, create, digest, expected_parts, load_cases,
)

FACTORY_SHA256 = '3936357e1a2dee4e4fe9bd7d7c422b35f6cea0724dc7a0df7da93b396b2da205'


def files(destination):
    result = {}
    for path in sorted(destination.rglob('*')):
        if path.is_symlink():
            raise ValueError('Fixture link is not permitted')
        if path.is_file() and path != destination / 'manifest.json':
            result[path.relative_to(destination).as_posix()] = dict(
                bytes=path.stat().st_size, sha256=digest(path))
    return result


def version_case(destination, before, after):
    """Native WAL commits differing only in an official document-reference ID."""
    destination.mkdir(parents=True, exist_ok=False)
    sql = before['exact_sql']
    if sql != after['exact_sql'] or before['expected'] != after['expected']:
        raise ValueError('Version controls must have exactly equal SQL and text')
    with tempfile.TemporaryDirectory(prefix='owned-document-versions-') as tmp:
        source = Path(tmp) / 'cache4.db'
        con = sqlite3.connect(source)
        try:
            con.execute('PRAGMA page_size=4096')
            con.execute('PRAGMA secure_delete=ON')
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('PRAGMA wal_autocheckpoint=0')
            con.execute(before['sql_schema'])
            con.execute('INSERT INTO messages_v2(mid,uid,read_state,send_state,date,data,out,ttl,media) VALUES(?,?,?,?,?,?,?,?,?)',
                (sql['mid'], sql['uid'], 0, 0, sql['date'], before['blob'], int(before['expected']['out']), 0, 0))
            con.commit()
            con.execute('UPDATE messages_v2 SET data=? WHERE mid=? AND uid=?',
                        (after['blob'], sql['mid'], sql['uid']))
            con.commit()
            if con.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ValueError('Native version database is corrupt')
            for suffix in ('', '-wal', '-shm'):
                shutil.copyfile(Path(str(source) + suffix), destination / ('cache4.db' + suffix))
        finally:
            con.close()
    return dict(database='versions/cache4.db', oracle_names=['id0', 'id1'],
                source_files={p.name: digest(p) for p in sorted(destination.iterdir())})


def build(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    official = list(load_cases())
    by_name = {case['name']: case for case in official}

    def entry(name, case, category, variant='current', overrides=None):
        database, golden = create(destination / category / name, case, variant,
                                  sql_overrides=overrides)
        return dict(name=name, oracle_name=case['name'], variant=variant,
            database=database.relative_to(destination).as_posix(),
            source_files=golden['source_files'], exact_sql=case['exact_sql'],
            source_sql=golden['sql'], text_parts=list(expected_parts(case)),
            layer=case['layer'], constructor=case['constructor'],
            tl_body_sha256=case['tl_body_sha256'])

    cases = [entry(case['name'], case, 'current') for case in official]
    base = by_name['layer118-flags3']
    snapshots = [entry(variant, base, 'snapshots', variant)
                 for variant in ('history', 'residual')]
    controls = [
        entry('bad-mid', base, 'controls', overrides={'mid': 42}),
        entry('bad-date', base, 'controls', overrides={'date': 1790000001}),
        entry('bad-uid', base, 'controls', overrides={'uid': 909}),
        entry('photo-only-cache', base, 'controls', 'media-cache'),
    ]
    versions = version_case(destination / 'versions', by_name['id0'], by_name['id1'])
    factory = Path(__file__).with_name('build_telegram_document_empty_fixtures.py')
    if digest(factory) != FACTORY_SHA256:
        raise ValueError('Changed frozen independent source factory')
    manifest = dict(schema=1, source_commit=COMMIT,
        generator_sha256=digest(Path(__file__)),
        source_factory_sha256=FACTORY_SHA256,
        oracle_manifest_sha256=digest(BUNDLE / 'manifest.json'),
        cases=cases, snapshot_cases=snapshots, controls=controls,
        version_case=versions, files=files(destination))
    (destination / 'manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    return dict(cases=len(cases), snapshot_cases=len(snapshots), controls=len(controls), versions=1,
        expected_text_records=sum(len(case['text_parts']) for case in cases))


def verify(destination):
    """Verify an existing complete fixture set; never repair or overwrite it."""
    destination = Path(destination)
    manifest = json.loads((destination / 'manifest.json').read_text(encoding='utf8'))
    cases = {case['name']: case for case in load_cases()}
    factory = Path(__file__).with_name('build_telegram_document_empty_fixtures.py')
    if (manifest['schema'] != 1 or manifest['source_commit'] != COMMIT or
            manifest['generator_sha256'] != digest(Path(__file__)) or
            manifest['source_factory_sha256'] != FACTORY_SHA256 or digest(factory) != FACTORY_SHA256 or
            manifest['oracle_manifest_sha256'] != digest(BUNDLE / 'manifest.json') or
            manifest['files'] != files(destination)):
        raise ValueError('Changed/stale/incomplete portable fixture set')
    expected_files = set()

    def check(item, category, name, oracle_name, variant, overrides=None):
        case = cases[oracle_name]
        folder = category + '/' + name
        expected = dict(name=name, oracle_name=oracle_name, variant=variant,
            database=folder + '/cache4.db', source_files=item['source_files'],
            exact_sql=case['exact_sql'], source_sql={**case['exact_sql'], **(overrides or {})},
            text_parts=list(expected_parts(case)), layer=case['layer'],
            constructor=case['constructor'], tl_body_sha256=case['tl_body_sha256'])
        if item != expected:
            raise ValueError('Changed independent expected case binding')
        members = {'cache4.db', 'golden.json'}
        if variant in {'history', 'residual'}:
            members.update({'cache4.db-wal', 'cache4.db-shm'})
        if set(item['source_files']) != members - {'golden.json'}:
            raise ValueError('Changed native source fileset')
        for member, sha in item['source_files'].items():
            if digest(destination / folder / member) != sha:
                raise ValueError('Changed native source hash')
        expected_files.update(folder + '/' + member for member in members)

    current = manifest['cases']
    if len(current) != 167 or {item['name'] for item in current} != set(cases):
        raise ValueError('Incomplete current case set')
    for item in current:
        check(item, 'current', item['name'], item['name'], 'current')
    snapshots = manifest['snapshot_cases']
    if len(snapshots) != 2 or {item['name'] for item in snapshots} != {'history', 'residual'}:
        raise ValueError('Incomplete WAL case set')
    for item in snapshots:
        check(item, 'snapshots', item['name'], 'layer118-flags3', item['name'])
    controls = manifest['controls']
    invalid = {'bad-mid': {'mid': 42}, 'bad-date': {'date': 1790000001},
               'bad-uid': {'uid': 909}, 'photo-only-cache': {}}
    if len(controls) != 4 or {item['name'] for item in controls} != set(invalid):
        raise ValueError('Incomplete rejection control set')
    for item in controls:
        name = item['name']
        check(item, 'controls', name, 'layer118-flags3',
              'media-cache' if name == 'photo-only-cache' else 'current', invalid[name])
    version = manifest['version_case']
    if (set(version) != {'database', 'oracle_names', 'source_files'} or
            version['database'] != 'versions/cache4.db' or version['oracle_names'] != ['id0', 'id1'] or
            set(version['source_files']) != {'cache4.db', 'cache4.db-wal', 'cache4.db-shm'}):
        raise ValueError('Changed same-account version control')
    for member, sha in version['source_files'].items():
        if digest(destination / 'versions' / member) != sha:
            raise ValueError('Changed version source bytes')
        expected_files.add('versions/' + member)
    if set(manifest['files']) != expected_files:
        raise ValueError('Unexpected or absent fixture payload file')
    return dict(status='verified', files=len(expected_files), cases=167,
                snapshot_cases=2, controls=4, versions=1)


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == '--verify':
        result = verify(sys.argv[2])
    elif len(sys.argv) == 2:
        result = build(sys.argv[1])
    else:
        raise SystemExit('Expected <fresh destination> or --verify <existing destination>')
    print(json.dumps(result))
