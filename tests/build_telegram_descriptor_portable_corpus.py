"""Freeze native SQLite inputs for the no-Python packaged acceptance suite.

Wire bytes and expected fields come from the pinned official Java corpus.
This producer imports no recovery module and refuses existing destinations.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sqlite3
import zipfile

from build_telegram_document_descriptor_fixtures import (
    BUNDLE, COMMIT, MANIFEST_SHA256, FACTORY_SHA256,
    create, create_versions, digest, expected_parts, load_cases,
)


def build(work, destination):
    work, destination = Path(work), Path(destination)
    if work.exists() or destination.exists():
        raise ValueError('Fresh owned corpus and source directories required')
    work.mkdir(parents=True, exist_ok=False)
    destination.mkdir(parents=True, exist_ok=False)
    positives, controls = list(load_cases()), list(load_cases(controls=True))
    by_name = {case['name']: case for case in positives}
    cases, sources = [], {}

    def capture(folder):
        for name in ('cache4.db', 'cache4.db-wal', 'cache4.db-shm'):
            path = folder / name
            if path.is_file():
                relative = path.relative_to(work).as_posix()
                sources[relative] = dict(bytes=path.stat().st_size, sha256=digest(path))

    def entry(case, category, variant='current'):
        folder = work / category / case['name']
        database, golden = create(folder, case, variant)
        assert golden['expected_parts'] == list(expected_parts(case))
        capture(folder)
        cases.append(dict(name=case['name'], category=category, variant=variant,
                          database=database.relative_to(work).as_posix(),
                          oracle_name=case.get('parent', case['name']), control_name=case['name'] if category == 'controls' else None))

    for case in positives:
        entry(case, 'current')
    for case in controls:
        entry(case, 'controls')
    base = by_name['descriptor-filename']
    for variant in ('history', 'residual'):
        entry(base, variant, variant)
    before, after = by_name['descriptor-id-zero'], by_name['descriptor-id-negative']
    version_db = create_versions(work / 'versions', before, after)
    capture(version_db.parent)
    cases.append(dict(name='versions', category='versions', variant='versions', database='versions/cache4.db',
                      oracle_names=[before['name'], after['name']]))
    archive = destination / 'native-cases.zip'
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for relative in sorted(sources):
            info = zipfile.ZipInfo(relative, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, (work / relative).read_bytes())
    with zipfile.ZipFile(archive) as source:
        assert source.testzip() is None and set(source.namelist()) == set(sources)
        for relative, row in sources.items():
            raw = source.read(relative)
            assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    manifest = dict(schema=1, scope='Owned native SQLite only; no recovery run, no devices',
                    telegram_commit=COMMIT, oracle_manifest_sha256=MANIFEST_SHA256,
                    generator_sha256=digest(Path(__file__)),
                    source_factory_sha256=digest(Path(__file__).with_name('build_telegram_document_descriptor_fixtures.py')),
                    original_sqlite_factory_sha256=FACTORY_SHA256, sqlite_version=sqlite3.sqlite_version,
                    archive=dict(path='native-cases.zip', bytes=archive.stat().st_size, sha256=digest(archive)),
                    cases=cases, files=sources)
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status='PASS', cases=len(cases), files=len(sources),
                         manifest_sha256=digest(destination / 'manifest.json'), archive_sha256=digest(archive))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('work')
    parser.add_argument('destination')
    args = parser.parse_args()
    build(args.work, args.destination)
