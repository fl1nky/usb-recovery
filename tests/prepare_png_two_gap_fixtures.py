"""Fresh or fully verified native PNG three-run fixtures, without recovery code."""
from pathlib import Path
import json

from prepare_photo_telegram_fixtures import ROOT, BUILD, inventory, plain, require, sha
from build_png_two_gap_fixtures import CASE_NAMES, build


def prepare():
    target = plain(BUILD / 'png-two-gap-fixtures-current')
    marker = plain(BUILD / 'png-two-gap-fixtures-current.prepared.json')
    sources = {name: sha(ROOT / name) for name in (
        'tests/build_png_two_gap_fixtures.py', 'tests/build_png_idat_gap_fixtures.py',
        'tests/prepare_png_two_gap_fixtures.py')}
    if target.exists():
        require(marker.is_file(), 'Unrecorded PNG two-gap cache; preserve it before preparing a fresh destination')
        previous = json.loads(marker.read_text(encoding='utf-8'))
        require(previous.get('schema') == 1 and previous.get('sources') == sources,
                'Changed PNG fixture sources; the existing cache was preserved')
        require(previous.get('files') == inventory(target), 'Changed PNG fixture bytes; existing evidence was preserved')
    else:
        require(not marker.exists(), 'Orphaned PNG fixture receipt; preserve existing evidence')
        build(target)
        require(all(sha(ROOT / name) == digest for name, digest in sources.items()),
                'PNG fixture source changed during preparation')
    manifest = json.loads((target / 'manifest.json').read_text(encoding='utf-8'))
    cases = manifest.get('Cases', [])
    require(manifest.get('Schema') == 1 and manifest.get('IndependentEncoder') is True and
            manifest.get('GeneratorSha256') == sources['tests/build_png_two_gap_fixtures.py'] and
            len(cases) == len(CASE_NAMES) == 20 and {case['Name'] for case in cases} == set(CASE_NAMES),
            'Incomplete independent PNG three-run corpus')
    for case in cases:
        folder = target / case['Name']
        require(case == dict(json.loads((folder / 'golden.json').read_text(encoding='utf-8')),
                             Image=(case['Name'] + '/image.dd')), 'PNG fixture expectations changed')
        require(sha(folder / 'image.dd') == case['SourceSha256'] and
                sha(folder / 'original.png') == case['Sha256'], 'PNG source or original oracle changed')
    if not marker.exists():
        with marker.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(dict(schema=1, sources=sources, files=inventory(target)), stream, indent=2)
            stream.write('\n')
    print(json.dumps(dict(fixture='png-two-gap', status='verified', cases=len(cases))))


if __name__ == '__main__':
    BUILD.mkdir(exist_ok=True)
    prepare()
