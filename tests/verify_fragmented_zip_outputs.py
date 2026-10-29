"""Verify published synthetic reconstructions with independent Python zipfile."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

root = Path(sys.argv[1]).resolve()
fixtures = json.loads((root / 'fixtures.json').read_text(encoding='utf-8'))
known_hashes = {row['sha256'] for fixture in fixtures for row in fixture['expected']}
checked = 0
for report_path in root.glob('*/fragmented-zip.json'):
    # Guard tests also deliberately create non-JSON files with the report name;
    # the pipeline test mutates output to exercise changed-file rejection
    if not any(report_path.parent.name.startswith(fixture['case'] + '-')
               for fixture in fixtures):
        continue
    report = json.loads(report_path.read_text(encoding='utf-8-sig'))
    for row in report['Files']:
        output = (report_path.parent / row['Path']).resolve()
        assert output.is_relative_to(report_path.parent.resolve())
        payload = output.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        assert digest == row['Sha256'] and digest in known_hashes
        assert len(payload) == row['Bytes']
        with zipfile.ZipFile(output) as archive:
            assert archive.testzip() is None
            assert len(archive.infolist()) == row['Members']
        checked += 1
assert checked > 0
print(f'PASS independent Python zipfile verification: {checked} published archives')
