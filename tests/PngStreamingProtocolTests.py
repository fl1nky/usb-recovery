"""Actual source helper NDJSON mode, anchored resume and safe index errors."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from build_png_two_gap_fixtures import create


class PngStreamingProtocolTests(unittest.TestCase):
    def test_actual_helper_uses_mode_and_rejects_changed_mode_or_index(self):
        with tempfile.TemporaryDirectory(prefix='owned-png-protocol-') as temporary:
            folder = Path(temporary)
            source, golden = create(folder / 'source', 'physical-order-012')
            output = folder / 'output'
            original = hashlib.sha256(source.read_bytes()).hexdigest()

            def run(options):
                request = dict(protocol=1, operation='fragmented_photos', source=str(source),
                               destination=str(output), options=options)
                result = subprocess.run([sys.executable, '-B', '-E', '-s', '-X', 'utf8',
                                         str(ROOT / 'helpers/recovery_engine/engine.py')],
                                        input=json.dumps(request) + '\n', text=True,
                                        encoding='utf-8', capture_output=True, timeout=30)
                self.assertEqual(result.stderr, '')
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual(sum(row['type'] == 'result' for row in rows), 1)
                return result, rows

            result, rows = run(dict(streaming_png=True))
            self.assertEqual((result.returncode, rows[-1]['status']), (0, 'complete'))
            report = json.loads((output / 'report.json').read_text('utf-8'))
            self.assertTrue(report['StreamingPng'])
            self.assertEqual(report['Files'][0]['Sha256'], golden['Sha256'])
            self.assertEqual(report['IndexBytes'], (source.stat().st_size // 512 + 1) * 4)
            checkpoints = [row for row in rows if row.get('phase') == 'photo_checkpoint']
            self.assertTrue(checkpoints)
            last = checkpoints[-1]
            anchor = dict(Path=last['checkpoint_path'], Sha256=last['checkpoint_sha256'],
                          Sequence=last['checkpoint_sequence'])
            self.assertEqual(hashlib.sha256(Path(anchor['Path']).read_bytes()).hexdigest(), anchor['Sha256'])
            result, rows = run(dict(resume_checkpoint=anchor))
            self.assertEqual((result.returncode, rows[-1]['status'], rows[-1]['code']),
                             (2, 'error', 'PHOTO_CHECKPOINT_BINDING_MISMATCH'))
            index = output.with_name(output.name + '.index') / 'sector-crcs.bin'
            with index.open('r+b') as target:
                target.seek(8); value = target.read(1); target.seek(8); target.write(bytes([value[0] ^ 1]))
            result, rows = run(dict(streaming_png=True, resume_checkpoint=anchor))
            self.assertEqual((result.returncode, rows[-1]['status'], rows[-1]['code']),
                             (2, 'error', 'PHOTO_CHECKPOINT_PNG_INDEX_HASH_MISMATCH'))
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
