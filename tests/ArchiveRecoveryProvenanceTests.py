"""Search must retain complete recovery maps, never truncated proof claims."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'helpers'/'recovery_engine'))
import archive_search


def record():
    return dict(app='Telegram',text='owned overflow recipe',evidence_kind='backup',
        recovery_status='deleted_supported_by_evidence',deleted=None,
        sqlite_payload_length=648,sqlite_payload_sha256=hashlib.sha256(b'a'*648).hexdigest(),
        sqlite_payload_ranges=[
            dict(logical_offset=0,bytes=140,sqlite_page=2,physical_source='db',physical_byte_offset=845,wal_frame=None),
            dict(logical_offset=140,bytes=508,sqlite_page=3,physical_source='db',physical_byte_offset=1028,wal_frame=None)],
        sqlite_overflow_pages=[3],sqlite_overflow_chain_verified=True)


class ArchiveRecoveryProvenanceTests(unittest.TestCase):
    def test_full_map_and_scalar_fields_are_preserved_without_aliasing(self):
        raw=record();normalized=archive_search._normalized(raw)
        for name in archive_search.OVERFLOW_FIELDS:
            self.assertEqual(normalized[name],raw[name])
        normalized['sqlite_payload_ranges'][0]['bytes']=1
        self.assertEqual(raw['sqlite_payload_ranges'][0]['bytes'],140)

    def test_incomplete_incoherent_and_oversized_maps_are_rejected(self):
        mutations=[
            lambda r:r.pop('sqlite_payload_sha256'),
            lambda r:r.update(sqlite_payload_length=True),
            lambda r:r.update(sqlite_payload_length=647),
            lambda r:r.update(sqlite_payload_sha256='g'*64),
            lambda r:r.update(sqlite_overflow_chain_verified=1),
            lambda r:r['sqlite_payload_ranges'][1].update(logical_offset=141),
            lambda r:r['sqlite_payload_ranges'][0].update(logical_offset=True),
            lambda r:r['sqlite_payload_ranges'][0].update(bytes=0),
            lambda r:r['sqlite_payload_ranges'][0].update(bytes=65537),
            lambda r:r['sqlite_payload_ranges'][1].update(physical_source='http'),
            lambda r:r['sqlite_payload_ranges'][1].update(physical_byte_offset=900),
            lambda r:r['sqlite_payload_ranges'][1].update(physical_byte_offset=2**32-100),
            lambda r:r['sqlite_payload_ranges'][1].update(sqlite_page=True),
            lambda r:r['sqlite_payload_ranges'][1].update(sqlite_page=2),
            lambda r:r['sqlite_payload_ranges'][1].update(wal_frame=1),
            lambda r:r['sqlite_payload_ranges'][1].update(physical_source='wal'),
            lambda r:r['sqlite_payload_ranges'][1].update(unrecognized_secret='PRIVATE_CANARY'),
            lambda r:r.update(sqlite_overflow_pages=[4]),
            lambda r:r.update(sqlite_overflow_pages=[True]),
            lambda r:r.update(sqlite_payload_ranges=r['sqlite_payload_ranges']*2049),
        ]
        for number,mutate in enumerate(mutations):
            with self.subTest(number=number):
                raw=record();mutate(raw)
                self.assertIsNone(archive_search._normalized(raw))

    def test_wal_ranges_preserve_exact_frame_and_offset(self):
        raw=record()
        raw['sqlite_payload_ranges'][1].update(physical_source='wal',physical_byte_offset=8732,wal_frame=17)
        self.assertEqual(archive_search._normalized(raw)['sqlite_payload_ranges'],raw['sqlite_payload_ranges'])
        for bad in (True,0,262145):
            raw['sqlite_payload_ranges'][1]['wal_frame']=bad
            self.assertIsNone(archive_search._normalized(raw))

    def test_complete_maps_survive_residual_and_duplicate_origins(self):
        nested={k:v for k,v in record().items() if k in archive_search.OVERFLOW_FIELDS}
        base=dict(app='Telegram',text='existing verified history',evidence_kind='previous',
            residual_sources=[copy.deepcopy(nested)],additional_sources=[copy.deepcopy(nested)])
        normalized=archive_search._normalized(base)
        for field in ('residual_sources','sources'):
            for name in archive_search.OVERFLOW_FIELDS:
                self.assertEqual(normalized[field][0][name],nested[name])
        base['residual_sources'][0].pop('sqlite_payload_ranges')
        base['additional_sources'][0]['sqlite_payload_ranges'][0]['bytes']=0
        normalized=archive_search._normalized(base)
        self.assertEqual(normalized['text'],'existing verified history')
        self.assertEqual(normalized['residual_sources'],[])
        self.assertEqual(normalized['sources'],[])

    def test_wal_tail_duplicate_provenance_keeps_boolean_and_integer_types(self):
        tail=dict(wal_tail_reason='torn_frame',wal_validated_prefix_bytes=8296,
            wal_snapshot_latest_known_commit=True,wal_current_state_confirmed=False)
        raw=dict(app='Telegram',text='owned snapshot',evidence_kind='backup',additional_sources=[tail])
        normalized=archive_search._normalized(raw)
        self.assertEqual(normalized['sources'],[tail])
        self.assertIs(normalized['sources'][0]['wal_current_state_confirmed'],False)

    def test_search_returns_full_provenance_and_skips_malformed_claim(self):
        with tempfile.TemporaryDirectory(prefix='owned-provenance-search-') as temporary:
            root=Path(temporary);good=record();bad=record();bad['sqlite_payload_ranges'].pop()
            (root/'messages.jsonl').write_text('\n'.join(json.dumps(row) for row in (good,bad)),encoding='utf-8')
            result=archive_search.search(dict(protocol=1,operation='search',archive=str(root),app='Telegram',query='recipe',evidence='deleted'))
            self.assertEqual(result['total'],1)
            self.assertIn('RECORD_SKIPPED',result['warnings'])
            self.assertEqual(result['records'][0]['sqlite_payload_ranges'],good['sqlite_payload_ranges'])
            self.assertEqual(result['records'][0]['sqlite_payload_sha256'],good['sqlite_payload_sha256'])


if __name__=='__main__':
    unittest.main(verbosity=2)
