"""Independent real SQLite/tail fixtures for last validated WAL snapshots."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'helpers'/'recovery_engine'))
import archive_search
import engine
import sqlite_history
import telegram_auto
from build_telegram_wal_tail_fixtures import build,LATEST,OLD,UNTRUSTED


class TelegramWalTailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='telegram-wal-tail-tests-')
        cls.root=Path(cls.temporary.name)
        cls.manifest=build(cls.root/'fixtures')
        cls.cases={case['name']:case for case in cls.manifest['cases']}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def source(self,name):
        return self.root/'fixtures'/self.cases[name]['path']

    def snapshots(self,name,**options):
        source=self.source(name)
        work=self.root/('snapshots-'+self._testMethodName+'-'+name)
        work.mkdir()
        report={}
        snapshots=list(sqlite_history.iter_committed_snapshots(source,Path(str(source)+'-wal'),work,report=report,**options))
        return snapshots,report

    def analyze(self,name):
        source=self.source(name)
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.parent.iterdir() if p.is_file()}
        output=self.root/(self._testMethodName+'-'+name)
        saved_sidecars=[]
        validate=telegram_auto.Analyzer.validate_wal
        def observed_validation(analyzer,copied,original):
            result=validate(analyzer,copied,original)
            wal=Path(str(copied)+'-wal')
            saved_sidecars.append((result,wal.exists(),hashlib.sha256(wal.read_bytes()).hexdigest() if wal.exists() else None))
            return result
        with patch.object(telegram_auto.Analyzer,'validate_wal',observed_validation),patch('engine.emit'):
            result=telegram_auto.analyze({'protocol':1,'operation':'telegram_analyze','destination':str(output),
                'options':{'roots':[str(source)],'recover_deleted':True}},engine.Importer,lambda *args,**kw:None)
        after={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.parent.iterdir() if p.is_file()}
        self.assertEqual(before,after,'Original DB/WAL bytes and source file list must remain unchanged')
        rows=[json.loads(line) for line in (output/'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        return output,result,rows,saved_sidecars

    def test_last_committed_prefix_is_reconstructed_only_with_opt_in(self):
        snapshots,report=self.snapshots('torn-after-commit')
        self.assertEqual(report['status'],'complete_valid_prefix')
        self.assertFalse(any(s['is_latest_known_commit'] for s in snapshots))
        snapshots,report=self.snapshots('checksum-after-commit',include_latest_on_incomplete_tail=True)
        self.assertTrue(snapshots[-1]['is_latest_known_commit'])
        self.assertEqual(snapshots[-1]['tail_reason'],'frame_checksum')
        self.assertEqual(snapshots[-1]['validated_prefix_bytes'],report['validated_prefix_bytes'])
        with sqlite3.connect(Path(snapshots[-1]['path']).as_uri()+'?mode=ro&immutable=1',uri=True) as connection:
            blob=connection.execute('SELECT data FROM messages_v2 WHERE mid=21').fetchone()[0]
        self.assertIn(LATEST.encode(),blob)
        self.assertNotIn(UNTRUSTED.encode(),blob)

    def test_latest_known_prefix_text_survives_all_bad_tail_types(self):
        for name in ('torn-after-commit','checksum-after-commit','salt-after-commit','page-bounds-after-commit',
                     'partial-uncommitted-transaction','topic-torn-tail','torn-tail-512','torn-tail-65536','corrupt-base-torn-tail'):
            with self.subTest(name=name):
                _,result,rows,sidecars=self.analyze(name)
                latest=[row for row in rows if row['text']==LATEST]
                self.assertEqual(len(latest),1,'The last complete valid commit must not be dropped with the invalid tail')
                row=latest[0];case=self.cases[name]
                self.assertEqual(row['evidence_kind'],'backup')
                self.assertEqual(row['recovery_status'],'committed_wal_prefix_snapshot')
                self.assertIsNone(row['deleted'])
                self.assertIs(row['previous_version'],False)
                self.assertIs(row['wal_current_state_confirmed'],False)
                self.assertIs(row['wal_snapshot_latest_known_commit'],True)
                self.assertEqual(row['wal_tail_reason'],case['tail_reason'])
                self.assertEqual(row['wal_proof'],'all_pages_from_validated_wal')
                self.assertEqual(row['wal_sha256'],case['wal_sha256'])
                self.assertEqual(row['wal_db_sha256'],case['source_sha256'])
                self.assertIn('@wal_commit:',row['source_record'])
                self.assertIn(':commit:',row['snapshot_id'])
                self.assertGreater(row['wal_validated_prefix_bytes'],32)
                self.assertLess(row['wal_validated_prefix_bytes'],Path(str(self.source(name))+'-wal').stat().st_size)
                self.assertEqual(row['message_id'],21)
                self.assertEqual(row['chat_id'],-88 if case['topic'] else 77)
                self.assertTrue(row['application_confirmed'])
                self.assertIn('TELEGRAM_WAL_HISTORY_INCOMPLETE',result['warnings'])
                self.assertEqual(sidecars,[(False,True,case['wal_sha256'])])
                self.assertFalse(any(UNTRUSTED in r['text'] for r in rows))
                old=[r for r in rows if r['text']==OLD]
                self.assertEqual(len(old),1)
                self.assertEqual(old[0]['evidence_kind'],'previous')
                self.assertIs(old[0]['previous_version'],True)
                if name=='corrupt-base-torn-tail':
                    self.assertIn('TELEGRAM_SQLITE_CURRENT_UNREADABLE',result['warnings'])
                    self.assertFalse(any(row.get('recovery_status')=='deleted_supported_by_evidence' for row in rows))

    def test_bad_header_or_first_frame_never_resynchronizes_later_commits(self):
        for name in ('bad-header-checksum','bad-first-frame-no-resync'):
            with self.subTest(name=name):
                _,_,rows,sidecars=self.analyze(name)
                self.assertFalse(any(row.get('application_confirmed') for row in rows))
                self.assertFalse(any(row.get('recovery_status')=='committed_wal_prefix_snapshot' for row in rows))
                self.assertEqual(sidecars,[(False,True,self.cases[name]['wal_sha256'])])

    def test_scan_limit_prefix_is_explicitly_not_confirmed_current_state(self):
        source=self.source('normal-valid-wal');wal=Path(str(source)+'-wal').read_bytes()
        page=int.from_bytes(wal[8:12],'big');step=24+page
        commits=[(at-32)//step+1 for at in range(32,len(wal),step) if int.from_bytes(wal[at+4:at+8],'big')]
        limits=sqlite_history.HistoryLimits(max_frames=commits[-2])
        snapshots,report=self.snapshots('normal-valid-wal',limits=limits,include_latest_on_incomplete_tail=True)
        self.assertEqual(report['tail_reason'],'frame_limit')
        self.assertTrue(snapshots[-1]['is_latest_known_commit'])
        self.assertEqual(snapshots[-1]['tail_reason'],'frame_limit')
        self.assertLess(snapshots[-1]['commit_frame'],commits[-1])
        self.assertEqual(snapshots[-1]['validated_prefix_bytes'],32+commits[-2]*step)

    def test_valid_wal_and_valid_uncommitted_tail_do_not_change_categories(self):
        for name in ('normal-valid-wal','valid-uncommitted-tail'):
            with self.subTest(name=name):
                _,_,rows,_=self.analyze(name)
                row=next(r for r in rows if r['text']==LATEST)
                self.assertEqual(row['evidence_kind'],'backup')
                self.assertEqual(row['wal_proof'],'validated_wal_commit')
                self.assertNotEqual(row.get('recovery_status'),'committed_wal_prefix_snapshot')
                self.assertFalse(row.get('wal_tail_reason'))
                self.assertFalse(any(UNTRUSTED in r['text'] for r in rows))

    def test_missing_wal_page_preimages_and_no_commit_stay_unattributed(self):
        for name in ('missing-page-preimage','no-committed-frame'):
            with self.subTest(name=name):
                _,_,rows,_=self.analyze(name)
                self.assertFalse(any(row.get('recovery_status')=='committed_wal_prefix_snapshot' for row in rows))
                self.assertFalse(any(row.get('application_confirmed') and row['text']==LATEST for row in rows))
                snapshots,report=self.snapshots(name,include_latest_on_incomplete_tail=True)
                self.assertEqual(snapshots,[])
                if name=='missing-page-preimage':
                    self.assertIn('historical_page_preimage_missing',{item['reason'] for item in report['skipped']})

    def test_search_preserves_tail_provenance_and_excludes_deleted_filter(self):
        output,_,rows,_=self.analyze('torn-after-commit')
        for mode,query in (('literal','прабабушки'),('regex','сохранённый.*рецепт')):
            result=archive_search.search(dict(protocol=1,operation='search',archive=str(output),app='Telegram',
                query=query,query_mode=mode,evidence='backup'))
            self.assertEqual(result['total'],1)
            row=result['records'][0]
            self.assertEqual(row['wal_tail_reason'],'torn_frame')
            self.assertIs(row['wal_current_state_confirmed'],False)
            self.assertIs(row['wal_snapshot_latest_known_commit'],True)
            self.assertGreater(row['wal_validated_prefix_bytes'],32)
        result=archive_search.search(dict(protocol=1,operation='search',archive=str(output),app='Telegram',query='прабабушки',evidence='deleted'))
        self.assertEqual(result['total'],0)


if __name__=='__main__':
    unittest.main(verbosity=2)
