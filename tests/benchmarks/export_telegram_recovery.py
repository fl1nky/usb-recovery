"""Append-only, path-sanitized Telegram receipts and owned replay corpus."""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
from score_telegram_recovery import score,REVISION


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def write(path,value):
    with path.open('x',encoding='utf-8') as out:json.dump(value,out,ensure_ascii=False,indent=2)


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def validate(folder):
    if (folder/'run.incomplete').exists():raise ValueError('RUN_INCOMPLETE')
    run=read(folder/'run.json');before=read(folder/'binding-before.json');after=read(folder/'binding-after.json')
    if (before!=after or not run['source_runtime_code_unchanged'] or len(run['results'])!=19 or
        run['binding_before_sha256']!=digest(folder/'binding-before.json') or run['binding_after_sha256']!=digest(folder/'binding-after.json')):
        raise ValueError('BINDING_MISMATCH')
    for row in run['results']:
        case=folder/row['name'];execution=row['execution']
        if (row['status']!='completed' or execution['exit_code']!=0 or execution['result_events']!=1 or
            any(value['exit_code']!=0 or value['result_events']!=1 for value in row['search_execution'].values()) or
            len(row['search_execution'])!=3):raise ValueError('EXECUTION_INCOMPLETE')
        for step,record in [('analyze',execution),*row['search_execution'].items()]:
            if (record['stdout_sha256']!=digest(case/(step+'-stdout.jsonl')) or
                record['stderr_sha256']!=digest(case/(step+'-stderr.bin'))):raise ValueError('TRANSCRIPT_CHANGED')
        for name,record in row['archive_files'].items():
            target=case/'archive'/name
            if not target.is_file() or record['bytes']!=target.stat().st_size or record['sha256']!=digest(target):raise ValueError('ARCHIVE_CHANGED')
    return run,before,after


def totals(run):
    rows=run['results'];scores=[row['score'] for row in rows]
    return dict(completed_cases=len(rows),expected_positive_cases=sum(s['expected_attributed_target'] for s in scores),
        full_exact_text_cases=sum(s['observed_full_exact_text_count']>0 for s in scores),
        full_exact_text_rows=sum(s['observed_full_exact_text_count'] for s in scores),
        attributed_exact_text_cases=sum(s['observed_attributed_target_count']>0 for s in scores),
        expected_prefix_cases=sum(s['expected_prefix'] for s in scores),verified_prefix_cases=sum(s['verified_prefix_count']>0 for s in scores),
        expected_overflow_cases=sum(s['expected_overflow'] for s in scores),verified_overflow_cases=sum(s['verified_overflow_count']>0 for s in scores),
        negative_cases=sum(not s['expected_attributed_target'] for s in scores),
        unexpected_confirmed_target_cases=sum(s['unexpected_confirmed_target'] for s in scores),
        confirmed_target_with_wrong_gold_ids=sum(s.get('confirmed_target_with_wrong_gold_ids',0) for s in scores),
        corrupt_or_uncommitted_tail_promoted=sum(s['corrupt_or_uncommitted_tail_promoted'] for s in scores),
        literal_search_attributed_cases=sum(s['searches']['literal_all']['attributed_target_views']>0 for s in scores),
        regex_search_attributed_cases=sum(s['searches']['regex_all']['attributed_target_views']>0 for s in scores),
        deleted_search_verified_overflow_cases=sum(s['expected_overflow'] and s['searches']['literal_deleted']['full_proof_target_views']>0 for s in scores),
        wal_incorrectly_found_as_deleted_cases=sum(row['kind']=='wal' and row['score']['searches']['literal_deleted']['attributed_target_views']>0 for row in rows),
        all_attributed_targets_keep_deletion_unknown=all(s['unknown_deletion_for_all_attributed'] for s in scores if s['observed_attributed_target_count']>0))


def binding(before,after):
    def compact(value):
        result={key:data for key,data in value.items() if key!='helper_files'}
        result['helper_file_count']=len(value['helper_files'])
        result['helper_inventory_sha256']=hashlib.sha256(canonical(value['helper_files'])).hexdigest()
        return result
    return dict(before=compact(before),after=compact(after),identical=before==after)


def rescore(folder,run,wal,overflow):
    records=[]
    manifests={kind:{item['name']:item for item in read(root/'manifest.json')['cases']}
               for kind,root in (('wal',wal),('overflow',overflow))}
    for row in run['results']:
        kind=row['kind'];name=row['name'][len(kind)+1:];case=manifests[kind][name]
        root=wal if kind=='wal' else overflow;source=root/(case.get('path') or case['image'])
        directory=folder/row['name'];archive=directory/'archive'
        messages=[json.loads(line) for line in (archive/'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        replies={}
        for step in row['search_execution']:
            events=[json.loads(line) for line in (directory/(step+'-stdout.jsonl')).read_text(encoding='utf-8-sig').splitlines()]
            replies[step]=[event for event in events if event.get('event',event.get('type'))=='result'][-1]
        records.append({**row,'score':score(kind,case,source,messages,replies,True)})
    return {**run,'results':records}


def publish(old_folder,new_folder,wal,overflow,destination):
    own_before=digest(Path(__file__))
    old,old_before,old_after=validate(old_folder);new,new_before,new_after=validate(new_folder)
    for key in ('wal_manifest_sha256','overflow_manifest_sha256'):
        if old[key]!=new[key]:raise ValueError('DIFFERENT_INPUTS')
    if old_before['owned_fixtures']!=new_before['owned_fixtures']:raise ValueError('DIFFERENT_FIXTURE_BYTES')
    if old_before['benchmark_code']!=new_before['benchmark_code']:raise ValueError('DIFFERENT_SCORER')
    score_path=Path(__file__).with_name('score_telegram_recovery.py')
    writer=Path(__file__).resolve().parents[1]/'build_telegram_native_fixtures.py'
    scoring_before=dict(revision=REVISION,scorer_sha256=digest(score_path),fixture_writer_sha256=digest(writer))
    if scoring_before['fixture_writer_sha256']!=new_before['working_source_context']['tests/build_telegram_native_fixtures.py']:
        raise ValueError('FIXTURE_WRITER_CHANGED')
    # Original executed runs/scores are retained unchanged. Revision 2 is an
    # independent replay of saved archives/transcripts, not a helper rerun.
    scored_old=rescore(old_folder,old,wal,overflow);scored_new=rescore(new_folder,new,wal,overflow)
    destination.mkdir(parents=True,exist_ok=False)
    corpus=[]
    for kind,root in (('wal',wal),('overflow',overflow)):
        for name,record in new_before['owned_fixtures'][kind].items():
            path=root/name;raw=path.read_bytes()
            if len(raw)!=record['bytes'] or hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('CORPUS_CHANGED')
            corpus.append(dict(path=kind+'/'+name,bytes=len(raw),sha256=record['sha256'],
                gzip_base64=base64.b64encode(gzip.compress(raw,compresslevel=9,mtime=0)).decode('ascii')))
    write(destination/'owned-corpus.json',dict(schema=1,scope='Only owned generated SQLite fixtures; no phones, profiles or personal messages',files=corpus))
    for label,run,before,after,folder in (('v6',old,old_before,old_after,old_folder),('v7',new,new_before,new_after,new_folder)):
        write(destination/(label+'-run.json'),dict(schema=1,scope=run['scope'],label=run['label'],utc=run['utc'],
            application_sha256=run['application_sha256'],helper_sha256=run['helper_sha256'],
            wal_manifest_sha256=run['wal_manifest_sha256'],overflow_manifest_sha256=run['overflow_manifest_sha256'],
            request_options=run['request_options'],real_devices_tested=False,commercial_programs_compared=False,
            raw_run_sha256=digest(folder/'run.json'),reruns=run['reruns'],results=run['results']))
        write(destination/(label+'-binding.json'),binding(before,after))
    scoring_after=dict(revision=REVISION,scorer_sha256=digest(score_path),fixture_writer_sha256=digest(writer))
    if scoring_before!=scoring_after:raise ValueError('SCORING_CODE_CHANGED')
    for label,original,scored in (('v6',old,scored_old),('v7',new,scored_new)):
        write(destination/(label+'-score-v'+str(REVISION)+'.json'),dict(schema=1,revision=REVISION,helper_rerun=False,
            executed_run_sha256=digest(old_folder/'run.json' if label=='v6' else new_folder/'run.json'),
            original_scorer_sha256=new_before['benchmark_code']['score_telegram_recovery.py'],
            scoring_before=scoring_before,scoring_after=scoring_after,
            results=[dict(name=row['name'],score=row['score']) for row in scored['results']]))
    summary=dict(schema=1,scope='Frozen-helper stdin protocol comparison on identical owned fixtures; app binaries only hashed as distribution context',
        score_revision=REVISION,scoring_before=scoring_before,scoring_after=scoring_after,
        v6=totals(scored_old),v7=totals(scored_new),real_devices_tested=False,commercial_programs_compared=False,
        timing_comparison_claimed=False,corpus_sha256=digest(destination/'owned-corpus.json'),
        exporter_sha256_before=own_before,exporter_sha256_after=digest(Path(__file__)))
    if summary['exporter_sha256_before']!=summary['exporter_sha256_after']:raise ValueError('EXPORTER_CHANGED')
    write(destination/'comparison.json',summary)
    write(destination/'inventory.json',dict(schema=1,files={path.name:dict(bytes=path.stat().st_size,sha256=digest(path)) for path in sorted(destination.iterdir())}))
    print(json.dumps(summary,ensure_ascii=False))


def restore(corpus_path,destination):
    corpus=read(corpus_path)
    if corpus.get('schema')!=1 or not isinstance(corpus.get('files'),list) or len(corpus['files'])>128:raise ValueError('CORPUS_INVALID')
    destination.mkdir(parents=True,exist_ok=False)
    seen=set();total=0
    for record in corpus['files']:
        name=record['path'];relative=PurePosixPath(name);size=record['bytes']
        if (relative.is_absolute() or any(part in ('..','.') or ':' in part or '\\' in part for part in relative.parts) or
            name in seen or type(size) is not int or not 0<=size<=32*1024**2):raise ValueError('CORPUS_PATH_INVALID')
        total+=size
        if total>256*1024**2:raise ValueError('CORPUS_LIMIT')
        seen.add(name)
        with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(record['gzip_base64'],validate=True))) as stream:raw=stream.read(size+1)
        if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('CORPUS_HASH_MISMATCH')
        target=destination.joinpath(*relative.parts);target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as output:output.write(raw)
    print('Restored '+str(len(seen))+' exact owned fixture files')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('old','new','wal','overflow','out','restore-corpus'):parser.add_argument('--'+name)
    args=parser.parse_args()
    if args.restore_corpus:restore(Path(args.restore_corpus),Path(args.out))
    else:publish(*(Path(getattr(args,name)) for name in ('old','new','wal','overflow','out')))
