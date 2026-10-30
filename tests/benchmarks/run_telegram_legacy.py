"""Collect actual frozen-helper transcripts; score later without runtime reruns."""
import argparse,datetime,hashlib,json,subprocess,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
QUERIES={21:'Прабабушка',22:'Outgoing legacy',23:'Channel recipe',24:'Basic group',25:'Unknown channel author'}


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):h.update(block)
    return h.hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix():dict(bytes=p.stat().st_size,sha256=digest(p)) for p in sorted(root.rglob('*')) if p.is_file()}


def write(path,value):
    with path.open('x',encoding='utf-8',newline='\n') as out:json.dump(value,out,ensure_ascii=False,indent=2)


def snapshot(helper,app,corpus,controls):
    return dict(helper_sha256=digest(helper),helper_inventory=inventory(helper.parent),
        application_context_sha256=digest(app) if app else None,application_executed=False,
        runner_sha256=digest(Path(__file__)),corpus=inventory(corpus),controls=inventory(controls),
        working_source_context_not_executed={name:digest(ROOT/name) for name in (
            'helpers/recovery_engine/telegram_auto.py','helpers/recovery_engine/telegram_tl.py',
            'helpers/recovery_engine/engine.py','helpers/recovery_engine/archive_search.py',
            'helpers/recovery_engine/sqlite_history.py','helpers/recovery_engine/sqlite_deleted.py',
            'tests/build_telegram_legacy_fixtures.py')})


def invoke(helper,request,folder,step):
    write(folder/(step+'-request.json'),request)
    begin=time.perf_counter();child=subprocess.Popen([str(helper)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=helper.parent)
    print(json.dumps(dict(event='helper_started',step=step,pid=child.pid)),flush=True)
    out,err=child.communicate(json.dumps(request,ensure_ascii=False).encode('utf-8'))
    (folder/(step+'-stdout.jsonl')).write_bytes(out);(folder/(step+'-stderr.bin')).write_bytes(err)
    events=[]
    for line in out.decode('utf-8-sig').splitlines():
        try:event=json.loads(line)
        except ValueError:continue
        if isinstance(event,dict) and event.get('event',event.get('type'))=='result':events.append(event)
    reply=events[-1] if events else dict(status='protocol_error',code='NO_RESULT')
    return reply,dict(exit_code=child.returncode,seconds=round(time.perf_counter()-begin,6),result_events=len(events),
        stdout_sha256=digest(folder/(step+'-stdout.jsonl')),stderr_sha256=digest(folder/(step+'-stderr.bin')))


def main():
    ap=argparse.ArgumentParser()
    for name in ('label','helper','expected-helper','corpus','controls','out'):ap.add_argument('--'+name,required=True)
    ap.add_argument('--application-context');ap.add_argument('--expected-application-context')
    args=ap.parse_args();helper=Path(args.helper).resolve();app=Path(args.application_context).resolve() if args.application_context else None
    corpus=Path(args.corpus).resolve();controls=Path(args.controls).resolve();out=Path(args.out).resolve()
    if digest(helper)!=args.expected_helper:raise ValueError('HELPER_HASH_MISMATCH')
    if app and digest(app)!=args.expected_application_context:raise ValueError('APP_CONTEXT_HASH_MISMATCH')
    positive=json.loads((corpus/'manifest.json').read_text(encoding='utf-8'))
    negative=json.loads((controls/'manifest.json').read_text(encoding='utf-8'))
    if len(positive['cases'])!=4 or any(len(c['targets'])!=5 for c in positive['cases']) or len(negative['cases'])!=5:raise ValueError('CORPUS_CONTRACT_MISMATCH')
    out.mkdir(parents=True,exist_ok=False);(out/'run.incomplete').write_text('Unfinished benchmark\n',encoding='utf-8')
    before=snapshot(helper,app,corpus,controls);write(out/'binding-before.json',before);rows=[]
    for suite,root,cases in (('legacy',corpus,positive['cases']),('control',controls,negative['cases'])):
        for case in cases:
            name=suite+'-'+case['name'];directory=out/name;directory.mkdir();source=root/case['path']
            for member,wanted in case['source_files'].items():
                if digest(source.parent/member)!=wanted:raise ValueError('SOURCE_HASH_MISMATCH')
            print(json.dumps(dict(event='case_started',label=args.label,case=name)),flush=True)
            archive=directory/'archive'
            reply,execution=invoke(helper,dict(protocol=1,operation='telegram_analyze',destination=str(archive),
                options=dict(roots=[str(source)],scan_fragments=True,fragment_query='',query_mode='literal',application_directory=str(helper.parent))),directory,'analyze')
            complete=execution['exit_code']==0 and reply.get('status') in ('complete','partial') and (archive/'messages.jsonl').is_file() and not (archive/'job.incomplete').exists()
            searches={}
            if complete:
                queries=[('literal-'+str(index),target.get('query') or QUERIES[target['message_id']],'literal') for index,target in enumerate(case['targets'])]
                if suite=='legacy':queries.append(('regex-all',r'рецепт|recipe|author','regex'))
                for step,query,mode in queries:
                    _,searches[step]=invoke(helper,dict(protocol=1,operation='search',archive=str(archive),app='Telegram',query=query,query_mode=mode,evidence='',offset=0,limit=100),directory,step)
            row=dict(name=name,suite=suite,status='completed' if complete else 'analysis_error',
                analysis_status=reply.get('status'),analysis_code=reply.get('code'),execution=execution,search_execution=searches,
                archive_inventory=inventory(archive) if archive.is_dir() else {})
            write(directory/'case.json',row);rows.append(row)
            print(json.dumps(dict(event='case_completed',label=args.label,case=name,status=row['status'])),flush=True)
    after=snapshot(helper,app,corpus,controls);write(out/'binding-after.json',after)
    if before!=after:raise ValueError('SOURCE_OR_RUNTIME_OR_RUNNER_CHANGED')
    write(out/'run.json',dict(schema=1,label=args.label,scope='Actual frozen-helper stdin API only; no application/UI/C# pipeline executed',
        utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),paid_results='not_tested',real_devices_tested=False,helper_reruns=0,
        helper_sha256=before['helper_sha256'],application_context_sha256=before['application_context_sha256'],
        corpus_manifest_sha256=digest(corpus/'manifest.json'),controls_manifest_sha256=digest(controls/'manifest.json'),
        binding_before_sha256=digest(out/'binding-before.json'),binding_after_sha256=digest(out/'binding-after.json'),
        source_runtime_code_unchanged=True,results=rows))
    (out/'run.incomplete').unlink();print(json.dumps(dict(event='benchmark_completed',label=args.label,cases=len(rows))),flush=True)


if __name__=='__main__':main()
