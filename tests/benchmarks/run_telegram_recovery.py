"""Append-only actual frozen-helper stdin benchmark; never imports recovery code."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from score_telegram_recovery import score,sha,text_sha

REPO=Path(__file__).resolve().parents[2]
SOURCES=('helpers/recovery_engine/engine.py','helpers/recovery_engine/telegram_auto.py',
         'helpers/recovery_engine/sqlite_history.py','helpers/recovery_engine/sqlite_deleted.py',
         'helpers/recovery_engine/archive_search.py','tests/build_telegram_native_fixtures.py',
         'tests/build_telegram_wal_tail_fixtures.py','tests/build_telegram_overflow_fixtures.py')


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):h.update(block)
    return h.hexdigest()


def write(path,value):
    with path.open('x',encoding='utf-8') as out:json.dump(value,out,ensure_ascii=False,indent=2)


def inventory(root):
    return {path.relative_to(root).as_posix():dict(bytes=path.stat().st_size,sha256=digest(path))
            for path in sorted(root.rglob('*')) if path.is_file()}


def snapshot(app,helper,wal,overflow):
    return dict(application_sha256=digest(app),helper_sha256=digest(helper),
        helper_files=inventory(helper.parent),
        benchmark_code={path.name:digest(path) for path in (Path(__file__),Path(__file__).with_name('score_telegram_recovery.py'))},
        working_source_context={name:digest(REPO/name) for name in SOURCES},
        owned_fixtures=dict(wal=inventory(wal),overflow=inventory(overflow)))


def invoke(helper,request,folder,name):
    write(folder/(name+'-request.json'),request)
    started=time.perf_counter()
    process=subprocess.Popen([str(helper)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=helper.parent)
    print(json.dumps(dict(event='helper_started',step=name,pid=process.pid)),flush=True)
    # The outer exec may yield; this exact child remains running. No retries.
    out,error=process.communicate(json.dumps(request,ensure_ascii=False).encode('utf-8'))
    (folder/(name+'-stdout.jsonl')).write_bytes(out)
    (folder/(name+'-stderr.bin')).write_bytes(error)
    replies=[]
    for line in out.decode('utf-8-sig').splitlines():
        try:value=json.loads(line)
        except ValueError:continue
        if isinstance(value,dict) and value.get('event',value.get('type'))=='result':replies.append(value)
    reply=replies[-1] if replies else dict(status='protocol_error',code='NO_RESULT')
    return reply,dict(exit_code=process.returncode,seconds=round(time.perf_counter()-started,6),
        stdout_sha256=sha(out),stderr_sha256=sha(error),stderr_bytes=len(error),result_events=len(replies))


def main():
    parser=argparse.ArgumentParser()
    for name in ('label','app','helper','wal','overflow','out','expected-app','expected-helper'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();app=Path(args.app).resolve();helper=Path(args.helper).resolve()
    wal=Path(args.wal).resolve();overflow=Path(args.overflow).resolve();output=Path(args.out).resolve()
    if digest(app)!=args.expected_app or digest(helper)!=args.expected_helper:raise ValueError('RUNTIME_HASH_MISMATCH')
    wal_manifest=json.loads((wal/'manifest.json').read_text(encoding='utf-8'))
    overflow_manifest=json.loads((overflow/'manifest.json').read_text(encoding='utf-8'))
    if len(wal_manifest['cases'])!=15 or len(overflow_manifest['cases'])!=4:raise ValueError('CASE_SET_MISMATCH')
    output.mkdir(parents=True,exist_ok=False)
    (output/'run.incomplete').write_text('This benchmark has not completed.\n',encoding='utf-8')
    before=snapshot(app,helper,wal,overflow);write(output/'binding-before.json',before)
    results=[]
    for kind,root,cases in (('wal',wal,wal_manifest['cases']),('overflow',overflow,overflow_manifest['cases'])):
        for case in cases:
            name=kind+'-'+case['name'];source=root/(case.get('path') or case['image'])
            if digest(source)!=case['source_sha256']:raise ValueError('FIXTURE_HASH_MISMATCH')
            if kind=='wal' and digest(Path(str(source)+'-wal'))!=case['wal_sha256']:raise ValueError('WAL_HASH_MISMATCH')
            print(json.dumps(dict(event='case_started',label=args.label,case=name,index=len(results)+1)),flush=True)
            folder=output/name;folder.mkdir();archive=folder/'archive'
            request=dict(protocol=1,operation='telegram_analyze',destination=str(archive),options=dict(
                roots=[str(source)],scan_fragments=True,fragment_query='',query_mode='literal',
                application_directory=str(app.parent)))
            reply,execution=invoke(helper,request,folder,'analyze')
            complete=(execution['exit_code']==0 and reply.get('status') in ('complete','partial') and
                (archive/'messages.jsonl').is_file() and not (archive/'job.incomplete').exists())
            rows=[json.loads(line) for line in (archive/'messages.jsonl').read_text(encoding='utf-8').splitlines()] if complete else []
            searches={};search_execution={}
            queries=(('literal_all','прабабушки' if kind=='wal' else 'recipe 3 яблоки','literal',''),
                     ('regex_all',r'рецепт\s+прабабушки' if kind=='wal' else r'recipe\s+3\s+яблоки','regex',''),
                     ('literal_deleted','прабабушки' if kind=='wal' else 'recipe 3 яблоки','literal','deleted'))
            if complete:
                for query_name,query,mode,evidence in queries:
                    searches[query_name],search_execution[query_name]=invoke(helper,dict(protocol=1,operation='search',archive=str(archive),
                        app='Telegram',query=query,query_mode=mode,evidence=evidence,offset=0,limit=100),folder,query_name)
            scored=score(kind,case,source,rows,searches,complete)
            row=dict(name=name,kind=kind,status='completed' if complete else 'analysis_error',
                source_sha256=case['source_sha256'],wal_sha256=case.get('wal_sha256'),analysis_code=reply.get('code'),
                analysis_status=reply.get('status'),archive_records=len(rows) if complete else None,
                execution=execution,search_execution=search_execution,score=scored,
                archive_files=inventory(archive) if archive.is_dir() else {})
            write(folder/'case.json',row);results.append(row)
            print(json.dumps(dict(event='case_completed',label=args.label,case=name,status=row['status'],
                exact_full_text=scored['observed_full_exact_text_count'],prefix=scored['verified_prefix_count'],overflow=scored['verified_overflow_count'])),flush=True)
    after=snapshot(app,helper,wal,overflow);write(output/'binding-after.json',after)
    if before!=after:raise ValueError('SOURCE_CODE_OR_RUNTIME_CHANGED')
    run=dict(schema=1,label=args.label,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope='Actual frozen-helper stdin protocol; application hash is distribution context, application/UI/pipeline not executed',
        real_devices_tested=False,commercial_programs_compared=False,reruns=0,
        request_options=dict(scan_fragments=True,fragment_query='',query_mode='literal',recover_deleted='helper default'),
        application_sha256=before['application_sha256'],helper_sha256=before['helper_sha256'],
        wal_manifest_sha256=digest(wal/'manifest.json'),overflow_manifest_sha256=digest(overflow/'manifest.json'),
        binding_before_sha256=digest(output/'binding-before.json'),binding_after_sha256=digest(output/'binding-after.json'),
        source_runtime_code_unchanged=before==after,results=results)
    write(output/'run.json',run);(output/'run.incomplete').unlink()
    print(json.dumps(dict(event='benchmark_completed',label=args.label,cases=len(results),out=str(output))),flush=True)


if __name__=='__main__':main()
