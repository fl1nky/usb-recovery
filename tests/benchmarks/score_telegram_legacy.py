"""Independent SQLite/WAL/TL-gold scoring of saved frozen-helper transcripts."""
import argparse,datetime,hashlib,importlib.util,json,sqlite3,struct,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
WRITER=ROOT/'tests'/'build_telegram_legacy_fixtures.py'
spec=importlib.util.spec_from_file_location('legacy_benchmark_gold',WRITER)
gold=importlib.util.module_from_spec(spec);spec.loader.exec_module(gold)
REVISION=2
FIELDS=('app','application_confirmed','record_kind','message_id','chat_id','sqlite_stored_mid','text','sender_id','timestamp',
    'source_file','source_record','source_sha256','snapshot_id','evidence_kind','previous_version','deleted','recovery_status',
    'native_constructor','native_layer','native_tl_body_sha256','wal_proof','wal_commit_frame','wal_sha256','wal_db_sha256','wal_snapshot_sha256')


def sha(data):return hashlib.sha256(data).hexdigest()
def digest(path):return sha(path.read_bytes())
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def text_sha(row):return sha(row['text'].encode('utf-8')) if isinstance(row.get('text'),str) else None
def integer(value):return type(value) is int
def write(path,value):
    with path.open('x',encoding='utf-8',newline='\n') as output:json.dump(value,output,ensure_ascii=False,indent=2)


def checksum(data,little,a=0,b=0):
    for at in range(0,len(data),8):
        x,y=struct.unpack(('<' if little else '>')+'II',data[at:at+8])
        a=(a+x+b)&0xffffffff;b=(b+y+a)&0xffffffff
    return a,b


def wal_snapshots(raw):
    if len(raw)<32:raise ValueError('WAL_HEADER')
    magic,version,page,_,salt1,salt2,a,b=struct.unpack('>8I',raw[:32])
    little=magic==0x377f0682
    if magic not in (0x377f0682,0x377f0683) or version!=3007000 or not 512<=page<=65536 or page&(page-1) or checksum(raw[:24],little)!=(a,b):raise ValueError('WAL_HEADER')
    if (len(raw)-32)%(24+page):raise ValueError('WAL_TORN')
    pages={};snapshots={}
    for number,at in enumerate(range(32,len(raw),24+page),1):
        head=raw[at:at+24];body=raw[at+24:at+24+page]
        target,count,one,two,wanted_a,wanted_b=struct.unpack('>6I',head)
        if not 1<=target<=262144 or count>262144 or (one,two)!=(salt1,salt2):raise ValueError('WAL_FRAME')
        a,b=checksum(head[:8]+body,little,a,b)
        if (a,b)!=(wanted_a,wanted_b):raise ValueError('WAL_CHECKSUM')
        pages[target]=body
        if count:
            pages={key:value for key,value in pages.items() if key<=count}
            if all(key in pages for key in range(1,count+1)):
                snapshots[number]=b''.join(pages[key] for key in range(1,count+1))
    if not snapshots:raise ValueError('WAL_NO_COMPLETE_SNAPSHOT')
    return snapshots


def blob_for(row,profile):
    mid=row['message_id']
    settings={21:dict(peer=77),22:dict(peer=99,out=True),23:dict(peer=88,kind='channel'),
              24:dict(peer=55,kind='chat'),25:dict(peer=88,kind='channel',sender=None)}
    return gold.message(row['text'],mid=mid,profile=profile,**settings[mid])


class SourceProof:
    def __init__(self,case,source,recorded_source=None):
        self.case,self.source=case,source;self.db=source.read_bytes();self.cache={}
        self.recorded_source=recorded_source or str(source)
        self.snapshots=wal_snapshots(Path(str(source)+'-wal').read_bytes()) if case['wal'] else {}
        self.latest=max(self.snapshots) if self.snapshots else None

    def sqlite_row(self,data,key):
        cache_key=(sha(data),key)
        if cache_key in self.cache:return self.cache[cache_key]
        with tempfile.TemporaryDirectory(prefix='owned-legacy-proof-') as temporary:
            path=Path(temporary)/'snapshot.sqlite';path.write_bytes(data)
            db=sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)
            try:
                db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF')
                if db.execute('PRAGMA quick_check(1)').fetchone()!=('ok',):raise ValueError('SQLITE_INTEGRITY')
                cols=db.execute('PRAGMA table_info(messages)').fetchall()
                names=['mid','uid','read_state','send_state','date','data','out','ttl','media','replydata','imp','mention']
                if [item[1] for item in cols]!=names or [item[5] for item in cols]!=[1]+[0]*11:raise ValueError('SQLITE_SCHEMA')
                result=db.execute('SELECT mid,uid,date,data FROM messages WHERE mid=?',(key,)).fetchone()
            finally:db.close()
        self.cache[cache_key]=result;return result

    def origin(self,row,target,*,additional=False):
        key=target['sqlite_stored_mid'];base='messages(uid='+str(target['chat_id'])+',mid='+str(key)+')'
        if row.get('source_file')!=self.recorded_source or row.get('sqlite_stored_mid')!=key or not integer(row.get('sqlite_stored_mid')) or row.get('source_sha256')!=self.case['source_files'][self.source.name]:return False
        data=self.db
        if self.case['wal']:
            frame=row.get('wal_commit_frame');proof=row.get('wal_proof');wal_sha=self.case['source_files'][self.source.name+'-wal']
            if not integer(frame) or frame not in self.snapshots or row.get('wal_sha256')!=wal_sha or row.get('wal_db_sha256')!=self.case['source_files'][self.source.name]:return False
            data=self.snapshots[frame]
            if proof=='all_pages_from_validated_wal':
                if frame>=self.latest or row.get('source_record')!=base+'@wal_commit:'+str(frame) or row.get('snapshot_id')!='wal:'+wal_sha+':commit:'+str(frame) or row.get('wal_snapshot_sha256')!=sha(data):return False
                if not additional and (row.get('evidence_kind')!='previous' or row.get('previous_version') is not True):return False
            elif proof=='validated_wal_commit':
                if frame!=self.latest or row.get('source_record')!=base or row.get('snapshot_id')!=self.case['source_files'][self.source.name]:return False
                if not additional and (row.get('evidence_kind')!='backup' or row.get('previous_version') is True):return False
            else:return False
        elif row.get('source_record')!=base or row.get('snapshot_id')!=self.case['source_files'][self.source.name] or row.get('evidence_kind')!='backup' or row.get('previous_version') is True:return False
        actual=self.sqlite_row(data,key)
        return actual==(key,target['chat_id'],gold.DATE,blob_for(row,self.case['profile']))

    def qualifies(self,row,target):
        if (row.get('app')!='Telegram' or row.get('record_kind')!='tl_message' or row.get('application_confirmed') is not True or
            any(not integer(row.get(k)) or row[k]!=target[k] for k in ('message_id','chat_id','sqlite_stored_mid')) or
            text_sha(row)!=target['text_sha256'] or row.get('deleted') is not None or row.get('recovery_status') is not None or
            row.get('native_layer')!=self.case['profile'] or row.get('native_constructor')!={114:'0x452c0e65',118:'0xf52e6b7f'}[self.case['profile']] or
            row.get('sender_id')!=(None if target['message_id']==25 else 'user:77') or
            row.get('timestamp')!=datetime.datetime.fromtimestamp(gold.DATE,datetime.timezone.utc).isoformat()):return False
        expected=blob_for(row,self.case['profile'])
        if row.get('native_tl_body_sha256')!=sha(expected[:-4]):return False
        return self.origin(row,target)


def linked(row):
    return row.get('record_kind')=='tl_message' or (row.get('evidence_kind') in ('backup','previous','export') and (row.get('message_id') is not None or row.get('chat_id') is not None))


def search_same(view,row):
    return all(view.get(key)==row.get(key) for key in FIELDS)


def last_result(path):
    values=[json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines()]
    return [value for value in values if value.get('event',value.get('type'))=='result'][-1]


def load_run(folder):
    if (folder/'run.incomplete').exists():raise ValueError('RUN_INCOMPLETE')
    run=read(folder/'run.json');before=read(folder/'binding-before.json');after=read(folder/'binding-after.json')
    if before!=after or run['binding_before_sha256']!=digest(folder/'binding-before.json') or run['binding_after_sha256']!=digest(folder/'binding-after.json'):raise ValueError('RUN_BINDING_CHANGED')
    if (run['helper_sha256']!=before['helper_sha256'] or run['application_context_sha256']!=before['application_context_sha256'] or
        run['corpus_manifest_sha256']!=before['corpus']['manifest.json']['sha256'] or
        run['controls_manifest_sha256']!=before['controls']['manifest.json']['sha256']):raise ValueError('RUNTIME_OR_MANIFEST_BINDING_CHANGED')
    for case in run['results']:
        directory=folder/case['name']
        if case['status']!='completed':raise ValueError('UNCOMPLETED_CASE')
        for step,execution in [('analyze',case['execution']),*case['search_execution'].items()]:
            if execution['exit_code']!=0 or execution['result_events']!=1 or execution['stdout_sha256']!=digest(directory/(step+'-stdout.jsonl')) or execution['stderr_sha256']!=digest(directory/(step+'-stderr.bin')):raise ValueError('TRANSCRIPT_CHANGED')
        for name,record in case['archive_inventory'].items():
            if digest(directory/'archive'/name)!=record['sha256']:raise ValueError('ARCHIVE_CHANGED')
    return run,before


def score_run(folder,corpus,controls):
    run,binding=load_run(folder);results=[]
    if digest(corpus/'manifest.json')!=run['corpus_manifest_sha256'] or digest(controls/'manifest.json')!=run['controls_manifest_sha256']:raise ValueError('MANIFEST_CHANGED')
    if digest(WRITER)!=binding['working_source_context_not_executed']['tests/build_telegram_legacy_fixtures.py']:raise ValueError('GOLD_WRITER_CHANGED')
    for key,root in (('corpus',corpus),('controls',controls)):
        actual={path.relative_to(root).as_posix():dict(bytes=path.stat().st_size,sha256=digest(path)) for path in root.rglob('*') if path.is_file()}
        if actual!=binding[key]:raise ValueError('COMPLETE_SOURCE_INVENTORY_CHANGED')
    manifests={suite:{item['name']:item for item in read(root/'manifest.json')['cases']} for suite,root in (('legacy',corpus),('control',controls))}
    for execution in run['results']:
        suite=execution['suite'];name=execution['name'][len(suite)+1:];case=manifests[suite][name]
        root=corpus if suite=='legacy' else controls;source=root/case['path'];directory=folder/execution['name']
        request=read(directory/'analyze-request.json');recorded_source=request['options']['roots'][0]
        relative=Path(case['path']);recorded=Path(recorded_source)
        if tuple(part.casefold() for part in recorded.parts[-len(relative.parts):])!=tuple(part.casefold() for part in relative.parts):raise ValueError('REQUEST_SOURCE_CASE_MISMATCH')
        inventory_key='corpus' if suite=='legacy' else 'controls'
        if binding[inventory_key][relative.as_posix()]['sha256']!=case['source_files'][source.name]:raise ValueError('REQUEST_SOURCE_HASH_MISMATCH')
        for member,wanted in case['source_files'].items():
            if digest(source.parent/member)!=wanted:raise ValueError('SOURCE_CHANGED')
        rows=[json.loads(line) for line in (directory/'archive'/'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        searches={step:last_result(directory/(step+'-stdout.jsonl')) for step in execution['search_execution']}
        if suite=='control':
            target=case['targets'][0];matches=[row for row in rows if text_sha(row)==target['text_sha256']]
            result=dict(name=execution['name'],suite=suite,exact_text_anywhere_rows=len(matches),
                wrongly_linked_rows=sum(linked(row) for row in rows),
                wrongly_linked_search_rows=sum(linked(row) for reply in searches.values() for row in reply.get('records',[])))
        else:
            proof=SourceProof(case,source,recorded_source);targets=[];origins=set();verified_contents=set();public_ids=set()
            for index,target in enumerate(case['targets']):
                exact=[row for row in rows if text_sha(row)==target['text_sha256']]
                valid=[row for row in exact if proof.qualifies(row,target)]
                for row in valid:
                    key=(row['chat_id'],row['message_id'],text_sha(row));verified_contents.add(key);public_ids.add(key[:2])
                    origins.add((row['snapshot_id'],row['source_record']))
                    for origin in row.get('additional_sources',[]):
                        combined={**row,**origin}
                        if proof.origin(combined,target,additional=True):origins.add((combined['snapshot_id'],combined['source_record']))
                def matching(step):return any(search_same(view,row) for view in searches[step].get('records',[]) for row in valid)
                targets.append(dict(message_id=target['message_id'],chat_id=target['chat_id'],sqlite_stored_mid=target['sqlite_stored_mid'],
                    text_sha256=target['text_sha256'],exact_text_anywhere_rows=len(exact),verified=bool(valid),
                    verified_content_rows=len(valid),literal_search_verified=matching('literal-'+str(index)),regex_search_verified=matching('regex-all')))
            # The edited current user text is one extra content version of ID21,
            # not a sixth independent chat/message and not a gold occurrence.
            extras=[]
            if case['wal']:
                target=dict(message_id=21,chat_id=77,sqlite_stored_mid=21,text_sha256=sha(b'Current legacy recipe'))
                extras=[row for row in rows if proof.qualifies(row,target)]
            result=dict(name=execution['name'],suite=suite,targets=targets,gold_target_occurrences=len(targets),
                verified_target_occurrences=sum(target['verified'] for target in targets),
                logical_public_ids=len(public_ids),verified_gold_content_versions=len(verified_contents),
                verified_extra_edited_content_versions=len({(r['chat_id'],r['message_id'],text_sha(r)) for r in extras}),
                verified_snapshot_origin_links=len(origins),unique_verified_snapshot_ids=len({item[0] for item in origins}),
                raw_archive_rows=len(rows))
        results.append(result)
    positives=[r for r in results if r['suite']=='legacy'];negatives=[r for r in results if r['suite']=='control']
    return dict(schema=1,revision=REVISION,executed_run_sha256=digest(folder/'run.json'),helper_sha256=run['helper_sha256'],
        scope='Frozen-helper API only; case-specific target occurrences, not distinct people/chats across repeated fixtures',
        helper_rerun=False,paid_results='not_tested',real_devices_tested=False,results=results,
        summary=dict(primary_cases=len(positives),gold_case_specific_target_occurrences=sum(r['gold_target_occurrences'] for r in positives),
            verified_target_occurrences=sum(r['verified_target_occurrences'] for r in positives),
            complete_five_target_cases=sum(r['verified_target_occurrences']==5 for r in positives),
            literal_search_verified_occurrences=sum(t['literal_search_verified'] for r in positives for t in r['targets']),
            regex_search_verified_occurrences=sum(t['regex_search_verified'] for r in positives for t in r['targets']),
            negative_controls=len(negatives),wrongly_linked_control_rows=sum(r['wrongly_linked_rows'] for r in negatives),
            wrongly_linked_control_search_rows=sum(r['wrongly_linked_search_rows'] for r in negatives)))


if __name__=='__main__':
    ap=argparse.ArgumentParser()
    for name in ('run','corpus','controls','out'):ap.add_argument('--'+name,required=True)
    args=ap.parse_args();path=Path(args.out);before=dict(scorer_sha256=digest(Path(__file__)),fixture_writer_sha256=digest(WRITER))
    result=score_run(Path(args.run),Path(args.corpus),Path(args.controls))
    after=dict(scorer_sha256=digest(Path(__file__)),fixture_writer_sha256=digest(WRITER))
    if before!=after:raise ValueError('SCORING_CODE_CHANGED')
    write(path,dict(**result,scoring_before=before,scoring_after=after));print(json.dumps(result['summary']))
