"""Byte-exact owned evidence envelopes; safe fresh-directory restoration."""
import argparse,base64,gzip,hashlib,io,json,re,stat
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SECRET_KEYS={'password','passphrase','auth_key','api_key','api_hash','session_string','recovery_key','secret','token'}
DISALLOWED_SUFFIXES={'.exe','.dll','.pyd','.png','.jpg','.jpeg','.heic','.webp','.bmp'}


def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(path):return sha(path.read_bytes())
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def write(path,value):
    with path.open('x',encoding='utf-8',newline='\n') as output:json.dump(value,output,ensure_ascii=False,indent=2)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def privacy_scan(path,raw):
    text=raw.decode('utf-8','ignore').replace('\\\\','\\').replace('\\','/')
    problems=[]
    if '/appdata/' in text.casefold():problems.append('PERSONAL_APPDATA_PATH')
    allowed=[str(ROOT/'.build'/'benchmarks-v8-telegram').replace('\\','/').casefold(),
             str(ROOT/'.build'/'telegram-legacy-fixtures-current').replace('\\','/').casefold()]
    for found in re.findall(r'(?<![A-Za-z0-9])[A-Za-z]:[/][^\x00-\x20<>\"\']+',text):
        candidate=found.rstrip('.,;})]').casefold()
        if not any(candidate==prefix or candidate.startswith(prefix+'/') or prefix.startswith(candidate) for prefix in allowed):
            problems.append('OUTSIDE_OWNED_PROJECT_PATH')
    if path.suffix.casefold() in DISALLOWED_SUFFIXES or raw.startswith((b'MZ',b'\x7fELF')):problems.append('RUNTIME_OR_SCREENSHOT_FILE')
    def inspect(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if str(key).casefold() in SECRET_KEYS and item not in (None,'',{},[],False):problems.append('NONEMPTY_SECRET_FIELD')
                inspect(item)
        elif isinstance(value,list):
            for item in value:inspect(item)
    if path.suffix.casefold() in ('.json','.jsonl'):
        try:
            if path.suffix.casefold()=='.jsonl':
                for line in raw.decode('utf-8-sig').splitlines():inspect(json.loads(line))
            else:inspect(json.loads(raw.decode('utf-8-sig')))
        except (ValueError,UnicodeError):problems.append('MALFORMED_EXPECTED_JSON')
    return sorted(set(problems))


def envelope(roots):
    files=[];directories=[];omitted=[];scanned=0
    for prefix,root in roots:
        for path in sorted(root.rglob('*')):
            relative=prefix+'/'+path.relative_to(root).as_posix()
            if path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400:raise ValueError('SOURCE_PATH_LINK')
            if path.is_dir():directories.append(relative);continue
            if not path.is_file():raise ValueError('SOURCE_SPECIAL_FILE')
            raw=path.read_bytes();scanned+=1;problems=privacy_scan(path,raw)
            if problems:omitted.append(dict(path=relative,sha256=sha(raw),reasons=problems));continue
            files.append(dict(path=relative,bytes=len(raw),sha256=sha(raw),gzip_base64=base64.b64encode(gzip.compress(raw,mtime=0)).decode('ascii')))
    return dict(schema=1,scope='Only generated owned project fixtures and frozen-helper outputs; project workspace paths are provenance, no devices/profiles scanned',
        encoding='gzip+base64',directories=directories,files=files),dict(scanned_files=scanned,omitted=omitted)


def validate_name(name):
    if not isinstance(name,str) or not name or '\\' in name or ':' in name or any(ord(c)<32 for c in name):raise ValueError('RESTORE_PATH_UNSAFE')
    parts=name.split('/')
    reserved={'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}
    if any(not part or part in ('.','..') or part[-1:] in ('.',' ') or part.split('.')[0].upper() in reserved for part in parts):raise ValueError('RESTORE_PATH_UNSAFE')
    return parts


def check_ancestors(path):
    for parent in (path,*path.parents):
        if parent.exists():
            item=parent.lstat()
            if stat.S_ISLNK(item.st_mode) or getattr(item,'st_file_attributes',0)&0x400:raise ValueError('RESTORE_PATH_LINK')


def restore(envelopes,destination):
    check_ancestors(destination);destination.mkdir(parents=True,exist_ok=False)
    marker=destination/'restore.incomplete';marker.write_text('Restore unfinished\n',encoding='utf-8')
    count=0;total=0;seen=set();payloads=[]
    for path in envelopes:
        value=read(path)
        if value.get('schema')!=1 or value.get('encoding')!='gzip+base64' or not isinstance(value.get('files'),list) or len(value['files'])>4096:raise ValueError('ENVELOPE_INVALID')
        for name in value.get('directories',[]):
            target=destination.joinpath(*validate_name(name));check_ancestors(target);target.mkdir(parents=True,exist_ok=True)
        for record in value['files']:
            name=record['path'];parts=validate_name(name);folded=name.casefold();size=record['bytes']
            if folded in seen or type(size) is not int or not 0<=size<=64*1024**2:raise ValueError('RESTORE_DUPLICATE_OR_LIMIT')
            seen.add(folded);total+=size
            if total>512*1024**2:raise ValueError('RESTORE_TOTAL_LIMIT')
            encoded=record['gzip_base64']
            if not isinstance(encoded,str) or len(encoded)>128*1024**2:raise ValueError('RESTORE_COMPRESSED_LIMIT')
            with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(encoded,validate=True))) as stream:raw=stream.read(size+1)
            if len(raw)!=size or sha(raw)!=record['sha256']:raise ValueError('RESTORE_HASH_MISMATCH')
            target=destination.joinpath(*parts);check_ancestors(target);target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as output:output.write(raw)
            if digest(target)!=record['sha256']:raise ValueError('RESTORE_WRITTEN_HASH_MISMATCH')
            payloads.append(dict(path=name,bytes=size,sha256=record['sha256']));count+=1
    marker.unlink();return dict(status='passed',files=count,bytes=total,inventory_sha256=sha(canonical(payloads)))


def publish(args):
    destination=Path(args.out);destination.mkdir(parents=True,exist_ok=False)
    own_before=digest(Path(__file__));code=Path(__file__).parent
    code_before={name:digest(code/name) for name in ('run_telegram_legacy.py','score_telegram_legacy.py','prepare_telegram_legacy_controls.py','audit_telegram_legacy_scorer.py')}
    folders={label:Path(getattr(args,label+'_run')) for label in ('v7','v8')}
    scores={label:Path(getattr(args,label+'_score')) for label in ('v7','v8')}
    raw={label:read(folder/'run.json') for label,folder in folders.items()}
    scored={label:read(path) for label,path in scores.items()}
    for label in ('v7','v8'):
        before=read(folders[label]/'binding-before.json');after=read(folders[label]/'binding-after.json')
        if before!=after or scored[label]['executed_run_sha256']!=digest(folders[label]/'run.json') or scored[label]['scoring_before']!=scored[label]['scoring_after'] or scored[label]['scoring_before']['scorer_sha256']!=code_before['score_telegram_legacy.py'] or before['runner_sha256']!=code_before['run_telegram_legacy.py']:raise ValueError('FROZEN_EXECUTION_OR_SCORE_MISMATCH')
    if raw['v7']['corpus_manifest_sha256']!=raw['v8']['corpus_manifest_sha256'] or raw['v7']['controls_manifest_sha256']!=raw['v8']['controls_manifest_sha256']:raise ValueError('PAIRED_INPUTS_DIFFER')
    audit=Path(args.audit);receipt=read(audit)
    if receipt['status']!='passed' or receipt['scorer_sha256']!=code_before['score_telegram_legacy.py'] or receipt['auditor_sha256']!=code_before['audit_telegram_legacy_scorer.py']:raise ValueError('AUDIT_BINDING_MISMATCH')
    corpus,corpus_scan=envelope([('inputs/corpus',Path(args.corpus)),('inputs/controls',Path(args.controls))])
    reports,report_scan=envelope([('runs/'+label,folder) for label,folder in folders.items()])
    write(destination/'owned-inputs.json',corpus);write(destination/'complete-raw-runs.json',reports)
    write(destination/'privacy-scan.json',dict(schema=1,scope='Workspace paths only for owned project fixture/runtime/output locations; no AppData sourcepaths, personal profiles, screenshots or runtime binaries',inputs=corpus_scan,raw_runs=report_scan))
    if corpus_scan['omitted'] or report_scan['omitted']:raise ValueError('PRIVACY_OMISSIONS_REVIEW_REQUIRED')
    for label,path in scores.items():(destination/(label+'-score.json')).write_bytes(path.read_bytes())
    (destination/'independent-audit.json').write_bytes(audit.read_bytes())
    restored=restore([destination/'owned-inputs.json',destination/'complete-raw-runs.json'],Path(args.restore_check))
    write(destination/'restoration-check.json',restored)
    code_after={name:digest(code/name) for name in code_before}
    if code_before!=code_after or own_before!=digest(Path(__file__)):raise ValueError('EXPORT_CODE_CHANGED')
    write(destination/'comparison.json',dict(schema=1,scope='Paired frozen-helper stdin API; no V8 application/UI/C# pipeline executed; same five logical target contents reused across four corpus cases',
        v7=scored['v7']['summary'],v8=scored['v8']['summary'],paid_results='not_tested',real_devices_tested=False,
        helper_sha256={label:raw[label]['helper_sha256'] for label in raw},helper_reruns=0,
        collector_scorer_auditor_before=code_before,collector_scorer_auditor_after=code_after,
        exporter_sha256_before=own_before,exporter_sha256_after=digest(Path(__file__)),
        input_envelope_sha256=digest(destination/'owned-inputs.json'),raw_envelope_sha256=digest(destination/'complete-raw-runs.json'),
        restoration=restored,audit_checks=receipt['checks']))
    write(destination/'inventory.json',dict(schema=1,files={path.name:dict(bytes=path.stat().st_size,sha256=digest(path)) for path in sorted(destination.iterdir()) if path.is_file()}))
    print(json.dumps(dict(status='published',out=str(destination),restored=restored)))


if __name__=='__main__':
    ap=argparse.ArgumentParser()
    for name in ('v7-run','v8-run','v7-score','v8-score','corpus','controls','audit','out','restore-check'):ap.add_argument('--'+name)
    ap.add_argument('--restore',nargs='+')
    args=ap.parse_args()
    if args.restore:print(json.dumps(restore([Path(p) for p in args.restore],Path(args.out))))
    else:publish(args)
