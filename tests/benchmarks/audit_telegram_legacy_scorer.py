"""Independent in-memory proof mutations; never changes saved helper runs."""
import argparse,copy,hashlib,importlib.util,json,shutil,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SCORER=ROOT/'tests/benchmarks/score_telegram_legacy.py'
spec=importlib.util.spec_from_file_location('frozen_legacy_score',SCORER)
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)

def main():
 ap=argparse.ArgumentParser()
 for name in ('run','corpus','controls','out'):ap.add_argument('--'+name,required=True,type=Path)
 a=ap.parse_args();before=s.digest(SCORER);checks=[]
 def check(ok,label):
  if not ok:raise AssertionError(label)
  checks.append(label)
 baseline=s.score_run(a.run,a.corpus,a.controls)
 check(baseline['summary']['verified_target_occurrences']==20,'reference V8 verifies20case-specific target occurrences')
 manifest=s.read(a.corpus/'manifest.json')
 for case in manifest['cases']:
  directory=a.run/('legacy-'+case['name']);request=s.read(directory/'analyze-request.json')
  proof=s.SourceProof(case,a.corpus/case['path'],request['options']['roots'][0])
  rows=[json.loads(line) for line in (directory/'archive/messages.jsonl').read_text(encoding='utf-8').splitlines()]
  target=next(t for t in case['targets'] if t['message_id']==23)
  row=next(r for r in rows if proof.qualifies(r,target))
  mutations={'source_file':'wrong-owned-source.db','source_record':'wrong:record','source_sha256':'0'*64,
   'sqlite_stored_mid':target['sqlite_stored_mid']+1,'message_id':24,'chat_id':-89,'text':row['text']+' altered',
   'native_tl_body_sha256':'0'*64,'application_confirmed':False,'timestamp':'2026-01-01T00:00:00+00:00',
   'deleted':True,'recovery_status':'deleted_supported_by_evidence','snapshot_id':'wrong:snapshot'}
  if case['wal']:
   mutations.update(wal_sha256='0'*64,wal_db_sha256='0'*64,wal_snapshot_sha256='0'*64,wal_commit_frame=999,
    wal_proof='unverified',evidence_kind='backup',previous_version=False)
  for field,value in mutations.items():
   changed=copy.deepcopy(row);changed[field]=value
   check(not proof.qualifies(changed,target),case['name']+': rejects altered '+field)
  changed=copy.deepcopy(row);changed['source_file']='wrong-owned-source.db'
  check(not s.search_same(changed,row),case['name']+': search provenance path cannot silently differ')
 check(s.linked(dict(record_kind='tl_message',text='altered unrecognized control text')),'negative native attribution detected even when control text changes')
 for field in ('message_id','chat_id'):
  check(s.linked(dict(evidence_kind='backup',text='different',**{field:23})),'negative linked '+field+' detected independently of exact target text')
 with tempfile.TemporaryDirectory(prefix='owned-legacy-scorer-audit-') as temporary:
  copied=Path(temporary)/'corpus';shutil.copytree(a.corpus,copied)
  value=s.read(copied/'manifest.json');value['scope']='deliberately modified audit manifest'
  (copied/'manifest.json').write_text(json.dumps(value),encoding='utf-8')
  rejected=False
  try:s.score_run(a.run,copied,a.controls)
  except ValueError as error:rejected=str(error)=='MANIFEST_CHANGED'
  check(rejected,'changed input manifest cannot be substituted after execution')
 check(s.digest(SCORER)==before,'scorer bytes unchanged during independent audit')
 output=dict(schema=1,status='passed',checks=len(checks),scorer_sha256=before,auditor_sha256=s.digest(Path(__file__)),
  scope='In-memory mutations and separate owned temporary input copy; original runs/archives/sources untouched; no helper rerun',assertions=checks)
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8',newline='\n') as stream:json.dump(output,stream,indent=2)
 print(json.dumps(dict(status='passed',checks=len(checks))))

if __name__=='__main__':main()
