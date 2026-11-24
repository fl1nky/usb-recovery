"""Exercise the two programs extracted from the final portable archive, including source provenance."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,zipfile,shutil
from portable import TARGET,digest,safe
src=Path(sys.argv[1]).resolve()
archive=Path(sys.argv[2]).resolve()
scratch=Path(sys.argv[3]).resolve()
scratch.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(src/'tests'))
from build_media_boundary_fixtures import create
from JpegSparseBoundaryTests import layout
fixtures=Path(sys.argv[4]).resolve() if len(sys.argv)>4 else scratch/'fixtures'
if len(sys.argv)<=4:create(fixtures)
program=scratch/'runtime'
with zipfile.ZipFile(archive) as z:
    assert TARGET in z.read('BUILD.txt').decode()
    for n in z.namelist():
        if n in ('USB-Recovery.exe','USB-Recovery.exe.config','tools/recovery-helper/recovery-helper.exe') or n.startswith('tools/recovery-helper/_internal/'):
            safe(n)
            z.extract(n,program)
exe=program/'USB-Recovery.exe';helper=program/'tools/recovery-helper/recovery-helper.exe'
harness=program/'MediaCheck.exe'
shutil.copyfile(str(exe)+'.config',str(harness)+'.config')
env=dict(os.environ,__COMPAT_LAYER='RunAsInvoker')
def run(args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,env=env,timeout=240,**kwargs)
compiler=Path(os.environ['WINDIR'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
run([str(compiler),'/nologo','/codepage:65001','/reference:System.Web.Extensions.dll','/reference:'+str(exe),'/win32manifest:'+str(src/'tests/test.manifest'),'/out:'+str(harness),str(src/'tests/MediaBoundaryRecoveryTests.cs')])
managed=run([str(harness),str(fixtures),str(scratch/'restored')]).stdout.decode()
layouts=json.loads((fixtures/'manifest.json').read_text());target_count=len(layouts)
assert managed.splitlines()[-1]==f'{target_count}/{target_count} layouts passed',managed[-1500:]
print(managed.splitlines()[-1],flush=True)
rows=[]
for case in ('restart-split','stuffed-split','eoi-split','missing-tail','marker-noise','window-end'):
    data,original,offsets=layout(case); input_hash=hashlib.sha256(data).hexdigest()
    source=scratch/'input.dd';source.write_bytes(data);dest=scratch/case
    req=dict(operation='fragmented_photos',protocol=1,source=str(source),destination=str(dest),options={})
    run([str(helper)],input=(json.dumps(req)+'\n').encode())
    r=json.loads((dest/'report.json').read_text('utf-8-sig'))
    assert r['SourceUnchanged'] and r['SourceSha256']==input_hash==digest(source)
    expected=case!='missing-tail'
    assert len(r['Files'])==int(expected),(case,r['Skipped'])
    assert r['Status']==('limited' if case=='marker-noise' else 'complete')
    if expected:
        row=r['Files'][0];safe(row['Path'])
        assert (dest/row['Path']).read_bytes()==original
        assert [x['ImageOffset'] for x in row['Extents']]==offsets
        cursor=0
        for x in row['Extents']:
            at,length=x['ImageOffset'],x['Length']
            assert x['LogicalOffset']==cursor and data[at:at+length]==original[cursor:cursor+length]
            cursor+=length
        assert cursor==len(original)
    rows.append(dict(case=case,source_sha256=input_hash,source_unchanged=True,candidates=len(r['Files']),expected_result=True,coverage=r['Status']))
    print(case,'passed',flush=True)
    source.unlink()
result=dict(commit=TARGET,zip_sha256=digest(archive),app_sha256=digest(exe),helper_sha256=digest(helper),
        managed_cases_passed=target_count,managed_cases=[i['name'] for i in layouts],jpeg_cases=rows,
        scope='Owned image fixtures. Hash, extraction offset and false-positive controls. No physical devices or commercial comparisons.')
(scratch/'receipt.json').write_text(json.dumps(result,indent=2))
