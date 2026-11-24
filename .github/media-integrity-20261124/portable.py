"""Build and verify a Windows update from the tested source and pinned redistributable inputs."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import zipfile

PARENT = 'd679e038f48e84e510a3abfbbdee0e3d6905d5e7'
TARGET = '9448116d8daab735f30d3c30aeeeca1ae2339b95'
OLD_DIGEST = 'f2b71918f960d960961ce368610d8d4b1996a440f7e2984625549df9f03b4109'
PREFIX = 'tools/recovery-helper/'

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def safe(name):
    path = PurePosixPath(name)
    assert not path.is_absolute() and not {'.git','.ignore','.build','..','__pycache__'}.intersection(path.parts)
    assert ':' not in name and '\\' not in name and name == str(path), name

def executable(path):
    return PurePosixPath(path).suffix.lower() in {'.exe','.dll','.config','.pyd'}

def prepare(product, old):
    # The only files restored into the checkout are the exact offline build inputs.
    allowed = ('helpers/recovery_engine/wheels/', 'helpers/recovery_engine/dependency-sources/', 'vendor/iphone-backup-decrypt/')
    counts = [0,0,0]
    for item in old.infolist():
        prefix = PREFIX+'rebuild/'
        if not item.filename.startswith(prefix) or item.is_dir():continue
        rel = item.filename[len(prefix):]
        match = next((i for i,rule in enumerate(allowed) if rel.startswith(rule)),None)
        if match is None:continue
        safe(rel); counts[match]+=1
        dest=product/rel; dest.parent.mkdir(parents=True,exist_ok=True)
        if dest.is_file():
            with old.open(item) as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==digest(dest)
        else:
            with old.open(item) as stream,dest.open('xb') as out:shutil.copyfileobj(stream,out)
    assert all(counts),counts

def package(product, old, destination):
    def git(*args):
        return subprocess.check_output(['git','-C',str(product),*args])
    assert git('rev-parse','HEAD').decode().strip()==TARGET
    assert not git('diff','HEAD','--name-only')
    # Replace all changed tracked sources, both runtime manifests, and both freshly built programs.
    delta = git('diff','--name-only','-z',PARENT,TARGET).decode().split('\0')
    updates = {'source/'+rel:product/rel for rel in delta if rel}
    for rel in delta:
        if rel.startswith('docs/') or rel in ('README.md','README.ru.md'): updates[rel]=product/rel
    for rel in ('README.md','README.ru.md'):
        updates[rel]=product/rel
    for name in ('USB-Recovery.exe','USB-Recovery.exe.config'):
        updates[name] = product/'.build/qa'/name
    helper=product/PREFIX
    manifest=json.loads((helper/'runtime-SHA256.json').read_text('utf-8-sig'))
    for row in manifest:
        safe(row['path']);disk=helper/row['path']
        assert row['size']==disk.stat().st_size and row['sha256']==digest(disk)
        updates[PREFIX+row['path']]=disk
    updates[PREFIX+'runtime-SHA256.json']=helper/'runtime-SHA256.json'
    previous={r['path']:r for r in json.loads(old.read('package-sha256.json').decode('utf-8-sig'))}
    runtime=[]
    build=('Windows x64 portable\nSource commit: '+TARGET+'\nApplication SHA256: '+digest(updates['USB-Recovery.exe'])+
           '\nHelper SHA256: '+digest(helper/'recovery-helper.exe')+'\n').encode()
    final=destination/'USB-Recovery-Windows-x64.zip'
    out=destination/(final.name+'.partial');destination.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(out,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as archive:
        for item in old.infolist():
            name=item.filename;safe(name)
            if name in updates or name in ('BUILD.txt','package-sha256.json') or name.startswith(PREFIX):continue
            with old.open(item) as src,archive.open(item,'w') as dest:shutil.copyfileobj(src,dest,1024*1024)
            if executable(name):runtime.append(previous[name])
        for name,f in sorted(updates.items()):
            safe(name);archive.write(f,name)
            if executable(name):runtime.append(dict(path=name,sha256=digest(f),bytes=f.stat().st_size))
        archive.writestr('BUILD.txt',build)
        archive.writestr('package-sha256.json',json.dumps(sorted(runtime,key=lambda r:r['path']),indent=2).encode('utf-8-sig'))
    with zipfile.ZipFile(out) as z:
        assert z.testzip() is None
        names=z.namelist();assert len(set(names))==len(names)
        assert {r['path'] for r in runtime}=={n for n in names if executable(n)}
        for r in runtime:
            with z.open(r['path']) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==r['sha256'] and z.getinfo(r['path']).file_size==r['bytes']
        for r in manifest:
            with z.open(PREFIX+r['path']) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==r['sha256']
        assert z.read('BUILD.txt')==build and z.read('README.md')==(product/'README.md').read_bytes()
        assert 'Анализ данных'.encode('utf-16le') in z.read('USB-Recovery.exe')
        for rel in delta:
            if rel:assert z.read('source/'+rel)==(product/rel).read_bytes()
    h=digest(out);out.replace(final)
    (destination/'SHA256SUMS.txt').write_bytes((h+'  '+final.name+'\n').encode())
    print(final.name, final.stat().st_size,h,'executables:',len(runtime),'helper files:',len(manifest),flush=True)

if __name__=='__main__':
    mode,src,zip_path,out=sys.argv[1:]
    old=Path(zip_path).resolve()
    assert digest(old)==OLD_DIGEST
    with zipfile.ZipFile(old) as z:
        if mode=='prepare':prepare(Path(src).resolve(),z)
        elif mode=='package':package(Path(src).resolve(),z,Path(out).resolve())
        else:raise ValueError(mode)
