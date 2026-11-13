"""Bounded extraction of pinned independently produced EWF test inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def extract(source,destination):
    source,destination=Path(source).absolute(),Path(destination).absolute()
    for path in (source,destination):
        for node in (path,*path.parents):
            if node.is_symlink() or node.is_junction():raise ValueError('Linked fixture path')
    manifest=json.loads((source/'manifest.json').read_text())
    archive=source/'native-ewf.tar.gz'
    if sha(archive)!=manifest['archive_sha256']:raise ValueError('Fixture archive changed')
    if destination.exists() and any(destination.iterdir()):raise FileExistsError('Use an empty fixture destination')
    destination.mkdir(parents=True,exist_ok=True)
    if len(manifest['files'])>64:raise ValueError('Too many fixtures')
    with tarfile.open(archive) as inputs:
        members=inputs.getmembers()
        if len(members)!=len(manifest['files']) or {m.name for m in members}!=set(manifest['files']):raise ValueError('Unexpected fixture entries')
        for member in members:
            row=manifest['files'][member.name]
            if not member.isfile() or member.name in ('.','..') or any(c in member.name for c in '/\\:') or member.size!=row['bytes'] or not 0<=member.size<=16*1024*1024:raise ValueError('Unsafe fixture entry')
            target=destination/member.name
            with inputs.extractfile(member) as read,target.open('xb') as write:shutil.copyfileobj(read,write)
            if sha(target)!=row['sha256']:raise ValueError('Fixture bytes changed')
    shutil.copyfile(source/'manifest.json',destination/'manifest.json')
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--extract',required=True);parser.add_argument('--destination',required=True)
    args=parser.parse_args();extract(args.extract,args.destination)
