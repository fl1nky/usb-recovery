# SPDX-License-Identifier: AGPL-3.0-or-later
"""Durable stream-copy checkpoints, shared by storage preparation adapters.

The caller must authenticate/unlock its source before calling this function,
hold its source and job leases, and publish reports before publish(). No key,
password or credential fingerprint belongs in a binding.
"""
import hashlib
from pathlib import Path
import os

from recovery_io import RecoveryIOError, atomic, plain, writable, read_json, read_only, digest

CHUNK=1024*1024
INTERVAL=8*CHUNK


def _binding_safe(value):
    banned={'password','passphrase','secret','secrets','key','keys','bek_base64','fvek','vmk','recovery_password','recovery_key'}
    if isinstance(value,dict):
        if any(str(k).lower() in banned for k in value):raise RecoveryIOError('INVALID_CHECKPOINT_BINDING')
        for item in value.values():_binding_safe(item)
    elif isinstance(value,list):
        for item in value:_binding_safe(item)


def stage(reader,total,output,binding,resume,emit=None,phase='copy',checkpoint=None):
    output=plain(str(output))
    if type(total) is not int or total<0:raise RecoveryIOError('INVALID_REQUEST')
    _binding_safe(binding)
    checkpoint=Path(checkpoint) if checkpoint else output.with_name(output.name+'.resume.json')
    plain(str(checkpoint))
    partial=output.with_name(output.name+'.partial')
    current=hashlib.sha256();done=0;reused=0
    state=None
    if partial.exists() or checkpoint.exists() or output.exists():
        if not resume or not checkpoint.is_file():raise RecoveryIOError('RESUME_REQUIRED')
        state=read_json(checkpoint)
        if not isinstance(state,dict) or state.get('schema')!=1 or state.get('binding')!=binding or state.get('total')!=total:
            raise RecoveryIOError('RESUME_SOURCE_CHANGED')
        done=state.get('completed')
        if type(done) is not int or not 0<=done<=total:raise RecoveryIOError('RESUME_CHECKPOINT_INVALID')
        if output.exists():
            if done!=total:raise RecoveryIOError('RESUME_CHECKPOINT_INVALID')
            with read_only(output) as copy:
                if os.fstat(copy.fileno()).st_size!=total or digest(copy)!=state.get('prefix_sha256'):
                    raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
            if partial.exists():
                plain(str(partial),True)
                if not os.path.samefile(partial,output):raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
                # A crash may occur after the atomic link and before unlinking
                # its private alias. Never truncate either link in this case.
                partial.unlink()
            return {'partial':None,'sha256':state['prefix_sha256'],'resumed_bytes':total,'published':True}
        plain(str(partial),True);writable(partial)
        if partial.stat().st_size<done:raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
        reader.seek(0)
        with read_only(partial) as copy:
            while reused<done:
                count=min(CHUNK,done-reused)
                raw=reader.read(count);prior=copy.read(count)
                if len(raw)!=count or raw!=prior:raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
                current.update(raw);reused+=count
                if emit:emit('progress',phase='verify_prefix',completed=reused,total=done)
        if current.hexdigest()!=state.get('prefix_sha256'):raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
    writable(partial)
    reader.seek(done)
    def save():atomic(checkpoint,{'schema':1,'binding':binding,'total':total,'completed':done,'prefix_sha256':current.hexdigest()})
    with partial.open('r+b' if partial.exists() else 'xb') as target:
        target.truncate(done);target.seek(done);saved=done
        if state is None:save()
        while done<total:
            count=min(CHUNK,total-done);block=reader.read(count)
            if len(block)!=count:raise RecoveryIOError('SOURCE_TRUNCATED')
            target.write(block);current.update(block);done+=count
            if done-saved>=INTERVAL or done==total:
                target.flush();os.fsync(target.fileno());save();saved=done
            if emit:emit('progress',phase=phase,completed=done,total=total)
    return {'partial':partial,'sha256':current.hexdigest(),'resumed_bytes':reused,'published':False}


def publish(staged,output):
    if staged['published']:return
    output=plain(str(output));partial=plain(str(staged['partial']),True)
    if output.exists():raise RecoveryIOError('OUTPUT_EXISTS')
    os.link(partial,output)
    partial.unlink()
