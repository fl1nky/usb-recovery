# SPDX-License-Identifier: AGPL-3.0-or-later
"""Durable stream-copy checkpoints shared by storage preparation adapters.

The caller authenticates/unlocks its source, holds source/job leases, and
publishes reports before publish(). Bindings must contain no credentials.
"""
import hashlib
import os
from pathlib import Path

from recovery_io import (
    RecoveryIOError, atomic, digest, plain, read_json, read_only, writable, write_all,
)

CHUNK = 1024 * 1024
INTERVAL = 8 * CHUNK
SECRET_FIELDS = frozenset({
    'password', 'passphrase', 'secret', 'secrets', 'key', 'keys', 'bek_base64',
    'fvek', 'vmk', 'recovery_password', 'recovery_key',
})


def _binding_safe(value):
    if isinstance(value, dict):
        if any(str(key).lower() in SECRET_FIELDS for key in value):
            raise RecoveryIOError('INVALID_CHECKPOINT_BINDING')
        for item in value.values():
            _binding_safe(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _binding_safe(item)


def _read_exact(stream, count, eof_code):
    """A short read is allowed; EOF before the requested boundary is not."""
    result = bytearray()
    while len(result) < count:
        remaining = count - len(result)
        block = stream.read(remaining)
        if not isinstance(block, (bytes, bytearray, memoryview)) or len(block) > remaining:
            raise RecoveryIOError('IO_ERROR')
        if not block:
            raise RecoveryIOError(eof_code)
        result.extend(block)
    return result


def _load_checkpoint(checkpoint, binding, total):
    state = read_json(checkpoint)
    if (not isinstance(state, dict) or state.get('schema') != 1
            or state.get('binding') != binding or state.get('total') != total):
        raise RecoveryIOError('RESUME_SOURCE_CHANGED')
    done = state.get('completed')
    if type(done) is not int or not 0 <= done <= total:
        raise RecoveryIOError('RESUME_CHECKPOINT_INVALID')
    return state


def _verify_published(output, partial, state, total):
    if state['completed'] != total:
        raise RecoveryIOError('RESUME_CHECKPOINT_INVALID')
    with read_only(output) as copy:
        if os.fstat(copy.fileno()).st_size != total or digest(copy) != state.get('prefix_sha256'):
            raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
    if partial.exists():
        plain(str(partial), True)
        if not os.path.samefile(partial, output):
            raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
        # A crash between link and unlink leaves two names for the same inode.
        # Verify both names before removing the alias; never truncate it.
        partial.unlink()
    return {'partial': None, 'sha256': state['prefix_sha256'],
            'resumed_bytes': total, 'published': True}


def _verify_prefix(reader, partial, state, emit):
    plain(str(partial), True)
    writable(partial)
    done = state['completed']
    if partial.stat().st_size < done:
        raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
    current = hashlib.sha256()
    reader.seek(0)
    reused = 0
    with read_only(partial) as copy:
        while reused < done:
            count = min(CHUNK, done - reused)
            raw = _read_exact(reader, count, 'RESUME_OUTPUT_CHANGED')
            prior = _read_exact(copy, count, 'RESUME_OUTPUT_CHANGED')
            if raw != prior:
                raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
            current.update(raw)
            reused += count
            if emit:
                emit('progress', phase='verify_prefix', completed=reused, total=done)
    if current.hexdigest() != state.get('prefix_sha256'):
        raise RecoveryIOError('RESUME_OUTPUT_CHANGED')
    return current


def stage(reader, total, output, binding, resume, emit=None, phase='copy', checkpoint=None):
    output = plain(str(output))
    if type(total) is not int or total < 0:
        raise RecoveryIOError('INVALID_REQUEST')
    _binding_safe(binding)
    checkpoint = Path(checkpoint) if checkpoint else output.with_name(output.name + '.resume.json')
    plain(str(checkpoint))
    partial = output.with_name(output.name + '.partial')
    current = hashlib.sha256()
    state = None
    done = reused = 0
    if partial.exists() or checkpoint.exists() or output.exists():
        if not resume or not checkpoint.is_file():
            raise RecoveryIOError('RESUME_REQUIRED')
        state = _load_checkpoint(checkpoint, binding, total)
        if output.exists():
            return _verify_published(output, partial, state, total)
        current = _verify_prefix(reader, partial, state, emit)
        done = reused = state['completed']

    def save():
        atomic(checkpoint, {'schema': 1, 'binding': binding, 'total': total,
                            'completed': done, 'prefix_sha256': current.hexdigest()})

    writable(partial)
    reader.seek(done)
    with partial.open('r+b' if partial.exists() else 'xb') as target:
        target.truncate(done)
        target.seek(done)
        saved = done
        if state is None:
            target.flush()
            os.fsync(target.fileno())
            save()
        while done < total:
            block = _read_exact(reader, min(CHUNK, total - done), 'SOURCE_TRUNCATED')
            write_all(target, block)
            current.update(block)
            done += len(block)
            if done - saved >= INTERVAL or done == total:
                # Commit data before its checkpoint. Any uncommitted tail is
                # verified/truncated on resume, never reported as complete.
                target.flush()
                os.fsync(target.fileno())
                save()
                saved = done
            if emit:
                emit('progress', phase=phase, completed=done, total=total)
    return {'partial': partial, 'sha256': current.hexdigest(),
            'resumed_bytes': reused, 'published': False}


def publish(staged, output):
    if staged['published']:
        return
    output = plain(str(output))
    partial = plain(str(staged['partial']), True)
    if output.exists():
        raise RecoveryIOError('OUTPUT_EXISTS')
    os.link(partial, output)
    partial.unlink()
