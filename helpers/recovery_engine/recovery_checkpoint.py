"""Bounded immutable, externally anchored checkpoints for local recovery jobs.

The parent records a checkpoint SHA after acknowledging it. A local checkpoint
is never trusted merely because its own fields or an adjacent checksum agree.
No source files, secrets or external services are written by this module.
"""
from contextlib import contextmanager
import hashlib
import json
import marshal
import os
from pathlib import Path
import re
import stat
import types
import uuid

SCHEMA = 1
MAX_GENERATIONS = 4096
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
NAME = re.compile(r'checkpoint-([0-9]{12})\.json\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


class CheckpointError(ValueError):
    pass


def plain(path, *, hardlinks=False):
    path = Path(os.path.abspath(path))
    for entry in (path, *path.parents):
        try:
            value = entry.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise CheckpointError('PHOTO_CHECKPOINT_UNSAFE_PATH')
        if entry == path and hardlinks and stat.S_ISREG(value.st_mode) and value.st_nlink != 1:
            raise CheckpointError('PHOTO_CHECKPOINT_UNSAFE_PATH')
    return path


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def fingerprint(modules):
    """Hash executing code objects, including dependencies, without source paths.

    This works when PyInstaller loaded bytecode from PYZ and no .py exists.
    Editable rebuild sources are deliberately not read.
    """
    def normalize(code):
        return code.replace(co_filename='', co_consts=tuple(
            normalize(item) if isinstance(item, types.CodeType) else item
            for item in code.co_consts))
    def defaults(value):
        if isinstance(value,re.Pattern):
            return ('regex',defaults(value.pattern),value.flags)
        if isinstance(value,bytes):
            return ('bytes',value.hex())
        if value is None or isinstance(value,(str,int,float,bool)):
            return (type(value).__name__,value)
        if isinstance(value,(tuple,list)):
            return (type(value).__name__,tuple(defaults(item) for item in value))
        if isinstance(value,dict):
            return ('dict',tuple(sorted((str(key),defaults(item)) for key,item in value.items())))
        raise CheckpointError('PHOTO_CHECKPOINT_DEFAULT_UNSUPPORTED')
    def function(value):
        digest.update(marshal.dumps(normalize(value.__code__)))
        digest.update(encoded(defaults(value.__defaults__)))
        digest.update(encoded(defaults(value.__kwdefaults__)))
    digest = hashlib.sha256()
    for module in modules:
        for name, value in sorted(vars(module).items()):
            code = getattr(value, '__code__', None)
            if isinstance(value, type) and value.__module__ == module.__name__:
                for method, content in sorted(vars(value).items()):
                    if isinstance(content, (staticmethod, classmethod)):
                        content = content.__func__
                    method_code = getattr(content, '__code__', None)
                    if method_code:
                        digest.update((name + '.' + method).encode())
                        function(content)
            elif code and value.__module__ == module.__name__:
                digest.update(name.encode())
                function(value)
            elif name.isupper() and isinstance(value, (str, int, float, bool, bytes, type(None))):
                digest.update(name.encode())
                digest.update(repr(value).encode())
            elif isinstance(value, re.Pattern):
                digest.update(name.encode())
                digest.update(repr((value.pattern, value.flags)).encode())
    return digest.hexdigest()


@contextmanager
def locked(directory):
    directory = plain(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = plain(directory / 'job.lock', hardlinks=True)
    with path.open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'0'); stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise CheckpointError('PHOTO_CHECKPOINT_JOB_BUSY') from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class Journal:
    def __init__(self, directory, binding, anchor=None, notify=None):
        self.directory = plain(directory)
        self.binding, self.notify = binding, notify
        self.sequence, self.previous = 0, None
        self.generations, self.bytes = 0, 0
        self.chain = []
        if anchor is not None:
            self.chain = self.load(anchor)
            self.sequence = self.chain[-1]['Sequence']
            self.previous = dict(Name=Path(anchor['Path']).name, Sha256=anchor['Sha256'])
        self.inventory()

    def inventory(self):
        self.generations, self.bytes = 0, 0
        for root, directories, files in os.walk(self.directory, followlinks=False):
            for name in directories:
                plain(Path(root) / name)
            for name in files:
                path = plain(Path(root) / name, hardlinks=True)
                self.bytes += path.stat().st_size
                self.generations += bool(NAME.fullmatch(name))
                if self.generations > MAX_GENERATIONS or self.bytes > MAX_TOTAL_BYTES:
                    raise CheckpointError('PHOTO_CHECKPOINT_STORAGE_LIMIT')

    def load(self, anchor):
        if not isinstance(anchor, dict) or not isinstance(anchor.get('Path'), str) or not SHA.fullmatch(str(anchor.get('Sha256', ''))):
            raise CheckpointError('PHOTO_CHECKPOINT_ANCHOR_INVALID')
        path = plain(anchor['Path'], hardlinks=True)
        match = NAME.fullmatch(path.name)
        if path.parent != self.directory or not match:
            raise CheckpointError('PHOTO_CHECKPOINT_ANCHOR_INVALID')
        expected_sequence = int(match[1])
        if 'Sequence' in anchor and (type(anchor['Sequence']) is not int or anchor['Sequence'] != expected_sequence):
            raise CheckpointError('PHOTO_CHECKPOINT_ANCHOR_INVALID')
        digest, chain, total, seen = anchor['Sha256'], [], 0, set()
        while True:
            plain(path, hardlinks=True)
            if path.name in seen or len(chain) >= MAX_GENERATIONS or not path.is_file():
                raise CheckpointError('PHOTO_CHECKPOINT_CHAIN_INVALID')
            seen.add(path.name)
            size = path.stat().st_size
            total += size
            if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                raise CheckpointError('PHOTO_CHECKPOINT_STORAGE_LIMIT')
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest:
                raise CheckpointError('PHOTO_CHECKPOINT_HASH_MISMATCH')
            try:
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError()
                        result[key] = value
                    return result
                def nonstandard_constant(_):
                    raise ValueError()
                value = json.loads(raw, object_pairs_hook=unique,parse_constant=nonstandard_constant)
            except (ValueError, UnicodeError, RecursionError):
                raise CheckpointError('PHOTO_CHECKPOINT_STRUCTURE_INVALID') from None
            if (not isinstance(value, dict) or type(value.get('Schema')) is not int or value.get('Schema') != SCHEMA or
                    type(value.get('Sequence')) is not int or value.get('Sequence') != expected_sequence or
                    encoded(value.get('Binding')) != encoded(self.binding)):
                raise CheckpointError('PHOTO_CHECKPOINT_BINDING_MISMATCH')
            chain.append(value)
            previous = value.get('Previous')
            if previous is None:
                if expected_sequence != 1:
                    raise CheckpointError('PHOTO_CHECKPOINT_CHAIN_INVALID')
                break
            if not isinstance(previous, dict) or set(previous) != {'Name', 'Sha256'} or not NAME.fullmatch(str(previous['Name'])) or not SHA.fullmatch(str(previous['Sha256'])):
                raise CheckpointError('PHOTO_CHECKPOINT_CHAIN_INVALID')
            expected_sequence -= 1
            if expected_sequence < 1 or previous['Name'] != 'checkpoint-%012d.json' % expected_sequence:
                raise CheckpointError('PHOTO_CHECKPOINT_CHAIN_INVALID')
            path, digest = self.directory / previous['Name'], previous['Sha256']
        return list(reversed(chain))

    def commit(self, payload):
        if self.generations >= MAX_GENERATIONS:
            raise CheckpointError('PHOTO_CHECKPOINT_STORAGE_LIMIT')
        value = dict(payload, Schema=SCHEMA, Binding=self.binding, Sequence=self.sequence+1, Previous=self.previous)
        raw = encoded(value)
        if len(raw) > MAX_FILE_BYTES or self.bytes + len(raw) > MAX_TOTAL_BYTES:
            raise CheckpointError('PHOTO_CHECKPOINT_STORAGE_LIMIT')
        final = self.directory / ('checkpoint-%012d.json' % value['Sequence'])
        partial = Path(str(final) + '.partial')
        if final.exists() or partial.exists():
            raise CheckpointError('PHOTO_CHECKPOINT_GENERATION_EXISTS')
        with partial.open('xb') as target:
            target.write(raw); target.flush(); os.fsync(target.fileno())
        partial.rename(final)
        digest = hashlib.sha256(raw).hexdigest()
        self.sequence, self.previous = value['Sequence'], dict(Name=final.name, Sha256=digest)
        self.generations += 1; self.bytes += len(raw)
        if self.notify:
            self.notify(dict(Path=str(final), Sha256=digest, Sequence=self.sequence))
        return value

    def quarantine(self, paths):
        paths = list(paths)
        if not paths:
            return
        for path in paths:
            plain(path, hardlinks=True)
            if not path.is_file():
                raise CheckpointError('PHOTO_CHECKPOINT_ORPHAN_INVALID')
        amount = sum(path.stat().st_size for path in paths if path.parent != self.directory)
        if self.bytes + amount > MAX_TOTAL_BYTES:
            raise CheckpointError('PHOTO_CHECKPOINT_STORAGE_LIMIT')
        target = self.directory / ('orphan-' + uuid.uuid4().hex)
        target.mkdir()
        for index, path in enumerate(paths):
            path.rename(target / ('%06d-' % index + path.name))
        self.inventory()
