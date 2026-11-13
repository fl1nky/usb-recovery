# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared bounded file IO; no formats, secrets, devices or network access."""
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

CHUNK=1024*1024

class RecoveryIOError(Exception):
    pass


def plain(value, exists=False):
    if not isinstance(value, str) or not value or value.startswith(("\\\\", "//")):
        raise RecoveryIOError("INVALID_SOURCE")
    path = Path(os.path.abspath(value))
    for node in (path, *path.parents):
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RecoveryIOError("INVALID_SOURCE")
    if exists and not path.is_file():
        raise RecoveryIOError("INVALID_SOURCE")
    return path


def digest(stream, emit=None, phase="source_hash"):
    stream.seek(0)
    value = hashlib.sha256()
    done, last = 0, 0.0
    while block := stream.read(CHUNK):
        value.update(block)
        done += len(block)
        now = time.monotonic()
        if emit is not None and now - last >= .2:
            emit("progress", phase=phase, completed=done, total=os.fstat(stream.fileno()).st_size)
            last = now
    return value.hexdigest()


def writable(path):
    plain(str(path))
    if path.exists() and (not path.is_file() or path.stat().st_nlink > 1):
        raise RecoveryIOError("INVALID_DESTINATION")


def atomic_bytes(path, data):
    writable(path)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temp.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, path)


def atomic(path, value):
    atomic_bytes(path, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())


@contextlib.contextmanager
def writer_lock(path):
    writable(path)
    with path.open("a+b") as lock:
        lock.seek(0, 2)
        if lock.tell() == 0:
            lock.write(b"\0")
            lock.flush()
        lock.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise RecoveryIOError("SOURCE_PREPARATION_BUSY") from None
        else:
            import fcntl
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RecoveryIOError("SOURCE_PREPARATION_BUSY") from None
        yield


def read_json(path):
    plain(str(path), True)
    if path.stat().st_size > 4 * CHUNK:
        raise RecoveryIOError("INVALID_SOURCE")
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, UnicodeError):
        raise RecoveryIOError("INVALID_SOURCE") from None


@contextlib.contextmanager
def read_only(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            yield source
        return
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x08000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise RecoveryIOError("IO_ERROR")
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, "rb") as source:
        yield source
