# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only authenticated BitLocker image preparation using dissect.fve 4.6.

Authentication protects key metadata, not every data sector. This adapter never
mounts/repairs Windows volumes, guesses credentials or accepts raw FVEKs.
"""
from __future__ import annotations

import base64
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import time

_CHUNK = 1024 * 1024
_DEFAULT_LIMIT = 16 * 1024**4


class BitLockerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _integer(value, default, minimum=0):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**63 - 1:
        raise BitLockerError("INVALID_REQUEST")
    return value


def _plain_path(value, must_exist=False):
    if not isinstance(value, str) or not value or "\0" in value:
        raise BitLockerError("INVALID_REQUEST")
    if value.startswith(("\\\\", "//")):
        raise BitLockerError("INVALID_SOURCE")
    path = Path(os.path.abspath(value))
    if path.name.lower().endswith(".partial"):
        raise BitLockerError("INVALID_SOURCE")
    for node in (path, *path.parents):
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BitLockerError("INVALID_SOURCE")
    if must_exist and not path.is_file():
        raise BitLockerError("INVALID_SOURCE")
    return path


@contextlib.contextmanager
def _read_only(path):
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
        raise BitLockerError("IO_ERROR")
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, "rb") as source:
        yield source


class _BoundedReader(io.RawIOBase):
    """Relative partition view; read operations cannot escape selected bounds."""
    def __init__(self, source, offset, length):
        super().__init__()
        self.source, self.offset, self.size, self.position = source, offset, length, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        target = offset if whence == io.SEEK_SET else self.position + offset if whence == io.SEEK_CUR else self.size + offset if whence == io.SEEK_END else -1
        if not 0 <= target <= 2**63 - 1:
            raise BitLockerError("INVALID_SOURCE")
        self.position = target
        return target

    def read(self, size=-1):
        if self.position >= self.size:
            return b""
        if size is None or size < 0:
            size = self.size - self.position
        if size > 16 * _CHUNK:
            raise BitLockerError("INVALID_SOURCE")
        count = min(size, self.size - self.position)
        self.source.seek(self.offset + self.position)
        data = self.source.read(count)
        self.position += len(data)
        return data

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)


def _hash(source, total, emit, phase):
    source.seek(0)
    digest = hashlib.sha256()
    done, last = 0, 0.0
    while True:
        block = source.read(_CHUNK)
        if not block:
            break
        digest.update(block)
        done += len(block)
        now = time.monotonic()
        if now - last >= .2 or done == total:
            emit("progress", phase=phase, completed=done, total=total)
            last = now
    if done != total:
        raise BitLockerError("INVALID_SOURCE")
    return digest.hexdigest()


def _secret(secrets):
    if not isinstance(secrets, dict):
        raise BitLockerError("INVALID_REQUEST")
    values = []
    for name in ("recovery_password", "password", "bek_base64"):
        value = secrets.get(name)
        if value not in (None, ""):
            if not isinstance(value, str):
                raise BitLockerError("INVALID_REQUEST")
            values.append((name, value))
    if not values:
        raise BitLockerError("SECRET_REQUIRED")
    if len(values) != 1:
        raise BitLockerError("INVALID_REQUEST")
    name, value = values[0]
    if name == "recovery_password":
        compact = re.sub(r"[\s-]", "", value)
        if not re.fullmatch(r"[0-9]{48}", compact):
            raise BitLockerError("INVALID_REQUEST")
        value = "-".join(compact[index:index + 6] for index in range(0, 48, 6))
    elif name == "bek_base64":
        if len(value) > 96 * 1024:
            raise BitLockerError("INVALID_REQUEST")
        try:
            value = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise BitLockerError("INVALID_REQUEST") from None
        if not 16 <= len(value) <= 64 * 1024:
            raise BitLockerError("INVALID_REQUEST")
    elif len(value) > 1024:
        raise BitLockerError("INVALID_REQUEST")
    return name, value


def _publish(partial, target):
    if os.name == "nt":
        os.rename(partial, target)
    else:
        os.link(partial, target, follow_symlinks=False)
        partial.unlink()


def _write_new(path, data):
    partial = path.with_name(path.name + ".partial")
    with partial.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    _publish(partial, path)


def _declared_length(boot):
    if len(boot) < 512 or boot[510:512] != b"\x55\xaa":
        return None
    if boot[3:11] == b"EXFAT   ":
        shift = boot[108]
        return struct.unpack_from("<Q", boot, 72)[0] << shift if 9 <= shift <= 12 else None
    sector = struct.unpack_from("<H", boot, 11)[0]
    if sector not in (512, 1024, 2048, 4096):
        return None
    if boot[3:11] == b"NTFS    ":
        return (struct.unpack_from("<Q", boot, 40)[0] + 1) * sector
    if boot[54:57] == b"FAT" or boot[82:85] == b"FAT":
        return (struct.unpack_from("<H", boot, 19)[0] or struct.unpack_from("<I", boot, 32)[0]) * sector
    return None


def _prepare(request, emit):
    try:
        from dissect.fve.bde import BDE
        from dissect.fve.bde.c_bde import FVE_STATE
    except ImportError:
        raise BitLockerError("DEPENDENCY_MISSING") from None
    if not isinstance(request, dict):
        raise BitLockerError("INVALID_REQUEST")
    options = request.get("options", {})
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise BitLockerError("INVALID_REQUEST")
    credential, secret = _secret(request.get("secrets") or {})
    source_path = _plain_path(request.get("source"), True)
    destination = _plain_path(request.get("destination"))
    if source_path == destination or destination in source_path.parents:
        raise BitLockerError("INVALID_SOURCE")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise BitLockerError("INVALID_REQUEST")
    offset = _integer(options.get("offset_bytes"), 0)
    limit = _integer(options.get("max_output_bytes"), _DEFAULT_LIMIT, 512)

    class AuthenticatedBDE(BDE):
        def unlock(self, key):
            # dissect.fve4.6 ignores False here. Enforce the available integrity proof.
            if not self.information.check_integrity(key):
                raise ValueError("METADATA_INTEGRITY_FAILED")
            return super().unlock(key)

    with _read_only(source_path) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BitLockerError("INVALID_SOURCE")
        length = _integer(options.get("length_bytes"), info.st_size - offset, 512)
        if offset % 512 or length % 512 or offset >= info.st_size or length > info.st_size - offset:
            raise BitLockerError("INVALID_REQUEST")
        reader = _BoundedReader(source, offset, length)
        try:
            bde = AuthenticatedBDE(reader)
        except Exception:
            raise BitLockerError("INVALID_SOURCE") from None
        if bde.version not in (1, 2) or bde.sector_size not in (512, 1024, 2048, 4096):
            raise BitLockerError("UNSUPPORTED_VERSION")
        if bde.information.current_state != FVE_STATE.ENCRYPTED or bde.information.next_state != FVE_STATE.ENCRYPTED:
            raise BitLockerError("UNSUPPORTED_FORMAT")
        try:
            if credential == "password":
                bde.unlock_with_passphrase(secret)
            elif credential == "recovery_password":
                bde.unlock_with_recovery_password(secret)
            else:
                bde.unlock_with_bek(io.BytesIO(secret))
        except Exception:
            raise BitLockerError("AUTH_FAILED") from None
        if not bde.unlocked:
            raise BitLockerError("AUTH_FAILED")
        stream = bde.open()
        available = stream.size
        if not isinstance(available, int) or available <= 0 or available > length or available % bde.sector_size:
            raise BitLockerError("INVALID_SOURCE")
        total = _integer(options.get("output_length_bytes"), available, 512)
        if total > available or total % bde.sector_size:
            raise BitLockerError("INVALID_REQUEST")
        if total > limit:
            raise BitLockerError("INVALID_REQUEST")
        declared = _declared_length(stream.read(512))
        if declared is not None:
            declared = max(declared, bde.information.state_offset)
        incomplete = declared is None or total < declared or total < available
        warnings = ["TRUNCATED_SOURCE"] if declared is not None and available < declared else ["LOGICAL_SIZE_UNKNOWN"] if declared is None else []
        if total < available:
            warnings.append("OUTPUT_LENGTH_LIMIT")
        if len(bde._valid_information) < len(bde.boot_sector.information_offsets):
            warnings.append("METADATA_COPY_UNAVAILABLE")
        source_hash = _hash(source, info.st_size, emit, "source_hash")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        if shutil.disk_usage(destination).free < total + 16 * _CHUNK:
            raise BitLockerError("IO_ERROR")
        name = "decrypted-prefix.dd" if incomplete else "decrypted.dd"
        partial, image = destination / (name + ".partial"), destination / name
        stream.seek(0)
        digest, done, last = hashlib.sha256(), 0, 0.0
        with partial.open("xb") as output:
            while done < total:
                count = min(_CHUNK, total - done)
                block = stream.read(count)
                if len(block) != count:
                    raise BitLockerError("INVALID_SOURCE")
                output.write(block)
                digest.update(block)
                done += count
                now = time.monotonic()
                if now - last >= .2 or done == total:
                    emit("progress", phase="decrypt", completed=done, total=total)
                    last = now
            output.flush()
            os.fsync(output.fileno())
        if _hash(source, info.st_size, emit, "verify_source") != source_hash:
            raise BitLockerError("INVALID_SOURCE")
        image_hash = digest.hexdigest()
        report = {
            "format": "bitlocker-derived-image", "version": 1,
            "source": {"path": str(source_path), "bytes": info.st_size, "sha256": source_hash,
                       "offset_bytes": offset, "length_bytes": length, "unchanged": True},
            "image": name, "bytes": total, "sha256": image_hash,
            "declared_logical_bytes": declared, "available_source_bytes": available,
            "materialized_plaintext_bytes": total,
            "completeness": "available_prefix" if incomplete else "declared_length_available",
            "bitlocker_version": bde.version, "sector_size": bde.sector_size,
            "cipher": bde.information.dataset.fvek_type.name,
            "protector_identifiers": [str(value) for value in bde.identifiers],
            "valid_metadata_copies": len(bde._valid_information),
            "eow": bde.eow_information is not None,
            "authentication": {"key_metadata": "AES-CCM and available metadata integrity",
                               "data_sectors": "not_authenticated_by_bitlocker"},
            "warnings": warnings,
            "limits": ["No proof that every plaintext sector is undamaged",
                       "No TPM unlock, password guessing, repair or Windows mount",
                       "Paused or changing encryption states are not supported"],
        }
        _write_new(destination / (name + ".sha256"), (image_hash + "\n").encode("ascii"))
        _write_new(destination / "bitlocker-report.json", json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
        _publish(partial, image)
        return {"status": "partial" if incomplete else "complete", "code": "PARTIAL_DATA" if incomplete else "OK",
                "image": name, "bytes": total, "image_sha256": image_hash,
                "report": "bitlocker-report.json", "warnings": warnings}


def handle_bitlocker(request, emit):
    """Return only controlled protocol fields; never serialize library errors."""
    try:
        return _prepare(request, emit)
    except BitLockerError as error:
        return {"status": "error", "code": error.code, "warnings": []}
    except Exception:
        return {"status": "error", "code": "IO_ERROR", "warnings": []}
