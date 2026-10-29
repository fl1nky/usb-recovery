# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only APFS extraction, including referenced historical snapshots.

The parser is pinned to dissect.apfs 1.1.  Exported hashes identify our copies;
they are not independent original-content checksums.  Live files are explicitly
different from previous snapshot versions.  No free block is called a deleted
file and no symlink is followed.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import struct
import time
import zlib
from pathlib import Path


class _Failure(Exception):
    def __init__(self, code: str, warning: str):
        self.code, self.warning = code, warning


class _Limit(Exception):
    pass


def _integer(options, name, default, low, high):
    value = options.get(name, default)
    if type(value) is not int or not low <= value <= high:
        raise _Failure("INVALID_REQUEST", "APFS_INVALID_OPTIONS")
    return value


def _no_reparse(path: Path):
    for ancestor in (path, *path.parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise _Failure("INVALID_SOURCE", "APFS_REPARSE_PATH_REJECTED")


def _is_under(child, parent):
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


@contextlib.contextmanager
def _source_guard(path: Path):
    """On Windows deny writes/deletes for the full hash/parse/export lifetime."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        create.restype = wintypes.HANDLE
        handle = create(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise _Failure("IO_ERROR", "APFS_SOURCE_LOCK_FAILED")
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except Exception:
            kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel.CloseHandle(handle)
            raise
        with os.fdopen(descriptor, "rb", buffering=0) as stream:
            yield stream
    else:
        with path.open("rb", buffering=0) as stream:
            yield stream


def _hash(stream, notify=None):
    stream.seek(0)
    digest = hashlib.sha256()
    total = os.fstat(stream.fileno()).st_size
    done = 0
    while chunk := stream.read(4 * 1024 * 1024):
        digest.update(chunk)
        done += len(chunk)
        if notify:
            notify(done, total)
    return digest.hexdigest()


class _Range(io.RawIOBase):
    """Confine parser offsets to the selected container, including negative seeks."""
    def __init__(self, stream, offset, length, max_calls):
        self.stream, self.offset, self.length = stream, offset, length
        self.position, self.calls, self.max_calls = 0, 0, max_calls

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.length + offset if whence == 2 else -1
        if not 0 <= position <= self.length:
            raise _Failure("INVALID_SOURCE", "APFS_RANGE_INVALID")
        self.position = position
        return position

    def read(self, size=-1):
        self.calls += 1
        if self.calls > self.max_calls:
            raise _Limit()
        size = self.length - self.position if size is None or size < 0 else min(size, self.length - self.position)
        if size > 64 * 1024 * 1024:
            raise _Limit()
        self.stream.seek(self.offset + self.position)
        data = self.stream.read(size)
        self.position += len(data)
        if len(data) != size:
            raise _Failure("IO_ERROR", "APFS_SHORT_READ")
        return data


def _check_object(obj):
    if not obj.is_valid():
        raise _Failure("INVALID_SOURCE", "APFS_METADATA_CHECKSUM_FAILED")


def _check_tree(tree, budget, omap=None, oid=0, xid=None):
    """Validate every node used by a selected tree before trusting its records."""
    _check_object(tree)
    stack = [(tree.root, None, 0)]
    seen = set()
    while stack:
        node, parent_level, depth = stack.pop()
        marker = (int(node.address), int(node.xid))
        if marker in seen or depth > 64:
            raise _Failure("INVALID_SOURCE", "APFS_TREE_CYCLE_REJECTED")
        seen.add(marker)
        budget[0] -= 1
        if budget[0] < 0:
            raise _Limit()
        _check_object(node)
        if node.level > 64 or (parent_level is not None and node.level >= parent_level):
            raise _Failure("INVALID_SOURCE", "APFS_TREE_LEVEL_INVALID")
        if node.nkeys > len(node.block) // 4:
            raise _Failure("INVALID_SOURCE", "APFS_TREE_SIZE_INVALID")
        # Force bounded TOC parsing, including leaf nodes.
        if len(node.toc) != node.nkeys:
            raise _Failure("INVALID_SOURCE", "APFS_TREE_SIZE_INVALID")
        if node.is_nonleaf:
            for index in range(node.nkeys):
                child = tree._node_child(node, index, omap, oid, xid)
                stack.append((child, node.level, depth + 1))
        elif node.level != 0:
            raise _Failure("INVALID_SOURCE", "APFS_TREE_LEVEL_INVALID")


@contextlib.contextmanager
def _bounded_file_reads():
    """Keep large extents streaming instead of allocating an entire extent.

    This is a scoped adapter for the pinned FileStream implementation.  Cipher
    tweak offsets follow its AES-XTS sector convention and are verified against
    the independently supplied encrypted fixture.  Vendor sources stay intact.
    """
    from dissect.apfs.stream import FileStream

    original = FileStream._read

    def read_range(stream, offset, length):
        result = []
        while length:
            logical, physical, extent_length, crypto_id = stream._lookup(offset)
            within = offset - logical
            if within < 0 or within >= extent_length or extent_length % stream.align or within % stream.align:
                raise _Failure("INVALID_SOURCE", "APFS_EXTENT_INVALID")
            if physical < 0 or (physical and physical > stream.volume.container.block_count - extent_length // stream.align):
                raise _Failure("INVALID_SOURCE", "APFS_EXTENT_INVALID")
            amount = min(length, extent_length - within, 4 * 1024 * 1024)
            blocks = (amount + stream.align - 1) // stream.align
            if physical == 0:
                # Sparse extents have no physical data blocks.
                block = bytes(blocks * stream.align)
            else:
                block = stream.volume.container._read_block(physical + within // stream.align, blocks)
                if len(block) != blocks * stream.align:
                    raise _Failure("IO_ERROR", "APFS_SHORT_READ")
                if stream.volume.is_encrypted:
                    if not stream.volume._cipher or not stream.volume.is_onekey:
                        raise _Failure("UNSUPPORTED_FORMAT", "APFS_MULTIKEY_UNSUPPORTED")
                    tweak = crypto_id * stream.volume.container.sectors_per_block + within // 512
                    block = stream.volume._cipher.decrypt(block, tweak)
            result.append(block[:amount])
            offset += amount
            length -= amount
        return b"".join(result)

    FileStream._read = read_range
    try:
        yield
    finally:
        FileStream._read = original


def _atomic_json(path, value):
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _open_file(node):
    # A clone's private data-stream identifier can differ from its inode ID.
    # Keep the original inode ID as provenance, but resolve file extents through
    # that referenced data stream, as defined by j_inode_val.private_id.
    if not node.is_compressed():
        from dissect.apfs.c_apfs import c_apfs
        from dissect.apfs.stream import FileStream

        if dstream := node.xfields.get(c_apfs.INO_EXT_TYPE.DSTREAM):
            return FileStream(node.volume, node.private_id, dstream[1].size)
    return _CompressedFile(node) if node.is_compressed() else node.open()


def _compression_error():
    return _Failure("INVALID_SOURCE", "APFS_COMPRESSED_DATA_INVALID")


def _exact(stream, count):
    if count < 0 or count > 128 * 1024:
        raise _compression_error()
    value = stream.read(count)
    if len(value) != count:
        raise _compression_error()
    return value


def _preflight_lzfse(data, maximum):
    """Validate header-controlled loops and allocations before the vendor codec."""
    from dissect.util.compression import lzfse
    source, expanded = io.BytesIO(data), 0
    while True:
        magic = _exact(source, 4)
        if magic == b"bvx$":
            if any(source.read()):
                raise _compression_error()
            return
        if magic == b"bvx-":
            raw = struct.unpack("<I", _exact(source, 4))[0]
            payload = raw
        elif magic == b"bvxn":
            raw, payload = struct.unpack("<II", _exact(source, 8))
        elif magic in (b"bvx1", b"bvx2"):
            header = (lzfse.LZFSECompressedBlockHeader.parse_v1(source) if magic == b"bvx1"
                      else lzfse.LZFSECompressedBlockHeader.parse_v2(source))
            raw, payload = header.n_raw_bytes, header.n_payload_bytes
            if (header.n_literals > raw + 3 or header.n_matches > raw
                    or payload != header.n_literal_payload_bytes + header.n_lmd_payload_bytes
                    or sum(header.literal_freq) != 1024 or sum(header.l_freq) != 64
                    or sum(header.m_freq) != 64 or sum(header.d_freq) != 256):
                raise _compression_error()
        else:
            raise _compression_error()
        expanded += raw
        if expanded > maximum or payload < 0 or payload > len(data) - source.tell():
            raise _compression_error()
        source.seek(payload, io.SEEK_CUR)


@contextlib.contextmanager
def _bounded_codec_arrays(maximum):
    """Bound the pure-Python Dissect codec output, including LZFSE's LZVN child.

    Each helper handles one request.  Namespace overrides are scoped to a single
    chunk and restored even on error; the vendored files are never modified.
    """
    from dissect.util.compression import lzfse, lzvn

    class LimitedArray(bytearray):
        def __init__(self, value=b""):
            size = value if isinstance(value, int) else len(value)
            if size > maximum:
                raise _compression_error()
            super().__init__(value)

        def __iadd__(self, value):
            if len(value) > maximum - len(self):
                raise _compression_error()
            return super().__iadd__(value)

        def extend(self, value):
            self.__iadd__(value)

        def append(self, value):
            if len(self) >= maximum:
                raise _compression_error()
            super().append(value)

    saved = [(module, "bytearray" in vars(module), vars(module).get("bytearray")) for module in (lzfse, lzvn)]
    try:
        for module, _, _ in saved:
            module.bytearray = LimitedArray
        yield
    finally:
        for module, existed, previous in saved:
            if existed:
                module.bytearray = previous
            else:
                del module.bytearray


def _decode_chunk(algorithm, data, expected):
    """Decode one known decmpfs chunk with a hard output ceiling, never flush unbounded zlib."""
    from dissect.util.compression import lzfse, lzvn
    if not data or not 0 <= expected <= 65536 or len(data) > 128 * 1024:
        raise _compression_error()
    try:
        if algorithm in (3, 4):
            if data[0] == 0x78 and len(data) >= 2:
                decoder = zlib.decompressobj()
                decoded = decoder.decompress(data, expected + 1)
                if len(decoded) > expected or decoder.unconsumed_tail or not decoder.eof or any(decoder.unused_data):
                    raise _compression_error()
            elif data[0] & 0x0F == 0x0F:
                decoded = data[1:]
            else:
                raise _compression_error()
        elif algorithm in (7, 8):
            if data[0] == 0x06:
                decoded = data[1:]
            else:
                with _bounded_codec_arrays(65536):
                    decoded = lzvn.decompress(data)
        elif algorithm in (9, 10):
            decoded = data[1:]
        elif algorithm in (11, 12):
            if data[0] == 0xFF:
                decoded = data[1:]
            else:
                _preflight_lzfse(data, 65536)
                with _bounded_codec_arrays(65536):
                    decoded = lzfse.decompress(data)
        else:
            raise _Failure("UNSUPPORTED_FORMAT", "APFS_COMPRESSION_UNSUPPORTED")
    except _Failure:
        raise
    except Exception:
        raise _compression_error() from None
    if len(decoded) != expected:
        raise _compression_error()
    return decoded


class _CompressedFile(io.RawIOBase):
    """Bounded decmpfs reader; tables are read per entry, not allocated by counts."""
    def __init__(self, node):
        self.fork, self.position, self.cached_index, self.cached = None, 0, -1, b""
        self.inline, self.table_offset, self.data_offset = None, 0, 0
        attribute = node.xattr.get("com.apple.decmpfs")
        if attribute is None:
            raise _compression_error()
        with attribute.open() as stream:
            stream.seek(0, io.SEEK_END)
            length = stream.tell()
            if not 16 <= length <= 128 * 1024:
                raise _compression_error()
            stream.seek(0)
            magic, self.algorithm, self.size = struct.unpack("<IIQ", _exact(stream, 16))
            if magic != int.from_bytes(b"cmpf", "big") or self.size != node.size:
                raise _compression_error()
            self.block_count = (self.size + 65535) // 65536
            if self.algorithm not in (3, 4, 7, 8, 9, 10, 11, 12):
                raise _Failure("UNSUPPORTED_FORMAT", "APFS_COMPRESSION_UNSUPPORTED")
            if self.algorithm & 1:
                if self.size > 65536:
                    raise _Failure("UNSUPPORTED_FORMAT", "APFS_INLINE_COMPRESSION_LIMIT")
                self.inline = _exact(stream, length - 16)
        if self.inline is not None:
            return
        resource = node.xattr.get("com.apple.ResourceFork")
        if resource is None:
            raise _compression_error()
        self.fork = resource.open()
        self.fork.seek(0, io.SEEK_END)
        self.fork_size = self.fork.tell()
        self.fork.seek(0)
        if self.algorithm in (4, 10):
            self.data_offset = struct.unpack(">IIII", _exact(self.fork, 16))[0]
            if self.data_offset > self.fork_size - 8:
                raise _compression_error()
            self.fork.seek(self.data_offset)
            count = struct.unpack("<II", _exact(self.fork, 8))[1]
            self.table_offset = self.data_offset + 8
            if count != self.block_count or count * 8 > self.fork_size - self.table_offset:
                raise _compression_error()
            self.table_end = self.table_offset + count * 8
        else:
            self.table_end = (self.block_count + 1) * 4
            if self.table_end > self.fork_size:
                raise _compression_error()

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset if whence == 2 else -1
        if not 0 <= position <= self.size:
            raise _compression_error()
        self.position = position
        return position

    def _chunk(self, index):
        if self.cached_index == index:
            return self.cached
        if self.inline is not None:
            encoded = self.inline
        else:
            if self.algorithm in (4, 10):
                self.fork.seek(self.table_offset + index * 8)
                offset, length = struct.unpack("<II", _exact(self.fork, 8))
                offset += self.data_offset + 4
            else:
                self.fork.seek(index * 4)
                offset, end = struct.unpack("<II", _exact(self.fork, 8))
                length = end - offset
            if offset < self.table_end or length <= 0 or length > 128 * 1024 or offset > self.fork_size - length:
                raise _compression_error()
            self.fork.seek(offset)
            encoded = _exact(self.fork, length)
        expected = min(65536, self.size - index * 65536)
        self.cached = _decode_chunk(self.algorithm, encoded, expected)
        self.cached_index = index
        return self.cached

    def read(self, size=-1):
        remaining = self.size - self.position
        size = remaining if size is None or size < 0 else min(size, remaining)
        if size > 4 * 1024 * 1024:
            raise _Failure("INVALID_SOURCE", "APFS_COMPRESSED_READ_LIMIT")
        output = []
        while size:
            index, within = divmod(self.position, 65536)
            chunk = self._chunk(index)
            amount = min(size, len(chunk) - within)
            if amount <= 0:
                raise _compression_error()
            output.append(chunk[within:within + amount])
            self.position += amount
            size -= amount
        return b"".join(output)

    def close(self):
        if self.fork is not None:
            self.fork.close()
        super().close()


def handle_apfs(request, emit):
    """Extract an APFS container from one ordinary file, never mount or modify it."""
    records, warnings, published = [], set(), []
    destination = None
    owns_directory = False
    try:
        if not isinstance(request, dict):
            raise _Failure("INVALID_REQUEST", "APFS_INVALID_REQUEST")
        options, secrets = request.get("options", {}), request.get("secrets", {})
        if not isinstance(options, dict) or not isinstance(secrets, dict):
            raise _Failure("INVALID_REQUEST", "APFS_INVALID_REQUEST")
        if not isinstance(request.get("source"), str) or not isinstance(request.get("destination"), str):
            raise _Failure("INVALID_REQUEST", "APFS_INVALID_REQUEST")
        source = Path(os.path.abspath(request["source"]))
        destination = Path(os.path.abspath(request["destination"]))
        _no_reparse(source)
        _no_reparse(destination)
        if not source.is_file() or source.suffix.lower() == ".partial" or not stat.S_ISREG(source.stat().st_mode):
            raise _Failure("INVALID_SOURCE", "APFS_REGULAR_IMAGE_REQUIRED")
        source, destination = source.resolve(), destination.resolve()
        if _is_under(source, destination) or _is_under(destination, source):
            raise _Failure("INVALID_SOURCE", "APFS_SOURCE_DESTINATION_OVERLAP")
        if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
            raise _Failure("INVALID_REQUEST", "APFS_DESTINATION_NOT_EMPTY")
        offset = _integer(options, "offset_bytes", 0, 0, 2**63 - 1)
        length = _integer(options, "length_bytes", 0, 0, 2**63 - 1)
        max_files = _integer(options, "max_files", 100000, 1, 1000000)
        max_file = _integer(options, "max_file_bytes", 2 * 1024**3, 1, 1024**4)
        max_total = _integer(options, "max_output_bytes", 32 * 1024**3, 1, 1024**5)
        max_snapshots = _integer(options, "max_snapshots", 1024, 0, 16384)
        max_nodes = _integer(options, "max_metadata_nodes", 262144, 1, 4000000)
        max_metadata = _integer(options, "max_metadata_bytes", 64 * 1024**2, 4096, 512 * 1024**2)
        prefer_recent = options.get("prefer_recent_snapshots", False)
        if not isinstance(prefer_recent, bool):
            raise _Failure("INVALID_REQUEST", "APFS_OPTIONS_INVALID")
        include_snapshots = options.get("include_snapshots", True)
        if type(include_snapshots) is not bool:
            raise _Failure("INVALID_REQUEST", "APFS_INVALID_OPTIONS")
        password = secrets.get("apfs_password", secrets.get("password", ""))
        if not isinstance(password, str) or len(password) > 4096 or "\0" in password:
            raise _Failure("INVALID_REQUEST", "APFS_INVALID_SECRET")
        from dissect.apfs import APFS
        from dissect.apfs.c_apfs import c_apfs
        from dissect.apfs.util import fletcher64

        last_notice = [0.0]

        def notify(phase, **fields):
            if emit:
                now = time.monotonic()
                is_end = fields.get("total", 0) > 0 and fields.get("completed") == fields.get("total")
                if now - last_notice[0] < 0.1 and not is_end:
                    return
                last_notice[0] = now
                emit("progress", phase=phase, **fields)

        with _source_guard(source) as original:
            size = os.fstat(original.fileno()).st_size
            length = length or size - offset
            if offset % 512 or length < 4096 or offset > size - length:
                raise _Failure("INVALID_SOURCE", "APFS_RANGE_INVALID")
            view = _Range(original, offset, length, max_nodes * 16 + max_files * 32)
            header = view.read(4096)
            if header[32:36] != b"NXSB":
                raise _Failure("UNSUPPORTED_FORMAT", "APFS_CONTAINER_REQUIRED")
            if struct.unpack_from("<I", header, 36)[0] != 4096:
                raise _Failure("UNSUPPORTED_FORMAT", "APFS_BLOCK_SIZE_UNSUPPORTED")
            if int.from_bytes(header[:8], "little") != fletcher64(header[8:]):
                raise _Failure("INVALID_SOURCE", "APFS_METADATA_CHECKSUM_FAILED")
            nx = c_apfs.nx_superblock(header)
            known_container_flags = sum(int(value) for value in c_apfs.NX_INCOMPAT.__members__.values())
            if int(nx.nx_incompatible_features) & ~known_container_flags:
                raise _Failure("UNSUPPORTED_VERSION", "APFS_UNKNOWN_CONTAINER_FEATURES")
            if nx.nx_block_count < 1 or nx.nx_block_count > length // 4096:
                raise _Failure("INVALID_SOURCE", "APFS_CONTAINER_TRUNCATED")
            if nx.nx_fusion_uuid != bytes(16) or int(nx.nx_incompatible_features) & int(c_apfs.NX_INCOMPAT.FUSION):
                raise _Failure("UNSUPPORTED_FORMAT", "APFS_FUSION_UNSUPPORTED")
            for start, count in ((nx.nx_xp_desc_base, nx.nx_xp_desc_blocks), (nx.nx_xp_data_base, nx.nx_xp_data_blocks)):
                if count & 0x80000000 or count > min(max_nodes, 65536):
                    raise _Failure("UNSUPPORTED_FORMAT", "APFS_CHECKPOINT_LAYOUT_UNSUPPORTED")
                if count and (start < 0 or start > nx.nx_block_count - count):
                    raise _Failure("INVALID_SOURCE", "APFS_RANGE_INVALID")
            source_hash = _hash(original, lambda done, total: notify("verify-source", completed=done, total=total))
            container = APFS(view)
            _check_object(container.sb)
            _check_object(container.sb.omap)
            budget = [max_nodes]
            _check_tree(container.sb.omap.btree, budget)
            volumes = container.volumes
            if not volumes or len(volumes) > 100:
                raise _Failure("UNSUPPORTED_FORMAT", "APFS_NO_SUPPORTED_VOLUMES")
            # Verify unlock and metadata before publishing any file.  A wrong
            # password cannot produce a superficially successful empty archive.
            for volume in volumes:
                _check_object(volume)
                known_volume_flags = sum(int(value) for value in c_apfs.APFS_INCOMPAT.__members__.values())
                if int(volume.incompatible_features) & ~known_volume_flags:
                    raise _Failure("UNSUPPORTED_VERSION", "APFS_UNKNOWN_VOLUME_FEATURES")
                if volume.incompatible_features & (c_apfs.APFS_INCOMPAT.PFK | c_apfs.APFS_INCOMPAT.SECONDARY_FSROOT | c_apfs.APFS_INCOMPAT.RESERVED_80):
                    raise _Failure("UNSUPPORTED_FORMAT", "APFS_VOLUME_FEATURES_UNSUPPORTED")
                if volume.incompatible_features & c_apfs.APFS_INCOMPAT.INCOMPLETE_RESTORE:
                    warnings.add("APFS_INCOMPLETE_RESTORE_FLAG")
                if volume.object.apfs_er_state_oid:
                    raise _Failure("UNSUPPORTED_FORMAT", "APFS_KEY_ROLLING_UNSUPPORTED")
                if volume.is_sealed:
                    raise _Failure("UNSUPPORTED_FORMAT", "APFS_SEALED_VOLUME_UNVERIFIED")
                if volume.is_encrypted:
                    if not volume.is_onekey:
                        raise _Failure("UNSUPPORTED_FORMAT", "APFS_MULTIKEY_UNSUPPORTED")
                    if not password:
                        raise _Failure("SECRET_REQUIRED", "APFS_PASSWORD_REQUIRED")
                    try:
                        volume.unlock(password)
                    except Exception:
                        raise _Failure("AUTH_FAILED", "APFS_AUTH_FAILED") from None
                _check_object(volume.omap)
                _check_tree(volume.omap.btree, budget)
                _check_tree(volume.root_tree, budget, volume.omap, 0, volume.xid)
                if include_snapshots and volume.object.apfs_num_snapshots:
                    _check_tree(volume.snap_meta_tree, budget)

            destination.mkdir(parents=True, exist_ok=True)
            _no_reparse(destination)
            files_dir = destination / "apfs-files"
            files_dir.mkdir()
            owns_directory = True
            report = {"format": "APFS", "parser": "dissect.apfs==1.1", "status": "running",
                      "source_sha256": source_hash, "source_bytes": size, "source_offset_bytes": offset,
                      "container_bytes": container.block_count * container.block_size,
                      "container_id": str(container.uuid), "checkpoint_xid": int(container.sb.xid),
                      "checkpoint_fallback": any(sb.xid > container.sb.xid for sb in container.sbs),
                      "files": 0, "bytes": 0, "volumes": [], "warnings": [],
                      "limits": {"max_files": max_files, "max_file_bytes": max_file, "max_output_bytes": max_total,
                                 "max_snapshots": max_snapshots, "max_metadata_nodes": max_nodes, "max_metadata_bytes": max_metadata},
                      "limitations": ["LIVE_FILES_ARE_NOT_DELETED_RECOVERY", "SNAPSHOTS_ARE_PREVIOUS_REFERENCED_VERSIONS",
                                      "NO_UNREFERENCED_INODE_UNDELETE", "DATA_HASH_IS_COPY_IDENTITY_ONLY",
                                      "NO_FUSION_MULTIKEY_T2_OR_SEALED_VOLUME_GUARANTEE", "SYMLINKS_AND_SPECIAL_FILES_NOT_EXPORTED"]}

            def save(state, include_candidates=True):
                report.update(status=state, files=len(records), bytes=sum(item["bytes"] for item in records), warnings=sorted(warnings))
                if include_candidates:
                    _atomic_json(destination / "storage-candidates.json", records)
                _atomic_json(destination / "apfs-report.json", report)

            save("running")
            total_written, visited_entries, snapshots_seen, metadata_written = 0, 0, 0, 0

            def walk(volume, snapshot=None):
                nonlocal total_written, visited_entries, metadata_written
                stack, visited_dirs = [(volume.root, "/", 0)], set()
                while stack:
                    directory, parent_path, depth = stack.pop()
                    if depth > 256 or directory.oid in visited_dirs:
                        warnings.add("APFS_DIRECTORY_CYCLE_OR_DEPTH_SKIPPED")
                        continue
                    visited_dirs.add(directory.oid)
                    try:
                        children = directory.iterdir()
                        for entry in children:
                            visited_entries += 1
                            if visited_entries > max_files * 16:
                                raise _Limit()
                            name = entry.name
                            if not name or name in (".", "..") or "/" in name or "\0" in name or len(name) > 4096:
                                warnings.add("APFS_UNSAFE_NAME_SKIPPED")
                                continue
                            logical_path = parent_path.rstrip("/") + "/" + name
                            if len(logical_path) > 32768:
                                warnings.add("APFS_UNSAFE_NAME_SKIPPED")
                                continue
                            if entry.is_symlink() or not (entry.is_dir() or entry.is_file()):
                                # Intentional omissions, not an incomplete regular-file search.
                                continue
                            try:
                                node = entry.inode
                                if entry.is_dir() and node.is_dir():
                                    stack.append((node, logical_path, depth + 1))
                                    continue
                                if not entry.is_file() or not node.is_file() or node.is_symlink():
                                    warnings.add("APFS_RECORD_TYPE_MISMATCH")
                                    continue
                                amount = int(node.size)
                                if amount < 0 or amount > max_file or amount > max_total - total_written:
                                    warnings.add("APFS_FILE_OR_OUTPUT_LIMIT_REACHED")
                                    continue
                                if len(records) >= max_files:
                                    raise _Limit()
                                extension = Path(name).suffix
                                if not extension or len(extension) > 16 or not all(c.isascii() and (c.isalnum() or c == ".") for c in extension):
                                    extension = ".bin"
                                relative = "apfs-files/" + str(len(records) + 1).zfill(8) + extension.lower()
                                output = destination / relative
                                partial = output.with_name(output.name + ".partial")
                                digest, copied = hashlib.sha256(), 0
                                try:
                                    with partial.open("xb") as target, _open_file(node) as data:
                                        while copied < amount:
                                            chunk = data.read(min(1024 * 1024, amount - copied))
                                            if not chunk:
                                                raise _Failure("IO_ERROR", "APFS_SHORT_FILE_READ")
                                            target.write(chunk)
                                            copied += len(chunk)
                                            digest.update(chunk)
                                        if data.read(1):
                                            raise _Failure("INVALID_SOURCE", "APFS_FILE_SIZE_MISMATCH")
                                        target.flush()
                                        os.fsync(target.fileno())
                                    if os.name == "nt":
                                        os.rename(partial, output)
                                    else:
                                        os.link(partial, output)
                                        partial.unlink()
                                    published.append(output)
                                except Exception:
                                    partial.unlink(missing_ok=True)
                                    raise
                                record = {"path": relative, "name": name, "original_path": logical_path,
                                          "original_path_components": logical_path.lstrip("/").split("/"),
                                          "bytes": copied, "sha256": digest.hexdigest(), "filesystem": "APFS",
                                          "source_sha256": source_hash, "source_offset_bytes": offset,
                                          "volume_id": str(volume.uuid), "volume_name": volume.name,
                                          "record_id": int(node.oid), "inode": int(node.oid),
                                          "snapshot_id": str(snapshot.xid) if snapshot else None,
                                          "snapshot_xid": int(snapshot.xid) if snapshot else None,
                                          "snapshot_name": snapshot.name if snapshot else None,
                                          "checkpoint_xid": int(container.sb.xid),
                                          "checkpoint_fallback": report["checkpoint_fallback"],
                                          "origin": "previous-version" if snapshot or report["checkpoint_fallback"] else "existing",
                                          "deleted": None if snapshot or report["checkpoint_fallback"] else False,
                                          "validation": "metadata-checksum-and-readable-stream",
                                          "physical_ranges": None}
                                record_json = json.dumps(record, ensure_ascii=False) + "\n"
                                metadata_size = len(record_json.encode("utf-8"))
                                if metadata_size > max_metadata - metadata_written:
                                    output.unlink()
                                    published.pop()
                                    raise _Limit()
                                records.append(record)
                                journal.write(record_json)
                                metadata_written += metadata_size
                                total_written += copied
                                notify("export-files", files=len(records), bytes=total_written)
                                if len(records) % 25 == 0:
                                    journal.flush()
                                if len(records) % 1000 == 0:
                                    save("running", include_candidates=False)
                            except _Limit:
                                raise
                            except _Failure as failure:
                                warnings.add(failure.warning)
                                warnings.add("APFS_REFERENCED_FILE_UNREADABLE")
                            except Exception:
                                warnings.add("APFS_REFERENCED_FILE_UNREADABLE")
                    except _Limit:
                        raise
                    except Exception:
                        warnings.add("APFS_DIRECTORY_UNREADABLE")

            with _bounded_file_reads(), (destination / "apfs-candidates.journal.jsonl").open("x", encoding="utf-8", newline="\n") as journal:
                try:
                    for volume in volumes:
                        report["volumes"].append({"id": str(volume.uuid), "name": volume.name,
                                                  "encrypted": bool(volume.is_encrypted), "snapshots": int(volume.object.apfs_num_snapshots)})
                        notify("read-live-files")
                        walk(volume)
                        if include_snapshots and volume.object.apfs_num_snapshots:
                            for snapshot in sorted(volume.snapshots, key=lambda item: item.xid, reverse=prefer_recent):
                                if snapshots_seen >= max_snapshots:
                                    warnings.add("APFS_SNAPSHOT_LIMIT_REACHED")
                                    break
                                snapshots_seen += 1
                                try:
                                    previous = snapshot.open()
                                    _check_object(previous)
                                    if previous.is_encrypted:
                                        previous.unlock(password)
                                    _check_tree(previous.root_tree, budget, previous.omap, 0, previous.xid)
                                    notify("read-snapshot", snapshots=snapshots_seen)
                                    walk(previous, snapshot)
                                except _Limit:
                                    raise
                                except Exception:
                                    warnings.add("APFS_SNAPSHOT_UNREADABLE")
                except _Limit:
                    warnings.add("APFS_RESOURCE_LIMIT_REACHED")
            if _hash(original) != source_hash:
                raise _Failure("INVALID_SOURCE", "APFS_SOURCE_CHANGED")
            state = "partial" if warnings else "complete"
            report["snapshots_examined"] = snapshots_seen
            report["source_unchanged"] = True
            save(state)
            return {"status": state, "code": "PARTIAL_DATA" if warnings else "OK" if records else "NO_DATA",
                    "files": len(records), "media": len(records), "source_sha256": source_hash,
                    "archive": str(destination), "warnings": sorted(warnings)}
    except ImportError:
        failure = _Failure("DEPENDENCY_MISSING", "APFS_DEPENDENCY_MISSING")
    except _Failure as error:
        failure = error
    except _Limit:
        failure = _Failure("INVALID_SOURCE", "APFS_RESOURCE_LIMIT_REACHED")
    except (OSError, ValueError, TypeError, OverflowError):
        failure = _Failure("IO_ERROR", "APFS_SOURCE_OR_OUTPUT_ERROR")
    except Exception:
        failure = _Failure("INVALID_SOURCE", "APFS_STRUCTURE_UNREADABLE")
    # Only files owned by this invocation can be removed.  Failed source/auth
    # validation never leaves a successful report or published candidate set.
    if owns_directory and destination is not None:
        for path in published:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        for name in ("storage-candidates.json", "apfs-report.json", "apfs-candidates.journal.jsonl"):
            try:
                (destination / name).unlink(missing_ok=True)
                (destination / (name + ".partial")).unlink(missing_ok=True)
            except OSError:
                pass
    return {"status": "error", "code": failure.code, "files": 0, "media": 0, "archive": "", "warnings": [failure.warning]}
