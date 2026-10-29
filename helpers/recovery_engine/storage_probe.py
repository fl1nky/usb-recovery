# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded read-only discovery; detection is not successful filesystem parsing."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import struct
import zlib
import uuid


def _safe_source(value):
    path = Path(value).absolute()
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("INVALID_SOURCE")
    if not path.is_file() or path.suffix.lower() == ".partial":
        raise ValueError("INVALID_SOURCE")
    return path


def probe(request, emit=None):
    try:
        source = _safe_source(request["source"])
        with source.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            found, warnings = [], []

            def detect(offset, length, label):
                if offset < 0 or length < 512 or offset > size - length:
                    return
                handle.seek(offset)
                boot = handle.read(4096)
                kind = "APFS" if boot[32:36] == b"NXSB" else "BitLocker" if (boot[3:11] == b"-FVE-FS-" or any(uuid.UUID(value).bytes_le in boot[:512] for value in ("4967d63b-2e29-4ad8-8399-f6a339e3d001", "92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8"))) else None
                if kind:
                    found.append({"kind": kind, "name": label, "offset_bytes": offset,
                                  "length_bytes": length, "identifier": f"{offset}:{length}"})

            detect(0, size, "Образ тома")
            gpt_seen = False
            for sector in (512, 4096):
                if size < sector * 3:
                    continue
                handle.seek(sector)
                header = handle.read(sector)
                if header[:8] != b"EFI PART":
                    continue
                gpt_seen = True
                header_size = struct.unpack_from("<I", header, 12)[0]
                if not 92 <= header_size <= sector:
                    warnings.append("GPT_HEADER_INVALID")
                    continue
                header_bytes = bytearray(header[:header_size])
                expected_crc = struct.unpack_from("<I", header, 16)[0]
                header_bytes[16:20] = b"\0" * 4
                table_lba, count, entry_size, table_crc = struct.unpack_from("<QIII", header, 72)
                if zlib.crc32(header_bytes) != expected_crc or count > 4096 or not 128 <= entry_size <= 4096:
                    warnings.append("GPT_HEADER_INVALID")
                    continue
                total = count * entry_size
                if total > 16 * 1024 * 1024 or table_lba * sector > size - total:
                    warnings.append("GPT_TABLE_INVALID")
                    continue
                handle.seek(table_lba * sector)
                table = handle.read(total)
                if len(table) != total or zlib.crc32(table) != table_crc:
                    warnings.append("GPT_TABLE_INVALID")
                    continue
                for index in range(count):
                    entry = table[index * entry_size:(index + 1) * entry_size]
                    if not any(entry[:16]):
                        continue
                    first, last = struct.unpack_from("<QQ", entry, 32)
                    if first > last or first < 2 or last >= size // sector:
                        warnings.append("PARTITION_RANGE_INVALID")
                        continue
                    detect(first * sector, (last - first + 1) * sector, f"GPT · раздел {index + 1}")
                break
            if not gpt_seen and size >= 512:
                handle.seek(0)
                mbr = handle.read(512)
                if mbr[510:512] == b"\x55\xaa":
                    for index in range(4):
                        entry = mbr[446 + index * 16:462 + index * 16]
                        first, count = struct.unpack_from("<II", entry, 8)
                        if entry[4] and count:
                            detect(first * 512, count * 512, f"MBR · раздел {index + 1}")
            unique = {(item["kind"], item["offset_bytes"]): item for item in found}
            return {"status": "partial" if warnings else "complete", "code": "PARTIAL_DATA" if warnings else "OK",
                    "volumes": list(unique.values()), "warnings": sorted(set(warnings)),
                    "source_bytes": size, "detection_only": True}
    except (OSError, ValueError, TypeError, KeyError):
        return {"status": "error", "code": "INVALID_SOURCE", "volumes": []}
