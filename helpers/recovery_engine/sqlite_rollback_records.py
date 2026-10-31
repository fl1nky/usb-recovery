"""Unattributed TL candidates from verified SQLite rollback page before-images.

Only journal-owned pages participate. Partial journals never establish a table,
account, sender, date or deletion, even when a complete SQLite cell survives.
Overflow geometry comes from the journal's old page one, never a nearby DB.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass
import hashlib
import re
import struct

from sqlite_history import HistoryError, _safe_path, _state, _sha256, _db_header
from sqlite_rollback import RollbackError, iter_validated_pages
from telegram_tl import parse_message, TelegramTlError, PROFILES

_CONSTRUCTORS = re.compile(b"|".join(re.escape(struct.pack("<I", value)) for value in PROFILES))


@dataclass(frozen=True, slots=True)
class FragmentLimits:
    max_scan_bytes: int = 256 * 1024 * 1024
    max_payload_bytes: int = 4 * 1024 * 1024
    max_chain_pages: int = 4096
    max_candidates: int = 200000
    max_records: int = 20000
    max_output_bytes: int = 64 * 1024 * 1024


def _limits(value):
    if value is None:
        return FragmentLimits()
    try:
        result = FragmentLimits(**value) if isinstance(value, dict) else value
    except TypeError:
        raise RollbackError("INVALID_LIMITS") from None
    if not isinstance(result, FragmentLimits) or any(
            type(getattr(result, name)) is not int or not 0 < getattr(result, name) <= cap
            for name, cap in asdict(FragmentLimits()).items()):
        raise RollbackError("INVALID_LIMITS")
    return result


def _cancel(cancel):
    if cancel is not None and cancel():
        raise RollbackError("CANCELLED")


def _varint(data, offset, end):
    value = 0
    for index in range(9):
        if offset >= end:
            raise ValueError("varint truncated")
        byte = data[offset]
        offset += 1
        if index == 8:
            return (value << 8) | byte, offset
        value = (value << 7) | (byte & 127)
        if byte < 128:
            if index and value < 1 << (index * 7):
                raise ValueError("noncanonical varint")
            return value, offset
    raise ValueError("varint invalid")


def _blob_fields(payload):
    """SQLite record framing only; no guessed SQL column names or row IDs."""
    size, at = _varint(payload, 0, len(payload))
    if not at <= size <= min(len(payload), 128 * 9 + 9):
        raise ValueError("record header invalid")
    serials = []
    while at < size:
        serial, at = _varint(payload, at, size)
        if serial in (10, 11) or len(serials) >= 128:
            raise ValueError("record serial invalid")
        serials.append(serial)
    if at != size or not serials:
        raise ValueError("record header invalid")
    fields = []
    at = size
    for serial in serials:
        length = (0, 1, 2, 3, 4, 6, 8, 8, 0, 0)[serial] if serial < 10 else (serial - 12) // 2
        if length < 0 or at + length > len(payload):
            raise ValueError("record payload truncated")
        if serial >= 12 and serial % 2 == 0 and length:
            fields.append((at, length))
        at += length
    if at != len(payload):
        raise ValueError("record payload length mismatch")
    return fields


def _physical(ranges, offset):
    for value in ranges:
        if value["logical_offset"] <= offset < value["logical_offset"] + value["bytes"]:
            return value["physical_byte_offset"] + offset - value["logical_offset"]
    raise ValueError("payload offset outside map")


def _tl_candidate(blob):
    value = parse_message(blob, allow_trailing=True)
    if not value["text"]:
        return None
    return dict(text=value["text"], byte_offset=0, byte_length=value["tl_bytes"],
                encoding="telegram_tl_utf8", application_confirmed=True,
                candidate_message_id=value["id"], candidate_peer=value["peer"],
                candidate_date=value["date"], native_constructor=value["constructor"],
                native_layer=value["layer"],
                native_tl_body_sha256=hashlib.sha256(blob[:value["tl_bytes"]]).hexdigest(),
                proof="supported_tl_body_without_confirmed_table_or_account")


def recover_fragments(journal, parsed, *, matcher=None, cancel=None, limits=None, report=None):
    """Return staged candidates only after complete source consistency checks.

    A checksum-valid prefix can yield fragments after an invalid tail, but can
    never be promoted to a complete snapshot by this function.
    """
    limits = _limits(limits)
    report = {} if report is None else report
    report.clear()
    report.update(scanned_pages=0, candidates_checked=0, payloads_checked=0,
                  overflow_payloads=0, fragments=0, limited=False,
                  overflow_geometry_known=False, scan_bytes=0)
    try:
        path = _safe_path(journal, regular=True)
        before = _state(path)
        values, index, seen = [], {}, set()
        output_bytes = 0
        first = None

        def add(value, record, ranges=None, payload=None):
            nonlocal output_bytes
            text = value["text"]
            if matcher is not None and not matcher(text):
                return
            amount = len(text.encode("utf-8"))
            if len(values) >= limits.max_records or amount > limits.max_output_bytes - output_bytes:
                report["limited"] = True
                return
            physical = value["byte_offset"]
            key = (physical, value["native_tl_body_sha256"])
            if key in seen:
                return
            seen.add(key)
            output_bytes += amount
            value.update(sqlite_page=record["page"], sqlite_region="rollback_before_image",
                         physical_source="rollback_journal", physical_byte_offset=physical,
                         rollback_header_offset=record["header_offset"],
                         rollback_record_offset=record["record_offset"],
                         rollback_page=record["page"],
                         offset_kind="rollback_journal_file_byte" if ranges is None else "rollback_payload_chain",
                         chat_id=None, sender_id=None, sender_name=None, message_id=None,
                         timestamp=None, deleted=None, deletion_interpretation="unknown",
                         recovery_status="unattributed_structured_fragment")
            if ranges is not None:
                value.update(rollback_payload_ranges=ranges,
                             rollback_payload_length=len(payload),
                             rollback_payload_sha256=hashlib.sha256(payload).hexdigest(),
                             rollback_payload_chain_verified=True)
            values.append(value)

        # Exhaust this validating iterator even after a result/scan limit, so
        # source changes cannot leave an apparently successful partial result.
        for record, data in iter_validated_pages(path, parsed, cancel=cancel):
            index[record["page"]] = record
            if record["page"] == 1:
                first = data
            if report["scan_bytes"] + len(data) > limits.max_scan_bytes:
                report["limited"] = True
                continue
            report["scan_bytes"] += len(data)
            report["scanned_pages"] += 1
            if len(values) < limits.max_records and not report["limited"]:
                for match in _CONSTRUCTORS.finditer(data):
                    _cancel(cancel)
                    if report["candidates_checked"] >= limits.max_candidates:
                        report["limited"] = True
                        break
                    report["candidates_checked"] += 1
                    try:
                        value = _tl_candidate(data[match.start():])
                    except (TelegramTlError, ValueError, OverflowError):
                        continue
                    if value is not None:
                        value["byte_offset"] = record["data_offset"] + match.start()
                        add(value, record)
                    if report["limited"] or len(values) >= limits.max_records:
                        report["limited"] = True
                        break

        page_size = parsed.get("page_size")
        initial_pages = parsed.get("initial_pages")
        usable = None
        if first is not None and type(page_size) is int and type(initial_pages) is int:
            try:
                checked = _db_header(first[:100], page_size * initial_pages)
                if checked == page_size:
                    usable = page_size - first[20]
                    report["overflow_geometry_known"] = True
            except HistoryError:
                pass
        cache = OrderedDict()
        with path.open("rb") as source:
            def page(number):
                _cancel(cancel)
                if number in cache:
                    cache.move_to_end(number)
                    return cache[number]
                record = index.get(number)
                if record is None:
                    raise ValueError("overflow page missing from journal")
                if report["scan_bytes"] + page_size > limits.max_scan_bytes:
                    report["limited"] = True
                    raise ValueError("scan limit")
                source.seek(record["data_offset"])
                data = source.read(page_size)
                report["scan_bytes"] += len(data)
                if len(data) != page_size or hashlib.sha256(data).hexdigest() != record["page_sha256"]:
                    raise RollbackError("ROLLBACK_SOURCE_CHANGED")
                cache[number] = data
                if len(cache) > 16:
                    cache.popitem(last=False)
                return data

            if usable is not None and not report["limited"]:
                for number, record in index.items():
                    _cancel(cancel)
                    if report["limited"]:
                        break
                    data = page(number)
                    header = 100 if number == 1 else 0
                    if len(data) < header + 8 or data[header] != 13:
                        continue
                    count = int.from_bytes(data[header + 3:header + 5], "big")
                    pointers_end = header + 8 + 2 * count
                    content_start = int.from_bytes(data[header + 5:header + 7], "big") or 65536
                    if pointers_end > usable or not pointers_end <= content_start <= usable or data[header + 7] > 60:
                        continue
                    starts = [int.from_bytes(data[header + 8 + 2 * i:header + 10 + 2 * i], "big") for i in range(count)]
                    if len(set(starts)) != len(starts) or any(not content_start <= at < usable for at in starts):
                        continue
                    ordered = sorted(starts)
                    ends = dict(zip(ordered, ordered[1:] + [usable]))
                    freeblocks = []
                    free = int.from_bytes(data[header + 1:header + 3], "big")
                    valid_free = True
                    while free:
                        if not content_start <= free <= usable - 4 or len(freeblocks) >= usable // 4:
                            valid_free = False
                            break
                        following = int.from_bytes(data[free:free + 2], "big")
                        amount = int.from_bytes(data[free + 2:free + 4], "big")
                        if amount < 4 or free + amount > usable or following and not free + amount <= following <= usable - 4:
                            valid_free = False
                            break
                        freeblocks.append((free, free + amount))
                        free = following
                    if not valid_free:
                        continue
                    for start in starts:
                        _cancel(cancel)
                        if report["candidates_checked"] >= limits.max_candidates or len(values) >= limits.max_records:
                            report["limited"] = True
                            break
                        report["candidates_checked"] += 1
                        try:
                            length, at = _varint(data, start, usable)
                            _, at = _varint(data, at, usable)  # rowid stays unknown
                            if not 1 <= length <= limits.max_payload_bytes:
                                continue
                            maximum = usable - 35
                            minimum = ((usable - 12) * 32 // 255) - 23
                            local = length if length <= maximum else minimum + (length - minimum) % (usable - 4)
                            if length > maximum and local > maximum:
                                local = minimum
                            cell_end = at + local + (4 if local < length else 0)
                            if cell_end > ends[start] or any(start < right and cell_end > left for left, right in freeblocks):
                                continue
                            payload = bytearray(data[at:at + local])
                            ranges = [dict(logical_offset=0, bytes=local, sqlite_page=number,
                                           physical_source="rollback_journal", physical_byte_offset=record["data_offset"] + at)]
                            visited = {number}
                            pointer = int.from_bytes(data[at + local:at + local + 4], "big") if local < length else 0
                            while len(payload) < length:
                                if not 1 <= pointer <= initial_pages or pointer in visited or len(visited) >= limits.max_chain_pages:
                                    raise ValueError("overflow chain invalid")
                                visited.add(pointer)
                                block = page(pointer)
                                take = min(usable - 4, length - len(payload))
                                ranges.append(dict(logical_offset=len(payload), bytes=take, sqlite_page=pointer,
                                                   physical_source="rollback_journal", physical_byte_offset=index[pointer]["data_offset"] + 4))
                                payload.extend(block[4:4 + take])
                                pointer = int.from_bytes(block[:4], "big")
                            if pointer:
                                raise ValueError("overflow chain has unused tail")
                            fields = _blob_fields(payload)
                            report["payloads_checked"] += 1
                            if len(ranges) > 1:
                                report["overflow_payloads"] += 1
                            for offset, amount in fields:
                                if report["candidates_checked"] >= limits.max_candidates:
                                    report["limited"] = True
                                    break
                                report["candidates_checked"] += 1
                                try:
                                    blob = bytes(payload[offset:offset + amount])
                                    candidate = _tl_candidate(blob)
                                except (TelegramTlError, ValueError, OverflowError):
                                    continue
                                if candidate is None:
                                    continue
                                candidate["byte_offset"] = _physical(ranges, offset)
                                add(candidate, record, ranges if len(ranges) > 1 else None,
                                    payload if len(ranges) > 1 else None)
                        except RollbackError:
                            raise
                        except (ValueError, OverflowError):
                            continue
        _cancel(cancel)
        if _state(path) != before or _sha256(path, cancel) != parsed.get("journal_sha256"):
            raise RollbackError("ROLLBACK_SOURCE_CHANGED")
        report["fragments"] = len(values)
        return values
    except HistoryError as error:
        raise RollbackError(error.code) from None
