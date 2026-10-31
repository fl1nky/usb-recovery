"""Independent byte oracle for actual native SQLite rollback overflow fixtures.

Reads only owned corpus and immutable before DB. No recovery or fixture-writer
imports; SQLite btree/record decoding below verifies the long data column and
that every byte of its payload exists in validated journal page before-images.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def sha(data):
    return hashlib.sha256(data).hexdigest()


def varint(data, offset):
    result = 0
    for index in range(9):
        byte = data[offset + index]
        result = (result << (8 if index == 8 else 7)) | (byte if index == 8 else byte & 127)
        if index == 8 or byte < 128:
            return result, offset + index + 1
    raise AssertionError("unreachable")


def serial_bytes(serial):
    if serial in (0, 8, 9):
        return 0
    if serial in (1, 2, 3, 4, 5, 6, 7):
        return (1, 2, 3, 4, 6, 8, 8)[serial - 1]
    assert serial >= 12
    return (serial - (12 if serial % 2 == 0 else 13)) // 2


def row_payload(database, root_page, target_rowid):
    page_size = int.from_bytes(database[16:18], "big")
    page_size = 65536 if page_size == 1 else page_size
    usable = page_size - database[20]
    number = root_page
    visited = set()
    while True:
        assert number not in visited
        visited.add(number)
        page = database[(number - 1) * page_size:number * page_size]
        header = 100 if number == 1 else 0
        kind = page[header]
        count = int.from_bytes(page[header + 3:header + 5], "big")
        start = header + (12 if kind == 5 else 8)
        pointers = [int.from_bytes(page[start + 2 * index:start + 2 * index + 2], "big") for index in range(count)]
        if kind == 5:
            child = int.from_bytes(page[header + 8:header + 12], "big")
            for pointer in pointers:
                split, _ = varint(page, pointer + 4)
                if target_rowid <= split:
                    child = int.from_bytes(page[pointer:pointer + 4], "big")
                    break
            number = child
            continue
        assert kind == 13
        for pointer in pointers:
            size, cursor = varint(page, pointer)
            rowid, cursor = varint(page, cursor)
            if rowid != target_rowid:
                continue
            maximum = usable - 35
            minimum = ((usable - 12) * 32 // 255) - 23
            local = size if size <= maximum else minimum + ((size - minimum) % (usable - 4))
            if local > maximum:
                local = minimum
            payload = bytearray(page[cursor:cursor + local])
            pieces = [{"page": number, "offset": cursor, "bytes": local, "payload_offset": 0}]
            overflow = []
            next_page = int.from_bytes(page[cursor + local:cursor + local + 4], "big") if size > local else 0
            while len(payload) < size:
                assert next_page and next_page not in visited
                visited.add(next_page)
                overflow.append(next_page)
                value = database[(next_page - 1) * page_size:next_page * page_size]
                take = min(size - len(payload), usable - 4)
                pieces.append({"page": next_page, "offset": 4, "bytes": take, "payload_offset": len(payload)})
                payload.extend(value[4:4 + take])
                next_page = int.from_bytes(value[:4], "big")
            assert next_page == 0 and len(payload) == size
            return bytes(payload), pieces, overflow, number, page_size
        raise AssertionError("target row not found")


def verify(corpus):
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    assert manifest["fixture_profile"] == "native_partial_overflow"
    outcomes = []
    for case in manifest["cases"]:
        assert len(case["expected_text"].encode()) > 5000
        before_path = corpus / "references" / (case["name"] + "-before.sqlite")
        before = before_path.read_bytes()
        assert sha(before) == case["before_sha256"]
        connection = sqlite3.connect(before_path.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            root_page = connection.execute("SELECT rootpage FROM sqlite_schema WHERE name='messages'").fetchone()[0]
            columns = [value[1] for value in connection.execute("PRAGMA table_info(messages)")]
            blob_from_sqlite = connection.execute("SELECT data FROM messages WHERE mid=21 AND uid=77").fetchone()[0]
        finally:
            connection.close()
        payload, pieces, overflow, leaf, page_size = row_payload(before, root_page, 21)
        assert page_size == 512 and overflow
        header_size, offset = varint(payload, 0)
        serials = []
        while offset < header_size:
            serial, offset = varint(payload, offset)
            serials.append(serial)
        assert offset == header_size and len(serials) == len(columns)
        data_index = columns.index("data")
        blob_start = header_size + sum(serial_bytes(serial) for serial in serials[:data_index])
        blob_length = serial_bytes(serials[data_index])
        blob = payload[blob_start:blob_start + blob_length]
        assert blob == blob_from_sqlite and sha(blob) == case["expected_blob_sha256"]
        journal = (corpus / case["name"] / "cache4.db-journal").read_bytes()
        assert sha(journal) == case["source_files"]["cache4.db-journal"]
        records = {record["page"]: record for record in case["journal_records"]}
        mappings = []
        rebuilt = bytearray()
        for piece in pieces:
            record = records[piece["page"]]
            data = journal[record["data_offset"]:record["data_offset"] + page_size]
            assert data == before[(piece["page"] - 1) * page_size:piece["page"] * page_size]
            header = record["header_offset"]
            nonce = int.from_bytes(journal[header + 12:header + 16], "big")
            stored = int.from_bytes(journal[record["data_offset"] + page_size:record["data_offset"] + page_size + 4], "big")
            assert stored == (nonce + sum(data[index] for index in range(page_size - 200, 0, -200))) & 0xffffffff
            offset = record["data_offset"] + piece["offset"]
            part = journal[offset:offset + piece["bytes"]]
            assert len(rebuilt) == piece["payload_offset"]
            rebuilt.extend(part)
            mappings.append(dict(piece, journal_offset=offset, sha256=sha(part)))
        assert bytes(rebuilt) == payload
        assert len(records) < case["initial_pages"] and 1 in records
        outcomes.append({"name": case["name"], "page_size": page_size, "initial_pages": case["initial_pages"],
            "journal_pages": sorted(records), "leaf_page": leaf, "overflow_pages": overflow,
            "payload_bytes": len(payload), "payload_sha256": sha(payload), "blob_payload_offset": blob_start,
            "blob_bytes": blob_length, "blob_sha256": sha(blob), "old_text_utf8_bytes": len(case["expected_text"].encode()),
            "all_payload_pages_in_journal": True, "payload_equal_to_before_image": True, "physical_segments": mappings})
    return {"schema": 1, "status": "passed", "scope": "Independent own SQLite before-image btree/overflow/data-column byte oracle; no recovery/writer imports",
            "manifest_sha256": sha(manifest_path.read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()), "cases": outcomes}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    result = verify(arguments.corpus.resolve())
    with arguments.out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "cases": len(result["cases"])}))
