"""Own real SQLite rollback journals; no recovery decoder imports.

The pass-through SQLite VFS captures bytes immediately before journal deletion
at a normal COMMIT, after SQLite has synced the DB and journal. No journal header,
nonce or record is fabricated for positive cases. All databases are newly made.
Official layouts/wire writers are shared only with independent fixture builders.
"""
from __future__ import annotations

import ctypes as ct
import ctypes.util
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import uuid

from build_telegram_legacy_fixtures import SCHEMA, message as legacy_message, DATE
from build_telegram_native_fixtures import message as modern_message
from build_telegram_wal_tail_fixtures import COLUMNS

MAGIC = bytes.fromhex("d9d505f920a163d7")
OLD = "Старый рецепт из журнала SQLite 🥧\nпрабабушка: две ложки масла"
NEW = "Updated owned recipe; this is not the old journal text"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inspect(raw):
    """Independent fixture receipt, not the production parser."""
    pages = {}; records = []; headers = []; offset = 0
    while offset + 28 <= len(raw) and raw[offset:offset + 8] == MAGIC:
        count, nonce, total, sector, page = struct.unpack(">5I", raw[offset + 8:offset + 28])
        headers.append({"offset": offset, "count": count, "nonce": nonce})
        if count in (0, 0xffffffff):
            break
        assert 512 <= page <= 65536 and page & (page - 1) == 0
        assert 32 <= sector <= 65536 and sector & (sector - 1) == 0
        cursor = offset + sector
        for _ in range(count):
            number = int.from_bytes(raw[cursor:cursor + 4], "big")
            data = raw[cursor + 4:cursor + 4 + page]
            expected = int.from_bytes(raw[cursor + 4 + page:cursor + 8 + page], "big")
            actual = (nonce + sum(data[page - 200:0:-200])) & 0xffffffff
            assert len(data) == page and expected == actual
            assert number > 0 and number not in pages
            pages[number] = data
            records.append({"page": number, "record_offset": cursor, "data_offset": cursor + 4,
                            "bytes": page, "header_offset": offset, "sha256": sha(data)})
            cursor += page + 8
        offset = (cursor + sector - 1) // sector * sector
    return {"headers": headers, "records": records, "pages": pages,
            "initial_pages": total if headers else None}


class _Vfs(ct.Structure):
    _fields_ = [("version", ct.c_int), ("file_size", ct.c_int), ("max_path", ct.c_int),
                ("next", ct.c_void_p), ("name", ct.c_char_p), ("app", ct.c_void_p)] + [
        (name, ct.c_void_p) for name in ("open", "delete", "access", "fullpath", "dlopen", "dlerror",
        "dlsym", "dlclose", "random", "sleep", "time", "error", "time64", "setsystem", "getsystem", "nextsystem")]


class Capture:
    """Forward every SQLite operation; observe only the chosen own journal."""
    def __init__(self):
        library = Path(sys.base_prefix) / "DLLs/sqlite3.dll"
        self.lib = ct.CDLL(str(library) if library.is_file() else ctypes.util.find_library("sqlite3"))
        self.lib.sqlite3_libversion.restype = ct.c_char_p
        self.version = self.lib.sqlite3_libversion().decode()
        if self.version != sqlite3.sqlite_version:
            raise RuntimeError("SQLITE_FIXTURE_RUNTIME_MISMATCH")
        self.lib.sqlite3_vfs_find.argtypes = [ct.c_char_p]
        self.lib.sqlite3_vfs_find.restype = ct.POINTER(_Vfs)
        self.original = self.lib.sqlite3_vfs_find(None)
        if self.original.contents.version != 3:
            raise RuntimeError("SQLITE_FIXTURE_VFS_VERSION_UNSUPPORTED")
        self.vfs = _Vfs()
        ct.memmove(ct.byref(self.vfs), self.original, ct.sizeof(_Vfs))
        self.name = ("owned-rollback-" + uuid.uuid4().hex).encode()
        self.vfs.name = self.name; self.vfs.next = None
        callback_type = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_char_p, ct.c_int)
        self.forward_delete = callback_type(self.original.contents.delete)
        self.path = None; self.captured = []; self.errors = []
        @callback_type
        def deleting(vfs, path, sync):
            try:
                if self.path is not None and os.path.normcase(os.path.abspath(os.fsdecode(path))) == os.path.normcase(str(self.path) + "-journal"):
                    self.captured.append((self.path.read_bytes(), Path(str(self.path) + "-journal").read_bytes()))
                return self.forward_delete(self.original, path, sync)
            except BaseException:
                self.errors.append("OWN_CAPTURE_CALLBACK_FAILED")
                return 10
        self.callback = deleting
        self.vfs.delete = ct.cast(deleting, ct.c_void_p).value
        self.lib.sqlite3_vfs_register.argtypes = [ct.POINTER(_Vfs), ct.c_int]
        self.lib.sqlite3_vfs_unregister.argtypes = [ct.POINTER(_Vfs)]
        self.lib.sqlite3_open_v2.argtypes = [ct.c_char_p, ct.POINTER(ct.c_void_p), ct.c_int, ct.c_char_p]
        self.lib.sqlite3_exec.argtypes = [ct.c_void_p, ct.c_char_p, ct.c_void_p, ct.c_void_p, ct.c_void_p]
        self.lib.sqlite3_close.argtypes = [ct.c_void_p]
        if self.lib.sqlite3_vfs_register(ct.byref(self.vfs), 0):
            raise RuntimeError("OWN_VFS_REGISTER_FAILED")

    def close(self):
        self.lib.sqlite3_vfs_unregister(ct.byref(self.vfs))

    def make(self, path, *, full=False, update=False, wide=False, page=512, persist=False, old_text=OLD):
        db = ct.c_void_p()
        if self.lib.sqlite3_open_v2(str(path).encode(), ct.byref(db), 6, self.name):
            raise RuntimeError("OWN_DB_OPEN_FAILED")
        def sql(value):
            if self.lib.sqlite3_exec(db, value.encode(), None, None, None):
                raise RuntimeError("OWN_SQLITE_STATEMENT_FAILED")
        table = "messages_v2" if wide else "messages"
        def body(text, mid=21):
            return modern_message(text, mid=mid) if wide else legacy_message(text, mid=mid, profile=114)
        try:
            sql(f"PRAGMA page_size={page};PRAGMA journal_mode={'PERSIST' if persist else 'DELETE'};"
                "PRAGMA synchronous=FULL;PRAGMA secure_delete=ON;PRAGMA cache_size=1;PRAGMA cache_spill=ON;")
            sql("CREATE TABLE " + table + "(" + (COLUMNS + ",PRIMARY KEY(mid,uid)" if wide else SCHEMA) + ");BEGIN;")
            for mid in [21] + list(range(100, 107)):
                text = old_text if mid == 21 else "Owned other row " + str(mid) + " filler" * 5
                sql(f"INSERT INTO {table}(mid,uid,date,data) VALUES({mid},77,{DATE},X'{body(text, mid).hex()}');")
            if not full:
                sql("CREATE TABLE unrelated(payload BLOB);")
                for index in range(70):
                    sql("INSERT INTO unrelated VALUES(X'" + (bytes([index]) * 300).hex() + "');")
            sql("COMMIT;")
            before = path.read_bytes()
            self.path = path; self.captured = []
            sql("BEGIN IMMEDIATE;")
            if update:
                sql(f"UPDATE {table} SET data=X'{body(NEW).hex()}' WHERE mid=21;")
            else:
                sql("DELETE FROM " + table + (";" if full else " WHERE mid=21;"))
            if full:
                sql("PRAGMA user_version=1234;")
            sql("COMMIT;")
            self.path = None
            if persist:
                main, journal = path.read_bytes(), Path(str(path) + "-journal").read_bytes()
            else:
                if self.errors or len(self.captured) != 1:
                    raise RuntimeError("OWN_CAPTURE_NOT_EXACTLY_ONCE")
                main, journal = self.captured[0]
            return main, journal, before, table, body(old_text)
        finally:
            self.path = None
            self.lib.sqlite3_close(db)


def build(destination, *, overflow=False):
    root = Path(destination).resolve(); root.mkdir(parents=True, exist_ok=False)
    cases = []; writer = Capture()
    target_text = OLD + "\n" + ("Own long SQLite journal overflow recipe row: προτυπο 🙂\n" * 140) if overflow else OLD
    def save(name, main, journal, old, table, blob, *, expected_full=False, mutation=None, standalone=False, expected_journal_result=None):
        folder = root / name; folder.mkdir()
        if not standalone:
            (folder / "cache4.db").write_bytes(main)
        (folder / "cache4.db-journal").write_bytes(journal)
        facts = inspect(journal) if mutation is None and journal[:8] == MAGIC else None
        exact = False
        if facts:
            covered = facts["pages"]
            exact = len(covered) == len(old) // int.from_bytes(old[16:18], "big") and all(
                covered.get(i + 1) == old[i * len(old) // facts["initial_pages"]:(i + 1) * len(old) // facts["initial_pages"]]
                for i in range(facts["initial_pages"]))
            assert exact == expected_full, (name, "coverage expectation")
        files = {p.name: sha(p.read_bytes()) for p in folder.iterdir()}
        reference = root / "references"; reference.mkdir(exist_ok=True)
        (reference / (name + "-before.sqlite")).write_bytes(old)
        cases.append({"name": name, "path": name + ("/cache4.db-journal" if standalone else "/cache4.db"),
                      "source_files": files, "expected_full_snapshot": expected_full,
                      "expected_journal_result": expected_journal_result or ("complete_snapshot" if expected_full else "unattributed_fragment"),
                      "positive_header_origin": "SQLite native VFS capture" if mutation is None else None,
                      "mutation": mutation, "standalone": standalone, "table": table,
                      "before_sha256": sha(old), "expected_text": target_text, "expected_text_sha256": sha(target_text.encode()),
                      "expected_text_utf8_bytes": len(target_text.encode()),
                      "expected_blob_sha256": sha(blob), "message_id": 21, "chat_id": 77,
                      "journal_headers": facts["headers"] if facts else None,
                      "journal_records": facts["records"] if facts else None,
                      "initial_pages": facts["initial_pages"] if facts else None,
                      "covered_pages": sorted(facts["pages"]) if facts else None,
                      "byte_exact_before_image": exact})
    try:
        with tempfile.TemporaryDirectory(prefix="own-rollback-writer-", dir=root.parent) as temporary:
            scratch = Path(temporary)
            bases = {}
            # `full` selects a compact DB and all-row DELETE, not journal coverage.
            # SQLite only dirties two of four pages for the compact UPDATE; keep
            # that genuine partial case rather than fabricating a full journal.
            case_specs = (("partial-overflow-delete", {"old_text": target_text}, False),
                          ("partial-overflow-update", {"old_text": target_text, "update": True}, False)) if overflow else (
                                  ("full-delete", {"full": True}, True),
                                  ("partial-compact-update", {"full": True, "update": True}, False),
                                  ("partial-delete", {}, False), ("partial-update", {"update": True}, False),
                                  ("partial-wide", {"wide": True}, False), ("persist-zero", {"persist": True}, False))
            for name, options, expected_full in case_specs:
                path = scratch / (name + ".sqlite")
                record = writer.make(path, **options); bases[name] = record
                save(name, *record, expected_full=expected_full,
                     mutation="real_PERSIST_zero_header" if options.get("persist") else None,
                     expected_journal_result="unsupported_zeroed_header" if options.get("persist") else None)
            if not overflow:
                main, journal, old, table, blob = bases["full-delete"]
                save("full-standalone", main, journal, old, table, blob, expected_full=True, standalone=True)
                for name, offset, value in (("bad-magic", 0, b"BROKEN!!"), ("zero-count", 8, b"\0" * 4),
                                        ("sentinel-count", 8, b"\xff" * 4)):
                    changed = journal[:offset] + value + journal[offset + len(value):]
                    save(name, main, changed, old, table, blob, mutation=name,
                     expected_journal_result="invalid_magic" if name == "bad-magic" else "unsupported_record_count")
                first = inspect(journal)["records"][0]
                offset = first["data_offset"] + first["bytes"]
                changed = bytearray(journal); changed[offset] ^= 1
                save("bad-checksum", main, bytes(changed), old, table, blob, mutation="checksum_bit_flip", expected_journal_result="invalid_checksum")
                save("torn-record", main, journal[:-100], old, table, blob, mutation="truncated_final_record", expected_journal_result="invalid_truncated_record")
                super_name = b"DO_NOT_FOLLOW_SYNTHETIC_SUPER_JOURNAL"
                footer = struct.pack(">I", 0x40000000 // 512 + 1) + super_name + struct.pack(">II", len(super_name), sum(super_name)) + MAGIC
                save("super-journal", main, journal + footer, old, table, blob, mutation="explicit_super_journal_control", expected_journal_result="unsupported_super_journal")
                partial = bases["partial-delete"]
            # A genuinely different, independently created current database. It
            # must not lend uid/author/date values to the old partial journal.
                foreign_path = scratch / "foreign-current.sqlite"
                with sqlite3.connect(foreign_path) as foreign_db:
                    foreign_db.execute("CREATE TABLE messages(" + SCHEMA + ")")
                    foreign_db.execute("INSERT INTO messages(mid,uid,date,data) VALUES(?,?,?,?)",
                    (21, 99, DATE, legacy_message("Unrelated owned current account", mid=21, peer=99, profile=114)))
                foreign_db.close()
                save("foreign-paired", foreign_path.read_bytes(), *partial[1:], mutation="independent_foreign_current_database",
                 expected_journal_result="unattributed_fragment")
    finally:
        writer.close()
    result = {"schema": 1, "scope": "Own synthetic SQLite transactions; no phone/profile data. Positive headers emitted by SQLite, not fabricated.",
              "sqlite_version": writer.version, "generator_sha256": sha(Path(__file__).read_bytes()),
              "fixture_profile": "native_partial_overflow" if overflow else "native_full_partial_and_controls",
              "android_legacy_commit": "f424ea165af4e868391b24640d2e715d1a45ce3c",
              "android_wide_commit": "4de548e79fed27f1a66fbdff84223321838fe925", "cases": cases}
    (root / "manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    parser.add_argument("--overflow", action="store_true")
    args = parser.parse_args()
    build(args.destination, overflow=args.overflow)
