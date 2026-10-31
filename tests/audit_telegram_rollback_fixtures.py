"""Independent stdlib verification and frozen-helper baseline of owned journals.

No recovery decoder or fixture generator is imported. Positive journal pages are
checked against independently preserved pre-transaction SQLite database bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import subprocess
from datetime import datetime, timezone

MAGIC = bytes.fromhex("d9d505f920a163d7")
V8_HELPER = "29e66798fd750c6672046bc8178aac54184ae3391e0a4ff8fd0d563f0c1f9786"


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def files(root):
    return {str(path.relative_to(root)).replace("\\", "/"):
            {"bytes": path.stat().st_size, "sha256": digest(path)}
            for path in sorted(root.rglob("*")) if path.is_file()}


def journal(raw):
    """Native finite-record segments only; independently compute sparse CRC."""
    cursor = 0
    pages = {}
    segments = []
    records = []
    initial = None
    while cursor + 28 <= len(raw) and raw[cursor:cursor + 8] == MAGIC:
        count, nonce, size, sector, page = struct.unpack_from(">IIIII", raw, cursor + 8)
        assert 0 < count < 0xffffffff and 0 < size <= 262144
        assert 512 <= page <= 65536 and page & (page - 1) == 0
        assert 32 <= sector <= 65536 and sector & (sector - 1) == 0
        assert initial in (None, size)
        initial = size
        segments.append({"offset": cursor, "count": count, "nonce": nonce})
        record = cursor + sector
        assert record + count * (page + 8) <= len(raw)
        for _ in range(count):
            number = struct.unpack_from(">I", raw, record)[0]
            payload = raw[record + 4:record + 4 + page]
            stored = struct.unpack_from(">I", raw, record + 4 + page)[0]
            checksum = nonce
            for index in range(page - 200, 0, -200):
                checksum = (checksum + payload[index]) & 0xffffffff
            assert stored == checksum
            assert 0 < number <= initial and number not in pages
            pages[number] = payload
            records.append({"page": number, "record_offset": record,
                            "data_offset": record + 4, "bytes": page,
                            "header_offset": cursor,
                            "sha256": hashlib.sha256(payload).hexdigest()})
            record += page + 8
        cursor = (record + sector - 1) // sector * sector
    return {"pages": pages, "segments": segments, "records": records,
            "initial_pages": initial}


def verify(corpus):
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8-sig"))
    outcomes = []
    for case in manifest["cases"]:
        folder = corpus / case["name"]
        for name, wanted in case["source_files"].items():
            assert Path(name).name == name and digest(folder / name) == wanted
        before = corpus / "references" / (case["name"] + "-before.sqlite")
        assert digest(before) == case["before_sha256"]
        raw = before.read_bytes()
        with sqlite3.connect(before.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            assert db.execute("PRAGMA quick_check(1)").fetchone() == ("ok",)
            table = case["table"]
            assert table in ("messages", "messages_v2")
            row = db.execute("SELECT uid,data FROM " + table + " WHERE mid=21").fetchone()
            assert row[0] == 77
            assert hashlib.sha256(row[1]).hexdigest() == case["expected_blob_sha256"]
        details = {"name": case["name"], "expected_journal_result": case["expected_journal_result"]}
        if case["mutation"] is None:
            report = journal((folder / "cache4.db-journal").read_bytes())
            page = int.from_bytes(raw[16:18], "big")
            page = 65536 if page == 1 else page
            assert report["initial_pages"] == len(raw) // page
            for number, data in report["pages"].items():
                assert data == raw[(number - 1) * page:number * page]
            complete = set(report["pages"]) == set(range(1, report["initial_pages"] + 1))
            assert complete is case["expected_full_snapshot"]
            assert complete is case["byte_exact_before_image"]
            assert report["segments"] == case["journal_headers"]
            assert report["records"] == case["journal_records"]
            assert sorted(report["pages"]) == case["covered_pages"]
            if complete:
                assert b"".join(report["pages"][n] for n in range(1, report["initial_pages"] + 1)) == raw
            details.update(initial_pages=report["initial_pages"], covered_pages=sorted(report["pages"]),
                           exact_before_image=complete, records=len(report["records"]))
        elif case["name"] == "foreign-paired":
            with sqlite3.connect((folder / "cache4.db").as_uri() + "?mode=ro&immutable=1", uri=True) as db:
                assert db.execute("SELECT uid FROM messages WHERE mid=21").fetchone() == (99,)
            report = journal((folder / "cache4.db-journal").read_bytes())
            assert len(report["pages"]) < report["initial_pages"]
        elif case["name"] == "persist-zero":
            assert (folder / "cache4.db-journal").read_bytes()[:28] == b"\0" * 28
        outcomes.append(details)
    return {"schema": 1, "status": "passed", "scope": "Independent pre-transaction bytes/SQLite validation; no recovery parser imports",
            "manifest_sha256": digest(corpus / "manifest.json"), "cases": outcomes,
            "verifier_sha256": digest(Path(__file__))}


def helper_call(command, request, folder):
    write(folder / "request.json", request)
    completed = subprocess.run([str(value) for value in command], input=json.dumps(request, ensure_ascii=False) + "\n",
        text=True, encoding="utf-8", errors="strict", capture_output=True, timeout=120, check=False)
    (folder / "stdout.ndjson").write_bytes(completed.stdout.encode("utf-8"))
    (folder / "stderr.txt").write_bytes(completed.stderr.encode("utf-8"))
    events = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    results = [event for event in events if event.get("event", event.get("type")) == "result"]
    assert results, ("no_result", folder.name, completed.returncode)
    return {"exit_code": completed.returncode, "result": results[-1]}


def baseline(corpus, helper, output, *, source_engine=None, python=None, expected_helper_sha=V8_HELPER):
    if source_engine is not None:
        assert python is not None and python.is_file() and source_engine.is_file()
        command = [python, "-X", "utf8", "-B", source_engine]
        def runtime_binding():
            return {"mode": "source_engine", "python_sha256": digest(python),
                "engine_sha256": digest(source_engine),
                "top_level_source_files": {path.name: {"bytes": path.stat().st_size, "sha256": digest(path)}
                    for path in sorted(source_engine.parent.iterdir())
                    if path.is_file() and path.suffix in (".py", ".json", ".txt")}}
        execution_kind = "source_engine"
    else:
        assert helper is not None and digest(helper) == expected_helper_sha, "Frozen helper hash mismatch"
        command = [helper]
        runtime_binding = lambda: files(helper.parent)
        execution_kind = "frozen_helper"
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8-sig"))
    before = {"corpus": files(corpus), "runtime": runtime_binding()}
    write(output / "binding-before.json", before)
    verification = verify(corpus)
    write(output / "corpus-verification.json", verification)
    plan = [(case, False) for case in manifest["cases"]]
    extra = [(case, True) for case in manifest["cases"] if case["name"] in
             ("full-delete", "partial-delete", "partial-wide", "partial-overflow-delete", "partial-overflow-update")]
    plan += extra
    write(output / "plan.json", {"normal_automatic_cases": len(manifest["cases"]),
                                "explicit_generic_dump_controls": len(extra),
                                "cases": [{"name": case["name"], "explicit_dump": dump} for case, dump in plan]})
    results = []
    for case, dump in plan:
        name = case["name"] + ("--explicit-dump" if dump else "")
        folder = output / name
        folder.mkdir()
        archive = folder / "archive"
        source = corpus / (case["name"] + "/cache4.db-journal" if dump else case["path"])
        request = {"protocol": 1, "operation": "telegram_analyze", "destination": str(archive),
                   "options": {"roots": [{"path": str(source), "kind": "dump"}] if dump else [str(source)],
                               "scan_fragments": True, "recover_deleted": True}}
        analysis = helper_call(command, request, folder)
        rows = [json.loads(line) for line in (archive / "messages.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        exact = [row for row in rows if row.get("text") == case["expected_text"]]
        contains = [row for row in rows if isinstance(row.get("text"), str) and case["expected_text"] in row["text"]]
        search_results = {}
        for mode, query in (("literal", "прабабушка"), ("regex", "рецепт[\\s\\S]*прабабушка")):
            search_folder = folder / ("search-" + mode)
            search_folder.mkdir()
            search = helper_call(command, {"protocol": 1, "operation": "search", "archive": str(archive),
                "app": "Telegram", "query": query, "query_mode": mode}, search_folder)
            search_results[mode] = {"exit_code": search["exit_code"], "records": len(search["result"].get("records", []))}
        result = {"name": name, "explicit_dump": dump, "analysis": analysis, "archive_rows": len(rows),
            "exact_old_text_rows": len(exact), "contains_old_text_rows": len(contains),
            "confirmed_old_text_rows": sum(row.get("application_confirmed") is True for row in exact),
            "exact_old_text_evidence": [{key: row.get(key) for key in
                ("record_kind", "evidence_kind", "application_confirmed", "chat_id", "message_id", "timestamp", "sender_id", "source_file", "source_record")}
                for row in exact], "search": search_results}
        write(folder / "case-result.json", result)
        results.append(result)
        print(json.dumps({"case": name, "old_exact": len(exact), "confirmed": result["confirmed_old_text_rows"]}), flush=True)
    after = {"corpus": files(corpus), "runtime": runtime_binding()}
    write(output / "binding-after.json", after)
    assert before == after, "Corpus or frozen runtime changed"
    result = {"schema": 1, "status": "complete", "utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Owned native SQLite journal analysis; execution_kind separates source engine from actual frozen helper; no devices/user data/paid comparison",
        "execution_kind": execution_kind, "command": [str(value) for value in command],
        "helper_sha256": digest(helper) if helper else None,
        "source_engine_sha256": digest(source_engine) if source_engine else None,
        "source_binding_limit": "Interpreter EXE and top-level helper sources pinned; installed Python dependency packages not fully inventoried" if source_engine else None,
        "manifest_sha256": digest(corpus / "manifest.json"),
        "runner_sha256": digest(Path(__file__)), "source_runtime_unchanged": True,
        "binding_before_sha256": digest(output / "binding-before.json"),
        "binding_after_sha256": digest(output / "binding-after.json"), "results": results}
    write(output / "run.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--verify-out", type=Path)
    parser.add_argument("--helper", type=Path)
    parser.add_argument("--helper-sha256", default=V8_HELPER)
    parser.add_argument("--source-engine", type=Path)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--baseline-out", type=Path)
    arguments = parser.parse_args()
    corpus = arguments.corpus.resolve()
    verified = verify(corpus)
    if arguments.verify_out:
        write(arguments.verify_out.resolve(), verified)
    print(json.dumps({"verification": "passed", "cases": len(verified["cases"])}), flush=True)
    if arguments.helper or arguments.source_engine or arguments.baseline_out:
        assert arguments.baseline_out and bool(arguments.helper) != bool(arguments.source_engine)
        assert re.fullmatch(r"[0-9a-f]{64}", arguments.helper_sha256)
        baseline(corpus, arguments.helper.resolve() if arguments.helper else None, arguments.baseline_out.resolve(),
                 source_engine=arguments.source_engine.resolve() if arguments.source_engine else None,
                 python=arguments.python.resolve() if arguments.python else None,
                 expected_helper_sha=arguments.helper_sha256)
