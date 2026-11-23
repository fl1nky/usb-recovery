"""Exercise the actual CLI on databases authored by Python's SQLite engine.

No Telegram account, device, helper runtime or network access is required.
"""
import argparse
import csv
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    executable = args.exe.resolve(strict=True)
    checks = 0

    def check(condition, message):
        nonlocal checks
        if not condition:
            raise AssertionError(message)
        checks += 1

    with tempfile.TemporaryDirectory(prefix="sqlite-evidence-", dir=args.work) as temporary:
        root = Path(temporary)
        sources = root / "sources"
        sources.mkdir()
        expected = {
            "Payroll, not a Telegram chat",
            "Unicode: прабабушка\nsecond line, \"quoted\"",
            "<img src='https://example.invalid/tracker' onerror='alert(1)'>",
            "=1+1",
            "CREATE TABLE is also legitimate user text",
        }
        for name in ("payroll.db", "another.db"):
            with closing(sqlite3.connect(sources / name)) as db:
                db.execute("CREATE TABLE unrelated (id INTEGER, account INTEGER, date INTEGER, memo TEXT, outgoing INTEGER, detail TEXT)")
                db.execute("INSERT INTO unrelated VALUES (7001, 987654321, 1700000000, ?, 1, ?)",
                           ("Payroll, not a Telegram chat", "Unicode: прабабушка\nsecond line, \"quoted\""))
                db.execute("INSERT INTO unrelated VALUES (?, 12, 1700000000, ?, 0, ?)",
                           (-(2**63), "<img src='https://example.invalid/tracker' onerror='alert(1)'>", "=1+1"))
                db.execute("CREATE TABLE notes (body TEXT)")
                db.execute("INSERT INTO notes VALUES (?)", ("CREATE TABLE is also legitimate user text",))
                db.commit()
        before = {p.name: sha256(p) for p in sources.iterdir()}
        for name, source in (("folder", sources), ("single", sources / "payroll.db")):
            output = root / name
            completed = subprocess.run(
                [str(executable), "telegram", str(source), "--json", "--output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
            )
            check(completed.returncode == 0, "CLI failed: " + completed.stderr.decode(errors="replace"))
            report = json.loads((output / "telegram-report.json").read_text(encoding="utf-8-sig"))
            check(report["Messages"] == [], "Unrelated SQLite rows became Telegram messages")
            check(report["ActiveMessagesCount"] == report["CarvedMessagesCount"] == 0, "Unrelated data inflated message counts")
            fragments = report["TextFragments"]
            check(expected <= {f["Text"] for f in fragments}, "Text without timestamps, additional columns or Unicode was lost")
            check(all(f["EvidenceKind"] == "UnattributedSqliteText" for f in fragments), "Fragment evidence kind missing")
            check(all("MessageId" not in f and "PeerId" not in f and "TimestampUtc" not in f and "IsDeleted" not in f for f in fragments), "Invented message metadata")
            paths = {str(p.resolve()) for p in sources.iterdir()} if name == "folder" else {str(source.resolve())}
            check({f["SourcePath"] for f in fragments} == paths, "Database provenance lost")
            for path in paths:
                rows = [f for f in fragments if f["SourcePath"] == path and f["Text"] == "Payroll, not a Telegram chat" and f["SourceOrigin"] == "ActiveCell"]
                check(len(rows) == 1 and rows[0]["SqliteRowId"] == 1 and rows[0]["ColumnIndex"] == 3 and rows[0]["Offset"] > 4096, "Active row coordinates lost or duplicated")
            with (output / "text-fragments.csv").open(encoding="utf-8-sig", newline="") as handle:
                csv_rows = list(csv.DictReader(handle))
            check(len(csv_rows) == len(fragments), "CSV multiline boundaries damaged")
            check("'=1+1" in {row["Text"] for row in csv_rows}, "CSV formula not neutralized")
            check("=1+1" in {f["Text"] for f in fragments}, "Exact JSON evidence mutated by CSV formatting")
        check(before == {p.name: sha256(p) for p in sources.iterdir()}, "Input databases changed")
    print(f"PASS TelegramEvidenceIntegrationTests: {checks} checks; real SQLite writer, CLI JSON/CSV, source hashes")


if __name__ == "__main__":
    main()
