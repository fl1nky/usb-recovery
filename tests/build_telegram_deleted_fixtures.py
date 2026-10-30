"""Generate real SQLite DELETE fixtures; no recovery-parser serialization."""
from pathlib import Path
import hashlib
import json
import shutil
import sys
import tempfile

from TelegramDeletedTests import TelegramDeleted
from TelegramResidualProvenanceTests import ResidualProvenance
from build_telegram_native_fixtures import message


def build(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    fixture = TelegramDeleted()
    fixture.setUp()
    cases = []
    try:
        for secure in (False, True):
            source, connection, table = fixture.database(actual=True, secure=secure)
            fixture.delete(connection, table)
            connection.close()
            target = destination / ("secure-on.db" if secure else "secure-off.db")
            shutil.copyfile(source, target)
            cases.append(dict(Name="secure-on" if secure else "secure-off", Path=target.name,
                              Sha256=hashlib.sha256(target.read_bytes()).hexdigest(), ExpectedResiduals=0 if secure else 3))
        target = destination / "provided.mem"
        target.write_bytes(b"\0" * 33 + message("recipe keyword 🥧", mid=321) + b"\0" * 150)
        cases.append(dict(Name="typed-dump", Path=target.name,
                          Sha256=hashlib.sha256(target.read_bytes()).hexdigest(), ExpectedResiduals=0))
    finally:
        fixture.tearDown()
    provenance = ResidualProvenance()
    provenance.setUp()
    try:
        source, wal, before, _ = provenance.fixture(deleted_before_history=True, secure_delete=False)
        target = destination / "provenance" / "cache4.db"
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(source, target)
        shutil.copyfile(wal, str(target) + "-wal")
        cases.append(dict(Name="current-residual-with-history", Path="provenance/cache4.db",
                          Sha256=before["db"], WalSha256=before["wal"], ExpectedResiduals=1))
    finally:
        provenance.tearDown()
    (destination / "manifest.json").write_text(json.dumps(dict(Schema=1, Cases=cases), ensure_ascii=False, indent=2), encoding="utf-8")
    print("Generated 4 independent SQLite/dump fixtures")


if __name__ == "__main__":
    build(sys.argv[1])
