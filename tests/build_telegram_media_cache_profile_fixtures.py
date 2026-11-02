"""Independent official-Java BLOBs and native SQLite-created test copies."""
from pathlib import Path
import base64
import gzip
import hashlib
import json
import shutil
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parent
BUNDLE = ROOT / "fixtures/telegram-cache-profiles"
SOURCE_COMMIT = "4de548e79fed27f1a66fbdff84223321838fe925"
MEDIA_SCHEMA = "mid INTEGER,uid INTEGER,date INTEGER,type INTEGER,data BLOB,PRIMARY KEY(mid,uid,type)"
MAIN_SCHEMA = "mid INTEGER,uid INTEGER,date INTEGER,data BLOB,PRIMARY KEY(mid,uid)"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(folder):
    return {path.relative_to(folder).as_posix(): digest(path)
            for path in sorted(Path(folder).rglob("*")) if path.is_file()}


def load_cases(bundle=BUNDLE):
    bundle = Path(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf8"))
    if manifest["schema"] != 1 or manifest["cases"] != 855 or manifest["telegram_commit"] != SOURCE_COMMIT:
        raise ValueError("Unsupported independent profile fixture manifest")
    for item in manifest["files"]:
        if item["path"] not in ("oracle.json.gz", "oracle-sources.tar.gz", "LICENSE"):
            raise ValueError("Unexpected fixture path")
        file = bundle / item["path"]
        if file.stat().st_size != item["bytes"] or digest(file) != item["sha256"]:
            raise ValueError("Changed independent profile fixture")
    with gzip.open(bundle / "oracle.json.gz", "rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024 or len(raw) != manifest["uncompressed_json_bytes"]:
        raise ValueError("Fixture JSON size limit")
    payload = json.loads(raw)
    if payload["schema"] != 1 or len(payload["cases"]) != 855:
        raise ValueError("Incomplete profile fixture corpus")
    names = set()
    for case in payload["cases"]:
        if case["name"] in names or not case["name"].replace("-", "").replace("_", "").isalnum():
            raise ValueError("Invalid profile fixture name")
        names.add(case["name"])
        blob = base64.b64decode(case.pop("blob_base64"), validate=True)
        if (len(blob) != case["bytes"] or hashlib.sha256(blob).hexdigest() != case["blob_sha256"] or
                not 0 < case["tl_bytes"] <= len(blob) or
                hashlib.sha256(blob[:case["tl_bytes"]]).hexdigest() != case["tl_body_sha256"]):
            raise ValueError("Changed official serialized BLOB")
        case["blob"] = blob
        yield case


def expected_parts(case):
    outer, caption = case["expected"]["text"], case["expected_legacy_caption"]
    parts = []
    if outer:
        parts.append(dict(text=outer, text_field="message", supplemental=False))
    if caption and caption != outer:
        parts.append(dict(text=caption, text_field="media.legacy_caption", supplemental=bool(outer)))
    return parts


def create(destination, case, variant="current"):
    if variant not in {"current", "history", "primary-current", "primary-historical",
                       "native-current", "native-history", "native-residual"}:
        raise ValueError("Unknown profile fixture variant")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    target = destination / "cache4.db"
    native = variant.startswith(("native-", "primary-"))
    cache = not variant.startswith("native-")
    historical = variant in {"history", "primary-historical", "native-history", "native-residual"}
    sql = case["exact_sql"]
    with tempfile.TemporaryDirectory(prefix="owned-profile-sqlite-writer-") as temporary:
        database = Path(temporary) / "cache4.db"
        con = sqlite3.connect(database)
        try:
            con.execute("PRAGMA page_size=4096")
            con.execute("PRAGMA secure_delete=" + ("OFF" if variant == "native-residual" else "ON"))
            if historical:
                con.execute("PRAGMA journal_mode=WAL")
                con.execute("PRAGMA wal_autocheckpoint=0")
            if cache:
                con.execute("CREATE TABLE media_v4(" + MEDIA_SCHEMA + ")")
                con.execute("INSERT INTO media_v4 VALUES(?,?,?,?,?)", (sql["mid"], sql["uid"], sql["date"], sql["type"], case["blob"]))
            if native:
                con.execute("CREATE TABLE messages_v2(" + MAIN_SCHEMA + ")")
                if variant == "native-residual":
                    # Opaque non-TL filler establishes native middle-cell
                    # freeblocks without fabricating other Telegram records.
                    for mid in (39, 40, 42, 43):
                        con.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)",
                            (mid, sql["uid"], sql["date"], b"owned non-TL filler " * 20))
                con.execute("INSERT INTO messages_v2 VALUES(?,?,?,?)", (sql["mid"], sql["uid"], sql["date"], case["blob"]))
            con.commit()
            if historical:
                table = "messages_v2" if native else "media_v4"
                con.execute("DELETE FROM " + table + " WHERE mid=? AND uid=?", (sql["mid"], sql["uid"]))
                con.commit()
            for suffix in ("", "-wal", "-shm"):
                source = Path(str(database) + suffix)
                if source.is_file():
                    shutil.copyfile(source, Path(str(target) + suffix))
        finally:
            con.close()
    golden = {name: value for name, value in case.items() if name != "blob"}
    golden.update(variant=variant, text_parts=expected_parts(case), source_files=inventory(destination),
                  native_sqlite_writer=True, secure_delete=variant != "native-residual")
    (destination / "golden.json").write_text(json.dumps(golden, ensure_ascii=False, indent=2) + "\n", encoding="utf8")
    return target, golden


def build(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    cases, snapshots = [], []
    official = list(load_cases())

    def entry(name, database, golden):
        return dict(name=name, database=database.relative_to(destination).as_posix(),
            source_files=golden["source_files"], text_parts=golden["text_parts"],
            layer=golden["layer"], constructor=golden["constructor"],
            tl_body_sha256=golden["tl_body_sha256"], exact_sql=golden["exact_sql"])

    for case in official:
        database, golden = create(destination / "current" / case["name"], case)
        cases.append(entry(case["name"], database, golden))
    for name, variant, mode in (("cache-history", "history", 0),
            ("primary-current", "primary-current", 0),
            ("primary-historical", "primary-historical", 0),
            ("native-history", "native-history", 0),
            ("native-residual", "native-residual", 0),
            ("caption-only", "primary-current", 1)):
        case = next(case for case in official if case["layer"] == 118 and
            case["media_constructor"] == "0xb5223b0f" and case["mode"] == mode and case["direction"] == 3)
        database, golden = create(destination / "snapshots" / name, case, variant)
        snapshots.append(entry(name, database, golden))
    manifest = dict(schema=1, generator_sha256=digest(Path(__file__)), source_commit=SOURCE_COMMIT,
                    oracle_manifest_sha256=digest(BUNDLE / "manifest.json"), cases=cases, snapshot_cases=snapshots)
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf8")
    return dict(cases=len(cases), snapshot_cases=len(snapshots), database_files=len(cases)+len(snapshots),
                expected_text_records=sum(len(x["text_parts"]) for x in cases))


if __name__ == "__main__":
    import sys
    print(json.dumps(build(sys.argv[1])))
