"""Independent INPUT producer: native Qt5 QDataStream + SQLite + pinned Java.

Run once with --upstream and --android directories from the pinned source/
native Java producer. PyQt5 is a developer-only producer dependency; normal
tests only load the frozen corpus and never need Qt or a compiler. No product
reader is imported. Output directories must not already exist.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import zipfile

if os.environ.get("TELEGRAM_QT_PRODUCER"):
    sys.path.insert(0, os.environ["TELEGRAM_QT_PRODUCER"])
from PyQt5.QtCore import QByteArray, QDataStream, QIODevice, QT_VERSION_STR
from Crypto.Cipher import AES

# Public, artificial producer values. Never real client keys/passcodes.
TEST_KEY = bytes((i * 37 + 11) % 256 for i in range(256))
TEST_PASSCODE = "synthetic-known-passcode"
ACCOUNT = "0123456789ABCDEF"
DRAFT_FILE = "ABCDEF0123456789s"


def qt(write):
    output = QByteArray()
    stream = QDataStream(output, QIODevice.WriteOnly)
    stream.setVersion(QDataStream.Qt_5_1)
    write(stream)
    assert stream.status() == QDataStream.Ok
    return bytes(output)


def wrap_file(body, version=7003004):
    check = hashlib.md5(body + struct.pack("<II", len(body), version) + b"TDF$").digest()
    return b"TDF$" + struct.pack("<I", version) + body + check


def encrypt(clear, key=TEST_KEY):
    clear = struct.pack("<I", len(clear) + 4) + clear
    clear += bytes((0xA0 + i) % 256 for i in range(-len(clear) % 16))
    msg = hashlib.sha1(clear).digest()[:16]
    # Independent encryption direction, AuthKey::prepareAES_oldmtp(false).
    hashes = [hashlib.sha1(part).digest() for part in (
        msg + key[8:40], key[40:56] + msg + key[56:72], key[72:104] + msg, msg + key[104:136])]
    a, b, c, d = hashes
    aes = AES.new(a[:8] + b[8:] + c[4:16], AES.MODE_ECB)
    prior_cipher = a[8:] + b[:4]
    # Full native 32-byte IV, divided in the native IGE order.
    iv = a[8:] + b[:8] + c[16:] + d[:8]
    prior_cipher, prior_plain = iv[:16], iv[16:]
    encrypted = bytearray()
    for offset in range(0, len(clear), 16):
        plain = clear[offset:offset + 16]
        cipher = bytes(x ^ y for x, y in zip(aes.encrypt(bytes(x ^ y for x, y in zip(plain, prior_cipher))), prior_plain))
        encrypted.extend(cipher)
        prior_cipher, prior_plain = cipher, plain
    return msg + bytes(encrypted)


def key_data(passcode=TEST_PASSCODE, trailer=False):
    salt = bytes(range(32))
    p = passcode.encode("utf-8")
    derived = hashlib.pbkdf2_hmac("sha512", hashlib.sha512(salt + p + salt).digest(), salt,
        100000 if p else 1, 256)
    def write(s):
        for raw in (salt, encrypt(TEST_KEY, derived), b"OPAQUE_ACCOUNT_INFO_NEVER_DECRYPT"):
            s << QByteArray(raw)
        if trailer:
            s << QByteArray(b"UNKNOWN_NEW_KDF_TRAILER")
    return wrap_file(qt(write))


def draft_clear(tag=0xFFFFFFFFFFFFFF06, keys=(-1, 123), text="Desktop native черновик 🥧\n第二行", late_corrupt=False):
    def write(s):
        s.writeUInt64(tag)
        s.writeUInt64((0x80 << 48) | 909)
        s.writeUInt32(len(keys))
        for index, key in enumerate(keys):
            s.writeInt64(key)
            s.writeQString(text + (" topic" if index else ""))
            s << QByteArray(b"TAGS_NEVER_MESSAGE")
            if tag == 0xFFFFFFFFFFFFFF03:
                s.writeInt64(777)
                s.writeInt32(0)
            else:
                s.writeInt64(909)
                s.writeInt64(777)
                if tag == 0xFFFFFFFFFFFFFF06:
                    s.writeUInt64(0)
                    s.writeUInt64(0)
                s.writeQString("https://NEVER_FETCH_OR_USE_AS_TEXT.invalid/FILENAME")
                for _ in range(5):
                    s.writeInt32(0)
    result = qt(write)
    return result[:-1] if late_corrupt else result


def draft_file(**kwargs):
    return wrap_file(qt(lambda s: s.__lshift__(QByteArray(encrypt(draft_clear(**kwargs))))))


def inventory(root):
    return [dict(path=p.relative_to(root).as_posix(), bytes=p.stat().st_size,
                 sha256=hashlib.sha256(p.read_bytes()).hexdigest())
            for p in sorted(root.rglob("*")) if p.is_file()]


def produce(destination, upstream, android):
    destination, upstream, android = map(Path, (destination, upstream, android))
    if destination.exists():
        raise ValueError("Preserve previous corpus")
    destination.mkdir(parents=True)
    cases = destination / "native-cases"
    cases.mkdir()
    native_schema = re.search(r'"(CREATE TABLE scheduled_messages_v2\([^"\n]+)"',
        (upstream / "Android232-MessagesStorage.java").read_text("utf-8")).group(1)
    ios_source = (upstream / "TGDatabase.mm").read_text("utf-8")
    ios_sql = re.search(r'@"(CREATE TABLE IF NOT EXISTS %@ \(mid INTEGER PRIMARY KEY, cid INTEGER, localMid[^"\n]+)"', ios_source).group(1).replace("%@", "messages_v29")
    service_sql = re.search(r'@"(CREATE TABLE IF NOT EXISTS %@ \(key INTEGER PRIMARY KEY, value BLOB\))"', ios_source).group(1).replace("%@", "service_v29")
    schema = dict(android=native_schema, ios=ios_sql, ios_service=service_sql)
    expected = {"android": [], "ios": [], "desktop": []}

    def db_at(relative, kind):
        path = cases / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(path)
        if kind == "android":
            db.execute(native_schema)
        else:
            db.execute(ios_sql)
            db.execute("ALTER TABLE messages_v29 ADD COLUMN content_properties BLOB")
            db.execute(service_sql)
        db.commit()
        return path, db

    def insert_android(db):
        for i in range(3):
            raw = (android / f"scheduled-{i}.blob").read_bytes()
            text = (android / f"scheduled-{i}.text").read_text("utf-8")
            db.execute("INSERT INTO scheduled_messages_v2 VALUES(?,?,?,?,?,?,NULL,0)",
                (5101 + i, 909, 0, 1794001000 + i, raw, 0))
            expected["android"].append(dict(mid=5101+i, uid=909, date=1794001000+i, text=text,
                blob_sha256=hashlib.sha256(raw).hexdigest()))
        db.commit()

    _, db = db_at("positive/android/cache4.db", "android")
    insert_android(db)
    db.close()
    for control, edit in (
        ("wrong-keys", "UPDATE scheduled_messages_v2 SET uid=111"),
        ("wrong-schema", "ALTER TABLE scheduled_messages_v2 ADD COLUMN fake INTEGER"),
        ("unknown-tl", "UPDATE scheduled_messages_v2 SET data=X'01020304'")):
        _, db = db_at(f"controls/android-{control}/cache4.db", "android")
        for i in range(3):
            db.execute("INSERT INTO scheduled_messages_v2 VALUES(?,?,?,?,?,?,NULL,0)",
                (5101+i,909,0,1794001000+i,(android/f"scheduled-{i}.blob").read_bytes(),0))
        db.execute(edit); db.commit(); db.close()

    _, db = db_at("positive/ios/tgdata.db", "ios")
    for i, text in enumerate(("iOS native исторический пирог 🥧", "iOS native exact second line\n第二行")):
        row = (6101+i, 909, 0, text, b"MEDIA_FILENAME_NEVER_TEXT", 77, 909, 0, None, 0, 1794002000+i, 0, 0, 0, b"")
        db.execute("INSERT INTO messages_v29 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
        expected["ios"].append(dict(mid=6101+i,cid=909,author=77,date=1794002000+i,text=text))
    db.commit(); db.close()
    for control, edit in (
        ("wrong-version", "ALTER TABLE messages_v29 RENAME TO messages_v30"),
        ("wrong-schema", "ALTER TABLE messages_v29 ADD COLUMN fake INTEGER"),
        ("secret-id", "UPDATE messages_v29 SET cid=-9223372036854775000"),
        ("unconfirmed-author", "UPDATE messages_v29 SET from_id=0")):
        target = cases / f"controls/ios-{control}/tgdata.db"
        target.parent.mkdir(parents=True)
        shutil.copyfile(cases / "positive/ios/tgdata.db", target)
        with sqlite3.connect(target) as db:
            db.execute(edit)

    def save_desktop(relative, raw, passcode=TEST_PASSCODE, trailer=False):
        base = cases / relative
        account = base / ACCOUNT
        account.mkdir(parents=True)
        (base / "key_datas").write_bytes(key_data(passcode, trailer))
        (account / DRAFT_FILE).write_bytes(raw)
        # Authorization/settings/map files must remain closed, even with key.
        (base / (ACCOUNT + "s")).write_bytes(b"AUTH_MATERIAL_NEVER_READ")
        (account / "maps").write_bytes(b"MAP_MATERIAL_NEVER_READ")
        return base

    for suffix in (3, 5, 6):
        tag = 0xFFFFFFFFFFFFFF00 + suffix
        save_desktop(f"positive/desktop-tag{suffix}", draft_file(tag=tag))
        expected["desktop"].append(dict(case=f"desktop-tag{suffix}",tag=f"0x{tag:016x}",texts=[
            "Desktop native черновик 🥧\n第二行", "Desktop native черновик 🥧\n第二行 topic"]))
    save_desktop("positive/desktop-empty-passcode", draft_file(), passcode="")
    controls = {
        "unknown-tag": draft_file(tag=0xFFFFFFFFFFFFFF07),
        "cloud-key": draft_file(keys=(-2,)),
        "duplicate-key": draft_file(keys=(-1,-1)),
        "truncated-final": draft_file(late_corrupt=True),
        "unknown-version": wrap_file(qt(lambda s:s.__lshift__(QByteArray(encrypt(draft_clear())))), 0x7fffffff),
    }
    valid = draft_file()
    controls["bad-checksum"] = valid[:-1] + bytes([valid[-1] ^ 1])
    body = bytearray(valid[8:-16]);body[25] ^= 1
    controls["ciphertext-integrity"] = wrap_file(bytes(body))
    for name, raw in controls.items():
        save_desktop("controls/desktop-" + name, raw)
    save_desktop("controls/desktop-modern-key-wrap", draft_file(), trailer=True)

    # Actual SQLite WAL transactions. No hand-crafted pages or fake WAL frame.
    for platform in ("android", "ios"):
        with tempfile.TemporaryDirectory(prefix="native-platform-wal-") as temporary:
            path = Path(temporary) / "native.db"
            db = sqlite3.connect(path)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_autocheckpoint=0")
            if platform == "android":
                db.execute(native_schema)
                db.execute("INSERT INTO scheduled_messages_v2 VALUES(?,?,?,?,?,?,NULL,0)",
                    (5101,909,0,1794001000,(android/'scheduled-0.blob').read_bytes(),0))
            else:
                db.execute(ios_sql);db.execute("ALTER TABLE messages_v29 ADD COLUMN content_properties BLOB");db.execute(service_sql)
                db.execute("INSERT INTO messages_v29 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (6101,909,0,"iOS WAL historical surviving text",None,77,909,0,None,0,1794002000,0,0,0,None))
            db.commit()
            table = "scheduled_messages_v2" if platform == "android" else "messages_v29"
            db.execute("DELETE FROM " + table);db.commit()
            target = cases / f"wal/{platform}/native.db"
            target.parent.mkdir(parents=True)
            for suffix in ("", "-wal", "-shm"):
                shutil.copyfile(Path(str(path)+suffix), Path(str(target)+suffix))
            db.close()

    manifest = dict(schema=1, fixture_kind="native_qt5_java_sqlite_inputs_not_recovery_acceptance",
        qt_version=QT_VERSION_STR, sqlite_version=sqlite3.sqlite_version,
        upstream=dict(android="4de548e79fed27f1a66fbdff84223321838fe925",
            ios_original="f41e9695b5d92e94105afc073a2bbd6a15a1d33c",
            ios_official_import="1423d5381fcdaaef85565755b087fbed6a4ed97d",
            desktop="a8de5f928ba68197195e6e752293af39d4db8e6c"),
        schema_statements=schema, expected=expected, sources=inventory(cases))
    with zipfile.ZipFile(destination / "native-cases.zip", "x", zipfile.ZIP_DEFLATED) as archive:
        for row in manifest["sources"]:
            archive.write(cases/row['path'],row['path'])
    archive = (destination/'native-cases.zip').read_bytes()
    manifest['archive_sha256']=hashlib.sha256(archive).hexdigest()
    (destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(native_qt=QT_VERSION_STR,native_sqlite=sqlite3.sqlite_version,files=len(manifest['sources']),
        manifest_sha256=hashlib.sha256((destination/'manifest.json').read_bytes()).hexdigest())))


if __name__ == "__main__":
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--upstream',required=True);p.add_argument('--android',required=True)
    a=p.parse_args();produce(a.out,a.upstream,a.android)
