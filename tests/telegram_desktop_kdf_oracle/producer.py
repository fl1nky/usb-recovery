"""Independent Qt5 writer for the pinned Desktop KD2/v2 key-data layout.

Developer-only producer; normal tests read frozen bytes and need no Qt.
The existing independent writer supplies native IGE encryption and TDF framing.
Scrypt is produced by PyCryptodome, independently of the reader's OpenSSL KDF.
Only public artificial test constants are used, never a client profile.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telegram_platform_fixture_producer import (
    QByteArray, QT_VERSION_STR, TEST_KEY, TEST_PASSCODE, encrypt, qt, wrap_file)
from Crypto.Protocol.KDF import scrypt

PIN = "a8de5f928ba68197195e6e752293af39d4db8e6c"
OPEN_SALT = bytes(range(32))
SALT = bytes(range(32, 64))
OPAQUE = b"OPAQUE_ACCOUNT_INFO_NEVER_DECRYPT_KD2"


def slot(n=131072, generation=7):
    key = scrypt(TEST_PASSCODE.encode("utf-8"), SALT, 256, n, 8, 1)
    return (2, generation, n, 8, 1, SALT, encrypt(TEST_KEY, key))


def trailer(slots, committed=7, magic=0x4b443200, version=2, tail=b""):
    def write(stream):
        for value in (magic, version, committed, len(slots)):
            stream.writeUInt32(value)
        for kind, generation, memory, time, parallel, salt, encrypted in slots:
            for value in (kind, generation, memory, time, parallel):
                stream.writeUInt32(value)
            stream << QByteArray(salt) << QByteArray(encrypted)
        if tail:
            stream.writeRawData(tail)
    return qt(write)


def container(inner, opened=b"", extra=b"", opaque=OPAQUE):
    def write(stream):
        for value in (OPEN_SALT, opened, opaque, inner):
            stream << QByteArray(value)
        if extra:
            stream.writeRawData(extra)
    return wrap_file(qt(write))


def make(destination, upstream):
    if destination.exists():
        raise RuntimeError("Output must not already exist")
    destination.mkdir(parents=True)
    modern = slot()
    x86 = slot(65536)
    salt, password = OPEN_SALT, b""
    empty_key = hashlib.pbkdf2_hmac("sha512", hashlib.sha512(salt + password + salt).digest(), salt, 1, 256)
    opened = encrypt(TEST_KEY, empty_key)
    stale = (2, 8, 131072, 8, 1, SALT, b"\x53" * 288)
    argon = (1, 8, 65536, 8, 1, SALT, b"\x41" * 288)
    cases = {}
    def add(name, inner, secret="passcode", good=False, **kwargs):
        cases[name] = (container(inner, **kwargs), secret, good)
    add("scrypt-default", trailer([modern]), good=True)
    add("scrypt-x86", trailer([x86]), good=True)
    add("committed-first", trailer([modern, stale]), good=True)
    add("committed-second", trailer([stale, modern]), good=True)
    add("staged-argon2", trailer([argon, modern]), good=True)
    add("passcode-and-open", trailer([modern]), opened=opened, good=True)
    add("open-no-wraps", trailer([], committed=0), secret="empty", opened=opened, good=True)
    add("open-with-staged", trailer([stale], committed=7), secret="empty", opened=opened, good=True)
    add("open-with-argon2", trailer([argon], committed=8), secret="empty", opened=opened, good=True)
    add("bad-magic", trailer([modern], magic=0x4b443201))
    add("old-trailer-version", trailer([modern], version=1))
    add("new-trailer-version", trailer([modern], version=3))
    add("too-many-slots", trailer([modern, stale, argon]))
    add("duplicate-generation", trailer([modern, modern]))
    add("missing-committed", trailer([stale]))
    add("selected-argon2", trailer([argon], committed=8))
    add("open-missing", trailer([]), secret="empty")
    add("outer-trailing", trailer([modern]), extra=b"TRAILING")
    add("inner-trailing", trailer([modern], tail=b"TRAILING"))
    add("opaque-contains-fake-trailer", trailer([stale]), opaque=trailer([modern]))
    changes = {
        "unknown-kdf": (0, 9), "scrypt-not-power-two": (2, 1000),
        "scrypt-too-large": (2, 262144), "scrypt-r-zero": (3, 0),
        "scrypt-r-large": (3, 9), "scrypt-p-zero": (4, 0), "scrypt-p-large": (4, 2),
        "salt-short": (5, b"\x01" * 7), "salt-long": (5, b"\x01" * 1025),
        "cipher-short": (6, modern[6][:-1]), "cipher-integrity": (6, b"\x51" * 288),
        "authenticated-wrong-key-size": (6, encrypt(TEST_KEY[:-1], scrypt(TEST_PASSCODE.encode(), SALT, 256, 131072, 8, 1))),
    }
    for name, (index, value) in changes.items():
        changed = list(modern)
        changed[index] = value
        add(name, trailer([changed]))
    # A malformed inactive slot must fail before any live-slot derivation.
    changed = list(stale)
    changed[5] = b"x" * 7
    add("malformed-staged-slot", trailer([modern, changed]))
    add("truncated-trailer", trailer([modern])[:-1])
    raw, secret, good = cases["scrypt-default"]
    cases["bad-container-checksum"] = (raw[:-1] + bytes([raw[-1] ^ 1]), secret, False)
    inventory = []
    with zipfile.ZipFile(destination / "native-cases.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for name, (data, secret, good) in sorted(cases.items()):
            entry = zipfile.ZipInfo(name + ".tdf", date_time=(2026, 11, 13, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
            inventory.append(dict(path=entry.filename, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                secret=secret, accepted=good))
    sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(upstream.glob("*.cpp"))}
    sources.update({path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(upstream.glob("*.h"))})
    manifest = dict(format="telegram-desktop-kd2-v2-owned-inputs", upstream_commit=PIN,
        qt_version=QT_VERSION_STR, scrypt_producer="Crypto.Protocol.KDF.scrypt", sources=sources,
        archive_sha256=hashlib.sha256((destination/'native-cases.zip').read_bytes()).hexdigest(),
        producers={Path(__file__).name: hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'telegram_platform_fixture_producer.py': hashlib.sha256(
                (Path(__file__).resolve().parents[1]/'telegram_platform_fixture_producer.py').read_bytes()).hexdigest()},
        fixture_count=len(inventory), cases=inventory)
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(fixture_count=len(inventory), accepted=sum(c[2] for c in cases.values()),
        qt_version=QT_VERSION_STR)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, required=True)
    args = parser.parse_args()
    make(args.destination, args.upstream)
