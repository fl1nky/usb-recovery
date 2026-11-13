"""Strict native profiles; no account, process-memory or password discovery.

Android: DrKLO/Telegram 4de548e79fed27f1a66fbdff84223321838fe925,
MessagesStorage.java, scheduled_messages_v2. iOS: original iOS upstream
peter-iakovlev/Telegram f41e9695b5d92e94105afc073a2bbd6a15a1d33c,
legacy/TelegraphKit/TGDatabase.mm (schema29), corroborated by official
TelegramMessenger/Telegram-iOS 1423d5381fcdaaef85565755b087fbed6a4ed97d,
LegacyDataImport/Sources/LegacyChatImport.swift. This is NOT current Postbox.
Desktop: telegramdesktop/tdesktop a8de5f928ba68197195e6e752293af39d4db8e6c,
storage_account.cpp, storage_domain.cpp, storage_file_utilities.cpp and
mtproto_auth_key.{cpp,h}. Only draft tags FF03/FF05/FF06 and the legacy
three-blob and KD2/v2 scrypt/open key_data wraps are supported. Argon2id
passcode wraps remain unsupported. Drafts are unsent, not history.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import struct

MAX_NATIVE_FILE = 16 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_DESKTOP_VERSION = 7003004
MAX_SCRYPT_MEMORY = 192 * 1024 * 1024
DESKTOP_TAGS = {0xFFFFFFFFFFFFFF03, 0xFFFFFFFFFFFFFF05, 0xFFFFFFFFFFFFFF06}
SCHEDULED_COLUMNS = (("mid", "INTEGER", 1), ("uid", "INTEGER", 2),
    ("send_state", "INTEGER", 0), ("date", "INTEGER", 0), ("data", "BLOB", 0),
    ("ttl", "INTEGER", 0), ("replydata", "BLOB", 0), ("reply_to_message_id", "INTEGER", 0))
IOS_COLUMNS = tuple((name, kind, int(name == "mid")) for name, kind in (
    ("mid", "INTEGER"), ("cid", "INTEGER"), ("localMid", "INTEGER"),
    ("message", "TEXT"), ("media", "BLOB"), ("from_id", "INTEGER"),
    ("to_id", "INTEGER"), ("outgoing", "INTEGER"), ("unread", "INTEGER"),
    ("dstate", "INTEGER"), ("date", "INTEGER"), ("flags", "INTEGER"),
    ("seq_in", "INTEGER"), ("seq_out", "INTEGER"), ("content_properties", "BLOB")))


class PlatformError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def exact_schema(connection, table, columns):
    """Only ordinary native tables, exact fields, affinities and primary keys."""
    if not re.fullmatch(r"[a-zA-Z_0-9]+", table):
        return False
    row = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    if (not row or not isinstance(row[0], str) or not re.match(r"CREATE\s+TABLE\b", row[0], re.I)
            or re.search(r"\bWITHOUT\s+ROWID\b", row[0], re.I)):
        return False
    info = connection.execute("PRAGMA table_xinfo(" + table + ")").fetchall()
    return len(info) == len(columns) and all(
        (row[1], row[2].upper(), row[5]) == expected and row[3] == 0 and row[4] is None and row[6] == 0
        for row, expected in zip(info, columns))


def ios_schema(connection):
    return (exact_schema(connection, "messages_v29", IOS_COLUMNS) and
            exact_schema(connection, "service_v29", (("key", "INTEGER", 1), ("value", "BLOB", 0))))


def ios_messages(connection, limit, cancel=None, report=None):
    """Historical native plaintext text only; no media/path or secret-ID guessing."""
    if not ios_schema(connection):
        raise PlatformError("TELEGRAM_IOS29_SCHEMA_UNSUPPORTED")
    report = report if report is not None else {}
    report.update(checked=0, rejected=0, limited=False)
    query = ("SELECT mid,cid,from_id,date,outgoing,dstate,CASE WHEN typeof(message)='text' "
             "AND length(CAST(message AS BLOB))<=? THEN message ELSE NULL END "
             "FROM messages_v29 ORDER BY date DESC LIMIT ?")
    for row in connection.execute(query, (MAX_TEXT_BYTES, limit + 1)):
        if cancel and cancel():
            raise PlatformError("TELEGRAM_PLATFORM_CANCELLED")
        if report["checked"] >= limit:
            report["limited"] = True
            break
        report["checked"] += 1
        mid, cid, author, date, outgoing, state, text = row
        if (not all(type(x) is int for x in (mid, cid, date, outgoing, state)) or not 0 < mid <= 0x7fffffff or
                not 0 < abs(cid) <= 0x7fffffff or
                (author is not None and (type(author) is not int or not 0 <= author <= 0x7fffffff)) or
                not 0 <= date <= 0x7fffffff or outgoing not in (0, 1) or state not in (0, 1, 2) or
                not isinstance(text, str) or not text or "\x00" in text):
            report["rejected"] += 1
            continue
        try:
            text.encode("utf-8", "strict")
        except UnicodeError:
            report["rejected"] += 1
            continue
        yield dict(mid=mid, cid=cid, author=author or None, date=date, outgoing=outgoing, state=state, text=text)


class _QtReader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, size):
        if size < 0 or size > len(self.data) - self.at:
            raise PlatformError("TELEGRAM_DESKTOP_TRUNCATED")
        value = self.data[self.at:self.at + size]
        self.at += size
        return value

    def number(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def blob(self, limit=MAX_TEXT_BYTES):
        size = self.number(">I")
        if size == 0xffffffff:
            return b""
        if size > limit:
            raise PlatformError("TELEGRAM_DESKTOP_FIELD_LIMIT")
        return self.take(size)

    def text(self):
        raw = self.blob()
        if len(raw) % 2:
            raise PlatformError("TELEGRAM_DESKTOP_TEXT_INVALID")
        try:
            text = raw.decode("utf-16-be", "strict")
            text.encode("utf-8", "strict")
        except UnicodeError:
            raise PlatformError("TELEGRAM_DESKTOP_TEXT_INVALID") from None
        if "\x00" in text:
            raise PlatformError("TELEGRAM_DESKTOP_TEXT_INVALID")
        return text

    def skip_blob(self, limit=MAX_NATIVE_FILE):
        # Frame opaque account authorization bytes without copying/interpreting.
        size = self.number(">I")
        if size == 0xffffffff:
            return
        if size > limit:
            raise PlatformError("TELEGRAM_DESKTOP_FIELD_LIMIT")
        if size > len(self.data) - self.at:
            raise PlatformError("TELEGRAM_DESKTOP_TRUNCATED")
        self.at += size

    def end(self):
        if self.at != len(self.data):
            raise PlatformError("TELEGRAM_DESKTOP_TRAILING_DATA")


def tdf_payload(data):
    """Validate the native container checksum before any decryption/allocation."""
    if not isinstance(data, bytes) or not 28 <= len(data) <= MAX_NATIVE_FILE or data[:4] != b"TDF$":
        raise PlatformError("TELEGRAM_DESKTOP_CONTAINER_INVALID")
    version = struct.unpack_from("<I", data, 4)[0]
    if not 1 <= version <= MAX_DESKTOP_VERSION:
        raise PlatformError("TELEGRAM_DESKTOP_VERSION_UNSUPPORTED")
    body = data[8:-16]
    digest = hashlib.md5(body + struct.pack("<II", len(body), version) + b"TDF$").digest()
    if not hmac.compare_digest(digest, data[-16:]):
        raise PlatformError("TELEGRAM_DESKTOP_CHECKSUM_INVALID")
    return body, version


def _local_aes_key(key, msgkey):
    # AuthKey::prepareAES_oldmtp(send=false), x=8; NOT MTProto2 AES derivation.
    if not isinstance(key, bytes) or len(key) != 256:
        raise PlatformError("TELEGRAM_DESKTOP_KEY_INVALID")
    a = hashlib.sha1(msgkey + key[8:40]).digest()
    b = hashlib.sha1(key[40:56] + msgkey + key[56:72]).digest()
    c = hashlib.sha1(key[72:104] + msgkey).digest()
    d = hashlib.sha1(msgkey + key[104:136]).digest()
    return a[:8] + b[8:20] + c[4:16], a[8:20] + b[:8] + c[16:20] + d[:8]


def _decrypt_local(encrypted, key):
    if not isinstance(encrypted, bytes) or not 32 <= len(encrypted) <= MAX_NATIVE_FILE or len(encrypted) % 16:
        raise PlatformError("TELEGRAM_DESKTOP_CIPHERTEXT_INVALID")
    from Crypto.Cipher import AES
    aes_key, iv = _local_aes_key(key, encrypted[:16])
    aes = AES.new(aes_key, AES.MODE_ECB)
    previous_cipher, previous_plain = iv[:16], iv[16:]
    output = bytearray()
    for offset in range(16, len(encrypted), 16):
        block = encrypted[offset:offset + 16]
        plain = bytes(x ^ y for x, y in zip(aes.decrypt(bytes(x ^ y for x, y in zip(block, previous_plain))), previous_cipher))
        output.extend(plain)
        previous_cipher, previous_plain = block, plain
    if not hmac.compare_digest(hashlib.sha1(output).digest()[:16], encrypted[:16]):
        raise PlatformError("TELEGRAM_DESKTOP_KEY_OR_INTEGRITY_INVALID")
    size = struct.unpack_from("<I", output)[0]
    if not max(4, len(output) - 15) <= size <= len(output):
        raise PlatformError("TELEGRAM_DESKTOP_LENGTH_INVALID")
    return bytes(output[4:size])


def _key_data_wrap(reader, password, salt, encrypted):
    """Parse the entire KD2/v2 trailer before selecting one committed wrap.

    The two slots support interrupted passcode changes. Staged/stale slots
    must never become fallback passcode attempts. Costs are checked before KDF.
    """
    trailer = _QtReader(reader.blob(4096))
    reader.end()
    magic, version, committed, count = (trailer.number(">I") for _ in range(4))
    if magic != 0x4b443200 or version != 2 or count > 2:
        raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_UNSUPPORTED")
    generations, live = set(), None
    for _ in range(count):
        kind, generation, memory, time, parallel = (trailer.number(">I") for _ in range(5))
        wrap_salt, wrap_encrypted = trailer.blob(1024), trailer.blob(288)
        if generation in generations or not 8 <= len(wrap_salt) <= 1024 or len(wrap_encrypted) != 288:
            raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_INVALID")
        generations.add(generation)
        if kind == 2:
            # Upstream scrypt uses 192 MiB maxmem; additionally bound CPU work.
            if not (2 <= memory <= 131072 and not memory & (memory - 1)
                    and 1 <= time <= 8 and parallel == 1):
                raise PlatformError("TELEGRAM_DESKTOP_KDF_COST_UNSUPPORTED")
        elif kind == 1:
            # Frame native Argon2id slots, but do not derive unsupported keys.
            if not (1 <= parallel <= 16 and 8 * parallel <= memory <= 262144 and 1 <= time <= 64):
                raise PlatformError("TELEGRAM_DESKTOP_KDF_COST_UNSUPPORTED")
        else:
            raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_UNSUPPORTED")
        if generation == committed:
            live = (kind, memory, time, parallel, wrap_salt, wrap_encrypted)
    trailer.end()
    if not password:
        if len(encrypted) != 288:
            raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_INVALID")
        return salt, encrypted, None
    if live is None or live[0] != 2:
        raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_UNSUPPORTED")
    kind, memory, time, parallel, salt, encrypted = live
    return salt, encrypted, (memory, time, parallel)


def unwrap_key_data(data, passcode):
    """One supplied passcode, one selected KDF; no guessing or slot fallback.

    Empty string means the caller explicitly supplied the known no-passcode
    state. Encrypted account-info bytes are framed but never decrypted/read.
    """
    if not isinstance(passcode, str):
        raise PlatformError("TELEGRAM_DESKTOP_PASSCODE_INVALID")
    try:
        password = passcode.encode("utf-8", "strict")
    except UnicodeError:
        raise PlatformError("TELEGRAM_DESKTOP_PASSCODE_INVALID") from None
    if len(password) > 4096:
        raise PlatformError("TELEGRAM_DESKTOP_PASSCODE_INVALID")
    body, _ = tdf_payload(data)
    reader = _QtReader(body)
    salt, encrypted = reader.blob(32), reader.blob(512)
    reader.skip_blob()  # encrypted account metadata is opaque
    if len(salt) != 32 or len(encrypted) not in (0, 288):
        raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_INVALID")
    scrypt = None
    if reader.at != len(body):
        salt, encrypted, scrypt = _key_data_wrap(reader, password, salt, encrypted)
    elif len(encrypted) != 288:
        raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_INVALID")
    if scrypt is None:
        derived = hashlib.pbkdf2_hmac("sha512", hashlib.sha512(salt + password + salt).digest(),
            salt, 100000 if password else 1, dklen=256)
    else:
        n, r, p = scrypt
        try:
            derived = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p,
                maxmem=MAX_SCRYPT_MEMORY, dklen=256)
        except (AttributeError, ValueError, MemoryError):
            raise PlatformError("TELEGRAM_DESKTOP_KDF_UNAVAILABLE") from None
    key = _decrypt_local(encrypted, derived)
    if len(key) != 256:
        raise PlatformError("TELEGRAM_DESKTOP_KEY_WRAP_INVALID")
    return key


def _peer(serialized):
    # Official SerializePeerId reserved bit distinguishes old/new peer IDs.
    if serialized & (0x80 << 48):
        value = serialized & ~(0x80 << 48)
        kind, bare = value >> 48, value & 0xffffffffffff
    else:
        if serialized >> 36:
            raise PlatformError("TELEGRAM_DESKTOP_PEER_UNSUPPORTED")
        kind, bare = (serialized >> 32) & 15, serialized & 0xffffffff
    if kind not in (0, 1, 2) or not 0 < bare < 1 << 48:
        raise PlatformError("TELEGRAM_DESKTOP_PEER_UNSUPPORTED")
    return ("user:", "chat:", "channel:")[kind] + str(bare)


def desktop_drafts(data, key):
    """Atomic strict parsing; a damaged last draft publishes no earlier draft.

    Formatting/link preview data is framed without opening links. The basic
    local/topic draft subset excludes cloud/edit/shortcut keys. A draft has no
    observed sent message ID, sender or timestamp.
    """
    body, version = tdf_payload(data)
    container = _QtReader(body)
    encrypted = container.blob(MAX_NATIVE_FILE)
    container.end()
    reader = _QtReader(_decrypt_local(encrypted, key))
    tag = reader.number(">Q")
    if tag not in DESKTOP_TAGS:
        raise PlatformError("TELEGRAM_DESKTOP_DRAFT_FORMAT_UNSUPPORTED")
    peer = _peer(reader.number(">Q"))
    count = reader.number(">I")
    if not 1 <= count <= 1000:
        raise PlatformError("TELEGRAM_DESKTOP_DRAFT_COUNT_INVALID")
    result, keys = [], set()
    for index in range(count):
        draft_key = reader.number(">q")
        # The supported subset is Local()=-1 or a normal topic root ID.
        if draft_key != -1 and not 0 < draft_key < 0x3fffffff:
            raise PlatformError("TELEGRAM_DESKTOP_DRAFT_KEY_UNSUPPORTED")
        if draft_key in keys:
            raise PlatformError("TELEGRAM_DESKTOP_DRAFT_DUPLICATE_KEY")
        keys.add(draft_key)
        text = reader.text()
        reader.blob()  # TextUtilities serialized tags, never text content
        if tag == 0xFFFFFFFFFFFFFF03:
            reader.number(">q")  # reply/edit message ID, NOT this draft's ID
            if reader.number(">i") not in (0, 1, 2):
                raise PlatformError("TELEGRAM_DESKTOP_DRAFT_FLAGS_INVALID")
        else:
            reader.number(">q")  # reply peer, not sender
            reader.number(">q")  # reply/edit ID, not draft message ID
            if tag == 0xFFFFFFFFFFFFFF06:
                reader.number(">Q")
                reader.number(">Q")
            reader.text()  # URL is metadata only, never fetched
            if any(reader.number(">i") not in (0, 1) for _ in range(5)):
                raise PlatformError("TELEGRAM_DESKTOP_DRAFT_FLAGS_INVALID")
        if text:
            result.append(dict(text=text, peer=peer, draft_key=draft_key, index=index,
                version=version, tag=f"0x{tag:016x}"))
    reader.end()
    return result
