# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded text extraction from readable Telegram iOS Postbox schema 25.

Wire layout: TelegramMessenger/Telegram-iOS 1423d5381fcdaaef85565755b087fbed6a4ed97d,
Postbox.swift, MetadataTable.swift, MessageHistory{,Index}Table.swift and
ValueBoxKey.swift. This never unlocks SQLCipher, reads keychains, or interprets
unlinked free bytes as messages. Each t7 row must match its t4 history index.
"""
import hashlib
import re
import struct

MAX_RECORD = 4 * 1024 * 1024
MAX_TEXT = 1024 * 1024
USER_VERSION = 25


class PostboxError(ValueError):
    pass


def _table(connection, name, key_type):
    row = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    if not row or not isinstance(row[0], str) or not re.match(r'CREATE\s+TABLE\b', row[0], re.I):
        return False
    fields = connection.execute('PRAGMA table_xinfo(' + name + ')').fetchall()
    return (len(fields) == 2 and
            (fields[0][1], fields[0][2].upper(), fields[0][5], fields[0][6]) == ('key', key_type, 1, 0) and
            fields[0][3] in (0, 1) and fields[0][4] is None and
            (fields[1][1], fields[1][2].upper(), fields[1][3], fields[1][4], fields[1][5], fields[1][6]) ==
            ('value', 'BLOB', 0, None, 0, 0))


def verify_schema(connection):
    if not (_table(connection, 't0', 'INTEGER') and _table(connection, 't4', 'BLOB') and _table(connection, 't7', 'BLOB')):
        raise PostboxError('TELEGRAM_POSTBOX_SCHEMA_UNSUPPORTED')
    version = connection.execute("SELECT CASE WHEN typeof(value)='blob' AND length(value)=4 THEN value ELSE NULL END FROM t0 WHERE key=1").fetchone()
    if not version or not isinstance(version[0], bytes) or len(version[0]) != 4:
        raise PostboxError('TELEGRAM_POSTBOX_VERSION_UNKNOWN')
    if struct.unpack('<i', version[0])[0] != USER_VERSION:
        raise PostboxError('TELEGRAM_POSTBOX_VERSION_UNSUPPORTED')


class _Reader:
    def __init__(self, data):
        if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_RECORD:
            raise PostboxError('TELEGRAM_POSTBOX_RECORD_INVALID')
        self.data, self.at = data, 0

    def take(self, length):
        if type(length) is not int or length < 0 or length > len(self.data) - self.at:
            raise PostboxError('TELEGRAM_POSTBOX_RECORD_INVALID')
        result = self.data[self.at:self.at + length]
        self.at += length
        return result

    def integer(self, kind):
        return struct.unpack('<' + kind, self.take(struct.calcsize('<' + kind)))[0]

    def text(self):
        size = self.integer('i')
        if not 0 <= size <= MAX_TEXT:
            raise PostboxError('TELEGRAM_POSTBOX_TEXT_LIMIT')
        try:
            result = self.take(size).decode('utf-8', 'strict')
        except UnicodeError:
            raise PostboxError('TELEGRAM_POSTBOX_TEXT_INVALID') from None
        if '\0' in result:
            raise PostboxError('TELEGRAM_POSTBOX_TEXT_INVALID')
        return result

    def objects(self):
        count = self.integer('i')
        if not 0 <= count <= 4096:
            raise PostboxError('TELEGRAM_POSTBOX_OBJECT_LIMIT')
        for _ in range(count):
            self.take(self.integer('i'))
        return count


def decode(key, value, index):
    if not isinstance(key, bytes) or len(key) != 20 or not isinstance(index, bytes) or len(index) != 5:
        raise PostboxError('TELEGRAM_POSTBOX_INDEX_INVALID')
    peer, namespace, timestamp, mid = struct.unpack('>qiii', key)
    if not peer or namespace < 0 or timestamp < 0 or mid == 0:
        raise PostboxError('TELEGRAM_POSTBOX_KEY_INVALID')
    index_flags, index_date = struct.unpack('<Bi', index)
    if index_flags not in (0, 2) or index_date != timestamp:
        raise PostboxError('TELEGRAM_POSTBOX_INDEX_MISMATCH')
    r = _Reader(value)
    if r.integer('B') != 0:
        raise PostboxError('TELEGRAM_POSTBOX_RECORD_TYPE_UNSUPPORTED')
    stable_id, stable_version, data_flags = r.integer('I'), r.integer('I'), r.integer('B')
    if data_flags & ~63:
        raise PostboxError('TELEGRAM_POSTBOX_FLAGS_UNSUPPORTED')
    for bit, width in ((1, 8), (2, 4), (4, 8), (8, 4), (16, 4), (32, 8)):
        if data_flags & bit:
            r.take(width)
    flags, tags = r.integer('I'), r.integer('I')
    if flags & ~0x3f7:
        raise PostboxError('TELEGRAM_POSTBOX_FLAGS_UNSUPPORTED')
    if bool(index_flags & 2) != bool(flags & (4 | 256)):
        raise PostboxError('TELEGRAM_POSTBOX_INDEX_MISMATCH')
    forward = r.integer('B')
    if forward & ~63 or forward and not forward & 1:
        raise PostboxError('TELEGRAM_POSTBOX_FLAGS_UNSUPPORTED')
    if forward:
        r.take(12)
        if forward & 2: r.take(8)
        if forward & 4: r.take(16)
        if forward & 8: r.text()
        if forward & 16: r.text()
        if forward & 32: r.take(4)
    has_author = r.integer('B')
    if has_author not in (0, 1):
        raise PostboxError('TELEGRAM_POSTBOX_AUTHOR_INVALID')
    author = r.integer('q') if has_author else None
    text = r.text()
    attributes, embedded = r.objects(), r.objects()
    references = r.integer('i')
    if not 0 <= references <= 4096:
        raise PostboxError('TELEGRAM_POSTBOX_OBJECT_LIMIT')
    r.take(references * 12)
    if r.at != len(value):
        raise PostboxError('TELEGRAM_POSTBOX_TRAILING_DATA')
    return {'peer': peer, 'namespace': namespace, 'mid': mid, 'date': timestamp,
            'author': author, 'text': text, 'unsent': bool(flags & (1 | 2 | 32)),
            'stable_id': stable_id, 'stable_version': stable_version, 'key_hex': key.hex(),
            'value_sha256': hashlib.sha256(value).hexdigest(),
            'opaque_attributes': attributes, 'opaque_media': embedded + references}


def messages(connection, limit, cancel=None, report=None):
    verify_schema(connection)
    report = report if report is not None else {}
    report.update(checked=0, rejected=0, limited=False)
    query = ('SELECT key,CASE WHEN typeof(value)=\'blob\' AND length(value)<=? THEN value ELSE NULL END '
             'FROM t7 ORDER BY key LIMIT ?')
    for key, value in connection.execute(query, (MAX_RECORD, limit + 1)):
        if cancel and cancel():
            raise PostboxError('CANCELLED')
        if report['checked'] >= limit:
            report['limited'] = True
            break
        report['checked'] += 1
        try:
            index_key = key[:12] + key[16:] if isinstance(key, bytes) and len(key) == 20 else b''
            found = connection.execute('SELECT value FROM t4 WHERE key=? AND length(value)=5', (index_key,)).fetchone()
            yield decode(key, value, found[0] if found else None)
        except PostboxError as error:
            report['rejected'] += 1
            report[str(error)] = report.get(str(error), 0) + 1
