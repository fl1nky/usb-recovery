"""Read supplied HPROF files; never attach to a process or collect credentials.

References: OpenJDK HPROF Agent binary format and AOSP ART hprof.cc.
Object IDs are dump identifiers, not permission to access virtual addresses.
Recognized Java object graphs remain structured, unattributed candidates.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import tempfile
import time


class HeapError(Exception):
    pass


SIZES = {4: 1, 5: 2, 6: 4, 7: 8, 8: 1, 9: 2, 10: 4, 11: 8}
ROOTS = {0xff: (1, 0), 1: (2, 0), 2: (1, 8), 3: (1, 8),
         4: (1, 4), 5: (1, 0), 6: (1, 4), 7: (1, 0), 8: (1, 8),
         0x89: (1, 0), 0x8a: (1, 0), 0x8b: (1, 0), 0x8c: (1, 0),
         0x8d: (1, 0), 0x8e: (1, 8), 0x90: (1, 0)}
WANTED = {'id', 'date', 'message', 'peer_id', 'to_id', 'from_id', 'dialog_id',
          'user_id', 'chat_id', 'channel_id', 'value', 'coder', 'offset', 'count'}
MESSAGE = re.compile(r'org\.telegram\.tgnet\.TLRPC\$TL_message(?:_layer[0-9]+)?\Z')


class HeapIndex:
    def __init__(self, source, database, *, cancel=None, progress=None, max_objects=1_000_000,
                 max_seconds=120, max_text_bytes=64 * 1024 * 1024):
        self.source, self.db = source, database
        self.cancel, self.progress = cancel, progress
        self.max_objects, self.max_text_bytes = max_objects, max_text_bytes
        self.deadline = time.monotonic() + max_seconds
        self.objects = self.strings = self.string_bytes = self.fields = self.classes = 0
        self.limit = self.size = os.fstat(source.fileno()).st_size
        self.id_size = 0
        self.heap_count, self.segmented, self.ended = 0, False, False
        self.byte_order = None
        self.layouts = {}
        self.db.executescript('''
            PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-4096;
            CREATE TABLE strings(id BLOB PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE names(id BLOB PRIMARY KEY, symbol BLOB NOT NULL);
            CREATE TABLE classes(id BLOB PRIMARY KEY, parent BLOB NOT NULL,
                fields TEXT NOT NULL, statics TEXT NOT NULL, position INTEGER NOT NULL);
            CREATE TABLE objects(id BLOB PRIMARY KEY, kind INTEGER NOT NULL,
                cls BLOB, position INTEGER NOT NULL, bytes INTEGER NOT NULL,
                element INTEGER, count INTEGER);
            CREATE INDEX byclass ON objects(cls);
        ''')

    def check(self):
        if self.cancel and self.cancel():
            raise HeapError('HPROF_CANCELLED')
        if time.monotonic() > self.deadline:
            raise HeapError('HPROF_TIME_LIMIT')

    def read(self, count):
        if count < 0 or count > self.limit - self.source.tell():
            raise HeapError('HPROF_TRUNCATED')
        value = self.source.read(count)
        if len(value) != count:
            raise HeapError('HPROF_TRUNCATED')
        return value

    def skip(self, count):
        if count < 0 or count > self.limit - self.source.tell():
            raise HeapError('HPROF_TRUNCATED')
        self.source.seek(count, 1)

    def number(self, count):
        return int.from_bytes(self.read(count), 'big')

    def ident(self):
        return self.read(self.id_size)

    @staticmethod
    def defined(ident):
        if not any(ident):
            raise HeapError('HPROF_NULL_IDENTIFIER')
        return ident

    def width(self, kind):
        if kind == 2:
            return self.id_size
        if kind not in SIZES:
            raise HeapError('HPROF_FIELD_TYPE_UNSUPPORTED')
        return SIZES[kind]

    def object(self, ident, kind, cls, position, length, element=None, count=None):
        self.defined(ident)
        self.objects += 1
        if self.objects > self.max_objects:
            raise HeapError('HPROF_OBJECT_LIMIT')
        self.db.execute('INSERT INTO objects VALUES(?,?,?,?,?,?,?)',
                        (ident, kind, cls, position, length, element, count))
        if self.objects % 4096 == 0:
            self.check()
            if self.progress:
                self.progress(self.source.tell(), self.size)

    def class_record(self, position):
        self.classes += 1
        if self.classes > 50000:
            raise HeapError('HPROF_CLASS_LIMIT')
        ident = self.ident()
        self.skip(4)
        parent = self.ident()
        self.skip(5 * self.id_size + 4)
        for _ in range(self.number(2)):
            self.skip(2)
            self.skip(self.width(self.number(1)))
        statics = []
        for _ in range(self.number(2)):
            name, kind = self.ident(), self.number(1)
            statics.append((name.hex(), kind, self.source.tell()))
            self.skip(self.width(kind))
        fields = []
        for _ in range(self.number(2)):
            name, kind = self.ident(), self.number(1)
            self.width(kind)
            fields.append((name.hex(), kind))
        self.fields += len(fields) + len(statics)
        if len(fields) > 1024 or self.fields > 1_000_000:
            raise HeapError('HPROF_FIELD_LIMIT')
        self.db.execute('INSERT INTO classes VALUES(?,?,?,?,?)',
                        (ident, parent, json.dumps(fields), json.dumps(statics), position))
        self.object(ident, 0x20, None, position, self.source.tell() - position)

    def heap(self):
        while self.source.tell() < self.limit:
            position, tag = self.source.tell(), self.number(1)
            if tag in ROOTS:
                ids, extra = ROOTS[tag]
                self.skip(ids * self.id_size + extra)
            elif tag == 0xfe:
                self.skip(4 + self.id_size)
            elif tag == 0x20:
                self.class_record(position)
            elif tag == 0x21:
                ident = self.ident()
                self.skip(4)
                cls, length = self.ident(), self.number(4)
                self.object(ident, tag, cls, self.source.tell(), length)
                self.skip(length)
            elif tag in {0x22, 0x23, 0xc3}:
                ident = self.ident()
                self.skip(4)
                count = self.number(4)
                if tag == 0x22:
                    cls, element, width = self.ident(), 2, self.id_size
                else:
                    cls, element = None, self.number(1)
                    if element == 2:
                        raise HeapError('HPROF_PRIMITIVE_TYPE_INVALID')
                    width = self.width(element)
                length = 0 if tag == 0xc3 else count * width
                self.object(ident, tag, cls, self.source.tell(), length, element, count)
                self.skip(length)
            else:
                raise HeapError('HPROF_HEAP_TAG_UNSUPPORTED')
            self.check()

    def index(self):
        header = bytearray()
        for _ in range(32):
            value = self.read(1)
            if value == b'\0':
                break
            header.extend(value)
        else:
            raise HeapError('HPROF_HEADER_INVALID')
        if bytes(header) not in {b'JAVA PROFILE 1.0.1', b'JAVA PROFILE 1.0.2', b'JAVA PROFILE 1.0.3'}:
            raise HeapError('HPROF_VERSION_UNSUPPORTED')
        self.version = header.decode('ascii')
        self.id_size = self.number(4)
        if self.id_size not in {4, 8}:
            raise HeapError('HPROF_ID_SIZE_UNSUPPORTED')
        self.timestamp_ms = self.number(8)
        while self.source.tell() < self.size:
            self.check()
            self.limit = self.size
            tag = self.number(1)
            self.skip(4)
            length = self.number(4)
            end = self.source.tell() + length
            if end > self.size:
                raise HeapError('HPROF_TRUNCATED')
            self.limit = end
            if tag == 1:
                ident = self.defined(self.ident())
                if length - self.id_size > 1024 * 1024:
                    raise HeapError('HPROF_SYMBOL_LIMIT')
                data = self.read(length - self.id_size)
                self.strings += 1
                self.string_bytes += len(data)
                if self.strings > 500_000 or self.string_bytes > 64 * 1024 * 1024:
                    raise HeapError('HPROF_SYMBOL_LIMIT')
                try:
                    value = data.replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogatepass')
                    value = value.encode('utf-16-le', 'surrogatepass').decode('utf-16-le')
                except UnicodeError:
                    value = ''  # Unrecognized metadata cannot match a known class.
                self.db.execute('INSERT INTO strings VALUES(?,?)', (ident, value))
            elif tag == 2:
                self.skip(4)
                ident = self.defined(self.ident())
                self.skip(4)
                self.db.execute('INSERT INTO names VALUES(?,?)', (ident, self.ident()))
            elif tag in {0x0c, 0x1c}:
                if self.ended or self.heap_count and (tag == 0x0c or not self.segmented):
                    raise HeapError('HPROF_MULTIPLE_SNAPSHOTS_UNSUPPORTED')
                self.heap_count += 1
                self.segmented |= tag == 0x1c
                self.heap()
            elif tag == 0x2c:
                if length or not self.heap_count or not self.segmented or self.ended:
                    raise HeapError('HPROF_END_INVALID')
                self.ended = True
            else:
                self.skip(length)
            if self.source.tell() != end:
                raise HeapError('HPROF_RECORD_LENGTH_INVALID')
        if not self.heap_count or self.segmented and not self.ended:
            raise HeapError('HPROF_INCOMPLETE')
        self.limit = self.size
        self.db.commit()

    def symbol(self, ident):
        if not any(ident):
            return None
        row = self.db.execute('SELECT value FROM strings WHERE id=? AND length(value)<=1024', (ident,)).fetchone()
        return row[0] if row else None

    def name(self, ident):
        row = self.db.execute('SELECT symbol FROM names WHERE id=?', (ident,)).fetchone()
        return self.symbol(row[0]).replace('/', '.') if row and self.symbol(row[0]) else None

    def layout(self, cls):
        original = cls
        if original in self.layouts:
            return self.layouts[original]
        fields, visited, names = [], set(), set()
        while any(cls):
            if cls in visited or len(visited) >= 64:
                raise HeapError('HPROF_CLASS_CYCLE')
            visited.add(cls)
            row = self.db.execute('SELECT parent,fields FROM classes WHERE id=?', (cls,)).fetchone()
            if not row:
                return None
            for ident, kind in json.loads(row[1]):
                name = self.symbol(bytes.fromhex(ident))
                if not name or name in names:
                    return None
                fields.append((name, kind))
                names.add(name)
                if len(fields) > 4096:
                    return None
            cls = row[0]
        result = tuple(fields)
        if len(self.layouts) < 256:
            self.layouts[original] = result
        return result

    def instance(self, ident):
        if not any(ident):
            return None
        row = self.db.execute('SELECT cls,position,bytes FROM objects WHERE id=? AND kind=33', (ident,)).fetchone()
        if not row:
            return None
        fields = self.layout(row[0])
        if fields is None or sum(self.width(kind) for _, kind in fields) != row[2]:
            return None
        self.source.seek(row[1])
        values = {}
        for name, kind in fields:
            raw = self.read(self.width(kind))
            if name in WANTED:
                if kind == 2:
                    value = raw
                elif kind in {4, 5, 8, 9, 10, 11}:
                    value = int.from_bytes(raw, 'big', signed=kind in {8, 9, 10, 11})
                else:
                    value = None
                values[name] = (kind, value)
        return self.name(row[0]), values, row[1], row[2]

    def compact_byte_order(self):
        rows = self.db.execute('''SELECT c.statics FROM classes c JOIN names n ON n.id=c.id
            JOIN strings s ON s.id=n.symbol WHERE s.value IN
            ('java.lang.StringUTF16','java/lang/StringUTF16')''').fetchall()
        found = set()
        for row in rows:
            shifts = {}
            for name, kind, position in json.loads(row[0]):
                name = self.symbol(bytes.fromhex(name))
                if kind == 10 and name in {'HI_BYTE_SHIFT', 'LO_BYTE_SHIFT'}:
                    self.source.seek(position)
                    shifts[name] = self.number(4)
            pair = shifts.get('HI_BYTE_SHIFT'), shifts.get('LO_BYTE_SHIFT')
            if pair == (0, 8):
                found.add('utf-16-le')
            elif pair == (8, 0):
                found.add('utf-16-be')
        return next(iter(found)) if len(found) == 1 else None

    def string(self, ident):
        instance = self.instance(ident)
        if not instance or instance[0] != 'java.lang.String':
            return None
        fields = instance[1]
        if fields.get('value', (None,))[0] != 2:
            return None
        array = self.db.execute('SELECT kind,position,bytes,element,count FROM objects WHERE id=?',
                                (fields['value'][1],)).fetchone()
        if not array or array[0] != 0x23 or array[2] > 256 * 1024:
            return None
        _, position, length, element, count = array
        if element == 5:
            start = fields.get('offset', (10, 0))
            end = fields.get('count', (10, count))
            if start[0] != 10 or end[0] != 10 or not 0 <= start[1] <= count or not 0 <= end[1] <= count - start[1]:
                return None
            position += start[1] * 2
            length, encoding = end[1] * 2, 'utf-16-be'
        elif element == 8:
            coder = fields.get('coder')
            if coder is None or coder[0] != 8 or coder[1] not in {0, 1} or 'offset' in fields or 'count' in fields:
                return None
            encoding = 'latin-1' if coder[1] == 0 else self.byte_order
            if encoding is None or coder[1] == 1 and length % 2:
                return None
        else:
            return None
        self.source.seek(position)
        try:
            text = self.read(length).decode(encoding)
        except UnicodeError:
            return None
        if not text.strip() or len(text) > 65536:
            return None
        return text, position, length, encoding

    def peer(self, field):
        if not field or field[0] != 2:
            return None
        instance = self.instance(field[1])
        if not instance:
            return None
        name, fields, _, _ = instance
        for kind in ('User', 'Chat', 'Channel'):
            if name != 'org.telegram.tgnet.TLRPC$TL_peer' + kind:
                continue
            value = fields.get(kind.lower() + '_id')
            if value and value[0] in {10, 11} and 0 < value[1] < 2**63:
                return kind.lower() + ':' + str(value[1])
        return None

    def message_class(self, cls):
        seen = set()
        while any(cls):
            if cls in seen or len(seen) >= 64:
                return False
            seen.add(cls)
            if self.name(cls) == 'org.telegram.tgnet.TLRPC$Message':
                return True
            row = self.db.execute('SELECT parent FROM classes WHERE id=?', (cls,)).fetchone()
            if not row:
                break
            cls = row[0]
        return False

    def messages(self, matcher=None, limit=20000):
        self.byte_order = self.compact_byte_order()
        classes = []
        for (ident,) in self.db.execute('SELECT id FROM classes'):
            self.check()
            name = self.name(ident)
            if name and MESSAGE.fullmatch(name) and self.message_class(ident):
                classes.append(ident)
        records, text_bytes = [], 0
        for cls in classes:
            for (ident,) in self.db.execute('SELECT id FROM objects WHERE cls=? AND kind=33', (cls,)):
                self.check()
                instance = self.instance(ident)
                if not instance:
                    continue
                name, fields, position, length = instance
                if fields.get('id', (None,))[0] != 10 or fields.get('date', (None,))[0] != 10 or fields.get('message', (None,))[0] != 2:
                    continue
                value = self.string(fields['message'][1])
                if value is None or matcher and not matcher(value[0]):
                    continue
                text, offset, byte_length, encoding = value
                peer = self.peer(fields.get('peer_id') or fields.get('to_id'))
                sender = self.peer(fields.get('from_id'))
                if not sender and fields.get('from_id', (None,))[0] == 10 and fields['from_id'][1] > 0:
                    sender = 'user:' + str(fields['from_id'][1])
                mid, date = fields['id'][1], fields['date'][1]
                if not mid or not 946684800 <= date <= 4102444800:
                    continue
                self.source.seek(position)
                record_hash = hashlib.sha256(self.read(length)).hexdigest()
                text_bytes += len(text.encode('utf-8'))
                if len(records) >= limit or text_bytes > self.max_text_bytes:
                    raise HeapError('HPROF_RESULT_LIMIT')
                records.append(dict(text=text, byte_offset=offset, byte_length=byte_length,
                    encoding=encoding, physical_byte_offset=position, offset_kind='hprof_instance_data',
                    candidate_message_id=mid, candidate_peer=peer, candidate_sender=sender,
                    candidate_date=date, heap_class=name, heap_object_id=ident.hex(),
                    heap_record_sha256=record_hash, heap_record_length=length,
                    heap_text_sha256=hashlib.sha256(text.encode('utf-8')).hexdigest(),
                    heap_snapshot_ms=self.timestamp_ms, heap_version=self.version,
                    heap_identifier_bytes=self.id_size, proof='hprof_class_and_object_references',
                    source_record='hprof-object:' + ident.hex()))
        return records


def recover(path, workspace, *, matcher=None, cancel=None, progress=None,
            max_objects=1_000_000, max_seconds=120, limit=20000):
    """Return candidates only after complete framing and source identity checks.

    The temporary SQLite index stores metadata and offsets, never resolved
    message bodies or credential fields. It is removed when the reader exits.
    """
    path, workspace = Path(path), Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='hprof-', dir=workspace) as directory:
        if not Path(directory).resolve().is_relative_to(workspace.resolve()):
            raise HeapError('HPROF_WORKSPACE_INVALID')
        with path.open('rb') as source, closing(sqlite3.connect(str(Path(directory) / 'index.sqlite'))) as database:
            identity = os.fstat(source.fileno())
            if identity.st_size > 2 * 1024 * 1024 * 1024:
                raise HeapError('HPROF_SOURCE_LIMIT')
            reader = HeapIndex(source, database, cancel=cancel, progress=progress,
                               max_objects=max_objects, max_seconds=max_seconds)
            def digest():
                source.seek(0)
                value = hashlib.sha256()
                while block := source.read(1024 * 1024):
                    reader.check()
                    value.update(block)
                return value.hexdigest()
            before = digest()
            source.seek(0)
            try:
                reader.index()
                records = reader.messages(matcher, limit)
            except sqlite3.IntegrityError:
                raise HeapError('HPROF_DUPLICATE_IDENTIFIER') from None
            after = digest()
            state, current = os.fstat(source.fileno()), path.stat()
            if ((identity.st_size, identity.st_mtime_ns, identity.st_ino) !=
                    (state.st_size, state.st_mtime_ns, state.st_ino) or
                    state.st_ino != current.st_ino or before != after):
                raise HeapError('HPROF_SOURCE_CHANGED')
            return dict(schema=1, status='complete', source_sha256=before,
                        source_unchanged=True, objects=reader.objects, records=records)
