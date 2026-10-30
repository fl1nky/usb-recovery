"""Independent HPROF envelopes plus an actual owned HotSpot heap control."""
from pathlib import Path
from contextlib import closing
import hashlib
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'helpers/recovery_engine'), str(ROOT / 'tests')]
import android_heap


class Heap:
    """Test writer from the documented binary envelope; not a production API."""
    def __init__(self, width=4, version='1.0.3', compact=None):
        self.width, self.version, self.compact = width, version, compact
        self.serial, self.symbols, self.classes, self.parts, self.loads = 1000, {}, {}, [], []
        self.obj = self.klass('java.lang.Object', 0, [])
        fields = [('value', 2)] + ([('coder', 8)] if compact else [])
        self.string = self.klass('java.lang.String', self.obj, fields)
        if compact in {'le', 'be'}:
            shifts = (0, 8) if compact == 'le' else (8, 0)
            self.klass('java.lang.StringUTF16', self.obj, [], [('HI_BYTE_SHIFT', 10, shifts[0]), ('LO_BYTE_SHIFT', 10, shifts[1])])
        self.base = self.klass('org.telegram.tgnet.TLRPC$Message', self.obj,
            [('id', 10), ('date', 10), ('message', 2), ('peer_id', 2), ('from_id', 2)])
        self.message = self.klass('org.telegram.tgnet.TLRPC$TL_message', self.base, [])
        self.peer = self.klass('org.telegram.tgnet.TLRPC$TL_peerUser', self.obj, [('user_id', 11)])

    def new(self):
        self.serial += 1
        return self.serial

    def ident(self, value):
        return value.to_bytes(self.width, 'big')

    def symbol(self, name):
        if name not in self.symbols:
            self.symbols[name] = self.new()
        return self.symbols[name]

    def pack(self, kind, value):
        size = self.width if kind == 2 else {4: 1, 5: 2, 6: 4, 7: 8, 8: 1, 9: 2, 10: 4, 11: 8}[kind]
        return int(value).to_bytes(size, 'big', signed=kind in {8, 9, 10, 11})

    def klass(self, name, parent, fields, statics=()):
        value = self.new()
        self.loads.append(struct.pack('>I', value) + self.ident(value) + b'\0'*4 + self.ident(self.symbol(name)))
        body = self.ident(value) + b'\0'*4 + self.ident(parent) + b'\0'*(self.width*5) + b'\0'*4 + b'\0'*2
        body += struct.pack('>H', len(statics))
        for key, kind, content in statics:
            body += self.ident(self.symbol(key)) + bytes([kind]) + self.pack(kind, content)
        body += struct.pack('>H', len(fields))
        for key, kind in fields:
            body += self.ident(self.symbol(key)) + bytes([kind])
        self.classes[value] = (parent, fields)
        self.parts.append(b'\x20' + body)
        return value

    def instance(self, cls, values):
        ident, fields, at = self.new(), [], cls
        while at:
            parent, own = self.classes[at]
            fields.extend(own)
            at = parent
        body = b''.join(self.pack(kind, values.get(name, 0)) for name, kind in fields)
        self.parts.append(b'\x21' + self.ident(ident) + b'\0'*4 + self.ident(cls) + struct.pack('>I', len(body)) + body)
        return ident

    def text(self, text, count=None):
        ident = self.new()
        if self.compact:
            kind, coder = 8, 0 if text.isascii() else 1
            raw = text.encode('latin-1' if coder == 0 else 'utf-16-' + ('be' if self.compact == 'be' else 'le'))
        else:
            kind, coder, raw = 5, None, text.encode('utf-16-be')
        count = len(raw) // (2 if kind == 5 else 1) if count is None else count
        self.parts.append(b'\x23' + self.ident(ident) + b'\0'*4 + struct.pack('>IB', count, kind) + raw)
        values = {'value': ident}
        if coder is not None:
            values['coder'] = coder
        return self.instance(self.string, values)

    def add_message(self, text='recipe 🥧\nвторая строка', mid=31, cls=None, **extra):
        peer = self.instance(self.peer, {'user_id': 71})
        sender = self.instance(self.peer, {'user_id': 72})
        values = dict(id=mid, date=1700000000, message=self.text(text), peer_id=peer, from_id=sender)
        values.update(extra)
        return self.instance(cls or self.message, values)

    def data(self, end=True):
        def record(kind, data):
            return struct.pack('>BII', kind, 0, len(data)) + data
        symbols = b''.join(record(1, self.ident(ident) + key.encode('utf-8')) for key, ident in self.symbols.items())
        loads = b''.join(record(2, body) for body in self.loads)
        return (b'JAVA PROFILE ' + self.version.encode('ascii') + b'\0' + struct.pack('>IQ', self.width, 1700000000000) +
                symbols + loads + record(0x1c, b''.join(self.parts)) + (record(0x2c, b'') if end else b''))


class AndroidHeap(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / '.build/heap-tests'
        self.base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=self.base)
        self.work = Path(self.temp.name)

    def tearDown(self):
        assert self.work.resolve().is_relative_to(self.base.resolve())
        self.temp.cleanup()

    def parse(self, heap, **options):
        self.path = self.work / 'provided.hidden'
        self.path.write_bytes(heap.data() if isinstance(heap, Heap) else heap)
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        report = android_heap.recover(self.path, self.work / 'scratch', **options)
        self.assertEqual(report['source_sha256'], before)
        self.assertTrue(report['source_unchanged'])
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), before)
        self.assertEqual(list((self.work / 'scratch').iterdir()), [])
        return report['records']

    def test_art_char_array_unicode_and_inherited_fields(self):
        for width in (4, 8):
            with self.subTest(width=width):
                h = Heap(width); h.add_message()
                rows = self.parse(h)
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row['text'], 'recipe 🥧\nвторая строка')
                self.assertEqual((row['candidate_message_id'], row['candidate_peer'], row['candidate_sender']), (31, 'user:71', 'user:72'))
                with self.path.open('rb') as stream:
                    stream.seek(row['byte_offset'])
                    self.assertEqual(stream.read(row['byte_length']).decode('utf-16-be'), row['text'])

    def test_compact_strings_native_byte_order_from_static_fields(self):
        for order in ('le', 'be'):
            h = Heap(compact=order); h.add_message()
            rows = self.parse(h)
            self.assertEqual(rows[0]['text'], 'recipe 🥧\nвторая строка')
            self.assertEqual(rows[0]['encoding'], 'utf-16-' + order)

    def test_unknown_compact_byte_order_is_not_guessed(self):
        h = Heap(compact='unknown'); h.add_message()
        self.assertEqual(self.parse(h), [])

    def test_unrelated_class_text_is_not_a_message(self):
        h = Heap(); other = h.klass('unrelated.TL_message', h.base, [])
        h.add_message(cls=other)
        self.assertEqual(self.parse(h), [])

    def test_known_class_requires_known_message_base(self):
        h = Heap(); _, fields = h.classes[h.base]
        other = h.klass('org.telegram.tgnet.TLRPC$TL_message_layer999', h.obj, fields)
        h.add_message(cls=other)
        self.assertEqual(self.parse(h), [])

    def test_truncation_and_missing_segment_end_never_publish(self):
        h = Heap(); h.add_message()
        for data in (h.data(False), h.data()[:-1], h.data()[:-13]):
            with self.subTest(size=len(data)), self.assertRaises(android_heap.HeapError):
                self.parse(data)

    def test_duplicate_object_identifiers_are_rejected(self):
        h = Heap(); h.add_message(); h.parts.append(h.parts[-1])
        with self.assertRaisesRegex(android_heap.HeapError, 'DUPLICATE_IDENTIFIER'):
            self.parse(h)

    def test_invalid_array_count_is_bounded(self):
        h = Heap(); text = h.text('recipe', count=0xffffffff)
        h.add_message(message=text)
        with self.assertRaises(android_heap.HeapError):
            self.parse(h)

    def test_keyword_filter_and_equal_text_distinct_objects(self):
        h = Heap(); h.add_message('recipe'); h.add_message('recipe', mid=32); h.add_message('other', mid=33)
        rows = self.parse(h, matcher=lambda text: text == 'recipe')
        self.assertEqual([row['candidate_message_id'] for row in rows], [31, 32])
        self.assertNotEqual(rows[0]['heap_object_id'], rows[1]['heap_object_id'])

    def test_cancel_and_resource_limits_fail_explicitly(self):
        h = Heap(); h.add_message()
        for options, code in ((dict(cancel=lambda: True), 'CANCELLED'), (dict(max_objects=1), 'OBJECT_LIMIT'), (dict(limit=0), 'RESULT_LIMIT')):
            with self.subTest(code=code), self.assertRaisesRegex(android_heap.HeapError, code):
                self.parse(h, **options)

    def test_source_mutation_with_restored_mtime_is_rejected(self):
        h = Heap(); h.add_message()
        original = android_heap.HeapIndex.messages
        def mutate(reader, *args, **kwargs):
            result = original(reader, *args, **kwargs)
            state = self.path.stat()
            with self.path.open('r+b') as stream:
                stream.seek(24); value = stream.read(1); stream.seek(24); stream.write(bytes([value[0] ^ 1]))
            os.utime(self.path, ns=(state.st_atime_ns, state.st_mtime_ns))
            return result
        with patch.object(android_heap.HeapIndex, 'messages', mutate), self.assertRaisesRegex(android_heap.HeapError, 'SOURCE_CHANGED'):
            self.parse(h)

    def test_automatic_header_import_keeps_graph_unattributed(self):
        import engine
        import telegram_auto
        import archive_search
        h = Heap(); h.add_message()
        source = self.work / 'provided.hidden'
        source.write_bytes(h.data())
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        output = self.work / 'archive'
        request = dict(protocol=1, operation='telegram_analyze', destination=str(output),
                       options=dict(roots=[str(source)], scan_fragments=False))
        with patch.object(engine, 'emit', lambda *args, **kwargs: None):
            result = telegram_auto.analyze(request, engine.Importer, lambda *args, **kwargs: None)
        self.assertEqual(result['structured_fragment_records'], 1)
        import json
        rows = [json.loads(line) for line in (output / 'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertEqual(len(rows), 1)
        row = archive_search._normalized(rows[0])
        self.assertEqual(row['record_kind'], 'android_heap_message')
        for field in ('chat_id', 'sender_id', 'timestamp', 'message_id', 'deleted'):
            self.assertIsNone(row.get(field), field)
        self.assertEqual((row['candidate_message_id'], row['candidate_peer'], row['candidate_sender']), (31, 'user:71', 'user:72'))
        self.assertEqual(row['heap_class'], 'org.telegram.tgnet.TLRPC$TL_message')
        self.assertEqual(row['heap_text_sha256'], hashlib.sha256(row['text'].encode('utf-8')).hexdigest())
        self.assertEqual(row['evidence_kind'], 'fragment')
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

    def test_raw_scan_does_not_repeat_structured_heap_text(self):
        import engine
        import telegram_auto
        import json
        h = Heap(); h.add_message('recipe long reference message')
        source = self.work / 'provided.hprof'; source.write_bytes(h.data())
        output = self.work / 'archive'
        request = dict(protocol=1, operation='telegram_analyze', destination=str(output),
                       options=dict(roots=[str(source)], scan_fragments=True,
                                    fragment_query='recipe', query_mode='literal'))
        with patch.object(engine, 'emit', lambda *args, **kwargs: None):
            telegram_auto.analyze(request, engine.Importer, lambda *args, **kwargs: None)
        rows = [json.loads(line) for line in (output / 'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['record_kind'], 'android_heap_message')

    @unittest.skipUnless(shutil.which('java') and shutil.which('javac'), 'Developer JDK unavailable; real JVM control not run')
    def test_real_owned_hotspot_heap_independent_writer(self):
        from build_telegram_heap_fixtures import build
        manifest = build(self.work / 'jvm')
        path = self.work / 'jvm' / manifest['path']
        result = android_heap.recover(path, self.work / 'scratch')
        self.assertEqual(result['source_sha256'], manifest['sha256'])
        self.assertEqual(len(result['records']), 2)
        for expected, row in zip(manifest['expected'], sorted(result['records'], key=lambda row: row['candidate_message_id'])):
            self.assertEqual((row['text'], row['candidate_message_id'], row['candidate_date']), (expected['text'], expected['id'], expected['date']))
            self.assertEqual((row['candidate_peer'], row['candidate_sender']), (expected['peer'], expected['sender']))
        self.assertNotIn('PRIVATE_CANARY', str(result['records']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
