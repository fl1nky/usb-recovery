"""Independent malformed HPROF envelopes; no production fixture writer is used."""
from pathlib import Path
import hashlib
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'helpers/recovery_engine'))
import android_heap


def top(tag, payload=b''):
    return struct.pack('>BII', tag, 0, len(payload)) + payload


class Envelope:
    """A deliberately small, separately written envelope with fixed identifiers."""
    def __init__(self, width=4):
        self.width = width
        self.symbols = {}
        self.loads = []
        self.parts = []
        self.names = {
            6: 'java.lang.Object', 1: 'org.telegram.tgnet.TLRPC$Message',
            2: 'org.telegram.tgnet.TLRPC$TL_message', 3: 'java.lang.String',
            4: 'org.telegram.tgnet.TLRPC$TL_peerUser',
        }
        self.parents = {6: 0, 1: 6, 2: 1, 3: 6, 4: 6}
        self.fields = {6: [], 1: [('id', 10), ('date', 10), ('message', 2),
                                      ('peer_id', 2), ('from_id', 2)],
                       2: [], 3: [('value', 2)], 4: [('user_id', 11)]}
        self.text = 'independent recipe\nпирожки 🥧'
        self.message_ref = 21
        self.array_ref = 20
        self.message_tail = b''

    def ident(self, value):
        return value.to_bytes(self.width, 'big')

    def sym(self, text):
        if text not in self.symbols:
            self.symbols[text] = 100 + len(self.symbols)
        return self.ident(self.symbols[text])

    def instance(self, ident, cls, payload):
        return (b'\x21' + self.ident(ident) + b'\0' * 4 + self.ident(cls) +
                struct.pack('>I', len(payload)) + payload)

    def elements(self):
        classes = []
        self.loads = []
        for ident in (6, 1, 2, 3, 4):
            self.loads.append(top(2, struct.pack('>I', ident) + self.ident(ident) +
                                  b'\0' * 4 + self.sym(self.names[ident])))
            fields = self.fields[ident]
            body = self.ident(ident) + b'\0' * 4 + self.ident(self.parents[ident])
            body += b'\0' * (5 * self.width + 4) + b'\0' * 4
            body += struct.pack('>H', len(fields))
            for name, kind in fields:
                body += self.sym(name) + bytes([kind])
            classes.append(b'\x20' + body)
        encoded = self.text.encode('utf-16-be')
        array = b'\x23' + self.ident(20) + b'\0' * 4 + struct.pack('>IB', len(encoded) // 2, 5) + encoded
        string = self.instance(21, 3, self.ident(self.array_ref))
        peer = self.instance(22, 4, struct.pack('>q', 71))
        sender = self.instance(23, 4, struct.pack('>q', 72))
        message = self.instance(24, 2, struct.pack('>ii', 31, 1700000000) +
                                self.ident(self.message_ref) + self.ident(22) + self.ident(23) + self.message_tail)
        return classes + [array, string, peer, sender, message]

    def header(self):
        return b'JAVA PROFILE 1.0.3\0' + struct.pack('>IQ', self.width, 1700000000000)

    def metadata(self):
        return (b''.join(top(1, self.ident(ident) + name.encode('utf-8'))
                         for name, ident in self.symbols.items()) + b''.join(self.loads))

    def data(self, *, parts=None, records=None):
        generated = self.elements()
        parts = generated if parts is None else parts
        records = [top(0x1c, b''.join(parts)), top(0x2c)] if records is None else records
        return self.header() + self.metadata() + b''.join(records)


class AndroidHeapAudit(unittest.TestCase):
    def setUp(self):
        base = ROOT / '.build/android-heap-audit'
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.work = Path(self.temp.name)
        self.path = self.work / 'provided.hidden'

    def tearDown(self):
        self.temp.cleanup()

    def parse(self, raw, **kwargs):
        self.path.write_bytes(raw)
        expected = hashlib.sha256(raw).hexdigest()
        try:
            result = android_heap.recover(self.path, self.work / 'index', **kwargs)
            self.assertEqual(result['source_sha256'], expected)
            self.assertTrue(result['source_unchanged'])
            return result['records']
        finally:
            self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), expected)
            self.assertEqual(list((self.work / 'index').iterdir()), [])

    def test_independent_positive_and_physical_proof(self):
        for width in (4, 8):
            with self.subTest(width=width):
                h = Envelope(width)
                raw = h.data()
                rows = self.parse(raw)
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row['text'], h.text)
                self.assertEqual((row['candidate_message_id'], row['candidate_peer'], row['candidate_sender']),
                                 (31, 'user:71', 'user:72'))
                self.assertEqual(raw[row['byte_offset']:row['byte_offset'] + row['byte_length']].decode('utf-16-be'), h.text)
                record = raw[row['physical_byte_offset']:row['physical_byte_offset'] + row['heap_record_length']]
                self.assertEqual(hashlib.sha256(record).hexdigest(), row['heap_record_sha256'])
                for unknown in ('message_id', 'chat_id', 'sender_id', 'deleted', 'timestamp'):
                    self.assertNotIn(unknown, row)

    def test_complete_unsegmented_and_split_segmented_controls(self):
        h = Envelope(); pieces = h.elements()
        for records in ([top(0x0c, b''.join(pieces))],
                        [top(0x1c, b''.join(pieces[:-1])), top(0x1c, pieces[-1]), top(0x2c)]):
            self.assertEqual(len(self.parse(h.data(records=records))), 1)

    def test_multiple_unsegmented_snapshots_cannot_cross_link(self):
        h = Envelope(); pieces = h.elements()
        records = [top(0x0c, b''.join(pieces[:-1])), top(0x0c, pieces[-1])]
        with self.assertRaisesRegex(android_heap.HeapError, 'MULTIPLE_SNAPSHOTS'):
            self.parse(h.data(records=records))

    def test_segmented_and_unsegmented_snapshots_cannot_cross_link(self):
        h = Envelope(); pieces = h.elements()
        combinations = ([top(0x1c, b''.join(pieces[:-1])), top(0x0c, pieces[-1])],
                        [top(0x0c, b''.join(pieces[:-1])), top(0x1c, pieces[-1]), top(0x2c)],
                        [top(0x1c, b''.join(pieces)), top(0x2c), top(0x1c), top(0x2c)])
        for records in combinations:
            with self.subTest(tags=[r[0] for r in records]), self.assertRaisesRegex(android_heap.HeapError, 'MULTIPLE_SNAPSHOTS'):
                self.parse(h.data(records=records))

    def test_invalid_segment_end_never_publishes(self):
        h = Envelope(); pieces = h.elements()
        for records in ([top(0x1c, b''.join(pieces))],
                        [top(0x2c), top(0x1c, b''.join(pieces))],
                        [top(0x1c, b''.join(pieces)), top(0x2c, b'x')],
                        [top(0x1c, b''.join(pieces)), top(0x2c), top(0x2c)]):
            with self.assertRaises(android_heap.HeapError):
                self.parse(h.data(records=records))

    def test_zero_object_definition_rejected_for_all_heap_kinds(self):
        h = Envelope(); pieces = h.elements()
        for index in (0, 5, 6, 9):  # class, primitive array, String instance, message instance
            altered = pieces.copy()
            altered[index] = altered[index][:1] + bytes(h.width) + altered[index][1+h.width:]
            with self.subTest(index=index), self.assertRaisesRegex(android_heap.HeapError, 'NULL_IDENTIFIER'):
                self.parse(h.data(parts=altered))

    def test_zero_symbol_or_load_class_definition_rejected(self):
        h = Envelope(); raw = h.data(); header = len(h.header())
        first_length = struct.unpack_from('>I', raw, header+5)[0]
        zero_string = raw[:header+9] + bytes(h.width) + raw[header+9+h.width:]
        self.assertGreater(first_length, h.width)
        with self.assertRaisesRegex(android_heap.HeapError, 'NULL_IDENTIFIER'):
            self.parse(zero_string)
        # Load-class body starts with serial (4), then the class object identifier.
        pos = header
        while raw[pos] != 2:
            pos += 9 + struct.unpack_from('>I', raw, pos+5)[0]
        zero_load = raw[:pos+13] + bytes(h.width) + raw[pos+13+h.width:]
        with self.assertRaisesRegex(android_heap.HeapError, 'NULL_IDENTIFIER'):
            self.parse(zero_load)

    def test_null_and_dangling_text_references_do_not_find_unrelated_strings(self):
        for reference in (0, 999999):
            h = Envelope(); h.message_ref = reference
            self.assertEqual(self.parse(h.data()), [])
            h = Envelope(); h.array_ref = reference
            self.assertEqual(self.parse(h.data()), [])

    def test_duplicate_identifier_across_distinct_object_kinds_rejected(self):
        h = Envelope(); pieces = h.elements()
        pieces[-1] = pieces[-1][:1] + h.ident(20) + pieces[-1][1+h.width:]
        with self.assertRaisesRegex(android_heap.HeapError, 'DUPLICATE_IDENTIFIER'):
            self.parse(h.data(parts=pieces))

    def test_exact_class_name_and_base_required(self):
        for wrong in ('other.TLRPC$TL_message', 'org.telegram.tgnet.TLRPC$TL_messageSuffix'):
            h = Envelope(); h.names[2] = wrong
            self.assertEqual(self.parse(h.data()), [])
        h = Envelope(); h.parents[2] = 6
        self.assertEqual(self.parse(h.data()), [])

    def test_class_cycle_and_ambiguous_inherited_field_names(self):
        h = Envelope(); h.parents[6] = 2
        with self.assertRaisesRegex(android_heap.HeapError, 'CLASS_CYCLE'):
            self.parse(h.data())
        h = Envelope(); h.fields[2] = [('id', 10)]
        self.assertEqual(self.parse(h.data()), [])

    def test_instance_length_and_array_type_are_not_guessed(self):
        h = Envelope(); h.message_tail = b'\0'
        self.assertEqual(self.parse(h.data()), [])
        h = Envelope(); pieces = h.elements()
        # Byte array without a compact-String coder is not a UTF-16 char array.
        index = 1 + h.width + 4 + 4
        pieces[5] = pieces[5][:index] + b'\x08' + pieces[5][index+1:]
        # Preserve framing by correcting the byte-array count to its byte count.
        count_at = 1+h.width+4
        length = len(pieces[5]) - index - 1
        pieces[5] = pieces[5][:count_at] + struct.pack('>I', length) + pieces[5][count_at+4:]
        self.assertEqual(self.parse(h.data(parts=pieces)), [])

    def test_trailing_record_truncation_cannot_publish_earlier_candidates(self):
        h = Envelope()
        for tail in (b'\x01', top(1, b'\0'*h.width)[:-1], top(0x1c, b'\xff')[:-1]):
            with self.assertRaises(android_heap.HeapError):
                self.parse(h.data()+tail)

    def test_no_data_array_does_not_supply_zero_filled_text(self):
        h = Envelope(); pieces = h.elements()
        data_start = 1+h.width+4+4+1
        pieces[5] = b'\xc3' + pieces[5][1:data_start]
        self.assertEqual(self.parse(h.data(parts=pieces)), [])

    def test_unpaired_surrogate_string_not_decoded_with_replacement(self):
        h = Envelope(); pieces = h.elements()
        at = 1+h.width+4+4+1
        pieces[5] = pieces[5][:at] + b'\xd8\x00' + pieces[5][at+2:]
        self.assertEqual(self.parse(h.data(parts=pieces)), [])

    def test_arbitrary_text_cannot_be_promoted_without_message_objects(self):
        h = Envelope(); pieces = h.elements()
        self.assertEqual(self.parse(h.data(parts=pieces[:-1])), [])

    def test_index_removed_after_matcher_exception(self):
        h = Envelope()
        def fail(_):
            raise RuntimeError('controlled audit exception')
        with self.assertRaisesRegex(RuntimeError, 'controlled audit'):
            self.parse(h.data(), matcher=fail)

    def test_cancelled_heap_does_not_start_generic_fallback(self):
        import telegram_auto
        import memory_fragments
        request = dict(destination=str(self.work / 'archive'), options={})
        analyzer = telegram_auto.Analyzer(request, None, lambda *a, **kw: None)
        analyzer.worker = SimpleNamespace(work=self.work, messages=[], remark=Mock(), message=Mock())
        analyzer.stop = True
        with patch.object(android_heap, 'recover') as heap_scan, \
                patch.object(memory_fragments, 'scan') as raw_scan, \
                patch.object(memory_fragments, 'scan_tl') as typed_scan:
            self.assertEqual(analyzer.heap_from(self.path, self.path), [])
            analyzer.fragments_from(self.path, self.path)
            heap_scan.assert_not_called()
            raw_scan.assert_not_called()
            typed_scan.assert_not_called()
        analyzer.stop = False
        def interrupted(*args, **kwargs):
            analyzer.stop = True
            raise android_heap.HeapError('HPROF_CANCELLED')
        with patch.object(android_heap, 'recover', interrupted), \
                patch.object(memory_fragments, 'scan') as raw_scan, \
                patch.object(memory_fragments, 'scan_tl') as typed_scan:
            self.assertEqual(analyzer.heap_from(self.path, self.path), [])
            analyzer.fragments_from(self.path, self.path)
            raw_scan.assert_not_called()
            typed_scan.assert_not_called()
        analyzer.worker.message.assert_not_called()

    def test_generic_fragment_scan_checks_cancellation_between_candidates(self):
        import memory_fragments
        from text_match import Matcher
        self.path.write_bytes(b'independent recipe reference\0' * 20)
        self.assertEqual(list(memory_fragments.scan(self.path, Matcher('recipe', 'literal'), cancel=lambda: True)), [])
        stopped = False
        scan = memory_fragments.scan(self.path, Matcher('recipe', 'literal'), cancel=lambda: stopped)
        first = next(scan)
        self.assertIn('recipe', first['text'])
        stopped = True
        self.assertEqual(list(scan), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
