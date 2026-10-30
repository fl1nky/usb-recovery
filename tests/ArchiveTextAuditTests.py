"""Independent read-only paging/Unicode audit using synthetic local archives."""
from pathlib import Path
from contextlib import closing
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'helpers/recovery_engine'))
import archive_search
import archive_text


def record(text, **fields):
    return dict(app='Telegram', evidence_kind='export', text=text, **fields)


def fingerprint(folder):
    return {path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
            for path in folder.iterdir() if path.is_file()}


class ArchiveTextAudit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owned-archive-text-audit-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)

    def archive(self, values, *, indexed=False, text_ids=False):
        raw = [json.dumps(value, ensure_ascii=False, separators=(',', ':')) for value in values]
        (self.folder / 'messages.jsonl').write_text('\n'.join(raw) + '\n', encoding='utf-8')
        if indexed:
            with closing(sqlite3.connect(self.folder / 'chat-index.sqlite')) as connection:
                connection.execute('CREATE TABLE messages(id ' + ('TEXT' if text_ids else 'INTEGER PRIMARY KEY') + ',json TEXT)')
                for index, value in enumerate(raw):
                    connection.execute('INSERT INTO messages VALUES(?,?)', (str(index) if text_ids else index, value))
                connection.commit()

    def search(self, query=''):
        return archive_search.search(dict(protocol=1, operation='search', archive=str(self.folder),
                                          app='Telegram', query=query))

    def page(self, key, offset=0, limit=37):
        return archive_text.read_page(dict(protocol=1, operation='message_page', archive=str(self.folder),
                                          record_key=key, text_offset=offset, limit=limit))

    def test_late_match_context_uses_original_codepoint_offsets(self):
        text = '🥧Straßeİé' + 'x' * 70000 + ' РЕЦЕПТ_ПРАБАБУШКИ ' + 'z' * 200
        self.archive([record(text)])
        before = fingerprint(self.folder)
        result = self.search('рецепт_прабабушки')['records'][0]
        self.assertGreater(result['text_offset'], 0)
        self.assertEqual(result['text'], text[result['text_offset']:result['text_end']])
        self.assertEqual(text[result['match_offset']:result['match_end']], 'РЕЦЕПТ_ПРАБАБУШКИ')
        page = self.page(result['archive_record_key'], result['match_offset'], 25)
        self.assertEqual(page['text'], text[result['match_offset']:result['match_offset'] + 25])
        self.assertEqual(fingerprint(self.folder), before)

    def test_casefold_expansion_span_does_not_use_folded_coordinates(self):
        text = '🥧xßİﬃ' + 'z' * 70000
        self.archive([record(text)])
        for query, expected in (('ss', 'ß'), ('i̇', 'İ'), ('ffi', 'ﬃ')):
            with self.subTest(query=query):
                value = self.search(query)['records'][0]
                self.assertEqual(text[value['match_offset']:value['match_end']], expected)

    def test_paging_astral_combining_and_unknown_fields_remains_read_only(self):
        text = ('🥧aßé' * 71) + ' END'
        self.archive([record(text, password='PRIVATE_CANARY', secret={'key': 'PRIVATE_CANARY'})], indexed=True)
        before = fingerprint(self.folder)
        value = self.search()['records'][0]
        self.assertTrue(value['archive_record_key'].startswith('sqlite:'))
        offset, parts = 0, []
        while True:
            page = self.page(value['archive_record_key'], offset, 13)
            self.assertEqual(page['text'], text[offset:offset + 13])
            self.assertEqual(page['text_offset'], offset)
            self.assertEqual(page['text_length'], len(text))
            self.assertNotIn('PRIVATE_CANARY', json.dumps(page))
            page['text'].encode('utf-8', 'strict')
            parts.append(page['text'])
            if page['eof']:
                break
            self.assertGreater(page['next_offset'], offset)
            offset = page['next_offset']
        self.assertEqual(''.join(parts), text)
        self.assertEqual(fingerprint(self.folder), before)

    def test_jsonl_locator_must_start_at_an_actual_line_boundary(self):
        raw = json.dumps(record('owned'), separators=(',', ':')).encode() + b'\n'
        (self.folder / 'messages.jsonl').write_bytes(b' ' + raw)
        key = 'jsonl:1:' + hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(archive_search.SearchError, '^RECORD_CHANGED$'):
            self.page(key)
        key = self.search()['records'][0]['archive_record_key']
        self.assertEqual(self.page(key)['text'], 'owned')

    def test_stale_raw_fingerprint_is_rejected_even_with_restored_metadata(self):
        self.archive([record('old text')])
        key = self.search()['records'][0]['archive_record_key']
        path = self.folder / 'messages.jsonl'
        saved = path.stat()
        path.write_bytes(path.read_bytes().replace(b'old text', b'new text'))
        os.utime(path, ns=(saved.st_atime_ns, saved.st_mtime_ns))
        with self.assertRaisesRegex(archive_search.SearchError, '^RECORD_CHANGED$'):
            self.page(key)

    def test_noninteger_sql_ids_use_bound_ordinal_after_invalid_rows(self):
        self.archive([record('first'), record('second')], indexed=True, text_ids=True)
        with closing(sqlite3.connect(self.folder / 'chat-index.sqlite')) as connection:
            connection.execute('UPDATE messages SET json=? WHERE id=?', ('{bad', '0'))
            connection.commit()
        value = self.search()['records'][0]
        self.assertTrue(value['archive_record_key'].startswith('sqlite-ordinal:1:'))
        self.assertEqual(self.page(value['archive_record_key'])['text'], 'second')

    def test_nonzero_wal_is_not_ignored_for_direct_index_paging(self):
        self.archive([record('saved')], indexed=True)
        key = self.search()['records'][0]['archive_record_key']
        (self.folder / 'chat-index.sqlite-wal').write_bytes(b'unverified pending sidecar')
        before = fingerprint(self.folder)
        with self.assertRaisesRegex(archive_search.SearchError, '^ARCHIVE_INCOMPLETE$'):
            self.page(key)
        self.assertEqual(fingerprint(self.folder), before)

    def test_index_directory_is_a_controlled_error(self):
        self.archive([record('fallback JSONL')])
        (self.folder / 'chat-index.sqlite').mkdir()
        with self.assertRaises(archive_search.SearchError):
            self.page('sqlite:1:' + '0' * 64)

    def test_multibyte_byte_limit_does_not_emit_unreadable_locator(self):
        self.archive([record('я' * 120)], indexed=True)
        with patch.object(archive_search, 'MAX_RECORD', 256), patch.object(archive_text, 'MAX_RECORD', 256):
            found = self.search()['records']
            for value in found:
                self.assertEqual(self.page(value['archive_record_key'], limit=13)['text'], value['text'][:13])

    def test_unpaired_escaped_unicode_does_not_hide_valid_records(self):
        values = [record('broken ' + chr(0xd800)), record('still readable')]
        lines = [(json.dumps(value, ensure_ascii=True) + '\n').encode('utf-8') for value in values]
        (self.folder / 'messages.jsonl').write_bytes(b''.join(lines))
        before = fingerprint(self.folder)
        result = self.search()
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['records'][0]['text'], 'still readable')
        json.dumps(result, ensure_ascii=False).encode('utf-8', 'strict')
        with self.assertRaisesRegex(archive_search.SearchError, '^RECORD_UNAVAILABLE$'):
            self.page('jsonl:0:' + hashlib.sha256(lines[0]).hexdigest())
        self.assertEqual(fingerprint(self.folder), before)

    def test_invalid_metadata_unicode_becomes_unknown_without_text_replacement(self):
        valid_attachment = 'media/' + 'a' * 64 + '.jpg'
        value = record('valid 🥧 text', sender_name=chr(0xd800), source_record=chr(0xdc00),
                       attachments=['media/' + chr(0xd800) + '.jpg', valid_attachment],
                       residual_sources=[{'source_file': chr(0xd800), 'proof': 'owned'}],
                       additional_sources=[{'source_record': chr(0xdc00), 'source_file': 'owned'}])
        path = self.folder / 'messages.jsonl'
        path.write_text(json.dumps(value, ensure_ascii=True) + '\n', encoding='utf-8')
        before = fingerprint(self.folder)
        normalized = self.search()['records'][0]
        self.assertEqual(normalized['text'], value['text'])
        self.assertIsNone(normalized['sender_name'])
        self.assertIsNone(normalized['source_record'])
        self.assertEqual(normalized['attachments'], [valid_attachment])
        encoded = json.dumps(normalized, ensure_ascii=False).encode('utf-8', 'strict')
        self.assertNotIn('\ufffd'.encode(), encoded)
        self.assertEqual(self.page(normalized['archive_record_key'])['text'], value['text'])
        self.assertEqual(fingerprint(self.folder), before)

    def test_locator_path_injection_limits_and_eof_are_controlled(self):
        self.archive([record('🥧owned')])
        key = self.search()['records'][0]['archive_record_key']
        for bad in ('../messages.jsonl:0:' + '0' * 64, 'jsonl:9223372036854775808:' + '0' * 64,
                    'jsonl:0:' + 'A' * 64, 'sqlite-ordinal:-1:' + '0' * 64):
            with self.subTest(key=bad), self.assertRaises(archive_search.SearchError):
                self.page(bad)
        for offset, limit in ((True, 5), (-1, 5), (0, True), (0, 0), (0, 65537), (8, 5)):
            with self.subTest(offset=offset, limit=limit), self.assertRaises(archive_search.SearchError):
                self.page(key, offset, limit)
        page = self.page(key, len('🥧owned'), 7)
        self.assertEqual(page['text'], '')
        self.assertTrue(page['eof'])
        self.assertEqual(page['next_offset'], len('🥧owned'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
