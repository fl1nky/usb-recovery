"""Owned HTML export examples; verify complete records, not just parser output."""
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'helpers/recovery_engine'))
import engine
from telegram_html import TelegramHTML, plain_markup


def message(text, identifier='42'):
    return ('<div class="message default clearfix" id="message' + identifier + '">'
            '<div class="date" title="11.10.2026 12:30"></div>'
            '<div class="from_name">Alice</div><div class="text">' + text + '</div></div>')


class TelegramHtmlTests(unittest.TestCase):
    def parse(self, text):
        parser = TelegramHTML()
        parser.feed(text)
        parser.close()
        return parser.messages

    def test_existing_normal_export_remains_exact(self):
        row, = self.parse(message('Рецепт &amp; тест<br>вторая строка 🥧'))
        self.assertEqual(row['text'], 'Рецепт & тест\nвторая строка 🥧')
        self.assertEqual(row['sender_name'], 'Alice')
        self.assertEqual(row['message_id'], '42')
        self.assertEqual(row['timestamp'], '11.10.2026 12:30')

    def test_self_closing_line_breaks_keep_the_whole_message(self):
        row, = self.parse(message('before<br/>after<BR />tail'))
        self.assertEqual(row['text'], 'before\nafter\ntail')

    def test_void_elements_cannot_close_a_message(self):
        for tag in ('img', 'hr', 'input', 'meta', 'link', 'source', 'wbr', 'area', 'embed', 'track'):
            with self.subTest(tag=tag):
                row, = self.parse(message('before<' + tag + ' />after'))
                self.assertEqual(row['text'], 'beforeafter')

    def test_stray_void_end_tag_does_not_pop_a_real_container(self):
        row, = self.parse(message('before</br>after<br/>tail'))
        self.assertEqual(row['text'], 'beforeafter\ntail')

    def test_multiple_message_identifiers_are_preserved(self):
        rows = self.parse(message('same<br/>text', '1') + message('same<br/>text', '2'))
        self.assertEqual([row['message_id'] for row in rows], ['1', '2'])
        self.assertEqual([row['text'] for row in rows], ['same\ntext', 'same\ntext'])

    def test_markup_is_data_and_script_style_are_excluded(self):
        row, = self.parse(message('safe<script>SECRET_SCRIPT</script><style>SECRET_STYLE</style><br/>end'))
        self.assertEqual(row['text'], 'safe\nend')
        self.assertEqual(plain_markup('<b>safe</b><br/><script>SECRET</script>end'), 'safe\nend')

    def test_missing_author_and_date_stay_unknown(self):
        row, = self.parse('<div class="message default" id="message9"><div class="text">text<br/>end</div></div>')
        self.assertEqual(row['sender_name'], '')
        self.assertIsNone(row['timestamp'])

    def test_truncated_open_message_is_not_published_as_complete(self):
        self.assertEqual(self.parse('<div class="message default"><div class="text">unfinished<br/>'), [])

    def test_importer_recovers_complete_text_without_changing_source(self):
        with tempfile.TemporaryDirectory(prefix='owned-html-export-') as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            file = source / 'messages.html'
            file.write_text(message('Рецепт<br/>начинка<br/>🥧'), encoding='utf-8')
            before = hashlib.sha256(file.read_bytes()).hexdigest()
            worker = engine.Importer(source, root / 'archive', deep=False)
            with patch.object(engine, 'emit'):
                result = worker.run()
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(len(worker.messages), 1)
            self.assertEqual(worker.messages[0]['text'], 'Рецепт\nначинка\n🥧')
            self.assertEqual(worker.messages[0]['evidence_kind'], 'export')
            self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
