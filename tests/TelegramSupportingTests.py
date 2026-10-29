"""Frozen photo/acquisition/iOS-transport checks for the Telegram-only release.

The iOS backup fixture deliberately contains a known canonical test DB. This
verifies the backup transport, not the private schema of Telegram for iPhone.
"""
import json
import sqlite3
import sys
import unittest
from PortableFormatsTests import PortableFormats, fixtures, rows, codes


class TelegramSupport(PortableFormats):
    def test_ios_backup_transport_known_password_wrong_password_and_digest(self):
        plain = self.test_root / "known-test-database.sqlite"
        con = sqlite3.connect(plain)
        con.execute("CREATE TABLE messages(id INTEGER,app TEXT,json TEXT)")
        con.execute("INSERT INTO messages VALUES(1,'Telegram',?)", (json.dumps({
            "app":"Telegram", "text":"Known Telegram archive transported in backup", "evidence_kind":"backup",
            "chat_id":123,"message_id":1,"timestamp":"2026-10-27T10:00:00Z"}),))
        con.commit();con.close()
        backup = self.source / "encrypted-ios"
        password = "Synthetic local password 8AF379"
        encrypted = fixtures.encrypted_iphone(backup, plain, password=password)
        output, result = self.invoke({"ios_password":password}, deep=False, source=backup)
        self.assertEqual([m["text"] for m in rows(output)], ["Known Telegram archive transported in backup"])
        output, result = self.invoke({"ios_password":"Wrong synthetic password"}, deep=False, source=backup, expected="error")
        self.assertIn("IOS_PASSWORD_INCORRECT", codes(output))
        payload=bytearray(encrypted.read_bytes());payload[64]^=1;encrypted.write_bytes(payload)
        output, result = self.invoke({"ios_password":password}, deep=False, source=backup, expected="error")
        self.assertIn("IOS_FILE_DIGEST_MISMATCH", codes(output))


if __name__ == "__main__":
    names = ["test_telegram_json_html_missing_media_and_unicode",
             "test_images_webp_heif_no_extension_embedded_thumbnail_damaged_duplicates",
             "test_acquisition_manifest_verified_origin_and_partial_exclusion",
             "test_ios_backup_transport_known_password_wrong_password_and_digest"]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(TelegramSupport(name) for name in names))
    sys.exit(not result.wasSuccessful())
