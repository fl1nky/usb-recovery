# Native Telegram platform input corpus

These 63 files are controlled inputs, not real profiles or device results.
`manifest.json` records each byte count/SHA256 and independently supplied expected
text/IDs. `native-cases.zip` is the only data restored by normal tests.

Android BLOBs were emitted by the pinned official Java `TL_message` and Android
attachment-tail serializers, using three outgoing messages, including one empty
`documentEmpty` media-only record. SQLite tables use the exact upstream
`scheduled_messages_v2` CREATE statement. The reader does not produce inputs.

iOS uses native SQLite, the historical `TGDatabase` schema29 CREATE/ALTER
statements, and original TEXT fields. The official iOS legacy importer also
confirms `messages_v29`, text, author and date fields. This corpus does not model
current Postbox. One fixture has a missing author: its original text survives
with an unknown sender. Wrong versions/schema and secret-dialog identifiers are
separate controls.

Desktop records are serialized by native Qt5.15.2 `QDataStream(Qt_5_1)`, following
the three explicit native draft layouts FF03/FF05/FF06. The independent producer
implements the published encryption direction, PBKDF2-HMAC-SHA512 key wrap and
AES256-IGE container integrity. No product decoder is imported. Public artificial
fixture passcode/key constants are in the loader; they are unrelated to accounts.
The third key-data blob is deliberately opaque, and root authorization/map files
are access canaries. Corrupt checksums/ciphertext, unknown version/tag, unsupported
cloud key, duplicate key, truncated final record and modern KDF trailer are
negative controls. Wrong and missing secrets are exercised separately.

Actual SQLite WAL transactions insert then delete one Android/iOS row. A complete
validated earlier WAL snapshot can retain that row. It does not prove a user's
deletion, a phone state, or current cloud history.

`oracle-sources.tar.gz` preserves the independent producer, Java writer/support
sources and pinned GPL Android/Desktop source copies, plus their byte hashes.
Historical iOS sources are represented by their URLs/commit/byte hashes rather
than redistributed full source files. The Java serializer support source comes
from the existing immutable `telegram-media-only` source corpus. Qt binaries are
developer-only and are not included in the application or this fixture bundle.

Primary source pins:

- [Android MessagesStorage](https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/messenger/MessagesStorage.java).
- [Historical iOS TGDatabase](https://github.com/peter-iakovlev/Telegram/blob/f41e9695b5d92e94105afc073a2bbd6a15a1d33c/legacy/TelegraphKit/TGDatabase.mm), [official iOS legacy importer](https://github.com/TelegramMessenger/Telegram-iOS/blob/1423d5381fcdaaef85565755b087fbed6a4ed97d/submodules/LegacyDataImport/Sources/LegacyChatImport.swift).
- [Desktop draft reader/writer](https://github.com/telegramdesktop/tdesktop/blob/a8de5f928ba68197195e6e752293af39d4db8e6c/Telegram/SourceFiles/storage/storage_account.cpp), [key-data wrapper](https://github.com/telegramdesktop/tdesktop/blob/a8de5f928ba68197195e6e752293af39d4db8e6c/Telegram/SourceFiles/storage/storage_domain.cpp), [native containers/KDF](https://github.com/telegramdesktop/tdesktop/blob/a8de5f928ba68197195e6e752293af39d4db8e6c/Telegram/SourceFiles/storage/details/storage_file_utilities.cpp).

Corpus01 and its failed Unicode producer evidence remain private and unchanged.
Corpus02 corrects the Java producer's temporary Windows encoding mistake with
explicit Java Unicode escapes and UTF8 source I/O. Existing earlier project
corpora were not edited. These inputs establish bounded format coverage; they
do not establish complete platform or real-device recovery.
