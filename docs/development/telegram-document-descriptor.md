# Android message text with document descriptors

The Telegram reader can retain text from layer232 `TL_message` (`7600b9d3`)
carrying current document media (`52d8ccd9`, flags1). It validates a full
`TL_document` (`8fd4c4d8`, flags0) with zero attributes or one filename attribute,
or an explicit `DocumentEmpty`. The document size is an int64 and never causes
allocation or a download. Other media flags, thumbnail vectors, attributes,
outer profiles and nested reply media remain outside this validated profile.

Only original message text and the observed signed document ID are published.
Declared names, MIME types, sizes, access hashes and file references do not become
chat text, filesystem paths or attachments. An empty message with a filename
does not create a text message. The existing document-reference label explains
that original attachment bytes have not been recovered from the record.

The adapter preserves exact SQL/TL identity checks, source scope and complete
body hashes. Current rows, previous WAL versions and structurally supported
SQLite residuals retain their distinct evidence. A body found in a dump remains
an unattributed text fragment, with its original offset and hash. Unknown author,
chat, date and deletion remain unknown; supplied JSON cannot borrow physical
evidence from a checked native record.

An independent Java oracle executes exact serializers and the original
`SerializedData`/`Vector` from official Android commit
`4de548e79fed27f1a66fbdff84223321838fe925`. The pinned corpus includes21 native
serializations and42 separately labelled malformed/scope controls. Native SQLite
fixtures cover outgoing/incoming dialog keys, signed IDs, int64 sizes,
Unicode/padding, WAL/residual replay, keyword/Regex/full-text search and untrusted
reimport. The initial outgoing SQL metadata error is preserved as a separate
revision; no native BLOB was changed to fit the reader.

See [native fixtures](../../tests/fixtures/telegram-document-descriptor/README.md),
[source tests](../../tests/TelegramDocumentDescriptorTests.py), and the independent
[generator](../../tests/telegram_document_descriptor_fixture_generator.py).
The one paired original case produced0 native messages with the previous
published helper and1 exact message with the new source reader. This is a
controlled case, not a recovery rate for phones or a paid-tool comparison.

Protocol references: [official document descriptor](https://core.telegram.org/constructor/document),
[pinned Android serializer](https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java).
