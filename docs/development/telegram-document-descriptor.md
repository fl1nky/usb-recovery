# Android message text with document descriptors

The attributes extension is covered by source tests and a focused packaged
gate:30 exact nonempty messages,171 rejection/scope controls and two cached
thumbnail origins. Expected opaque-thumbnail and unattributed-fragment
warnings remain explicit; this does not certify complete source recovery.
The earlier `v2026.11.03-telegram-indexed-video` has the filename-only profile.
Release-wide acceptance, devices and paid-tool comparison are separate evidence.

The Telegram reader can retain text from layer232 `TL_message` (`7600b9d3`)
carrying current document media (`52d8ccd9`). Its bounded profile understands
document/TTL/video-timestamp fields and the known nopremium/spoiler/video/round/
voice booleans. It reads `TL_document` (`8fd4c4d8`, flags0–3) or `DocumentEmpty`.
Supported attributes are current Filename, Video, Audio, ImageSize and Animated;
repeated attribute kinds remain outside this profile. Video duration is a double,
audio duration an int32. Unknown fields, alternate documents, video covers,
other outer profiles and nested reply media remain unsupported.

Only original message text and the observed signed document ID become chat data.
Declared names, MIME types, sizes, access hashes and file references do not become
chat text, filesystem paths or attachments. An empty message with metadata
does not create a text message. Cached photo thumbnails are decoded with byte,
count and dimension limits and preserve their exact bytes and BLOB-relative
origins. Remote photo/video thumbnail descriptors do not supply image bytes.
A cached thumbnail is distinct from the original document; a reference alone
does not mean that attachment bytes have been recovered. The document size
remains an int64 and never causes allocation or a download.

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

The old 21/42 fixture and its historical zero-result goldens are unchanged.
A [supplemental native proof](../../tests/fixtures/telegram-document-attributes-compatibility/README.md)
reserializes five old boolean controls as exact whole Android BLOBs. Current
tests explicitly expect one text record for each of those five; the other37
controls remain rejected. Duplicate filename attributes are a strict unsupported
profile rather than a claim that the TL wire format itself forbids duplicates.

The separate [attributes corpus](../../tests/fixtures/telegram-document-attributes/README.md)
contains31 official Java serializations and171 wire/SQL controls, with202 pinned
SQLite sources. Source tests recover all30 nonempty text slots, keep the empty
metadata-only case empty, extract two exact cached PNGs, and check WAL/residual
thumbnail origins, keyword/Regex/full-text search and untrusted reimport.
The frozen published helper recovered one native text slot from the same31
sources. This paired source result does not establish a phone recovery rate.

See [native fixtures](../../tests/fixtures/telegram-document-descriptor/README.md),
[source tests](../../tests/TelegramDocumentDescriptorTests.py), and the independent
[generator](../../tests/telegram_document_descriptor_fixture_generator.py).
In the earlier filename-only milestone, one paired original case produced0
native messages with its baseline helper and1 exact message after the change.
That historical result is separate from the new31-source attributes comparison;
neither result is a recovery rate for phones or a paid-tool comparison.

Protocol references: [official document descriptor](https://core.telegram.org/constructor/document),
[pinned Android serializer](https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java).
