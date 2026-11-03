# Independent current Document oracle

21 native Java cases and 42 explicit adversarial controls, generated from Telegram
Android commit `4de548e79fed27f1a66fbdff84223321838fe925` (layer 232).

The Java oracle was compiled and run. It uses unchanged official `SerializedData`,
`Vector`, interfaces and `TLObject`, seven exact serializer method spans and the
exact `Message.writeAttachPath` method. Field containers and small Android/logging
services are standalone scaffolding. No recovery implementation generates the
expected bytes. Original upstream files and GPL v2-or-later license are included
in `oracle-sources.tar.gz`; that archive is source evidence, never imported or run
by the fixture loader.

The native message body and native local attach-path tail are measured separately
through the official Android test-environment gate, with exact prefix equality
required. Each blob and body has its own SHA256. Positive cases include full
current Document with flags 0, empty/one-filename attributes, signed IDs, 64-bit
declared sizes, Unicode, TL padding, current Empty and legacy Empty.
`descriptor-empty-text` is structurally valid and must create no text from its
filename. The two legacy cases preserve independent text slots.

Malformed/unsupported bodies are mutations of the native bytes, explicitly marked
`parser_reject`; SQL/outer-profile controls use `scope_reject`. Their `tl_bytes`
identifies an observed/capped prefix, not a successfully parsed native body.
No filename is an attachment payload, executable path or recovered message text.
Document ID, MIME, access hash and file reference do not establish account,
sender, attachment ownership or deletion.

`telegram_document_descriptor_fixture_generator.py` verifies the pinned manifest
and three payload files before it creates new SQLite sources. It never extracts
the source archive, serializes golden TL, reads devices or imports the recovery
parser. Current, WAL/residual and photo-type media-cache sources are separate own
copies. Product parsing, packaged/offline acceptance and real devices require
separate validation; native-oracle success proves none of them.
