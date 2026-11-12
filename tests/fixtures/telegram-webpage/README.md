# Native Android link-preview input corpus

Eight messages were serialized by official Java methods from Telegram Android
commit `4de548e79fed27f1a66fbdff84223321838fe925`. Controlled Unicode text and
IDs are stored beside each BLOB. The recovery decoder never produces inputs.
`oracle.json.gz` contains the frozen native bytes. `manifest.json` pins hashes.

`oracle-sources.tar.gz` includes the exact Java serializers and developer stubs.
The source is covered by the enclosed GPL version 2 or later license. Original
Telegram Android source copyright belongs to Nikolai Kudashov, 2013–2018.

The native corpus covers current and legacy empty/pending previews, URL-pending
previews, scalar full previews and one full preview with PhotoEmpty metadata.
Tests create ordinary SQLite/WAL files using these bytes and compare original
text, SQL identities, snapshot provenance, damaged inputs and source hashes.

Regeneration uses a developer JDK and the pinned upstream `TLRPC.java` snapshot.
Run `tests/build_telegram_webpage_fixtures.py --upstream <file> --work <new-folder>
--output <new-folder>`. The generator validates the upstream SHA256 and preserves
existing output folders. Tests consume frozen files without a JDK or network.

[Official TLRPC.java](https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java)
