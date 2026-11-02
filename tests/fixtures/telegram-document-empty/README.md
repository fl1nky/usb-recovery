# Telegram DocumentEmpty text oracle

167 own cases serialized with unchanged official Java methods and `SerializedData`, pinned to Telegram Android `4de548e79fed27f1a66fbdff84223321838fe925`. No personal chats or devices are involved. These are valid wire examples with declared synthetic field values, not Android execution or evidence of deleted attachment bytes.

Coverage: 19 existing outer Message profiles, all eight legacy document-media flags combinations, absent/zero/positive/signed-extreme document IDs, text roles, peer relations, zero date and a negative local message ID. The photo control differs from the original documented failure by exactly eight constructor bytes. All nested documents are `TL_documentEmpty`; no file/video payload is supplied.

`oracle.json.gz` contains immutable BLOBs and expected fields. `manifest.json` pins every file, the upstream sources and exact method provenance. `oracle-sources.tar.gz` supplies generated Java field stubs, unchanged exercised serializers, the independent case runner, original upstream sources/schema and source pins. GPL license: `LICENSE`.

For developer regeneration, extract the source archive into a new directory, compile `oracle-src/**/*.java` with `javac -encoding UTF-8 -d <classes>`, and run `java -cp <classes> DocumentEmptyOracle <fresh-wire-directory>`. TSV metadata goes to stdout. The field stubs are explicit; `writeAttachPath` writes an opaque synthetic tail and records the TL boundary. This does not simulate the Android application. Recovery never executes the archived sources or follows the tail path.

The Python factory verifies the pinned oracle and uses native SQLite to create fresh DB/WAL/SHM copies. It does not import the recovery parser or generate TL bytes. JDK is needed only for developer regeneration.
