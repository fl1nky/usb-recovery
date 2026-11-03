# Telegram current-document flag compatibility proof

Independent native Java INPUT evidence for five exact old descriptor controls.
It is not product recovery acceptance, a device test, or server authentication.

The pinned Telegram Android commit is
`4de548e79fed27f1a66fbdff84223321838fe925`.
The original `TL_message`, `TL_messageMediaDocument`, `TL_document`,
`TL_documentAttributeFilename`, peer and Android attach-path writers are executed
without changes, with the original `SerializedData` and `Vector` classes.
Complete upstream sources and GPL license are included.

The independent bounded primitive reader reconstructs typed fields from the
unchanged old BLOB. The native writer starts the media flags at document-present
`1`; typed booleans recreate these bits:

| Old control | Native boolean |
|---|---|
| `reject-media-flags-bit3` | `nopremium` |
| `reject-media-flags-bit4` | `spoiler` |
| `reject-media-flags-bit6` | `video` |
| `reject-media-flags-bit7` | `round` |
| `reject-media-flags-bit8` | `voice` |

The whole document, whole media, whole TL body and whole Android BLOB match the
old bytes exactly. No copied prefix or tail substitutes for native serialization.
Two Java runs produced the same 24 files and the same metadata stream.
One unchanged filename-only parent is a sixth baseline proof.

`compatibility.json.gz` is the canonical supplemental policy input. It preserves
the old manifest SHA, case names, original metadata, SQL identifiers and complete
BLOB/body hashes. The old 21/42 oracle and its zero-result historical controls
remain unchanged. A new reader may explicitly upgrade only these five pinned
cases to one native text record. The duplicate-filename case remains a separate
strict unsupported profile; no other old control is upgraded.

The older Empty corpus has 166 legacy document cases using media `0x7c4414d3`
and one paired legacy photo. Its malformed flag tests concern that older media
constructor. This proof does not reclassify them. Three current Empty baselines
inside the descriptor corpus have flags `1`; there are no old boolean-bearing
Empty controls to upgrade here.

To reproduce the native proof, unpack `oracle-sources.tar.gz` into a new folder.
Compile every `.java` file under `java-src` with UTF-8 and the supplied JDK25
toolchain version recorded in `native-run-receipt.json`. Run
`CompatibilityOracle <absolute-inputs-folder> <new-empty-output-folder>` using
the compiled classes. All six inputs and their observed body boundaries are in
`inputs/cases.tsv`. Compare the new files with `native-run-01`.

The Python construction scripts retain original local provenance locations;
the generated Java source tree and inputs are self-contained for replay.
No Python installation is needed to replay this native Java evidence.

No recovery parser, helper, application, private profile, phone, network service,
paid program or frozen 20-image comparison was run or changed by this producer.
