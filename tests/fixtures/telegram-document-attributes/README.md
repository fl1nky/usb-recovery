# Telegram document attributes: independent inputs only

Status: **OUTSIDE_CURRENT_READER / NOT_ACCEPTED**. No recovery reader, helper, application, phone, server or paid program was run.

31 native Java serializations cover one filename-only profile control, 14 attribute profiles, 7 media-flag profiles and 9 thumbnail-vector profiles. There are 30 text slots and one intentionally empty message; filename/title/performer are never expected message text. Video uses the current double-duration constructor; audio, animation and image-size attributes are separate. One thumbnail is deliberately opaque/damaged: valid TL framing does not establish valid image content or complete attachment recovery.

The exact serializers and original `SerializedData`/`Vector` come from Android commit `4de548e79fed27f1a66fbdff84223321838fe925`. Full pinned primary sources, GPL license, extracted methods and compiled Java source are in `oracle-sources.tar.gz`. The Java output was produced twice; all 256 artifacts and metadata streams matched. SQLite independently stored the native BLOBs twice; all 202 files matched.

171 controls separately mark truncation, unknown constructors/flags and contradictory SQL dialog identity. They are explicit mutations, not valid native serialization claims. Their desired strict future-profile result is zero attributed native text; untyped fragment counts are unspecified. Current-reader outcomes remain NOT_RUN.

`oracle.json.gz` contains native bytes, expected producer fields, exact SQL keys and observed component ranges. `native-sqlite-cases.zip` contains current DB inputs. All files are own synthetic data; no real user exports are included. This corpus is separate from the frozen 20-image comparison and does not change its denominator.

For self-contained native replay, extract the source archive, compile every file under `java-src` with the recorded JDK25 `javac -encoding UTF-8 -d <fresh-classes>`, then run `AttributeOracle <fresh-output-directory> <absolute-thumbnail.png>` with that classes directory. The generated `java-src` tree is complete; it does not require the previous oracle. The original scaffolding-construction script records its local predecessor for provenance; use the complete generated tree for replay.

Future work: independently review these sources and expected profile policy, measure the current reader on the same inputs, implement a bounded parser extension in a new worktree, then run new source/portable/negative/provenance gates. Input production is not recovery acceptance.
