# Telegram photo-caption oracle

Own synthetic strings serialized by the pinned official Java writer and 32 unchanged serializer methods. No chats, accounts or devices were used. The data contains 855 Message/photo-media combinations; nested photos are `PhotoEmpty`, without image bytes.

`manifest.json` records hashes, upstream commit, URLs and exact method provenance. `oracle.json.gz` contains the serialized bytes and declared input expectations. Its writer does not import the recovery decoder. `oracle-sources.tar.gz` contains the Java sources, original upstream sources, extraction scripts and pins; the upstream GPL license is included.

For independent regeneration, unpack the source archive into a new developer directory, compile `oracle-src/**/*.java` with `javac -encoding UTF-8 -d <classes>`, then run `java -cp <classes> OfficialWireOracle <fresh-output> 5`. The program emits its TSV metadata to stdout. JDK is needed only for developer regeneration; runtime recovery reads the frozen data without Java or network access.
