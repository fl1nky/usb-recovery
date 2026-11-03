# Telegram media-only messages: independent inputs

This is an input oracle, **not a recovery result**. It does not modify or run the
current application, helper or parser. There are no phone, server-authentication,
paid-tool or original-attachment recovery claims.

Fourteen exact native Android BLOBs cover seven document profiles, each with an
empty message and a nonempty paired caption: plain reference, Video, Audio/voice,
Animated, valid cached PNG, opaque cached bytes and DocumentEmpty. The seven empty
strings contain exactly zero UTF-8 bytes. All14 native messages have observed
producer metadata and consistent SQLite keys; only7 have nonempty text slots.
The future product's record-retention policy is deliberately unspecified. Zero
text slots must not be confused with proof that no message metadata exists.

Filename, MIME, title, performer, waveform and Android attachPath remain separate
metadata. A relative `NEVER_OPEN` attachPath is serialized as data, never opened.
The known70-byte cached PNG is2x1 with red and blue pixels; native byte ranges,
PNG chunks/CRCs and decompressed pixels are independently checked. The opaque
thumbnail is valid TL byte framing but is not asserted to be an image. Neither
thumbnail supplies the original document/video/audio bytes. No network lookup is
performed for document IDs, access hashes or file references.

The56 controls separately cover unsupported reserved media flags, a constructor
unknown to the pinned schema, truncation before a complete TL body, and exact
native BLOBs paired with a contradictory SQL dialog. Unsupported flags are
bounded-profile negatives; they are not a declaration that every such bit pattern
is globally invalid TL. Weak-fragment counts are unspecified. Source-only strict
attribution expectations are not measured product outcomes.

Evidence → finding → path:

| Evidence | Finding | Path |
|---|---|---|
| Two pinned native Java runs | All90 emitted artifacts and metadata streams match | `native-run-receipt.json`, `native-run-01/` |
| Independent primitive framing | Exact fields, empty strings, complete body and Android tail | `build_oracle.py`, `verification.json` |
| Two native SQLite productions | All70 DB byte streams match and pass integrity/row checks | `native-sqlite-cases.zip`, `oracle.json.gz` |
| Separate review | Source methods, metadata, controls and native bytes reviewed | `independent-review-01/` |

The exact serializers, original SerializedData/Vector primitives and complete
primary sources are pinned to Telegram Android commit
`4de548e79fed27f1a66fbdff84223321838fe925`. GPL license and complete native replay
source are in `oracle-sources.tar.gz`. Unused Android/platform scaffolding only
supplies declared fields and stubs; every executed TL/body/tail serializer comes
from the pinned source. No old native BLOB prefix or tail is copied to manufacture
equality.

For native replay, extract the source archive into a fresh folder and run this
PowerShell from that extracted folder with the recorded JDK25 installed:

```powershell
$jdk = 'C:/Program Files/Eclipse Adoptium/jdk-25.0.3.9-hotspot/bin'
if ((Test-Path ./replay-classes) -or (Test-Path ./replay-native)) { throw 'Preserve earlier replay outputs.' }
$javaFiles = @(Get-ChildItem ./java-src -Recurse -File -Filter '*.java' | Sort-Object FullName | Select-Object -ExpandProperty FullName)
& (Join-Path $jdk 'javac.exe') -encoding UTF-8 -d ./replay-classes @javaFiles
if ($LASTEXITCODE -ne 0) { throw 'Native producer compile failed.' }
& (Join-Path $jdk 'java.exe') -Xmx96m '-Dfile.encoding=UTF-8' -cp ./replay-classes MediaOnlyOracle ./replay-native (Join-Path $PWD 'thumbnail.png')
if ($LASTEXITCODE -ne 0) { throw 'Native producer failed.' }
```

Compare the new outputs with `native-run-01`. The generated Java source tree is
self-contained. The Python scaffolding-construction script retains predecessor
paths for provenance; that builder is not needed for native Java replay.

Before closure, control classification wording was refined without changing any
Java/native/SQLite bytes; initial metadata and producer bytes are preserved in
`metadata-before-01`, with an explicit refinement receipt. One shell stdout-path
typo was corrected by moving its newly created log into this case folder; native
producer exit0 was unaffected. Neither event was a product failure.

The old21/42 and31/171 inputs and current release source remain unchanged. This
corpus is separate from the20-image comparison and does not change its denominator.
