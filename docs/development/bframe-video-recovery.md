# Fragmented AVC with B-frames

The indexed native fMP4 profile accepts `trun` version 0 unsigned composition
offsets and version 1 signed offsets. `tfdt` and accumulated sample durations
still establish continuous decode time starting at zero. Each `tfra` entry
must equal the first sample's presentation time (`decode + composition`),
with the existing sequence, byte-length, sync-sample, source coverage and
non-overlap checks. Negative presentation times and integer overflow are
rejected. AVC NAL framing remains structural evidence; recovery does not
authenticate ownership or decode reference pictures.

The distinction follows FFmpeg's native writer:
[movenc.c](https://github.com/FFmpeg/FFmpeg/blob/n8.0/libavformat/movenc.c),
`mov_add_tfra_entries` records the first sample's DTS plus CTS. Signed
composition offsets are described by the official
[FFmpeg MOV options](https://ffmpeg.org/ffmpeg-formats.html#mov_002c-mp4_002c-ismv).
The previous zero-composition profile rejected both new native layouts.

The pinned FFmpeg 9.0.2 writer creates two own 12-frame AVC videos with B-frames,
one unsigned-offset and one signed negative-offset variant. Three intact
`moof+mdat` pairs, init and index are placed at independently chosen source
offsets. The public `tests/fixtures/video-bframes` corpus retains compressed
images, exact originals, independent decoded-frame hashes and full source maps.
All compressed/expanded files are SHA-checked before use. `prepare_bframe_media_fixtures.py`
expands the corpus without FFmpeg; `--verify` reads it without repairing changes.

`VideoBFrameRecoveryTests.py --destination <fresh-short-path> --ffmpeg <pinned-exe>`
performs the source comparison, exact-byte/map and native 12-frame checks, plus
missing, identical-source-alias and competing-byte controls for both layouts.
Distinct complete byte results remain ambiguous. The corpus demonstrates this
specific timing/layout extension, not arbitrary fMP4, encrypted/multitrack
fragments, remuxed missing bytes, device recovery or packaged acceptance.
