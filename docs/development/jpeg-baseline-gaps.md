# Baseline JPEG sector gaps

Baseline Huffman JPEG without restart markers has a paged one-gap hypothesis
up to the ordinary 64 MiB photo limit. Both source runs and their split/jump
must be sector aligned; the tail must contain an intact EOI. The first run has
no 8 KiB restriction. Source ranges must be disjoint. Every byte comes from
the read-only source; no map, expected SHA, pixel similarity or filler value
is supplied to recovery.

All eligible one-gap alternatives are exhausted before a unique byte result
is published. A second valid byte result yields two explicit
`jpeg_gap_ambiguous_candidate` witnesses, with unknown original ownership.
Search may stop once ambiguity is proved; further content/maps are then not
exhaustive. Byte-identical one-gap source aliases are retained as full maps,
bounded by the ordinary alias/output budgets. The additional two-gap fallback
still covers files up to 128 KiB and first/middle runs up to 8 KiB. Arbitrary
multi-gap JPEG recovery is not implemented.

The parser checks baseline Huffman categories/runs, the exact MCU/block count,
stuffed bytes, one-bit padding and EOI before native Pillow decoding. Decoder
success alone never selects an original. A grammar-derived minimum block-bit
cost prunes only impossible block counts, independently of image appearance.
Suffix memo entries are exact counts or proved-invalid suffixes. A path that
merely exceeds one prefix's required count cannot poison later suffix states.

Source views use sixteen 256 KiB pages. Prefix checkpoints advance once through
successive cuts. Suffix parsing uses a bounded LRU index; at most 20,000 exact
memo entries are carried into the next anchored journal state. Prefix/join/end
cursors, active suffix bit/block state and withheld candidate/map descriptors
are also durable. A failed candidate read leaves the cursor on that candidate.
Nothing is emitted before complete bounded coverage or proved ambiguity.

The existing source SHA, executing-code/runtime/options binding, 8 MiB journal
generation and 256 MiB journal chain checks remain effective. A slice retains
work within one JPEG head; source or code changes reject its checkpoint. The
120-second work interval, 512 MiB verified-byte budget and bounded prefix,
join, suffix and alias states still produce an incomplete job when exhausted.
Large random-noise layouts can remain expensive; finite bounds do not promise
recovery of every damaged or fragmented photo.

`JpegStreamingCheckpointTests.py` checks a read failure after a complete
entropy match and full byte-identical source-map preservation.
`JpegLargeStreamingTests.py` uses pinned Pillow 12.3 native encodings: an
independent 6,803,878-byte original split after 6,802,432 bytes, changed-content
late alternatives, missing EOI, overwritten source bytes, repeated short
slices/cancellation and large restart/progressive controls. Its default run
is offline and Git-independent. `--baseline` adds an optional paired developer
comparison against immutable commit 5684800. Existing baseline/progressive,
two-gap, photo-checkpoint and source-alias regressions remain required.

The separate native 16 MiB scattered-source controls currently recover zero
files: the 6.8 MiB restart reference reaches `jpeg_search_incomplete`, and the
6.9 MiB progressive reference reaches `jpeg_progressive_memory_search_incomplete`.
These are retained failed capabilities, not successful large restart/progressive
recoveries. The proved extension is the nonrestart one-gap profile above.

Portable acceptance uses `JpegVideoExpansionPortableTests.cs`, after generating
`.build/jpeg-large-portable-fixtures` with `build_large_jpeg_fixtures.py` and
preparing `.build/video-bframes-fixtures` with `prepare_bframe_media_fixtures.py`.
It must run against the freshly rebuilt application and helper.

These are synthetic source checks. Fresh helper/app builds, portable acceptance,
publication and real devices are separate evidence. Historical accepted releases
and their failure/ambiguity reports are unchanged.
