# Baseline JPEG sector gaps

Baseline Huffman JPEG without restart markers uses a bounded minimum-gap
hypothesis. Contiguous strict-valid files stay with normal carving. All one-gap
paths are checked first; two-gap paths are considered only when no one-gap
result exists. This does not establish uniqueness across arbitrary layouts.

The first cut must be a 512-byte source boundary in the first 8 KiB. An optional
middle run starts on a source boundary and has 512..8192 bytes in whole sectors.
The final run starts on a boundary and ends at a surviving EOI. The complete
file is at most 128 KiB. Physical ranges must be disjoint; bytes are never
synthesized. The search reads source bytes without reference maps, expected
hashes, pixel similarity or assumptions about filler values.

Huffman checkpoints retain a complete-block boundary before a cut, including
the partial byte and component/table phase. Completion requires the exact MCU
count, legal symbols/runs, one-bit padding, EOI and image decoding. Cached
suffix counts distinguish an exact count from a lower bound: exceeding one
prefix's remaining count must not invalidate a different prefix. Identical
source windows share parsing while retaining their physical occurrences for
disjoint-range checks.

Two different valid byte results reject a unique-result claim. At most two
content witnesses per JPEG start are saved as `jpeg_gap_ambiguous_candidate`.
Search stops after proving ambiguity; further content alternatives and physical
aliases are not exhaustively enumerated. Extents show one reproducible mapping,
not the original placement. An otherwise unique byte result with multiple
physical mappings also records `jpeg_gap_source_mapping_ambiguous`. Neither
case authenticates ownership, original bytes or deletion.

Limits include 20,000 sector starts, `max_states` distinct middle windows,
`max_states * 8` middle checkpoints, `max_states * 256` completion attempts and
`max_states * 16384` suffix steps. Tail/window/transition pools each have a
32 MiB bound; suffix cache and pending-path pools each have a conservative
96 MiB entry bound. FIFO eviction discards only cached work. Existing 120-second,
verified-byte and output budgets remain effective. Exceeding a search bound
leaves the job incomplete and does not advance that JPEG start.

Cancellation is polled through the existing read/time boundary and throttled
progress callback. Durable resume remains at a whole JPEG-start boundary,
bound to source bytes, options and executing-code/runtime fingerprints; it does
not serialize partial Huffman work. Both ambiguous witnesses are retained and
revalidated on resume. C# mapping validation and file/photo catalogs preserve
the ambiguity status after decoding and byte-identical-copy grouping.

Source controls are `JpegTwoGapRecoveryTests.py` and
`JpegAmbiguityProvenanceTests.cs`. Actual packaged acceptance additionally uses
`JpegTwoGapPortableTests.cs`: exact independent gray bytes, two unknown-original
RGB witnesses, both physical gaps, mapping replay, decoder/dedup uncertainty,
acknowledged cancellation and pipeline resume. A five-minute watchdog is a test
failure, not a recovery result. Foreign unrecorded stage output remains rejected.

The integrated portable gate passed 56 Quality suites / 27,454 assertions,
4 Telegram suites / 137 assertions and 1 USB suite / 16 assertions, with Python
absent from PATH and temporary outbound rules removed. The JPEG suite contributes
110 actual checks; the gallery adds 37. Real devices are separately deferred.
The difficult 45,234-byte raw-scattered-baseline original was not recovered:
the two valid 44,722-byte witnesses remain explicitly ambiguous.
