# One IDAT in three physical runs

The bounded fragmented-PNG source reader now joins one surviving IDAT header/prefix, one512-aligned middle run and an anchored suffix. Original bytes and stored CRC are retained. It does not invent bytes, infer the original filename/owner or prove deletion. The normal two-run search remains in the union; a foreign intact chunk cannot establish uniqueness before fragmented alternatives are considered.

The independent baseline contains two valid PNGs that the previous packaged helper completed without recovering:256×192 with cuts32KiB/128KiB and1024×512 with cuts128KiB/1.25MiB. All original bytes survive. On the same complete source images, the new packaged public wrapper recovers each exact original SHA/pixels with disjoint source ranges. Separate controls retain two different valid images as ambiguous and byte-identical content with two physical middle placements as one file with source-map alternatives.

Packaged acceptance covers20 independently encoded layouts:18 expected exact case outcomes and two explicit ambiguity controls. Every emitted map is replayed against real source bytes; catalog, gallery and export preserve the available maps. Actual cancellation/resume, copied-checkpoint tamper rejection and incomplete work limits are checked separately. The full offline gate also retains the existing recovery, Telegram and synthetic USB-image suites. These are owned regular-image tests; physical USB/Android/iPhone tests and broader commercial comparisons remain separate work.

For a complete IDAT chunk of lengthT, let cutsa<b be relative to its header, m=d+a the physical middle start, H(x)=CRC(source[:x]), P(a)=CRC(type+prefix), S(b)=CRC(suffix payload), and C the surviving stored CRC. With inverse linear CRC shift Unshift, the necessary CRC relation is:

```
Unshift(H(d+a), a) xor Unshift(P(a), a)
  == Unshift(H(d+b), b) xor Unshift(C xor S(b), T-4)
```

Both cuts share the absolute512-byte phase, so physical prefix-CRC indices are integer sector positions. The implementation streams H once, builds compact inverse byte tables, then hash-joins start/end keys for each displacement. It avoids the naivea×b×middle-start Cartesian search. Hash buckets retain all matching endpoints; CRC equality is only a gate. Every hit is re-read from its three real physical ranges and checked against the unchanged original full IDAT CRC. The existing PNG walker independently checks chunk context, full zlib/Adler consumption, row filters, palette/geometry and strict image decode.

A final cut can fall at the CRC start or after its first1–3bytes. For E=d+T-4, the observed high CRC bytes belong to the middle and the remaining bytes precede the real suffix anchor. Removing those bytes from H(middleEnd) yields H(E); no CRC bytes are synthesized. A first cut inside the CRC cannot precede a second cut by a whole512-byte sector and is excluded geometrically. An intact eight-byte IDAT header is required; broken headers remain unsupported.

Prefix inflation prunes only when the source has exactly one indexed IDAT header, so every PNG path must use it first. With multiple headers, an IDAT may continue another chunk's decoder state; all cuts remain eligible. The sole-header probe stops only at an actual zlib error/end and charges the existing global decoded-byte budget. No8KiB prefix assumption or oracle SHA/pixel hint is used.

The main bounds are explicit:

| Resource | Bound / behavior |
|---|---|
| Declared fragmented IDAT |2MiB, all absolute512 cuts; at most4097 cut tables |
| Inverse tables |16MiB+4KiB maximum |
| Physical source index |128MiB limit for this join, streamed CRC states only (about1MiB array); exceeding a bound remains incomplete |
| CRC work |existing128MiB shared budget, including the source index |
| Cheap join cells |min(32Mi cells, max_states×8192) |
| Physical candidates |512 maps;128 distinct byte-identical-content groups |
| Distinct candidate raw buffers |existing64MiB; sharing requires SHA bucket and actual byte equality |
| Source reads/time/decode |existing512MiB verified reads /120seconds /256MiB inflation |

Any unvisited search due to work/byte/time bounds is incomplete, even after an early hit; it cannot establish a unique result. Physical aliases are separate from content ambiguity. Byte-identical candidates keep their bounded maps, while two fully valid different PNG contents suppress unique publication. Adjacent forward subdivisions are the already enumerated two-run model and are not counted as new three-run maps. Shared report/checkpoint handling retains alternate maps and replays every map on resume.

[The independent factory](../../tests/build_png_two_gap_fixtures.py) supplies20 layouts: the four pinned baseline cases, all six physical orders, an unaligned head, final cuts at/inside CRC, multi-IDAT continuation, palette/ancillary context and an intact-versus-three-run ambiguity control. [Source tests](../../tests/PngTwoGapRecoveryTests.py) additionally check corrupt bytes, valid chunk CRC with bad Adler/filter, exact source replay, budgets, cancellation/resume and code fingerprints. Existing26-case PNG and70MiB checkpoint-resume regressions are retained. Independent CRC math covers39256 native-zlib checks across signs/phases/orders.

Source tests, packaged-wrapper acceptance, full offline gates and publication have separate receipts. The checks above establish only the covered layouts and limits. Larger or more fragmented IDAT layouts, arbitrary physical alignment and overwritten bytes require further work; the program cannot promise recovery of every deleted photograph or video.
