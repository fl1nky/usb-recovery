# Telegram media-only records

Native Android rows with a supported document reference now remain in the local
archive even when their message text is exactly empty. The same retention applies
to checked WAL snapshots and deleted SQLite records with confirmed table/TL
relationships. A serialized ID of zero is distinct from an absent reference.

The text remains `""`; filenames, MIME types, title/performer metadata and Android
attachment paths never become message text. Records without original attachment
bytes say `document_reference_only`. A decoded cached thumbnail says
`cached_thumbnail_available`, retains its BLOB-relative origin and remains a
thumbnail rather than the original document/video/audio. Opaque or unavailable
thumbnail bytes do not suppress the checked message metadata.

Browsing an archive includes these records. A word or Regex query matches only
the surviving text, so an empty message does not match its attachment metadata.
Unbound memory bytes do not acquire chat, sender, timestamp or deletion claims.
Reimported archive metadata remains provided metadata, not independently verified
native evidence.

`tests/fixtures/telegram-media-only` contains14 exact independent official-Java
serializations (7 empty and7 paired captions) and56 wire/profile/SQL controls,
with native SQLite inputs, complete replay sources and GPL license. The immutable
oracle counts7 nonempty text slots and deliberately specifies no retention
policy. `telegram_media_retention_policy.py` separately names product policy
`retained_media_records_v1`; old oracle text counts and old goldens are unchanged.

Relative to released9488f5d, three older empty-text cases also gain one metadata
record: `mode4`, `descriptor-empty-text`, `empty-text-audio-metadata`. The31-case
attributes corpus therefore has31 native records but still only30 nonempty text
slots. This is a record-retention change, not newly recovered text bytes.

The focused suite covers the14 native rows,56 controls, zero-length full-text
pages, index/search, missing references, actual SQLite DELETE freeblocks, checked
WAL histories, thumbnail limits and source preservation. Source testing does not
prove packaged/offline operation, real-device recovery or competitor superiority.
