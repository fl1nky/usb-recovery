# NTFS record regression control

Pinned project-generated test data for `MetadataRescueTests`. The image was created with mkntfs/ntfscp and deliberately altered for a deleted fragmented synthetic JPEG. Exact historical tool versions are unknown. Its deleted FILE record has torn USA tails and must be rejected. The test repairs four bytes only in a new working copy, then requires the original JPEG SHA256.

`build_ntfs_record_checkpoint_fixtures.py` verifies and expands this source into a fresh owned `.build` directory. It never writes to the compressed fixture or a physical device. Other checkpoint images produced by that script are structural controls, not native-formatted disks.

These project-authored control files use the repository's AGPL-3.0 license. The JPEG is synthetic test content; the image is an ordinary generated filesystem fixture.
