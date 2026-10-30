"""Independent negative boundaries for fragmented-photo publication.

These are small owned synthetic images. No real device or personal file is
opened. The PNG writer is independent of the reassembler's parsing routines.
"""
from pathlib import Path
import hashlib
import os
import struct
import sys
import tempfile
import tracemalloc
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "helpers/recovery_engine"), str(ROOT / "tests")]
from fragmented_photos import PhotoAssembler, PNG, recover
from FragmentedPhotoTests import chunk, specimen, disk


class PhotoPublicationAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="photo-publication-audit-")
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_idat_embedded_inside_ancillary_cannot_be_reused_as_disjoint_piece(self):
        _, pieces = specimen(parts=1)
        wire = pieces[0][pieces[0].index(b"IDAT") - 4:]
        wire = wire[:wire.index(b"IEND") - 4]
        ihdr = PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", 39, 31, 8, 2, 0, 0, 0))
        ancillary = chunk(b"tEXt", b"K\0" + wire)
        data = bytearray(b"\xa5" * 100000)
        prefix = ihdr + ancillary
        data[4096:4096 + len(prefix)] = prefix
        data[80000:80012] = chunk(b"IEND", b"")
        source = self.base / "overlap.dd"
        source.write_bytes(data)
        result = recover(source, self.base / "out")
        self.assertEqual(result["Candidates"], 0)

    def test_iend_inside_compressed_pixels_is_not_a_separate_end_fragment(self):
        # zlib level=0 stores these valid RGB bytes literally, including a byte
        # pattern that independently passes the IEND chunk CRC. It is still
        # physically inside the IDAT extent and cannot terminate the file.
        ihdr = PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", 5, 1, 8, 2, 0, 0, 0))
        rows = b"\0" + chunk(b"IEND", b"") + b"\0" * 3
        idat = chunk(b"IDAT", zlib.compress(rows, 0))
        data = bytearray(b"\xa5" * 65536)
        data[4096:4096 + len(ihdr)] = ihdr
        data[16384:16384 + len(idat)] = idat
        source = self.base / "embedded-end.dd"
        source.write_bytes(data)
        result = recover(source, self.base / "out")
        self.assertEqual(result["Candidates"], 0)

    def test_token_index_memory_is_bounded_independently_of_match_count(self):
        source = self.base / "many-jpeg-tokens.dd"
        source.write_bytes(b"\xff\xd8\xff" * 400000)
        tracemalloc.start()
        try:
            with source.open("rb") as stream:
                assembler = PhotoAssembler(stream)
                assembler.index()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # The old global set consumed over 36 MB for this 1.2 MB source. Fixed
        # block buffers and the bounded header list need far less than 12 MB.
        self.assertLess(peak, 12 * 1024 * 1024)

    def test_source_content_change_with_restored_metadata_is_rejected(self):
        source = self.base / "source.dd"
        _, first = specimen(seed=1)
        _, second = specimen(seed=2)
        source.write_bytes(disk(first))
        initial = source.stat()
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        changed = False
        def replace_content(done, total):
            nonlocal changed
            if not changed:
                changed = True
                source.write_bytes(disk(second))
                os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        output = self.base / "out"
        with self.assertRaisesRegex(ValueError, "PHOTO_SOURCE_CHANGED"):
            recover(source, output, progress=replace_content)
        self.assertNotEqual(before, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertFalse(list(output.glob("*.png")))

    def test_disjoint_reordered_real_pieces_still_recover_exactly(self):
        payload, pieces = specimen(seed=9281)
        source = self.base / "source.dd"
        source.write_bytes(disk(pieces, [49152, 81920, 4096]))
        result = recover(source, self.base / "out")
        self.assertEqual(result["Candidates"], 1)
        candidate = result["Files"][0]
        self.assertEqual((self.base / "out" / candidate["Path"]).read_bytes(), payload)
        extents = candidate["Extents"]
        for index, left in enumerate(extents):
            for right in extents[index + 1:]:
                self.assertTrue(left["ImageOffset"] + left["Length"] <= right["ImageOffset"] or
                                right["ImageOffset"] + right["Length"] <= left["ImageOffset"])

    def test_cancelled_index_does_not_publish_final_files(self):
        _, pieces = specimen()
        source = self.base / "source.dd"
        source.write_bytes(disk(pieces))
        output = self.base / "out"
        def cancel(done, total):
            raise InterruptedError("owned synthetic cancellation")
        with self.assertRaises(InterruptedError):
            recover(source, output, progress=cancel)
        self.assertFalse(list(output.glob("*.png")))
        self.assertTrue((output / "job.incomplete").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
