"""Independent PNG encoder, damaged-media layouts, exact-byte recovery checks."""
from pathlib import Path
import hashlib
import io
import json
import random
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers/recovery_engine"))
from fragmented_photos import recover, PNG


def chunk(kind, payload):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))


def specimen(seed=17, width=39, height=31, parts=3):
    rng = random.Random(seed)
    rows = b"".join(b"\0" + rng.randbytes(width * 3) for _ in range(height))
    packed = zlib.compress(rows)
    cuts = [len(packed) * i // parts for i in range(parts + 1)]
    head = PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"tEXt", b"Comment\0independent fixture")
    pieces = [head + chunk(b"IDAT", packed[cuts[0]:cuts[1]])]
    pieces += [chunk(b"IDAT", packed[cuts[i]:cuts[i + 1]]) for i in range(1, parts)]
    pieces[-1] += chunk(b"tEXt", b"Tail\0preserved metadata") + chunk(b"IEND", b"")
    payload = b"".join(pieces)
    from PIL import Image
    with Image.open(io.BytesIO(payload)) as image:
        image.load()
        assert image.size == (width, height)
    return payload, pieces


def disk(pieces, slots=None):
    slots = slots or [4096, 49152, 16384, 65536, 81920]
    data = bytearray(b"\xa5" * 131072)
    for piece, offset in zip(pieces, slots):
        data[offset:offset + len(piece)] = piece
    return data


def critical_specimen(seed=109, width=23, height=19, parts=3, indexed=False, zero=False, filters=(0,)):
    """A separate tiny encoder with every critical chunk in its own extent."""
    rng = random.Random(seed)
    channels = 1 if indexed else 3
    rows = b"".join(bytes([filters[row % len(filters)]]) + (bytes(width * channels) if zero else
                            bytes(rng.randrange(4) for _ in range(width)) if indexed else
                            rng.randbytes(width * channels)) for row in range(height))
    packed = zlib.compress(rows)
    pieces = [PNG, chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 3 if indexed else 2, 0, 0, 0))]
    if indexed:
        pieces.append(chunk(b"PLTE", b"\x00\x00\x00\xff\x00\x00\x00\xff\x00\x00\x00\xff"))
    pieces += [chunk(b"IDAT", packed[len(packed) * i // parts:len(packed) * (i + 1) // parts])
               for i in range(parts)]
    pieces.append(chunk(b"IEND", b""))
    return b"".join(pieces), pieces


def scatter(pieces, seed=311):
    rng = random.Random(seed)
    size = max(512 * 1024, (len(pieces) + 1) * 16384)
    slots = rng.sample(list(range(4096, size, 16384)), len(pieces))
    data = bytearray(b"\xa5" * size)
    for raw, at in zip(pieces, slots):
        if len(raw) > 16384:
            raise ValueError("independent fixture chunk exceeds its slot")
        data[at:at + len(raw)] = raw
    return data


class FragmentedPhotos(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fragmented-png-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_image(self, content, options=None):
        source, output = self.root / "source.dd", self.root / "out"
        source.write_bytes(content)
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        result = recover(source, output, options)
        self.assertEqual(before, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertFalse((output / "job.incomplete").exists())
        return result, output

    def test_exact_disordered_idat_and_metadata(self):
        payload, pieces = specimen()
        result, output = self.run_image(disk(pieces))
        self.assertEqual(result["Candidates"], 1)
        entry = result["Files"][0]
        self.assertEqual((output / entry["Path"]).read_bytes(), payload)
        self.assertEqual(entry["Status"], "png_crc_zlib_reassembled_candidate")
        logical = 0
        for extent in entry["Extents"]:
            self.assertEqual(extent["LogicalOffset"], logical)
            logical += extent["Length"]
        self.assertEqual(logical, len(payload))

    def test_two_distinct_complete_streams_are_ambiguous(self):
        _, first = specimen(1)
        _, second = specimen(2)
        # Keep one header; both complete compressed streams fit its dimensions.
        foreign_first = second[0][second[0].index(b"IDAT") - 4:]
        extra = [first[0], *first[1:], foreign_first, *second[1:]]
        result, _ = self.run_image(disk(extra, [4096, 49152, 16384, 65536, 81920, 98304]))
        self.assertEqual(result["Candidates"], 0)
        self.assertGreater(result["Skipped"].get("png_ambiguous", 0), 0)

    def test_overwritten_chunk_not_success(self):
        _, pieces = specimen()
        data = disk(pieces)
        data[49152 + 15] ^= 0x40
        result, _ = self.run_image(data)
        self.assertEqual(result["Candidates"], 0)

    def test_crc_repaired_but_wrong_stream_not_success(self):
        _, pieces = specimen()
        raw = bytearray(pieces[1]); raw[15] ^= 0x40
        raw[-4:] = struct.pack(">I", zlib.crc32(raw[4:-4]))
        pieces[1] = bytes(raw)
        result, _ = self.run_image(disk(pieces))
        self.assertEqual(result["Candidates"], 0)

    def test_unchanged_contiguous_file_not_reported_as_reassembled(self):
        payload, _ = specimen()
        result, _ = self.run_image(disk([payload]))
        self.assertEqual(result["Candidates"], 0)

    def test_duplicate_idat_bytes_do_not_create_ambiguity(self):
        payload, pieces = specimen()
        result, output = self.run_image(disk(pieces + [pieces[1]]))
        self.assertEqual(result["Candidates"], 1)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), payload)

    def test_bounded_search_does_not_publish_unexplored_candidate(self):
        _, pieces = specimen()
        result, _ = self.run_image(disk(pieces), {"max_states": 1})
        self.assertEqual(result["Candidates"], 0)
        self.assertGreater(result["Skipped"].get("png_search_incomplete", 0), 0)
        self.assertEqual(result["Status"], "limited")

    def test_absurd_dimensions_and_chunk_length(self):
        head = PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", 0x7fffffff, 31, 8, 2, 0, 0, 0))
        result, _ = self.run_image(disk([head + struct.pack(">I4s", 0x7fffffff, b"IDAT")]))
        self.assertEqual(result["Candidates"], 0)

    def test_existing_destination_untouched(self):
        source, output = self.root / "source.dd", self.root / "out"
        source.write_bytes(b"test"); output.mkdir(); (output / "keep").write_bytes(b"owned data")
        with self.assertRaises(ValueError):
            recover(source, output)
        self.assertEqual((output / "keep").read_bytes(), b"owned data")

    def test_signature_header_data_and_end_all_separate(self):
        payload, pieces = critical_specimen()
        result, output = self.run_image(scatter(pieces))
        self.assertEqual(result["Candidates"], 1)
        entry = result["Files"][0]
        self.assertEqual((output / entry["Path"]).read_bytes(), payload)
        self.assertEqual(len(entry["Extents"]), len(pieces))

    def test_detached_header_keeps_its_surviving_metadata(self):
        payload, pieces = specimen(parts=3)
        # Signature was split off while header/metadata/first IDAT stayed linked.
        result, output = self.run_image(scatter([PNG, pieces[0][8:], *pieces[1:]], seed=709))
        self.assertEqual(result["Candidates"], 1)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), payload)

    def test_detached_indexed_color_palette_exact(self):
        payload, pieces = critical_specimen(indexed=True)
        result, output = self.run_image(scatter(pieces, seed=713))
        self.assertEqual(result["Candidates"], 1)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), payload)

    def test_distinct_structurally_valid_headers_reject_ambiguity(self):
        _, pieces = critical_specimen(width=3, height=4, parts=1, zero=True)
        # Both layouts consume forty filtered bytes and are valid zero images.
        alternate = chunk(b"IHDR", struct.pack(">IIBBBBB", 13, 1, 8, 2, 0, 0, 0))
        result, _ = self.run_image(scatter([*pieces, alternate]))
        self.assertEqual(result["Candidates"], 0)
        self.assertGreater(result["Skipped"].get("png_ambiguous", 0), 0)

    def test_adjacent_header_not_replaced_by_unrelated_global_header(self):
        payload, pieces = critical_specimen(width=3, height=4, parts=1, zero=True)
        alternate = chunk(b"IHDR", struct.pack(">IIBBBBB", 13, 1, 8, 2, 0, 0, 0))
        result, output = self.run_image(scatter([pieces[0] + pieces[1], *pieces[2:], alternate]))
        self.assertEqual(result["Candidates"], 1)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), payload)

    def test_identical_detached_headers_and_palettes_do_not_create_ambiguity(self):
        payload, pieces = critical_specimen(indexed=True, parts=2)
        result, output = self.run_image(scatter([*pieces, pieces[1], pieces[2]], seed=719))
        self.assertEqual(result["Candidates"], 1)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), payload)

    def test_distinct_valid_palettes_are_ambiguous_even_for_same_stream(self):
        _, pieces = critical_specimen(indexed=True, parts=1)
        alternative = chunk(b"PLTE", bytes(reversed(pieces[2][8:-4])))
        result, _ = self.run_image(scatter([*pieces, alternative], seed=727))
        self.assertEqual(result["Candidates"], 0)
        self.assertGreater(result["Skipped"].get("png_ambiguous", 0), 0)

    def test_missing_mandatory_palette_rejected(self):
        _, pieces = critical_specimen(indexed=True)
        result, _ = self.run_image(scatter(pieces[:2] + pieces[3:]))
        self.assertEqual(result["Candidates"], 0)

    def test_palette_with_out_of_range_pixel_indices_rejected(self):
        _, pieces = critical_specimen(indexed=True, parts=1)
        pieces[2] = chunk(b"PLTE", b"\0\0\0")
        result, _ = self.run_image(scatter(pieces))
        self.assertEqual(result["Candidates"], 0)

    def test_invalid_palette_length_rejected(self):
        _, pieces = critical_specimen(indexed=True, parts=1)
        pieces[2] = chunk(b"PLTE", b"\0" * 5)
        result, _ = self.run_image(scatter(pieces))
        self.assertEqual(result["Candidates"], 0)

    def test_detached_header_crc_and_dimensions_must_agree(self):
        _, pieces = critical_specimen()
        damaged = bytearray(pieces[1]); damaged[-1] ^= 1
        mismatch = chunk(b"IHDR", struct.pack(">IIBBBBB", 24, 19, 8, 2, 0, 0, 0))
        result, _ = self.run_image(scatter([pieces[0], bytes(damaged), mismatch, *pieces[2:]]))
        self.assertEqual(result["Candidates"], 0)

    def test_search_limit_shared_across_detached_headers(self):
        _, pieces = critical_specimen(width=3, height=4, parts=1, zero=True)
        alternate = chunk(b"IHDR", struct.pack(">IIBBBBB", 13, 1, 8, 2, 0, 0, 0))
        result, _ = self.run_image(scatter([*pieces, alternate]), {"max_states": 1})
        self.assertEqual(result["Candidates"], 0)
        self.assertEqual(result["Status"], "limited")
        self.assertGreater(result["Skipped"].get("png_search_incomplete", 0), 0)

    def test_detached_ihdr_token_across_index_block_boundary(self):
        payload, pieces = critical_specimen(parts=1)
        data = bytearray(b"\xa5" * (2 * 1024 * 1024))
        # Split the IHDR token itself across the scanner's one-megabyte boundary.
        slots = [4001, 1024 * 1024 - 6, 196608, 1572864]
        for raw, at in zip(pieces, slots):
            data[at:at + len(raw)] = raw
        result, output = self.run_image(data)
        self.assertEqual(result["Candidates"], 1)
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), payload)

    def test_many_weakly_compressed_idat_chunks_use_png_row_structure(self):
        # Random filtered bytes compress into stored deflate blocks. Incorrect
        # chunk permutations can survive zlib until its final Adler checksum,
        # so the decoder must also validate each surviving row's filter byte.
        payload, pieces = critical_specimen(seed=3987, width=197, height=131,
                                           parts=32, filters=(0, 1, 2, 3, 4))
        result, output = self.run_image(scatter(pieces, seed=937))
        self.assertEqual(result["Candidates"], 1)
        self.assertEqual(result["Status"], "complete")
        self.assertEqual((output / result["Files"][0]["Path"]).read_bytes(), payload)

    def test_invalid_png_filter_byte_rejected_despite_valid_chunk_crc_and_zlib(self):
        _, pieces = critical_specimen(parts=1, filters=(5,))
        result, _ = self.run_image(scatter(pieces))
        self.assertEqual(result["Candidates"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
