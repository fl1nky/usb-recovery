"""Independent JPEG controls for marker boundaries and noisy disk images."""
import io
from pathlib import Path
import random
import sys
import tempfile
import unittest

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "helpers/recovery_engine"))
from fragmented_photos import PhotoAssembler
from jpeg_fragments import header, recover_jpegs, sparse_fallback
from jpeg_sector_runs import sector_runs, recover as join_runs


def sample():
    rng = random.Random(431)
    image = Image.frombytes("L", (160, 120), rng.randbytes(160 * 120))
    out = io.BytesIO()
    image.save(out, "JPEG", quality=86, restart_marker_blocks=40)
    return out.getvalue()


def align_marker(raw, marker):
    # Insert an ordinary COM segment; pixel and entropy bytes stay unchanged.
    pad = (-(marker + 1)) % 512
    if pad < 4:
        pad += 512
    return raw[:2] + b"\xff\xfe" + (pad - 2).to_bytes(2, "big") + bytes(pad - 4) + raw[2:], marker + pad + 1


def layout(which):
    raw = sample()
    if which in ("header-two-parts", "header-three-parts", "header-missing-table"):
        # Keep the opaque comment non-uniform. Split through the header itself,
        # then through entropy bytes that are well past the start of scan.
        padding = 300 if which == "header-two-parts" else 810
        body = random.Random(563).randbytes(padding)
        raw = raw[:2] + b"\xff\xfe" + (padding+2).to_bytes(2, "big") + body + raw[2:]
        cuts = [0, 512, 1024, 2048, len(raw)]
        offsets = [4103, 32775, 18439, 49159]
        disk = bytearray(128 * 1024)
        for n, (at, a, b) in enumerate(zip(offsets, cuts, cuts[1:])):
            if which != "header-missing-table" or n != 2:
                disk[at:at+b-a] = raw[a:b]
        return bytes(disk), raw, offsets
    first_restart = raw.index(b"\xff\xd0")
    if which in ("restart-split", "marker-noise", "missing-tail", "window-end"):
        raw, cut = align_marker(raw, first_restart)
    elif which == "eoi-split":
        raw, cut = align_marker(raw, len(raw) - 2)
    else:
        stuffed = raw.index(b"\xff\x00", first_restart + 2)
        raw, cut = align_marker(raw, stuffed)
    cuts = [0, cut, cut + 512, cut + 1024, len(raw)] if which != "eoi-split" else [0, 1024, 2048, cut, len(raw)]
    offsets = [4103, 32775, 18439, 49159]
    if which == "window-end":
        # The source ends partway through a sector in the SOI's alignment grid.
        offsets = [x + 64 * 1024 * 1024 for x in offsets]
    data = bytearray(max(at + b-a for at, a, b in zip(offsets, cuts, cuts[1:])))
    for at, a, b in zip(offsets, cuts, cuts[1:]):
        data[at:at+b-a] = raw[a:b]
    if which == "marker-noise":
        data += bytes(512) + b"\xff\xe1\xab\xcd" * 100050
    if which == "missing-tail":
        data = data[:-1]
    return bytes(data), raw, offsets


class SparseBoundaries(unittest.TestCase):
    def check(self, case, method=False):
        image, original, offsets = layout(case)
        with tempfile.TemporaryFile() as source:
            source.write(image)
            source.seek(0)
            assembler = PhotoAssembler(source)
            if method:
                frame = header(assembler, offsets[0])
                recipes = join_runs(assembler, frame, sector_runs(assembler, offsets[0]))
            else:
                assembler.index()
                recipes = [r for r, _, _ in recover_jpegs(assembler)]
        if case in ("missing-tail", "header-missing-table"):
            self.assertFalse(recipes, "missing source bytes must not be synthesized")
            return
        found = [recipe for recipe in recipes if b"".join(data for _, data in recipe) == original]
        self.assertEqual(len(found), 1, (case, assembler.skipped))
        self.assertEqual([p for p, _ in found[0]], offsets)
        for at, piece in found[0]:
            self.assertEqual(image[at:at+len(piece)], piece)
        with Image.open(io.BytesIO(original)) as ref, Image.open(io.BytesIO(b"".join(r[1] for r in found[0]))) as actual:
            self.assertEqual(actual.tobytes(), ref.tobytes())

    def test_restart_pair_split_and_marker_free_middle(self): self.check("restart-split")
    def test_stuffed_ff_zero_split(self): self.check("stuffed-split")
    def test_eoi_on_different_sectors(self): self.check("eoi-split")
    def test_global_marker_saturation(self): self.check("marker-noise")
    def test_truncated_final_marker(self): self.check("missing-tail")
    def test_partial_last_sector_after_large_offset(self): self.check("window-end", method=True)
    def test_header_in_two_extents(self): self.check("header-two-parts")
    def test_header_in_three_extents(self): self.check("header-three-parts")
    def test_missing_header_and_entropy_extent(self): self.check("header-missing-table")

    def test_short_extent_cannot_be_an_interior_sector(self):
        original = sample()
        runs = [(0, original[:1024]), (8192, original[1024:1283]), (24576, original[1283:])]
        with tempfile.TemporaryFile() as source:
            for at, part in runs:
                source.seek(at)
                source.write(part)
            assembler = PhotoAssembler(source)
            self.assertEqual(join_runs(assembler, header(assembler, 0), runs), [])

    def test_distinct_decodable_tails_remain_ambiguous(self):
        from JpegTwoGapRecoveryTests import encoded, scattered
        raw = encoded()
        other = next(data for value in range(256) if (data := encoded(last=value)) != raw
                     and len(data) == len(raw) and data[:1024] == raw[:1024])
        image, offsets = scattered(raw, alternate=other)
        with tempfile.TemporaryFile() as source:
            source.write(image)
            assembler = PhotoAssembler(source)
            candidates = list(sparse_fallback(assembler, header(assembler, offsets[0])))
        self.assertEqual({b"".join(part for _, part in recipe) for recipe, _, _ in candidates}, {raw, other})
        self.assertEqual({status for _, status, _ in candidates}, {"jpeg_gap_ambiguous_candidate"})
        self.assertEqual(assembler.skipped["jpeg_sparse_ambiguous"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
