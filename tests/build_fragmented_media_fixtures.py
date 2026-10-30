"""Independent QTFF table writer and scatterer, not imported by the recovery engine.

JPEG samples are actual Pillow-encoded images. Tiny AVC-only samples below are
syntactic NAL fixtures, deliberately NOT evidence of successful H.264 decoding.
Real codec-decoded fixtures belong to the separate external benchmark suite.
"""
from pathlib import Path
import hashlib
import io
import json
import struct
import sys

from PIL import Image


def be(*values):
    return struct.pack(">" + "I" * len(values), *values)


def atom(kind, body):
    return be(8 + len(body)) + kind.encode("ascii") + body


def full(kind, body, flags=0):
    return atom(kind, be(flags) + body)


def jpeg(index):
    stream = io.BytesIO()
    Image.new("RGB", (32, 24), (index * 37 % 256, 71, index * 53 % 256)).save(stream, format="JPEG", quality=80)
    raw = stream.getvalue()
    comment = ("independent-frame-%d:" % index).encode() + bytes([65 + index]) * (index * 37 + 5)
    return raw[:2] + b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment + raw[2:]


def avc(index):
    payload = bytes([0x65 if index == 0 else 0x41]) + bytes([0x88, 0x84, 0x21]) + bytes([0x30 + index]) * (19 + index * 23)
    return be(len(payload)) + payload


def sample_entry(codec):
    visual = bytes(6) + struct.pack(">H", 1) + bytes(16) + struct.pack(">HH", 32, 24)
    visual += be(0x480000, 0x480000, 0) + struct.pack(">H", 1) + bytes(32) + struct.pack(">HH", 24, 0xffff)
    assert len(visual) == 78
    if codec in ("avc1", "avc3"):
        sps = bytes.fromhex("6742c00ada7b011000000300100000030320f1226a")
        pps = bytes.fromhex("68ce0fc8")
        visual += atom("avcC", bytes([1, 66, 0, 10, 255, 225]) + struct.pack(">H", len(sps)) + sps + b"\x01" + struct.pack(">H", len(pps)) + pps)
    return atom(codec, visual)


def track(index, codec, chunks, offsets, co64):
    sizes = [len(sample) for chunk in chunks for sample in chunk]
    runs = []
    for n, chunk in enumerate(chunks, 1):
        if not runs or runs[-1][1] != len(chunk):
            runs.append((n, len(chunk), 1))
    stsd = full("stsd", be(1) + sample_entry(codec))
    stts = full("stts", be(1, len(sizes), 1000))
    stsc = full("stsc", be(len(runs)) + b"".join(be(*run) for run in runs))
    stsz = full("stsz", be(0, len(sizes)) + be(*sizes))
    stco = full("co64" if co64 else "stco", be(len(offsets)) + (struct.pack(">" + "Q" * len(offsets), *offsets) if co64 else be(*offsets)))
    dref = full("dref", be(1) + full("url ", b"", 1))
    stbl = atom("stbl", stsd + stts + stsc + stsz + stco)
    minf = atom("minf", full("vmhd", bytes(8), 1) + atom("dinf", dref) + stbl)
    mdhd = full("mdhd", be(0, 0, 1000, len(sizes) * 1000) + bytes(4))
    hdlr = full("hdlr", be(0) + b"vide" + bytes(12) + b"Independent video\0")
    mdia = atom("mdia", mdhd + hdlr + minf)
    tkhd = full("tkhd", be(0, 0, index + 1, 0, len(sizes) * 1000) + bytes(8) + bytes(8) + be(0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000, 32 << 16, 24 << 16), 7)
    return atom("trak", tkhd + mdia)


def movie(tracks, front=False, co64=False, free=False, extended=False):
    ftyp = atom("ftyp", b"isom" + be(512) + b"isomiso2avc1mp41")
    free_box = atom("free", b"") if free else b""
    chunks = [(t, n, b"".join(chunk)) for t, (_, groups) in enumerate(tracks) for n, chunk in enumerate(groups)]
    chunks.sort(key=lambda item: (item[1], item[0]))
    offsets = [[0] * len(groups) for _, groups in tracks]
    def moov():
        mvhd = full("mvhd", be(0, 0, 1000, 4000, 0x10000) + struct.pack(">H", 0x100) + bytes(10) + be(0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) + bytes(24) + be(len(tracks) + 1))
        return atom("moov", mvhd + b"".join(track(t, codec, groups, offsets[t], co64) for t, (codec, groups) in enumerate(tracks)) + atom("udta", atom("name", "Тестовая запись".encode())))
    preliminary = moov()
    header_size = 16 if extended else 8
    data_start = len(ftyp) + len(free_box) + header_size + (len(preliminary) if front else 0)
    position = data_start
    for t, n, body in chunks:
        offsets[t][n] = position
        position += len(body)
    metadata = moov()
    assert len(metadata) == len(preliminary)
    payload = b"".join(body for _, _, body in chunks)
    header = be(1) + b"mdat" + struct.pack(">Q", len(payload) + 16) if extended else be(len(payload) + 8) + b"mdat"
    sections = [(0, ftyp, "ftyp")]
    at = len(ftyp)
    if front:
        sections.append((at, metadata, "moov")); at += len(metadata)
    if free_box:
        sections.append((at, free_box, "free")); at += len(free_box)
    sections.append((at, header, "mdat_header")); at += len(header)
    for _, _, body in chunks:
        sections.append((at, body, "sample_chunk")); at += len(body)
    if not front:
        sections.append((at, metadata, "moov")); at += len(metadata)
    original = b"".join(body for _, body, _ in sections)
    assert len(original) == at
    return original, sections


def main(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    def add(name, tracks, expected=1, front=False, co64=False, free=False, extended=False, mode="scatter"):
        original, sections = movie(tracks, front, co64, free, extended)
        image = bytearray(b"\xcc" * (2 * 1024 * 1024 + 1024))
        extents = []
        # Reverse physical placement, with unrelated bytes between complete chunks.
        for n, (logical, body, kind) in enumerate(sections):
            physical = 4096 + (len(sections) - n) * 16384
            image[physical:physical + len(body)] = body
            extents.append(dict(ImageOffset=physical, LogicalOffset=logical, Length=len(body), Kind=kind))
        chunk_indices = [i for i, x in enumerate(sections) if x[2] == "sample_chunk"]
        if mode == "duplicate":
            i = chunk_indices[0]; body = sections[i][1]; image[500000:500000 + len(body)] = body
        if mode == "ambiguous":
            i = chunk_indices[0]; body = bytearray(sections[i][1]); body[12] ^= 1
            image[500000:500000 + len(body)] = body
        if mode == "missing":
            i = chunk_indices[-1]; physical = extents[i]["ImageOffset"]; image[physical:physical + extents[i]["Length"]] = bytes(extents[i]["Length"])
        if mode == "inside":
            i = chunk_indices[-1]; body = sections[i][1]; physical = extents[i]["ImageOffset"]; half = 3
            image[physical + half:physical + len(body)] = b"\x00" * (len(body) - half)
            image[600000:600000 + len(body) - half] = body[half:]
        if mode == "payload-overwrite":
            i = chunk_indices[-1]; physical = extents[i]["ImageOffset"]
            image[physical + 12:physical + 24] = bytes(12)
        if mode == "torn":
            i = next(i for i, x in enumerate(sections) if x[2] == "moov"); physical = extents[i]["ImageOffset"]
            image[physical + 8:physical + 12] = be(0xffffffff)
        if mode == "contiguous":
            image = bytearray(b"\xcc" * 4096 + original + b"\xcc" * 1024)
        (output / (name + ".dd")).write_bytes(image)
        (output / (name + ".original.mp4")).write_bytes(original)
        cases.append(dict(name=name, expected=expected, exact=mode != "payload-overwrite", sha256=hashlib.sha256(original).hexdigest(), bytes=len(original), chunks=len(chunk_indices), tracks=len(tracks), extents=extents, jpeg_decodable=all(codec == "jpeg" for codec, _ in tracks)))
    j = [[jpeg(0)], [jpeg(1), jpeg(2)], [jpeg(3)]]
    a = [[avc(0)], [avc(1), avc(2)], [avc(3)]]
    add("mjpeg-scattered", [("jpeg", j)])
    add("mjpeg-faststart-free", [("jpeg", j)], front=True, free=True)
    add("avc-scattered", [("avc1", a)])
    add("avc-faststart-co64", [("avc1", a)], front=True, co64=True)
    add("avc-extended-mdat", [("avc3", a)], extended=True)
    add("two-tracks-interleaved", [("jpeg", j), ("avc1", a)], front=True)
    same_length_b = bytearray(avc(0)); same_length_b[-1] ^= 1
    add("global-no-overlap-resolves", [("avc1", [[avc(0)], [bytes(same_length_b), avc(2)]])])
    add("global-distinct-permutations", [("avc1", [[avc(0)], [bytes(same_length_b)]])], expected=0)
    add("identical-duplicate", [("avc1", a)], mode="duplicate")
    add("ambiguous-avc", [("avc1", a)], expected=0, mode="ambiguous")
    add("missing-chunk", [("avc1", a)], expected=0, mode="missing")
    add("inside-chunk-split", [("avc1", a)], expected=0, mode="inside")
    add("overwritten-payload-structural-only", [("avc1", a)], mode="payload-overwrite")
    add("torn-moov", [("avc1", a)], expected=0, mode="torn")
    add("unsupported-codec", [("hvc1", a)], expected=0)
    add("contiguous-control", [("jpeg", j)], expected=0, mode="contiguous")
    (output / "manifest.json").write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Independent QTFF fixtures:", len(cases))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
