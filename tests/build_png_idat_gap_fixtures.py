"""Independent native PNG/DEFLATE fixtures with physical allocation-unit gaps.

This module never imports recovery code. Pillow encodes pixels; a small format
writer may repartition that same DEFLATE stream into legal PNG IDAT chunks.
CRC/zlib and all PNG8 row filters are checked independently before scattering.
Expected maps remain outside the raw image and are not passed to recovery.
"""
from pathlib import Path
import hashlib
import io
import json
import random
import struct
import zlib

from PIL import Image, __version__ as pillow_version

PNG = b"\x89PNG\r\n\x1a\n"
CASE_NAMES = (
    "contiguous", "whole-idat", "cut-512", "cut-4k", "cut-32k", "cut-128k", "cut-1280k",
    "unaligned-head", "reversed", "zero-padding", "random-padding", "ancillary-prefix",
    "ancillary-tail", "indexed-palette", "multi-idat-middle", "crc-split", "duplicate-tail",
    "false-anchor", "corrupt-crc", "invalid-adler", "missing-payload", "overlap",
    "forbidden-tail-context", "invalid-filter", "ambiguous-tail", "mixed-intact-gap-ambiguous")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def chunk(kind, payload):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind+payload))


def packets(raw):
    if raw[:8] != PNG:
        raise ValueError("Fixture PNG signature invalid")
    result, at = [], 8
    while at < len(raw):
        length, kind = struct.unpack_from(">I4s", raw, at)
        end = at + length + 12
        if end > len(raw) or zlib.crc32(raw[at+4:end-4]) != struct.unpack_from(">I", raw, end-4)[0]:
            raise ValueError("Fixture PNG CRC or chunk bounds invalid")
        result.append((kind, raw[at+8:end-4], at, end))
        at = end
    return result


def oracle(raw):
    parts = packets(raw)
    width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", parts[0][1])
    if (depth, compression, filtering, interlace) != (8, 0, 0, 0) or color not in (2, 3):
        raise ValueError("Independent oracle supports PNG RGB8/indexed8")
    channels = 3 if color == 2 else 1
    expected = height * (1 + width * channels)
    decoder = zlib.decompressobj()
    rows = decoder.decompress(b"".join(data for kind,data,_,_ in parts if kind == b"IDAT"), expected+1)
    if len(rows) != expected or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
        raise ValueError("Fixture zlib stream is not exact and complete")
    prior, pixels, filters = bytes(width*channels), bytearray(), set()
    def paeth(a, b, c):
        p = a+b-c
        x,y,z = abs(p-a),abs(p-b),abs(p-c)
        return a if x <= y and x <= z else b if y <= z else c
    for row_index in range(height):
        at = row_index * (1 + width*channels)
        kind, row = rows[at], bytearray(rows[at+1:at+1+width*channels])
        if kind > 4:
            raise ValueError("Invalid PNG filter")
        filters.add(kind)
        for x in range(len(row)):
            left, up, upper_left = row[x-channels] if x >= channels else 0, prior[x], prior[x-channels] if x >= channels else 0
            row[x] = (row[x] + (0,left,up,(left+up)//2,paeth(left,up,upper_left))[kind]) & 255
        pixels.extend(row)
        prior = row
    with Image.open(io.BytesIO(raw)) as image:
        image.load()
        if image.size != (width,height) or image.tobytes() != pixels:
            raise ValueError("Independent rows disagree with image decoder")
    return dict(Width=width, Height=height, Mode="RGB" if color == 2 else "P", PixelsSha256=digest(pixels),
                Filters=sorted(filters), Chunks=[dict(Type=kind.decode("ascii"), Offset=at, Bytes=end-at) for kind,_,at,end in parts])


def encode(width=128, height=96, *, indexed=False, zeros=False, compression=6, salt=0):
    rng = random.Random(0xC0DE519 + salt)
    pixels = bytes(width*height*(1 if indexed else 3)) if zeros else (bytes(rng.randrange(16) for _ in range(width*height)) if indexed else rng.randbytes(width*height*3))
    image = Image.frombytes("P" if indexed else "RGB", (width,height), pixels)
    if indexed:
        image.putpalette(bytes(value for index in range(256) for value in (index,(index*3)%256,(index*7)%256)))
    output = io.BytesIO()
    image.save(output, "PNG", optimize=False, compress_level=compression)
    native = output.getvalue()
    parts = packets(native)
    prefix = [(kind,data) for kind,data,_,_ in parts if kind not in (b"IDAT",b"IEND")]
    packed = b"".join(data for kind,data,_,_ in parts if kind == b"IDAT")
    return prefix, packed, pixels


def create(destination, name):
    if name not in CASE_NAMES:
        raise ValueError("Unknown independent PNG gap case")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    width, height = (256,192) if name == "cut-128k" else (1024,512) if name == "cut-1280k" else (128,96)
    indexed = name == "indexed-palette"
    if indexed:
        width,height = 256,128
    compression = 0 if name in ("overlap","ambiguous-tail") else 6
    prefix, packed, pixels = encode(width,height,indexed=indexed,zeros=name == "overlap",compression=compression)
    if name == "ancillary-prefix":
        prefix += [(b"gAMA",struct.pack(">I",45455)),(b"tEXt",b"Comment\0independent prefix")]
    count = 3 if name == "multi-idat-middle" else 1
    data_chunks = [packed[len(packed)*i//count:len(packed)*(i+1)//count] for i in range(count)]
    tail = [(b"tEXt",b"Tail\0preserve actual tail bytes")] if name == "ancillary-tail" else []
    raw = PNG + b"".join(chunk(kind,data) for kind,data in prefix) + b"".join(chunk(b"IDAT",data) for data in data_chunks) + b"".join(chunk(kind,data) for kind,data in tail) + chunk(b"IEND",b"")
    original = raw
    known = oracle(original)
    if known["PixelsSha256"] != digest(pixels):
        raise ValueError("Native encoded PNG differs from original pixels")
    idats = [item for item in packets(raw) if item[0] == b"IDAT"]
    desired = {"cut-512":512,"cut-32k":32768,"cut-128k":131072,"cut-1280k":1310720}.get(name,4096)
    if name == "multi-idat-middle":
        desired = idats[1][2] + 8 + len(idats[1][1])//2
    if name == "crc-split":
        desired = idats[0][3]-2
    source_at = 8192 + (73 if name == "unaligned-head" else (-desired)%512 if name == "crc-split" else 0)
    cut = desired if name == "crc-split" else ((source_at+desired+511)//512)*512-source_at
    if name == "whole-idat":
        cut = idats[0][2]
    if name == "contiguous":
        cut = len(raw)
    expected = 0 if name in ("contiguous","corrupt-crc","invalid-adler","missing-payload","overlap","forbidden-tail-context","invalid-filter","ambiguous-tail","mixed-intact-gap-ambiguous") else 1
    if name in ("corrupt-crc","invalid-adler"):
        _, data, at, end = idats[0]
        body = bytearray(data)
        if name == "corrupt-crc":
            wire = bytearray(raw);wire[end-1] ^= 1;raw = bytes(wire)
        else:
            body[-1] ^= 1  # Invalid Adler, with intentionally correct chunk CRC.
            raw = raw[:at] + chunk(b"IDAT",body) + raw[end:]
    if name == "invalid-filter":
        rows = bytearray(zlib.decompress(packed));rows[0] = 5
        raw = PNG + b"".join(chunk(kind,data) for kind,data in prefix) + chunk(b"IDAT",zlib.compress(rows)) + chunk(b"IEND",b"")
    if name == "forbidden-tail-context":
        raw = raw[:-12] + chunk(b"pHYs",struct.pack(">IIB",72,72,1)) + raw[-12:]
    if name == "reversed":
        source_at = ((8192+len(raw)-cut+16384+4095)//4096)*4096
        tail_at = 8192
    elif name == "overlap":
        tail_at = source_at+cut-512
        if raw[cut-512:cut] != raw[cut:cut+512]:
            raise ValueError("Overlapping test slices must agree in their physical overlap")
    else:
        tail_at = ((max(65536,source_at+cut+16384)+511)//512)*512
    foreign = None
    if name == "ambiguous-tail":
        # A separate native uncompressed PNG changes a later pixel while the
        # prefix/geometry are identical. Both tails must remain plausible.
        mutated = bytearray(pixels);mutated[-19] ^= 0x40
        foreign_image = Image.frombytes("RGB", (width,height), bytes(mutated))
        buffer = io.BytesIO();foreign_image.save(buffer,"PNG",compress_level=0,optimize=False)
        foreign_parts = packets(buffer.getvalue())
        foreign_packed = b"".join(data for kind,data,_,_ in foreign_parts if kind == b"IDAT")
        foreign = PNG + b"".join(chunk(kind,data) for kind,data in prefix) + chunk(b"IDAT",foreign_packed) + chunk(b"IEND",b"")
        if len(foreign) != len(original) or foreign[:cut] != original[:cut] or oracle(foreign)["PixelsSha256"] == known["PixelsSha256"]:
            raise ValueError("Native ambiguous tail construction failed")
    if name == "mixed-intact-gap-ambiguous":
        # The sole physical header precedes fragmented native image A. A
        # foreign image B contributes only an intact IDAT/IEND, with matching
        # dimensions. Neither logical reassembly may be called unique.
        _, foreign_packed, foreign_pixels = encode(width,height,compression=compression,salt=71)
        foreign = PNG + b"".join(chunk(kind,data) for kind,data in prefix) + chunk(b"IDAT",foreign_packed) + chunk(b"IEND",b"")
        if oracle(foreign)["PixelsSha256"] != digest(foreign_pixels) or digest(foreign_pixels) == known["PixelsSha256"]:
            raise ValueError("Independent foreign native PNG construction failed")
    extra_at = ((tail_at+len(raw)-cut+8192+511)//512)*512
    size = max(256*1024, ((max(source_at+min(cut,len(raw)),tail_at+len(raw)-cut,extra_at+(len(raw)-cut if name in ("duplicate-tail","ambiguous-tail") else 0))+8192+4095)//4096)*4096)
    if name == "mixed-intact-gap-ambiguous":
        size = max(size, ((extra_at+len(foreign)+8192+4095)//4096)*4096)
    image = bytearray(random.Random(20261102).randbytes(size)) if name == "random-padding" else bytearray(bytes([0 if name == "zero-padding" else 0xA5])*size)
    extents = []
    image[source_at:source_at+cut] = raw[:cut]
    extents.append(dict(ImageOffset=source_at,LogicalOffset=0,Length=cut))
    if cut < len(raw):
        image[tail_at:tail_at+len(raw)-cut] = raw[cut:]
        extents.append(dict(ImageOffset=tail_at,LogicalOffset=cut,Length=len(raw)-cut))
    if name in ("duplicate-tail","ambiguous-tail"):
        image[extra_at:extra_at+len(raw)-cut] = (foreign if foreign is not None else raw)[cut:]
    if name == "mixed-intact-gap-ambiguous":
        foreign_start = next(at for kind,_,at,_ in packets(foreign) if kind == b"IDAT")
        foreign_tail = foreign[foreign_start:]
        image[extra_at:extra_at+len(foreign_tail)] = foreign_tail
    if name == "false-anchor":
        end = tail_at+len(raw)-cut-12+8192
        image[end:end+12] = chunk(b"IEND",b"")
    if name == "missing-payload":
        image[tail_at+1024:tail_at+1536] = b"\xCC"*512
    source = destination / "image.dd"
    source.write_bytes(image)
    (destination / "original.png").write_bytes(original)
    if foreign is not None:
        (destination / "alternative.png").write_bytes(foreign)
    valid_source_bytes = b"".join(image[x["ImageOffset"]:x["ImageOffset"]+x["Length"]] for x in extents) == original
    golden = dict(Name=name, Image="image.dd", Original="original.png", Sha256=digest(original), Bytes=len(original),
        ExpectedCandidates=expected, ExpectedSha256=digest(original) if expected else None,
        SourceSha256=digest(image), SourceBytes=len(image), LogicalCut=cut, PhysicalExtents=extents,
        AllOriginalBytesPresent=valid_source_bytes, Oracle=known, Pillow=pillow_version,
        SourceCutIsAbsolute512=(source_at+cut)%512 == 0,
        IdatChunks=[dict(Offset=at,Bytes=end-at) for _,_,at,end in idats])
    (destination / "golden.json").write_text(json.dumps(golden,indent=2)+"\n",encoding="utf8")
    return source, golden


def build(destination):
    destination = Path(destination)
    destination.mkdir(parents=True,exist_ok=False)
    cases = []
    for name in CASE_NAMES:
        source, golden = create(destination / name,name)
        cases.append(dict(golden,Image=source.relative_to(destination).as_posix(),Original=(source.parent/"original.png").relative_to(destination).as_posix()))
    manifest = dict(Schema=1,GeneratorSha256=digest(Path(__file__).read_bytes()),
        IndependentEncoder=True,SourceSpec="https://www.w3.org/TR/2025/REC-png-3-20250624/",Cases=cases)
    (destination / "manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf8")
    return manifest


if __name__ == "__main__":
    import sys
    manifest = build(sys.argv[1])
    print(json.dumps(dict(cases=len(manifest["Cases"]),generator_sha256=manifest["GeneratorSha256"])))
