"""Small independent file-layout controls for the managed byte-offset passes."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib


def box(kind, body, wide=False):
    if wide:
        return struct.pack(">I4sQ", 1, kind, 16 + len(body)) + body
    return struct.pack(">I4s", 8 + len(body), kind) + body


def movie(brand, payload, compatible=b"", wide=False):
    return (box(b"ftyp", brand + bytes(4) + compatible, wide)
            + box(b"mdat", payload) + box(b"moov", b""))


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png(color, depth, chunks):
    header = struct.pack(">IIBBBBB", 2, 1, depth, color, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + b"".join(chunks) + chunk(b"IEND", b"")


def pdf(payload, update=False):
    # A one-page document with a valid classic cross-reference table. Text in a
    # stream is opaque. Incremental updates refer back to the original xref.
    entry = lambda at: f"{at:010d} 00000 n \n".encode()
    out = bytearray(b"%PDF-1.4\n")
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 50 50] /Contents 4 0 R >>",
               b"<< /Length %d >>\nstream\n" % len(payload) + payload + b"\nendstream"]
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out.extend(b"%d 0 obj\n" % i + obj + b"\nendobj\n")
    xref = len(out)
    out.extend(b"xref\n0 5\n0000000000 65535 f \n" + b"".join(map(entry, offsets)))
    out.extend(b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\r\n" % xref)
    if update:
        info = len(out)
        out.extend(b"5 0 obj\n<< /Title (Recovered revision) >>\nendobj\n")
        new = len(out)
        out.extend(b"xref\n5 1\n"+entry(info))
        out.extend(b"trailer\n<< /Size 6 /Root 1 0 R /Info 5 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (xref, new))
    return bytes(out)


def create(directory):
    directory.mkdir(parents=True, exist_ok=True)
    manifest = []
    def record(name, mode, pieces, expected):
        data = b"".join(pieces)
        (directory / (name + ".dd")).write_bytes(data)
        entries = [{"extension": ext, "sha256": hashlib.sha256(raw).hexdigest(), "offset": pos, "size": len(raw)}
                   for ext, raw, pos in expected]
        manifest.append(dict(name=name, mode=mode, source_sha256=hashlib.sha256(data).hexdigest(), expected=entries))

    left = movie(b"isom", b"first independent payload", b"mp42")
    right = movie(b"qt  ", b"second independent payload")
    record("two-adjacent-movies", "containers", [b"AB",left,right], [(".mp4",left,2),(".mov",right,2+len(left))])
    audio = movie(b"M4A ", b"audio sample", b"isom", wide=True)
    record("wide-audio-ftyp", "containers", [audio], [(".m4a",audio,0)])
    # AVIF may advertise a generic major brand and identify itself in compatible_brands.
    avif = box(b"ftyp",b"mif1"+bytes(4)+b"avif")+box(b"meta",bytes(4))+box(b"mdat",b"payload")
    record("avif-compatible-brand", "containers", [b"xxx",avif], [(".avif",avif,3)])
    # An ftyp without minor_version cannot introduce a complete file.
    fake = box(b"ftyp",b"isom")+box(b"mdat",b"data")+box(b"moov",b"")
    record("short-ftyp", "containers", [fake], [])

    stream_pdf = pdf(b"% unrelated text inside a stream\n%%EOF\n% same page\n")
    record("pdf-marker-in-stream", "containers", [b"+++",stream_pdf], [(".pdf",stream_pdf,3)])
    revision = pdf(b"q Q", update=True)
    separate = pdf(b"q 0 0 1 1 re Q")
    record("pdf-revision-and-neighbour", "containers", [revision,separate],
           [(".pdf",revision,0),(".pdf",separate,len(revision))])
    # The new revision lost its real EOF. Keep the complete original revision.
    first = pdf(b"q Q")
    torn = first[:first.index(b"xref\n")]
    record("pdf-torn-next-to-intact", "containers", [torn,separate], [(".pdf",separate,len(torn))])
    embedded = pdf(b"attachment\n" + separate + b"\nend of attachment")
    record("pdf-with-embedded-pdf", "containers", [embedded], [(".pdf",embedded,0)])
    record("pdf-torn-update", "containers", [revision[:-8]], [(".pdf",first,0)])
    no_eol = first.rstrip(b"\r\n")
    record("pdf-no-final-newline", "containers", [no_eol,b"\xae"*32], [(".pdf",no_eol,0)])
    private_note = revision.replace(b"/Prev ", b"/Note ")  # An unlinked trailer cannot extend the previous revision.
    record("pdf-unlinked-update", "containers", [private_note], [(".pdf",first,0)])
    note = revision.replace(b"/Info 5 0 R", b"/Private /Prev /Comment (trailer) /Info 5 0 R")
    record("pdf-quoted-trailer-and-name-value", "containers", [note], [(".pdf",note,0)])
    base = first[:first.index(b"xref\n")].replace(b"%PDF-1.4", b"%PDF-1.5")
    object_offsets = [0] + [base.index(b"%d 0 obj" % i) for i in range(1,5)] + [len(base)]
    fields = b"".join(struct.pack(">BIH", int(n > 0), at, 0 if n else 65535) for n,at in enumerate(object_offsets))
    stream_xref = (base + b"5 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n" % len(fields)
                   + fields + b"\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n" % len(base))
    record("pdf-xref-stream", "containers", [stream_xref], [(".pdf",stream_xref,0)])

    palette = chunk(b"PLTE", b"\0\0\0\xff\xff\xff")
    compressed = zlib.compress(b"\0\0\x01")
    idat = chunk(b"IDAT", compressed)
    text = chunk(b"tEXt",b"K\0V")
    split_idat = [chunk(b"IDAT",compressed[:1]),chunk(b"IDAT",b""),chunk(b"IDAT",compressed[1:])]
    valid = png(3,8,[palette]+split_idat+[text])
    record("png-split-header-and-empty-idat", "photos", [b"abc",valid], [(".png",valid,3)])
    for name,data in [
        ("png-missing-palette", png(3,8,[idat])),
        ("png-bad-bit-depth", png(2,1,[idat])),
        ("png-split-idat-order", png(3,8,[palette,split_idat[0],text,split_idat[2]])),
        ("png-duplicate-palette", png(3,8,[palette,palette,idat])),
        ("png-unknown-critical", png(3,8,[palette,chunk(b"ABCD",b"x"),idat])),
        ("png-bad-zlib-header", png(3,8,[palette,chunk(b"IDAT", b"\0\0"+compressed[2:])])),
    ]:
        record(name,"photos",[data],[])
    (directory / "manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(len(create(Path(sys.argv[1]))), "media boundary layouts")
