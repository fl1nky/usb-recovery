"""Independent bounded Pillow JPEGs and a physical scatterer, with no recovery imports.

The manifest is a scorer input. Only the source image is passed to recovery.
RGB references prove that two different encoded originals can fit the source;
they do not select or authenticate any result produced by the recovery helper.
"""
from pathlib import Path
import hashlib
import io
import json
import random
import sys

from PIL import Image, __version__ as pillow_version


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(mode, last=None):
    rng = random.Random(71)
    image = Image.new(mode, (83, 61))
    if mode == "L":
        image.putdata([rng.randrange(256) for _ in range(83 * 61)])
    else:
        image.putdata([tuple(rng.randrange(256) for _ in range(3)) for _ in range(83 * 61)])
    if last is not None:
        old = image.getpixel((82, 60))
        image.putpixel((82, 60), last if mode == "L" else (last, old[1], old[2]))
    stream = io.BytesIO()
    image.save(stream, "JPEG", quality=85, subsampling=0)
    raw = stream.getvalue()
    with Image.open(io.BytesIO(raw)) as decoded:
        decoded.load()
        pixels = digest(decoded.convert("RGB").tobytes())
    return raw, pixels


def scatter(raw, cuts, alternate=None):
    # RGB filler uses invalid repeated entropy markers so that this positive
    # control exercises two real jumps, rather than a shorter valid hypothesis
    # that happens to decode filler. The recovery receives no filler metadata.
    image = bytearray((b"\xff" if alternate is not None else b"\xcc") * (256 * 1024))
    positions = [32 * 512, 300 * 512, 150 * 512]
    extents = []
    for at, left, right in zip(positions, cuts, cuts[1:]):
        image[at:at + right - left] = raw[left:right]
        extents.append(dict(ImageOffset=at, LogicalOffset=left, Length=right - left))
    if alternate is not None:
        at, left = 400 * 512, cuts[2]
        image[at:at + len(alternate) - left] = alternate[left:]
    assert b"".join(image[x["ImageOffset"]:x["ImageOffset"] + x["Length"]] for x in extents) == raw
    if alternate is not None:
        assert raw[:cuts[2]] + image[400 * 512:400 * 512 + len(alternate) - cuts[2]] == alternate
    return bytes(image), extents


def main(destination):
    destination.mkdir(parents=True, exist_ok=True)
    gray, gray_pixels = encode("L")
    rgb, rgb_pixels = encode("RGB")
    # Alter only the last pixel and retain two independently encoded JPEGs.
    # A fixed bounded encoder search does not invoke or inspect recovery code.
    alternatives = (encode("RGB", value) for value in range(256))
    alternate, alternate_pixels = next((raw, pixels) for raw, pixels in alternatives
                                      if raw != rgb and len(raw) == len(rgb)
                                      and raw[:1536] == rgb[:1536] and pixels != rgb_pixels)
    cases = []
    for name, raw, pixels, cuts, other, other_pixels, status, count in (
        ("gray-exact-two-gap", gray, gray_pixels, [0, 512, 1024, len(gray)], None, None,
         "jpeg_gap_structural_candidate", 1),
        ("rgb-ambiguous-two-gap", rgb, rgb_pixels, [0, 1024, 1536, len(rgb)], alternate,
         alternate_pixels, "jpeg_gap_ambiguous_candidate", 2),
    ):
        image, extents = scatter(raw, cuts, other)
        references = []
        for suffix, payload, pixel_sha in (("reference", raw, pixels), ("alternate", other, other_pixels)):
            if payload is None:
                continue
            filename = name + "-" + suffix + ".jpg"
            (destination / filename).write_bytes(payload)
            references.append(dict(Path=filename, Sha256=digest(payload), Bytes=len(payload), RgbSha256=pixel_sha))
        filename = name + ".dd"
        (destination / filename).write_bytes(image)
        cases.append(dict(Name=name, Image=filename, SourceSha256=digest(image), SourceBytes=len(image),
                          ExpectedStatus=status, ExpectedCandidates=count,
                          ExactSha256=digest(raw) if other is None else None,
                          Width=83, Height=61, References=references, ReferenceExtents=extents))
    manifest = dict(Schema=1, Generator="independent-pillow-sector-scatter-v1", Pillow=pillow_version,
                    Scope="Synthetic 256KiB regular images only. Gray exact control; RGB content ambiguity, no authenticated original or device recovery.",
                    Cases=cases)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Independent two-gap portable fixtures: 2 cases; gray exact and RGB ambiguous, no recovery imports")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
