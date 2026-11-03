"""Independent multi-MiB Pillow JPEGs and preselected physical placements.

Constant-mean 8x8 textures give diverse coefficients while the encoder can
optimize DC symbols. No recovery parser, status or map informs the writer.
"""
from pathlib import Path
import hashlib
import io
import json
import random
from PIL import Image, __version__ as PILLOW


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(image, **options):
    stream = io.BytesIO()
    image.save(stream, 'JPEG', quality=100, optimize=True, **options)
    return stream.getvalue()


def specimen(size=2560):
    rng, pixels = random.Random(61104), bytearray(size*size)
    for y in range(0, size, 8):
        for x in range(0, size, 8):
            block = [n for i in rng.sample(range(128), 32) for n in (i,255-i)]
            rng.shuffle(block)
            for row in range(8):
                pixels[(y+row)*size+x:(y+row)*size+x+8] = bytes(block[row*8:row*8+8])
    return Image.frombytes('L', (size,size), pixels)


def scatter(raw, *, alternate=None, overwritten=False, missing=False):
    cut = (len(raw)//512-2)*512
    start, tail = 1024*1024, 16384
    image = bytearray(b'\xcc'*(len(raw)+2*1024*1024))
    image[start:start+cut], image[tail:tail+len(raw)-cut] = raw[:cut],raw[cut:]
    extents = [dict(ImageOffset=start, LogicalOffset=0, Length=cut),
               dict(ImageOffset=tail, LogicalOffset=cut, Length=len(raw)-cut)]
    if alternate is not None:
        assert alternate[:cut] == raw[:cut] and alternate != raw
        image[65536:65536+len(alternate)-cut] = alternate[cut:]
    if overwritten:
        image[start+512:start+1024] = b'\xff'*512
    if missing:
        image[tail+len(raw)-cut-2:tail+len(raw)-cut] = b'\x00\x00'
    assert b''.join(image[e['ImageOffset']:e['ImageOffset']+e['Length']] for e in extents) == raw or overwritten or missing
    return bytes(image), extents


def build(destination):
    assert PILLOW == '12.3.0', 'Independent encoder is pinned, do not silently change the oracle'
    destination.mkdir(parents=True, exist_ok=False)
    image = specimen()
    raw = encode(image)
    assert len(raw) == 6803878 and sha(raw) == '0da911b938c9d7c93e7844f2e5069bffd4b86341f1aef531ba81adc85d88cb0d'
    (destination/'original.jpg').write_bytes(raw)
    with Image.open(io.BytesIO(raw)) as decoded:
        decoded.load()
        pixel_sha = sha(decoded.tobytes())
    cut = (len(raw)//512-2)*512
    alternate = None
    last = (2559,2559)
    for n in range(63):
        position = (2552+n%8,2552+n//8)
        if image.getpixel(position) == image.getpixel(last):
            continue
        changed = image.copy()
        changed.putpixel(position,image.getpixel(last))
        changed.putpixel(last,image.getpixel(position))
        other = encode(changed)
        if other != raw and other[:cut] == raw[:cut]:
            alternate = other
            break
    assert alternate is not None, 'No independent encoder alternative, do not invent bytes'
    (destination/'alternate.jpg').write_bytes(alternate)
    cases = []
    for name, options in [('exact', {}), ('late-alternative',dict(alternate=alternate)),
                          ('overwritten',dict(overwritten=True)), ('missing-eoi',dict(missing=True))]:
        data, extents = scatter(raw, **options)
        path = destination/(name+'.dd')
        path.write_bytes(data)
        cases.append(dict(Name=name,Path=path.name,SourceSha256=sha(data),Extents=extents))
    # Native large restart/progressive references are decoded independently;
    # focused recovery tests report their actual bounded support separately.
    for name, options in [('restart',dict(restart_marker_blocks=256)),
                          ('progressive',dict(progressive=True,restart_marker_blocks=512))]:
        payload = encode(image, **options)
        (destination/(name+'.jpg')).write_bytes(payload)
        with Image.open(io.BytesIO(payload)) as decoded:
            decoded.load()
        assert len(payload)>1024*1024
    manifest = dict(Pillow=PILLOW,OriginalBytes=len(raw),OriginalSha256=sha(raw),
                    PixelSha256=pixel_sha,AlternateSha256=sha(alternate),Cases=cases)
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    return manifest


if __name__ == '__main__':
    import sys
    print(json.dumps(build(Path(sys.argv[1]).resolve()), indent=2))
