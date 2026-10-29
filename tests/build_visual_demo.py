"""Package real-window demo frames as a small, reproducible README animation."""

import argparse
import json
from pathlib import Path

from PIL import Image


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "docs/images/recovery-demo.gif")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
    records = manifest["frames"]
    if not records or manifest["caption"] != "Пример на тестовых данных":
        raise ValueError("Expected labelled real-window test-data frames")
    size = (manifest["width"], manifest["height"])
    palette_source = Image.new("RGB", (size[0], size[1] * 3))
    for position, index in enumerate((0, len(records) // 3, len(records) - 1)):
        with Image.open(records[index]["path"]) as image:
            if image.size != size:
                raise ValueError("Inconsistent frame dimensions")
            palette_source.paste(image.convert("RGB"), (0, position * size[1]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for colors in (256, 160, 96):
        palette = palette_source.quantize(colors=colors, method=Image.Quantize.MEDIANCUT)
        images = []
        try:
            for record in records:
                with Image.open(record["path"]) as source:
                    if source.size != size:
                        raise ValueError("Inconsistent frame dimensions")
                    images.append(source.convert("RGB").quantize(palette=palette, dither=Image.Dither.NONE))
            images[0].save(args.output, save_all=True, append_images=images[1:], duration=[max(40, record["duration"]) for record in records], loop=0, optimize=True, disposal=1, comment="Пример на тестовых данных. Реальный поиск по созданному образу, без устройств и профилей.".encode("utf-8"))
        finally:
            for image in images:
                image.close()
            palette.close()
        if args.output.stat().st_size <= 5_000_000:
            break
    else:
        raise ValueError("GIF exceeds the 5 MB delivery limit")
    with Image.open(args.output) as result:
        total_duration = 0
        for index in range(result.n_frames):
            result.seek(index)
            total_duration += result.info.get("duration", 0)
        evidence = {"bytes": args.output.stat().st_size, "width": result.width, "height": result.height, "frames": result.n_frames, "duration_ms": total_duration, "caption": manifest["caption"], "progress": "captured from real RecoveryPipeline observations; no invented percentages"}
    args.manifest.with_name("gif-evidence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(evidence, ensure_ascii=False))


if __name__ == "__main__":
    main()
