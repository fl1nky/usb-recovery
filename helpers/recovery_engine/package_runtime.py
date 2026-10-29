"""Copy runtime licenses, the exact sources and offline rebuild dependencies."""
from pathlib import Path
import hashlib
import importlib.metadata as md
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "tools/recovery-helper"
licenses = DEST / "licenses"
licenses.mkdir(exist_ok=True)
inventory = []
for dist in md.distributions():
    name, version = dist.metadata["Name"], dist.version
    if name.lower().replace("_", "-") in {"wa-crypt-tools", "whatsapp-chat-exporter", "pycryptodomex"}:
        continue
    copied = []
    for file in dist.files or []:
        token = str(file).lower()
        if ".dist-info/" not in token or not any(word in token for word in ("license", "copying", "notice", "authors")):
            continue
        source = Path(dist.locate_file(file))
        if not source.is_file():
            continue
        target = licenses / name / str(file).split(".dist-info/", 1)[-1]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(target.relative_to(DEST).as_posix())
    inventory.append({"name": name, "version": version, "licenses": copied})
python_license = Path(sys.base_prefix) / "LICENSE.txt"
if not python_license.exists():
    python_license = Path(sys.base_prefix) / "LICENSE"
if python_license.is_file():
    shutil.copyfile(python_license, licenses / "Python-LICENSE.txt")
for name in ("iphone-backup-decrypt",):
    vendor = ROOT / "vendor" / name
    for file in vendor.iterdir():
        if file.is_file() and any(word in file.name.lower() for word in ("license", "copying", "notice")):
            target = licenses / name / file.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, target)
(DEST / "dependencies.json").write_text(json.dumps({"python": sys.version.split()[0], "packages": inventory}, indent=2), encoding="utf-8")
if "--skip-rebuild-bundle" not in sys.argv:
    rebuild = DEST / "rebuild"
    source_dest = rebuild / "helpers/recovery_engine"
    shutil.copytree(ROOT / "helpers/recovery_engine", source_dest,
                    ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
    for name in ("iphone-backup-decrypt",):
        shutil.copytree(ROOT / "vendor" / name, rebuild / "vendor" / name,
                        ignore=shutil.ignore_patterns(".git", "__pycache__", "build", "*.egg-info"), dirs_exist_ok=True)
    shutil.copyfile(ROOT / "build-engine.ps1", rebuild / "build-engine.ps1")
    (rebuild / "tests").mkdir(exist_ok=True)
    for name in ("TelegramAutoTests.py", "TelegramMemoryTests.py", "ArchiveSearchTests.py", "TelegramTlTests.py", "SqliteHistoryTests.py", "build_telegram_native_fixtures.py", "TelegramMediaTests.py", "build_telegram_media_fixtures.py", "Oct30IndependentReviewTests.py"):
        shutil.copyfile(ROOT / "tests" / name, rebuild / "tests" / name)
    (rebuild / "REBUILD.txt").write_text(
        "Developer rebuild: Windows x64, Python 3.12.14.\n"
        "Run build-engine.ps1 -Python312 <absolute interpreter path>.\n"
        "No package index is used: fixed wheels, source packages and SHA256 inventory are bundled.\n"
        "Runtime use requires no Python or network installation.\n"
        "Current messenger support is Telegram only.\n", encoding="utf-8")
files = []
for file in sorted(DEST.rglob("*")):
    if file.is_file() and file.name != "runtime-SHA256.json" and "__pycache__" not in file.parts and file.suffix != ".pyc":
        h = hashlib.sha256()
        with file.open("rb") as inp:
            for block in iter(lambda: inp.read(1024 * 1024), b""):
                h.update(block)
        files.append({"path": file.relative_to(DEST).as_posix(), "size": file.stat().st_size, "sha256": h.hexdigest()})
(DEST / "runtime-SHA256.json").write_text(json.dumps(files, indent=2), encoding="utf-8")
print(f"Packaged {len(files)} runtime, source and license files.")
