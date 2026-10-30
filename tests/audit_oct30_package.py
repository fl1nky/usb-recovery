"""Read-only integrity/source audit of the prepared Windows recovery bundle.

PyInstaller code is read from the archive, never executed. Only source filename
metadata is normalized before recursively comparing Python code objects.
"""
from collections import Counter
import datetime as dt
import hashlib
import json
import marshal
from pathlib import Path
import shutil
import types
import xml.etree.ElementTree as ET

from PyInstaller.archive.readers import CArchiveReader
from verify_upgrade_package import repository_runtime, verify_sources

ROOT = Path(__file__).resolve().parents[1]
READY = ROOT / "dist/USB-Recovery"


def require(value, explanation):
    if not value:
        raise ValueError(explanation)


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def safe(base, relative):
    require(isinstance(relative, str) and relative and "\\" not in relative and ":" not in relative,
            "unsafe inventory name")
    result = base / relative
    require(result.resolve().is_relative_to(base.resolve()) and not result.is_symlink(), "inventory escapes bundle")
    return result


def normalize(code):
    require(isinstance(code, types.CodeType), "compiled module expected")
    constants = tuple(normalize(value) if isinstance(value, types.CodeType) else value for value in code.co_consts)
    return code.replace(co_filename="<normalized-source-filename>", co_consts=constants)


def audit():
    manifest = read(READY / "package-sha256.json")
    require(isinstance(manifest, list) and bool(manifest), "missing runtime inventory")
    names = set()
    for row in manifest:
        require(row["path"] not in names, "duplicate runtime inventory entry")
        names.add(row["path"])
        delivered = safe(READY, row["path"])
        require(delivered.stat().st_size == row["bytes"] and sha(delivered) == row["sha256"],
                "runtime mismatch: " + row["path"])
        require(sha(repository_runtime(ROOT, row["path"])) == row["sha256"], "build/runtime differs: " + row["path"])
    actual = {path.relative_to(READY).as_posix() for path in READY.rglob("*")
              if path.is_file() and path.suffix.lower() in (".exe", ".dll", ".pyd")}
    require(actual == names, "unexpected runtime binary or temporary harness remains: " + str(sorted(actual ^ names)))

    sources = verify_sources(ROOT, READY)
    csharp = sources["cs_sources"]
    build = (ROOT / "scripts/build-app.ps1").read_text(encoding="utf-8-sig")
    require("Get-ChildItem" in build and "-Recurse" in build and "-Filter '*.cs'" in build and
            "$taskLayout.Source" in build, "application build must include recursive source tree")
    project = ET.parse(ROOT / "src/Recovery/Recovery.csproj").getroot()
    ns = {"msbuild": "http://schemas.microsoft.com/developer/msbuild/2003"}
    compile_items = project.findall("msbuild:ItemGroup/msbuild:Compile", ns)
    require(any(item.get("Include", "").replace("\\", "/") == "**/*.cs" for item in compile_items),
            "project must include recursive C# source tree")
    ET.parse(ROOT / "src/Recovery/app.manifest")

    helper = READY / "tools/recovery-helper"
    helper_manifest = read(helper / "runtime-SHA256.json")
    require(isinstance(helper_manifest, list) and bool(helper_manifest), "missing helper inventory")
    helper_names = set()
    for row in helper_manifest:
        require(row["path"] not in helper_names, "duplicate helper inventory entry")
        helper_names.add(row["path"])
        delivered = safe(helper, row["path"])
        require(delivered.stat().st_size == row["size"] and sha(delivered) == row["sha256"],
                "helper file mismatch: " + row["path"])
    actual_helper = {path.relative_to(helper).as_posix() for path in helper.rglob("*") if path.is_file()}
    require(actual_helper == helper_names | {"runtime-SHA256.json"}, "unlisted helper files")
    require(not any("signal" in name.lower() or "wa_crypt" in name.lower() or "whatsapp_chat" in name.lower()
                    for name in actual if name.endswith((".exe", ".dll", ".pyd"))), "removed messenger runtime returned")

    source_results = []
    for source in sorted((ROOT / "helpers/recovery_engine").glob("*")):
        if not source.is_file() or source.suffix.lower() not in (".py", ".json", ".txt"):
            continue
        delivered = helper / "rebuild/helpers/recovery_engine" / source.name
        require(sha(source) == sha(READY / "source/helpers/recovery_engine" / source.name) == sha(delivered),
                "Python/config source mismatch: " + source.name)
        source_results.append({"path": source.relative_to(ROOT).as_posix(), "sha256": sha(source), "matched": True})
    require(bool(source_results), "empty Python/config source set")

    archive = CArchiveReader(str(helper / "recovery-helper.exe"))
    pyz = archive.open_embedded_archive("PYZ.pyz")
    embedded = []
    for name in ("engine", "telegram_auto", "telegram_tl", "sqlite_history", "archive_search", "text_match", "memory_fragments", "storage_probe", "storage_apfs", "storage_bitlocker", "sqlite_deleted", "fragmented_photos", "jpeg_fragments"):
        code = marshal.loads(archive.extract(name)) if name == "engine" else pyz.extract(name)
        source = ROOT / "helpers/recovery_engine" / (name + ".py")
        reference = compile(source.read_bytes(), str(source), "exec", optimize=0)
        require(normalize(code) == normalize(reference), "frozen code differs from source: " + name)
        embedded.append({"module": name, "source_sha256": sha(source), "matched": True,
                         "comparison": "recursive code objects; only co_filename normalized"})

    rebuild_tests = []
    required_tests = ("TelegramAutoTests.py", "TelegramMemoryTests.py", "ArchiveSearchTests.py", "TelegramTlTests.py",
                      "SqliteHistoryTests.py", "build_telegram_native_fixtures.py", "TelegramMediaTests.py",
                      "build_telegram_media_fixtures.py", "Oct30IndependentReviewTests.py", "ApfsRecoveryTests.py", "BitLockerRecoveryTests.py", "StorageProbeTests.py", 'TelegramDeletedTests.py', 'TelegramResidualProvenanceTests.py', 'DeletedArchiveSearchTests.py', 'FragmentedPhotoTests.py', 'JpegFragmentRecoveryTests.py','FragmentedPhotoAuditTests.py','PngContextAuditTests.py')
    for name in required_tests:
        require(sha(ROOT / "tests" / name) == sha(helper / "rebuild/tests" / name), "rebuild test missing or stale: " + name)
        rebuild_tests.append({"path": name, "sha256": sha(ROOT / "tests" / name), "matched": True})
    for name in ("build-helper.ps1", "ProjectPaths.ps1"):
        require(sha(ROOT / "scripts" / name) == sha(helper / "rebuild/scripts" / name),
                "rebuild runner mismatch: " + name)
    for fixture in ("TelegramNativeFixtures", "TelegramMediaFixtures"):
        require(sha(ROOT / "tests" / fixture / "manifest.json") == sha(READY / "source/tests" / fixture / "manifest.json"),
                "synthetic fixture manifest mismatch")
        for row in read(ROOT / "tests" / fixture / "manifest.json")["files"]:
            require(sha(safe(READY / "source/tests" / fixture, row["path"])) == row["sha256"], "synthetic fixture bytes mismatch")

    return {"status": "passed", "checked_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "scope": "Read-only artifact/archive/source audit; no personal profiles, source media or devices accessed",
            "application_sha256": sha(READY / "USB-Recovery.exe"),
            "helper_sha256": sha(helper / "recovery-helper.exe"),
            "runtime_files_verified": len(manifest),
            "runtime_extension_counts": dict(Counter(Path(name).suffix.lower() for name in actual)),
            "helper_inventory_files_verified": len(helper_manifest),
            "helper_unlisted_files": [], "temporary_harnesses_remaining": [],
            "cs_sources_verified": len(csharp), "cs_sources": csharp,
            "packaged_sources_verified": sources["sources_verified"],
            "runtime_documents_verified": sources["runtime_documents_verified"],
            "application_metadata": sources["application_metadata"],
            "python_config_sources_verified": len(source_results), "python_config_sources": source_results,
            "frozen_modules": embedded, "rebuild_tests": rebuild_tests,
            "runtime_manifest_sha256": sha(READY / "package-sha256.json"),
            "helper_manifest_sha256": sha(helper / "runtime-SHA256.json"),
            "real_usb": False, "real_android": False, "real_iphone": False}


if __name__ == "__main__":
    result = audit()
    target = ROOT / "tests/October30-package-audit.json"
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    shutil.copyfile(target, READY / "source/tests" / target.name)
    print(f"PASS independent package audit: {result['runtime_files_verified']} runtime files, "
          f"{result['helper_inventory_files_verified']} helper files, {result['cs_sources_verified']} C# sources, "
          f"{len(result['frozen_modules'])} frozen Python modules exactly match source")
