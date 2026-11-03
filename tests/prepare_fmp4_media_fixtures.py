"""Extract/verify owned pinned fMP4 fixtures; never run recovery or native tools."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).absolute().parents[1]
SOURCE = ROOT / "tests/fixtures/video-fmp4"
MAX_FILE = 4 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def plain(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("FMP4_FIXTURE_LINKED_PATH")
    return path


def relative(value):
    reserved = {"con", "prn", "aux", "nul", *("com" + str(i) for i in range(1, 10)), *("lpt" + str(i) for i in range(1, 10))}
    if (not isinstance(value, str) or not value or re.search(r'[<>:"\\|?*\x00-\x1f]', value) or
            any(p in ("", ".", "..") or p.rstrip(" .") != p or p.split(".")[0].casefold() in reserved for p in value.split("/"))):
        raise ValueError("FMP4_FIXTURE_UNSAFE_PATH")
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("FMP4_FIXTURE_DUPLICATE_KEY")
        result[key] = value
    return result


def files(folder):
    result = {}
    pending = [plain(folder)]
    while pending:
        for path in pending.pop().iterdir():
            plain(path)
            if path.is_dir():
                pending.append(path)
            elif stat.S_ISREG(path.lstat().st_mode):
                result[path.relative_to(folder).as_posix()] = path
            else:
                raise ValueError("FMP4_FIXTURE_SPECIAL_FILE")
    return result


def expected():
    if plain(SOURCE / "manifest.json").stat().st_size > MAX_FILE:
        raise ValueError("FMP4_FIXTURE_MANIFEST_LIMIT")
    manifest_raw = plain(SOURCE / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8-sig"), object_pairs_hook=unique)
    if manifest.get("schema") != 1 or manifest.get("native_cases") != 1 or not isinstance(manifest.get("files"), list):
        raise ValueError("FMP4_FIXTURE_MANIFEST_SCHEMA")
    sources, payloads, folded = {"manifest.json"}, {"manifest.json": manifest_raw}, set()
    for row in manifest["files"]:
        if set(row) != {"source", "source_bytes", "source_sha256", "payload", "bytes", "sha256", "gzip"}:
            raise ValueError("FMP4_FIXTURE_MANIFEST_FIELDS")
        source, payload = relative(row["source"]), relative(row["payload"])
        if source in sources or payload in payloads or payload.casefold() in folded or type(row["gzip"]) is not bool:
            raise ValueError("FMP4_FIXTURE_DUPLICATE_PATH")
        sources.add(source)
        folded.add(payload.casefold())
        for count in (row["source_bytes"], row["bytes"]):
            if type(count) is not int or count < 1 or count > MAX_FILE:
                raise ValueError("FMP4_FIXTURE_SIZE_LIMIT")
        path = plain(SOURCE / source)
        if path.stat().st_size != row["source_bytes"]:
            raise ValueError("FMP4_FIXTURE_SOURCE_CHANGED")
        raw = path.read_bytes()
        if len(raw) != row["source_bytes"] or sha(raw) != row["source_sha256"]:
            raise ValueError("FMP4_FIXTURE_SOURCE_CHANGED")
        if row["gzip"]:
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                raw = stream.read(row["bytes"] + 1)
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
            raise ValueError("FMP4_FIXTURE_PAYLOAD_CHANGED")
        payloads[payload] = raw
    if set(files(SOURCE)) != sources:
        raise ValueError("FMP4_FIXTURE_SOURCE_FILESET_CHANGED")
    marker = {"schema": 1, "kind": "owned-native-fmp4-cache-v1", "manifest_sha256": sha(manifest_raw),
              "preparer_sha256": sha(Path(__file__).read_bytes()),
              "files": {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in sorted(payloads.items())}}
    return payloads, marker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("target", nargs="?", default=str(ROOT / ".build/fmp4-fixtures-current"))
    args = parser.parse_args()
    target = plain(args.target)
    if not target.is_relative_to(plain(ROOT / ".build")):
        raise ValueError("FMP4_FIXTURE_TARGET_OUTSIDE_OWN_BUILD")
    payloads, marker = expected()
    if args.verify:
        actual = files(target)
        if set(actual) != set(payloads) | {".prepared.json"}:
            raise ValueError("FMP4_FIXTURE_CACHE_FILESET_CHANGED")
        for name, raw in payloads.items():
            if actual[name].stat().st_size != len(raw) or actual[name].read_bytes() != raw:
                raise ValueError("FMP4_FIXTURE_CACHE_CHANGED")
        if actual[".prepared.json"].stat().st_size > MAX_FILE:
            raise ValueError("FMP4_FIXTURE_CACHE_MARKER_LIMIT")
        saved = json.loads(actual[".prepared.json"].read_text(encoding="utf-8"), object_pairs_hook=unique)
        if saved != marker:
            raise ValueError("FMP4_FIXTURE_CACHE_MARKER_CHANGED")
    else:
        target.mkdir(parents=True, exist_ok=False)
        for name, raw in payloads.items():
            path = plain(target / name)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
        with (target / ".prepared.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(marker, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"status": "verified" if args.verify else "prepared", "native_cases": 1,
                      "files": len(payloads) + 1, "manifest_sha256": marker["manifest_sha256"],
                      "preparer_sha256": marker["preparer_sha256"], "recovery_executed": False}))


if __name__ == "__main__":
    main()
