"""Offline PhotoRec integration test. Uses only synthetic regular-file images.

Run: python tests/verify_photorec.py
Requires Pillow. Never opens or enumerates physical disks.
"""
from __future__ import annotations

import hashlib
import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import io
import json
import os
from pathlib import Path
import subprocess
import shlex
import sys
from datetime import datetime, timezone

from PIL import Image


@contextmanager
def source_read_lock(source: Path, enabled: bool):
    """Match FileAccess.Read/FileShare.Read, and confirm writers are refused."""
    if not enabled:
        yield {"enabled": False}
        return
    if os.name != "nt":
        raise RuntimeError("Windows CreateFileW lock test requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    handle = kernel32.CreateFileW(str(source), 0x80000000, 1, None, 3, 0x80, None)
    if handle == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # Request write permission only; do not write any bytes even on failure.
        writer = kernel32.CreateFileW(str(source), 0x40000000, 3, None, 3, 0x80, None)
        error = ctypes.get_last_error()
        if writer != invalid:
            kernel32.CloseHandle(writer)
            raise AssertionError("Read/share-read lock unexpectedly permits a writer")
        if error != 32:
            raise AssertionError(f"Expected sharing violation 32, got {error}")
        yield {"enabled": True, "api": "CreateFileW",
               "access": "GENERIC_READ", "share": "FILE_SHARE_READ",
               "writer_open_refused": True, "writer_win32_error": error}
    finally:
        kernel32.CloseHandle(handle)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_bytes(fmt: str) -> bytes:
    image = Image.new("RGB", (96, 64))
    image.putdata([
        ((x * 3 + y * 5) % 256, (x * 7 + y * 11) % 256,
         (x * 13 + y * 17) % 256)
        for y in range(64) for x in range(96)
    ])
    stream = io.BytesIO()
    options = {"quality": 92, "subsampling": 0} if fmt == "JPEG" else {}
    image.save(stream, format=fmt, **options)
    return stream.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unicode-path", action="store_true")
    parser.add_argument("--read-lock", action="store_true")
    parser.add_argument("--posix-quoting", action="store_true")
    parser.add_argument("--no-glob", action="store_true")
    args = parser.parse_args()
    tests_root = Path(__file__).resolve().parent
    app_root = tests_root.parent
    executable = app_root / "tools" / "testdisk-7.2" / "photorec_win.exe"
    if not executable.is_file():
        raise FileNotFoundError(executable)

    run_name = datetime.now(timezone.utc).strftime("photorec-%Y%m%dT%H%M%S%fZ")
    if args.unicode_path:
        run_name = "Проверка фото и путей " + run_name
    run_dir = tests_root / run_name
    run_dir.mkdir(parents=True, exist_ok=False)
    fixtures_dir = run_dir / "fixtures"
    fixtures_dir.mkdir()
    offsets = {"expected.jpg": 128 * 1024, "expected.png": 512 * 1024}
    fixture_hashes: dict[str, str] = {}
    image_data = bytearray(8 * 1024 * 1024)
    for name, fmt in (("expected.jpg", "JPEG"), ("expected.png", "PNG")):
        content = fixture_bytes(fmt)
        offset = offsets[name]
        assert offset % 512 == 0
        image_data[offset:offset + len(content)] = content
        fixture_path = fixtures_dir / name
        fixture_path.write_bytes(content)
        with Image.open(fixture_path) as fixture:
            fixture.verify()
        fixture_hashes[name] = sha256(fixture_path)

    source = run_dir / ("Образ флешки с фото.dd" if args.unicode_path else "synthetic-usb.dd")
    source.write_bytes(image_data)
    assert source.is_file() and source.parent == run_dir
    source_before = sha256(source)
    output_prefix = run_dir / ("Восстановленные фото" if args.unicode_path else "recovered")
    log = run_dir / ("Журнал PhotoRec.log" if args.unicode_path else "photorec.log")
    command = [
        str(executable), "/log", "/logname", str(log),
        "/d", str(output_prefix), "/cmd", str(source),
        "partition_none,fileopt,everything,enable,wholespace,search",
    ]
    env = os.environ.copy()
    env["__COMPAT_LAYER"] = "RunAsInvoker"
    env["LANG"] = "C.UTF-8"
    env["LC_ALL"] = "C.UTF-8"
    if args.no_glob:
        env["CYGWIN"] = "noglob"
    child_command = (" ".join(shlex.quote(argument.replace("\\", "/"))
                              for argument in command)
                     if args.posix_quoting else command)
    timed_out = False
    with source_read_lock(source, args.read_lock) as lock_result:
        process = subprocess.Popen(
            child_command, executable=str(executable), cwd=run_dir, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
    (run_dir / "stdout.bin").write_bytes(stdout)
    (run_dir / "stderr.bin").write_bytes(stderr)

    recovered: list[dict[str, object]] = []
    for output_dir in sorted(run_dir.glob(output_prefix.name + ".*")):
        if not output_dir.is_dir():
            continue
        for path in sorted(output_dir.rglob("*")):
            if not path.is_file():
                continue
            digest = sha256(path)
            matched = [name for name, value in fixture_hashes.items() if digest == value]
            image_verified = False
            if path.suffix.lower() in (".jpg", ".jpeg", ".png"):
                try:
                    with Image.open(path) as image:
                        image.verify()
                    image_verified = True
                except Exception:
                    pass
            recovered.append({
                "path": str(path.relative_to(run_dir)), "size_bytes": path.stat().st_size,
                "sha256": digest, "matches_fixtures": matched,
                "image_verified": image_verified,
            })
    source_after = sha256(source)
    matched_names = {name for item in recovered for name in item["matches_fixtures"]}
    passed = (not timed_out and process.returncode == 0
              and source_before == source_after
              and set(fixture_hashes) <= matched_names)
    result = {
        "passed": passed, "scope": "synthetic regular files only; no physical disk access",
        "command": command, "cwd": str(run_dir),
        "posix_quoting": args.posix_quoting,
        "cygwin_noglob": args.no_glob,
        "windows_command_line": (child_command if isinstance(child_command, str)
                                 else subprocess.list2cmdline(child_command)),
        "unicode_path": args.unicode_path, "source_read_lock": lock_result,
        "child_environment_override": {
            key: env[key] for key in ("__COMPAT_LAYER", "LANG", "LC_ALL", "CYGWIN")
            if key in env
        },
        "timeout_seconds": 30, "timed_out": timed_out, "exit_code": process.returncode,
        "source": {"path": str(source), "size_bytes": source.stat().st_size,
                   "sha256_before": source_before, "sha256_after": source_after,
                   "unchanged": source_before == source_after},
        "fixture_sha256": fixture_hashes, "fixture_offsets_bytes": offsets,
        "recovered": recovered,
        "stdout_size_bytes": len(stdout), "stderr_size_bytes": len(stderr),
        "stdout_text": stdout.decode("utf-8", errors="replace"),
        "stderr_text": stderr.decode("utf-8", errors="replace"),
        "log_exists": log.is_file(),
        "session_file_exists": (run_dir / "photorec.ses").is_file(),
        "interaction": "stdin closed; no supplied responses or confirmations",
    }
    result_path = run_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    variant = ("-unicode" if args.unicode_path else "") + ("-lock" if args.read_lock else "")
    variant += "-posix" if args.posix_quoting else ""
    variant += "-noglob" if args.no_glob else ""
    summary_name = "photorec" + (variant or "-integration") + "-result.json"
    (tests_root / summary_name).write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps({"passed": passed, "result": str(result_path),
                      "exit_code": process.returncode, "timed_out": timed_out,
                      "matched_fixtures": sorted(matched_names),
                      "source_unchanged": source_before == source_after,
                      "source_read_lock": lock_result,
                      "session_file_exists": (run_dir / "photorec.ses").is_file(),
                      "stdout_size_bytes": len(stdout), "stderr_size_bytes": len(stderr)},
                     indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
