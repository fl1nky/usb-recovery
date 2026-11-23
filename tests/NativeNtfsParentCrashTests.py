# SPDX-License-Identifier: AGPL-3.0-or-later
"""Terminate an owned product-host process, observe native child death, resume.

Uses the packaged product assembly and worker without modifying their bytes.
No screen, physical device, unowned process, credentials or network is used.
"""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET

ROOT = Path(__file__).absolute().parents[1]


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def native_child_handles(parent):
    class Entry(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
                    ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                    ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
                    ("name", wintypes.WCHAR * 260)]
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    api.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    api.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = api.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "Owned child snapshot failed")
    result = []
    try:
        entry = Entry()
        entry.size = ctypes.sizeof(entry)
        valid = api.Process32FirstW(snapshot, ctypes.byref(entry))
        while valid:
            if entry.parent == parent and entry.name.lower() == "ntfs_worker.exe":
                handle = api.OpenProcess(0x100000, False, entry.pid)  # SYNCHRONIZE only
                if not handle:
                    raise OSError(ctypes.get_last_error(), "Owned child wait handle failed")
                result.append((entry.pid, handle))
            valid = api.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        api.CloseHandle(snapshot)
    return api, result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    package, image, expected = args.package.resolve(), args.image.resolve(), args.expected.resolve()
    evidence = args.evidence.resolve()
    if evidence.exists():
        raise ValueError("Fresh parent-crash evidence required")
    runtime = evidence / "runtime"
    runtime.mkdir(parents=True)
    for name in ("USB-Recovery.exe", "USB-Recovery.exe.config"):
        shutil.copyfile(package / name, runtime / name)
    shutil.copytree(package / "tools/native-recovery", runtime / "tools/native-recovery")
    inputs = {str(path): sha(path) for path in (package / "USB-Recovery.exe", package / "tools/native-recovery/ntfs_worker.exe", image, expected)}
    manifest = ET.parse(ROOT / "src/Recovery/app.manifest")
    for element in manifest.iter():
        if element.tag.endswith("requestedExecutionLevel"):
            element.set("level", "asInvoker")
    manifest_path = evidence / "as-invoker.manifest"
    manifest.write(manifest_path, encoding="utf-8", xml_declaration=True)
    driver = runtime / "NativeNtfsParentCrashDriver.exe"
    compiler = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    command = [str(compiler), "/nologo", "/target:exe", "/platform:x64", "/optimize+", "/warnaserror+", "/codepage:65001",
               "/win32manifest:" + str(manifest_path), "/reference:" + str(runtime / "USB-Recovery.exe"), "/out:" + str(driver),
               str(ROOT / "tests/NativeNtfsParentCrashDriver.cs"), str(ROOT / "tests/FrameworkTarget.cs")]
    with (evidence / "compile.log").open("wb") as output:
        subprocess.run(command, check=True, stdout=output, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
    shutil.copyfile(runtime / "USB-Recovery.exe.config", driver.with_name(driver.name + ".config"))
    environment = os.environ.copy()
    environment["PATH"] = str(Path(os.environ["WINDIR"]) / "System32")
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["__COMPAT_LAYER"] = "RunAsInvoker"
    result = evidence / "result"
    events = queue.Queue()
    with (evidence / "start-stderr.log").open("wb") as errors:
        child = subprocess.Popen([str(driver), "start", str(image), str(result)], cwd=runtime, env=environment,
                                 stdout=subprocess.PIPE, stderr=errors, creationflags=subprocess.CREATE_NO_WINDOW)
        def read_events():
            try:
                for line in iter(child.stdout.readline, b""):
                    events.put(line)
            finally:
                events.put(None)
        reader = threading.Thread(target=read_events, daemon=True)
        reader.start()
        handles = []
        try:
            line = events.get(timeout=120)
            if line is None or b"PARENT_CRASH_POINT_AFTER_DURABLE_MIB" not in line:
                raise ValueError("Product did not reach the acknowledged copy crash point")
            api, handles = native_child_handles(child.pid)
            if len(handles) != 1:
                raise ValueError("Expected exactly one owned native child awaiting parent acknowledgement")
            child.kill()
            child.wait(timeout=10)
            api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            if any(api.WaitForSingleObject(handle, 10000) != 0 for _, handle in handles):
                raise ValueError("Owned native child survived abrupt parent termination")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            for _, handle in handles:
                api.CloseHandle(handle)
            child.stdout.close()
            reader.join(timeout=5)
    session = json.loads((result / "recovery-session.json").read_text(encoding="utf-8-sig"))
    stage = next(row for row in session["Stages"] if row["Key"] == "ntfs")
    partials = list((result / "ntfs.state").rglob("*.partial"))
    if stage["Status"] != "running" or stage["CheckpointSequence"] < 1 or len(partials) != 1 or partials[0].stat().st_size != 1024**2:
        raise ValueError("Abrupt parent termination lost its durable 1-MiB checkpoint")
    with (evidence / "resume.log").open("wb") as output:
        subprocess.run([str(driver), "resume", str(image), str(result)], cwd=runtime, env=environment,
                       stdout=output, stderr=subprocess.STDOUT, check=True, timeout=180, creationflags=subprocess.CREATE_NO_WINDOW)
    catalog = json.loads((result / "files-index.json").read_text(encoding="utf-8-sig"))
    if len(catalog["Items"]) != 1 or sha(result / catalog["Items"][0]["Path"]) != inputs[str(expected)] or (result / "attempt-history").exists():
        raise ValueError("Post-crash resume did not preserve the same attempt and exact output")
    for path, digest in inputs.items():
        if sha(Path(path)) != digest:
            raise ValueError("Bound package or source changed during parent-crash test")
    receipt = dict(status="passed", scope="Actual packaged product assembly; abrupt owned host termination after durable MiB, native child exits, session resumes",
                   child_pids=[pid for pid, _ in handles], checkpoint_bytes=1024**2, output_sha256=inputs[str(expected)], inputs=inputs,
                   native_children_terminated=True, same_attempt=True, child_python_on_path=False, real_devices_tested=False, gui_tests_run=False,
                   network_isolated=False, full_portable_acceptance=False)
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
