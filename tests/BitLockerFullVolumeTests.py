"""Full external BitLocker volume vs official libbde, including the frozen helper.

No download, device, Windows mount, repair, synthetic tail or credential guessing.
Credentials arrive as one JSON object on stdin and never enter command arguments.
Missing external inputs fail explicitly; they are not a skipped acceptance pass.
See docs/guides/bitlocker-validation.md for the pinned public CTF provenance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
MANIFEST = PROJECT / "tests/fixtures/bitlocker-full-volume/GTekSD.json"
CHUNK = 1024 * 1024


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compare_all(left, right):
    """Read and compare both complete streams, including EOF; no sampled bytes."""
    compared = 0
    with Path(left).open("rb") as first, Path(right).open("rb") as second:
        while True:
            a, b = first.read(CHUNK), second.read(CHUNK)
            if a != b:
                raise AssertionError("Complete plaintext differs at or after byte " + str(compared))
            if not a:
                return compared
            compared += len(a)


def verify_wheel(wheel, manifest, module):
    if sha(wheel) != manifest["wheel_sha256"]:
        raise AssertionError("Independent oracle wheel SHA256 differs from pinned PyPI artifact")
    path = Path(module.__file__)
    with zipfile.ZipFile(wheel) as archive:
        members = [name for name in archive.namelist() if Path(name).name == path.name]
        if len(members) != 1 or hashlib.sha256(archive.read(members[0])).hexdigest() != sha(path):
            raise AssertionError("Loaded independent oracle differs from the pinned wheel")
    return {"version": module.get_version(), "module_sha256": sha(path), "wheel_sha256": sha(wheel)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True, type=Path, help="Pinned secret_data.vhdx regular file")
    parser.add_argument("--oracle-module-dir", type=Path, help="Private directory holding pybde and dissect.hypervisor")
    parser.add_argument("--oracle-wheel", required=True, type=Path, help="Pinned official libbde-python wheel")
    parser.add_argument("--helper", required=True, type=Path, help="Actual frozen recovery-helper.exe")
    parser.add_argument("--output", required=True, type=Path, help="New private output directory; must not exist")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output must be a new directory; previous evidence is preserved")
    if not args.container.is_file() or not args.helper.is_file() or not args.oracle_wheel.is_file():
        parser.error("All external inputs must already be regular files")
    # These are known CTF credentials supplied by the caller, not retrieved or guessed.
    raw_secret = sys.stdin.buffer.read(16385)
    if len(raw_secret) > 16384:
        parser.error("stdin credential object exceeds the size limit")
    try:
        secrets = json.loads(raw_secret)
    except (ValueError, UnicodeError):
        parser.error("stdin must contain a JSON credential object")
    if not isinstance(secrets, dict) or set(secrets) != {"password"} or not isinstance(secrets["password"], str) or not secrets["password"]:
        parser.error("stdin must contain exactly one nonempty password field")
    if args.oracle_module_dir:
        sys.path.insert(0, str(args.oracle_module_dir.resolve()))
    sys.path.insert(0, str(PROJECT / "helpers/recovery_engine"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    args.output.mkdir(parents=True)
    checks = []
    receipt = {"schema": 1, "fixture": manifest["id"], "status": "failed",
               "started_utc": datetime.now(timezone.utc).isoformat(),
               "test_sha256": sha(__file__), "manifest_sha256": sha(MANIFEST),
               "scope": "Full external AES-128-CBC volume, source adapter and actual frozen helper against independent libbde",
               "checks": checks, "limits": manifest["limits"], "network_blocked": False,
               "devices_or_mounts_used": False}
    immutable = {}
    started = time.monotonic()

    def require(condition, label):
        if not condition:
            raise AssertionError(label)
        checks.append(label)

    def pin(path, expected, label):
        measured = {"bytes": path.stat().st_size, "sha256": sha(path)}
        require(measured["bytes"] == expected["bytes"] and measured["sha256"] == expected["sha256"], label)
        immutable[str(path)] = measured
        return measured

    def verify_result(label, result, events, destination, source):
        require(result.get("status") == "complete" and result.get("code") == "OK" and not result.get("warnings"), label + " reports complete without truncation")
        require(result.get("image") == "decrypted.dd" and result.get("bytes") == manifest["volume"]["bytes"], label + " publishes the complete declared volume")
        output = destination / result["image"]
        report_path = destination / result["report"]
        report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        require(sha(output) == result["image_sha256"] == manifest["oracle"]["sha256"], label + " whole-output SHA256 matches independent oracle")
        compared = compare_all(output, args.output / "independent-libbde.dd")
        require(compared == manifest["volume"]["bytes"], label + " every plaintext byte and EOF match independent oracle")
        require(report["bytes"] == report["declared_logical_bytes"] == report["available_source_bytes"] == report["materialized_plaintext_bytes"] == compared, label + " measured and declared lengths agree")
        require(report["cipher"] == manifest["volume"]["cipher"] and report["bitlocker_version"] == manifest["volume"]["fve_version"] and report["valid_metadata_copies"] == manifest["volume"]["valid_metadata_copies"] and report["eow"] is False, label + " actual cipher and three valid metadata copies")
        require(report["source"]["sha256"] == sha(source) == manifest["volume"]["sha256"] and report["source"]["unchanged"] is True, label + " encrypted source is unchanged")
        require(report["authentication"]["data_sectors"] == "not_authenticated_by_bitlocker", label + " preserves data-sector integrity boundary")
        require((destination / "decrypted.dd.sha256").read_text().strip() == sha(output), label + " output sidecar matches actual complete bytes")
        require(not list(destination.rglob("*.partial")), label + " no unfinished plaintext remains")
        for phase in ("source_hash", "decrypt", "verify_source"):
            rows = [row for row in events if row.get("type") == "progress" and row.get("phase") == phase]
            require(bool(rows) and rows[-1]["completed"] == rows[-1]["total"] == manifest["volume"]["bytes"], label + " completed measured byte progress: " + phase)
            require(all(0 <= row["completed"] <= row["total"] for row in rows) and [row["completed"] for row in rows] == sorted(row["completed"] for row in rows), label + " monotonic byte progress: " + phase)
        serialized = json.dumps(result) + json.dumps(report) + json.dumps(events)
        require(all(value not in serialized for value in secrets.values()), label + " credentials absent from result, report and protocol")
        receipt[label] = {"result": result, "report_sha256": sha(report_path), "bytes_compared_exact": compared, "plaintext_sha256": sha(output)}

    try:
        from dissect.hypervisor.disk.vhdx import VHDX
        import pybde
        from storage_bitlocker import handle_bitlocker

        receipt["independent_oracle"] = verify_wheel(args.oracle_wheel, manifest["oracle"], pybde)
        require(pybde.get_version() == manifest["oracle"]["version"], "Pinned independent libbde version")
        receipt["container"] = pin(args.container.resolve(), manifest["container"], "Pinned externally authored VHDX bytes")
        disk = args.output / "materialized-disk.dd"
        with args.container.open("rb") as container:
            reader = VHDX(container)
            require(not reader.has_parent and not any(reader.header.log_guid), "VHDX has no parent or active log requiring replay")
            require(reader.size == manifest["disk"]["bytes"] and reader.sector_size == manifest["disk"]["sector_bytes"], "Complete virtual disk declared size and sector size")
            with disk.open("xb") as output:
                for offset in range(0, reader.size, CHUNK):
                    wanted = min(CHUNK, reader.size - offset)
                    block = reader.read(wanted)
                    require(len(block) == wanted, "Complete VHDX read at byte " + str(offset))
                    output.write(block)
        receipt["disk"] = pin(disk, manifest["disk"], "Entire materialized disk matches pinned bytes")
        source = args.output / "encrypted-volume.dd"
        with disk.open("rb") as raw:
            boot = raw.read(512)
            entry = boot[446:462]
            first, sectors = struct.unpack_from("<II", entry, 8)
            require(boot[510:512] == b"\x55\xaa" and entry[4] == 7 and first * 512 == manifest["disk"]["partition_offset"] and sectors * 512 == manifest["volume"]["bytes"], "Independent MBR bounds describe full BitLocker partition")
            raw.seek(first * 512)
            with source.open("xb") as output:
                left = sectors * 512
                while left:
                    block = raw.read(min(CHUNK, left))
                    require(bool(block), "Encrypted volume has no unavailable tail")
                    output.write(block)
                    left -= len(block)
        receipt["volume"] = pin(source, manifest["volume"], "All externally authored encrypted volume bytes available")
        oracle_path = args.output / "independent-libbde.dd"
        oracle = pybde.volume()
        try:
            oracle.set_password(secrets["password"])
            oracle.open(str(source))
            require(not oracle.is_locked() and oracle.size == manifest["volume"]["bytes"], "Independent libbde unlocks full declared volume")
            with oracle_path.open("xb") as output:
                left = oracle.size
                while left:
                    block = oracle.read(min(CHUNK, left))
                    require(bool(block), "Independent libbde whole-volume read")
                    output.write(block)
                    left -= len(block)
            require(oracle.read(1) == b"", "Independent libbde reaches true EOF")
        finally:
            oracle.close()
        receipt["oracle"] = pin(oracle_path, manifest["oracle"], "Full independent libbde plaintext digest")
        source_events = []
        source_destination = args.output / "source"
        request = {"source": str(source.resolve()), "destination": str(source_destination.resolve()), "secrets": secrets, "options": {}}
        result = handle_bitlocker(request, lambda kind, **fields: source_events.append({"type": kind, **fields}))
        verify_result("source", result, source_events, source_destination, source)
        wrong = "wrong-public-full-volume-test-only"
        if wrong == secrets["password"]:
            wrong += "-different"
        wrong_source_destination = args.output / "source-wrong-key"
        wrong_result = handle_bitlocker({**request, "destination": str(wrong_source_destination.resolve()), "secrets": {"password": wrong}}, lambda *args, **kwargs: None)
        require(wrong_result.get("status") == "error" and wrong_result.get("code") == "AUTH_FAILED", "Source rejects wrong key")
        require(not wrong_source_destination.exists(), "Source wrong key publishes no plaintext or output directory")
        receipt["source_wrong_key"] = wrong_result
        helper = args.helper.resolve()
        receipt["frozen_helper"] = {"path": str(helper), "sha256_before": sha(helper)}
        helper_env = dict(os.environ)
        helper_env["PATH"] = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32")
        helper_env.pop("PYTHONPATH", None)
        helper_env.pop("PYTHONHOME", None)
        receipt["helper_path_contains_python"] = "python" in helper_env["PATH"].lower()
        for label, password, expected_exit in (("frozen", secrets["password"], 0), ("frozen_wrong_key", wrong, 2)):
            destination = args.output / label
            payload = {"protocol": 1, "operation": "bitlocker", **request, "destination": str(destination.resolve()), "secrets": {"password": password}}
            child = subprocess.run([str(helper)], input=json.dumps(payload).encode("utf-8") + b"\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=helper_env, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            require(child.returncode == expected_exit, label + " actual helper native exit")
            require(password.encode() not in child.stdout + child.stderr, label + " credential absent from child streams")
            require(not child.stderr, label + " no dependency diagnostics escaped")
            events = [json.loads(line) for line in child.stdout.decode("utf-8-sig").splitlines() if line.strip()]
            require(all(row.get("protocol") == 1 for row in events), label + " valid protocol stream")
            results = [row for row in events if row.get("type") == "result"]
            require(len(results) == 1, label + " exactly one terminal result")
            (args.output / (label + "-stdout.ndjson")).write_bytes(child.stdout)
            if expected_exit == 0:
                verify_result(label, results[0], events, destination, source)
            else:
                require(results[0].get("status") == "error" and results[0].get("code") == "AUTH_FAILED", "Frozen helper rejects wrong key")
                require(not destination.exists(), "Frozen helper wrong key publishes no plaintext or output directory")
                receipt[label] = {"result": results[0], "native_exit": child.returncode}
        receipt["frozen_helper"]["sha256_after"] = sha(helper)
        require(receipt["frozen_helper"]["sha256_before"] == receipt["frozen_helper"]["sha256_after"], "Actual frozen helper bytes unchanged")
        receipt["source_modules"] = {name: sha(PROJECT / "helpers/recovery_engine" / name) for name in ("storage_bitlocker.py", "resumable_copy.py", "recovery_io.py")}
        receipt["status"] = "passed"
    except Exception as exc:
        # Exception text from parsers may contain credentials; retain only a
        # controlled assertion label or the class name, never an arbitrary message.
        receipt["failure"] = str(exc) if isinstance(exc, AssertionError) else type(exc).__name__
    finally:
        unchanged = {}
        for path, expected in immutable.items():
            try:
                unchanged[path] = Path(path).stat().st_size == expected["bytes"] and sha(path) == expected["sha256"]
            except OSError:
                unchanged[path] = False
        receipt["immutable_inputs"] = unchanged
        if not all(unchanged.values()):
            receipt["status"] = "failed"
            receipt["failure"] = "Input bytes changed"
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
        serialized = json.dumps(receipt, ensure_ascii=False, indent=2)
        if any(value in serialized for value in secrets.values()):
            serialized = json.dumps({"status": "failed", "failure": "Receipt rejected because a credential appeared"})
            receipt["status"] = "failed"
        (args.output / "receipt.json").write_text(serialized + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "receipt": str((args.output / "receipt.json").resolve()), "bytes_compared_per_successful_implementation": manifest["volume"]["bytes"] if receipt["status"] == "passed" else 0}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
