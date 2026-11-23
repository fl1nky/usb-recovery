# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the compiled native protocol over actual owned process pipes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

HEADER = struct.Struct('<4sBBHQII')
checks = 0


def check(value, message):
    global checks
    checks += 1
    if not value:
        raise AssertionError(message)


def packet(kind, sequence, body=b'', *, version=1, flags=0, reserved=0, magic=b'URC1', size=None):
    return HEADER.pack(magic, version, kind, flags, sequence, len(body) if size is None else size, reserved) + body


def exact(stream, count):
    parts = []
    while count:
        data = stream.read(count)
        if not data:
            raise AssertionError('native worker ended inside its outgoing frame')
        parts.append(data); count -= len(data)
    return b''.join(parts)


def outgoing(child):
    magic, version, kind, flags, sequence, count, reserved = HEADER.unpack(exact(child.stdout, HEADER.size))
    check(magic == b'URC1' and version == 1 and flags == reserved == 0, 'canonical native header')
    check(count <= 1024**2 and sequence > 0, 'bounded native payload and positive sequence')
    return kind, sequence, exact(child.stdout, count)


def worker(exe, *args):
    return subprocess.Popen([str(exe), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)


def close(child):
    if child.poll() is None:
        child.kill()
    child.wait(timeout=10)
    for stream in (child.stdin, child.stdout, child.stderr):
        if stream is not None:
            stream.close()


def initial(child):
    kind, sequence, body = outgoing(child)
    check(kind == 2 and sequence == 1 and body == struct.pack('<QI', 512, 4),
          'actual native source-read request carries exact offset and count')


def roundtrip(exe, fragmented, prefix=b''):
    child = worker(exe)
    try:
        initial(child)
        payload = b'\x00\r\n\xff'
        response = prefix + packet(3, 1, payload)
        if fragmented:
            for byte in response:
                child.stdin.write(bytes([byte])); child.stdin.flush()
        else:
            child.stdin.write(response); child.stdin.flush()
        kind, sequence, body = outgoing(child)
        check((kind, sequence, body) == (11, 2, payload), 'binary bytes survive native pipes without newline or encoding conversion')
        check(child.poll() is None, 'native child waits for explicit checkpoint acknowledgement')
        child.stdin.write(packet(7, 2)); child.stdin.flush()
        check(outgoing(child) == (8, 3, b''), 'native completion follows acknowledged snapshot')
        check(child.poll() is None, 'completion still waits for parent acknowledgement')
        child.stdin.write(packet(7, 3)); child.stdin.flush()
        check(child.wait(timeout=10) == 0 and child.stdout.read() == b'', 'fully acknowledged transaction exits successfully without stray protocol bytes')
    finally:
        close(child)


def invalid_reply(exe, label, response, expected):
    child = worker(exe)
    try:
        initial(child)
        child.stdin.write(response); child.stdin.flush(); child.stdin.close(); child.stdin = None
        check(child.wait(timeout=10) == expected, label + ': deterministic native failure code')
        check(child.stdout.read() == b'', label + ': no snapshot, completion or success after bad input')
    finally:
        close(child)


def aborted_ack(exe, step):
    child = worker(exe)
    try:
        initial(child)
        child.stdin.write(packet(3, 1, b'abcd')); child.stdin.flush()
        check(outgoing(child) == (11, 2, b'abcd'), 'native snapshot emitted before acknowledgement test')
        if step == 'done':
            child.stdin.write(packet(7, 2)); child.stdin.flush()
            check(outgoing(child) == (8, 3, b''), 'native completion emitted before missing final acknowledgement')
        child.stdin.close(); child.stdin = None
        check(child.wait(timeout=10) == 3 and child.stdout.read() == b'', 'parent EOF never counts as checkpoint acknowledgement at ' + step)
    finally:
        close(child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    exe = args.worker.absolute()
    before = hashlib.sha256(exe.read_bytes()).hexdigest()
    roundtrip(exe, False); roundtrip(exe, True); roundtrip(exe, True, b'\xef\xbb\xbf')
    failures = [
        ('magic', packet(3, 1, b'abcd', magic=b'BAD!'), 4),
        ('duplicate connection preamble', b'\xef\xbb\xbf' * 2 + packet(3, 1, b'abcd'), 4),
        ('version', packet(3, 1, b'abcd', version=2), 4),
        ('unknown kind', packet(255, 1, b'abcd'), 4),
        ('wrong reply kind', packet(7, 1), 4),
        ('flags', packet(3, 1, b'abcd', flags=1), 4),
        ('reserved', packet(3, 1, b'abcd', reserved=1), 4),
        ('stale sequence', packet(3, 0, b'abcd'), 6),
        ('future sequence', packet(3, 2, b'abcd'), 6),
        ('reply capacity', packet(3, 1, b'abcde'), 5),
        ('maximum payload', packet(3, 1, size=1024**2 + 1), 5),
        ('uint32 maximum', packet(3, 1, size=2**32 - 1), 5),
        ('header EOF', b'URC1', 3),
        ('body EOF', packet(3, 1, b'ab', size=4), 3),
        ('cancel', packet(10, 1), 7),
        ('malformed cancel', packet(10, 1, b'a'), 4),
        ('short semantic body', packet(3, 1, b'a'), 91),
    ]
    for label, response, expected in failures:
        invalid_reply(exe, label, response, expected)
    for step in ('snapshot', 'done'):
        aborted_ack(exe, step)
    for option, expected in (('--overflow', 6), ('--too-large', 5)):
        with worker(exe, option) as child:
            out, _ = child.communicate(timeout=10)
            check(child.returncode == expected and out == b'', 'native producer rejects ' + option + ' before emitting any frame')
    check(hashlib.sha256(exe.read_bytes()).hexdigest() == before, 'actual tested executable remains unchanged')
    result = dict(status='passed', checks=checks, worker_sha256=before,
                  scope='Compiled C framing over actual local process pipes; not recovery or controller acceptance',
                  real_devices_tested=False, gui_used=False)
    if args.receipt:
        args.receipt.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f'PASS NativeRecoveryProtocol: {checks} checks; actual native pipes, binary data, '
          'bounded framing, malformed inputs, sequence/EOF/cancel and explicit acknowledgements; not filesystem recovery')


if __name__ == '__main__':
    main()
