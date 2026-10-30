"""Owned, real HotSpot HPROF; this generator imports no recovery implementation.

A developer JDK is needed only to generate the fixture, never to run Recovery.
No application, account, device or foreign process is accessed.
"""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys


TLRPC = '''package org.telegram.tgnet;
public class TLRPC {
 public static class Peer { public long user_id, chat_id, channel_id; }
 public static class TL_peerUser extends Peer { }
 public static class Message { public int id, date; public String message; public Peer peer_id, from_id; public long dialog_id; }
 public static class TL_message extends Message { }
 public static class Other { public String message; public int id,date; }
}'''
JAVA = r'''import org.telegram.tgnet.TLRPC;
import java.lang.management.ManagementFactory;
import com.sun.management.HotSpotDiagnosticMXBean;
public class HeapFixture {
 static Object[] keep;
 public static void main(String[] args) throws Exception {
  TLRPC.TL_message a=new TLRPC.TL_message();a.id=31;a.date=1700000000;a.message="recipe first line\nsecond line";
  a.peer_id=new TLRPC.TL_peerUser();a.peer_id.user_id=71;a.from_id=new TLRPC.TL_peerUser();a.from_id.user_id=72;
  TLRPC.TL_message b=new TLRPC.TL_message();b.id=32;b.date=1700000001;b.message="\u0440\u0435\u0446\u0435\u043f\u0442 \ud83e\udd67";b.peer_id=a.peer_id;b.from_id=a.from_id;
  TLRPC.Other other=new TLRPC.Other();other.id=99;other.date=a.date;other.message="PRIVATE_CANARY_UNRELATED_CLASS";
  keep=new Object[]{a,b,other};ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class).dumpHeap(args[0],true);
 }
}'''


def sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def build(directory, java=None, javac=None):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / 'source'
    package = source / 'org/telegram/tgnet'
    package.mkdir(parents=True, exist_ok=True)
    (package / 'TLRPC.java').write_text(TLRPC, encoding='utf-8')
    (source / 'HeapFixture.java').write_text(JAVA, encoding='utf-8')
    java, javac = java or shutil.which('java'), javac or shutil.which('javac')
    if not java or not javac:
        raise RuntimeError('A developer JDK is required for fixture generation only')
    target = directory / 'own-jvm.hprof'
    if target.exists():
        raise FileExistsError('Keep existing fixture; select a new directory')
    subprocess.run([javac, '-encoding', 'UTF-8', '-d', str(source), str(package / 'TLRPC.java'),
                    str(source / 'HeapFixture.java')], check=True, timeout=60, capture_output=True)
    subprocess.run([java, '-Xms32m', '-Xmx64m', '-XX:+UseSerialGC', '-cp', str(source),
                    'HeapFixture', str(target)], check=True, timeout=60, capture_output=True)
    version = subprocess.run([java, '-version'], check=True, capture_output=True, timeout=20)
    manifest = dict(schema=1, scope='Owned JVM and synthetic Telegram-shaped classes; not Android hardware or the Telegram application',
        path=target.name, sha256=sha(target), java_sha256=sha(java), javac_sha256=sha(javac),
        java_version=version.stderr.decode('utf-8', errors='replace'),
        expected=[dict(id=31, date=1700000000, text='recipe first line\nsecond line', peer='user:71', sender='user:72'),
                  dict(id=32, date=1700000001, text='рецепт 🥧', peer='user:71', sender='user:72')])
    (directory / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Generated owned JVM HPROF; SHA256=' + manifest['sha256'])
    return manifest


if __name__ == '__main__':
    build(sys.argv[1])
