"""Independent Python/cryptography fixtures for actual Signal local wire formats.

All data is synthetic. The writers do not import either helper implementation.
"""
from pathlib import Path
import base64, gzip, hashlib, hmac, json, shutil, struct, subprocess, sys, time, unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.build' / 'signal-test-python'))
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

WORK = ROOT / '.build' / 'SignalHelpers-tests'
PHOTO = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j3ioAAAAASUVORK5CYII=')
LEGACY_SECRET = '123456789012345678901234567890'
MODERN_SECRET = 'm' * 64
TEXT = 'Секрет прабабушки: пирожки с яблоками. Independent fixture.'

def vi(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128); n >>= 7
    return bytes(out) + bytes([n])

def p(n, value):
    if isinstance(value, int): return vi(n << 3) + vi(value & ((1 << 64) - 1))
    if isinstance(value, str): value = value.encode('utf-8')
    return vi((n << 3) | 2) + vi(len(value)) + value

def hkdf(key, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)

def ctr(key, iv, data):
    ctx = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return ctx.update(data) + ctx.finalize()

def cbc(key, iv, data):
    pad = padding.PKCS7(128).padder(); data = pad.update(data) + pad.finalize()
    ctx = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return ctx.update(data) + ctx.finalize()

def old_key(secret, salt):
    raw = secret.encode('ascii'); current = raw
    for n in range(250000): current = hashlib.sha512((salt if n == 0 else b'') + current + raw).digest()
    return hkdf(current[:32], b'Backup Export', 64)

def sql_frame(statement, args=()):
    inner = p(1, statement)
    for value in args:
        param = p(1, value) if isinstance(value, str) else p(2, value) if value is not None else p(5, 1)
        inner += p(2, param)
    return p(2, inner)

def make_legacy(path, version=1):
    salt = bytes(range(32)); iv = b'\x00\x00\x00\x11' + b'I' * 12
    keys = old_key(LEGACY_SECRET, salt); aes, mac = keys[:32], keys[32:]
    header = p(1, p(1, iv) + p(2, salt) + p(3, version))
    out = bytearray(struct.pack('>I', len(header)) + header); counter = 17
    def frame(raw):
        nonlocal counter
        biv = struct.pack('>I', counter) + iv[4:]; counter += 1
        length = struct.pack('>I', len(raw) + 10)
        if version == 1:
            enc = ctr(aes, biv, length + raw); lb, body = enc[:4], enc[4:]
            tag = hmac.new(mac, lb + body, hashlib.sha256).digest()[:10]
        else:
            lb, body = length, ctr(aes, biv, raw)
            tag = hmac.new(mac, body, hashlib.sha256).digest()[:10]
        out.extend(lb + body + tag)
    frame(p(5, p(1, 300)))
    frame(sql_frame('CREATE TABLE recipient (_id INTEGER PRIMARY KEY, profile_given_name TEXT, profile_family_name TEXT)'))
    frame(sql_frame('INSERT INTO recipient VALUES (?, ?, ?)', (2, 'Fixture', 'Grandmother')))
    frame(sql_frame('CREATE TABLE message (_id INTEGER PRIMARY KEY, thread_id INTEGER, from_recipient_id INTEGER, date_sent INTEGER, body TEXT)'))
    frame(sql_frame('INSERT INTO message VALUES (?, ?, ?, ?, ?)', (101, 10, 2, 1700000000123, TEXT)))
    frame(sql_frame('CREATE TABLE attachment (_id INTEGER PRIMARY KEY, message_id INTEGER)'))
    frame(sql_frame('INSERT INTO attachment VALUES (?, ?)', (22, 101)))
    frame(p(4, p(1, 22) + p(2, 33) + p(3, len(PHOTO))))
    biv = struct.pack('>I', counter) + iv[4:]; counter += 1
    encrypted = ctr(aes, biv, PHOTO); out.extend(encrypted + hmac.new(mac, biv + encrypted, hashlib.sha256).digest()[:10])
    frame(p(6, 1)); path.write_bytes(out)

def make_modern(root, metadata_version=1, unknown=False):
    snapshot = root / 'signal-backup-2026-10-12-01-02-03'; snapshot.mkdir(parents=True)
    media = root / 'files'; media.mkdir()
    backup_key = hkdf(MODERN_SECRET.encode(), b'20240801_SIGNAL_BACKUP_KEY', 32)
    metadata_key = hkdf(backup_key, b'20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY', 32)
    backup_id = b'B' * 16; metadata_iv = b'M' * 12
    metadata = p(1, metadata_version) + p(2, p(1, metadata_iv) + p(2, ctr(metadata_key, metadata_iv + b'\x00'*4, backup_id)))
    (snapshot / 'metadata').write_bytes(metadata)
    keys = hkdf(backup_key, b'20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:' + backup_id, 64)
    mac_key, aes_key = keys[:32], keys[32:]
    local_key = bytes(range(64)); photo_hash = hashlib.sha256(PHOTO).digest()
    filename = hashlib.sha256(photo_hash + local_key).hexdigest()
    shard = media / filename[:2]; shard.mkdir()
    media_iv = b'A' * 16; encrypted = media_iv + cbc(local_key[:32], media_iv, PHOTO + b'\x00'*29)
    (shard / filename).write_bytes(encrypted + hmac.new(local_key[32:], encrypted, hashlib.sha256).digest())
    header = p(1, 1) + p(2, 1700000000000) + p(3, b'K'*32) + p(4, 'synthetic-fixture')
    account = p(1, p(1, b'P'*32))
    recipient_self = p(2, p(1, 1) + p(5, b''))
    contact = p(11, 'Fixture') + p(12, 'Grandmother')
    recipient = p(2, p(1, 2) + p(2, contact))
    chat = p(3, p(1, 10) + p(2, 2))
    locator = p(1, b'R'*64) + p(3, len(PHOTO)) + p(9, local_key) + p(10, photo_hash)
    pointer = p(4, 'image/png') + p(7, 'old-photo.png') + p(13, locator)
    standard = p(2, p(1, TEXT)) + p(3, p(1, pointer))
    item = p(4, p(1, 10) + p(2, 2) + p(3, 1700000000123) + p(8, p(1, 1700000000124)) + p(11, standard))
    if unknown: item += p(99, 'unrecognized-future-frame-field')
    raw = b''.join(vi(len(x)) + x for x in (header, account, recipient_self, recipient, chat, item))
    iv = b'I'*16; encrypted = iv + cbc(aes_key, iv, gzip.compress(raw, mtime=0))
    (snapshot / 'main').write_bytes(encrypted + hmac.new(mac_key, encrypted, hashlib.sha256).digest())
    (snapshot / 'files').write_bytes(p(1, filename))
    return snapshot

def invoke(name, source, destination, secret, cancel=False):
    request = {'protocol': 1, 'operation': 'import', 'source': str(source), 'destination': str(destination), 'secret': secret}
    payload = json.dumps(request, ensure_ascii=False) + '\n'
    if cancel: payload += '{"protocol":1,"operation":"cancel"}\n'
    proc = subprocess.run([str(ROOT / 'tools' / 'signal' / name)], input=payload, text=True, encoding='utf-8', capture_output=True, timeout=120)
    events = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert events and events[-1]['type'] == 'result', (proc.returncode, proc.stdout, proc.stderr)
    assert secret not in proc.stdout + proc.stderr
    assert TEXT not in proc.stdout + proc.stderr
    return events[-1], proc

class SignalHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if WORK.exists(): shutil.rmtree(WORK)
        WORK.mkdir(parents=True)
        cls.v0 = WORK/'legacy-v0.backup'; make_legacy(cls.v0, 0)
        cls.v1 = WORK/'legacy-v1.backup'; make_legacy(cls.v1, 1)
        cls.modern = make_modern(WORK/'modern')
        cls.unknown = make_modern(WORK/'unknown', unknown=True)
        cls.future = make_modern(WORK/'future', metadata_version=2)

    def output(self, name): return WORK / name

    def check_success(self, exe, source, secret, name, status='complete'):
        digest_before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in ([source] if source.is_file() else source.rglob('*')) if p.is_file()}
        dest = self.output(name); result, _ = invoke(exe, source, dest, secret)
        self.assertEqual(result['status'], status, result); self.assertEqual(result['messages'], 1, result); self.assertEqual(result['media'], 1, result)
        messages = [json.loads(x) for x in (dest/'messages.jsonl').read_text('utf-8').splitlines()]
        self.assertEqual(messages[0]['text'], TEXT); self.assertEqual(messages[0]['sender_name'], 'Fixture Grandmother')
        self.assertEqual((dest/messages[0]['attachments'][0]).read_bytes(), PHOTO)
        self.assertEqual(messages[0]['timestamp'], 1700000000123)
        for p, expected in digest_before.items(): self.assertEqual(hashlib.sha256(Path(p).read_bytes()).hexdigest(), expected)

    def test_legacy_v0(self): self.check_success('SignalLegacyHelper.exe', self.v0, LEGACY_SECRET, 'out-legacy-v0')
    def test_legacy_v1(self): self.check_success('SignalLegacyHelper.exe', self.v1, LEGACY_SECRET, 'out-legacy-v1')
    def test_legacy_unicode_source(self):
        source=WORK/'прабабушка.backup';shutil.copyfile(self.v1,source)
        self.check_success('SignalLegacyHelper.exe',source,LEGACY_SECRET,'out-legacy-unicode')
    def test_modern(self): self.check_success('SignalModernHelper.exe', self.modern, MODERN_SECRET, 'out-modern')
    def test_official_local_crypto_fixture(self):
        upstream = ROOT/'vendor'/'signal-libsignal'/'libsignal-4beb029d8a941f81e7d9c6d8af1ed25a677569a8'
        original = upstream/'rust'/'message-backup'/'tests'/'res'/'test-cases'/'valid-encrypted'/'legacy-account.binproto.encrypted'
        root = WORK/'official-fixture'; snapshot = root/'signal-backup-official';snapshot.mkdir(parents=True);(root/'files').mkdir()
        backup_key=hkdf(MODERN_SECRET.encode(),b'20240801_SIGNAL_BACKUP_KEY',32)
        encrypted=original.read_bytes(); selected_id=None
        # The published test uses ACI UUID 1111..., and Signal's ACI service-id representation.
        for aci_bytes in (b'\x11'*16,b'\x00'+b'\x11'*16):
            backup_id=hkdf(backup_key,b'20241024_SIGNAL_BACKUP_ID:'+aci_bytes,16)
            keys=hkdf(backup_key,b'20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:'+backup_id,64)
            if hmac.compare_digest(hmac.new(keys[:32],encrypted[:-32],hashlib.sha256).digest(),encrypted[-32:]):selected_id=backup_id;break
        self.assertIsNotNone(selected_id,'Official file must match official independent key vectors')
        metadata_key=hkdf(backup_key,b'20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY',32);iv=b'O'*12
        (snapshot/'metadata').write_bytes(p(1,1)+p(2,p(1,iv)+p(2,ctr(metadata_key,iv+b'\x00'*4,selected_id))))
        shutil.copyfile(original,snapshot/'main')
        dest=self.output('out-official');result,_=invoke('SignalModernHelper.exe',snapshot,dest,MODERN_SECRET)
        self.assertEqual(result['status'],'complete',result);self.assertEqual(result['messages'],0)
    def test_unknown_field_is_partial(self): self.check_success('SignalModernHelper.exe', self.unknown, MODERN_SECRET, 'out-unknown', 'partial')
    def test_future_metadata(self):
        dest=self.output('out-future'); result,_=invoke('SignalModernHelper.exe',self.future,dest,MODERN_SECRET)
        self.assertEqual(result['code'],'UNSUPPORTED_VERSION'); self.assertFalse((dest/'messages.jsonl').exists())
    def test_wrong_keys(self):
        for exe,source,secret,name in [('SignalLegacyHelper.exe',self.v1,'9'*30,'bad-key-legacy'),('SignalModernHelper.exe',self.modern,'n'*64,'bad-key-modern')]:
            dest=self.output(name); result,_=invoke(exe,source,dest,secret)
            self.assertEqual(result['code'],'AUTH_FAILED'); self.assertFalse((dest/'messages.jsonl').exists())
            self.assertFalse((dest/'media').exists());self.assertFalse((dest/'manifest.json').exists())
    def test_legacy_bad_last_mac_removes_already_decoded_media(self):
        source=WORK/'legacy-corrupt-last.backup';raw=bytearray(self.v1.read_bytes());raw[-1]^=1;source.write_bytes(raw)
        dest=self.output('out-legacy-corrupt-last');result,_=invoke('SignalLegacyHelper.exe',source,dest,LEGACY_SECRET)
        self.assertEqual(result['code'],'AUTH_FAILED');self.assertFalse(dest.exists())
    def test_legacy_future_version(self):
        source=WORK/'legacy-future-version.backup';make_legacy(source,2)
        dest=self.output('out-legacy-future');result,_=invoke('SignalLegacyHelper.exe',source,dest,LEGACY_SECRET)
        self.assertEqual(result['code'],'UNSUPPORTED_VERSION');self.assertFalse(dest.exists())
    def test_bad_main_mac(self):
        root=WORK/'corrupt-main'; shutil.copytree(self.modern.parent,root); source=root/self.modern.name
        raw=bytearray((source/'main').read_bytes());raw[-1]^=1;(source/'main').write_bytes(raw)
        dest=self.output('out-bad-mac');result,_=invoke('SignalModernHelper.exe',source,dest,MODERN_SECRET)
        self.assertEqual(result['code'],'AUTH_FAILED');self.assertFalse((dest/'messages.jsonl').exists())
    def test_bad_media_mac_partial(self):
        root=WORK/'corrupt-media';shutil.copytree(self.modern.parent,root);source=root/self.modern.name
        pth=next((root/'files').rglob('*/*'));raw=bytearray(pth.read_bytes());raw[-1]^=1;pth.write_bytes(raw)
        dest=self.output('out-bad-media');result,_=invoke('SignalModernHelper.exe',source,dest,MODERN_SECRET)
        self.assertEqual(result['status'],'partial');self.assertEqual(result['messages'],1);self.assertEqual(result['media'],0)
        self.assertEqual(list((dest/'media').iterdir()),[])
        self.assertEqual(json.loads((dest/'messages.jsonl').read_text('utf-8'))['attachments'],[])
    def test_modern_frame_ordinal_is_not_message_id(self):
        dest=self.output('out-modern-no-id');result,_=invoke('SignalModernHelper.exe',self.modern,dest,MODERN_SECRET)
        self.assertEqual(result['status'],'complete');message=json.loads((dest/'messages.jsonl').read_text('utf-8'))
        self.assertIsNone(message['message_id']);self.assertTrue(message['source_record'].startswith('frame:'))
    def test_cancel(self):
        for exe,source,secret,name in [('SignalLegacyHelper.exe',self.v1,LEGACY_SECRET,'cancel-legacy'),('SignalModernHelper.exe',self.modern,MODERN_SECRET,'cancel-modern')]:
            dest=self.output(name);result,_=invoke(exe,source,dest,secret,True)
            self.assertEqual(result['code'],'CANCELLED');self.assertFalse((dest/'messages.jsonl').exists())
            self.assertFalse((dest/'media').exists());self.assertFalse((dest/'manifest.json').exists())
    def test_existing_destination_preserved(self):
        for exe,source,secret,name in [('SignalLegacyHelper.exe',self.v1,LEGACY_SECRET,'occupied-legacy'),('SignalModernHelper.exe',self.modern,MODERN_SECRET,'occupied-modern')]:
            dest=self.output(name);dest.mkdir();(dest/'messages.jsonl').write_text('Existing result must remain',encoding='utf-8')
            result,_=invoke(exe,source,dest,secret);self.assertEqual(result['code'],'DESTINATION_NOT_EMPTY')
            self.assertEqual((dest/'messages.jsonl').read_text('utf-8'),'Existing result must remain')

if __name__ == '__main__': unittest.main(verbosity=2)
