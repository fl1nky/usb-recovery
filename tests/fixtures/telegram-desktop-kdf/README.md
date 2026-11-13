# Desktop KD2/v2 controlled key-data inputs

`native-cases.zip` contains 35 artificial TDF key-data files: nine positive
wrappers and 26 rejection controls. Each file's size, SHA256 and expected outcome
are in `manifest.json`. The fixture local key and passcode are the existing public
artificial values in `build_telegram_platform_fixtures.py`; no account or real
Desktop profile was used. The account-info field is deliberately opaque.

The independent producer is
[`producer.py`](../../telegram_desktop_kdf_oracle/producer.py). It writes the
trailer using native Qt5.15.2 `QDataStream(Qt_5_1)`, the existing independent
encryption-direction writer, and PyCryptodome scrypt. The reader uses OpenSSL
`hashlib.scrypt`. The producer imports neither the reader nor the collector.
Normal tests use the frozen bytes without Qt. Reproduction requires developer
PyQt5, PyCryptodome, the three pinned upstream source files and a fresh output
directory:

```powershell
$env:TELEGRAM_QT_PRODUCER = '<private Qt dependency folder>'
python tests/telegram_desktop_kdf_oracle/producer.py --destination <fresh-folder> --upstream <pinned-sources>
python tests/TelegramPlatformTests.py
```

Source pin: `telegramdesktop/tdesktop`
`a8de5f928ba68197195e6e752293af39d4db8e6c`:

- [storage_domain.cpp](https://github.com/telegramdesktop/tdesktop/blob/a8de5f928ba68197195e6e752293af39d4db8e6c/Telegram/SourceFiles/storage/storage_domain.cpp): `ReadKeyData`, `WriteKeyData`, `startModern`; KD2 magic, format 2, at most two slots and committed-generation selection
- [storage_file_utilities.cpp](https://github.com/telegramdesktop/tdesktop/blob/a8de5f928ba68197195e6e752293af39d4db8e6c/Telegram/SourceFiles/storage/details/storage_file_utilities.cpp): `CreateLocalKey`, `CreatePasscodeKey`, TDF and IGE wrapper verification
- [storage_file_utilities.h](https://github.com/telegramdesktop/tdesktop/blob/a8de5f928ba68197195e6e752293af39d4db8e6c/Telegram/SourceFiles/storage/details/storage_file_utilities.h): KDF family IDs

The exact downloaded source SHA256 values are in the manifest. Positive inputs
cover scrypt `N=131072,r=8,p=1` and the Windows x86 `N=65536,r=8,p=1`, either
committed-slot position, an inactive Argon2id slot, and explicit known open wraps.
An inactive slot is never tried. A wrong supplied code never falls back to an
open wrap. Selected Argon2id is unsupported; a separately verified open wrap can
still be opened when the caller explicitly supplies the known no-passcode state.

Controls cover unknown magic/version/KDF, missing or duplicate generations,
excess slots, inner/outer trailing bytes, truncation, malformed inactive slots,
invalid/excessive costs, short/oversized salt, short/corrupt ciphertext,
authenticated wrong key size, missing open wrap, checksum damage and a fake
trailer hidden inside the opaque account field. Structural/cost controls must
fail before scrypt runs. Collector tests reuse the existing native draft corpus,
keep authorization/maps closed, exercise stdin, preserve source bytes and check
secret non-disclosure and draft-only provenance.

These are source tests on owned synthetic inputs. They do not prove a real
client/profile/device, complete Desktop history, deleted messages, a rebuilt
portable helper or a published release. The old `telegram-platforms` corpus and
its unknown-trailer negative control remain unchanged.
