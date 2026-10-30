# Компоненты текущего комплекта

| Компонент | Фиксация | Лицензии/исходники |
|---|---|---|
| CPython | 3.12.14 x64 | tools/recovery-helper/licenses/Python-LICENSE.txt |
| PyInstaller | 6.22.3 | tools/recovery-helper/licenses/pyinstaller; GPL с исключением bootloader |
| Pillow / pillow-heif | 12.3.0 / 1.8.1 | tools/recovery-helper/licenses; включены уведомления нативных кодеков |
| regex | 2026.9.29 | tools/recovery-helper/licenses/regex; wheel и SHA256 включены |
| pycryptodome | 3.24.1 | tools/recovery-helper/licenses/pycryptodome |
| dissect.apfs | 1.1 | AGPL-3.0-or-later; tools/recovery-helper/licenses/dissect.apfs |
| dissect.fve | 4.6 | AGPL-3.0-or-later; tools/recovery-helper/licenses/dissect.fve |
| dissect.volume | 3.18 | AGPL-3.0-or-later; tools/recovery-helper/licenses/dissect.volume |
| dissect.cstruct | 4.7 | Apache-2.0; tools/recovery-helper/licenses/dissect.cstruct |
| dissect.util | 3.24 | Apache-2.0; tools/recovery-helper/licenses/dissect.util |
| asn1crypto | 1.5.1 | MIT; tools/recovery-helper/licenses/asn1crypto |
| iphone_backup_decrypt | c4a3e1a2f2548ecfdcb7c523f7405acb8779e6bb | vendor/iphone-backup-decrypt; MIT |
| Android platform-tools | 37.0.1 Windows | tools/platform-tools/NOTICE.txt, source.properties |
| TestDisk/PhotoRec | 7.2 Windows x64 | tools/testdisk-7.2/COPYING.txt, AUTHORS.txt; исходный архив и SHA256 также поставляются в tools/testdisk-7.2/source; [исходники](https://www.cgsecurity.org/testdisk-7.2.tar.bz2) |

WhatsApp и Signal исключены из текущего интерфейса; их сторонние парсеры и native helper не включаются в готовую папку. Исторические тесты/совместимый внутренний код могут упоминать прежние форматы; это не перечень текущих возможностей.

`package-sha256.json` — контрольные суммы исполняемых частей текущей готовой папки. `tools/recovery-helper/runtime-SHA256.json` — runtime, исходники и лицензии. `dependencies.json` включает также установленные пакеты сборочного окружения, а не только выполняемые модули. `requirements-wheel-lock.txt` и `wheels/SHA256.json` фиксируют локальные wheel-файлы.

Разработчик: `build.ps1` использует встроенный .NET Framework 4 compiler; `build.ps1 -Action Helper -Python312 <путь>` — Python 3.12 x64, локальные wheels и vendor/iphone-backup-decrypt. Исходники helper и офлайн-зависимости пересборки также находятся в `tools/recovery-helper/rebuild`. Для запуска готовой программы установка Python/Rust не требуется.

## Исходники компонентов хранения

Dissect APFS/FVE/volume поставляются с AGPL-3.0-or-later, cstruct/util — с Apache-2.0, asn1crypto — с MIT. Уведомления COPYRIGHT и тексты лицензий копируются из конкретных зафиксированных дистрибутивов

В репозитории [storage-dependencies.json](../helpers/recovery_engine/storage-dependencies.json) содержит версии, исходные URL и SHA256 source-архивов. В переносимом комплекте находятся:

- `tools/recovery-helper/rebuild/helpers/recovery_engine/dependency-sources/` — исходные архивы зафиксированных зависимостей
- `tools/recovery-helper/rebuild/helpers/recovery_engine/storage-dependencies.json` — их проверяемый перечень
- `tools/recovery-helper/rebuild/helpers/recovery_engine/storage_*.py` — полный исходный код адаптеров с SPDX AGPL-3.0-or-later
- `tools/recovery-helper/licenses/` — тексты лицензий и уведомления конкретных пакетов
- `RaidRecovery.cs` и `tests/RaidRecoveryTests.cs` — собственная сборка RAID и её воспроизводимые проверки

Публичные тестовые ключи опубликованных fixtures не являются ключами по умолчанию для пользовательских данных. Форматы и реально проверенные варианты описаны отдельно в [STORAGE-SUPPORT.md](guides/storage.md)

## Константы AAC

`src/Recovery/Recovery/Engines/AacSyntaxTables.cs` адаптирует числовые Huffman/scalefactor-band таблицы официального FFmpeg n8.0 `libavcodec/aactab.c` под LGPL-2.1-or-later. Сохранены авторство, URL и SHA256 источника, описание изменения формата; полный текст лицензии — `AacSyntaxTables.LICENSE.txt`. Оба файла включены в исходники готового комплекта. Исполняемый FFmpeg для работы приложения не требуется
