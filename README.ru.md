# USB-Recovery 🔬💾

[![Лицензия: AGPL-3.0](https://img.shields.io/badge/Лицензия-AGPL--3.0-blue.svg)](LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/Телеметрия-0%25%20Air--Gapped-success.svg)](README.ru.md)
[![Forensic Grade](https://img.shields.io/badge/Форензика-Chain%20of%20Custody-orange.svg)](README.ru.md)
[![Tests Passing](https://img.shields.io/badge/Тесты-4950%2B%20PASS-brightgreen.svg)](README.ru.md)
[![Платформа](https://img.shields.io/badge/Платформа-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.ru.md)

[English](README.md) · [Русский](README.ru.md)

**USB-Recovery** — профессиональный открытый комплекс цифровой криминалистики (DFIR) и глубокого восстановления данных enterprise-уровня. Спроектирован с нуля для экспертов-криминалистов, специалистов по реагированию на инциденты (IR) и системных инженеров: гарантирует 100% защиту источника от записи (write-blocking), сканирование со скоростью в гигабайты в секунду и реконструкцию файлов и системных артефактов даже при разрушенных таблицах разделов и затертых метаданных.

---

## ⚡ Ключевые возможности

- **Криминалистические образы и виртуальные диски**: Нативные ридеры на чистом C# с произвольным доступом для **E01 / Ex01 (Expert Witness)**, **AFF4 (Advanced Forensic Format 4)**, **QCOW2 (QEMU / KVM v2/v3)**, **VHD**, **VHDX** и **VMDK**.
- **Скауты современных файловых систем**: Анализ метаданных на уровне экстентов и деревьев для **Btrfs** (деревья чанков и генераций), **XFS** (группы распределения и BMBT), **ZFS** (uberblock и dnode), **APFS**, **Ext4**, **ReFS**, **NTFS**, **FAT12/16/32/exFAT**.
- **Глубокий анализ артефактов Windows**:
  - **Журнал изменений NTFS USN ($UsnJrnl:$J)**: Потоковый парсинг V2/V3, 48-битная MFT-индексация и реконструкция полного жизненного цикла удаленных файлов.
  - **Карвер записей NTFS $MFT**: Поиск 1024-байтных записей `FILE` в нераспределенном пространстве, исправление массивов Fixup, извлечение резидентных данных прямо из записи MFT и детектирование таймстемпинга.
  - **Движок реестра Windows (REGF)**: Иерархический обход, декодирование ячеек, карвинг удаленных ключей/значений из нераспределенных ячеек (slack space) и авто-сводка системы (`SYSTEM`, `SOFTWARE`, `SAM`).
  - **Shimcache / AppCompatCache**: Парсинг кэша запуска программ для Windows 7/8 (`0xBADC0FFE`) и Windows 10/11 (`10ts`).
  - **Единый супер-таймлайн (Super-Timeline)**: Сводный хронологический таймлайн событий (USN, MFT, EVTX, Prefetch, история браузеров, Shimcache) с экспортом в RFC 4180 CSV.
  - **SQLite B-Tree карвер**: Глубокий анализ баз данных, страниц свободного пространства (freelist) и свободных блоков (freeblocks).
- **Локальный Web-UI (`http://127.0.0.1:8080`)**: Автономный интерфейс без внешних зависимостей с интерактивной картой распределения кластеров в реальном времени, Hex-инспектором, потоковым ZIP-экспортом и фиксацией цепочки сохранности доказательств (Chain of Custody / SHA-256).
- **Защита от утечек памяти (Zero-Bloat)**: Фиксированные буферы 64 КиБ O(1), предотвращающие фрагментацию Large Object Heap (LOH), работа строго на loopback-интерфейсе (`127.0.0.1`), 0 байт исходящего сетевого трафика.

---

## 📊 Сравнение с конкурентами

| Возможность / Критерий | USB-Recovery | PhotoRec / TestDisk | Autopsy / SleuthKit | R-Studio (Коммерческая) |
| :--- | :---: | :---: | :---: | :---: |
| **Лицензия и цена** | **Бесплатно, Open-Source (AGPL-3)** | Бесплатно (GPLv2) | Бесплатно (Apache 2.0) | Проприетарная ($80 – $900) |
| **Поддержка образов** | **E01, AFF4, QCOW2, VHD/X, VMDK, ddrescue** | RAW, частично E01 | RAW, E01 | RAW, E01, VHD/X, VMDK |
| **Метаданные Btrfs / XFS / ZFS** | **Нативные скауты экстентов** | ❌ Нет | ⚠️ Базовая / Неполная | Нативная |
| **Восстановление удаленных через USN** | **Авто-реконструкция жизненного цикла** | ❌ Нет | ⚠️ Ручной модуль | Базовая |
| **Карвинг MFT и таймстемпинг** | **Встроенный карвер и детектор аномалий** | ❌ Нет | Нужен плагин | Базовая |
| **Карвер реестра REGF** | **Карвинг удаленных ячеек и ключей** | ❌ Нет | Нужен RegRipper | Только просмотр |
| **Парсинг Shimcache / AppCompat** | **Встроенный для Win7/10/11** | ❌ Нет | Нужен плагин | ❌ Нет |
| **Супер-таймлайн (Super-Timeline)** | **Встроенный экспорт в CSV RFC 4180** | ❌ Нет | Интеграция с Plaso | ❌ Нет |
| **Интерактивная карта кластеров и Hex** | **Встроенный Web-UI (127.0.0.1)** | ❌ Только консоль | Тяжелый Java GUI | Только десктопный GUI |
| **Расход памяти (RAM Footprint)** | **Строго O(1) 64 КиБ буферы** | Легкий (C) | Тяжелый (Java VM / Solr) | Средний (C++) |
| **Гарантия неизменности данных** | **100% на уровне виртуального потока** | Зависит от ОС | На уровне потока | На уровне потока |

---

## 🖥️ Консольный интерфейс (CLI)

`USB-Recovery.exe` предоставляет развитый CLI для автоматизации и интеграции в аналитические скрипты:

### Форензик-артефакты и Таймлайн
```bash
# Построение единого супер-таймлайна из образа или директории
USB-Recovery.exe timeline C:\images\evidence.e01 -o timeline.csv --from 2026-01-01 --to 2026-12-31

# Парсинг журнала изменений NTFS USN и реконструкция удаленных файлов
USB-Recovery.exe usn C:\images\volume.raw --deleted --json

# Карвинг 1024-байтных записей $MFT и дамп резидентных файлов в папку
USB-Recovery.exe carve-mft C:\images\disk.aff4 -o C:\cases\mft_dump\

# Инспекция ветки реестра Windows REGF и извлечение системной сводки
USB-Recovery.exe registry C:\cases\SYSTEM --summary

# Карвинг удаленных ключей и ячеек из реестра
USB-Recovery.exe registry C:\cases\NTUSER.DAT --carve
```

### Образы дисков и веб-интерфейс
```bash
# Запуск интерактивного локального Web-UI с картой кластеров и Hex-просмотрщиком
USB-Recovery.exe serve C:\images\disk.qcow2 --port 8080 --open-browser

# Исследование структуры образа, таблицы разделов и сигнатур файловых систем
USB-Recovery.exe probe C:\images\disk.vhdx

# Глубокое неинтерактивное криминалистическое сканирование
USB-Recovery.exe scan C:\images\usb.e01 -o C:\recovered --mode full --fs ntfs
```

---

## 🛠️ Сборка и запуск

### Windows (.NET Framework 4.8)
```powershell
# Клонирование репозитория
git clone https://github.com/fl1nky/usb-recovery.git
cd usb-recovery

# Сборка исполняемого файла
powershell -ExecutionPolicy Bypass -File scripts\build-app.ps1

# Запуск тестов и сборка дистрибутива
powershell -ExecutionPolicy Bypass -File scripts\package.ps1
```

### Linux / macOS (.NET 8.0 Headless)
```bash
dotnet build src/Recovery/Recovery.Net8.csproj -c Release
```

---

## 📄 Лицензия

Распространяется под лицензией **GNU Affero General Public License v3.0 (AGPL-3.0)**.  
Copyright (C) 2026 USB-Recovery Contributors. 100% Free & Open Source · Zero Telemetry.
