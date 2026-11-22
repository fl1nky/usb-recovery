# USB-Recovery 🔬💾

[![Лицензия: AGPL-3.0](https://img.shields.io/badge/Лицензия-AGPL--3.0-blue.svg)](LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/Телеметрия-0%25%20Air--Gapped-success.svg)](README.ru.md)
[![Forensic Grade](https://img.shields.io/badge/Форензика-Chain%20of%20Custody-orange.svg)](README.ru.md)
[![Tests Passing](https://img.shields.io/badge/Тесты-46000%2B%20PASS-brightgreen.svg)](README.ru.md)
[![Платформа](https://img.shields.io/badge/Платформа-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.ru.md)

[English](README.md) · [Русский](README.ru.md)

**USB-Recovery** — профессиональный открытый комплекс цифровой криминалистики (DFIR) и глубокого восстановления данных enterprise-уровня. Спроектирован с нуля для экспертов-криминалистов, специалистов по реагированию на инциденты (IR) и системных инженеров: гарантирует 100% защиту источника от записи (write-blocking), сканирование со скоростью в гигабайты в секунду и реконструкцию файлов и системных артефактов даже при разрушенных таблицах разделов и затертых метаданных.

---

## ⚡ Ключевые возможности

- **Криминалистические образы и виртуальные диски**: Нативные ридеры на чистом C# с произвольным доступом для **E01 / Ex01 (Expert Witness)**, **AFF4 (Advanced Forensic Format 4)**, **QCOW2 (QEMU / KVM v2/v3)**, **VHD**, **VHDX** и **VMDK**.
- **Скауты современных файловых систем**: Анализ метаданных на уровне экстентов и деревьев для **exFAT** (глубокий карвинг удаленных наборов записей 0x05+0x40+0x41, извлечение непрерывных потоков NoFatChain, валидация контрольных сумм VBR), **HFS+ / HFSX** (обход B-Tree каталога Apple, прямое отображение экстентов, карвинг сиротских записей из slack узлов), **F2FS** (flash-память, таблица NAT, встроенные payload в инode), **Btrfs** (деревья чанков и генераций), **XFS** (группы распределения и BMBT), **ZFS** (uberblock и dnode), **APFS**, **Ext4**, **ReFS**, **NTFS**, **FAT12/16/32**.
- **Глубокий анализ артефактов Windows**:
  - **Журнал изменений NTFS USN ($UsnJrnl:$J)**: Потоковый парсинг V2/V3, 48-битная MFT-индексация и реконструкция полного жизненного цикла удаленных файлов.
  - **Карвер записей NTFS $MFT**: Поиск 1024-байтных записей `FILE` в нераспределенном пространстве, исправление массивов Fixup, извлечение резидентных данных прямо из записи MFT и детектирование таймстемпинга.
  - **Движок реестра Windows (REGF)**: Иерархический обход, декодирование ячеек, карвинг удаленных ключей/значений из нераспределенных ячеек (slack space) и авто-сводка системы (`SYSTEM`, `SOFTWARE`, `SAM`).
  - **Amcache.hve парсер**: Анализ реестра программ Windows 10/11 (`InventoryApplicationFile`) и Windows 7/8 (`File`), извлечение SHA-1 хешей исполняемых файлов и эвристика угроз (запуск из TEMP, двойные расширения).
  - **Shellbags парсер**: Анализ `UsrClass.dat`/`NTUSER.DAT` и дерева `BagMRU`, хронология открытия папок на съемных USB-накопителях и сетевых ресурсах.
  - **Shimcache / AppCompatCache**: Парсинг кэша запуска программ для Windows 7/8 (`0xBADC0FFE`) и Windows 10/11 (`10ts`).
  - **Классификатор энтропии Шеннона (Shannon Entropy)**: Потоковый анализ байтовой энтропии ($H = -\sum p \log_2 p$) без телеметрии и детектирование вымогателей (Ransomware).
  - **Пакет судебной экспертизы (Rule 902(14))**: Автоматическая генерация отчетов по стандарту Federal Rule of Evidence 902(14) и ISO/IEC 27037 с криптографическими хешами Chain of Custody (SHA-256).
  - **Монитор ресурсов и утечек SRUM**: Парсер базы данных ESE (`SRUDB.dat`), сопоставление сетевых передач приложений, SID пользователей, сетевых интерфейсов, точного объема выгруженных данных (Data Exfiltration) и активности CPU.
  - **Парсер Windows Jump Lists**: Анализ AutomaticDestinations (формат составных файлов CFBF/OLE) и CustomDestinations с извлечением порядка доступа MRU, статуса закрепления (Pinned), временных меток выполнения, NetBIOS-имен хостов, Volume/File DROID, встроенных LNK-потоков и детекцией подозрительных запусков.
  - **Парсер корзины Windows Recycle Bin**: Анализ артефактов $I / $R для Windows Vista/7/8/10/11, определение SID пользователя, восстановление оригинального имени и пути, проверка целостности пейлоада, детектирование анти-криминалистического затирания (Anti-Forensics) и автоматическое спасение удаленных файлов.
  - **Единый супер-таймлайн (Super-Timeline)**: Сводный хронологический таймлайн событий (USN, MFT, EVTX, Prefetch, LNK, история браузеров, Shimcache, Amcache, Shellbags, SRUM, Jump Lists, Recycle Bin, exFAT, HFS+) с экспортом в RFC 4180 CSV.
  - **SQLite B-Tree карвер**: Глубокий анализ баз данных, страниц свободного пространства (freelist) и свободных блоков (freeblocks).
- **Пакет бенчмарков (Forensic Benchmark Suite)**: Высокоскоростное тестирование скорости SWAR-поиска сигнатур, пропускной способности энтропии, парсинга MFT и аудит стабильности памяти (Zero-Leak).
- **Локальный Web-UI (`http://127.0.0.1:8080`)**: Автономный интерфейс без внешних зависимостей с интерактивной картой распределения кластеров, Hex-инспектором, вкладками MFT, Shimcache, Super-Timeline, Amcache, Shellbags, Entropy, Court Report, потоковым ZIP-экспортом и фиксацией цепочки сохранности доказательств (Chain of Custody / SHA-256).
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
| **Amcache и форензика запуска** | **Встроенный для Win7/10/11 и SHA-1** | ❌ Нет | Нужен плагин | ❌ Нет |
| **Shellbags (История папок и USB)** | **Нативный иерархический BagMRU** | ❌ Нет | Нужен плагин | ❌ Нет |
| **Сетевая эксфильтрация SRUM** | **Встроенный ESE-карвинг и корреляция IdMap** | ❌ Нет | Нужен SrumECmd | ❌ Нет |
| **Windows Jump Lists (Автоматические/Кастомные)** | **Нативный парсер CFBF и категорий LNK** | ❌ Нет | Нужен JLECmd | ❌ Нет |
| **Корзина Windows ($I / $R)** | **Нативный парсер V1/V2, восстановление и карвинг** | ❌ Нет | Нужен плагин | Базовое |
| **Энтропия Шеннона и Ransomware** | **Потоковый O(1) анализ аномалий** | ❌ Нет | ❌ Нет | Базовый просмотр |
| **Судебный отчет (Rule 902(14))** | **Автоматический ISO/IEC 27037 & SHA-256** | ❌ Нет | Ручной экспорт | Базовый отчет |
| **Flash / F2FS скаут метаданных** | **Нативный парсер Superblock и NAT** | ❌ Нет | ❌ Нет | Базовый |
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

# Парсинг Amcache.hve для выявления запусков ПО и SHA-1 индикаторов угроз
USB-Recovery.exe amcache C:\cases\Amcache.hve --json

# Парсинг Shellbags для истории подключения USB-накопителей и открытия каталогов
USB-Recovery.exe shellbags C:\cases\UsrClass.dat --json

# Парсинг базы данных Windows SRUM и выявление утечек данных
USB-Recovery.exe srum C:\cases\SRUDB.dat --json

# Парсинг Windows Jump Lists (.automaticDestinations-ms / .customDestinations-ms)
USB-Recovery.exe jumplist C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations --json

# Парсинг корзины Windows Recycle Bin, анализ SID пользователей и восстановление файлов
USB-Recovery.exe recycle-bin C:\$Recycle.Bin -o C:\recovered_recycle --json

# Анализ энтропии Шеннона потока и выявление шифрования вымогателями (Ransomware)
USB-Recovery.exe entropy C:\images\evidence.raw --json

# Генерация пакета судебной экспертизы по стандарту FRE Rule 902(14)
USB-Recovery.exe court-report C:\images\evidence.e01 -o C:\reports\court_package.html

# Разведка суперблоков, NAT-таблицы и экстентов flash-файловой системы F2FS
USB-Recovery.exe f2fs-scout C:\images\nvme_flash.raw

# Анализ флеш-накопителей exFAT, карвинг удаленных наборов записей и спасение файлов
USB-Recovery.exe exfat-scout C:\images\sdcard_exfat.raw --json

# Разведка Apple HFS+ / HFSX каталога B-Tree и карвинг файлов из нераспределенных блоков
USB-Recovery.exe hfs-scout C:\images\macos_disk.raw

# Запуск высокоскоростного бенчмарка и аудит отсутствия утечек памяти
USB-Recovery.exe benchmark

# Анализ ярлыков Windows (.lnk) и структур TrackerDataBlock
USB-Recovery.exe lnk C:\cases\recent\document.lnk
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
