# Восстановление метаданных ReFS (Resilient File System)

Модуль `RefsRecovery` выполняет строго read-only извлечение файлов и метаданных из томов ReFS (Resilient File System) версий v1.2 (Windows 8 / Server 2012) и v3.x (Windows 10 / Server 2016 / Server 2019 / Server 2022). Исходный файл образа открывается исключительно для чтения (`FileAccess.Read`, `FileShare.Read`); SHA256 тома вычисляется до и после прохода и строго проверяется на неизменность (`report.SourceUnchanged`).

В архитектуре ReFS отсутствуют классические таблицы MFT или фиксированные таблицы дескрипторов inode: всё состояние файловой системы организовано в виде B+ деревьев Ministore с copy-on-write транзакциями. При удалении файла или сбое метаданные могут сохраняться в предыдущих checkpoints (пинг-понг последовательностях) или в виде неразрушенных страниц B+ деревьев в свободном пространстве тома.

---

## Архитектура и поддерживаемые форматы

ReFS претерпела существенную эволюцию между версиями:

| Параметр | ReFS v1.2 | ReFS v3.x (v3.4+) |
|---|---|---|
| Размер метаданного блока | Фиксирован: 16 КиБ (16384 Б) | Равен размеру кластера: 4 КиБ или 64 КиБ |
| Сигнатура узлов B+ дерева | Отсутствует | `"MSB+"` (0x4D 0x53 0x42 0x2B) |
| Сигнатура суперблока | Отсутствует | `"SUPB"` (0x53 0x55 0x50 0x42) |
| Сигнатура контрольной точки | Отсутствует | `"CHKP"` (0x43 0x48 0x4B 0x50) |
| Размер BlockReference | 24 байта | 48 байт |
| Смещение записей узла | 16-битный offset | 32-битный offset с маской `0xFFFF0000` |
| Адресация блоков | Прямая кластерная адресация | Контейнерная адресация через Tree 7 |
| Контрольные суммы | CRC32-C (Castagnoli) | CRC32-C и CRC64-ECMA-182 |

`RefsRecovery` прозрачно поддерживает обе версии в едином конвейере.

---

## Что проверяется и ключевые этапы восстановления

### 1. Детекция VBR и резервного сектора (Backup VBR)
- Первичный сектор VBR (смещение 0): проверяется сигнатура `"ReFS\0\0\0\0"` со смещения 3 и `"FSRS"` со смещения 16. Читаются размер сектора (512 или 4096 байт), кластерный множитель, мажорная и минорная версии, серийный номер тома и размер контейнера (смещение 64 в v3.4+).
- Резервный VBR (Backup VBR fallback): если сектор 0 повреждён или занулён, сканируется хвостовой сектор тома (`VolumeSectors - 1` или 512/4096 байт от конца файла). При обнаружении валидного `"ReFS"/"FSRS"` сектор используется для восстановления геометрии с фиксацией `BackupVbrUsed = true` в матрице возможностей.

### 2. Суперблок (Metadata Block 30)
- Суперблок расположен в фиксированном метаданном блоке 30 (`30 * 16384` для v1.2; `30 * cluster_size` для v3.x).
- Проверяется блок заголовка (`SUPB` в v3), извлекаются GUID тома, счётчик последовательности и блочные ссылки на пару контрольных точек первого уровня (Checkpoints).

### 3. Арбитраж контрольных точек (Checkpoint Ping-Pong Clock Arbitration)
- ReFS использует схему двойной буферизации (пинг-понг) с двумя контрольными точками первого уровня (блоки 31 и 32).
- Вычисляются и сопоставляются контрольные суммы (CRC32-C / CRC64). Сверяются sequence clocks (счётчики монотонных часов).
- Выбирается точка с наивысшим валидным счётчиком последовательности (`CheckpointIndexUsed`). Если одна из точек повреждена, автоматически выбирается альтернативная с выдачей диагностического предупреждения.
- Из трейлера контрольной точки извлекаются корневые ссылки на Таблицу объектов (Tree 0) и Таблицу контейнеров (Tree 7).

### 4. B+ деревья Ministore и маскирование смещений v3
- Узлы деревьев содержат 32-байтный заголовок: уровень узла (`NodeLevel`: 0 — лист, >0 — ветвь), флаги типа узла (`NodeTypeFlags`: 0x1 — ветвь, 0x2 — корень, 0x4 — поток), смещение массива записей и количество записей.
- **Маска ReFS v3**: В ReFS v3 смещения записей упакованы как `uint32`, в которых старшие 16 бит установлены в `0xFFFF`. Движок строго маскирует значения: `offset & 0xFFFF`. Без этого маскирования разбор записей в v3 приводит к выходу за пределы буфера.
- Разбор записей: заголовок записи (14 байт), длина и смещение ключа, длина и смещение значения.

### 5. Таблица объектов (Tree 0) и обход каталогов
- Tree 0 сопоставляет 64-битные Object ID с B+ деревьями соответствующих объектов.
- Корневой каталог всегда имеет фиксированный ObjectId `0x600`.
- Вложенные каталоги имеют ObjectId `0x701+`.
- Рекурсивный обход защищён от циклических ссылок (`visitedObjects`, `visitedDirs`) и ограничен максимальной глубиной дерева (32) и каталогов (64).

### 6. Записи каталога (Key Type 0x0030)
- Записи каталога имеют тип ключа `0x0030`. Ключ содержит тип записи (1 — файл, 2 — каталог) и имя в кодировке UTF-16LE.
- `DecodeReFsString` корректно обрабатывает UTF-16LE, включая многобайтовые суррогатные пары (эмодзи, редкие символы CJK) и локализованные имена без выбрасывания исключений.
- Значение каталога (72 байта) содержит child ObjectId, 4 отметки времени FILETIME и атрибуты Win32.
- Значение файла содержит 128-байтный заголовок (`fsrefs_file_values_t`), отметки времени (Creation, LastWrite, Change, LastAccess), атрибуты Win32 и Атрибут 0x80 ($DATA).

### 7. Извлечение данных: Resident и Non-Resident Extents
- **Resident inline stream**: если флаг атрибута не содержит `0x08`, полезная нагрузка хранится непосредственно внутри записи метаданных. Извлекается без обращения к кластерам данных.
- **Non-resident extents**: список экстентов (логическое смещение, количество блоков, номер физического блока).
- **Контейнерная трансляция (ReFS v3)**: виртуальные кластеры $\ge container\_size$ транслируются через Tree 7:
  $$\text{container\_id} = \text{block} / \text{container\_size}$$
  $$\text{block\_offset} = \text{block} \pmod{\text{container\_size}}$$
  $$\text{physical\_cluster} = \text{container\_start} + \text{block\_offset}$$

### 8. Сальваж удалённых узлов из свободного пространства (Free Space Salvage)
- Сканируются неиспользуемые страницы метаданных тома, не входящие в активные деревья.
- Извлекаются сохранившиеся записи типа `0x0030`, чей ObjectId каталога уже не привязан к активному дереву.
- Такие кандидаты помечаются статусом `deleted_refs_candidate` и регистрируются в доказательной базе (`refs_deleted_candidate`).

---

## Матрица возможностей (Capability Matrix)

ReFS поддерживает ряд корпоративных возможностей, требующих прозрачной фиксации в отчёте:

```json
"capabilities": {
  "refs_version": "3.4",
  "bytes_per_sector": 4096,
  "cluster_block_size": 4096,
  "metadata_block_size": 4096,
  "container_size": 16384,
  "primary_vbr_valid": true,
  "backup_vbr_used": false,
  "superblock_checksum_verified": true,
  "active_checkpoint_valid": true,
  "checkpoint_index_used": 1,
  "container_translation_supported": true,
  "compression_detected": false,
  "bitlocker_detected": false,
  "supported_features": [
    "vbr_fsrs_parsed",
    "superblock_level1",
    "checkpoint_pingpong_arbitration",
    "btree_msb_traversal",
    "tree0_objects_table",
    "directory_entry_0x30",
    "attribute_data_resident",
    "attribute_data_extents",
    "container_translation_tree7",
    "crc32c_castagnoli",
    "free_space_salvage"
  ],
  "unsupported_features": [],
  "handled_features": [
    "vbr_fsrs_parsed",
    "superblock_level1",
    "checkpoint_pingpong_arbitration",
    "container_translation_tree7"
  ]
}
```

При обнаружении сжатых файлов (`FILE_ATTRIBUTE_COMPRESSED 0x800`) файл не повреждается и не подменяется нулями: он регистрируется со статусом `unsupported_feature`, причиной `unsupported_compression`, а в матрицу добавляется `cluster_compression`.

---

## Безопасность и целостность

1. **Строго read-only**: чтение выполняется через `FileStream` с `FileAccess.Read` и `FileShare.Read`. Ни один байт на диске не модифицируется.
2. **Верификация неизменности SHA256**: SHA256 исходного образа рассчитывается до начала сканирования и повторно проверяется после завершения. Отчёт фиксирует `SourceUnchanged = true`.
3. **Честность верификации**: CRC32-C верифицирует только метаданные ReFS. Для исторических файлов и кандидатов из свободного пространства свойство `ContentAuthenticityVerified` строго устанавливается в `false`, а в отчёт включается явное предупреждение.
4. **Защита от повреждений и атак**:
   - `NoLinks`: запрещены символические ссылки и junction points в путях источника и назначения.
   - Ограничения бюджета памяти и глубины: `MaximumTreeDepth = 32`, `MaximumDirectoryDepth = 64`, `MaximumDirectories = 20000`, `MaximumEntries = 1000000`.
   - Изоляция временных файлов: при отмене операции все файлы `.partial` немедленно удаляются; повреждённые артефакты не остаются на диске.

---

## Воспроизведение тестов offline

Для автономной верификации без сети и внешних утилит в `tests/fixtures/refs/` сохранены 10 эталонных синтетических томов с `manifest.json`.

```powershell
# 1. Распаковка эталонных фикстур
& .build\engine-env\Scripts\python.exe tests\refs_fixture_generator.py --extract tests\fixtures\refs --destination .build\refs-fixtures-current

# 2. Сборка приложения
.\build.ps1 -Action Build

# 3. Сборка и запуск тестового набора ReFS
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:exe /out:".build\app\RefsRecoveryTests.exe" /reference:".build\app\USB-Recovery.exe" /reference:System.Web.Extensions.dll /warnaserror+ "tests\RefsRecoveryTests.cs"
& ".build\app\RefsRecoveryTests.exe" ".build\refs-fixtures-current"

# 4. Полный прогон offline-проверок качества
powershell -ExecutionPolicy Bypass -File scripts\test.ps1 -Python312 .build\engine-env\Scripts\python.exe
```

---

## Доказательная база и тестовые сценарии

| Сценарий | Описание проверки | Ожидаемый результат |
|---|---|---|
| `refs-v12-minimal` | ReFS v1.2, блоки 16 КиБ, resident + non-resident экстенты | 100% совпадение SHA256 содержимого файлов |
| `refs-v34-minimal` | ReFS v3.4, блоки 4 КиБ, MSB+ B+ дерево, Tree 7 трансляция | Корректное чтение файлов и матрица 3.4 |
| `refs-v34-nested-dirs` | Трехуровневая иерархия каталогов (`Documents/Work/report.pdf`) | Полная реконструкция относительного пути |
| `refs-v34-discontiguous` | Фрагментированный файл с 4 экстентами через полосы контейнеров | Побайтное совпадение файла (20480 байт) |
| `refs-backup-vbr` | Сектор 0 занулён; резервный VBR в конце тома | Автоматическое переключение на Backup VBR |
| `refs-checkpoint-pingpong` | Чекпоинт 31 (seq 42) vs Чекпоинт 32 (seq 43) | Выбор чекпоинта с sequence 43 |
| `refs-corrupted-crc` | Битовое повреждение узла B+ дерева | Отклонение с `metadata_checksum_mismatch` |
| `refs-unsupported-compression` | Файл с атрибутом сжатия 0x800 | Отклонение с `unsupported_compression` |
| `refs-unicode-surrogates` | Кириллица, иероглифы, пробелы и эмодзи суррогаты (`🚀`) | Точное сохранение имени `Project🚀Plan.txt` |
| `refs-deleted-salvage` | Непривязанный лист B+ дерева в свободном пространстве | Восстановление `deleted_secret.doc` |
