# Чтение разметки RAID (Linux MD, Intel IMSM, SNIA DDF, Windows Storage Spaces)

`RaidMetadataProbe` читает метаданные только из предоставленных завершённых RAW-образов компонентов. Он не открывает физические диски, не запускает mdadm или драйверы контроллеров, не подключает массив и не меняет исходники.

## API

```csharp
var report = RaidMetadataProbe.Probe(images, cancellationToken, (done, total) => { });
// report.Members: распознанные записи, формат ("0.90", "1.x", "imsm", "ddf", "storage-spaces"),
// UUID, role/dev_number, events, data offset/size, checksum, причины ограничения
// report.Groups: массивы по UUID
// group.Configuration != null только при Status == "candidate"
```

`Group.Configuration` — предложение для проверки человеком. `MetadataOnly` и `RequiresReview` остаются `true`, `DataIntegrityEstablished` — `false`. Автоматический запуск сборки не выполняется; существующий `RaidImageBuilder` отдельно проверяет зеркала/P/Q, где избыточность позволяет такую проверку.

## Поддерживаемые форматы разметки

1. **Linux MD (0.90, 1.0, 1.1, 1.2)**:
   - 0.90 little/big endian: суперблок 4 КиБ перед последней зарезервированной областью 64 КиБ, host-endian folded additive checksum.
   - 1.0 — конец, 1.1 — начало, 1.2 — смещение 4 КиБ; little-endian поля и checksum по объявленной таблице ролей.
2. **Intel Matrix Storage Manager (IMSM / Intel RST)**:
   - Метаданные MPB (1024 байта) размещаются в хвосте диска (`length - 1024`).
   - Сигнатура `Intel Raid ISM Cfg Sig. `, 32-битная аддитивная контрольная сумма по блоку.
   - Декодирование `generation_num`, таблицы дисков, таблицы томов, размера блока, смещения данных и ролей участников.
   - Поддерживаются RAID 0, RAID 1 и RAID 5 (схема `left-asymmetric`).
3. **SNIA DDF (Disk Data Format v1.2)**:
   - Заголовок anchor и запись виртуального диска (512 байт) в хвосте диска (`length - 512`).
   - Сигнатура `0xDE11DE11`, CRC-32 (IEEE 802.3), Virtual Disk Record `0xDD01DD01`.
   - Декодирование UUID массива, GUID диска, уровня RAID, степени размера полосы (stripe unit shift) и роли диска.
4. **Windows Storage Spaces**:
   - Заголовок пула и слабов (512 байт) по смещению 4096 байт.
   - Сигнатура `MSFT\0\0\0\0`, CRC-32 (IEEE 802.3).
   - Поддерживаются типы устойчивости Simple (RAID 0) и Mirror (RAID 1), число колонок, размер слаба, смещение данных и счётчик поколений.

## Проверки и границы

- Проверяются UUID, таблица и номер устройства, активная роль, event counters, схема, chunk size, границы данных и суперблока. `dev_number` не принимается за порядок роли.
- Поддержаны только схемы существующего сборщика: равномерный RAID0, RAID1, перечисленные RAID5/6, RAID10 near=2/far=1 из соседних пар при чётном количестве от четырёх участников.
- Разные поколения/events, геометрия, роли, повторные устройства и несколько суперблоков не выбираются автоматически. `unsupported`, `inconsistent` и `ambiguous` не содержат готовой конфигурации.
- Не полностью синхронизированные/dirty массивы, reshape/recovery/replacement, активные bad-block mappings, journal/PPL/clustered metadata и неизвестные features отклоняются.
- Читаются и повторно проверяются только документированные диапазоны (до 4 КиБ каждый, до 64 КиБ на файл). Проверяются file identity/size/mtime, hardlinks и reparse paths.
- Checksum метаданных обнаруживает повреждение, но не удостоверяет оригинальность массива или отсутствие намеренных правок. `SourceUnchanged` относится к проверенным метаданным и идентичности файла во время чтения; после probe сборщик заново открывает и проверяет образы.

## Воспроизводимые образцы

- `tests/fixtures/raid-md`: 23 gzip-образца из официального dissect.volume (SHA-256 проверены).
- `tests/fixtures/raid-controller`: 15 синтетических gzip-образцов Intel IMSM (RAID 0, 1, 5), SNIA DDF (RAID 0, 1) и Storage Spaces (Simple, Mirror), генерируемых `tests/raid_controller_fixture_generator.py`.
- `tests/RaidControllerRecoveryTests.cs`: 60 проверок декодирования геометрии, сборки образов, проверки CRC/аддитивных сумм и устойчивости к конфликту поколений.
