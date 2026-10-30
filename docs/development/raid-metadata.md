# Чтение Linux MD metadata

`RaidMetadataProbe` читает метаданные только из предоставленных завершённых RAW-образов компонентов. Он не открывает физические диски, не запускает mdadm, не подключает массив и не меняет исходники

## API

```csharp
var report = RaidMetadataProbe.Probe(images, cancellationToken, (done, total) => { });
// report.Members: распознанные записи, формат, UUID, role/dev_number, events,
// data offset/size, checksum, причины ограничения
// report.Groups: массивы по UUID
// group.Configuration != null только при Status == "candidate"
```

`Group.Configuration` — предложение для проверки человеком. `MetadataOnly` и `RequiresReview` остаются `true`, `DataIntegrityEstablished` — `false`. Автоматический запуск сборки не выполняется; существующий `RaidImageBuilder` отдельно проверяет зеркала/P/Q, где избыточность позволяет такую проверку

## Проверки и границы

- 0.90 little/big endian: суперблок 4 КиБ перед последней зарезервированной областью 64 КиБ, host-endian folded additive checksum; 1.0 — конец, 1.1 — начало, 1.2 — смещение 4 КиБ; версии 1.x имеют little-endian поля и checksum по объявленной таблице ролей
- Проверяются UUID, таблица и номер устройства, активная роль, event counters, схема, chunk size, границы данных и суперблока. `dev_number` не принимается за порядок роли
- Поддержаны только схемы существующего сборщика: равномерный RAID0, RAID1, перечисленные RAID5/6, RAID10 near=2/far=1 из соседних пар при чётном количестве от четырёх участников
- Разные поколения/events, геометрия, роли, повторные устройства и несколько суперблоков не выбираются автоматически. `unsupported`, `inconsistent` и `ambiguous` не содержат готовой конфигурации
- Не полностью синхронизированные/dirty массивы, reshape/recovery/replacement, активные bad-block mappings, journal/PPL/clustered metadata и неизвестные features отклоняются. Наличие bitmap допускается только при завершённой синхронизации
- Разноразмерные RAID0 zones, DDF/IMSM/контроллеры, угадывание неизвестной схемы, разделы внутри whole-disk образов и Alpha-вариант legacy checksum не входят в реализацию. Образ должен начинаться с начала самого MD-компонента
- Максимум 128 предоставленных файлов; читаются и повторно проверяются только документированные диапазоны до 4 КиБ каждый, до 32 КиБ на файл. Проверяются file identity/size/mtime, hardlinks и reparse paths; полный hash всех данных при таком быстром probe не вычисляется

Checksum метаданных обнаруживает повреждение, но не удостоверяет оригинальность массива или отсутствие намеренных правок. `SourceUnchanged` относится к проверенным метаданным и идентичности файла во время чтения; после probe сборщик заново открывает и проверяет образы

## Воспроизводимые образцы

В `tests/fixtures/raid-md` сохранены 23 небольших gzip-образца из [официального dissect.volume](https://github.com/fox-it/dissect.volume/tree/d2da189112cae3a627f96d9de78341193eb6dc52/tests/_data/md), commit `d2da189112cae3a627f96d9de78341193eb6dc52`. SHA256 сверены с LFS pointers; в manifest закреплены также hashes и размеры распакованных файлов. LICENSE/COPYRIGHT исходного набора приложены. Суммарный размер сжатых образцов около 130 КиБ, распакованные файлы остаются в `.build`

```powershell
.build/engine-env/Scripts/python.exe -B tests/build_raid_md_fixtures.py --destination .build/raid-metadata-fixtures
```

Нужна новая пустая папка. Генератор работает без сети и отдельно маркирует производные геометрии 1.0/1.1, big endian, uniform RAID0, clean-state RAID6 и четырёхдисковый RAID10. Это проверки ветвей интерпретации, не новые mdadm-запуски и не независимое доказательство целостности этих производных данных

`RaidMetadataProbeTests.cs`: 2345 проверок. Независимые опубликованные 0.90/1.2-образцы распознаются; существующий сборщик по предложениям probe извлекает по 512 эталонных блоков из опубликованных чистых RAID1 и RAID5. Эталоны взяты из [upstream test_md.py](https://github.com/fox-it/dissect.volume/blob/d2da189112cae3a627f96d9de78341193eb6dc52/tests/md/test_md.py), а не из нашего генератора. Случаи с неполным resync и разноразмерными зонами сохраняются как ограничения

Местного mdadm не было: доступный WSL содержал только Docker environment, Docker daemon не работал. Службы не менялись, новые внешние исполняемые файлы не устанавливались. Реальные пользовательские массивы не испытывались

Первичные форматы: [Linux md_p.h v6.17](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/raid/md_p.h), [Linux md.c](https://github.com/torvalds/linux/blob/v6.17/drivers/md/md.c), [mdadm super0/super1/util](https://github.com/md-raid-utilities/mdadm/tree/c940aae94ac55efadaf741e9dd2a81fb6fbf8794), [kernel MD documentation](https://docs.kernel.org/admin-guide/md.html)
Независимая проверка: `RaidMetadataAuditTests.cs` — 72 проверки, `RaidMetadataUiAuditTests.cs` — 20 проверок реальных элементов интерфейса. Исправлены слишком короткие области данных, пересечение available data с суперблоком 1.0 и неизвестные состояния legacy-участников. Результаты входят в общий офлайн-запуск готового комплекта
