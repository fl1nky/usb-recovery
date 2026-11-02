# Восстановление по сохранившимся inode ext4

`Ext4Recovery` читает обычный локальный образ и извлекает кандидатов по сохранившейся карте удалённого inode и истории транзакций журнала JBD2. Исходник открывается только для чтения, SHA256 проверяется до и после прохода.

Обычное удаление через ядро Linux может очистить карту inode в активной таблице. В этом случае данные могут сохраниться в кольцевом буфере журнала JBD2 (транзакции до фиксации удаления) или в сохранившейся карте inode (`debugfs` / немедленный сбой). Свободные блоки могли быть перезаписаны после удаления: даже согласованные CRC метаданных не подтверждают исходное содержимое файла.

## Что проверяется

- Суперблок, версия, поддерживаемые feature flags, геометрия и границы раздела.
- Допустимые feature flags:
  - `INCOMPAT_MMP` (0x100) — multi-mount protection: безвреден для read-only восстановления.
  - `INCOMPAT_LARGEDIR` (0x4000) — каталоги >2GB / 3-уровневые htree: линейный обход каталогов ограничен лимитами и безопасен.
  - `RO_COMPAT_ORPHAN_PRESENT` (0x10000) — orphan file (inode 12): стандартен для ядер 5.15+ и безопасен для чтения.
  - `INCOMPAT_RECOVER` (0x4) — незавершённый unmount: выполняется безопасный replay журнала в оперативную память.
- CRC32C суперблока, дескрипторов, bitmap, inode и внешних extent nodes, когда включён `metadata_csum`; старый CRC16 дескрипторов при `gdt_csum`.
- Отсутствие пересечений таблиц inode и bitmap с первичными/резервными superblock и GDT, а также с метаданными других групп.
- Свободный inode, нулевой `links_count`, ненулевой `dtime` (для записей inode на диске), полностью покрытая карта данных без пересечений и циклов.
- Для кандидатов из журнала JBD2 (`journal_transaction_pre_deletion_record`): проверка целостности блока таблицы inode, проверка валидности транзакции и отсутствие коллизий со занятыми блоками в живом bitmap тома.
- Текущая незанятость каждого блока данных и внешнего узла карты (при коллизии с занятым блоком кандидат отклоняется со статусом `currently_allocated_block_conflict`).
- Ограничения объёма, количества inode, кандидатов, каталогов, узлов и результата; отмена оставляет явный незавершённый отчёт.

Поддержаны extent trees и старые direct/indirect maps. В образцах проверены прямые, одно- и двухуровневые indirect pointers, внешний extent node с физически разнесёнными блоками, 1/4 КиБ blocks, 64bit, `metadata_csum_seed`, CRC16 и раздел со смещением 1 МиБ.

`ext4/report.json` содержит исходный SHA256, inode/generation, диапазоны образа, полученный SHA256, причину отказа, список обработанных (`HandledFeatures`) и неподдерживаемых (`UnsupportedFeatures`) флагов тома, а также статус replay журнала (`JournalReplayAttempted`, `JournalReplayApplied`) и количество найденных исторических inode (`JournalHistoricalInodesFound`). `ContentAuthenticityVerified` всегда `false`; успешный файл имеет статус `deleted_inode_candidate`.

## Журнал JBD2 и безопасный replay в памяти

Если том был отмонтирован некорректно (установлен флаг `INCOMPAT_RECOVER` 0x4), `Ext4Recovery` выполняет симуляцию наката журнала:
1. **Поиск журнала**: внутренний журнал определяется по Inode 8 (`s_journal_inum`) через карту extents.
2. **Парсинг суперблока JBD2**: проверяются magic `0xC03B3998`, тип блока, размер блока и валидность последовательности транзакций (`s_start`, `s_sequence`).
3. **In-Memory Overlay**: зафиксированные транзакции (дескрипторные блоки с тегами блоков и коммит-блоки) накладываются в память (`Volume.Overlay`), обновляя дескрипторы групп и битовые карты без изменения файла образа на диске. Исходный файл остаётся неизменным (гарантируется проверкой SHA256).
4. **Исторический поиск (Historical Sweep)**: сканируется весь кольцевой буфер журнала на наличие транзакций, содержащих блоки таблиц inode до удаления файла. Кандидаты, у которых на диске inode уже очищен, извлекаются из журнала при условии валидности метаданных и отсутствия коллизий блоков.
5. **Проверка коллизий**: если хотя бы один блок данных кандидата из журнала помечен как занятый в текущей битовой карте блоков тома, файл бракуется (`AllocationStatus = "currently_allocated_block_conflict"`), предотвращая выдачу чужих или перезаписанных данных.
6. **Интеграция с Evidence**: кандидаты из журнала получают контрактную метку `Kind = "ext4_journal_candidate"`, метод `"ext4 · журнал JBD2"` и статус `"Кандидат ext4 (журнал)"`.

## Имена и ограничения

Имя результата строится из смещения тома, номера inode и generation. Суффикс JPEG/PNG/GIF/WebP/PDF/ZIP выбирается только по сигнатуре текущих байтов и отмечается `ContentTypeHint=..._signature_only`. Суффикс помогает предпросмотру, но не удостоверяет тип, целостность или старое имя.

Проверенные ссылки каталогов и Unicode-имена сохраняются отдельно в `Names`. Directory entry ext4 не содержит generation inode, поэтому даже согласованная ссылка не превращается в подтверждённый исходный путь.

Не выполняются запись на диск, опасная модификация файловой системы или синтез пропущенных байтов. Sparse/unwritten maps, inline/encrypted/compressed/verity/EA inodes, bigalloc, meta_bg и неподдерживаемые features не выдаются за исходные файлы. Образ с пропусками чтения нельзя использовать для подтверждения незанятости блоков.

## Воспроизвести без WSL и сети

В `tests/fixtures/ext4` сохранены 42 сжатых синтетических образа и manifest с SHA256 сжатых и исходных файлов. Они созданы настоящими `mke2fs`/`debugfs` 1.47.3 и детерминированными скриптами расширения; бинарные программы и пользовательские данные в комплект не входят.

`PROVENANCE.txt` описывает происхождение синтетических данных и не задаёт отдельную лицензию.

Из корня подготовленного checkout с Python-окружением сборки:

```powershell
$fixtureRoot = '.build\ext4-offline-' + [Guid]::NewGuid().ToString('N')
& .build\engine-env\Scripts\python.exe tests\ext4_fixture_generator.py --extract tests\fixtures\ext4 --destination $fixtureRoot
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /r:System.Web.Extensions.dll /out:.build\Ext4RecoveryTests.exe src\Recovery\Recovery\Engines\Ext4Recovery.cs tests\Ext4RecoveryTests.cs
& .build\Ext4RecoveryTests.exe $fixtureRoot
```

Нужна новая папка результатов. Распаковщик проверяет имена, размеры, SHA256 и ограничивает объём; WSL не вызывается. Готовая пользовательская программа также не требует WSL или установленного Python.

Чтобы заново получить образцы внешними инструментами, нужен уже установленный WSL `docker-desktop` с `mke2fs` и `debugfs`. Генератор не монтирует образы, не устанавливает пакеты и не меняет службы:

```powershell
$generatedRoot = '.build\ext4-generated-' + [Guid]::NewGuid().ToString('N')
& .build\engine-env\Scripts\python.exe tests\ext4_fixture_generator.py --destination $generatedRoot --distribution docker-desktop
```

## Доказательства и границы проверки

| Доказательство | Вывод | Где проверить |
|---|---|---|
| 433 assertions на 42 реальных и синтетических образах | Положительные случаи совпадают с независимым payload SHA256, флаги MMP/largedir/orphan_present обрабатываются, replay и historical inode работают, повреждённые/неподдерживаемые карты не экспортируются | `tests/Ext4RecoveryTests.cs`, manifest |
| Те же 433 assertions после offline-распаковки | Поддерживаемый набор воспроизводится без вызова Linux-инструментов | `ext4_fixture_generator.py --extract` |
| 18 workflow checks | Реальный конвейер, каталог, сохранение/возобновление прохода, защита от пропусков чтения и выбор ext4 в настройках работают совместно | `tests/Ext4WorkflowTests.cs` |
| 28 независимых integration audit checks | Противоречивые отчёты, неверная привязка к источнику, неполные карты и изменённые файлы не получают прежнее происхождение; дубликат PhotoRec сохраняет ссылку ext4 | `tests/Ext4IntegrationAuditTests.cs` |
| Replay и historical sweep JBD2 | Восстановление удалённого файла из транзакции журнала при затёртом на диске inode; отказ при коллизии блока с занятым | `journal-dirty-replay`, `journal-historical-deleted`, `journal-historical-conflict` |
| Толерантность к benign флагам | Тома с `INCOMPAT_MMP`, `INCOMPAT_LARGEDIR` и `RO_COMPAT_ORPHAN_PRESENT` безопасно сканируются и извлекают файлы | `mmp-feature-tolerated`, `largedir-feature-tolerated`, `orphan-present-tolerated` |
| Мутации указателей с заново рассчитанными CRC | Пересечения, неизвестные features, неверные bounds и циклы отклоняются независимо от раннего checksum-отказа | Случаи `*-valid-crc` в manifest |
| Содержимое свободного блока изменено после удаления | Выдаются текущие байты как кандидат; исходное содержимое не угадывается | `free-data-overwritten` |

Это тесты обычных образов. Восстановление на физических устройствах, удаление через реальное ядро, все варианты ext4 и результаты платных конкурентов этими проверками не подтверждаются.

Первичные форматы: [ext4 checksums](https://docs.kernel.org/filesystems/ext4/checksums.html), [group descriptors](https://docs.kernel.org/filesystems/ext4/group_descr.html), [extent/indirect maps](https://docs.kernel.org/filesystems/ext4/ifork.html), [JBD2 journal](https://docs.kernel.org/filesystems/ext4/journal.html), [e2fsprogs 1.47.3](https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/tree/?h=v1.47.3)
