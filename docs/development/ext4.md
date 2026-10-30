# Восстановление по сохранившимся inode ext4

`Ext4Recovery` читает обычный локальный образ и извлекает кандидатов по сохранившейся карте удалённого inode. Исходник открывается только для чтения, SHA256 проверяется до и после прохода

Обычное удаление через ядро Linux может очистить карту inode. Наши положительные образцы удалены через `debugfs`, который оставляет её доступной. Свободные блоки могли быть перезаписаны после удаления: даже согласованные CRC метаданных не подтверждают исходное содержимое файла

## Что проверяется

- Суперблок, версия, поддерживаемые feature flags, геометрия и границы раздела
- CRC32C суперблока, дескрипторов, bitmap, inode и внешних extent nodes, когда включён `metadata_csum`; старый CRC16 дескрипторов при `gdt_csum`
- Отсутствие пересечений таблиц inode и bitmap с первичными/резервными superblock и GDT, а также с метаданными других групп
- Свободный inode, нулевой `links_count`, ненулевой `dtime`, полностью покрытая карта данных без пересечений и циклов
- Текущая незанятость каждого блока данных и внешнего узла карты
- Ограничения объёма, количества inode, кандидатов, каталогов, узлов и результата; отмена оставляет явный незавершённый отчёт

Поддержаны extent trees и старые direct/indirect maps. В образцах проверены прямые, одно- и двухуровневые indirect pointers, внешний extent node с физически разнесёнными блоками, 1/4 КиБ blocks, 64bit, `metadata_csum_seed`, CRC16 и раздел со смещением 1 МиБ

`ext4/report.json` содержит исходный SHA256, inode/generation, диапазоны образа, полученный SHA256, причину отказа и состояние прохода. `ContentAuthenticityVerified` всегда `false`; успешный файл имеет статус `deleted_inode_candidate`

## Имена и ограничения

Имя результата строится из смещения тома, номера inode и generation. Суффикс JPEG/PNG/GIF/WebP/PDF/ZIP выбирается только по сигнатуре текущих байтов и отмечается `ContentTypeHint=..._signature_only`. Суффикс помогает предпросмотру, но не удостоверяет тип, целостность или старое имя

Проверенные ссылки каталогов и Unicode-имена сохраняются отдельно в `Names`. Directory entry ext4 не содержит generation inode, поэтому даже согласованная ссылка не превращается в подтверждённый исходный путь

Не выполняются journal replay, восстановление истории журнала, ремонт файловой системы или синтез пропущенных байтов. Sparse/unwritten maps, inline/encrypted/compressed/verity/EA inodes, bigalloc, meta_bg, требующий replay журнал и неизвестные features не выдаются за исходные файлы. Образ с пропусками чтения нельзя использовать для подтверждения незанятости блоков

## Воспроизвести без WSL и сети

В `tests/fixtures/ext4` сохранены 36 сжатых синтетических образов и manifest с SHA256 сжатых и исходных файлов. Они созданы настоящими `mke2fs`/`debugfs` 1.47.3; бинарные программы и пользовательские данные в комплект не входят. Объём набора около 1,4 МБ, распаковка — около 1,2 ГБ

`PROVENANCE.txt` описывает происхождение синтетических данных и не задаёт отдельную лицензию

Из корня подготовленного checkout с Python-окружением сборки:

```powershell
$fixtureRoot = '.build\ext4-offline-' + [Guid]::NewGuid().ToString('N')
& .build\engine-env\Scripts\python.exe tests\ext4_fixture_generator.py --extract tests\fixtures\ext4 --destination $fixtureRoot
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /r:System.Web.Extensions.dll /out:.build\Ext4RecoveryTests.exe src\Recovery\Recovery\Engines\Ext4Recovery.cs tests\Ext4RecoveryTests.cs
& .build\Ext4RecoveryTests.exe $fixtureRoot
```

Нужна новая папка результатов. Распаковщик проверяет имена, размеры, SHA256 и ограничивает объём; WSL не вызывается. Готовая пользовательская программа также не требует WSL или установленного Python

Чтобы заново получить образцы внешними инструментами, нужен уже установленный WSL `docker-desktop` с `mke2fs` и `debugfs`. Генератор не монтирует образы, не устанавливает пакеты и не меняет службы:

```powershell
$generatedRoot = '.build\ext4-generated-' + [Guid]::NewGuid().ToString('N')
& .build\engine-env\Scripts\python.exe tests\ext4_fixture_generator.py --destination $generatedRoot --distribution docker-desktop
```

## Доказательства и границы проверки

| Доказательство | Вывод | Где проверить |
|---|---|---|
| 359 assertions на 36 реальных e2fsprogs-образах | Положительные случаи совпадают с независимым payload SHA256, повреждённые/неподдерживаемые карты не экспортируются | `tests/Ext4RecoveryTests.cs`, manifest |
| Те же 359 assertions после offline-распаковки | Поддерживаемый набор воспроизводится без вызова Linux-инструментов | `ext4_fixture_generator.py --extract` |
| 18 workflow checks | Реальный конвейер, каталог, сохранение/возобновление прохода, защита от пропусков чтения и выбор ext4 в настройках работают совместно | `tests/Ext4WorkflowTests.cs` |
| 28 независимых integration audit checks | Противоречивые отчёты, неверная привязка к источнику, неполные карты и изменённые файлы не получают прежнее происхождение; дубликат PhotoRec сохраняет ссылку ext4 | `tests/Ext4IntegrationAuditTests.cs` |
| Мутации указателей с заново рассчитанными CRC | Пересечения, неизвестные features, неверные bounds и циклы отклоняются независимо от раннего checksum-отказа | Случаи `*-valid-crc` в manifest |
| Содержимое свободного блока изменено после удаления | Выдаются текущие байты как кандидат; исходное содержимое не угадывается | `free-data-overwritten` |

Это тесты обычных образов. Восстановление на физических устройствах, удаление через реальное ядро, все варианты ext4 и результаты платных конкурентов этими проверками не подтверждаются

Первичные форматы: [ext4 checksums](https://docs.kernel.org/filesystems/ext4/checksums.html), [group descriptors](https://docs.kernel.org/filesystems/ext4/group_descr.html), [extent/indirect maps](https://docs.kernel.org/filesystems/ext4/ifork.html), [e2fsprogs 1.47.3](https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/tree/?h=v1.47.3)
