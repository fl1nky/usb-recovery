# ReFS: возможности и проверенные границы

`RefsRecovery` открывает образ только для чтения, сохраняет SHA-256 до и после прохода и пишет результат в новую папку `refs`. Контрольная сумма метаданных не удостоверяет подлинность содержимого файла.

## Формат и извлечение

Реализованы uint64-указатели SUPB на два checkpoint, проверка собственных descriptor/контрольных сумм SUPB и CHKP, выбор валидного checkpoint по clock, косвенный заголовок Ministore, ограниченные записи B+ tree, смещение ссылки объекта `value+32` в v3 и `value+0` в v1. У v1 смещения записей имеют размер uint32, контрольная сумма ссылки начинается с descriptor-relative offset 8.

Метаданные v3 собираются из всех адресов ссылки: четыре кластера при 4 КиБ и один при 64 КиБ. Container tree читается по физическим адресам; остальные деревья и данные переводятся через проверенную таблицу контейнеров. Неизвестный контейнер не подменяется физическим адресом. Проверяются CRC32-C, CRC64/NVME и SHA-256. CRC64/NVME использует полином `0x9A6C9329AC4BC9B5`, а не ECMA-182. Пустой, неизвестный или неверный descriptor не считается проверенным.

Файл читается через вложенное дерево атрибутов: inline `$DATA`, текущая версия `0x1000`, структурная карта экстентов и вынесенная запись `0x40`, найденная по паре home object / file ordinal. Пропуски и перекрытия карты отклоняются. Явные unwritten/sparse флаги означают логические нули; соответствующие физические кластеры не читаются.

## Доказательства на 2 ноября 2026

| Проверка | Результат | Что она доказывает |
|---|---|---|
| Полный опубликованный Windows ReFS 3.14, 64 КиБ, SHA-256, образ 8 ГиБ | 776/776 живых имён, 862 148 781 байт | Чтение этого конкретного тома |
| Независимый `forefst`, без изменения его кода | Все 776 размеров и SHA-256 совпали, 0 ошибок извлечения | Побайтовое совпадение двух реализаций на этом образе |
| Замороженный исходник `494baa3` на том же образе | 0 файлов | Предыдущие синтетические PASS не доказывали native-совместимость |
| 6 неизменённых массивов метаданных libfsrefs v1/v3 | Native SUPB/CHKP checksum и descriptor совпадают; изменение бита отвергается | Независимая проверка метаданных, не полный том v1 |
| 13 созданных структурных фикстур + проверки native-метаданных | 169 assertions PASS | Регрессии, включая четыре разнесённых слота страницы |
| 48 adversarial-фикстур, включая положительные границы | 287 assertions PASS | Полные границы extent/branch rows, uint32 checksum length, overflow массива, отсутствующий первый контейнер и прежние проверки |

Источник native-тома: [forefst, закреплённый commit](https://github.com/xbqt/forefst/tree/d4d5fd28942eb14ebe11d90f4eb9342f5e3d7b92/analysis/samples/disks/wininsiderrefs8gtest2). SHA-256 распакованного образа: `246d3c2f969ff6a67d6a9879723de50c20152b0e11d61034e38c4c7851c24ffc`. Большой образ и восстановленные файлы не включены в репозиторий.

Локальные receipts: `.build/refs-real-format-20261102/native-run-04/refs/report.json` и `oracle-contents-02/score.json`. Windows не предоставляет `SEEK_HOLE` этому Python reader: сравнение выполнялось по полностью материализованным байтам проверенного несжатого, non-sparse файла. Это не проверка Windows-драйвером и не доказательство для sparse acquisition.

После независимого review исправлены границы собственных extent/branch-записей, полный uint32 checksum length и отказ от физического чтения неизвестного контейнера. На 35 новых образах замороженный прежний код воспроизвёл 32 ошибочных принятия; исправленный код проходит 287 assertions. Повторный native-проход даёт прежние 776/776 точных файлов: `review-fix-02/score.json`. Эти правки выполнялись только в отдельной рабочей копии `fix/native-format-validation-20261102`.

## Ограничения

Полное восстановление ReFS v1.2 и v3.4 **не подтверждено** независимыми полными томами. Чтение v1-метаданных и собственные фикстуры этого не заменяют. Не реализованы все integrity-stream layouts, сжатие, ADS/snapshots и неоднозначные backing-записи; неподдерживаемые записи сохраняются в отчёте с причиной.

Проход вне посещённых деревьев ограничен `MaximumSalvageBlocks` (4096 по умолчанию); усечение явно ставит `Limited`. Такой результат называется `unreferenced_refs_candidate`, имеет `MetadataChecksumVerified=false`, `ContentAuthenticityVerified=false` и не содержит `DeletionEvidence`. Непосещённый лист не доказывает удаление или свободное состояние кластеров. Известная повреждённая ссылка не выдаётся повторно как непроверенный salvage.

## Повторение регрессий

```powershell
.\.build\engine-env\Scripts\python.exe tests\refs_fixture_generator.py --extract tests\fixtures\refs --destination .build\refs-fixtures-current
.\.build\engine-env\Scripts\python.exe tests\adversarial_refs_generator.py
```

C# harnesses `RefsRecoveryTests` и `RefsChallenger1Tests` собираются с проверяемой сборкой приложения и `System.Web.Extensions.dll`. Эти результаты относятся к исходникам; новый portable-пакет и устройства требуют отдельной проверки.

Первичные описания: [libfsrefs](https://github.com/libyal/libfsrefs/blob/77e1b7ba68cf225ec888a61e9784fb9a93a0156f/documentation/Resilient%20File%20System%20%28ReFS%29.asciidoc), [современная архитектура checksum](https://github.com/xbqt/forefst/blob/d4d5fd28942eb14ebe11d90f4eb9342f5e3d7b92/docs/concepts/checksum_architecture.md), [page references](https://github.com/xbqt/forefst/blob/d4d5fd28942eb14ebe11d90f4eb9342f5e3d7b92/docs/structures/page_references.md), [записи каталогов](https://github.com/xbqt/forefst/blob/d4d5fd28942eb14ebe11d90f4eb9342f5e3d7b92/docs/structures/directory_entries.md).
