# Telegram: длинные остатки и неполный WAL

Два дополнения к [поиску сохранившихся записей](telegram-residual-recovery.md): сборка длинной SQLite-записи из уцелевших overflow-страниц и чтение последнего проверенного коммита перед повреждённым хвостом WAL. Они работают с предоставленной читаемой локальной копией и поддерживаемыми схемами Android Telegram

Ниже описаны изменения проверенных исходников; отдельная проверка переносимой сборки ещё ожидается

## Как искать

1. Передай неподвижную копию базы вместе с одноимёнными `-wal`/`-shm`, если они сохранились. Сохрани исходный комплект отдельно; не открывай его в Telegram для «исправления»
2. Выбери **Telegram → Источник… → Папка / копия телефона… → Анализировать**. Новые методы включены в конвейер анализа без отдельных флагов поиска
3. Введи ключевые слова и нажми **Найти**; для выражения вроде `рецепт|пирожк` включи **Regex**
4. Выбери строку и прочитай происхождение. Фильтр **Удалённые записи (остатки)** и категория **Из резервной копии** отвечают на разные вопросы

Исходники не открываются для записи. Проверка и разбор выполняются на рабочих копиях; ошибочный WAL не удаляется для принудительного чтения базы. При отключении его обычного воспроизведения основная база читается в режиме `immutable`

## Что означает результат

| Случай | Результат | Ограничение вывода |
|---|---|---|
| В свободной области страницы поддерживаемой таблицы остался заголовок длинной записи и полная цепочка свободных overflow-листьев | `deleted_supported_by_evidence`, если ключ отсутствует в текущей таблице; `previous_version_residual` при другом содержимом существующего ключа | Совпадают SQL/TL-ключи и структура, но ручное удаление не доказано; `deleted=null` |
| У WAL есть проверенный коммит перед обрывом, неверной контрольной суммой/солью или пределом чтения | `committed_wal_prefix_snapshot`, категория `backup`, `previous_version=false` для последнего известного коммита | Текущее состояние переписки и факт удаления неизвестны |
| Более ранний полный коммит WAL | Категория `previous` | Это предыдущий зафиксированный снимок, а не доказательство удаления |
| Не хватает страницы, связь повреждена или схема не подтверждена | Полная структурная запись не публикуется | Отдельный текстовый фрагмент, если найден, остаётся фрагментом |

У WAL-снимка **все** страницы, включая схему, берутся из проверенного журнала до выбранного коммита. Недостающие страницы не дополняются нынешней основной базой. Поэтому даже повреждённая основная B-tree не мешает чтению независимого полного снимка, но неполная карта WAL не превращается в достоверную переписку. Незавершённые транзакции и кадры после первой ошибки не становятся историей. Алгоритм коммитов и контрольных сумм описан в [формате WAL SQLite](https://sqlite.org/fileformat2.html#wal_file_format)

Для длинной записи нужны сохранившиеся указатели, полностью читаемая цепочка и совпадение ключей с TL-телом. Занятые страницы, freelist-trunk, циклы и неполные цепочки отвергаются; максимум — 4096 диапазонов вместе с локальной частью. Основа — [overflow-страницы и freelist SQLite](https://sqlite.org/fileformat2.html#cell_payload_overflow_pages)

`sqlite_overflow_chain_verified=true` означает **структурную проверку уцелевшей цепочки**. Она не удостоверяет первоначальный текст: свободные страницы могли раньше повторно использоваться. SHA256 фиксирует найденные байты, а не подлинность переписки

## Где посмотреть байты и замечания

- `sqlite_payload_ranges`: полная упорядоченная карта с `logical_offset`, `bytes`, `sqlite_page`, `physical_source` (`db`/`wal`), `physical_byte_offset`, `wal_frame`
- `sqlite_payload_length`/`sqlite_payload_sha256`: размер и SHA256 всей собранной последовательности; `sqlite_overflow_pages` — номера её продолжений. Прежние `sqlite_record_length`/`sqlite_record_sha256` по-прежнему относятся только к локальной физической части записи
- `wal_commit_frame`, `wal_sha256`, `wal_db_sha256`, `wal_snapshot_sha256`: выбранный коммит и хеши входов/снимка
- `wal_tail_reason`, `wal_validated_prefix_bytes`, `wal_snapshot_latest_known_commit`, `wal_current_state_confirmed=false`: граница проверенного префикса и причина неопределённости

Карты и замечания сохраняются в JSON архива и результатах поиска, в том числе в дополнительных источниках совпавшей записи. Совпадение текста само по себе не объединяет сообщения. Неполная или несогласованная заявленная overflow-карта отбрасывается при чтении архива; её не обрезают до «успешного» доказательства

## Почему восстановление может не сработать

В закреплённом [официальном Android Telegram](https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/messenger/MessagesStorage.java#L304) включены `secure_delete=ON` и WAL. [Secure-delete SQLite](https://sqlite.org/pragma.html#pragma_secure_delete) затирает удаляемое содержимое обычных таблиц; превращение overflow-страницы в freelist-trunk также может уничтожить нужный указатель. После утраты этих байтов программа не достраивает цепочку по догадке. Наличие старого проверенного WAL-снимка оценивается отдельно

## Проверить исходники

| Набор | Что воспроизводит на собственных сгенерированных данных |
|---|---|
| [TelegramOverflowTests.py](../../tests/TelegramOverflowTests.py), [TelegramOverflowAuditTests.py](../../tests/TelegramOverflowAuditTests.py) | Реальный SQLite DELETE длинных записей, карты DB/WAL, secure-delete/trunk, недопустимые связи, отмену и изменение источника |
| [TelegramWalTailTests.py](../../tests/TelegramWalTailTests.py), [TelegramWalTailAuditTests.py](../../tests/TelegramWalTailAuditTests.py) | Хвосты WAL, неполные транзакции, отсутствующие страницы, повреждённую базу, дубликаты источников и окончательную проверку SHA256 |
| [ArchiveRecoveryProvenanceTests.py](../../tests/ArchiveRecoveryProvenanceTests.py) | Сохранение полных карт/типов при поиске и отказ от некорректной provenance |

Из корня подготовленной среды разработчика:

```powershell
.\.build\engine-env\Scripts\python.exe tests\TelegramOverflowTests.py
.\.build\engine-env\Scripts\python.exe tests\TelegramOverflowAuditTests.py
.\.build\engine-env\Scripts\python.exe tests\TelegramWalTailTests.py
.\.build\engine-env\Scripts\python.exe tests\TelegramWalTailAuditTests.py
.\.build\engine-env\Scripts\python.exe tests\ArchiveRecoveryProvenanceTests.py
```

Цепочка доказательств: генераторы [overflow](../../tests/build_telegram_overflow_fixtures.py) и [WAL](../../tests/build_telegram_wal_tail_fixtures.py) создают известные SQLite-транзакции → тесты сравнивают текст, физические диапазоны и хеши источников → [sqlite_deleted.py](../../helpers/recovery_engine/sqlite_deleted.py), [sqlite_history.py](../../helpers/recovery_engine/sqlite_history.py) и [telegram_auto.py](../../helpers/recovery_engine/telegram_auto.py) реализуют соответствующие пути, [archive_search.py](../../helpers/recovery_engine/archive_search.py) сохраняет проверяемую карту при поиске

Срез этого этапа: на собранных EXE/helper пройдены 215 [проверок полного конвейера](../../tests/TelegramRecoveryPortableTests.cs) по 15 WAL-примерам и четырём размерам страниц, плюс 17 проверок DTO/отображения. Полный автономный набор и хеши двоичных файлов приведены в [отчёте этапа](telegram-video-release.md). Настоящие телефоны и личные переписки в этих тестах не использовались
