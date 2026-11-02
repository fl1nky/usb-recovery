# Подписи к фотографиям в Android media_v4

Адаптер читает поддержанные TL232-сообщения из медиакэша Telegram Android и проверенных committed WAL-снимков. Удаление строки кэша не доказывает удаление переписки пользователем; `deleted` остаётся `null`.

## Проверить на синтетических данных

Из корня проекта с подготовленным разработческим Python:

```powershell
python -m pytest tests/TelegramMediaCacheTests.py -q
python tests/build_telegram_media_cache_fixtures.py .build/media-cache-fixtures
```

Каталог назначения генератора должен отсутствовать. Генератор не импортирует recovery-код: собственные строки кодируются по официальному формату, настоящая SQLite WAL создаётся при `secure_delete=ON`, SQL-эталон сохраняется до удаления. Согласованные DB/WAL/SHM копируются при остановленном писателе. Это source-only проверка, без собранного helper и реального Android.

## Формат и проверка

Формат закреплён официальным [commit 4de548e](https://github.com/DrKLO/Telegram/commit/4de548e79fed27f1a66fbdff84223321838fe925).

- [MessagesStorage.java](https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/messenger/MessagesStorage.java#L559-L561): пять столбцов `mid`, `uid`, `date`, `type`, `data`; составной ключ `(mid, uid, type)`.
- [MediaDataController.java](https://github.com/DrKLO/Telegram/blob/4de548e79fed27f1a66fbdff84223321838fe925/TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java#L4556-L4562): BLOB декодируется как полное сообщение.

Читатель требует точный порядок, SQL-типы и ключ. Дополнительные, generated, виртуальные и `WITHOUT ROWID` схемы отвергаются. Поддержан только `type=0` с полностью прочитанным photo-media сообщением слоя 232. Конструктор, SQL `mid`, `uid` и `date` сверяются независимо. Секретные dialog IDs, неизвестные поля и другие медиа не интерпретируются догадкой.

Подпись сохраняется как `telegram_media_cache` с состоянием `current_cache_record` либо `historical_cache_record`. История получает привязку к проверенному WAL commit и хешам снимка. Непроверенный WAL не доказывает текущее состояние. Исходный DB/WAL/SHM не меняется; SQLite открывает рабочую копию.

## Происхождение и объединение

Путь данных: `Analyzer.sqlite` → `telegram_media_cache.photo_captions` → строгий TL-reader → публикация с происхождением кэша.

Совпадение подтверждённых source/account scope, dialog/message IDs и полного TL-body SHA позволяет объединить кэш с основной записью. Основная запись сохраняет свои статус, текст и доказательства; кэш добавляет источник. Разные байты при одинаковых IDs и разные аккаунты не объединяются. Повторные кэш-источники ограничены десятью; достижение предела отмечается.

Фото-метаданные не означают наличие фотографии: сохраняется `photo_reference_only`, Android attachment path не разрешается, изображение из этого кэша не извлекается. Отсутствующие имена автора остаются неизвестными.

## Границы

Адаптер не исследует свободные блоки, произвольные дампы, зашифрованные источники, профили или устройства. Затёртые байты не восстанавливаются. Secure-delete positive относится к сохранившейся ранней WAL-версии, а не к чтению затёртой текущей страницы.

Цепочка доказательств: официальная схема → независимый SQLite/SQL-эталон → source-only тесты → будущая отдельная сборка helper и portable-приёмка. Ранее принятый runtime этот исходник не подтверждает.
