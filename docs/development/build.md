# Собрать и проверить Recovery

Разработка ведётся под Windows x64 с .NET Framework 4.8. Для обычного использования достаточно [готового выпуска](https://github.com/fl1nky/usb-recovery/releases/latest): устанавливать Python или компилятор не требуется

## Подготовить зависимости

```powershell
git clone https://github.com/fl1nky/usb-recovery.git
Set-Location usb-recovery
```

В Git находятся исходники и сценарии. Большие исполняемые зависимости, колёса Python и сторонние исходники поставляются с переносимым выпуском. Распакуй его целиком и скопируй в клон:

| Из распакованного выпуска | В корень клона |
|---|---|
| `tools` | `tools` |
| `source/helpers/recovery_engine/wheels` | `helpers/recovery_engine/wheels` |
| `source/helpers/recovery_engine/dependency-sources` | `helpers/recovery_engine/dependency-sources` |
| `source/vendor/iphone-backup-decrypt` | `vendor/iphone-backup-decrypt` |

Не заменяй текущие исходники обработчика кодом из старого выпуска. Колёса проверяются по `SHA256.json` и `requirements-wheel-lock.txt`, сторонние исходники хранения — по `storage-dependencies.json`. Каталоги `tools`, `vendor`, `wheels` и `dependency-sources` не входят в историю Git

## Собрать интерфейс

В PowerShell из корня проекта:

```powershell
.\build.ps1
```

По умолчанию выполняется действие `Build`. Оно вызывает `scripts/build-app.ps1`, использует компилятор .NET Framework из Windows и создаёт `.build/app/USB-Recovery.exe`. Проект для редактора находится в `src/Recovery/Recovery.csproj`. Готовые обработчики читаются из корневого `tools` через `ApplicationPaths`

## Пересобрать обработчик

Для разработки нужен Windows x64 Python 3.12. Если он выбран в `PATH`, проверь версию и выполни:

```powershell
$taskPython = (Get-Command python.exe -ErrorAction Stop).Source
& $taskPython -c 'import sys; assert sys.version_info[:2] == (3, 12), sys.version'
if ($LASTEXITCODE -ne 0) { throw 'Выбери интерпретатор Python 3.12' }
.\build.ps1 -Action Helper -Python312 $taskPython
```

Если `python.exe` в `PATH` относится к другой версии, укажи в `$taskPython` полный путь к установленному Python 3.12. При уже созданном `.build/engine-env` параметр можно опустить

`scripts/build-helper.ps1` создаёт окружение в `.build/engine-env`, устанавливает закреплённые локальные зависимости без обращения к индексу пакетов, запускает выбранные Python-регрессии и собирает `tools/recovery-helper` через PyInstaller. Офлайн-комплект следующей пересборки сохраняется в `tools/recovery-helper/rebuild`

## Собрать переносимый комплект

```powershell
.\build.ps1 -Action Package
```

Для упаковки уже должны существовать `.build/app/USB-Recovery.exe`, готовый helper, PhotoRec/TestDisk и ADB в `tools`. `scripts/package.ps1` сначала создаёт отдельную промежуточную папку, затем публикует `dist/USB-Recovery`. Предыдущий комплект перемещается в `.build/previous-packages`, а контрольные суммы исполняемых файлов записываются в `package-sha256.json`

В `dist/USB-Recovery` находятся готовая программа, `tools`, документация и папка `source` с `src`, `scripts`, `helpers`, `tests`, `vendor`, `docs` и корневым `build.ps1`. Это комплект для локального запуска и пересборки; разработческие окружения и восстановленные личные данные в него не входят

## Проверить готовый комплект

```powershell
.\build.ps1 -Action Test
```

`scripts/test.ps1` по умолчанию проверяет `dist/USB-Recovery`, запускает `QualityOfflineTests.ps1`, `TelegramOfflineTests.ps1`, `UsbOfflineTests.ps1` и проверку привязки отчётов к файлам поставки. Для проверяющих Python-сценариев используется `.build/engine-env/Scripts/python.exe`; другой интерпретатор передаётся напрямую сценарию:

```powershell
.\scripts\test.ps1 -Python312 $taskPython
```

Офлайн-проверки временно блокируют сеть Windows Firewall и требуют прав администратора. Некоторые наборы ожидают заранее подготовленные искусственные образы в `.build` и закреплённые образцы в `tests`; чистый клон без них не является полной тестовой средой. Отсутствующие образцы восстанавливаются из того же выпуска или создаются соответствующими сценариями в `tests`. Личные файлы, профили и физические устройства не используются вместо тестовых данных

Для проверки больших фрагментированных видео `scripts/test.ps1` использует `.build/media-scale-fixtures-01`. Если набора нет, сценарий ищет закреплённый `ffmpeg.exe` в `tools/benchmarks/ffmpeg` и создаёт искусственные образы через `tests/build_media_scale_fixtures.py`. SHA256 разработческого FFmpeg: `3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec`; рядом нужен `ffprobe.exe`. Этот инструмент требуется для подготовки и независимой проверки образцов, готовой программе он не нужен. Большие образы остаются в `.build` и не загружаются в Git

Контрольные проверки интерфейса `ArchiveTextUiTests.ps1`, протокола `ArchiveTextProtocolAuditTests.ps1` и коротких заголовков `MediaRangeAnchorAuditTests.ps1` собирают отдельные искусственные приложения. Они запускаются отдельно от набора, проверяющего настоящие переносимые EXE

Для полного цикла после подготовки зависимостей и образцов:

```powershell
.\build.ps1 -Action All -Python312 $taskPython
```

`All` выполняет `Build`, `Helper`, `Package`, `Test` по порядку. Упаковка сама по себе не подтверждает успешную приёмку; после изменений исполняемых файлов нужные проверки запускаются заново. Проверки реальных Android/iPhone и физических носителей учитываются отдельно

Новые контрольные наборы: MD разворачивается из закреплённых gzip без сети; ext4 — через `ext4_fixture_generator.py --extract`. Для первого создания независимого HPROF-контроля нужен JDK с `java` и `javac` в PATH. Это зависимость разработчика, готовая программа её не использует
