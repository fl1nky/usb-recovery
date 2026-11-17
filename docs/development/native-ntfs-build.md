# Сборка NTFS-компонента

Для разработки нужны Windows x64, .NET Framework 4.8 и Python 3.12/3.14 x64. Готовая программа использует включённые исполняемые файлы; установка Python пользователю не нужна.

Команды выполняются из корня репозитория в PowerShell. Архивы проверяются по SHA256/SHA512; компилятор распаковывается в `.build`, установщики и исходный `testdisk.exe` не запускаются.

```powershell
./scripts/restore-native-build-inputs.ps1
py -3.14 scripts/prepare-native-toolchain.py --destination .build/native-toolchain --archive-cache .build/native-archives --offline --runtime-sources
py -3.14 scripts/build-native-recovery.py --toolchain .build/native-toolchain --archive-cache .build/native-archives --testdisk-archive .build/native-archives/upstream/testdisk-7.2-source.tar.bz2 --ntfs-archive .build/native-archives/upstream/ntfs-3g_ntfsprogs-2026.9.28.tgz --destination .build/native-build
./build.ps1 -Action Native -NativeRuntime .build/native-build/runtime
```

После этого обычная сборка приложения и helper:

```powershell
py -3.12 scripts/bootstrap-build.py --native-tools
./build.ps1 -Action Build
./build.ps1 -Action Helper -Python312 (py -3.12 -c "import sys; print(sys.executable)")
./build.ps1 -Action Package
```

Результат — `dist/USB-Recovery`. Упаковка проверяет бинарные файлы, соответствующие исходники и лицензии NTFS-компонента. Предыдущие локальные комплекты сохраняются в `.build/previous-packages`.

Полный NTFS-тест выполняет [процедура CI](../../.github/workflows/ntfs-checkpoints.yml). Исходные образцы и искусственно изменённые копии разделены в результатах; они не заменяют испытания на настоящей флешке. Зашифрованные и сжатые NTFS-потоки этот обработчик не декодирует.
