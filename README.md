# USB Recovery

[English](README.md) · [Русский](README.ru.md)

Recover files from USB drives and disk images on Windows x64, and search surviving local Telegram data.

**[Download the latest Windows x64 ZIP](https://github.com/fl1nky/usb-recovery/releases/latest)**

Extract the whole ZIP and run `USB-Recovery.exe`. Keep its folders together. No separate Python installation is required.

The steps below use the Russian button labels shown in the recovery panels.

## Recover files from a USB drive

1. Stop writing to the drive after deleting a file.
2. Open **Drives & Images / «Флешки и образы»**, select the drive and use **«Папка…»** to choose a folder on a **different physical disk**.
3. Select **«Фотографии»** for photos, then click **«Начать восстановление»**. The program first creates an image of the USB drive and searches that copy.
4. Open **«Все файлы и экспорт»**, preview and select the files, then click **«Копировать отмеченные»**. Export to a different physical disk too.

## Search local Telegram data

1. Open **Telegram** and click **«Анализировать»**. For your own export, phone copy or dump, choose **«Источник…»** first.
2. Enter keywords and click **«Найти»**. Enable **Regex** for a pattern such as `recipe|пирожк.*`.
3. Check each match's category and source. **«Полный текст»** opens the complete available text.

Recovery depends on the surviving bytes and supported format. A text fragment may have an unknown author, date or chat. An empty result describes the selected source and search settings.

The product is a public beta. Validation uses controlled files and images. Real USB drives and Android/iPhone devices still need separate testing.

[Step-by-step guide](docs/guides/quick-start.md) · [Recovery methods](docs/guides/recovery.md) · [Telegram coverage](docs/guides/media-and-telegram.md) · [Storage formats](docs/guides/storage.md)

[Build and tests](docs/development/build.md) · [AGPLv3 license](LICENSE)

[E01/Ex01 and ddrescue](docs/guides/forensic-images.md)
