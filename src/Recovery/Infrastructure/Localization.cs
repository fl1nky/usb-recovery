using System;
using System.Collections.Generic;
using System.Globalization;

namespace UsbRecovery
{
    public enum Language
    {
        English,
        Russian
    }

    public static class Localization
    {
        public static event Action LanguageChanged;

        static Language currentLanguage;
        static readonly Dictionary<string, string> En = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, string> Ru = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        static Localization()
        {
            InitializeDictionaries();
            // Default to English unless system culture is Russian/Belarusian/Ukrainian/Kazakh
            string culture = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLowerInvariant();
            currentLanguage = (culture == "ru" || culture == "be" || culture == "uk" || culture == "kk")
                ? Language.Russian
                : Language.English;
        }

        public static Language Current
        {
            get { return currentLanguage; }
            set
            {
                if (currentLanguage != value)
                {
                    currentLanguage = value;
                    var handler = LanguageChanged;
                    if (handler != null) handler();
                }
            }
        }

        public static void ToggleLanguage()
        {
            Current = (Current == Language.English) ? Language.Russian : Language.English;
        }

        public static string T(string key, string fallback = null)
        {
            var dict = (currentLanguage == Language.Russian) ? Ru : En;
            string value;
            if (dict.TryGetValue(key, out value)) return value;
            if (fallback != null) return fallback;
            // Fallback to English dict if Russian missed, or Russian dict if English missed
            var alt = (currentLanguage == Language.Russian) ? En : Ru;
            if (alt.TryGetValue(key, out value)) return value;
            return key;
        }

        static void Map(string key, string english, string russian)
        {
            En[key] = english;
            Ru[key] = russian;
        }

        static void InitializeDictionaries()
        {
            Map("AppTitle", "USB Recovery — High-Performance Data Recovery", "Recovery — восстановление данных");
            Map("RecoverySubtitle", "DATA RECOVERY", "ВОССТАНОВЛЕНИЕ ДАННЫХ");
            Map("SectionRecovery", "RECOVERY", "ВОССТАНОВЛЕНИЕ");
            Map("NavUsb", "Drives & Images", "Флешки и образы");
            Map("NavStorage", "APFS · RAID · BitLocker", "APFS · RAID · BitLocker");
            Map("SectionChats", "MESSENGERS", "ПЕРЕПИСКИ");
            Map("NavTelegram", "Telegram", "Telegram");
            Map("SectionSources", "SOURCES", "ИСТОЧНИКИ");
            Map("NavAndroid", "Android", "Android");
            Map("NavIphone", "iPhone", "iPhone");
            Map("NavFiles", "Import & Cache", "Импорт и кэш");
            Map("FooterPrivacy", "100% Offline Processing\r\nNo Subscriptions · Zero Telemetry", "Локальная обработка\r\nБез подписки и облака");
            Map("MotionToggle", "Animations", "Анимации");
            Map("LanguageToggle", "🌐 English", "🌐 Русский");
            Map("BtnScan", "Scan", "Сканировать");
            Map("BtnStop", "Stop", "Остановить");
            Map("BtnResume", "Resume", "Продолжить");
            Map("BtnExport", "Export", "Экспорт");
            Map("BtnSettings", "Settings", "Настройки");
            Map("BtnGallery", "Gallery", "Галерея");
            Map("SelectDriveOrImage", "Select a drive or disk image to begin", "Выбери диск или образ для поиска");
            Map("FullScanProfile", "Full Recovery (All Filesystems & Carving)", "Полное восстановление (все ФС и поиск)");
            Map("FastScanProfile", "Fast Metadata Scan", "Быстрый поиск по метаданным");
            Map("PhotoProfile", "Photos & Media Reassembly", "Сборка фото и медиа");
            Map("TelegramProfile", "Telegram Artifacts", "Артефакты Telegram");
        }
    }
}
