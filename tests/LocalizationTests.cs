using System;
using UsbRecovery;

public static class LocalizationTests
{
    static int checks;

    static void Check(bool condition, string description)
    {
        checks++;
        if (!condition) throw new Exception(description);
    }

    public static int Main(string[] args)
    {
        // 1. Initial culture check
        var initial = Localization.Current;
        Check(initial == Language.English || initial == Language.Russian, "initial language is valid enum");

        // 2. Explicit switch to English
        Localization.Current = Language.English;
        Check(Localization.Current == Language.English, "explicit set to English");
        Check(Localization.T("AppTitle").Contains("USB Recovery"), "English AppTitle contains USB Recovery");
        Check(Localization.T("BtnScan") == "Scan", "English BtnScan is Scan");
        Check(Localization.T("BtnStop") == "Stop", "English BtnStop is Stop");
        Check(Localization.T("BtnExport") == "Export", "English BtnExport is Export");
        Check(Localization.T("SectionRecovery") == "RECOVERY", "English SectionRecovery is RECOVERY");
        Check(Localization.T("FooterPrivacy").Contains("100% Offline"), "English Footer contains 100% Offline");

        // 3. Explicit switch to Russian
        Localization.Current = Language.Russian;
        Check(Localization.Current == Language.Russian, "explicit set to Russian");
        Check(Localization.T("AppTitle").Contains("Recovery"), "Russian AppTitle contains Recovery");
        Check(Localization.T("BtnScan") == "Сканировать", "Russian BtnScan is Сканировать");
        Check(Localization.T("BtnStop") == "Остановить", "Russian BtnStop is Остановить");
        Check(Localization.T("BtnExport") == "Экспорт", "Russian BtnExport is Экспорт");
        Check(Localization.T("SectionRecovery") == "ВОССТАНОВЛЕНИЕ", "Russian SectionRecovery is ВОССТАНОВЛЕНИЕ");
        Check(Localization.T("FooterPrivacy").Contains("Локальная"), "Russian Footer contains Локальная");

        // 4. Toggle functionality
        Localization.Current = Language.English;
        Localization.ToggleLanguage();
        Check(Localization.Current == Language.Russian, "toggle from EN -> RU");
        Localization.ToggleLanguage();
        Check(Localization.Current == Language.English, "toggle from RU -> EN");

        // 5. Event firing
        bool fired = false;
        Action handler = () => { fired = true; };
        Localization.LanguageChanged += handler;
        try
        {
            Localization.Current = Language.Russian;
            Check(fired, "LanguageChanged event fired on change");
            fired = false;
            Localization.Current = Language.Russian;
            Check(!fired, "LanguageChanged event does not fire when set to same language");
        }
        finally
        {
            Localization.LanguageChanged -= handler;
            Localization.Current = initial; // Restore initial
        }

        // 6. Unknown key fallback
        string missing = Localization.T("NonExistentKey_XYZ", "FallbackValue");
        Check(missing == "FallbackValue", "missing key returns fallback");

        Console.WriteLine("PASS Localization: {0} checks; bilingual English and Russian dictionary mappings and event dispatch verified.", checks);
        return 0;
    }
}
