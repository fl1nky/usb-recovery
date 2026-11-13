using System;
using System.IO;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace UsbRecovery
{
    public static class TelegramAnalysisService
    {
        // Explicit roots are provided by development fixtures only. The normal
        // button uses the worker's bounded, Telegram-specific discovery list.
        public static HelperResult Analyze(string destination, string[] roots, CancellationToken cancel, Action<string> progress)
        { return AnalyzeCore(destination, roots, "", false, null, cancel, progress); }
        public static HelperResult AnalyzeSelected(string destination, string source, string query, bool useRegex, CancellationToken cancel, Action<string> progress)
        { return AnalyzeSelected(destination, source, query, useRegex, null, cancel, progress); }
        public static HelperResult AnalyzeSelected(string destination, string source, string query, bool useRegex, Dictionary<string,string> secrets, CancellationToken cancel, Action<string> progress)
        {
            object roots = String.IsNullOrEmpty(source) ? null : new object[] { new { path = source, kind = File.Exists(source) ? "dump" : "explicit" } };
            return AnalyzeCore(destination, roots, query, useRegex, secrets, cancel, progress);
        }
        static HelperResult AnalyzeCore(string destination, object roots, string query, bool useRegex, Dictionary<string,string> secrets, CancellationToken cancel, Action<string> progress)
        {
            cancel.ThrowIfCancellationRequested();
            string output = Path.GetFullPath(destination);
            if (output.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("ANALYSIS_PATH_UNSAFE");
            var scratch = new DirectoryInfo(output + ".work");
            for (var ancestor = scratch; ancestor != null; ancestor = ancestor.Parent) if (ancestor.Exists && (ancestor.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("ANALYSIS_PATH_UNSAFE");
            if (scratch.Exists || File.Exists(scratch.FullName) || Directory.Exists(output) || File.Exists(output)) throw new IOException("ANALYSIS_PATH_EXISTS");
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            scratch.Create(acl);
            try {
                var result = HelperClient.Run(HelperClient.Executable, new { protocol = 1, operation = "telegram_analyze", destination = output, secrets = secrets, options = new { roots = roots, scan_fragments = roots != null, fragment_query = query, query_mode = useRegex ? "regex" : "literal", scratch = scratch.FullName, application_directory = ApplicationPaths.RuntimeRoot } }, cancel, progress);
                if (result.Status != "error") {
                    if (!String.Equals(Path.GetFullPath(result.Archive ?? ""), output, StringComparison.OrdinalIgnoreCase) || !File.Exists(Path.Combine(output, "messages.jsonl")) || File.Exists(Path.Combine(output, "job.incomplete"))) throw new IOException("ANALYSIS_PROTOCOL_ERROR");
                }
                return result;
            } finally { try { HelperClient.RemoveWork(scratch); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
        }
        public static string Summary(HelperResult result)
        {
            if (result.Status == "error") return "Не удалось завершить чтение источника. Готовый архив не создан.";
            string text = "Записей истории Telegram: " + result.HistoryMessages + ". Читаемых источников: " + result.ReadableSources + ".";
            if(result.DeletedSupportedRecords>0)text+=" Сохранившихся остатков удалённых записей: "+result.DeletedSupportedRecords+". Причина удаления не установлена.";
            if(result.StructuredFragmentRecords>0)text+=" Структурных фрагментов: "+result.StructuredFragmentRecords+" (связи с чатом могут быть неизвестны).";
            if (result.NativeRecords > 0) text += " Записей в поддерживаемых локальных форматах: " + result.NativeRecords + ".";
            if (result.DraftRecords > 0) text += " Черновиков Desktop: " + result.DraftRecords + " (неотправленный текст, не история и не удалённые сообщения).";
            if (result.ScheduledRecords > 0) text += " Запланированных записей Android: " + result.ScheduledRecords + " (дата означает время планируемой отправки).";
            if (result.UnsentRecords > 0) text += " Неотправленных записей iOS: " + result.UnsentRecords + ".";
            if (result.PreviousRecords > 0) text += " Предыдущих версий из проверенного журнала: " + result.PreviousRecords + ".";
            if (result.NotificationRecords > 0) text += " Сохранённых уведомлений: " + result.NotificationRecords + " (могут содержать только часть сообщения).";
            if (result.FragmentRecords > 0) text += " Текстовых фрагментов: " + result.FragmentRecords + " (автор, дата и принадлежность Telegram не подтверждены).";
            if (result.EncryptedSources > 0) text += " Найдены защищённые элементы кэша tdata: " + result.EncryptedSources + ". Текст истории из них не получен.";
            if(result.Warnings!=null){
                if(Array.IndexOf(result.Warnings,"TELEGRAM_DESKTOP_KEY_WRAP_UNSUPPORTED")>=0)text+=" Формат защиты локального кода Desktop в этой копии пока не поддерживается.";
                if(Array.IndexOf(result.Warnings,"TELEGRAM_DESKTOP_KEY_OR_INTEGRITY_INVALID")>=0)text+=" Известный код Desktop не подошёл или защищённый файл повреждён.";
                if(Array.IndexOf(result.Warnings,"TELEGRAM_DESKTOP_KNOWN_PASSCODE_REQUIRED")>=0)text+=" Для чтения поддерживаемых черновиков укажи известный локальный код Desktop.";
            }
            if (result.BlockedSources > 0) text += " Недоступных источников: " + result.BlockedSources + ".";
            if (result.Messages == 0) text += " В доступных локальных файлах переписки не найдены.";
            if (result.Status == "partial") text += " Подробнее — в отчёте источников.";
            return text;
        }
    }
}
