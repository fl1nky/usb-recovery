using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static class RecoveryStageCompletion
    {
        static readonly Dictionary<string,string> Reports=new Dictionary<string,string>(StringComparer.Ordinal){
            {"partitions","partition-search.json"},{"ext4","ext4/report.json"},{"refs","refs/report.json"},{"apfs","apfs/report.json"},
            {"ntfs-records","metadata-rescue/report.json"},{"photos","extra-photo-search.json"},
            {"containers","container-search.json"},{"archive-members","archive-salvage.json"},
            {"fragmented-zip","fragmented-zip.json"},{"fragmented-photos","fragmented-photo-search.json"},
            {"fragmented-media","fragmented-media.json"},{"user-signatures","user-signatures.json"},{"text","text-search.json"}};
        public static void RequireComplete(string directory,string key)
        {
            string relative;if(!Reports.TryGetValue(key,out relative))return;
            string file=RecoveryCatalog.SafeFile(directory,relative);
            if(!File.Exists(file)||new FileInfo(file).Length>128L*1024*1024)throw new IOException("Не найден полный отчёт этапа. Проход сохранён как незавершённый.");
            Dictionary<string,object> raw;
            try{raw=new JavaScriptSerializer{MaxJsonLength=128*1024*1024}.Deserialize<Dictionary<string,object>>(File.ReadAllText(file));}
            catch(ArgumentException error){throw new IOException("Отчёт этапа не удалось проверить.",error);}
            catch(InvalidOperationException error){throw new IOException("Отчёт этапа не удалось проверить.",error);}
            if(raw==null)throw new IOException("Пустой отчёт этапа.");
            var row=new Dictionary<string,object>(StringComparer.OrdinalIgnoreCase);foreach(var pair in raw){if(row.ContainsKey(pair.Key))throw new IOException("Повторное поле в отчёте этапа.");row.Add(pair.Key,pair.Value);}
            object value;
            if(row.TryGetValue("status",out value)&&(! (value is string)||!new[]{"complete","completed","finished"}.Contains((string)value)))
                throw new IOException("Этап остановлен или достиг ограничения. Кандидаты сохранены; при продолжении незавершённый метод будет выполнен повторно.");
            foreach(string flag in new[]{"Limited","CandidateLimitReached","OutputLimitReached"})
                if(row.TryGetValue(flag,out value)&&value is bool&&(bool)value)throw new IOException("Этап достиг ограничения и не может использоваться как завершённый.");
        }
    }
}
