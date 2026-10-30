using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static class FragmentedPhotoRecovery
    {
        public sealed class Extent { public long ImageOffset,LogicalOffset,Length; }
        public sealed class Candidate { public string Path,Sha256,Status,Note;public long Bytes;public List<Extent> Extents=new List<Extent>(); }
        public sealed class Report { public int Schema,Candidates;public string Status,SourceSha256;public bool SourceUnchanged;public long OutputBytes,VerifiedBytes;public Dictionary<string,int> Skipped=new Dictionary<string,int>();public List<Candidate> Files=new List<Candidate>(); }
        public static int Recover(string image,string directory,CancellationToken cancel,Action<long,long> progress)
        {
            cancel.ThrowIfCancellationRequested();SourcePaths.NoLinks(image);
            string output=RecoveryCatalog.SafeFile(directory,"fragmented-photos");
            var result=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="fragmented_photos",source=image,destination=output},cancel,delegate(string message){},delegate(HelperProgress update){progress(update.Completed,update.Total);});
            cancel.ThrowIfCancellationRequested();
            if(result.Status=="error")throw new IOException("Поиск фрагментов фотографий: "+result.Code);
            string reportPath=RecoveryCatalog.SafeFile(directory,"fragmented-photos/report.json");
            if(!File.Exists(reportPath)||new FileInfo(reportPath).Length>16L*1024*1024)throw new IOException("Отчёт сборки фотографий отсутствует или превышает лимит.");
            var report=new JavaScriptSerializer{MaxJsonLength=16*1024*1024}.Deserialize<Report>(File.ReadAllText(reportPath));
            if(report==null||report.Schema!=1||report.Files==null||report.Files.Count>1000||report.Candidates!=report.Files.Count)throw new IOException("Неверный отчёт сборки фотографий.");
            foreach(var candidate in report.Files){
                if(candidate.Path==null||candidate.Path.IndexOfAny(new[]{'/','\\',':'})>=0)throw new IOException("Неверный путь кандидата фотографии.");
                candidate.Path="fragmented-photos/"+candidate.Path;
                if(!File.Exists(RecoveryCatalog.SafeFile(directory,candidate.Path)))throw new IOException("Кандидат фотографии отсутствует.");
            }
            RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"fragmented-photo-search.json"),report);
            progress(new FileInfo(image).Length,new FileInfo(image).Length);
            if(result.Status=="partial"||report.Status!="complete")throw new IOException("Сборка фотографий достигла ограничения; подтверждённые кандидаты сохранены, проход неполный.");
            return report.Candidates;
        }
    }
}
