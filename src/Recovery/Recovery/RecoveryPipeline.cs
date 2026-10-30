using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class ScanResult
    {
        public int Candidates,UniqueFiles,ResumedStages;
        public bool HasWarnings;
        public string Gallery,FileCatalog;
    }
    public static class RecoveryPipeline
    {
        sealed class Work { public string Key,Name;public Func<int> Run; }
        sealed class PartitionReport { public string status{get;set;}public List<BootCandidate> candidates{get;set;} }
        public static ScanResult Run(string image,string directory,bool deep,CancellationToken cancel,Action<string> progress)
        {return Run(image,directory,RecoveryOptions.Legacy(deep),cancel,progress);}
        public static ScanResult Run(string image,string directory,RecoveryOptions options,CancellationToken cancel,Action<string> progress,string imageChecksum=null,Action<RecoveryStageProgress> activity=null)
        {return Execute(image,directory,options,cancel,progress,imageChecksum,false,activity);}
        public static ScanResult Resume(string directory,CancellationToken cancel,Action<string> progress,Action<RecoveryStageProgress> activity=null)
        {
            var saved=RecoverySession.Read(directory);return Execute(saved.SourcePath,directory,saved.Options,cancel,progress,null,true,activity);
        }
        static string ExpectedSha(string checksum)
        {
            if(new FileInfo(checksum).Length>4096)throw new IOException("Слишком длинный файл контрольной суммы.");return File.ReadAllText(checksum).Split((char[])null,StringSplitOptions.RemoveEmptyEntries)[0];
        }
        static ScanResult Execute(string image,string directory,RecoveryOptions options,CancellationToken cancel,Action<string> progress,string imageChecksum,bool resume,Action<RecoveryStageProgress> activity)
        {
            options.Validate();cancel.ThrowIfCancellationRequested();if(progress==null)progress=s=>{};
            if(image.EndsWith(".partial",StringComparison.OrdinalIgnoreCase))throw new IOException("Неполная копия .partial не подходит для поиска.");
            var bootCandidates=new List<BootCandidate>();var stages=new List<object>();int completed=0,reused=0;bool warnings=false;RecoverySession session=null;
            string currentKey="verify",currentTitle="Проверка образа";
            string lastActivityKey=null,lastActivityState=null;long lastActivityTick=0;
            Action<string,long,long,long> observe=(state,done,total,candidates)=>{
                if(activity==null)return;long now=System.Diagnostics.Stopwatch.GetTimestamp();
                if(state=="running"&&currentKey==lastActivityKey&&state==lastActivityState&&(total<=0||done<total)&&now-lastActivityTick<System.Diagnostics.Stopwatch.Frequency/10)return;
                lastActivityKey=currentKey;lastActivityState=state;lastActivityTick=now;
                activity(new RecoveryStageProgress{Key=currentKey,Title=currentTitle,State=state,Completed=done,Total=total,Candidates=candidates});
            };
            var source=new ImageRecoverySource(image);
            using(var guard=source.OpenRead(source.Enumerate("",cancel).First(),cancel)){
                progress("Проверка полной копии флешки…");observe("running",0,0,-1);string expected;
                if(resume){var saved=RecoverySession.Read(directory);expected=saved.SourceSha256;if(!String.Equals(RecoveryCore.HashFile(image,cancel,(a,b)=>observe("running",a,b,-1)),expected,StringComparison.OrdinalIgnoreCase))throw new IOException("Образ изменился после сохранения сессии. Продолжение остановлено.");}
                else {string checksum=imageChecksum??image+".sha256";RecoveryCore.VerifyImage(image,checksum,cancel,(done,total)=>observe("running",done,total,-1));expected=ExpectedSha(checksum);}
                if(!resume){
                    RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"search-options.json"),options);
                    string capture=Path.Combine(Path.GetDirectoryName(image),"capture.json"),errors=image+".read-errors.json";
                    string provenance=RecoveryCatalog.SafeFile(directory,"source-image.json");
                    if(File.Exists(capture)&&!File.Exists(provenance)&&!String.Equals(Path.GetFullPath(capture),Path.GetFullPath(Path.Combine(directory,"capture.json")),StringComparison.OrdinalIgnoreCase)){
                        var report=MatchingCapture(capture,expected,guard.Length);
                        if(report!=null)RecoveryCore.SaveJson(provenance,report);
                        else {warnings=true;progress("Соседний capture.json не подтверждает этот образ. Происхождение носителя не переносится.");}
                    }
                    if(imageChecksum!=null){warnings=true;progress("Внешний образ: контрольная сумма фиксирует текущий файл, полнота исходного съёма не подтверждена.");if(!File.Exists(Path.Combine(directory,"source-image.json")))RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"source-image.json"),new{origin="external_image",sourcePath=image,completeness="unknown",checksumFile=Path.GetFileName(imageChecksum)});}
                    if(File.Exists(errors))File.Copy(errors,RecoveryCatalog.SafeFile(directory,"source-read-errors.json"),false);
                    session=RecoverySession.Start(directory,image,expected,options,cancel);session.State.ExternalImage=imageChecksum!=null;session.Status("running");
                }else {session=RecoverySession.Open(directory,image,options,cancel,progress);warnings=session.State.ExternalImage;progress("Сессия проверена. Завершённые этапы используются повторно; незавершённый метод начнётся сначала.");}
                try{
                    if(FileEvidence.HasUnreadSource(directory,image)){warnings=true;progress("В образе есть пропуски или недостоверная карта чтения. Метаданные занятости не считаются доказательством свободных кластеров.");}
                    var methods=new List<Work>();
                    if(options.Ext4Metadata)methods.Add(new Work{Key="ext4",Name="Удалённые записи ext4",Run=()=>{
                        if(FileEvidence.HasUnreadSource(directory,image))throw new IOException("ext4: карта ошибок чтения не позволяет подтвердить метаданные занятости.");
                        int found=Ext4Recovery.Recover(image,directory,cancel,progress);
                        var report=new JavaScriptSerializer{MaxJsonLength=64*1024*1024}.Deserialize<Ext4Recovery.Report>(File.ReadAllText(RecoveryCatalog.SafeFile(directory,"ext4/report.json")));
                        if(report==null||report.Status!="complete")throw new IOException("ext4: проход не завершён; найденные кандидаты сохранены.");
                        return found;
                    }});
                    if(options.LostPartitions)methods.Add(new Work{Key="partitions",Name="Поиск потерянных разделов по всему образу",Run=()=>{
                        bootCandidates=BootScout.Find(image,cancel,(done,total)=>{observe("running",done,total,-1);progress("Поиск разделов: "+done*100/Math.Max(1,total)+"%");});
                        RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"partition-search.json"),new{status=bootCandidates.Count>=BootScout.MaximumVolumes?"limited":"complete",candidates=bootCandidates,note="Candidates validated by filesystem parsers. Original image unchanged."});if(bootCandidates.Count>=BootScout.MaximumVolumes)warnings=true;return 0;
                    }});
                    bool unsafeMetadata=FileEvidence.HasUnreadSource(directory,image);
                    if(unsafeMetadata&&(options.FatMetadata||options.NtfsMetadata)){warnings=true;stages.Add(new{method="Поиск по таблицам размещения FAT/exFAT/NTFS",status="skipped_read_errors",reason="Unread source ranges can replace allocation metadata with zeros."});}
                    if(options.FatMetadata&&!unsafeMetadata)methods.Add(new Work{Key="fat",Name="Записи удалённых файлов FAT/exFAT",Run=()=>FilesystemRecovery.Recover(image,directory,cancel,progress,options.LostPartitions?bootCandidates:null,options.AlternateFat,options.OrphanDirectories)});
                    if(options.NtfsMetadata&&!unsafeMetadata)methods.Add(new Work{Key="ntfs",Name="Записи удалённых файлов NTFS",Run=()=>AdvancedEngines.RecoverNtfs(image,directory,cancel,progress,options.LostPartitions?bootCandidates:null)});
                    if(options.MetadataRescue)methods.Add(new Work{Key="ntfs-records",Name="Независимые уцелевшие записи NTFS",Run=()=>{
                        int found=MetadataRescue.Recover(image,directory,cancel,progress,options.LostPartitions?bootCandidates:null);var report=new JavaScriptSerializer{MaxJsonLength=128*1024*1024}.Deserialize<MetadataRescue.Report>(File.ReadAllText(RecoveryCatalog.SafeFile(directory,"metadata-rescue/report.json")));
                        if(report.CandidateLimitReached||report.OutputLimitReached)throw new IOException("Поиск записей NTFS достиг предела; проход неполный.");if(report.Entries.Any(e=>e.Status=="not_extracted"||e.Status=="partial_candidate")){warnings=true;progress("Часть NTFS-кандидатов пропущена или извлечена частично; причины в отчёте.");}return found;
                    }});
                    if(options.Signatures)methods.Add(new Work{Key="photorec",Name="Поиск по содержимому PhotoRec",Run=()=>RecoveryCore.Recover(image,directory,false,cancel,n=>{observe("running",0,0,n);progress("PhotoRec: найдено кандидатов "+n);},options)});
                    if(options.EmbeddedPhotos)methods.Add(new Work{Key="photos",Name="JPEG/PNG внутри данных",Run=()=>ExtraPhotoSearch.Recover(image,directory,cancel,(done,total)=>{observe("running",done,total,-1);progress("Фотографии: "+done*100/Math.Max(1,total)+"%");})});
                    if(options.Containers)methods.Add(new Work{Key="containers",Name="Контейнеры и медиа по смещениям",Run=()=>ContainerCarver.Recover(image,directory,options,cancel,(done,total)=>{observe("running",done,total,-1);progress("Контейнеры: "+done*100/Math.Max(1,total)+"%");})});
                    if(options.ArchiveMembers)methods.Add(new Work{Key="archive-members",Name="Исправные части повреждённых ZIP / Office",Run=()=>ArchiveSalvage.Recover(image,directory,cancel,(done,total)=>{observe("running",done,total,-1);progress("Части архивов: "+done*100/Math.Max(1,total)+"%");})});
                    if(options.FragmentedArchives)methods.Add(new Work{Key="fragmented-zip",Name="Сборка ZIP / Office из раздельных записей",Run=()=>FragmentedZipRecovery.Recover(image,directory,cancel,(done,total)=>{observe("running",done,total,-1);progress("Сборка ZIP: "+done*100/Math.Max(1,total)+"%");})});
                    if(options.FragmentedPhotos)methods.Add(new Work{Key="fragmented-photos",Name="Сборка разрозненных фотографий",Run=()=>FragmentedPhotoRecovery.Recover(image,directory,cancel,(done,total)=>{observe("running",done,total,-1);progress("Фрагменты фотографий: "+done*100/Math.Max(1,total)+"%");})});
                    if(options.FragmentedVideo)methods.Add(new Work{Key="fragmented-media",Name="Сборка фрагментов MP4 / MOV",Run=()=>FragmentedMediaRecovery.Recover(image,directory,cancel,(done,total)=>{observe("running",done,total,-1);progress("Фрагменты видео: "+done*100/Math.Max(1,total)+"%");})});
                    if(options.CustomSignatures)methods.Add(new Work{Key="user-signatures",Name="Свои типы файлов",Run=()=>UserSignatureRecovery.Recover(image,directory,options.CustomRules,cancel,(done,total)=>{observe("running",done,total,-1);progress("Свои типы: "+done*100/Math.Max(1,total)+"%");})});
                    if(options.TextFragments)methods.Add(new Work{Key="text",Name="Текстовые остатки по ключевым словам",Run=()=>RawTextSearch.Recover(image,directory,options.TextQuery,cancel,(done,total)=>{observe("running",done,total,-1);progress("Текст: "+done*100/Math.Max(1,total)+"%");})});
                    foreach(var method in methods){
                        cancel.ThrowIfCancellationRequested();currentKey=method.Key;currentTitle=method.Name;observe("running",0,0,-1);var prior=session.Completed(method.Key);
                        if(prior!=null){
                            if(method.Key=="partitions"){var report=new JavaScriptSerializer{MaxJsonLength=4*1024*1024}.Deserialize<PartitionReport>(File.ReadAllText(RecoveryCatalog.SafeFile(directory,"partition-search.json")));if(report==null||report.candidates==null)throw new IOException("Не удалось восстановить проверенный список разделов.");bootCandidates=report.candidates;}
                            observe("reused",0,0,prior.Candidates);reused++;if(method.Key!="partitions")completed++;warnings|=prior.Warnings;stages.Add(new{method=method.Name,status="reused",candidates=prior.Candidates});progress(method.Name+": проверенный результат этапа сохранён, повторный проход не нужен.");continue;
                        }
                        session.Begin(method.Key);progress(method.Name+"…");
                        try{int count=method.Run();observe("complete",0,0,count);session.Finish(method.Key,count,warnings,cancel);if(method.Key!="partitions")completed++;stages.Add(new{method=method.Name,status="complete",candidates=count});progress(method.Name+": сохранено кандидатов "+count+".");}
                        catch(OperationCanceledException){observe("cancelled",0,0,-1);session.Fail(method.Key,"cancelled",null);throw;}
                        catch(IOException error){observe("incomplete",0,0,-1);warnings=true;session.Fail(method.Key,"incomplete",error.Message);stages.Add(new{method=method.Name,status="incomplete",message=error.Message});progress(method.Name+": "+error.Message+" Другие способы продолжатся.");}
                        RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"scan-stages.json"),new{status="running",options=options,stages=stages});
                    }
                    cancel.ThrowIfCancellationRequested();if(completed==0)throw new IOException("Ни один способ поиска не завершился. Посмотри scan-stages.json и журналы в папке результатов.");
                    currentKey="catalog";currentTitle="Проверка найденных файлов";observe("running",0,0,-1);progress("Проверка файлов и создание каталога…");string gallery=PhotoCatalog.Build(directory,cancel,progress);var files=RecoveryCatalog.Build(directory,cancel,progress);int candidates=RecoveryCore.RecoveredFiles(directory).Count();
                    if(Directory.Exists(RecoveryCatalog.SafeFile(directory,"attempt-history")))warnings=true;
                    string status=warnings?"finished_with_warnings":"finished";RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"scan-stages.json"),new{status=status,options=options,utc=DateTime.UtcNow.ToString("o"),candidates=candidates,uniqueFiles=files.Items.Count,resumedStages=reused,stages=stages});session.Status(status);
                    currentKey="finished";currentTitle="Поиск завершён";observe("complete",0,0,candidates);return new ScanResult{Candidates=candidates,UniqueFiles=files.Items.Count,Gallery=gallery,FileCatalog=Path.Combine(directory,"files-index.json"),HasWarnings=warnings,ResumedStages=reused};
                }catch(OperationCanceledException){session.Status("cancelled");RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"scan-stages.json"),new{status="cancelled",options=options,stages=stages});throw;}
                catch{session.Status("error");RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"scan-stages.json"),new{status="error",options=options,stages=stages});throw;}
            }
        }
        static Dictionary<string,object> MatchingCapture(string path,string sha256,long bytes)
        {
            try {
                SourcePaths.NoLinks(path);Dictionary<string,object> report;
                using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){
                    if(input.Length>1024*1024)return null;
                    using(var reader=new StreamReader(input,System.Text.Encoding.UTF8,true))report=new JavaScriptSerializer{MaxJsonLength=1024*1024}.Deserialize<Dictionary<string,object>>(reader.ReadToEnd());
                }
                object value;long size,unread;
                if(report==null||!report.TryGetValue("sha256",out value)||!String.Equals(Convert.ToString(value),sha256,StringComparison.OrdinalIgnoreCase))return null;
                if(!report.TryGetValue("size",out value)||!Int64.TryParse(Convert.ToString(value,System.Globalization.CultureInfo.InvariantCulture),System.Globalization.NumberStyles.Integer,System.Globalization.CultureInfo.InvariantCulture,out size)||size!=bytes)return null;
                if(!report.TryGetValue("unreadBytes",out value)||!Int64.TryParse(Convert.ToString(value,System.Globalization.CultureInfo.InvariantCulture),System.Globalization.NumberStyles.Integer,System.Globalization.CultureInfo.InvariantCulture,out unread)||unread<0||unread>size)return null;
                if(!report.TryGetValue("status",out value))return null;string status=Convert.ToString(value);
                return status=="complete"&&unread==0||status=="complete_with_read_errors"&&unread>0?report:null;
            }catch(IOException){return null;}catch(UnauthorizedAccessException){return null;}catch(ArgumentException){return null;}catch(InvalidOperationException){return null;}
        }
    }
}
