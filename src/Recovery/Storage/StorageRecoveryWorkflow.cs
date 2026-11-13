using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // The request lives only for one operation. Secrets are never serialized here.
    public sealed class StorageRecoveryRequest
    {
        public string Kind, Source, OutputDirectory;
        public string[] LvmSources;
        public StorageVolumeInfo Volume;
        public RaidConfiguration Raid;
        public Dictionary<string, string> Secrets;
        public bool IncludeSnapshots, SearchAfterPreparation, MaximumSearch;
        public long MaximumOutputBytes;
        public int MaximumSnapshots = 1024;
    }

    // Completed preparation remains available if the following search is stopped.
    public sealed class StorageRecoveryExecution
    {
        public string Directory, Catalog, RaidResumeDirectory;
        public StoragePreparedResult Prepared;
        public RecoveryFileIndex Index;
        public bool ResumePreparation;
    }

    // Deliberate whitelist: the in-memory request contains credentials.
    public sealed class StorageResumePlan
    {
        public int Schema = 1, MaximumSnapshots;
        public string Kind, Source;
        public string[] LvmSources;
        public string VolumeIdentifier;
        public long Offset, Length, MaximumOutputBytes;
        public bool IncludeSnapshots, SearchAfterPreparation, MaximumSearch;
    }

    public static class StorageRecoveryWorkflow
    {
        public static void Validate(StorageRecoveryRequest request)
        {
            if (request == null) throw new ArgumentNullException("request");
            if (request.MaximumOutputBytes <= 0)
                throw new IOException("Лимит результатов должен быть положительным.");
            if (request.Kind != "APFS" && request.Kind != "RAID" && request.Kind != "BitLocker" && request.Kind != "LVM")
                throw new IOException("Неизвестный режим восстановления.");
            if (request.Kind != "RAID") {
                if (request.Volume == null || request.Volume.Kind != request.Kind)
                    throw new IOException("Сначала нажми «Проверить образ» и выбери том.");
                if(request.Kind=="LVM"&&(request.LvmSources==null||request.LvmSources.Length<1||request.LvmSources.Length>32||String.IsNullOrWhiteSpace(request.Volume.Identifier)))throw new IOException("Добавь образы LVM, нажми «Найти тома» и выбери логический том.");
                if(request.Kind=="LVM"&&!String.Equals(Path.GetFullPath(request.Source),Path.GetFullPath(request.LvmSources[0]),StringComparison.OrdinalIgnoreCase))throw new IOException("Первый исходный образ LVM не совпадает с сохранённой операцией.");
                return;
            }

            RaidImageBuilder.Validate(request.Raid);
            long smallest = request.Raid.Members.Where(member => !member.Missing)
                .Min(member => new FileInfo(member.Path).Length - member.Offset);
            string level = request.Raid.Level.Trim().ToUpperInvariant().Replace("RAID", "").Replace("-", "").Trim();
            int dataMembers = level == "0" ? request.Raid.Members.Count :
                level == "5" ? request.Raid.Members.Count - 1 :
                level == "6" ? request.Raid.Members.Count - 2 :
                level == "10" ? request.Raid.Members.Count / 2 : 1;
            if (request.Raid.LogicalSize > request.MaximumOutputBytes ||
                (request.Raid.LogicalSize == 0 &&
                 smallest > request.MaximumOutputBytes / Math.Max(1, dataMembers)))
                throw new IOException("Образ RAID превысит выбранный лимит. Увеличь лимит результатов.");
        }

        public static StorageRecoveryExecution Create(StorageRecoveryRequest request)
        {
            Validate(request);
            if (String.IsNullOrWhiteSpace(request.OutputDirectory))
                throw new IOException("Выбери папку результатов.");
            string parent = Path.GetFullPath(request.OutputDirectory);
            SourcePaths.NoLinks(parent);
            System.IO.Directory.CreateDirectory(parent);
            string directory = Path.Combine(parent, "Storage-" +
                DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" +
                Guid.NewGuid().ToString("N").Substring(0, 8));
            StorageRecovery.CreatePrivateDirectory(directory);
            if(request.Kind!="RAID")RecoveryCore.SaveJson(Path.Combine(directory,"storage-request.json"),Plan(request));
            return new StorageRecoveryExecution { Directory = directory };
        }

        static StorageResumePlan Plan(StorageRecoveryRequest request)
        {
            return new StorageResumePlan {Kind=request.Kind,Source=Path.GetFullPath(request.Source),
                LvmSources=request.LvmSources==null?null:request.LvmSources.Select(Path.GetFullPath).ToArray(),VolumeIdentifier=request.Volume.Identifier,
                Offset=request.Volume.OffsetBytes,Length=request.Volume.LengthBytes,
                MaximumOutputBytes=request.MaximumOutputBytes,MaximumSnapshots=request.MaximumSnapshots,
                IncludeSnapshots=request.IncludeSnapshots,SearchAfterPreparation=request.SearchAfterPreparation,
                MaximumSearch=request.MaximumSearch};
        }

        public static StorageRecoveryRequest ReadResumeRequest(string directory)
        {
            string path=Path.Combine(Path.GetFullPath(directory),"storage-request.json");
            SourcePaths.NoLinks(path);
            if(!File.Exists(path)||new FileInfo(path).Length>65536)throw new IOException("Выбери рабочую папку APFS или BitLocker со storage-request.json.");
            StorageResumePlan plan;
            try{plan=new JavaScriptSerializer().Deserialize<StorageResumePlan>(File.ReadAllText(path));}
            catch(ArgumentException){throw new IOException("Параметры продолжения повреждены.");}
            if(plan==null||plan.Schema!=1||(plan.Kind!="APFS"&&plan.Kind!="BitLocker"&&plan.Kind!="LVM")||String.IsNullOrWhiteSpace(plan.Source)||plan.Offset<0||plan.Length<=0||plan.MaximumSnapshots<0||plan.MaximumSnapshots>16384)
                throw new IOException("Параметры продолжения не поддерживаются.");
            var request=new StorageRecoveryRequest{Kind=plan.Kind,Source=plan.Source,
                Volume=new StorageVolumeInfo{Kind=plan.Kind,OffsetBytes=plan.Offset,LengthBytes=plan.Length,Identifier=plan.VolumeIdentifier},LvmSources=plan.LvmSources,
                OutputDirectory=Path.GetDirectoryName(Path.GetFullPath(directory)),MaximumOutputBytes=plan.MaximumOutputBytes,
                MaximumSnapshots=plan.MaximumSnapshots,IncludeSnapshots=plan.IncludeSnapshots,
                SearchAfterPreparation=plan.SearchAfterPreparation,MaximumSearch=plan.MaximumSearch};
            Validate(request);
            return request;
        }

        public static StorageRecoveryExecution Resume(StorageRecoveryRequest request,string directory)
        {
            Validate(request);
            var saved=ReadResumeRequest(directory);
            var serializer=new JavaScriptSerializer();
            if(serializer.Serialize(Plan(request))!=serializer.Serialize(Plan(saved)))
                throw new IOException("Параметры изменены. Загрузи сохранённую операцию кнопкой «Продолжить».");
            return new StorageRecoveryExecution{Directory=Path.GetFullPath(directory),ResumePreparation=true};
        }

        public static StorageRecoveryExecution ResumeRaid(StorageRecoveryRequest request, string directory)
        {
            Validate(request);
            if (request.Kind != "RAID") throw new IOException("Выбери режим RAID для продолжения сборки.");
            string full = Path.GetFullPath(directory);
            SourcePaths.NoLinks(full);
            if (!File.Exists(Path.Combine(full, "raid.dd.partial")) || !File.Exists(Path.Combine(full, "raid-resume.json")))
                throw new IOException("Выбери папку RAID с raid.dd.partial и raid-resume.json.");
            return new StorageRecoveryExecution { Directory = full, RaidResumeDirectory = full };
        }

        public static void Execute(StorageRecoveryRequest request, StorageRecoveryExecution execution,
            CancellationToken token, Action<RecoveryStageProgress> activity)
        {
            Validate(request);
            if (execution == null || String.IsNullOrEmpty(execution.Directory))
                throw new ArgumentException("Не создана рабочая папка операции.", "execution");
            token.ThrowIfCancellationRequested();
            if (request.Kind == "RAID") {
                string output = execution.RaidResumeDirectory ?? Path.Combine(execution.Directory, "raid");
                Action<long, long> progress = (completed, total) => Observe(activity, new RecoveryStageProgress {
                        Title = "Сборка RAID", Completed = completed, Total = total
                    });
                Action<string> phase = title => Observe(activity, new RecoveryStageProgress { Title = title });
                var built = execution.RaidResumeDirectory == null
                    ? RaidImageBuilder.Build(request.Raid, output, token, progress, phase)
                    : RaidImageBuilder.Resume(request.Raid, output, token, progress, phase);
                execution.Prepared = new StoragePreparedResult {
                    Directory = output, Image = built.ImagePath, Checksum = built.ImagePath + ".sha256"
                };
            } else {
                execution.Prepared = StorageRecovery.Prepare(request.Kind, request.Source,
                    Path.Combine(execution.Directory, request.Kind == "APFS" ? "apfs" : request.Kind=="LVM"?"lvm":"unlock"),
                    request.Volume, request.Secrets, request.IncludeSnapshots, request.MaximumOutputBytes,
                    token, activity, request.MaximumSnapshots, execution.ResumePreparation, request.LvmSources);
            }

            string catalog = execution.Prepared.Catalog;
            if (request.Kind != "APFS" && request.SearchAfterPreparation && !execution.Prepared.Partial)
                catalog = StorageRecovery.Search(execution.Prepared,
                    Path.Combine(execution.Directory, execution.ResumePreparation ? "search-"+Guid.NewGuid().ToString("N").Substring(0,8) : "search"), request.MaximumSearch, token, activity);
            var index = catalog == null ? null : RecoveryCatalog.Load(catalog);
            execution.Catalog = catalog;
            execution.Index = index;
        }

        public static string SearchPrepared(StorageRecoveryExecution execution, bool maximum,
            CancellationToken token, Action<RecoveryStageProgress> activity)
        {
            if (execution == null || execution.Prepared == null)
                throw new IOException("Сначала подготовь образ.");
            string catalog = StorageRecovery.Search(execution.Prepared,
                Path.Combine(execution.Directory, "search-" + Guid.NewGuid().ToString("N").Substring(0, 8)),
                maximum, token, activity);
            var index = RecoveryCatalog.Load(catalog);
            execution.Catalog = catalog;
            execution.Index = index;
            return execution.Catalog;
        }

        static void Observe(Action<RecoveryStageProgress> activity, RecoveryStageProgress value)
        {
            if (activity != null) activity(value);
        }
    }
}
