using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace UsbRecovery
{
    // The request lives only for one operation. Secrets are never serialized here.
    public sealed class StorageRecoveryRequest
    {
        public string Kind, Source, OutputDirectory;
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
        public string Directory, Catalog;
        public StoragePreparedResult Prepared;
        public RecoveryFileIndex Index;
    }

    public static class StorageRecoveryWorkflow
    {
        public static void Validate(StorageRecoveryRequest request)
        {
            if (request == null) throw new ArgumentNullException("request");
            if (request.MaximumOutputBytes <= 0)
                throw new IOException("Лимит результатов должен быть положительным.");
            if (request.Kind != "APFS" && request.Kind != "RAID" && request.Kind != "BitLocker")
                throw new IOException("Неизвестный режим восстановления.");
            if (request.Kind != "RAID") {
                if (request.Volume == null || request.Volume.Kind != request.Kind)
                    throw new IOException("Сначала нажми «Проверить образ» и выбери том.");
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
            return new StorageRecoveryExecution { Directory = directory };
        }

        public static void Execute(StorageRecoveryRequest request, StorageRecoveryExecution execution,
            CancellationToken token, Action<RecoveryStageProgress> activity)
        {
            Validate(request);
            if (execution == null || String.IsNullOrEmpty(execution.Directory))
                throw new ArgumentException("Не создана рабочая папка операции.", "execution");
            token.ThrowIfCancellationRequested();
            if (request.Kind == "RAID") {
                string output = Path.Combine(execution.Directory, "raid");
                var built = RaidImageBuilder.Build(request.Raid, output, token,
                    (completed, total) => Observe(activity, new RecoveryStageProgress {
                        Title = "Сборка RAID", Completed = completed, Total = total
                    }),
                    phase => Observe(activity, new RecoveryStageProgress { Title = phase }));
                execution.Prepared = new StoragePreparedResult {
                    Directory = output, Image = built.ImagePath, Checksum = built.ImagePath + ".sha256"
                };
            } else {
                execution.Prepared = StorageRecovery.Prepare(request.Kind, request.Source,
                    Path.Combine(execution.Directory, request.Kind == "APFS" ? "apfs" : "unlock"),
                    request.Volume, request.Secrets, request.IncludeSnapshots, request.MaximumOutputBytes,
                    token, activity, request.MaximumSnapshots);
            }

            string catalog = execution.Prepared.Catalog;
            if (request.Kind != "APFS" && request.SearchAfterPreparation && !execution.Prepared.Partial)
                catalog = StorageRecovery.Search(execution.Prepared,
                    Path.Combine(execution.Directory, "search"), request.MaximumSearch, token, activity);
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
