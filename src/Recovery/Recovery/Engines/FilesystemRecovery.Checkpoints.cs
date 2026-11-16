using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class FilesystemRecovery
    {
        sealed class FsMetadataView
        {
            public Volume Volume;
            public RecoveryOutputLedger<FsMetadataEvent> Ledger;
            public readonly List<DirectoryTask> Tasks = new List<DirectoryTask>();
            public readonly DirectoryQueue Queue = new DirectoryQueue();
            public int SavedCandidates;
        }

        static FsMetadataView ReadMetadata(FsGeometry geometry, FsVolumeProgress progress,
            RecoveryCheckpointContext context, CancellationToken cancel)
        {
            var view = new FsMetadataView { Volume = geometry.Create(),
                Ledger = new RecoveryOutputLedger<FsMetadataEvent>(context, progress.Metadata, MaximumMetadataRecords, cancel) };
            var v = view.Volume;
            var bitmap = new List<uint>();
            var bitmapSeen = new HashSet<uint>();
            foreach (FsMetadataEvent row in view.Ledger.Records)
            {
                cancel.ThrowIfCancellationRequested();
                if (row.Kind == "directory")
                {
                    DirectoryTask task = row.Directory;
                    if (task == null || task.Path == null || task.Path.Length > 32700 || task.Depth < 0 || task.Depth > 64 ||
                        task.Length < 0 || task.Length > MaxDirectoryBytes || view.Tasks.Count >= 4 * MaxDirectories ||
                        task.FixedRoot && (v.Exfat || v.Bits == 32 || task.Start != 0) ||
                        !task.FixedRoot && (!ClusterValid(v, task.Start) || !v.Directories.Add(task.Start)))
                        throw new IOException("FAT_DIRECTORY_LEDGER_INVALID");
                    view.Tasks.Add(task);
                }
                else if (row.Kind == "candidate")
                {
                    ValidateCandidate(v, row.Candidate);
                    if (v.Candidates.Count >= MaxCandidates) throw new IOException("FAT_CANDIDATE_LEDGER_LIMIT");
                    v.Candidates.Add(row.Candidate);
                }
                else if (row.Kind == "live" || row.Kind == "bitmap")
                {
                    if (row.Clusters == null || row.Clusters.Length < 1 || row.Clusters.Length > ClusterBatch)
                        throw new IOException("FAT_CLUSTER_LEDGER_INVALID");
                    foreach (uint cluster in row.Clusters)
                    {
                        if (!ClusterValid(v, cluster)) throw new IOException("FAT_CLUSTER_LEDGER_INVALID");
                        if (row.Kind == "live")
                        {
                            if (v.LiveClusters.Count >= MaxClusters || !v.LiveClusters.Add(cluster)) throw new IOException("FAT_LIVE_LEDGER_INVALID");
                        }
                        else
                        {
                            if (!bitmapSeen.Add(cluster) || bitmap.Count >= MaxClusters) throw new IOException("FAT_BITMAP_LEDGER_INVALID");
                            bitmap.Add(cluster);
                        }
                    }
                }
                else throw new IOException("FAT_METADATA_LEDGER_INVALID");
            }
            if (progress.QueueCursor < 0 || progress.QueueCursor > view.Tasks.Count || progress.MainVisited < 0 || progress.MainVisited > MaxDirectories ||
                progress.OrphanVisited < 0 || progress.OrphanVisited > MaxDirectories || progress.MainEntries < 0 || progress.MainEntries > MaxEntries + 1 ||
                progress.OrphanEntries < 0 || progress.OrphanEntries > MaxEntries + 1 || progress.OrphanFound < 0 || progress.OrphanFound > MaxDirectories ||
                progress.OrphanCluster < 0 || progress.OrphanCluster > v.ClusterCount || progress.ExportCursor < 0 || progress.ExportCursor > v.Candidates.Count ||
                progress.Notes == null || progress.Notes.Count > 32 || progress.Notes.Any(x => x == null || x.Length > 2048) ||
                !new[] { "initialize", "enumerate", "bitmap", "orphan", "export", "finished" }.Contains(progress.Phase))
                throw new IOException("FAT_VOLUME_CHECKPOINT_INVALID");
            v.AllocationComplete = progress.AllocationComplete; v.BitmapStart = progress.BitmapStart; v.BitmapLength = progress.BitmapLength;
            if (progress.BitmapValid)
            {
                if (!v.Exfat || bitmap.Count == 0 || progress.BitmapLength < 1 || progress.BitmapLength > MaxDirectoryBytes ||
                    (long)bitmap.Count * v.ClusterBytes < progress.BitmapLength)
                    throw new IOException("FAT_BITMAP_CHECKPOINT_INVALID");
                v.BitmapChain = bitmap;
            }
            else if (bitmap.Count != 0) throw new IOException("FAT_BITMAP_CHECKPOINT_INVALID");
            foreach (var task in view.Tasks.Skip(progress.QueueCursor)) view.Queue.Restore(task);
            view.SavedCandidates = v.Candidates.Count;
            return view;
        }

        sealed class FsRuntime
        {
            readonly string root;
            readonly ImageReader image;
            readonly CancellationToken cancel;
            readonly Action<string> progress;
            readonly RecoveryCheckpointContext context;
            readonly RecoveryMethodJournal<FsState> journal;
            readonly RecoveryOutputLedger<FsExportEvent> exports;
            readonly FsState state;
            readonly bool orphanDirectories;
            readonly Dictionary<int, FsVolumeProgress> finished = new Dictionary<int, FsVolumeProgress>();
            readonly HashSet<string> knownOutputs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FsMetadataView active, repairView;
            int repairVolume = -1;

            public FsRuntime(string source, string destination, ImageReader reader, IList<BootCandidate> discovered,
                bool alternateFat, bool orphans, CancellationToken token, Action<string> observe, RecoveryCheckpointContext checkpoint)
            {
                root = destination; image = reader; cancel = token; progress = observe; context = checkpoint; orphanDirectories = orphans;
                var notes = new List<string>();
                var definitions = Discover(image, notes, cancel, discovered, alternateFat).Select(FsGeometry.From).ToList();
                journal = new RecoveryMethodJournal<FsState>(source, new FsState { Volumes = definitions, DiscoveryNotes = notes }, context, cancel);
                state = journal.Payload;
                var json = new JavaScriptSerializer { MaxJsonLength = MaximumPlanBytes };
                if (state.Volumes == null || state.DiscoveryNotes == null || state.Current == null ||
                    json.Serialize(state.Volumes) != json.Serialize(definitions) || state.VolumeIndex < 0 || state.VolumeIndex > definitions.Count ||
                    state.Number < 0 || state.Number > MaxCandidates || state.Recovered < 0 || state.Recovered > state.Number ||
                    state.RecoveredBytes < 0 || state.RecoveredBytes > image.Length * 2L ||
                    state.Complete && state.VolumeIndex != definitions.Count ||
                    state.VolumeIndex < definitions.Count && state.Current.Phase == "finished")
                    throw new IOException("FAT_CHECKPOINT_BINDING_INVALID");
                exports = new RecoveryOutputLedger<FsExportEvent>(context, state.Exports, MaxCandidates + definitions.Count, cancel);
                ValidateExports();
                ValidateOutputInventory();
                RepairExports();
            }
            void Observe(string text)
            {
                if (progress != null) progress(text);
            }
            void Save()
            {
                journal.Save(state);
            }
            void SaveExports(IList<FsExportEvent> rows)
            {
                state.Exports = exports.Append(state.Exports, rows);
                Save(); exports.Accept(rows);
            }
            void SaveMetadata(bool bitmap = false)
            {
                var v = active.Volume;
                var p = state.Current;
                var rows = new List<FsMetadataEvent>();
                rows.AddRange(active.Queue.Added.Select(x => new FsMetadataEvent { Kind = "directory", Directory = x }));
                for (int i = 0; i < v.PendingLiveClusters.Count; i += ClusterBatch)
                    rows.Add(new FsMetadataEvent { Kind = "live", Clusters = v.PendingLiveClusters.GetRange(i, Math.Min(ClusterBatch, v.PendingLiveClusters.Count - i)).ToArray() });
                rows.AddRange(v.Candidates.GetRange(active.SavedCandidates, v.Candidates.Count - active.SavedCandidates).Select(x => new FsMetadataEvent { Kind = "candidate", Candidate = x }));
                if (bitmap && p.BitmapValid)
                    for (int i = 0; i < v.BitmapChain.Count; i += ClusterBatch)
                        rows.Add(new FsMetadataEvent { Kind = "bitmap", Clusters = v.BitmapChain.GetRange(i, Math.Min(ClusterBatch, v.BitmapChain.Count - i)).ToArray() });
                p.AllocationComplete = v.AllocationComplete; p.BitmapStart = v.BitmapStart; p.BitmapLength = v.BitmapLength;
                p.Metadata = active.Ledger.Append(p.Metadata, rows);
                Save(); active.Ledger.Accept(rows);
                active.Tasks.AddRange(active.Queue.Added); active.Queue.Added.Clear(); v.PendingLiveClusters.Clear();
                active.SavedCandidates = v.Candidates.Count;
            }
            void ValidatePlan(FsCandidatePlan plan, FsExportEvent row, int number)
            {
                if (row.VolumeIndex < 0 || row.VolumeIndex >= state.Volumes.Count || row.VolumeIndex > state.VolumeIndex ||
                    plan.VolumeIndex != row.VolumeIndex || plan.CandidateIndex != row.CandidateIndex || plan.CandidateIndex < 0 ||
                    plan.CandidateIndex >= MaxCandidates || plan.Number != number || plan.Ranges == null || plan.Ranges.Count > 100000 ||
                    plan.Candidate == null || plan.Bytes < 0 || plan.Bytes > MaxFileBytes || plan.Bytes > plan.Candidate.Length ||
                    plan.InitializedBytes < 0 || plan.InitializedBytes > plan.Bytes || plan.Reason == null || plan.Reason.Length > 2048 ||
                    !new[] { "candidate", "uncertain", "partial", "skipped" }.Contains(plan.Status))
                    throw new IOException("FAT_OUTPUT_PLAN_INVALID");
                var v = state.Volumes[row.VolumeIndex].Create();
                ValidateCandidate(v, plan.Candidate);
                if (plan.FileSystem != v.Kind || plan.VolumeOffset != v.Offset || plan.Method == null ||
                    !new[] { "contiguous-guess", "retained-fat-uncertain", "exfat-contiguous", "exfat-fat-chain",
                        "orphan-contiguous-guess", "orphan-retained-fat-uncertain", "orphan-exfat-contiguous", "orphan-exfat-fat-chain" }.Contains(plan.Method))
                    throw new IOException("FAT_OUTPUT_PLAN_INVALID");
                if (plan.Bytes == 0)
                {
                    if (plan.Status != "skipped" || plan.Path != "" || plan.Sha256 != null || plan.Ranges.Count != 0 || plan.InitializedBytes != 0)
                        throw new IOException("FAT_OUTPUT_PLAN_INVALID");
                    return;
                }
                string leaf = number.ToString("D6", CultureInfo.InvariantCulture) + (plan.Status == "partial" ? "_PARTIAL_" : "_") + SafeName(plan.Candidate.Name);
                if (leaf.EndsWith(".partial", StringComparison.OrdinalIgnoreCase)) leaf += ".recovered";
                string expected = "filesystem/files/volume-" + (row.VolumeIndex + 1).ToString("D3", CultureInfo.InvariantCulture) + "-" + v.Kind + "/" + plan.Method + "/" + leaf;
                if (plan.Path != expected || !FsHash(plan.Sha256) || plan.InitializedBytes != Math.Min(plan.Candidate.ValidLength, plan.Bytes))
                    throw new IOException("FAT_OUTPUT_PLAN_INVALID");
                long mapped = 0;
                foreach (FileExtent range in plan.Ranges)
                {
                    if (range == null || range.Offset < v.DataOffset || range.Length < 1 || range.Offset > v.Offset + v.Length - range.Length ||
                        mapped > plan.InitializedBytes - range.Length) throw new IOException("FAT_OUTPUT_PLAN_INVALID");
                    mapped += range.Length;
                }
                if (plan.MappingComplete && mapped != plan.InitializedBytes) throw new IOException("FAT_OUTPUT_PLAN_INVALID");
            }
            void ValidateExports()
            {
                int number = 0, recovered = 0, nextVolume = 0, nextCandidate = 0;
                long bytes = 0;
                foreach (FsExportEvent row in exports.Records)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (row.VolumeIndex != nextVolume) throw new IOException("FAT_EXPORT_ORDER_INVALID");
                    if (row.Kind == "candidate")
                    {
                        if (row.CandidateIndex != nextCandidate++) throw new IOException("FAT_EXPORT_ORDER_INVALID");
                        var plan = ReadPlan(root, row, cancel); ValidatePlan(plan, row, ++number);
                        if (plan.Bytes > 0)
                        {
                            if (!knownOutputs.Add(plan.Path)) throw new IOException("FAT_OUTPUT_PLAN_DUPLICATE");
                            recovered++; bytes += plan.Bytes;
                        }
                    }
                    else if (row.Kind == "volume")
                    {
                        if (row.FinishedVolume == null || row.FinishedVolume.Phase != "finished" || nextVolume >= state.VolumeIndex)
                            throw new IOException("FAT_VOLUME_SUMMARY_INVALID");
                        finished.Add(nextVolume++, row.FinishedVolume); nextCandidate = 0;
                    }
                    else throw new IOException("FAT_EXPORT_LEDGER_INVALID");
                }
                if (number != state.Number || recovered != state.Recovered || bytes != state.RecoveredBytes || nextVolume != state.VolumeIndex ||
                    state.VolumeIndex < state.Volumes.Count && nextCandidate != state.Current.ExportCursor)
                    throw new IOException("FAT_EXPORT_COUNTERS_INVALID");
            }
            void ValidateOutputInventory()
            {
                string folder = RecoveryCatalog.SafeFile(root, "filesystem/guard"); folder = Path.GetDirectoryName(folder);
                string[] reports = { "metadata.csv", "file-extents.jsonl", "report.json", "notes.json", "ПРОЧИТАЙ О РЕЗУЛЬТАТАХ.txt" };
                foreach (string file in Directory.EnumerateFiles(folder))
                {
                    RecoveryCatalog.SafeFile(root, "filesystem/" + Path.GetFileName(file));
                    if (!reports.Contains(Path.GetFileName(file)) && !Path.GetFileName(file).EndsWith(".partial", StringComparison.Ordinal))
                        throw new IOException("FAT_OUTPUT_UNEXPECTED");
                }
                foreach (string directory in Directory.EnumerateDirectories(folder))
                    if (Path.GetFileName(directory) != "files") throw new IOException("FAT_OUTPUT_UNEXPECTED");
                string files = RecoveryCatalog.SafeFile(root, "filesystem/files/guard"); files = Path.GetDirectoryName(files);
                if (!Directory.Exists(files)) return;
                foreach (string file in Directory.EnumerateFiles(files)) throw new IOException("FAT_OUTPUT_UNEXPECTED");
                var volumeNames = new HashSet<string>(state.Volumes.Select((v, i) => "volume-" + (i + 1).ToString("D3", CultureInfo.InvariantCulture) + "-" + v.Kind), StringComparer.Ordinal);
                foreach (string directory in Directory.EnumerateDirectories(files))
                {
                    if (!volumeNames.Contains(Path.GetFileName(directory))) throw new IOException("FAT_OUTPUT_UNEXPECTED");
                    RecoveryCatalog.SafeFile(root, directory.Substring(root.TrimEnd('\\').Length + 1) + "/guard");
                    foreach (string file in Directory.EnumerateFiles(directory)) throw new IOException("FAT_OUTPUT_UNEXPECTED");
                    foreach (string method in Directory.EnumerateDirectories(directory))
                    {
                        if (!new[] { "contiguous-guess", "retained-fat-uncertain", "exfat-contiguous", "exfat-fat-chain", "orphan-contiguous-guess",
                            "orphan-retained-fat-uncertain", "orphan-exfat-contiguous", "orphan-exfat-fat-chain" }.Contains(Path.GetFileName(method)))
                            throw new IOException("FAT_OUTPUT_UNEXPECTED");
                        RecoveryCatalog.SafeFile(root, method.Substring(root.TrimEnd('\\').Length + 1) + "/guard");
                        if (Directory.EnumerateDirectories(method).Any()) throw new IOException("FAT_OUTPUT_UNEXPECTED");
                        foreach (string file in Directory.EnumerateFiles(method))
                        {
                            string relative = file.Substring(root.TrimEnd('\\').Length + 1).Replace('\\', '/');
                            RecoveryCatalog.SafeFile(root, relative);
                            if (!knownOutputs.Contains(relative)) throw new IOException("FAT_OUTPUT_UNEXPECTED");
                        }
                    }
                }
            }
            FsMetadataView RepairVolume(int index)
            {
                if (repairVolume != index)
                {
                    FsVolumeProgress p = index == state.VolumeIndex ? state.Current : finished[index];
                    repairView = ReadMetadata(state.Volumes[index], p, context, cancel); repairVolume = index;
                }
                return repairView;
            }
            void RepairExports()
            {
                foreach (FsExportEvent row in exports.Records.Where(x => x.Kind == "candidate"))
                {
                    cancel.ThrowIfCancellationRequested();
                    var plan = ReadPlan(root, row, cancel);
                    if (plan.Bytes == 0) continue;
                    string path = RecoveryCatalog.SafeFile(root, plan.Path);
                    if (!File.Exists(path))
                    {
                        string scratch = FsScratch(root, plan.Number);
                        bool ready = File.Exists(scratch) && new FileInfo(scratch).Length == plan.Bytes &&
                            RecoveryCore.HashFile(scratch, cancel, (a, b) => { }) == plan.Sha256;
                        if (!ready)
                        {
                            var view = RepairVolume(row.VolumeIndex);
                            if (row.CandidateIndex >= view.Volume.Candidates.Count || !SameCandidate(plan.Candidate, view.Volume.Candidates[row.CandidateIndex]))
                                throw new IOException("FAT_REPAIR_CANDIDATE_CHANGED");
                            var rebuilt = PrepareCandidate(image, view.Volume, view.Volume.Candidates[row.CandidateIndex], root,
                                row.VolumeIndex, row.CandidateIndex, plan.Number, cancel);
                            var json = new JavaScriptSerializer { MaxJsonLength = MaximumPlanBytes };
                            if (json.Serialize(rebuilt) != json.Serialize(plan)) throw new IOException("FAT_REPAIR_PLAN_CHANGED");
                        }
                    }
                    PublishPlan(root, plan, cancel);
                }
                repairView = null; repairVolume = -1;
            }
            void Initialize()
            {
                var v = active.Volume;
                active.Queue.Enqueue(new DirectoryTask { FixedRoot = !v.Exfat && v.Bits != 32, Start = v.RootCluster, Path = "", Depth = 0 });
                if (v.RootCluster != 0) { v.Directories.Add(v.RootCluster); MarkLive(image, v, v.RootCluster, -1, false, cancel); }
                state.Current.Phase = "enumerate"; SaveMetadata();
            }
            void ProcessDirectory(bool orphan)
            {
                var p = state.Current;
                DirectoryTask task = active.Queue.Dequeue();
                byte[] bytes = DirectoryBytes(image, active.Volume, task, cancel);
                if (orphan)
                {
                    p.OrphanVisited++;
                    FatDirectory(image, active.Volume, bytes, task, active.Queue, ref p.OrphanEntries, cancel);
                }
                else
                {
                    p.MainVisited++;
                    if (active.Volume.Exfat) ExfatDirectory(image, active.Volume, bytes, task, active.Queue, ref p.MainEntries, cancel);
                    else FatDirectory(image, active.Volume, bytes, task, active.Queue, ref p.MainEntries, cancel);
                }
                p.QueueCursor++; SaveMetadata();
                Observe("FAT/exFAT: каталоги " + p.MainVisited + "; потерянные " + p.OrphanVisited + "; записи " + active.Volume.Candidates.Count);
            }
            void EnumerateVolume()
            {
                var p = state.Current; var v = active.Volume;
                while (active.Queue.Count > 0 && p.MainVisited < MaxDirectories && p.MainEntries < MaxEntries) ProcessDirectory(false);
                if (active.Queue.Count > 0 || p.MainEntries >= MaxEntries)
                { v.AllocationComplete = false; p.Notes.Add(v.Kind + ": directory traversal limit reached; allocated FAT candidates will be skipped."); }
                p.QueueCursor = active.Tasks.Count; active.Queue.Clear();
                p.Phase = "bitmap"; SaveMetadata();
            }
            void Bitmap()
            {
                var p = state.Current; var v = active.Volume;
                if (v.Exfat && v.BitmapStart != 0)
                {
                    bool complete;
                    v.BitmapChain = Chain(image, v, v.BitmapStart, v.BitmapLength, false, out complete, cancel);
                    if (!complete) { v.BitmapChain = null; v.AllocationComplete = false; p.Notes.Add("exFAT: allocation bitmap is truncated or corrupt; deleted candidates will be skipped."); }
                    else p.BitmapValid = true;
                }
                if (v.Exfat && v.BitmapChain == null) { v.AllocationComplete = false; p.Notes.Add("exFAT: no valid active allocation bitmap; deleted candidates will be skipped."); }
                if (!v.AllocationComplete) p.Notes.Add(v.Kind + ": current allocation ownership could not be completely enumerated.");
                p.Notes.Add(v.Kind + " at offset " + v.Offset + ": " + p.MainVisited + " directories, " + v.Candidates.Count + " deleted file records.");
                if (!v.AllocationComplete) state.Limited = true;
                if (orphanDirectories && !v.Exfat && v.AllocationComplete) p.Phase = "orphan";
                else
                {
                    if (orphanDirectories) p.Notes.Add(v.Exfat ? "Orphan-directory sweep: exFAT is not supported by this detector." : "Orphan-directory sweep skipped: live ownership incomplete.");
                    p.Phase = "export";
                }
                SaveMetadata(true);
            }
            void Orphans()
            {
                var p = state.Current; var v = active.Volume;
                long chunk = Math.Max(4L * 1024 * 1024, v.ClusterBytes);
                byte[] data = new byte[(int)chunk];
                while (p.OrphanCluster < v.ClusterCount || active.Queue.Count > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    while (active.Queue.Count > 0 && p.OrphanVisited < MaxDirectories && p.OrphanEntries < MaxEntries) ProcessDirectory(true);
                    if (p.OrphanFound >= MaxDirectories || p.OrphanVisited >= MaxDirectories || p.OrphanEntries >= MaxEntries)
                    {
                        p.Notes.Add("Orphan-directory sweep limit reached."); v.AllocationComplete = false; state.Limited = true; break;
                    }
                    if (p.OrphanCluster >= v.ClusterCount) break;
                    long first = p.OrphanCluster;
                    int clusters = (int)Math.Min(chunk / v.ClusterBytes, v.ClusterCount - first), count = (int)(clusters * v.ClusterBytes);
                    image.Read(v.DataOffset + first * v.ClusterBytes, data, count);
                    bool found = false;
                    for (int c = 0; c < clusters; c++)
                    {
                        cancel.ThrowIfCancellationRequested();
                        uint cluster = (uint)(first + c + 2);
                        if (!OrphanAt(v, data, (int)(c * v.ClusterBytes), cluster)) continue;
                        v.Directories.Add(cluster);
                        active.Queue.Enqueue(new DirectoryTask { Start = cluster, Deleted = true, Path = "/orphan-directory-cluster-" + cluster, Depth = 0 });
                        p.OrphanFound++; p.OrphanCluster = first + c + 1; found = true; break;
                    }
                    if (!found) p.OrphanCluster = first + clusters;
                    SaveMetadata();
                    Observe("Потерянные каталоги FAT: " + p.OrphanCluster * 100 / Math.Max(1, v.ClusterCount) + "%");
                }
                p.QueueCursor = active.Tasks.Count; active.Queue.Clear();
                p.Notes.Add("Orphan-directory candidates: " + p.OrphanFound + ". Parent/deletion state not inferred; live clusters excluded.");
                p.Phase = "export"; SaveMetadata();
            }
            void Export()
            {
                var p = state.Current; var v = active.Volume;
                while (p.ExportCursor < v.Candidates.Count)
                {
                    cancel.ThrowIfCancellationRequested();
                    Candidate candidate = v.Candidates[p.ExportCursor];
                    if (state.Number >= MaxCandidates || candidate.Length > image.Length * 2L - state.RecoveredBytes)
                    { state.Limited = true; p.Notes.Add("Recovery output budget reached; remaining metadata candidates not exported."); break; }
                    var plan = PrepareCandidate(image, v, candidate, root, state.VolumeIndex, p.ExportCursor, state.Number + 1, cancel);
                    var row = StorePlan(root, plan, cancel);
                    state.Number++; p.ExportCursor++;
                    if (plan.Bytes > 0) { state.Recovered++; state.RecoveredBytes += plan.Bytes; }
                    SaveExports(new[] { row });
                    if (plan.Bytes > 0) knownOutputs.Add(plan.Path);
                    PublishPlan(root, plan, cancel);
                    Observe("По метаданным сохранено: " + state.Recovered + "; проверено записей: " + state.Number);
                }
                p.Phase = "finished";
                var summary = new FsExportEvent { Kind = "volume", VolumeIndex = state.VolumeIndex, FinishedVolume = p };
                finished.Add(state.VolumeIndex, p);
                state.VolumeIndex++; state.Current = new FsVolumeProgress();
                SaveExports(new[] { summary }); active = null;
            }
            public int Run()
            {
                try
                {
                    while (state.VolumeIndex < state.Volumes.Count)
                    {
                        cancel.ThrowIfCancellationRequested();
                        active = ReadMetadata(state.Volumes[state.VolumeIndex], state.Current, context, cancel);
                        if (state.Current.Phase == "initialize") Initialize();
                        Observe("Поиск удалённых записей " + active.Volume.Kind + "…");
                        Observe("FAT/exFAT: каталоги " + state.Current.MainVisited + "; потерянные " + state.Current.OrphanVisited + "; записи " + active.Volume.Candidates.Count);
                        if (state.Current.Phase == "enumerate") EnumerateVolume();
                        if (state.Current.Phase == "bitmap") Bitmap();
                        if (state.Current.Phase == "orphan") Orphans();
                        if (state.Current.Phase == "export") Export();
                    }
                    state.Complete = true; Save();
                    if (state.Limited) throw new IOException("Поиск по метаданным завершён частично: повреждение или предел обработки. Сохранённые кандидаты и отчёт доступны в filesystem.");
                    return state.Recovered;
                }
                finally
                {
                    var notes = new List<string>(state.DiscoveryNotes);
                    foreach (var row in exports.Records.Where(x => x.Kind == "volume")) notes.AddRange(row.FinishedVolume.Notes);
                    if (state.VolumeIndex < state.Volumes.Count) notes.AddRange(state.Current.Notes);
                    if (state.Volumes.Count == 0) notes.Add("No supported FAT/exFAT volume found. No absence-of-data conclusion is implied.");
                    WriteFsReports(root, exports.Records, notes, state.Volumes.Count, state.Recovered, state.RecoveredBytes,
                        state.Complete && !state.Limited && !cancel.IsCancellationRequested, state.Limited, cancel);
                }
            }
        }

        static bool OrphanAt(Volume v, byte[] data, int at, uint cluster)
        {
            if (v.Directories.Contains(cluster) || v.LiveClusters.Contains(cluster)) return false;
            byte[] dot = Encoding.ASCII.GetBytes(".          "), dotdot = Encoding.ASCII.GetBytes("..         ");
            for (int n = 0; n < 11; n++) if (data[at + n] != dot[n] || data[at + 32 + n] != dotdot[n]) return false;
            if (data[at + 11] != 0x10 || data[at + 43] != 0x10 || U32(data, at + 28) != 0 || U32(data, at + 60) != 0) return false;
            uint self = U16(data, at + 26), parent = U16(data, at + 58);
            if (v.Bits == 32) { self |= (uint)U16(data, at + 20) << 16; parent |= (uint)U16(data, at + 52) << 16; }
            if (self != cluster || parent != 0 && !ClusterValid(v, parent) || data[at + 64] == 0) return false;
            for (int entry = 64; entry + 32 <= Math.Min(v.ClusterBytes, 4096); entry += 32)
            {
                if (data[at + entry] == 0) break;
                if (data[at + entry + 11] != 0x0f && ValidShortName(data, at + entry, data[at + entry] == 0xe5) && (data[at + entry + 11] & 0xc8) == 0) return true;
            }
            return false;
        }

        static int RecoverCheckpointed(string imagePath, string runDirectory, CancellationToken cancel, Action<string> progress,
            IList<BootCandidate> discovered, bool alternateFat, bool orphanDirectories, RecoveryCheckpointContext checkpoint)
        {
            cancel.ThrowIfCancellationRequested();
            string imageFull = Path.GetFullPath(imagePath), runFull = Path.GetFullPath(runDirectory);
            if (imageFull.StartsWith("\\\\", StringComparison.Ordinal) || imageFull.IndexOf(':', 2) >= 0 || !File.Exists(imageFull) ||
                (File.GetAttributes(imageFull) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Filesystem recovery requires a regular local image file.");
            RejectReparseParents(imageFull); RejectReparseParents(runFull);
            string folder = OutputPath(runFull, "filesystem");
            if (imageFull.Equals(folder, StringComparison.OrdinalIgnoreCase) || imageFull.StartsWith(folder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Source image must be outside the recovery output directory.");
            if (Directory.Exists(folder) && (checkpoint == null || checkpoint.Resume == null))
                throw new IOException("Filesystem output directory already exists; choose a fresh recovery run.");
            Directory.CreateDirectory(folder);
            using (var image = new ImageReader(imageFull, cancel))
                return new FsRuntime(imageFull, runFull, image, discovered, alternateFat, orphanDirectories, cancel, progress, checkpoint).Run();
        }
    }
}
