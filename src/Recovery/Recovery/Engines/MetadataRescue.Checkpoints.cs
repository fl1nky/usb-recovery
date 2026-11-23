using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace UsbRecovery
{
    public static partial class MetadataRescue
    {
        sealed class RescueRuntime
        {
            readonly string root;
            readonly FileStream input;
            readonly CancellationToken cancel;
            readonly Action<string> observe;
            readonly bool allowUnknown;
            readonly RescueReadMaps maps;
            readonly RecoveryMethodJournal<RescueState> journal;
            readonly RescueState state;
            readonly RecoveryOutputLedger<RescueFact> metadata;
            readonly RecoveryOutputLedger<RescueBlob> outputs;
            readonly List<Volume> volumes = new List<Volume>();
            readonly List<Record> candidates = new List<Record>();
            readonly List<RescuePlan> plans = new List<RescuePlan>();
            readonly HashSet<string> knownOutputs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            public RescueRuntime(string image, string destination, FileStream reader, IList<BootCandidate> discovered,
                bool unknown, CancellationToken token, Action<string> progress, RescueReadMaps readMaps,
                RecoveryCheckpointContext context)
            {
                root = destination; input = reader; cancel = token; observe = progress; allowUnknown = unknown; maps = readMaps;
                bool untrusted = maps.Untrusted || UntrustedReadMap(image, root, input.Length);
                var initial = new RescueState { ReadMapIdentity = maps.Identity, AllocationUntrusted = untrusted };
                initial.Counters.InputBytes = input.Length;
                if (untrusted) initial.Counters.Warnings.Add("В образе известны пропуски чтения либо карта ошибок неполна/повреждена. Занятость кластеров NTFS не считается подтверждённой: nonresident-потоки пропущены; resident-кандидаты также могут содержать пропуски.");
                journal = new RecoveryMethodJournal<RescueState>(image, initial, context, cancel);
                state = journal.Payload;
                ValidateState(untrusted);
                metadata = new RecoveryOutputLedger<RescueFact>(context, state.Metadata, MaximumFacts, cancel);
                outputs = new RecoveryOutputLedger<RescueBlob>(context, state.Outputs, MaximumCandidates, cancel);
                ReadFacts();
                if (state.Phase != "scan") PrepareVolumes();
                ReadOutputs();
                VerifyInventory();
                RepairOutputs();
                if (!state.Initialized)
                {
                    var rows = new List<RescueFact>();
                    if (discovered != null) foreach (BootCandidate known in discovered)
                    {
                        cancel.ThrowIfCancellationRequested();
                        if (known.Kind != "NTFS") continue;
                        byte[] boot = Read(input, known.BootOffset, 512);
                        if (boot != null) RememberVolume(DecodeBoot(boot, known.Offset, input.Length), rows);
                    }
                    state.Initialized = true; Save(rows, new RescueBlob[0]);
                }
            }
            void ValidateState(bool untrusted)
            {
                Report r = state == null ? null : state.Counters;
                if (r == null || state.ReadMapIdentity != maps.Identity || state.AllocationUntrusted != untrusted ||
                    !new[] { "scan", "prepare", "export", "complete" }.Contains(state.Phase) ||
                    state.ScanOffset < 0 || state.ScanOffset > input.Length || state.ScanOffset != input.Length && state.ScanOffset % ScanUnitBytes != 0 ||
                    state.Phase != "scan" && state.ScanOffset != input.Length || state.ExportCursor < 0 || state.ExportCursor > MaximumCandidates ||
                    state.TotalRuns < 0 || state.TotalRuns > MaximumTotalRuns || r.Schema != 2 || r.ScanAlignment != Stride ||
                    r.Method != "orphan_ntfs_records" || r.InputBytes != input.Length || r.ScannedBytes != state.ScanOffset ||
                    r.Entries == null || r.Entries.Count != 0 || r.Warnings == null || r.Warnings.Count > 128 ||
                    r.Warnings.Any(x => x == null || x.Length > 8192) || r.ValidatedRecords < 0 || r.InvalidSignatures < 0 ||
                    r.DeletedCandidates < 0 || r.DeletedCandidates > r.ValidatedRecords || r.RecoveredFiles < 0 ||
                    r.RecoveredFiles > state.ExportCursor || r.OutputBytes < 0 || r.OutputBytes > MaximumOutputBytes ||
                    r.ResolvedPaths < 0 || r.UnresolvedPaths < 0 || r.DirectoryRecordsChecked < 0 || r.DirectoryRecordsChecked > MaximumDirectoryRecords ||
                    r.DirectoryEvidenceLinks < 0 || r.DirectoryEvidenceLinks > MaximumDirectoryEvidenceLinks ||
                    r.PathReportCharacters < 0 || r.PathReportCharacters > MaximumPathReportCharacters ||
                    !state.Initialized && (state.Metadata != null || state.Outputs != null || state.ScanOffset != 0 || state.ExportCursor != 0))
                    throw new IOException("NTFS_RECORD_CHECKPOINT_INVALID");
            }
            void Observe(string text) { if (observe != null) observe(text); }
            void Save(IList<RescueFact> facts, IList<RescueBlob> added)
            {
                maps.Verify();
                state.Metadata = metadata.Append(state.Metadata, facts);
                state.Outputs = outputs.Append(state.Outputs, added);
                journal.Save(state);
                metadata.Accept(facts); outputs.Accept(added);
                foreach (Volume v in volumes) { v.NewPathNodes.Clear(); v.NewInvalidPathNodes.Clear(); }
            }
            void Save() { Save(new RescueFact[0], new RescueBlob[0]); }
            void RememberVolume(Volume volume, List<RescueFact> rows)
            {
                int before = volumes.Count; AddVolume(volumes, volume);
                if (volumes.Count != before) rows.Add(new RescueFact { Kind = "volume", Volume = RescueVolume.From(volume) });
            }
            void ValidateCandidate(Record record)
            {
                if (record == null || record.Offset < 0 || record.Offset % Stride != 0 || record.Offset >= state.ScanOffset ||
                    !Power(record.Size) || record.Size < 512 || record.Size > MaximumRecordBytes || record.Offset > input.Length - record.Size ||
                    record.Flags != 0 || record.Number < 16 || record.Number > UInt32.MaxValue || record.Name == null ||
                    record.Name.Length < 1 || record.Name.Length > 255 || record.Sequence < 1 || record.Sequence > UInt16.MaxValue ||
                    record.Data == null || record.Data.Runs == null || record.Data.Runs.Count > MaximumRuns || record.Data.FileSize < 0 ||
                    record.Data.ValidLength < 0 || record.Data.ValidLength > record.Data.FileSize ||
                    record.Data.Runs.Any(x => x == null || x.Clusters < 1 || x.Vcn < 0 || x.Lcn < 0))
                    throw new IOException("NTFS_RECORD_CANDIDATE_INVALID");
            }
            void ReadFacts()
            {
                var offsets = new HashSet<long>(); int runs = 0, nodes = 0;
                foreach (RescueFact fact in metadata.Records)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (fact.Kind == "volume")
                    {
                        if (fact.Volume == null || volumes.Count >= 128) throw new IOException("NTFS_RECORD_VOLUME_INVALID");
                        int before = volumes.Count; AddVolume(volumes, fact.Volume.Create(input.Length));
                        if (before == volumes.Count) throw new IOException("NTFS_RECORD_VOLUME_DUPLICATE");
                    }
                    else if (fact.Kind == "candidate")
                    {
                        if (candidates.Count >= MaximumCandidates || fact.InlineCandidate != null && fact.Candidate != null ||
                            fact.InlineCandidate == null && (fact.Candidate == null || fact.Candidate.Index != candidates.Count))
                            throw new IOException("NTFS_RECORD_CANDIDATE_ORDER_INVALID");
                        var record = fact.InlineCandidate ?? ReadRescueBlob<Record>(root, "candidates", fact.Candidate, cancel);
                        ValidateCandidate(record);
                        if (fact.InlineCandidate != null && record.Data.Runs.Count > 64) throw new IOException("NTFS_RECORD_INLINE_CANDIDATE_INVALID");
                        if (!offsets.Add(record.Offset) || runs > MaximumTotalRuns - record.Data.Runs.Count)
                            throw new IOException("NTFS_RECORD_CANDIDATE_LIMIT");
                        runs += record.Data.Runs.Count; candidates.Add(record);
                    }
                    else if (fact.Kind == "node" || fact.Kind == "invalid-node")
                    {
                        if (fact.VolumeIndex < 0 || fact.VolumeIndex >= volumes.Count || ++nodes > MaximumDirectoryRecords)
                            throw new IOException("NTFS_RECORD_PATH_CACHE_INVALID");
                        var v = volumes[fact.VolumeIndex];
                        long number = fact.Kind == "node" && fact.Node != null ? fact.Node.Number : fact.InvalidNode;
                        if (number < 0 || number > 0x0000ffffffffffffL || v.PathNodes.ContainsKey(number) || v.InvalidPathNodes.Contains(number))
                            throw new IOException("NTFS_RECORD_PATH_CACHE_INVALID");
                        if (fact.Kind == "invalid-node") v.InvalidPathNodes.Add(number);
                        else
                        {
                            var n = fact.Node;
                            if (n == null || n.Offset < 0 || n.Offset > input.Length - 48 || n.Name != null && n.Name.Length > 255 ||
                                n.Sequence < 1 || n.Sequence > UInt16.MaxValue || n.ParentSequence < 0 || n.ParentSequence > UInt16.MaxValue ||
                                n.Parent < 0 || n.Parent > 0x0000ffffffffffffL || (n.Flags & ~15) != 0)
                                throw new IOException("NTFS_RECORD_PATH_CACHE_INVALID");
                            v.PathNodes.Add(number, n);
                        }
                    }
                    else throw new IOException("NTFS_RECORD_METADATA_INVALID");
                }
                if (runs != state.TotalRuns || nodes != state.Counters.DirectoryRecordsChecked ||
                    state.ExportCursor > candidates.Count || state.Counters.DeletedCandidates < candidates.Count ||
                    state.Phase == "scan" && (state.ExportCursor != 0 || nodes != 0) ||
                    state.Phase == "complete" && state.ExportCursor != candidates.Count)
                    throw new IOException("NTFS_RECORD_METADATA_COUNTERS_INVALID");
            }
            void PrepareVolumes()
            {
                foreach (Volume volume in volumes)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (state.AllocationUntrusted) volume.BitmapProblem = "source_read_errors_allocation_untrusted";
                    else PrepareBitmap(input, volume, cancel);
                }
            }
            void ReadOutputs()
            {
                int recovered = 0, resolved = 0, unresolved = 0, links = 0, characters = 0; long bytes = 0;
                foreach (RescueBlob blob in outputs.Records)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (blob.Index != plans.Count || blob.Index >= candidates.Count) throw new IOException("NTFS_RECORD_OUTPUT_ORDER_INVALID");
                    var plan = ReadRescueBlob<RescuePlan>(root, "plans", blob, cancel);
                    ValidatePlan(plan, blob.Index);
                    var item = plan.Item;
                    if (item.Output != null)
                    {
                        if (!knownOutputs.Add(item.Output)) throw new IOException("NTFS_RECORD_OUTPUT_DUPLICATE");
                        recovered++; bytes += item.RecoveredBytes;
                    }
                    if (item.OriginalPath != null) { resolved++; characters += item.OriginalPath.Length; } else unresolved++;
                    links += item.DirectoryChain.Count; plans.Add(plan);
                }
                var r = state.Counters;
                if (plans.Count != state.ExportCursor || recovered != r.RecoveredFiles || bytes != r.OutputBytes ||
                    resolved != r.ResolvedPaths || unresolved != r.UnresolvedPaths || links != r.DirectoryEvidenceLinks || characters != r.PathReportCharacters)
                    throw new IOException("NTFS_RECORD_OUTPUT_COUNTERS_INVALID");
            }
            void ValidatePlan(RescuePlan plan, int index)
            {
                var item = plan == null ? null : plan.Item; var record = candidates[index];
                if (item == null || plan.Schema != 1 || plan.CandidateIndex != index || item.RecordOffset != record.Offset ||
                    item.RecordNumber != record.Number || item.Sequence != record.Sequence || item.Name != record.Name ||
                    item.ParentRecordNumber != (record.Parent & 0x0000ffffffffffffL) || item.ParentSequence != record.ParentSequence ||
                    item.DeclaredSize != record.Data.FileSize || item.InitializedBytes != record.Data.ValidLength || item.UsaFixupsRestored != record.Data.Resident ||
                    item.RecoveredBytes < 0 || item.RecoveredBytes > item.DeclaredSize || item.RecoveredBytes > MaximumFileBytes ||
                    item.Extents == null || item.Extents.Count > MaximumRuns || item.Extents.Any(x => x == null || x.ImageOffset < 0 ||
                        x.Length < 1 || x.ImageOffset > input.Length - x.Length || x.LogicalOffset < 0) ||
                    item.DirectoryChain == null || item.DirectoryChain.Count > MaximumPathDepth || item.DirectoryChain.Any(x => x == null ||
                        x.Name != null && x.Name.Length > 255) || item.Note == null || item.Note.Length > 8192 ||
                    item.Reason == null || item.Reason.Length > 2048 || item.PathEvidence == null || item.PathEvidence.Length > 8192 ||
                    item.PathStatus == null || item.PathStatus.Length > 128 || item.OriginalPath != null &&
                        (item.OriginalPath.Length > MaximumPathCharacters || item.PathStatus != "verified_parent_chain"))
                    throw new IOException("NTFS_RECORD_OUTPUT_PLAN_INVALID");
                if (item.Output == null)
                {
                    if (item.RecoveredBytes != 0 || item.Sha256 != null || item.Status != "not_extracted") throw new IOException("NTFS_RECORD_OUTPUT_PLAN_INVALID");
                    return;
                }
                string expected = RescueOutputName(record, item.RecoveredBytes);
                if (item.Output != expected || item.RecoveredBytes < 1 || !RescueHash(item.Sha256) ||
                    !new[] { "resident_candidate", "unallocated_candidate", "partial_candidate", "allocation_unknown_candidate" }.Contains(item.Status))
                    throw new IOException("NTFS_RECORD_OUTPUT_PLAN_INVALID");
                long mapped = 0;
                foreach (var extent in item.Extents)
                {
                    if (extent.LogicalOffset != mapped || extent.Length > item.RecoveredBytes - mapped) throw new IOException("NTFS_RECORD_OUTPUT_PLAN_INVALID");
                    mapped += extent.Length;
                }
                if (mapped != item.RecoveredBytes) throw new IOException("NTFS_RECORD_OUTPUT_PLAN_INVALID");
            }
            void VerifyInventory()
            {
                string folder = Path.GetDirectoryName(RecoveryCatalog.SafeFile(root, "metadata-rescue/guard"));
                foreach (string file in Directory.EnumerateFiles(folder))
                {
                    RecoveryCatalog.SafeFile(root, "metadata-rescue/" + Path.GetFileName(file));
                    if (Path.GetFileName(file) != "report.json" && !Path.GetFileName(file).EndsWith(".partial", StringComparison.Ordinal))
                        throw new IOException("NTFS_RECORD_OUTPUT_UNEXPECTED");
                }
                foreach (string directory in Directory.EnumerateDirectories(folder))
                    if (Path.GetFileName(directory) != "files") throw new IOException("NTFS_RECORD_OUTPUT_UNEXPECTED");
                string files = Path.GetDirectoryName(RecoveryCatalog.SafeFile(root, "metadata-rescue/files/guard"));
                if (!Directory.Exists(files)) return;
                if (Directory.EnumerateDirectories(files).Any()) throw new IOException("NTFS_RECORD_OUTPUT_UNEXPECTED");
                foreach (string file in Directory.EnumerateFiles(files))
                {
                    string relative = "files/" + Path.GetFileName(file);
                    RecoveryCatalog.SafeFile(root, "metadata-rescue/" + relative);
                    if (!knownOutputs.Contains(relative)) throw new IOException("NTFS_RECORD_OUTPUT_UNEXPECTED");
                }
            }
            void RepairOutputs()
            {
                foreach (RescuePlan plan in plans.Where(x => x.Item.Output != null))
                {
                    cancel.ThrowIfCancellationRequested();
                    string target = RecoveryCatalog.SafeFile(root, "metadata-rescue/" + plan.Item.Output);
                    if (!File.Exists(target))
                    {
                        string scratch = RescueScratch(root, plan.CandidateIndex);
                        if (!RescueMatches(scratch, plan.Item, cancel))
                        {
                            var record = candidates[plan.CandidateIndex];
                            if (RescueJson(ParseAt(input, record.Offset)) != RescueJson(record)) throw new IOException("NTFS_RECORD_REPAIR_RECORD_CHANGED");
                            var rebuilt = PrepareRescueEntry(input, volumes, record, root, plan.CandidateIndex, state.Counters,
                                state.AllocationUntrusted, allowUnknown, MaximumOutputBytes, cancel, plan.Item);
                            if (RescueJson(rebuilt) != RescueJson(plan.Item)) throw new IOException("NTFS_RECORD_REPAIR_PLAN_CHANGED");
                        }
                    }
                    maps.Verify(); PublishRescue(root, plan, cancel);
                }
            }
            void Scan()
            {
                byte[] block = new byte[ScanUnitBytes];
                while (state.ScanOffset < input.Length)
                {
                    cancel.ThrowIfCancellationRequested();
                    long position = state.ScanOffset; input.Position = position;
                    int count = ReadScanUnit(input, block, (int)Math.Min(block.Length, input.Length - position));
                    var facts = new List<RescueFact>();
                    for (int at = 0; at + 48 <= count; at += Stride)
                    {
                        if ((at & 65535) == 0) cancel.ThrowIfCancellationRequested();
                        long offset = position + at;
                        if (at + 512 <= count && block[at + 3] == 'N' && block[at + 4] == 'T' && block[at + 5] == 'F' && block[at + 6] == 'S')
                        {
                            byte[] boot = new byte[512]; Buffer.BlockCopy(block, at, boot, 0, 512);
                            RememberVolume(DecodeBoot(boot, offset, input.Length, allowUnknown), facts);
                            long length = BootLength(boot);
                            if (length >= 512 && offset >= length - 512) RememberVolume(DecodeBoot(boot, offset - length + 512, input.Length), facts);
                        }
                        if (block[at] != 'F' || block[at + 1] != 'I' || block[at + 2] != 'L' || block[at + 3] != 'E') continue;
                        var record = ParseAt(input, offset);
                        if (record == null) { state.Counters.InvalidSignatures++; continue; }
                        state.Counters.ValidatedRecords++;
                        if (record.Flags != 0 || record.Name == null || record.Data == null || record.Number < 16) continue;
                        state.Counters.DeletedCandidates++;
                        if (candidates.Count >= MaximumCandidates || record.Data.Runs.Count > MaximumTotalRuns - state.TotalRuns)
                        { state.Counters.CandidateLimitReached = true; continue; }
                        // Small parsed metadata shares immutable ledger pages.
                        // File payload bytes remain solely in the source image.
                        // Large run lists use separate bounded blobs.
                        var fact = new RescueFact { Kind = "candidate" };
                        if (record.Data.Runs.Count <= 64) fact.InlineCandidate = record;
                        else fact.Candidate = StoreRescueBlob(root, "candidates", candidates.Count, record, cancel);
                        facts.Add(fact);
                        candidates.Add(record); state.TotalRuns += record.Data.Runs.Count;
                    }
                    state.ScanOffset = position + count; state.Counters.ScannedBytes = state.ScanOffset; Save(facts, new RescueBlob[0]);
                    ObserveScan();
                }
                state.Phase = "prepare"; Save();
            }
            void ObserveScan()
            {
                Observe("Записи NTFS: просмотрено " + state.ScanOffset / (1024 * 1024) + " МБ, кандидатов " + candidates.Count);
            }
            List<RescueFact> PathFacts()
            {
                var facts = new List<RescueFact>();
                for (int i = 0; i < volumes.Count; i++)
                {
                    foreach (var node in volumes[i].NewPathNodes) facts.Add(new RescueFact { Kind = "node", VolumeIndex = i, Node = node });
                    foreach (long node in volumes[i].NewInvalidPathNodes) facts.Add(new RescueFact { Kind = "invalid-node", VolumeIndex = i, InvalidNode = node });
                }
                return facts;
            }
            void Export()
            {
                while (state.ExportCursor < candidates.Count)
                {
                    cancel.ThrowIfCancellationRequested(); int index = state.ExportCursor;
                    Entry item = PrepareRescueEntry(input, volumes, candidates[index], root, index, state.Counters,
                        state.AllocationUntrusted, allowUnknown, MaximumOutputBytes - state.Counters.OutputBytes, cancel);
                    var plan = new RescuePlan { CandidateIndex = index, Item = item };
                    ValidatePlan(plan, index);
                    var blob = StoreRescueBlob(root, "plans", index, plan, cancel);
                    state.ExportCursor++;
                    if (item.Output != null) { state.Counters.RecoveredFiles++; state.Counters.OutputBytes += item.RecoveredBytes; }
                    Save(PathFacts(), new[] { blob }); plans.Add(plan);
                    if (item.Output != null) knownOutputs.Add(item.Output);
                    maps.Verify(); PublishRescue(root, plan, cancel);
                    Observe("Записи NTFS: сохранено " + state.Counters.RecoveredFiles + "; обработано записей " + state.ExportCursor);
                }
                state.Phase = "complete"; Save();
            }
            public int Run()
            {
                bool failed = false, cancelled = false;
                try
                {
                    if (journal.Resumed) ObserveScan();
                    if (state.Phase == "scan") Scan();
                    if (state.Phase == "prepare") { PrepareVolumes(); state.Phase = "export"; Save(); }
                    if (state.Phase == "export") Export();
                    return state.Counters.RecoveredFiles;
                }
                catch (OperationCanceledException) { cancelled = true; throw; }
                catch { failed = true; throw; }
                finally { WriteRescueReport(root, state, plans, volumes, allowUnknown, failed, cancelled, cancel); }
            }
        }

        static int ReadScanUnit(Stream input, byte[] buffer, int wanted)
        {
            int count = ReadInto(input, buffer, 0, wanted);
            if (count != wanted) throw new IOException("NTFS_RECORD_SCAN_SHORT_READ");
            return count;
        }
        static int RecoverCheckpointed(string image, string runDirectory, CancellationToken cancel, Action<string> progress,
            IList<BootCandidate> discovered, bool allowUnknown, RecoveryCheckpointContext checkpoint)
        {
            cancel.ThrowIfCancellationRequested(); string source = LocalImage(image), root = Path.GetFullPath(runDirectory);
            SafeAncestors(root);
            string folder = Path.GetDirectoryName(RecoveryCatalog.SafeFile(root, "metadata-rescue/guard"));
            string stateFolder = Path.GetDirectoryName(RecoveryCatalog.SafeFile(root, "ntfs-records.state/guard"));
            foreach (string owned in new[] { folder, stateFolder })
                if (source.StartsWith(owned + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || source.Equals(owned, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("NTFS_RECORD_SOURCE_WITHIN_OUTPUT");
            if ((Directory.Exists(folder) || File.Exists(folder)) && (checkpoint == null || checkpoint.Resume == null))
                throw new IOException("Папка поиска записей NTFS уже существует");
            Directory.CreateDirectory(folder);
            Directory.CreateDirectory(Path.GetDirectoryName(RecoveryCatalog.SafeFile(root, "metadata-rescue/files/guard")));
            // The scanner already owns a 4-MiB block. Per-record seeks must not
            // trigger a second 4-MiB read-ahead for each 48-byte/1-KiB read.
            using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 4096))
            using (var maps = new RescueReadMaps(source, root, cancel))
                return new RescueRuntime(source, root, input, discovered, allowUnknown, cancel, progress, maps, checkpoint).Run();
        }
    }
}
