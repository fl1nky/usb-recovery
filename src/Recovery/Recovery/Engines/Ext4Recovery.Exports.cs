using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class ExportProgress
        {
            public int Schema = 1, Next, Repair = -1;
            public string Identity, Eligibility;
            public bool Complete;
            public RecoveryMethodCheckpoint Prepare, Plan, Copy, RepairCopy;
            public RecoveryOutputHead Facts;
        }
        sealed class ExportFact
        {
            public int Index, Next;
            public string Kind, Manifest, Eligibility;
            public bool Limited;
            public Dictionary<string,int> Skips;
        }
        sealed class ExportCandidate { public Inode Inode; public HistoricalCandidate History; }
        sealed class EligibilityPayload { public int Schema = 1; public string Data; }

        sealed class VolumeExportCheckpoint
        {
            readonly Context c;
            readonly Volume v;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly List<ExportCandidate> candidates;
            readonly Dictionary<uint,List<NameLink>> names;
            readonly RecoveryMethodJournal<ExportProgress> journal;
            readonly RecoveryOutputLedger<ExportFact> ledger;
            ExportProgress state;

            public VolumeExportCheckpoint(Context owner, Volume volume, List<Inode> current,
                Dictionary<uint,HistoricalCandidate> history, Dictionary<uint,List<NameLink>> references,
                RecoveryCheckpointContext checkpoint, Action<string> notify)
            {
                c = owner; v = volume; context = checkpoint; progress = notify; names = references;
                ValidateMetadataSource(c, context);
                string outputRoot = Path.GetFullPath(c.Root), source = Path.GetFullPath(c.Input.Name);
                NoLinks(outputRoot);
                if (source.Equals(outputRoot,StringComparison.OrdinalIgnoreCase) || source.StartsWith(outputRoot+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))
                    throw new IOException("EXT4_EXPORT_SOURCE_IN_OUTPUT");
                if (current == null || names == null || current.Count > c.Limits.MaximumCandidates - c.Report.Entries.Count)
                    throw new IOException("EXT4_EXPORT_INPUT_INVALID");
                candidates = current.Select(x => new ExportCandidate { Inode = x }).ToList();
                if (history != null) foreach (var item in history)
                {
                    var old = item.Value;
                    if (old == null || item.Key != old.Number) throw new IOException("EXT4_EXPORT_HISTORY_INVALID");
                    candidates.Add(new ExportCandidate { History = old, Inode = new Inode {
                        Number = old.Number, Offset = v.Offset + (long)old.TargetDiskBlock * v.BlockBytes + old.OffsetInBlock,
                        Mode = old.Mode, Links = old.Links, Dtime = old.Dtime, Flags = old.Flags, Generation = old.Generation,
                        Size = old.Size, Allocated = false, Bytes = old.InodeBytes } });
                }
                var initial = new ExportProgress { Identity = ExportIdentity(), Complete = candidates.Count == 0 };
                journal = new RecoveryMethodJournal<ExportProgress>(c.Input.Name, initial, context, c.Cancel); state = journal.Payload;
                if (state.Schema != 1 || state.Identity != initial.Identity || state.Next < 0 || state.Next > candidates.Count ||
                    state.Complete != (state.Next == candidates.Count) || state.Complete && (state.Prepare != null || state.Plan != null || state.Copy != null || state.Eligibility != null) ||
                    state.Repair < -1 || state.Repair >= state.Next || state.Repair == -1 && state.RepairCopy != null)
                    throw new IOException("EXT4_EXPORT_CHECKPOINT_INVALID");
                if (state.Next < candidates.Count && candidates[state.Next].History == null && state.Eligibility != null)
                    throw new IOException("EXT4_EXPORT_ELIGIBILITY_ROLE_INVALID");
                ledger = new RecoveryOutputLedger<ExportFact>(context, state.Facts, Math.Max(1,candidates.Count), c.Cancel,
                    RecoveryLedgerScope.MethodOutput, Math.Max(1024,(long)Math.Max(1,candidates.Count)*256*1024));
            }
            ExportProgress Clone()
            { return new ExportProgress { Identity = state.Identity, Next = state.Next, Repair = state.Repair, Complete = state.Complete,
                Eligibility = state.Eligibility, Prepare = state.Prepare, Plan = state.Plan, Copy = state.Copy, RepairCopy = state.RepairCopy, Facts = state.Facts }; }
            void Save(ExportProgress next)
            { c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits(); journal.Save(next); state = next; }
            static string Slot(int index) { return "candidate-"+index.ToString("D8",CultureInfo.InvariantCulture); }
            RecoveryCheckpointContext PlanContext(int index)
            { return Ext4Child(context,Slot(index)+"/plan",null,null); }
            Entry NewEntry(ExportCandidate candidate)
            {
                var inode = candidate.Inode;
                var entry = new Entry { VolumeOffset = v.Offset, InodeOffset = inode.Offset, Inode = inode.Number,
                    Generation = inode.Generation, DeletionTime = inode.Dtime, DeclaredSize = inode.Size > Int64.MaxValue ? Int64.MaxValue : (long)inode.Size,
                    InodeChecksumVerified = v.Csum, Status = "not_recovered" };
                if (candidate.History != null)
                {
                    entry.DeletionEvidence = "journal_transaction_pre_deletion_record";
                    entry.Note = "Историческая карта inode из транзакции журнала JBD2 (seq " + candidate.History.TransactionSeq + "). Свободные блоки могли быть перезаписаны до снимка; контрольной суммы исходного содержимого в ext4 нет.";
                }
                List<NameLink> links; if (names.TryGetValue(inode.Number,out links)) entry.Names = links;
                return entry;
            }
            string ExportIdentity()
            {
                using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,sha,CryptoStreamMode.Write))
                using (var writer = new BinaryWriter(stream,new UTF8Encoding(false,true)))
                {
                    var folder = new Uri(Path.GetFullPath(context.Directory)+Path.DirectorySeparatorChar);
                    writer.Write(folder.MakeRelativeUri(new Uri(Path.GetFullPath(c.Root)+Path.DirectorySeparatorChar)).ToString());
                    writer.Write(v.Offset); writer.Write(GroupBytesHash(v.Superblock)); writer.Write(GroupOverlayHash(c,v));
                    writer.Write(InodeGroupsHash(c,v)); writer.Write(Ext4LimitsIdentity(c.Limits));
                    writer.Write(c.Report.Candidates); writer.Write(c.Report.RecoveredFiles); writer.Write(c.Report.OutputBytes); writer.Write(c.Report.Limited);
                    WriteCandidateSkips(c,writer); writer.Write(c.Report.Entries.Count);
                    foreach (var old in c.Report.Entries) writer.Write(Ext4EntryIdentity(old,c.Cancel));
                    writer.Write(candidates.Count);
                    foreach (var item in candidates)
                    {
                        var inode = item.Inode;
                        if (inode == null || inode.Bytes == null || inode.Bytes.Length != v.InodeBytes) throw new IOException("EXT4_EXPORT_INODE_INVALID");
                        writer.Write(Ext4EntryIdentity(NewEntry(item),c.Cancel)); writer.Write(inode.Mode); writer.Write(inode.Links); writer.Write(inode.Flags);
                        writer.Write(inode.Allocated); writer.Write(inode.Size); writer.Write(inode.Bytes.Length); writer.Write(inode.Bytes);
                        writer.Write(item.History != null);
                        if (item.History != null) { writer.Write(item.History.JournalBlock); writer.Write(item.History.TargetDiskBlock);
                            writer.Write(item.History.TransactionSeq); writer.Write(item.History.OffsetInBlock); }
                    }
                    writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
                }
            }
            bool HistoricalEligible(ExportCandidate candidate,string hash,bool create)
            {
                var old = candidate.History; if (old == null) return true;
                uint index = (old.Number-1)/v.InodesPerGroup, slot = (old.Number-1)%v.InodesPerGroup;
                bool needsRead = index < (uint)v.Groups.Count && v.Groups[(int)index].Valid && v.Groups[(int)index].InodeMapValid && Bit(v.Groups[(int)index].Inodes,slot);
                EligibilityPayload payload;
                if (create)
                {
                    byte[] bytes = null;
                    if (needsRead)
                    {
                        ulong block = v.Groups[(int)index].InodeTable + (ulong)((long)slot*v.InodeBytes/v.BlockBytes);
                        bytes = Block(c,v,block);
                        if (bytes == null || bytes.Length != v.BlockBytes) throw new EndOfStreamException("EXT4_EXPORT_LIVE_INODE_SHORT_READ");
                    }
                    payload = new EligibilityPayload { Data = bytes == null ? null : Convert.ToBase64String(bytes) };
                    var next = Clone(); next.Eligibility = StoreMetadataPayload(context,"export-blobs",payload,c.Cancel); Save(next);
                    if (progress != null) progress("ext4: historical eligibility "+state.Next);
                }
                else payload = ReadMetadataPayload<EligibilityPayload>(context,"export-blobs",hash,c.Cancel);
                if (payload.Schema != 1 || needsRead != (payload.Data != null)) throw new IOException("EXT4_EXPORT_ELIGIBILITY_INVALID");
                if (index >= (uint)v.Groups.Count || !v.Groups[(int)index].Valid || !v.Groups[(int)index].InodeMapValid) return false;
                if (!needsRead) return true;
                byte[] all = GroupDecode(payload.Data,v.BlockBytes,true), live = new byte[v.InodeBytes];
                int at = (int)((long)slot*v.InodeBytes%v.BlockBytes); Buffer.BlockCopy(all,at,live,0,live.Length);
                return InodeChecksum(v,old.Number,live) && U32(live,0x64) != old.Generation;
            }
            static Dictionary<string,int> Delta(Dictionary<string,int> before,Dictionary<string,int> after)
            {
                var delta = new Dictionary<string,int>();
                foreach (var pair in after) { int prior; before.TryGetValue(pair.Key,out prior);
                    if (pair.Value < prior) throw new IOException("EXT4_EXPORT_COUNTER_INVALID"); if (pair.Value != prior) delta.Add(pair.Key,pair.Value-prior); }
                if (before.Keys.Any(key => !after.ContainsKey(key))) throw new IOException("EXT4_EXPORT_COUNTER_INVALID"); return delta;
            }
            void ApplyEffects(ExportFact fact)
            {
                if (fact.Skips == null || fact.Skips.Count > 1024 || c.Report.Limited && !fact.Limited) throw new IOException("EXT4_EXPORT_EFFECTS_INVALID");
                foreach (var pair in fact.Skips)
                {
                    int prior; c.Report.Skipped.TryGetValue(pair.Key,out prior);
                    if (String.IsNullOrEmpty(pair.Key) || pair.Value < 1 || prior > Int32.MaxValue-pair.Value) throw new IOException("EXT4_EXPORT_COUNTER_INVALID");
                    c.Report.Skipped[pair.Key] = prior+pair.Value;
                }
                c.Report.Limited = fact.Limited;
            }
            void CheckOutput(Entry entry)
            {
                string file = RecoveryCatalog.SafeFile(c.Root,entry.Output);
                if (Directory.Exists(file)) throw new IOException("EXT4_EXPORT_OUTPUT_CHANGED");
                if (!File.Exists(file)) return;
                using (var guard = new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read))
                    if (guard.Length != entry.RecoveredBytes || HashStream(guard,c.Cancel) != entry.Sha256) throw new IOException("EXT4_EXPORT_OUTPUT_CHANGED");
            }
            void RestoreEntry(ExportFact fact)
            {
                Entry final = ReadEntryPlan(c,PlanContext(fact.Index),fact.Manifest); var expected = NewEntry(candidates[fact.Index]);
                if (final.VolumeOffset != expected.VolumeOffset || final.Inode != expected.Inode || final.Generation != expected.Generation ||
                    final.InodeOffset != expected.InodeOffset || final.DeclaredSize != expected.DeclaredSize || final.DeletionEvidence != expected.DeletionEvidence ||
                    final.Note != expected.Note || final.Output != null && (final.RecoveredBytes != final.DeclaredSize || !GroupDigest(final.Sha256)))
                    throw new IOException("EXT4_EXPORT_ENTRY_INVALID");
                if (final.Output != null) CheckOutput(final);
                c.Report.Candidates++; ApplyEffects(fact);
                if (final.Output == null) { c.Report.Entries.Add(final); return; }
                string file = RecoveryCatalog.SafeFile(c.Root,final.Output);
                if (File.Exists(file))
                {
                    c.Report.Entries.Add(final); c.Report.RecoveredFiles++; c.Report.OutputBytes += final.RecoveredBytes;
                    if (state.Repair == fact.Index) { var acknowledged = Clone(); acknowledged.Repair = -1; acknowledged.RepairCopy = null; Save(acknowledged); }
                    return;
                }
                var original = final.HeaderCopy(); original.Extents = final.Extents; original.Names = final.Names;
                original.Output = original.Sha256 = null; original.RecoveredBytes = 0; original.ContentTypeHint = null; original.Status = "not_recovered";
                c.Report.Entries.Add(original);
                if (state.Repair != -1 && state.Repair != fact.Index) throw new IOException("EXT4_EXPORT_REPAIR_ORDER_INVALID");
                if (state.Repair == -1) { var next = Clone(); next.Repair = fact.Index; Save(next); }
                var child = Ext4Child(context,"repair-"+Slot(fact.Index),state.RepairCopy,link => { var next = Clone(); next.Repair = fact.Index; next.RepairCopy = link; Save(next); });
                WriteFileCheckpointed(c,original,child,progress);
                if (Ext4EntryIdentity(original,c.Cancel) != Ext4EntryIdentity(final,c.Cancel)) throw new IOException("EXT4_EXPORT_REPAIR_CHANGED");
                var repaired = Clone(); repaired.Repair = -1; repaired.RepairCopy = null; Save(repaired);
            }
            void Finish(ExportFact fact)
            {
                var next = Clone(); next.Next = fact.Next; next.Complete = next.Next == candidates.Count;
                next.Prepare = next.Plan = next.Copy = null; next.Eligibility = null;
                var rows = new List<ExportFact> { fact }; next.Facts = ledger.Append(state.Facts,rows);
                Save(next); ledger.Accept(rows); if (progress != null) progress("ext4: finished candidate "+fact.Index);
            }
            void NextCandidate()
            {
                int index = state.Next; var candidate = candidates[index]; var before = new Dictionary<string,int>(c.Report.Skipped);
                var fact = new ExportFact { Index = index, Next = index+1, Kind = "entry" };
                bool sized = candidate.Inode.Size > 0 && candidate.Inode.Size <= (ulong)c.Limits.MaximumFileBytes;
                if (!sized && (state.Prepare != null || state.Copy != null) || state.Copy != null && (state.Plan == null || state.Prepare == null) ||
                    candidate.History == null && state.Eligibility != null) throw new IOException("EXT4_EXPORT_ACTIVE_ROLE_INVALID");
                if (sized && (state.Plan != null || state.Copy != null) && (state.Prepare == null ||
                    !new RecoveryMethodJournal<CandidateProgress>(c.Input.Name,new CandidateProgress(),
                        Ext4Child(context,Slot(index)+"/prepare",state.Prepare,null),c.Cancel).Payload.Complete))
                    throw new IOException("EXT4_EXPORT_PREPARATION_INCOMPLETE");
                if (state.Copy != null && !new RecoveryMethodJournal<EntryPlanProgress>(c.Input.Name,new EntryPlanProgress(),
                    Ext4Child(context,Slot(index)+"/plan",state.Plan,null),c.Cancel).Payload.Complete)
                    throw new IOException("EXT4_EXPORT_PLAN_INCOMPLETE");
                if (candidate.History != null)
                {
                    if (c.Report.Entries.Any(x => x.VolumeOffset == v.Offset && x.Inode == candidate.Inode.Number && x.Output != null)) fact.Kind = "already_recovered";
                    else if (!HistoricalEligible(candidate,state.Eligibility,state.Eligibility == null)) fact.Kind = "not_eligible";
                    else if (c.Report.Entries.Count >= c.Limits.MaximumCandidates)
                    { c.Report.Limited = true; Skip(c,"candidate_limit"); fact.Kind = "limit"; fact.Next = candidates.Count; }
                    fact.Eligibility = state.Eligibility;
                }
                if (fact.Kind == "entry")
                {
                    var entry = NewEntry(candidate); c.Report.Candidates++; c.Report.Entries.Add(entry); bool prepared = false;
                    if (candidate.Inode.Size == 0 || candidate.Inode.Size > (ulong)c.Limits.MaximumFileBytes)
                    {
                        entry.Reason = "empty_or_file_size_limit";
                        if (candidate.Inode.Size > (ulong)c.Limits.MaximumFileBytes) { c.Report.Limited = true; Skip(c,"file_size_limit"); }
                    }
                    else
                    {
                        var prep = Ext4Child(context,Slot(index)+"/prepare",state.Prepare,link => { var next = Clone(); next.Prepare = link; Save(next); });
                        prepared = PrepareMappedEntryCheckpointed(c,v,candidate.Inode,entry,prep,progress);
                    }
                    var plan = Ext4Child(context,Slot(index)+"/plan",state.Plan,link => { var next = Clone(); next.Plan = link; Save(next); });
                    string manifest = StoreEntryPlan(c,entry,plan,progress);
                    if (prepared)
                    {
                        var copy = Ext4Child(context,Slot(index)+"/copy",state.Copy,link => { var next = Clone(); next.Copy = link; Save(next); });
                        WriteFileCheckpointed(c,entry,copy,progress);
                        var stored = ReadMetadataPayload<EntryPlanManifest>(plan,"export-blobs",manifest,c.Cancel);
                        stored.Header = entry.HeaderCopy(); stored.Identity = Ext4EntryIdentity(entry,c.Cancel);
                        manifest = StoreMetadataPayload(plan,"export-blobs",stored,c.Cancel);
                    }
                    fact.Manifest = manifest;
                }
                fact.Limited = c.Report.Limited; fact.Skips = Delta(before,c.Report.Skipped); Finish(fact);
            }
            public void Run()
            {
                int next = 0;
                foreach (var fact in ledger.Records)
                {
                    if (fact.Index != next || fact.Next != fact.Index+1 && (fact.Kind != "limit" || fact.Next != candidates.Count) || fact.Next > candidates.Count ||
                        fact.Kind != "entry" && fact.Kind != "already_recovered" && fact.Kind != "not_eligible" && fact.Kind != "limit")
                        throw new IOException("EXT4_EXPORT_FACT_ORDER_INVALID");
                    if (fact.Kind == "entry") RestoreEntry(fact);
                    else
                    {
                        var candidate = candidates[fact.Index];
                        if (candidate.History == null || fact.Manifest != null ||
                            fact.Kind == "already_recovered" && !c.Report.Entries.Any(x => x.VolumeOffset == v.Offset && x.Inode == candidate.Inode.Number && x.Output != null) ||
                            fact.Kind != "already_recovered" && (fact.Eligibility == null || HistoricalEligible(candidate,fact.Eligibility,false) != (fact.Kind == "limit")))
                            throw new IOException("EXT4_EXPORT_DECISION_INVALID");
                        ApplyEffects(fact);
                    }
                    next = fact.Next;
                }
                if (next != state.Next) throw new IOException("EXT4_EXPORT_CURSOR_INVALID");
                while (!state.Complete) NextCandidate();
                if (!journal.Resumed && ledger.Records.Count == 0) Save(state);
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
            }
        }
        static void ExportVolumeCandidatesCheckpointed(Context c, Volume v, List<Inode> current,
            Dictionary<uint,HistoricalCandidate> history, Dictionary<uint,List<NameLink>> names,
            RecoveryCheckpointContext context, Action<string> progress)
        {
            if (context == null) { ExportVolumeCandidatesLegacy(c,v,current,history,names); return; }
            using (new MetadataSourceScope(c,context)) new VolumeExportCheckpoint(c,v,current,history,names,context,progress).Run();
        }
    }
}
