using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class CandidateProgress
        {
            public int Schema = 1, Next;
            public long CheckedBlocks;
            public string Identity, Header, Groups, Overlay, Limits;
            public bool Mapped, Complete;
            public RecoveryOutputHead Facts;
        }
        sealed class CandidateUnit
        {
            public int Schema = 1, Number, Count;
            public string Kind, Data, Digest, Failure;
            public ulong Block;
            public long Start;
            public bool Accepted;
        }
        sealed class CandidatePreparationCheckpoint
        {
            readonly Context c;
            readonly Volume v;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly RecoveryMethodJournal<CandidateProgress> journal;
            readonly RecoveryOutputLedger<JournalFact> ledger;
            CandidateProgress state;
            int consumed;
            long checkedBlocks;
            bool mapped;

            public CandidatePreparationCheckpoint(Context owner, Volume volume, Inode inode, Entry entry,
                RecoveryCheckpointContext checkpoint, Action<string> notify)
            {
                c = owner; v = volume; context = checkpoint; progress = notify;
                if (v.Superblock == null || v.Superblock.Length != 1024 || v.BlockBytes < 1024 || v.BlockBytes > MaximumJournalUnitBytes ||
                    inode.Bytes == null || inode.Bytes.Length != v.InodeBytes || inode.Size == 0 || inode.Size > Int64.MaxValue ||
                    entry.DeclaredSize != (long)inode.Size || entry.Inode != inode.Number || entry.Extents == null || entry.Extents.Count != 0 ||
                    entry.Output != null || entry.Sha256 != null || entry.RecoveredBytes != 0 || entry.Names == null ||
                    c.Limits.AllocationBlocksPerCheckpoint < 1 || c.Limits.AllocationBlocksPerCheckpoint > MaximumAllocationUnitBlocks)
                    throw new IOException("EXT4_CANDIDATE_BASELINE_INVALID");
                ValidateMetadataSource(c, context);
                var initial = new CandidateProgress { Identity = CandidateInputsHash(c, v, inode, entry, context),
                    Header = GroupBytesHash(v.Superblock), Groups = InodeGroupsHash(c, v), Overlay = GroupOverlayHash(c, v),
                    Limits = Ext4LimitsIdentity(c.Limits) };
                journal = new RecoveryMethodJournal<CandidateProgress>(c.Input.Name, initial, context, c.Cancel); state = journal.Payload;
                if (state.Schema != 1 || state.Next < 0 || state.CheckedBlocks < 0 || state.Identity != initial.Identity ||
                    state.Header != initial.Header || state.Groups != initial.Groups || state.Overlay != initial.Overlay || state.Limits != initial.Limits)
                    throw new IOException("EXT4_CANDIDATE_CHECKPOINT_INVALID");
                long blocks = c.Input.Length / v.BlockBytes + c.Limits.MaximumTreeBlocks;
                int maximum = (int)Math.Min(Int32.MaxValue, c.Limits.MaximumTreeBlocks + 2L +
                    (blocks + c.Limits.AllocationBlocksPerCheckpoint - 1) / c.Limits.AllocationBlocksPerCheckpoint);
                ledger = new RecoveryOutputLedger<JournalFact>(context, state.Facts, maximum, c.Cancel,
                    RecoveryLedgerScope.MethodOutput, Math.Max(1024, (long)maximum * 1024));
                if (state.Next != ledger.Records.Count) throw new IOException("EXT4_CANDIDATE_CURSOR_INVALID");
                var last = state.Next == 0 ? null : ReadUnit(state.Next - 1);
                long expected = last == null || last.Kind == "tree" || last.Kind == "mapping" ? 0 :
                    last.Kind == "allocation" ? last.Start + last.Count : last.Start;
                if (state.Complete != (last != null && last.Kind == "end") || state.Mapped != (last != null && last.Kind != "tree") ||
                    state.CheckedBlocks != expected || state.CheckedBlocks > blocks)
                    throw new IOException("EXT4_CANDIDATE_CURSOR_INVALID");
            }
            CandidateUnit ReadUnit(int index)
            {
                var unit = ReadMetadataPayload<CandidateUnit>(context, "candidate-blobs", ledger.Records[index].BlobSha256, c.Cancel);
                if (unit.Schema != 1 || unit.Number != index || unit.Kind != "tree" && unit.Kind != "mapping" &&
                    unit.Kind != "allocation" && unit.Kind != "end") throw new IOException("EXT4_CANDIDATE_UNIT_INVALID");
                return unit;
            }
            byte[] Capture(CandidateUnit expected, Func<byte[]> read = null)
            {
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                expected.Number = consumed; CandidateUnit unit; byte[] bytes = null; bool stored = false;
                if (consumed < ledger.Records.Count)
                {
                    unit = ReadUnit(consumed);
                    if (unit.Kind != expected.Kind || unit.Count != expected.Count || unit.Digest != expected.Digest ||
                        unit.Failure != expected.Failure || unit.Block != expected.Block || unit.Start != expected.Start || unit.Accepted != expected.Accepted)
                        throw new IOException("EXT4_CANDIDATE_UNIT_ORDER_INVALID");
                    if (unit.Kind == "tree") bytes = GroupDecode(unit.Data, v.BlockBytes, true);
                    else if (unit.Data != null) throw new IOException("EXT4_CANDIDATE_UNIT_INVALID");
                }
                else
                {
                    if (state.Complete || consumed != state.Next || checkedBlocks != state.CheckedBlocks || mapped != state.Mapped)
                        throw new IOException("EXT4_CANDIDATE_CURSOR_INVALID");
                    unit = expected;
                    if (read != null)
                    {
                        bytes = read();
                        if (bytes == null || bytes.Length != v.BlockBytes) throw new EndOfStreamException("EXT4_CANDIDATE_TREE_SHORT_READ");
                        unit.Data = Convert.ToBase64String(bytes);
                    }
                    c.Cancel.ThrowIfCancellationRequested();
                    var rows = new List<JournalFact> { new JournalFact { BlobSha256 = StoreMetadataPayload(context, "candidate-blobs", unit, c.Cancel) } };
                    var next = new CandidateProgress { Identity = state.Identity, Header = state.Header, Groups = state.Groups, Overlay = state.Overlay,
                        Limits = state.Limits, Next = consumed + 1, Mapped = mapped || unit.Kind == "mapping", Complete = unit.Kind == "end",
                        CheckedBlocks = unit.Kind == "allocation" ? unit.Start + unit.Count : checkedBlocks, Facts = ledger.Append(state.Facts, rows) };
                    journal.Save(next); ledger.Accept(rows); state = next; stored = true;
                }
                if (unit.Kind == "mapping") mapped = true;
                if (unit.Kind == "allocation") checkedBlocks = unit.Start + unit.Count;
                consumed++;
                if (stored && progress != null) progress("ext4: candidate " + unit.Kind + ", allocation blocks " + checkedBlocks);
                return bytes;
            }
            public byte[] ReadTree(ulong block)
            { return Capture(new CandidateUnit { Kind = "tree", Block = block }, () => Block(c, v, block)); }
            public void ConfirmMap(Mapping map)
            { Capture(new CandidateUnit { Kind = "mapping", Digest = CandidateMappingHash(map) }); }
            public void ConfirmAllocation(AllocationCheck check)
            { Capture(new CandidateUnit { Kind = "allocation", Start = check.Start, Count = check.Count, Failure = check.Failure }); }
            public void Finish(Entry entry, bool accepted)
            {
                Capture(new CandidateUnit { Kind = "end", Start = checkedBlocks, Accepted = accepted,
                    Digest = CandidateResultHash(c, entry, context) });
                if (consumed != ledger.Records.Count || checkedBlocks != state.CheckedBlocks) throw new IOException("EXT4_CANDIDATE_TRAILING_UNITS");
            }
        }
        static string CandidateMappingHash(Mapping map)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            {
                CopyString(writer, map.Kind); CopyString(writer, map.Failure); writer.Write(map.TreeBlocks.Count);
                foreach (ulong block in map.TreeBlocks) writer.Write(block);
                writer.Write(map.Runs.Count);
                foreach (var run in map.Runs) { writer.Write(run.Logical); writer.Write(run.Physical); writer.Write(run.Count); writer.Write(run.Unwritten); }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static string CandidateInputsHash(Context c, Volume v, Inode inode, Entry entry, RecoveryCheckpointContext context)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            {
                writer.Write(FileCopyIdentity(c, entry, context)); writer.Write(v.Offset); writer.Write(v.BlockBytes); writer.Write(v.InodeBytes);
                writer.Write(v.Blocks); writer.Write(v.FirstData); writer.Write(v.BlocksPerGroup); writer.Write(v.Csum);
                writer.Write(inode.Number); writer.Write(inode.Generation); writer.Write(inode.Flags); writer.Write(inode.Dtime);
                writer.Write(inode.Mode); writer.Write(inode.Links); writer.Write(inode.Offset); writer.Write(inode.Size); writer.Write(inode.Allocated);
                writer.Write(inode.Bytes.Length); writer.Write(inode.Bytes); writer.Write(v.Reserved.Count);
                foreach (var range in v.Reserved) { writer.Write(range.Start); writer.Write(range.Length); }
                WriteCandidateSkips(c, writer); writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static void WriteCandidateSkips(Context c, BinaryWriter writer)
        {
            var keys = new List<string>(c.Report.Skipped.Keys); keys.Sort(StringComparer.Ordinal); writer.Write(keys.Count);
            foreach (string key in keys) { writer.Write(key); writer.Write(c.Report.Skipped[key]); }
        }
        static string CandidateResultHash(Context c, Entry entry, RecoveryCheckpointContext context)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            {
                writer.Write(FileCopyIdentity(c, entry, context)); WriteCandidateSkips(c, writer);
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static bool PrepareMappedEntryCheckpointed(Context c, Volume v, Inode inode, Entry entry,
            RecoveryCheckpointContext context, Action<string> progress)
        {
            if (context == null) return PrepareMappedEntry(c, v, inode, entry);
            using (new MetadataSourceScope(c, context))
            {
                var checkpoint = new CandidatePreparationCheckpoint(c, v, inode, entry, context, progress);
                bool accepted = PrepareMappedEntryCore(c, v, inode, entry, checkpoint); checkpoint.Finish(entry, accepted); return accepted;
            }
        }
    }
}
