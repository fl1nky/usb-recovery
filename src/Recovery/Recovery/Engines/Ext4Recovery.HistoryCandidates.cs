using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class HistoricalSweepProgress
        {
            public int Schema = 1;
            public string Identity, Groups, Phase = "transactions";
            public bool Limited;
            public RecoveryMethodCheckpoint Transactions, Candidates;
        }
        static HistoricalSweepProgress CopyHistoricalSweep(HistoricalSweepProgress state)
        {
            return new HistoricalSweepProgress { Identity = state.Identity, Groups = state.Groups, Phase = state.Phase,
                Limited = state.Limited, Transactions = state.Transactions, Candidates = state.Candidates };
        }
        static void SweepJournalHistoryCheckpointed(Context c, Volume v, JournalContext jc,
            RecoveryCheckpointContext context, Action<string> progress,
            out Dictionary<uint, HistoricalCandidate> candidates, out List<JournalDirectoryBlock> directories)
        {
            using (context == null ? null : new MetadataSourceScope(c, context))
            {
                ValidateMetadataSource(c, context);
                var initial = new HistoricalSweepProgress { Identity = context == null ? null : JournalIdentity(c, jc),
                    Groups = context == null ? null : InodeGroupsHash(c, v) };
                var journal = new RecoveryMethodJournal<HistoricalSweepProgress>(c.Input.Name, initial, context, c.Cancel);
                var state = journal.Payload;
                if (state.Schema != 1 || state.Identity != initial.Identity || state.Groups != initial.Groups ||
                    state.Phase != "transactions" && state.Phase != "candidates" && state.Phase != "complete" ||
                    state.Phase == "transactions" && (state.Candidates != null || state.Limited))
                    throw new IOException("EXT4_HISTORICAL_SWEEP_INVALID");
                var transactionContext = JournalChild(context, "transactions", state.Transactions, link => {
                    var linked = CopyHistoricalSweep(state); linked.Transactions = link; journal.Save(linked); state = linked;
                });
                if (context != null && state.Phase != "transactions" && (state.Transactions == null ||
                    new RecoveryMethodJournal<JournalScanProgress>(c.Input.Name, new JournalScanProgress(), transactionContext, c.Cancel).Payload.Phase != "complete"))
                    throw new IOException("EXT4_HISTORICAL_SWEEP_TRANSACTIONS_INCOMPLETE");
                var transactions = ReadJournalHistoryTransactionsCheckpointed(c, jc, transactionContext, progress);
                if (state.Phase == "transactions")
                {
                    var saved = CopyHistoricalSweep(state); saved.Limited = transactions == null;
                    saved.Phase = saved.Limited ? "complete" : "candidates"; journal.Save(saved); state = saved;
                }
                if (state.Limited != (transactions == null) || state.Limited && (state.Phase != "complete" || state.Candidates != null))
                    throw new IOException("EXT4_HISTORICAL_SWEEP_COVERAGE_INVALID");
                if (state.Limited) {
                    c.Cancel.ThrowIfCancellationRequested(); if (context != null) c.CheckpointSource.ValidateLimits();
                    candidates = new Dictionary<uint, HistoricalCandidate>(); directories = new List<JournalDirectoryBlock>(); return;
                }
                var candidateContext = JournalChild(context, "candidates", state.Candidates, link => {
                    var linked = CopyHistoricalSweep(state); linked.Candidates = link; journal.Save(linked); state = linked;
                });
                if (context != null && state.Phase == "complete" && (state.Candidates == null ||
                    !new RecoveryMethodJournal<HistoryProgress>(c.Input.Name, new HistoryProgress(), candidateContext, c.Cancel).Payload.Complete))
                    throw new IOException("EXT4_HISTORICAL_SWEEP_DATA_INCOMPLETE");
                CollectJournalHistoryCheckpointed(c, v, jc, transactions, candidateContext, progress, out candidates, out directories);
                if (state.Phase != "complete") { var saved = CopyHistoricalSweep(state); saved.Phase = "complete"; journal.Save(saved); }
                c.Cancel.ThrowIfCancellationRequested(); if (context != null) c.CheckpointSource.ValidateLimits();
            }
        }
        sealed class HistoryProgress
        {
            public int Schema = 1, Next, Count;
            public string Identity, Groups, Transactions;
            public bool Complete;
            public RecoveryOutputHead Facts;
        }
        sealed class HistoryPayload
        {
            public int Schema = 1, Start, Count;
            public string Data;
        }
        sealed class HistoryDataBlock { public JournalTag Tag; public ulong Physical; public uint Sequence; }
        static List<HistoryDataBlock> HistoryBlocks(Context c, Volume v, JournalContext jc,
            List<JournalTransaction> transactions, out string digest)
        {
            if (transactions == null || transactions.Count > jc.MaxLen - jc.First ||
                transactions.Any(transaction => transaction == null || transaction.DataBlocks == null ||
                    transaction.HeaderBlocks == null || transaction.RevokedBlocks == null))
                throw new IOException("EXT4_HISTORY_TRANSACTIONS_INVALID");
            var physical = new HashSet<ulong>(jc.Blocks); var sequences = new HashSet<uint>();
            var result = new List<HistoryDataBlock>(); var revokes = JournalRevokes(transactions);
            long work = 0, maximum = (long)(jc.MaxLen - jc.First) * 4;
            using (var hash = SHA256.Create())
            using (var stream = new CryptoStream(Stream.Null, hash, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, Encoding.UTF8))
            {
                writer.Write(transactions.Count);
                foreach (var transaction in transactions)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    if (transaction == null || !transaction.Committed || !sequences.Add(transaction.Sequence) ||
                        transaction.HeaderBlocks.Count == 0) throw new IOException("EXT4_HISTORY_TRANSACTION_INVALID");
                    work += transaction.HeaderBlocks.Count + transaction.DataBlocks.Count + 1L;
                    if (work > maximum) throw new IOException("EXT4_HISTORY_TRANSACTION_WORK_INVALID");
                    writer.Write(transaction.Sequence); writer.Write(transaction.HeaderBlocks.Count);
                    foreach (uint header in transaction.HeaderBlocks.OrderBy(x => x))
                    {
                        if (header < jc.First || header >= jc.MaxLen) throw new IOException("EXT4_HISTORY_HEADER_INVALID");
                        writer.Write(header);
                    }
                    writer.Write(transaction.RevokedBlocks.Count);
                    foreach (ulong block in transaction.RevokedBlocks)
                    {
                        if (!BlockRange(v, block, 1)) throw new IOException("EXT4_HISTORY_REVOKE_INVALID");
                        writer.Write(block);
                    }
                    writer.Write(transaction.DataBlocks.Count);
                    foreach (var item in transaction.DataBlocks)
                    {
                        if (item == null || !physical.Contains(item.Item2) || !BlockRange(v, item.Item1.DestinationBlock, 1) ||
                            (item.Item1.Flags & ~11U) != 0) throw new IOException("EXT4_HISTORY_DATA_MAP_INVALID");
                        writer.Write(item.Item1.DestinationBlock); writer.Write(item.Item1.Flags);
                        writer.Write(item.Item1.Checksum); writer.Write(item.Item2);
                        uint revokedAt;
                        if (!revokes.TryGetValue(item.Item1.DestinationBlock, out revokedAt) || !SequenceAtOrAfter(revokedAt, transaction.Sequence))
                            result.Add(new HistoryDataBlock { Tag = item.Item1, Physical = item.Item2, Sequence = transaction.Sequence });
                    }
                }
                writer.Flush(); stream.FlushFinalBlock(); digest = Hex(hash.Hash);
            }
            return result;
        }
        static void ParseHistoricalBlock(Context c, Volume v, HistoryDataBlock source, byte[] bytes,
            Dictionary<uint, HistoricalCandidate> candidates, List<JournalDirectoryBlock> directories)
        {
            c.Cancel.ThrowIfCancellationRequested();
            Group group = FindInodeTableGroup(v, source.Tag.DestinationBlock);
            if (group == null)
            {
                if (IsDirectoryBlock(bytes)) directories.Add(new JournalDirectoryBlock {
                    TargetDiskBlock = source.Tag.DestinationBlock, JournalBlock = source.Physical,
                    TransactionSequence = source.Sequence, Bytes = bytes });
                return;
            }
            ulong blockOffset = source.Tag.DestinationBlock - group.InodeTable;
            uint perBlock = (uint)(v.BlockBytes / v.InodeBytes);
            uint first = group.Number * v.InodesPerGroup + (uint)blockOffset * perBlock + 1;
            uint count = Math.Min(perBlock, v.InodesPerGroup - (uint)blockOffset * perBlock);
            for (uint index = 0; index < count; index++)
            {
                c.Cancel.ThrowIfCancellationRequested(); uint number = first + index;
                if (number < Math.Max(11, v.FirstInode) || number > v.Inodes) continue;
                int at = (int)index * v.InodeBytes; byte[] inode = new byte[v.InodeBytes];
                Buffer.BlockCopy(bytes, at, inode, 0, inode.Length);
                ushort mode = U16(inode, 0); uint flags = U32(inode, 0x20);
                ulong size = U32(inode, 4) | (ulong)U32(inode, 0x6c) << 32;
                if ((mode & 0xf000) != 0x8000 || !InodeChecksum(v, number, inode) || size == 0 ||
                    size > (ulong)c.Limits.MaximumFileBytes || (flags & (0x800U | 0x10000000U | 4U | 0x100000U | 0x200000U)) != 0) continue;
                if ((flags & 0x80000) != 0 ? U16(inode, 0x28) != 0xf30a || U16(inode, 0x2a) == 0 : U32(inode, 0x28) == 0) continue;
                HistoricalCandidate old;
                if (candidates.TryGetValue(number, out old) && !SequenceAtOrAfter(source.Sequence, old.TransactionSeq)) continue;
                candidates[number] = new HistoricalCandidate { Number = number, TransactionSeq = source.Sequence,
                    JournalBlock = source.Physical, TargetDiskBlock = source.Tag.DestinationBlock, OffsetInBlock = at,
                    Mode = mode, Links = U16(inode, 0x1a), Dtime = U32(inode, 0x14), Flags = flags,
                    Generation = U32(inode, 0x64), Size = size, InodeBytes = inode };
            }
        }
        static void ApplyHistoryPayload(Context c, Volume v, JournalContext jc, List<HistoryDataBlock> blocks,
            HistoryPayload payload, ref int next, Dictionary<uint, HistoricalCandidate> candidates,
            List<JournalDirectoryBlock> directories)
        {
            int count = Math.Min(MaximumJournalUnitBytes / v.BlockBytes, blocks.Count - next);
            if (payload == null || payload.Schema != 1 || payload.Start != next || count < 1 || payload.Count != count)
                throw new IOException("EXT4_HISTORY_DATA_UNIT_INVALID");
            byte[] all = GroupDecode(payload.Data, count * v.BlockBytes, true);
            for (int index = 0; index < count; index++)
            {
                c.Cancel.ThrowIfCancellationRequested(); HistoryDataBlock source = blocks[next + index];
                if (!JournalDataChecksumValid(jc, source.Tag, source.Sequence, all, index * v.BlockBytes))
                    throw new IOException("EXT4_HISTORY_DATA_CHECKSUM_INVALID");
                byte[] bytes = new byte[v.BlockBytes]; Buffer.BlockCopy(all, index * v.BlockBytes, bytes, 0, bytes.Length);
                if ((source.Tag.Flags & 1) != 0) { bytes[0] = 0xc0; bytes[1] = 0x3b; bytes[2] = 0x39; bytes[3] = 0x98; }
                ParseHistoricalBlock(c, v, source, bytes, candidates, directories);
            }
            next += count;
        }
        static void CollectJournalHistoryCheckpointed(Context c, Volume v, JournalContext jc,
            List<JournalTransaction> transactions, RecoveryCheckpointContext context, Action<string> progress,
            out Dictionary<uint, HistoricalCandidate> candidates, out List<JournalDirectoryBlock> directories)
        {
            using (context == null ? null : new MetadataSourceScope(c, context))
                CollectJournalHistoryCore(c, v, jc, transactions, context, progress, out candidates, out directories);
        }
        static void CollectJournalHistoryCore(Context c, Volume v, JournalContext jc, List<JournalTransaction> transactions,
            RecoveryCheckpointContext context, Action<string> progress,
            out Dictionary<uint, HistoricalCandidate> candidates, out List<JournalDirectoryBlock> directories)
        {
            if (jc == null || !Object.ReferenceEquals(jc.Volume, v) || jc.First < 1 || jc.First >= jc.MaxLen ||
                jc.MaxLen > jc.Blocks.Count || jc.MaxLen > c.Limits.MaximumJournalBlocks || jc.BlockBytes != v.BlockBytes ||
                v.BlockBytes < 1024 || v.BlockBytes > MaximumJournalUnitBytes)
                throw new IOException("EXT4_HISTORY_DATA_PHASE_INVALID");
            ValidateMetadataSource(c, context); string transactionHash;
            var blocks = HistoryBlocks(c, v, jc, transactions, out transactionHash);
            var initial = new HistoryProgress { Count = blocks.Count, Complete = blocks.Count == 0,
                Identity = context == null ? null : JournalIdentity(c, jc),
                Groups = context == null ? null : InodeGroupsHash(c, v), Transactions = transactionHash };
            var journal = new RecoveryMethodJournal<HistoryProgress>(c.Input.Name, initial, context, c.Cancel);
            var state = journal.Payload;
            if (state.Schema != 1 || state.Identity != initial.Identity || state.Groups != initial.Groups ||
                state.Transactions != initial.Transactions || state.Count != blocks.Count || state.Next < 0 || state.Next > blocks.Count ||
                state.Complete != (state.Next == blocks.Count)) throw new IOException("EXT4_HISTORY_DATA_CHECKPOINT_INVALID");
            var ledger = new RecoveryOutputLedger<JournalFact>(context, state.Facts, Math.Max(1, blocks.Count), c.Cancel,
                RecoveryLedgerScope.MethodOutput, 64L * 1024 * 1024);
            candidates = new Dictionary<uint, HistoricalCandidate>(); directories = new List<JournalDirectoryBlock>(); int next = 0;
            foreach (var fact in ledger.Records)
                ApplyHistoryPayload(c, v, jc, blocks, ReadMetadataPayload<HistoryPayload>(context, "history-blobs", fact.BlobSha256, c.Cancel),
                    ref next, candidates, directories);
            if (next != state.Next) throw new IOException("EXT4_HISTORY_DATA_CURSOR_INVALID");
            while (next < blocks.Count)
            {
                int count = Math.Min(MaximumJournalUnitBytes / v.BlockBytes, blocks.Count - next);
                byte[] bytes = new byte[count * v.BlockBytes];
                for (int index = 0; index < count; index++)
                {
                    c.Cancel.ThrowIfCancellationRequested(); HistoryDataBlock source = blocks[next + index];
                    byte[] data = Read(c, v.Offset + (long)source.Physical * v.BlockBytes, v.BlockBytes);
                    if (data == null || data.Length != v.BlockBytes) throw new EndOfStreamException("EXT4_HISTORY_DATA_SHORT_READ");
                    if (!JournalDataChecksumValid(jc, source.Tag, source.Sequence, data, 0))
                        throw new IOException("EXT4_HISTORY_DATA_CHECKSUM_INVALID");
                    Buffer.BlockCopy(data, 0, bytes, index * v.BlockBytes, data.Length);
                }
                c.Cancel.ThrowIfCancellationRequested();
                var payload = new HistoryPayload { Start = next, Count = count, Data = Convert.ToBase64String(bytes) };
                var rows = new List<JournalFact> { new JournalFact { BlobSha256 = context == null ? null : StoreMetadataPayload(context, "history-blobs", payload, c.Cancel) } };
                var saved = new HistoryProgress { Identity = initial.Identity, Groups = initial.Groups, Transactions = initial.Transactions,
                    Count = blocks.Count, Next = next + count, Complete = next + count == blocks.Count, Facts = ledger.Append(state.Facts, rows) };
                journal.Save(saved); ledger.Accept(rows); state = saved;
                ApplyHistoryPayload(c, v, jc, blocks, payload, ref next, candidates, directories);
                if (progress != null) progress("ext4: historical data blocks " + next);
            }
            if (!journal.Resumed && state.Facts == null) journal.Save(state);
            c.Cancel.ThrowIfCancellationRequested(); if (context != null) c.CheckpointSource.ValidateLimits();
        }
    }
}
