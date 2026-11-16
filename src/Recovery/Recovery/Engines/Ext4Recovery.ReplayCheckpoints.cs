using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class ReplayProgress
        {
            public int Schema = 1, Steps, OverlayIndex;
            public string Identity, Phase = "scan", Failure, PendingProbe;
            public uint Cursor, Sequence;
            public long Budget;
            public RecoveryMethodCheckpoint Active;
            public RecoveryOutputHead Transactions, Overlay;
        }
        sealed class ReplayFact
        {
            public string Kind, Probe;
            public long Before, After;
            public RecoveryMethodCheckpoint Checkpoint;
        }
        sealed class ReplayProbe { public int Schema = 1; public uint Cursor; public string Header; }
        sealed class ReplayOverlay { public int Schema = 1, Start, Count; public string Data; }
        sealed class ReplayBlock { public JournalTag Tag; public ulong Physical; public uint Sequence; }
        sealed class ReplayCursor
        {
            public uint Cursor, Sequence;
            public long Budget;
            public int Steps;
            public string Failure;
            public bool Stopped;
            public List<JournalTransaction> Committed = new List<JournalTransaction>();
        }
        static ReplayProgress CopyReplay(ReplayProgress state)
        {
            return new ReplayProgress { Identity = state.Identity, Phase = state.Phase, Failure = state.Failure,
                PendingProbe = state.PendingProbe, Cursor = state.Cursor, Sequence = state.Sequence, Budget = state.Budget,
                Steps = state.Steps, Active = state.Active, Transactions = state.Transactions,
                Overlay = state.Overlay, OverlayIndex = state.OverlayIndex };
        }
        static bool ReplayProbeContinues(JournalContext jc, ReplayProbe probe, uint cursor, uint sequence)
        {
            if (probe == null || probe.Schema != 1 || probe.Cursor != cursor || cursor < jc.First || cursor >= jc.MaxLen)
                throw new IOException("EXT4_REPLAY_PROBE_INVALID");
            byte[] bytes = GroupDecode(probe.Header, 12, true);
            return Be32(bytes, 0) == 0xc03b3998 && Be32(bytes, 8) == sequence;
        }
        static ReplayProbe ReadReplayProbe(Context c, JournalContext jc, uint cursor)
        {
            byte[] bytes = Read(c, jc.Volume.Offset + (long)jc.Blocks[(int)cursor] * jc.BlockBytes, 12);
            if (bytes == null || bytes.Length != 12) throw new EndOfStreamException("EXT4_REPLAY_PROBE_SHORT_READ");
            return new ReplayProbe { Cursor = cursor, Header = Convert.ToBase64String(bytes) };
        }
        static void ApplyReplayTransaction(JournalContext jc, ReplayCursor cursor,
            JournalTransaction transaction, bool committed, uint next, string failure, long budget)
        {
            if (cursor.Stopped || transaction.Sequence != cursor.Sequence)
                throw new IOException("EXT4_REPLAY_TRANSACTION_SEQUENCE_INVALID");
            cursor.Budget = budget; cursor.Steps++;
            if (!committed) { cursor.Failure = failure; cursor.Stopped = true; return; }
            cursor.Committed.Add(transaction); cursor.Cursor = next; cursor.Sequence++;
            cursor.Stopped = cursor.Steps >= jc.MaxLen - jc.First;
        }
        static List<ReplayBlock> ReplayBlocks(JournalContext jc, ReplayCursor cursor)
        {
            var blocks = new List<ReplayBlock>();
            if (cursor.Failure != null && cursor.Failure != "journal_transaction_uncommitted") return blocks;
            var revokes = JournalRevokes(cursor.Committed);
            foreach (var transaction in cursor.Committed) foreach (var item in transaction.DataBlocks)
            {
                uint sequence;
                if (revokes.TryGetValue(item.Item1.DestinationBlock, out sequence) && SequenceAtOrAfter(sequence, transaction.Sequence)) continue;
                if (BlockRange(jc.Volume, item.Item1.DestinationBlock, 1))
                    blocks.Add(new ReplayBlock { Tag = item.Item1, Physical = item.Item2, Sequence = transaction.Sequence });
            }
            return blocks;
        }
        static byte[] ReplayOverlayBytes(Context c, JournalContext jc, List<ReplayBlock> blocks,
            ReplayOverlay payload, int next)
        {
            int count = Math.Min(MaximumJournalUnitBytes / (int)jc.BlockBytes, blocks.Count - next);
            if (payload == null || payload.Schema != 1 || payload.Start != next || count < 1 || payload.Count != count)
                throw new IOException("EXT4_REPLAY_OVERLAY_CURSOR_INVALID");
            byte[] bytes = GroupDecode(payload.Data, count * (int)jc.BlockBytes, true);
            long existing = (long)jc.Volume.Overlay.Count * jc.BlockBytes;
            var additions = new HashSet<ulong>();
            for (int index = 0; index < count; index++)
            {
                c.Cancel.ThrowIfCancellationRequested(); ReplayBlock item = blocks[next + index];
                if (!JournalDataChecksumValid(jc, item.Tag, item.Sequence, bytes, index * (int)jc.BlockBytes))
                    throw new IOException("EXT4_REPLAY_OVERLAY_CHECKSUM_INVALID");
                if (!jc.Volume.Overlay.ContainsKey(item.Tag.DestinationBlock)) additions.Add(item.Tag.DestinationBlock);
            }
            if (additions.Count > c.Limits.MaximumJournalBlocks - jc.Volume.Overlay.Count ||
                (long)additions.Count * jc.BlockBytes > c.Limits.MaximumJournalBytes - existing)
                throw new IOException("EXT4_REPLAY_OVERLAY_LIMIT");
            return bytes;
        }
        static void ApplyReplayOverlay(JournalContext jc, List<ReplayBlock> blocks, int at, int count, byte[] bytes)
        {
            for (int index = 0; index < count; index++)
            {
                ReplayBlock item = blocks[at + index]; byte[] block = new byte[jc.BlockBytes];
                Buffer.BlockCopy(bytes, index * (int)jc.BlockBytes, block, 0, block.Length);
                if ((item.Tag.Flags & 1) != 0) { block[0] = 0xc0; block[1] = 0x3b; block[2] = 0x39; block[3] = 0x98; }
                jc.Volume.Overlay[item.Tag.DestinationBlock] = block;
            }
        }
        static void ReplayJournalCheckpointed(Context c, JournalContext jc, RecoveryCheckpointContext context, Action<string> progress)
        {
            using (context == null ? null : new MetadataSourceScope(c, context)) ReplayJournalCore(c, jc, context, progress);
        }
        static void ReplayJournalCore(Context c, JournalContext jc, RecoveryCheckpointContext context, Action<string> progress)
        {
            Volume v = jc.Volume;
            if (v.Overlay.Count != 0 || jc.First < 1 || jc.First >= jc.MaxLen || jc.MaxLen > jc.Blocks.Count ||
                jc.MaxLen > c.Limits.MaximumJournalBlocks || jc.BlockBytes != v.BlockBytes ||
                jc.Start != 0 && (jc.Start < jc.First || jc.Start >= jc.MaxLen) ||
                jc.BlockBytes < 1024 || jc.BlockBytes > MaximumJournalUnitBytes)
                throw new IOException("EXT4_REPLAY_PHASE_INVALID");
            ValidateMetadataSource(c, context); v.JournalReplayAttempted = v.Report.JournalReplayAttempted = true;
            var initial = new ReplayProgress { Identity = context == null ? null : JournalIdentity(c, jc),
                Cursor = jc.Start, Sequence = jc.Sequence, Budget = (long)(jc.MaxLen - jc.First) * 2,
                Phase = jc.Start == 0 ? "complete" : "scan" };
            var journal = new RecoveryMethodJournal<ReplayProgress>(c.Input.Name, initial, context, c.Cancel);
            var state = journal.Payload;
            if (state.Schema != 1 || state.Identity != initial.Identity || state.Steps < 0 || state.OverlayIndex < 0 ||
                state.Phase != "scan" && state.Phase != "overlay" && state.Phase != "complete")
                throw new IOException("EXT4_REPLAY_CHECKPOINT_INVALID");
            var ledger = new RecoveryOutputLedger<ReplayFact>(context, state.Transactions,
                checked((int)(jc.MaxLen - jc.First) + 1), c.Cancel, RecoveryLedgerScope.MethodOutput, 256L * 1024 * 1024);
            var cursor = new ReplayCursor { Cursor = jc.Start, Sequence = jc.Sequence, Budget = initial.Budget, Stopped = jc.Start == 0 };
            int factIndex = 0;
            foreach (var fact in ledger.Records)
            {
                if (cursor.Stopped || fact.Before != cursor.Budget) throw new IOException("EXT4_REPLAY_FACT_ORDER_INVALID");
                if (fact.Kind == "end")
                {
                    if (fact.Checkpoint != null || fact.Before != fact.After || ReplayProbeContinues(jc,
                        ReadMetadataPayload<ReplayProbe>(context, "journal-blobs", fact.Probe, c.Cancel), cursor.Cursor, cursor.Sequence))
                        throw new IOException("EXT4_REPLAY_END_INVALID");
                    cursor.Stopped = true;
                }
                else if (fact.Kind == "transaction")
                {
                    if (fact.Checkpoint == null || fact.Probe != null) throw new IOException("EXT4_REPLAY_FACT_INVALID");
                    var child = JournalPhaseChild(context, "replay", AttemptName(factIndex), fact.Checkpoint,
                        link => { throw new IOException("EXT4_REPLAY_COMPLETE_CHILD_RESTARTED"); });
                    if (!new RecoveryMethodJournal<JournalProgress>(c.Input.Name, new JournalProgress(), child, c.Cancel).Payload.Complete)
                        throw new IOException("EXT4_REPLAY_CHILD_INCOMPLETE");
                    JournalTransaction transaction; uint next; string failure; long budget = cursor.Budget;
                    bool committed = TryJournalTransactionCheckpointed(c, jc, cursor.Cursor, out transaction, out next, out failure, ref budget, child, null);
                    if (budget != fact.After) throw new IOException("EXT4_REPLAY_BUDGET_INVALID");
                    ApplyReplayTransaction(jc, cursor, transaction, committed, next, failure, budget);
                    if (!committed) Skip(c, failure);
                }
                else throw new IOException("EXT4_REPLAY_FACT_INVALID");
                factIndex++;
            }
            if (cursor.Cursor != state.Cursor || cursor.Sequence != state.Sequence || cursor.Budget != state.Budget ||
                cursor.Steps != state.Steps || cursor.Failure != state.Failure || (state.Phase != "scan") != cursor.Stopped ||
                state.Active != null && state.PendingProbe == null ||
                state.Phase != "scan" && (state.Active != null || state.PendingProbe != null) ||
                state.Phase == "scan" && (state.Overlay != null || state.OverlayIndex != 0))
                throw new IOException("EXT4_REPLAY_CURSOR_INVALID");
            while (!cursor.Stopped)
            {
                ReplayProbe probe = state.PendingProbe == null ? ReadReplayProbe(c, jc, cursor.Cursor) :
                    ReadMetadataPayload<ReplayProbe>(context, "journal-blobs", state.PendingProbe, c.Cancel);
                bool continues = ReplayProbeContinues(jc, probe, cursor.Cursor, cursor.Sequence);
                if (!continues && state.Active != null) throw new IOException("EXT4_REPLAY_ACTIVE_PROBE_INVALID");
                if (context != null && state.PendingProbe == null)
                {
                    var linked = CopyReplay(state); linked.PendingProbe = StoreMetadataPayload(context, "journal-blobs", probe, c.Cancel);
                    journal.Save(linked); state = linked;
                }
                var fact = new ReplayFact { Before = cursor.Budget, After = cursor.Budget };
                if (continues)
                {
                    var child = JournalPhaseChild(context, "replay", AttemptName(ledger.Records.Count), state.Active, link => {
                        var linked = CopyReplay(state); linked.Active = link; journal.Save(linked); state = linked;
                    });
                    JournalTransaction transaction; uint next; string failure; long budget = cursor.Budget;
                    bool committed = TryJournalTransactionCheckpointed(c, jc, cursor.Cursor, out transaction, out next, out failure, ref budget, child, progress);
                    fact.Kind = "transaction"; fact.Checkpoint = state.Active; fact.After = budget;
                    ApplyReplayTransaction(jc, cursor, transaction, committed, next, failure, budget);
                }
                else { fact.Kind = "end"; fact.Probe = state.PendingProbe; cursor.Stopped = true; }
                var rows = new List<ReplayFact> { fact };
                var saved = CopyReplay(state); saved.Cursor = cursor.Cursor; saved.Sequence = cursor.Sequence; saved.Budget = cursor.Budget;
                saved.Steps = cursor.Steps; saved.Failure = cursor.Failure; saved.Active = null; saved.PendingProbe = null;
                saved.Transactions = ledger.Append(state.Transactions, rows); saved.Phase = cursor.Stopped ? "overlay" : "scan";
                journal.Save(saved); ledger.Accept(rows); state = saved;
                if (fact.Kind == "transaction" && cursor.Failure != null) Skip(c, cursor.Failure);
                if (progress != null) progress("ext4: replay transactions " + cursor.Committed.Count);
            }
            var blocks = ReplayBlocks(jc, cursor);
            var overlayContext = JournalPhaseChild(context, "replay", "overlay", null,
                link => { throw new IOException("EXT4_REPLAY_OVERLAY_CHILD_UNEXPECTED"); });
            var overlays = new RecoveryOutputLedger<JournalFact>(overlayContext, state.Overlay,
                Math.Max(1, (int)(jc.MaxLen - jc.First) * 2), c.Cancel, RecoveryLedgerScope.MethodOutput, 64L * 1024 * 1024);
            int at = 0;
            foreach (var fact in overlays.Records)
            {
                var payload = ReadMetadataPayload<ReplayOverlay>(context, "journal-blobs", fact.BlobSha256, c.Cancel);
                byte[] bytes = ReplayOverlayBytes(c, jc, blocks, payload, at);
                ApplyReplayOverlay(jc, blocks, at, payload.Count, bytes); at += payload.Count;
            }
            if (at != state.OverlayIndex || state.Phase == "complete" && at != blocks.Count || state.Phase == "scan")
                throw new IOException("EXT4_REPLAY_OVERLAY_CHECKPOINT_INVALID");
            while (at < blocks.Count)
            {
                int count = Math.Min(MaximumJournalUnitBytes / (int)jc.BlockBytes, blocks.Count - at);
                byte[] bytes = new byte[count * (int)jc.BlockBytes];
                for (int index = 0; index < count; index++)
                {
                    byte[] data = Read(c, v.Offset + (long)blocks[at + index].Physical * v.BlockBytes, v.BlockBytes);
                    if (data == null || data.Length != v.BlockBytes) throw new EndOfStreamException("EXT4_REPLAY_DATA_SHORT_READ");
                    Buffer.BlockCopy(data, 0, bytes, index * v.BlockBytes, data.Length);
                }
                var payload = new ReplayOverlay { Start = at, Count = count, Data = Convert.ToBase64String(bytes) };
                ReplayOverlayBytes(c, jc, blocks, payload, at);
                var rows = new List<JournalFact> { new JournalFact { BlobSha256 = context == null ? null : StoreMetadataPayload(context, "journal-blobs", payload, c.Cancel) } };
                var saved = CopyReplay(state); saved.Overlay = overlays.Append(state.Overlay, rows); saved.OverlayIndex = at + count;
                saved.Phase = saved.OverlayIndex == blocks.Count ? "complete" : "overlay";
                journal.Save(saved); overlays.Accept(rows); state = saved;
                ApplyReplayOverlay(jc, blocks, at, count, bytes); at += count;
                if (progress != null) progress("ext4: replay overlay " + at);
            }
            if (state.Phase != "complete") { var saved = CopyReplay(state); saved.Phase = "complete"; journal.Save(saved); state = saved; }
            if (!journal.Resumed && state.Transactions == null) journal.Save(state);
            c.Cancel.ThrowIfCancellationRequested();
            if (context != null) c.CheckpointSource.ValidateLimits();
            if (cursor.Failure != null) v.Report.JournalStatus = cursor.Failure;
            if (cursor.Committed.Count > 0 && (cursor.Failure == null || cursor.Failure == "journal_transaction_uncommitted"))
            {
                v.JournalReplayApplied = v.Report.JournalReplayApplied = true;
                v.Report.JournalStatus = "committed_transactions_replayed_in_memory";
            }
        }
    }
}
