using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        const int MaximumJournalUnitBytes = 64 * 1024;
        sealed class JournalProgress
        {
            public int Schema = 1;
            public string Identity, Failure;
            public long InitialBudget, Budget;
            public uint Start, Next;
            public bool Complete, Committed;
            public RecoveryOutputHead Facts;
        }
        sealed class JournalFact { public string BlobSha256; }
        sealed class JournalStep
        {
            public uint Logical;
            public string Data, Stop;
        }
        sealed class JournalPayload
        {
            public int Schema = 1;
            public List<JournalStep> Steps = new List<JournalStep>();
        }
        // Local working state is reconstructed by the same parser from immutable
        // raw facts. No transaction/counter is published before parent Save.
        sealed class JournalMachine
        {
            public JournalTransaction Transaction = new JournalTransaction();
            public HashSet<uint> Visited = new HashSet<uint>();
            public List<JournalTag> Pending;
            public int TagIndex;
            public uint Next, OldChecksum = 0xffffffff;
            public long Budget;
            public bool Complete;
            public string Failure = "journal_transaction_uncommitted";
        }
        static string JournalIdentity(Context c, JournalContext jc)
        {
            var shape = new {
                jc.Volume.Offset, Header = GroupBytesHash(jc.Volume.Superblock),
                Overlay = GroupOverlayHash(c, jc.Volume), jc.BlockBytes, jc.MaxLen, jc.First,
                jc.Sequence, jc.Start, jc.Incompat, jc.Seed, jc.HasCsumV1, jc.HasCsumV2,
                jc.HasCsumV3, jc.Is64Bit, Uuid = Convert.ToBase64String(jc.Uuid),
                jc.Blocks, c.Limits
            };
            return GroupBytesHash(Encoding.UTF8.GetBytes(new JavaScriptSerializer {
                MaxJsonLength = 16 * 1024 * 1024 }.Serialize(shape)));
        }
        static string JournalStop(JournalMachine machine)
        {
            return machine.Budget <= 0 ? "budget" : machine.Visited.Contains(machine.Next) ? "cycle" : null;
        }
        static void JournalFail(JournalMachine machine, string failure)
        { machine.Complete = true; machine.Failure = failure; }
        static void ApplyJournalStep(Context c, JournalContext jc, JournalMachine machine, JournalStep step,
            byte[] sourceBytes = null)
        {
            c.Cancel.ThrowIfCancellationRequested();
            if (step == null || machine.Complete || step.Logical != machine.Next || step.Stop != JournalStop(machine))
                throw new IOException("EXT4_JOURNAL_STEP_INVALID");
            machine.Budget--;
            if (step.Stop != null)
            {
                if (step.Data != null) throw new IOException("EXT4_JOURNAL_STOP_DATA_INVALID");
                JournalFail(machine, step.Stop == "budget" ? "journal_work_limit" : "journal_transaction_cycle"); return;
            }
            byte[] block = sourceBytes ?? GroupDecode(step.Data, (int)jc.BlockBytes, true);
            if (block.Length != jc.BlockBytes) throw new IOException("EXT4_JOURNAL_BLOCK_SIZE_INVALID");
            machine.Visited.Add(step.Logical);
            if (machine.Pending != null)
            {
                JournalTag tag = machine.Pending[machine.TagIndex];
                if (jc.HasCsumV2 || jc.HasCsumV3)
                {
                    uint seq = machine.Transaction.Sequence;
                    byte[] sequence = { (byte)(seq >> 24), (byte)(seq >> 16), (byte)(seq >> 8), (byte)seq };
                    uint checksum = Crc(Crc(jc.Seed, sequence, 0, 4), block, 0, block.Length);
                    if ((jc.HasCsumV3 ? checksum : checksum & 65535) != tag.Checksum)
                    { JournalFail(machine, "journal_data_checksum_invalid"); return; }
                }
                if (jc.HasCsumV1) machine.OldChecksum = Crc32BigEndian(machine.OldChecksum, block);
                machine.Transaction.DataBlocks.Add(Tuple.Create(tag, jc.Blocks[(int)step.Logical]));
                machine.Next = NextJournalBlock(machine.Next, jc.First, jc.MaxLen);
                if (++machine.TagIndex == machine.Pending.Count) { machine.Pending = null; machine.TagIndex = 0; }
                return;
            }
            if (machine.Visited.Count == 1) machine.Transaction.Sequence = Be32(block, 8);
            if (Be32(block, 0) != 0xc03b3998 || Be32(block, 8) != machine.Transaction.Sequence)
            { machine.Complete = true; return; }
            uint type = Be32(block, 4);
            machine.Next = NextJournalBlock(machine.Next, jc.First, jc.MaxLen);
            if (type == 2)
            {
                if (!JournalMetadataChecksum(jc, block, 16) || jc.HasCsumV1 &&
                    !(block[12] == 1 && block[13] == 4 && Be32(block, 16) == machine.OldChecksum))
                { JournalFail(machine, "journal_commit_checksum_invalid"); return; }
                machine.Transaction.Committed = true; machine.Complete = true; return;
            }
            if (type == 5)
            {
                machine.Transaction.HeaderBlocks.Add(step.Logical);
                if ((jc.Incompat & 1) == 0) { JournalFail(machine, "journal_revoke_feature_missing"); return; }
                if (!JournalMetadataChecksum(jc, block, block.Length - 4))
                { JournalFail(machine, "journal_revoke_checksum_invalid"); return; }
                uint count = Be32(block, 12); int width = jc.Is64Bit ? 8 : 4;
                int limit = block.Length - (jc.HasCsumV2 || jc.HasCsumV3 ? 4 : 0);
                if (count < 16 || count > limit || (count - 16) % width != 0)
                { JournalFail(machine, "journal_revoke_bounds"); return; }
                for (int at = 16; at < count; at += width)
                {
                    ulong revoked = jc.Is64Bit ? Be64(block, at) : Be32(block, at);
                    if (!BlockRange(jc.Volume, revoked, 1)) { JournalFail(machine, "journal_revoke_bounds"); return; }
                    machine.Transaction.RevokedBlocks.Add(revoked);
                }
                return;
            }
            if (type != 1) { machine.Complete = true; return; }
            machine.Transaction.HeaderBlocks.Add(step.Logical);
            if (!JournalMetadataChecksum(jc, block, block.Length - 4))
            { JournalFail(machine, "journal_descriptor_checksum_invalid"); return; }
            var tags = ParseDescriptorTags(block, jc);
            if (tags == null || tags.Count == 0) { JournalFail(machine, "journal_descriptor_tags_invalid"); return; }
            if (jc.HasCsumV1) machine.OldChecksum = Crc32BigEndian(machine.OldChecksum, block);
            machine.Pending = tags;
        }
        static JournalProgress JournalCursor(JournalProgress initial, JournalMachine machine, RecoveryOutputHead facts)
        {
            return new JournalProgress { Identity = initial.Identity, Start = initial.Start,
                InitialBudget = initial.InitialBudget, Budget = machine.Budget, Next = machine.Next,
                Complete = machine.Complete, Committed = machine.Transaction.Committed,
                Failure = machine.Failure, Facts = facts };
        }
        static bool TryJournalTransactionCheckpointed(Context c, JournalContext jc, uint start,
            out JournalTransaction trans, out uint next, out string failure, ref long budget,
            RecoveryCheckpointContext context, Action<string> progress)
        {
            if (jc == null || jc.First < 1 || jc.First >= jc.MaxLen || start < jc.First || start >= jc.MaxLen ||
                jc.MaxLen > jc.Blocks.Count || jc.BlockBytes != jc.Volume.BlockBytes ||
                jc.BlockBytes < 1024 || jc.BlockBytes > MaximumJournalUnitBytes || budget < 0 ||
                jc.MaxLen > c.Limits.MaximumJournalBlocks)
                throw new IOException("EXT4_JOURNAL_PHASE_INVALID");
            ValidateMetadataSource(c, context);
            var initial = new JournalProgress { Start = start, Next = start, InitialBudget = budget,
                Budget = budget, Failure = "journal_transaction_uncommitted",
                Identity = context == null ? null : JournalIdentity(c, jc) };
            var journal = new RecoveryMethodJournal<JournalProgress>(c.Input.Name, initial, context, c.Cancel);
            JournalProgress state = journal.Payload;
            if (state.Schema != 1 || state.Start != start || state.InitialBudget != budget || state.Identity != initial.Identity)
                throw new IOException("EXT4_JOURNAL_CHECKPOINT_INVALID");
            var ledger = new RecoveryOutputLedger<JournalFact>(context, state.Facts,
                checked((int)(jc.MaxLen - jc.First) + 1), c.Cancel,
                RecoveryLedgerScope.MethodOutput, 64L * 1024 * 1024);
            var machine = new JournalMachine { Next = start, Budget = budget };
            foreach (JournalFact fact in ledger.Records)
            {
                var payload = ReadMetadataPayload<JournalPayload>(context, "journal-blobs", fact.BlobSha256, c.Cancel);
                if (payload.Schema != 1 || payload.Steps == null || payload.Steps.Count < 1 ||
                    payload.Steps.Count > MaximumJournalUnitBytes / jc.BlockBytes + 1)
                    throw new IOException("EXT4_JOURNAL_UNIT_INVALID");
                int bytes = 0;
                foreach (JournalStep step in payload.Steps)
                {
                    if (step != null && step.Data != null) bytes = checked(bytes + (int)jc.BlockBytes);
                    if (bytes > MaximumJournalUnitBytes) throw new IOException("EXT4_JOURNAL_UNIT_LIMIT");
                    ApplyJournalStep(c, jc, machine, step);
                }
            }
            if (state.Next != machine.Next || state.Budget != machine.Budget || state.Complete != machine.Complete ||
                state.Committed != machine.Transaction.Committed || state.Failure != machine.Failure)
                throw new IOException("EXT4_JOURNAL_CURSOR_INVALID");
            while (!machine.Complete)
            {
                var payload = new JournalPayload(); int bytes = 0;
                while (!machine.Complete && bytes < MaximumJournalUnitBytes)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    var step = new JournalStep { Logical = machine.Next, Stop = JournalStop(machine) };
                    byte[] data = null;
                    if (step.Stop == null)
                    {
                        data = JournalBlock(c, jc, machine.Next);
                        if (data == null || data.Length != jc.BlockBytes) throw new EndOfStreamException("EXT4_JOURNAL_SHORT_READ");
                        if (context != null) step.Data = Convert.ToBase64String(data);
                        bytes += data.Length;
                    }
                    ApplyJournalStep(c, jc, machine, step, data); payload.Steps.Add(step);
                }
                var rows = new List<JournalFact> { new JournalFact { BlobSha256 = context == null ? null :
                    StoreMetadataPayload(context, "journal-blobs", payload, c.Cancel) } };
                var saved = JournalCursor(initial, machine, ledger.Append(state.Facts, rows));
                journal.Save(saved); ledger.Accept(rows); state = saved;
                if (progress != null) progress("ext4: journal blocks " + machine.Visited.Count);
            }
            c.Cancel.ThrowIfCancellationRequested();
            trans = machine.Transaction; next = machine.Next; failure = machine.Failure; budget = machine.Budget;
            if (failure == "journal_work_limit") c.Report.Limited = true;
            return trans.Committed;
        }
    }
}
