using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        const int JournalHeadersPerUnit = 256, JournalHeaderBytes = 12;
        sealed class JournalHeaderProgress
        {
            public int Schema = 1;
            public string Identity;
            public uint Next;
            public bool Complete;
            public RecoveryOutputHead Facts;
        }
        sealed class JournalHeaderPayload
        {
            public int Schema = 1, Count;
            public uint Start;
            public string Headers;
        }
        static void ApplyJournalHeaders(Context c, JournalContext jc, JournalHeaderPayload payload,
            ref uint next, Dictionary<uint, List<uint>> starts)
        {
            c.Cancel.ThrowIfCancellationRequested();
            if (payload == null || payload.Schema != 1 || payload.Start != next || next >= jc.MaxLen ||
                payload.Count != (int)Math.Min(JournalHeadersPerUnit, jc.MaxLen - next))
                throw new IOException("EXT4_JOURNAL_HEADERS_INVALID");
            byte[] bytes = GroupDecode(payload.Headers, payload.Count * JournalHeaderBytes, true);
            for (int index = 0; index < payload.Count; index++)
            {
                int at = index * JournalHeaderBytes; uint type = Be32(bytes, at + 4);
                if (Be32(bytes, at) != 0xc03b3998 || type != 1 && type != 5) continue;
                uint sequence = Be32(bytes, at + 8); List<uint> positions;
                if (!starts.TryGetValue(sequence, out positions)) starts[sequence] = positions = new List<uint>();
                positions.Add(next + (uint)index);
            }
            next += (uint)payload.Count;
        }
        // Header bytes identify candidates only. A message/file still requires
        // a complete checksum-valid transaction and every header of its sequence.
        static Dictionary<uint, List<uint>> ReadJournalHeadersCheckpointed(Context c, JournalContext jc,
            RecoveryCheckpointContext context, Action<string> progress)
        {
            if (jc.First < 1 || jc.First >= jc.MaxLen || jc.MaxLen > jc.Blocks.Count ||
                jc.MaxLen > c.Limits.MaximumJournalBlocks) throw new IOException("EXT4_JOURNAL_HEADERS_GEOMETRY_INVALID");
            ValidateMetadataSource(c, context);
            var initial = new JournalHeaderProgress { Identity = context == null ? null : JournalIdentity(c, jc), Next = jc.First };
            var journal = new RecoveryMethodJournal<JournalHeaderProgress>(c.Input.Name, initial, context, c.Cancel);
            var state = journal.Payload;
            if (state.Schema != 1 || state.Identity != initial.Identity || state.Next < jc.First || state.Next > jc.MaxLen ||
                state.Complete != (state.Next == jc.MaxLen)) throw new IOException("EXT4_JOURNAL_HEADERS_CHECKPOINT_INVALID");
            int units = (int)((jc.MaxLen - jc.First + JournalHeadersPerUnit - 1) / JournalHeadersPerUnit);
            var ledger = new RecoveryOutputLedger<JournalFact>(context, state.Facts, units, c.Cancel,
                RecoveryLedgerScope.MethodOutput, 4L * 1024 * 1024);
            var starts = new Dictionary<uint, List<uint>>(); uint next = jc.First;
            foreach (var fact in ledger.Records)
                ApplyJournalHeaders(c, jc, ReadMetadataPayload<JournalHeaderPayload>(context, "journal-blobs", fact.BlobSha256, c.Cancel), ref next, starts);
            if (next != state.Next) throw new IOException("EXT4_JOURNAL_HEADERS_CURSOR_INVALID");
            while (next < jc.MaxLen)
            {
                int count = (int)Math.Min(JournalHeadersPerUnit, jc.MaxLen - next);
                byte[] bytes = new byte[count * JournalHeaderBytes];
                for (int index = 0; index < count; index++)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    long at = jc.Volume.Offset + (long)jc.Blocks[(int)next + index] * jc.BlockBytes;
                    byte[] header = Read(c, at, JournalHeaderBytes);
                    if (header == null || header.Length != JournalHeaderBytes) throw new EndOfStreamException("EXT4_JOURNAL_HEADER_SHORT_READ");
                    Buffer.BlockCopy(header, 0, bytes, index * JournalHeaderBytes, JournalHeaderBytes);
                }
                c.Cancel.ThrowIfCancellationRequested();
                var payload = new JournalHeaderPayload { Start = next, Count = count, Headers = Convert.ToBase64String(bytes) };
                var rows = new List<JournalFact> { new JournalFact { BlobSha256 = context == null ? null :
                    StoreMetadataPayload(context, "journal-blobs", payload, c.Cancel) } };
                var saved = new JournalHeaderProgress { Identity = initial.Identity, Next = next + (uint)count,
                    Complete = next + (uint)count == jc.MaxLen, Facts = ledger.Append(state.Facts, rows) };
                journal.Save(saved); ledger.Accept(rows); state = saved;
                ApplyJournalHeaders(c, jc, payload, ref next, starts);
                if (progress != null) progress("ext4: journal headers " + (next - jc.First));
            }
            c.Cancel.ThrowIfCancellationRequested();
            return starts;
        }
        sealed class JournalScanProgress
        {
            public int Schema = 1, Candidate, Attempt;
            public string Identity, Phase = "headers";
            public long Budget;
            public bool Limited;
            public RecoveryMethodCheckpoint Headers, Active;
            public RecoveryOutputHead Facts;
        }
        sealed class JournalAttemptFact
        {
            public int Candidate, Attempt;
            public long Before, After;
            public bool Accepted;
            public RecoveryMethodCheckpoint Checkpoint;
        }
        static JournalScanProgress CopyJournalScan(JournalScanProgress state)
        {
            return new JournalScanProgress { Identity = state.Identity, Phase = state.Phase, Budget = state.Budget,
                Candidate = state.Candidate, Attempt = state.Attempt, Limited = state.Limited,
                Headers = state.Headers, Active = state.Active, Facts = state.Facts };
        }
        static RecoveryMethodCheckpoint RelativeJournalChild(RecoveryCheckpointContext parent, RecoveryMethodCheckpoint anchor)
        {
            string root = Path.GetFullPath(parent.Directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string file = Path.GetFullPath(anchor.Path);
            if (!file.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new IOException("EXT4_JOURNAL_CHILD_OUTSIDE_ROOT");
            string relative = file.Substring(root.Length).Replace(Path.DirectorySeparatorChar, '/');
            RecoveryCatalog.SafeFile(parent.Directory, relative);
            return new RecoveryMethodCheckpoint { Path = relative, Sha256 = anchor.Sha256, Sequence = anchor.Sequence };
        }
        static RecoveryCheckpointContext JournalChild(RecoveryCheckpointContext parent, string name,
            RecoveryMethodCheckpoint anchor, Action<RecoveryMethodCheckpoint> commit)
        { return JournalPhaseChild(parent, "history", name, anchor, commit); }
        static RecoveryCheckpointContext JournalPhaseChild(RecoveryCheckpointContext parent, string phase, string name,
            RecoveryMethodCheckpoint anchor, Action<RecoveryMethodCheckpoint> commit)
        {
            if (parent == null) return null;
            if (phase != "history" && phase != "replay") throw new IOException("EXT4_JOURNAL_CHILD_PHASE_INVALID");
            string directory = Path.GetDirectoryName(RecoveryCatalog.SafeFile(parent.Directory, "ext4.state/" + phase + "/" + name + "/guard"));
            RecoveryMethodCheckpoint resume = null;
            if (anchor != null)
            {
                if (anchor.Path == null || Path.IsPathRooted(anchor.Path)) throw new IOException("EXT4_JOURNAL_CHILD_LINK_INVALID");
                resume = new RecoveryMethodCheckpoint { Path = RecoveryCatalog.SafeFile(parent.Directory, anchor.Path),
                    Sha256 = anchor.Sha256, Sequence = anchor.Sequence };
            }
            return new RecoveryCheckpointContext { Directory = directory, Method = "ext4", SourceSha256 = parent.SourceSha256,
                Settings = GroupBytesHash(Encoding.UTF8.GetBytes(parent.Settings)) + ":" + phase + ":" + name, Resume = resume,
                Commit = value => commit(RelativeJournalChild(parent, value)) };
        }
        static string AttemptName(int number) { return "attempt-" + number.ToString("D8", CultureInfo.InvariantCulture); }
        static bool ApplyJournalAttempt(Context c, KeyValuePair<uint, List<uint>>[] candidates, JournalTransaction transaction,
            bool committed, string failure, long budget, ref int candidate, ref int attempt)
        {
            bool accepted = committed && transaction.HeaderBlocks.SetEquals(candidates[candidate].Value);
            if (budget < 0) { Skip(c, "journal_work_limit"); return false; }
            if (!accepted) Skip(c, failure);
            if (accepted || attempt + 1 == candidates[candidate].Value.Count) { candidate++; attempt = 0; }
            else attempt++;
            return accepted;
        }
        static List<JournalTransaction> ReadJournalHistoryTransactionsCheckpointed(Context c, JournalContext jc,
            RecoveryCheckpointContext context, Action<string> progress)
        {
            using (context == null ? null : new MetadataSourceScope(c, context))
                return ReadJournalHistoryTransactionsCore(c, jc, context, progress);
        }
        static List<JournalTransaction> ReadJournalHistoryTransactionsCore(Context c, JournalContext jc,
            RecoveryCheckpointContext context, Action<string> progress)
        {
            if (jc == null || jc.First < 1 || jc.First >= jc.MaxLen || jc.MaxLen > jc.Blocks.Count ||
                jc.MaxLen > c.Limits.MaximumJournalBlocks) throw new IOException("EXT4_JOURNAL_SCAN_GEOMETRY_INVALID");
            ValidateMetadataSource(c, context);
            var initial = new JournalScanProgress { Identity = context == null ? null : JournalIdentity(c, jc), Budget = (long)(jc.MaxLen - jc.First) * 4 };
            var journal = new RecoveryMethodJournal<JournalScanProgress>(c.Input.Name, initial, context, c.Cancel);
            JournalScanProgress state = journal.Payload;
            if (state.Schema != 1 || state.Identity != initial.Identity || state.Candidate < 0 || state.Attempt < 0 ||
                state.Phase != "headers" && state.Phase != "transactions" && state.Phase != "complete")
                throw new IOException("EXT4_JOURNAL_SCAN_INVALID");
            if (state.Phase == "headers" && (state.Facts != null || state.Candidate != 0 || state.Attempt != 0 ||
                state.Active != null || state.Budget != initial.Budget || state.Limited))
                throw new IOException("EXT4_JOURNAL_SCAN_HEADER_STATE_INVALID");
            var headerContext = JournalChild(context, "headers", state.Headers, link => {
                var linked = CopyJournalScan(state); linked.Headers = link; journal.Save(linked); state = linked;
            });
            if (context != null && state.Phase != "headers")
            {
                if (state.Headers == null || !new RecoveryMethodJournal<JournalHeaderProgress>(
                    c.Input.Name, new JournalHeaderProgress(), headerContext, c.Cancel).Payload.Complete)
                    throw new IOException("EXT4_JOURNAL_SCAN_HEADERS_INCOMPLETE");
            }
            var starts = ReadJournalHeadersCheckpointed(c, jc, headerContext, progress);
            var candidates = starts.OrderBy(row => row.Value[0]).ToArray();
            if (state.Phase == "headers")
            {
                var saved = CopyJournalScan(state); saved.Phase = candidates.Length == 0 ? "complete" : "transactions";
                journal.Save(saved); state = saved;
            }
            var ledger = new RecoveryOutputLedger<JournalAttemptFact>(context, state.Facts,
                (int)(jc.MaxLen - jc.First), c.Cancel, RecoveryLedgerScope.MethodOutput, 256L * 1024 * 1024);
            var transactions = new List<JournalTransaction>(); int candidate = 0, attempt = 0, factIndex = 0; long budget = initial.Budget;
            foreach (var fact in ledger.Records)
            {
                if (budget < 0 || candidate >= candidates.Length || fact.Candidate != candidate || fact.Attempt != attempt || fact.Before != budget || fact.Checkpoint == null)
                    throw new IOException("EXT4_JOURNAL_ATTEMPT_FACT_INVALID");
                var child = JournalChild(context, AttemptName(factIndex++), fact.Checkpoint,
                    link => { throw new IOException("EXT4_JOURNAL_COMPLETED_CHILD_RESTARTED"); });
                var childState = new RecoveryMethodJournal<JournalProgress>(c.Input.Name, new JournalProgress(), child, c.Cancel);
                if (!childState.Payload.Complete) throw new IOException("EXT4_JOURNAL_CHILD_INCOMPLETE");
                JournalTransaction transaction; uint next; string failure;
                bool committed = TryJournalTransactionCheckpointed(c, jc, candidates[candidate].Value[attempt], out transaction, out next, out failure, ref budget, child, null);
                bool accepted = ApplyJournalAttempt(c, candidates, transaction, committed, failure, budget, ref candidate, ref attempt);
                if (budget != fact.After || accepted != fact.Accepted) throw new IOException("EXT4_JOURNAL_ATTEMPT_VERDICT_INVALID");
                if (accepted) transactions.Add(transaction);
            }
            if (candidate != state.Candidate || attempt != state.Attempt || budget != state.Budget || state.Limited != (budget < 0) ||
                (state.Phase == "complete") != (candidate == candidates.Length || budget < 0) || state.Phase == "complete" && state.Active != null)
                throw new IOException("EXT4_JOURNAL_SCAN_CURSOR_INVALID");
            while (state.Phase != "complete")
            {
                long before = budget;
                var child = JournalChild(context, AttemptName(ledger.Records.Count), state.Active, link => {
                    var linked = CopyJournalScan(state); linked.Active = link; journal.Save(linked); state = linked;
                });
                JournalTransaction transaction; uint next; string failure;
                bool committed = TryJournalTransactionCheckpointed(c, jc, candidates[candidate].Value[attempt], out transaction, out next, out failure, ref budget, child, progress);
                int nextCandidate = candidate, nextAttempt = attempt;
                bool accepted = committed && budget >= 0 && transaction.HeaderBlocks.SetEquals(candidates[candidate].Value);
                if (budget >= 0) {
                    if (accepted || attempt + 1 == candidates[candidate].Value.Count) { nextCandidate++; nextAttempt = 0; }
                    else nextAttempt++;
                }
                var rows = new List<JournalAttemptFact> { new JournalAttemptFact { Candidate = candidate, Attempt = attempt,
                    Before = before, After = budget, Accepted = accepted, Checkpoint = state.Active } };
                var saved = CopyJournalScan(state); saved.Budget = budget; saved.Candidate = nextCandidate; saved.Attempt = nextAttempt;
                saved.Limited = budget < 0; saved.Phase = nextCandidate == candidates.Length || budget < 0 ? "complete" : "transactions";
                saved.Facts = ledger.Append(state.Facts, rows); saved.Active = null;
                journal.Save(saved); ledger.Accept(rows); state = saved;
                ApplyJournalAttempt(c, candidates, transaction, committed, failure, budget, ref candidate, ref attempt);
                if (accepted) transactions.Add(transaction);
                if (progress != null) progress("ext4: journal transactions " + ledger.Records.Count);
            }
            c.Cancel.ThrowIfCancellationRequested();
            if (context != null && JournalIdentity(c, jc) != initial.Identity) throw new IOException("EXT4_JOURNAL_SCAN_BINDING_CHANGED");
            return state.Limited ? null : transactions;
        }
    }
}
