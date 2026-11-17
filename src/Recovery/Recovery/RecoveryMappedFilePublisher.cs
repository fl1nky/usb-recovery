// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    internal sealed class RecoveryMappedRange
    {
        // -1 denotes logical zeroes, never an unreadable source range.
        public long ImageOffset, LogicalOffset, Length;
    }

    internal sealed class RecoveryMappedFilePlan
    {
        public string ArchiveRoot, OutputRoot, RelativeOutput, Provenance;
        public long Length;
        public byte[] Resident;
        public List<RecoveryMappedRange> Ranges = new List<RecoveryMappedRange>();
    }

    // A metadata parser supplies an already validated plan. This publisher
    // binds and copies that plan; it makes no filesystem/authenticity claim.
    // A caller must use a distinct child checkpoint context for each file.
    internal sealed class RecoveryMappedFilePublisher : IDisposable
    {
        const int UnitBytes = 1024 * 1024;
        sealed class CopyState
        {
            public int Schema = 1;
            public string Identity, WorkId, Phase = "copy", Sha256;
            public long Next, WorkBytes;
            public bool Repairing;
            public RecoveryOutputHead Facts;
        }
        sealed class CopyFact { public long At; public int Length; public string Sha256; }

        readonly FileStream input, sourceLease;
        readonly RecoveryVerifiedImage verifiedImage;
        readonly RecoveryMappedFilePlan plan;
        readonly RecoveryCheckpointContext context;
        readonly CancellationToken cancel;
        readonly Action validate;
        readonly Action<string> progress;
        readonly string identity, contextRoot, method, settings, sourceHash;
        readonly long size;
        readonly RecoveryMethodJournal<CopyState> journal;
        readonly RecoveryOutputLedger<CopyFact> ledger;
        CopyState state;
        bool disposed, ran;

        static bool Digest(string value)
        { return value != null && value.Length == 64 && value.All(x => x >= '0' && x <= '9' || x >= 'a' && x <= 'f'); }
        static bool WorkId(string value)
        { return value != null && value.Length == 32 && value.All(x => x >= '0' && x <= '9' || x >= 'a' && x <= 'f'); }
        static string Hex(byte[] value) { return BitConverter.ToString(value).Replace("-", "").ToLowerInvariant(); }
        static string Hash(byte[] value) { using (var sha = SHA256.Create()) return Hex(sha.ComputeHash(value)); }
        string Hash(Stream value)
        {
            value.Position = 0;
            using (var sha = SHA256.Create()) {
                byte[] bytes = new byte[UnitBytes]; int count;
                while ((count = value.Read(bytes, 0, bytes.Length)) != 0) { cancel.ThrowIfCancellationRequested(); sha.TransformBlock(bytes, 0, count, bytes, 0); }
                sha.TransformFinalBlock(new byte[0], 0, 0); return Hex(sha.Hash);
            }
        }
        string Identity()
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true))) {
                var parent = new Uri(Path.GetFullPath(plan.ArchiveRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar);
                writer.Write(parent.MakeRelativeUri(new Uri(Path.GetFullPath(context.Directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar)).ToString());
                writer.Write(parent.MakeRelativeUri(new Uri(Path.GetFullPath(plan.OutputRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar)).ToString());
                writer.Write(plan.RelativeOutput); writer.Write(plan.Provenance); writer.Write(plan.Length);
                writer.Write(plan.Resident != null);
                if (plan.Resident != null) { writer.Write(plan.Resident.Length); writer.Write(Hash(plan.Resident)); }
                writer.Write(plan.Ranges.Count);
                foreach (var range in plan.Ranges) { cancel.ThrowIfCancellationRequested(); writer.Write(range.ImageOffset); writer.Write(range.LogicalOffset); writer.Write(range.Length); }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static bool Within(string path, string root)
        { return path.Equals(root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase); }
        void ValidatePlan()
        {
            if (plan == null || plan.Provenance == null || plan.Ranges == null || plan.Ranges.Count > 1000000 || plan.Length < 0 ||
                String.IsNullOrWhiteSpace(plan.ArchiveRoot) || String.IsNullOrWhiteSpace(plan.OutputRoot) || String.IsNullOrWhiteSpace(plan.RelativeOutput)) throw new IOException("MAPPED_FILE_PLAN_INVALID");
            string destination = RecoveryCatalog.SafeFile(plan.OutputRoot, plan.RelativeOutput);
            string root = Path.GetFullPath(plan.OutputRoot), source = Path.GetFullPath(input.Name);
            string stateRoot = Path.GetDirectoryName(RecoveryCatalog.SafeFile(context.Directory, context.Method + ".state/guard"));
            string archive = Path.GetFullPath(plan.ArchiveRoot);
            RecoveryCatalog.SafeFile(archive, "guard");
            if (!Within(root, archive) || !Within(Path.GetFullPath(context.Directory), archive) ||
                Within(destination, stateRoot) || Within(source, root) || Within(source, stateRoot))
                throw new IOException("MAPPED_FILE_PATH_INVALID");
            if (plan.Resident != null) {
                if (plan.Resident.LongLength != plan.Length || plan.Ranges.Count != 0) throw new IOException("MAPPED_FILE_RESIDENT_INVALID");
                return;
            }
            long covered = 0;
            foreach (var range in plan.Ranges) {
                if (range == null || range.LogicalOffset != covered || range.Length <= 0 || range.Length > plan.Length - covered ||
                    range.ImageOffset < -1 || range.ImageOffset >= 0 && range.ImageOffset > input.Length - range.Length)
                    throw new IOException("MAPPED_FILE_RANGE_INVALID");
                covered += range.Length;
            }
            // ReFS clones may reuse physical ranges. Logical coverage must be exact.
            if (covered != plan.Length) throw new IOException("MAPPED_FILE_RANGE_INVALID");
        }
        public RecoveryMappedFilePublisher(FileStream source, RecoveryMappedFilePlan candidate, RecoveryCheckpointContext checkpoint,
            CancellationToken token, Action guard, Action<string> notify, RecoveryVerifiedImage verified = null)
        {
            input = source; plan = candidate; context = checkpoint; cancel = token; validate = guard; progress = notify;
            if (context == null || !RecoveryStageFiles.Keys.Contains(context.Method) || input == null || input.CanWrite)
                throw new IOException("MAPPED_FILE_CONTEXT_INVALID");
            contextRoot = Path.GetFullPath(context.Directory); method = context.Method; settings = context.Settings; sourceHash = context.SourceSha256;
            ValidatePlan(); size = plan.Length; identity = Identity();
            verifiedImage = verified;
            if (verifiedImage == null) sourceLease = new FileStream(input.Name, FileMode.Open, FileAccess.Read, FileShare.Read);
            try {
                if (verifiedImage != null) verifiedImage.Validate(input, context.SourceSha256);
                else if (!String.Equals(Hash(sourceLease), context.SourceSha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("MAPPED_FILE_SOURCE_CHANGED");
                journal = new RecoveryMethodJournal<CopyState>(input.Name, new CopyState { Identity = identity }, context, cancel); state = journal.Payload;
                if (state.Schema != 1 || state.Identity != identity || state.Next < 0 || state.Next > size ||
                    state.WorkBytes < 0 || state.WorkBytes > state.Next || state.Repairing != (state.WorkBytes != state.Next) ||
                    state.Phase != "copy" && state.Phase != "ready" && state.Phase != "published" ||
                    state.Phase == "copy" && (journal.Resumed && state.Next == size || state.Sha256 != null) ||
                    state.Phase != "copy" && (state.Next != size || !Digest(state.Sha256)) || journal.Resumed && !WorkId(state.WorkId))
                    throw new IOException("MAPPED_FILE_CHECKPOINT_INVALID");
                int maximum = (int)Math.Min(Int32.MaxValue, Math.Max(1, size / UnitBytes + (size % UnitBytes == 0 ? 0 : 1)));
                ledger = new RecoveryOutputLedger<CopyFact>(context, state.Facts, maximum, cancel, RecoveryLedgerScope.MethodOutput, Math.Max(1024, (long)maximum * 1024));
                long next = 0; bool boundary = state.WorkBytes == 0;
                foreach (var fact in ledger.Records) {
                    if (fact.At != next || fact.Length <= 0 || fact.Length != Math.Min(UnitBytes, size - next) || !Digest(fact.Sha256))
                        throw new IOException("MAPPED_FILE_FACT_INVALID");
                    next += fact.Length; if (next == state.WorkBytes) boundary = true;
                }
                if (next != state.Next || !boundary) throw new IOException("MAPPED_FILE_CURSOR_INVALID");
            } catch { if (sourceLease != null) sourceLease.Dispose(); throw; }
        }
        void Guard()
        {
            cancel.ThrowIfCancellationRequested(); if (disposed) throw new ObjectDisposedException("RecoveryMappedFilePublisher");
            if (Path.GetFullPath(context.Directory) != contextRoot || context.Method != method || context.Settings != settings || context.SourceSha256 != sourceHash)
                throw new IOException("MAPPED_FILE_CONTEXT_CHANGED");
            if (verifiedImage != null) verifiedImage.Validate(input, sourceHash);
            if (validate != null) validate(); ValidatePlan();
            if (Identity() != identity) throw new IOException("MAPPED_FILE_PLAN_CHANGED");
        }
        CopyState Clone()
        { return new CopyState { Identity = state.Identity, WorkId = state.WorkId, Phase = state.Phase, Sha256 = state.Sha256,
            Next = state.Next, WorkBytes = state.WorkBytes, Repairing = state.Repairing, Facts = state.Facts }; }
        void Save(CopyState next, CopyFact fact = null)
        {
            Guard(); var rows = fact == null ? null : new List<CopyFact> { fact };
            if (rows != null) next.Facts = ledger.Append(state.Facts, rows);
            journal.Save(next); if (rows != null) ledger.Accept(rows); state = next;
            if (progress != null) progress(context.Method + ": mapped bytes " + state.WorkBytes + " (" + state.Phase + (state.Repairing ? "/repair" : "") + ")");
        }
        string WorkFile()
        {
            if (!WorkId(state.WorkId)) throw new IOException("MAPPED_FILE_WORK_INVALID");
            return RecoveryCatalog.SafeFile(context.Directory, context.Method + ".state/work/copy-" + state.WorkId + ".partial");
        }
        string Destination() { return RecoveryCatalog.SafeFile(plan.OutputRoot, plan.RelativeOutput); }
        FileStream Create(string id)
        {
            if (!WorkId(id)) throw new IOException("MAPPED_FILE_WORK_INVALID");
            string path = RecoveryCatalog.SafeFile(context.Directory, context.Method + ".state/work/copy-" + id + ".partial");
            Directory.CreateDirectory(Path.GetDirectoryName(path)); return new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
        }
        byte[] ReadMapped(long at, int length)
        {
            Guard(); byte[] bytes = new byte[length];
            if (plan.Resident != null) { Buffer.BlockCopy(plan.Resident, checked((int)at), bytes, 0, length); return bytes; }
            int done = 0;
            foreach (var range in plan.Ranges) {
                if (at >= range.LogicalOffset + range.Length) continue;
                long within = at - range.LogicalOffset; int count = (int)Math.Min(length - done, range.Length - within);
                if (range.ImageOffset >= 0) {
                    input.Position = range.ImageOffset + within; int read = 0;
                    while (read < count) { Guard(); int n = input.Read(bytes, done + read, count - read); if (n == 0) throw new EndOfStreamException("MAPPED_FILE_SHORT_READ"); read += n; }
                }
                done += count; at += count; if (done == length) return bytes;
            }
            throw new IOException("MAPPED_FILE_RANGE_INVALID");
        }
        void VerifyWork(FileStream file)
        {
            long allowance = state.WorkBytes < state.Next ? ledger.Records.First(x => x.At == state.WorkBytes).Length : Math.Min(UnitBytes, size - state.Next);
            if (file.Length < state.WorkBytes || file.Length - state.WorkBytes > allowance) throw new IOException("MAPPED_FILE_WORK_CHANGED");
            file.Position = 0;
            foreach (var fact in ledger.Records) {
                if (fact.At >= state.WorkBytes) break;
                byte[] bytes = new byte[fact.Length]; int done = 0;
                while (done < bytes.Length) { Guard(); int n = file.Read(bytes, done, bytes.Length - done); if (n == 0) throw new IOException("MAPPED_FILE_WORK_CHANGED"); done += n; }
                if (Hash(bytes) != fact.Sha256) throw new IOException("MAPPED_FILE_WORK_CHANGED");
            }
        }
        FileStream OpenWork()
        {
            if (!File.Exists(WorkFile())) {
                var next = Clone(); next.WorkId = Guid.NewGuid().ToString("N"); next.WorkBytes = 0; next.Repairing = next.Next != 0;
                using (var created = Create(next.WorkId)) { created.Flush(true); Save(next); }
            }
            var file = new FileStream(WorkFile(), FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
            try { VerifyWork(file); return file; } catch { file.Dispose(); throw; }
        }
        void WriteUnit(FileStream file, byte[] bytes)
        {
            Guard(); int tail = (int)(file.Length - state.WorkBytes);
            if (tail != 0) {
                file.Position = state.WorkBytes; byte[] existing = new byte[tail]; int done = 0;
                while (done < tail) { Guard(); int n = file.Read(existing, done, tail - done); if (n == 0) throw new IOException("MAPPED_FILE_WORK_CHANGED"); done += n; }
                if (!existing.SequenceEqual(bytes.Take(tail))) throw new IOException("MAPPED_FILE_WORK_CHANGED");
            }
            file.Position = state.WorkBytes; file.Write(bytes, 0, bytes.Length); file.SetLength(state.WorkBytes + bytes.Length); file.Flush(true);
        }
        FileStream ExistingOutput()
        {
            string path = Destination(); if (Directory.Exists(path)) throw new IOException("MAPPED_FILE_OUTPUT_CHANGED");
            if (!File.Exists(path)) return null;
            if (state.Phase == "copy") throw new IOException("MAPPED_FILE_OUTPUT_UNPLANNED");
            var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try { if (file.Length != size || Hash(file) != state.Sha256) throw new IOException("MAPPED_FILE_OUTPUT_CHANGED"); return file; }
            catch { file.Dispose(); throw; }
        }
        string Published()
        {
            Guard(); if (state.Phase != "published") { var next = Clone(); next.Phase = "published"; Save(next); }
            return state.Sha256;
        }
        public string Run()
        {
            Guard(); if (ran) throw new IOException("MAPPED_FILE_ALREADY_RUN"); ran = true;
            if (!journal.Resumed) {
                var initial = Clone(); initial.WorkId = Guid.NewGuid().ToString("N");
                if (size == 0) { initial.Phase = "ready"; initial.Sha256 = Hash(new byte[0]); }
                using (var created = Create(initial.WorkId)) { created.Flush(true); Save(initial); }
            }
            using (var existing = ExistingOutput()) if (existing != null) return Published();
            using (var file = OpenWork()) {
                foreach (var fact in ledger.Records) {
                    if (fact.At < state.WorkBytes) continue;
                    byte[] bytes = ReadMapped(fact.At, fact.Length); if (Hash(bytes) != fact.Sha256) throw new IOException("MAPPED_FILE_REPAIR_CHANGED");
                    WriteUnit(file, bytes); var next = Clone(); next.WorkBytes += bytes.Length; next.Repairing = next.WorkBytes != next.Next; Save(next);
                }
                while (state.Next < size) {
                    byte[] bytes = ReadMapped(state.Next, (int)Math.Min(UnitBytes, size - state.Next)); WriteUnit(file, bytes);
                    var next = Clone(); long at = next.Next; next.Next = next.WorkBytes = next.Next + bytes.Length;
                    if (next.Next == size) { next.Phase = "ready"; next.Sha256 = Hash(file); }
                    Save(next, new CopyFact { At = at, Length = bytes.Length, Sha256 = Hash(bytes) });
                }
                if (Hash(file) != state.Sha256) throw new IOException("MAPPED_FILE_WORK_CHANGED");
            }
            Guard(); string destination = Destination(); Directory.CreateDirectory(Path.GetDirectoryName(destination)); File.Move(WorkFile(), destination);
            using (var final = ExistingOutput()) { if (final == null) throw new IOException("MAPPED_FILE_OUTPUT_MISSING"); return Published(); }
        }
        public void Dispose() { if (disposed) return; disposed = true; if (sourceLease != null) sourceLease.Dispose(); }
    }
}
