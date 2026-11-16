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
        const int FileCopyUnitBytes = 1024 * 1024;
        sealed class FileCopyProgress
        {
            public int Schema = 1;
            public string Identity, Limits, WorkId, Header, Phase = "copy", Sha256;
            public long Next, WorkBytes;
            public bool Repairing;
            public RecoveryOutputHead Facts;
        }
        sealed class FileCopyFact { public long At; public int Length; public string Sha256; }

        // The caller supplies a prepared, allocation-checked entry. This child
        // pins its exact mapping, baseline and bytes; it does not certify that
        // a historical file's free blocks still contain the original content.
        sealed class MappedFileCheckpoint
        {
            readonly Context c;
            readonly Entry entry;
            readonly RecoveryCheckpointContext context;
            readonly Action<string> progress;
            readonly List<Extent> extents;
            readonly string root, identity, limits;
            readonly long size;
            readonly RecoveryMethodJournal<FileCopyProgress> journal;
            readonly RecoveryOutputLedger<FileCopyFact> ledger;
            FileCopyProgress state;

            public MappedFileCheckpoint(Context owner, Entry candidate, RecoveryCheckpointContext checkpoint, Action<string> notify)
            {
                if (candidate == null) throw new IOException("EXT4_FILE_PLAN_INVALID");
                c = owner; entry = candidate; context = checkpoint; progress = notify;
                root = Path.GetFullPath(c.Root); size = entry.DeclaredSize;
                NoLinks(root); ValidateMetadataSource(c, context);
                string source = Path.GetFullPath(c.Input.Name);
                if (source.Equals(root, StringComparison.OrdinalIgnoreCase) ||
                    source.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("EXT4_FILE_SOURCE_IN_OUTPUT");
                if (c.Limits.MaximumFileBytes < 1 || c.Limits.MaximumOutputBytes < 1 || size < 1 ||
                    size > c.Limits.MaximumFileBytes || c.Report.OutputBytes < 0 ||
                    size > c.Limits.MaximumOutputBytes - c.Report.OutputBytes || c.Report.RecoveredFiles < 0 ||
                    c.Report.RecoveredFiles == Int32.MaxValue || entry.Extents == null || entry.Extents.Count < 1 ||
                    entry.Extents.Count > c.Limits.MaximumExtents || entry.Names == null || entry.Names.Count > c.Limits.MaximumNames ||
                    entry.Names.Any(x => x == null) || entry.Output != null || entry.Sha256 != null || entry.RecoveredBytes != 0)
                    throw new IOException("EXT4_FILE_PLAN_INVALID");
                extents = entry.Extents.Select(x => x == null ? null : new Extent {
                    ImageOffset = x.ImageOffset, LogicalOffset = x.LogicalOffset, Length = x.Length }).ToList();
                long covered = 0;
                foreach (var extent in extents)
                {
                    if (extent == null || extent.LogicalOffset != covered || extent.Length < 1 || extent.Length > size - covered ||
                        extent.ImageOffset < 0 || extent.ImageOffset > c.Input.Length - extent.Length)
                        throw new IOException("EXT4_FILE_MAP_INVALID");
                    covered += extent.Length;
                }
                var physical = extents.OrderBy(x => x.ImageOffset).ToList();
                for (int i = 1; i < physical.Count; i++)
                    if (physical[i - 1].Length > physical[i].ImageOffset - physical[i - 1].ImageOffset)
                        throw new IOException("EXT4_FILE_MAP_OVERLAP");
                if (covered != size) throw new IOException("EXT4_FILE_MAP_INVALID");
                identity = FileCopyIdentity(c, entry, context); limits = Ext4LimitsIdentity(c.Limits);
                journal = new RecoveryMethodJournal<FileCopyProgress>(c.Input.Name,
                    new FileCopyProgress { Identity = identity, Limits = limits }, context, c.Cancel);
                state = journal.Payload;
                if (state.Schema != 1 || state.Identity != identity || state.Limits != limits || state.Next < 0 || state.Next > size ||
                    state.WorkBytes < 0 || state.WorkBytes > state.Next || !state.Repairing && state.WorkBytes != state.Next ||
                    state.Repairing && state.WorkBytes == state.Next ||
                    state.Phase != "copy" && state.Phase != "ready" && state.Phase != "published" ||
                    state.Phase == "copy" && (state.Next == size || state.Sha256 != null) ||
                    state.Phase != "copy" && (state.Next != size || !GroupDigest(state.Sha256)))
                    throw new IOException("EXT4_FILE_CHECKPOINT_INVALID");
                int maximum = (int)Math.Min(Int32.MaxValue, (size - 1) / FileCopyUnitBytes + 2);
                ledger = new RecoveryOutputLedger<FileCopyFact>(context, state.Facts, maximum, c.Cancel,
                    RecoveryLedgerScope.MethodOutput, Math.Max(1024, (long)maximum * 1024));
                long next = 0; bool workBoundary = state.WorkBytes == 0;
                foreach (var fact in ledger.Records)
                {
                    int expected = next == 0 ? (int)Math.Min(32, size) : (int)Math.Min(FileCopyUnitBytes, size - next);
                    if (fact.At != next || fact.Length < 1 || fact.Length != expected || !GroupDigest(fact.Sha256))
                        throw new IOException("EXT4_FILE_FACT_INVALID");
                    next += fact.Length; if (next == state.WorkBytes) workBoundary = true;
                }
                if (next != state.Next || !workBoundary || journal.Resumed && state.Next == 0)
                    throw new IOException("EXT4_FILE_CURSOR_INVALID");
                if (journal.Resumed)
                {
                    if (!WorkIdValid(state.WorkId)) throw new IOException("EXT4_FILE_WORK_INVALID");
                    byte[] header = GroupDecode(state.Header, ledger.Records[0].Length, true);
                    if (GroupBytesHash(header) != ledger.Records[0].Sha256) throw new IOException("EXT4_FILE_HEADER_INVALID");
                }
            }
            static bool WorkIdValid(string id)
            { return id != null && id.Length == 32 && id.All(x => x >= '0' && x <= '9' || x >= 'a' && x <= 'f'); }
            string WorkFile(string id)
            {
                if (!WorkIdValid(id)) throw new IOException("EXT4_FILE_WORK_INVALID");
                return RecoveryCatalog.SafeFile(context.Directory, "ext4.state/work/copy-" + id + ".partial");
            }
            string RelativeOutput()
            {
                byte[] header = GroupDecode(state.Header, ledger.Records[0].Length, true);
                return "files/volume_" + entry.VolumeOffset.ToString(CultureInfo.InvariantCulture) + "_inode_" +
                    entry.Inode.ToString(CultureInfo.InvariantCulture) + "_generation_" + entry.Generation.ToString(CultureInfo.InvariantCulture) + SignatureExtension(header);
            }
            string Destination() { return RecoveryCatalog.SafeFile(root, RelativeOutput()); }
            FileCopyProgress CopyState()
            {
                return new FileCopyProgress { Identity = state.Identity, Limits = state.Limits, WorkId = state.WorkId, Header = state.Header,
                    Phase = state.Phase, Sha256 = state.Sha256, Next = state.Next, WorkBytes = state.WorkBytes,
                    Repairing = state.Repairing, Facts = state.Facts };
            }
            void Save(FileCopyProgress next, List<FileCopyFact> rows = null)
            {
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                if (rows != null) next.Facts = ledger.Append(state.Facts, rows);
                journal.Save(next); if (rows != null) ledger.Accept(rows); state = next;
                if (progress != null) progress("ext4: file bytes " + state.WorkBytes + " (" + state.Phase + (state.Repairing ? "/repair" : "") + ")");
            }
            byte[] ReadMapped(long at, int length)
            {
                byte[] bytes = new byte[length]; int done = 0;
                foreach (var extent in extents)
                {
                    if (at >= extent.LogicalOffset + extent.Length) continue;
                    long within = at - extent.LogicalOffset;
                    int count = (int)Math.Min(length - done, extent.Length - within);
                    c.Input.Position = extent.ImageOffset + within; int read = 0;
                    while (read < count)
                    {
                        c.Cancel.ThrowIfCancellationRequested(); int n = c.Input.Read(bytes, done + read, count - read);
                        if (n == 0) throw new EndOfStreamException("EXT4_FILE_SHORT_READ"); read += n;
                    }
                    done += count; at += count; if (done == length) return bytes;
                }
                throw new IOException("EXT4_FILE_MAP_INVALID");
            }
            FileStream CreateWork(string id)
            {
                string path = WorkFile(id); Directory.CreateDirectory(Path.GetDirectoryName(path));
                return new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
            }
            void Initialize()
            {
                byte[] header = ReadMapped(0, (int)Math.Min(32, size));
                var next = CopyState(); next.Header = Convert.ToBase64String(header); next.WorkId = Guid.NewGuid().ToString("N");
                // Never clean a path merely because CreateNew failed. A unique
                // work file becomes owned by a resume only after parent ack.
                using (var output = CreateWork(next.WorkId))
                {
                    output.Write(header, 0, header.Length); output.Flush(true);
                    next.Next = next.WorkBytes = header.Length;
                    if (next.Next == size) { next.Phase = "ready"; next.Sha256 = GroupBytesHash(header); }
                    Save(next, new List<FileCopyFact> { new FileCopyFact { At = 0, Length = header.Length, Sha256 = GroupBytesHash(header) } });
                }
            }
            void VerifyWork(FileStream file)
            {
                long allowance = 0;
                if (state.WorkBytes < state.Next) allowance = ledger.Records.First(x => x.At == state.WorkBytes).Length;
                else if (state.Next < size) allowance = Math.Min(FileCopyUnitBytes, size - state.Next);
                if (file.Length < state.WorkBytes || file.Length - state.WorkBytes > allowance)
                    throw new IOException("EXT4_FILE_WORK_CHANGED");
                file.Position = 0;
                foreach (var fact in ledger.Records)
                {
                    if (fact.At >= state.WorkBytes) break;
                    byte[] bytes = new byte[fact.Length]; int done = 0;
                    while (done < bytes.Length)
                    {
                        c.Cancel.ThrowIfCancellationRequested(); int n = file.Read(bytes, done, bytes.Length - done);
                        if (n == 0) throw new IOException("EXT4_FILE_WORK_CHANGED"); done += n;
                    }
                    if (GroupBytesHash(bytes) != fact.Sha256) throw new IOException("EXT4_FILE_WORK_CHANGED");
                }
            }
            void WriteUnit(FileStream output, byte[] bytes)
            {
                // A crash/parent failure may leave one unacknowledged tail.
                // Compare it with this exact mapped unit before replacing it.
                int tail = (int)(output.Length - state.WorkBytes);
                if (tail != 0)
                {
                    output.Position = state.WorkBytes; byte[] existing = new byte[tail]; int done = 0;
                    while (done < tail) { c.Cancel.ThrowIfCancellationRequested(); int n = output.Read(existing, done, tail - done);
                        if (n == 0) throw new IOException("EXT4_FILE_WORK_CHANGED"); done += n; }
                    if (!existing.SequenceEqual(bytes.Take(tail))) throw new IOException("EXT4_FILE_WORK_CHANGED");
                }
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                output.Position = state.WorkBytes; output.Write(bytes, 0, bytes.Length); output.SetLength(state.WorkBytes + bytes.Length); output.Flush(true);
            }
            FileStream OpenOrRepairWork()
            {
                string path = WorkFile(state.WorkId);
                if (!File.Exists(path))
                {
                    var next = CopyState(); next.WorkId = Guid.NewGuid().ToString("N"); next.WorkBytes = 0; next.Repairing = true;
                    using (var created = CreateWork(next.WorkId)) { created.Flush(true); Save(next); }
                    path = WorkFile(state.WorkId);
                }
                NoLinks(path);
                var output = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                try { VerifyWork(output); return output; } catch { output.Dispose(); throw; }
            }
            FileStream ExistingOutput()
            {
                string path = Destination();
                if (Directory.Exists(path)) throw new IOException("EXT4_FILE_OUTPUT_CHANGED");
                if (!File.Exists(path)) return null;
                if (state.Phase == "copy") throw new IOException("EXT4_FILE_OUTPUT_UNPLANNED");
                var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                try {
                    if (file.Length != size || HashStream(file, c.Cancel) != state.Sha256) throw new IOException("EXT4_FILE_OUTPUT_CHANGED");
                    return file;
                } catch { file.Dispose(); throw; }
            }
            void ApplyOutput()
            {
                if (FileCopyIdentity(c, entry, context) != identity) throw new IOException("EXT4_FILE_PLAN_CHANGED");
                byte[] header = GroupDecode(state.Header, ledger.Records[0].Length, true);
                string extension = SignatureExtension(header);
                entry.Output = RelativeOutput(); entry.Sha256 = state.Sha256; entry.RecoveredBytes = size;
                entry.ContentTypeHint = extension == ".bin" ? null : extension.Substring(1) + "_signature_only";
                entry.Status = "deleted_inode_candidate"; c.Report.RecoveredFiles++; c.Report.OutputBytes += size;
            }
            void ConfirmPublished()
            {
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                if (FileCopyIdentity(c, entry, context) != identity) throw new IOException("EXT4_FILE_PLAN_CHANGED");
                if (state.Phase != "published") { var published = CopyState(); published.Phase = "published"; Save(published); }
                ApplyOutput();
            }
            public void Run()
            {
                if (!journal.Resumed) Initialize();
                using (var existing = ExistingOutput()) if (existing != null) { ConfirmPublished(); return; }
                using (var output = OpenOrRepairWork())
                {
                    foreach (var fact in ledger.Records)
                    {
                        if (fact.At < state.WorkBytes) continue;
                        byte[] bytes = ReadMapped(fact.At, fact.Length);
                        if (GroupBytesHash(bytes) != fact.Sha256) throw new IOException("EXT4_FILE_REPAIR_CHANGED");
                        WriteUnit(output, bytes); var repaired = CopyState(); repaired.WorkBytes += bytes.Length;
                        repaired.Repairing = repaired.WorkBytes != repaired.Next; Save(repaired);
                    }
                    while (state.Next < size)
                    {
                        byte[] bytes = ReadMapped(state.Next, (int)Math.Min(FileCopyUnitBytes, size - state.Next));
                        WriteUnit(output, bytes); var next = CopyState(); long at = next.Next;
                        next.Next = next.WorkBytes = state.Next + bytes.Length;
                        if (next.Next == size) { next.Phase = "ready"; next.Sha256 = HashStream(output, c.Cancel); }
                        Save(next, new List<FileCopyFact> { new FileCopyFact { At = at, Length = bytes.Length, Sha256 = GroupBytesHash(bytes) } });
                    }
                    if (HashStream(output, c.Cancel) != state.Sha256) throw new IOException("EXT4_FILE_WORK_CHANGED");
                }
                c.Cancel.ThrowIfCancellationRequested(); c.CheckpointSource.ValidateLimits();
                if (FileCopyIdentity(c, entry, context) != identity) throw new IOException("EXT4_FILE_PLAN_CHANGED");
                string destination = Destination(); Directory.CreateDirectory(Path.GetDirectoryName(destination));
                File.Move(WorkFile(state.WorkId), destination);
                using (var final = ExistingOutput()) { if (final == null) throw new IOException("EXT4_FILE_OUTPUT_MISSING"); ConfirmPublished(); }
            }
        }

        static void CopyString(BinaryWriter writer, string value) { writer.Write(value != null); if (value != null) writer.Write(value); }
        static string FileCopyIdentity(Context c, Entry entry, RecoveryCheckpointContext context)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            {
                var folder = new Uri(Path.GetFullPath(context.Directory) + Path.DirectorySeparatorChar);
                writer.Write(folder.MakeRelativeUri(new Uri(Path.GetFullPath(c.Root) + Path.DirectorySeparatorChar)).ToString());
                writer.Write(c.Report.RecoveredFiles); writer.Write(c.Report.OutputBytes); writer.Write(c.Report.Candidates);
                writer.Write(c.Report.Entries.Count); writer.Write(c.Report.Limited);
                writer.Write(entry.VolumeOffset); writer.Write(entry.InodeOffset); writer.Write(entry.DeclaredSize); writer.Write(entry.Inode);
                writer.Write(entry.Generation); writer.Write(entry.DeletionTime); writer.Write(entry.InodeChecksumVerified); writer.Write(entry.ContentAuthenticityVerified);
                foreach (string value in new[] { entry.Status, entry.Reason, entry.Mapping, entry.MappingIntegrity, entry.AllocationStatus, entry.DeletionEvidence, entry.Note }) CopyString(writer, value);
                writer.Write(entry.Extents.Count);
                foreach (var extent in entry.Extents) { c.Cancel.ThrowIfCancellationRequested(); writer.Write(extent.ImageOffset); writer.Write(extent.LogicalOffset); writer.Write(extent.Length); }
                writer.Write(entry.Names.Count);
                foreach (var name in entry.Names)
                {
                    c.Cancel.ThrowIfCancellationRequested(); writer.Write(name.DirectoryInode); writer.Write(name.TargetInode); writer.Write(name.EntryOffset);
                    writer.Write(name.DirectoryChecksumVerified); CopyString(writer, name.Name); CopyString(writer, name.DirectoryPath); CopyString(writer, name.Status);
                    writer.Write(name.JournalBlockOffset.HasValue); if (name.JournalBlockOffset.HasValue) writer.Write(name.JournalBlockOffset.Value);
                    writer.Write(name.TargetBlockOffset.HasValue); if (name.TargetBlockOffset.HasValue) writer.Write(name.TargetBlockOffset.Value);
                    writer.Write(name.JournalTransactionSequence.HasValue); if (name.JournalTransactionSequence.HasValue) writer.Write(name.JournalTransactionSequence.Value);
                }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static void WriteFileCheckpointed(Context c, Entry entry, RecoveryCheckpointContext context, Action<string> progress)
        {
            if (context == null) { WriteFile(c, entry); return; }
            using (new MetadataSourceScope(c, context)) new MappedFileCheckpoint(c, entry, context, progress).Run();
        }
    }
}
