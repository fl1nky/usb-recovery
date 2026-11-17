// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class RefsRecovery
    {
        static void FileString(BinaryWriter writer, string value)
        { writer.Write(value != null); if (value != null) writer.Write(value); }
        static void FileDate(BinaryWriter writer, DateTime? value)
        { writer.Write(value.HasValue); if (value.HasValue) { writer.Write(value.Value.Ticks); writer.Write((int)value.Value.Kind); } }
        static string FilePlanIdentity(Context c, Entry entry)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true))) {
                writer.Write(MetadataLimitsIdentity(c.Limits)); writer.Write(c.OutputBytes);
                writer.Write(c.Report.OutputBytes); writer.Write(c.Report.RecoveredFiles); writer.Write(c.Report.Candidates);
                writer.Write(c.Report.Entries.Count); writer.Write(c.Report.Limited);
                writer.Write(entry.VolumeOffset); writer.Write(entry.ObjectId); writer.Write(entry.ParentObjectId); writer.Write(entry.DeclaredSize);
                FileDate(writer, entry.CreationTimeUtc); FileDate(writer, entry.LastWriteTimeUtc);
                FileDate(writer, entry.EntryChangeTimeUtc); FileDate(writer, entry.LastAccessTimeUtc);
                writer.Write(entry.FileAttributes); writer.Write(entry.IsResident); writer.Write(entry.MetadataChecksumVerified); writer.Write(entry.ContentAuthenticityVerified);
                foreach (string value in new[] { entry.Name, entry.RelativePath, entry.Status, entry.Reason, entry.DeletionEvidence, entry.Note }) FileString(writer, value);
                writer.Write(entry.Extents.Count);
                foreach (var extent in entry.Extents) { c.Cancel.ThrowIfCancellationRequested(); writer.Write(extent.ImageOffset); writer.Write(extent.LogicalOffset); writer.Write(extent.Length); }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static void WriteFileCheckpointed(Context c, Entry entry, byte[] resident, string relativeOutput,
            RecoveryCheckpointContext context, Action<string> progress)
        {
            if (entry == null || c.Report == null || c.Limits == null || entry.Extents == null || entry.Extents.Any(x => x == null) ||
                entry.Extents.Count > c.Limits.MaximumExtents || entry.DeclaredSize < 0 || entry.DeclaredSize > c.Limits.MaximumFileBytes ||
                c.OutputBytes < 0 || c.Report.OutputBytes < 0 || c.Report.RecoveredFiles < 0 || c.Report.RecoveredFiles == Int32.MaxValue ||
                entry.DeclaredSize > c.Limits.MaximumOutputBytes - c.OutputBytes || entry.DeclaredSize > c.Limits.MaximumOutputBytes - c.Report.OutputBytes ||
                entry.IsResident != (resident != null) || entry.Output != null || entry.Sha256 != null || entry.RecoveredBytes != 0)
                throw new IOException("REFS_FILE_PLAN_INVALID");
            string identity = FilePlanIdentity(c, entry);
            FileStream input = c.Input;
            var plan = new RecoveryMappedFilePlan { ArchiveRoot = Path.GetDirectoryName(Path.GetFullPath(c.Root)), OutputRoot = c.Root, RelativeOutput = relativeOutput, Provenance = identity,
                Length = entry.DeclaredSize, Resident = resident,
                Ranges = entry.Extents.Select(x => new RecoveryMappedRange { ImageOffset = x.ImageOffset, LogicalOffset = x.LogicalOffset, Length = x.Length }).ToList() };
            Action guard = () => {
                if (c.Input != input || Path.GetFullPath(c.Root) != Path.GetFullPath(plan.OutputRoot) ||
                    entry.Output != null || entry.Sha256 != null || entry.RecoveredBytes != 0 || FilePlanIdentity(c, entry) != identity)
                    throw new IOException("REFS_FILE_PLAN_CHANGED");
            };
            string digest;
            using (var publisher = new RecoveryMappedFilePublisher(c.Input, plan, context, c.Cancel, guard, progress)) digest = publisher.Run();
            guard(); entry.Output = relativeOutput; entry.Sha256 = digest; entry.RecoveredBytes = entry.DeclaredSize;
        }
    }
}
