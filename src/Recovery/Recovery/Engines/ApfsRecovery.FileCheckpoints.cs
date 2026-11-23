// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class ApfsRecovery
    {
        static void FileString(BinaryWriter writer,string value)
        { writer.Write(value != null); if (value != null) writer.Write(value); }
        static void FileDate(BinaryWriter writer,DateTime? value)
        { writer.Write(value.HasValue); if (value.HasValue) { writer.Write(value.Value.Ticks); writer.Write((int)value.Value.Kind); } }
        static string FilePlanIdentity(Context c,Entry entry)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,sha,CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream,new UTF8Encoding(false,true))) {
                writer.Write(MetadataLimitsIdentity(c.Limits)); writer.Write(c.OutputBytes); writer.Write(c.EntryCount);
                writer.Write(c.Report.Entries.Count); writer.Write(c.Report.Limited);
                writer.Write(entry.VolumeOffset); writer.Write(entry.ObjectId); writer.Write(entry.ParentObjectId);
                writer.Write(entry.DeclaredSize); writer.Write(entry.TransactionId); writer.Write(entry.FileAttributes);
                writer.Write(entry.IsResident); writer.Write(entry.IsOrphan); writer.Write(entry.MetadataChecksumVerified); writer.Write(entry.ContentAuthenticityVerified);
                FileDate(writer,entry.CreationTimeUtc); FileDate(writer,entry.LastWriteTimeUtc); FileDate(writer,entry.EntryChangeTimeUtc); FileDate(writer,entry.LastAccessTimeUtc);
                foreach (string value in new[] { entry.Name,entry.RelativePath,entry.Status,entry.Reason,entry.DeletionEvidence }) FileString(writer,value);
                writer.Write(entry.Extents.Count);
                foreach (var extent in entry.Extents) { c.Cancel.ThrowIfCancellationRequested(); writer.Write(extent.ImageOffset); writer.Write(extent.LogicalOffset); writer.Write(extent.Length); writer.Write(extent.PhysicalBlockNumber); }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static void WriteFileCheckpointed(Context c,Entry entry,RecoveryCheckpointContext context,Action<string> progress)
        {
            PrepareFileMap(c,entry);
            if (entry.Extents.Count > c.Limits.MaximumExtents || entry.DeclaredSize > c.Limits.MaximumFileBytes || c.OutputBytes < 0 ||
                entry.DeclaredSize > c.Limits.MaximumOutputBytes-c.OutputBytes || entry.Output != null || entry.Sha256 != null || entry.RecoveredBytes != 0)
                throw new IOException("APFS_FILE_PLAN_INVALID");
            string identity = FilePlanIdentity(c,entry),relative = OutputPath(entry);
            var input = c.Stream; var verified = c.VerifiedImage;
            var plan = new RecoveryMappedFilePlan { ArchiveRoot = Path.GetDirectoryName(Path.GetFullPath(c.Destination)), OutputRoot = c.Destination,
                RelativeOutput = relative, Provenance = identity, Length = entry.DeclaredSize,
                Ranges = entry.Extents.Select(x => new RecoveryMappedRange { ImageOffset = x.PhysicalBlockNumber == 0 ? -1 : x.ImageOffset, LogicalOffset = x.LogicalOffset, Length = x.Length }).ToList() };
            Action guard = () => {
                if (c.Stream != input || c.VerifiedImage != verified || Path.GetFullPath(c.Destination) != Path.GetFullPath(plan.OutputRoot) ||
                    entry.Output != null || entry.Sha256 != null || entry.RecoveredBytes != 0 || FilePlanIdentity(c,entry) != identity)
                    throw new IOException("APFS_FILE_PLAN_CHANGED");
            };
            string digest;
            using (var publisher = new RecoveryMappedFilePublisher(input,plan,context,c.Cancel,guard,progress,verified)) digest = publisher.Run();
            guard(); entry.Output = relative; entry.Sha256 = digest; entry.RecoveredBytes = entry.DeclaredSize;
        }
    }
}
