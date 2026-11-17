// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace UsbRecovery
{
    public static partial class ApfsRecovery
    {
        static string SafeOutputName(string name)
        {
            var invalid = Path.GetInvalidFileNameChars();
            string value = new string((name ?? "file").Take(80).Select(ch => invalid.Contains(ch) || Char.IsControl(ch) ? '_' : ch).ToArray()).TrimEnd(' ','.');
            return String.IsNullOrEmpty(value) ? "file" : value;
        }
        static string OutputPath(Entry entry)
        {
            return "files/volume_"+entry.VolumeOffset.ToString(CultureInfo.InvariantCulture)+"_object_"+
                entry.ObjectId.ToString(CultureInfo.InvariantCulture)+"_xid_"+entry.TransactionId.ToString(CultureInfo.InvariantCulture)+"_"+SafeOutputName(entry.Name);
        }
        static void PrepareFileMap(Context ctx, Entry entry)
        {
            long covered = 0;
            foreach (var extent in entry.Extents) {
                if (extent == null || extent.LogicalOffset != covered || extent.Length <= 0 || covered >= entry.DeclaredSize)
                    throw new IOException("APFS_FILE_MAP_INVALID");
                extent.Length = Math.Min(extent.Length,entry.DeclaredSize-covered);
                if (extent.PhysicalBlockNumber != 0 && (extent.ImageOffset < 0 || extent.ImageOffset > ctx.Stream.Length-extent.Length))
                    throw new IOException("APFS_FILE_MAP_OUTSIDE_SOURCE");
                covered += extent.Length;
            }
            if (covered != entry.DeclaredSize || entry.DeclaredSize < 0) throw new IOException("APFS_FILE_MAP_INCOMPLETE");
        }
        static void WriteFileLegacy(Context ctx, Entry entry)
        {
            PrepareFileMap(ctx,entry);
            string relative = OutputPath(entry),destination = RecoveryCatalog.SafeFile(ctx.Destination,relative);
            string temporary = RecoveryCatalog.SafeFile(ctx.Destination,"files/copy-"+Guid.NewGuid().ToString("N")+".partial");
            Directory.CreateDirectory(Path.GetDirectoryName(destination));
            // Original directory names are evidence strings, not host paths.
            // Never truncate a previous result, even when its name collides.
            if (File.Exists(destination) || Directory.Exists(destination)) throw new IOException("APFS_OUTPUT_EXISTS");
            bool own = false;
            try {
                using (var output = new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
                using (var sha = SHA256.Create()) {
                    own = true; byte[] bytes = new byte[65536]; long remaining = entry.DeclaredSize;
                    foreach (var extent in entry.Extents) {
                        long count = Math.Min(extent.Length,remaining); if (count == 0) break;
                        if (extent.PhysicalBlockNumber == 0) Array.Clear(bytes,0,bytes.Length); else ctx.Stream.Position = extent.ImageOffset;
                        while (count > 0) {
                            ctx.Cancel.ThrowIfCancellationRequested(); int wanted = (int)Math.Min(count,bytes.Length);
                            int read = extent.PhysicalBlockNumber == 0 ? wanted : ctx.Stream.Read(bytes,0,wanted);
                            if (read == 0) throw new EndOfStreamException("APFS_FILE_SHORT_READ");
                            output.Write(bytes,0,read); sha.TransformBlock(bytes,0,read,bytes,0);
                            count -= read; remaining -= read;
                        }
                    }
                    if (remaining != 0) throw new IOException("APFS_FILE_MAP_INCOMPLETE");
                    sha.TransformFinalBlock(new byte[0],0,0); entry.Sha256 = BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
                    output.Flush(true);
                }
                ctx.Cancel.ThrowIfCancellationRequested(); File.Move(temporary,destination);
                entry.Output = relative; entry.RecoveredBytes = entry.DeclaredSize;
            } finally { if (own && File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
