// SPDX-License-Identifier: AGPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;

namespace UsbRecovery
{
    public static partial class RefsRecovery
    {
        // Kept for callers without a durable parent checkpoint. The managed
        // controller supplies PublishFile for resumable copying instead.
        static void WriteFileLegacy(Context c, Entry entry, byte[] resident, string relativeOutput)
        {
            string destination = RecoveryCatalog.SafeFile(c.Root, relativeOutput), temporary = destination + ".partial";
            byte[] buffer = new byte[1024 * 1024]; bool own = false; string digest;
            try {
                using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    own = true;
                    if (resident != null) output.Write(resident, 0, resident.Length);
                    else foreach (var extent in entry.Extents) {
                        if (extent.ImageOffset >= 0) c.Input.Position = extent.ImageOffset;
                        long remaining = extent.Length;
                        if (extent.ImageOffset < 0) System.Array.Clear(buffer, 0, buffer.Length);
                        while (remaining > 0) {
                            c.Cancel.ThrowIfCancellationRequested();
                            int n = extent.ImageOffset < 0 ? (int)System.Math.Min(remaining, buffer.Length) : c.Input.Read(buffer, 0, (int)System.Math.Min(remaining, buffer.Length));
                            if (n == 0) throw new EndOfStreamException("Неполное чтение refs");
                            output.Write(buffer, 0, n); remaining -= n;
                        }
                    }
                    output.Flush(true);
                }
                using (var input = File.OpenRead(temporary)) using (var sha = SHA256.Create()) digest = Hex(sha.ComputeHash(input));
                c.Cancel.ThrowIfCancellationRequested(); File.Move(temporary, destination);
            } finally { if (own && File.Exists(temporary)) File.Delete(temporary); }
            entry.Output = relativeOutput; entry.Sha256 = digest; entry.RecoveredBytes = entry.DeclaredSize;
        }
    }
}
