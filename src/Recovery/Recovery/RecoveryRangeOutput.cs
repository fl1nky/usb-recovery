using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace UsbRecovery
{
    public sealed class RecoveryRangeRecord
    {
        public string Path, Sha256, Format;
        public long Offset, Bytes;
    }
    public sealed class RecoveryRangeScanState
    {
        public long Position, SkipUntil;
        public int Probes;
        public bool Complete, Limited;
        public RecoveryOutputHead Output;
    }

    // Source ranges are hashed before a write-ahead plan is committed. Named
    // output appears only after its exact bytes match that committed digest.
    internal sealed class RecoveryRangeOutput
    {
        readonly string root, folder;
        readonly long maximumBytes;
        readonly FileStream source;
        readonly CancellationToken cancel;
        readonly Func<RecoveryRangeRecord, bool> canonicalName;
        public RecoveryRangeOutput(string directory, string outputFolder, FileStream image,
            long maximum, CancellationToken token, Func<RecoveryRangeRecord, bool> namePolicy = null)
        {
            root = directory; folder = outputFolder; source = image; maximumBytes = maximum; cancel = token;
            canonicalName = namePolicy;
        }
        public RecoveryRangeRecord Plan(long offset, long bytes, string format, string relativePath = null)
        {
            var record = new RecoveryRangeRecord { Offset = offset, Bytes = bytes, Format = format,
                Path = relativePath ?? folder + "/offset-" + offset.ToString("D16", System.Globalization.CultureInfo.InvariantCulture) + format };
            Validate(record, false);
            record.Sha256 = CopyHash(record, null);
            return record;
        }
        void Validate(RecoveryRangeRecord record, bool requireHash)
        {
            if (record == null || record.Offset < 0 || record.Bytes <= 0 || record.Bytes > maximumBytes ||
                record.Offset > source.Length - record.Bytes || record.Format == null ||
                record.Format.Length < 2 || record.Format.Length > 13 || record.Format[0] != '.' ||
                System.Linq.Enumerable.Any(record.Format.Substring(1), c => !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9')) ||
                record.Path == null || !record.Path.StartsWith(folder + "/", StringComparison.Ordinal) ||
                (canonicalName == null ?
                    record.Path != folder + "/offset-" + record.Offset.ToString("D16", System.Globalization.CultureInfo.InvariantCulture) + record.Format :
                    !canonicalName(record)) ||
                requireHash && (record.Sha256 == null || record.Sha256.Length != 64 ||
                System.Linq.Enumerable.Any(record.Sha256, c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f'))))
                throw new IOException("METHOD_OUTPUT_RANGE_INVALID");
            RecoveryCatalog.SafeFile(root, record.Path);
        }
        string CopyHash(RecoveryRangeRecord record, Stream output)
        {
            source.Position = record.Offset;
            long left = record.Bytes;
            byte[] buffer = new byte[64 * 1024];
            using (var sha = SHA256.Create())
            {
                while (left > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    int read = source.Read(buffer, 0, (int)Math.Min(left, buffer.Length));
                    if (read == 0) throw new IOException("METHOD_SOURCE_TRUNCATED");
                    sha.TransformBlock(buffer, 0, read, null, 0);
                    if (output != null) output.Write(buffer, 0, read);
                    left -= read;
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                return BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
            }
        }
        public void Restore(RecoveryRangeRecord record)
        {
            Validate(record, true);
            string target = RecoveryCatalog.SafeFile(root, record.Path);
            if (File.Exists(target))
            {
                if (new FileInfo(target).Length != record.Bytes ||
                    RecoveryCore.HashFile(target, cancel, (a, b) => { }) != record.Sha256 ||
                    CopyHash(record, null) != record.Sha256)
                    throw new IOException("METHOD_OUTPUT_CHANGED");
                return;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            string partial = RecoveryCatalog.SafeFile(root, record.Path + ".partial");
            if (File.Exists(partial)) File.Delete(partial); // Unlink; never truncate an alias.
            using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (CopyHash(record, output) != record.Sha256) throw new IOException("METHOD_OUTPUT_SOURCE_CHANGED");
                output.Flush(true);
            }
            cancel.ThrowIfCancellationRequested();
            File.Move(partial, target);
        }
        public void RestoreAll(IList<RecoveryRangeRecord> records, long position)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var record in records)
            {
                Validate(record, true);
                if (record.Offset >= position || !names.Add(record.Path))
                    throw new IOException("METHOD_OUTPUT_INVENTORY_INVALID");
            }
            string output = Path.GetDirectoryName(RecoveryCatalog.SafeFile(root, folder + "/guard"));
            if (Directory.Exists(output))
            {
                if (Directory.EnumerateDirectories(output).Any()) throw new IOException("METHOD_OUTPUT_CHANGED");
                foreach (string path in Directory.EnumerateFiles(output))
                {
                    cancel.ThrowIfCancellationRequested();
                    if (!path.EndsWith(".partial", StringComparison.OrdinalIgnoreCase) &&
                        !names.Contains(folder + "/" + Path.GetFileName(path)))
                        throw new IOException("METHOD_OUTPUT_CHANGED");
                }
            }
            foreach (var record in records) Restore(record);
        }
    }
}
