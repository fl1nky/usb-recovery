using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class SalvagedArchiveMember
    {
        public string Path, OriginalMemberName, Sha256, Status = "member_crc_verified", Note;
        public long HeaderOffset, DataOffset, CompressedBytes, Bytes;
        public int CompressionMethod;
        public string Crc32;
    }

    // Salvages independent local ZIP32 entries. It deliberately does not claim
    // that the archive, Office package, or original document is complete.
    // No source member is executed, rendered, or resolved as an output path.
    public static class ArchiveSalvage
    {
        public const long MaximumMemberBytes = 64L * 1024 * 1024;
        public const long MaximumTotalBytes = 512L * 1024 * 1024;
        public const int MaximumMembers = 5000, MaximumHeaders = 20000;
        const int BlockBytes = 1024 * 1024;
        static readonly Encoding Utf8 = new UTF8Encoding(false, true), LegacyName = Encoding.GetEncoding(437);
        static readonly uint[] CrcTable = MakeCrcTable();

        public sealed class ScanState
        {
            public long Position, SkipUntil, TotalBytes, DecodedWorkBytes;
            public int Candidates;
            public bool Complete, Limited;
            public RecoveryOutputHead Output;
            public Dictionary<string, int> Skipped = new Dictionary<string, int>();
        }

        sealed class WorkBudget
        {
            public long Remaining = MaximumTotalBytes;
            public void Consume(int count) { if (count > Remaining) { Remaining = 0; throw new MemberError("ZIP_WORK_LIMIT"); } Remaining -= count; }
        }

        sealed class MemberError : Exception
        {
            public readonly string Code;
            public MemberError(string code) { Code = code; }
        }

        // Restricts the decompressor to the declared compressed body. Dispose
        // never closes the shared read-only source stream.
        sealed class SliceStream : Stream
        {
            readonly FileStream source; readonly long start, count; long position;
            public SliceStream(FileStream source, long start, long count) { this.source = source; this.start = start; this.count = count; }
            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { return count; } }
            public override long Position { get { return position; } set { throw new NotSupportedException(); } }
            public override int Read(byte[] buffer, int offset, int length)
            {
                if (position >= count) return 0;
                source.Position = start + position;
                int read = source.Read(buffer, offset, (int)Math.Min(length, count - position)); position += read;
                if (read == 0) throw new IOException("ZIP_SOURCE_TRUNCATED");
                return read;
            }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        }

        static void PlainPath(string path)
        {
            for (var item = new FileInfo(Path.GetFullPath(path)); item != null; ) {
                if (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Путь поиска не должен содержать перенаправления.");
                DirectoryInfo directory = item.Directory;
                while (directory != null) { if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Путь поиска не должен содержать перенаправления."); directory = directory.Parent; }
                break;
            }
            if (Directory.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Папка поиска не должна быть ссылкой.");
        }

        static byte[] Read(FileStream stream, long offset, int size)
        {
            if (offset < 0 || size < 0 || offset > stream.Length - size) throw new MemberError("ZIP_HEADER_TRUNCATED");
            byte[] data = new byte[size]; stream.Position = offset; int done = 0, read;
            while (done < size && (read = stream.Read(data, done, size - done)) > 0) done += read;
            if (done != size) throw new IOException("ZIP_SOURCE_TRUNCATED");
            return data;
        }

        static string MemberName(byte[] bytes, ushort flags)
        {
            string name;
            try { name = ((flags & 0x800) != 0 ? Utf8 : LegacyName).GetString(bytes).Replace('\\', '/'); }
            catch (DecoderFallbackException) { throw new MemberError("ZIP_NAME_INVALID"); }
            if (String.IsNullOrEmpty(name) || name.Length > 1024 || name[0] == '/' || name.IndexOf(':') >= 0 || name.Any(c => Char.IsControl(c))) throw new MemberError("ZIP_NAME_UNSAFE");
            string[] parts = name.Split('/');
            if (parts.Any(p => p == "." || p == "..") || parts.Take(parts.Length - 1).Any(p => p.Length == 0)) throw new MemberError("ZIP_NAME_UNSAFE");
            if (name.EndsWith("/", StringComparison.Ordinal)) throw new MemberError("ZIP_DIRECTORY_SKIPPED");
            if (parts.Any(p => p.Length == 0)) throw new MemberError("ZIP_NAME_UNSAFE");
            return name;
        }

        static string SafeLeaf(string name)
        {
            string leaf = name.Substring(name.LastIndexOf('/') + 1);
            leaf = new String(leaf.Where(c => Array.IndexOf(Path.GetInvalidFileNameChars(), c) < 0).ToArray()).Trim().TrimEnd('.');
            if (leaf.Length == 0) leaf = "member.bin";
            if (leaf.Length > 100) leaf = leaf.Substring(0, 80) + Path.GetExtension(leaf).Substring(0, Math.Min(16, Path.GetExtension(leaf).Length));
            string stem = Path.GetFileNameWithoutExtension(leaf).TrimEnd(' ', '.').ToUpperInvariant();
            if (new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }.Contains(stem)) leaf = "_" + leaf;
            string ext = Path.GetExtension(leaf).ToLowerInvariant();
            if (new[] { ".exe", ".dll", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".html", ".htm", ".svg", ".lnk", ".url" }.Contains(ext)) leaf += ".untrusted.bin";
            return leaf;
        }

        static void CheckExtra(byte[] extra)
        {
            int at = 0;
            while (at < extra.Length) {
                if (at > extra.Length - 4) throw new MemberError("ZIP_EXTRA_INVALID");
                ushort id = BitConverter.ToUInt16(extra, at), size = BitConverter.ToUInt16(extra, at + 2); at += 4;
                if (size > extra.Length - at) throw new MemberError("ZIP_EXTRA_INVALID");
                if (id == 0x0001 || id == 0x9901 || id == 0x0017) throw new MemberError("ZIP_FEATURE_UNSUPPORTED");
                at += size;
            }
        }

        static SalvagedArchiveMember Header(FileStream source, long offset, long remaining)
        {
            byte[] header = Read(source, offset, 30);
            if (header[0] != 0x50 || header[1] != 0x4b || header[2] != 3 || header[3] != 4) throw new MemberError("ZIP_HEADER_INVALID");
            ushort version = BitConverter.ToUInt16(header, 4), flags = BitConverter.ToUInt16(header, 6), method = BitConverter.ToUInt16(header, 8);
            if ((flags & 1) != 0 || (flags & 0x2040) != 0) throw new MemberError("ZIP_ENCRYPTED_UNSUPPORTED");
            if ((flags & 8) != 0) throw new MemberError("ZIP_DESCRIPTOR_UNSUPPORTED");
            if (version > 20 || version < 10 || (flags & ~0x0806) != 0 || (method != 0 && method != 8) || (method == 0 && (flags & 6) != 0)) throw new MemberError("ZIP_FEATURE_UNSUPPORTED");
            uint crc = BitConverter.ToUInt32(header, 14), compressed = BitConverter.ToUInt32(header, 18), original = BitConverter.ToUInt32(header, 22);
            int nameBytes = BitConverter.ToUInt16(header, 26), extraBytes = BitConverter.ToUInt16(header, 28);
            if (compressed == UInt32.MaxValue || original == UInt32.MaxValue) throw new MemberError("ZIP_FEATURE_UNSUPPORTED");
            if (nameBytes == 0 || nameBytes > 1024) throw new MemberError("ZIP_NAME_INVALID");
            if (compressed > MaximumMemberBytes || original > MaximumMemberBytes || original > remaining || (compressed == 0 && original != 0) || (compressed > 0 && original > compressed * 1000L)) throw new MemberError("ZIP_MEMBER_LIMIT");
            if (method == 0 && compressed != original) throw new MemberError("ZIP_SIZE_INVALID");
            string name = MemberName(Read(source, offset + 30, nameBytes), flags);
            CheckExtra(Read(source, offset + 30L + nameBytes, extraBytes));
            long dataOffset = offset + 30L + nameBytes + extraBytes;
            if (dataOffset > source.Length - compressed) throw new MemberError("ZIP_MEMBER_TRUNCATED");
            string relative = "salvage-content/member-" + offset.ToString("D16", System.Globalization.CultureInfo.InvariantCulture) + "_" + SafeLeaf(name);
            return new SalvagedArchiveMember { Path = relative, OriginalMemberName = name,
                HeaderOffset = offset, DataOffset = dataOffset, CompressedBytes = compressed, Bytes = original,
                CompressionMethod = method, Crc32 = crc.ToString("x8"),
                Note = "Independent ZIP member CRC and size verified. Archive/document completeness and deletion state unknown. Active file extensions neutralized; nothing executed." };
        }

        // Only a private partial is produced here. The parent must commit the
        // corresponding CRC/SHA plan before Publish creates its public name.
        static SalvagedArchiveMember Extract(FileStream source, long offset, string output, long remaining, WorkBudget work, CancellationToken cancel)
        {
            var member = Header(source, offset, remaining);
            string target = Path.Combine(output, Path.GetFileName(member.Path)), partial = target + ".partial";
            PlainPath(partial);
            if (File.Exists(partial)) File.Delete(partial); // Unlink only; never truncate an alias.
            long original = member.Bytes, compressed = member.CompressedBytes;
            int method = member.CompressionMethod;
            uint crc = Convert.ToUInt32(member.Crc32, 16);
            uint actualCrc = 0xffffffff; long written = 0;
            bool verified = false;
            try {
                using (var file = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                using (var digest = SHA256.Create())
                using (var body = new SliceStream(source, member.DataOffset, compressed)) {
                    Stream decoded = method == 8 ? (Stream)new DeflateStream(body, CompressionMode.Decompress, true) : body;
                    try {
                        byte[] bytes = new byte[32768]; int count;
                        while ((count = decoded.Read(bytes, 0, bytes.Length)) > 0) {
                            cancel.ThrowIfCancellationRequested();
                            work.Consume(count);
                            if (written > original - count || written > remaining - count) throw new MemberError("ZIP_EXPANSION_LIMIT");
                            file.Write(bytes, 0, count); digest.TransformBlock(bytes, 0, count, null, 0); written += count;
                            for (int i = 0; i < count; i++) actualCrc = CrcTable[(actualCrc ^ bytes[i]) & 255] ^ (actualCrc >> 8);
                        }
                        cancel.ThrowIfCancellationRequested();
                    } finally { if (method == 8) decoded.Dispose(); }
                    if (written != original || (~actualCrc) != crc) throw new MemberError("ZIP_CRC_OR_SIZE_MISMATCH");
                    // Refuse unused body bytes after a completed stream. Some
                    // DeflateStream implementations prefetch, so CRC/length
                    // remain the main content verification, not this check.
                    if (body.Position != compressed) throw new MemberError("ZIP_COMPRESSED_SIZE_MISMATCH");
                    digest.TransformFinalBlock(new byte[0], 0, 0);
                    member.Sha256 = BitConverter.ToString(digest.Hash).Replace("-", "").ToLowerInvariant(); file.Flush(true);
                }
                verified = true;
                return member;
            } finally { if (!verified && File.Exists(partial)) File.Delete(partial); }
        }

        public static int Recover(string image, string runDirectory, CancellationToken cancel, Action<long, long> progress)
        {
            return Recover(image, runDirectory, cancel, progress, null);
        }

        static bool SameHeader(SalvagedArchiveMember a, SalvagedArchiveMember b)
        {
            return a.Path == b.Path && a.OriginalMemberName == b.OriginalMemberName && a.HeaderOffset == b.HeaderOffset &&
                a.DataOffset == b.DataOffset && a.CompressedBytes == b.CompressedBytes && a.Bytes == b.Bytes &&
                a.CompressionMethod == b.CompressionMethod && a.Crc32 == b.Crc32;
        }

        static string Hash(string path, CancellationToken cancel)
        {
            return RecoveryCore.HashFile(path, cancel, (done, total) => { });
        }

        static void Publish(FileStream source, string root, SalvagedArchiveMember member,
            WorkBudget repair, CancellationToken cancel)
        {
            string target = RecoveryCatalog.SafeFile(root, member.Path);
            string partial = RecoveryCatalog.SafeFile(root, member.Path + ".partial");
            if (File.Exists(target))
            {
                if (new FileInfo(target).Length != member.Bytes || Hash(target, cancel) != member.Sha256)
                    throw new IOException("ZIP_MEMBER_OUTPUT_CHANGED");
                return;
            }
            if (!File.Exists(partial) || new FileInfo(partial).Length != member.Bytes || Hash(partial, cancel) != member.Sha256)
            {
                SalvagedArchiveMember recreated;
                try { recreated = Extract(source, member.HeaderOffset, Path.GetDirectoryName(target), MaximumMemberBytes, repair, cancel); }
                catch (MemberError) { throw new IOException("ZIP_MEMBER_REPAIR_FAILED"); }
                catch (InvalidDataException) { throw new IOException("ZIP_MEMBER_REPAIR_FAILED"); }
                if (!SameHeader(member, recreated) || member.Sha256 != recreated.Sha256)
                    throw new IOException("ZIP_MEMBER_SOURCE_CHANGED");
            }
            cancel.ThrowIfCancellationRequested();
            File.Move(partial, target);
        }

        static void Validate(ScanState state, IList<SalvagedArchiveMember> records, FileStream source, CancellationToken cancel)
        {
            if (state.Position < 0 || state.Position > source.Length || state.SkipUntil < 0 || state.SkipUntil > source.Length ||
                state.Complete && state.Position != source.Length || state.Complete && state.Limited ||
                !state.Complete && !state.Limited && state.Position % BlockBytes != 0 ||
                state.Candidates < records.Count || state.Candidates > MaximumHeaders + 1 ||
                state.TotalBytes < 0 || state.TotalBytes > MaximumTotalBytes || state.DecodedWorkBytes < state.TotalBytes ||
                state.DecodedWorkBytes > MaximumTotalBytes || state.Skipped == null || state.Skipped.Count > 32 ||
                state.Skipped.Any(x => x.Key == null || x.Key.Length > 64 || !x.Key.StartsWith("ZIP_", StringComparison.Ordinal) ||
                    x.Value < 0 || x.Value > state.Candidates))
                throw new IOException("ZIP_MEMBER_CHECKPOINT_INVALID");
            long total = 0, end = 0;
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var record in records)
            {
                cancel.ThrowIfCancellationRequested();
                if (record == null || record.HeaderOffset < 0 || record.HeaderOffset >= state.Position ||
                    record.Bytes < 0 || record.Bytes > MaximumMemberBytes || record.Sha256 == null || record.Sha256.Length != 64 ||
                    record.Sha256.Any(c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) ||
                    record.Status != "member_crc_verified" || !names.Add(record.Path))
                    throw new IOException("ZIP_MEMBER_CHECKPOINT_RECORD_INVALID");
                try
                {
                    if (!SameHeader(record, Header(source, record.HeaderOffset, MaximumMemberBytes)))
                        throw new IOException("ZIP_MEMBER_SOURCE_CHANGED");
                }
                catch (MemberError) { throw new IOException("ZIP_MEMBER_SOURCE_CHANGED"); }
                total += record.Bytes;
                end = Math.Max(end, record.DataOffset + record.CompressedBytes);
            }
            if (state.TotalBytes != total || state.SkipUntil != end)
                throw new IOException("ZIP_MEMBER_CHECKPOINT_COUNT_CHANGED");
        }

        internal static int Recover(string image, string runDirectory, CancellationToken cancel,
            Action<long, long> progress, RecoveryCheckpointContext checkpoint)
        {
            cancel.ThrowIfCancellationRequested();
            image = Path.GetFullPath(image); runDirectory = Path.GetFullPath(runDirectory);
            if (image.StartsWith(@"\\", StringComparison.Ordinal) || image.IndexOf(':', 2) >= 0 || !File.Exists(image)) throw new IOException("Спасение ZIP работает только с обычным локальным файлом образа.");
            if (runDirectory.StartsWith(@"\\", StringComparison.Ordinal) || runDirectory.IndexOf(':', 2) >= 0) throw new IOException("Папка спасения должна быть локальной.");
            PlainPath(image); PlainPath(runDirectory);
            string output = Path.Combine(runDirectory, "salvage-content"), report = Path.Combine(runDirectory, "archive-salvage.json"); PlainPath(output);
            PlainPath(report);
            if (String.Equals(image, report, StringComparison.OrdinalIgnoreCase) || image.StartsWith(output + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Источник пересекается с результатами спасения ZIP.");
            if (Directory.Exists(report) || checkpoint == null && File.Exists(report))
                throw new IOException("Отчёт спасения уже существует. Для повторного поиска выбери новый результат.");
            if (File.Exists(output) || checkpoint == null && Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any())
                throw new IOException("Папка спасения содержимого уже существует. Для повторного поиска выбери новый результат.");
            var journal = new RecoveryMethodJournal<ScanState>(image, new ScanState(), checkpoint, cancel);
            var state = journal.Payload;
            var ledger = new RecoveryOutputLedger<SalvagedArchiveMember>(checkpoint, state.Output, MaximumMembers, cancel);
            var work = new WorkBudget { Remaining = MaximumTotalBytes - state.DecodedWorkBytes };
            var repair = new WorkBudget();
            string status = "incomplete";
            Action<string> skip = code => { int count; state.Skipped.TryGetValue(code, out count); state.Skipped[code] = count + 1; };
            Action save = () => RecoveryCore.SaveJson(report, new { status = status, engine = "ZIP local-member salvage", sourceImage = image,
                sourceAccess = "read_only", candidates = state.Candidates, members = ledger.Records.Count,
                bytes = ledger.Records.Sum(x => x.Bytes), decodedWorkBytes = MaximumTotalBytes - work.Remaining,
                repairWorkBytes = MaximumTotalBytes - repair.Remaining, maximumMemberBytes = MaximumMemberBytes,
                maximumTotalBytes = MaximumTotalBytes, skipped = state.Skipped, files = ledger.Records,
                note = "Only ZIP32 stored/deflate with known local sizes. Search work includes failed candidates; repair of committed files has a separate bounded budget. Data descriptors, ZIP64, encryption and arbitrary fragmented bodies unsupported. Whole archive/Office document not reconstructed." });
            using (var scan = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, BlockBytes))
            using (var parser = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            {
                Validate(state, ledger.Records, parser, cancel);
                var expected = new HashSet<string>(ledger.Records.Select(x => x.Path), StringComparer.OrdinalIgnoreCase);
                if (Directory.Exists(output))
                {
                    if (Directory.EnumerateDirectories(output).Any()) throw new IOException("ZIP_MEMBER_OUTPUT_CHANGED");
                    foreach (string file in Directory.EnumerateFiles(output))
                        if (!file.EndsWith(".partial", StringComparison.OrdinalIgnoreCase) &&
                            !expected.Contains("salvage-content/" + Path.GetFileName(file))) throw new IOException("ZIP_MEMBER_OUTPUT_CHANGED");
                }
                Directory.CreateDirectory(output);
                foreach (var member in ledger.Records) Publish(parser, runDirectory, member, repair, cancel);
                if (journal.Resumed && progress != null) progress(state.Position, scan.Length);
                if (state.Limited) throw new IOException("Спасение ZIP ранее достигло предела. Проверенные файлы сохранены; нужен отдельный поиск.");
                var pending = new List<SalvagedArchiveMember>();
                long lastHeader = state.Position;
                Action commit = () =>
                {
                    state.DecodedWorkBytes = MaximumTotalBytes - work.Remaining;
                    state.Output = ledger.Append(state.Output, pending);
                    journal.Save(state);
                    ledger.Accept(pending);
                    foreach (var member in pending) Publish(parser, runDirectory, member, repair, cancel);
                    pending.Clear();
                };
                try
                {
                    if (journal.Enabled && !journal.Resumed) journal.Save(state);
                    byte[] block = new byte[BlockBytes + 3];
                    while (!state.Complete && state.Position < scan.Length)
                    {
                        cancel.ThrowIfCancellationRequested();
                        scan.Position = state.Position;
                        int length = (int)Math.Min(block.Length, scan.Length - state.Position), done = 0;
                        while (done < length)
                        {
                            int amount = scan.Read(block, done, length - done);
                            if (amount == 0) throw new IOException("ZIP_SOURCE_TRUNCATED");
                            done += amount;
                        }
                        int limit = (int)Math.Min(BlockBytes, scan.Length - state.Position);
                        for (int i = 0; i < limit; i++)
                        {
                            if ((i & 65535) == 0) cancel.ThrowIfCancellationRequested();
                            lastHeader = state.Position + i;
                            if (lastHeader < state.SkipUntil || i > length - 4 || block[i] != 0x50 || block[i + 1] != 0x4b || block[i + 2] != 3 || block[i + 3] != 4) continue;
                            if (++state.Candidates > MaximumHeaders || ledger.Records.Count + pending.Count >= MaximumMembers ||
                                state.TotalBytes >= MaximumTotalBytes || work.Remaining <= 0)
                            { status = "limited"; throw new IOException("Спасение содержимого ZIP достигло ограничения. Проверенные файлы сохранены."); }
                            try
                            {
                                var member = Extract(parser, lastHeader, output, MaximumTotalBytes - state.TotalBytes, work, cancel);
                                state.TotalBytes += member.Bytes;
                                pending.Add(member);
                                state.SkipUntil = member.DataOffset + member.CompressedBytes;
                            }
                            catch (MemberError error)
                            {
                                skip(error.Code);
                                if (error.Code == "ZIP_WORK_LIMIT") { status = "limited"; throw new IOException("Достигнут предел распаковки ZIP. Проверенные файлы сохранены."); }
                            }
                            catch (InvalidDataException) { skip("ZIP_DEFLATE_INVALID"); }
                        }
                        state.Position += limit;
                        state.Complete = state.Position == scan.Length;
                        commit();
                        if (progress != null) progress(state.Position, scan.Length);
                        save();
                    }
                    cancel.ThrowIfCancellationRequested();
                    if (!state.Complete) { state.Complete = true; commit(); }
                    status = "complete";
                    return ledger.Records.Count;
                }
                catch (OperationCanceledException) { status = "cancelled"; throw; }
                catch (IOException)
                {
                    if (status == "limited")
                    {
                        state.Position = Math.Min(scan.Length, lastHeader + 1);
                        state.Limited = true;
                        commit();
                    }
                    throw;
                }
                finally { save(); }
            }
        }

        static uint[] MakeCrcTable()
        {
            uint[] values = new uint[256]; for (uint i = 0; i < 256; i++) { uint value = i; for (int n = 0; n < 8; n++) value = (value & 1) != 0 ? (value >> 1) ^ 0xedb88320 : value >> 1; values[i] = value; } return values;
        }
    }
}
