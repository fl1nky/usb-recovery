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
                if (read == 0) throw new MemberError("ZIP_MEMBER_TRUNCATED");
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
            if (done != size) throw new MemberError("ZIP_HEADER_TRUNCATED");
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

        static SalvagedArchiveMember Extract(FileStream source, long offset, string output, long remaining, WorkBudget work, CancellationToken cancel)
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
            string relative = "salvage-content/member-" + offset.ToString("D16") + "_" + SafeLeaf(name), target = Path.Combine(output, Path.GetFileName(relative)), partial = target + ".partial";
            uint actualCrc = 0xffffffff; long written = 0;
            string sha;
            try {
                using (var file = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                using (var digest = SHA256.Create())
                using (var body = new SliceStream(source, dataOffset, compressed)) {
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
                    digest.TransformFinalBlock(new byte[0], 0, 0); sha = BitConverter.ToString(digest.Hash).Replace("-", "").ToLowerInvariant(); file.Flush(true);
                }
                File.Move(partial, target);
                return new SalvagedArchiveMember { Path = relative, OriginalMemberName = name, Sha256 = sha, HeaderOffset = offset, DataOffset = dataOffset, CompressedBytes = compressed, Bytes = written, CompressionMethod = method, Crc32 = crc.ToString("x8"), Note = "Independent ZIP member CRC and size verified. Archive/document completeness and deletion state unknown. Active file extensions neutralized; nothing executed." };
            } finally { if (File.Exists(partial)) File.Delete(partial); }
        }

        public static int Recover(string image, string runDirectory, CancellationToken cancel, Action<long, long> progress)
        {
            cancel.ThrowIfCancellationRequested();
            image = Path.GetFullPath(image); runDirectory = Path.GetFullPath(runDirectory);
            if (image.StartsWith(@"\\", StringComparison.Ordinal) || image.IndexOf(':', 2) >= 0 || !File.Exists(image)) throw new IOException("Спасение ZIP работает только с обычным локальным файлом образа.");
            if (runDirectory.StartsWith(@"\\", StringComparison.Ordinal) || runDirectory.IndexOf(':', 2) >= 0) throw new IOException("Папка спасения должна быть локальной.");
            PlainPath(image); PlainPath(runDirectory);
            string output = Path.Combine(runDirectory, "salvage-content"), report = Path.Combine(runDirectory, "archive-salvage.json"); PlainPath(output);
            PlainPath(report);
            if (File.Exists(report) || Directory.Exists(report)) throw new IOException("Отчёт спасения уже существует. Для повторного поиска выбери новый результат.");
            if (File.Exists(output) || Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any()) throw new IOException("Папка спасения содержимого уже существует. Для повторного поиска выбери новый результат.");
            Directory.CreateDirectory(output); var files = new List<SalvagedArchiveMember>(); var skipped = new Dictionary<string, int>();
            var work = new WorkBudget();
            string status = "incomplete"; long totalBytes = 0, position = 0, skipUntil = 0; int carry = 0, candidates = 0;
            Action<string> skip = code => { int count; skipped.TryGetValue(code, out count); skipped[code] = count + 1; };
            Action save = () => File.WriteAllText(report, new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024 }.Serialize(new { status = status, engine = "ZIP local-member salvage", sourceImage = image, sourceAccess = "read_only", candidates = candidates, members = files.Count, bytes = totalBytes, decodedWorkBytes = MaximumTotalBytes - work.Remaining, maximumMemberBytes = MaximumMemberBytes, maximumTotalBytes = MaximumTotalBytes, skipped = skipped, files = files, note = "Only ZIP32 stored/deflate with known local sizes. The shared work budget includes failed candidates. Data descriptors, ZIP64, encryption and arbitrary fragmented bodies unsupported. Whole archive/Office document not reconstructed." }), new UTF8Encoding(false));
            try {
                using (var scan = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, BlockBytes))
                using (var parser = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 65536)) {
                    byte[] block = new byte[BlockBytes + 3]; int read;
                    while ((read = scan.Read(block, carry, block.Length - carry)) > 0) {
                        cancel.ThrowIfCancellationRequested(); int length = carry + read, limit = scan.Position == scan.Length ? length : Math.Max(0, length - 3); long start = position - carry;
                        for (int i = 0; i < limit; i++) {
                            if ((i & 65535) == 0) cancel.ThrowIfCancellationRequested();
                            if (start + i < skipUntil || i > length - 4 || block[i] != 0x50 || block[i + 1] != 0x4b || block[i + 2] != 3 || block[i + 3] != 4) continue;
                            if (++candidates > MaximumHeaders || files.Count >= MaximumMembers || totalBytes >= MaximumTotalBytes || work.Remaining <= 0) { status = "limited"; save(); throw new IOException("Спасение содержимого ZIP достигло ограничения. Проверенные файлы сохранены."); }
                            try {
                                var member = Extract(parser, start + i, output, MaximumTotalBytes - totalBytes, work, cancel);
                                totalBytes += member.Bytes; files.Add(member); skipUntil = member.DataOffset + member.CompressedBytes;
                            } catch (MemberError error) { skip(error.Code); if (error.Code == "ZIP_WORK_LIMIT") { status = "limited"; throw new IOException("Достигнут предел распаковки ZIP. Проверенные файлы сохранены."); } }
                            catch (InvalidDataException) { skip("ZIP_DEFLATE_INVALID"); }
                        }
                        position += read; carry = length - limit; Buffer.BlockCopy(block, limit, block, 0, carry); if (progress != null) progress(scan.Position, scan.Length); save();
                    }
                }
                cancel.ThrowIfCancellationRequested(); status = "complete"; return files.Count;
            } catch (OperationCanceledException) { status = "cancelled"; throw; }
            finally { save(); }
        }

        static uint[] MakeCrcTable()
        {
            uint[] values = new uint[256]; for (uint i = 0; i < 256; i++) { uint value = i; for (int n = 0; n < 8; n++) value = (value & 1) != 0 ? (value >> 1) ^ 0xedb88320 : value >> 1; values[i] = value; } return values;
        }
    }
}
