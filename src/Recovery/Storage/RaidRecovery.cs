using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

namespace UsbRecovery
{
    public sealed class RaidMember
    {
        public string Path;
        public long Offset;
        public bool Missing;
    }

    public sealed class RaidConfiguration
    {
        public string Level, Layout, ExpectedSha256;
        public long ChunkSize = 65536, LogicalSize;
        public List<RaidMember> Members = new List<RaidMember>();
    }

    public sealed class RaidBuildResult
    {
        public string ImagePath, Sha256, ReportPath;
        public long Bytes;
        public bool Degraded;
    }

    public sealed class RaidRecoveryException : IOException
    {
        public readonly string Code;
        public RaidRecoveryException(string code, string message) : base(message) { Code = code; }
    }

    // A raw-image assembler, not a controller driver or an automatic layout detector.
    // RAID5/6 mapping follows Linux md's documented symmetric/asymmetric layouts.
    // RAID6 Q = sum(2^i * D_i) over GF(256), polynomial x^8+x^4+x^3+x^2+1.
    // References: kernel.org/doc/html/latest/admin-guide/device-mapper/dm-raid.html
    // and kernel.org/pub/linux/kernel/people/hpa/raid6.pdf. No native RAID code is used.
    public static class RaidImageBuilder
    {
        public const int MaximumMembers = 32;
        public const long MaximumChunkSize = 4L * 1024 * 1024;
        static readonly string[] FiveLayouts = { "left-symmetric", "right-symmetric", "left-asymmetric", "right-asymmetric", "parity-first", "parity-last" };
        static readonly string[] SixLayouts = { "left-symmetric", "right-symmetric", "parity-last" };
        static readonly byte[] Exp = new byte[512], Log = new byte[256];

        sealed class OpenMember : IDisposable
        {
            public FileStream Stream;
            public RaidMember Member;
            public string Sha256;
            public long Bytes;
            public void Dispose() { if (Stream != null) Stream.Dispose(); }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FileIdentity
        {
            public uint Attributes, CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileIdentity identity);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder name, uint length, uint flags);

        static RaidImageBuilder()
        {
            int value = 1;
            for (int i = 0; i < 255; i++) { Exp[i] = (byte)value; Log[value] = (byte)i; value <<= 1; if ((value & 256) != 0) value ^= 0x11D; }
            for (int i = 255; i < Exp.Length; i++) Exp[i] = Exp[i - 255];
        }

        public static string[] SupportedLayouts(string level)
        {
            switch (Level(level)) {
                case "0": return new[] { "striped" };
                case "1": return new[] { "mirror" };
                case "5": return (string[])FiveLayouts.Clone();
                case "6": return (string[])SixLayouts.Clone();
                case "10": return new[] { "adjacent-pairs" };
                default: return new string[0];
            }
        }
        static string Level(string value) { return (value ?? "").Trim().ToUpperInvariant().Replace("RAID", "").Replace("-", "").Trim(); }
        static RaidRecoveryException Error(string code, string message) { return new RaidRecoveryException(code, message); }

        public static void Validate(RaidConfiguration configuration) { Snapshot(configuration); }
        static RaidConfiguration Snapshot(RaidConfiguration configuration)
        {
            if (configuration == null || configuration.Members == null) throw Error("RAID_CONFIG_REQUIRED", "Нужны параметры массива и образы участников.");
            var result = new RaidConfiguration { Level = Level(configuration.Level), Layout = (configuration.Layout ?? "").Trim().ToLowerInvariant(), ChunkSize = configuration.ChunkSize, LogicalSize = configuration.LogicalSize, ExpectedSha256 = configuration.ExpectedSha256 };
            if (!new[] { "0", "1", "5", "6", "10" }.Contains(result.Level)) throw Error("RAID_LEVEL_UNSUPPORTED", "Поддерживаются RAID 0, 1, 5, 6 и RAID 10 из соседних зеркальных пар.");
            if (result.Layout.Length == 0) result.Layout = result.Level == "0" ? "striped" : result.Level == "1" ? "mirror" : result.Level == "10" ? "adjacent-pairs" : "";
            if (!SupportedLayouts(result.Level).Contains(result.Layout)) throw Error("RAID_LAYOUT_UNSUPPORTED", "Выбери поддерживаемую схему RAID. Автоматическое угадывание не выполняется.");
            if (result.ChunkSize < 512 || result.ChunkSize > MaximumChunkSize || (result.ChunkSize & (result.ChunkSize - 1)) != 0) throw Error("RAID_CHUNK_INVALID", "Размер блока должен быть степенью двойки от 512 байт до 4 МиБ.");
            if (result.LogicalSize < 0) throw Error("RAID_SIZE_INVALID", "Размер логического образа не может быть отрицательным.");
            if (!String.IsNullOrEmpty(result.ExpectedSha256)) {
                result.ExpectedSha256 = result.ExpectedSha256.Trim().ToLowerInvariant();
                if (result.ExpectedSha256.Length != 64 || !result.ExpectedSha256.All(Uri.IsHexDigit)) throw Error("RAID_SHA256_INVALID", "Эталонная SHA256 должна содержать 64 шестнадцатеричных символа.");
            }
            int count = configuration.Members.Count, minimum = result.Level == "5" ? 3 : result.Level == "6" || result.Level == "10" ? 4 : 2;
            if (count < minimum || count > MaximumMembers || result.Level == "10" && count % 2 != 0) throw Error("RAID_MEMBER_COUNT_INVALID", "Число участников не соответствует выбранному уровню RAID.");
            foreach (var member in configuration.Members) {
                if (member == null || member.Offset < 0) throw Error("RAID_MEMBER_INVALID", "У каждого участника нужно корректное смещение данных.");
                if (!member.Missing && String.IsNullOrWhiteSpace(member.Path)) throw Error("RAID_MEMBER_REQUIRED", "Выбери образ участника либо явно отметь отсутствующий диск.");
                string path = member.Missing ? null : Path.GetFullPath(member.Path);
                if (path != null && (path.StartsWith(@"\\.\", StringComparison.Ordinal) || path.EndsWith(".partial", StringComparison.OrdinalIgnoreCase))) throw Error("RAID_REGULAR_IMAGE_REQUIRED", "Нужен завершённый обычный образ, а не физическое устройство или .partial.");
                if (path != null && new[] { ".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2", ".e01", ".aff4" }.Contains(Path.GetExtension(path).ToLowerInvariant())) throw Error("RAID_RAW_IMAGE_REQUIRED", "Сначала преобразуй виртуальный или упакованный диск в обычный RAW-образ.");
                result.Members.Add(new RaidMember { Path = path, Offset = member.Offset, Missing = member.Missing });
            }
            int missing = result.Members.Count(m => m.Missing);
            if (result.Level == "0" && missing != 0 || result.Level == "1" && missing == count || result.Level == "5" && missing > 1 || result.Level == "6" && missing > 2) throw Error("RAID_TOO_MANY_MISSING", "Для этого уровня отсутствует слишком много участников.");
            if (result.Level == "10") for (int i = 0; i < count; i += 2) if (result.Members[i].Missing && result.Members[i + 1].Missing) throw Error("RAID_MIRROR_PAIR_MISSING", "В одной зеркальной паре отсутствуют оба участника.");
            return result;
        }

        static void NoLinks(string path)
        {
            string current = Path.GetFullPath(path);
            while (!String.IsNullOrEmpty(current)) {
                if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw Error("RAID_LINK_REJECTED", "Путь содержит символическую ссылку или junction.");
                string next = Path.GetDirectoryName(current); if (next == current) break; current = next;
            }
        }
        static FileIdentity CheckHandle(FileStream stream, string expected)
        {
            FileIdentity identity;
            if (!GetFileInformationByHandle(stream.SafeFileHandle, out identity) || identity.Links != 1) throw Error("RAID_FILE_IDENTITY_INVALID", "Не удалось подтвердить обычный файл без жёстких ссылок.");
            var name = new StringBuilder(32768); uint length = GetFinalPathNameByHandle(stream.SafeFileHandle, name, (uint)name.Capacity, 0);
            string actual = name.ToString(); if (actual.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) actual = @"\\" + actual.Substring(8); else if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
            if (length == 0 || length >= name.Capacity || !String.Equals(Path.GetFullPath(actual), Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase)) throw Error("RAID_PATH_CHANGED", "Путь файла изменился во время открытия.");
            return identity;
        }
        static string Hash(FileStream stream, CancellationToken cancel)
        {
            stream.Position = 0;
            using (var sha = SHA256.Create()) {
                var buffer = new byte[1024 * 1024]; int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) > 0) { cancel.ThrowIfCancellationRequested(); sha.TransformBlock(buffer, 0, count, null, 0); }
                cancel.ThrowIfCancellationRequested(); sha.TransformFinalBlock(new byte[0], 0, 0); return BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
            }
        }
        static void Read(OpenMember member, long offset, byte[] buffer, int count, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested(); member.Stream.Position = checked(member.Member.Offset + offset); int done = 0;
            while (done < count) { cancel.ThrowIfCancellationRequested(); int read = member.Stream.Read(buffer, done, count - done); if (read == 0) throw Error("RAID_MEMBER_TRUNCATED", "Образ участника закончился раньше ожидаемых данных."); done += read; }
        }
        static bool Equal(byte[] first, byte[] second, int count) { for (int i = 0; i < count; i++) if (first[i] != second[i]) return false; return true; }
        static byte Multiply(byte first, byte second) { return first == 0 || second == 0 ? (byte)0 : Exp[Log[first] + Log[second]]; }
        static byte Divide(byte first, byte second) { if (second == 0) throw Error("RAID_GF_INVALID", "Некорректная система уравнений RAID6."); return first == 0 ? (byte)0 : Exp[Log[first] - Log[second] + 255]; }

        static void Mapping(RaidConfiguration configuration, long row, int count, out int parity, out int q, int[] data)
        {
            bool right = configuration.Layout.StartsWith("right-", StringComparison.Ordinal);
            parity = configuration.Layout == "parity-first" ? 0 : configuration.Layout == "parity-last" ? count - (configuration.Level == "6" ? 2 : 1) : right ? (int)(row % count) : count - 1 - (int)(row % count);
            q = configuration.Level == "6" ? (parity + 1) % count : -1;
            bool symmetric = configuration.Layout.EndsWith("-symmetric", StringComparison.Ordinal);
            for (int i = 0; i < data.Length; i++) {
                if (symmetric) data[i] = (parity + (q < 0 ? 1 : 2) + i) % count;
                else { int disk = i; if (disk >= parity) disk++; if (q >= 0 && disk >= q) disk++; data[i] = disk; }
            }
        }

        // Missing data is reconstructed only from the explicitly supplied array.
        // Equations consumed by reconstruction cannot independently validate it.
        static void Parity(OpenMember[] members, byte[][] blocks, int[] data, int p, int q, int length,byte[] px,byte[] qx,int[] missing,out int independentEquations)
        {
            int missingCount=0;for (int i = 0; i < data.Length; i++) if (members[data[i]] == null)missing[missingCount++]=i;
            bool hasP = members[p] != null, hasQ = q >= 0 && members[q] != null;
            int equations = (hasP ? 1 : 0) + (hasQ ? 1 : 0);
            if (missingCount > equations) throw Error("RAID_RECONSTRUCTION_UNAVAILABLE", "Доступных блоков чётности недостаточно для восстановления полосы.");
            Array.Clear(px,0,length);if(qx!=null)Array.Clear(qx,0,length);
            for (int d = 0; d < data.Length; d++) if (members[data[d]] != null) {
                byte coefficient = Exp[d]; var block = blocks[data[d]];
                for (int b = 0; b < length; b++) { px[b] ^= block[b]; if (q >= 0) qx[b] ^= Multiply(coefficient, block[b]); }
            }
            if (missingCount == 1) {
                int first = missing[0]; byte coefficient = Exp[first]; var restored = blocks[data[first]];
                for (int b = 0; b < length; b++) restored[b] = hasP ? (byte)(blocks[p][b] ^ px[b]) : Divide((byte)(blocks[q][b] ^ qx[b]), coefficient);
            } else if (missingCount == 2) {
                int first = missing[0], second = missing[1]; byte a = Exp[first], b = Exp[second]; var one = blocks[data[first]]; var two = blocks[data[second]];
                for (int i = 0; i < length; i++) { byte sum = (byte)(blocks[p][i] ^ px[i]), weighted = (byte)(blocks[q][i] ^ qx[i]); one[i] = Divide((byte)(weighted ^ Multiply(b, sum)), (byte)(a ^ b)); two[i] = (byte)(sum ^ one[i]); }
            }
            Array.Clear(px, 0, length); if (qx != null) Array.Clear(qx, 0, length);
            for (int d = 0; d < data.Length; d++) { byte coefficient = Exp[d]; var block = blocks[data[d]]; for (int b = 0; b < length; b++) { px[b] ^= block[b]; if (q >= 0) qx[b] ^= Multiply(coefficient, block[b]); } }
            if (hasP && !Equal(px, blocks[p], length) || hasQ && !Equal(qx, blocks[q], length)) throw Error("RAID_PARITY_MISMATCH", "Блоки чётности не совпали. Проверь образы и параметры массива.");
            independentEquations = equations - missingCount;
        }

        static void WriteJson(string path, object value)
        {
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) using (var writer = new StreamWriter(stream, new UTF8Encoding(false))) writer.Write(new JavaScriptSerializer().Serialize(value));
        }
        static string MemberIdentity(FileIdentity identity) { return identity.Volume.ToString("x8") + ":" + identity.IndexHigh.ToString("x8") + identity.IndexLow.ToString("x8"); }

        public static RaidBuildResult Build(RaidConfiguration configuration, string outputDirectory, CancellationToken cancel, Action<long, long> progress, Action<string> phase = null)
        {
            cancel.ThrowIfCancellationRequested(); var config = Snapshot(configuration);
            if (String.IsNullOrWhiteSpace(outputDirectory)) throw Error("RAID_DESTINATION_REQUIRED", "Выбери отдельную папку для собранного образа.");
            string directory = Path.GetFullPath(outputDirectory);if(directory.Length>Path.GetPathRoot(directory).Length)directory=directory.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar);
            NoLinks(directory);
            if (File.Exists(directory) || Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any()) throw Error("RAID_DESTINATION_NOT_EMPTY", "Для сборки нужна новая или пустая папка. Готовые файлы не перезаписываются.");
            foreach (var member in config.Members) if (!member.Missing && member.Path.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw Error("RAID_SOURCE_IN_DESTINATION", "Образы участников должны находиться за пределами папки сборки.");
            var opened = new OpenMember[config.Members.Count]; var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string partial = Path.Combine(directory, "raid.dd.partial"), image = Path.Combine(directory, "raid.dd"), checksum = image + ".sha256", report = Path.Combine(directory, "raid-report.json");
            bool created = false, published = false, reportMoved = false; long logical = 0, written = 0, independentBytes = 0, verifiedMirrorBytes = 0; string hash = null;
            long lastProgress=0;bool reportedData=false;
            Action reportProgress=()=>{if(progress==null)return;long now=System.Diagnostics.Stopwatch.GetTimestamp();if(written==0||written==logical||!reportedData||now-lastProgress>=System.Diagnostics.Stopwatch.Frequency/10){lastProgress=now;reportedData|=written>0;progress(written,logical);}};
            try {
                for (int i = 0; i < opened.Length; i++) {
                    var member = config.Members[i]; if (member.Missing) continue;
                    cancel.ThrowIfCancellationRequested(); NoLinks(member.Path);
                    if (!File.Exists(member.Path) || (File.GetAttributes(member.Path) & FileAttributes.Directory) != 0) throw Error("RAID_REGULAR_IMAGE_REQUIRED", "Участником должен быть обычный файл образа.");
                    var item = new OpenMember { Member = member }; opened[i] = item;
                    item.Stream = new FileStream(member.Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.RandomAccess);
                    var identity = CheckHandle(item.Stream, member.Path); if (!identities.Add(MemberIdentity(identity))) throw Error("RAID_DUPLICATE_MEMBER", "Один файл нельзя использовать как несколько участников массива.");
                    item.Bytes = item.Stream.Length;
                    if (member.Offset >= item.Bytes) throw Error("RAID_OFFSET_INVALID", "Смещение находится за пределами образа участника.");
                }
                int dataDisks = config.Level == "0" ? opened.Length : config.Level == "1" ? 1 : config.Level == "10" ? opened.Length / 2 : opened.Length - (config.Level == "6" ? 2 : 1);
                long[] sizes = opened.Where(m => m != null).Select(m => m.Bytes - m.Member.Offset).ToArray();
                if (config.LogicalSize == 0 && sizes.Any(s => s != sizes[0])) throw Error("RAID_LENGTHS_DIFFER", "Размеры участников различаются. Укажи известный логический размер; граница не угадывается.");
                long capacity = config.Level == "1" ? sizes.Min() : checked(sizes.Min() / config.ChunkSize * config.ChunkSize * dataDisks);
                logical = config.LogicalSize == 0 ? capacity : config.LogicalSize;
                if (logical <= 0 || logical > capacity) throw Error("RAID_SIZE_EXCEEDS_MEMBERS", "Указанный размер не помещается в доступных образах участников.");
                long rows = config.Level == "1" ? 0 : checked((logical - 1) / checked(config.ChunkSize * dataDisks) + 1);
                long required = config.Level == "1" ? logical : checked(rows * config.ChunkSize);
                if (sizes.Any(s => s < required)) throw Error("RAID_MEMBER_TRUNCATED", "Образ участника короче требуемого размера.");
                if (phase != null) phase("Проверка образов участников");
                foreach (var member in opened) if (member != null) member.Sha256 = Hash(member.Stream, cancel);
                cancel.ThrowIfCancellationRequested(); NoLinks(directory);
                if (!Directory.Exists(directory)) {
                    var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false); acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    new DirectoryInfo(directory).Create(acl);
                }
                NoLinks(directory); if (Directory.EnumerateFileSystemEntries(directory).Any()) throw Error("RAID_DESTINATION_NOT_EMPTY", "Папка сборки уже содержит файлы.");
                created = true;reportProgress();if (phase != null) phase("Сборка логического образа RAID");
                using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1024 * 1024, FileOptions.SequentialScan)) {
                    CheckHandle(output, partial);
                    if (config.Level == "1") {
                        int window = 1024 * 1024; var one = new byte[window]; var other = new byte[window]; var available = opened.Where(m => m != null).ToArray();
                        while (written < logical) {
                            int count = (int)Math.Min(window, logical - written); Read(available[0], written, one, count, cancel);
                            for (int i = 1; i < available.Length; i++) { Read(available[i], written, other, count, cancel); if (!Equal(one, other, count)) throw Error("RAID_MIRROR_MISMATCH", "Зеркальные копии различаются; правильная версия автоматически не выбирается."); }
                            if (available.Length > 1) verifiedMirrorBytes += count;
                            output.Write(one, 0, count); written += count;reportProgress();
                        }
                    } else {
                        int chunk = (int)config.ChunkSize; var blocks = Enumerable.Range(0, opened.Length).Select(i => new byte[chunk]).ToArray(); var data = new int[dataDisks];var px=new byte[chunk];var qx=config.Level=="6"?new byte[chunk]:null;var missing=new int[dataDisks];
                        for (long row = 0; row < rows; row++) {
                            cancel.ThrowIfCancellationRequested(); long position = checked(row * config.ChunkSize);
                            for (int disk = 0; disk < opened.Length; disk++) if (opened[disk] != null) Read(opened[disk], position, blocks[disk], chunk, cancel);
                            if (config.Level == "0") for (int i = 0; i < data.Length; i++) data[i] = i;
                            else if (config.Level == "10") {
                                for (int i = 0; i < data.Length; i++) { int first = i * 2, second = first + 1; if (opened[first] != null && opened[second] != null) { if (!Equal(blocks[first], blocks[second], chunk)) throw Error("RAID_MIRROR_MISMATCH", "Зеркальная пара различается; правильная версия автоматически не выбирается."); verifiedMirrorBytes += chunk; } data[i] = opened[first] == null ? second : first; }
                            } else {
                                int p, q, equations; Mapping(config, row, opened.Length, out p, out q, data); Parity(opened, blocks, data, p, q, chunk,px,qx,missing,out equations); independentBytes = checked(independentBytes + (long)equations * chunk);
                            }
                            foreach (int disk in data) { int count = (int)Math.Min(chunk, logical - written); if (count == 0) break; cancel.ThrowIfCancellationRequested(); output.Write(blocks[disk], 0, count); written += count;reportProgress(); }
                        }
                    }
                    if(written!=logical)throw Error("RAID_OUTPUT_LENGTH_INVALID","Не все логические байты были собраны.");
                    cancel.ThrowIfCancellationRequested(); output.Flush(true); if (phase != null) phase("Проверка собранного образа"); hash = Hash(output, cancel);
                    if (!String.IsNullOrEmpty(config.ExpectedSha256) && !String.Equals(hash, config.ExpectedSha256, StringComparison.Ordinal)) throw Error("RAID_EXPECTED_HASH_MISMATCH", "Собранный образ не совпал с эталонной SHA256. Проверь порядок, схему и смещения.");
                }
                if (phase != null) phase("Повторная проверка исходных образов");
                foreach (var member in opened) if (member != null && !String.Equals(member.Sha256, Hash(member.Stream, cancel), StringComparison.Ordinal)) throw Error("RAID_SOURCE_CHANGED", "Исходный образ участника изменился. Результат не опубликован.");
                cancel.ThrowIfCancellationRequested(); NoLinks(directory);
                string checksumWork = checksum + ".partial", reportWork = report + ".partial";
                using (var stream = new FileStream(checksumWork, FileMode.CreateNew, FileAccess.Write, FileShare.None)) using (var writer = new StreamWriter(stream, new UTF8Encoding(false))) writer.Write(hash + "  raid.dd\n");
                bool degraded = config.Members.Any(m => m.Missing);
                WriteJson(reportWork, new { schema = 1, status = "assembled_and_hashed", utc = DateTime.UtcNow.ToString("o"), level = config.Level, layout = config.Layout, chunk_bytes = config.ChunkSize, logical_bytes = logical, boundary = config.LogicalSize == 0 ? "derived_conservative_whole_stripes" : "provided_by_user", image = "raid.dd", sha256 = hash, degraded = degraded, source_access = "read_only_share_read", source_hashes_verified_after = true, expected_sha256_verified = !String.IsNullOrEmpty(config.ExpectedSha256), layout_confirmed = false, logical_reference_confirmed = !String.IsNullOrEmpty(config.ExpectedSha256), independent_parity_equation_bytes = independentBytes, verified_mirror_bytes = verifiedMirrorBytes, parameters_origin = "provided_by_user", raw_member_images = true, filesystem_validated = false, limitations = new[] { "No automatic order/layout/offset detection; correct parity alone does not establish the original layout.", "No metadata interpretation, reshape, Storage Spaces, LVM, vendor RAID or controller-specific layouts.", "Degraded reconstruction can have no independent redundancy left; a SHA256 records output, not original-data authenticity.", "Derived length covers common full stripes only; an explicitly supplied logical size is preferred." }, members = config.Members.Select((m, i) => new { index = i, path = m.Path, offset_bytes = m.Offset, missing = m.Missing, bytes = opened[i] == null ? 0 : opened[i].Bytes, sha256 = opened[i] == null ? null : opened[i].Sha256 }).ToArray() });
                cancel.ThrowIfCancellationRequested(); File.Move(checksumWork, checksum); File.Move(reportWork, report);reportMoved=true;File.Move(partial, image); published = true;
                if (phase != null) phase("Образ RAID собран и проверен");
                return new RaidBuildResult { ImagePath = image, ReportPath = report, Sha256 = hash, Bytes = logical, Degraded = degraded };
            } catch (OperationCanceledException) {
                if (created && !published) SaveFailure(directory, "cancelled", "CANCELLED", written,reportMoved); throw;
            } catch (RaidRecoveryException error) {
                if (created && !published) SaveFailure(directory, "error", error.Code, written,reportMoved); throw;
            } catch (OverflowException) {
                if (created && !published) SaveFailure(directory, "error", "RAID_SIZE_OVERFLOW", written,reportMoved); throw Error("RAID_SIZE_OVERFLOW", "Размеры или смещения массива выходят за поддерживаемые границы.");
            } catch (UnauthorizedAccessException) {
                if (created && !published) SaveFailure(directory, "error", "RAID_ACCESS_DENIED", written,reportMoved); throw Error("RAID_ACCESS_DENIED", "Нет доступа к образу участника или папке результата.");
            } catch (IOException) {
                if (created && !published) SaveFailure(directory, "error", "RAID_IO_ERROR", written,reportMoved); throw Error("RAID_IO_ERROR", "Не удалось прочитать образ или сохранить результат. Незавершённый файл оставлен как .partial.");
            } finally { foreach (var member in opened) if (member != null) member.Dispose(); }
        }
        static void SaveFailure(string directory, string state, string code, long written,bool reportMoved)
        {
            try { NoLinks(directory); string report = Path.Combine(directory, "raid-report.json"); if (reportMoved&&File.Exists(report)) File.Delete(report); WriteJson(Path.Combine(directory, "raid-failure.json"), new { schema = 1, status = state, code = code, written_bytes = written, published = false, partial = "raid.dd.partial", note = "Incomplete output must not be treated as a complete logical image." }); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}
