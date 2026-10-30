using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // Read-only NTFS 3.1 record salvage. A valid old record is evidence, not proof
    // that its nonresident clusters still contain the original file.
    public static class MetadataRescue
    {
        public const int MaximumCandidates = 20000;
        public const long MaximumFileBytes = 2L * 1024 * 1024 * 1024;
        public const long MaximumOutputBytes = 32L * 1024 * 1024 * 1024;
        const int Stride = 512, MaximumRecordBytes = 65536, MaximumRuns = 4096;
        const int MaximumTotalRuns = 250000, MaximumDirectoryRecords = 100000, MaximumPathDepth = 128, MaximumPathCharacters = 32768;
        const int MaximumPathReportCharacters = 8 * 1024 * 1024, MaximumDirectoryEvidenceLinks = 100000;
        static readonly Encoding Unicode = new UnicodeEncoding(false, false, true);

        public sealed class Extent
        {
            public long ImageOffset, LogicalOffset, Length;
        }
        public sealed class Entry
        {
            public long RecordOffset, RecordNumber, ParentRecordNumber, DeclaredSize, InitializedBytes, RecoveredBytes;
            public int Sequence, ParentSequence;
            public bool UsaFixupsRestored;
            public long? VolumeOffset;
            public string Name, Output, Sha256, Status, Reason;
            public string OriginalPath, PathStatus = "unknown", PathEvidence;
            public bool DirectoryChainComplete = true;
            public long? PathVolumeOffset;
            public List<DirectoryLink> DirectoryChain = new List<DirectoryLink>();
            public string DeletionEvidence = "FILE_record_not_in_use";
            public string Note = "Сохранившаяся запись NTFS; исходная папка и сохранность содержимого не подтверждены";
            public List<Extent> Extents = new List<Extent>();
        }
        public sealed class DirectoryLink
        {
            public long RecordNumber, RecordOffset;
            public int Sequence;
            public bool InUse;
            public string Name;
        }
        public sealed class Report
        {
            public int Schema = 2, ScanAlignment = Stride, ValidatedRecords, DeletedCandidates, RecoveredFiles, InvalidSignatures;
            public int ResolvedPaths, UnresolvedPaths, DirectoryRecordsChecked;
            public int DirectoryEvidenceLinks, PathReportCharacters;
            public long InputBytes, ScannedBytes, OutputBytes;
            public bool Cancelled, CandidateLimitReached, OutputLimitReached, Failed, PathResolutionLimited;
            public string Method = "orphan_ntfs_records";
            public List<string> Warnings = new List<string>();
            public List<Entry> Entries = new List<Entry>();
        }
        sealed class Run { public long Lcn, Clusters, Vcn; }
        sealed class Data
        {
            public bool Resident;
            public int ValueOffset, ValueLength;
            public long FileSize, ValidLength, Allocated;
            public List<Run> Runs = new List<Run>();
            public string Unsupported;
        }
        sealed class Record
        {
            public long Offset, Number, Parent;
            public int Sequence, ParentSequence, Size, Flags;
            public string Name;
            public Data Data;
            public bool AttributeList, ProtectedFileFlags, AmbiguousName;
        }
        sealed class PathNode
        {
            public long Number, Offset, Parent;
            public int Sequence, ParentSequence, Flags;
            public string Name;
            public bool AmbiguousName, AttributeList;
        }
        sealed class Volume
        {
            public long Offset, Length, MftLcn, Clusters;
            public int ClusterBytes, RecordBytes;
            public Data Bitmap, Mft;
            public byte[] BitmapRecord;
            public string BitmapProblem;
            public long CachePage = -1;
            public byte[] Cache = new byte[65536];
            public int CacheLength;
            public readonly Dictionary<long, PathNode> PathNodes = new Dictionary<long, PathNode>();
            public readonly HashSet<long> InvalidPathNodes = new HashSet<long>();
        }

        public static int Recover(string image, string runDirectory, CancellationToken cancel,
            Action<string> progress, IList<BootCandidate> discovered = null)
        {
            string full = LocalImage(image), root = Path.GetFullPath(Path.Combine(runDirectory, "metadata-rescue"));
            SafeAncestors(Path.GetDirectoryName(root));
            if (Directory.Exists(root) || File.Exists(root)) throw new IOException("Папка поиска записей NTFS уже существует");
            cancel.ThrowIfCancellationRequested();
            var report = new Report();
            report.Warnings.Add("Просматриваются записи FILE на границах 512 байт. Проверка USA обнаруживает повреждённую запись, но не является контрольной суммой содержимого файла.");
            report.Warnings.Add("Поддерживаются заголовки NTFS 3.1 с отдельным номером записи; старые заголовки с USA до смещения 48 пропускаются.");
            report.Warnings.Add("Сжатие, шифрование, разреженные потоки, ATTRIBUTE_LIST и потоки из нескольких записей не восстанавливаются. Путь строится только по однозначной текущей карте MFT и совпавшим sequence родительских ссылок; прежние перемещения не угадываются.");
            report.Warnings.Add("OriginalPath — виртуальный путь из снимка метаданных, он не используется как путь записи. RecordOffset в DirectoryChain обозначает начало записи; для фрагментированной MFT запись читается по всей карте потоков.");
            Directory.CreateDirectory(root);
            string files = Path.Combine(root, "files"); Directory.CreateDirectory(files);
            try {
                using (var input = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 4 * 1024 * 1024)) {
                    report.InputBytes = input.Length;
                    bool allocationUntrusted = UntrustedReadMap(full, runDirectory, input.Length);
                    if (allocationUntrusted) report.Warnings.Add("В образе известны пропуски чтения либо карта ошибок неполна/повреждена. Занятость кластеров NTFS не считается подтверждённой: nonresident-потоки пропущены; resident-кандидаты также могут содержать пропуски.");
                    var volumes = new List<Volume>();
                    if (discovered != null) foreach (BootCandidate known in discovered) {
                        if (known.Kind != "NTFS") continue;
                        byte[] boot = Read(input, known.BootOffset, 512);
                        if (boot != null) AddVolume(volumes, DecodeBoot(boot, known.Offset, input.Length));
                    }
                    var candidates = new List<Record>(); byte[] block = new byte[4 * 1024 * 1024];
                    int totalRuns = 0;
                    for (long position = 0; position < input.Length; position += block.Length) {
                        cancel.ThrowIfCancellationRequested();
                        input.Position = position;
                        int count = ReadInto(input, block, 0, (int)Math.Min(block.Length, input.Length - position));
                        for (int at = 0; at + 48 <= count; at += Stride) {
                            if ((at & 65535) == 0) cancel.ThrowIfCancellationRequested();
                            long offset = position + at;
                            if (at + 512 <= count && block[at + 3] == 'N' && block[at + 4] == 'T' && block[at + 5] == 'F' && block[at + 6] == 'S') {
                                byte[] boot = new byte[512]; Buffer.BlockCopy(block, at, boot, 0, 512);
                                AddVolume(volumes, DecodeBoot(boot, offset, input.Length));
                                long length = BootLength(boot);
                                if (length >= 512 && offset >= length - 512)
                                    AddVolume(volumes, DecodeBoot(boot, offset - length + 512, input.Length));
                            }
                            if (block[at] != 'F' || block[at + 1] != 'I' || block[at + 2] != 'L' || block[at + 3] != 'E') continue;
                            Record record = ParseAt(input, offset);
                            if (record == null) { report.InvalidSignatures++; continue; }
                            report.ValidatedRecords++;
                            if (record.Flags != 0 || record.Name == null || record.Data == null || record.Number < 16) continue;
                            report.DeletedCandidates++;
                            int runs = record.Data.Runs.Count;
                            if (candidates.Count >= MaximumCandidates || runs > MaximumTotalRuns - totalRuns) {
                                report.CandidateLimitReached = true; continue;
                            }
                            candidates.Add(record); totalRuns += runs;
                        }
                        report.ScannedBytes = position + count;
                        if (progress != null) progress("Записи NTFS: просмотрено " + (report.ScannedBytes / (1024 * 1024)) + " МБ, кандидатов " + candidates.Count);
                    }
                    foreach (Volume volume in volumes) {
                        cancel.ThrowIfCancellationRequested();
                        if (allocationUntrusted) volume.BitmapProblem = "source_read_errors_allocation_untrusted";
                        else PrepareBitmap(input, volume, cancel);
                    }
                    if (report.CandidateLimitReached) report.Warnings.Add("Достигнут предел кандидатов или экстентов; остальные подписи проверены без добавления результатов.");
                    foreach (Record record in candidates) {
                        cancel.ThrowIfCancellationRequested();
                        Entry item = new Entry { RecordOffset = record.Offset, RecordNumber = record.Number, Sequence = record.Sequence,
                            Name = record.Name, ParentRecordNumber = record.Parent & 0x0000ffffffffffffL, ParentSequence = record.ParentSequence,
                            DeclaredSize = record.Data.FileSize, InitializedBytes = record.Data.ValidLength, Status = "not_extracted", UsaFixupsRestored = record.Data.Resident };
                        if (allocationUntrusted) item.Note += "; у образа есть пропуски чтения или недостоверная карта ошибок: сохранность байтов записи не подтверждена";
                        ResolvePath(input, volumes, record, item, report, allocationUntrusted, cancel);
                        report.Entries.Add(item);
                        if (record.AttributeList) { item.Reason = "attribute_list_unsupported"; continue; }
                        if (record.Data.Unsupported != null) { item.Reason = record.Data.Unsupported; continue; }
                        if (record.Data.FileSize == 0) { item.Reason = "empty_stream"; continue; }
                        if (record.Data.FileSize > MaximumFileBytes) { item.Reason = "file_size_limit"; continue; }
                        byte[] fixedRecord = null;
                        long available = record.Data.FileSize;
                        if (record.Data.Resident) {
                            fixedRecord = FixedRecord(input, record.Offset);
                            if (fixedRecord == null) { item.Reason = "record_changed_or_damaged"; continue; }
                            item.Note += "; Extents задают позиции содержимого до восстановления USA: заменённые слова в конце секторов берутся из массива USA, поэтому это не точная побайтовая карта источника";
                            item.Extents.Add(new Extent { ImageOffset = record.Offset + record.Data.ValueOffset, LogicalOffset = 0, Length = available });
                        } else {
                            if (allocationUntrusted) { item.Reason = "source_read_errors_allocation_untrusted"; continue; }
                            List<Volume> matches = volumes.Where(v => record.Offset >= v.Offset && record.Offset < v.Offset + v.Length && v.Bitmap != null).ToList();
                            if (matches.Count != 1) { item.Reason = matches.Count > 1 ? "ambiguous_volume" : "current_bitmap_unavailable"; continue; }
                            Volume volume = matches[0]; item.VolumeOffset = volume.Offset;
                            if (!CheckRuns(record.Data, volume)) { item.Reason = "invalid_cluster_bounds"; continue; }
                            available = Math.Min(record.Data.FileSize, record.Data.ValidLength);
                            long prefix = FreePrefix(input, volume, record.Data, available, cancel);
                            if (prefix < available) { available = prefix; item.Reason = "allocated_cluster_stop"; }
                            if (available == 0) { if (item.Reason == null) item.Reason = "no_initialized_bytes"; continue; }
                            if (available < record.Data.FileSize && item.Reason == null) item.Reason = "uninitialized_tail_not_invented";
                            AddExtents(item.Extents, record.Data, volume, available);
                        }
                        if (available > MaximumOutputBytes - report.OutputBytes) {
                            item.Reason = "output_budget"; report.OutputLimitReached = true; continue;
                        }
                        bool partial = available < record.Data.FileSize;
                        string relative = "files/" + (partial ? "PARTIAL_" : "") + "record-" + record.Offset.ToString("x") + "-" + SafeName(record.Name);
                        string target = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
                        string pending = target + ".partial";
                        try {
                            using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                                if (fixedRecord != null) {
                                    cancel.ThrowIfCancellationRequested();
                                    output.Write(fixedRecord, record.Data.ValueOffset, checked((int)available));
                                } else CopyExtents(input, output, item.Extents, cancel);
                                output.Flush(true);
                            }
                            cancel.ThrowIfCancellationRequested();
                            File.Move(pending, target);
                        } finally { if (File.Exists(pending)) File.Delete(pending); }
                        item.Output = relative; item.RecoveredBytes = available;
                        using (var payload = File.OpenRead(target)) using (var sha = SHA256.Create())
                            item.Sha256 = BitConverter.ToString(sha.ComputeHash(payload)).Replace("-", "").ToLowerInvariant();
                        item.Status = partial ? "partial_candidate" : fixedRecord != null ? "resident_candidate" : "unallocated_candidate";
                        if (item.Reason == null) item.Reason = fixedRecord != null ? "validated_record_resident_data" : "all_copied_clusters_currently_free";
                        report.RecoveredFiles++; report.OutputBytes += available;
                    }
                    foreach (Volume volume in volumes.Where(v => v.Bitmap == null))
                        report.Warnings.Add("Том " + volume.Offset + ": nonresident-потоки пропущены (" + volume.BitmapProblem + ")");
                }
                return report.RecoveredFiles;
            } catch (OperationCanceledException) { report.Cancelled = true; throw; }
            catch { report.Failed = true; throw; }
            finally {
                string json = new JavaScriptSerializer { MaxJsonLength = 128 * 1024 * 1024, RecursionLimit = 32 }.Serialize(report);
                File.WriteAllText(Path.Combine(root, "report.json"), json, new UTF8Encoding(false));
            }
        }

        static string LocalImage(string image)
        {
            if (String.IsNullOrWhiteSpace(image) || image.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Требуется обычный локальный файл образа");
            string full = Path.GetFullPath(image);
            if (full.IndexOf(':', 2) >= 0 || !File.Exists(full)) throw new IOException("Требуется обычный локальный файл образа");
            FileAttributes attributes = File.GetAttributes(full);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) throw new IOException("Источник-ссылка недопустим");
            SafeAncestors(Path.GetDirectoryName(full)); return full;
        }
        static bool UntrustedReadMap(string image, string runDirectory, long imageLength)
        {
            foreach (string path in new[] { Path.Combine(runDirectory, "source-read-errors.json"), image + ".read-errors.json" }) {
                if (!File.Exists(path) && !Directory.Exists(path)) continue;
                try {
                    FileAttributes attributes = File.GetAttributes(path);
                    if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 || new FileInfo(path).Length > 2 * 1024 * 1024) return true;
                    var map = new JavaScriptSerializer { MaxJsonLength = 2 * 1024 * 1024, RecursionLimit = 16 }.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
                    object value; long unread;
                    if (map == null || !map.TryGetValue("unreadBytes", out value) || !MapInteger(value, out unread) || unread != 0) return true;
                    // A positive range in a supposedly zero-error map, absent
                    // ranges, a mismatched image size or an incomplete capture
                    // cannot certify that the allocation metadata was read.
                    object ranges;
                    if (!map.TryGetValue("ranges", out ranges) || !(ranges is System.Collections.IList) || ((System.Collections.IList)ranges).Count != 0) return true;
                    long size;
                    if (!map.TryGetValue("size", out value) || !MapInteger(value, out size) || size != imageLength) return true;
                    if (!map.TryGetValue("status", out value) || !String.Equals(value as string, "complete", StringComparison.Ordinal)) return true;
                } catch (IOException) { return true; }
                catch (UnauthorizedAccessException) { return true; }
                catch (ArgumentException) { return true; }
                catch (InvalidOperationException) { return true; }
            }
            return false;
        }
        static bool MapInteger(object value, out long number)
        {
            if (value is int) { number = (int)value; return true; }
            if (value is long) { number = (long)value; return true; }
            number = 0; return false;
        }
        static void SafeAncestors(string path)
        {
            for (var directory = new DirectoryInfo(path); directory != null; directory = directory.Parent)
                if (directory.Exists && (directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Путь через ссылку недопустим");
        }
        static string SafeName(string name)
        {
            var result = new StringBuilder();
            foreach (char value in name) result.Append(value < 32 || "<>:\"/\\|?*".IndexOf(value) >= 0 ? '_' : value);
            string safe = result.ToString().Trim(' ', '.');
            if (safe.Length > 160) {
                string extension = Path.GetExtension(safe); if (extension.Length > 20) extension = "";
                safe = safe.Substring(0, 140) + extension;
            }
            return safe.Length == 0 ? "unknown.bin" : safe;
        }
        static ushort U16(byte[] b, int p) { return BitConverter.ToUInt16(b, p); }
        static uint U32(byte[] b, int p) { return BitConverter.ToUInt32(b, p); }
        static long I64(byte[] b, int p) { return BitConverter.ToInt64(b, p); }
        static bool Power(int value) { return value > 0 && (value & (value - 1)) == 0; }
        static int ReadInto(Stream stream, byte[] bytes, int offset, int count)
        {
            int total = 0, got; while (total < count && (got = stream.Read(bytes, offset + total, count - total)) != 0) total += got; return total;
        }
        static byte[] Read(FileStream input, long offset, int count)
        {
            if (offset < 0 || count < 0 || offset > input.Length - count) return null;
            byte[] data = new byte[count]; input.Position = offset;
            return ReadInto(input, data, 0, count) == count ? data : null;
        }
        static byte[] FixedRecord(FileStream input, long offset)
        {
            byte[] header = Read(input, offset, 48);
            if (header == null || header[0] != 'F' || header[1] != 'I' || header[2] != 'L' || header[3] != 'E') return null;
            uint size = U32(header, 28), used = U32(header, 24); int first = U16(header, 20), usa = U16(header, 4), count = U16(header, 6);
            if (size < Stride || size > MaximumRecordBytes || !Power((int)size) || used < 52 || used > size || first < 48 || (first & 7) != 0 || first > used - 4 ||
                usa < 48 || (usa & 1) != 0 || count != size / Stride + 1 || usa + count * 2 > Math.Min(first, Stride - 2) || U16(header, 16) == 0) return null;
            byte[] record = Read(input, offset, (int)size); if (record == null) return null;
            ushort number = U16(record, usa); if (number == 0) return null;
            for (int sector = 1; sector < count; sector++) {
                int tail = sector * Stride - 2;
                if (U16(record, tail) != number) return null;
                record[tail] = record[usa + sector * 2]; record[tail + 1] = record[usa + sector * 2 + 1];
            }
            return record;
        }
        static Record ParseAt(FileStream input, long offset)
        {
            byte[] bytes = FixedRecord(input, offset); return bytes == null ? null : ParseRecord(bytes, offset);
        }
        static Record ParseRecord(byte[] b, long offset)
        {
            int used = (int)U32(b, 24), at = U16(b, 20), flags = U16(b, 22), attributes = 0, nameRank = -1;
            if ((flags & ~15) != 0 || I64(b, 32) != 0) return null;
            var record = new Record { Offset = offset, Size = b.Length, Flags = flags, Sequence = U16(b, 16), Number = U32(b, 44) };
            bool ended = false; uint previousType = 0;
            while (at <= used - 4 && ++attributes <= 256) {
                uint type = U32(b, at); if (type == UInt32.MaxValue) { ended = true; break; }
                if (type < 0x10 || type > 0x100 || (type & 15) != 0 || type < previousType || at > used - 24) return null;
                previousType = type; uint rawLength = U32(b, at + 4);
                if (rawLength < 24 || rawLength > used - at || (rawLength & 7) != 0) return null;
                int length = (int)rawLength, form = b[at + 8], nameLength = b[at + 9], nameOffset = U16(b, at + 10);
                if (form > 1 || (nameLength != 0 && (nameOffset < (form == 0 ? 24 : 64) || nameOffset + nameLength * 2 > length))) return null;
                int valueOffset = 0, valueLength = 0;
                if (form == 0) {
                    uint rawValueLength = U32(b, at + 16); valueOffset = U16(b, at + 20);
                    if (valueOffset < 24 || rawValueLength > length - valueOffset || (nameLength != 0 && valueOffset < nameOffset + nameLength * 2)) return null;
                    valueLength = (int)rawValueLength;
                } else if (length < 64) return null;
                if (type == 0x20) record.AttributeList = true;
                if (type == 0x10 && form == 0 && valueLength >= 36 && (U32(b, at + valueOffset + 32) & 0x4a00) != 0) record.ProtectedFileFlags = true;
                if (type == 0x30 && form == 0 && valueLength >= 66 && nameLength == 0) {
                    int start = at + valueOffset, characters = b[start + 64], nameSpace = b[start + 65];
                    if ((U32(b, start + 56) & 0x4a00) != 0) record.ProtectedFileFlags = true;
                    if (characters == 0 || nameSpace > 3 || characters * 2 > valueLength - 66) return null;
                    string name;
                    try { name = Unicode.GetString(b, start + 66, characters * 2); } catch (DecoderFallbackException) { return null; }
                    if (name.IndexOf('\0') >= 0 || name == ".." || name == "." && (record.Number != 5 || (flags & 2) == 0)) return null;
                    int rank = nameSpace == 1 || nameSpace == 3 ? 2 : nameSpace == 0 ? 1 : 0;
                    long parent = I64(b, start);
                    if (rank > nameRank) { nameRank = rank; record.Name = name; record.Parent = parent; record.ParentSequence = (int)((ulong)record.Parent >> 48); record.AmbiguousName = false; }
                    else if (rank == nameRank && (record.Name != name || record.Parent != parent)) record.AmbiguousName = true;
                }
                if (type == 0x80 && nameLength == 0) {
                    if (record.Data != null) return null;
                    Data data = new Data { Resident = form == 0 };
                    if ((U16(b, at + 12) & 0xc0ff) != 0) data.Unsupported = "compressed_encrypted_or_sparse";
                    if (form == 0) {
                        data.ValueOffset = at + valueOffset; data.ValueLength = valueLength; data.FileSize = data.ValidLength = valueLength;
                    } else {
                        data.FileSize = I64(b, at + 48); data.ValidLength = I64(b, at + 56); data.Allocated = I64(b, at + 40);
                        if (data.FileSize < 0 || data.ValidLength < 0 || data.ValidLength > data.FileSize || data.Allocated < 0) return null;
                        if (I64(b, at + 16) != 0) data.Unsupported = "extension_stream_unsupported";
                        if (U16(b, at + 34) != 0) data.Unsupported = "compressed_encrypted_or_sparse";
                        if (data.Unsupported == null && !MappingPairs(b, at, length, data)) return null;
                    }
                    record.Data = data;
                }
                at += length;
            }
            if (record.ProtectedFileFlags && record.Data != null) record.Data.Unsupported = "compressed_encrypted_or_sparse";
            return ended ? record : null;
        }
        static bool MappingPairs(byte[] b, int at, int length, Data data)
        {
            int position = U16(b, at + 32), end = at + length;
            if (position < 64 || position >= length) return false;
            position += at; long vcn = 0, lcn = 0; bool ended = false;
            while (position < end && data.Runs.Count < MaximumRuns) {
                int header = b[position++]; if (header == 0) { ended = true; break; }
                int cb = header & 15, ob = header >> 4;
                if (cb < 1 || cb > 8 || ob < 1 || ob > 8 || position + cb + ob > end) return false;
                ulong count = 0, rawDelta = 0;
                for (int i = 0; i < cb; i++) count |= (ulong)b[position++] << (i * 8);
                for (int i = 0; i < ob; i++) rawDelta |= (ulong)b[position++] << (i * 8);
                if (ob < 8 && (rawDelta & (1UL << (ob * 8 - 1))) != 0) rawDelta |= UInt64.MaxValue << (ob * 8);
                long delta = unchecked((long)rawDelta);
                if (count == 0 || count > Int64.MaxValue || vcn > Int64.MaxValue - (long)count || (delta > 0 && lcn > Int64.MaxValue - delta) || (delta < 0 && lcn < Int64.MinValue - delta)) return false;
                lcn += delta; if (lcn <= 0) return false;
                data.Runs.Add(new Run { Vcn = vcn, Lcn = lcn, Clusters = (long)count }); vcn += (long)count;
            }
            return ended && vcn > 0 && I64(b, at + 24) == vcn - 1;
        }
        static long BootLength(byte[] b)
        {
            if (b.Length < 512 || b[510] != 0x55 || b[511] != 0xaa || Encoding.ASCII.GetString(b, 3, 8) != "NTFS    ") return 0;
            int sector = U16(b, 11); long last = I64(b, 40);
            if (!Power(sector) || sector < 512 || sector > 4096 || last < 15 || last >= Int64.MaxValue / sector) return 0;
            return (last + 1) * sector;
        }
        static Volume DecodeBoot(byte[] boot, long offset, long imageLength)
        {
            long length = BootLength(boot); int sector = U16(boot, 11), clusters = boot[13];
            if (length == 0 || offset < 0 || offset > imageLength - length || !Power(clusters) || clusters > 128) return null;
            int clusterBytes = sector * clusters; long mft = I64(boot, 48), count = length / clusterBytes;
            int encoded = unchecked((sbyte)boot[64]);
            int record = encoded > 0 && encoded <= 128 ? encoded * clusterBytes : encoded >= -16 && encoded <= -9 ? 1 << -encoded : 0;
            if (!Power(record) || record < 512 || record > MaximumRecordBytes || mft <= 0 || mft >= count || mft > (length - record) / clusterBytes) return null;
            return new Volume { Offset = offset, Length = length, ClusterBytes = clusterBytes, Clusters = count, MftLcn = mft, RecordBytes = record };
        }
        static void AddVolume(List<Volume> volumes, Volume volume)
        {
            if (volume == null || volumes.Count >= 128 || volumes.Any(v => v.Offset == volume.Offset && v.Length == volume.Length && v.ClusterBytes == volume.ClusterBytes && v.MftLcn == volume.MftLcn && v.RecordBytes == volume.RecordBytes)) return;
            volumes.Add(volume);
        }
        static bool CheckRuns(Data data, Volume volume)
        {
            if (data.Resident) return true;
            if (data.Runs.Count == 0 || data.Allocated % volume.ClusterBytes != 0) return false;
            long clusters = 0;
            foreach (Run run in data.Runs) {
                if (run.Lcn <= 0 || run.Clusters <= 0 || run.Lcn >= volume.Clusters || run.Clusters > volume.Clusters - run.Lcn || clusters > Int64.MaxValue - run.Clusters) return false;
                clusters += run.Clusters;
            }
            if (clusters > Int64.MaxValue / volume.ClusterBytes || clusters * volume.ClusterBytes != data.Allocated || data.FileSize > data.Allocated) return false;
            // Self-overlapping runs are never used to invent duplicated bytes.
            List<Run> sorted = data.Runs.OrderBy(r => r.Lcn).ToList();
            for (int i = 1; i < sorted.Count; i++) if (sorted[i].Lcn < sorted[i - 1].Lcn + sorted[i - 1].Clusters) return false;
            return true;
        }
        static void PrepareBitmap(FileStream input, Volume volume, CancellationToken cancel)
        {
            volume.BitmapProblem = "active_mft_or_bitmap_unavailable";
            Record mft = ParseAt(input, volume.Offset + volume.MftLcn * volume.ClusterBytes);
            if (mft == null || mft.Number != 0 || mft.Flags != 1 || mft.Name != "$MFT" || mft.AmbiguousName || mft.Size != volume.RecordBytes || mft.AttributeList || mft.Data == null || mft.Data.Resident || mft.Data.Unsupported != null || !CheckRuns(mft.Data, volume) || mft.Data.Runs[0].Lcn != volume.MftLcn) return;
            volume.Mft = mft.Data;
            byte[] record = LogicalRead(input, mft.Data, volume, 6L * volume.RecordBytes, volume.RecordBytes, cancel);
            if (record == null || !FixLogicalRecord(record)) return;
            Record bitmap = ParseRecord(record, -1);
            if (bitmap == null || bitmap.Number != 6 || (bitmap.Flags & 1) == 0 || (bitmap.Flags & 2) != 0 || bitmap.Name != "$Bitmap" || bitmap.AttributeList || bitmap.Data == null || bitmap.Data.Unsupported != null || !CheckRuns(bitmap.Data, volume)) return;
            long bytes = (volume.Clusters + 7) / 8;
            if (bitmap.Data.ValidLength < bytes || bitmap.Data.FileSize < bytes) return;
            volume.Bitmap = bitmap.Data; volume.BitmapRecord = record; volume.BitmapProblem = null;
            // A zeroed/damaged bitmap is not evidence that every cluster is free.
            // Its own stream and the active $MFT must agree with allocation bits.
            if (!AllocatedMetadata(input, volume, mft.Data, cancel) || !AllocatedMetadata(input, volume, bitmap.Data, cancel)) {
                volume.Bitmap = null; volume.BitmapRecord = null; volume.Mft = null; volume.CachePage = -1;
                volume.BitmapProblem = "allocation_metadata_inconsistent";
            }
        }
        static bool PathComponent(string name)
        {
            return !String.IsNullOrEmpty(name) && name != "." && name != ".." && name.IndexOf('/') < 0 && name.IndexOf('\\') < 0 && !name.Any(c => c < 32);
        }
        // An orphan's stored record number is not enough to attach it to a
        // directory tree. Its on-image position must also match the currently
        // validated $MFT stream mapping for that record number.
        static long MftRecordOffset(Volume volume, long number, bool contiguous)
        {
            Data mft = volume.Mft;
            if (mft == null || number < 0 || mft.ValidLength < volume.RecordBytes || number > (mft.ValidLength - volume.RecordBytes) / volume.RecordBytes) return -1;
            long logical = number * volume.RecordBytes, copied = 0, first = -1;
            foreach (Run run in mft.Runs) {
                long start = run.Vcn * volume.ClusterBytes, length = run.Clusters * volume.ClusterBytes;
                if (logical >= start + length) continue;
                if (logical < start) return -1;
                long take = Math.Min(volume.RecordBytes - copied, start + length - logical);
                long physical = volume.Offset + run.Lcn * volume.ClusterBytes + logical - start;
                if (first < 0) first = physical;
                else if (contiguous && physical != first + copied) return -1;
                logical += take; copied += take;
                if (copied == volume.RecordBytes) return first;
            }
            return -1;
        }
        static PathNode MftPathNode(FileStream input, Volume volume, long number, Report report, CancellationToken cancel, out string problem)
        {
            problem = null; PathNode cached;
            if (volume.PathNodes.TryGetValue(number, out cached)) return cached;
            if (volume.InvalidPathNodes.Contains(number)) { problem = "invalid_parent_record"; return null; }
            long at = MftRecordOffset(volume, number, false);
            if (at < 0) { problem = "parent_outside_current_mft"; return null; }
            if (report.DirectoryRecordsChecked >= MaximumDirectoryRecords) { problem = "directory_record_budget"; report.PathResolutionLimited = true; return null; }
            report.DirectoryRecordsChecked++; cancel.ThrowIfCancellationRequested();
            byte[] bytes = LogicalRead(input, volume.Mft, volume, number * volume.RecordBytes, volume.RecordBytes, cancel);
            Record record = bytes == null || !FixLogicalRecord(bytes) ? null : ParseRecord(bytes, at);
            if (record == null || record.Number != number || record.Size != volume.RecordBytes) { volume.InvalidPathNodes.Add(number); problem = "invalid_parent_record"; return null; }
            cached = new PathNode { Number = number, Offset = at, Name = record.Name, Parent = record.Parent & 0x0000ffffffffffffL,
                Sequence = record.Sequence, ParentSequence = record.ParentSequence, Flags = record.Flags, AmbiguousName = record.AmbiguousName, AttributeList = record.AttributeList };
            volume.PathNodes.Add(number, cached); return cached;
        }
        static void UnknownPath(Entry item, Report report, string status)
        {
            item.PathStatus = status; item.OriginalPath = null; item.DirectoryChainComplete = false; report.UnresolvedPaths++;
            item.PathEvidence = "Полный путь не подтверждён (" + status + "). Имя и ссылки записи сохранены; папка не угадывается.";
        }
        static void ResolvePath(FileStream input, IList<Volume> volumes, Record record, Entry item, Report report, bool untrusted, CancellationToken cancel)
        {
            if (untrusted) { UnknownPath(item, report, "source_read_errors"); return; }
            if (record.AttributeList) { UnknownPath(item, report, "attribute_list_unsupported"); return; }
            if (record.AmbiguousName) { UnknownPath(item, report, "ambiguous_file_names"); return; }
            if (!PathComponent(record.Name)) { UnknownPath(item, report, "invalid_file_component"); return; }
            List<Volume> matches = volumes.Where(v => v.RecordBytes == record.Size && MftRecordOffset(v, record.Number, true) == record.Offset).ToList();
            if (matches.Count != 1) { UnknownPath(item, report, matches.Count > 1 ? "ambiguous_volume" : volumes.Any(v => v.Mft != null) ? "record_outside_current_mft" : "current_mft_unavailable"); return; }
            Volume volume = matches[0]; item.PathVolumeOffset = volume.Offset;
            var parts = new List<string> { record.Name }; var seen = new HashSet<long> { record.Number };
            long parent = record.Parent & 0x0000ffffffffffffL; int expectedSequence = record.ParentSequence, characters = record.Name.Length + 1;
            for (int depth = 0; depth < MaximumPathDepth; depth++) {
                cancel.ThrowIfCancellationRequested();
                if (expectedSequence == 0) { UnknownPath(item, report, "missing_parent_sequence"); return; }
                if (!seen.Add(parent)) { UnknownPath(item, report, "directory_cycle"); return; }
                string problem; PathNode node = MftPathNode(input, volume, parent, report, cancel, out problem);
                if (node == null) { UnknownPath(item, report, problem); return; }
                if (node.Sequence != expectedSequence) { UnknownPath(item, report, "stale_parent_reference"); return; }
                if ((node.Flags & 2) == 0 || (node.Flags & ~3) != 0) { UnknownPath(item, report, "parent_not_directory"); return; }
                if (node.AttributeList) { UnknownPath(item, report, "parent_attribute_list_unsupported"); return; }
                if (node.AmbiguousName) { UnknownPath(item, report, "ambiguous_parent_names"); return; }
                if (report.DirectoryEvidenceLinks < MaximumDirectoryEvidenceLinks) {
                    item.DirectoryChain.Add(new DirectoryLink { RecordNumber = node.Number, RecordOffset = node.Offset, Sequence = node.Sequence, Name = node.Name, InUse = (node.Flags & 1) != 0 }); report.DirectoryEvidenceLinks++;
                } else { item.DirectoryChainComplete = false; report.PathResolutionLimited = true; }
                if (parent == 5) {
                    if (node.Flags != 3 || node.Name != "." || node.Parent != 5 || node.ParentSequence != node.Sequence) { UnknownPath(item, report, "invalid_root_directory"); return; }
                    parts.Reverse(); string path = "/" + String.Join("/", parts);
                    if (path.Length > MaximumPathReportCharacters - report.PathReportCharacters) { report.PathResolutionLimited = true; UnknownPath(item, report, "path_report_budget"); return; }
                    item.OriginalPath = path; item.PathStatus = "verified_parent_chain"; report.ResolvedPaths++; report.PathReportCharacters += path.Length;
                    item.PathEvidence = "Цепочка FILE_NAME проверена по текущей карте MFT, флагам каталогов и совпавшим sequence. Это путь доступного снимка метаданных; прежние перемещения и содержимое файла им не подтверждаются.";
                    if (!item.DirectoryChainComplete) item.PathEvidence += " Подробная цепочка в отчёте сокращена общим лимитом; полный путь вычислен до сокращения.";
                    return;
                }
                if (!PathComponent(node.Name)) { UnknownPath(item, report, "invalid_parent_component"); return; }
                characters += node.Name.Length + 1;
                if (characters > MaximumPathCharacters) { report.PathResolutionLimited = true; UnknownPath(item, report, "path_length_limit"); return; }
                parts.Add(node.Name); parent = node.Parent; expectedSequence = node.ParentSequence;
            }
            report.PathResolutionLimited = true; UnknownPath(item, report, "path_depth_limit");
        }
        static bool AllocatedMetadata(FileStream input, Volume volume, Data stream, CancellationToken cancel)
        {
            if (stream.Resident) return true;
            foreach (Run run in stream.Runs) for (long cluster = 0; cluster < run.Clusters; cluster++) {
                if ((cluster & 4095) == 0) cancel.ThrowIfCancellationRequested();
                long lcn = run.Lcn + cluster;
                if ((BitmapByte(input, volume, lcn / 8, cancel) & (1 << (int)(lcn & 7))) == 0) return false;
            }
            return true;
        }
        static bool FixLogicalRecord(byte[] record)
        {
            // The $MFT run map may cross extents; validate its reconstructed record
            // with the same USA rules before trusting record 6's allocation bitmap.
            if (record.Length < 48 || record[0] != 'F' || record[1] != 'I' || record[2] != 'L' || record[3] != 'E' || U32(record, 28) != record.Length) return false;
            int usa = U16(record, 4), count = U16(record, 6), first = U16(record, 20), used = (int)U32(record, 24);
            if (usa < 48 || (usa & 1) != 0 || count != record.Length / Stride + 1 || usa + count * 2 > Math.Min(first, Stride - 2) || first < 48 || (first & 7) != 0 || used < 52 || first > used - 4 || used > record.Length || U16(record, 16) == 0) return false;
            ushort number = U16(record, usa); if (number == 0) return false;
            for (int sector = 1; sector < count; sector++) {
                int tail = sector * Stride - 2; if (U16(record, tail) != number) return false;
                record[tail] = record[usa + sector * 2]; record[tail + 1] = record[usa + sector * 2 + 1];
            }
            return true;
        }
        static byte[] LogicalRead(FileStream input, Data data, Volume volume, long offset, int count, CancellationToken cancel)
        {
            if (offset < 0 || count < 0 || offset > data.ValidLength - count || data.Resident) return null;
            byte[] result = new byte[count]; int copied = 0;
            foreach (Run run in data.Runs) {
                cancel.ThrowIfCancellationRequested(); long start = run.Vcn * volume.ClusterBytes, length = run.Clusters * volume.ClusterBytes;
                if (offset >= start + length) continue;
                if (offset < start) return null;
                int take = (int)Math.Min(count - copied, start + length - offset);
                byte[] bytes = Read(input, volume.Offset + run.Lcn * volume.ClusterBytes + offset - start, take);
                if (bytes == null) return null;
                Buffer.BlockCopy(bytes, 0, result, copied, take); offset += take; copied += take;
                if (copied == count) return result;
            }
            return null;
        }
        static int BitmapByte(FileStream input, Volume volume, long offset, CancellationToken cancel)
        {
            Data bitmap = volume.Bitmap;
            if (bitmap.Resident) return volume.BitmapRecord[bitmap.ValueOffset + checked((int)offset)];
            long page = offset / volume.Cache.Length * volume.Cache.Length;
            if (volume.CachePage != page) {
                int length = (int)Math.Min(volume.Cache.Length, bitmap.ValidLength - page);
                byte[] bytes = LogicalRead(input, bitmap, volume, page, length, cancel);
                if (bytes == null) throw new IOException("Не удалось прочитать проверенную карту занятости NTFS");
                Buffer.BlockCopy(bytes, 0, volume.Cache, 0, length); volume.CachePage = page; volume.CacheLength = length;
            }
            int at = (int)(offset - page);
            if (at >= volume.CacheLength) throw new IOException("Неполная карта занятости NTFS");
            return volume.Cache[at];
        }
        static long FreePrefix(FileStream input, Volume volume, Data data, long bytes, CancellationToken cancel)
        {
            long copied = 0;
            foreach (Run run in data.Runs) {
                for (long cluster = 0; cluster < run.Clusters && copied < bytes; cluster++) {
                    if ((cluster & 4095) == 0) cancel.ThrowIfCancellationRequested();
                    long lcn = run.Lcn + cluster;
                    if ((BitmapByte(input, volume, lcn / 8, cancel) & (1 << (int)(lcn & 7))) != 0) return copied;
                    copied += Math.Min(volume.ClusterBytes, bytes - copied);
                }
                if (copied >= bytes) break;
            }
            return copied;
        }
        static void AddExtents(List<Extent> extents, Data data, Volume volume, long bytes)
        {
            long copied = 0;
            foreach (Run run in data.Runs) {
                long length = Math.Min(bytes - copied, run.Clusters * volume.ClusterBytes); if (length <= 0) break;
                extents.Add(new Extent { ImageOffset = volume.Offset + run.Lcn * volume.ClusterBytes, LogicalOffset = copied, Length = length }); copied += length;
            }
        }
        static void CopyExtents(FileStream input, FileStream output, IList<Extent> extents, CancellationToken cancel)
        {
            byte[] buffer = new byte[1024 * 1024];
            foreach (Extent extent in extents) {
                input.Position = extent.ImageOffset; long left = extent.Length;
                while (left > 0) {
                    cancel.ThrowIfCancellationRequested(); int take = (int)Math.Min(buffer.Length, left);
                    if (ReadInto(input, buffer, 0, take) != take) throw new IOException("Образ обрезан во время чтения");
                    output.Write(buffer, 0, take); left -= take;
                }
            }
        }
    }
}
