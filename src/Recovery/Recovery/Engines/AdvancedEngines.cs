using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // Only ordinary disk-image files are accepted. Every child runs with a read-only
    // sharing guard held over the image; none of these commands repairs a filesystem.
    public static class AdvancedEngines
    {
        public static string DeepPhotoRecCommand { get { return BuildCommand(true); } }
        public static string BuildCommand(bool deep)
        {
            return deep ? "partition_none,options,paranoid_bf,keep_corrupted_file,blocksize,512,fileopt,everything,enable,wholespace,search"
                        : "partition_none,fileopt,everything,enable,wholespace,search";
        }

        internal sealed class NtfsPartition
        {
            public int Number, SectorSize;
            public long Offset, Length;
            public string Table;
        }

        static string Quote(string path)
        {
            if (path.IndexOf('"') >= 0 || path.EndsWith("\\", StringComparison.Ordinal)) throw new IOException("Недопустимый путь.");
            return "\"" + path + "\"";
        }

        static string ValidateImage(string image)
        {
            if (String.IsNullOrWhiteSpace(image) || image.StartsWith(@"\\", StringComparison.Ordinal) || image.StartsWith("/dev/", StringComparison.Ordinal))
                throw new IOException("Нужна обычная копия флешки, а не устройство.");
            string full = Path.GetFullPath(image);
            var info = new FileInfo(full);
            if (!info.Exists || info.Length < 512 || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Нужна обычная непустая копия флешки.");
            return full;
        }

        static byte[] ReadAt(FileStream input, long offset, int count)
        {
            if (offset < 0 || count < 0 || offset > input.Length - count) return null;
            byte[] data = new byte[count]; input.Position = offset;
            int read = 0;
            while (read < count) { int n = input.Read(data, read, count - read); if (n == 0) return null; read += n; }
            return data;
        }

        static bool IsNtfs(FileStream input, long offset, long length)
        {
            byte[] boot = ReadAt(input, offset, 512);
            if (boot == null || length < 512 || Encoding.ASCII.GetString(boot, 3, 8) != "NTFS    " || boot[510] != 0x55 || boot[511] != 0xaa) return false;
            int sector = BitConverter.ToUInt16(boot, 11), cluster = boot[13];
            if ((sector != 512 && sector != 1024 && sector != 2048 && sector != 4096) || cluster == 0 || (cluster & (cluster - 1)) != 0) return false;
            ulong sectors = BitConverter.ToUInt64(boot, 40);
            if (sectors == 0 || sectors > (ulong)(length / sector) || BitConverter.ToUInt64(boot, 48) >= sectors / (uint)cluster) return false;
            return true;
        }

        static void AddNtfs(FileStream input, List<NtfsPartition> result, string table, int number, int sector, ulong start, ulong sectors)
        {
            if (start > (ulong)(input.Length / sector) || sectors == 0 || sectors > (ulong)(input.Length / sector) - start) return;
            long offset = (long)start * sector, length = (long)sectors * sector;
            if (IsNtfs(input, offset, length) && !result.Any(p => p.Offset == offset))
                result.Add(new NtfsPartition { Number = number, SectorSize = sector, Offset = offset, Length = length, Table = table });
        }

        internal static List<NtfsPartition> FindNtfs(string image, CancellationToken cancel)
        {
            image = ValidateImage(image);
            var result = new List<NtfsPartition>();
            using (var input = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                cancel.ThrowIfCancellationRequested();
                byte[] first = ReadAt(input, 0, 512);
                if (IsNtfs(input, 0, input.Length))
                {
                    result.Add(new NtfsPartition { Number = 0, SectorSize = BitConverter.ToUInt16(first, 11), Offset = 0, Length = input.Length, Table = "partition_none" });
                    return result;
                }
                if (first == null || first[510] != 0x55 || first[511] != 0xaa) return result;
                foreach (int sector in new[] { 512, 4096 })
                {
                    cancel.ThrowIfCancellationRequested();
                    byte[] gpt = ReadAt(input, sector, sector);
                    if (gpt != null && Encoding.ASCII.GetString(gpt, 0, 8) == "EFI PART")
                    {
                        uint headerLength = BitConverter.ToUInt32(gpt, 12), entries = BitConverter.ToUInt32(gpt, 80), entrySize = BitConverter.ToUInt32(gpt, 84);
                        ulong entriesLba = BitConverter.ToUInt64(gpt, 72);
                        if (headerLength < 92 || headerLength > sector || entries > 4096 || entrySize < 128 || entrySize > 4096 || entriesLba > (ulong)(input.Length / sector)) continue;
                        long entriesOffset = (long)entriesLba * sector;
                        if ((ulong)entries * entrySize > (ulong)(input.Length - entriesOffset)) continue;
                        for (int i = 0; i < entries; i++)
                        {
                            cancel.ThrowIfCancellationRequested();
                            byte[] entry = ReadAt(input, entriesOffset + (long)i * entrySize, (int)entrySize);
                            if (entry.Take(16).All(b => b == 0)) continue;
                            ulong start = BitConverter.ToUInt64(entry, 32), last = BitConverter.ToUInt64(entry, 40);
                            if (last >= start && last != UInt64.MaxValue) AddNtfs(input, result, "partition_gpt", i + 1, sector, start, last - start + 1);
                        }
                        if (result.Count != 0) return result;
                        continue;
                    }
                    for (int i = 0; i < 4; i++)
                    {
                        cancel.ThrowIfCancellationRequested();
                        int entry = 446 + i * 16, type = first[entry + 4];
                        ulong start = BitConverter.ToUInt32(first, entry + 8), count = BitConverter.ToUInt32(first, entry + 12);
                        if (type == 0x07 || type == 0x17) AddNtfs(input, result, "partition_i386", i + 1, sector, start, count);
                        if (type != 0x05 && type != 0x0f && type != 0x85) continue;
                        ulong extendedBase = start, ebrLba = start; var seen = new HashSet<ulong>(); int logical = 5;
                        while (seen.Add(ebrLba) && logical < 133 && ebrLba < (ulong)(input.Length / sector))
                        {
                            cancel.ThrowIfCancellationRequested();
                            byte[] ebr = ReadAt(input, (long)ebrLba * sector, 512);
                            if (ebr == null || ebr[510] != 0x55 || ebr[511] != 0xaa) break;
                            ulong relative = BitConverter.ToUInt32(ebr, 454), logicalCount = BitConverter.ToUInt32(ebr, 458);
                            if ((ebr[450] == 0x07 || ebr[450] == 0x17) && relative <= UInt64.MaxValue - ebrLba)
                                AddNtfs(input, result, "partition_i386", logical, sector, ebrLba + relative, logicalCount);
                            ulong next = BitConverter.ToUInt32(ebr, 470);
                            if (next == 0 || (ebr[466] != 0x05 && ebr[466] != 0x0f && ebr[466] != 0x85) || next > UInt64.MaxValue - extendedBase) break;
                            ebrLba = extendedBase + next; logical++;
                        }
                    }
                    if (result.Count != 0) return result;
                }
            }
            return result;
        }

        static void RunTestDisk(string image, NtfsPartition partition, string output, string log, CancellationToken cancel)
        {
            string tool = ApplicationPaths.Tool("testdisk-7.2/testdisk_win.exe");
            if (!File.Exists(tool)) throw new IOException("Не найден TestDisk. Скопируй всю папку tools.");
            string command = partition.Table + ",geometry,N," + partition.SectorSize.ToString(CultureInfo.InvariantCulture) + ",advanced,";
            if (partition.Number != 0) command += partition.Number.ToString(CultureInfo.InvariantCulture) + ",";
            command += "undelete,allundelete";
            // /logname precedes /log: TestDisk opens the selected log when it sees /log.
            var start = new ProcessStartInfo(tool, "/logname " + Quote(log) + " /log /cmd " + Quote(image) + " " + command);
            start.UseShellExecute = false; start.CreateNoWindow = true; start.WorkingDirectory = output;
            start.EnvironmentVariables["CYGWIN"] = "noglob";
            start.EnvironmentVariables["LANG"] = "C.UTF-8";
            start.EnvironmentVariables["LC_ALL"] = "C.UTF-8";
            using (var guard = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var process = Process.Start(start))
            {
                try
                {
                    while (!process.WaitForExit(250)) cancel.ThrowIfCancellationRequested();
                    cancel.ThrowIfCancellationRequested();
                    if (process.ExitCode != 0) throw new IOException("TestDisk завершился с кодом " + process.ExitCode.ToString(CultureInfo.InvariantCulture) + ".");
                }
                catch { if (!process.HasExited) { process.Kill(); process.WaitForExit(); } throw; }
            }
        }

        public static IEnumerable<string> NtfsRecoveredFiles(string runDirectory)
        {
            string root = Path.Combine(runDirectory, "ntfs");
            if (!Directory.Exists(root)) return Enumerable.Empty<string>();
            return Directory.EnumerateDirectories(root, "partition-*").SelectMany(p => Directory.Exists(Path.Combine(p, "data"))
                ? Directory.EnumerateFiles(Path.Combine(p, "data"), "*", SearchOption.AllDirectories) : Enumerable.Empty<string>());
        }

        public static int RecoverNtfs(string image, string runDirectory, CancellationToken cancel, Action<string> progress)
        { return RecoverNtfs(image, runDirectory, cancel, progress, null); }
        public static int RecoverNtfs(string image, string runDirectory, CancellationToken cancel, Action<string> progress, IList<BootCandidate> discovered)
        {
            cancel.ThrowIfCancellationRequested(); image = ValidateImage(image);
            string root = Path.Combine(Path.GetFullPath(runDirectory), "ntfs");
            Directory.CreateDirectory(root);
            var reports = new List<Dictionary<string, object>>();
            List<NtfsPartition> partitions = FindNtfs(image, cancel);
            if (discovered != null) foreach (var candidate in discovered.Where(x => x.Kind == "NTFS"))
                if (!partitions.Any(x => x.Offset == candidate.Offset)) partitions.Add(new NtfsPartition { Number = 1000 + partitions.Count, SectorSize = candidate.SectorSize, Offset = candidate.Offset, Length = candidate.Length, Table = "discovered_view" });
            foreach (var partition in partitions)
            {
                cancel.ThrowIfCancellationRequested();
                string partitionRoot = Path.Combine(root, "partition-" + partition.Number.ToString(CultureInfo.InvariantCulture)), data = Path.Combine(partitionRoot, "data"), log = Path.Combine(partitionRoot, "testdisk.log");
                if (Directory.Exists(partitionRoot)) throw new IOException("Папка NTFS уже существует. Для повторного поиска создай новый результат.");
                Directory.CreateDirectory(data);
                var report = new Dictionary<string, object> { { "partition", partition.Number }, { "offset", partition.Offset }, { "length", partition.Length }, { "table", partition.Table }, { "status", "started" } };
                reports.Add(report);
                try
                {
                    if (progress != null) progress("Поиск удалённых файлов в таблице NTFS…");
                    if (partition.Table == "discovered_view") {
                        string view = Path.Combine(partitionRoot, "working-partition.dd");
                        try {
                            using (var source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
                            using (var target = new FileStream(view, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                                source.Position = partition.Offset; long remaining = partition.Length; byte[] block = new byte[RecoveryCore.ChunkSize];
                                while (remaining > 0) { cancel.ThrowIfCancellationRequested(); int read = source.Read(block,0,(int)Math.Min(remaining,block.Length)); if (read == 0) throw new IOException("Неполный раздел в копии."); target.Write(block,0,read); remaining -= read; }
                            }
                            BootCandidate boot = discovered.First(x => x.Kind == "NTFS" && x.Offset == partition.Offset);
                            if (boot.BootOffset != boot.Offset) {
                                using (var source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
                                using (var target = new FileStream(view, FileMode.Open, FileAccess.Write, FileShare.None)) {
                                    byte[] sector = new byte[boot.SectorSize]; source.Position = boot.BootOffset; if (source.Read(sector,0,sector.Length) != sector.Length) throw new IOException("Неполный резервный сектор."); target.Write(sector,0,sector.Length);
                                }
                                report["working_copy_boot"] = "from_backup; original_unchanged";
                            }
                            RunTestDisk(view, new NtfsPartition { Number=0, SectorSize=partition.SectorSize, Table="partition_none" }, data, log, cancel);
                        } finally { if (File.Exists(view)) File.Delete(view); }
                    } else RunTestDisk(image, partition, data, log, cancel);
                    string contents = File.Exists(log) ? File.ReadAllText(log, Encoding.UTF8) : "";
                    Match summary = Regex.Match(contents, @"NTFS undelete done \((\d+)/(\d+)\)");
                    if (!summary.Success || !contents.Contains("TestDisk exited normally.") || contents.Contains("Syntax error in command line:"))
                        throw new IOException(contents.Contains("Support for this filesystem wasn't enabled") ? "В этой сборке TestDisk недоступен поиск NTFS." : "Таблица NTFS повреждена или полное завершение не подтверждено. Продолжится поиск по содержимому.");
                    report["status"] = "complete"; report["mft_records_recovered"] = summary.Groups[1].Value; report["mft_records_attempted"] = summary.Groups[2].Value;
                }
                catch (OperationCanceledException) { report["status"] = "cancelled"; WriteReport(root, reports, partitions.Count); throw; }
                catch (Exception ex)
                {
                    if (!(ex is IOException) && !(ex is System.ComponentModel.Win32Exception) && !(ex is UnauthorizedAccessException)) throw;
                    report["status"] = "unavailable"; report["message"] = ex.Message;
                    if (progress != null) progress("Таблица NTFS недоступна; поиск по содержимому продолжится.");
                }
                report["files"] = Directory.EnumerateFiles(data, "*", SearchOption.AllDirectories).Count();
                WriteReport(root, reports, partitions.Count);
            }
            WriteReport(root, reports, partitions.Count);
            if (reports.Any(p => (string)p["status"] == "unavailable"))
                throw new IOException("Поиск по таблице NTFS завершён не для всех разделов. Уже найденные файлы сохранены; сведения есть в ntfs/report.json. Продолжится поиск по содержимому.");
            return NtfsRecoveredFiles(runDirectory).Count();
        }

        static void WriteReport(string root, List<Dictionary<string, object>> reports, int detected)
        {
            var report = new Dictionary<string, object> { { "engine", "TestDisk NTFS undelete" }, { "detected_partitions", detected }, { "partitions", reports }, { "note", "Recovered candidates may contain overwritten or incomplete data. Source image is opened read-only." } };
            File.WriteAllText(Path.Combine(root, "report.json"), new JavaScriptSerializer().Serialize(report), new UTF8Encoding(false));
        }
    }
}
