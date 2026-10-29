using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class SourceInfo
    {
        public string Id, Name, Kind, Status;
        public override string ToString() { return Name + " | " + Kind + " | " + Status; }
    }

    public sealed class SourceEntry
    {
        public string Id, RelativePath, OriginalPath, Modified;
        public long Size = -1;
        public bool IsDirectory;
    }

    public interface IRecoverySource
    {
        SourceInfo Info { get; }
        IEnumerable<SourceEntry> Enumerate(string root, CancellationToken cancel);
        Stream OpenRead(SourceEntry entry, CancellationToken cancel);
    }

    public interface ILocalRecoverySource : IRecoverySource
    {
        string RootDirectory { get; }
        string SelectedPath(string root);
    }

    public interface IRecoverySourceWarnings
    {
        IList<string> Warnings { get; }
    }

    public static class SourceLimits
    {
        public const int MaximumEntries = 200000;
        public const int MaximumDirectories = 50000;
        public const int MaximumDepth = 64;
        public const long MaximumFileBytes = 128L * 1024 * 1024 * 1024;
    }

    internal static class SourcePaths
    {
        internal static string Full(string path)
        {
            string full = Path.GetFullPath(path), root = Path.GetPathRoot(full);
            return full.Length == root.Length ? full : full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        internal static bool Within(string path, string root)
        {
            return String.Equals(path, root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        internal static void NoLinks(string path)
        {
            string current = Path.GetFullPath(path);
            while (!String.IsNullOrEmpty(current))
            {
                if (File.Exists(current) || Directory.Exists(current))
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Путь содержит ссылку или junction: " + current);
                string parent = Path.GetDirectoryName(current);
                if (String.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
                current = parent;
            }
        }
        internal static string Relative(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || path.Length > 16384 || path.IndexOf('\0') >= 0 || Path.IsPathRooted(path)) throw new IOException("Источник вернул небезопасный путь файла.");
            string normalized = path.Replace('\\', '/');
            foreach (string component in normalized.Split('/'))
                if (component.Length == 0 || component == "." || component == ".." || component.IndexOf(':') >= 0) throw new IOException("Источник вернул небезопасный путь файла.");
            return normalized;
        }
        internal static string SafeName(string relative)
        {
            string name = relative.Replace('\\', '/').Split('/').Last();
            var invalid = new HashSet<char>(Path.GetInvalidFileNameChars());
            var safe = new StringBuilder();
            foreach (char character in name) safe.Append(invalid.Contains(character) || Char.IsControl(character) ? '_' : character);
            string value = safe.ToString().TrimEnd(' ', '.');
            if (value.Length == 0) value = "file";
            string extension = Path.GetExtension(value);
            if (extension.Length > 24) extension = "";
            if (value.Length > 80) value = value.Substring(0, 80 - extension.Length) + extension;
            string baseName = Path.GetFileNameWithoutExtension(value).ToUpperInvariant();
            if (baseName == "CON" || baseName == "PRN" || baseName == "AUX" || baseName == "NUL" ||
                (baseName.Length == 4 && (baseName.StartsWith("COM") || baseName.StartsWith("LPT")) && baseName[3] >= '1' && baseName[3] <= '9')) value = "_" + value;
            return value;
        }
        internal static string HashText(string text)
        {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "").ToLowerInvariant();
        }
    }

    public sealed class LocalFolderSource : ILocalRecoverySource, IRecoverySourceWarnings
    {
        readonly string directory;
        readonly SourceInfo info;
        readonly List<string> warnings = new List<string>();
        public SourceInfo Info { get { return info; } }
        public IList<string> Warnings { get { return warnings.AsReadOnly(); } }
        public string RootDirectory { get { return directory; } }
        public LocalFolderSource(string directory)
        {
            if (String.IsNullOrWhiteSpace(directory)) throw new ArgumentException("Не задана папка источника.", "directory");
            this.directory = SourcePaths.Full(directory);
            if (!Directory.Exists(this.directory)) throw new DirectoryNotFoundException(this.directory);
            SourcePaths.NoLinks(this.directory);
            info = new SourceInfo { Id = this.directory, Name = Path.GetFileName(this.directory), Kind = "folder", Status = "ready" };
        }
        public string SelectedPath(string root)
        {
            string selected = String.IsNullOrWhiteSpace(root) ? directory : SourcePaths.Full(Path.IsPathRooted(root) ? root : Path.Combine(directory, root));
            if (!SourcePaths.Within(selected, directory)) throw new IOException("Выбранный путь находится вне папки источника.");
            SourcePaths.NoLinks(selected);
            if (!Directory.Exists(selected) && !File.Exists(selected)) throw new FileNotFoundException("Выбранный источник не найден.", selected);
            return selected;
        }
        SourceEntry Entry(string path, string selected, bool isDirectory)
        {
            var file = isDirectory ? null : new FileInfo(path);
            string relativeRoot = File.Exists(selected) ? Path.GetDirectoryName(selected) : selected;
            return new SourceEntry { Id = path, OriginalPath = path, RelativePath = path.Substring(relativeRoot.TrimEnd('\\', '/').Length + 1).Replace('\\', '/'), Modified = isDirectory ? Directory.GetLastWriteTimeUtc(path).ToString("o") : file.LastWriteTimeUtc.ToString("o"), Size = isDirectory ? -1 : file.Length, IsDirectory = isDirectory };
        }
        public IEnumerable<SourceEntry> Enumerate(string root, CancellationToken cancel)
        {
            warnings.Clear();
            string selected = SelectedPath(root);
            if (File.Exists(selected))
            {
                cancel.ThrowIfCancellationRequested();
                yield return Entry(selected, selected, false);
                // A SQLite database is incomplete without a surviving transaction log.
                foreach (string suffix in new[] { "-wal", "-shm" })
                {
                    string sibling = selected + suffix;
                    if (File.Exists(sibling)) { SourcePaths.NoLinks(sibling); cancel.ThrowIfCancellationRequested(); yield return Entry(sibling, selected, false); }
                }
                yield break;
            }
            var pending = new Stack<KeyValuePair<string, int>>();
            pending.Push(new KeyValuePair<string, int>(selected, 0));
            int entries = 0, directories = 0;
            while (pending.Count > 0)
            {
                cancel.ThrowIfCancellationRequested();
                var current = pending.Pop();
                SourcePaths.NoLinks(current.Key);
                if (++directories > SourceLimits.MaximumDirectories || current.Value > SourceLimits.MaximumDepth) throw new IOException("Слишком много вложенных папок. Выберите меньшую папку.");
                string[] files, children;
                try { files = Directory.EnumerateFiles(current.Key).Take(SourceLimits.MaximumEntries + 1).ToArray(); children = Directory.EnumerateDirectories(current.Key).Take(SourceLimits.MaximumDirectories + 1).ToArray(); }
                catch (UnauthorizedAccessException) { warnings.Add("Доступ к папке закрыт: " + current.Key); continue; }
                catch (IOException) { warnings.Add("Папка недоступна: " + current.Key); continue; }
                if (files.Length > SourceLimits.MaximumEntries || children.Length > SourceLimits.MaximumDirectories) throw new IOException("Слишком много объектов в папке. Выберите меньшую папку.");
                Array.Sort(files, StringComparer.OrdinalIgnoreCase);
                Array.Sort(children, StringComparer.OrdinalIgnoreCase);
                foreach (string path in files)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (++entries > SourceLimits.MaximumEntries) throw new IOException("Превышен предел файлов. Выберите меньшую папку.");
                    if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) { warnings.Add("Ссылка пропущена: " + path); continue; }
                    yield return Entry(path, selected, false);
                }
                for (int i = children.Length - 1; i >= 0; i--)
                {
                    string child = children[i];
                    if (++entries > SourceLimits.MaximumEntries) throw new IOException("Превышен предел объектов. Выберите меньшую папку.");
                    if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) { warnings.Add("Ссылка пропущена: " + child); continue; }
                    yield return Entry(child, selected, true);
                    pending.Push(new KeyValuePair<string, int>(child, current.Value + 1));
                }
            }
        }
        public Stream OpenRead(SourceEntry entry, CancellationToken cancel)
        {
            if (entry == null || entry.IsDirectory) throw new ArgumentException("Нужен файл.", "entry");
            cancel.ThrowIfCancellationRequested();
            string path = SourcePaths.Full(entry.OriginalPath);
            if (!SourcePaths.Within(path, directory)) throw new IOException("Путь файла находится вне источника.");
            SourcePaths.NoLinks(path);
            var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
            var current = new FileInfo(path);
            if (current.Length != entry.Size || current.LastWriteTimeUtc.ToString("o") != entry.Modified) { source.Dispose(); throw new IOException("Файл изменился после перечисления; повторите копирование."); }
            return source;
        }
    }

    public sealed class WpdRecoverySource : IRecoverySource, IRecoverySourceWarnings
    {
        readonly SourceInfo info;
        readonly List<string> warnings = new List<string>();
        public SourceInfo Info { get { return info; } }
        public IList<string> Warnings { get { return warnings.AsReadOnly(); } }
        public WpdRecoverySource(string deviceId)
        {
            if (String.IsNullOrWhiteSpace(deviceId)) throw new ArgumentException("Не выбрано устройство WPD.", "deviceId");
            // Device access happens on the acquisition worker, not on the GUI thread.
            info = new SourceInfo { Id = deviceId, Name = deviceId, Kind = "wpd", Status = "detected" };
        }
        public IEnumerable<SourceEntry> Enumerate(string root, CancellationToken cancel)
        {
            warnings.Clear();
            string selected = String.IsNullOrWhiteSpace(root) ? "DEVICE" : root;
            var seen = new HashSet<string>(StringComparer.Ordinal) { selected };
            var pending = new Stack<Tuple<string, string, int>>();
            pending.Push(Tuple.Create(selected, "", 0));
            int count = 0, directories = 0;
            using (var session = new WpdInterop.Session(info.Id))
            using (cancel.Register(session.Cancel))
            {
                info.Status = "ready";
                while (pending.Count > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    var current = pending.Pop();
                    if (++directories > SourceLimits.MaximumDirectories || current.Item3 > SourceLimits.MaximumDepth) throw new IOException("Превышен предел папок телефона. Выберите меньшую папку.");
                    List<string> children;
                    try { children = session.Children(current.Item1, cancel); }
                    catch (IOException) { if (current.Item3 == 0) throw; warnings.Add("Папка телефона недоступна: " + current.Item2); continue; }
                    foreach (string id in children)
                    {
                        cancel.ThrowIfCancellationRequested();
                        if (!seen.Add(id)) { warnings.Add("Повторный объект WPD пропущен: " + current.Item2); continue; }
                        if (++count > SourceLimits.MaximumEntries) throw new IOException("Превышен предел объектов телефона. Выберите меньшую папку.");
                        WpdInterop.Node node;
                        try { node = session.ReadNode(id); }
                        catch (IOException) { warnings.Add("Сведения об объекте телефона недоступны."); continue; }
                        string relative = String.IsNullOrEmpty(current.Item2) ? node.Name : current.Item2 + "/" + node.Name;
                        var entry = new SourceEntry { Id = id, OriginalPath = relative, RelativePath = relative, Modified = node.Modified, Size = node.Size, IsDirectory = node.Folder };
                        yield return entry;
                        if (node.Folder) pending.Push(Tuple.Create(id, relative, current.Item3 + 1));
                    }
                }
            }
        }
        public Stream OpenRead(SourceEntry entry, CancellationToken cancel)
        {
            if (entry == null || entry.IsDirectory) throw new ArgumentException("Нужен файл.", "entry");
            cancel.ThrowIfCancellationRequested();
            var session = new WpdInterop.Session(info.Id);
            try
            {
                WpdInterop.Node current = session.ReadNode(entry.Id);
                if (current.Folder || current.Size != entry.Size || current.Modified != entry.Modified) throw new IOException("Объект телефона изменился после перечисления.");
                return session.OpenRead(entry, cancel);
            }
            catch { session.Dispose(); throw; }
        }
    }

    public static class SourceDiscovery
    {
        public static string AdbExecutable { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "platform-tools", "adb.exe"); } }
        public static List<SourceInfo> ListWpdDevices() { return WpdInterop.Discover(); }
        public static List<SourceInfo> ListAdbDevices()
        {
            if (!File.Exists(AdbExecutable)) return new List<SourceInfo>();
            var output = AdbProcess.Capture(null, new[] { "devices", "-l" }, CancellationToken.None, 1024 * 1024, 30000);
            if (output.Error && !Encoding.UTF8.GetString(output.Data).Contains("List of devices attached")) throw new IOException("ADB не смог получить список устройств.");
            var result = new List<SourceInfo>();
            foreach (string line in Encoding.UTF8.GetString(output.Data).Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || parts[0] == "List" || parts[0].StartsWith("*")) continue;
                string name = parts.FirstOrDefault(p => p.StartsWith("model:", StringComparison.Ordinal));
                string state = parts[1];
                result.Add(new SourceInfo { Id = parts[0], Name = String.IsNullOrEmpty(name) ? parts[0] : name.Substring(6).Replace('_', ' '), Kind = "adb", Status = state == "device" ? "ready" : state });
            }
            return result;
        }
    }

    public sealed class AdbRecoverySource : IRecoverySource, IRecoverySourceWarnings
    {
        readonly SourceInfo info;
        readonly List<string> warnings = new List<string>();
        public SourceInfo Info { get { return info; } }
        public IList<string> Warnings { get { return warnings.AsReadOnly(); } }
        public AdbRecoverySource(string serial)
        {
            AdbProcess.ValidateSerial(serial);
            info = new SourceInfo { Id = serial, Name = serial, Kind = "adb", Status = "detected" };
        }
        void Ready()
        {
            SourceInfo current = SourceDiscovery.ListAdbDevices().FirstOrDefault(d => d.Id == info.Id);
            info.Status = current == null ? "disconnected" : current.Status;
            if (info.Status != "ready") throw new IOException("Телефон ADB недоступен (" + info.Status + "). Разблокируйте его и подтвердите запрос USB debugging.");
        }
        internal static string AndroidRoot(string root)
        {
            string path = String.IsNullOrWhiteSpace(root) ? "/storage/emulated/0" : root.TrimEnd('/');
            if (!(path == "/sdcard" || path.StartsWith("/sdcard/", StringComparison.Ordinal) || path == "/storage/emulated/0" || path.StartsWith("/storage/emulated/0/", StringComparison.Ordinal) || path.StartsWith("/storage/", StringComparison.Ordinal))) throw new IOException("Выберите папку общего хранилища телефона.");
            if (path.IndexOf('\0') >= 0 || path.Split('/').Any(p => p == ".." || p == ".")) throw new IOException("Некорректный путь телефона.");
            return path;
        }
        public IEnumerable<SourceEntry> Enumerate(string root, CancellationToken cancel)
        {
            warnings.Clear(); Ready();
            string selected = AndroidRoot(root);
            // NUL separates paths; newlines and quotes inside a filename cannot split records.
            // The remote script only lists objects and reads stat metadata. It cannot modify files.
            string remote = ListCommand(selected);
            // shell-v2 without a PTY preserves bytes, separates stderr and supplies a real
            // remote exit code; legacy exec-out would report zero even if remote cat failed.
            AdbOutput output = AdbProcess.Capture(info.Id, new[] { "shell", "-T", remote }, cancel, 128 * 1024 * 1024, 120000);
            if (output.Error) warnings.Add("Некоторые папки телефона недоступны. Закрытые данные приложений не скопированы.");
            if (output.Data.Length == 0 && output.Error) throw new IOException("ADB не смог перечислить выбранную папку телефона.");
            foreach (SourceEntry entry in ParseListing(output.Data, selected, warnings, cancel)) yield return entry;
        }
        internal static string ListCommand(string selected)
        {
            string script = "for p do if stat -c '%F|%s|%Y' \"$p\"; then printf '%s\\0' \"$p\"; fi; done";
            return "find " + AdbProcess.UnixQuote(selected + "/") + " \\( -type f -o -type d \\) -exec sh -c " + AdbProcess.UnixQuote(script) + " sh {} +";
        }
        internal static IEnumerable<SourceEntry> ParseListing(byte[] data, string selected, List<string> warnings, CancellationToken cancel)
        {
            string text = new UTF8Encoding(false, true).GetString(data);
            int entries = 0, directories = 0;
            foreach (string record in text.Split('\0'))
            {
                cancel.ThrowIfCancellationRequested();
                if (record.Length == 0) continue;
                int line = record.IndexOf('\n');
                if (line < 0) { warnings.Add("Неполная запись списка ADB пропущена."); continue; }
                string[] properties = record.Substring(0, line).TrimEnd('\r').Split('|');
                string path = record.Substring(line + 1);
                if (properties.Length != 3 || !path.StartsWith(selected + "/", StringComparison.Ordinal)) { warnings.Add("Некорректная запись списка ADB пропущена."); continue; }
                string relative = path.Substring(selected.Length + 1);
                if (relative.Length == 0) continue;
                bool folder = properties[0] == "directory";
                if (!folder && properties[0] != "regular file" && properties[0] != "regular empty file") continue;
                long size, modified;
                if (!Int64.TryParse(properties[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out size) || !Int64.TryParse(properties[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out modified)) { warnings.Add("Метаданные ADB не удалось разобрать."); continue; }
                if (++entries > SourceLimits.MaximumEntries || (folder && ++directories > SourceLimits.MaximumDirectories) || relative.Count(c => c == '/') > SourceLimits.MaximumDepth) throw new IOException("Превышен предел файлов телефона. Выберите меньшую папку.");
                yield return new SourceEntry { Id = path, OriginalPath = path, RelativePath = relative, Modified = modified.ToString(CultureInfo.InvariantCulture), Size = folder ? -1 : size, IsDirectory = folder };
            }
        }
        public Stream OpenRead(SourceEntry entry, CancellationToken cancel)
        {
            if (entry == null || entry.IsDirectory) throw new ArgumentException("Нужен файл.", "entry");
            cancel.ThrowIfCancellationRequested();
            string path = AndroidRoot(entry.OriginalPath);
            // stat before every read prevents reusing metadata for a changed source file.
            var stat = AdbProcess.Capture(info.Id, new[] { "shell", "-T", "stat -c '%s|%Y' " + AdbProcess.UnixQuote(path) }, cancel, 4096, 30000);
            string[] values = Encoding.UTF8.GetString(stat.Data).Trim().Split('|');
            long size;
            if (stat.Error || values.Length != 2 || !Int64.TryParse(values[0], out size) || size != entry.Size || values[1] != entry.Modified) throw new IOException("Файл телефона изменился или недоступен. Повторите копирование.");
            return AdbProcess.OpenRead(info.Id, "cat " + AdbProcess.UnixQuote(path), cancel);
        }
    }

    internal sealed class AdbOutput { internal byte[] Data; internal bool Error; }
    internal static class AdbProcess
    {
        internal static void ValidateSerial(string serial)
        {
            if (String.IsNullOrWhiteSpace(serial) || serial.Length > 256 || serial.StartsWith("-", StringComparison.Ordinal) || serial.Any(c => !(Char.IsLetterOrDigit(c) || "._:-".IndexOf(c) >= 0))) throw new ArgumentException("Некорректный идентификатор ADB.", "serial");
        }
        internal static string UnixQuote(string value) { if (value.IndexOf('\0') >= 0) throw new ArgumentException("NUL in path"); return "'" + value.Replace("'", "'\"'\"'") + "'"; }
        internal static string WindowsQuote(string value)
        {
            var text = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) { if (c == '\\') { slashes++; continue; } if (c == '"') text.Append('\\', slashes * 2 + 1); else text.Append('\\', slashes); text.Append(c); slashes = 0; }
            text.Append('\\', slashes * 2); return text.Append('"').ToString();
        }
        static Process Start(string serial, string[] arguments)
        {
            if (!File.Exists(SourceDiscovery.AdbExecutable)) throw new FileNotFoundException("Не найден официальный adb.exe.", SourceDiscovery.AdbExecutable);
            var values = new List<string>();
            if (serial != null) { ValidateSerial(serial); values.Add("-s"); values.Add(serial); }
            values.AddRange(arguments);
            var start = new ProcessStartInfo(SourceDiscovery.AdbExecutable, String.Join(" ", values.Select(WindowsQuote).ToArray())) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            return Process.Start(start);
        }
        internal static void Kill(Process process) { try { if (!process.HasExited) process.Kill(); } catch (InvalidOperationException) { } }
        internal static AdbOutput Capture(string serial, string[] arguments, CancellationToken cancel, int limit, int timeout)
        {
            using (var process = Start(serial, arguments))
            using (cancel.Register(() => Kill(process)))
            using (var memory = new MemoryStream())
            {
                Exception readError = null;
                bool stderr = false;
                var reader = new Thread(() => {
                    try { byte[] buffer = new byte[65536]; int read; while ((read = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) > 0) { if (memory.Length + read > limit) throw new IOException("Список файлов ADB слишком большой. Выберите меньшую папку."); memory.Write(buffer, 0, read); } }
                    catch (Exception error) { readError = error; Kill(process); }
                }) { IsBackground = true };
                var errors = new Thread(() => { try { char[] buffer = new char[4096]; while (process.StandardError.Read(buffer, 0, buffer.Length) > 0) stderr = true; } catch (IOException) { } catch (ObjectDisposedException) { } }) { IsBackground = true };
                reader.Start(); errors.Start();
                try
                {
                    var timer = Stopwatch.StartNew();
                    while (!process.WaitForExit(100)) { cancel.ThrowIfCancellationRequested(); if (timer.ElapsedMilliseconds > timeout) { Kill(process); throw new IOException("Телефон не ответил вовремя при перечислении файлов."); } }
                    reader.Join(3000); errors.Join(3000);
                    cancel.ThrowIfCancellationRequested();
                    if (reader.IsAlive || errors.IsAlive) throw new IOException("Не удалось завершить чтение ответа ADB.");
                    if (readError != null) throw new IOException("Не удалось прочитать ответ ADB.", readError);
                    return new AdbOutput { Data = memory.ToArray(), Error = process.ExitCode != 0 || stderr };
                }
                finally { Kill(process); process.WaitForExit(3000); reader.Join(3000); errors.Join(3000); }
            }
        }
        internal static Stream OpenRead(string serial, string command, CancellationToken cancel) { return new AdbReadStream(Start(serial, new[] { "shell", "-T", command }), cancel); }
        sealed class AdbReadStream : Stream
        {
            readonly Process process;
            readonly CancellationToken cancel;
            CancellationTokenRegistration registration;
            readonly Thread errors;
            bool disposed;
            long position;
            internal AdbReadStream(Process process, CancellationToken cancel)
            {
                this.process = process; this.cancel = cancel;
                registration = cancel.Register(() => Kill(process));
                errors = new Thread(() => { try { char[] data = new char[4096]; while (process.StandardError.Read(data, 0, data.Length) > 0) { } } catch (IOException) { } catch (ObjectDisposedException) { } }) { IsBackground = true };
                errors.Start();
            }
            public override bool CanRead { get { return !disposed; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { return position; } set { throw new NotSupportedException(); } }
            public override int Read(byte[] buffer, int offset, int count)
            {
                if (disposed) throw new ObjectDisposedException("ADB stream");
                cancel.ThrowIfCancellationRequested();
                if (count == 0) return 0;
                IAsyncResult pending = process.StandardOutput.BaseStream.BeginRead(buffer, offset, count, null, null);
                var timer = Stopwatch.StartNew();
                using (pending.AsyncWaitHandle)
                {
                    while (!pending.AsyncWaitHandle.WaitOne(100)) { cancel.ThrowIfCancellationRequested(); if (timer.ElapsedMilliseconds > 120000) { Kill(process); throw new IOException("Телефон прервал передачу данных."); } }
                    int read = process.StandardOutput.BaseStream.EndRead(pending);
                    cancel.ThrowIfCancellationRequested();
                    if (read == 0 && (!process.WaitForExit(3000) || process.ExitCode != 0)) throw new IOException("ADB не смог полностью прочитать файл телефона.");
                    position += read; return read;
                }
            }
            protected override void Dispose(bool disposing)
            {
                if (!disposed) { disposed = true; registration.Dispose(); Kill(process); process.WaitForExit(3000); errors.Join(3000); process.Dispose(); }
                base.Dispose(disposing);
            }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException("ADB источник открыт только для чтения."); }
        }
    }

    public sealed class AcquisitionFile
    {
        public string Id, RelativePath, OriginalPath, Modified, Sha256, LocalPath, PartialPath, Status, Message;
        public long Size, CopiedBytes;
    }
    public sealed class AcquisitionManifest
    {
        public int Schema = 1;
        public SourceInfo Source;
        public string SelectedRoot, Status, UpdatedUtc;
        public List<AcquisitionFile> Files = new List<AcquisitionFile>();
        public List<string> Warnings = new List<string>();
    }
    public static class SourceAcquisition
    {
        static JavaScriptSerializer Serializer() { return new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue, RecursionLimit = 64 }; }
        public static void ValidateOutput(IRecoverySource source, string selectedRoot, string runDirectory)
        {
            if (source == null) throw new ArgumentNullException("source");
            if (String.IsNullOrWhiteSpace(runDirectory)) throw new ArgumentException("Не задана папка результата.", "runDirectory");
            string output = SourcePaths.Full(runDirectory);
            if (output.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Выберите локальную папку компьютера.");
            if (output.Length > 140) throw new IOException("Путь результатов слишком длинный для этой версии Windows-программы. Выберите более короткую папку, например C:\\Recovery-Results.");
            SourcePaths.NoLinks(output);
            var local = source as ILocalRecoverySource;
            if (local != null)
            {
                local.SelectedPath(selectedRoot);
                if (SourcePaths.Within(output, local.RootDirectory)) throw new IOException("Папка результатов не должна находиться внутри источника.");
            }
        }
        static void AtomicJson(string path, object value)
        {
            SourcePaths.NoLinks(path);
            string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false))) { writer.Write(Serializer().Serialize(value)); writer.Flush(); stream.Flush(true); }
                if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        static string HashFile(string path, CancellationToken cancel)
        {
            SourcePaths.NoLinks(path);
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var hash = SHA256.Create())
            {
                byte[] data = new byte[1024 * 1024]; int read;
                while ((read = stream.Read(data, 0, data.Length)) > 0) { cancel.ThrowIfCancellationRequested(); hash.TransformBlock(data, 0, read, data, 0); }
                hash.TransformFinalBlock(new byte[0], 0, 0);
                return BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
            }
        }
        public static string Copy(IRecoverySource source, string selectedRoot, string runDirectory, CancellationToken cancel, Action<string> progress)
        {
            ValidateOutput(source, selectedRoot, runDirectory);
            cancel.ThrowIfCancellationRequested();
            string directory = SourcePaths.Full(runDirectory);
            string snapshot = Path.Combine(directory, "snapshot");
            string index = Path.Combine(directory, "acquisition-index");
            string manifestPath = Path.Combine(directory, "acquisition.json");
            SourcePaths.NoLinks(snapshot); SourcePaths.NoLinks(index); SourcePaths.NoLinks(manifestPath);
            Directory.CreateDirectory(snapshot); Directory.CreateDirectory(index);
            if (File.Exists(manifestPath))
            {
                if (new FileInfo(manifestPath).Length > 256L * 1024 * 1024) throw new IOException("Слишком большой файл сведений о копировании.");
                AcquisitionManifest previous = Serializer().Deserialize<AcquisitionManifest>(File.ReadAllText(manifestPath, Encoding.UTF8));
                if (previous == null || previous.Schema != 1 || previous.Source == null || previous.Source.Kind != source.Info.Kind || previous.Source.Id != source.Info.Id || previous.SelectedRoot != (selectedRoot ?? "")) throw new IOException("Папка содержит копию другого источника. Выберите новую папку.");
            }
            var manifest = new AcquisitionManifest { Source = source.Info, SelectedRoot = selectedRoot ?? "", Status = "running", UpdatedUtc = DateTime.UtcNow.ToString("o") };
            AtomicJson(manifestPath, manifest);
            var identities = new HashSet<string>(StringComparer.Ordinal);
            var outputPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int count = 0, failed = 0, successiveFailures = 0;
            try
            {
                foreach (SourceEntry entry in source.Enumerate(selectedRoot, cancel))
                {
                    cancel.ThrowIfCancellationRequested();
                    if (++count > SourceLimits.MaximumEntries) throw new IOException("Источник содержит слишком много объектов.");
                    if (entry == null) throw new IOException("Источник вернул пустую запись.");
                    if (entry.IsDirectory) continue;
                    string relative = SourcePaths.Relative(entry.RelativePath);
                    if (String.IsNullOrEmpty(entry.Id) || entry.Size < -1 || entry.Size > SourceLimits.MaximumFileBytes) throw new IOException("Некорректная запись или файл больше предела 128 ГиБ.");
                    string identity = SourcePaths.HashText(source.Info.Kind + "\n" + source.Info.Id + "\n" + entry.Id + "\n" + relative);
                    if (!identities.Add(identity)) throw new IOException("Источник вернул повторную запись файла.");
                    string output = Path.Combine(snapshot, relative.Replace('/', '\\'));
                    bool representable = relative.Split('/').All(part => SourcePaths.SafeName(part) == part) && output.Length < 245;
                    if (!representable || !outputPaths.Add(output))
                    {
                        // Preserve standard backup trees exactly. Exceptional Android names cannot
                        // be represented on Windows; retain the payload with explicit provenance.
                        string extension = Path.GetExtension(SourcePaths.SafeName(relative));
                        output = Path.Combine(snapshot, "path-conflicts", identity + extension);
                        if (!outputPaths.Add(output)) throw new IOException("Повторный путь результата.");
                        manifest.Warnings.Add("Исходный путь нельзя точно сохранить в Windows; содержимое сохранено отдельно: " + relative);
                    }
                    string fileDirectory = Path.GetDirectoryName(output);
                    // Temporary files stay outside the logical tree: a real file called *.partial
                    // must never collide with another source file's in-progress destination.
                    string partial = Path.Combine(index, identity + ".partial");
                    string checkpoint = Path.Combine(index, identity + ".json");
                    SourcePaths.NoLinks(fileDirectory); SourcePaths.NoLinks(output); SourcePaths.NoLinks(partial); SourcePaths.NoLinks(checkpoint);
                    var record = new AcquisitionFile { Id = entry.Id, RelativePath = relative, OriginalPath = entry.OriginalPath, Modified = entry.Modified ?? "", Size = entry.Size, CopiedBytes = 0, Sha256 = "", LocalPath = output.Substring(directory.Length + 1).Replace('\\', '/'), PartialPath = partial.Substring(directory.Length + 1).Replace('\\', '/'), Status = "copying", Message = "" };
                    manifest.Files.Add(record);
                    if (File.Exists(checkpoint) && new FileInfo(checkpoint).Length <= 131072)
                    {
                        AcquisitionFile old = Serializer().Deserialize<AcquisitionFile>(File.ReadAllText(checkpoint, Encoding.UTF8));
                        if (old != null && old.Status == "complete" && old.Id == record.Id && old.RelativePath == relative && old.LocalPath == record.LocalPath && old.Size == entry.Size && old.Modified == record.Modified && entry.Size >= 0 && !String.IsNullOrEmpty(record.Modified) && File.Exists(output) && new FileInfo(output).Length == old.CopiedBytes && HashFile(output, cancel) == old.Sha256)
                        {
                            record.CopiedBytes = old.CopiedBytes; record.Sha256 = old.Sha256; record.Status = "complete";
                            successiveFailures = 0; if (progress != null) progress("Проверена готовая копия: " + relative); continue;
                        }
                    }
                    Directory.CreateDirectory(fileDirectory);
                    if (File.Exists(output)) File.Delete(output); // Only this source's deterministic snapshot file, never the source.
                    if (File.Exists(partial)) File.Delete(partial);
                    AtomicJson(checkpoint, record);
                    if (progress != null) progress("Копирование: " + relative);
                    try
                    {
                        using (Stream input = source.OpenRead(entry, cancel))
                        using (var target = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                        using (var hash = SHA256.Create())
                        {
                            if (input == null || !input.CanRead) throw new IOException("Источник не открыл поток чтения.");
                            byte[] data = new byte[1024 * 1024]; int read;
                            var timer = Stopwatch.StartNew();
                            while ((read = input.Read(data, 0, data.Length)) > 0)
                            {
                                cancel.ThrowIfCancellationRequested();
                                if (read > data.Length || record.CopiedBytes > SourceLimits.MaximumFileBytes - read || (entry.Size >= 0 && record.CopiedBytes > entry.Size - read)) throw new IOException("Размер файла изменился во время чтения.");
                                target.Write(data, 0, read); hash.TransformBlock(data, 0, read, data, 0); record.CopiedBytes += read;
                                if (timer.ElapsedMilliseconds >= 1000) { if (progress != null) progress("Копирование " + relative + ": " + record.CopiedBytes.ToString(CultureInfo.InvariantCulture) + " байт"); timer.Restart(); }
                            }
                            cancel.ThrowIfCancellationRequested();
                            if (entry.Size >= 0 && record.CopiedBytes != entry.Size) throw new IOException("Файл прочитан не полностью.");
                            hash.TransformFinalBlock(new byte[0], 0, 0); record.Sha256 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant(); target.Flush(true);
                        }
                        File.Move(partial, output); record.Status = "complete"; successiveFailures = 0;
                        AtomicJson(checkpoint, record);
                    }
                    catch (OperationCanceledException) { record.Status = "partial"; record.Message = "Копирование остановлено."; AtomicJson(checkpoint, record); throw; }
                    catch (IOException error) { record.Status = "partial"; record.Message = error.Message; AtomicJson(checkpoint, record); failed++; successiveFailures++; }
                    catch (UnauthorizedAccessException) { record.Status = "partial"; record.Message = "Доступ к файлу закрыт."; AtomicJson(checkpoint, record); failed++; successiveFailures++; }
                    if (successiveFailures >= 8) throw new IOException("Восемь файлов подряд недоступны. Переподключите телефон или выберите другой источник.");
                }
                var sourceWarnings = source as IRecoverySourceWarnings;
                if (sourceWarnings != null) manifest.Warnings.AddRange(sourceWarnings.Warnings.Take(1000));
                manifest.Status = failed > 0 || manifest.Warnings.Count > 0 ? "finished_with_warnings" : "finished";
                if (manifest.Files.Count == 0 && manifest.Warnings.Count > 0) throw new IOException("Ни один доступный файл не найден; проверьте права доступа к источнику.");
                if (manifest.Files.Count > 0 && manifest.Files.All(f => f.Status != "complete")) throw new IOException("Не удалось полностью скопировать ни один файл.");
                return snapshot;
            }
            catch (OperationCanceledException) { manifest.Status = "cancelled"; throw; }
            catch (Exception error) { manifest.Status = "incomplete"; manifest.Warnings.Add(error.Message); throw; }
            finally { manifest.UpdatedUtc = DateTime.UtcNow.ToString("o"); AtomicJson(manifestPath, manifest); }
        }
    }
}
