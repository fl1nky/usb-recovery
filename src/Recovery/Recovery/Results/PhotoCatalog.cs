using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>Inspects recovery output only. Never opens or modifies the source device.</summary>
    public static class PhotoCatalog
    {
        public const long MaximumFileBytes = 128L * 1024 * 1024;
        public const long MaximumPixels = 60000000;
        public const int MaximumDimension = 32768;
        static readonly HashSet<string> RasterExtensions = new HashSet<string>(new[] { ".jpg", ".jpeg", ".jpe", ".png", ".gif", ".bmp", ".tif", ".tiff" }, StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> ViewerExtensions = new HashSet<string>(new[] { ".heic", ".heif", ".avif", ".webp", ".cr2", ".cr3", ".nef", ".nrw", ".arw", ".sr2", ".srf", ".dng", ".raf", ".rw2", ".orf", ".pef", ".raw", ".kdc", ".mos", ".mrw", ".x3f" }, StringComparer.OrdinalIgnoreCase);
        static readonly uint[] CrcTable = MakeCrcTable();

        public sealed class Item
        {
            public string Name, Path, Url, Extension, Status, Detail, Sha256, Captured, Thumbnail;
            public long Bytes;
            public int Width, Height, Copies;
            public List<string> OtherPaths = new List<string>();
            public List<string> OtherUrls = new List<string>();
        }

        sealed class Probe
        {
            public int Width, Height;
            public bool EndChecked, HasEnd;
            public string Format, Detail;
        }

        public static string Build(string runDirectory, CancellationToken cancel, Action<string> progress)
        {
            if (String.IsNullOrWhiteSpace(runDirectory)) throw new ArgumentException("Не задана папка результатов.", "runDirectory");
            string root = System.IO.Path.GetFullPath(runDirectory).TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);
            if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
            // Output must not be redirected onto another volume by a reparse point.
            if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new IOException("Папка результатов не должна быть ссылкой.");
            string thumbnailDirectory = System.IO.Path.Combine(root, "photo-thumbnails");
            if (Directory.Exists(thumbnailDirectory) && (File.GetAttributes(thumbnailDirectory) & FileAttributes.ReparsePoint) != 0) throw new IOException("Папка миниатюр не должна быть ссылкой.");
            cancel.ThrowIfCancellationRequested();
            var items = new List<Item>();
            var inspectedHashes = new Dictionary<string, Item>(StringComparer.Ordinal);
            int visited = 0;
            foreach (string candidate in Candidates(root, cancel))
            {
                cancel.ThrowIfCancellationRequested();
                Item item = Inspect(candidate, root, thumbnailDirectory, inspectedHashes, cancel);
                if (!String.IsNullOrEmpty(item.Sha256) && !inspectedHashes.ContainsKey(item.Sha256)) inspectedHashes.Add(item.Sha256, new Item { Sha256 = item.Sha256, Extension = item.Extension, Status = item.Status, Detail = item.Detail, Width = item.Width, Height = item.Height, Captured = item.Captured, Thumbnail = item.Thumbnail });
                SourceHints(item);
                items.Add(item);
                visited++;
                if (progress != null && (visited == 1 || visited % 25 == 0)) progress("Проверка фотографий: " + visited.ToString(CultureInfo.InvariantCulture) + ". Повторы объединяются в галерее.");
            }
            cancel.ThrowIfCancellationRequested();
            var groups = items.GroupBy(i => String.IsNullOrEmpty(i.Sha256) ? "path:" + i.Path : "sha256:" + i.Sha256, StringComparer.Ordinal).Select(g => Best(g)).ToList();
            groups.Sort(delegate(Item a, Item b) { int rank = StatusRank(b.Status).CompareTo(StatusRank(a.Status)); return rank != 0 ? rank : StringComparer.OrdinalIgnoreCase.Compare(a.Path, b.Path); });
            var serializer = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue, RecursionLimit = 100 };
            string data = serializer.Serialize(new { schema = 1, generatedUtc = DateTime.UtcNow.ToString("o"), candidates = items.Count, unique = groups.Count, decoded = groups.Count(i => i.Status == "decoded"), partial = groups.Count(i => i.Status == "partial"), items = groups });
            WriteAtomic(System.IO.Path.Combine(root, "photo-catalog.json"), data, cancel);
            WriteAtomic(System.IO.Path.Combine(root, "photo-catalog.csv"), Csv(items), cancel);
            string html = Html(serializer.Serialize(groups), items.Count, groups.Count);
            string gallery = System.IO.Path.Combine(root, "Фото.html");
            WriteAtomic(gallery, html, cancel);
            if (progress != null) progress("Галерея готова: " + groups.Count + " уникальных кандидатов; все " + items.Count + " исходных файлов сохранены.");
            return gallery;
        }

        static IEnumerable<string> Candidates(string root, CancellationToken cancel)
        {
            foreach (string directory in Directory.EnumerateDirectories(root).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
            {
                cancel.ThrowIfCancellationRequested();
                string name = System.IO.Path.GetFileName(directory);
                bool accepted = name.Equals("attempt-history",StringComparison.OrdinalIgnoreCase)||name.Equals("filesystem", StringComparison.OrdinalIgnoreCase) || name.Equals("ntfs", StringComparison.OrdinalIgnoreCase) || name.Equals("metadata-rescue", StringComparison.OrdinalIgnoreCase) || name.Equals("salvage-content", StringComparison.OrdinalIgnoreCase) || name.Equals("fragmented-photos", StringComparison.OrdinalIgnoreCase) || name.Equals("fragmented-media", StringComparison.OrdinalIgnoreCase) || name.Equals("fragmented-archives", StringComparison.OrdinalIgnoreCase) || name.Equals("user-signatures", StringComparison.OrdinalIgnoreCase) || name.Equals("containers", StringComparison.OrdinalIgnoreCase) || name.Equals("extra-photos", StringComparison.OrdinalIgnoreCase) || name.StartsWith("files.", StringComparison.OrdinalIgnoreCase);
                if (!accepted || (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) continue;
                var pending = new Stack<string>();
                if (name.Equals("filesystem", StringComparison.OrdinalIgnoreCase))
                {
                    string files = System.IO.Path.Combine(directory, "files");
                    if (Directory.Exists(files) && (File.GetAttributes(files) & FileAttributes.ReparsePoint) == 0) pending.Push(files);
                }
                else if (name.Equals("ntfs", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (string partition in Directory.EnumerateDirectories(directory))
                    {
                        if ((File.GetAttributes(partition) & FileAttributes.ReparsePoint) != 0) continue;
                        string data = System.IO.Path.Combine(partition, "data");
                        if (Directory.Exists(data) && (File.GetAttributes(data) & FileAttributes.ReparsePoint) == 0) pending.Push(data);
                    }
                }
                else pending.Push(directory);
                while (pending.Count > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    string current = pending.Pop();
                    foreach (string path in Directory.EnumerateFiles(current).OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
                    {
                        cancel.ThrowIfCancellationRequested();
                        string extension = System.IO.Path.GetExtension(path);
                        if (!RasterExtensions.Contains(extension) && !ViewerExtensions.Contains(extension)) continue;
                        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0) yield return path;
                    }
                    foreach (string child in Directory.EnumerateDirectories(current).OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase))
                        if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) pending.Push(child);
                }
            }
        }

        static Item Inspect(string path, string root, string thumbnailDirectory, Dictionary<string, Item> inspectedHashes, CancellationToken cancel)
        {
            string relative = path.Substring(root.Length + 1).Replace('\\', '/');
            var item = new Item { Name = System.IO.Path.GetFileName(path), Path = relative, Url = Url(relative), Extension = System.IO.Path.GetExtension(path).ToLowerInvariant(), Status = "unreadable", Detail = "Файл не удалось проверить.", Captured = "", Thumbnail = "", Copies = 1 };
            try
            {
                item.Bytes = new FileInfo(path).Length;
                if (item.Bytes <= 0) { item.Detail = "Пустой файл."; return item; }
                if (item.Bytes > MaximumFileBytes) { item.Status = "limited"; item.Detail = "Больше 128 МиБ: автоматическое открытие пропущено. Проверьте во внешнем просмотрщике."; return item; }
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
                using (var sha = SHA256.Create())
                {
                    byte[] buffer = new byte[65536];
                    int read;
                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) { cancel.ThrowIfCancellationRequested(); sha.TransformBlock(buffer, 0, read, buffer, 0); }
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    item.Sha256 = BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
                }
                Item cached;
                // A byte-identical raster need not be decoded twice. Different extension classes
                // remain separate so an unsupported RAW candidate does not suppress JPEG decoding.
                if (inspectedHashes.TryGetValue(item.Sha256, out cached) && RasterExtensions.Contains(item.Extension) == RasterExtensions.Contains(cached.Extension))
                {
                    item.Status = cached.Status; item.Detail = cached.Detail; item.Width = cached.Width; item.Height = cached.Height; item.Captured = cached.Captured; item.Thumbnail = cached.Thumbnail;
                    return item;
                }
                if (ViewerExtensions.Contains(item.Extension))
                {
                    item.Status = "viewer";
                    item.Detail = "Нужен внешний просмотрщик для HEIC/RAW/WebP/AVIF. Содержимое и целостность не проверены.";
                    return item;
                }
                Probe probe;
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536)) probe = ReadProbe(stream, cancel);
                if (probe == null) { item.Detail = "Заголовок изображения не распознан; возможно ложное совпадение."; return item; }
                item.Width = probe.Width;
                item.Height = probe.Height;
                if (!WithinLimits(probe.Width, probe.Height)) { item.Status = "limited"; item.Detail = "Размер изображения неизвестен или превышает предел: 32 768 по стороне и 60 млн пикселей. Проверьте отдельно."; return item; }
                cancel.ThrowIfCancellationRequested();
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
                using (Image decoded = Image.FromStream(stream, false, true))
                {
                    if (!WithinLimits(decoded.Width, decoded.Height)) { item.Status = "limited"; item.Detail = "Размер изображения превышает предел безопасного предпросмотра."; return item; }
                    item.Width = decoded.Width;
                    item.Height = decoded.Height;
                    item.Captured = CaptureDate(decoded);
                    int width = Math.Max(1, (int)Math.Round(decoded.Width * Math.Min(1.0, Math.Min(360.0 / decoded.Width, 260.0 / decoded.Height))));
                    int height = Math.Max(1, (int)Math.Round(decoded.Height * Math.Min(1.0, Math.Min(360.0 / decoded.Width, 260.0 / decoded.Height))));
                    // Rendering forces pixel decoding; a matching header alone is not accepted.
                    using (var thumbnail = new Bitmap(width, height, PixelFormat.Format24bppRgb))
                    using (Graphics graphics = Graphics.FromImage(thumbnail))
                    {
                        graphics.Clear(Color.White);
                        graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                        graphics.DrawImage(decoded, new Rectangle(0, 0, width, height));
                        cancel.ThrowIfCancellationRequested();
                        Directory.CreateDirectory(thumbnailDirectory);
                        string thumbnailName = item.Sha256 + ".jpg";
                        string thumbnailPath = System.IO.Path.Combine(thumbnailDirectory, thumbnailName);
                        if (File.Exists(thumbnailPath) && (File.GetAttributes(thumbnailPath) & FileAttributes.ReparsePoint) != 0) throw new IOException("Миниатюра не должна быть ссылкой.");
                        if (!File.Exists(thumbnailPath))
                        {
                            string temporary = thumbnailPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                            try { thumbnail.Save(temporary, ImageFormat.Jpeg); File.Move(temporary, thumbnailPath); }
                            finally { if (File.Exists(temporary)) File.Delete(temporary); }
                        }
                        item.Thumbnail = "photo-thumbnails/" + thumbnailName;
                    }
                }
                item.Status = probe.EndChecked && !probe.HasEnd ? "partial" : "decoded";
                item.Detail = item.Status == "partial" ? "Изображение открывается, но структура неполна или повреждена: " + probe.Detail : "Изображение декодировано. Это не гарантирует восстановление всех исходных пикселей.";
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                if (!(ex is IOException) && !(ex is UnauthorizedAccessException) && !(ex is ArgumentException) && !(ex is ExternalException) && !(ex is OutOfMemoryException) && !(ex is NotSupportedException)) throw;
                item.Status = "unreadable";
                item.Detail = "Декодер не смог открыть изображение: файл повреждён, неполон или является ложным совпадением.";
                item.Thumbnail = "";
            }
            return item;
        }

        static bool WithinLimits(int width, int height) { return width > 0 && height > 0 && width <= MaximumDimension && height <= MaximumDimension && (long)width * height <= MaximumPixels; }

        static Probe ReadProbe(FileStream stream, CancellationToken cancel)
        {
            byte[] header = new byte[32];
            int length = stream.Read(header, 0, header.Length);
            stream.Position = 0;
            if (length >= 2 && header[0] == 255 && header[1] == 216) return JpegProbe(stream, cancel);
            if (length >= 24 && header[0] == 137 && Encoding.ASCII.GetString(header, 1, 3) == "PNG" && header[4] == 13 && header[5] == 10 && header[6] == 26 && header[7] == 10) return PngProbe(stream, cancel);
            if (length >= 10 && (Encoding.ASCII.GetString(header, 0, 6) == "GIF87a" || Encoding.ASCII.GetString(header, 0, 6) == "GIF89a")) return new Probe { Format = "GIF", Width = header[6] | header[7] << 8, Height = header[8] | header[9] << 8 };
            if (length >= 26 && header[0] == 66 && header[1] == 77)
            {
                uint dibLength = Little32(header, 14);
                if (dibLength == 12) return new Probe { Format = "BMP", Width = header[18] | header[19] << 8, Height = header[20] | header[21] << 8 };
                if (dibLength >= 40)
                {
                    int width = unchecked((int)Little32(header, 18));
                    int height = unchecked((int)Little32(header, 22));
                    return new Probe { Format = "BMP", Width = width, Height = height == Int32.MinValue ? 0 : Math.Abs(height) };
                }
            }
            if (length >= 8 && ((header[0] == 73 && header[1] == 73 && header[2] == 42 && header[3] == 0) || (header[0] == 77 && header[1] == 77 && header[2] == 0 && header[3] == 42))) return TiffProbe(stream, header, cancel);
            return null;
        }

        static Probe JpegProbe(FileStream stream, CancellationToken cancel)
        {
            var result = new Probe { Format = "JPEG", EndChecked = true, Detail = "Нет завершающего маркера JPEG." };
            stream.Position = 2;
            int pending = -1;
            while (stream.Position < stream.Length)
            {
                cancel.ThrowIfCancellationRequested();
                int marker = pending;
                pending = -1;
                if (marker < 0)
                {
                    if (stream.ReadByte() != 255) { result.Detail = "Нарушена последовательность маркеров JPEG."; return result; }
                    do { marker = stream.ReadByte(); } while (marker == 255);
                }
                if (marker < 0) return result;
                if (marker == 217) { result.HasEnd = result.Width > 0 && result.Height > 0; return result; }
                if (marker == 0 || marker == 216) { result.Detail = "Недопустимый маркер JPEG."; return result; }
                if (marker == 1 || (marker >= 208 && marker <= 215)) continue;
                int high = stream.ReadByte(), low = stream.ReadByte();
                if (high < 0 || low < 0) return result;
                int count = (high << 8) | low;
                if (count < 2 || stream.Position + count - 2 > stream.Length) { result.Detail = "Оборван сегмент JPEG."; return result; }
                long segmentEnd = stream.Position + count - 2;
                bool sof = marker >= 192 && marker <= 207 && marker != 196 && marker != 200 && marker != 204;
                if (sof)
                {
                    if (count < 8) return result;
                    stream.ReadByte();
                    int h1 = stream.ReadByte(), h2 = stream.ReadByte(), w1 = stream.ReadByte(), w2 = stream.ReadByte();
                    result.Height = (h1 << 8) | h2;
                    result.Width = (w1 << 8) | w2;
                    if (!WithinLimits(result.Width, result.Height)) return result;
                }
                stream.Position = segmentEnd;
                if (marker == 218)
                {
                    long nextCancel = stream.Position + 65536;
                    while (stream.Position < stream.Length)
                    {
                        if (stream.Position >= nextCancel) { cancel.ThrowIfCancellationRequested(); nextCancel = stream.Position + 65536; }
                        if (stream.ReadByte() != 255) continue;
                        int code;
                        do { code = stream.ReadByte(); } while (code == 255);
                        if (code < 0) return result;
                        if (code == 0 || (code >= 208 && code <= 215)) continue;
                        pending = code;
                        break;
                    }
                    if (pending < 0) return result;
                }
            }
            // An EOI consumed as the final two bytes is processed here as well.
            if (pending == 217) result.HasEnd = result.Width > 0 && result.Height > 0;
            return result;
        }

        static Probe PngProbe(FileStream stream, CancellationToken cancel)
        {
            var result = new Probe { Format = "PNG", EndChecked = true, Detail = "Нет корректного завершающего блока PNG IEND." };
            stream.Position = 8;
            bool first = true, hasIdat = false;
            byte[] header = new byte[8], buffer = new byte[65536], crcBytes = new byte[4];
            while (stream.Position + 12 <= stream.Length)
            {
                cancel.ThrowIfCancellationRequested();
                if (!ReadFully(stream, header, 0, 8)) return result;
                uint count = Big32(header, 0);
                if (count > Int32.MaxValue || stream.Position + count + 4 > stream.Length) { result.Detail = "Оборван блок PNG."; return result; }
                string type = Encoding.ASCII.GetString(header, 4, 4);
                if (first && (type != "IHDR" || count != 13)) return result;
                uint crc = 0xffffffff;
                for (int i = 4; i < 8; i++) crc = CrcTable[(crc ^ header[i]) & 255] ^ (crc >> 8);
                uint remaining = count;
                bool headRead = false;
                while (remaining > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    int chunk = (int)Math.Min(remaining, (uint)buffer.Length);
                    if (!ReadFully(stream, buffer, 0, chunk)) return result;
                    if (type == "IHDR" && !headRead && chunk >= 8)
                    {
                        uint width = Big32(buffer, 0), height = Big32(buffer, 4);
                        result.Width = width > Int32.MaxValue ? 0 : (int)width;
                        result.Height = height > Int32.MaxValue ? 0 : (int)height;
                        headRead = true;
                    }
                    for (int i = 0; i < chunk; i++) crc = CrcTable[(crc ^ buffer[i]) & 255] ^ (crc >> 8);
                    remaining -= (uint)chunk;
                }
                if (!ReadFully(stream, crcBytes, 0, 4)) return result;
                if ((crc ^ 0xffffffff) != Big32(crcBytes, 0)) { result.Detail = "Контрольная сумма блока PNG не совпадает."; return result; }
                if (type == "IDAT") hasIdat = true;
                if (type == "IEND") { result.HasEnd = count == 0 && hasIdat && result.Width > 0 && result.Height > 0; return result; }
                first = false;
            }
            return result;
        }

        static Probe TiffProbe(FileStream stream, byte[] header, CancellationToken cancel)
        {
            bool little = header[0] == 73;
            uint offset = little ? Little32(header, 4) : Big32(header, 4);
            var result = new Probe { Format = "TIFF" };
            if (offset < 8 || offset > stream.Length - 2) return result;
            stream.Position = offset;
            int a = stream.ReadByte(), b = stream.ReadByte();
            int entries = little ? a | b << 8 : a << 8 | b;
            if (entries > 1024 || stream.Position + entries * 12L > stream.Length) return result;
            byte[] entry = new byte[12];
            for (int i = 0; i < entries; i++)
            {
                cancel.ThrowIfCancellationRequested();
                if (!ReadFully(stream, entry, 0, 12)) return result;
                int tag = little ? entry[0] | entry[1] << 8 : entry[0] << 8 | entry[1];
                int type = little ? entry[2] | entry[3] << 8 : entry[2] << 8 | entry[3];
                uint count = little ? Little32(entry, 4) : Big32(entry, 4);
                if ((tag != 256 && tag != 257) || count != 1 || (type != 3 && type != 4)) continue;
                uint value = type == 3 ? (uint)(little ? entry[8] | entry[9] << 8 : entry[8] << 8 | entry[9]) : little ? Little32(entry, 8) : Big32(entry, 8);
                int dimension = value > Int32.MaxValue ? 0 : (int)value;
                if (tag == 256) result.Width = dimension; else result.Height = dimension;
            }
            return result;
        }

        static bool ReadFully(Stream stream, byte[] bytes, int offset, int count)
        {
            while (count > 0) { int read = stream.Read(bytes, offset, count); if (read == 0) return false; offset += read; count -= read; }
            return true;
        }
        static uint Little32(byte[] bytes, int offset) { return (uint)(bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16 | bytes[offset + 3] << 24); }
        static uint Big32(byte[] bytes, int offset) { return (uint)(bytes[offset] << 24 | bytes[offset + 1] << 16 | bytes[offset + 2] << 8 | bytes[offset + 3]); }
        static uint[] MakeCrcTable()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < table.Length; i++) { uint value = i; for (int bit = 0; bit < 8; bit++) value = (value & 1) == 1 ? 0xedb88320 ^ (value >> 1) : value >> 1; table[i] = value; }
            return table;
        }
        static string CaptureDate(Image image)
        {
            foreach (int id in new[] { 36867, 36868, 306 })
            {
                try
                {
                    string raw = Encoding.ASCII.GetString(image.GetPropertyItem(id).Value).Trim('\0', ' ', '\r', '\n');
                    DateTime date;
                    if (DateTime.TryParseExact(raw, "yyyy:MM:dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out date)) return date.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                }
                catch (ArgumentException) { }
            }
            return "";
        }
        static int StatusRank(string status) { return status == "decoded" ? 5 : status == "partial" ? 4 : status == "viewer" ? 3 : status == "limited" ? 2 : 1; }
        static void SourceHints(Item item)
        {
            if (!item.Path.StartsWith("filesystem/", StringComparison.OrdinalIgnoreCase)) return;
            if(item.Path.IndexOf("/orphan-",StringComparison.OrdinalIgnoreCase)>=0)item.Detail+=" Файл из не связанного с корнем каталога; исходный родитель и факт удаления неизвестны.";
            if (item.Path.IndexOf("/contiguous-guess/", StringComparison.OrdinalIgnoreCase) >= 0 || item.Path.IndexOf("/retained-fat-uncertain/", StringComparison.OrdinalIgnoreCase) >= 0)
                item.Detail += " Порядок фрагментов восстановлен предположительно по файловой системе; изображение может содержать чужие или перезаписанные данные.";
            if (item.Name.IndexOf("_PARTIAL_", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                if (item.Status == "decoded") item.Status = "partial";
                item.Detail += " Файловая система сообщила о неполном восстановлении; даже открывающееся изображение может быть лишь частью фотографии.";
            }
        }
        static int PathRank(string path) { return path.StartsWith("filesystem/", StringComparison.OrdinalIgnoreCase) ? 3 : path.StartsWith("ntfs/", StringComparison.OrdinalIgnoreCase) ? 2 : 1; }
        static Item Best(IEnumerable<Item> group)
        {
            var all = group.OrderByDescending(i => StatusRank(i.Status)).ThenByDescending(i => PathRank(i.Path)).ThenBy(i => i.Path, StringComparer.OrdinalIgnoreCase).ToList();
            Item best = all[0];
            best.Copies = all.Count;
            for (int i = 1; i < all.Count; i++) { best.OtherPaths.Add(all[i].Path); best.OtherUrls.Add(all[i].Url); }
            return best;
        }
        static string Url(string relative) { return String.Join("/", relative.Replace('\\', '/').Split('/').Select(part => Uri.EscapeDataString(part).Replace("'", "%27"))); }
        static string Csv(IEnumerable<Item> items)
        {
            var csv = new StringBuilder("\uFEFFПуть;Статус;Пояснение;Байт;Ширина;Высота;Дата съёмки EXIF;SHA256\r\n");
            foreach (Item item in items) csv.Append(String.Join(";", new[] { Cell(item.Path), Cell(item.Status), Cell(item.Detail), Cell(item.Bytes.ToString(CultureInfo.InvariantCulture)), Cell(item.Width.ToString(CultureInfo.InvariantCulture)), Cell(item.Height.ToString(CultureInfo.InvariantCulture)), Cell(item.Captured), Cell(item.Sha256) })).Append("\r\n");
            return csv.ToString();
        }
        static string Cell(string value)
        {
            value = value ?? "";
            if (value.Length > 0 && "=+-@\t\r\n".IndexOf(value[0]) >= 0) value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        static void WriteAtomic(string path, string content, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();
            if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Файл каталога не должен быть ссылкой.");
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temporary, content, new UTF8Encoding(false));
                cancel.ThrowIfCancellationRequested();
                if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }

        static string Html(string json, int candidates, int unique)
        {
            // Prevent a recovered filename from closing the script element. All visible strings use textContent.
            json = json.Replace("<", "\\u003c").Replace(">", "\\u003e").Replace("&", "\\u0026").Replace("\u2028", "\\u2028").Replace("\u2029", "\\u2029");
            return @"<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='Content-Security-Policy' content=""default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; object-src 'none'; connect-src 'none'""><title>Найденные фотографии</title><style>
*{box-sizing:border-box}body{font:16px system-ui,Segoe UI,sans-serif;margin:0;background:#f3f5fa;color:#182744}header,main{max-width:1250px;margin:auto;padding:24px}header{padding-bottom:12px}h1{font-size:28px;margin:0 0 10px}p{line-height:1.5;margin:10px 0}.muted,small{color:#56657e}.controls{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}.controls label{display:flex;flex-direction:column;gap:5px;font-size:13px}input,select,button{font:inherit;padding:9px;border:1px solid #bcc8dc;border-radius:8px;background:white;color:#182744}input[type=search]{min-width:260px}input[type=number]{width:130px}button{cursor:pointer}button:disabled{opacity:.4;cursor:default}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px}article{background:white;border-radius:12px;padding:12px;overflow:hidden;border:1px solid #dde4ef}img{width:100%;height:190px;object-fit:contain;background:#edf1f7;border-radius:7px}.placeholder{height:190px;display:flex;align-items:center;justify-content:center;text-align:center;background:#edf1f7;border-radius:7px;padding:14px;color:#56657e}a{color:#224dab;overflow-wrap:anywhere}article p{font-size:14px;margin:8px 0}article .name{font-weight:600;display:block;margin:10px 0 6px}.badge{display:inline-block;padding:4px 8px;border-radius:5px;background:#e5ecf7;font-size:12px}.decoded{background:#dff3e8;color:#236646}.partial{background:#fff0cd;color:#7e5808}.unreadable{background:#f8e3e3;color:#8b3d3d}nav{display:flex;gap:14px;align-items:center;justify-content:center;margin:24px 0}details{font-size:13px;margin-top:9px}details div{padding-top:7px}#empty{padding:25px;text-align:center}noscript{display:block;padding:24px;background:#fff0cd}@media(max-width:650px){header,main{padding:16px}.controls{flex-direction:column}.controls input,.controls select{width:100%}}
</style></head><body><header><h1>Найденные фотографии</h1><p>Проверено кандидатов: " + candidates + "; уникальных: " + unique + @". Одинаковые файлы объединены по SHA256 только в галерее: все копии сохранены в папках результатов.</p><p class='muted'>«Открывается» означает, что декодер прочитал изображение; это не гарантирует целостность всех пикселей и не доказывает, что файл был удалён. «Возможно неполный» — изображение читается, но структура JPEG/PNG повреждена. Дата съёмки берётся из EXIF, если она сохранилась; часовой пояс может быть неизвестен.</p><div class='controls'><label>Поиск по имени и пути<input id='query' type='search' placeholder='Например, бабушка или .jpg'></label><label>Состояние<select id='state'><option value='usable'>Открывающиеся и неполные</option><option value='all'>Все кандидаты</option><option value='decoded'>Открывается</option><option value='partial'>Возможно неполный</option><option value='viewer'>Нужен просмотрщик</option><option value='unreadable'>Не читается</option><option value='limited'>Превышен предел проверки</option></select></label><label>Не меньше по ширине<input id='minwidth' type='number' min='0' step='100' value='0'></label><label>Не меньше по высоте<input id='minheight' type='number' min='0' step='100' value='0'></label><label>Дата съёмки от<input id='datefrom' type='date'></label><label>Сортировка<select id='sort'><option value='quality'>Открывающиеся сначала</option><option value='pixels'>Большие фотографии сначала</option><option value='date'>Новые по EXIF сначала</option><option value='name'>Имя файла</option><option value='size'>Размер файла</option></select></label></div><p><a href='photo-catalog.csv'>Полный список CSV</a> · <a href='photo-catalog.json'>Каталог JSON</a></p><p id='summary' aria-live='polite'></p></header><main><noscript>Включите JavaScript для локальной галереи или откройте полный список CSV. Интернет не требуется.</noscript><nav><button id='prev'>Назад</button><span id='page'></span><button id='next'>Далее</button></nav><div id='grid' class='grid'></div><p id='empty' hidden>По этим условиям фотографий нет. Выберите «Все кандидаты» или уменьшите ограничения.</p><nav><button id='prevbottom'>Назад</button><span id='pagebottom'></span><button id='nextbottom'>Далее</button></nav></main><script>
'use strict';
var items=" + json + @",page=0,pageSize=100,filtered=[];
var labels={decoded:'Открывается',partial:'Возможно неполный',viewer:'Нужен просмотрщик',unreadable:'Не читается',limited:'Превышен предел проверки'};
var ranks={decoded:5,partial:4,viewer:3,limited:2,unreadable:1};
function el(tag,text,cls){var node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;}
function input(id){return document.getElementById(id);}
function link(url,text){var a=el('a',text);a.setAttribute('href',url);return a;}
function update(){var q=input('query').value.toLowerCase(),state=input('state').value,w=Math.max(0,Number(input('minwidth').value)||0),h=Math.max(0,Number(input('minheight').value)||0),from=input('datefrom').value,sort=input('sort').value;filtered=items.filter(function(i){var names=[i.Path].concat(i.OtherPaths).join(' ').toLowerCase();return(!q||names.indexOf(q)>=0)&&(state==='all'||(state==='usable'?(i.Status==='decoded'||i.Status==='partial'):i.Status===state))&&i.Width>=w&&i.Height>=h&&(!from||(i.Captured&&i.Captured.slice(0,10)>=from));});filtered.sort(function(a,b){if(sort==='pixels')return b.Width*b.Height-a.Width*a.Height;if(sort==='size')return b.Bytes-a.Bytes;if(sort==='date')return(b.Captured||'').localeCompare(a.Captured||'');if(sort==='name')return a.Name.localeCompare(b.Name);return(ranks[b.Status]||0)-(ranks[a.Status]||0)||b.Width*b.Height-a.Width*a.Height;});page=0;render();}
function render(){var grid=input('grid');while(grid.firstChild)grid.removeChild(grid.firstChild);var pages=Math.max(1,Math.ceil(filtered.length/pageSize));page=Math.max(0,Math.min(page,pages-1));filtered.slice(page*pageSize,(page+1)*pageSize).forEach(function(i){var card=el('article'),a=link(i.Url);if(i.Thumbnail){var img=el('img');img.setAttribute('src',i.Thumbnail);img.setAttribute('alt',i.Name);img.setAttribute('loading','lazy');a.appendChild(img);}else a.appendChild(el('div','Предпросмотр недоступен','placeholder'));card.appendChild(a);card.appendChild(link(i.Url,i.Name));card.lastChild.className='name';card.appendChild(el('span',labels[i.Status]||i.Status,'badge '+i.Status));card.appendChild(el('p',(i.Width&&i.Height?i.Width+' × '+i.Height+' · ':'')+(i.Bytes/1048576).toFixed(2)+' МиБ'+(i.Copies>1?' · копий: '+i.Copies:'')));if(i.Captured)card.appendChild(el('p','Съёмка: '+i.Captured));card.appendChild(el('p',i.Detail,'muted'));var paths=el('details');paths.appendChild(el('summary','Путь и все копии'));var row=el('div');row.appendChild(link(i.Url,i.Path));paths.appendChild(row);i.OtherPaths.forEach(function(p,j){var r=el('div');r.appendChild(link(i.OtherUrls[j],p));paths.appendChild(r);});card.appendChild(paths);grid.appendChild(card);});input('summary').textContent='По фильтру: '+filtered.length+' из '+items.length+'. Не больше 100 карточек на странице.';input('page').textContent=input('pagebottom').textContent='Страница '+(page+1)+' из '+pages;input('prev').disabled=input('prevbottom').disabled=page===0;input('next').disabled=input('nextbottom').disabled=page+1>=pages;input('empty').hidden=filtered.length!==0;}
['query','state','minwidth','minheight','datefrom','sort'].forEach(function(id){input(id).addEventListener(id==='query'?'input':'change',update);});['prev','prevbottom'].forEach(function(id){input(id).addEventListener('click',function(){page--;render();window.scrollTo(0,0);});});['next','nextbottom'].forEach(function(id){input(id).addEventListener('click',function(){page++;render();window.scrollTo(0,0);});});update();
</script></body></html>";
        }
    }
}
