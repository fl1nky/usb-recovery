using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // Finds complete JPEG/PNG streams at arbitrary byte offsets, including embedded thumbnails.
    // It does not infer missing fragments or manufacture missing image content.
    public static class ExtraPhotoSearch
    {
        const long MaximumPhoto = 128L * 1024 * 1024;
        static readonly byte[] PngSignature = { 137, 80, 78, 71, 13, 10, 26, 10 };
        static readonly uint[] CrcTable = CreateCrcTable();

        public static int Recover(string image, string runDirectory, CancellationToken cancel, Action<long, long> progress)
        {
            cancel.ThrowIfCancellationRequested();
            if (image.StartsWith(@"\\.\") || image.StartsWith(@"\\?\") || !File.Exists(image)) throw new IOException("Дополнительный поиск работает только с обычным файлом копии.");
            string output = Path.Combine(runDirectory, "extra-photos");
            var records = new List<object>();
            byte[] block = new byte[4 * 1024 * 1024 + 8];
            int carry = 0, found = 0;
            long position = 0;
            using (var scan = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 4 * 1024 * 1024))
            using (var parser = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024))
            {
                int read;
                while ((read = scan.Read(block, carry, block.Length - carry)) > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    int length = carry + read;
                    long blockStart = position - carry;
                    // Keep seven bytes so signatures crossing a read boundary are tested once.
                    int limit = scan.Position == scan.Length ? length : length - 7;
                    for (int i = 0; i < limit; i++)
                    {
                        if ((i & 65535) == 0) cancel.ThrowIfCancellationRequested();
                        bool jpeg = i + 2 < length && block[i] == 255 && block[i + 1] == 216 && block[i + 2] == 255;
                        bool png = i + 7 < length && IsPng(block, i);
                        if (!jpeg && !png) continue;
                        long offset = blockStart + i;
                        long end = jpeg ? JpegEnd(parser, offset, cancel) : PngEnd(parser, offset, cancel);
                        if (end <= offset) continue;
                        if (found >= 100000) throw new IOException("Дополнительный поиск достиг ограничения 100 000 изображений. Уже найденные файлы сохранены.");
                        Directory.CreateDirectory(output);
                        string name = "offset-" + offset.ToString("D16") + (jpeg ? ".jpg" : ".png");
                        string target = Path.Combine(output, name);
                        if (File.Exists(target)) continue;
                        CopyRange(parser, offset, end - offset, target, cancel);
                        records.Add(new { path = "extra-photos/" + name, offset = offset, size = end - offset, method = "byte-offset-structural", check = jpeg ? "JPEG markers and EOI" : "PNG chunks and CRC32" });
                        found++;
                    }
                    position += read;
                    carry = length - limit;
                    Buffer.BlockCopy(block, limit, block, 0, carry);
                    progress(scan.Position, scan.Length);
                }
            }
            cancel.ThrowIfCancellationRequested();
            File.WriteAllText(Path.Combine(runDirectory, "extra-photo-search.json"), new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Serialize(new { status = "complete", candidates = found, maximumFileBytes = MaximumPhoto, files = records }), new UTF8Encoding(false));
            return found;
        }

        static bool IsPng(byte[] data, int index)
        {
            for (int j = 0; j < PngSignature.Length; j++) if (data[index + j] != PngSignature[j]) return false;
            return true;
        }

        static long JpegEnd(FileStream stream, long start, CancellationToken cancel)
        {
            stream.Position = start + 2;
            long limit = Math.Min(stream.Length, start + MaximumPhoto);
            bool frame = false, scan = false;
            int pending = -1, markers = 0;
            while (stream.Position < limit && markers++ < 10000)
            {
                cancel.ThrowIfCancellationRequested();
                int marker;
                if (pending >= 0) { marker = pending; pending = -1; }
                else
                {
                    if (stream.ReadByte() != 255) return -1;
                    do { marker = stream.ReadByte(); } while (marker == 255 && stream.Position < limit);
                }
                if (marker < 0 || marker == 0 || marker == 216) return -1;
                if (marker == 217) return frame && scan ? stream.Position : -1;
                if (marker == 1 || (marker >= 208 && marker <= 215)) continue;
                if (marker < 192 || marker > 254) return -1;
                int high = stream.ReadByte(), low = stream.ReadByte();
                if (high < 0 || low < 0) return -1;
                int size = (high << 8) | low;
                if (size < 2 || stream.Position + size - 2 > limit) return -1;
                long next = stream.Position + size - 2;
                if (IsFrame(marker))
                {
                    if (size < 8) return -1;
                    int precision = stream.ReadByte(); int height = ReadBig16(stream), width = ReadBig16(stream);
                    if (precision <= 0 || precision > 16 || width <= 0 || height <= 0 || (long)width * height > 100000000L) return -1;
                    frame = true;
                }
                stream.Position = next;
                if (marker != 218) continue;
                if (!frame || size < 6) return -1;
                scan = true;
                while (stream.Position < limit)
                {
                    if ((stream.Position & 65535) == 0) cancel.ThrowIfCancellationRequested();
                    if (stream.ReadByte() != 255) continue;
                    int value;
                    do { value = stream.ReadByte(); } while (value == 255 && stream.Position < limit);
                    if (value < 0) return -1;
                    if (value == 0 || (value >= 208 && value <= 215)) continue;
                    if (value == 217) return stream.Position;
                    pending = value; break;
                }
                if (pending < 0) return -1;
            }
            return -1;
        }

        static bool IsFrame(int marker) { return marker >= 192 && marker <= 207 && marker != 196 && marker != 200 && marker != 204; }
        static int ReadBig16(Stream stream) { int a = stream.ReadByte(), b = stream.ReadByte(); return a < 0 || b < 0 ? -1 : (a << 8) | b; }
        static uint ReadBig32(byte[] bytes, int offset) { return ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3]; }

        static long PngEnd(FileStream stream, long start, CancellationToken cancel)
        {
            stream.Position = start + 8;
            long limit = Math.Min(stream.Length, start + MaximumPhoto);
            byte[] header = new byte[8], chunk = new byte[65536], expected = new byte[4];
            bool first = true, data = false;
            int chunks = 0;
            while (stream.Position + 12 <= limit && chunks++ < 100000)
            {
                cancel.ThrowIfCancellationRequested();
                if (!ReadExact(stream, header, 8)) return -1;
                uint length = ReadBig32(header, 0);
                if (length > MaximumPhoto || stream.Position + length + 4 > limit) return -1;
                for (int i = 4; i < 8; i++) if (!((header[i] >= 65 && header[i] <= 90) || (header[i] >= 97 && header[i] <= 122))) return -1;
                string type = Encoding.ASCII.GetString(header, 4, 4);
                if (first && (type != "IHDR" || length != 13)) return -1;
                if (!first && type == "IHDR") return -1;
                uint crc = 0xffffffff;
                for (int i = 4; i < 8; i++) crc = CrcTable[(crc ^ header[i]) & 255] ^ (crc >> 8);
                uint remaining = length;
                while (remaining > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    int count = (int)Math.Min((uint)chunk.Length, remaining);
                    if (!ReadExact(stream, chunk, count)) return -1;
                    if (first)
                    {
                        uint width = ReadBig32(chunk, 0), height = ReadBig32(chunk, 4);
                        if (width == 0 || height == 0 || (ulong)width * height > 100000000UL) return -1;
                    }
                    for (int i = 0; i < count; i++) crc = CrcTable[(crc ^ chunk[i]) & 255] ^ (crc >> 8);
                    remaining -= (uint)count;
                }
                if (!ReadExact(stream, expected, 4) || (crc ^ 0xffffffff) != ReadBig32(expected, 0)) return -1;
                first = false;
                if (type == "IDAT") data = true;
                if (type == "IEND") return length == 0 && data ? stream.Position : -1;
            }
            return -1;
        }

        static bool ReadExact(Stream stream, byte[] buffer, int length)
        {
            int total = 0;
            while (total < length) { int read = stream.Read(buffer, total, length - total); if (read == 0) return false; total += read; }
            return true;
        }
        static void CopyRange(FileStream source, long offset, long length, string target, CancellationToken cancel)
        {
            source.Position = offset;
            byte[] buffer = new byte[65536];
            string partial = target + "." + Guid.NewGuid().ToString("N") + ".partial";
            using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            {
                while (length > 0) { cancel.ThrowIfCancellationRequested(); int count = (int)Math.Min(length, buffer.Length); if (!ReadExact(source, buffer, count)) throw new IOException("Копия изменилась или оборвалась во время дополнительного поиска."); output.Write(buffer, 0, count); length -= count; }
                cancel.ThrowIfCancellationRequested(); output.Flush(true);
            }
            File.Move(partial, target);
        }
        static uint[] CreateCrcTable()
        {
            var table = new uint[256];
            for (uint n = 0; n < 256; n++) { uint c = n; for (int bit = 0; bit < 8; bit++) c = (c & 1) != 0 ? 0xedb88320 ^ (c >> 1) : c >> 1; table[n] = c; }
            return table;
        }
    }
}
