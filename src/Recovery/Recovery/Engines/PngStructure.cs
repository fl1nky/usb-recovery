// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    // Byte-offset carving and the photo catalog must agree about the critical chunk sequence.
    // This checks the container and zlib header. The catalog separately decodes pixels.
    internal sealed class PngStructure
    {
        internal int Width, Height;
        internal long End = -1;
        internal string Detail = "Нарушена структура PNG или отсутствует корректный IEND.";
        int depth, color, zlibHeader;
        long compressedBytes;
        bool palette, idat, afterIdat;
        static readonly uint[] CrcTable = CreateCrcTable();

        internal static PngStructure Read(Stream source, long start, long limit, CancellationToken cancel)
        {
            var result = new PngStructure();
            source.Position = start + 8; // The caller verified the PNG signature.
            var header = new byte[8];
            var buffer = new byte[65536];
            var checksum = new byte[4];
            for (int index = 0; index < 100000 && limit - source.Position >= 12; index++)
            {
                cancel.ThrowIfCancellationRequested();
                if (!ReadFully(source, header, 8)) break;
                uint size = Big32(header);
                if (size > limit - source.Position - 4) break;
                for (int i = 4; i < 8; i++)
                    if (!(header[i] >= 'A' && header[i] <= 'Z' || header[i] >= 'a' && header[i] <= 'z')) return result;
                string type = Encoding.ASCII.GetString(header, 4, 4);
                if (!result.AcceptChunk(type, size, index)) break;
                uint crc = UpdateCrc(UInt32.MaxValue, header, 4, 4);
                uint left = size;
                while (left > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    int count = (int)Math.Min(left, (uint)buffer.Length);
                    if (!ReadFully(source, buffer, count)) return result;
                    if (type == "IHDR" && !result.AcceptHeader(buffer)) return result;
                    if (type == "IDAT" && !result.AcceptData(buffer, count)) return result;
                    crc = UpdateCrc(crc, buffer, 0, count);
                    left -= (uint)count;
                }
                if (!ReadFully(source, checksum, 4) || ~crc != Big32(checksum))
                {
                    result.Detail = "Контрольная сумма блока PNG не совпадает.";
                    break;
                }
                if (type == "IEND")
                {
                    result.End = source.Position;
                    result.Detail = "Порядок блоков, контрольные суммы и заголовок zlib проверены.";
                    break;
                }
            }
            return result;
        }

        bool AcceptChunk(string type, uint size, int index)
        {
            if (index == 0 || type == "IHDR") return index == 0 && type == "IHDR" && size == 13;
            if (type == "PLTE")
            {
                if (palette || idat || color == 0 || color == 4 || size == 0 || size > 768 || size % 3 != 0 ||
                    color == 3 && size / 3 > (1U << depth)) return false;
                palette = true;
                return true;
            }
            if (type == "IDAT")
            {
                if (afterIdat || color == 3 && !palette) return false;
                idat = true;
                return true;
            }
            if (type == "IEND") return size == 0 && idat && compressedBytes >= 8;
            if (idat) afterIdat = true;
            return type[0] >= 'a'; // An unknown ancillary chunk can be preserved opaquely.
        }

        bool AcceptHeader(byte[] raw)
        {
            uint width = Big32(raw), height = Big32(raw, 4);
            if (width == 0 || height == 0 || width > Int32.MaxValue || height > Int32.MaxValue) return false;
            Width = (int)width; Height = (int)height;
            depth = raw[8]; color = raw[9];
            if ((long)Width * Height > 100000000 || raw[10] != 0 || raw[11] != 0 || raw[12] > 1) return false;
            switch (color)
            {
                case 0: return depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16;
                case 2: case 4: case 6: return depth == 8 || depth == 16;
                case 3: return depth == 1 || depth == 2 || depth == 4 || depth == 8;
                default: return false;
            }
        }

        bool AcceptData(byte[] data, int count)
        {
            for (int i = 0; i < count && compressedBytes + i < 2; i++) zlibHeader = (zlibHeader << 8) | data[i];
            compressedBytes += count;
            return compressedBytes < 2 || (zlibHeader >> 8 & 15) == 8 && (zlibHeader >> 12) <= 7 &&
                (zlibHeader & 32) == 0 && zlibHeader % 31 == 0;
        }

        static uint Big32(byte[] bytes, int i = 0)
        {
            return (uint)(bytes[i] << 24 | bytes[i+1] << 16 | bytes[i+2] << 8 | bytes[i+3]);
        }

        static bool ReadFully(Stream stream, byte[] bytes, int count)
        {
            int done = 0;
            while (done < count)
            {
                int n = stream.Read(bytes, done, count - done);
                if (n == 0) return false;
                done += n;
            }
            return true;
        }

        static uint UpdateCrc(uint crc, byte[] bytes, int start, int count)
        {
            for (int i = start; i < start + count; i++) crc = CrcTable[(crc ^ bytes[i]) & 255] ^ (crc >> 8);
            return crc;
        }

        static uint[] CreateCrcTable()
        {
            var table = new uint[256];
            for (uint i = 0; i < table.Length; i++)
            {
                uint crc = i;
                for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? 0xedb88320 ^ (crc >> 1) : crc >> 1;
                table[i] = crc;
            }
            return table;
        }
    }
}
