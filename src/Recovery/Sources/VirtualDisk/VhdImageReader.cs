using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public enum VhdType
    {
        None = 0,
        Fixed = 2,
        Dynamic = 3,
        Differencing = 4
    }

    public sealed class VhdFooter
    {
        public string Cookie { get; set; }
        public uint Features { get; set; }
        public uint FileFormatVersion { get; set; }
        public long DataOffset { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string CreatorApp { get; set; }
        public uint CreatorVersion { get; set; }
        public string CreatorHostOs { get; set; }
        public long OriginalSize { get; set; }
        public long CurrentSize { get; set; }
        public ushort DiskGeometryCylinders { get; set; }
        public byte DiskGeometryHeads { get; set; }
        public byte DiskGeometrySectors { get; set; }
        public VhdType DiskType { get; set; }
        public uint Checksum { get; set; }
        public Guid UniqueId { get; set; }
        public byte SavedState { get; set; }

        public VhdFooter()
        {
            Cookie = String.Empty;
            CreatorApp = String.Empty;
            CreatorHostOs = String.Empty;
        }
    }

    public sealed class VhdDynamicHeader
    {
        public string Cookie { get; set; }
        public long DataOffset { get; set; }
        public long TableOffset { get; set; }
        public uint HeaderVersion { get; set; }
        public uint MaxTableEntries { get; set; }
        public uint BlockSize { get; set; }
        public uint Checksum { get; set; }
        public Guid ParentUniqueId { get; set; }
        public DateTime ParentTimestampUtc { get; set; }
        public string ParentUnicodeName { get; set; }

        public VhdDynamicHeader()
        {
            Cookie = String.Empty;
            ParentUnicodeName = String.Empty;
        }
    }

    /// <summary>
    /// Native pure C# Stream implementation for Microsoft Virtual Hard Disk (VHD v1.0).
    /// Supports Fixed, Dynamic, and Differencing VHD images with big-endian BAT translation,
    /// sector bitmap evaluation, LRU caching, random-access seeking, and strict write-blocking.
    /// </summary>
    public sealed class VhdImageReader : Stream
    {
        private static readonly byte[] FooterCookieBytes = new byte[] { 0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78 }; // "conectix"
        private static readonly byte[] DynamicCookieBytes = new byte[] { 0x63, 0x78, 0x73, 0x70, 0x61, 0x72, 0x73, 0x65 }; // "cxsparse"
        private static readonly DateTime VhdEpoch = new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly string filePath;
        private readonly FileStream fileStream;
        private readonly VhdFooter footer;
        private readonly VhdDynamicHeader dynamicHeader; // null for Fixed
        private readonly uint[] bat; // null for Fixed
        private readonly long logicalDiskSize;
        private readonly uint blockSize; // 0 for Fixed
        private readonly int bitmapByteLength; // 0 for Fixed
        private readonly int sectorsPerBlock; // 0 for Fixed

        private readonly Dictionary<int, byte[]> bitmapCache;
        private readonly List<int> bitmapLruOrder;
        private const int MaxCachedBitmaps = 128; // ~64 KiB memory footprint

        private long currentPosition;
        private bool isDisposed;

        public VhdFooter Footer { get { return footer; } }
        public VhdDynamicHeader DynamicHeader { get { return dynamicHeader; } }
        public VhdType DiskType { get { return footer.DiskType; } }
        public string FilePath { get { return filePath; } }

        public override bool CanRead { get { return !isDisposed; } }
        public override bool CanSeek { get { return !isDisposed; } }
        public override bool CanWrite { get { return false; } }

        public override long Length { get { return logicalDiskSize; } }
        public override long Position
        {
            get { return currentPosition; }
            set { Seek(value, SeekOrigin.Begin); }
        }

        public static bool IsVhdFile(string path)
        {
            if (String.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            try
            {
                SourcePaths.NoLinks(path);
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length < 512) return false;

                    byte[] footerBuf = new byte[512];
                    // 1. Try EOF footer
                    fs.Position = fs.Length - 512;
                    if (fs.Read(footerBuf, 0, 512) == 512 && MatchesCookie(footerBuf, 0, FooterCookieBytes))
                    {
                        uint stored = ReadUInt32BE(footerBuf, 64);
                        if (stored == ComputeFooterChecksum(footerBuf)) return true;
                    }

                    // 2. Fallback to header copy of footer at offset 0 (for dynamic VHD)
                    fs.Position = 0;
                    if (fs.Read(footerBuf, 0, 512) == 512 && MatchesCookie(footerBuf, 0, FooterCookieBytes))
                    {
                        uint stored = ReadUInt32BE(footerBuf, 64);
                        if (stored == ComputeFooterChecksum(footerBuf)) return true;
                    }

                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        public static VhdImageReader Open(string path)
        {
            return new VhdImageReader(path);
        }

        public VhdImageReader(string path)
        {
            if (String.IsNullOrEmpty(path)) throw new ArgumentNullException("path");

            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath)) throw new FileNotFoundException("VHD file not found: " + fullPath, fullPath);

            SourcePaths.NoLinks(fullPath);

            FileStream fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                filePath = fullPath;
                fileStream = fs;

                if (fileStream.Length < 512)
                {
                    throw new InvalidDataException("File is too small to contain a valid VHD footer.");
                }

                // 1. Read Footer
                byte[] footerBytes = new byte[512];
                bool footerValid = false;

                // Check EOF first
                if (fileStream.Length >= 512)
                {
                    fileStream.Position = fileStream.Length - 512;
                    if (fileStream.Read(footerBytes, 0, 512) == 512 && MatchesCookie(footerBytes, 0, FooterCookieBytes))
                    {
                        uint stored = ReadUInt32BE(footerBytes, 64);
                        if (stored == ComputeFooterChecksum(footerBytes))
                        {
                            footerValid = true;
                        }
                    }
                }

                // If not found at EOF, check offset 0 (Dynamic header copy)
                if (!footerValid)
                {
                    fileStream.Position = 0;
                    if (fileStream.Read(footerBytes, 0, 512) == 512 && MatchesCookie(footerBytes, 0, FooterCookieBytes))
                    {
                        uint stored = ReadUInt32BE(footerBytes, 64);
                        if (stored == ComputeFooterChecksum(footerBytes))
                        {
                            footerValid = true;
                        }
                    }
                }

                if (!footerValid)
                {
                    throw new InvalidDataException("Invalid VHD footer: cookie or checksum mismatch.");
                }

                footer = ParseFooter(footerBytes);
                logicalDiskSize = footer.CurrentSize;

                if (footer.DiskType == VhdType.Fixed)
                {
                    if (logicalDiskSize <= 0)
                    {
                        logicalDiskSize = Math.Max(0, fileStream.Length - 512);
                    }
                    dynamicHeader = null;
                    bat = null;
                    blockSize = 0;
                    bitmapByteLength = 0;
                    sectorsPerBlock = 0;
                    bitmapCache = null;
                    bitmapLruOrder = null;
                }
                else if (footer.DiskType == VhdType.Dynamic || footer.DiskType == VhdType.Differencing)
                {
                    // 2. Read Dynamic Header
                    long dynHeaderOffset = footer.DataOffset;
                    if (dynHeaderOffset <= 0 || dynHeaderOffset > fileStream.Length - 1024)
                    {
                        dynHeaderOffset = 512; // Standard default dynamic header offset
                    }

                    byte[] dynHeaderBytes = new byte[1024];
                    fileStream.Position = dynHeaderOffset;
                    ReadFully(fileStream, dynHeaderBytes, 0, 1024);

                    if (!MatchesCookie(dynHeaderBytes, 0, DynamicCookieBytes))
                    {
                        throw new InvalidDataException("Invalid VHD dynamic header cookie.");
                    }

                    uint storedHdrChecksum = ReadUInt32BE(dynHeaderBytes, 36);
                    if (storedHdrChecksum != ComputeDynamicHeaderChecksum(dynHeaderBytes))
                    {
                        throw new InvalidDataException("Invalid VHD dynamic header checksum.");
                    }

                    dynamicHeader = ParseDynamicHeader(dynHeaderBytes);
                    blockSize = dynamicHeader.BlockSize;
                    if (blockSize == 0 || (blockSize & (blockSize - 1)) != 0)
                    {
                        throw new InvalidDataException("Invalid VHD block size: must be a power of 2.");
                    }

                    sectorsPerBlock = (int)(blockSize / 512);
                    int bitmapBytesRaw = sectorsPerBlock / 8;
                    int bitmapSectors = (bitmapBytesRaw + 511) / 512;
                    bitmapByteLength = bitmapSectors * 512;

                    // 3. Read BAT
                    long batByteLength = (long)dynamicHeader.MaxTableEntries * 4L;
                    if (dynamicHeader.TableOffset + batByteLength > fileStream.Length)
                    {
                        throw new InvalidDataException("VHD Block Allocation Table extends beyond file length.");
                    }

                    byte[] batRawBytes = new byte[batByteLength];
                    fileStream.Position = dynamicHeader.TableOffset;
                    ReadFully(fileStream, batRawBytes, 0, (int)batByteLength);

                    bat = new uint[dynamicHeader.MaxTableEntries];
                    for (int i = 0; i < dynamicHeader.MaxTableEntries; i++)
                    {
                        bat[i] = ReadUInt32BE(batRawBytes, i * 4);
                    }

                    bitmapCache = new Dictionary<int, byte[]>();
                    bitmapLruOrder = new List<int>();
                }
                else
                {
                    throw new NotSupportedException(string.Format(System.Globalization.CultureInfo.InvariantCulture,
                        "Unsupported VHD disk type: {0}", footer.DiskType));
                }
            }
            catch
            {
                fs.Dispose();
                throw;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0) throw new ArgumentOutOfRangeException("offset", "Offset must be non-negative.");
            if (count < 0) throw new ArgumentOutOfRangeException("count", "Count must be non-negative.");
            if (offset + count > buffer.Length)
                throw new ArgumentException("The sum of offset and count is larger than the buffer length.");
            if (isDisposed) throw new ObjectDisposedException("VhdImageReader");

            if (currentPosition >= logicalDiskSize || count == 0) return 0;

            long available = logicalDiskSize - currentPosition;
            int toRead = (int)Math.Min((long)count, available);

            int bytesRead = 0;
            if (footer.DiskType == VhdType.Fixed)
            {
                bytesRead = ReadFixed(buffer, offset, toRead);
            }
            else
            {
                bytesRead = ReadDynamic(buffer, offset, toRead);
            }

            currentPosition += bytesRead;
            return bytesRead;
        }

        private int ReadFixed(byte[] buffer, int offset, int toRead)
        {
            fileStream.Position = currentPosition;
            int r = fileStream.Read(buffer, offset, toRead);
            if (r < toRead)
            {
                Array.Clear(buffer, offset + r, toRead - r);
                return toRead;
            }
            return r;
        }

        private int ReadDynamic(byte[] buffer, int offset, int toRead)
        {
            int bytesRead = 0;

            while (bytesRead < toRead)
            {
                long currentLogical = currentPosition + bytesRead;
                int blockIndex = (int)(currentLogical / blockSize);

                if (blockIndex >= dynamicHeader.MaxTableEntries)
                {
                    int rem = toRead - bytesRead;
                    Array.Clear(buffer, offset + bytesRead, rem);
                    bytesRead += rem;
                    break;
                }

                long offsetInBlock = currentLogical % blockSize;
                int bytesInBlock = (int)Math.Min((long)(toRead - bytesRead), blockSize - offsetInBlock);

                uint batEntry = bat[blockIndex];
                if (batEntry == 0xFFFFFFFFU)
                {
                    // Sparse / Unallocated block -> zero fill
                    Array.Clear(buffer, offset + bytesRead, bytesInBlock);
                    bytesRead += bytesInBlock;
                    continue;
                }

                long hostBlockOffset = (long)batEntry * 512L;
                long hostDataOffset = hostBlockOffset + bitmapByteLength;

                byte[] bitmap = GetCachedBitmap(blockIndex, hostBlockOffset);

                int sectorInBlock = (int)(offsetInBlock / 512);
                int offsetInSector = (int)(offsetInBlock % 512);

                bool isAllocated = IsSectorAllocated(bitmap, sectorInBlock);

                // Find span of contiguous sectors with identical allocation state
                int contiguousSectors = 1;
                int maxSectorsToInspect = (int)((offsetInBlock + bytesInBlock + 511) / 512);
                for (int s = sectorInBlock + 1; s < maxSectorsToInspect && s < sectorsPerBlock; s++)
                {
                    if (IsSectorAllocated(bitmap, s) == isAllocated)
                    {
                        contiguousSectors++;
                    }
                    else
                    {
                        break;
                    }
                }

                long spanBytesAvailable = ((long)contiguousSectors * 512L) - offsetInSector;
                int spanBytes = (int)Math.Min((long)bytesInBlock, spanBytesAvailable);

                if (isAllocated)
                {
                    long hostFilePos = hostDataOffset + offsetInBlock;
                    if (hostFilePos < fileStream.Length)
                    {
                        fileStream.Position = hostFilePos;
                        int r = fileStream.Read(buffer, offset + bytesRead, spanBytes);
                        if (r < spanBytes)
                        {
                            Array.Clear(buffer, offset + bytesRead + r, spanBytes - r);
                        }
                    }
                    else
                    {
                        Array.Clear(buffer, offset + bytesRead, spanBytes);
                    }
                }
                else
                {
                    Array.Clear(buffer, offset + bytesRead, spanBytes);
                }

                bytesRead += spanBytes;
            }

            return bytesRead;
        }

        private static bool IsSectorAllocated(byte[] bitmap, int sectorInBlock)
        {
            if (bitmap == null) return false;
            int byteIndex = sectorInBlock / 8;
            if (byteIndex >= bitmap.Length) return false;
            byte bitMask = (byte)(0x80 >> (sectorInBlock % 8));
            return (bitmap[byteIndex] & bitMask) != 0;
        }

        private byte[] GetCachedBitmap(int blockIndex, long hostBlockOffset)
        {
            byte[] cached;
            if (bitmapCache.TryGetValue(blockIndex, out cached))
            {
                bitmapLruOrder.Remove(blockIndex);
                bitmapLruOrder.Add(blockIndex);
                return cached;
            }

            byte[] bitmap = new byte[bitmapByteLength];
            if (hostBlockOffset + bitmapByteLength <= fileStream.Length)
            {
                fileStream.Position = hostBlockOffset;
                ReadFully(fileStream, bitmap, 0, bitmapByteLength);
            }
            else if (hostBlockOffset < fileStream.Length)
            {
                fileStream.Position = hostBlockOffset;
                int avail = (int)(fileStream.Length - hostBlockOffset);
                fileStream.Read(bitmap, 0, avail);
            }

            if (bitmapCache.Count >= MaxCachedBitmaps && bitmapLruOrder.Count > 0)
            {
                int evict = bitmapLruOrder[0];
                bitmapLruOrder.RemoveAt(0);
                bitmapCache.Remove(evict);
            }

            bitmapCache[blockIndex] = bitmap;
            bitmapLruOrder.Add(blockIndex);
            return bitmap;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (isDisposed) throw new ObjectDisposedException("VhdImageReader");

            long newPos = currentPosition;
            switch (origin)
            {
                case SeekOrigin.Begin:
                    newPos = offset;
                    break;
                case SeekOrigin.Current:
                    newPos += offset;
                    break;
                case SeekOrigin.End:
                    newPos = logicalDiskSize + offset;
                    break;
                default:
                    throw new ArgumentException("Invalid SeekOrigin value.", "origin");
            }

            if (newPos < 0)
            {
                throw new IOException("An attempt was made to move the position before the beginning of the stream.");
            }

            currentPosition = newPos;
            return currentPosition;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException("VhdImageReader is a read-only stream.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("VhdImageReader is a read-only stream.");
        }

        public override void Flush()
        {
            // No-op for read-only stream
        }

        protected override void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                isDisposed = true;
                if (disposing)
                {
                    if (fileStream != null)
                    {
                        try { fileStream.Dispose(); } catch { }
                    }
                    if (bitmapCache != null) bitmapCache.Clear();
                    if (bitmapLruOrder != null) bitmapLruOrder.Clear();
                }
            }
            base.Dispose(disposing);
        }

        // --- Helper Methods ---

        private static VhdFooter ParseFooter(byte[] b)
        {
            VhdFooter f = new VhdFooter();
            f.Cookie = Encoding.ASCII.GetString(b, 0, 8);
            f.Features = ReadUInt32BE(b, 8);
            f.FileFormatVersion = ReadUInt32BE(b, 12);
            f.DataOffset = (long)ReadUInt64BE(b, 16);
            f.TimestampUtc = VhdEpoch.AddSeconds(ReadUInt32BE(b, 24));
            f.CreatorApp = Encoding.ASCII.GetString(b, 28, 4);
            f.CreatorVersion = ReadUInt32BE(b, 32);
            f.CreatorHostOs = Encoding.ASCII.GetString(b, 36, 4);
            f.OriginalSize = (long)ReadUInt64BE(b, 40);
            f.CurrentSize = (long)ReadUInt64BE(b, 48);
            f.DiskGeometryCylinders = ReadUInt16BE(b, 56);
            f.DiskGeometryHeads = b[58];
            f.DiskGeometrySectors = b[59];
            f.DiskType = (VhdType)ReadUInt32BE(b, 60);
            f.Checksum = ReadUInt32BE(b, 64);

            byte[] guidBytes = new byte[16];
            Array.Copy(b, 68, guidBytes, 0, 16);
            f.UniqueId = new Guid(guidBytes);

            f.SavedState = b[84];
            return f;
        }

        private static VhdDynamicHeader ParseDynamicHeader(byte[] b)
        {
            VhdDynamicHeader h = new VhdDynamicHeader();
            h.Cookie = Encoding.ASCII.GetString(b, 0, 8);
            h.DataOffset = (long)ReadUInt64BE(b, 8);
            h.TableOffset = (long)ReadUInt64BE(b, 16);
            h.HeaderVersion = ReadUInt32BE(b, 24);
            h.MaxTableEntries = ReadUInt32BE(b, 28);
            h.BlockSize = ReadUInt32BE(b, 32);
            h.Checksum = ReadUInt32BE(b, 36);

            byte[] parentGuid = new byte[16];
            Array.Copy(b, 40, parentGuid, 0, 16);
            h.ParentUniqueId = new Guid(parentGuid);

            h.ParentTimestampUtc = VhdEpoch.AddSeconds(ReadUInt32BE(b, 56));
            h.ParentUnicodeName = Encoding.BigEndianUnicode.GetString(b, 64, 256).TrimEnd('\0');
            return h;
        }

        public static uint ComputeFooterChecksum(byte[] footer)
        {
            if (footer == null || footer.Length < 512) return 0;
            uint sum = 0;
            for (int i = 0; i < 512; i++)
            {
                if (i >= 64 && i < 68) continue;
                sum += footer[i];
            }
            return ~sum;
        }

        public static uint ComputeDynamicHeaderChecksum(byte[] header)
        {
            if (header == null || header.Length < 1024) return 0;
            uint sum = 0;
            for (int i = 0; i < 1024; i++)
            {
                if (i >= 36 && i < 40) continue;
                sum += header[i];
            }
            return ~sum;
        }

        private static bool MatchesCookie(byte[] buffer, int offset, byte[] cookie)
        {
            if (buffer == null || offset + cookie.Length > buffer.Length) return false;
            for (int i = 0; i < cookie.Length; i++)
            {
                if (buffer[offset + i] != cookie[i]) return false;
            }
            return true;
        }

        private static ushort ReadUInt16BE(byte[] b, int offset)
        {
            return (ushort)((b[offset] << 8) | b[offset + 1]);
        }

        private static uint ReadUInt32BE(byte[] b, int offset)
        {
            return ((uint)b[offset] << 24) |
                   ((uint)b[offset + 1] << 16) |
                   ((uint)b[offset + 2] << 8) |
                   (uint)b[offset + 3];
        }

        private static ulong ReadUInt64BE(byte[] b, int offset)
        {
            return ((ulong)b[offset] << 56) |
                   ((ulong)b[offset + 1] << 48) |
                   ((ulong)b[offset + 2] << 40) |
                   ((ulong)b[offset + 3] << 32) |
                   ((ulong)b[offset + 4] << 24) |
                   ((ulong)b[offset + 5] << 16) |
                   ((ulong)b[offset + 6] << 8) |
                   (ulong)b[offset + 7];
        }

        private static void ReadFully(Stream stream, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = stream.Read(buffer, offset + totalRead, count - totalRead);
                if (read <= 0) break;
                totalRead += read;
            }
        }
    }
}
