using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace UsbRecovery
{
    public sealed class Qcow2Header
    {
        public uint Magic { get; set; }
        public uint Version { get; set; }
        public ulong BackingFileOffset { get; set; }
        public uint BackingFileSize { get; set; }
        public uint ClusterBits { get; set; }
        public ulong VirtualDiskSize { get; set; }
        public uint CryptMethod { get; set; }
        public uint L1Size { get; set; }
        public ulong L1TableOffset { get; set; }
        public ulong RefcountTableOffset { get; set; }
        public uint RefcountTableClusters { get; set; }
        public uint NumberOfSnapshots { get; set; }
        public ulong SnapshotsOffset { get; set; }

        // Version 3 specific fields
        public ulong IncompatibleFeatures { get; set; }
        public ulong CompatibleFeatures { get; set; }
        public ulong AutoclearFeatures { get; set; }
        public uint RefcountOrder { get; set; }
        public uint HeaderLength { get; set; }

        public string BackingFilePath { get; set; }

        public uint ClusterSize
        {
            get { return 1U << (int)ClusterBits; }
        }

        public bool IsDirty
        {
            get { return Version >= 3 && (IncompatibleFeatures & 0x1) != 0; }
        }

        public bool IsCorrupt
        {
            get { return Version >= 3 && (IncompatibleFeatures & 0x2) != 0; }
        }

        public bool HasExternalDataFile
        {
            get { return Version >= 3 && (IncompatibleFeatures & 0x4) != 0; }
        }

        public Qcow2Header()
        {
            BackingFilePath = String.Empty;
        }
    }

    /// <summary>
    /// Native pure C# Stream implementation for QEMU Copy-On-Write version 2 and 3 virtual disk images (QCOW2).
    /// Supports two-level L1/L2 address translation, sparse/unallocated clusters, zlib-compressed clusters,
    /// v3 zero cluster flags, write-blocking, LRU caching, and random-access seeking.
    /// </summary>
    public sealed class Qcow2ImageReader : Stream
    {
        public const uint Qcow2Magic = 0x514649FB; // 'Q', 'F', 'I', 0xFB
        private static readonly byte[] MagicBytes = new byte[] { 0x51, 0x46, 0x49, 0xFB };

        private readonly string filePath;
        private readonly Stream sourceStream;
        private readonly bool leaveOpen;
        private readonly Qcow2Header header;
        private readonly ulong[] l1Table;
        private readonly uint clusterSize;
        private readonly int clusterBits;
        private readonly int l2EntriesPerCluster;
        private readonly int l2Bits;

        // Caches for high-performance seeking and reading
        private readonly Dictionary<ulong, ulong[]> l2Cache;
        private readonly List<ulong> l2LruOrder;
        private const int MaxCachedL2Tables = 128;

        private readonly Dictionary<long, byte[]> compressedClusterCache;
        private readonly List<long> compressedLruOrder;
        private const int MaxCachedCompressedClusters = 64;

        private long currentPosition;
        private bool isDisposed;

        public Qcow2Header Header { get { return header; } }
        public string FilePath { get { return filePath; } }
        public uint ClusterSize { get { return clusterSize; } }

        public override bool CanRead { get { return !isDisposed; } }
        public override bool CanSeek { get { return !isDisposed; } }
        public override bool CanWrite { get { return false; } }

        public override long Length
        {
            get
            {
                ThrowIfDisposed();
                return (long)header.VirtualDiskSize;
            }
        }

        public override long Position
        {
            get
            {
                ThrowIfDisposed();
                return currentPosition;
            }
            set
            {
                Seek(value, SeekOrigin.Begin);
            }
        }

        public static bool IsQcow2File(string path)
        {
            if (String.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length < 72) return false;
                    byte[] headerBuf = new byte[4];
                    if (fs.Read(headerBuf, 0, 4) < 4) return false;
                    return IsQcow2Signature(headerBuf);
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool IsQcow2Signature(byte[] buffer)
        {
            if (buffer == null || buffer.Length < 4) return false;
            return buffer[0] == MagicBytes[0] &&
                   buffer[1] == MagicBytes[1] &&
                   buffer[2] == MagicBytes[2] &&
                   buffer[3] == MagicBytes[3];
        }

        public static Qcow2ImageReader Open(string path)
        {
            if (path == null) throw new ArgumentNullException("path");
            if (!File.Exists(path)) throw new FileNotFoundException("QCOW2 image not found: " + path, path);

            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            try
            {
                return new Qcow2ImageReader(fs, path, false);
            }
            catch
            {
                fs.Dispose();
                throw;
            }
        }

        public static Qcow2ImageReader Open(Stream stream, bool leaveOpen = false)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            return new Qcow2ImageReader(stream, null, leaveOpen);
        }

        public Qcow2ImageReader(Stream stream, string filePath, bool leaveOpen)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead || !stream.CanSeek)
            {
                throw new ArgumentException("Source stream must support reading and seeking.", "stream");
            }

            this.sourceStream = stream;
            this.filePath = filePath ?? String.Empty;
            this.leaveOpen = leaveOpen;
            this.currentPosition = 0;

            this.l2Cache = new Dictionary<ulong, ulong[]>();
            this.l2LruOrder = new List<ulong>();
            this.compressedClusterCache = new Dictionary<long, byte[]>();
            this.compressedLruOrder = new List<long>();

            this.header = ParseHeader(sourceStream);

            this.clusterBits = (int)header.ClusterBits;
            this.clusterSize = 1U << clusterBits;
            this.l2EntriesPerCluster = (int)(clusterSize / 8);
            this.l2Bits = clusterBits - 3;

            this.l1Table = ReadL1Table(sourceStream, header);
        }

        private static Qcow2Header ParseHeader(Stream stream)
        {
            if (stream.Length < 72)
            {
                throw new InvalidDataException("Stream is too short to contain a valid QCOW2 header.");
            }

            stream.Seek(0, SeekOrigin.Begin);
            byte[] buf = new byte[104];
            int read = stream.Read(buf, 0, buf.Length);
            if (read < 72)
            {
                throw new InvalidDataException("Failed to read QCOW2 header.");
            }

            uint magic = ReadUInt32BE(buf, 0);
            if (magic != Qcow2Magic)
            {
                throw new InvalidDataException(string.Format(CultureInfo.InvariantCulture,
                    "Invalid QCOW2 magic 0x{0:X8}, expected 0x{1:X8}.", magic, Qcow2Magic));
            }

            uint version = ReadUInt32BE(buf, 4);
            if (version != 2 && version != 3)
            {
                throw new NotSupportedException(string.Format(CultureInfo.InvariantCulture,
                    "Unsupported QCOW2 version {0}. Only version 2 and 3 are supported.", version));
            }

            Qcow2Header h = new Qcow2Header();
            h.Magic = magic;
            h.Version = version;
            h.BackingFileOffset = ReadUInt64BE(buf, 8);
            h.BackingFileSize = ReadUInt32BE(buf, 16);
            h.ClusterBits = ReadUInt32BE(buf, 20);
            h.VirtualDiskSize = ReadUInt64BE(buf, 24);
            h.CryptMethod = ReadUInt32BE(buf, 32);
            h.L1Size = ReadUInt32BE(buf, 36);
            h.L1TableOffset = ReadUInt64BE(buf, 40);
            h.RefcountTableOffset = ReadUInt64BE(buf, 48);
            h.RefcountTableClusters = ReadUInt32BE(buf, 56);
            h.NumberOfSnapshots = ReadUInt32BE(buf, 60);
            h.SnapshotsOffset = ReadUInt64BE(buf, 64);

            if (h.ClusterBits < 9 || h.ClusterBits > 21)
            {
                throw new InvalidDataException(string.Format(CultureInfo.InvariantCulture,
                    "Invalid cluster_bits {0}. Must be between 9 (512 B) and 21 (2 MB).", h.ClusterBits));
            }

            if (h.CryptMethod != 0)
            {
                throw new NotSupportedException(string.Format(CultureInfo.InvariantCulture,
                    "Encrypted QCOW2 images (crypt_method {0}) are not supported.", h.CryptMethod));
            }

            if (version >= 3 && read >= 104)
            {
                h.IncompatibleFeatures = ReadUInt64BE(buf, 72);
                h.CompatibleFeatures = ReadUInt64BE(buf, 80);
                h.AutoclearFeatures = ReadUInt64BE(buf, 88);
                h.RefcountOrder = ReadUInt32BE(buf, 96);
                h.HeaderLength = ReadUInt32BE(buf, 100);

                if (h.HasExternalDataFile)
                {
                    throw new NotSupportedException("QCOW2 with external data file is not supported.");
                }
            }

            if (h.BackingFileOffset > 0 && h.BackingFileSize > 0 && h.BackingFileSize < 4096)
            {
                if (h.BackingFileOffset + h.BackingFileSize <= (ulong)stream.Length)
                {
                    byte[] backingBuf = new byte[h.BackingFileSize];
                    stream.Seek((long)h.BackingFileOffset, SeekOrigin.Begin);
                    if (stream.Read(backingBuf, 0, backingBuf.Length) == backingBuf.Length)
                    {
                        h.BackingFilePath = Encoding.UTF8.GetString(backingBuf);
                    }
                }
            }

            return h;
        }

        private static ulong[] ReadL1Table(Stream stream, Qcow2Header header)
        {
            if (header.L1Size == 0) return new ulong[0];
            if (header.L1Size > 1000000)
            {
                throw new InvalidDataException("L1 table size exceeds 1,000,000 entries.");
            }

            int byteLength = (int)(header.L1Size * 8);
            byte[] buf = new byte[byteLength];
            stream.Seek((long)header.L1TableOffset, SeekOrigin.Begin);
            int read = stream.Read(buf, 0, byteLength);
            if (read < byteLength)
            {
                throw new InvalidDataException("Unexpected end of stream while reading L1 table.");
            }

            ulong[] l1 = new ulong[header.L1Size];
            for (int i = 0; i < (int)header.L1Size; i++)
            {
                l1[i] = ReadUInt64BE(buf, i * 8);
            }
            return l1;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ThrowIfDisposed();
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0 || count < 0 || offset + count > buffer.Length) throw new ArgumentOutOfRangeException();
            if (count == 0 || currentPosition >= (long)header.VirtualDiskSize) return 0;

            long remainingDisk = (long)header.VirtualDiskSize - currentPosition;
            int toRead = (int)Math.Min(count, remainingDisk);
            int totalBytesRead = 0;

            while (totalBytesRead < toRead)
            {
                long pos = currentPosition;
                long clusterOffset = pos & (clusterSize - 1);
                long bytesInThisCluster = Math.Min(clusterSize - clusterOffset, toRead - totalBytesRead);

                int l2Index = (int)((pos >> clusterBits) & (l2EntriesPerCluster - 1));
                int l1Index = (int)(pos >> (clusterBits + l2Bits));

                if (l1Index >= l1Table.Length)
                {
                    // Past L1 table bounds: fill zeros
                    Array.Clear(buffer, offset + totalBytesRead, (int)bytesInThisCluster);
                }
                else
                {
                    ulong l1Entry = l1Table[l1Index];
                    ulong l2Offset = l1Entry & 0x00FFFFFFFFFFFF00UL;

                    if (l2Offset == 0)
                    {
                        // Unallocated L2 table: sparse
                        Array.Clear(buffer, offset + totalBytesRead, (int)bytesInThisCluster);
                    }
                    else
                    {
                        ulong[] l2Table = GetOrLoadL2Table(l2Offset);
                        ulong l2Entry = (l2Index < l2Table.Length) ? l2Table[l2Index] : 0UL;

                        ReadClusterData(l2Entry, clusterOffset, buffer, offset + totalBytesRead, (int)bytesInThisCluster);
                    }
                }

                currentPosition += bytesInThisCluster;
                totalBytesRead += (int)bytesInThisCluster;
            }

            return totalBytesRead;
        }

        private void ReadClusterData(ulong l2Entry, long clusterOffset, byte[] targetBuffer, int targetOffset, int count)
        {
            if (l2Entry == 0)
            {
                // Sparse cluster: zeros
                Array.Clear(targetBuffer, targetOffset, count);
                return;
            }

            // Version 3: bit 0 indicates zero cluster
            if (header.Version >= 3 && (l2Entry & 0x1UL) != 0)
            {
                Array.Clear(targetBuffer, targetOffset, count);
                return;
            }

            // Bit 62: Compressed cluster
            bool isCompressed = (l2Entry & (1UL << 62)) != 0;
            if (isCompressed)
            {
                ReadCompressedCluster(l2Entry, clusterOffset, targetBuffer, targetOffset, count);
                return;
            }

            // Standard cluster: bits 9..55 contain host offset
            ulong hostClusterOffset = l2Entry & 0x00FFFFFFFFFFFF00UL;
            if (hostClusterOffset == 0)
            {
                Array.Clear(targetBuffer, targetOffset, count);
                return;
            }

            long readPos = (long)hostClusterOffset + clusterOffset;
            sourceStream.Seek(readPos, SeekOrigin.Begin);
            int read = sourceStream.Read(targetBuffer, targetOffset, count);
            if (read < count)
            {
                Array.Clear(targetBuffer, targetOffset + read, count - read);
            }
        }

        private void ReadCompressedCluster(ulong l2Entry, long clusterOffset, byte[] targetBuffer, int targetOffset, int count)
        {
            byte[] cached;
            long entryKey = (long)(l2Entry & 0x3FFFFFFFFFFFFFFFUL);

            if (!compressedClusterCache.TryGetValue(entryKey, out cached))
            {
                // Compute compressed parameters
                // Bit 62 is compressed flag
                // Next (cluster_bits - 8) bits: sector count minus 1
                // Remaining bits: host offset
                int csizeShift = 62 - (clusterBits - 8);
                ulong csizeMask = (1UL << (clusterBits - 8)) - 1UL;
                int nbSectors = (int)((l2Entry >> csizeShift) & csizeMask) + 1;
                long hostOffsetMask = (1L << csizeShift) - 1L;
                long hostOffset = (long)(l2Entry & (ulong)hostOffsetMask);

                int compressedLength = nbSectors * 512;
                byte[] compBuf = new byte[compressedLength];
                sourceStream.Seek(hostOffset, SeekOrigin.Begin);
                int r = sourceStream.Read(compBuf, 0, compressedLength);

                cached = DecompressZlibCluster(compBuf, r, (int)clusterSize);
                if (cached == null)
                {
                    cached = new byte[clusterSize];
                }

                // Add to LRU cache
                if (compressedClusterCache.Count >= MaxCachedCompressedClusters && compressedLruOrder.Count > 0)
                {
                    long oldest = compressedLruOrder[0];
                    compressedLruOrder.RemoveAt(0);
                    compressedClusterCache.Remove(oldest);
                }
                compressedClusterCache[entryKey] = cached;
                compressedLruOrder.Add(entryKey);
            }
            else
            {
                // Refresh LRU
                compressedLruOrder.Remove(entryKey);
                compressedLruOrder.Add(entryKey);
            }

            // Copy requested slice
            int copyBytes = Math.Min(count, (int)Math.Max(0, cached.Length - clusterOffset));
            if (copyBytes > 0)
            {
                Buffer.BlockCopy(cached, (int)clusterOffset, targetBuffer, targetOffset, copyBytes);
            }
            if (copyBytes < count)
            {
                Array.Clear(targetBuffer, targetOffset + copyBytes, count - copyBytes);
            }
        }

        private static byte[] DecompressZlibCluster(byte[] raw, int length, int expectedSize)
        {
            if (raw == null || length <= 0) return null;

            // QCOW2 uses raw deflate or zlib. Check for zlib header (0x78)
            int skip = 0;
            if (length > 2 && raw[0] == 0x78)
            {
                skip = 2;
            }

            try
            {
                using (MemoryStream ms = new MemoryStream(raw, skip, length - skip, false))
                using (DeflateStream def = new DeflateStream(ms, CompressionMode.Decompress))
                using (MemoryStream dest = new MemoryStream(expectedSize))
                {
                    byte[] temp = new byte[8192];
                    int read;
                    while ((read = def.Read(temp, 0, temp.Length)) > 0)
                    {
                        dest.Write(temp, 0, read);
                        if (dest.Length >= expectedSize) break;
                    }
                    return dest.ToArray();
                }
            }
            catch
            {
                return null;
            }
        }

        private ulong[] GetOrLoadL2Table(ulong l2Offset)
        {
            ulong[] cached;
            if (l2Cache.TryGetValue(l2Offset, out cached))
            {
                l2LruOrder.Remove(l2Offset);
                l2LruOrder.Add(l2Offset);
                return cached;
            }

            // Load L2 table from file
            int byteLength = l2EntriesPerCluster * 8;
            byte[] buf = new byte[byteLength];
            sourceStream.Seek((long)l2Offset, SeekOrigin.Begin);
            int read = sourceStream.Read(buf, 0, byteLength);

            ulong[] l2 = new ulong[l2EntriesPerCluster];
            int availableEntries = read / 8;
            for (int i = 0; i < availableEntries; i++)
            {
                l2[i] = ReadUInt64BE(buf, i * 8);
            }

            if (l2Cache.Count >= MaxCachedL2Tables && l2LruOrder.Count > 0)
            {
                ulong oldest = l2LruOrder[0];
                l2LruOrder.RemoveAt(0);
                l2Cache.Remove(oldest);
            }
            l2Cache[l2Offset] = l2;
            l2LruOrder.Add(l2Offset);

            return l2;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            ThrowIfDisposed();
            long newPos;
            switch (origin)
            {
                case SeekOrigin.Begin:
                    newPos = offset;
                    break;
                case SeekOrigin.Current:
                    newPos = currentPosition + offset;
                    break;
                case SeekOrigin.End:
                    newPos = (long)header.VirtualDiskSize + offset;
                    break;
                default:
                    throw new ArgumentOutOfRangeException("origin");
            }

            if (newPos < 0)
            {
                throw new IOException("Attempted to seek before beginning of stream.");
            }
            currentPosition = newPos;
            return currentPosition;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException("Qcow2ImageReader is strictly read-only.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("Qcow2ImageReader is strictly read-only.");
        }

        public override void Flush()
        {
            // Read-only stream: no-op
        }

        private void ThrowIfDisposed()
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                if (disposing)
                {
                    if (!leaveOpen && sourceStream != null)
                    {
                        sourceStream.Dispose();
                    }
                    l2Cache.Clear();
                    l2LruOrder.Clear();
                    compressedClusterCache.Clear();
                    compressedLruOrder.Clear();
                }
                isDisposed = true;
            }
            base.Dispose(disposing);
        }

        private static uint ReadUInt32BE(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset] << 24) |
                   ((uint)buffer[offset + 1] << 16) |
                   ((uint)buffer[offset + 2] << 8) |
                   ((uint)buffer[offset + 3]);
        }

        private static ulong ReadUInt64BE(byte[] buffer, int offset)
        {
            return ((ulong)buffer[offset] << 56) |
                   ((ulong)buffer[offset + 1] << 48) |
                   ((ulong)buffer[offset + 2] << 40) |
                   ((ulong)buffer[offset + 3] << 32) |
                   ((ulong)buffer[offset + 4] << 24) |
                   ((ulong)buffer[offset + 5] << 16) |
                   ((ulong)buffer[offset + 6] << 8) |
                   ((ulong)buffer[offset + 7]);
        }
    }
}
