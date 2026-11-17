using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public enum VmdkSubformat
    {
        Unknown = 0,
        MonolithicFlat = 1,
        MonolithicSparse = 2
    }

    public sealed class VmdkExtentDescriptor
    {
        public string Access { get; set; }        // "RW", "RDONLY", "NOACCESS"
        public long SectorCount { get; set; }     // Number of 512-byte sectors
        public string Type { get; set; }          // "FLAT", "SPARSE", "ZERO"
        public string FileName { get; set; }      // Relative or absolute extent path
        public long OffsetInSectors { get; set; } // Offset in host extent (sectors)
        public long GuestStartSector { get; set; }
        public FileStream ExtentStream { get; set; }

        public VmdkExtentDescriptor()
        {
            Access = String.Empty;
            Type = String.Empty;
            FileName = String.Empty;
        }
    }

    public sealed class VmdkSparseHeader
    {
        public uint MagicNumber { get; set; }         // 0x564D444B ("VMDK" LE)
        public uint Version { get; set; }             // 1, 2, or 3
        public uint Flags { get; set; }
        public ulong Capacity { get; set; }           // Total sectors
        public ulong GrainSize { get; set; }          // Sectors per grain (typically 128)
        public ulong DescriptorOffset { get; set; }   // Sector offset of descriptor
        public ulong DescriptorSize { get; set; }     // Size of descriptor in sectors
        public uint NumGTEsPerGT { get; set; }        // Typically 512
        public ulong RgdOffset { get; set; }          // Sector offset of redundant GD
        public ulong GdOffset { get; set; }           // Sector offset of primary GD
        public ulong OverHead { get; set; }           // Metadata overhead in sectors
        public byte UncleanShutdown { get; set; }
        public ushort CompressAlgorithm { get; set; } // 0 = uncompressed, 1 = deflate
    }

    /// <summary>
    /// Native pure C# Stream implementation for VMware Virtual Machine Disk (VMDK).
    /// Supports Monolithic Flat (descriptor + extent) and Monolithic Sparse (two-level GD/GT index),
    /// random-access seeking, bounded LRU caching, and strict write-blocking guarantees.
    /// </summary>
    public sealed class VmdkImageReader : Stream
    {
        private const uint VmdkSparseMagic = 0x564D444BU; // "VMDK" LE
        private const int DefaultGTEsPerGT = 512;
        private const int MaxCachedGrainTables = 128; // Caches up to 4 GB virtual address space

        private readonly string mainFilePath;
        private readonly VmdkSubformat subformat;
        private readonly long virtualDiskSize;
        private FileStream sparseStream;
        private List<VmdkExtentDescriptor> flatExtents;

        // Sparse VMDK metadata & tables
        private VmdkSparseHeader sparseHeader;
        private uint[] grainDirectory;
        private readonly Dictionary<int, uint[]> gtCache;
        private readonly List<int> gtLruOrder;

        private long currentPosition;
        private bool isDisposed;

        public VmdkSubformat Subformat { get { return subformat; } }
        public VmdkSparseHeader SparseHeader { get { return sparseHeader; } }
        public IList<VmdkExtentDescriptor> Extents
        {
            get { return flatExtents != null ? flatExtents.AsReadOnly() : null; }
        }
        public string FilePath { get { return mainFilePath; } }

        public override bool CanRead { get { return !isDisposed; } }
        public override bool CanSeek { get { return !isDisposed; } }
        public override bool CanWrite { get { return false; } }

        public override long Length { get { return virtualDiskSize; } }
        public override long Position
        {
            get { return currentPosition; }
            set { Seek(value, SeekOrigin.Begin); }
        }

        public static bool IsVmdkFile(string path)
        {
            if (String.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            try
            {
                SourcePaths.NoLinks(path);
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length < 4) return false;
                    byte[] sig = new byte[512];
                    int r = fs.Read(sig, 0, Math.Min((int)fs.Length, 512));
                    if (r < 4) return false;
                    return IsVmdkSignature(sig, r);
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool IsVmdkSignature(byte[] header, int length)
        {
            if (header == null || length < 4) return false;

            // Check Sparse Magic: 0x564D444B ("VMDK" in little-endian)
            uint magic = (uint)(header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24));
            if (magic == VmdkSparseMagic) return true;

            // Check ASCII descriptor file signature
            string text = Encoding.ASCII.GetString(header, 0, Math.Min(length, 256));
            if (text.IndexOf("# Disk DescriptorFile", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("createType=\"monolithicFlat\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("createType=\"twoGbMaxExtentFlat\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("createType=\"monolithicSparse\"", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            return false;
        }

        public static VmdkImageReader Open(string path)
        {
            return new VmdkImageReader(path);
        }

        public VmdkImageReader(string path)
        {
            if (String.IsNullOrEmpty(path)) throw new ArgumentNullException("path");

            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath)) throw new FileNotFoundException("VMDK file not found: " + fullPath, fullPath);

            SourcePaths.NoLinks(fullPath);

            mainFilePath = fullPath;
            gtCache = new Dictionary<int, uint[]>();
            gtLruOrder = new List<int>();

            // Inspect initial 512 bytes to determine subformat
            byte[] headerBytes = new byte[512];
            using (FileStream probe = new FileStream(mainFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                int r = probe.Read(headerBytes, 0, Math.Min((int)probe.Length, 512));
                if (r < 4) throw new InvalidDataException("VMDK file is too short to contain a valid header.");
            }

            uint magic = (uint)(headerBytes[0] | (headerBytes[1] << 8) | (headerBytes[2] << 16) | (headerBytes[3] << 24));
            if (magic == VmdkSparseMagic)
            {
                subformat = VmdkSubformat.MonolithicSparse;
                InitializeSparse(mainFilePath, headerBytes);
                virtualDiskSize = (long)sparseHeader.Capacity * 512L;
            }
            else
            {
                string textSample = Encoding.ASCII.GetString(headerBytes, 0, Math.Min(headerBytes.Length, 256));
                if (textSample.IndexOf("# Disk DescriptorFile", StringComparison.OrdinalIgnoreCase) < 0 &&
                    textSample.IndexOf("createType=", StringComparison.OrdinalIgnoreCase) < 0 &&
                    textSample.IndexOf("CID=", StringComparison.OrdinalIgnoreCase) < 0 &&
                    textSample.IndexOf("RW ", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    throw new InvalidDataException("Unrecognized VMDK format: not a valid sparse header or descriptor file.");
                }

                subformat = VmdkSubformat.MonolithicFlat;
                InitializeFlat(mainFilePath);
                long totalBytes = 0;
                for (int i = 0; i < flatExtents.Count; i++)
                {
                    totalBytes += flatExtents[i].SectorCount * 512L;
                }
                virtualDiskSize = totalBytes;
            }
        }

        private void InitializeFlat(string descriptorPath)
        {
            flatExtents = new List<VmdkExtentDescriptor>();
            string dir = Path.GetDirectoryName(descriptorPath);
            string[] lines = File.ReadAllLines(descriptorPath, Encoding.ASCII);

            long currentGuestSector = 0;
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;

                // Match extent lines: e.g. RW 20971520 FLAT "disk-flat.vmdk" 0 or RW 64 ZERO
                string[] parts = ParseExtentLine(line);
                if (parts != null && parts.Length >= 3)
                {
                    string access = parts[0];
                    long sectors;
                    if (!long.TryParse(parts[1], out sectors)) continue;
                    string type = parts[2].ToUpperInvariant();

                    // FLAT extents require a backing file name (at least 4 tokens)
                    if (type == "FLAT" && (parts.Length < 4 || String.IsNullOrEmpty(parts[3]))) continue;

                    string fileName = parts.Length >= 4 ? parts[3] : "ZERO";
                    long offsetInSectors = 0;
                    if (parts.Length >= 5) long.TryParse(parts[4], out offsetInSectors);

                    VmdkExtentDescriptor ext = new VmdkExtentDescriptor();
                    ext.Access = access;
                    ext.SectorCount = sectors;
                    ext.Type = type;
                    ext.OffsetInSectors = offsetInSectors;
                    ext.GuestStartSector = currentGuestSector;

                    if (type == "FLAT")
                    {
                        string resolvedPath = Path.IsPathRooted(fileName) ? fileName : Path.Combine(dir, fileName);
                        SourcePaths.NoLinks(resolvedPath);
                        if (!File.Exists(resolvedPath))
                        {
                            // Clean up already opened extents on error
                            DisposeFlatExtents();
                            throw new FileNotFoundException("VMDK flat extent file not found: " + resolvedPath, resolvedPath);
                        }
                        ext.FileName = resolvedPath;
                        ext.ExtentStream = new FileStream(resolvedPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    }
                    else if (type == "ZERO")
                    {
                        ext.FileName = "ZERO";
                        ext.ExtentStream = null;
                    }

                    flatExtents.Add(ext);
                    currentGuestSector += sectors;
                }
            }

            if (flatExtents.Count == 0)
            {
                throw new InvalidDataException("VMDK descriptor contains no valid extent descriptions.");
            }
        }

        private void DisposeFlatExtents()
        {
            if (flatExtents != null)
            {
                for (int i = 0; i < flatExtents.Count; i++)
                {
                    if (flatExtents[i].ExtentStream != null)
                    {
                        try { flatExtents[i].ExtentStream.Dispose(); } catch { }
                        flatExtents[i].ExtentStream = null;
                    }
                }
                flatExtents.Clear();
            }
        }

        private static string[] ParseExtentLine(string line)
        {
            // Parses lines like: RW 20971520 FLAT "test-flat.vmdk" 0
            List<string> tokens = new List<string>();
            int idx = 0;
            while (idx < line.Length)
            {
                while (idx < line.Length && Char.IsWhiteSpace(line[idx])) idx++;
                if (idx >= line.Length) break;

                if (line[idx] == '\"')
                {
                    idx++;
                    int end = line.IndexOf('\"', idx);
                    if (end < 0) end = line.Length;
                    tokens.Add(line.Substring(idx, end - idx));
                    idx = end + 1;
                }
                else
                {
                    int start = idx;
                    while (idx < line.Length && !Char.IsWhiteSpace(line[idx])) idx++;
                    tokens.Add(line.Substring(start, idx - start));
                }
            }
            if (tokens.Count >= 3 && (tokens[0].Equals("RW", StringComparison.OrdinalIgnoreCase) ||
                                      tokens[0].Equals("RDONLY", StringComparison.OrdinalIgnoreCase) ||
                                      tokens[0].Equals("NOACCESS", StringComparison.OrdinalIgnoreCase)))
            {
                return tokens.ToArray();
            }
            return null;
        }

        private void InitializeSparse(string sparsePath, byte[] headerBytes)
        {
            sparseStream = new FileStream(sparsePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            sparseHeader = new VmdkSparseHeader();
            sparseHeader.MagicNumber = BitConverter.ToUInt32(headerBytes, 0);
            sparseHeader.Version = BitConverter.ToUInt32(headerBytes, 4);
            sparseHeader.Flags = BitConverter.ToUInt32(headerBytes, 8);
            sparseHeader.Capacity = BitConverter.ToUInt64(headerBytes, 12);
            sparseHeader.GrainSize = BitConverter.ToUInt64(headerBytes, 20);
            sparseHeader.DescriptorOffset = BitConverter.ToUInt64(headerBytes, 28);
            sparseHeader.DescriptorSize = BitConverter.ToUInt64(headerBytes, 36);
            sparseHeader.NumGTEsPerGT = BitConverter.ToUInt32(headerBytes, 44);
            sparseHeader.RgdOffset = BitConverter.ToUInt64(headerBytes, 48);
            sparseHeader.GdOffset = BitConverter.ToUInt64(headerBytes, 56);
            sparseHeader.OverHead = BitConverter.ToUInt64(headerBytes, 64);
            sparseHeader.UncleanShutdown = headerBytes[72];
            sparseHeader.CompressAlgorithm = BitConverter.ToUInt16(headerBytes, 77);

            if (sparseHeader.GrainSize == 0 || (sparseHeader.GrainSize & (sparseHeader.GrainSize - 1)) != 0)
            {
                throw new InvalidDataException("Invalid VMDK grain size: " + sparseHeader.GrainSize);
            }
            if (sparseHeader.NumGTEsPerGT == 0)
            {
                sparseHeader.NumGTEsPerGT = DefaultGTEsPerGT;
            }

            // Load Grain Directory
            ulong totalGrains = (sparseHeader.Capacity + sparseHeader.GrainSize - 1) / sparseHeader.GrainSize;
            int numGdEntries = (int)((totalGrains + (ulong)sparseHeader.NumGTEsPerGT - 1) / (ulong)sparseHeader.NumGTEsPerGT);

            grainDirectory = new uint[numGdEntries];
            long gdByteOffset = (long)sparseHeader.GdOffset * 512L;
            if (gdByteOffset == 0 && sparseHeader.RgdOffset != 0)
            {
                gdByteOffset = (long)sparseHeader.RgdOffset * 512L;
            }

            if (gdByteOffset > 0 && gdByteOffset < sparseStream.Length)
            {
                sparseStream.Position = gdByteOffset;
                byte[] gdBuf = new byte[numGdEntries * 4];
                int bytesRead = sparseStream.Read(gdBuf, 0, gdBuf.Length);
                int entriesLoaded = bytesRead / 4;
                for (int i = 0; i < entriesLoaded; i++)
                {
                    grainDirectory[i] = BitConverter.ToUInt32(gdBuf, i * 4);
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
                throw new ArgumentOutOfRangeException("offset");
            if (isDisposed) throw new ObjectDisposedException("VmdkImageReader");

            if (currentPosition >= virtualDiskSize || count == 0) return 0;

            int bytesToRead = (int)Math.Min((long)count, virtualDiskSize - currentPosition);
            int bytesRead = 0;

            if (subformat == VmdkSubformat.MonolithicFlat)
            {
                bytesRead = ReadFlatData(currentPosition, buffer, offset, bytesToRead);
            }
            else
            {
                bytesRead = ReadSparseData(currentPosition, buffer, offset, bytesToRead);
            }

            currentPosition += bytesRead;
            return bytesRead;
        }

        private int ReadFlatData(long guestOffset, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                long currentLogical = guestOffset + totalRead;
                long currentSector = currentLogical / 512L;
                int offsetInSector = (int)(currentLogical % 512L);

                VmdkExtentDescriptor targetExtent = null;
                for (int i = 0; i < flatExtents.Count; i++)
                {
                    VmdkExtentDescriptor ext = flatExtents[i];
                    if (currentSector >= ext.GuestStartSector && currentSector < ext.GuestStartSector + ext.SectorCount)
                    {
                        targetExtent = ext;
                        break;
                    }
                }

                if (targetExtent == null)
                {
                    // Past defined extents
                    int remaining = count - totalRead;
                    Array.Clear(buffer, offset + totalRead, remaining);
                    totalRead += remaining;
                    break;
                }

                long extentSectorOffset = currentSector - targetExtent.GuestStartSector;
                long extentByteOffset = (extentSectorOffset * 512L) + offsetInSector;
                long extentBytesRemaining = (targetExtent.SectorCount * 512L) - extentByteOffset;
                int bytesInExtent = (int)Math.Min((long)(count - totalRead), extentBytesRemaining);

                if (targetExtent.Type == "ZERO" || targetExtent.ExtentStream == null)
                {
                    Array.Clear(buffer, offset + totalRead, bytesInExtent);
                }
                else
                {
                    long targetPos = (targetExtent.OffsetInSectors * 512L) + extentByteOffset;
                    if (targetPos < targetExtent.ExtentStream.Length)
                    {
                        targetExtent.ExtentStream.Position = targetPos;
                        int r = targetExtent.ExtentStream.Read(buffer, offset + totalRead, bytesInExtent);
                        if (r < bytesInExtent)
                        {
                            Array.Clear(buffer, offset + totalRead + r, bytesInExtent - r);
                        }
                    }
                    else
                    {
                        Array.Clear(buffer, offset + totalRead, bytesInExtent);
                    }
                }

                totalRead += bytesInExtent;
            }

            return totalRead;
        }

        private int ReadSparseData(long guestOffset, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            long grainBytes = (long)sparseHeader.GrainSize * 512L;
            uint gtesPerGt = sparseHeader.NumGTEsPerGT;

            while (totalRead < count)
            {
                long currentLogical = guestOffset + totalRead;
                long grainIndex = currentLogical / grainBytes;
                int offsetInGrain = (int)(currentLogical % grainBytes);
                int bytesInGrain = (int)Math.Min((long)(count - totalRead), grainBytes - offsetInGrain);

                int gdIndex = (int)(grainIndex / (long)gtesPerGt);
                int gtIndex = (int)(grainIndex % (long)gtesPerGt);

                if (grainDirectory == null || gdIndex >= grainDirectory.Length || grainDirectory[gdIndex] == 0)
                {
                    // Unallocated Grain Table -> zero fill
                    Array.Clear(buffer, offset + totalRead, bytesInGrain);
                    totalRead += bytesInGrain;
                    continue;
                }

                uint[] gt = GetCachedGrainTable(gdIndex, (long)grainDirectory[gdIndex] * 512L, (int)gtesPerGt);
                uint gte = (gt != null && gtIndex < gt.Length) ? gt[gtIndex] : 0;

                if (gte == 0)
                {
                    // Unallocated Grain -> zero fill
                    Array.Clear(buffer, offset + totalRead, bytesInGrain);
                }
                else
                {
                    // Allocated grain
                    long hostPos = ((long)gte * 512L) + offsetInGrain;
                    if (hostPos < sparseStream.Length)
                    {
                        sparseStream.Position = hostPos;
                        int r = sparseStream.Read(buffer, offset + totalRead, bytesInGrain);
                        if (r < bytesInGrain)
                        {
                            Array.Clear(buffer, offset + totalRead + r, bytesInGrain - r);
                        }
                    }
                    else
                    {
                        Array.Clear(buffer, offset + totalRead, bytesInGrain);
                    }
                }

                totalRead += bytesInGrain;
            }

            return totalRead;
        }

        private uint[] GetCachedGrainTable(int gdIndex, long fileOffset, int entryCount)
        {
            uint[] cached;
            if (gtCache.TryGetValue(gdIndex, out cached))
            {
                gtLruOrder.Remove(gdIndex);
                gtLruOrder.Add(gdIndex);
                return cached;
            }

            uint[] gt = new uint[entryCount];
            if (fileOffset > 0 && fileOffset < sparseStream.Length)
            {
                sparseStream.Position = fileOffset;
                byte[] buf = new byte[entryCount * 4];
                int r = sparseStream.Read(buf, 0, buf.Length);
                int count = r / 4;
                for (int i = 0; i < count; i++)
                {
                    gt[i] = BitConverter.ToUInt32(buf, i * 4);
                }
            }

            if (gtCache.Count >= MaxCachedGrainTables && gtLruOrder.Count > 0)
            {
                int evict = gtLruOrder[0];
                gtLruOrder.RemoveAt(0);
                gtCache.Remove(evict);
            }

            gtCache[gdIndex] = gt;
            gtLruOrder.Add(gdIndex);
            return gt;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (isDisposed) throw new ObjectDisposedException("VmdkImageReader");

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
                    newPos = virtualDiskSize + offset;
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
            throw new NotSupportedException("VmdkImageReader is a read-only stream.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("VmdkImageReader is a read-only stream.");
        }

        public override void Flush()
        {
            // Read-only stream: no-op
        }

        protected override void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                isDisposed = true;
                if (disposing)
                {
                    if (sparseStream != null)
                    {
                        try { sparseStream.Dispose(); } catch { }
                        sparseStream = null;
                    }
                    DisposeFlatExtents();
                    if (gtCache != null) gtCache.Clear();
                    if (gtLruOrder != null) gtLruOrder.Clear();
                }
            }
            base.Dispose(disposing);
        }
    }
}
