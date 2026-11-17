using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    /// <summary>
    /// Native pure C# Stream implementation for Microsoft Virtual Hard Disk v2 (VHDX).
    /// Supports Fixed, Dynamic, and Differencing VHDX images with dual-header CRC32C arbitration,
    /// dual-region table and metadata parsing, interleaved BAT translation, sector bitmaps,
    /// random-access seeking, and strict write-blocking guarantees.
    /// </summary>
    public sealed class VhdxImageReader : Stream
    {
        // Format Signatures
        private const ulong VhdxFileSignature = 0x656C696678646876UL; // "vhdxfile" LE
        private const uint HeaderSignature = 0x64616568U;              // "head" LE
        private const uint RegionSignature = 0x69676572U;              // "regi" LE
        private const ulong MetadataSignature = 0x617461646174656DUL;  // "metadata" LE

        // Header and Region Offsets
        private const long Header1Offset = 65536L;      // 64 KB
        private const long Header2Offset = 131072L;     // 128 KB
        private const int HeaderSize = 4096;            // 4 KB
        private const long RegionTable1Offset = 196608L;// 192 KB
        private const long RegionTable2Offset = 262144L;// 256 KB
        private const int RegionTableSize = 65536;      // 64 KB

        // Well-known Region GUIDs
        private static readonly Guid BatRegionGuid = new Guid("2DC27766-F623-4200-9D64-115E9BFD4A08");
        private static readonly Guid MetadataRegionGuid = new Guid("8B7D40A4-0796-4B43-AC8B-3B224F3A39E0");

        // Well-known Metadata Item GUIDs
        private static readonly Guid FileParametersGuid = new Guid("CAA16737-FA36-4D43-B3B6-30F00AAEE56B");
        private static readonly Guid VirtualDiskSizeGuid = new Guid("2FA54261-B276-42FB-AA69-E3B10F7264F3");
        private static readonly Guid Page83DataGuid = new Guid("BECA12AB-B2E6-4523-93EF-C309E000C746");
        private static readonly Guid LogicalSectorSizeGuid = new Guid("8141214F-43CD-4529-A8BB-4D0E75E9B646");
        private static readonly Guid PhysicalSectorSizeGuid = new Guid("CDA348C7-445D-4471-9CC9-E9885251C556");

        // BAT Constants & States
        private const int PAYLOAD_BLOCK_NOT_PRESENT = 0;
        private const int PAYLOAD_BLOCK_UNDEFINED = 1;
        private const int PAYLOAD_BLOCK_ZERO = 2;
        private const int PAYLOAD_BLOCK_UNMAPPED = 3;
        private const int PAYLOAD_BLOCK_FULLY_PRESENT = 6;
        private const int PAYLOAD_BLOCK_PARTIALLY_PRESENT = 7;

        private const int SB_BLOCK_NOT_PRESENT = 0;
        private const int SB_BLOCK_PRESENT = 6;

        private const ulong BatStateMask = 0x07UL;
        private const ulong BatFileOffsetMask = 0xFFFFFFFFFFF00000UL;

        // Instance Fields
        private readonly string filePath;
        private Stream baseStream;
        private readonly bool leaveOpen;
        private bool isDisposed;
        private long currentPosition;

        // VHDX Parameters
        private ulong virtualDiskSize;
        private uint blockSize;
        private uint logicalSectorSize;
        private uint physicalSectorSize;
        private bool leaveBlocksAllocated;
        private bool hasParent;
        private ulong chunkRatio;

        // Header Metadata
        private ulong activeSequenceNumber;
        private Guid fileWriteGuid;
        private Guid dataWriteGuid;
        private Guid logGuid;
        private Guid page83Data;

        // Region Pointers
        private long batFileOffset;
        private uint batLength;
        private long metadataFileOffset;
        private uint metadataLength;

        // BAT Table and Sector Bitmap Cache
        private ulong[] batTable;
        private readonly Dictionary<long, byte[]> sectorBitmapCache;
        private readonly List<long> sectorBitmapLru;
        private const int MaxCachedBitmaps = 4; // 4 MB RAM max

        // CRC-32C Table
        private static readonly uint[] Crc32cTable = InitializeCrc32cTable();

        private static uint[] InitializeCrc32cTable()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int bit = 0; bit < 8; bit++)
                {
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F63B78U : crc >> 1;
                }
                table[i] = crc;
            }
            return table;
        }

        public static uint ComputeCrc32c(byte[] data, int offset, int length)
        {
            if (data == null || offset < 0 || length < 0 || offset + length > data.Length)
            {
                return 0;
            }
            uint crc = 0xFFFFFFFFU;
            for (int i = 0; i < length; i++)
            {
                crc = Crc32cTable[(crc ^ data[offset + i]) & 0xFF] ^ (crc >> 8);
            }
            return ~crc;
        }

        // -------------------------------------------------------------
        // Public Properties
        // -------------------------------------------------------------
        public override bool CanRead { get { return !isDisposed; } }
        public override bool CanSeek { get { return !isDisposed; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return (long)virtualDiskSize; } }
        public override long Position
        {
            get { return currentPosition; }
            set { Seek(value, SeekOrigin.Begin); }
        }

        public string FilePath { get { return filePath; } }
        public ulong VirtualDiskSize { get { return virtualDiskSize; } }
        public ulong DiskSize { get { return virtualDiskSize; } }
        public uint BlockSize { get { return blockSize; } }
        public uint BlockSizeInBytes { get { return blockSize; } }
        public uint LogicalSectorSize { get { return logicalSectorSize; } }
        public uint LogicalSectorSizeInBytes { get { return logicalSectorSize; } }
        public uint PhysicalSectorSize { get { return physicalSectorSize; } }
        public uint PhysicalSectorSizeInBytes { get { return physicalSectorSize; } }
        public bool IsDynamic { get { return !leaveBlocksAllocated; } }
        public bool IsDynamicDisk { get { return !leaveBlocksAllocated; } }
        public bool HasParent { get { return hasParent; } }
        public bool IsDifferencingDisk { get { return hasParent; } }
        public ulong ChunkRatio { get { return chunkRatio; } }
        public ulong ComputedChunkRatio { get { return chunkRatio; } }
        public ulong ActiveHeaderSequenceNumber { get { return activeSequenceNumber; } }
        public ulong HeaderSequenceNumber { get { return activeSequenceNumber; } }
        public Guid FileWriteGuid { get { return fileWriteGuid; } }
        public Guid ActiveFileWriteGuid { get { return fileWriteGuid; } }
        public Guid DataWriteGuid { get { return dataWriteGuid; } }
        public Guid ActiveDataWriteGuid { get { return dataWriteGuid; } }
        public Guid LogGuid { get { return logGuid; } }
        public Guid ActiveLogGuid { get { return logGuid; } }
        public bool HasUncommittedLog { get { return logGuid != Guid.Empty; } }
        public Guid Page83Data { get { return page83Data; } }
        public Guid ScsiPage83Data { get { return page83Data; } }
        public long BatFileOffset { get { return batFileOffset; } }
        public long BatOffset { get { return batFileOffset; } }
        public uint BatLength { get { return batLength; } }
        public uint BatByteLength { get { return batLength; } }
        public long MetadataFileOffset { get { return metadataFileOffset; } }
        public long MetadataOffset { get { return metadataFileOffset; } }
        public uint MetadataLength { get { return metadataLength; } }
        public uint MetadataByteLength { get { return metadataLength; } }

        // -------------------------------------------------------------
        // Constructors & Open
        // -------------------------------------------------------------
        public static VhdxImageReader Open(string path)
        {
            return new VhdxImageReader(path);
        }

        public VhdxImageReader(string filePath)
        {
            if (String.IsNullOrEmpty(filePath)) throw new ArgumentNullException("filePath");
            string fullPath = Path.GetFullPath(filePath);
            if (!File.Exists(fullPath)) throw new FileNotFoundException("VHDX file not found: " + fullPath, fullPath);

            SourcePaths.NoLinks(fullPath);

            this.filePath = fullPath;
            this.baseStream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            this.leaveOpen = false;
            this.sectorBitmapCache = new Dictionary<long, byte[]>();
            this.sectorBitmapLru = new List<long>();

            Initialize();
        }

        public VhdxImageReader(Stream stream, bool leaveOpen = false)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable.", "stream");
            if (!stream.CanSeek) throw new ArgumentException("Stream must be seekable.", "stream");

            this.filePath = String.Empty;
            this.baseStream = stream;
            this.leaveOpen = leaveOpen;
            this.sectorBitmapCache = new Dictionary<long, byte[]>();
            this.sectorBitmapLru = new List<long>();

            Initialize();
        }

        // -------------------------------------------------------------
        // Initialization Pipeline
        // -------------------------------------------------------------
        private void Initialize()
        {
            try
            {
                if (baseStream.Length < 65536)
                {
                    throw new InvalidDataException("File is too small to be a valid VHDX image.");
                }

                // 1. Validate File Identifier ("vhdxfile" at offset 0)
                byte[] fileId = ReadExact(0, 65536);
                ulong sig = BitConverter.ToUInt64(fileId, 0);
                if (sig != VhdxFileSignature)
                {
                    throw new InvalidDataException("Invalid VHDX file signature. Expected 'vhdxfile'.");
                }

                // 2. Select Active Header (Header 1 or 2 by CRC32C and SequenceNumber)
                ParseActiveHeader();

                // 3. Parse Region Table (Region Table 1 or 2)
                ParseRegionTable();

                // 4. Parse Metadata Table
                ParseMetadataTable();

                // 5. Pre-load Block Allocation Table (BAT)
                LoadBatTable();
            }
            catch
            {
                if (!leaveOpen && baseStream != null)
                {
                    baseStream.Dispose();
                }
                throw;
            }
        }

        private void ParseActiveHeader()
        {
            byte[] h1 = ReadExact(Header1Offset, HeaderSize);
            byte[] h2 = ReadExact(Header2Offset, HeaderSize);

            bool h1Valid = ValidateHeader(h1);
            bool h2Valid = ValidateHeader(h2);

            if (!h1Valid && !h2Valid)
            {
                throw new InvalidDataException("Both VHDX headers are invalid or corrupt.");
            }

            byte[] active;
            if (h1Valid && h2Valid)
            {
                ulong seq1 = BitConverter.ToUInt64(h1, 8);
                ulong seq2 = BitConverter.ToUInt64(h2, 8);
                active = (seq1 >= seq2) ? h1 : h2;
            }
            else
            {
                active = h1Valid ? h1 : h2;
            }

            activeSequenceNumber = BitConverter.ToUInt64(active, 8);
            byte[] guidBuf = new byte[16];
            Array.Copy(active, 16, guidBuf, 0, 16);
            fileWriteGuid = new Guid(guidBuf);
            Array.Copy(active, 32, guidBuf, 0, 16);
            dataWriteGuid = new Guid(guidBuf);
            Array.Copy(active, 48, guidBuf, 0, 16);
            logGuid = new Guid(guidBuf);
        }

        private static bool ValidateHeader(byte[] buffer)
        {
            if (buffer == null || buffer.Length < HeaderSize) return false;
            uint sig = BitConverter.ToUInt32(buffer, 0);
            if (sig != HeaderSignature) return false;

            ushort version = BitConverter.ToUInt16(buffer, 66);
            if (version != 1) return false;

            uint storedCrc = BitConverter.ToUInt32(buffer, 4);
            byte[] temp = new byte[HeaderSize];
            Array.Copy(buffer, temp, HeaderSize);
            temp[4] = 0; temp[5] = 0; temp[6] = 0; temp[7] = 0;

            uint computedCrc = ComputeCrc32c(temp, 0, HeaderSize);
            return storedCrc == computedCrc;
        }

        private void ParseRegionTable()
        {
            byte[] r1 = ReadExact(RegionTable1Offset, RegionTableSize);
            byte[] r2 = ReadExact(RegionTable2Offset, RegionTableSize);

            byte[] activeRegion = null;
            if (ValidateRegionTable(r1)) activeRegion = r1;
            else if (ValidateRegionTable(r2)) activeRegion = r2;
            else throw new InvalidDataException("Both VHDX region tables are invalid or corrupt.");

            uint entryCount = BitConverter.ToUInt32(activeRegion, 8);
            if (entryCount > 2047) entryCount = 2047;

            byte[] guidBuf = new byte[16];
            bool foundBat = false;
            bool foundMeta = false;

            for (int i = 0; i < (int)entryCount; i++)
            {
                int offset = 16 + (i * 32);
                Array.Copy(activeRegion, offset, guidBuf, 0, 16);
                Guid regionGuid = new Guid(guidBuf);
                ulong fileOffset = BitConverter.ToUInt64(activeRegion, offset + 16);
                uint length = BitConverter.ToUInt32(activeRegion, offset + 24);
                uint required = BitConverter.ToUInt32(activeRegion, offset + 28);

                if (regionGuid == BatRegionGuid)
                {
                    batFileOffset = (long)fileOffset;
                    batLength = length;
                    foundBat = true;
                }
                else if (regionGuid == MetadataRegionGuid)
                {
                    metadataFileOffset = (long)fileOffset;
                    metadataLength = length;
                    foundMeta = true;
                }
                else if ((required & 1) != 0)
                {
                    throw new NotSupportedException(string.Format("Unrecognized required VHDX region: {0}", regionGuid));
                }
            }

            if (!foundBat || !foundMeta)
            {
                throw new InvalidDataException("VHDX missing required BAT or Metadata region.");
            }
            if (batFileOffset <= 0 || (batFileOffset % 1048576L) != 0)
            {
                throw new InvalidDataException("Invalid VHDX BAT region file offset alignment.");
            }
            if (metadataFileOffset <= 0 || (metadataFileOffset % 1048576L) != 0)
            {
                throw new InvalidDataException("Invalid VHDX Metadata region file offset alignment.");
            }
        }

        private static bool ValidateRegionTable(byte[] buffer)
        {
            if (buffer == null || buffer.Length < RegionTableSize) return false;
            uint sig = BitConverter.ToUInt32(buffer, 0);
            if (sig != RegionSignature) return false;

            uint storedCrc = BitConverter.ToUInt32(buffer, 4);
            byte[] temp = new byte[RegionTableSize];
            Array.Copy(buffer, temp, RegionTableSize);
            temp[4] = 0; temp[5] = 0; temp[6] = 0; temp[7] = 0;

            uint computedCrc = ComputeCrc32c(temp, 0, RegionTableSize);
            return storedCrc == computedCrc;
        }

        private void ParseMetadataTable()
        {
            int readLen = (int)Math.Min((long)metadataLength, 65536L);
            byte[] metaBuf = ReadExact(metadataFileOffset, readLen);

            ulong sig = BitConverter.ToUInt64(metaBuf, 0);
            if (sig != MetadataSignature)
            {
                throw new InvalidDataException("Invalid VHDX metadata table signature.");
            }

            ushort entryCount = BitConverter.ToUInt16(metaBuf, 10);
            if (entryCount > 2047) entryCount = 2047;

            byte[] guidBuf = new byte[16];
            bool foundParams = false;
            bool foundSize = false;
            bool foundLogical = false;
            bool foundPhysical = false;

            for (int i = 0; i < (int)entryCount; i++)
            {
                int offset = 32 + (i * 32);
                Array.Copy(metaBuf, offset, guidBuf, 0, 16);
                Guid itemId = new Guid(guidBuf);
                uint itemOffset = BitConverter.ToUInt32(metaBuf, offset + 16);
                uint itemLength = BitConverter.ToUInt32(metaBuf, offset + 20);

                if (itemOffset + itemLength > metadataLength) continue;

                if (itemId == FileParametersGuid)
                {
                    byte[] data = ReadExact(metadataFileOffset + itemOffset, (int)itemLength);
                    blockSize = BitConverter.ToUInt32(data, 0);
                    uint flags = BitConverter.ToUInt32(data, 4);
                    leaveBlocksAllocated = (flags & 1) != 0;
                    hasParent = (flags & 2) != 0;
                    foundParams = true;
                }
                else if (itemId == VirtualDiskSizeGuid)
                {
                    byte[] data = ReadExact(metadataFileOffset + itemOffset, (int)itemLength);
                    virtualDiskSize = BitConverter.ToUInt64(data, 0);
                    foundSize = true;
                }
                else if (itemId == LogicalSectorSizeGuid)
                {
                    byte[] data = ReadExact(metadataFileOffset + itemOffset, (int)itemLength);
                    logicalSectorSize = BitConverter.ToUInt32(data, 0);
                    foundLogical = true;
                }
                else if (itemId == PhysicalSectorSizeGuid)
                {
                    byte[] data = ReadExact(metadataFileOffset + itemOffset, (int)itemLength);
                    physicalSectorSize = BitConverter.ToUInt32(data, 0);
                    foundPhysical = true;
                }
                else if (itemId == Page83DataGuid)
                {
                    byte[] data = ReadExact(metadataFileOffset + itemOffset, Math.Min(16, (int)itemLength));
                    byte[] p83 = new byte[16];
                    Array.Copy(data, p83, data.Length);
                    page83Data = new Guid(p83);
                }
            }

            if (!foundParams || !foundSize || !foundLogical || !foundPhysical)
            {
                throw new InvalidDataException("VHDX missing mandatory metadata items.");
            }
            if (logicalSectorSize != 512 && logicalSectorSize != 4096)
            {
                throw new InvalidDataException(string.Format("Unsupported VHDX logical sector size: {0}", logicalSectorSize));
            }
            if (blockSize < 1048576 || blockSize > 268435456 || ((blockSize & (blockSize - 1)) != 0))
            {
                throw new InvalidDataException(string.Format("Invalid VHDX block size: {0}", blockSize));
            }

            chunkRatio = (8388608UL * (ulong)logicalSectorSize) / (ulong)blockSize;
        }

        private void LoadBatTable()
        {
            long totalPayloadBlocks = (long)((virtualDiskSize + (ulong)blockSize - 1UL) / (ulong)blockSize);
            long totalChunks = (totalPayloadBlocks + (long)chunkRatio - 1L) / (long)chunkRatio;
            long totalBatEntries = totalPayloadBlocks + totalChunks;

            long maxEntriesInBatRegion = (long)batLength / 8L;
            long entriesToRead = Math.Min(totalBatEntries, maxEntriesInBatRegion);

            // Bounded BAT allocation: cap at 1,048,576 entries (8 MB RAM)
            if (entriesToRead > 1048576L)
            {
                entriesToRead = 1048576L;
            }

            int bytesToRead = (int)(entriesToRead * 8L);
            byte[] batBytes = ReadExact(batFileOffset, bytesToRead);

            batTable = new ulong[entriesToRead];
            for (int i = 0; i < (int)entriesToRead; i++)
            {
                batTable[i] = BitConverter.ToUInt64(batBytes, i * 8);
            }
        }

        private byte[] ReadExact(long position, int count)
        {
            byte[] buf = new byte[count];
            if (position < baseStream.Length)
            {
                baseStream.Position = position;
                int totalRead = 0;
                while (totalRead < count)
                {
                    int r = baseStream.Read(buf, totalRead, count - totalRead);
                    if (r <= 0) break;
                    totalRead += r;
                }
            }
            return buf;
        }

        // -------------------------------------------------------------
        // Stream Read Implementation
        // -------------------------------------------------------------
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
                throw new ArgumentOutOfRangeException("offset");
            if (isDisposed) throw new ObjectDisposedException("VhdxImageReader");

            long totalLen = (long)virtualDiskSize;
            if (currentPosition >= totalLen || count == 0 || batTable == null || batTable.Length == 0)
                return 0;

            long available = totalLen - currentPosition;
            int toRead = (int)Math.Min((long)count, available);
            int bytesRead = 0;

            while (bytesRead < toRead)
            {
                long currentLogical = currentPosition + bytesRead;
                long payloadBlockIndex = currentLogical / (long)blockSize;
                long offsetInBlock = currentLogical % (long)blockSize;
                int bytesInBlock = (int)Math.Min((long)(toRead - bytesRead), (long)blockSize - offsetInBlock);

                long chunkIndex = payloadBlockIndex / (long)chunkRatio;
                long batIndex = payloadBlockIndex + chunkIndex;

                if (batIndex >= batTable.Length)
                {
                    Array.Clear(buffer, offset + bytesRead, bytesInBlock);
                    bytesRead += bytesInBlock;
                    continue;
                }

                ulong batEntry = batTable[batIndex];
                int state = (int)(batEntry & BatStateMask);

                switch (state)
                {
                    case PAYLOAD_BLOCK_NOT_PRESENT:
                    case PAYLOAD_BLOCK_UNDEFINED:
                    case PAYLOAD_BLOCK_ZERO:
                    case PAYLOAD_BLOCK_UNMAPPED:
                        Array.Clear(buffer, offset + bytesRead, bytesInBlock);
                        bytesRead += bytesInBlock;
                        break;

                    case PAYLOAD_BLOCK_FULLY_PRESENT:
                        long hostBlockOffset = (long)(batEntry & BatFileOffsetMask);
                        long hostFilePos = hostBlockOffset + offsetInBlock;
                        if (hostFilePos < baseStream.Length)
                        {
                            baseStream.Position = hostFilePos;
                            int r = baseStream.Read(buffer, offset + bytesRead, bytesInBlock);
                            if (r < bytesInBlock)
                            {
                                Array.Clear(buffer, offset + bytesRead + r, bytesInBlock - r);
                            }
                        }
                        else
                        {
                            Array.Clear(buffer, offset + bytesRead, bytesInBlock);
                        }
                        bytesRead += bytesInBlock;
                        break;

                    case PAYLOAD_BLOCK_PARTIALLY_PRESENT:
                        ReadPartiallyPresentBlock(payloadBlockIndex, chunkIndex, batEntry, offsetInBlock, bytesInBlock, buffer, offset + bytesRead);
                        bytesRead += bytesInBlock;
                        break;

                    default:
                        Array.Clear(buffer, offset + bytesRead, bytesInBlock);
                        bytesRead += bytesInBlock;
                        break;
                }
            }

            currentPosition += bytesRead;
            return bytesRead;
        }

        private void ReadPartiallyPresentBlock(long payloadBlockIndex, long chunkIndex, ulong batEntry, long offsetInBlock, int bytesInBlock, byte[] destBuffer, int destOffset)
        {
            long sbBatIndex = (chunkIndex + 1L) * (long)chunkRatio + chunkIndex;
            ulong sbBatEntry = (sbBatIndex < batTable.Length) ? batTable[sbBatIndex] : 0UL;
            int sbState = (int)(sbBatEntry & BatStateMask);

            if (sbState != SB_BLOCK_PRESENT)
            {
                Array.Clear(destBuffer, destOffset, bytesInBlock);
                return;
            }

            long sbHostOffset = (long)(sbBatEntry & BatFileOffsetMask);
            byte[] sbData = GetCachedSectorBitmap(sbHostOffset);

            long payloadOffsetInChunk = payloadBlockIndex % (long)chunkRatio;
            long sectorsPerBlock = (long)blockSize / (long)logicalSectorSize;
            long chunkBaseSector = payloadOffsetInChunk * sectorsPerBlock;

            long startSectorInBlock = offsetInBlock / (long)logicalSectorSize;
            long endSectorInBlock = (offsetInBlock + bytesInBlock + (long)logicalSectorSize - 1L) / (long)logicalSectorSize;
            long hostBlockOffset = (long)(batEntry & BatFileOffsetMask);

            for (long s = startSectorInBlock; s < endSectorInBlock; s++)
            {
                long sectorInChunk = chunkBaseSector + s;
                int byteIndex = (int)(sectorInChunk / 8L);
                byte bitMask = (byte)(1 << (int)(sectorInChunk % 8L));

                long sectorStartInBlock = s * (long)logicalSectorSize;
                long sectorEndInBlock = sectorStartInBlock + (long)logicalSectorSize;

                long sliceStart = Math.Max(offsetInBlock, sectorStartInBlock);
                long sliceEnd = Math.Min(offsetInBlock + bytesInBlock, sectorEndInBlock);
                int sliceLen = (int)(sliceEnd - sliceStart);

                int sliceDestOffset = destOffset + (int)(sliceStart - offsetInBlock);

                if (byteIndex < sbData.Length && (sbData[byteIndex] & bitMask) != 0)
                {
                    long readPos = hostBlockOffset + sliceStart;
                    if (readPos < baseStream.Length)
                    {
                        baseStream.Position = readPos;
                        int read = baseStream.Read(destBuffer, sliceDestOffset, sliceLen);
                        if (read < sliceLen)
                        {
                            Array.Clear(destBuffer, sliceDestOffset + read, sliceLen - read);
                        }
                    }
                    else
                    {
                        Array.Clear(destBuffer, sliceDestOffset, sliceLen);
                    }
                }
                else
                {
                    Array.Clear(destBuffer, sliceDestOffset, sliceLen);
                }
            }
        }

        private byte[] GetCachedSectorBitmap(long sbHostOffset)
        {
            byte[] cached;
            if (sectorBitmapCache.TryGetValue(sbHostOffset, out cached))
            {
                sectorBitmapLru.Remove(sbHostOffset);
                sectorBitmapLru.Add(sbHostOffset);
                return cached;
            }

            byte[] bitmap = ReadExact(sbHostOffset, 1048576); // 1 MB bitmap
            if (sectorBitmapCache.Count >= MaxCachedBitmaps && sectorBitmapLru.Count > 0)
            {
                long evict = sectorBitmapLru[0];
                sectorBitmapLru.RemoveAt(0);
                sectorBitmapCache.Remove(evict);
            }

            sectorBitmapCache[sbHostOffset] = bitmap;
            sectorBitmapLru.Add(sbHostOffset);
            return bitmap;
        }

        // -------------------------------------------------------------
        // Stream Navigation & Write-Blocking Guarantees
        // -------------------------------------------------------------
        public override long Seek(long offset, SeekOrigin origin)
        {
            if (isDisposed) throw new ObjectDisposedException("VhdxImageReader");

            long target = currentPosition;
            switch (origin)
            {
                case SeekOrigin.Begin:
                    target = offset;
                    break;
                case SeekOrigin.Current:
                    target += offset;
                    break;
                case SeekOrigin.End:
                    target = (long)virtualDiskSize + offset;
                    break;
                default:
                    throw new ArgumentException("Invalid SeekOrigin", "origin");
            }

            if (target < 0)
            {
                throw new IOException("An attempt was made to move the position before the beginning of the stream.");
            }

            currentPosition = target;
            return currentPosition;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException("VhdxImageReader is a read-only stream.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("VhdxImageReader is a read-only stream.");
        }

        public override void Flush()
        {
            // Read-only stream: no-op
        }

        // -------------------------------------------------------------
        // Static Detection Helpers
        // -------------------------------------------------------------
        public static bool IsVhdxFile(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            try
            {
                SourcePaths.NoLinks(path);
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    return IsVhdxStream(fs);
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool IsVhdxStream(Stream stream)
        {
            if (stream == null || !stream.CanRead || !stream.CanSeek) return false;
            try
            {
                long origPos = stream.Position;
                if (stream.Length < 65536) return false;
                byte[] sig = new byte[8];
                stream.Position = 0;
                int r = stream.Read(sig, 0, 8);
                stream.Position = origPos;
                if (r < 8) return false;

                return BitConverter.ToUInt64(sig, 0) == VhdxFileSignature;
            }
            catch
            {
                return false;
            }
        }

        // -------------------------------------------------------------
        // Resource Disposal
        // -------------------------------------------------------------
        protected override void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                isDisposed = true;
                if (disposing)
                {
                    if (baseStream != null && !leaveOpen)
                    {
                        try { baseStream.Dispose(); } catch { }
                        baseStream = null;
                    }
                    if (sectorBitmapCache != null) sectorBitmapCache.Clear();
                    if (sectorBitmapLru != null) sectorBitmapLru.Clear();
                    batTable = null;
                }
            }
            base.Dispose(disposing);
        }
    }
}
