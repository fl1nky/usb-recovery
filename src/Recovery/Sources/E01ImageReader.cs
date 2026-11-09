using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    public sealed class E01Metadata
    {
        public int SegmentNumber { get; set; }
        public int TotalSegments { get; set; }
        public long TotalSectors { get; set; }
        public int BytesPerSector { get; set; }
        public int SectorsPerChunk { get; set; }
        public string CaseNumber { get; set; }
        public string EvidenceNumber { get; set; }
        public string Examiner { get; set; }
        public string Description { get; set; }
        public string Notes { get; set; }
        public string AcquisitionDate { get; set; }
        public string SystemDate { get; set; }
        public string StoredMd5 { get; set; }
        public string StoredSha1 { get; set; }
        public List<string> SegmentPaths { get; set; }

        public long ChunkSize
        {
            get { return (long)BytesPerSector * (SectorsPerChunk > 0 ? SectorsPerChunk : 64); }
        }

        public long LogicalDiskSize
        {
            get { return TotalSectors * (BytesPerSector > 0 ? BytesPerSector : 512); }
        }

        public E01Metadata()
        {
            BytesPerSector = 512;
            SectorsPerChunk = 64;
            TotalSectors = 0;
            SegmentNumber = 1;
            TotalSegments = 1;
            CaseNumber = String.Empty;
            EvidenceNumber = String.Empty;
            Examiner = String.Empty;
            Description = String.Empty;
            Notes = String.Empty;
            AcquisitionDate = String.Empty;
            SystemDate = String.Empty;
            StoredMd5 = String.Empty;
            StoredSha1 = String.Empty;
            SegmentPaths = new List<string>();
        }
    }

    public sealed class E01ChunkEntry
    {
        public int SegmentIndex;
        public long FileOffset;
        public uint DataLength;
        public bool IsCompressed;

        public E01ChunkEntry()
        {
            SegmentIndex = 0;
            FileOffset = 0;
            DataLength = 0;
            IsCompressed = false;
        }

        public E01ChunkEntry(int segmentIndex, long offset, uint length, bool compressed)
        {
            SegmentIndex = segmentIndex;
            FileOffset = offset;
            DataLength = length;
            IsCompressed = compressed;
        }
    }

    // Native pure C# Stream implementation for Expert Witness Compression Format
    // (EnCase / Guymager / FTK Imager .E01 / .Ex01 forensic disk images).
    // Supports multi-segment files (.E01..E99, .EAA..EZZ), zlib chunk decompression,
    // LRU block caching, random-access seeking, and metadata recovery.
    public sealed class E01ImageReader : Stream
    {
        // Expert Witness Format file signature: EVF\t\r\n\xff\x00
        private static readonly byte[] E01Signature = new byte[] { 0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00 };

        private readonly E01Metadata metadata;
        private readonly List<FileStream> segmentStreams;
        private readonly List<E01ChunkEntry> chunks;
        private readonly Dictionary<int, byte[]> lruCache;
        private readonly List<int> lruOrder;
        private const int MaxCachedChunks = 64; // ~2 MB cache for typical 32 KiB chunks

        private long currentPosition;
        private bool isDisposed;

        public E01Metadata Metadata
        {
            get { return metadata; }
        }

        public int ChunkCount
        {
            get { return chunks.Count; }
        }

        public override bool CanRead
        {
            get { return !isDisposed; }
        }

        public override bool CanSeek
        {
            get { return !isDisposed; }
        }

        public override bool CanWrite
        {
            get { return false; }
        }

        public override long Length
        {
            get { return metadata.LogicalDiskSize; }
        }

        public override long Position
        {
            get { return currentPosition; }
            set { Seek(value, SeekOrigin.Begin); }
        }

        public static bool IsE01File(string path)
        {
            if (String.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length < 13) return false;
                    byte[] sig = new byte[8];
                    if (fs.Read(sig, 0, 8) < 8) return false;
                    return IsE01Signature(sig);
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool IsE01Signature(byte[] buffer)
        {
            if (buffer == null || buffer.Length < 8) return false;
            for (int i = 0; i < 8; i++)
            {
                if (buffer[i] != E01Signature[i]) return false;
            }
            return true;
        }

        public static E01ImageReader Open(string primaryFilePath)
        {
            if (String.IsNullOrEmpty(primaryFilePath))
                throw new ArgumentNullException("primaryFilePath");

            string fullPath = Path.GetFullPath(primaryFilePath);
            if (!File.Exists(fullPath))
                throw new FileNotFoundException("E01 image file not found: " + fullPath);

            List<string> segments = DiscoverSegments(fullPath);
            return new E01ImageReader(segments);
        }

        private E01ImageReader(List<string> segmentPaths)
        {
            metadata = new E01Metadata();
            metadata.SegmentPaths = new List<string>(segmentPaths);
            metadata.TotalSegments = segmentPaths.Count;

            segmentStreams = new List<FileStream>();
            chunks = new List<E01ChunkEntry>();
            lruCache = new Dictionary<int, byte[]>();
            lruOrder = new List<int>();

            try
            {
                for (int i = 0; i < segmentPaths.Count; i++)
                {
                    FileStream fs = new FileStream(segmentPaths[i], FileMode.Open, FileAccess.Read, FileShare.Read);
                    segmentStreams.Add(fs);
                    ParseSegment(fs, i);
                }

                if (metadata.TotalSectors == 0 && chunks.Count > 0)
                {
                    metadata.TotalSectors = (long)chunks.Count * metadata.SectorsPerChunk;
                }
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public static List<string> DiscoverSegments(string primaryPath)
        {
            List<string> result = new List<string>();
            result.Add(primaryPath);

            string dir = Path.GetDirectoryName(primaryPath);
            if (String.IsNullOrEmpty(dir)) dir = Directory.GetCurrentDirectory();
            string fileName = Path.GetFileName(primaryPath);
            string ext = Path.GetExtension(primaryPath);
            if (String.IsNullOrEmpty(ext)) return result;

            string baseName = fileName.Substring(0, fileName.Length - ext.Length);

            // Pattern 1: .E01, .E02, ..., .E99
            // Pattern 2: .EAA, .EAB, ..., .EZZ
            int segmentNumber = 2;
            while (true)
            {
                string nextExt;
                if (segmentNumber <= 99)
                {
                    nextExt = string.Format(System.Globalization.CultureInfo.InvariantCulture, ".E{0:D2}", segmentNumber);
                }
                else
                {
                    int alphaIndex = segmentNumber - 100;
                    char c1 = (char)('A' + (alphaIndex / 26));
                    char c2 = (char)('A' + (alphaIndex % 26));
                    if (c1 > 'Z') break;
                    nextExt = string.Format(System.Globalization.CultureInfo.InvariantCulture, ".E{0}{1}", c1, c2);
                }

                string candidate = Path.Combine(dir, baseName + nextExt);
                if (File.Exists(candidate))
                {
                    result.Add(candidate);
                    segmentNumber++;
                }
                else
                {
                    // Check lowercase extension as well
                    string candidateLower = Path.Combine(dir, baseName + nextExt.ToLowerInvariant());
                    if (File.Exists(candidateLower))
                    {
                        result.Add(candidateLower);
                        segmentNumber++;
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return result;
        }

        private void ParseSegment(FileStream fs, int segmentIndex)
        {
            if (fs.Length < 13) throw new InvalidDataException("Invalid E01 file: header truncated.");

            byte[] headerBytes = new byte[13];
            fs.Position = 0;
            if (fs.Read(headerBytes, 0, 13) < 13)
                throw new InvalidDataException("Unable to read E01 file header.");

            if (!IsE01Signature(headerBytes))
                throw new InvalidDataException("Not a valid Expert Witness Format (E01) file signature.");

            ushort segNum = BitConverter.ToUInt16(headerBytes, 9);
            if (segmentIndex == 0) metadata.SegmentNumber = segNum;

            long fileLen = fs.Length;
            long currentSectionOffset = 13;

            // Read section headers
            byte[] sectHdr = new byte[76];
            while (currentSectionOffset + 76 <= fileLen)
            {
                fs.Position = currentSectionOffset;
                int read = fs.Read(sectHdr, 0, 76);
                if (read < 76) break;

                string sectType = Encoding.ASCII.GetString(sectHdr, 0, 16).TrimEnd('\0', ' ');
                long nextSectOffset = (long)BitConverter.ToUInt64(sectHdr, 16);
                long sectSize = (long)BitConverter.ToUInt64(sectHdr, 24);

                if (sectType.Equals("header", StringComparison.OrdinalIgnoreCase) ||
                    sectType.Equals("header2", StringComparison.OrdinalIgnoreCase))
                {
                    ParseHeaderSection(fs, currentSectionOffset + 76, sectSize > 76 ? sectSize - 76 : 0);
                }
                else if (sectType.Equals("volume", StringComparison.OrdinalIgnoreCase) ||
                         sectType.Equals("disk", StringComparison.OrdinalIgnoreCase))
                {
                    ParseVolumeSection(fs, currentSectionOffset + 76);
                }
                else if (sectType.Equals("table", StringComparison.OrdinalIgnoreCase) ||
                         sectType.Equals("table2", StringComparison.OrdinalIgnoreCase))
                {
                    ParseTableSection(fs, segmentIndex, currentSectionOffset + 76, sectSize > 76 ? sectSize - 76 : 0);
                }
                else if (sectType.Equals("hash", StringComparison.OrdinalIgnoreCase))
                {
                    ParseHashSection(fs, currentSectionOffset + 76);
                }
                else if (sectType.Equals("done", StringComparison.OrdinalIgnoreCase) ||
                         sectType.Equals("next", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                if (nextSectOffset <= currentSectionOffset || nextSectOffset >= fileLen)
                {
                    break;
                }
                currentSectionOffset = nextSectOffset;
            }
        }

        private void ParseHeaderSection(FileStream fs, long dataOffset, long length)
        {
            if (length <= 0) return;
            long readLen = Math.Min(length, 65536);
            byte[] raw = new byte[readLen];
            fs.Position = dataOffset;
            int r = fs.Read(raw, 0, (int)readLen);
            if (r <= 0) return;

            string headerText = String.Empty;
            // E01 header is typically zlib compressed
            if (raw.Length > 2 && raw[0] == 0x78)
            {
                try
                {
                    using (MemoryStream ms = new MemoryStream(raw, 2, r - 2, false))
                    using (DeflateStream def = new DeflateStream(ms, CompressionMode.Decompress))
                    using (StreamReader sr = new StreamReader(def, Encoding.UTF8))
                    {
                        headerText = sr.ReadToEnd();
                    }
                }
                catch
                {
                    headerText = Encoding.UTF8.GetString(raw, 0, r);
                }
            }
            else
            {
                headerText = Encoding.UTF8.GetString(raw, 0, r);
            }

            if (!String.IsNullOrEmpty(headerText))
            {
                ParseMetadataLines(headerText);
            }
        }

        private void ParseMetadataLines(string text)
        {
            string[] lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                int tabIdx = line.IndexOf('\t');
                if (tabIdx <= 0) continue;

                string key = line.Substring(0, tabIdx).Trim().ToLowerInvariant();
                string val = line.Substring(tabIdx + 1).Trim();

                if (key == "c" || key == "case") metadata.CaseNumber = val;
                else if (key == "e" || key == "evidence") metadata.EvidenceNumber = val;
                else if (key == "a" || key == "examiner") metadata.Examiner = val;
                else if (key == "d" || key == "description") metadata.Description = val;
                else if (key == "n" || key == "notes") metadata.Notes = val;
                else if (key == "av" || key == "acq_date") metadata.AcquisitionDate = val;
                else if (key == "ov" || key == "sys_date") metadata.SystemDate = val;
            }
        }

        private void ParseVolumeSection(FileStream fs, long dataOffset)
        {
            byte[] volBytes = new byte[64];
            fs.Position = dataOffset;
            if (fs.Read(volBytes, 0, 64) < 64) return;

            uint chunkCount = BitConverter.ToUInt32(volBytes, 4);
            uint sectorsPerChunk = BitConverter.ToUInt32(volBytes, 8);
            uint bytesPerSector = BitConverter.ToUInt32(volBytes, 12);
            ulong totalSectors = BitConverter.ToUInt64(volBytes, 16);

            if (bytesPerSector > 0 && bytesPerSector <= 65536)
                metadata.BytesPerSector = (int)bytesPerSector;
            if (sectorsPerChunk > 0 && sectorsPerChunk <= 1024)
                metadata.SectorsPerChunk = (int)sectorsPerChunk;
            if (totalSectors > 0)
                metadata.TotalSectors = (long)totalSectors;
            else if (chunkCount > 0)
                metadata.TotalSectors = (long)chunkCount * metadata.SectorsPerChunk;
        }

        private void ParseTableSection(FileStream fs, int segmentIndex, long dataOffset, long length)
        {
            if (length < 24) return;
            byte[] tblHdr = new byte[24];
            fs.Position = dataOffset;
            if (fs.Read(tblHdr, 0, 24) < 24) return;

            uint entryCount = BitConverter.ToUInt32(tblHdr, 0);
            long baseOffset = (long)BitConverter.ToUInt64(tblHdr, 8);

            if (entryCount == 0 || entryCount > 1000000) return;

            int tableDataLen = (int)(entryCount * 4);
            byte[] tableBytes = new byte[tableDataLen];
            if (fs.Read(tableBytes, 0, tableDataLen) < tableDataLen) return;

            for (uint i = 0; i < entryCount; i++)
            {
                uint val = BitConverter.ToUInt32(tableBytes, (int)(i * 4));
                bool compressed = (val & 0x80000000u) != 0;
                long relativeOffset = val & 0x7FFFFFFFu;
                long chunkFileOffset = baseOffset + relativeOffset;

                // Estimate chunk length using next entry if available
                uint chunkLen = (uint)metadata.ChunkSize;
                if (i + 1 < entryCount)
                {
                    uint nextVal = BitConverter.ToUInt32(tableBytes, (int)((i + 1) * 4));
                    long nextRel = nextVal & 0x7FFFFFFFu;
                    if (nextRel > relativeOffset)
                    {
                        chunkLen = (uint)(nextRel - relativeOffset);
                    }
                }

                chunks.Add(new E01ChunkEntry(segmentIndex, chunkFileOffset, chunkLen, compressed));
            }
        }

        private void ParseHashSection(FileStream fs, long dataOffset)
        {
            byte[] hashBytes = new byte[36];
            fs.Position = dataOffset;
            int r = fs.Read(hashBytes, 0, 36);
            if (r >= 16)
            {
                metadata.StoredMd5 = BytesToHex(hashBytes, 0, 16);
            }
            if (r >= 36)
            {
                metadata.StoredSha1 = BytesToHex(hashBytes, 16, 20);
            }
        }

        private static string BytesToHex(byte[] buffer, int offset, int length)
        {
            StringBuilder sb = new StringBuilder(length * 2);
            int end = offset + length;
            for (int i = offset; i < end; i++)
            {
                sb.Append(buffer[i].ToString("x2"));
            }
            return sb.ToString();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
                throw new ArgumentOutOfRangeException("offset");
            if (isDisposed) throw new ObjectDisposedException("E01ImageReader");

            long totalLen = metadata.LogicalDiskSize;
            if (currentPosition >= totalLen || count == 0 || chunks.Count == 0) return 0;

            long available = totalLen - currentPosition;
            int toRead = (int)Math.Min((long)count, available);

            int bytesRead = 0;
            long chunkSize = metadata.ChunkSize;

            while (bytesRead < toRead)
            {
                long currentLogical = currentPosition + bytesRead;
                int chunkIndex = (int)(currentLogical / chunkSize);
                if (chunkIndex >= chunks.Count) break;

                long offsetInChunk = currentLogical % chunkSize;
                int bytesInThisChunk = (int)Math.Min((long)(toRead - bytesRead), chunkSize - offsetInChunk);

                byte[] decompressedChunk = GetChunkData(chunkIndex);
                if (decompressedChunk == null || decompressedChunk.Length == 0)
                {
                    // Zero-fill unreadable / missing chunk
                    Array.Clear(buffer, offset + bytesRead, bytesInThisChunk);
                }
                else
                {
                    int copyLen = (int)Math.Min((long)bytesInThisChunk, Math.Max(0, decompressedChunk.Length - offsetInChunk));
                    if (copyLen > 0)
                    {
                        Array.Copy(decompressedChunk, offsetInChunk, buffer, offset + bytesRead, copyLen);
                    }
                    if (copyLen < bytesInThisChunk)
                    {
                        Array.Clear(buffer, offset + bytesRead + copyLen, bytesInThisChunk - copyLen);
                    }
                }

                bytesRead += bytesInThisChunk;
            }

            currentPosition += bytesRead;
            return bytesRead;
        }

        private byte[] GetChunkData(int chunkIndex)
        {
            // 1. Check LRU cache
            byte[] cached;
            if (lruCache.TryGetValue(chunkIndex, out cached))
            {
                // Touch cache order
                lruOrder.Remove(chunkIndex);
                lruOrder.Add(chunkIndex);
                return cached;
            }

            // 2. Read chunk from disk segment
            if (chunkIndex < 0 || chunkIndex >= chunks.Count) return null;
            E01ChunkEntry chunk = chunks[chunkIndex];
            if (chunk.SegmentIndex < 0 || chunk.SegmentIndex >= segmentStreams.Count) return null;

            FileStream fs = segmentStreams[chunk.SegmentIndex];
            int readLen = (int)Math.Max(chunk.DataLength, (uint)metadata.ChunkSize);
            if (chunk.FileOffset + readLen > fs.Length)
            {
                readLen = (int)Math.Max(0, fs.Length - chunk.FileOffset);
            }
            if (readLen <= 0) return null;

            byte[] rawData = new byte[readLen];
            fs.Position = chunk.FileOffset;
            int r = fs.Read(rawData, 0, readLen);
            if (r <= 0) return null;

            byte[] decompressed;
            if (!chunk.IsCompressed)
            {
                decompressed = rawData;
            }
            else
            {
                decompressed = DecompressZlibChunk(rawData, r, (int)metadata.ChunkSize);
            }

            if (decompressed != null)
            {
                PutInCache(chunkIndex, decompressed);
            }

            return decompressed;
        }

        private static byte[] DecompressZlibChunk(byte[] raw, int length, int expectedUncompressedSize)
        {
            if (raw == null || length <= 2) return null;

            // In E01, zlib compressed chunks begin with standard 2-byte header 0x78
            int skipHeader = (raw[0] == 0x78) ? 2 : 0;
            int deflateLen = length - skipHeader;
            if (deflateLen <= 0) return null;

            try
            {
                using (MemoryStream ms = new MemoryStream(raw, skipHeader, deflateLen, false))
                using (DeflateStream def = new DeflateStream(ms, CompressionMode.Decompress))
                using (MemoryStream dest = new MemoryStream(expectedUncompressedSize > 0 ? expectedUncompressedSize : 32768))
                {
                    byte[] buf = new byte[8192];
                    int read;
                    while ((read = def.Read(buf, 0, buf.Length)) > 0)
                    {
                        dest.Write(buf, 0, read);
                        if (expectedUncompressedSize > 0 && dest.Length >= expectedUncompressedSize) break;
                    }
                    return dest.ToArray();
                }
            }
            catch
            {
                // Return raw buffer if deflate decompression fails
                return raw;
            }
        }

        private void PutInCache(int chunkIndex, byte[] data)
        {
            if (lruCache.Count >= MaxCachedChunks && lruOrder.Count > 0)
            {
                int evict = lruOrder[0];
                lruOrder.RemoveAt(0);
                lruCache.Remove(evict);
            }
            lruCache[chunkIndex] = data;
            lruOrder.Add(chunkIndex);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            if (isDisposed) throw new ObjectDisposedException("E01ImageReader");

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
                    newPos = metadata.LogicalDiskSize + offset;
                    break;
            }

            if (newPos < 0) throw new IOException("An attempt was made to move the position before the beginning of the stream.");
            currentPosition = newPos;
            return currentPosition;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException("E01ImageReader is a read-only stream.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("E01ImageReader is a read-only stream.");
        }

        public override void Flush()
        {
        }

        protected override void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                isDisposed = true;
                if (disposing)
                {
                    foreach (FileStream fs in segmentStreams)
                    {
                        try { fs.Dispose(); } catch { }
                    }
                    segmentStreams.Clear();
                    lruCache.Clear();
                    lruOrder.Clear();
                }
            }
            base.Dispose(disposing);
        }
    }
}
