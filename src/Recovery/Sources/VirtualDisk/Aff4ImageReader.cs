using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    public sealed class Aff4Metadata
    {
        public string SubjectUrn { get; set; }
        public long Size { get; set; }
        public int ChunkSize { get; set; }
        public int ChunksPerSegment { get; set; }
        public string Compression { get; set; }
        public string TargetUrn { get; set; }
        public string DataStreamUrn { get; set; }
        public string CaseNumber { get; set; }
        public string EvidenceNumber { get; set; }
        public string Examiner { get; set; }
        public string AcquisitionDate { get; set; }
        public string StoredSha256 { get; set; }
        public string StoredMd5 { get; set; }
        public Dictionary<string, string> Properties { get; private set; }

        public Aff4Metadata()
        {
            SubjectUrn = String.Empty;
            Size = 0;
            ChunkSize = 32768; // 32 KiB default
            ChunksPerSegment = 1024;
            Compression = "Deflate";
            TargetUrn = String.Empty;
            DataStreamUrn = String.Empty;
            CaseNumber = String.Empty;
            EvidenceNumber = String.Empty;
            Examiner = String.Empty;
            AcquisitionDate = String.Empty;
            StoredSha256 = String.Empty;
            StoredMd5 = String.Empty;
            Properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public sealed class Aff4MapRange
    {
        public long VirtualOffset;
        public long TargetOffset;
        public long Length;
        public string TargetEntryName;

        public Aff4MapRange(long virtualOffset, long targetOffset, long length, string targetEntryName)
        {
            VirtualOffset = virtualOffset;
            TargetOffset = targetOffset;
            Length = length;
            TargetEntryName = targetEntryName ?? String.Empty;
        }
    }

    /// <summary>
    /// Native pure C# Stream implementation for Advanced Forensic Format 4 (AFF4) containers.
    /// Supports RDF Turtle manifest parsing, linear and segmented data streams, AFF4 map indexing,
    /// Deflate and Snappy decompression, LRU chunk caching, seeking, and strict write-blocking.
    /// </summary>
    public sealed class Aff4ImageReader : Stream
    {
        private static readonly byte[] ZipMagic = new byte[] { 0x50, 0x4B, 0x03, 0x04 };

        private readonly string filePath;
        private readonly Stream sourceStream;
        private readonly bool leaveOpen;
        private readonly ZipArchive zipArchive;
        private readonly Aff4Metadata metadata;
        private readonly List<Aff4MapRange> mapRanges;
        private readonly List<ZipArchiveEntry> segmentEntries;
        private readonly ZipArchiveEntry singleDataEntry;

        private readonly Dictionary<int, byte[]> chunkCache;
        private readonly List<int> chunkLruOrder;
        private const int MaxCachedChunks = 64; // ~2 MB cache

        private long currentPosition;
        private bool isDisposed;

        public Aff4Metadata Metadata { get { return metadata; } }
        public string FilePath { get { return filePath; } }

        public override bool CanRead { get { return !isDisposed; } }
        public override bool CanSeek { get { return !isDisposed; } }
        public override bool CanWrite { get { return false; } }

        public override long Length
        {
            get
            {
                ThrowIfDisposed();
                return metadata.Size;
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

        public static bool IsAff4File(string path)
        {
            if (String.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length < 30) return false;
                    byte[] header = new byte[4];
                    if (fs.Read(header, 0, 4) < 4) return false;
                    if (header[0] != ZipMagic[0] || header[1] != ZipMagic[1] || header[2] != ZipMagic[2] || header[3] != ZipMagic[3])
                    {
                        return false;
                    }

                    // Scan zip entries for *.turtle
                    fs.Seek(0, SeekOrigin.Begin);
                    using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Read, true))
                    {
                        foreach (ZipArchiveEntry entry in zip.Entries)
                        {
                            if (entry.FullName.EndsWith(".turtle", StringComparison.OrdinalIgnoreCase) ||
                                entry.FullName.EndsWith("information.turtle", StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch
            {
                return false;
            }
            return false;
        }

        public static Aff4ImageReader Open(string path)
        {
            if (path == null) throw new ArgumentNullException("path");
            if (!File.Exists(path)) throw new FileNotFoundException("AFF4 image not found: " + path, path);

            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            try
            {
                return new Aff4ImageReader(fs, path, false);
            }
            catch
            {
                fs.Dispose();
                throw;
            }
        }

        public static Aff4ImageReader Open(Stream stream, bool leaveOpen = false)
        {
            if (stream == null) throw new ArgumentNullException("stream");
            return new Aff4ImageReader(stream, null, leaveOpen);
        }

        public Aff4ImageReader(Stream stream, string filePath, bool leaveOpen)
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

            this.chunkCache = new Dictionary<int, byte[]>();
            this.chunkLruOrder = new List<int>();
            this.mapRanges = new List<Aff4MapRange>();
            this.segmentEntries = new List<ZipArchiveEntry>();

            this.zipArchive = new ZipArchive(stream, ZipArchiveMode.Read, true);
            this.metadata = ParseTurtleMetadata(zipArchive);

            // Locate data entries or map entries
            LocateDataStreams(zipArchive, metadata, out singleDataEntry, segmentEntries, mapRanges);

            if (metadata.Size == 0)
            {
                // If turtle did not specify size, infer from data entries
                if (singleDataEntry != null)
                {
                    metadata.Size = singleDataEntry.Length;
                }
                else if (segmentEntries.Count > 0)
                {
                    long total = 0;
                    foreach (ZipArchiveEntry seg in segmentEntries)
                    {
                        total += seg.Length;
                    }
                    metadata.Size = total;
                }
                else if (mapRanges.Count > 0)
                {
                    long maxEnd = 0;
                    foreach (Aff4MapRange r in mapRanges)
                    {
                        if (r.VirtualOffset + r.Length > maxEnd)
                        {
                            maxEnd = r.VirtualOffset + r.Length;
                        }
                    }
                    metadata.Size = maxEnd;
                }
            }
        }

        private static Aff4Metadata ParseTurtleMetadata(ZipArchive zip)
        {
            Aff4Metadata meta = new Aff4Metadata();

            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                if (entry.FullName.EndsWith(".turtle", StringComparison.OrdinalIgnoreCase))
                {
                    using (StreamReader reader = new StreamReader(entry.Open(), Encoding.UTF8))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;

                            if (line.StartsWith("<aff4://", StringComparison.OrdinalIgnoreCase))
                            {
                                int closeIdx = line.IndexOf('>');
                                if (closeIdx > 0 && string.IsNullOrEmpty(meta.SubjectUrn))
                                {
                                    meta.SubjectUrn = line.Substring(1, closeIdx - 1);
                                }
                            }

                            ParseTurtleProperty(line, meta);
                        }
                    }
                }
            }

            return meta;
        }

        private static void ParseTurtleProperty(string line, Aff4Metadata meta)
        {
            // Parse common RDF Turtle predicates
            // e.g. aff4:size 1073741824 ;
            // e.g. <http://aff4.org/Schema#size> 1073741824 .
            // e.g. aff4:chunk_size 32768 ;
            // e.g. aff4:compression aff4:Deflate ;
            Match mSize = Regex.Match(line, @"(?:aff4:size|<http://aff4\.org/Schema#size>)\s+""?(\d+)""?", RegexOptions.IgnoreCase);
            if (mSize.Success)
            {
                long sz;
                if (long.TryParse(mSize.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out sz))
                {
                    meta.Size = sz;
                }
            }

            Match mChunk = Regex.Match(line, @"(?:aff4:chunk_?size|<http://aff4\.org/Schema#chunk_?size>)\s+""?(\d+)""?", RegexOptions.IgnoreCase);
            if (mChunk.Success)
            {
                int csz;
                if (int.TryParse(mChunk.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out csz) && csz > 0)
                {
                    meta.ChunkSize = csz;
                }
            }

            Match mChunksPerSeg = Regex.Match(line, @"(?:aff4:chunks_per_segment|<http://aff4\.org/Schema#chunks_per_segment>)\s+""?(\d+)""?", RegexOptions.IgnoreCase);
            if (mChunksPerSeg.Success)
            {
                int cps;
                if (int.TryParse(mChunksPerSeg.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out cps) && cps > 0)
                {
                    meta.ChunksPerSegment = cps;
                }
            }

            Match mComp = Regex.Match(line, @"(?:aff4:compression|<http://aff4\.org/Schema#compression>)\s+(?:aff4:|<http://aff4\.org/Schema#)?(\w+)>?", RegexOptions.IgnoreCase);
            if (mComp.Success)
            {
                meta.Compression = mComp.Groups[1].Value;
            }

            Match mTarget = Regex.Match(line, @"(?:aff4:target|<http://aff4\.org/Schema#target>)\s+<([^>]+)>", RegexOptions.IgnoreCase);
            if (mTarget.Success)
            {
                meta.TargetUrn = mTarget.Groups[1].Value;
            }

            Match mDataStream = Regex.Match(line, @"(?:aff4:dataStream|<http://aff4\.org/Schema#dataStream>)\s+<([^>]+)>", RegexOptions.IgnoreCase);
            if (mDataStream.Success)
            {
                meta.DataStreamUrn = mDataStream.Groups[1].Value;
            }

            Match mCase = Regex.Match(line, @"(?:aff4:caseNumber|<http://aff4\.org/Schema#caseNumber>)\s+""([^""]+)""", RegexOptions.IgnoreCase);
            if (mCase.Success)
            {
                meta.CaseNumber = mCase.Groups[1].Value;
            }

            Match mEvidence = Regex.Match(line, @"(?:aff4:evidenceNumber|<http://aff4\.org/Schema#evidenceNumber>)\s+""([^""]+)""", RegexOptions.IgnoreCase);
            if (mEvidence.Success)
            {
                meta.EvidenceNumber = mEvidence.Groups[1].Value;
            }

            Match mExaminer = Regex.Match(line, @"(?:aff4:examiner|<http://aff4\.org/Schema#examiner>)\s+""([^""]+)""", RegexOptions.IgnoreCase);
            if (mExaminer.Success)
            {
                meta.Examiner = mExaminer.Groups[1].Value;
            }

            Match mSha256 = Regex.Match(line, @"(?:aff4:storedSha256|<http://aff4\.org/Schema#storedSha256>)\s+""([a-fA-F0-9]{64})""", RegexOptions.IgnoreCase);
            if (mSha256.Success)
            {
                meta.StoredSha256 = mSha256.Groups[1].Value;
            }

            Match mMd5 = Regex.Match(line, @"(?:aff4:storedMd5|<http://aff4\.org/Schema#storedMd5>)\s+""([a-fA-F0-9]{32})""", RegexOptions.IgnoreCase);
            if (mMd5.Success)
            {
                meta.StoredMd5 = mMd5.Groups[1].Value;
            }
        }

        private static void LocateDataStreams(ZipArchive zip, Aff4Metadata meta,
            out ZipArchiveEntry singleData, List<ZipArchiveEntry> segments, List<Aff4MapRange> mapList)
        {
            singleData = null;

            // 1. Look for binary map file (e.g. "map" or ending with "/map")
            ZipArchiveEntry mapEntry = null;
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                if (entry.FullName.Equals("map", StringComparison.OrdinalIgnoreCase) ||
                    entry.FullName.EndsWith("/map", StringComparison.OrdinalIgnoreCase))
                {
                    mapEntry = entry;
                    break;
                }
            }

            if (mapEntry != null)
            {
                ParseMapStream(mapEntry, mapList);
                if (mapList.Count > 0) return;
            }

            // 2. Look for sequential segment entries (e.g. 00000000, 00000001 or part0, part1)
            List<ZipArchiveEntry> potentialSegments = new List<ZipArchiveEntry>();
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                if (entry.FullName.EndsWith(".turtle", StringComparison.OrdinalIgnoreCase) ||
                    entry.FullName.Equals("version.txt", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string name = Path.GetFileName(entry.FullName);
                if (Regex.IsMatch(name, @"^\d{8}$") || Regex.IsMatch(name, @"^part\d+$", RegexOptions.IgnoreCase))
                {
                    potentialSegments.Add(entry);
                }
            }

            if (potentialSegments.Count > 0)
            {
                potentialSegments.Sort(delegate(ZipArchiveEntry a, ZipArchiveEntry b)
                {
                    return String.Compare(a.FullName, b.FullName, StringComparison.Ordinal);
                });
                segments.AddRange(potentialSegments);
                return;
            }

            // 3. Look for single data entry (e.g. "data", "disk.raw", or the only large entry)
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                if (entry.FullName.EndsWith(".turtle", StringComparison.OrdinalIgnoreCase) ||
                    entry.FullName.Equals("version.txt", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string name = Path.GetFileName(entry.FullName);
                if (name.Equals("data", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("disk.raw", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("image.raw", StringComparison.OrdinalIgnoreCase))
                {
                    singleData = entry;
                    return;
                }
            }

            // Fallback: pick the first non-metadata entry
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                if (!entry.FullName.EndsWith(".turtle", StringComparison.OrdinalIgnoreCase) &&
                    !entry.FullName.Equals("version.txt", StringComparison.OrdinalIgnoreCase))
                {
                    singleData = entry;
                    break;
                }
            }
        }

        private static void ParseMapStream(ZipArchiveEntry mapEntry, List<Aff4MapRange> mapList)
        {
            try
            {
                using (Stream s = mapEntry.Open())
                using (BinaryReader r = new BinaryReader(s))
                {
                    // AFF4 Map streams typically contain records of:
                    // (long map_offset, long target_offset, long length) = 24 bytes
                    // or with 32-byte header.
                    byte[] data = new byte[s.Length];
                    int total = 0;
                    while (total < data.Length)
                    {
                        int read = s.Read(data, total, data.Length - total);
                        if (read <= 0) break;
                        total += read;
                    }

                    int offset = 0;
                    // Check for optional 32-byte header
                    if (total >= 32 && (total % 24 != 0) && ((total - 32) % 24 == 0))
                    {
                        offset = 32;
                    }

                    while (offset + 24 <= total)
                    {
                        long mapOffset = BitConverter.ToInt64(data, offset);
                        long targetOffset = BitConverter.ToInt64(data, offset + 8);
                        long length = BitConverter.ToInt64(data, offset + 16);

                        if (length > 0)
                        {
                            mapList.Add(new Aff4MapRange(mapOffset, targetOffset, length, String.Empty));
                        }
                        offset += 24;
                    }
                }
            }
            catch
            {
                // Ignored fallback
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ThrowIfDisposed();
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0 || count < 0 || offset + count > buffer.Length) throw new ArgumentOutOfRangeException();
            if (count == 0 || currentPosition >= metadata.Size) return 0;

            long remainingDisk = metadata.Size - currentPosition;
            int toRead = (int)Math.Min(count, remainingDisk);
            int totalBytesRead = 0;

            int chunkSize = metadata.ChunkSize > 0 ? metadata.ChunkSize : 32768;

            while (totalBytesRead < toRead)
            {
                long pos = currentPosition;
                int chunkIndex = (int)(pos / chunkSize);
                int offsetInChunk = (int)(pos % chunkSize);
                int bytesInThisChunk = (int)Math.Min(chunkSize - offsetInChunk, toRead - totalBytesRead);

                byte[] chunkData = GetOrLoadChunk(chunkIndex);

                if (chunkData != null && chunkData.Length > offsetInChunk)
                {
                    int copyLen = Math.Min(bytesInThisChunk, chunkData.Length - offsetInChunk);
                    Buffer.BlockCopy(chunkData, offsetInChunk, buffer, offset + totalBytesRead, copyLen);
                    if (copyLen < bytesInThisChunk)
                    {
                        Array.Clear(buffer, offset + totalBytesRead + copyLen, bytesInThisChunk - copyLen);
                    }
                }
                else
                {
                    // Sparse / missing: fill zeros
                    Array.Clear(buffer, offset + totalBytesRead, bytesInThisChunk);
                }

                currentPosition += bytesInThisChunk;
                totalBytesRead += bytesInThisChunk;
            }

            return totalBytesRead;
        }

        private byte[] GetOrLoadChunk(int chunkIndex)
        {
            byte[] cached;
            if (chunkCache.TryGetValue(chunkIndex, out cached))
            {
                chunkLruOrder.Remove(chunkIndex);
                chunkLruOrder.Add(chunkIndex);
                return cached;
            }

            byte[] loaded = LoadChunkData(chunkIndex);
            if (loaded != null)
            {
                if (chunkCache.Count >= MaxCachedChunks && chunkLruOrder.Count > 0)
                {
                    int oldest = chunkLruOrder[0];
                    chunkLruOrder.RemoveAt(0);
                    chunkCache.Remove(oldest);
                }
                chunkCache[chunkIndex] = loaded;
                chunkLruOrder.Add(chunkIndex);
            }

            return loaded;
        }

        private byte[] LoadChunkData(int chunkIndex)
        {
            int chunkSize = metadata.ChunkSize > 0 ? metadata.ChunkSize : 32768;
            long virtualOffset = (long)chunkIndex * chunkSize;

            // Scenario 1: Map ranges
            if (mapRanges.Count > 0)
            {
                foreach (Aff4MapRange range in mapRanges)
                {
                    if (virtualOffset >= range.VirtualOffset && virtualOffset < range.VirtualOffset + range.Length)
                    {
                        long offsetInRange = virtualOffset - range.VirtualOffset;
                        long readTargetOffset = range.TargetOffset + offsetInRange;
                        int toRead = (int)Math.Min(chunkSize, range.Length - offsetInRange);

                        return ReadRawChunkFromStream(sourceStream, readTargetOffset, toRead, chunkSize);
                    }
                }
                return new byte[chunkSize]; // sparse
            }

            // Scenario 2: Segment entries
            if (segmentEntries.Count > 0)
            {
                int chunksPerSeg = metadata.ChunksPerSegment > 0 ? metadata.ChunksPerSegment : 1024;
                int segIndex = chunkIndex / chunksPerSeg;
                int chunkInSeg = chunkIndex % chunksPerSeg;

                if (segIndex < segmentEntries.Count)
                {
                    ZipArchiveEntry entry = segmentEntries[segIndex];
                    return ReadChunkFromZipEntry(entry, (long)chunkInSeg * chunkSize, chunkSize);
                }
                return new byte[chunkSize];
            }

            // Scenario 3: Single data entry
            if (singleDataEntry != null)
            {
                return ReadChunkFromZipEntry(singleDataEntry, virtualOffset, chunkSize);
            }

            return null;
        }

        private byte[] ReadChunkFromZipEntry(ZipArchiveEntry entry, long entryOffset, int expectedSize)
        {
            try
            {
                using (Stream s = entry.Open())
                {
                    // Seek forward to entryOffset
                    if (s.CanSeek)
                    {
                        s.Seek(entryOffset, SeekOrigin.Begin);
                    }
                    else
                    {
                        byte[] discard = new byte[8192];
                        long skipped = 0;
                        while (skipped < entryOffset)
                        {
                            int skipRead = (int)Math.Min(discard.Length, entryOffset - skipped);
                            int r = s.Read(discard, 0, skipRead);
                            if (r <= 0) break;
                            skipped += r;
                        }
                    }

                    byte[] chunk = new byte[expectedSize];
                    int totalRead = 0;
                    while (totalRead < expectedSize)
                    {
                        int r = s.Read(chunk, totalRead, expectedSize - totalRead);
                        if (r <= 0) break;
                        totalRead += r;
                    }

                    // Check if chunk is snappy compressed
                    if (string.Equals(metadata.Compression, "Snappy", StringComparison.OrdinalIgnoreCase))
                    {
                        byte[] decomp = DecompressSnappy(chunk, totalRead);
                        if (decomp != null) return decomp;
                    }

                    if (totalRead < expectedSize)
                    {
                        byte[] trimmed = new byte[totalRead];
                        Buffer.BlockCopy(chunk, 0, trimmed, 0, totalRead);
                        return trimmed;
                    }
                    return chunk;
                }
            }
            catch
            {
                return null;
            }
        }

        private static byte[] ReadRawChunkFromStream(Stream s, long offset, int length, int expectedSize)
        {
            try
            {
                s.Seek(offset, SeekOrigin.Begin);
                byte[] buf = new byte[length];
                int total = 0;
                while (total < length)
                {
                    int r = s.Read(buf, total, length - total);
                    if (r <= 0) break;
                    total += r;
                }
                return buf;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Pure C# implementation of Snappy decompressor (Snappy framing and raw LZ77 block format).
        /// </summary>
        public static byte[] DecompressSnappy(byte[] input, int length)
        {
            if (input == null || length <= 0) return null;

            int pos = 0;

            // Check for Snappy Framing Header: 0xFF 0x06 0x00 0x00 "sNaPpY"
            if (length >= 10 &&
                input[0] == 0xFF && input[1] == 0x06 && input[2] == 0x00 && input[3] == 0x00 &&
                input[4] == 0x73 && input[5] == 0x4E && input[6] == 0x61 && input[7] == 0x50 &&
                input[8] == 0x70 && input[9] == 0x59)
            {
                pos = 10;
                using (MemoryStream ms = new MemoryStream())
                {
                    while (pos + 4 <= length)
                    {
                        byte chunkType = input[pos++];
                        int chunkLen = input[pos++] | (input[pos++] << 8) | (input[pos++] << 16);
                        if (pos + chunkLen > length) break;

                        if (chunkType == 0x00) // Uncompressed
                        {
                            // Skip 4-byte CRC
                            if (chunkLen > 4)
                            {
                                ms.Write(input, pos + 4, chunkLen - 4);
                            }
                        }
                        else if (chunkType == 0x01) // Compressed
                        {
                            if (chunkLen > 4)
                            {
                                byte[] raw = DecompressRawSnappy(input, pos + 4, chunkLen - 4);
                                if (raw != null)
                                {
                                    ms.Write(raw, 0, raw.Length);
                                }
                            }
                        }
                        pos += chunkLen;
                    }
                    return ms.ToArray();
                }
            }

            // Raw Snappy block decompression
            return DecompressRawSnappy(input, 0, length);
        }

        private static byte[] DecompressRawSnappy(byte[] input, int offset, int length)
        {
            if (input == null || length <= 0) return null;

            int pos = offset;
            int end = offset + length;

            // 1. Read varint uncompressed length
            int uncompressedLength = 0;
            int shift = 0;
            while (pos < end)
            {
                byte b = input[pos++];
                uncompressedLength |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
                if (shift > 35) return null;
            }

            if (uncompressedLength <= 0 || uncompressedLength > 100 * 1024 * 1024)
            {
                return null;
            }

            byte[] output = new byte[uncompressedLength];
            int outPos = 0;

            while (pos < end && outPos < uncompressedLength)
            {
                byte tag = input[pos++];
                int tagType = tag & 0x03;

                if (tagType == 0)
                {
                    // Literal
                    int litLen = (tag >> 2);
                    if (litLen < 60)
                    {
                        litLen += 1;
                    }
                    else if (litLen == 60)
                    {
                        if (pos >= end) break;
                        litLen = input[pos++] + 1;
                    }
                    else if (litLen == 61)
                    {
                        if (pos + 2 > end) break;
                        litLen = (input[pos++] | (input[pos++] << 8)) + 1;
                    }
                    else if (litLen == 62)
                    {
                        if (pos + 3 > end) break;
                        litLen = (input[pos++] | (input[pos++] << 8) | (input[pos++] << 16)) + 1;
                    }
                    else // 63
                    {
                        if (pos + 4 > end) break;
                        litLen = (input[pos++] | (input[pos++] << 8) | (input[pos++] << 16) | (input[pos++] << 24)) + 1;
                    }

                    int copyLen = Math.Min(litLen, Math.Min(end - pos, uncompressedLength - outPos));
                    Buffer.BlockCopy(input, pos, output, outPos, copyLen);
                    pos += copyLen;
                    outPos += copyLen;
                }
                else if (tagType == 1)
                {
                    // Copy 1-byte offset
                    if (pos >= end) break;
                    int copyLen = ((tag >> 2) & 0x07) + 4;
                    int copyOffset = ((tag >> 5) << 8) | input[pos++];

                    if (copyOffset <= 0 || copyOffset > outPos) break;

                    for (int i = 0; i < copyLen && outPos < uncompressedLength; i++)
                    {
                        output[outPos] = output[outPos - copyOffset];
                        outPos++;
                    }
                }
                else if (tagType == 2)
                {
                    // Copy 2-byte offset
                    if (pos + 2 > end) break;
                    int copyLen = (tag >> 2) + 1;
                    int copyOffset = input[pos++] | (input[pos++] << 8);

                    if (copyOffset <= 0 || copyOffset > outPos) break;

                    for (int i = 0; i < copyLen && outPos < uncompressedLength; i++)
                    {
                        output[outPos] = output[outPos - copyOffset];
                        outPos++;
                    }
                }
                else // tagType == 3
                {
                    // Copy 4-byte offset
                    if (pos + 4 > end) break;
                    int copyLen = (tag >> 2) + 1;
                    int copyOffset = input[pos++] | (input[pos++] << 8) | (input[pos++] << 16) | (input[pos++] << 24);

                    if (copyOffset <= 0 || copyOffset > outPos) break;

                    for (int i = 0; i < copyLen && outPos < uncompressedLength; i++)
                    {
                        output[outPos] = output[outPos - copyOffset];
                        outPos++;
                    }
                }
            }

            return output;
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
                    newPos = metadata.Size + offset;
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
            throw new NotSupportedException("Aff4ImageReader is strictly read-only.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("Aff4ImageReader is strictly read-only.");
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
                    if (zipArchive != null)
                    {
                        zipArchive.Dispose();
                    }
                    if (!leaveOpen && sourceStream != null)
                    {
                        sourceStream.Dispose();
                    }
                    chunkCache.Clear();
                    chunkLruOrder.Clear();
                    mapRanges.Clear();
                    segmentEntries.Clear();
                }
                isDisposed = true;
            }
            base.Dispose(disposing);
        }
    }
}
