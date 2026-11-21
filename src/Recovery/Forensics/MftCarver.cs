using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    public sealed class MftDataRun
    {
        public long Lcn { get; set; }
        public long ClusterCount { get; set; }

        public override string ToString()
        {
            return string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "LCN: {0}, Clusters: {1}", Lcn, ClusterCount);
        }
    }

    public sealed class MftFileRecord
    {
        public ulong RecordNumber { get; set; }
        public ushort SequenceNumber { get; set; }
        public bool IsAllocated { get; set; }
        public bool IsDirectory { get; set; }
        public string FileName { get; set; }
        public ulong ParentRecordNumber { get; set; }
        public long FileSize { get; set; }
        public long AllocatedSize { get; set; }

        public DateTime CreationTimeUtc { get; set; }
        public DateTime ModificationTimeUtc { get; set; }
        public DateTime MftModificationTimeUtc { get; set; }
        public DateTime LastAccessTimeUtc { get; set; }
        public DateTime FnCreationTimeUtc { get; set; }

        public uint FileAttributes { get; set; }
        public bool IsResident { get; set; }
        public byte[] ResidentData { get; set; }
        public List<MftDataRun> DataRuns { get; set; }

        public long AbsoluteOffset { get; set; }
        public bool HasFixupError { get; set; }
        public bool IsTimestomped { get; set; }

        public MftFileRecord()
        {
            FileName = String.Empty;
            CreationTimeUtc = DateTime.MinValue;
            ModificationTimeUtc = DateTime.MinValue;
            MftModificationTimeUtc = DateTime.MinValue;
            LastAccessTimeUtc = DateTime.MinValue;
            FnCreationTimeUtc = DateTime.MinValue;
            ResidentData = new byte[0];
            DataRuns = new List<MftDataRun>();
            IsAllocated = false;
            IsDirectory = false;
            IsResident = false;
            HasFixupError = false;
            IsTimestomped = false;
        }

        public override string ToString()
        {
            return string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "[{0}] #{1}: {2} ({3} bytes, {4})",
                IsAllocated ? "ACTIVE" : "DELETED",
                RecordNumber,
                FileName,
                FileSize,
                IsDirectory ? "Directory" : (IsResident ? "Resident" : "Non-Resident"));
        }
    }

    /// <summary>
    /// Pure C# streaming carver and parser for NTFS Master File Table ($MFT) 1024-byte FILE records.
    /// Operates on raw disk streams or unallocated space even when partitions/boot sectors are destroyed.
    /// Decodes Fixup sequence arrays, $STANDARD_INFORMATION, $FILE_NAME, $DATA (resident & non-resident data runs),
    /// and detects forensic timestomping.
    /// </summary>
    public static class MftCarver
    {
        private const uint FileMagic = 0x454C4946U; // "FILE" in little-endian
        private const uint BaadMagic = 0x44414142U; // "BAAD" in little-endian
        private const int RecordSize = 1024;
        private const int ChunkSize = 65536;

        private const uint AttrStandardInformation = 0x10;
        private const uint AttrFileName = 0x30;
        private const uint AttrData = 0x80;
        private const uint AttrEndMarker = 0xFFFFFFFFU;

        private const long MinValidFileTime = 124339200000000000L; // ~1995-01-01 UTC
        private const long MaxValidFileTime = 141704640000000000L; // ~2050-01-01 UTC

        /// <summary>
        /// Attempts to parse a 1024-byte MFT record at the given offset.
        /// </summary>
        public static bool TryParseRecord(byte[] buffer, int offset, long absoluteOffset, out MftFileRecord record)
        {
            record = null;
            if (buffer == null || offset < 0 || offset + RecordSize > buffer.Length) return false;

            uint magic = BitConverter.ToUInt32(buffer, offset);
            if (magic != FileMagic && magic != BaadMagic) return false;

            ushort usaOffset = BitConverter.ToUInt16(buffer, offset + 4);
            ushort usaCount = BitConverter.ToUInt16(buffer, offset + 6);
            if (usaOffset < 42 || usaOffset + (usaCount * 2) > RecordSize) return false;
            if (usaCount < 3) return false; // 1 check value + 2 sectors for 1024 bytes

            ushort seqNum = BitConverter.ToUInt16(buffer, offset + 16);
            ushort firstAttrOff = BitConverter.ToUInt16(buffer, offset + 20);
            ushort flags = BitConverter.ToUInt16(buffer, offset + 22);
            uint realSize = BitConverter.ToUInt32(buffer, offset + 24);
            uint allocSize = BitConverter.ToUInt32(buffer, offset + 28);
            ulong baseRef = BitConverter.ToUInt64(buffer, offset + 32);

            if (firstAttrOff < 48 || firstAttrOff >= RecordSize) return false;
            if (allocSize != RecordSize) return false;
            if (realSize > RecordSize || realSize < firstAttrOff) return false;

            // In NTFS 3.1+, record number is stored at offset 44
            uint mftRecordNum = BitConverter.ToUInt32(buffer, offset + 44);

            // Clone buffer to apply fixup safely without mutating caller's source buffer
            byte[] recordBytes = new byte[RecordSize];
            Array.Copy(buffer, offset, recordBytes, 0, RecordSize);

            bool fixupError = false;
            ushort checkValue = BitConverter.ToUInt16(recordBytes, usaOffset);
            for (int s = 1; s < usaCount && s <= 2; s++)
            {
                int sectorEndOffset = (s * 512) - 2;
                ushort endValue = BitConverter.ToUInt16(recordBytes, sectorEndOffset);
                if (endValue != checkValue)
                {
                    fixupError = true;
                }
                ushort origValue = BitConverter.ToUInt16(recordBytes, usaOffset + (s * 2));
                recordBytes[sectorEndOffset] = (byte)(origValue & 0xFF);
                recordBytes[sectorEndOffset + 1] = (byte)((origValue >> 8) & 0xFF);
            }

            bool isAllocated = (flags & 0x0001) != 0;
            bool isDirectory = (flags & 0x0002) != 0;

            var result = new MftFileRecord
            {
                RecordNumber = mftRecordNum,
                SequenceNumber = seqNum,
                IsAllocated = isAllocated,
                IsDirectory = isDirectory,
                AbsoluteOffset = absoluteOffset,
                HasFixupError = fixupError
            };

            // Parse attributes
            int attrCursor = firstAttrOff;
            string bestName = String.Empty;
            byte bestNamespace = 255;

            while (attrCursor + 16 <= RecordSize)
            {
                uint attrType = BitConverter.ToUInt32(recordBytes, attrCursor);
                if (attrType == AttrEndMarker) break;

                uint attrLength = BitConverter.ToUInt32(recordBytes, attrCursor + 4);
                if (attrLength < 16 || attrCursor + (int)attrLength > RecordSize) break;

                byte nonResident = recordBytes[attrCursor + 8];
                byte nameLen = recordBytes[attrCursor + 9];
                ushort nameOff = BitConverter.ToUInt16(recordBytes, attrCursor + 10);

                if (attrType == AttrStandardInformation && nonResident == 0)
                {
                    ParseStandardInformation(recordBytes, attrCursor, result);
                }
                else if (attrType == AttrFileName && nonResident == 0)
                {
                    ParseFileName(recordBytes, attrCursor, result, ref bestName, ref bestNamespace);
                }
                else if (attrType == AttrData)
                {
                    // Check if unnamed default $DATA stream
                    if (nameLen == 0)
                    {
                        ParseDataAttribute(recordBytes, attrCursor, (int)attrLength, nonResident, result);
                    }
                }

                attrCursor += (int)attrLength;
            }

            if (!String.IsNullOrEmpty(bestName))
            {
                result.FileName = bestName;
            }

            // Timestomping detection: standard info created time differs significantly from file_name created time
            if (result.CreationTimeUtc != DateTime.MinValue && result.FnCreationTimeUtc != DateTime.MinValue)
            {
                TimeSpan diff = result.FnCreationTimeUtc - result.CreationTimeUtc;
                if (Math.Abs(diff.TotalMinutes) > 60)
                {
                    result.IsTimestomped = true;
                }
            }

            record = result;
            return true;
        }

        private static void ParseStandardInformation(byte[] recordBytes, int attrOffset, MftFileRecord record)
        {
            ushort valOff = BitConverter.ToUInt16(recordBytes, attrOffset + 20);
            uint valLen = BitConverter.ToUInt32(recordBytes, attrOffset + 16);
            int dataStart = attrOffset + valOff;

            if (dataStart + 48 <= RecordSize && valLen >= 48)
            {
                record.CreationTimeUtc = DecodeFileTime(BitConverter.ToInt64(recordBytes, dataStart));
                record.ModificationTimeUtc = DecodeFileTime(BitConverter.ToInt64(recordBytes, dataStart + 8));
                record.MftModificationTimeUtc = DecodeFileTime(BitConverter.ToInt64(recordBytes, dataStart + 16));
                record.LastAccessTimeUtc = DecodeFileTime(BitConverter.ToInt64(recordBytes, dataStart + 24));
                record.FileAttributes = BitConverter.ToUInt32(recordBytes, dataStart + 32);
            }
        }

        private static void ParseFileName(byte[] recordBytes, int attrOffset, MftFileRecord record, ref string bestName, ref byte bestNamespace)
        {
            ushort valOff = BitConverter.ToUInt16(recordBytes, attrOffset + 20);
            uint valLen = BitConverter.ToUInt32(recordBytes, attrOffset + 16);
            int dataStart = attrOffset + valOff;

            if (dataStart + 66 <= RecordSize && valLen >= 66)
            {
                ulong parentRef = BitConverter.ToUInt64(recordBytes, dataStart);
                ulong parentMft = parentRef & 0x0000FFFFFFFFFFFFUL;
                record.ParentRecordNumber = parentMft;

                DateTime fnCreate = DecodeFileTime(BitConverter.ToInt64(recordBytes, dataStart + 8));
                if (record.FnCreationTimeUtc == DateTime.MinValue)
                {
                    record.FnCreationTimeUtc = fnCreate;
                }

                long allocSz = BitConverter.ToInt64(recordBytes, dataStart + 40);
                long realSz = BitConverter.ToInt64(recordBytes, dataStart + 48);
                if (record.FileSize == 0) record.FileSize = realSz;
                if (record.AllocatedSize == 0) record.AllocatedSize = allocSz;

                byte fnLength = recordBytes[dataStart + 64];
                byte fnNamespace = recordBytes[dataStart + 65];

                if (fnLength > 0 && dataStart + 66 + (fnLength * 2) <= RecordSize)
                {
                    string name = Encoding.Unicode.GetString(recordBytes, dataStart + 66, fnLength * 2);
                    // Prefer Win32 / Win32&DOS namespace (1 or 3) over DOS 8.3 (2)
                    if (fnNamespace == 1 || fnNamespace == 3 || String.IsNullOrEmpty(bestName) || fnNamespace < bestNamespace)
                    {
                        bestName = name;
                        bestNamespace = fnNamespace;
                    }
                }
            }
        }

        private static void ParseDataAttribute(byte[] recordBytes, int attrOffset, int attrLength, byte nonResident, MftFileRecord record)
        {
            if (nonResident == 0)
            {
                record.IsResident = true;
                uint valLen = BitConverter.ToUInt32(recordBytes, attrOffset + 16);
                ushort valOff = BitConverter.ToUInt16(recordBytes, attrOffset + 20);
                int dataStart = attrOffset + valOff;

                record.FileSize = valLen;
                if (valLen > 0 && valLen <= RecordSize && dataStart + valLen <= RecordSize)
                {
                    record.ResidentData = new byte[valLen];
                    Array.Copy(recordBytes, dataStart, record.ResidentData, 0, valLen);
                }
            }
            else
            {
                record.IsResident = false;
                record.AllocatedSize = BitConverter.ToInt64(recordBytes, attrOffset + 40);
                record.FileSize = BitConverter.ToInt64(recordBytes, attrOffset + 48);

                ushort runOff = BitConverter.ToUInt16(recordBytes, attrOffset + 32);
                int runCursor = attrOffset + runOff;

                long currentLcn = 0;
                while (runCursor < attrOffset + attrLength)
                {
                    byte b = recordBytes[runCursor++];
                    if (b == 0) break;

                    int lenBytes = b & 0x0F;
                    int offBytes = (b >> 4) & 0x0F;

                    if (runCursor + lenBytes + offBytes > attrOffset + attrLength) break;

                    long clusterLen = 0;
                    for (int i = 0; i < lenBytes; i++)
                    {
                        clusterLen |= ((long)recordBytes[runCursor + i] << (i * 8));
                    }
                    runCursor += lenBytes;

                    long lcnDelta = 0;
                    for (int i = 0; i < offBytes; i++)
                    {
                        lcnDelta |= ((long)recordBytes[runCursor + i] << (i * 8));
                    }
                    // Sign extend LCN delta
                    if (offBytes > 0 && (recordBytes[runCursor + offBytes - 1] & 0x80) != 0)
                    {
                        for (int s = offBytes; s < 8; s++)
                        {
                            lcnDelta |= ((long)0xFF << (s * 8));
                        }
                    }
                    runCursor += offBytes;

                    currentLcn += lcnDelta;
                    record.DataRuns.Add(new MftDataRun
                    {
                        Lcn = currentLcn,
                        ClusterCount = clusterLen
                    });
                }
            }
        }

        private static DateTime DecodeFileTime(long fileTime)
        {
            if (fileTime < MinValidFileTime || fileTime > MaxValidFileTime) return DateTime.MinValue;
            try
            {
                return DateTime.FromFileTimeUtc(fileTime);
            }
            catch
            {
                return DateTime.MinValue;
            }
        }

        /// <summary>
        /// Carves MFT records from a byte buffer.
        /// </summary>
        public static List<MftFileRecord> Carve(byte[] buffer, long baseOffset = 0)
        {
            var records = new List<MftFileRecord>();
            if (buffer == null || buffer.Length < RecordSize) return records;

            int limit = buffer.Length - RecordSize;
            int cursor = 0;

            while (cursor <= limit)
            {
                uint magic = BitConverter.ToUInt32(buffer, cursor);
                if (magic == FileMagic || magic == BaadMagic)
                {
                    MftFileRecord rec;
                    if (TryParseRecord(buffer, cursor, baseOffset + cursor, out rec))
                    {
                        records.Add(rec);
                        cursor += RecordSize;
                        continue;
                    }
                }
                cursor += 512; // Advance sector by sector
            }

            return records;
        }

        /// <summary>
        /// Carves MFT records from a stream with constant 64 KiB buffer.
        /// </summary>
        public static List<MftFileRecord> CarveFromStream(Stream stream, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable", "stream");

            var records = new List<MftFileRecord>();
            byte[] chunk = new byte[ChunkSize + RecordSize];
            int carryOver = 0;
            long streamOffset = 0;

            while (true)
            {
                if (cancellationToken.IsCancellationRequested) break;

                int read = stream.Read(chunk, carryOver, ChunkSize);
                int total = carryOver + read;
                if (total < RecordSize) break;

                int cursor = 0;
                int limit = total - RecordSize;

                while (cursor <= limit)
                {
                    uint magic = BitConverter.ToUInt32(chunk, cursor);
                    if (magic == FileMagic || magic == BaadMagic)
                    {
                        MftFileRecord rec;
                        if (TryParseRecord(chunk, cursor, streamOffset + cursor, out rec))
                        {
                            records.Add(rec);
                            cursor += RecordSize;
                            continue;
                        }
                    }
                    cursor += 512;
                }

                carryOver = total - cursor;
                if (carryOver > 0 && cursor > 0)
                {
                    Array.Copy(chunk, cursor, chunk, 0, carryOver);
                }
                streamOffset += cursor;

                if (read == 0) break;
            }

            return records;
        }

        /// <summary>
        /// Filters out active files and returns only deleted / unallocated files.
        /// </summary>
        public static List<MftFileRecord> ExtractDeletedFiles(IEnumerable<MftFileRecord> records)
        {
            var result = new List<MftFileRecord>();
            if (records == null) return result;

            foreach (var r in records)
            {
                if (r != null && !r.IsAllocated && !r.IsDirectory && !String.IsNullOrEmpty(r.FileName))
                {
                    result.Add(r);
                }
            }
            return result;
        }
    }
}
