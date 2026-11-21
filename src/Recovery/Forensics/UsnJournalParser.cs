using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    [Flags]
    public enum UsnReason : uint
    {
        None = 0x00000000,
        DataOverwrite = 0x00000001,
        DataExtend = 0x00000002,
        DataTruncation = 0x00000004,
        NamedDataOverwrite = 0x00000010,
        NamedDataExtend = 0x00000020,
        NamedDataTruncation = 0x00000040,
        FileCreate = 0x00000100,
        FileDelete = 0x00000200,
        EaChange = 0x00000400,
        SecurityChange = 0x00000800,
        RenameOldName = 0x00001000,
        RenameNewName = 0x00002000,
        IndexableChange = 0x00004000,
        BasicInfoChange = 0x00008000,
        HardLinkChange = 0x00010000,
        CompressionChange = 0x00020000,
        EncryptionChange = 0x00040000,
        ObjectIdChange = 0x00080000,
        ReparsePointChange = 0x00100000,
        StreamChange = 0x00200000,
        TransactedChange = 0x00400000,
        IntegrityChange = 0x00800000,
        Close = 0x80000000
    }

    public sealed class UsnRecord
    {
        public uint RecordLength { get; set; }
        public ushort MajorVersion { get; set; }
        public ushort MinorVersion { get; set; }
        public ulong FileReferenceNumber { get; set; }
        public ulong ParentFileReferenceNumber { get; set; }
        public long Usn { get; set; }
        public DateTime TimeStampUtc { get; set; }
        public UsnReason Reason { get; set; }
        public uint SourceInfo { get; set; }
        public uint SecurityId { get; set; }
        public uint FileAttributes { get; set; }
        public string FileName { get; set; }
        public long AbsoluteOffset { get; set; }
        public bool IsCarved { get; set; }

        public ulong MftEntryIndex
        {
            get { return FileReferenceNumber & 0x0000FFFFFFFFFFFFUL; }
        }

        public ushort MftSequenceNumber
        {
            get { return (ushort)((FileReferenceNumber >> 48) & 0xFFFF); }
        }

        public ulong ParentMftEntryIndex
        {
            get { return ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFUL; }
        }

        public string ReasonText
        {
            get { return FormatReason(Reason); }
        }

        public UsnRecord()
        {
            FileName = String.Empty;
            TimeStampUtc = DateTime.MinValue;
            Reason = UsnReason.None;
            IsCarved = false;
        }

        public static string FormatReason(UsnReason reason)
        {
            if (reason == UsnReason.None) return "NONE";

            var parts = new List<string>(4);
            if ((reason & UsnReason.FileCreate) != 0) parts.Add("FILE_CREATE");
            if ((reason & UsnReason.FileDelete) != 0) parts.Add("FILE_DELETE");
            if ((reason & UsnReason.DataOverwrite) != 0) parts.Add("DATA_OVERWRITE");
            if ((reason & UsnReason.DataExtend) != 0) parts.Add("DATA_EXTEND");
            if ((reason & UsnReason.DataTruncation) != 0) parts.Add("DATA_TRUNCATION");
            if ((reason & UsnReason.RenameOldName) != 0) parts.Add("RENAME_OLD_NAME");
            if ((reason & UsnReason.RenameNewName) != 0) parts.Add("RENAME_NEW_NAME");
            if ((reason & UsnReason.SecurityChange) != 0) parts.Add("SECURITY_CHANGE");
            if ((reason & UsnReason.BasicInfoChange) != 0) parts.Add("BASIC_INFO_CHANGE");
            if ((reason & UsnReason.Close) != 0) parts.Add("CLOSE");

            if (parts.Count == 0) return string.Format(System.Globalization.CultureInfo.InvariantCulture, "0x{0:X8}", (uint)reason);
            return string.Join(" | ", parts.ToArray());
        }

        public override string ToString()
        {
            return string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "[{0:yyyy-MM-dd HH:mm:ss} UTC] USN {1}: {2} ({3}) MFT:{4}",
                TimeStampUtc, Usn, FileName, ReasonText, MftEntryIndex);
        }
    }

    public sealed class UsnDeletedFileArtifact
    {
        public string FileName { get; set; }
        public ulong FileReferenceNumber { get; set; }
        public ulong ParentFileReferenceNumber { get; set; }
        public DateTime DeletionTimeUtc { get; set; }
        public DateTime? CreationTimeUtc { get; set; }
        public long LastUsn { get; set; }
        public uint FileAttributes { get; set; }
        public List<UsnRecord> HistoryRecords { get; set; }

        public UsnDeletedFileArtifact()
        {
            FileName = String.Empty;
            DeletionTimeUtc = DateTime.MinValue;
            CreationTimeUtc = null;
            HistoryRecords = new List<UsnRecord>();
        }
    }

    /// <summary>
    /// Pure C# streaming parser and heuristic carver for the Windows NTFS Change Journal ($UsnJrnl:$J).
    /// Extracts timeline history, file creations, renames, and deletions from active journals or unallocated sectors.
    /// Operates in streaming sliding-window mode with constant memory overhead.
    /// </summary>
    public static class UsnJournalParser
    {
        private const int ChunkSize = 65536;
        private const int MaxRecordSize = 1024;
        private const int MinRecordSizeV2 = 60;
        private const int MinRecordSizeV3 = 80;

        // Earliest reasonable FILETIME: 1995-01-01 UTC (~124339200000000000)
        private const long MinValidFileTime = 124339200000000000L;
        // Latest reasonable FILETIME: 2050-01-01 UTC (~141704640000000000)
        private const long MaxValidFileTime = 141704640000000000L;

        /// <summary>
        /// Parses a contiguous USN Journal stream ($UsnJrnl:$J) with constant memory sliding window.
        /// </summary>
        public static List<UsnRecord> ParseStream(Stream stream, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable", "stream");

            var records = new List<UsnRecord>();
            byte[] buffer = new byte[ChunkSize + MaxRecordSize];
            int carryOver = 0;
            long streamOffset = 0;

            while (true)
            {
                if (cancellationToken.IsCancellationRequested) break;

                int bytesToRead = ChunkSize;
                int read = stream.Read(buffer, carryOver, bytesToRead);
                int totalInChunk = carryOver + read;
                if (totalInChunk < MinRecordSizeV2) break;

                int cursor = 0;
                while (cursor + MinRecordSizeV2 <= totalInChunk)
                {
                    uint recordLength = BitConverter.ToUInt32(buffer, cursor);

                    // Sparse gap in $J is common: zero blocks signify unwritten journal space
                    if (recordLength == 0)
                    {
                        // Fast skip zeroes in 8-byte increments
                        int skip = 4;
                        while (cursor + skip + 4 <= totalInChunk && BitConverter.ToUInt32(buffer, cursor + skip) == 0)
                        {
                            skip += 4;
                        }
                        cursor += skip;
                        continue;
                    }

                    // Sanity check record length
                    if (recordLength < MinRecordSizeV2 || recordLength > MaxRecordSize || (recordLength % 8 != 0))
                    {
                        // Invalid record length: advance 8 bytes (NTFS alignment)
                        cursor += 8;
                        continue;
                    }

                    if (cursor + recordLength > totalInChunk)
                    {
                        // Record spans boundary, preserve in carry-over
                        break;
                    }

                    UsnRecord record;
                    if (TryParseRecord(buffer, cursor, streamOffset + cursor, false, out record))
                    {
                        records.Add(record);
                        cursor += (int)recordLength;
                    }
                    else
                    {
                        cursor += 8;
                    }
                }

                // Preserve trailing bytes
                carryOver = totalInChunk - cursor;
                if (carryOver > 0 && cursor > 0)
                {
                    Array.Copy(buffer, cursor, buffer, 0, carryOver);
                }
                streamOffset += cursor;

                if (read == 0) break;
            }

            return records;
        }

        /// <summary>
        /// Heuristically carves USN records from an unallocated buffer or memory segment.
        /// </summary>
        public static List<UsnRecord> Carve(byte[] buffer, long baseOffset = 0)
        {
            var records = new List<UsnRecord>();
            if (buffer == null || buffer.Length < MinRecordSizeV2) return records;

            int limit = buffer.Length - MinRecordSizeV2;
            int cursor = 0;

            while (cursor <= limit)
            {
                uint recordLength = BitConverter.ToUInt32(buffer, cursor);

                if (recordLength < MinRecordSizeV2 || recordLength > MaxRecordSize || (recordLength % 8 != 0))
                {
                    cursor += 8;
                    continue;
                }

                if (cursor + (int)recordLength > buffer.Length)
                {
                    break;
                }

                UsnRecord record;
                if (TryParseRecord(buffer, cursor, baseOffset + cursor, true, out record))
                {
                    records.Add(record);
                    cursor += (int)recordLength;
                }
                else
                {
                    cursor += 8;
                }
            }

            return records;
        }

        /// <summary>
        /// Carves USN records from an arbitrary Stream (e.g. raw disk image or unallocated partition).
        /// </summary>
        public static List<UsnRecord> CarveFromStream(Stream stream, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (stream == null) throw new ArgumentNullException("stream");
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable", "stream");

            var records = new List<UsnRecord>();
            byte[] chunk = new byte[ChunkSize + MaxRecordSize];
            int carryOver = 0;
            long streamOffset = 0;

            while (true)
            {
                if (cancellationToken.IsCancellationRequested) break;

                int read = stream.Read(chunk, carryOver, ChunkSize);
                int total = carryOver + read;
                if (total < MinRecordSizeV2) break;

                int cursor = 0;
                int limit = total - MinRecordSizeV2;

                while (cursor <= limit)
                {
                    uint recordLength = BitConverter.ToUInt32(chunk, cursor);

                    if (recordLength == 0)
                    {
                        int skip = 4;
                        while (cursor + skip + 4 <= total && BitConverter.ToUInt32(chunk, cursor + skip) == 0)
                        {
                            skip += 4;
                        }
                        cursor += skip;
                        continue;
                    }

                    if (recordLength < MinRecordSizeV2 || recordLength > MaxRecordSize || (recordLength % 8 != 0))
                    {
                        cursor += 8;
                        continue;
                    }

                    if (cursor + (int)recordLength > total)
                    {
                        break;
                    }

                    UsnRecord record;
                    if (TryParseRecord(chunk, cursor, streamOffset + cursor, true, out record))
                    {
                        records.Add(record);
                        cursor += (int)recordLength;
                    }
                    else
                    {
                        cursor += 8;
                    }
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

        public static bool TryParseRecord(byte[] buffer, int offset, long absoluteOffset, bool isCarved, out UsnRecord record)
        {
            record = null;
            if (buffer == null || offset < 0 || offset + MinRecordSizeV2 > buffer.Length) return false;

            uint recordLength = BitConverter.ToUInt32(buffer, offset);
            if (recordLength < MinRecordSizeV2 || recordLength > MaxRecordSize || (recordLength % 8 != 0)) return false;
            if (offset + (int)recordLength > buffer.Length) return false;

            ushort major = BitConverter.ToUInt16(buffer, offset + 4);
            ushort minor = BitConverter.ToUInt16(buffer, offset + 6);

            if (major == 2 && minor == 0)
            {
                return TryParseRecordV2(buffer, offset, (int)recordLength, absoluteOffset, isCarved, out record);
            }
            if (major == 3 && minor == 0)
            {
                return TryParseRecordV3(buffer, offset, (int)recordLength, absoluteOffset, isCarved, out record);
            }

            return false;
        }

        private static bool TryParseRecordV2(byte[] buffer, int offset, int recordLength, long absoluteOffset, bool isCarved, out UsnRecord record)
        {
            record = null;
            if (recordLength < MinRecordSizeV2) return false;

            ulong fileRef = BitConverter.ToUInt64(buffer, offset + 8);
            ulong parentRef = BitConverter.ToUInt64(buffer, offset + 16);
            long usn = BitConverter.ToInt64(buffer, offset + 24);

            long fileTime = BitConverter.ToInt64(buffer, offset + 32);
            if (fileTime < MinValidFileTime || fileTime > MaxValidFileTime) return false;

            DateTime timeStamp;
            try
            {
                timeStamp = DateTime.FromFileTimeUtc(fileTime);
            }
            catch
            {
                return false;
            }

            uint reasonRaw = BitConverter.ToUInt32(buffer, offset + 40);
            if (reasonRaw == 0) return false; // Every valid USN record must record a non-zero reason

            uint sourceInfo = BitConverter.ToUInt32(buffer, offset + 44);
            uint securityId = BitConverter.ToUInt32(buffer, offset + 48);
            uint fileAttributes = BitConverter.ToUInt32(buffer, offset + 52);

            ushort fileNameLength = BitConverter.ToUInt16(buffer, offset + 56);
            ushort fileNameOffset = BitConverter.ToUInt16(buffer, offset + 58);

            if (fileNameLength == 0 || fileNameLength > 512 || (fileNameLength % 2 != 0)) return false;
            if (fileNameOffset < 56 || fileNameOffset + fileNameLength > recordLength) return false;
            if (offset + fileNameOffset + fileNameLength > buffer.Length) return false;

            string fileName = ReadUnicodeString(buffer, offset + fileNameOffset, fileNameLength);
            if (String.IsNullOrEmpty(fileName)) return false;

            // Reject invalid characters in filenames
            for (int i = 0; i < fileName.Length; i++)
            {
                char c = fileName[i];
                if (c < 0x20 && c != 0) return false; // Control characters not permitted in NTFS names
                if (c == 0)
                {
                    fileName = fileName.Substring(0, i);
                    break;
                }
            }
            if (fileName.Length == 0) return false;

            record = new UsnRecord
            {
                RecordLength = (uint)recordLength,
                MajorVersion = 2,
                MinorVersion = 0,
                FileReferenceNumber = fileRef,
                ParentFileReferenceNumber = parentRef,
                Usn = usn,
                TimeStampUtc = timeStamp,
                Reason = (UsnReason)reasonRaw,
                SourceInfo = sourceInfo,
                SecurityId = securityId,
                FileAttributes = fileAttributes,
                FileName = fileName,
                AbsoluteOffset = absoluteOffset,
                IsCarved = isCarved
            };
            return true;
        }

        private static bool TryParseRecordV3(byte[] buffer, int offset, int recordLength, long absoluteOffset, bool isCarved, out UsnRecord record)
        {
            record = null;
            if (recordLength < MinRecordSizeV3) return false;

            // V3 has 128-bit file references (low 64-bit taken)
            ulong fileRef = BitConverter.ToUInt64(buffer, offset + 8);
            ulong parentRef = BitConverter.ToUInt64(buffer, offset + 24);
            long usn = BitConverter.ToInt64(buffer, offset + 40);

            long fileTime = BitConverter.ToInt64(buffer, offset + 48);
            if (fileTime < MinValidFileTime || fileTime > MaxValidFileTime) return false;

            DateTime timeStamp;
            try { timeStamp = DateTime.FromFileTimeUtc(fileTime); } catch { return false; }

            uint reasonRaw = BitConverter.ToUInt32(buffer, offset + 56);
            if (reasonRaw == 0) return false;

            uint sourceInfo = BitConverter.ToUInt32(buffer, offset + 60);
            uint securityId = BitConverter.ToUInt32(buffer, offset + 64);
            uint fileAttributes = BitConverter.ToUInt32(buffer, offset + 68);

            ushort fileNameLength = BitConverter.ToUInt16(buffer, offset + 72);
            ushort fileNameOffset = BitConverter.ToUInt16(buffer, offset + 74);

            if (fileNameLength == 0 || fileNameLength > 512 || (fileNameLength % 2 != 0)) return false;
            if (fileNameOffset < 76 || fileNameOffset + fileNameLength > recordLength) return false;
            if (offset + fileNameOffset + fileNameLength > buffer.Length) return false;

            string fileName = ReadUnicodeString(buffer, offset + fileNameOffset, fileNameLength);
            if (String.IsNullOrEmpty(fileName)) return false;

            record = new UsnRecord
            {
                RecordLength = (uint)recordLength,
                MajorVersion = 3,
                MinorVersion = 0,
                FileReferenceNumber = fileRef,
                ParentFileReferenceNumber = parentRef,
                Usn = usn,
                TimeStampUtc = timeStamp,
                Reason = (UsnReason)reasonRaw,
                SourceInfo = sourceInfo,
                SecurityId = securityId,
                FileAttributes = fileAttributes,
                FileName = fileName,
                AbsoluteOffset = absoluteOffset,
                IsCarved = isCarved
            };
            return true;
        }

        private static string ReadUnicodeString(byte[] buffer, int offset, int length)
        {
            try
            {
                return Encoding.Unicode.GetString(buffer, offset, length);
            }
            catch
            {
                return String.Empty;
            }
        }

        /// <summary>
        /// Reconstructs all files that were deleted according to the USN Journal records.
        /// </summary>
        public static List<UsnDeletedFileArtifact> ExtractDeletedFiles(IEnumerable<UsnRecord> records)
        {
            var result = new List<UsnDeletedFileArtifact>();
            if (records == null) return result;

            // Group by FileReferenceNumber
            var grouped = new Dictionary<ulong, List<UsnRecord>>();
            foreach (var r in records)
            {
                if (r == null) continue;
                List<UsnRecord> list;
                if (!grouped.TryGetValue(r.FileReferenceNumber, out list))
                {
                    list = new List<UsnRecord>();
                    grouped[r.FileReferenceNumber] = list;
                }
                list.Add(r);
            }

            foreach (var kvp in grouped)
            {
                var history = kvp.Value;
                // Sort by USN or TimeStamp
                history.Sort((a, b) => a.Usn != b.Usn ? a.Usn.CompareTo(b.Usn) : a.TimeStampUtc.CompareTo(b.TimeStampUtc));

                bool wasDeleted = false;
                DateTime deletionTime = DateTime.MinValue;
                DateTime? creationTime = null;
                string latestName = String.Empty;
                ulong parentRef = 0;
                uint attrs = 0;
                long lastUsn = 0;

                for (int i = 0; i < history.Count; i++)
                {
                    var rec = history[i];
                    if (!String.IsNullOrEmpty(rec.FileName)) latestName = rec.FileName;
                    if (rec.ParentFileReferenceNumber != 0) parentRef = rec.ParentFileReferenceNumber;
                    if (rec.FileAttributes != 0) attrs = rec.FileAttributes;
                    if (rec.Usn > lastUsn) lastUsn = rec.Usn;

                    if ((rec.Reason & UsnReason.FileCreate) != 0 && creationTime == null)
                    {
                        creationTime = rec.TimeStampUtc;
                    }

                    if ((rec.Reason & UsnReason.FileDelete) != 0)
                    {
                        wasDeleted = true;
                        deletionTime = rec.TimeStampUtc;
                    }
                }

                if (wasDeleted)
                {
                    result.Add(new UsnDeletedFileArtifact
                    {
                        FileName = latestName,
                        FileReferenceNumber = kvp.Key,
                        ParentFileReferenceNumber = parentRef,
                        DeletionTimeUtc = deletionTime,
                        CreationTimeUtc = creationTime,
                        LastUsn = lastUsn,
                        FileAttributes = attrs,
                        HistoryRecords = history
                    });
                }
            }

            // Sort deleted artifacts chronologically descending
            result.Sort((a, b) => b.DeletionTimeUtc.CompareTo(a.DeletionTimeUtc));
            return result;
        }
    }
}
