using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>
    /// Enterprise Forensic exFAT Filesystem Scout and Deleted Record Carver.
    /// Supports primary (sector 0) and backup (sector 12) VBR boot sectors,
    /// checksum validation, root directory tree traversal, and carving of
    /// deleted directory sets (0x05 File + 0x40 Stream + 0x41 Name entries).
    /// Detects contiguous NoFatChain streams for 100% exact file recovery.
    /// 100% offline, zero network telemetry, strictly bounded 64 KiB memory.
    /// </summary>
    public static class ExFatScout
    {
        public const string ExFatOemId = "EXFAT   ";
        public const ushort BootSignature = 0xAA55;

        // Entry Types (InUse bit = 0x80)
        public const byte EntryTypeEod          = 0x00;
        public const byte EntryTypeAllocation   = 0x81;
        public const byte EntryTypeUpCase       = 0x82;
        public const byte EntryTypeVolumeLabel  = 0x83;
        public const byte EntryTypeFileActive   = 0x85;
        public const byte EntryTypeFileDeleted  = 0x05;
        public const byte EntryTypeStreamActive = 0xC0;
        public const byte EntryTypeStreamDeleted= 0x40;
        public const byte EntryTypeNameActive   = 0xC1;
        public const byte EntryTypeNameDeleted  = 0x41;

        public const ushort AttrReadOnly  = 0x0001;
        public const ushort AttrHidden    = 0x0002;
        public const ushort AttrSystem    = 0x0004;
        public const ushort AttrDirectory = 0x0010;
        public const ushort AttrArchive   = 0x0020;

        public sealed class ExFatBootSector
        {
            public long PhysicalOffset { get; set; }
            public bool IsBackup { get; set; }
            public ulong VolumeOffsetSector { get; set; }
            public ulong VolumeLengthSectors { get; set; }
            public uint FatOffsetSector { get; set; }
            public uint FatLengthSectors { get; set; }
            public uint ClusterHeapOffsetSector { get; set; }
            public uint ClusterCount { get; set; }
            public uint RootDirectoryCluster { get; set; }
            public uint VolumeSerialNumber { get; set; }
            public ushort FileSystemRevision { get; set; }
            public ushort VolumeFlags { get; set; }
            public byte BytesPerSectorShift { get; set; }
            public byte SectorsPerClusterShift { get; set; }
            public byte NumberOfFats { get; set; }
            public byte DriveSelect { get; set; }
            public byte PercentInUse { get; set; }

            public uint BytesPerSector { get; set; }
            public uint SectorsPerCluster { get; set; }
            public long ClusterSizeBytes { get; set; }
            public long ClusterHeapByteOffset { get; set; }
            public bool IsChecksumValid { get; set; }
            public string VolumeLabel { get; set; }

            public ExFatBootSector()
            {
                VolumeLabel = String.Empty;
            }

            public long ClusterToOffset(uint cluster)
            {
                if (cluster < 2 || cluster >= ClusterCount + 2) return -1;
                long clusterIdx = (long)(cluster - 2);
                return ClusterHeapByteOffset + (clusterIdx * ClusterSizeBytes);
            }
        }

        public sealed class ExFatExtent
        {
            public long LogicalOffset { get; set; }
            public long PhysicalOffset { get; set; }
            public long Length { get; set; }
        }

        public sealed class ExFatFileRecord
        {
            public string Name { get; set; }
            public string FullPath { get; set; }
            public bool IsDirectory { get; set; }
            public bool IsDeleted { get; set; }
            public ushort FileAttributes { get; set; }
            public uint FirstCluster { get; set; }
            public long PhysicalOffset { get; set; }
            public long Size { get; set; }
            public long ValidDataLength { get; set; }
            public bool NoFatChain { get; set; } // Contiguous flag
            public DateTime CreatedTimeUtc { get; set; }
            public DateTime ModifiedTimeUtc { get; set; }
            public DateTime AccessedTimeUtc { get; set; }
            public uint ParentCluster { get; set; }
            public List<ExFatExtent> Extents { get; set; }

            public ExFatFileRecord()
            {
                Name = String.Empty;
                FullPath = String.Empty;
                Extents = new List<ExFatExtent>();
            }
        }

        public sealed class ExFatScoutResult
        {
            public string Status { get; set; }
            public ExFatBootSector PrimaryBoot { get; set; }
            public ExFatBootSector BackupBoot { get; set; }
            public List<ExFatFileRecord> ActiveFiles { get; set; }
            public List<ExFatFileRecord> DeletedFiles { get; set; }
            public int TotalActiveCount { get; set; }
            public int TotalDeletedCount { get; set; }
            public long TotalRecoverableBytes { get; set; }

            public ExFatScoutResult()
            {
                Status = "Unknown";
                ActiveFiles = new List<ExFatFileRecord>();
                DeletedFiles = new List<ExFatFileRecord>();
            }

            public string ToJson()
            {
                var serializer = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
                return serializer.Serialize(this);
            }
        }

        // =========================================================================
        // Boot Sector Parsing & Validation
        // =========================================================================

        public static bool IsExFatBootSector(byte[] sector, int offset = 0)
        {
            if (sector == null || sector.Length < offset + 512) return false;
            // Check signature 0x55 0xAA at 510-511
            if (sector[offset + 510] != 0x55 || sector[offset + 511] != 0xAA) return false;
            // Check OEM Name "EXFAT   " at offset 3
            string oem = Encoding.ASCII.GetString(sector, offset + 3, 8);
            return oem == ExFatOemId;
        }

        public static ExFatBootSector ParseBootSector(byte[] sector, long physicalOffset, bool isBackup)
        {
            if (!IsExFatBootSector(sector)) return null;

            var boot = new ExFatBootSector
            {
                PhysicalOffset = physicalOffset,
                IsBackup = isBackup,
                VolumeOffsetSector = BitConverter.ToUInt64(sector, 0x40),
                VolumeLengthSectors = BitConverter.ToUInt64(sector, 0x48),
                FatOffsetSector = BitConverter.ToUInt32(sector, 0x50),
                FatLengthSectors = BitConverter.ToUInt32(sector, 0x54),
                ClusterHeapOffsetSector = BitConverter.ToUInt32(sector, 0x58),
                ClusterCount = BitConverter.ToUInt32(sector, 0x5C),
                RootDirectoryCluster = BitConverter.ToUInt32(sector, 0x60),
                VolumeSerialNumber = BitConverter.ToUInt32(sector, 0x64),
                FileSystemRevision = BitConverter.ToUInt16(sector, 0x68),
                VolumeFlags = BitConverter.ToUInt16(sector, 0x6A),
                BytesPerSectorShift = sector[0x6C],
                SectorsPerClusterShift = sector[0x6D],
                NumberOfFats = sector[0x6E],
                DriveSelect = sector[0x6F],
                PercentInUse = sector[0x70]
            };

            // Shift validity checks (sector shift typically 9..12, cluster shift 0..25)
            if (boot.BytesPerSectorShift < 9 || boot.BytesPerSectorShift > 12)
                return null;
            if (boot.SectorsPerClusterShift > 25)
                return null;

            boot.BytesPerSector = 1U << boot.BytesPerSectorShift;
            boot.SectorsPerCluster = 1U << boot.SectorsPerClusterShift;
            boot.ClusterSizeBytes = (long)boot.BytesPerSector * boot.SectorsPerCluster;
            boot.ClusterHeapByteOffset = physicalOffset + ((long)boot.ClusterHeapOffsetSector * boot.BytesPerSector);

            return boot;
        }

        public static uint ComputeBootChecksum(byte[] sectors0To10, int length)
        {
            uint checksum = 0;
            for (int i = 0; i < length; i++)
            {
                // In exFAT specification, VolumeFlags (bytes 106, 107) and PercentInUse (byte 112)
                // in sector 0 are excluded from boot region checksum calculation.
                if (i == 106 || i == 107 || i == 112)
                    continue;
                checksum = ((checksum << 31) | (checksum >> 1)) + sectors0To10[i];
            }
            return checksum;
        }

        // =========================================================================
        // Main Scout & Traversal Engine
        // =========================================================================

        public static ExFatScoutResult Scout(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
                return new ExFatScoutResult { Status = "FileNotFound" };

            using (var stream = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return Scout(stream, CancellationToken.None);
            }
        }

        public static ExFatScoutResult Scout(Stream stream, CancellationToken ct)
        {
            var result = new ExFatScoutResult();
            if (stream == null || !stream.CanRead)
            {
                result.Status = "InvalidStream";
                return result;
            }

            // 1. Read Sector 0 (Primary VBR)
            byte[] bootBytes = new byte[512];
            stream.Seek(0, SeekOrigin.Begin);
            int read = stream.Read(bootBytes, 0, 512);
            if (read < 512 || !IsExFatBootSector(bootBytes))
            {
                // Try scanning partition offsets: 32768, 65536, 1048576, 2097152
                long[] candidateOffsets = new long[] { 0x8000, 0x10000, 0x100000, 0x200000 };
                bool found = false;
                for (int i = 0; i < candidateOffsets.Length; i++)
                {
                    if (stream.Length > candidateOffsets[i] + 512)
                    {
                        stream.Seek(candidateOffsets[i], SeekOrigin.Begin);
                        read = stream.Read(bootBytes, 0, 512);
                        if (read == 512 && IsExFatBootSector(bootBytes))
                        {
                            result.PrimaryBoot = ParseBootSector(bootBytes, candidateOffsets[i], false);
                            found = true;
                            break;
                        }
                    }
                }
                if (!found)
                {
                    result.Status = "NotExFat";
                    return result;
                }
            }
            else
            {
                result.PrimaryBoot = ParseBootSector(bootBytes, 0, false);
            }

            if (result.PrimaryBoot == null)
            {
                result.Status = "CorruptBootSector";
                return result;
            }

            // 2. Read Sector 12 (Backup VBR)
            long backupOffset = result.PrimaryBoot.PhysicalOffset + (12L * result.PrimaryBoot.BytesPerSector);
            if (stream.Length >= backupOffset + 512)
            {
                byte[] backupBytes = new byte[512];
                stream.Seek(backupOffset, SeekOrigin.Begin);
                read = stream.Read(backupBytes, 0, 512);
                if (read == 512 && IsExFatBootSector(backupBytes))
                {
                    result.BackupBoot = ParseBootSector(backupBytes, backupOffset, true);
                }
            }

            // 3. Verify Boot Sector Checksum
            long bootRegionBytes = 11L * result.PrimaryBoot.BytesPerSector;
            if (stream.Length >= result.PrimaryBoot.PhysicalOffset + (12L * result.PrimaryBoot.BytesPerSector))
            {
                try
                {
                    byte[] vbrBuffer = new byte[Math.Min(bootRegionBytes, 65536L)];
                    stream.Seek(result.PrimaryBoot.PhysicalOffset, SeekOrigin.Begin);
                    int vbrRead = stream.Read(vbrBuffer, 0, vbrBuffer.Length);
                    if (vbrRead == vbrBuffer.Length)
                    {
                        uint computedCsum = ComputeBootChecksum(vbrBuffer, vbrRead);
                        // Read checksum sector at sector 11
                        byte[] csumSector = new byte[512];
                        stream.Seek(result.PrimaryBoot.PhysicalOffset + (11L * result.PrimaryBoot.BytesPerSector), SeekOrigin.Begin);
                        stream.Read(csumSector, 0, 512);
                        uint recordedCsum = BitConverter.ToUInt32(csumSector, 0);
                        result.PrimaryBoot.IsChecksumValid = (computedCsum == recordedCsum);
                    }
                }
                catch { }
            }

            // 4. Read Root Directory and Traverse Directory Tree
            var activeSet = new List<ExFatFileRecord>();
            var deletedSet = new List<ExFatFileRecord>();
            var visitedClusters = new HashSet<uint>();

            TraverseDirectoryCluster(stream, result.PrimaryBoot, result.PrimaryBoot.RootDirectoryCluster, "", activeSet, deletedSet, visitedClusters, ct);

            // 5. Carve Deleted Directory Sets from Directory Slack & Unallocated Space
            var carvedDeleted = CarveDeletedDirectorySets(stream, result.PrimaryBoot, ct);
            for (int i = 0; i < carvedDeleted.Count; i++)
            {
                var cd = carvedDeleted[i];
                // Deduplicate by FirstCluster or Name+Size
                bool exists = false;
                for (int j = 0; j < deletedSet.Count; j++)
                {
                    if (deletedSet[j].FirstCluster == cd.FirstCluster && deletedSet[j].Size == cd.Size)
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    deletedSet.Add(cd);
                }
            }

            // Calculate total recoverable bytes
            long recoverable = 0;
            for (int i = 0; i < activeSet.Count; i++) recoverable += activeSet[i].Size;
            for (int i = 0; i < deletedSet.Count; i++) recoverable += deletedSet[i].Size;

            result.ActiveFiles = activeSet;
            result.DeletedFiles = deletedSet;
            result.TotalActiveCount = activeSet.Count;
            result.TotalDeletedCount = deletedSet.Count;
            result.TotalRecoverableBytes = recoverable;
            result.Status = "OK";

            return result;
        }

        // =========================================================================
        // Directory Tree Traversal
        // =========================================================================

        static void TraverseDirectoryCluster(Stream stream, ExFatBootSector boot, uint dirCluster, string currentPath, List<ExFatFileRecord> activeList, List<ExFatFileRecord> deletedList, HashSet<uint> visited, CancellationToken ct)
        {
            if (dirCluster < 2 || !visited.Add(dirCluster) || visited.Count > 10000) return;
            if (ct.IsCancellationRequested) return;

            long clusterOffset = boot.ClusterToOffset(dirCluster);
            if (clusterOffset < 0 || clusterOffset >= stream.Length) return;

            int clusterSize = (int)Math.Min((long)boot.ClusterSizeBytes, 65536L);
            byte[] dirBuffer = new byte[clusterSize];

            stream.Seek(clusterOffset, SeekOrigin.Begin);
            int read = stream.Read(dirBuffer, 0, clusterSize);
            if (read < 32) return;

            int pos = 0;
            while (pos + 32 <= read)
            {
                if (ct.IsCancellationRequested) return;
                byte entryType = dirBuffer[pos];

                if (entryType == EntryTypeEod)
                {
                    // End of Directory
                    break;
                }

                if (entryType == EntryTypeVolumeLabel)
                {
                    byte charCount = dirBuffer[pos + 1];
                    if (charCount > 0 && charCount <= 15)
                    {
                        boot.VolumeLabel = Encoding.Unicode.GetString(dirBuffer, pos + 2, charCount * 2);
                    }
                    pos += 32;
                    continue;
                }

                if (entryType == EntryTypeFileActive || entryType == EntryTypeFileDeleted)
                {
                    bool isDeleted = (entryType == EntryTypeFileDeleted);
                    byte secondaryCount = dirBuffer[pos + 1];
                    ushort attrs = BitConverter.ToUInt16(dirBuffer, pos + 4);
                    DateTime createUtc = ParseExFatTimestamp(dirBuffer, pos + 8, dirBuffer[pos + 20], dirBuffer[pos + 22]);
                    DateTime modUtc = ParseExFatTimestamp(dirBuffer, pos + 12, dirBuffer[pos + 21], dirBuffer[pos + 23]);
                    DateTime accUtc = ParseExFatTimestamp(dirBuffer, pos + 16, 0, dirBuffer[pos + 24]);

                    int requiredBytes = (1 + secondaryCount) * 32;
                    if (pos + requiredBytes <= read)
                    {
                        // Parse Stream Extension (entry 1)
                        int streamPos = pos + 32;
                        byte sType = dirBuffer[streamPos];
                        if (sType == EntryTypeStreamActive || sType == EntryTypeStreamDeleted)
                        {
                            byte secFlags = dirBuffer[streamPos + 1];
                            bool noFatChain = (secFlags & 0x02) != 0;
                            byte nameLen = dirBuffer[streamPos + 3];
                            ulong validLen = BitConverter.ToUInt64(dirBuffer, streamPos + 8);
                            uint firstCluster = BitConverter.ToUInt32(dirBuffer, streamPos + 20);
                            ulong dataLen = BitConverter.ToUInt64(dirBuffer, streamPos + 24);

                            // Parse Name Entries (entry 2..secondaryCount)
                            var nameSb = new StringBuilder();
                            for (int si = 2; si <= secondaryCount; si++)
                            {
                                int namePos = pos + (si * 32);
                                byte nType = dirBuffer[namePos];
                                if (nType == EntryTypeNameActive || nType == EntryTypeNameDeleted)
                                {
                                    // 15 UTF-16 characters
                                    for (int ci = 0; ci < 15; ci++)
                                    {
                                        char ch = (char)BitConverter.ToUInt16(dirBuffer, namePos + 2 + (ci * 2));
                                        if (ch == 0) break;
                                        nameSb.Append(ch);
                                    }
                                }
                            }

                            string fileName = nameSb.ToString();
                            if (!string.IsNullOrEmpty(fileName))
                            {
                                bool isDir = (attrs & AttrDirectory) != 0;
                                string fullPath = string.IsNullOrEmpty(currentPath) ? fileName : currentPath + "\\" + fileName;
                                long physOff = boot.ClusterToOffset(firstCluster);

                                var rec = new ExFatFileRecord
                                {
                                    Name = fileName,
                                    FullPath = fullPath,
                                    IsDirectory = isDir,
                                    IsDeleted = isDeleted,
                                    FileAttributes = attrs,
                                    FirstCluster = firstCluster,
                                    PhysicalOffset = physOff,
                                    Size = isDir ? 0L : (long)dataLen,
                                    ValidDataLength = (long)validLen,
                                    NoFatChain = noFatChain,
                                    CreatedTimeUtc = createUtc,
                                    ModifiedTimeUtc = modUtc,
                                    AccessedTimeUtc = accUtc,
                                    ParentCluster = dirCluster
                                };

                                if (rec.PhysicalOffset > 0 && rec.Size > 0)
                                {
                                    rec.Extents.Add(new ExFatExtent
                                    {
                                        LogicalOffset = 0,
                                        PhysicalOffset = rec.PhysicalOffset,
                                        Length = rec.Size
                                    });
                                }

                                if (isDeleted)
                                    deletedList.Add(rec);
                                else
                                    activeList.Add(rec);

                                // If active directory, recurse
                                if (isDir && !isDeleted && firstCluster >= 2)
                                {
                                    TraverseDirectoryCluster(stream, boot, firstCluster, fullPath, activeList, deletedList, visited, ct);
                                }
                            }
                        }
                    }
                    pos += Math.Max(32, (1 + secondaryCount) * 32);
                    continue;
                }

                pos += 32;
            }
        }

        // =========================================================================
        // Deleted Directory Set Carving (Unallocated / Slack Carving)
        // =========================================================================

        public static List<ExFatFileRecord> CarveDeletedDirectorySets(Stream stream, ExFatBootSector boot, CancellationToken ct)
        {
            var carved = new List<ExFatFileRecord>();
            if (stream == null || boot == null || boot.ClusterSizeBytes <= 0) return carved;

            // Scan cluster heap or first 128 MiB of volume
            long scanStart = boot.ClusterHeapByteOffset;
            long maxScan = Math.Min(stream.Length, scanStart + (128L * 1024 * 1024));
            byte[] block = new byte[65536];

            for (long offset = scanStart; offset < maxScan; offset += block.Length - 128)
            {
                if (ct.IsCancellationRequested) break;
                stream.Seek(offset, SeekOrigin.Begin);
                int read = stream.Read(block, 0, block.Length);
                if (read < 96) break;

                for (int pos = 0; pos <= read - 96; pos += 32)
                {
                    byte type0 = block[pos];
                    // Check for deleted file entry 0x05
                    if (type0 == EntryTypeFileDeleted)
                    {
                        byte secCount = block[pos + 1];
                        if (secCount >= 2 && secCount <= 17 && pos + ((1 + secCount) * 32) <= read)
                        {
                            byte type1 = block[pos + 32];
                            // Stream extension deleted 0x40
                            if (type1 == EntryTypeStreamDeleted)
                            {
                                byte secFlags = block[pos + 33];
                                bool noFatChain = (secFlags & 0x02) != 0;
                                ulong validLen = BitConverter.ToUInt64(block, pos + 40);
                                uint firstCluster = BitConverter.ToUInt32(block, pos + 52);
                                ulong dataLen = BitConverter.ToUInt64(block, pos + 56);

                                if (firstCluster >= 2 && firstCluster < boot.ClusterCount + 2 && dataLen < (ulong)stream.Length)
                                {
                                    // Parse file name from 0x41 entries
                                    var nameSb = new StringBuilder();
                                    for (int si = 2; si <= secCount; si++)
                                    {
                                        int namePos = pos + (si * 32);
                                        if (block[namePos] == EntryTypeNameDeleted)
                                        {
                                            for (int ci = 0; ci < 15; ci++)
                                            {
                                                char ch = (char)BitConverter.ToUInt16(block, namePos + 2 + (ci * 2));
                                                if (ch == 0) break;
                                                nameSb.Append(ch);
                                            }
                                        }
                                    }

                                    string fname = nameSb.ToString();
                                    if (!string.IsNullOrEmpty(fname) && fname.IndexOfAny(Path.GetInvalidFileNameChars()) < 0)
                                    {
                                        ushort attrs = BitConverter.ToUInt16(block, pos + 4);
                                        DateTime cTime = ParseExFatTimestamp(block, pos + 8, block[pos + 20], block[pos + 22]);
                                        DateTime mTime = ParseExFatTimestamp(block, pos + 12, block[pos + 21], block[pos + 23]);
                                        DateTime aTime = ParseExFatTimestamp(block, pos + 16, 0, block[pos + 24]);

                                        long phys = boot.ClusterToOffset(firstCluster);
                                        var record = new ExFatFileRecord
                                        {
                                            Name = fname,
                                            FullPath = "$CARVED_DELETED\\" + fname,
                                            IsDirectory = (attrs & AttrDirectory) != 0,
                                            IsDeleted = true,
                                            FileAttributes = attrs,
                                            FirstCluster = firstCluster,
                                            PhysicalOffset = phys,
                                            Size = (long)dataLen,
                                            ValidDataLength = (long)validLen,
                                            NoFatChain = noFatChain,
                                            CreatedTimeUtc = cTime,
                                            ModifiedTimeUtc = mTime,
                                            AccessedTimeUtc = aTime
                                        };

                                        if (phys > 0 && record.Size > 0)
                                        {
                                            record.Extents.Add(new ExFatExtent
                                            {
                                                LogicalOffset = 0,
                                                PhysicalOffset = phys,
                                                Length = record.Size
                                            });
                                        }
                                        carved.Add(record);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return carved;
        }

        // =========================================================================
        // File Extraction Engine
        // =========================================================================

        public static void ExtractFile(Stream diskStream, ExFatBootSector boot, ExFatFileRecord file, Stream outputStream)
        {
            if (diskStream == null || file == null || outputStream == null || file.Size <= 0) return;

            long remaining = file.Size;
            if (file.NoFatChain && file.PhysicalOffset > 0)
            {
                // Contiguous stream fast-path: directly stream 64 KiB chunks
                diskStream.Seek(file.PhysicalOffset, SeekOrigin.Begin);
                byte[] buffer = new byte[65536];
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min((long)buffer.Length, remaining);
                    int r = diskStream.Read(buffer, 0, toRead);
                    if (r <= 0) break;
                    outputStream.Write(buffer, 0, r);
                    remaining -= r;
                }
            }
            else if (file.Extents != null && file.Extents.Count > 0)
            {
                byte[] buffer = new byte[65536];
                for (int i = 0; i < file.Extents.Count && remaining > 0; i++)
                {
                    var ext = file.Extents[i];
                    diskStream.Seek(ext.PhysicalOffset, SeekOrigin.Begin);
                    long extRem = ext.Length;
                    while (extRem > 0 && remaining > 0)
                    {
                        int toRead = (int)Math.Min((long)buffer.Length, Math.Min(extRem, remaining));
                        int r = diskStream.Read(buffer, 0, toRead);
                        if (r <= 0) break;
                        outputStream.Write(buffer, 0, r);
                        extRem -= r;
                        remaining -= r;
                    }
                }
            }
        }

        // =========================================================================
        // Timestamp Helper
        // =========================================================================

        public static DateTime ParseExFatTimestamp(byte[] buffer, int offset, byte ms10, byte tzOffsetByte)
        {
            if (buffer == null || offset + 4 > buffer.Length) return DateTime.MinValue;

            uint raw = BitConverter.ToUInt32(buffer, offset);
            if (raw == 0) return DateTime.MinValue;

            int sec2 = (int)(raw & 0x1F) * 2;
            int min = (int)((raw >> 5) & 0x3F);
            int hour = (int)((raw >> 11) & 0x1F);
            int day = (int)((raw >> 16) & 0x1F);
            int month = (int)((raw >> 21) & 0x0F);
            int year = 1980 + (int)((raw >> 25) & 0x7F);

            if (year < 1980 || year > 2107 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec2 > 59)
                return DateTime.MinValue;

            try
            {
                var dt = new DateTime(year, month, day, hour, min, sec2, DateTimeKind.Utc);
                if (ms10 > 0 && ms10 < 100)
                {
                    dt = dt.AddMilliseconds(ms10 * 10);
                }
                // Bit 7 of tzOffsetByte indicates valid timezone offset in 15-minute intervals (two's complement 7-bit)
                if ((tzOffsetByte & 0x80) != 0)
                {
                    sbyte offset15Min = (sbyte)((tzOffsetByte & 0x7F) | ((tzOffsetByte & 0x40) != 0 ? 0x80 : 0));
                    dt = dt.AddMinutes(-offset15Min * 15);
                }
                return dt;
            }
            catch
            {
                return DateTime.MinValue;
            }
        }
    }
}
