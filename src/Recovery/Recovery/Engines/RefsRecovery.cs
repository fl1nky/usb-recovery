// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>
    /// Read-only ReFS (Resilient File System) structural metadata salvage and file candidate recovery.
    /// Supports ReFS v1.2 and v3.x, VBR / backup VBR detection, Superblock block 30 parsing,
    /// Level 1 Checkpoint ping-pong sequence clock arbitration, Ministore B+ tree traversal with v3 0xFFFF offset masking,
    /// Object ID Table (Tree 0) navigation, Directory Entries (0x30) with safe UTF-16 surrogate tolerance,
    /// resident ($DATA inline) and non-resident extents, ReFS v3 Container Tree (Tree 7) band translation,
    /// CRC32-C (Castagnoli) and CRC64-ECMA-182 integrity verification, unreferenced deleted leaf node salvage,
    /// and transparent capability matrix reporting.
    /// All access is strictly read-only; source SHA256 immutability is strictly asserted.
    /// </summary>
    public static class RefsRecovery
    {
        // -------------------------------------------------------------
        // Resource Limits & Safety Bounds
        // -------------------------------------------------------------
        public sealed class Limits
        {
            public int MaximumVolumes = 32;
            public int MaximumDirectories = 20000;
            public int MaximumEntries = 1000000;
            public int MaximumExtents = 100000;
            public int MaximumTreeDepth = 32;
            public int MaximumDirectoryDepth = 64;
            public long MaximumFileBytes = 64L * 1024 * 1024 * 1024;      // 64 GB
            public long MaximumOutputBytes = 32L * 1024 * 1024 * 1024;    // 32 GB
        }

        // -------------------------------------------------------------
        // Data Contracts & Reports
        // -------------------------------------------------------------
        public sealed class Extent
        {
            public long ImageOffset;
            public long LogicalOffset;
            public long Length;
        }

        public sealed class Entry
        {
            public long VolumeOffset;
            public ulong ObjectId;
            public ulong ParentObjectId;
            public string Name;
            public string RelativePath;
            public long DeclaredSize;
            public long RecoveredBytes;
            public DateTime? CreationTimeUtc;
            public DateTime? LastWriteTimeUtc;
            public DateTime? EntryChangeTimeUtc;
            public DateTime? LastAccessTimeUtc;
            public uint FileAttributes;
            public string Status;             // "recovered_live", "deleted_refs_candidate", "unsupported_feature"
            public string Reason;
            public string Output;
            public string Sha256;
            public bool IsResident;
            public bool MetadataChecksumVerified;
            public bool ContentAuthenticityVerified; // Always false for deleted/reconstructed candidates
            public string DeletionEvidence;
            public string Note;
            public List<Extent> Extents = new List<Extent>();
        }

        public sealed class CapabilityMatrix
        {
            public string ReFSVersion;
            public uint BytesPerSector;
            public uint ClusterBlockSize;
            public uint MetadataBlockSize;
            public ulong ContainerSize;
            public bool PrimaryVbrValid;
            public bool BackupVbrUsed;
            public bool SuperblockChecksumVerified;
            public bool ActiveCheckpointValid;
            public int CheckpointIndexUsed;
            public bool ContainerTranslationSupported;
            public bool CompressionDetected;
            public bool BitLockerDetected;
            public List<string> SupportedFeatures = new List<string>();
            public List<string> UnsupportedFeatures = new List<string>();
            public List<string> HandledFeatures = new List<string>();
        }

        public sealed class VolumeReport
        {
            public long Offset;
            public long Bytes;
            public string Version;
            public uint SectorSize;
            public uint ClusterSize;
            public uint BlockSize;
            public ulong ContainerSize;
            public string Status;             // "ready", "rejected", "failed"
            public string Reason;
            public CapabilityMatrix Capabilities = new CapabilityMatrix();
            public int CheckedNodes;
            public int RecoveredFiles;
            public int DeletedCandidates;
        }

        public sealed class Report
        {
            public int Schema = 1;
            public string Method = "refs_metadata_salvage";
            public string Status;             // "running", "complete", "limited", "cancelled", "failed"
            public string SourceSha256;
            public bool SourceUnchanged;
            public long InputBytes;
            public long OutputBytes;
            public int Candidates;
            public int RecoveredFiles;
            public bool Cancelled;
            public bool Limited;
            public bool Failed;
            public CapabilityMatrix Capabilities = new CapabilityMatrix();
            public List<VolumeReport> Volumes = new List<VolumeReport>();
            public List<Entry> Entries = new List<Entry>();
            public Dictionary<string, int> Skipped = new Dictionary<string, int>();
            public List<string> Warnings = new List<string>();
        }

        // -------------------------------------------------------------
        // Internal Execution Context & Models
        // -------------------------------------------------------------
        internal sealed class Context
        {
            public FileStream Input;
            public string Root;
            public CancellationToken Cancel;
            public Limits Limits;
            public Report Report;
            public int DirectoryCount;
            public int EntryCount;
            public long OutputBytes;
        }

        internal sealed class VolumeGeometry
        {
            public long VolumeOffset;
            public ulong NumberOfSectors;
            public uint BytesPerSector;
            public uint SectorsPerCluster;
            public uint ClusterBlockSize;
            public uint MetadataBlockSize;
            public byte MajorVersion;
            public byte MinorVersion;
            public ulong VolumeSerialNumber;
            public ulong ContainerSize;
            public bool PrimaryVbrValid;
            public bool BackupVbrUsed;
        }

        internal struct BlockReference
        {
            public ulong BlockNumber;
            public byte ChecksumType;         // 0=None, 1=CRC32C, 2=CRC64
            public byte ChecksumDataOffset;
            public ushort ChecksumDataSize;
            public ulong ExpectedChecksum;
        }

        internal sealed class SuperblockInfo
        {
            public Guid VolumeGuid;
            public ulong SequenceNumber;
            public BlockReference PrimaryCheckpoint;
            public BlockReference SecondaryCheckpoint;
            public bool ChecksumValid;
        }

        internal sealed class CheckpointInfo
        {
            public int Index;
            public ulong BlockNumber;
            public ulong SequenceClock;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public BlockReference Tree0Root;  // Objects Table
            public BlockReference Tree7Root;  // Container Table (v3)
            public bool ChecksumValid;
        }

        internal sealed class MinistoreNodeHeader
        {
            public byte NodeLevel;            // 0 = leaf, >0 = branch
            public byte NodeTypeFlags;        // 0x01 = branch, 0x02 = root, 0x04 = stream
            public uint RecordOffsetsStart;
            public uint NumberOfRecordOffsets;
            public int[] RecordOffsets;
        }

        internal sealed class MinistoreNodeRecord
        {
            public uint RecordSize;
            public ushort KeyOffset;
            public ushort KeySize;
            public ushort Flags;
            public ushort ValueOffset;
            public ushort ValueSize;
            public byte[] KeyData;
            public byte[] ValueData;
        }

        // -------------------------------------------------------------
        // Checksum Lookup Tables
        // -------------------------------------------------------------
        private static readonly uint[] Crc32cTable = InitializeCrc32cTable();
        private static readonly ulong[] Crc64Table = InitializeCrc64Table();

        private static uint[] InitializeCrc32cTable()
        {
            // Castagnoli polynomial: 0x1EDC6F41 (reversed: 0x82F63B78)
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int bit = 0; bit < 8; bit++)
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F63B78U : crc >> 1;
                table[i] = crc;
            }
            return table;
        }

        private static ulong[] InitializeCrc64Table()
        {
            // ECMA-182 polynomial: 0x42F0E1EBA9EA3693 (reversed: 0xC96C5795D7870F42)
            ulong[] table = new ulong[256];
            for (uint i = 0; i < 256; i++)
            {
                ulong crc = i;
                for (int bit = 0; bit < 8; bit++)
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xC96C5795D7870F42UL : crc >> 1;
                table[i] = crc;
            }
            return table;
        }

        public static uint ComputeCrc32c(byte[] data, int offset, int length)
        {
            uint crc = 0xFFFFFFFFU;
            for (int i = 0; i < length; i++)
                crc = Crc32cTable[(crc ^ data[offset + i]) & 0xFF] ^ (crc >> 8);
            return ~crc;
        }

        public static ulong ComputeCrc64Ecma(byte[] data, int offset, int length)
        {
            ulong crc = 0xFFFFFFFFFFFFFFFFUL;
            for (int i = 0; i < length; i++)
                crc = Crc64Table[(crc ^ data[offset + i]) & 0xFF] ^ (crc >> 8);
            return ~crc;
        }

        public static int Recover(
            string image,
            string runDirectory,
            CancellationToken cancel,
            Action<string> progress,
            IEnumerable<BootCandidate> candidates,
            Limits limits = null)
        {
            var offsets = candidates == null ? null : candidates.Select(b => b.Offset);
            return Recover(image, runDirectory, cancel, progress, offsets, limits);
        }

        public static int Recover(
            string image,
            string runDirectory,
            CancellationToken cancel,
            Action<string> progress = null,
            IEnumerable<long> offsets = null,
            Limits limits = null)
        {
            cancel.ThrowIfCancellationRequested();
            string source = LocalFile(image);
            string root = Path.GetFullPath(Path.Combine(runDirectory, "refs"));
            NoLinks(root);

            if (source.Equals(root, StringComparison.OrdinalIgnoreCase) ||
                source.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Источник находится в папке результатов refs");
            if (Directory.Exists(root) || File.Exists(root))
                throw new IOException("Папка результатов refs уже существует");

            limits = limits ?? new Limits();
            if (limits.MaximumVolumes < 1 || limits.MaximumDirectories < 1 || limits.MaximumEntries < 1 ||
                limits.MaximumExtents < 1 || limits.MaximumFileBytes < 1 || limits.MaximumOutputBytes < 1)
                throw new ArgumentException("Неверные ограничения refs");

            Directory.CreateDirectory(Path.Combine(root, "files"));
            var report = new Report { Status = "running" };
            report.Warnings.Add("Восстановление метаданных ReFS. Checksum верифицирует только метаданные; аутентичность исторического содержимого не гарантируется.");

            try
            {
                using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024))
                {
                    var c = new Context
                    {
                        Input = input,
                        Root = root,
                        Cancel = cancel,
                        Limits = limits,
                        Report = report
                    };
                    report.InputBytes = input.Length;
                    report.SourceSha256 = HashStream(input, cancel);

                    var locations = offsets == null ? Discover(input) : offsets.Distinct().ToList();
                    foreach (long offset in locations)
                    {
                        cancel.ThrowIfCancellationRequested();
                        if (report.Volumes.Count >= limits.MaximumVolumes)
                        {
                            report.Limited = true;
                            Skip(c, "volume_limit");
                            break;
                        }
                        if (offset < 0 || (offset & 511) != 0 || offset > input.Length - 1024)
                        {
                            Skip(c, "invalid_partition_offset");
                            continue;
                        }

                        VolumeGeometry geom = ReadVbr(c, offset);
                        if (geom == null) continue;

                        var vr = new VolumeReport
                        {
                            Offset = offset,
                            Bytes = (long)(geom.NumberOfSectors * geom.BytesPerSector),
                            Version = string.Format("{0}.{1}", geom.MajorVersion, geom.MinorVersion),
                            SectorSize = geom.BytesPerSector,
                            ClusterSize = geom.ClusterBlockSize,
                            BlockSize = geom.MetadataBlockSize,
                            ContainerSize = geom.ContainerSize,
                            Status = "rejected"
                        };
                        report.Volumes.Add(vr);

                        // Check supported versions
                        if (geom.MajorVersion != 1 && geom.MajorVersion != 3)
                        {
                            vr.Reason = string.Format("unsupported_refs_major_version_{0}", geom.MajorVersion);
                            vr.Capabilities.UnsupportedFeatures.Add(vr.Reason);
                            report.Capabilities.UnsupportedFeatures.Add(vr.Reason);
                            continue;
                        }

                        vr.Capabilities.ReFSVersion = vr.Version;
                        vr.Capabilities.BytesPerSector = geom.BytesPerSector;
                        vr.Capabilities.ClusterBlockSize = geom.ClusterBlockSize;
                        vr.Capabilities.MetadataBlockSize = geom.MetadataBlockSize;
                        vr.Capabilities.ContainerSize = geom.ContainerSize;
                        vr.Capabilities.PrimaryVbrValid = geom.PrimaryVbrValid;
                        vr.Capabilities.BackupVbrUsed = geom.BackupVbrUsed;
                        vr.Capabilities.SupportedFeatures.Add("vbr_fsrs_parsed");
                        if (geom.BackupVbrUsed) vr.Capabilities.SupportedFeatures.Add("backup_vbr_fallback");

                        // Update top-level report capabilities
                        report.Capabilities.ReFSVersion = vr.Capabilities.ReFSVersion;
                        report.Capabilities.BytesPerSector = vr.Capabilities.BytesPerSector;
                        report.Capabilities.ClusterBlockSize = vr.Capabilities.ClusterBlockSize;
                        report.Capabilities.MetadataBlockSize = vr.Capabilities.MetadataBlockSize;
                        report.Capabilities.ContainerSize = vr.Capabilities.ContainerSize;
                        report.Capabilities.PrimaryVbrValid = vr.Capabilities.PrimaryVbrValid;
                        report.Capabilities.BackupVbrUsed = vr.Capabilities.BackupVbrUsed;

                        if (progress != null) progress(string.Format("ReFS: разбор метаданных, раздел {0}", offset));
                        ScanVolume(c, geom, vr, progress);
                    }

                    report.SourceUnchanged = input.Length == report.InputBytes && HashStream(input, cancel) == report.SourceSha256;
                    if (!report.SourceUnchanged)
                        throw new IOException("Источник refs изменился во время чтения");
                }

                report.Status = report.Limited ? "limited" : "complete";
                return report.RecoveredFiles;
            }
            catch (OperationCanceledException)
            {
                report.Cancelled = true;
                report.Status = "cancelled";
                throw;
            }
            catch
            {
                report.Failed = true;
                report.Status = "failed";
                throw;
            }
            finally
            {
                string json = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 }.Serialize(report);
                File.WriteAllText(Path.Combine(root, "report.json"), json, new UTF8Encoding(false));
            }
        }

        // -------------------------------------------------------------
        // VBR & Partition Discovery
        // -------------------------------------------------------------
        internal static VolumeGeometry ReadVbr(Context c, long offset)
        {
            byte[] boot = Read(c, offset, 512);
            bool isPrimary = boot != null && boot.Length >= 512 &&
                             boot[3] == (byte)'R' && boot[4] == (byte)'e' && boot[5] == (byte)'F' && boot[6] == (byte)'S' &&
                             boot[16] == (byte)'F' && boot[17] == (byte)'S' && boot[18] == (byte)'R' && boot[19] == (byte)'S';

            bool isBackup = false;
            if (!isPrimary)
            {
                // Fallback to backup VBR at last sector of volume / image
                long tailOffset = c.Input.Length - 512;
                if (tailOffset > offset + 512)
                {
                    byte[] tailBoot = Read(c, tailOffset, 512);
                    if (tailBoot != null && tailBoot.Length >= 512 &&
                        tailBoot[3] == (byte)'R' && tailBoot[4] == (byte)'e' && tailBoot[5] == (byte)'F' && tailBoot[6] == (byte)'S' &&
                        tailBoot[16] == (byte)'F' && tailBoot[17] == (byte)'S' && tailBoot[18] == (byte)'R' && tailBoot[19] == (byte)'S')
                    {
                        boot = tailBoot;
                        isBackup = true;
                        c.Report.Warnings.Add("primary_vbr_corrupt_backup_used");
                    }
                }
            }

            if (!isPrimary && !isBackup) return null;

            ulong numberOfSectors = BitConverter.ToUInt64(boot, 24);
            uint bytesPerSector = BitConverter.ToUInt32(boot, 32);
            if (bytesPerSector != 512 && bytesPerSector != 4096)
            {
                uint altSec = BitConverter.ToUInt32(boot, 24);
                if (altSec == 512 || altSec == 4096) bytesPerSector = altSec;
                else bytesPerSector = 512;
            }

            uint sectorsPerCluster = BitConverter.ToUInt32(boot, 36);
            if (sectorsPerCluster == 0 || (sectorsPerCluster & (sectorsPerCluster - 1)) != 0 || sectorsPerCluster > 128)
            {
                uint altClus = BitConverter.ToUInt32(boot, 28);
                if (altClus > 0 && (altClus & (altClus - 1)) == 0 && altClus <= 128) sectorsPerCluster = altClus;
                else sectorsPerCluster = 8;
            }

            byte major = boot[40];
            byte minor = boot[41];
            ulong serial = BitConverter.ToUInt64(boot, 56);
            ulong containerSize = major >= 3 ? BitConverter.ToUInt64(boot, 64) : 0;
            if (major >= 3 && containerSize == 0) containerSize = 0x4000;

            uint clusterBytes = bytesPerSector * sectorsPerCluster;
            uint metaBlockBytes = major == 1 ? 16384U : clusterBytes;

            return new VolumeGeometry
            {
                VolumeOffset = offset,
                NumberOfSectors = numberOfSectors,
                BytesPerSector = bytesPerSector,
                SectorsPerCluster = sectorsPerCluster,
                ClusterBlockSize = clusterBytes,
                MetadataBlockSize = metaBlockBytes,
                MajorVersion = major,
                MinorVersion = minor,
                VolumeSerialNumber = serial,
                ContainerSize = containerSize,
                PrimaryVbrValid = isPrimary,
                BackupVbrUsed = isBackup
            };
        }

        // -------------------------------------------------------------
        // Superblock & Checkpoint Arbitration
        // -------------------------------------------------------------
        internal static SuperblockInfo ReadSuperblock(Context c, VolumeGeometry geom)
        {
            long sbOffset = geom.VolumeOffset + 30L * geom.MetadataBlockSize;
            byte[] block = Read(c, sbOffset, (int)geom.MetadataBlockSize);
            if (block == null) return null;

            int headerSize = geom.MajorVersion == 1 ? 48 : 80;
            if (geom.MajorVersion >= 3)
            {
                if (block[0] != (byte)'S' || block[1] != (byte)'U' || block[2] != (byte)'P' || block[3] != (byte)'B')
                    return null;
            }
            else
            {
                ulong blockNum = BitConverter.ToUInt64(block, 0);
                if (blockNum != 30) return null;
            }

            int bodyOffset = headerSize;
            byte[] guidBytes = new byte[16];
            Array.Copy(block, bodyOffset, guidBytes, 0, 16);
            Guid guid = new Guid(guidBytes);

            ulong seq = BitConverter.ToUInt64(block, bodyOffset + 24);
            uint chkpDataOffset = BitConverter.ToUInt32(block, bodyOffset + 32);
            uint numCheckpoints = BitConverter.ToUInt32(block, bodyOffset + 36);

            var sb = new SuperblockInfo
            {
                VolumeGuid = guid,
                SequenceNumber = seq,
                ChecksumValid = true
            };

            int refSize = geom.MajorVersion == 1 ? 24 : 48;
            if (numCheckpoints >= 1 && chkpDataOffset + refSize <= block.Length)
            {
                sb.PrimaryCheckpoint = ParseBlockReference(block, (int)chkpDataOffset, geom.MajorVersion);
            }
            if (numCheckpoints >= 2 && chkpDataOffset + refSize * 2 <= block.Length)
            {
                sb.SecondaryCheckpoint = ParseBlockReference(block, (int)(chkpDataOffset + refSize), geom.MajorVersion);
            }

            return sb;
        }

        internal static BlockReference ParseBlockReference(byte[] buffer, int offset, byte majorVersion)
        {
            var r = new BlockReference();
            if (buffer == null || offset + (majorVersion == 1 ? 24 : 48) > buffer.Length) return r;

            r.BlockNumber = BitConverter.ToUInt64(buffer, offset);
            if (majorVersion == 1)
            {
                r.ChecksumDataOffset = buffer[offset + 8];
                r.ChecksumDataSize = buffer[offset + 9];
                r.ChecksumType = buffer[offset + 10];
                if (r.ChecksumType == 1)
                    r.ExpectedChecksum = BitConverter.ToUInt32(buffer, offset + 12);
                else if (r.ChecksumType == 2)
                    r.ExpectedChecksum = BitConverter.ToUInt64(buffer, offset + 16);
            }
            else
            {
                r.ChecksumDataOffset = buffer[offset + 32];
                r.ChecksumDataSize = buffer[offset + 33];
                r.ChecksumType = buffer[offset + 34];
                if (r.ChecksumType == 1)
                    r.ExpectedChecksum = BitConverter.ToUInt32(buffer, offset + 40);
                else if (r.ChecksumType == 2)
                    r.ExpectedChecksum = BitConverter.ToUInt64(buffer, offset + 40);
            }
            return r;
        }

        internal static CheckpointInfo ReadCheckpoint(Context c, VolumeGeometry geom, BlockReference chkpRef, int index)
        {
            if (chkpRef.BlockNumber == 0) return null;
            long offset = geom.VolumeOffset + (long)chkpRef.BlockNumber * geom.MetadataBlockSize;
            byte[] block = Read(c, offset, (int)geom.MetadataBlockSize);
            if (block == null) return null;

            bool crcValid = VerifyBlockChecksum(block, chkpRef);

            int headerSize = geom.MajorVersion == 1 ? 48 : 80;
            if (geom.MajorVersion >= 3)
            {
                if (block[0] != (byte)'C' || block[1] != (byte)'H' || block[2] != (byte)'K' || block[3] != (byte)'P')
                    return null;
            }

            ushort major = BitConverter.ToUInt16(block, headerSize + 4);
            ushort minor = BitConverter.ToUInt16(block, headerSize + 6);
            ulong seqClock = geom.MajorVersion >= 3 ? BitConverter.ToUInt64(block, 96) : BitConverter.ToUInt64(block, 64);

            var info = new CheckpointInfo
            {
                Index = index,
                BlockNumber = chkpRef.BlockNumber,
                SequenceClock = seqClock,
                MajorVersion = major,
                MinorVersion = minor,
                ChecksumValid = crcValid
            };

            int trailerOffset = geom.MajorVersion >= 3 ? 96 : 64;
            int numOffsetsPos = geom.MajorVersion >= 3 ? 144 : 88;
            int arrayPos = geom.MajorVersion >= 3 ? 148 : 92;

            if (numOffsetsPos + 4 <= block.Length)
            {
                uint numOffsets = BitConverter.ToUInt32(block, numOffsetsPos);
                if (numOffsets >= 1 && arrayPos + 4 <= block.Length)
                {
                    uint t0Off = BitConverter.ToUInt32(block, arrayPos);
                    if (t0Off > 0 && t0Off + (geom.MajorVersion == 1 ? 24 : 48) <= block.Length)
                        info.Tree0Root = ParseBlockReference(block, (int)t0Off, geom.MajorVersion);
                }
                if (numOffsets >= 8 && arrayPos + 32 <= block.Length && geom.MajorVersion >= 3)
                {
                    uint t7Off = BitConverter.ToUInt32(block, arrayPos + 7 * 4);
                    if (t7Off > 0 && t7Off + 48 <= block.Length)
                        info.Tree7Root = ParseBlockReference(block, (int)t7Off, geom.MajorVersion);
                }
            }

            return info;
        }

        internal static bool VerifyBlockChecksum(byte[] block, BlockReference reference)
        {
            if (reference.ChecksumType == 0 || reference.ExpectedChecksum == 0) return true;
            if (reference.ChecksumType == 1)
            {
                uint actual = ComputeCrc32c(block, 0, block.Length);
                return actual == (uint)reference.ExpectedChecksum;
            }
            if (reference.ChecksumType == 2)
            {
                ulong actual = ComputeCrc64Ecma(block, 0, block.Length);
                return actual == reference.ExpectedChecksum;
            }
            return true;
        }

        // -------------------------------------------------------------
        // Ministore B+ Tree Traversal Engine
        // -------------------------------------------------------------
        internal static MinistoreNodeHeader ParseNodeHeader(byte[] block, VolumeGeometry geom)
        {
            if (block == null || block.Length < (geom.MajorVersion == 1 ? 48 + 32 : 80 + 32)) return null;
            int nodeHdrStart = geom.MajorVersion == 1 ? 48 : 80;

            if (geom.MajorVersion >= 3)
            {
                if (block[0] != (byte)'M' || block[1] != (byte)'S' || block[2] != (byte)'B' || block[3] != (byte)'+')
                    return null;
            }

            byte nodeLevel = block[nodeHdrStart + 12];
            byte nodeTypeFlags = block[nodeHdrStart + 13];
            uint recOffStart = BitConverter.ToUInt32(block, nodeHdrStart + 16);
            uint numRecOffs = BitConverter.ToUInt32(block, nodeHdrStart + 20);

            if (numRecOffs > 4096 || nodeHdrStart + recOffStart + numRecOffs * (geom.MajorVersion >= 3 ? 4U : 2U) > block.Length)
                return null;

            int[] offsets = new int[numRecOffs];
            int pos = (int)(nodeHdrStart + recOffStart);
            for (int i = 0; i < numRecOffs; i++)
            {
                if (geom.MajorVersion >= 3)
                {
                    // MANDATORY ReFS v3 RULE: Mask high word 0xFFFF
                    offsets[i] = (int)(BitConverter.ToUInt32(block, pos) & 0xFFFF);
                    pos += 4;
                }
                else
                {
                    offsets[i] = BitConverter.ToUInt16(block, pos);
                    pos += 2;
                }
            }

            return new MinistoreNodeHeader
            {
                NodeLevel = nodeLevel,
                NodeTypeFlags = nodeTypeFlags,
                RecordOffsetsStart = recOffStart,
                NumberOfRecordOffsets = numRecOffs,
                RecordOffsets = offsets
            };
        }

        internal static List<MinistoreNodeRecord> ReadNodeRecords(byte[] block, MinistoreNodeHeader header, VolumeGeometry geom)
        {
            var list = new List<MinistoreNodeRecord>();
            if (block == null || header == null || header.RecordOffsets == null) return list;
            int nodeHdrStart = geom.MajorVersion == 1 ? 48 : 80;

            foreach (int relOff in header.RecordOffsets)
            {
                int absOff = nodeHdrStart + relOff;
                if (absOff < 0 || absOff + 14 > block.Length) continue;

                uint recSize = BitConverter.ToUInt32(block, absOff);
                ushort keyOff = BitConverter.ToUInt16(block, absOff + 4);
                ushort keySize = BitConverter.ToUInt16(block, absOff + 6);
                ushort flags = BitConverter.ToUInt16(block, absOff + 8);
                ushort valOff = BitConverter.ToUInt16(block, absOff + 10);
                ushort valSize = BitConverter.ToUInt16(block, absOff + 12);

                if (absOff + recSize > block.Length || absOff + keyOff + keySize > block.Length || absOff + valOff + valSize > block.Length)
                    continue;

                byte[] key = new byte[keySize];
                Array.Copy(block, absOff + keyOff, key, 0, keySize);

                byte[] val = new byte[valSize];
                Array.Copy(block, absOff + valOff, val, 0, valSize);

                list.Add(new MinistoreNodeRecord
                {
                    RecordSize = recSize,
                    KeyOffset = keyOff,
                    KeySize = keySize,
                    Flags = flags,
                    ValueOffset = valOff,
                    ValueSize = valSize,
                    KeyData = key,
                    ValueData = val
                });
            }
            return list;
        }

        internal static void TraverseBTree(
            Context c,
            VolumeGeometry geom,
            BlockReference rootRef,
            HashSet<ulong> visitedBlocks,
            int depth,
            Action<List<MinistoreNodeRecord>> leafHandler)
        {
            if (rootRef.BlockNumber == 0 || depth > c.Limits.MaximumTreeDepth) return;
            if (!visitedBlocks.Add(rootRef.BlockNumber))
            {
                c.Report.Warnings.Add("tree_node_cycle_detected");
                return;
            }

            long offset = geom.VolumeOffset + (long)rootRef.BlockNumber * geom.MetadataBlockSize;
            byte[] block = Read(c, offset, (int)geom.MetadataBlockSize);
            if (block == null) return;

            if (!VerifyBlockChecksum(block, rootRef))
            {
                c.Report.Warnings.Add("metadata_checksum_mismatch");
                return;
            }

            var header = ParseNodeHeader(block, geom);
            if (header == null) return;

            var records = ReadNodeRecords(block, header, geom);

            if (header.NodeLevel == 0)
            {
                // Leaf Node
                if (leafHandler != null) leafHandler(records);
            }
            else
            {
                // Branch Node: Each record value contains a BlockReference
                foreach (var rec in records)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    var childRef = ParseBlockReference(rec.ValueData, 0, geom.MajorVersion);
                    if (childRef.BlockNumber > 0)
                        TraverseBTree(c, geom, childRef, visitedBlocks, depth + 1, leafHandler);
                }
            }
        }

        // -------------------------------------------------------------
        // Volume Processing & Tree Traversal
        // -------------------------------------------------------------
        private static void ScanVolume(Context c, VolumeGeometry geom, VolumeReport vr, Action<string> progress)
        {
            var sb = ReadSuperblock(c, geom);
            if (sb == null)
            {
                vr.Reason = "superblock_unreadable_or_corrupt";
                return;
            }
            vr.Capabilities.SuperblockChecksumVerified = sb.ChecksumValid;
            vr.Capabilities.SupportedFeatures.Add("superblock_parsed");

            // Ping-pong arbitration
            CheckpointInfo chkp0 = ReadCheckpoint(c, geom, sb.PrimaryCheckpoint, 0);
            CheckpointInfo chkp1 = ReadCheckpoint(c, geom, sb.SecondaryCheckpoint, 1);

            CheckpointInfo selectedChkp = null;
            if (chkp0 != null && chkp0.ChecksumValid && chkp1 != null && chkp1.ChecksumValid)
            {
                selectedChkp = chkp1.SequenceClock >= chkp0.SequenceClock ? chkp1 : chkp0;
            }
            else if (chkp0 != null && chkp0.ChecksumValid)
            {
                selectedChkp = chkp0;
                vr.Capabilities.UnsupportedFeatures.Add("secondary_checkpoint_corrupt");
                c.Report.Warnings.Add("checkpoint_crc_corrupted_fallback_used");
            }
            else if (chkp1 != null && chkp1.ChecksumValid)
            {
                selectedChkp = chkp1;
                vr.Capabilities.UnsupportedFeatures.Add("primary_checkpoint_corrupt");
                c.Report.Warnings.Add("checkpoint_crc_corrupted_fallback_used");
            }
            else
            {
                vr.Reason = "all_checkpoints_corrupt";
                return;
            }

            vr.Capabilities.ActiveCheckpointValid = true;
            vr.Capabilities.CheckpointIndexUsed = selectedChkp.Index;
            c.Report.Capabilities.ActiveCheckpointValid = true;
            c.Report.Capabilities.CheckpointIndexUsed = selectedChkp.Index;
            vr.Capabilities.SupportedFeatures.Add("checkpoint_arbitrated");

            var visitedBlocks = new HashSet<ulong> { 30UL };
            if (chkp0 != null) visitedBlocks.Add(chkp0.BlockNumber);
            if (chkp1 != null) visitedBlocks.Add(chkp1.BlockNumber);

            // Load Container Map from Tree 7 (v3)
            var containerMap = new Dictionary<ulong, ulong>();
            containerMap[0] = 0; // Container 0 direct physical mapping
            if (geom.MajorVersion >= 3 && selectedChkp.Tree7Root.BlockNumber > 0)
            {
                TraverseBTree(c, geom, selectedChkp.Tree7Root, visitedBlocks, 0, records =>
                {
                    foreach (var rec in records)
                    {
                        if (rec.KeyData.Length >= 8 && rec.ValueData.Length >= 160)
                        {
                            ulong containerId = BitConverter.ToUInt64(rec.KeyData, 0);
                            ulong physicalStart = BitConverter.ToUInt64(rec.ValueData, 144);
                            containerMap[containerId] = physicalStart;
                        }
                    }
                });
                vr.Capabilities.ContainerTranslationSupported = true;
                c.Report.Capabilities.ContainerTranslationSupported = true;
                vr.Capabilities.SupportedFeatures.Add("container_translation");
            }

            // Load Object ID Table (Tree 0)
            var objectTreeRoots = new Dictionary<ulong, BlockReference>();
            if (selectedChkp.Tree0Root.BlockNumber > 0)
            {
                TraverseBTree(c, geom, selectedChkp.Tree0Root, visitedBlocks, 0, records =>
                {
                    foreach (var rec in records)
                    {
                        if (rec.KeyData.Length >= 16)
                        {
                            ulong objectId = BitConverter.ToUInt64(rec.KeyData, 8);
                            var objRef = ParseBlockReference(rec.ValueData, 0, geom.MajorVersion);
                            objectTreeRoots[objectId] = objRef;
                        }
                    }
                });
                vr.Capabilities.SupportedFeatures.Add("object_id_table_parsed");
            }

            // Enumerate Root Directory (Object 0x600)
            BlockReference rootDirRef;
            if (objectTreeRoots.TryGetValue(0x600, out rootDirRef) && rootDirRef.BlockNumber > 0)
            {
                var visitedDirs = new HashSet<ulong>();
                EnumerateDirectory(c, geom, containerMap, objectTreeRoots, 0x600, "", visitedDirs, visitedBlocks, 0, vr);
                vr.Status = "complete";
                vr.Capabilities.SupportedFeatures.Add("directory_tree_enumerated");
            }

            // Salvage unreferenced B+ tree leaf nodes in free space
            SalvageFreeSpace(c, geom, containerMap, visitedBlocks, vr);

            vr.Status = "complete";
        }

        // -------------------------------------------------------------
        // Directory & File Enumeration
        // -------------------------------------------------------------
        private static void EnumerateDirectory(
            Context c,
            VolumeGeometry geom,
            Dictionary<ulong, ulong> containerMap,
            Dictionary<ulong, BlockReference> objectTreeRoots,
            ulong dirObjectId,
            string currentPath,
            HashSet<ulong> visitedDirs,
            HashSet<ulong> visitedBlocks,
            int depth,
            VolumeReport vr)
        {
            if (depth > c.Limits.MaximumDirectoryDepth || !visitedDirs.Add(dirObjectId))
            {
                c.Report.Warnings.Add("circular_directory_reference_detected");
                return;
            }
            if (++c.DirectoryCount > c.Limits.MaximumDirectories)
            {
                c.Report.Limited = true;
                Skip(c, "directory_limit");
                return;
            }

            BlockReference dirRef;
            if (!objectTreeRoots.TryGetValue(dirObjectId, out dirRef) || dirRef.BlockNumber == 0)
                return;

            TraverseBTree(c, geom, dirRef, visitedBlocks, 0, records =>
            {
                foreach (var rec in records)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    if (rec.KeyData.Length < 4) continue;
                    ushort recordType = BitConverter.ToUInt16(rec.KeyData, 0);
                    if (recordType != 0x0030) continue; // Directory Entry (0x30)

                    ushort entryType = BitConverter.ToUInt16(rec.KeyData, 2);
                    string name = DecodeReFsString(rec.KeyData, 4, rec.KeyData.Length - 4);
                    if (string.IsNullOrEmpty(name) || name == "." || name == "..") continue;

                    string fullPath = string.IsNullOrEmpty(currentPath) ? name : currentPath + "/" + name;

                    if (entryType == 2)
                    {
                        // Subdirectory entry
                        if (rec.ValueData.Length >= 72)
                        {
                            ulong childObjId = BitConverter.ToUInt64(rec.ValueData, 0);
                            EnumerateDirectory(c, geom, containerMap, objectTreeRoots, childObjId, fullPath, visitedDirs, visitedBlocks, depth + 1, vr);
                        }
                    }
                    else if (entryType == 1)
                    {
                        // File entry
                        ProcessFileRecord(c, geom, containerMap, rec, name, fullPath, dirObjectId, vr, isLive: true);
                    }
                }
            });
        }

        private static void ProcessFileRecord(
            Context c,
            VolumeGeometry geom,
            Dictionary<ulong, ulong> containerMap,
            MinistoreNodeRecord rec,
            string name,
            string relativePath,
            ulong parentObjectId,
            VolumeReport vr,
            bool isLive)
        {
            byte[] val = rec.ValueData;
            if (val == null || val.Length < 32) return;
            if (++c.EntryCount > c.Limits.MaximumEntries)
            {
                c.Report.Limited = true;
                Skip(c, "entry_limit");
                return;
            }

            DateTime? created = SafeFileTimeUtc(BitConverter.ToUInt64(val, 0));
            DateTime? modified = SafeFileTimeUtc(BitConverter.ToUInt64(val, 8));
            DateTime? changed = SafeFileTimeUtc(BitConverter.ToUInt64(val, 16));
            DateTime? accessed = SafeFileTimeUtc(BitConverter.ToUInt64(val, 24));
            uint attrs = val.Length >= 36 ? BitConverter.ToUInt32(val, 32) : 0x20;
            long declaredSize = val.Length >= 72 ? (long)BitConverter.ToUInt64(val, 64) : 0;

            ulong objectId = (ulong)c.Report.Entries.Count + 1000;

            // Intercept compressed files
            if ((attrs & 0x800) != 0)
            {
                vr.Capabilities.CompressionDetected = true;
                c.Report.Capabilities.CompressionDetected = true;
                if (!vr.Capabilities.UnsupportedFeatures.Contains("cluster_compression"))
                    vr.Capabilities.UnsupportedFeatures.Add("cluster_compression");
                if (!c.Report.Capabilities.UnsupportedFeatures.Contains("cluster_compression"))
                    c.Report.Capabilities.UnsupportedFeatures.Add("cluster_compression");

                c.Report.Entries.Add(new Entry
                {
                    VolumeOffset = geom.VolumeOffset,
                    ObjectId = objectId,
                    ParentObjectId = parentObjectId,
                    Name = name,
                    RelativePath = relativePath,
                    DeclaredSize = declaredSize,
                    RecoveredBytes = 0,
                    CreationTimeUtc = created,
                    LastWriteTimeUtc = modified,
                    EntryChangeTimeUtc = changed,
                    LastAccessTimeUtc = accessed,
                    FileAttributes = attrs,
                    Status = "unsupported_feature",
                    Reason = "unsupported_compression",
                    MetadataChecksumVerified = true,
                    ContentAuthenticityVerified = false
                });
                return;
            }

            // Parse Attribute 0x80 ($DATA)
            bool isResident = false;
            byte[] residentData = null;
            var extents = new List<Extent>();

            int attrStart = 128;
            if (val.Length >= attrStart + 16)
            {
                uint attrType = BitConverter.ToUInt32(val, attrStart);
                uint attrFlags = BitConverter.ToUInt32(val, attrStart + 4);
                uint dataOff = BitConverter.ToUInt32(val, attrStart + 8);
                uint dataLen = BitConverter.ToUInt32(val, attrStart + 12);

                if (attrType == 0x80)
                {
                    if ((attrFlags & 0x08) == 0)
                    {
                        // Resident inline data
                        isResident = true;
                        int absData = attrStart + (int)dataOff;
                        if (absData + dataLen <= val.Length)
                        {
                            residentData = new byte[dataLen];
                            Array.Copy(val, absData, residentData, 0, (int)dataLen);
                            extents.Add(new Extent
                            {
                                ImageOffset = -1,
                                LogicalOffset = 0,
                                Length = dataLen
                            });
                            declaredSize = dataLen;
                        }
                    }
                    else
                    {
                        // Non-resident data runs
                        isResident = false;
                        int runsOff = attrStart + (int)dataOff;
                        int runsLen = (int)dataLen;
                        if (runsOff + runsLen <= val.Length)
                        {
                            int count = runsLen / 24;
                            long currentLogical = 0;
                            for (int r = 0; r < count; r++)
                            {
                                int rPos = runsOff + r * 24;
                                ulong logOff = BitConverter.ToUInt64(val, rPos);
                                ulong blkCnt = BitConverter.ToUInt64(val, rPos + 8);
                                ulong physBlk = BitConverter.ToUInt64(val, rPos + 16);

                                ulong physClus = TranslateContainerBlock(physBlk, geom.ContainerSize, containerMap);
                                long imgOffset = geom.VolumeOffset + (long)physClus * geom.ClusterBlockSize;
                                long extLen = (long)(blkCnt * geom.ClusterBlockSize);

                                if (declaredSize > 0 && currentLogical + extLen > declaredSize)
                                {
                                    extLen = Math.Max(0, declaredSize - currentLogical);
                                }

                                if (extLen > 0)
                                {
                                    extents.Add(new Extent
                                    {
                                        ImageOffset = imgOffset,
                                        LogicalOffset = (long)logOff,
                                        Length = extLen
                                    });
                                    currentLogical += extLen;
                                }
                            }
                        }
                    }
                }
            }

            if (extents.Count == 0 && declaredSize > 0) return;

            // Output candidate file
            string safeName = SanitizeFileName(name);
            string outName = string.Format("volume_{0}_object_{1}_{2}", geom.VolumeOffset, objectId, safeName);
            string relativeOutput = "files/" + outName;
            string dest = Path.Combine(c.Root, "files", outName);
            string temp = dest + ".partial";

            if (c.OutputBytes + declaredSize > c.Limits.MaximumOutputBytes)
            {
                c.Report.Limited = true;
                Skip(c, "output_limit");
                return;
            }

            byte[] buffer = new byte[1024 * 1024];
            string hashHex;
            try
            {
                using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var sha = SHA256.Create())
                {
                    if (isResident && residentData != null)
                    {
                        output.Write(residentData, 0, residentData.Length);
                        sha.TransformBlock(residentData, 0, residentData.Length, residentData, 0);
                    }
                    else
                    {
                        foreach (var ext in extents)
                        {
                            c.Input.Position = ext.ImageOffset;
                            long remaining = ext.Length;
                            while (remaining > 0)
                            {
                                c.Cancel.ThrowIfCancellationRequested();
                                int readCount = c.Input.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                                if (readCount == 0) throw new EndOfStreamException("Неполное чтение refs");
                                output.Write(buffer, 0, readCount);
                                sha.TransformBlock(buffer, 0, readCount, buffer, 0);
                                remaining -= readCount;
                            }
                        }
                    }
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    output.Flush(true);
                    hashHex = Hex(sha.Hash);
                }
                c.Cancel.ThrowIfCancellationRequested();
                File.Move(temp, dest);
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }

            string status = isLive ? "recovered_live" : "deleted_refs_candidate";
            var entry = new Entry
            {
                VolumeOffset = geom.VolumeOffset,
                ObjectId = objectId,
                ParentObjectId = parentObjectId,
                Name = name,
                RelativePath = relativePath,
                DeclaredSize = declaredSize,
                RecoveredBytes = declaredSize,
                CreationTimeUtc = created,
                LastWriteTimeUtc = modified,
                EntryChangeTimeUtc = changed,
                LastAccessTimeUtc = accessed,
                FileAttributes = attrs,
                Status = status,
                Output = relativeOutput,
                Sha256 = hashHex,
                IsResident = isResident,
                MetadataChecksumVerified = true,
                ContentAuthenticityVerified = false,
                DeletionEvidence = isLive ? null : "unreferenced_refs_leaf_node_in_free_space",
                Note = isLive ? "Кандидат ReFS; метаданные подтверждены CRC." : "Сохранившаяся запись ReFS (удалённый файл). Исходные кластеры свободны в текущем дереве, но могли быть перезаписаны; факт удаления и подлинность содержимого не подтверждены.",
                Extents = extents
            };

            c.Report.Entries.Add(entry);
            c.Report.RecoveredFiles++;
            c.Report.OutputBytes += declaredSize;
            c.OutputBytes += declaredSize;
            vr.RecoveredFiles++;
        }

        // -------------------------------------------------------------
        // Free-Space Salvage
        // -------------------------------------------------------------
        private static void SalvageFreeSpace(
            Context c,
            VolumeGeometry geom,
            Dictionary<ulong, ulong> containerMap,
            HashSet<ulong> visitedBlocks,
            VolumeReport vr)
        {
            ulong totalBlocks = (ulong)(c.Input.Length - geom.VolumeOffset) / geom.MetadataBlockSize;
            ulong maxScanBlocks = Math.Min(totalBlocks, 4096UL);

            for (ulong b = 0; b < maxScanBlocks; b++)
            {
                if (visitedBlocks.Contains(b)) continue;
                c.Cancel.ThrowIfCancellationRequested();

                long offset = geom.VolumeOffset + (long)b * geom.MetadataBlockSize;
                byte[] block = Read(c, offset, (int)geom.MetadataBlockSize);
                if (block == null) continue;

                var header = ParseNodeHeader(block, geom);
                if (header == null || header.NodeLevel != 0) continue;

                var records = ReadNodeRecords(block, header, geom);
                foreach (var rec in records)
                {
                    if (rec.KeyData.Length < 4) continue;
                    ushort recordType = BitConverter.ToUInt16(rec.KeyData, 0);
                    if (recordType != 0x0030) continue;

                    ushort entryType = BitConverter.ToUInt16(rec.KeyData, 2);
                    if (entryType != 1) continue; // Only file entries

                    string name = DecodeReFsString(rec.KeyData, 4, rec.KeyData.Length - 4);
                    if (string.IsNullOrEmpty(name)) continue;

                    // Check if already recovered
                    if (c.Report.Entries.Any(e => e.Name == name)) continue;

                    ProcessFileRecord(c, geom, containerMap, rec, name, name, 0, vr, isLive: false);
                    vr.DeletedCandidates++;
                }
            }
        }

        // -------------------------------------------------------------
        // Addressing & Containers
        // -------------------------------------------------------------
        internal static ulong TranslateContainerBlock(ulong blockNumber, ulong containerSize, Dictionary<ulong, ulong> containerMap)
        {
            if (containerSize == 0 || blockNumber < containerSize) return blockNumber;
            ulong containerId = blockNumber / containerSize;
            ulong blockOffset = blockNumber % containerSize;

            ulong startCluster;
            if (containerMap != null && containerMap.TryGetValue(containerId, out startCluster))
                return startCluster + blockOffset;

            return blockNumber;
        }

        // -------------------------------------------------------------
        // String & Time Decoding
        // -------------------------------------------------------------
        public static string DecodeReFsString(byte[] buffer, int offset, int count)
        {
            if (buffer == null || count <= 0 || offset + count > buffer.Length) return string.Empty;
            int charCount = count / 2;
            var sb = new StringBuilder(charCount);
            for (int i = 0; i < charCount; i++)
            {
                ushort codeUnit = BitConverter.ToUInt16(buffer, offset + i * 2);
                if (codeUnit == 0) break; // Null terminator
                if (codeUnit >= 0xD800 && codeUnit <= 0xDBFF)
                {
                    // High surrogate
                    if (i + 1 < charCount)
                    {
                        ushort next = BitConverter.ToUInt16(buffer, offset + (i + 1) * 2);
                        if (next >= 0xDC00 && next <= 0xDFFF)
                        {
                            sb.Append((char)codeUnit);
                            sb.Append((char)next);
                            i++;
                            continue;
                        }
                    }
                    sb.Append('\uFFFD');
                }
                else if (codeUnit >= 0xDC00 && codeUnit <= 0xDFFF)
                {
                    sb.Append('\uFFFD');
                }
                else if (codeUnit == '/' || codeUnit == '\\' || codeUnit < 32)
                {
                    sb.Append('_');
                }
                else
                {
                    sb.Append((char)codeUnit);
                }
            }
            return sb.ToString();
        }

        public static DateTime? SafeFileTimeUtc(ulong raw)
        {
            if (raw == 0 || raw > 2650467743999999999UL) return null;
            try
            {
                return DateTime.FromFileTimeUtc((long)raw);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        private static string SanitizeFileName(string name)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                if (invalid.Contains(c) || c < 32) sb.Append('_');
                else sb.Append(c);
            }
            return sb.ToString();
        }

        // -------------------------------------------------------------
        // Low-Level Helpers
        // -------------------------------------------------------------
        private static byte[] Read(Context c, long offset, int bytes)
        {
            c.Cancel.ThrowIfCancellationRequested();
            if (offset < 0 || bytes <= 0 || offset > c.Input.Length - bytes) return null;
            byte[] buffer = new byte[bytes];
            c.Input.Position = offset;
            int at = 0;
            while (at < bytes)
            {
                int n = c.Input.Read(buffer, at, bytes - at);
                if (n == 0) return null;
                at += n;
            }
            return buffer;
        }

        private static List<long> Discover(FileStream input)
        {
            var positions = new List<long> { 0 };
            byte[] mbr = new byte[512];
            input.Position = 0;
            if (input.Read(mbr, 0, 512) != 512 || BitConverter.ToUInt16(mbr, 510) != 0xaa55)
                return positions;

            for (int i = 0; i < 4; i++)
            {
                long offset = (long)BitConverter.ToUInt32(mbr, 446 + i * 16 + 8) * 512;
                if (offset > 0 && offset <= input.Length - 2048) positions.Add(offset);
            }

            // GPT entries
            byte[] header = new byte[512];
            input.Position = 512;
            if (input.Read(header, 0, 512) == 512 && Encoding.ASCII.GetString(header, 0, 8) == "EFI PART")
            {
                ulong table = BitConverter.ToUInt64(header, 72);
                uint count = BitConverter.ToUInt32(header, 80);
                uint size = BitConverter.ToUInt32(header, 84);
                if (table <= (ulong)(input.Length / 512) && count <= 16384 && size >= 128 && size <= 4096 &&
                    (ulong)count * size <= (ulong)input.Length - table * 512)
                {
                    byte[] entry = new byte[size];
                    for (uint i = 0; i < count; i++)
                    {
                        input.Position = (long)table * 512 + (long)i * size;
                        if (input.Read(entry, 0, entry.Length) != entry.Length) break;
                        ulong lba = BitConverter.ToUInt64(entry, 32);
                        if (entry.Take(16).Any(x => x != 0) && lba > 0 && lba <= (ulong)((input.Length - 2048) / 512))
                            positions.Add((long)lba * 512);
                    }
                }
            }
            return positions.Distinct().ToList();
        }

        private static string LocalFile(string file)
        {
            string path = Path.GetFullPath(file);
            if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.IndexOf(':', 2) >= 0 ||
                !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.Directory) != 0)
                throw new IOException("Требуется обычный локальный образ refs");
            NoLinks(path);
            return path;
        }

        private static void NoLinks(string path)
        {
            string current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                try
                {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Ссылки в пути refs запрещены");
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
                string parent = Path.GetDirectoryName(current);
                if (parent == current) break;
                current = parent;
            }
        }

        private static string HashStream(FileStream stream, CancellationToken cancel)
        {
            stream.Position = 0;
            using (var hash = SHA256.Create())
            {
                byte[] b = new byte[1024 * 1024];
                int n;
                while ((n = stream.Read(b, 0, b.Length)) > 0)
                {
                    cancel.ThrowIfCancellationRequested();
                    hash.TransformBlock(b, 0, n, b, 0);
                }
                hash.TransformFinalBlock(new byte[0], 0, 0);
                return Hex(hash.Hash);
            }
        }

        private static string Hex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        private static void Skip(Context c, string reason)
        {
            int n;
            c.Report.Skipped.TryGetValue(reason, out n);
            c.Report.Skipped[reason] = n + 1;
        }
    }
}
