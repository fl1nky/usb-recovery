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
    /// Reads version-dependent ReFS metadata, including self-checksummed volume anchors,
    /// translated multi-cluster B+ trees, embedded attributes and supported data runs.
    /// Native compatibility must be established on independent Windows-formatted images.
    /// Unreferenced pages are structural candidates, never proof of deletion or allocation state.
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
            public int MaximumSalvageBlocks = 4096;
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
            public HashSet<long> VerifiedMetadataOffsets = new HashSet<long>();
            public HashSet<long> ReferencedMetadataOffsets = new HashSet<long>();
            public Dictionary<ulong, List<MinistoreNodeRecord>> DirectoryRecords = new Dictionary<ulong, List<MinistoreNodeRecord>>();
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
            public Dictionary<ulong, ulong> ContainerMap;
            public int ReferenceSize;
        }

        internal struct BlockReference
        {
            public ulong BlockNumber;
            public byte ChecksumType;         // 1=CRC32C, 2=CRC64/NVME, 4=SHA256; missing/unknown is unverified
            public byte ChecksumDataOffset;
            public uint ChecksumDataSize;
            public ulong ExpectedChecksum;
            public ulong[] BlockNumbers;
            public byte[] Checksum;
            public bool DescriptorValid;
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
            public int HeaderOffset;
            public int HeaderDataOffset;
            public int HeaderDataSize;
            public uint DataStart;
            public uint DataEnd;
            public byte NodeLevel;            // 0 = leaf, >0 = branch
            public byte NodeTypeFlags;        // 0x01 = branch, 0x02 = root, 0x04 = stream
            public uint RecordOffsetsStart;
            public uint NumberOfRecordOffsets;
            public int[] RecordOffsets;
        }

        internal sealed class MinistoreNodeRecord
        {
            public bool MetadataChecksumVerified;
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
            // ReFS type 2 is CRC64/NVME, reflected polynomial 0x9A6C9329AC4BC9B5.
            ulong[] table = new ulong[256];
            for (uint i = 0; i < 256; i++)
            {
                ulong crc = i;
                for (int bit = 0; bit < 8; bit++)
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x9A6C9329AC4BC9B5UL : crc >> 1;
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

        public static ulong ComputeCrc64Nvme(byte[] data, int offset, int length)
        {
            ulong crc = 0xFFFFFFFFFFFFFFFFUL;
            for (int i = 0; i < length; i++)
                crc = Crc64Table[(crc ^ data[offset + i]) & 0xFF] ^ (crc >> 8);
            ulong result = ~crc;
            return result == 0xABBAFFFFABBAFFFEUL ? 0xABBAFFFFABBAFFFFUL : result;
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
                limits.MaximumExtents < 1 || limits.MaximumFileBytes < 1 || limits.MaximumOutputBytes < 1 ||
                limits.MaximumTreeDepth < 1 || limits.MaximumDirectoryDepth < 1 || limits.MaximumSalvageBlocks < 0)
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
            bool primary = VbrSignature(boot);
            bool backup = false;
            if (!primary)
            {
                // A backup can establish the volume base only when its geometry ends at this image boundary.
                foreach (int sector in new[] { 512, 4096 })
                {
                    byte[] tail = Read(c, c.Input.Length - sector, 512);
                    if (!VbrSignature(tail)) continue;
                    ulong n = BitConverter.ToUInt64(tail, 24);
                    uint bps = BitConverter.ToUInt32(tail, 32);
                    if (bps != sector || n > (ulong)((c.Input.Length - offset) / sector) ||
                        n * bps != (ulong)(c.Input.Length - offset)) continue;
                    boot = tail; backup = true; break;
                }
            }
            if (!primary && !backup) return null;
            ulong sectors = BitConverter.ToUInt64(boot, 24);
            uint bytesPerSector = BitConverter.ToUInt32(boot, 32);
            uint sectorsPerCluster = BitConverter.ToUInt32(boot, 36);
            if ((bytesPerSector != 512 && bytesPerSector != 4096) || sectorsPerCluster == 0 ||
                (sectorsPerCluster & (sectorsPerCluster - 1)) != 0 || sectorsPerCluster > 128 ||
                sectors == 0 || sectors > (ulong)((c.Input.Length - offset) / bytesPerSector))
            {
                Skip(c, "invalid_vbr_geometry"); return null;
            }
            uint cluster = bytesPerSector * sectorsPerCluster;
            if (cluster != 4096 && cluster != 65536) { Skip(c, "unsupported_cluster_size"); return null; }
            if (backup) c.Report.Warnings.Add("primary_vbr_corrupt_backup_used");
            return new VolumeGeometry
            {
                VolumeOffset = offset, NumberOfSectors = sectors, BytesPerSector = bytesPerSector,
                SectorsPerCluster = sectorsPerCluster, ClusterBlockSize = cluster,
                MetadataBlockSize = boot[40] == 1 ? 16384U : cluster,
                MajorVersion = boot[40], MinorVersion = boot[41],
                VolumeSerialNumber = BitConverter.ToUInt64(boot, 56),
                ContainerSize = boot[40] == 3 ? 0x4000000UL / cluster : 0,
                PrimaryVbrValid = primary, BackupVbrUsed = backup
            };
        }

        private static bool VbrSignature(byte[] b)
        {
            return b != null && b.Length >= 512 && Encoding.ASCII.GetString(b, 3, 8) == "ReFS\0\0\0\0" &&
                   Encoding.ASCII.GetString(b, 16, 4) == "FSRS";
        }

        // -------------------------------------------------------------
        // Superblock & Checkpoint Arbitration
        // -------------------------------------------------------------
        internal static SuperblockInfo ReadSuperblock(Context c, VolumeGeometry geom)
        {
            SuperblockInfo selected = null;
            ulong units = geom.NumberOfSectors * geom.BytesPerSector / geom.MetadataBlockSize;
            ulong[] copies = units > 33 ? new[] { 30UL, units - 2, units - 3 } : new[] { 30UL };
            foreach (ulong number in copies.Distinct())
            {
                byte[] block = ReadPhysicalBlock(c, geom, number);
                if (block == null || !MetadataHeader(block, geom, number, "SUPB")) continue;
                int h = geom.MajorVersion == 1 ? 48 : 80;
                uint cp = BitConverter.ToUInt32(block, h + 32), count = BitConverter.ToUInt32(block, h + 36);
                uint self = BitConverter.ToUInt32(block, h + 40), size = BitConverter.ToUInt32(block, h + 44);
                if (count != 2 || cp < h + 48 || cp > block.Length - 16 ||
                    !VerifySelfChecksum(block, geom, self, size, number)) continue;
                var candidate = new SuperblockInfo
                {
                    VolumeGuid = new Guid(block.Skip(h).Take(16).ToArray()),
                    SequenceNumber = BitConverter.ToUInt64(block, h + 24), ChecksumValid = true,
                    PrimaryCheckpoint = new BlockReference { BlockNumber = BitConverter.ToUInt64(block, (int)cp) },
                    SecondaryCheckpoint = new BlockReference { BlockNumber = BitConverter.ToUInt64(block, (int)cp + 8) }
                };
                if (candidate.PrimaryCheckpoint.BlockNumber == candidate.SecondaryCheckpoint.BlockNumber) continue;
                if (selected == null || candidate.SequenceNumber > selected.SequenceNumber) selected = candidate;
            }
            return selected;
        }

        internal static BlockReference ParseBlockReference(byte[] buffer, int offset, byte majorVersion)
        {
            var r = new BlockReference();
            int descriptor = majorVersion == 1 ? 8 : 32;
            if (buffer == null || offset < 0 || offset > buffer.Length - descriptor - 8) return r;
            r.BlockNumber = BitConverter.ToUInt64(buffer, offset);
            r.BlockNumbers = new ulong[majorVersion == 1 ? 1 : 4];
            for (int i = 0; i < r.BlockNumbers.Length; i++) r.BlockNumbers[i] = BitConverter.ToUInt64(buffer, offset + i * 8);
            int d = offset + descriptor;
            r.ChecksumType = buffer[d + 2]; r.ChecksumDataOffset = buffer[d + 3];
            r.ChecksumDataSize = BitConverter.ToUInt32(buffer, d + 4);
            int expectedSize = r.ChecksumType == 1 ? 4 : r.ChecksumType == 2 ? 8 : r.ChecksumType == 4 ? 32 : 0;
            int digest = d + r.ChecksumDataOffset;
            if (expectedSize == 0 || r.ChecksumDataSize != expectedSize || r.ChecksumDataOffset < 8 ||
                digest < d || digest > buffer.Length - expectedSize) return r;
            r.Checksum = buffer.Skip(digest).Take(expectedSize).ToArray();
            r.ExpectedChecksum = expectedSize == 4 ? BitConverter.ToUInt32(r.Checksum, 0) :
                                 expectedSize == 8 ? BitConverter.ToUInt64(r.Checksum, 0) : 0;
            r.DescriptorValid = true;
            return r;
        }

        internal static CheckpointInfo ReadCheckpoint(Context c, VolumeGeometry geom, BlockReference chkpRef, int index)
        {
            byte[] block = ReadPhysicalBlock(c, geom, chkpRef.BlockNumber);
            if (block == null || !MetadataHeader(block, geom, chkpRef.BlockNumber, "CHKP")) return null;
            int h = geom.MajorVersion == 1 ? 48 : 80;
            uint self = BitConverter.ToUInt32(block, h + 8), size = BitConverter.ToUInt32(block, h + 12);
            if (!VerifySelfChecksum(block, geom, self, size, chkpRef.BlockNumber)) return null;
            ushort major = BitConverter.ToUInt16(block, h + 4), minor = BitConverter.ToUInt16(block, h + 6);
            if (major != geom.MajorVersion) return null;
            int trailer = h + 16, countPos = trailer + (major == 1 ? 24 : 48), array = countPos + 4;
            uint count = BitConverter.ToUInt32(block, countPos);
            if (major == 3 && (BitConverter.ToUInt32(block, trailer + 24) & 0x200) != 0)
                array = (int)BitConverter.ToUInt32(block, array);
            if (count == 0 || count > 32 || array < countPos + 4 || (long)array + count * 4 > block.Length) return null;
            var info = new CheckpointInfo { Index = index, BlockNumber = chkpRef.BlockNumber,
                SequenceClock = BitConverter.ToUInt64(block, trailer), MajorVersion = major, MinorVersion = minor, ChecksumValid = true };
            uint t0 = BitConverter.ToUInt32(block, array);
            info.Tree0Root = ParseBlockReference(block, t0 <= int.MaxValue ? (int)t0 : -1, geom.MajorVersion);
            if (major == 3 && count >= 8)
            {
                uint t7 = BitConverter.ToUInt32(block, array + 28);
                info.Tree7Root = ParseBlockReference(block, t7 <= int.MaxValue ? (int)t7 : -1, geom.MajorVersion);
            }
            geom.ReferenceSize = (int)size;
            return info;
        }

        internal static bool VerifyBlockChecksum(byte[] block, BlockReference reference)
        {
            if (block == null || !reference.DescriptorValid || reference.Checksum == null) return false;
            if (reference.ChecksumType == 1) return ComputeCrc32c(block, 0, block.Length) == (uint)reference.ExpectedChecksum;
            if (reference.ChecksumType == 2) return ComputeCrc64Nvme(block, 0, block.Length) == reference.ExpectedChecksum;
            if (reference.ChecksumType == 4)
                using (var sha = SHA256.Create()) return sha.ComputeHash(block).SequenceEqual(reference.Checksum);
            return false;
        }

        private static bool VerifySelfChecksum(byte[] block, VolumeGeometry geom, uint offset, uint size, ulong number)
        {
            int min = geom.MajorVersion == 1 ? 24 : 48;
            if (size < min || offset < (geom.MajorVersion == 1 ? 96U : 128U) ||
                offset > block.Length || size > block.Length - offset) return false;
            BlockReference reference = ParseBlockReference(block, (int)offset, geom.MajorVersion);
            if (reference.BlockNumber != number || !reference.DescriptorValid) return false;
            byte[] data = (byte[])block.Clone();
            Array.Clear(data, (int)offset, (int)size);
            return VerifyBlockChecksum(data, reference);
        }

        private static bool MetadataHeader(byte[] block, VolumeGeometry geom, ulong number, string signature)
        {
            if (block == null || block.Length < 128) return false;
            if (geom.MajorVersion == 1) return BitConverter.ToUInt64(block, 0) == number;
            return Encoding.ASCII.GetString(block, 0, 4) == signature && BitConverter.ToUInt64(block, 32) == number;
        }

        private static byte[] ReadPhysicalBlock(Context c, VolumeGeometry geom, ulong number)
        {
            ulong bytes = geom.NumberOfSectors * geom.BytesPerSector;
            if (number == 0 || number > bytes / geom.MetadataBlockSize ||
                number * geom.MetadataBlockSize > bytes - geom.MetadataBlockSize) return null;
            return Read(c, geom.VolumeOffset + (long)(number * geom.MetadataBlockSize), (int)geom.MetadataBlockSize);
        }

        private static byte[] ReadReferencedPage(Context c, VolumeGeometry geom, BlockReference reference, bool physical)
        {
            int slots = geom.MajorVersion == 3 && geom.MetadataBlockSize == 4096 ? 4 : 1;
            if (reference.BlockNumbers == null || reference.BlockNumbers.Length < slots) return null;
            byte[] result = new byte[slots * geom.MetadataBlockSize];
            for (int i = 0; i < slots; i++)
            {
                ulong number = reference.BlockNumbers[i];
                if (number == 0 || number == ulong.MaxValue) return null;
                if (!physical) number = TranslateContainerBlock(number, geom.ContainerSize, geom.ContainerMap);
                if (number == ulong.MaxValue) { Skip(c, "unmapped_container"); return null; }
                if (number <= (ulong)(long.MaxValue / geom.MetadataBlockSize))
                    c.ReferencedMetadataOffsets.Add(geom.VolumeOffset + (long)(number * geom.MetadataBlockSize));
                byte[] part = ReadPhysicalBlock(c, geom, number);
                if (part == null) return null;
                Array.Copy(part, 0, result, i * (int)geom.MetadataBlockSize, part.Length);
            }
            return result;
        }

        // -------------------------------------------------------------
        // Ministore B+ Tree Traversal Engine
        // -------------------------------------------------------------
        internal static MinistoreNodeHeader ParseNodeHeader(byte[] block, VolumeGeometry geom)
        {
            int body = geom.MajorVersion == 1 ? 48 : 80;
            if (block == null || block.Length < body + 4) return null;
            if (geom.MajorVersion == 3 && Encoding.ASCII.GetString(block, 0, 4) != "MSB+") return null;
            return ParseEmbeddedNode(block, body, geom);
        }

        private static MinistoreNodeHeader ParseEmbeddedNode(byte[] data, int start, VolumeGeometry geom)
        {
            int minimum = geom.MajorVersion == 1 ? 32 : 40;
            if (data == null || start < 0 || start > data.Length - 4) return null;
            uint relative = BitConverter.ToUInt32(data, start);
            if (relative < 4 || relative > data.Length - start - minimum) return null;
            int h = start + (int)relative;
            uint first = BitConverter.ToUInt32(data, h), end = BitConverter.ToUInt32(data, h + 4);
            uint array = BitConverter.ToUInt32(data, h + 16), count = BitConverter.ToUInt32(data, h + 20);
            if (first < minimum || first > end || end > data.Length - h || array < minimum ||
                count > 8192 || (long)h + array + count * 4 > data.Length) return null;
            if (geom.MajorVersion == 3)
            {
                uint arrayEnd = BitConverter.ToUInt32(data, h + 32);
                if (arrayEnd != array + count * 4 || arrayEnd > data.Length - h) return null;
            }
            int[] offsets = new int[count];
            for (int i = 0; i < offsets.Length; i++)
            {
                uint value = BitConverter.ToUInt32(data, h + (int)array + i * 4);
                if (geom.MajorVersion == 3) value &= 0xffff;
                if (value < first || value >= end) return null;
                offsets[i] = (int)value;
            }
            return new MinistoreNodeHeader { HeaderOffset = h, HeaderDataOffset = start + 40,
                HeaderDataSize = relative >= 40 ? (int)relative - 40 : 0,
                NodeLevel = data[h + 12], NodeTypeFlags = data[h + 13], DataStart = first, DataEnd = end,
                RecordOffsetsStart = array, NumberOfRecordOffsets = count, RecordOffsets = offsets };
        }

        internal static List<MinistoreNodeRecord> ReadNodeRecords(byte[] block, MinistoreNodeHeader header, VolumeGeometry geom)
        {
            var result = new List<MinistoreNodeRecord>();
            if (block == null || header == null) return result;
            foreach (int relative in header.RecordOffsets)
            {
                int at = header.HeaderOffset + relative;
                if (at < 0 || at > block.Length - 16) continue;
                uint size = BitConverter.ToUInt32(block, at);
                ushort ko = BitConverter.ToUInt16(block, at + 4), kl = BitConverter.ToUInt16(block, at + 6);
                ushort flags = BitConverter.ToUInt16(block, at + 8), vo = BitConverter.ToUInt16(block, at + 10), vl = BitConverter.ToUInt16(block, at + 12);
                if (size < 16 || size > block.Length - at || size > header.DataEnd - relative ||
                    (kl > 0 && (ko < 16 || (uint)ko + kl > size)) || (vl > 0 && (vo < 16 || (uint)vo + vl > size))) continue;
                result.Add(new MinistoreNodeRecord { RecordSize = size, KeyOffset = ko, KeySize = kl, Flags = flags,
                    ValueOffset = vo, ValueSize = vl, KeyData = block.Skip(at + ko).Take(kl).ToArray(),
                    ValueData = block.Skip(at + vo).Take(vl).ToArray() });
            }
            return result;
        }

        internal static void TraverseBTree(Context c, VolumeGeometry geom, BlockReference rootRef,
            HashSet<ulong> visitedBlocks, int depth, Action<List<MinistoreNodeRecord>> leafHandler)
        {
            TraverseBTree(c, geom, rootRef, visitedBlocks, depth, leafHandler, false);
        }

        private static void TraverseBTree(Context c, VolumeGeometry geom, BlockReference rootRef,
            HashSet<ulong> visitedBlocks, int depth, Action<List<MinistoreNodeRecord>> leafHandler, bool physical)
        {
            c.Cancel.ThrowIfCancellationRequested();
            if (rootRef.BlockNumber == 0 || depth > c.Limits.MaximumTreeDepth) { Skip(c, "tree_depth_or_pointer"); return; }
            if (!visitedBlocks.Add(rootRef.BlockNumber)) { c.Report.Warnings.Add("tree_node_cycle_detected"); return; }
            byte[] block = ReadReferencedPage(c, geom, rootRef, physical);
            if (block == null) { Skip(c, "metadata_page_unreadable"); c.Report.Limited = true; return; }
            if (!VerifyBlockChecksum(block, rootRef))
            {
                c.Report.Warnings.Add("metadata_checksum_mismatch"); c.Report.Limited = true; return;
            }
            foreach (ulong number in rootRef.BlockNumbers.Where(x => x != 0 && x != ulong.MaxValue))
            {
                ulong physicalNumber = physical ? number : TranslateContainerBlock(number, geom.ContainerSize, geom.ContainerMap);
                if (physicalNumber != ulong.MaxValue)
                    c.VerifiedMetadataOffsets.Add(geom.VolumeOffset + (long)(physicalNumber * geom.MetadataBlockSize));
            }
            var header = ParseNodeHeader(block, geom);
            if (header == null) { Skip(c, "metadata_node_invalid"); c.Report.Limited = true; return; }
            var records = ReadNodeRecords(block, header, geom);
            if (records.Count != header.NumberOfRecordOffsets)
            {
                Skip(c, "metadata_record_invalid"); c.Report.Limited = true;
            }
            foreach (var record in records) record.MetadataChecksumVerified = true;
            if (header.NodeLevel == 0) { if (leafHandler != null) leafHandler(records); }
            else foreach (var record in records)
                TraverseBTree(c, geom, ParseBlockReference(record.ValueData, 0, geom.MajorVersion), visitedBlocks, depth + 1, leafHandler, physical);
        }

        // -------------------------------------------------------------
        // Volume Processing & Tree Traversal
        // -------------------------------------------------------------
        private static void ScanVolume(Context c, VolumeGeometry geom, VolumeReport vr, Action<string> progress)
        {
            c.DirectoryRecords.Clear();
            var sb = ReadSuperblock(c, geom);
            if (sb == null)
            {
                vr.Reason = "superblock_unreadable_or_corrupt";
                return;
            }
            vr.Capabilities.SuperblockChecksumVerified = sb.ChecksumValid;
            c.Report.Capabilities.SuperblockChecksumVerified = sb.ChecksumValid;
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
            geom.ContainerMap = null; // Container table child references are physical bootstrap addresses.
            if (geom.MajorVersion >= 3 && selectedChkp.Tree7Root.BlockNumber > 0)
            {
                TraverseBTree(c, geom, selectedChkp.Tree7Root, visitedBlocks, 0, records =>
                {
                    foreach (var rec in records)
                    {
                        if (rec.KeyData.Length >= 8 && rec.ValueData.Length >= 160)
                        {
                            ulong containerId = BitConverter.ToUInt64(rec.KeyData, 0);
                            ulong physicalStart = BitConverter.ToUInt64(rec.ValueData, rec.ValueData.Length - 16);
                            ulong cpc = BitConverter.ToUInt32(rec.ValueData, 24);
                            if (cpc != 0 && (cpc & (cpc - 1)) == 0) geom.ContainerSize = cpc;
                            containerMap[containerId] = physicalStart;
                        }
                    }
                }, true);
                vr.Capabilities.ContainerTranslationSupported = true;
                c.Report.Capabilities.ContainerTranslationSupported = true;
                vr.Capabilities.SupportedFeatures.Add("container_translation");
            }
            geom.ContainerMap = containerMap;

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
                            var objRef = ParseBlockReference(rec.ValueData, geom.MajorVersion == 1 ? 0 : 32, geom.MajorVersion);
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

            if (!objectTreeRoots.ContainsKey(0x600))
            {
                vr.Reason = "root_directory_unavailable";
                c.Report.Limited = true;
            }
            vr.Status = c.Report.Limited ? "limited" : "complete";
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

            List<MinistoreNodeRecord> directoryRecords;
            if (!c.DirectoryRecords.TryGetValue(dirObjectId, out directoryRecords))
            {
                directoryRecords = new List<MinistoreNodeRecord>();
                TraverseBTree(c, geom, dirRef, new HashSet<ulong>(), 0, rows => directoryRecords.AddRange(rows));
                c.DirectoryRecords[dirObjectId] = directoryRecords;
            }
            foreach (var records in new[] { directoryRecords })
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
                        if (rec.ValueData.Length >= 72 &&
                            (geom.MajorVersion == 1 || (BitConverter.ToUInt32(rec.ValueData, 64) & 0x10000010) != 0))
                        {
                            ulong childObjId = BitConverter.ToUInt64(rec.ValueData, geom.MajorVersion == 1 ? 0 : 8);
                            EnumerateDirectory(c, geom, containerMap, objectTreeRoots, childObjId, fullPath, visitedDirs, visitedBlocks, depth + 1, vr);
                        }
                        else if (geom.MajorVersion == 3 && rec.ValueData.Length >= 72)
                        {
                            ulong fileId = BitConverter.ToUInt64(rec.ValueData, 0), home = BitConverter.ToUInt64(rec.ValueData, 8);
                            List<MinistoreNodeRecord> homeRecords;
                            BlockReference homeRef;
                            if (!c.DirectoryRecords.TryGetValue(home, out homeRecords) && objectTreeRoots.TryGetValue(home, out homeRef))
                            {
                                homeRecords = new List<MinistoreNodeRecord>();
                                TraverseBTree(c, geom, homeRef, new HashSet<ulong>(), 0, rows => homeRecords.AddRange(rows));
                                c.DirectoryRecords[home] = homeRecords;
                            }
                            var candidates = homeRecords == null ? new List<MinistoreNodeRecord>() : homeRecords.Where(x =>
                                x.KeyData.Length >= 16 && BitConverter.ToUInt16(x.KeyData, 0) == 0x40 &&
                                BitConverter.ToUInt64(x.KeyData, 8) == fileId).ToList();
                            if (candidates.Count == 1)
                            {
                                ProcessFileRecord(c, geom, containerMap, candidates[0], name, fullPath, dirObjectId, vr, true);
                            }
                            else UnsupportedFile(c, geom, vr, name, fullPath, dirObjectId, "split_file_backing_unresolved", rec.MetadataChecksumVerified);
                        }
                        else UnsupportedFile(c, geom, vr, name, fullPath, dirObjectId, "split_file_record", rec.MetadataChecksumVerified);
                    }
                    else if (entryType == 1)
                    {
                        // File entry
                        ProcessFileRecord(c, geom, containerMap, rec, name, fullPath, dirObjectId, vr, isLive: true);
                    }
                }
            }
        }

        private static void UnsupportedFile(Context c, VolumeGeometry geom, VolumeReport vr,
            string name, string path, ulong parent, string reason, bool verified)
        {
            c.Report.Limited = true;
            Skip(c, reason);
            if (!vr.Capabilities.UnsupportedFeatures.Contains(reason)) vr.Capabilities.UnsupportedFeatures.Add(reason);
            if (!c.Report.Capabilities.UnsupportedFeatures.Contains(reason)) c.Report.Capabilities.UnsupportedFeatures.Add(reason);
            c.Report.Entries.Add(new Entry { VolumeOffset = geom.VolumeOffset, Name = name,
                RelativePath = path, ParentObjectId = parent, Status = "unsupported_feature", Reason = reason,
                MetadataChecksumVerified = verified, ContentAuthenticityVerified = false });
        }

        private static List<MinistoreNodeRecord> EmbeddedRecords(Context c, VolumeGeometry geom, byte[] data,
            MinistoreNodeHeader header, bool verified)
        {
            var records = new List<MinistoreNodeRecord>();
            if (header == null) return records;
            var rows = ReadNodeRecords(data, header, geom);
            if (header.NodeLevel == 0)
            {
                foreach (var row in rows) row.MetadataChecksumVerified = verified;
                return rows;
            }
            var seen = new HashSet<ulong>();
            foreach (var row in rows)
                TraverseBTree(c, geom, ParseBlockReference(row.ValueData, 0, geom.MajorVersion), seen, 0,
                    childRows => { foreach (var child in childRows) child.MetadataChecksumVerified &= verified; records.AddRange(childRows); });
            return records;
        }

        private static bool AddRun(Context c, VolumeGeometry geom, Dictionary<ulong, ulong> map,
            List<Extent> extents, ulong logicalCluster, ulong count, ulong virtualCluster, bool hole)
        {
            ulong unit = geom.MajorVersion == 1 ? geom.MetadataBlockSize : geom.ClusterBlockSize;
            ulong volumeBytes = geom.NumberOfSectors * geom.BytesPerSector;
            if (count == 0 || count > (ulong)c.Limits.MaximumFileBytes / unit ||
                logicalCluster > (ulong)c.Limits.MaximumFileBytes / unit ||
                count > (ulong)c.Limits.MaximumFileBytes / unit - logicalCluster) return false;
            for (ulong i = 0; i < count; i++)
            {
                if (extents.Count >= c.Limits.MaximumExtents) { c.Report.Limited = true; Skip(c, "extent_limit"); return false; }
                ulong physical = hole ? 0 : TranslateContainerBlock(virtualCluster + i, geom.ContainerSize, map);
                if (!hole && (physical == ulong.MaxValue || physical > volumeBytes / unit || physical * unit > volumeBytes - unit)) return false;
                extents.Add(new Extent { ImageOffset = hole ? -1 : geom.VolumeOffset + (long)(physical * unit),
                    LogicalOffset = (long)((logicalCluster + i) * unit), Length = (long)unit });
            }
            return true;
        }

        private static bool ReadExtentNode(Context c, VolumeGeometry geom, Dictionary<ulong, ulong> map,
            byte[] data, int node, List<Extent> extents, HashSet<ulong> seen, int depth)
        {
            if (depth > c.Limits.MaximumTreeDepth || node < 0 || node > data.Length - 40) return false;
            uint first = BitConverter.ToUInt32(data, node), end = BitConverter.ToUInt32(data, node + 4);
            uint array = BitConverter.ToUInt32(data, node + 16), count = BitConverter.ToUInt32(data, node + 20);
            uint arrayEnd = BitConverter.ToUInt32(data, node + 32);
            uint available = (uint)(data.Length - node);
            if (first != 40 || end < first || end > available || count > 8192 ||
                array < 40 || array > available || count > (available - array) / 4 ||
                arrayEnd != array + count * 4) return false;
            foreach (uint index in Enumerable.Range(0, (int)count).Select(x => (uint)x))
            {
                int relative = (int)(BitConverter.ToUInt32(data, node + (int)array + (int)index * 4) & 0xffff);
                int at = node + relative;
                if (relative < first || relative >= end || at > data.Length - 16) return false;
                if (data[node + 12] != 0)
                {
                    uint recordSize = BitConverter.ToUInt32(data, at);
                    ushort ko = BitConverter.ToUInt16(data, at + 4), kl = BitConverter.ToUInt16(data, at + 6);
                    ushort vo = BitConverter.ToUInt16(data, at + 10), vl = BitConverter.ToUInt16(data, at + 12);
                    if (recordSize < 16 || recordSize > end - relative || recordSize > data.Length - at ||
                        (kl > 0 && (ko < 16 || (uint)ko + kl > recordSize)) ||
                        vo < 16 || (uint)vo + vl > recordSize) return false;
                    var reference = ParseBlockReference(data.Skip(at + vo).Take(vl).ToArray(), 0, geom.MajorVersion);
                    if (!seen.Add(reference.BlockNumber)) return false;
                    byte[] child = ReadReferencedPage(c, geom, reference, false);
                    if (!VerifyBlockChecksum(child, reference)) return false;
                    var h = ParseNodeHeader(child, geom);
                    if (h == null || !ReadExtentNode(c, geom, map, child, h.HeaderOffset, extents, seen, depth + 1)) return false;
                }
                else
                {
                    if (end - relative < 24 || at > data.Length - 24) return false;
                    uint flags = BitConverter.ToUInt32(data, at + 8);
                    // Known unwritten/sparse flags explicitly describe logical zero ranges.
                    // Integrity layouts still require a separate decoder; no guessed stride is used.
                    ushort rowSize = BitConverter.ToUInt16(data, at + 10);
                    uint clusters = BitConverter.ToUInt32(data, at + 20);
                    bool logicalZeros = (flags & 0x20) != 0 || (flags & 0x10) == 0;
                    if (rowSize != 24 || rowSize > end - relative || rowSize > data.Length - at ||
                        (flags & 0xffff) == 0 || (flags & 0xffff & ~0xf0U) != 0 ||
                        !AddRun(c, geom, map, extents, BitConverter.ToUInt32(data, at + 12), clusters,
                            BitConverter.ToUInt64(data, at), logicalZeros)) return false;
                }
            }
            return true;
        }

        private static void ProcessFileRecord(Context c, VolumeGeometry geom, Dictionary<ulong, ulong> containerMap,
            MinistoreNodeRecord rec, string name, string relativePath, ulong parentObjectId, VolumeReport vr, bool isLive)
        {
            if (++c.EntryCount > c.Limits.MaximumEntries) { c.Report.Limited = true; Skip(c, "entry_limit"); return; }
            byte[] val = rec.ValueData;
            var fileNode = ParseEmbeddedNode(val, 0, geom);
            if (fileNode == null || fileNode.HeaderDataSize != 128)
            {
                UnsupportedFile(c, geom, vr, name, relativePath, parentObjectId, "file_embedded_node_invalid", rec.MetadataChecksumVerified); return;
            }
            int fh = fileNode.HeaderDataOffset;
            uint attrs = BitConverter.ToUInt32(val, fh + 32);
            ulong rawSize = BitConverter.ToUInt64(val, fh + 64);
            ulong objectId = geom.MajorVersion == 1 ? BitConverter.ToUInt64(val, fh + 40) : 0;
            if ((attrs & 0x800) != 0)
            {
                vr.Capabilities.CompressionDetected = true; c.Report.Capabilities.CompressionDetected = true;
                vr.Capabilities.UnsupportedFeatures.Add("cluster_compression"); c.Report.Capabilities.UnsupportedFeatures.Add("cluster_compression");
                UnsupportedFile(c, geom, vr, name, relativePath, parentObjectId, "unsupported_compression", rec.MetadataChecksumVerified); return;
            }
            var attributes = EmbeddedRecords(c, geom, val, fileNode, rec.MetadataChecksumVerified);
            byte[] resident = null;
            var extents = new List<Extent>();
            bool found = false, verified = rec.MetadataChecksumVerified;
            string unsupported = "data_attribute_unresolved";
            foreach (var attribute in attributes)
            {
                byte[] key = attribute.KeyData, av = attribute.ValueData;
                if (key.Length < 12) continue;
                uint marker = BitConverter.ToUInt32(key, 8);
                bool modern = marker == 0x80000001 || marker == 0x80000002;
                ushort type = modern && key.Length >= 16 ? BitConverter.ToUInt16(key, 12) : (ushort)marker;
                if (type != 0x80) continue;
                if (found) { unsupported = "ambiguous_default_data_stream"; found = false; break; }
                if (modern && marker == 0x80000001 && av.Length >= 60 && BitConverter.ToUInt32(av, 8) == 12)
                {
                    ulong size = BitConverter.ToUInt64(av, 32);
                    if (size > (ulong)(av.Length - 60)) continue;
                    resident = av.Skip(60).Take((int)size).ToArray(); rawSize = size; found = true;
                }
                else if (av.Length >= 136 && BitConverter.ToUInt32(av, 0) == 136 &&
                         (!modern || (key.Length >= 20 && BitConverter.ToUInt32(key, 16) == 0x1000)))
                {
                    rawSize = BitConverter.ToUInt64(av, geom.MinorVersion <= 4 ? 60 : 56);
                    found = ReadExtentNode(c, geom, containerMap, av, 136, extents, new HashSet<ulong>(), 0);
                    unsupported = "data_extent_layout_or_coverage_unsupported";
                }
                else if (!modern && av.Length >= 12 && BitConverter.ToUInt32(av, 0) == 0)
                {
                    uint dataOffset = BitConverter.ToUInt32(av, 4), length = BitConverter.ToUInt32(av, 8);
                    if (dataOffset < 12 || dataOffset > av.Length || length > av.Length - dataOffset) continue;
                    resident = av.Skip((int)dataOffset).Take((int)length).ToArray(); rawSize = length; found = true;
                }
                else if (!modern)
                {
                    var runNode = ParseEmbeddedNode(av, 0, geom);
                    if (runNode == null || runNode.HeaderDataSize != 96) continue;
                    int rh = runNode.HeaderDataOffset;
                    rawSize = BitConverter.ToUInt64(av, rh + 20);
                    found = true;
                    foreach (var run in EmbeddedRecords(c, geom, av, runNode, attribute.MetadataChecksumVerified))
                    {
                        if (run.ValueData.Length < 24 || !AddRun(c, geom, containerMap, extents,
                            BitConverter.ToUInt64(run.ValueData, 0), BitConverter.ToUInt64(run.ValueData, 8),
                            BitConverter.ToUInt64(run.ValueData, 16), false)) { found = false; break; }
                    }
                }
                verified &= attribute.MetadataChecksumVerified;
            }
            if (rawSize > (ulong)c.Limits.MaximumFileBytes)
            {
                c.Report.Limited = true; Skip(c, "file_size_limit"); return;
            }
            long declaredSize = (long)rawSize;
            if (resident == null && found)
            {
                extents = extents.OrderBy(x => x.LogicalOffset).ToList();
                long covered = 0;
                foreach (var extent in extents)
                {
                    if (extent.LogicalOffset != covered) { found = false; break; }
                    extent.Length = Math.Min(extent.Length, Math.Max(0, declaredSize - covered));
                    covered += extent.Length;
                }
                extents.RemoveAll(x => x.Length == 0);
                if (covered != declaredSize) found = false;
            }
            if (!found)
            {
                UnsupportedFile(c, geom, vr, name, relativePath, parentObjectId, unsupported, verified); return;
            }
            if (declaredSize > c.Limits.MaximumOutputBytes - c.OutputBytes)
            {
                c.Report.Limited = true; Skip(c, "output_limit"); return;
            }
            string outName = string.Format("volume_{0}_entry_{1}_{2}", geom.VolumeOffset, c.Report.Entries.Count, SanitizeFileName(name));
            string dest = Path.Combine(c.Root, "files", outName), temp = dest + ".partial";
            byte[] buffer = new byte[1024 * 1024];
            string hash;
            try
            {
                using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    if (resident != null) output.Write(resident, 0, resident.Length);
                    else foreach (var extent in extents)
                    {
                        if (extent.ImageOffset >= 0) c.Input.Position = extent.ImageOffset;
                        long remaining = extent.Length;
                        if (extent.ImageOffset < 0) Array.Clear(buffer, 0, buffer.Length);
                        while (remaining > 0)
                        {
                            c.Cancel.ThrowIfCancellationRequested();
                            int n = extent.ImageOffset < 0 ? (int)Math.Min(remaining, buffer.Length) : c.Input.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                            if (n == 0) throw new EndOfStreamException("Неполное чтение refs");
                            output.Write(buffer, 0, n); remaining -= n;
                        }
                    }
                    output.Flush(true);
                }
                using (var source = File.OpenRead(temp)) using (var sha = SHA256.Create()) hash = Hex(sha.ComputeHash(source));
                c.Cancel.ThrowIfCancellationRequested(); File.Move(temp, dest);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
            var entry = new Entry { VolumeOffset = geom.VolumeOffset, ObjectId = objectId,
                ParentObjectId = parentObjectId, Name = name, RelativePath = relativePath, DeclaredSize = declaredSize,
                RecoveredBytes = declaredSize, CreationTimeUtc = SafeFileTimeUtc(BitConverter.ToUInt64(val, fh)),
                LastWriteTimeUtc = SafeFileTimeUtc(BitConverter.ToUInt64(val, fh + 8)),
                EntryChangeTimeUtc = SafeFileTimeUtc(BitConverter.ToUInt64(val, fh + 16)),
                LastAccessTimeUtc = SafeFileTimeUtc(BitConverter.ToUInt64(val, fh + 24)), FileAttributes = attrs,
                Status = isLive ? "recovered_live" : "unreferenced_refs_candidate", Output = "files/" + outName,
                Sha256 = hash, IsResident = resident != null, MetadataChecksumVerified = verified,
                ContentAuthenticityVerified = false, DeletionEvidence = null,
                Note = isLive ? "Контрольные суммы метаданных проверены; целостность файловых данных отдельно не подтверждена." :
                    "Структурный кандидат вне посещённых деревьев; удаление, свободное состояние и checksum не подтверждены.", Extents = extents };
            c.Report.Entries.Add(entry); c.Report.Candidates++; c.Report.RecoveredFiles++; c.Report.OutputBytes += declaredSize;
            c.OutputBytes += declaredSize; vr.RecoveredFiles++;
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
            ulong totalBlocks = geom.NumberOfSectors * geom.BytesPerSector / geom.MetadataBlockSize;
            ulong maxScanBlocks = Math.Min(totalBlocks, (ulong)c.Limits.MaximumSalvageBlocks);
            if (maxScanBlocks < totalBlocks)
            {
                c.Report.Limited = true;
                Skip(c, "unreferenced_scan_limit");
            }

            for (ulong b = 0; b < maxScanBlocks; b++)
            {
                if (visitedBlocks.Contains(b)) continue;
                c.Cancel.ThrowIfCancellationRequested();

                long offset = geom.VolumeOffset + (long)b * geom.MetadataBlockSize;
                if (c.ReferencedMetadataOffsets.Contains(offset)) continue;
                int pageBytes = geom.MajorVersion == 3 && geom.MetadataBlockSize == 4096 ? 16384 : (int)geom.MetadataBlockSize;
                byte[] block = Read(c, offset, pageBytes);
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
                }
            }
        }

        // -------------------------------------------------------------
        // Addressing & Containers
        // -------------------------------------------------------------
        internal static ulong TranslateContainerBlock(ulong blockNumber, ulong containerSize, Dictionary<ulong, ulong> containerMap)
        {
            if (blockNumber == ulong.MaxValue) return ulong.MaxValue;
            if (containerSize == 0) return blockNumber;
            int shift = 0; ulong width = containerSize;
            while (width > 0) { shift++; width >>= 1; }
            ulong id = blockNumber >> shift, within = blockNumber & (containerSize - 1);
            if ((blockNumber & containerSize) != 0) return ulong.MaxValue;
            ulong start;
            if (containerMap != null && containerMap.TryGetValue(id, out start))
                return start > ulong.MaxValue - within ? ulong.MaxValue : start + within;
            if (containerMap != null && containerMap.Count > 0)
                return id < 2 ? blockNumber : ulong.MaxValue;
            // Without a container table only the direct region (container ids 0 and 1) is addressable.
            return id < 2 ? blockNumber : ulong.MaxValue;
        }

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
