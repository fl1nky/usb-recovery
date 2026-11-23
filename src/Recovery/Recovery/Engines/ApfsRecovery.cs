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
    /// Read-only Apple File System (APFS) structural metadata salvage and file recovery engine.
    /// Supports APFS container superblock (NXSB) discovery, volume superblock (APSB) parsing,
    /// B-Tree leaf node inspection (BTND) with 64-bit Fletcher checksum (Fletcher-64) verification,
    /// surviving live B-Tree traversal, and comprehensive salvage of unreferenced/deleted file candidates
    /// outside surviving trees and snapshots (unreferenced inodes, non-contiguous extents, and directory records).
    /// All access is strictly read-only; source SHA256 immutability is strictly asserted.
    /// </summary>
    public static partial class ApfsRecovery
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
            public int MaximumTreeDepth = 64;
            public int MaximumBlocks = 2000000;
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
            public ulong PhysicalBlockNumber;
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
            public string Status;             // "recovered_live", "unreferenced_apfs_candidate", "unsupported_feature"
            public string Reason;
            public string Output;
            public string Sha256;
            public bool IsResident;
            public bool MetadataChecksumVerified;
            public bool ContentAuthenticityVerified; // Always false for reconstructed deleted candidates
            public string DeletionEvidence;
            public bool IsOrphan;
            public ulong TransactionId;
            public List<Extent> Extents = new List<Extent>();
        }

        public sealed class CapabilityMatrix
        {
            public string ApfsVersion = "1.0";
            public uint BlockSize = 4096;
            public string ContainerUuid;
            public string VolumeName;
            public string VolumeUuid;
            public bool LiveTreeWalked;
            public bool UnreferencedSalvageSupported = true;
            public bool Fletcher64Verified = true;
            public List<string> SupportedFeatures = new List<string>();
            public List<string> UnsupportedFeatures = new List<string>();
            public List<string> HandledFeatures = new List<string>();
        }

        public sealed class VolumeReport
        {
            public long Offset;
            public uint BlockSize;
            public ulong BlockCount;
            public string VolumeName;
            public string VolumeUuid;
            public string Status;             // "ready", "rejected", "failed"
            public string Reason;
            public CapabilityMatrix Capabilities = new CapabilityMatrix();
            public int CheckedNodes;
            public int CorruptedNodesSkipped;
            public int RecoveredLiveFiles;
            public int DeletedCandidates;
        }

        public sealed class Report
        {
            public int Schema = 1;
            public string Method = "apfs_unreferenced_salvage";
            public string Status;             // "complete", "limited", "cancelled", "failed"
            public string SourceSha256;
            public bool SourceUnchanged;
            public long InputBytes;
            public long OutputBytes;
            public int Candidates;
            public int RecoveredFiles;
            public int DeletedCandidates;
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
        // Internal Context & Intermediate Records
        // -------------------------------------------------------------
        internal sealed class Context
        {
            public FileStream Stream;
            public string Destination;
            public CancellationToken Cancel;
            public Limits Limits;
            public Report Report;
            public long OutputBytes;
            public int EntryCount;
            public long ContainerOffset;
            public Func<long,int,byte[]> MetadataRead = null;
            public Action<Entry> PublishFile = null;
            public RecoveryVerifiedImage VerifiedImage = null;
        }

        internal sealed class RawInode
        {
            public ulong ObjectId;
            public ulong ParentId;
            public ulong PrivateId;
            public ulong Xid;
            public ulong CreateTimeNs;
            public ulong ModTimeNs;
            public ulong ChangeTimeNs;
            public ulong AccessTimeNs;
            public ushort Mode;
            public ulong UncompressedSize;
            public ulong DstreamSize;
            public string NameFromXfields;
            public bool HasDstream;
        }

        internal sealed class RawExtent
        {
            public ulong KeyOid;
            public ulong Xid;
            public ulong LogicalOffset;
            public ulong Length;
            public ulong PhysicalBlockNumber;
        }

        internal sealed class RawDrec
        {
            public ulong ParentId;
            public ulong FileId;
            public ulong Xid;
            public string Name;
            public ushort Flags;
        }

        // -------------------------------------------------------------
        // Public API
        // -------------------------------------------------------------
        public static int Recover(
            string imagePath,
            string destinationDirectory,
            CancellationToken cancel,
            Action<string> progress = null,
            IEnumerable<long> volumeOffsets = null,
            Limits limits = null)
        {
            if (string.IsNullOrEmpty(imagePath)) throw new ArgumentNullException("imagePath");
            if (string.IsNullOrEmpty(destinationDirectory)) throw new ArgumentNullException("destinationDirectory");
            if (!File.Exists(imagePath)) throw new FileNotFoundException("APFS source image file not found.", imagePath);
            cancel.ThrowIfCancellationRequested();

            if (limits == null) limits = new Limits();
            MetadataLimitsIdentity(limits);

            string apfsRoot = Path.Combine(destinationDirectory, "apfs");
            if (Directory.Exists(apfsRoot))
                throw new IOException("APFS destination directory already exists: " + apfsRoot);

            Directory.CreateDirectory(apfsRoot);

            string initialSha256 = null;
            long fileLength = new FileInfo(imagePath).Length;

            using (var sha = SHA256.Create())
            using (var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            {
                initialSha256 = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
            }

            var report = new Report
            {
                Status = "running",
                SourceSha256 = initialSha256,
                SourceUnchanged = true,
                InputBytes = fileLength,
                OutputBytes = 0,
                Candidates = 0,
                RecoveredFiles = 0,
                DeletedCandidates = 0,
                Cancelled = false,
                Limited = false,
                Failed = false
            };

            var ctx = new Context
            {
                Destination = apfsRoot,
                Cancel = cancel,
                Limits = limits,
                Report = report,
                OutputBytes = 0,
                EntryCount = 0
            };

            try
            {
                using (ctx.Stream = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.RandomAccess))
                {
                    ExecuteRecovery(ctx, volumeOffsets, progress);
                }

                report.Status = report.Limited ? "limited" : "complete";
            }
            catch (OperationCanceledException)
            {
                report.Status = "cancelled";
                report.Cancelled = true;
                throw;
            }
            catch (Exception ex)
            {
                report.Status = "failed";
                report.Failed = true;
                report.Warnings.Add("Execution failed: " + ex.Message);
                throw;
            }
            finally
            {
                string postSha256 = null;
                try
                {
                    using (var sha = SHA256.Create())
                    using (var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
                    {
                        postSha256 = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
                    }
                    report.SourceUnchanged = (initialSha256 == postSha256);
                }
                catch
                {
                    report.SourceUnchanged = false;
                }

                report.OutputBytes = ctx.OutputBytes;
                report.Candidates = report.Entries.Count;
                report.RecoveredFiles = report.Entries.Count(e => e.Status == "recovered_live");
                report.DeletedCandidates = report.Entries.Count(e => e.Status == "unreferenced_apfs_candidate");

                string reportJsonPath = Path.Combine(apfsRoot, "report.json");
                var serializer = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };
                string json = serializer.Serialize(report);
                File.WriteAllText(reportJsonPath, json, new UTF8Encoding(false));
            }

            return report.Entries.Count;
        }

        // -------------------------------------------------------------
        // Recovery Execution
        // -------------------------------------------------------------
        private static void ExecuteRecovery(Context ctx, IEnumerable<long> volumeOffsets, Action<string> progress)
        {
            if (volumeOffsets == null) { ExecuteContainer(ctx,progress); return; }
            var offsets = volumeOffsets.Take(16390).ToList();
            if (offsets.Count > 16389) throw new IOException("APFS_OFFSET_REQUEST_LIMIT");
            int found = 0;
            try {
                foreach (long offset in offsets.Distinct()) {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (offset < 0 || (offset&511) != 0 || offset > ctx.Stream.Length-4096) { ctx.Report.Warnings.Add("APFS invalid container offset"); continue; }
                    ctx.ContainerOffset = offset;
                    try { ExecuteContainer(ctx,progress); found++; }
                    catch (InvalidDataException) { ctx.Report.Warnings.Add("APFS container at requested offset is unreadable or unsupported"); }
                }
                if (found == 0) throw new InvalidDataException("No readable APFS container at supplied offsets");
            } finally { ctx.ContainerOffset = 0; }
        }
        private static void ExecuteContainer(Context ctx, Action<string> progress)
        {
            ctx.Cancel.ThrowIfCancellationRequested();
            if (progress != null) progress("Scanning container and volume headers...");

            long length = ctx.Stream.Length-ctx.ContainerOffset;
            uint blockSize = 4096;

            // 1. Locate Container Superblock (NXSB)
            byte[] block0 = ReadMetadata(ctx,0,(int)blockSize);
            if (block0 == null) throw new InvalidDataException("Source image smaller than minimum container block size.");
            long containerHeader = 0;

            string magic = Encoding.ASCII.GetString(block0, 32, 4);
            if (magic != "NXSB")
            {
                // Fallback scan for NXSB at first few blocks
                bool found = false;
                for (int b = 1; b < Math.Min(16L, length / blockSize); b++)
                {
                    containerHeader = (long)b * blockSize;
                    block0 = ReadMetadata(ctx,containerHeader,(int)blockSize);
                    if (block0 == null) break;
                    if (Encoding.ASCII.GetString(block0, 32, 4) == "NXSB")
                    {
                        found = true;
                        break;
                    }
                }
                if (!found) throw new InvalidDataException("No valid APFS container superblock (NXSB) found.");
            }

            uint nxBlockSize = BitConverter.ToUInt32(block0, 36);
            if (nxBlockSize < 1024 || nxBlockSize > 65536 || (nxBlockSize & (nxBlockSize-1)) != 0)
                throw new InvalidDataException("APFS block size is unsupported by this reader");
            blockSize = nxBlockSize;
            if (block0.Length != blockSize) block0 = ReadMetadata(ctx,containerHeader,(int)blockSize);
            if (block0 == null || BitConverter.ToUInt64(block0,0) != ComputeFletcher64(block0,8,(int)blockSize-8))
                throw new InvalidDataException("APFS container header checksum invalid");

            ulong blockCount = BitConverter.ToUInt64(block0, 40);
            if (blockCount == 0 || blockCount > (ulong)(length/blockSize)) throw new InvalidDataException("APFS container geometry outside source");
            length = (long)blockCount*blockSize;
            byte[] containerUuidBytes = new byte[16];
            Array.Copy(block0, 72, containerUuidBytes, 0, 16);
            string containerUuid = new Guid(containerUuidBytes).ToString("D");

            uint maxFs = BitConverter.ToUInt32(block0, 180);
            List<ulong> fsOids = new List<ulong>();
            for (int i = 0; i < Math.Min((int)maxFs, 16); i++)
            {
                int off = 184 + i * 8;
                if (off + 8 <= blockSize)
                {
                    ulong fsOid = BitConverter.ToUInt64(block0, off);
                    if (fsOid != 0) fsOids.Add(fsOid);
                }
            }

            // 2. Discover Volumes (APSB)
            var volumes = new List<DiscoveredVolume>();
            long totalBlocks = length / blockSize;
            long scanBlocks = Math.Min(totalBlocks, (long)ctx.Limits.MaximumBlocks);
            if (scanBlocks < totalBlocks) { ctx.Report.Limited = true; ctx.Report.Warnings.Add("APFS block scan limited by MaximumBlocks"); }

            byte[] scanBuf = new byte[blockSize];
            for (long b = 0; b < scanBlocks; b++)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                scanBuf = ReadMetadata(ctx,b*blockSize,(int)blockSize);
                if (scanBuf == null) break;

                // Check for APSB magic at offset 32
                if (scanBuf[32] == 'A' && scanBuf[33] == 'P' && scanBuf[34] == 'S' && scanBuf[35] == 'B')
                {
                    ulong expectedCk = BitConverter.ToUInt64(scanBuf, 0);
                    ulong calcCk = ComputeFletcher64(scanBuf, 8, (int)blockSize - 8);
                    if (expectedCk == calcCk)
                    {
                        var vol = new DiscoveredVolume();
                        vol.BlockNumber = (ulong)b;
                        vol.BlockOffset = ctx.ContainerOffset+b * blockSize;
                        vol.Oid = BitConverter.ToUInt64(scanBuf, 8);
                        vol.Xid = BitConverter.ToUInt64(scanBuf, 16);
                        vol.RootTreeType = BitConverter.ToUInt32(scanBuf, 116);
                        vol.RootTreeOid = BitConverter.ToUInt64(scanBuf, 136);

                        byte[] volUuidBytes = new byte[16];
                        Array.Copy(scanBuf, 240, volUuidBytes, 0, 16);
                        vol.VolumeUuid = new Guid(volUuidBytes).ToString("D");

                        // Name at 704
                        int nameEnd = 704;
                        while (nameEnd < blockSize && scanBuf[nameEnd] != 0 && (nameEnd - 704) < 255) nameEnd++;
                        vol.VolumeName = Encoding.UTF8.GetString(scanBuf, 704, nameEnd - 704);
                        if (string.IsNullOrEmpty(vol.VolumeName)) vol.VolumeName = "Volume_" + vol.Oid;

                        if (ctx.Report.Volumes.Count+volumes.Count < ctx.Limits.MaximumVolumes) volumes.Add(vol);
                        else { ctx.Report.Limited = true; ctx.Report.Warnings.Add("APFS volume limit reached"); break; }
                    }
                }
            }

            if (volumes.Count == 0)
                throw new InvalidDataException("No valid APFS volume superblock (APSB) found in container.");

            ctx.Report.Capabilities.ApfsVersion = "1.0";
            ctx.Report.Capabilities.BlockSize = blockSize;
            ctx.Report.Capabilities.ContainerUuid = containerUuid;
            ctx.Report.Capabilities.Fletcher64Verified = true;
            ctx.Report.Capabilities.UnreferencedSalvageSupported = true;
            ctx.Report.Capabilities.SupportedFeatures.Add("Container Superblock (NXSB)");
            ctx.Report.Capabilities.SupportedFeatures.Add("Volume Superblock (APSB)");
            ctx.Report.Capabilities.SupportedFeatures.Add("B-Tree Leaf Node Scanning (BTND)");
            ctx.Report.Capabilities.SupportedFeatures.Add("Fletcher-64 Checksum Verification");
            ctx.Report.Capabilities.SupportedFeatures.Add("Copy-on-Write (RoW) Unreferenced Salvage");
            ctx.Report.Capabilities.SupportedFeatures.Add("Non-contiguous Extent Assembly");
            ctx.Report.Capabilities.SupportedFeatures.Add("Surviving Tree Traversal");
            ctx.Report.Capabilities.SupportedFeatures.Add("Orphan File Inode-Name Reconstruction");

            // 3. Process Each Volume
            foreach (var vol in volumes)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                ProcessVolume(ctx, vol, blockSize, scanBlocks, progress);
            }
        }

        private sealed class DiscoveredVolume
        {
            public ulong BlockNumber;
            public long BlockOffset;
            public ulong Oid;
            public ulong Xid;
            public uint RootTreeType;
            public ulong RootTreeOid;
            public string VolumeName;
            public string VolumeUuid;
        }

        private static void ProcessVolume(Context ctx, DiscoveredVolume vol, uint blockSize, long scanBlocks, Action<string> progress)
        {
            var volReport = new VolumeReport
            {
                Offset = vol.BlockOffset,
                BlockSize = blockSize,
                BlockCount = (ulong)scanBlocks,
                VolumeName = vol.VolumeName,
                VolumeUuid = vol.VolumeUuid,
                Status = "ready",
                Reason = "ok",
                CheckedNodes = 0,
                CorruptedNodesSkipped = 0,
                RecoveredLiveFiles = 0,
                DeletedCandidates = 0
            };
            ctx.Report.Volumes.Add(volReport);

            var liveOids = new HashSet<ulong>();
            var parsedInodes = new List<RawInode>();
            var parsedExtents = new List<RawExtent>();
            var parsedDrecs = new List<RawDrec>();

            // 3a. Walk Live Tree if RootTree is Physical or Direct
            if (vol.RootTreeOid != 0 && vol.RootTreeOid < (ulong)scanBlocks)
            {
                byte[] rootBlock = new byte[blockSize];
                rootBlock = ReadMetadata(ctx,(long)vol.RootTreeOid*blockSize,(int)blockSize);
                if (rootBlock != null)
                {
                    ulong expectedCk = BitConverter.ToUInt64(rootBlock, 0);
                    ulong calcCk = ComputeFletcher64(rootBlock, 8, (int)blockSize - 8);
                    if (expectedCk == calcCk)
                    {
                        ushort btnFlags = BitConverter.ToUInt16(rootBlock, 32);
                        ushort btnLevel = BitConverter.ToUInt16(rootBlock, 34);
                        uint btnNkeys = BitConverter.ToUInt32(rootBlock, 36);

                        if (btnLevel == 0 && btnNkeys > 0 && btnNkeys <= (blockSize - 56) / 8)
                        {
                            ParseBTreeNodeRecords(rootBlock, blockSize, parsedInodes, parsedExtents, parsedDrecs);
                            foreach (var inode in parsedInodes)
                                liveOids.Add(inode.ObjectId);
                            volReport.Capabilities.LiveTreeWalked = true;
                        }
                    }
                }
            }

            // 3b. Container-Wide Block Sweep for all valid B-Tree Nodes
            byte[] blockBuf = new byte[blockSize];
            for (long b = 0; b < scanBlocks; b++)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                blockBuf = ReadMetadata(ctx,b*blockSize,(int)blockSize);
                if (blockBuf == null) break;

                // Object header obj_phys_t:
                // o_type at offset 24 (4 bytes), subtype at offset 28 (4 bytes)
                uint oType = BitConverter.ToUInt32(blockBuf, 24);
                uint oSubtype = BitConverter.ToUInt32(blockBuf, 28);
                uint baseType = oType & 0x0000FFFF;

                // Check if B-Tree or B-Tree Node with FS record subtype (14 / 0x0E)
                if ((baseType == 2 || baseType == 3) && oSubtype == 14)
                {
                    volReport.CheckedNodes++;

                    ulong expectedCk = BitConverter.ToUInt64(blockBuf, 0);
                    ulong calcCk = ComputeFletcher64(blockBuf, 8, (int)blockSize - 8);
                    if (expectedCk != calcCk)
                    {
                        volReport.CorruptedNodesSkipped++;
                        continue;
                    }

                    ushort btnFlags = BitConverter.ToUInt16(blockBuf, 32);
                    ushort btnLevel = BitConverter.ToUInt16(blockBuf, 34);
                    uint btnNkeys = BitConverter.ToUInt32(blockBuf, 36);

                    if (btnLevel == 0 && btnNkeys > 0 && btnNkeys <= (blockSize - 56) / 8)
                    {
                        ParseBTreeNodeRecords(blockBuf, blockSize, parsedInodes, parsedExtents, parsedDrecs);
                    }
                }
            }

            // 3c. Reconstruct Directory Map
            // Map: parent_id -> list of RawDrec
            var drecMap = new Dictionary<ulong, List<RawDrec>>();
            var drecByFileId = new Dictionary<ulong, RawDrec>();

            foreach (var drec in parsedDrecs.OrderByDescending(d => d.Xid))
            {
                if (!drecByFileId.ContainsKey(drec.FileId))
                    drecByFileId[drec.FileId] = drec;

                List<RawDrec> list;
                if (!drecMap.TryGetValue(drec.ParentId, out list))
                {
                    list = new List<RawDrec>();
                    drecMap[drec.ParentId] = list;
                }
                if (!list.Any(existing => existing.Name == drec.Name))
                    list.Add(drec);
            }

            // Map: inode_id -> RawInode (pick highest transaction Xid)
            var inodeById = new Dictionary<ulong, RawInode>();
            foreach (var inode in parsedInodes.OrderByDescending(i => i.Xid))
            {
                if (!inodeById.ContainsKey(inode.ObjectId))
                    inodeById[inode.ObjectId] = inode;
            }

            // Helper to build directory path for an inode
            Func<ulong, string> buildPath = null;
            buildPath = oid =>
            {
                var visited = new HashSet<ulong>(); var parts = new List<string>();
                while (oid > 2) {
                    ctx.Cancel.ThrowIfCancellationRequested();
                    if (!visited.Add(oid) || parts.Count >= ctx.Limits.MaximumTreeDepth || parts.Count >= ctx.Limits.MaximumDirectories) {
                        ctx.Report.Limited = true; ctx.Report.Warnings.Add("APFS parent chain cyclic or beyond limits"); return "[Lost+Found]";
                    }
                    RawDrec drec;
                    if (!drecByFileId.TryGetValue(oid,out drec)) { parts.Add("[Lost+Found]"); break; }
                    parts.Add(drec.Name); oid = drec.ParentId;
                }
                parts.Reverse(); return String.Join("/",parts);
            };

            // Group extents by KeyOid
            var extentsByOid = new Dictionary<ulong, List<RawExtent>>();
            foreach (var ext in parsedExtents)
            {
                List<RawExtent> list;
                if (!extentsByOid.TryGetValue(ext.KeyOid, out list))
                {
                    list = new List<RawExtent>();
                    extentsByOid[ext.KeyOid] = list;
                }
                list.Add(ext);
            }

            // 3d. Assemble and Recover Files
            foreach (var kvp in inodeById)
            {
                ctx.Cancel.ThrowIfCancellationRequested();
                RawInode inode = kvp.Value;

                // Check if directory
                bool isDir = (inode.Mode & 0xF000) == 0x00004000;
                if (isDir) continue;
                if (++ctx.EntryCount > ctx.Limits.MaximumEntries) { ctx.Report.Limited = true; ctx.Report.Warnings.Add("APFS entry limit reached"); break; }

                bool isLive = liveOids.Contains(inode.ObjectId);

                // Find extents: match on private_id or ObjectId
                List<RawExtent> rawExts = null;
                if (inode.PrivateId != 0 && extentsByOid.TryGetValue(inode.PrivateId, out rawExts))
                {
                }
                else if (extentsByOid.TryGetValue(inode.ObjectId, out rawExts))
                {
                }

                // If no extents and size is 0, allow 0-byte file
                long declaredSize = (long)(inode.HasDstream ? inode.DstreamSize : inode.UncompressedSize);
                if (rawExts == null && declaredSize > 0)
                {
                    // Inode without extents; skip or record unrecovered
                    continue;
                }

                // Deduplicate and order extents
                var cleanExtents = new List<Extent>();
                if (rawExts != null)
                {
                    // Group extents by LogicalOffset, pick newest Xid
                    var extByOffset = new Dictionary<ulong, RawExtent>();
                    foreach (var e in rawExts.OrderByDescending(x => x.Xid))
                    {
                        if (!extByOffset.ContainsKey(e.LogicalOffset))
                            extByOffset[e.LogicalOffset] = e;
                    }

                    foreach (var e in extByOffset.Values.OrderBy(x => x.LogicalOffset))
                    {
                        cleanExtents.Add(new Extent
                        {
                            ImageOffset = e.PhysicalBlockNumber > (ulong)((Int64.MaxValue-ctx.ContainerOffset)/blockSize) ? -1 : ctx.ContainerOffset+(long)e.PhysicalBlockNumber * blockSize,
                            LogicalOffset = (long)e.LogicalOffset,
                            Length = (long)e.Length,
                            PhysicalBlockNumber = e.PhysicalBlockNumber
                        });
                    }
                }

                // If declaredSize is 0 but extents exist, derive size from extents
                if (declaredSize == 0 && cleanExtents.Count > 0)
                {
                    declaredSize = cleanExtents.Sum(e => e.Length);
                }

                if (declaredSize > ctx.Limits.MaximumFileBytes)
                {
                    ctx.Report.Limited = true;
                    ctx.Report.Warnings.Add(string.Format("File inode {0} declared size {1} exceeds MaximumFileBytes limit {2}.",
                        inode.ObjectId, declaredSize, ctx.Limits.MaximumFileBytes));
                    continue;
                }

                if (declaredSize < 0 || ctx.OutputBytes < 0 || declaredSize > ctx.Limits.MaximumOutputBytes-ctx.OutputBytes)
                {
                    ctx.Report.Limited = true;
                    ctx.Report.Warnings.Add(string.Format("MaximumOutputBytes limit reached ({0} bytes); stopping file extraction.",
                        ctx.Limits.MaximumOutputBytes));
                    break;
                }

                // Resolve filename and path
                string filename = null;
                string dirPath = "";
                bool isOrphan = false;

                RawDrec drec;
                if (drecByFileId.TryGetValue(inode.ObjectId, out drec))
                {
                    filename = drec.Name;
                    dirPath = buildPath(drec.ParentId);
                }
                else if (!string.IsNullOrEmpty(inode.NameFromXfields))
                {
                    filename = inode.NameFromXfields;
                    dirPath = "[Lost+Found]";
                    isOrphan = true;
                }
                else
                {
                    filename = string.Format("apfs_inode_{0}.bin", inode.ObjectId);
                    dirPath = "[Lost+Found]";
                    isOrphan = true;
                }

                string relativePath = string.IsNullOrEmpty(dirPath) ? filename : dirPath + "/" + filename;
                var entry = new Entry
                {
                    VolumeOffset = vol.BlockOffset,
                    ObjectId = inode.ObjectId,
                    ParentObjectId = inode.ParentId,
                    Name = filename,
                    RelativePath = relativePath,
                    DeclaredSize = declaredSize,

                    CreationTimeUtc = FromUnixNs(inode.CreateTimeNs),
                    LastWriteTimeUtc = FromUnixNs(inode.ModTimeNs),
                    EntryChangeTimeUtc = FromUnixNs(inode.ChangeTimeNs),
                    LastAccessTimeUtc = FromUnixNs(inode.AccessTimeNs),
                    FileAttributes = (uint)inode.Mode,
                    Status = isLive ? "recovered_live" : "unreferenced_apfs_candidate",
                    Reason = isLive ? "live_filesystem_tree" : "unreferenced_leaf_node_salvage",
                    DeletionEvidence = null,

                    IsResident = false,
                    MetadataChecksumVerified = true,
                    ContentAuthenticityVerified = false,
                    IsOrphan = isOrphan,
                    TransactionId = inode.Xid,
                    Extents = cleanExtents
                };

                if (ctx.PublishFile != null) ctx.PublishFile(entry); else WriteFileLegacy(ctx, entry);
                ctx.OutputBytes += entry.RecoveredBytes;
                ctx.Report.Entries.Add(entry);
                if (isLive) volReport.RecoveredLiveFiles++;
                else volReport.DeletedCandidates++;
            }
        }

        // -------------------------------------------------------------
        // B-Tree Node Record Parsing
        // -------------------------------------------------------------
        private static void ParseBTreeNodeRecords(
            byte[] block,
            uint blockSize,
            List<RawInode> inodes,
            List<RawExtent> extents,
            List<RawDrec> drecs)
        {
            ulong xid = BitConverter.ToUInt64(block, 16);
            ushort btnFlags = BitConverter.ToUInt16(block, 32);
            bool isRoot = (btnFlags & 0x0001) != 0;
            bool isFixed = (btnFlags & 0x0004) != 0;
            uint nkeys = BitConverter.ToUInt32(block, 36);

            ushort tableSpaceOff = BitConverter.ToUInt16(block, 40);
            ushort tableSpaceLen = BitConverter.ToUInt16(block, 42);

            int nodeHeaderSize = 56;
            int keyStart = nodeHeaderSize + tableSpaceOff + tableSpaceLen;
            int valBase = (int)blockSize - (isRoot ? 40 : 0);

            for (int i = 0; i < nkeys; i++)
            {
                int tocOffset = nodeHeaderSize + tableSpaceOff + i * (isFixed ? 4 : 8);
                if (tocOffset + (isFixed ? 4 : 8) > blockSize) break;

                int kOff, kLen, vOff, vLen;
                if (isFixed)
                {
                    kOff = BitConverter.ToUInt16(block, tocOffset);
                    vOff = BitConverter.ToUInt16(block, tocOffset + 2);
                    kLen = 16;
                    vLen = 16;
                }
                else
                {
                    kOff = BitConverter.ToUInt16(block, tocOffset);
                    kLen = BitConverter.ToUInt16(block, tocOffset + 2);
                    vOff = BitConverter.ToUInt16(block, tocOffset + 4);
                    vLen = BitConverter.ToUInt16(block, tocOffset + 6);
                }

                int absKey = keyStart + kOff;
                int absVal = valBase - vOff;

                if (absKey < 0 || absKey + kLen > blockSize || absVal < 0 || absVal + vLen > blockSize)
                    continue;

                if (kLen < 8) continue;
                ulong rawKey = BitConverter.ToUInt64(block, absKey);
                uint keyType = (uint)(rawKey >> 60);
                ulong keyOid = rawKey & 0x0FFFFFFFFFFFFFFFL;

                if (keyType == 3) // INODE
                {
                    if (vLen >= 92)
                    {
                        var inod = new RawInode();
                        inod.ObjectId = keyOid;
                        inod.Xid = xid;
                        inod.ParentId = BitConverter.ToUInt64(block, absVal);
                        inod.PrivateId = BitConverter.ToUInt64(block, absVal + 8);
                        inod.CreateTimeNs = BitConverter.ToUInt64(block, absVal + 16);
                        inod.ModTimeNs = BitConverter.ToUInt64(block, absVal + 24);
                        inod.ChangeTimeNs = BitConverter.ToUInt64(block, absVal + 32);
                        inod.AccessTimeNs = BitConverter.ToUInt64(block, absVal + 40);
                        inod.Mode = BitConverter.ToUInt16(block, absVal + 80);
                        inod.UncompressedSize = BitConverter.ToUInt64(block, absVal + 84);

                        // Parse extended fields if present
                        if (vLen > 92 + 4)
                        {
                            int xfStart = absVal + 92;
                            ushort numExts = BitConverter.ToUInt16(block, xfStart);
                            ushort usedData = BitConverter.ToUInt16(block, xfStart + 2);
                            int extsTable = xfStart + 4;
                            int dataArea = extsTable + numExts * 4;

                            if (dataArea + usedData <= absVal + vLen)
                            {
                                int curOffset = 0;
                                for (int e = 0; e < numExts; e++)
                                {
                                    int fHdr = extsTable + e * 4;
                                    byte xType = block[fHdr];
                                    ushort xSize = BitConverter.ToUInt16(block, fHdr + 2);
                                    int fieldPos = dataArea + curOffset;

                                    if (fieldPos + xSize <= absVal + vLen)
                                    {
                                        if (xType == 4) // NAME
                                        {
                                            int nLen = xSize;
                                            while (nLen > 0 && block[fieldPos + nLen - 1] == 0) nLen--;
                                            if (nLen > 0)
                                                inod.NameFromXfields = Encoding.UTF8.GetString(block, fieldPos, nLen);
                                        }
                                        else if (xType == 8 && xSize >= 40) // DSTREAM
                                        {
                                            inod.HasDstream = true;
                                            inod.DstreamSize = BitConverter.ToUInt64(block, fieldPos);
                                        }
                                    }
                                    curOffset += xSize;
                                    curOffset = (curOffset + 7) & ~7;
                                }
                            }
                        }

                        inodes.Add(inod);
                    }
                }
                else if (keyType == 8) // FILE_EXTENT
                {
                    if (kLen >= 16 && vLen >= 24)
                    {
                        var ext = new RawExtent();
                        ext.KeyOid = keyOid;
                        ext.Xid = xid;
                        ext.LogicalOffset = BitConverter.ToUInt64(block, absKey + 8);
                        ulong lenAndFlags = BitConverter.ToUInt64(block, absVal);
                        ext.Length = lenAndFlags & 0x00FFFFFFFFFFFFFFUL;
                        ext.PhysicalBlockNumber = BitConverter.ToUInt64(block, absVal + 8);
                        extents.Add(ext);
                    }
                }
                else if (keyType == 9) // DIR_REC
                {
                    if (kLen >= 10 && vLen >= 18)
                    {
                        var drec = new RawDrec();
                        drec.ParentId = keyOid;
                        drec.Xid = xid;

                        // Check if unhashed (kLen == nameLen + 10) or hashed (kLen == nameLen + 12)
                        ushort nameLen16 = BitConverter.ToUInt16(block, absKey + 8);
                        int nameOffset;
                        int nameLength;

                        if (absKey + 10 + nameLen16 <= absKey + kLen)
                        {
                            nameOffset = absKey + 10;
                            nameLength = nameLen16;
                        }
                        else if (kLen >= 12)
                        {
                            uint nameLen32 = BitConverter.ToUInt32(block, absKey + 8) & 0x03FF;
                            nameOffset = absKey + 12;
                            nameLength = (int)nameLen32;
                        }
                        else
                        {
                            nameOffset = absKey + 10;
                            nameLength = kLen - 10;
                        }

                        while (nameLength > 0 && block[nameOffset + nameLength - 1] == 0) nameLength--;
                        if (nameLength > 0 && nameOffset + nameLength <= blockSize)
                            drec.Name = Encoding.UTF8.GetString(block, nameOffset, nameLength);
                        else
                            drec.Name = "unnamed";

                        drec.FileId = BitConverter.ToUInt64(block, absVal);
                        drec.Flags = BitConverter.ToUInt16(block, absVal + 16);
                        drecs.Add(drec);
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // Fletcher-64 Checksum
        // -------------------------------------------------------------
        public static ulong ComputeFletcher64(byte[] data, int offset, int length)
        {
            if (data == null) throw new ArgumentNullException("data");
            if (offset < 0 || length < 0 || offset + length > data.Length)
                throw new ArgumentOutOfRangeException("offset/length out of bounds.");

            ulong sum1 = 0;
            ulong sum2 = 0;
            int end = offset + (length & ~3);

            for (int i = offset; i < end; i += 4)
            {
                uint word = (uint)(data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24));
                sum1 += word;
                sum2 += sum1;
            }

            const ulong mod = 0xFFFFFFFFUL;
            ulong ckLow = mod - ((sum1 + sum2) % mod);
            ulong ckHigh = mod - ((sum1 + ckLow) % mod);

            return ckLow | (ckHigh << 32);
        }

        private static DateTime? FromUnixNs(ulong ns)
        {
            if (ns == 0) return null;
            try
            {
                long ticks = 621355968000000000L + (long)(ns / 100);
                if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return null;
                return new DateTime(ticks, DateTimeKind.Utc);
            }
            catch
            {
                return null;
            }
        }
    }
}
