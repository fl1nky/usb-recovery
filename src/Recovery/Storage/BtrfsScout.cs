using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>
    /// Btrfs (B-tree Filesystem) Metadata Scout and File Extent Recovery Engine.
    /// Discovers primary and backup superblocks (_BHRfS_M), parses system chunk mappings,
    /// traverses tree leaves, and reconstructs directory hierarchies and file extents.
    /// 100% offline, zero network telemetry, strictly deterministic.
    /// </summary>
    public static class BtrfsScout
    {
        public static readonly byte[] BtrfsMagic = Encoding.ASCII.GetBytes("_BHRfS_M"); // 5F 42 48 52 66 53 5F 4D

        // Standard superblock physical offsets
        public static readonly long[] SuperblockOffsets = new long[]
        {
            0x10000L,        // 64 KiB  (Primary)
            0x4000000L,      // 64 MiB  (Mirror 1)
            0x4000000000L    // 256 GiB (Mirror 2)
        };

        public const ushort KeyTypeInodeItem = 1;
        public const ushort KeyTypeInodeRef = 12;
        public const ushort KeyTypeDirItem = 84;   // 0x54
        public const ushort KeyTypeDirIndex = 96;  // 0x60
        public const ushort KeyTypeExtentData = 108; // 0x6C

        public sealed class BtrfsSuperblock
        {
            public long PhysicalOffset { get; set; }
            public string FsUuid { get; set; }
            public ulong Generation { get; set; }
            public ulong RootTreeLogical { get; set; }
            public ulong ChunkTreeLogical { get; set; }
            public ulong TotalBytes { get; set; }
            public ulong BytesUsed { get; set; }
            public ulong RootDirObjectId { get; set; }
            public uint SectorSize { get; set; }
            public uint NodeSize { get; set; }
            public uint LeafSize { get; set; }
            public uint Stripesize { get; set; }
            public string Label { get; set; }
            public List<ChunkMapping> SystemChunks { get; set; }

            public BtrfsSuperblock()
            {
                SystemChunks = new List<ChunkMapping>();
            }
        }

        public sealed class ChunkMapping
        {
            public ulong LogicalAddress { get; set; }
            public ulong Length { get; set; }
            public ulong PhysicalOffset { get; set; }
            public ulong StripeLength { get; set; }
            public ulong Type { get; set; }
            public ushort NumStripes { get; set; }
        }

        public sealed class BtrfsExtent
        {
            public ulong LogicalOffset { get; set; }
            public ulong DiskByteNr { get; set; }
            public ulong PhysicalOffset { get; set; }
            public ulong Length { get; set; }
            public bool IsInline { get; set; }
            public byte[] InlineData { get; set; }
        }

        public sealed class BtrfsFileRecord
        {
            public ulong InodeId { get; set; }
            public ulong ParentInodeId { get; set; }
            public string Name { get; set; }
            public string FullPath { get; set; }
            public ulong Size { get; set; }
            public uint Mode { get; set; }
            public bool IsDirectory { get; set; }
            public long ModifiedTimeUtcSeconds { get; set; }
            public List<BtrfsExtent> Extents { get; set; }

            public BtrfsFileRecord()
            {
                Extents = new List<BtrfsExtent>();
            }
        }

        public sealed class BtrfsScoutResult
        {
            public string Status { get; set; }
            public List<BtrfsSuperblock> Superblocks { get; set; }
            public List<ChunkMapping> ChunkTable { get; set; }
            public List<BtrfsFileRecord> Files { get; set; }
            public int DirectoriesCount { get; set; }
            public int FilesCount { get; set; }
            public ulong TotalRecoverableBytes { get; set; }

            public BtrfsScoutResult()
            {
                Superblocks = new List<BtrfsSuperblock>();
                ChunkTable = new List<ChunkMapping>();
                Files = new List<BtrfsFileRecord>();
            }
        }

        /// <summary>
        /// Probes a stream or image for Btrfs superblocks.
        /// </summary>
        public static List<BtrfsSuperblock> ProbeSuperblocks(Stream stream)
        {
            if (stream == null || !stream.CanRead) return new List<BtrfsSuperblock>();
            var results = new List<BtrfsSuperblock>();
            long origPos = stream.CanSeek ? stream.Position : 0;

            try
            {
                foreach (long offset in SuperblockOffsets)
                {
                    if (offset + 4096 > stream.Length) continue;
                    stream.Seek(offset, SeekOrigin.Begin);
                    byte[] sbBuf = new byte[4096];
                    int r = stream.Read(sbBuf, 0, sbBuf.Length);
                    if (r < 2048) continue;

                    // Magic at offset 0x40 (64)
                    if (MatchesAt(sbBuf, 0x40, BtrfsMagic))
                    {
                        var sb = ParseSuperblock(sbBuf, offset);
                        if (sb != null) results.Add(sb);
                    }
                }
            }
            finally
            {
                if (stream.CanSeek) stream.Position = origPos;
            }

            return results;
        }

        /// <summary>
        /// Parses a Btrfs superblock buffer.
        /// </summary>
        public static BtrfsSuperblock ParseSuperblock(byte[] buf, long physicalOffset)
        {
            if (buf == null || buf.Length < 0x200 || !MatchesAt(buf, 0x40, BtrfsMagic)) return null;

            var sb = new BtrfsSuperblock();
            sb.PhysicalOffset = physicalOffset;

            // UUID: 16 bytes at offset 0x20
            var uuidBytes = new byte[16];
            Buffer.BlockCopy(buf, 0x20, uuidBytes, 0, 16);
            sb.FsUuid = FormatUuid(uuidBytes);

            sb.Generation = ReadUInt64Le(buf, 0x48);
            sb.RootTreeLogical = ReadUInt64Le(buf, 0x50);
            sb.ChunkTreeLogical = ReadUInt64Le(buf, 0x58);
            sb.TotalBytes = ReadUInt64Le(buf, 0x68);
            sb.BytesUsed = ReadUInt64Le(buf, 0x70);
            sb.RootDirObjectId = ReadUInt64Le(buf, 0x78);
            sb.SectorSize = ReadUInt32Le(buf, 0x88);
            sb.NodeSize = ReadUInt32Le(buf, 0x8C);
            sb.LeafSize = ReadUInt32Le(buf, 0x90);
            sb.Stripesize = ReadUInt32Le(buf, 0x94);

            uint sysChunkArraySize = ReadUInt32Le(buf, 0x98);

            // Label: 256 bytes null-terminated at offset 0x12A (298)
            int labelLen = 0;
            while (labelLen < 256 && 0x12A + labelLen < buf.Length && buf[0x12A + labelLen] != 0)
            {
                labelLen++;
            }
            if (labelLen > 0)
            {
                sb.Label = Encoding.UTF8.GetString(buf, 0x12A, labelLen).Trim();
            }

            // System chunk array at offset 0x1A4 (420) or 0x1C1 depending on version
            // In standard btrfs, sys_chunks starts at offset 0x1A4 or 0x1B8. We locate chunk keys.
            ParseSysChunkArray(buf, 0x1A4, (int)sysChunkArraySize, sb.SystemChunks);

            return sb;
        }

        private static void ParseSysChunkArray(byte[] buf, int offset, int size, List<ChunkMapping> mappings)
        {
            if (offset + size > buf.Length || size <= 0) return;
            int cur = offset;
            int end = offset + size;

            while (cur + 17 + 48 <= end) // btrfs_key (17) + btrfs_chunk (min 48)
            {
                ulong keyObjId = ReadUInt64Le(buf, cur);
                byte keyType = buf[cur + 8];
                ulong keyOffset = ReadUInt64Le(buf, cur + 9);
                cur += 17;

                if (keyType == 228) // BTRFS_CHUNK_ITEM_KEY (0xE4 = 228)
                {
                    ulong chunkLen = ReadUInt64Le(buf, cur);
                    ulong chunkOwner = ReadUInt64Le(buf, cur + 8);
                    ulong stripeLen = ReadUInt64Le(buf, cur + 16);
                    ulong chunkType = ReadUInt64Le(buf, cur + 24);
                    ushort numStripes = ReadUInt16Le(buf, cur + 44);
                    cur += 48; // base chunk struct size

                    if (numStripes > 0 && cur + 32 <= end)
                    {
                        ulong devId = ReadUInt64Le(buf, cur);
                        ulong stripeOffset = ReadUInt64Le(buf, cur + 8);
                        cur += numStripes * 32;

                        mappings.Add(new ChunkMapping
                        {
                            LogicalAddress = keyOffset,
                            Length = chunkLen,
                            PhysicalOffset = stripeOffset,
                            StripeLength = stripeLen,
                            Type = chunkType,
                            NumStripes = numStripes
                        });
                    }
                }
                else
                {
                    cur++; // advance to next candidate
                }
            }
        }

        /// <summary>
        /// Translates a logical Btrfs address to physical disk offset using the chunk table.
        /// </summary>
        public static long LogicalToPhysical(ulong logicalAddr, List<ChunkMapping> chunkTable)
        {
            if (chunkTable == null) return -1;
            for (int i = 0; i < chunkTable.Count; i++)
            {
                var chunk = chunkTable[i];
                if (logicalAddr >= chunk.LogicalAddress && logicalAddr < chunk.LogicalAddress + chunk.Length)
                {
                    ulong offsetInChunk = logicalAddr - chunk.LogicalAddress;
                    return (long)(chunk.PhysicalOffset + offsetInChunk);
                }
            }
            return -1;
        }

        /// <summary>
        /// Scans an image stream, extracts Btrfs metadata, and recovers file records.
        /// </summary>
        public static BtrfsScoutResult Scout(Stream stream, CancellationToken cancel, Action<long, long> progress)
        {
            if (stream == null || !stream.CanRead) throw new ArgumentNullException("stream");
            var result = new BtrfsScoutResult();

            // 1. Probe superblocks
            var superblocks = ProbeSuperblocks(stream);
            if (superblocks.Count == 0)
            {
                result.Status = "no_superblock_found";
                return result;
            }

            result.Superblocks = superblocks;
            // Select newest superblock by generation
            BtrfsSuperblock activeSb = superblocks[0];
            for (int i = 1; i < superblocks.Count; i++)
            {
                if (superblocks[i].Generation > activeSb.Generation)
                {
                    activeSb = superblocks[i];
                }
            }

            result.ChunkTable = activeSb.SystemChunks;

            // 2. Scan leaves for Inodes, Dir items, and Extent data
            var inodes = new Dictionary<ulong, BtrfsFileRecord>();
            var dirEntries = new List<DirEntry>();

            byte[] leafBuf = new byte[activeSb.NodeSize > 0 ? activeSb.NodeSize : 16384];
            long streamLen = stream.Length;
            long pos = 0;

            // Step through 4KiB or NodeSize boundaries
            long step = activeSb.SectorSize > 0 ? activeSb.SectorSize : 4096;

            while (pos + leafBuf.Length <= streamLen)
            {
                cancel.ThrowIfCancellationRequested();
                stream.Seek(pos, SeekOrigin.Begin);
                int r = stream.Read(leafBuf, 0, leafBuf.Length);
                if (r < leafBuf.Length) break;

                // Validate btrfs header
                // Byte 0x20 (32): bytenr (8 bytes)
                // Byte 0x64 (100): level (1 byte). 0 = leaf.
                // Byte 0x60 (96): nritems (4 bytes).
                if (r >= 101)
                {
                    byte level = leafBuf[100];
                    uint nritems = ReadUInt32Le(leafBuf, 96);
                    ulong headerOwner = ReadUInt64Le(leafBuf, 88);

                    // Check if it's a valid leaf with reasonable items
                    if (level == 0 && nritems > 0 && nritems < 2000)
                    {
                        ParseLeaf(leafBuf, nritems, inodes, dirEntries, result.ChunkTable);
                    }
                }

                pos += step;
                if (progress != null && (pos & 0x1FFFFF) == 0)
                {
                    progress(pos, streamLen);
                }
            }

            // 3. Link directory hierarchy
            var parentMap = new Dictionary<ulong, ulong>();
            var nameMap = new Dictionary<ulong, string>();

            foreach (var de in dirEntries)
            {
                if (!nameMap.ContainsKey(de.ChildInodeId))
                {
                    nameMap[de.ChildInodeId] = de.Name;
                    parentMap[de.ChildInodeId] = de.ParentInodeId;
                }
            }

            // Assign names and resolve full paths
            foreach (var kvp in inodes)
            {
                ulong inodeId = kvp.Key;
                var record = kvp.Value;

                if (nameMap.ContainsKey(inodeId))
                {
                    record.Name = nameMap[inodeId];
                    record.ParentInodeId = parentMap[inodeId];
                }
                else if (string.IsNullOrEmpty(record.Name))
                {
                    record.Name = string.Format("inode_{0}", inodeId);
                }

                // Resolve path up to root (inode 256)
                record.FullPath = ResolveFullPath(inodeId, nameMap, parentMap);

                if (record.IsDirectory) result.DirectoriesCount++;
                else
                {
                    result.FilesCount++;
                    result.TotalRecoverableBytes += record.Size;
                }

                result.Files.Add(record);
            }

            result.Status = "complete";
            return result;
        }

        private sealed class DirEntry
        {
            public ulong ParentInodeId;
            public ulong ChildInodeId;
            public string Name;
            public byte Type;
        }

        private static void ParseLeaf(byte[] leaf, uint nritems, Dictionary<ulong, BtrfsFileRecord> inodes, List<DirEntry> dirEntries, List<ChunkMapping> chunkTable)
        {
            int headerSize = 101;
            int itemHeaderSize = 25; // 17 bytes key + 4 bytes offset + 4 bytes size

            if (headerSize + nritems * itemHeaderSize > leaf.Length) return;

            for (uint i = 0; i < nritems; i++)
            {
                int itemPos = headerSize + (int)(i * itemHeaderSize);
                ulong objId = ReadUInt64Le(leaf, itemPos);
                byte keyType = leaf[itemPos + 8];
                ulong keyOffset = ReadUInt64Le(leaf, itemPos + 9);
                uint dataOffsetRel = ReadUInt32Le(leaf, itemPos + 17);
                uint dataSize = ReadUInt32Le(leaf, itemPos + 21);

                int absDataPos = headerSize + (int)dataOffsetRel;
                if (absDataPos < 0 || absDataPos + dataSize > leaf.Length) continue;

                // 1. INODE_ITEM (Type 1)
                if (keyType == KeyTypeInodeItem && dataSize >= 160)
                {
                    ulong gen = ReadUInt64Le(leaf, absDataPos);
                    ulong size = ReadUInt64Le(leaf, absDataPos + 16);
                    uint mode = ReadUInt32Le(leaf, absDataPos + 40);
                    long mtimeSec = (long)ReadUInt64Le(leaf, absDataPos + 112);

                    BtrfsFileRecord rec;
                    if (!inodes.TryGetValue(objId, out rec))
                    {
                        rec = new BtrfsFileRecord { InodeId = objId };
                        inodes[objId] = rec;
                    }
                    rec.Size = size;
                    rec.Mode = mode;
                    rec.IsDirectory = (mode & 0x4000) != 0; // S_IFDIR
                    rec.ModifiedTimeUtcSeconds = mtimeSec;
                }
                // 2. DIR_ITEM (Type 84) or DIR_INDEX (Type 96)
                else if ((keyType == KeyTypeDirItem || keyType == KeyTypeDirIndex) && dataSize >= 30)
                {
                    // Location key (17 bytes): objId, type, offset
                    ulong childObjId = ReadUInt64Le(leaf, absDataPos);
                    byte childType = leaf[absDataPos + 8];
                    ushort dataLen = ReadUInt16Le(leaf, absDataPos + 17 + 8);
                    ushort nameLen = ReadUInt16Le(leaf, absDataPos + 17 + 10);
                    byte dirType = leaf[absDataPos + 17 + 12];

                    if (absDataPos + 30 + nameLen <= leaf.Length && nameLen > 0 && nameLen < 256)
                    {
                        string name = Encoding.UTF8.GetString(leaf, absDataPos + 30, nameLen);
                        dirEntries.Add(new DirEntry
                        {
                            ParentInodeId = objId,
                            ChildInodeId = childObjId,
                            Name = name,
                            Type = dirType
                        });
                    }
                }
                // 3. EXTENT_DATA (Type 108)
                else if (keyType == KeyTypeExtentData && dataSize >= 21)
                {
                    byte extentType = leaf[absDataPos + 20]; // 0=inline, 1=regular, 2=prealloc
                    var ext = new BtrfsExtent { LogicalOffset = keyOffset };

                    if (extentType == 0) // Inline
                    {
                        ext.IsInline = true;
                        int inlineLen = (int)dataSize - 21;
                        if (inlineLen > 0)
                        {
                            ext.InlineData = new byte[inlineLen];
                            Buffer.BlockCopy(leaf, absDataPos + 21, ext.InlineData, 0, inlineLen);
                            ext.Length = (ulong)inlineLen;
                        }
                    }
                    else if (extentType == 1 && dataSize >= 53) // Regular
                    {
                        ulong diskByteNr = ReadUInt64Le(leaf, absDataPos + 21);
                        ulong diskNumBytes = ReadUInt64Le(leaf, absDataPos + 29);
                        ulong extentOffset = ReadUInt64Le(leaf, absDataPos + 37);
                        ulong numBytes = ReadUInt64Le(leaf, absDataPos + 45);

                        ext.DiskByteNr = diskByteNr;
                        ext.Length = numBytes;

                        long phys = LogicalToPhysical(diskByteNr, chunkTable);
                        if (phys >= 0) ext.PhysicalOffset = (ulong)phys + extentOffset;
                    }

                    BtrfsFileRecord rec;
                    if (!inodes.TryGetValue(objId, out rec))
                    {
                        rec = new BtrfsFileRecord { InodeId = objId };
                        inodes[objId] = rec;
                    }
                    rec.Extents.Add(ext);
                }
            }
        }

        private static string ResolveFullPath(ulong inodeId, Dictionary<ulong, string> names, Dictionary<ulong, ulong> parents)
        {
            if (inodeId == 256) return "/"; // Btrfs root dir inode
            var parts = new List<string>();
            var visited = new HashSet<ulong>();
            ulong cur = inodeId;

            while (cur != 256 && !visited.Contains(cur))
            {
                visited.Add(cur);
                if (names.ContainsKey(cur))
                {
                    parts.Insert(0, names[cur]);
                }
                else
                {
                    parts.Insert(0, string.Format("inode_{0}", cur));
                }

                if (parents.ContainsKey(cur))
                {
                    cur = parents[cur];
                }
                else
                {
                    break;
                }
            }

            return "/" + string.Join("/", parts.ToArray());
        }

        // =========================================================================
        // Binary Helpers
        // =========================================================================
        private static bool MatchesAt(byte[] data, int offset, byte[] target)
        {
            if (data == null || target == null || offset < 0 || offset + target.Length > data.Length) return false;
            for (int i = 0; i < target.Length; i++)
            {
                if (data[offset + i] != target[i]) return false;
            }
            return true;
        }

        private static ushort ReadUInt16Le(byte[] b, int offset)
        {
            return (ushort)(b[offset] | (b[offset + 1] << 8));
        }

        private static uint ReadUInt32Le(byte[] b, int offset)
        {
            return (uint)(b[offset] | (b[offset + 1] << 8) | (b[offset + 2] << 16) | (b[offset + 3] << 24));
        }

        private static ulong ReadUInt64Le(byte[] b, int offset)
        {
            uint lo = ReadUInt32Le(b, offset);
            uint hi = ReadUInt32Le(b, offset + 4);
            return ((ulong)hi << 32) | lo;
        }

        private static string FormatUuid(byte[] uuid)
        {
            if (uuid == null || uuid.Length != 16) return "";
            var sb = new StringBuilder(36);
            for (int i = 0; i < 16; i++)
            {
                if (i == 4 || i == 6 || i == 8 || i == 10) sb.Append('-');
                sb.Append(uuid[i].ToString("x2"));
            }
            return sb.ToString();
        }
    }
}
