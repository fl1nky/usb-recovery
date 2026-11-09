using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>
    /// XFS Filesystem Metadata Scout and Extent Traversal Engine.
    /// Discovers Allocation Group (AG) superblocks (XFSB), parses inode records (IN),
    /// extracts extent maps (BMBT), and reconstructs directory structures and file extents.
    /// 100% offline, zero network telemetry, strictly deterministic.
    /// </summary>
    public static class XfsScout
    {
        public static readonly byte[] XfsMagic = new byte[] { 0x58, 0x46, 0x53, 0x42 }; // "XFSB"
        public static readonly byte[] InodeMagic = new byte[] { 0x49, 0x4E }; // "IN"

        public sealed class XfsSuperblock
        {
            public long PhysicalOffset { get; set; }
            public uint AllocationGroup { get; set; }
            public uint BlockSize { get; set; }
            public ulong DataBlocks { get; set; }
            public ulong RealtimeBlocks { get; set; }
            public ulong LogBlocks { get; set; }
            public string FsUuid { get; set; }
            public ulong RootInode { get; set; }
            public uint AgBlocks { get; set; }
            public uint AgCount { get; set; }
            public ushort InodeSize { get; set; }
            public ushort InodesPerBlock { get; set; }
            public string Label { get; set; }
        }

        public sealed class XfsExtent
        {
            public ulong LogicalBlockOffset { get; set; }
            public ulong PhysicalBlockNumber { get; set; }
            public long PhysicalByteOffset { get; set; }
            public ulong BlockCount { get; set; }
            public long LengthBytes { get; set; }
            public bool IsInline { get; set; }
            public byte[] InlineData { get; set; }
        }

        public sealed class XfsFileRecord
        {
            public ulong InodeId { get; set; }
            public ulong ParentInodeId { get; set; }
            public string Name { get; set; }
            public string FullPath { get; set; }
            public long Size { get; set; }
            public ushort Mode { get; set; }
            public uint Nlink { get; set; }
            public bool IsDirectory { get; set; }
            public long ModifiedTimeSec { get; set; }
            public byte Format { get; set; } // 1=local, 2=extents, 3=btree
            public List<XfsExtent> Extents { get; set; }

            public XfsFileRecord()
            {
                Extents = new List<XfsExtent>();
            }
        }

        public sealed class XfsScoutResult
        {
            public string Status { get; set; }
            public List<XfsSuperblock> Superblocks { get; set; }
            public List<XfsFileRecord> Files { get; set; }
            public int DirectoriesCount { get; set; }
            public int FilesCount { get; set; }
            public long TotalRecoverableBytes { get; set; }

            public XfsScoutResult()
            {
                Superblocks = new List<XfsSuperblock>();
                Files = new List<XfsFileRecord>();
            }
        }

        /// <summary>
        /// Probes a stream or image for XFS superblocks.
        /// </summary>
        public static List<XfsSuperblock> ProbeSuperblocks(Stream stream)
        {
            if (stream == null || !stream.CanRead) return new List<XfsSuperblock>();
            var results = new List<XfsSuperblock>();
            long origPos = stream.CanSeek ? stream.Position : 0;

            try
            {
                // Primary SB is at offset 0
                if (stream.Length >= 512)
                {
                    stream.Seek(0, SeekOrigin.Begin);
                    byte[] primaryBuf = new byte[512];
                    int r = stream.Read(primaryBuf, 0, primaryBuf.Length);
                    if (r >= 200 && MatchesPrefix(primaryBuf, XfsMagic))
                    {
                        var primarySb = ParseSuperblock(primaryBuf, 0, 0);
                        if (primarySb != null)
                        {
                            results.Add(primarySb);

                            // Discover secondary AG superblocks
                            if (primarySb.BlockSize > 0 && primarySb.AgBlocks > 0 && primarySb.AgCount > 1)
                            {
                                long agByteSize = (long)primarySb.AgBlocks * primarySb.BlockSize;
                                for (uint ag = 1; ag < primarySb.AgCount && ag < 16; ag++)
                                {
                                    long agOffset = (long)ag * agByteSize;
                                    if (agOffset + 512 > stream.Length) break;

                                    stream.Seek(agOffset, SeekOrigin.Begin);
                                    byte[] agBuf = new byte[512];
                                    if (stream.Read(agBuf, 0, agBuf.Length) >= 200 && MatchesPrefix(agBuf, XfsMagic))
                                    {
                                        var agSb = ParseSuperblock(agBuf, agOffset, ag);
                                        if (agSb != null) results.Add(agSb);
                                    }
                                }
                            }
                        }
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
        /// Parses an XFS superblock buffer (all fields in XFS are Big-Endian!).
        /// </summary>
        public static XfsSuperblock ParseSuperblock(byte[] buf, long physicalOffset, uint agIndex)
        {
            if (buf == null || buf.Length < 200 || !MatchesPrefix(buf, XfsMagic)) return null;

            var sb = new XfsSuperblock();
            sb.PhysicalOffset = physicalOffset;
            sb.AllocationGroup = agIndex;

            sb.BlockSize = ReadUInt32Be(buf, 4);
            sb.DataBlocks = ReadUInt64Be(buf, 8);
            sb.RealtimeBlocks = ReadUInt64Be(buf, 16);
            sb.LogBlocks = ReadUInt64Be(buf, 24);

            // UUID: 16 bytes at offset 32
            var uuidBytes = new byte[16];
            Buffer.BlockCopy(buf, 32, uuidBytes, 0, 16);
            sb.FsUuid = FormatUuid(uuidBytes);

            sb.RootInode = ReadUInt64Be(buf, 56);
            sb.AgBlocks = ReadUInt32Be(buf, 84);
            sb.AgCount = ReadUInt32Be(buf, 88);
            sb.InodeSize = ReadUInt16Be(buf, 104);
            sb.InodesPerBlock = ReadUInt16Be(buf, 106);

            // Label: 12 bytes at offset 108
            int labelLen = 0;
            while (labelLen < 12 && 108 + labelLen < buf.Length && buf[108 + labelLen] != 0)
            {
                labelLen++;
            }
            if (labelLen > 0)
            {
                sb.Label = Encoding.ASCII.GetString(buf, 108, labelLen).Trim();
            }

            return sb;
        }

        /// <summary>
        /// Scans an XFS image stream for inodes, recovers file extents and reconstructs directory graph.
        /// </summary>
        public static XfsScoutResult Scout(Stream stream, CancellationToken cancel, Action<long, long> progress)
        {
            if (stream == null || !stream.CanRead) throw new ArgumentNullException("stream");
            var result = new XfsScoutResult();

            var superblocks = ProbeSuperblocks(stream);
            if (superblocks.Count == 0)
            {
                result.Status = "no_xfs_superblock_found";
                return result;
            }

            result.Superblocks = superblocks;
            XfsSuperblock sb = superblocks[0];
            uint blockSize = sb.BlockSize > 0 ? sb.BlockSize : 4096;
            ushort inodeSize = sb.InodeSize > 0 ? sb.InodeSize : (ushort)256;

            var inodes = new Dictionary<ulong, XfsFileRecord>();
            var dirEntries = new List<XfsDirEntry>();

            long streamLen = stream.Length;
            long pos = 0;
            byte[] blockBuf = new byte[blockSize];

            while (pos + blockSize <= streamLen)
            {
                cancel.ThrowIfCancellationRequested();
                stream.Seek(pos, SeekOrigin.Begin);
                int r = stream.Read(blockBuf, 0, blockBuf.Length);
                if (r < blockBuf.Length) break;

                // Check each inode slot within the block
                for (int slot = 0; slot + inodeSize <= blockSize; slot += inodeSize)
                {
                    // Check inode magic "IN" (0x49 0x4E)
                    if (blockBuf[slot] == 0x49 && blockBuf[slot + 1] == 0x4E)
                    {
                        ParseInode(blockBuf, slot, inodeSize, pos + slot, blockSize, inodes, dirEntries);
                    }
                }

                pos += blockSize;
                if (progress != null && (pos & 0x1FFFFF) == 0)
                {
                    progress(pos, streamLen);
                }
            }

            // Reconstruct path graph
            var nameMap = new Dictionary<ulong, string>();
            var parentMap = new Dictionary<ulong, ulong>();

            foreach (var de in dirEntries)
            {
                if (!nameMap.ContainsKey(de.ChildInode))
                {
                    nameMap[de.ChildInode] = de.Name;
                    parentMap[de.ChildInode] = de.ParentInode;
                }
            }

            ulong rootIno = sb.RootInode > 0 ? sb.RootInode : 128;

            foreach (var kvp in inodes)
            {
                ulong ino = kvp.Key;
                var rec = kvp.Value;

                if (nameMap.ContainsKey(ino))
                {
                    rec.Name = nameMap[ino];
                    rec.ParentInodeId = parentMap[ino];
                }
                else if (string.IsNullOrEmpty(rec.Name))
                {
                    rec.Name = string.Format("inode_{0}", ino);
                }

                rec.FullPath = ResolveFullPath(ino, rootIno, nameMap, parentMap);

                if (rec.IsDirectory)
                {
                    result.DirectoriesCount++;
                }
                else
                {
                    result.FilesCount++;
                    if (rec.Size > 0) result.TotalRecoverableBytes += rec.Size;
                }

                result.Files.Add(rec);
            }

            result.Status = "complete";
            return result;
        }

        private sealed class XfsDirEntry
        {
            public ulong ParentInode;
            public ulong ChildInode;
            public string Name;
        }

        private static void ParseInode(byte[] buf, int slot, int inodeSize, long physicalOffset, uint blockSize,
            Dictionary<ulong, XfsFileRecord> inodes, List<XfsDirEntry> dirEntries)
        {
            // Inode struct (Big-Endian):
            // 0: magic 'IN' (2 bytes)
            // 2: di_mode (uint16)
            // 4: di_version (int8)
            // 5: di_format (int8): 1=local, 2=extents, 3=btree
            // 8: di_size (int64)
            // 16: di_nblocks (int64)
            // 24: di_extsize (uint32)
            // 28: di_nextents (uint32)
            // 32: di_anextents (uint16)
            // 34: di_forkoff (uint8)
            // 35: di_aformat (int8)
            // 36: di_dmevmask (uint32)
            // 40: di_dmstate (uint16)
            // 42: di_flags (uint16)
            // 44: di_gen (uint32)
            // 48: di_next_unlinked (uint32)
            // 100: header size (core inode = 100 or 176 bytes depending on version)

            ushort mode = ReadUInt16Be(buf, slot + 2);
            byte version = buf[slot + 4];
            byte format = buf[slot + 5];
            long size = (long)ReadUInt64Be(buf, slot + 8);
            uint nlink = ReadUInt32Be(buf, slot + 16);
            uint nextents = ReadUInt32Be(buf, slot + 28);

            // Compute synthetic or actual inode number from physical offset
            ulong inodeNum = (ulong)(physicalOffset / inodeSize);

            bool isDir = (mode & 0x4000) != 0; // S_IFDIR
            bool isReg = (mode & 0x8000) != 0; // S_IFREG

            if (!isDir && !isReg) return; // ignore unused/special

            var rec = new XfsFileRecord
            {
                InodeId = inodeNum,
                Mode = mode,
                Format = format,
                Size = size,
                Nlink = nlink,
                IsDirectory = isDir
            };

            int coreHeaderSize = (version == 3) ? 176 : 100;
            int dataStart = slot + coreHeaderSize;
            int dataLen = inodeSize - coreHeaderSize;

            if (dataStart + dataLen <= slot + inodeSize)
            {
                // Format 1: Local / Inline
                if (format == 1)
                {
                    if (isDir)
                    {
                        // Parse shortform directory entries
                        ParseShortformDir(buf, dataStart, dataLen, inodeNum, dirEntries);
                    }
                    else if (isReg && size > 0 && size <= dataLen)
                    {
                        var ext = new XfsExtent
                        {
                            IsInline = true,
                            LengthBytes = size,
                            InlineData = new byte[size]
                        };
                        Buffer.BlockCopy(buf, dataStart, ext.InlineData, 0, (int)size);
                        rec.Extents.Add(ext);
                    }
                }
                // Format 2: Extents (Array of 128-bit descriptors)
                else if (format == 2 && nextents > 0 && nextents < 1000)
                {
                    for (uint e = 0; e < nextents && dataStart + (e + 1) * 16 <= slot + inodeSize; e++)
                    {
                        int ep = dataStart + (int)(e * 16);
                        ulong hi = ReadUInt64Be(buf, ep);
                        ulong lo = ReadUInt64Be(buf, ep + 8);

                        // 128-bit packed extent descriptor:
                        // state: 1 bit (hi >> 63)
                        // startoff: 54 bits ((hi >> 9) & 0x3FFFFFFFFFFFFF)
                        // startblock: 52 bits (((hi & 0x1FF) << 43) | (lo >> 21))
                        // blockcount: 21 bits (lo & 0x1FFFFF)
                        ulong startOff = (hi >> 9) & 0x3FFFFFFFFFFFFFL;
                        ulong startBlock = ((hi & 0x1FFL) << 43) | (lo >> 21);
                        ulong blockCount = lo & 0x1FFFFFL;

                        if (blockCount > 0)
                        {
                            var ext = new XfsExtent
                            {
                                LogicalBlockOffset = startOff,
                                PhysicalBlockNumber = startBlock,
                                PhysicalByteOffset = (long)startBlock * blockSize,
                                BlockCount = blockCount,
                                LengthBytes = (long)blockCount * blockSize
                            };
                            rec.Extents.Add(ext);
                        }
                    }
                }
            }

            inodes[inodeNum] = rec;
        }

        private static void ParseShortformDir(byte[] buf, int offset, int length, ulong parentInode, List<XfsDirEntry> dirEntries)
        {
            // Shortform dir header:
            // 0: count (uint8)
            // 1: i8count (uint8) - count of 8-byte inodes
            // 2..5 or 2..9: parent inode
            if (length < 6) return;
            byte count = buf[offset];
            byte i8count = buf[offset + 1];

            int parentInoSize = (i8count > 0) ? 8 : 4;
            int cur = offset + 2 + parentInoSize;

            for (int i = 0; i < count && cur + 3 <= offset + length; i++)
            {
                byte nameLen = buf[cur];
                cur += 3; // namelen + offset (uint16)

                if (cur + nameLen + parentInoSize > offset + length) break;
                string name = Encoding.UTF8.GetString(buf, cur, nameLen);
                cur += nameLen;

                ulong childIno;
                if (parentInoSize == 8)
                {
                    childIno = ReadUInt64Be(buf, cur);
                    cur += 8;
                }
                else
                {
                    childIno = ReadUInt32Be(buf, cur);
                    cur += 4;
                }

                if (!string.IsNullOrEmpty(name) && name != "." && name != "..")
                {
                    dirEntries.Add(new XfsDirEntry
                    {
                        ParentInode = parentInode,
                        ChildInode = childIno,
                        Name = name
                    });
                }
            }
        }

        private static string ResolveFullPath(ulong inodeNum, ulong rootInode, Dictionary<ulong, string> names, Dictionary<ulong, ulong> parents)
        {
            if (inodeNum == rootInode) return "/";
            var parts = new List<string>();
            var visited = new HashSet<ulong>();
            ulong cur = inodeNum;

            while (cur != rootInode && !visited.Contains(cur))
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
        private static bool MatchesPrefix(byte[] data, byte[] prefix)
        {
            if (data == null || prefix == null || data.Length < prefix.Length) return false;
            for (int i = 0; i < prefix.Length; i++)
            {
                if (data[i] != prefix[i]) return false;
            }
            return true;
        }

        private static ushort ReadUInt16Be(byte[] b, int offset)
        {
            return (ushort)((b[offset] << 8) | b[offset + 1]);
        }

        private static uint ReadUInt32Be(byte[] b, int offset)
        {
            return (uint)((b[offset] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | b[offset + 3]);
        }

        private static ulong ReadUInt64Be(byte[] b, int offset)
        {
            uint hi = ReadUInt32Be(b, offset);
            uint lo = ReadUInt32Be(b, offset + 4);
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
