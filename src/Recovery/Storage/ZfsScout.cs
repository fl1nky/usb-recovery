using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>
    /// ZFS Storage Pool Metadata Scout and Uberblock Carver.
    /// Locates VDEV labels (0, 1, 2, 3), scans the 128-slot uberblock array (magic 0x00bab10c),
    /// identifies highest-generation transaction groups (TXG), and carves root block pointers and dnodes.
    /// 100% offline, zero network telemetry, strictly deterministic.
    /// </summary>
    public static class ZfsScout
    {
        // Uberblock 64-bit magic: 0x00bab10c (Little-Endian: 0C B1 BA 00 00 00 00 00)
        public const ulong UberblockMagicLe = 0x0000000000bab10cUL;
        public const ulong UberblockMagicBe = 0x0cb1ba0000000000UL;

        // VDEV label offsets
        public const long VdevLabel0Offset = 0;
        public const long VdevLabel1Offset = 256 * 1024; // 256 KiB
        public const long VdevLabelSize = 256 * 1024;    // 256 KiB
        public const long UberblockArrayOffset = 32 * 1024; // offset 32 KiB within each label
        public const int UberblockSlotSize = 1024;       // 1 KiB per slot
        public const int UberblockSlotCount = 128;       // 128 slots = 128 KiB

        public sealed class ZfsUberblock
        {
            public long PhysicalOffset { get; set; }
            public int VdevLabel { get; set; }
            public int SlotIndex { get; set; }
            public ulong Magic { get; set; }
            public ulong Txg { get; set; }
            public ulong GuidSum { get; set; }
            public ulong TimestampUtcSec { get; set; }
            public DateTime TimestampUtc { get; set; }
            public bool IsBigEndian { get; set; }
            public ZfsBlockPointer RootBlockPointer { get; set; }
        }

        public sealed class ZfsBlockPointer
        {
            public ulong DvaVdev { get; set; }
            public ulong DvaSectorOffset { get; set; }
            public long PhysicalByteOffset { get; set; }
            public ulong AllocatedBytes { get; set; }
            public byte CompressionType { get; set; }
            public byte ChecksumType { get; set; }
            public byte ObjectType { get; set; }
            public ulong BirthTxg { get; set; }
            public ulong FillCount { get; set; }
        }

        public sealed class ZfsFileRecord
        {
            public ulong ObjectId { get; set; }
            public ulong ParentObjectId { get; set; }
            public string Name { get; set; }
            public string FullPath { get; set; }
            public ulong FileSizeBytes { get; set; }
            public bool IsDirectory { get; set; }
            public byte ObjectType { get; set; }
            public List<ZfsBlockPointer> BlockExtents { get; set; }

            public ZfsFileRecord()
            {
                BlockExtents = new List<ZfsBlockPointer>();
            }
        }

        public sealed class ZfsScoutResult
        {
            public string Status { get; set; }
            public int LabelsFound { get; set; }
            public int UberblocksFound { get; set; }
            public ZfsUberblock ActiveUberblock { get; set; }
            public List<ZfsUberblock> UberblockHistory { get; set; }
            public List<ZfsFileRecord> Files { get; set; }
            public int DirectoriesCount { get; set; }
            public int FilesCount { get; set; }
            public ulong TotalRecoverableBytes { get; set; }

            public ZfsScoutResult()
            {
                UberblockHistory = new List<ZfsUberblock>();
                Files = new List<ZfsFileRecord>();
            }
        }

        /// <summary>
        /// Probes a stream or image for ZFS VDEV labels and uberblocks.
        /// </summary>
        public static List<ZfsUberblock> ProbeUberblocks(Stream stream)
        {
            if (stream == null || !stream.CanRead) return new List<ZfsUberblock>();
            var results = new List<ZfsUberblock>();
            long origPos = stream.CanSeek ? stream.Position : 0;

            try
            {
                long streamLen = stream.Length;

                // Label 0 (offset 0)
                if (streamLen >= VdevLabelSize)
                {
                    ScanLabelUberblocks(stream, VdevLabel0Offset, 0, results);
                }

                // Label 1 (offset 256 KiB)
                if (streamLen >= VdevLabel1Offset + VdevLabelSize)
                {
                    ScanLabelUberblocks(stream, VdevLabel1Offset, 1, results);
                }

                // Label 2 & 3 at end of stream (if length >= 1 MiB)
                if (streamLen >= 1024 * 1024)
                {
                    long label2Offset = streamLen - 2 * VdevLabelSize;
                    long label3Offset = streamLen - VdevLabelSize;

                    if (label2Offset > VdevLabel1Offset + VdevLabelSize)
                    {
                        ScanLabelUberblocks(stream, label2Offset, 2, results);
                        ScanLabelUberblocks(stream, label3Offset, 3, results);
                    }
                }
            }
            finally
            {
                if (stream.CanSeek) stream.Position = origPos;
            }

            return results;
        }

        private static void ScanLabelUberblocks(Stream stream, long labelBase, int labelIndex, List<ZfsUberblock> results)
        {
            long ubArrayStart = labelBase + UberblockArrayOffset;
            if (ubArrayStart + (UberblockSlotCount * UberblockSlotSize) > stream.Length) return;

            stream.Seek(ubArrayStart, SeekOrigin.Begin);
            byte[] slotBuf = new byte[UberblockSlotSize];

            for (int slot = 0; slot < UberblockSlotCount; slot++)
            {
                int r = stream.Read(slotBuf, 0, slotBuf.Length);
                if (r < slotBuf.Length) break;

                ulong magic = ReadUInt64Le(slotBuf, 0);
                bool isLe = (magic == UberblockMagicLe);
                bool isBe = (magic == UberblockMagicBe);

                if (isLe || isBe)
                {
                    var ub = ParseUberblock(slotBuf, ubArrayStart + (slot * UberblockSlotSize), labelIndex, slot, isBe);
                    if (ub != null)
                    {
                        results.Add(ub);
                    }
                }
            }
        }

        /// <summary>
        /// Parses a 1024-byte ZFS uberblock buffer.
        /// </summary>
        public static ZfsUberblock ParseUberblock(byte[] buf, long physicalOffset, int labelIndex, int slotIndex, bool isBe)
        {
            if (buf == null || buf.Length < 256) return null;

            ulong magic = isBe ? ReadUInt64Be(buf, 0) : ReadUInt64Le(buf, 0);
            if (magic != UberblockMagicLe && magic != 0x00bab10cUL) return null;

            ulong txg = isBe ? ReadUInt64Be(buf, 8) : ReadUInt64Le(buf, 8);
            ulong guidSum = isBe ? ReadUInt64Be(buf, 16) : ReadUInt64Le(buf, 16);
            ulong timestampSec = isBe ? ReadUInt64Be(buf, 24) : ReadUInt64Le(buf, 24);

            DateTime dt = DateTime.MinValue;
            if (timestampSec > 0 && timestampSec < 32503680000UL) // up to year 3000
            {
                try
                {
                    dt = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds((double)timestampSec);
                }
                catch { }
            }

            var ub = new ZfsUberblock
            {
                PhysicalOffset = physicalOffset,
                VdevLabel = labelIndex,
                SlotIndex = slotIndex,
                Magic = magic,
                Txg = txg,
                GuidSum = guidSum,
                TimestampUtcSec = timestampSec,
                TimestampUtc = dt,
                IsBigEndian = isBe
            };

            // Parse Root Block Pointer at offset 32 (128 bytes)
            ub.RootBlockPointer = ParseBlockPointer(buf, 32, isBe);

            return ub;
        }

        /// <summary>
        /// Parses a 128-byte ZFS block pointer (blkptr_t).
        /// </summary>
        public static ZfsBlockPointer ParseBlockPointer(byte[] buf, int offset, bool isBe)
        {
            if (buf == null || offset + 128 > buf.Length) return null;

            // DVA 0:
            // 0..7: [asize:24][grid:8][vdev:32]
            // 8..15: [G:1][offset:63] (in 512-byte sectors)
            ulong dva0_hi = isBe ? ReadUInt64Be(buf, offset) : ReadUInt64Le(buf, offset);
            ulong dva0_lo = isBe ? ReadUInt64Be(buf, offset + 8) : ReadUInt64Le(buf, offset + 8);

            ulong vdev = dva0_hi & 0xFFFFFFFFUL;
            ulong asize = (dva0_hi >> 40) * 512;
            ulong sectorOffset = dva0_lo & 0x7FFFFFFFFFFFFFFFUL;
            long physicalByteOffset = (long)sectorOffset * 512;

            // Props at offset + 48 (uint64)
            ulong props = isBe ? ReadUInt64Be(buf, offset + 48) : ReadUInt64Le(buf, offset + 48);
            byte comp = (byte)((props >> 56) & 0x7F);
            byte chksum = (byte)((props >> 48) & 0xFF);
            byte objType = (byte)((props >> 40) & 0xFF);

            ulong birthTxg = isBe ? ReadUInt64Be(buf, offset + 80) : ReadUInt64Le(buf, offset + 80);
            ulong fillCount = isBe ? ReadUInt64Be(buf, offset + 88) : ReadUInt64Le(buf, offset + 88);

            return new ZfsBlockPointer
            {
                DvaVdev = vdev,
                DvaSectorOffset = sectorOffset,
                PhysicalByteOffset = physicalByteOffset,
                AllocatedBytes = asize,
                CompressionType = comp,
                ChecksumType = chksum,
                ObjectType = objType,
                BirthTxg = birthTxg,
                FillCount = fillCount
            };
        }

        /// <summary>
        /// Scans an image stream, identifies all ZFS uberblocks and reconstructs file/block pointer extents.
        /// </summary>
        public static ZfsScoutResult Scout(Stream stream, CancellationToken cancel, Action<long, long> progress)
        {
            if (stream == null || !stream.CanRead) throw new ArgumentNullException("stream");
            var result = new ZfsScoutResult();

            var uberblocks = ProbeUberblocks(stream);
            if (uberblocks.Count == 0)
            {
                result.Status = "no_zfs_uberblock_found";
                return result;
            }

            result.UberblocksFound = uberblocks.Count;
            result.UberblockHistory = uberblocks;

            // Active uberblock is the one with highest TXG
            ZfsUberblock active = uberblocks[0];
            for (int i = 1; i < uberblocks.Count; i++)
            {
                if (uberblocks[i].Txg > active.Txg)
                {
                    active = uberblocks[i];
                }
            }
            result.ActiveUberblock = active;

            // Scan for dnodes (512-byte structs) across the image
            ScanDnodes(stream, result, cancel, progress);

            result.Status = "complete";
            return result;
        }

        private static void ScanDnodes(Stream stream, ZfsScoutResult result, CancellationToken cancel, Action<long, long> progress)
        {
            long streamLen = stream.Length;
            long pos = 0;
            byte[] block = new byte[128 * 1024]; // 128 KiB buffer
            var files = new Dictionary<ulong, ZfsFileRecord>();

            while (pos + block.Length <= streamLen)
            {
                cancel.ThrowIfCancellationRequested();
                stream.Seek(pos, SeekOrigin.Begin);
                int r = stream.Read(block, 0, block.Length);
                if (r < block.Length) break;

                for (int slot = 0; slot + 512 <= r; slot += 512)
                {
                    byte dnType = block[slot]; // dn_type
                    byte nlevels = block[slot + 3];
                    byte nblkptr = block[slot + 4];
                    ushort datablkszsec = ReadUInt16Le(block, slot + 6);

                    // Check for valid ZFS dnode types:
                    // 19 = DMU_OT_PLAIN_FILE_CONTENTS, 20 = DMU_OT_DIRECTORY_CONTENTS
                    if ((dnType == 19 || dnType == 20) && nblkptr > 0 && nblkptr <= 3 && datablkszsec > 0)
                    {
                        ulong objId = (ulong)((pos + slot) / 512);
                        bool isDir = (dnType == 20);

                        var rec = new ZfsFileRecord
                        {
                            ObjectId = objId,
                            ObjectType = dnType,
                            IsDirectory = isDir,
                            FileSizeBytes = (ulong)datablkszsec * 512
                        };

                        // Extract block pointers in dnode (starting at offset 64, up to nblkptr * 128)
                        for (int bp = 0; bp < nblkptr && 64 + (bp + 1) * 128 <= 512; bp++)
                        {
                            var ptr = ParseBlockPointer(block, slot + 64 + bp * 128, false);
                            if (ptr != null && ptr.PhysicalByteOffset > 0)
                            {
                                rec.BlockExtents.Add(ptr);
                            }
                        }

                        // Check bonus buffer for ZAP name (offset 512 - 320 = 192)
                        int bonusOffset = slot + 192;
                        string possibleName = ExtractZapName(block, bonusOffset, 128);
                        if (!string.IsNullOrEmpty(possibleName))
                        {
                            rec.Name = possibleName;
                        }
                        else
                        {
                            rec.Name = string.Format("zfs_object_{0}", objId);
                        }

                        rec.FullPath = "/" + rec.Name;

                        if (isDir) result.DirectoriesCount++;
                        else
                        {
                            result.FilesCount++;
                            result.TotalRecoverableBytes += rec.FileSizeBytes;
                        }

                        result.Files.Add(rec);
                        if (result.Files.Count >= 10000) return;
                    }
                }

                pos += block.Length;
                if (progress != null && (pos & 0x3FFFFF) == 0)
                {
                    progress(pos, streamLen);
                }
            }
        }

        private static string ExtractZapName(byte[] buf, int offset, int length)
        {
            if (offset + length > buf.Length) return null;
            // Scan for ASCII string in bonus
            for (int i = 0; i < length - 4; i++)
            {
                if (buf[offset + i] >= 0x20 && buf[offset + i] <= 0x7E)
                {
                    int len = 0;
                    while (i + len < length && buf[offset + i + len] >= 0x20 && buf[offset + i + len] <= 0x7E)
                    {
                        len++;
                    }
                    if (len >= 4 && len < 64)
                    {
                        string str = Encoding.ASCII.GetString(buf, offset + i, len);
                        if (str.Contains(".") || str.StartsWith("zfs_") || str.Contains("data"))
                        {
                            return str;
                        }
                    }
                }
            }
            return null;
        }

        // =========================================================================
        // Binary Helpers
        // =========================================================================
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
    }
}
