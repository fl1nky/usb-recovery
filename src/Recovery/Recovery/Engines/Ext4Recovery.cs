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
    // Read-only ext filesystem metadata salvage. Checksums authenticate metadata
    // consistency, never the historical contents of a deleted file's blocks.
    // On-disk definitions: kernel.org/doc/html/latest/filesystems/ext4/ and
    // e2fsprogs lib/ext2fs/csum.c. Journal replay is an in-memory overlay only.
    public static class Ext4Recovery
    {
        public sealed class Limits
        {
            public int MaximumVolumes = 32, MaximumGroups = 65536, MaximumInodes = 1000000;
            public int MaximumCandidates = 10000, MaximumExtents = 100000, MaximumTreeBlocks = 4096;
            public int MaximumDirectories = 20000, MaximumNames = 100000;
            public int MaximumJournalBlocks = 262144;
            public long MaximumJournalBytes = 256L * 1024 * 1024;
            public long MaximumDirectoryBytes = 256L * 1024 * 1024;
            public long MaximumFileBytes = 2L * 1024 * 1024 * 1024, MaximumOutputBytes = 32L * 1024 * 1024 * 1024;
        }
        public sealed class Extent { public long ImageOffset, LogicalOffset, Length; }
        public sealed class NameLink
        {
            public uint DirectoryInode, TargetInode;
            public long EntryOffset;
            public string Name, DirectoryPath, Status = "validated_directory_reference_no_inode_generation";
            public bool DirectoryChecksumVerified;
        }
        public sealed class Entry
        {
            public long VolumeOffset, InodeOffset, DeclaredSize, RecoveredBytes;
            public uint Inode, Generation, DeletionTime;
            public string Status, Reason, Output, Sha256, Mapping, AllocationStatus, ContentTypeHint;
            public string MappingIntegrity;
            public bool InodeChecksumVerified, ContentAuthenticityVerified;
            public string DeletionEvidence = "free_inode_bitmap_and_zero_links_and_nonzero_dtime";
            public string Note = "Сохранившаяся карта удалённого inode. Свободные блоки могли быть перезаписаны до снимка; контрольной суммы исходного содержимого в ext4 нет.";
            public List<Extent> Extents = new List<Extent>();
            public List<NameLink> Names = new List<NameLink>();
        }
        public sealed class VolumeReport
        {
            public long Offset, Bytes;
            public int BlockBytes, InodeBytes, Groups, CheckedGroups, CheckedInodes, LiveInodes;
            public bool MetadataChecksums, GroupChecksums;
            public string Uuid, Status, Reason;
            public List<string> UnsupportedFeatures = new List<string>();
            public List<string> HandledFeatures = new List<string>();
            public bool JournalReplayAttempted, JournalReplayApplied;
            public int JournalHistoricalInodesFound;
            public string JournalStatus;
        }
        public sealed class Report
        {
            public int Schema = 1, Candidates, RecoveredFiles;
            public long InputBytes, OutputBytes;
            public bool Cancelled, Limited, Failed, SourceUnchanged;
            public string Method = "ext4_retained_deleted_inode", Status, SourceSha256;
            public List<VolumeReport> Volumes = new List<VolumeReport>();
            public List<Entry> Entries = new List<Entry>();
            public Dictionary<string, int> Skipped = new Dictionary<string, int>();
            public List<string> Warnings = new List<string>();
        }
        sealed class Group
        {
            public uint Number;
            public ulong BlockBitmap, InodeBitmap, InodeTable;
            public ushort Flags;
            public byte[] Descriptor, Inodes, Blocks;
            public bool Valid, InodeMapValid, BlockMapValid;
        }
        sealed class Volume
        {
            public VolumeReport Report;
            public long Offset;
            public int BlockBytes, InodeBytes, DescriptorBytes;
            public uint Inodes, InodesPerGroup, BlocksPerGroup, FirstData, FirstInode, Seed, Incompat, RoCompat, Compat;
            public ulong Blocks;
            public bool Csum, GdtCsum;
            public byte[] Uuid;
            public List<Group> Groups = new List<Group>();
            public List<Range> Reserved = new List<Range>();
            public Dictionary<ulong, byte[]> Overlay = new Dictionary<ulong, byte[]>();
            public bool JournalReplayAttempted, JournalReplayApplied;
            public byte[] Superblock;
            public JournalContext Journal;
            public bool JournalLoaded;
        }
        struct JournalTag
        {
            public ulong DestinationBlock;
            public uint Flags;
            public uint Checksum;
        }
        sealed class JournalTransaction
        {
            public uint Sequence;
            public List<Tuple<JournalTag, ulong>> DataBlocks = new List<Tuple<JournalTag, ulong>>();
            public List<ulong> RevokedBlocks = new List<ulong>();
            public HashSet<uint> HeaderBlocks = new HashSet<uint>();
            public bool Committed;
        }
        sealed class JournalContext
        {
            public Volume Volume;
            public List<ulong> Blocks = new List<ulong>();
            public uint BlockBytes, MaxLen, First, Sequence, Start, Incompat, Seed;
            public bool HasCsumV1, HasCsumV2, HasCsumV3, Is64Bit;
            public byte[] Uuid;
        }
        sealed class HistoricalCandidate
        {
            public uint Number;
            public uint TransactionSeq;
            public ulong JournalBlock;
            public ulong TargetDiskBlock;
            public int OffsetInBlock;
            public ushort Mode;
            public ushort Links;
            public uint Dtime;
            public uint Flags;
            public uint Generation;
            public ulong Size;
            public byte[] InodeBytes;
        }
        sealed class Range { public ulong Start, Length; }
        sealed class MetadataArea { public Group Owner; public ulong Start, Length; }
        sealed class Inode
        {
            public uint Number, Generation, Flags, Dtime;
            public ushort Mode, Links;
            public long Offset;
            public ulong Size;
            public bool Allocated;
            public byte[] Bytes;
        }
        sealed class Mapping
        {
            public List<BlockRun> Runs = new List<BlockRun>();
            public HashSet<ulong> TreeBlocks = new HashSet<ulong>();
            public string Failure, Kind;
        }
        sealed class BlockRun { public ulong Logical, Physical, Count; public bool Unwritten; }
        sealed class Context
        {
            public FileStream Input;
            public string Root;
            public CancellationToken Cancel;
            public Limits Limits;
            public Report Report;
            public int InodesRead, DirectoryCount, NameCount;
            public long DirectoryBytes;
        }
        static readonly Encoding Utf8 = new UTF8Encoding(false, true);
        static readonly uint[] CrcTable = MakeCrcTable();

        public static int Recover(string image, string runDirectory, CancellationToken cancel,
            Action<string> progress, IEnumerable<long> offsets = null, Limits limits = null)
        {
            cancel.ThrowIfCancellationRequested();
            string source = LocalFile(image), root = Path.GetFullPath(Path.Combine(runDirectory, "ext4"));
            NoLinks(root);
            if (source.Equals(root, StringComparison.OrdinalIgnoreCase) || source.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Источник находится в папке результатов ext4");
            if (Directory.Exists(root) || File.Exists(root)) throw new IOException("Папка результатов ext4 уже существует");
            limits = limits ?? new Limits();
            if (limits.MaximumVolumes < 1 || limits.MaximumGroups < 1 || limits.MaximumInodes < 1 || limits.MaximumCandidates < 1 ||
                limits.MaximumExtents < 1 || limits.MaximumTreeBlocks < 1 || limits.MaximumFileBytes < 1 || limits.MaximumOutputBytes < 1 ||
                limits.MaximumDirectories < 1 || limits.MaximumNames < 1 || limits.MaximumDirectoryBytes < 1 ||
                limits.MaximumJournalBlocks < 1 || limits.MaximumJournalBytes < 1)
                throw new ArgumentException("Неверные ограничения ext4");
            Directory.CreateDirectory(Path.Combine(root, "files"));
            var report = new Report { Status = "running" };
            report.Warnings.Add("Восстанавливаются удалённые inode с полной инициализированной картой, включая зафиксированные транзакции JBD2. Replay выполняется только в памяти. Sparse/unwritten, inline data, fscrypt, bigalloc, meta_bg и fast commit не подменяются исходными байтами.");
            report.Warnings.Add("Проверенные CRC метаданных и свободный bitmap не доказывают сохранность старого содержимого. Имена — ссылки текущего проверенного каталога; ext4 dirent не содержит generation inode.");
            try {
                using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024)) {
                    var c = new Context { Input = input, Root = root, Cancel = cancel, Limits = limits, Report = report };
                    report.InputBytes = input.Length;
                    report.SourceSha256 = HashStream(input, cancel);
                    var locations = offsets == null ? Discover(input) : offsets.Distinct().ToList();
                    foreach (long offset in locations) {
                        cancel.ThrowIfCancellationRequested();
                        if (report.Volumes.Count >= limits.MaximumVolumes) { report.Limited = true; Skip(c, "volume_limit"); break; }
                        if (offset < 0 || (offset & 511) != 0 || offset > input.Length - 2048) { Skip(c, "invalid_partition_offset"); continue; }
                        Volume volume = OpenVolume(c, offset);
                        if (volume == null) continue;
                        if (volume.Report.Status != "ready") continue;
                        if (progress != null) progress("ext4: проверка inode, раздел " + offset);
                        ScanVolume(c, volume, progress);
                    }
                    report.SourceUnchanged = input.Length == report.InputBytes && HashStream(input, cancel) == report.SourceSha256;
                    if (!report.SourceUnchanged) throw new IOException("Источник ext4 изменился во время чтения");
                }
                report.Status = report.Limited ? "limited" : "complete";
                return report.RecoveredFiles;
            } catch (OperationCanceledException) { report.Cancelled = true; report.Status = "cancelled"; throw; }
              catch { report.Failed = true; report.Status = "failed"; throw; }
            finally { File.WriteAllText(Path.Combine(root, "report.json"), new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 }.Serialize(report), new UTF8Encoding(false)); }
        }

        static Volume OpenVolume(Context c, long offset)
        {
            byte[] sb = Read(c, offset + 1024, 1024);
            if (sb == null || U16(sb, 0x38) != 0xef53) return null;
            var vr = new VolumeReport { Offset = offset, Status = "rejected" }; c.Report.Volumes.Add(vr);
            var v = new Volume { Offset = offset, Report = vr, Inodes = U32(sb, 0), FirstData = U32(sb, 0x14),
                BlocksPerGroup = U32(sb, 0x20), InodesPerGroup = U32(sb, 0x28), FirstInode = U32(sb, 0x54),
                Compat = U32(sb, 0x5c), Incompat = U32(sb, 0x60), RoCompat = U32(sb, 0x64) };
            v.Csum = (v.RoCompat & 0x400) != 0; v.GdtCsum = (v.RoCompat & 0x10) != 0;
            vr.MetadataChecksums = v.Csum; vr.GroupChecksums = v.Csum || v.GdtCsum;
            if (v.Csum && (sb[0x175] != 1 || Crc(0xffffffff, sb, 0, 0x3fc) != U32(sb, 0x3fc))) { vr.Reason = "superblock_checksum_invalid"; return v; }
            if (U16(sb, 0x5a) != 0) { vr.Reason = "backup_superblock_is_not_partition_origin"; return v; }
            uint log = U32(sb, 0x18); if (log > 6) { vr.Reason = "block_size_unsupported"; return v; }
            v.BlockBytes = 1024 << (int)log; vr.BlockBytes = v.BlockBytes;
            v.InodeBytes = U32(sb, 0x4c) == 0 ? 128 : U16(sb, 0x58); vr.InodeBytes = v.InodeBytes;
            v.DescriptorBytes = (v.Incompat & 0x80) != 0 ? U16(sb, 0xfe) : 32;
            v.Blocks = U32(sb, 4) | ((v.Incompat & 0x80) != 0 ? (ulong)U32(sb, 0x150) << 32 : 0);
            uint supported = 0x2U | 0x4U | 0x40U | 0x80U | 0x100U | 0x200U | 0x400U | 0x2000U | 0x4000U | 0x8000U | 0x10000U | 0x20000U;
            uint supportedRo = 0x1U | 0x2U | 0x4U | 0x8U | 0x10U | 0x20U | 0x40U | 0x100U | 0x400U | 0x1000U | 0x2000U | 0x8000U | 0x10000U;
            PopulateFeatures(v, vr, supported, supportedRo);
            if ((v.Incompat & ~supported) != 0 || (v.RoCompat & ~supportedRo) != 0 || ((v.Incompat & 0x2000) != 0 && !v.Csum)) { vr.Reason = "unsupported_features_or_journal_replay_required"; return v; }
            if (U32(sb, 0x48) != 0 || U32(sb, 0x4c) > 1 || v.InodeBytes < 128 || v.InodeBytes > v.BlockBytes || (v.InodeBytes & (v.InodeBytes - 1)) != 0 ||
                v.DescriptorBytes < 32 || v.DescriptorBytes > v.BlockBytes || (v.DescriptorBytes & 7) != 0 ||
                ((v.Incompat & 0x80) != 0 && v.DescriptorBytes < 64) || v.Blocks <= v.FirstData ||
                v.Blocks > (ulong)((c.Input.Length - offset) / v.BlockBytes) || v.BlocksPerGroup == 0 || v.BlocksPerGroup > v.BlockBytes * 8U ||
                v.InodesPerGroup == 0 || v.InodesPerGroup > v.BlockBytes * 8U || v.Inodes == 0 ||
                (v.BlockBytes == 1024 ? v.FirstData != 1 : v.FirstData != 0) || U32(sb, 0x1c) != log || U32(sb, 0x24) != v.BlocksPerGroup) {
                vr.Reason = "superblock_geometry_invalid"; return v;
            }
            ulong groups = (v.Blocks - v.FirstData + v.BlocksPerGroup - 1) / v.BlocksPerGroup;
            if (groups > (ulong)c.Limits.MaximumGroups || (ulong)v.Inodes > groups * v.InodesPerGroup || (ulong)v.Inodes <= (groups - 1) * v.InodesPerGroup) { vr.Reason = "group_limit_or_inode_bounds"; c.Report.Limited = true; return v; }
            vr.Groups = (int)groups; vr.Bytes = (long)v.Blocks * v.BlockBytes;
            v.Uuid = new byte[16]; Buffer.BlockCopy(sb, 0x68, v.Uuid, 0, 16); vr.Uuid = BitConverter.ToString(v.Uuid).Replace("-", "").ToLowerInvariant();
            v.Seed = (v.Incompat & 0x2000) != 0 ? U32(sb, 0x270) : Crc(0xffffffff, v.Uuid, 0, 16);
            ulong gdStart = v.FirstData + 1UL, gdBlocks = (groups * (uint)v.DescriptorBytes + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes;
            if (gdStart + gdBlocks > v.Blocks) { vr.Reason = "descriptor_table_bounds"; return v; }
            ulong fixedLength = 1 + gdBlocks + U16(sb, 0xce);
            v.Reserved.Add(new Range { Start = 0, Length = v.FirstData + fixedLength });
            for (uint g = 1; g < groups; g++) if (HasSuper(sb, v, g))
                v.Reserved.Add(new Range { Start = v.FirstData + (ulong)g * v.BlocksPerGroup, Length = fixedLength });
            if (v.Reserved.Any(x => x.Start >= v.Blocks || x.Length > v.Blocks - x.Start)) { vr.Reason = "reserved_metadata_bounds"; return v; }
            var fixedReserved = v.Reserved.ToList();
            ReadGroups(c, v, groups, gdStart, fixedReserved);
            if ((v.Incompat & 0x4) != 0)
            {
                JournalContext jc = LoadJournal(c, v, sb);
                if (jc != null)
                {
                    ReplayJournal(c, jc);
                    if (!v.JournalReplayApplied && jc.Start != 0 && v.Report.JournalStatus != "journal_transaction_uncommitted") {
                        vr.Reason = v.Report.JournalStatus ?? "journal_replay_failed"; return v;
                    }
                    if (v.Overlay.Count > 0)
                    {
                        if (!ReplaySuperblockGeometry(c, v, sb)) { vr.Reason = vr.JournalStatus; return v; }
                        v.Groups.Clear(); v.Reserved = fixedReserved.ToList();
                        ReadGroups(c, v, groups, gdStart, fixedReserved);
                    }
                }
                else { vr.Reason = vr.JournalStatus ?? "journal_unavailable_for_dirty_volume"; return v; }
            }
            v.Superblock = sb;
            vr.CheckedGroups = v.Groups.Count(x => x.Valid);
            vr.Status = "ready"; return v;
        }

        static byte[] GroupDescriptor(Context c, Volume v, ulong gdStart, uint group)
        {
            ulong relative = (ulong)group * (uint)v.DescriptorBytes;
            byte[] block = Block(c, v, gdStart + relative / (uint)v.BlockBytes);
            if (block == null) return null;
            byte[] descriptor = new byte[v.DescriptorBytes];
            Buffer.BlockCopy(block, (int)(relative % (uint)v.BlockBytes), descriptor, 0, descriptor.Length);
            return descriptor;
        }

        static bool ReplaySuperblockGeometry(Context c, Volume v, byte[] original)
        {
            byte[] containing;
            if (!v.Overlay.TryGetValue((ulong)(1024 / v.BlockBytes), out containing)) return true;
            byte[] updated = new byte[1024];
            Buffer.BlockCopy(containing, 1024 % v.BlockBytes, updated, 0, 1024);
            if (v.Csum && (updated[0x175] != 1 || Crc(0xffffffff, updated, 0, 0x3fc) != U32(updated, 0x3fc))) {
                JournalFailure(c, v, "journal_replayed_superblock_checksum_invalid"); return false;
            }
            int[,] fields = { { 0, 8 }, { 0x14, 24 }, { 0x38, 2 }, { 0x4c, 4 }, { 0x54, 12 },
                { 0x68, 16 }, { 0xfe, 2 }, { 0x150, 4 }, { 0x270, 4 } };
            for (int item = 0; item < fields.GetLength(0); item++) for (int i = 0; i < fields[item, 1]; i++) {
                int at = fields[item, 0] + i;
                if (updated[at] != original[at]) { JournalFailure(c, v, "journal_replay_geometry_changed_unsupported"); return false; }
            }
            if (((U32(updated, 0x60) ^ U32(original, 0x60)) & ~4U) != 0 ||
                ((U32(updated, 0x64) ^ U32(original, 0x64)) & ~0x10000U) != 0) {
                JournalFailure(c, v, "journal_replay_features_changed_unsupported"); return false;
            }
            return true;
        }

        static void ReadGroups(Context c, Volume v, ulong groups, ulong gdStart, List<Range> fixedReserved)
        {
            for (uint g = 0; g < groups; g++) {
                c.Cancel.ThrowIfCancellationRequested();
                byte[] desc = GroupDescriptor(c, v, gdStart, g);
                var group = new Group { Number = g, Descriptor = desc }; v.Groups.Add(group);
                if (desc == null || !GroupChecksum(v, g, desc)) { Skip(c, "group_descriptor_checksum_invalid"); continue; }
                group.BlockBitmap = Wide(desc, 0, 0x20); group.InodeBitmap = Wide(desc, 4, 0x24); group.InodeTable = Wide(desc, 8, 0x28); group.Flags = U16(desc, 0x12);
                if ((group.Flags & ~7) != 0) { Skip(c, "group_flags_unsupported"); continue; }
                ulong tableBlocks = ((ulong)v.InodesPerGroup * (uint)v.InodeBytes + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes;
                if (group.BlockBitmap == 0 || group.InodeBitmap == 0 || group.InodeTable == 0 || !BlockRange(v, group.BlockBitmap, 1) || !BlockRange(v, group.InodeBitmap, 1) || !BlockRange(v, group.InodeTable, tableBlocks) ||
                    group.BlockBitmap == group.InodeBitmap || (group.BlockBitmap >= group.InodeTable && group.BlockBitmap - group.InodeTable < tableBlocks) || (group.InodeBitmap >= group.InodeTable && group.InodeBitmap - group.InodeTable < tableBlocks)) { Skip(c, "group_metadata_bounds_or_overlap"); continue; }
                if (fixedReserved.Any(x => Overlap(x, group.BlockBitmap, 1) || Overlap(x, group.InodeBitmap, 1) || Overlap(x, group.InodeTable, tableBlocks))) { Skip(c, "group_metadata_overlaps_super_or_gdt"); continue; }
                group.Valid = true; v.Report.CheckedGroups++;
                v.Reserved.Add(new Range { Start = group.BlockBitmap, Length = 1 }); v.Reserved.Add(new Range { Start = group.InodeBitmap, Length = 1 });
                v.Reserved.Add(new Range { Start = group.InodeTable, Length = tableBlocks });
                if ((group.Flags & 1) == 0) { group.Inodes = Block(c, v, group.InodeBitmap); group.InodeMapValid = BitmapChecksum(v, group, group.Inodes, true); }
                if ((group.Flags & 2) == 0) { group.Blocks = Block(c, v, group.BlockBitmap); group.BlockMapValid = BitmapChecksum(v, group, group.Blocks, false); }
                if (!group.InodeMapValid) Skip(c, "inode_bitmap_uninitialized_or_invalid");
                if (!group.BlockMapValid) Skip(c, "block_bitmap_uninitialized_or_invalid");
            }
            var areas = new List<MetadataArea>();
            foreach (Group group in v.Groups.Where(x => x.Valid)) {
                areas.Add(new MetadataArea { Owner = group, Start = group.BlockBitmap, Length = 1 });
                areas.Add(new MetadataArea { Owner = group, Start = group.InodeBitmap, Length = 1 });
                areas.Add(new MetadataArea { Owner = group, Start = group.InodeTable, Length = ((ulong)v.InodesPerGroup * (uint)v.InodeBytes + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes });
            }
            MetadataArea previous = null;
            foreach (MetadataArea area in areas.OrderBy(x => x.Start)) {
                if (previous != null && area.Start < previous.Start + previous.Length) {
                    area.Owner.Valid = previous.Owner.Valid = false; Skip(c, "cross_group_metadata_overlap");
                }
                if (previous == null || area.Start + area.Length > previous.Start + previous.Length) previous = area;
            }
        }

        static void ScanVolume(Context c, Volume v, Action<string> progress)
        {
            var deleted = new List<Inode>(); var directories = new Dictionary<uint, Inode>();
            foreach (Group group in v.Groups) {
                if (!group.Valid || !group.InodeMapValid) continue;
                uint count = Math.Min(v.InodesPerGroup, v.Inodes - group.Number * v.InodesPerGroup);
                for (uint at = 0; at < count; at++) {
                    c.Cancel.ThrowIfCancellationRequested();
                    if (++c.InodesRead > c.Limits.MaximumInodes) { c.Report.Limited = true; Skip(c, "inode_limit"); break; }
                    uint number = group.Number * v.InodesPerGroup + at + 1;
                    ulong tableBlock = group.InodeTable + (ulong)(((long)at * v.InodeBytes) / v.BlockBytes);
                    int offsetInBlock = (int)(((long)at * v.InodeBytes) % v.BlockBytes);
                    byte[] tableData = Block(c, v, tableBlock);
                    if (tableData == null || tableData.Length < offsetInBlock + v.InodeBytes) continue;
                    byte[] bytes = new byte[v.InodeBytes];
                    Buffer.BlockCopy(tableData, offsetInBlock, bytes, 0, v.InodeBytes);
                    long position = v.Offset + (long)tableBlock * v.BlockBytes + (long)offsetInBlock;
                    ushort mode = U16(bytes, 0); if ((mode & 0xf000) != 0x8000 && (mode & 0xf000) != 0x4000) continue;
                    if (!InodeChecksum(v, number, bytes)) { Skip(c, "inode_checksum_invalid"); continue; }
                    v.Report.CheckedInodes++;
                    var inode = new Inode { Number = number, Offset = position, Mode = mode, Links = U16(bytes, 0x1a), Dtime = U32(bytes, 0x14),
                        Flags = U32(bytes, 0x20), Generation = U32(bytes, 0x64), Size = U32(bytes, 4) | (ulong)U32(bytes, 0x6c) << 32,
                        Allocated = Bit(group.Inodes, at), Bytes = bytes };
                    if (inode.Allocated && inode.Links > 0 && inode.Dtime == 0) {
                        v.Report.LiveInodes++;
                        if ((mode & 0xf000) == 0x4000) {
                            if (directories.Count >= c.Limits.MaximumDirectories) { c.Report.Limited = true; Skip(c, "directory_count_limit"); }
                            else directories[number] = inode;
                        }
                        continue;
                    }
                    if ((mode & 0xf000) != 0x8000 || inode.Allocated || inode.Links != 0 || inode.Dtime == 0 || number < Math.Max(11, v.FirstInode)) continue;
                    if (c.Report.Entries.Count + deleted.Count >= c.Limits.MaximumCandidates) { c.Report.Limited = true; Skip(c, "candidate_limit"); continue; }
                    deleted.Add(inode);
                }
                if (progress != null) progress("ext4: inode " + Math.Min(c.InodesRead, c.Limits.MaximumInodes) + ", удалённых кандидатов " + deleted.Count);
                if (c.InodesRead > c.Limits.MaximumInodes) break;
            }

            JournalContext jc = LoadJournal(c, v, v.Superblock);
            Dictionary<uint, HistoricalCandidate> historicalInodes = null;
            List<Tuple<ulong, byte[]>> journalDirBlocks = null;
            if (jc != null)
            {
                SweepJournalHistory(c, v, jc, out historicalInodes, out journalDirBlocks);
                v.Report.JournalHistoricalInodesFound = historicalInodes.Count;
            }

            var names = DirectoryNames(c, v, directories, journalDirBlocks);
            foreach (Inode inode in deleted) {
                c.Cancel.ThrowIfCancellationRequested(); c.Report.Candidates++;
                var entry = new Entry { VolumeOffset = v.Offset, InodeOffset = inode.Offset, Inode = inode.Number, Generation = inode.Generation,
                    DeletionTime = inode.Dtime, DeclaredSize = inode.Size > long.MaxValue ? long.MaxValue : (long)inode.Size,
                    InodeChecksumVerified = v.Csum, Status = "not_recovered" };
                c.Report.Entries.Add(entry);
                List<NameLink> links; if (names.TryGetValue(inode.Number, out links)) entry.Names = links;
                if (inode.Size == 0 || inode.Size > (ulong)c.Limits.MaximumFileBytes) {
                    entry.Reason = "empty_or_file_size_limit";
                    if (inode.Size > (ulong)c.Limits.MaximumFileBytes) { c.Report.Limited = true; Skip(c, "file_size_limit"); }
                    continue;
                }
                Mapping map = Map(c, v, inode); entry.Mapping = map.Kind;
                entry.MappingIntegrity = map.Kind == "direct_indirect" ? "inode_only_indirect_blocks_have_no_checksum" : v.Csum ? "inode_and_extent_nodes_crc32c" : "structural_only_no_metadata_checksum";
                if (map.Failure != null) { entry.Reason = map.Failure; Skip(c, map.Failure); continue; }
                foreach (BlockRun run in map.Runs) {
                    long logical = (long)run.Logical * v.BlockBytes;
                    entry.Extents.Add(new Extent { ImageOffset = v.Offset + (long)run.Physical * v.BlockBytes, LogicalOffset = logical,
                        Length = Math.Min((long)run.Count * v.BlockBytes, (long)inode.Size - logical) });
                }
                string allocation = Allocation(c, v, map); entry.AllocationStatus = allocation;
                if (allocation != "currently_free" && allocation != "currently_free_unchecksummed_bitmap") { entry.Reason = allocation; Skip(c, allocation); continue; }
                if ((long)inode.Size > c.Limits.MaximumOutputBytes - c.Report.OutputBytes) { c.Report.Limited = true; entry.Reason = "output_limit"; continue; }
                WriteFile(c, entry);
            }

            if (historicalInodes != null)
            {
                foreach (HistoricalCandidate cand in historicalInodes.Values)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    if (c.Report.Entries.Any(x => x.VolumeOffset == v.Offset && x.Inode == cand.Number && x.Output != null)) continue;
                    if (!IsCandidateDeletedInLiveFs(c, v, cand)) continue;

                    if (c.Report.Entries.Count >= c.Limits.MaximumCandidates)
                    {
                        c.Report.Limited = true;
                        Skip(c, "candidate_limit");
                        break;
                    }

                    var inode = new Inode
                    {
                        Number = cand.Number,
                        Offset = v.Offset + (long)cand.TargetDiskBlock * v.BlockBytes + (long)cand.OffsetInBlock,
                        Mode = cand.Mode,
                        Links = cand.Links,
                        Dtime = cand.Dtime,
                        Flags = cand.Flags,
                        Generation = cand.Generation,
                        Size = cand.Size,
                        Allocated = false,
                        Bytes = cand.InodeBytes
                    };

                    c.Report.Candidates++;
                    var entry = new Entry
                    {
                        VolumeOffset = v.Offset,
                        InodeOffset = inode.Offset,
                        Inode = inode.Number,
                        Generation = inode.Generation,
                        DeletionTime = inode.Dtime,
                        DeclaredSize = inode.Size > long.MaxValue ? long.MaxValue : (long)inode.Size,
                        InodeChecksumVerified = v.Csum,
                        Status = "not_recovered",
                        DeletionEvidence = "journal_transaction_pre_deletion_record",
                        Note = "Историческая карта inode из транзакции журнала JBD2 (seq " + cand.TransactionSeq + "). Свободные блоки могли быть перезаписаны до снимка; контрольной суммы исходного содержимого в ext4 нет."
                    };
                    c.Report.Entries.Add(entry);

                    List<NameLink> links;
                    if (names.TryGetValue(inode.Number, out links)) entry.Names = links;

                    Mapping map = Map(c, v, inode);
                    entry.Mapping = map.Kind;
                    entry.MappingIntegrity = map.Kind == "direct_indirect" ? "inode_only_indirect_blocks_have_no_checksum" : v.Csum ? "inode_and_extent_nodes_crc32c" : "structural_only_no_metadata_checksum";
                    if (map.Failure != null) { entry.Reason = map.Failure; Skip(c, map.Failure); continue; }

                    foreach (BlockRun run in map.Runs)
                    {
                        long logical = (long)run.Logical * v.BlockBytes;
                        entry.Extents.Add(new Extent
                        {
                            ImageOffset = v.Offset + (long)run.Physical * v.BlockBytes,
                            LogicalOffset = logical,
                            Length = Math.Min((long)run.Count * v.BlockBytes, (long)inode.Size - logical)
                        });
                    }

                    string allocation = Allocation(c, v, map);
                    entry.AllocationStatus = allocation;
                    if (allocation != "currently_free" && allocation != "currently_free_unchecksummed_bitmap")
                    {
                        entry.Reason = allocation;
                        Skip(c, allocation);
                        continue;
                    }

                    if ((long)inode.Size > c.Limits.MaximumOutputBytes - c.Report.OutputBytes)
                    {
                        c.Report.Limited = true;
                        entry.Reason = "output_limit";
                        continue;
                    }

                    WriteFile(c, entry);
                }
            }

            v.Report.Status = c.Report.Limited ? "limited" : "complete";
        }

        static Mapping Map(Context c, Volume v, Inode inode)
        {
            var map = new Mapping { Kind = (inode.Flags & 0x80000) != 0 ? "extent_tree" : "direct_indirect" };
            if ((inode.Flags & (0x800U | 0x10000000U | 4U | 0x100000U | 0x200000U)) != 0) { map.Failure = "encrypted_inline_compressed_verity_or_ea_inode"; return map; }
            ulong needed = (inode.Size + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes;
            if ((inode.Flags & 0x80000) != 0) {
                byte[] root = new byte[60]; Buffer.BlockCopy(inode.Bytes, 0x28, root, 0, 60);
                ExtentNode(c, v, inode, map, root, -1, 0, 0x100000000UL);
            } else {
                ulong logical = 0;
                for (int i = 0; i < 12 && logical < needed; i++, logical++) AddRun(c, v, map, logical, U32(inode.Bytes, 0x28 + i * 4), 1, false);
                for (int depth = 1; depth <= 3 && logical < needed && map.Failure == null; depth++) {
                    ulong capacity = 1; for (int i = 0; i < depth; i++) capacity *= (uint)(v.BlockBytes / 4);
                    Indirect(c, v, map, U32(inode.Bytes, 0x28 + (11 + depth) * 4), depth, logical, needed);
                    logical += capacity;
                }
                if (logical < needed && map.Failure == null) map.Failure = "indirect_mapping_size_limit";
            }
            if (map.Failure != null) return map;
            map.Runs = map.Runs.Where(x => x.Logical < needed).OrderBy(x => x.Logical).ToList();
            ulong covered = 0;
            foreach (BlockRun run in map.Runs) {
                if (run.Logical != covered || run.Unwritten) { map.Failure = run.Unwritten ? "unwritten_extent_not_original_data" : "sparse_or_overlapping_logical_mapping"; return map; }
                covered = Math.Min(needed, run.Logical + run.Count);
                if (map.TreeBlocks.Any(x => x >= run.Physical && x - run.Physical < run.Count)) { map.Failure = "data_overlaps_mapping_metadata"; return map; }
            }
            if (covered != needed) map.Failure = "sparse_or_incomplete_mapping";
            var physical = map.Runs.OrderBy(x => x.Physical).ToList();
            for (int i = 1; i < physical.Count; i++) if (physical[i - 1].Physical + physical[i - 1].Count > physical[i].Physical) map.Failure = "overlapping_physical_extents";
            return map;
        }

        static void ExtentNode(Context c, Volume v, Inode inode, Mapping map, byte[] bytes, int expectedDepth, ulong lower, ulong upper)
        {
            if (map.Failure != null) return; c.Cancel.ThrowIfCancellationRequested();
            int entries = U16(bytes, 2), maximum = U16(bytes, 4), depth = U16(bytes, 6);
            if (U16(bytes, 0) != 0xf30a || maximum != (bytes.Length - 12) / 12 || entries > maximum || depth > 5 || (expectedDepth >= 0 && depth != expectedDepth)) { map.Failure = "extent_header_invalid"; return; }
            if (bytes.Length != 60 && v.Csum) {
                int tail = 12 + maximum * 12; uint seed = InodeSeed(v, inode.Number, inode.Generation);
                if (tail + 4 > bytes.Length || Crc(seed, bytes, 0, tail) != U32(bytes, tail)) { map.Failure = "extent_node_checksum_invalid"; return; }
            }
            ulong previous = lower;
            for (int i = 0; i < entries && map.Failure == null; i++) {
                int at = 12 + i * 12; ulong logical = U32(bytes, at);
                if (logical < lower || logical >= upper || (i > 0 && logical < previous)) { map.Failure = "extent_logical_bounds"; return; }
                if (depth == 0) {
                    uint rawLength = U16(bytes, at + 4); bool unwritten = rawLength > 32768;
                    ulong length = unwritten ? rawLength - 32768U : rawLength;
                    if (length == 0 || length > upper - logical) { map.Failure = "extent_length_invalid"; return; }
                    AddRun(c, v, map, logical, U32(bytes, at + 8) | (ulong)U16(bytes, at + 6) << 32, length, unwritten); previous = logical + length;
                } else {
                    ulong next = i + 1 < entries ? U32(bytes, at + 12) : upper;
                    ulong block = U32(bytes, at + 4) | (ulong)U16(bytes, at + 8) << 32;
                    if (next <= logical || !TreeBlock(c, v, map, block)) { if (map.Failure == null) map.Failure = "extent_index_invalid"; return; }
                    byte[] child = Block(c, v, block); if (child == null) { map.Failure = "extent_node_read_failed"; return; }
                    ExtentNode(c, v, inode, map, child, depth - 1, logical, next); previous = next;
                }
            }
        }
        static void Indirect(Context c, Volume v, Mapping map, ulong block, int depth, ulong logical, ulong needed)
        {
            if (map.Failure != null || logical >= needed) return;
            if (block == 0) { map.Failure = "sparse_indirect_pointer"; return; }
            if (!TreeBlock(c, v, map, block)) return;
            byte[] bytes = Block(c, v, block); if (bytes == null) { map.Failure = "indirect_block_read_failed"; return; }
            ulong stride = 1; for (int i = 1; i < depth; i++) stride *= (uint)(v.BlockBytes / 4);
            for (int i = 0; i < bytes.Length / 4 && logical < needed && map.Failure == null; i++, logical += stride) {
                c.Cancel.ThrowIfCancellationRequested(); ulong pointer = U32(bytes, i * 4);
                if (depth == 1) AddRun(c, v, map, logical, pointer, 1, false);
                else Indirect(c, v, map, pointer, depth - 1, logical, needed);
            }
        }
        static bool TreeBlock(Context c, Volume v, Mapping map, ulong block)
        {
            if (!BlockRange(v, block, 1) || Reserved(v, block, 1)) { map.Failure = "mapping_block_bounds_or_reserved"; return false; }
            if (!map.TreeBlocks.Add(block)) { map.Failure = "mapping_cycle_or_duplicate_node"; return false; }
            if (map.TreeBlocks.Count > c.Limits.MaximumTreeBlocks) { map.Failure = "mapping_tree_limit"; c.Report.Limited = true; return false; }
            return true;
        }
        static void AddRun(Context c, Volume v, Mapping map, ulong logical, ulong physical, ulong count, bool unwritten)
        {
            if (map.Failure != null) return;
            if (physical == 0) { map.Failure = "sparse_block_pointer"; return; }
            if (!BlockRange(v, physical, count) || Reserved(v, physical, count)) { map.Failure = "data_block_bounds_or_reserved"; return; }
            if (map.Runs.Count > 0) {
                BlockRun previous = map.Runs[map.Runs.Count - 1];
                if (previous.Unwritten == unwritten && previous.Logical + previous.Count == logical && previous.Physical + previous.Count == physical) { previous.Count += count; return; }
            }
            if (map.Runs.Count >= c.Limits.MaximumExtents) { map.Failure = "extent_count_limit"; c.Report.Limited = true; return; }
            map.Runs.Add(new BlockRun { Logical = logical, Physical = physical, Count = count, Unwritten = unwritten });
        }
        static string Allocation(Context c, Volume v, Mapping map)
        {
            foreach (ulong tree in map.TreeBlocks) { string failure = FreeBlock(v, tree); if (failure != null) return "mapping_" + failure; }
            foreach (BlockRun run in map.Runs) for (ulong i = 0; i < run.Count; i++) {
                if ((i & 4095) == 0) c.Cancel.ThrowIfCancellationRequested();
                string failure = FreeBlock(v, run.Physical + i); if (failure != null) return failure;
            }
            return v.Csum ? "currently_free" : "currently_free_unchecksummed_bitmap";
        }
        static string FreeBlock(Volume v, ulong block)
        {
            ulong index = (block - v.FirstData) / v.BlocksPerGroup;
            if (index >= (ulong)v.Groups.Count) return "allocation_group_out_of_bounds";
            Group group = v.Groups[(int)index];
            if (!group.Valid || !group.BlockMapValid) return "allocation_bitmap_unknown_or_invalid";
            return Bit(group.Blocks, (uint)((block - v.FirstData) % v.BlocksPerGroup)) ? "currently_allocated_block_conflict" : null;
        }

        static Dictionary<uint, List<NameLink>> DirectoryNames(Context c, Volume v, Dictionary<uint, Inode> directories, List<Tuple<ulong, byte[]>> journalDirBlocks = null)
        {
            var links = new Dictionary<uint, List<NameLink>>(); var directoryPaths = new Dictionary<uint, string>(); directoryPaths[2] = "/";
            foreach (Inode inode in directories.Values) {
                c.Cancel.ThrowIfCancellationRequested(); if (++c.DirectoryCount > c.Limits.MaximumDirectories) { c.Report.Limited = true; break; }
                if (inode.Size == 0 || inode.Size > 64L * 1024 * 1024) continue;
                Mapping map = Map(c, v, inode); if (map.Failure != null) continue;
                if (map.TreeBlocks.Any(x => FreeBlock(v, x) != "currently_allocated_block_conflict")) continue;
                foreach (BlockRun run in map.Runs) for (ulong i = 0; i < run.Count; i++) {
                    if (c.DirectoryBytes > c.Limits.MaximumDirectoryBytes - v.BlockBytes) { c.Report.Limited = true; Skip(c, "directory_byte_limit"); return links; }
                    c.DirectoryBytes += v.BlockBytes;
                    if (FreeBlock(v, run.Physical + i) != "currently_allocated_block_conflict") continue;
                    c.Cancel.ThrowIfCancellationRequested(); byte[] bytes = Block(c, v, run.Physical + i); if (bytes == null) continue;
                    int end = bytes.Length; bool checkedCsum = false;
                    if (v.Csum) {
                        int tail = bytes.Length - 12;
                        if (U32(bytes, tail) != 0 || U16(bytes, tail + 4) != 12 || bytes[tail + 6] != 0 || bytes[tail + 7] != 0xde || Crc(InodeSeed(v, inode.Number, inode.Generation), bytes, 0, tail) != U32(bytes, tail + 8)) continue;
                        checkedCsum = true; end = tail;
                    }
                    var blockLinks = new List<NameLink>(); int at = 0; bool valid = true;
                    while (at < end) {
                        if (at + 8 > end) { valid = false; break; }
                        uint target = U32(bytes, at); int length = U16(bytes, at + 4), nameLength = (v.Incompat & 2) != 0 ? bytes[at + 6] : U16(bytes, at + 6);
                        if (length < 8 || (length & 3) != 0 || length > end - at || nameLength > 255 || nameLength > length - 8) { valid = false; break; }
                        if (target > 0 && target <= v.Inodes && nameLength > 0) {
                            try {
                                string name = Utf8.GetString(bytes, at + 8, nameLength);
                                if (name != "." && name != ".." && name.IndexOfAny(new[] { '/', '\0' }) < 0)
                                    blockLinks.Add(new NameLink { DirectoryInode = inode.Number, TargetInode = target, Name = name,
                                        EntryOffset = v.Offset + (long)(run.Physical + i) * v.BlockBytes + at, DirectoryChecksumVerified = checkedCsum });
                            } catch (DecoderFallbackException) { }
                        }
                        int actual = (8 + nameLength + 3) & ~3;
                        int slack = at + actual;
                        while (slack + 8 <= at + length)
                        {
                            uint unlinkedTarget = U32(bytes, slack);
                            int unlinkedLen = U16(bytes, slack + 4);
                            int unlinkedNameLen = (v.Incompat & 2) != 0 ? bytes[slack + 6] : U16(bytes, slack + 6);
                            if (unlinkedLen < 8 || (unlinkedLen & 3) != 0 || slack + unlinkedLen > at + length ||
                                unlinkedNameLen == 0 || unlinkedNameLen > unlinkedLen - 8) break;
                            if (unlinkedTarget > 0 && unlinkedTarget <= v.Inodes)
                            {
                                try
                                {
                                    string unlinkedName = Utf8.GetString(bytes, slack + 8, unlinkedNameLen);
                                    if (unlinkedName != "." && unlinkedName != ".." && unlinkedName.IndexOfAny(new[] { '/', '\0' }) < 0)
                                    {
                                        blockLinks.Add(new NameLink
                                        {
                                            DirectoryInode = inode.Number,
                                            TargetInode = unlinkedTarget,
                                            Name = unlinkedName,
                                            EntryOffset = v.Offset + (long)(run.Physical + i) * v.BlockBytes + slack,
                                            DirectoryChecksumVerified = checkedCsum,
                                            Status = "unlinked_directory_slack_reference"
                                        });
                                    }
                                }
                                catch (DecoderFallbackException) { }
                            }
                            slack += unlinkedLen;
                        }
                        at += length;
                    }
                    if (!valid) continue;
                    foreach (NameLink link in blockLinks) {
                        if (++c.NameCount > c.Limits.MaximumNames) { c.Report.Limited = true; return links; }
                        List<NameLink> existing; if (!links.TryGetValue(link.TargetInode, out existing)) { existing = new List<NameLink>(); links[link.TargetInode] = existing; }
                        existing.Add(link);
                    }
                }
            }
            if (journalDirBlocks != null)
            {
                foreach (var jdb in journalDirBlocks)
                {
                    byte[] bytes = jdb.Item2;
                    ulong diskBlock = jdb.Item1;
                    if (bytes == null || bytes.Length < 12) continue;
                    int end = bytes.Length;
                    bool checkedCsum = false;
                    if (v.Csum)
                    {
                        int tail = bytes.Length - 12;
                        if (U32(bytes, tail) == 0 && U16(bytes, tail + 4) == 12 && bytes[tail + 6] == 0 && bytes[tail + 7] == 0xDE)
                        {
                            checkedCsum = true;
                            end = tail;
                        }
                    }
                    uint dirIno = 0;
                    if (bytes.Length > 24 && bytes[6] == 1 && bytes[8] == '.')
                    {
                        dirIno = U32(bytes, 0);
                    }
                    int at = 0;
                    while (at < end)
                    {
                        if (at + 8 > end) break;
                        uint target = U32(bytes, at);
                        int length = U16(bytes, at + 4);
                        int nameLength = (v.Incompat & 2) != 0 ? bytes[at + 6] : U16(bytes, at + 6);
                        if (length < 8 || (length & 3) != 0 || length > end - at || nameLength > 255 || nameLength > length - 8) break;
                        if (target > 0 && target <= v.Inodes && nameLength > 0)
                        {
                            try
                            {
                                string name = Utf8.GetString(bytes, at + 8, nameLength);
                                if (name != "." && name != ".." && name.IndexOfAny(new[] { '/', '\0' }) < 0)
                                {
                                    List<NameLink> existing;
                                    if (!links.TryGetValue(target, out existing)) { existing = new List<NameLink>(); links[target] = existing; }
                                    if (!existing.Any(x => x.TargetInode == target && x.Name == name))
                                    {
                                        existing.Add(new NameLink
                                        {
                                            DirectoryInode = dirIno,
                                            TargetInode = target,
                                            Name = name,
                                            EntryOffset = v.Offset + (long)diskBlock * v.BlockBytes + at,
                                            DirectoryChecksumVerified = checkedCsum,
                                            Status = "historical_journal_directory_reference"
                                        });
                                    }
                                }
                            }
                            catch (DecoderFallbackException) { }
                        }
                        at += length;
                    }
                }
            }
            // Only a connected, unambiguous current directory chain gets a path.
            for (int depth = 0; depth < 128; depth++) {
                bool changed = false;
                foreach (uint number in directories.Keys) {
                    if (directoryPaths.ContainsKey(number)) continue; List<NameLink> names;
                    if (!links.TryGetValue(number, out names) || names.Count != 1 || !directoryPaths.ContainsKey(names[0].DirectoryInode)) continue;
                    string path = directoryPaths[names[0].DirectoryInode] + names[0].Name + "/"; if (path.Length > 32768) continue;
                    directoryPaths[number] = path; changed = true;
                }
                if (!changed) break;
            }
            foreach (List<NameLink> names in links.Values) foreach (NameLink name in names) { string path; if (directoryPaths.TryGetValue(name.DirectoryInode, out path)) name.DirectoryPath = path; }
            return links;
        }

        static void WriteFile(Context c, Entry entry)
        {
            byte[] header = Read(c, entry.Extents[0].ImageOffset, (int)Math.Min(32, entry.Extents[0].Length));
            string extension = SignatureExtension(header); entry.ContentTypeHint = extension == ".bin" ? null : extension.Substring(1) + "_signature_only";
            string name = "volume_" + entry.VolumeOffset + "_inode_" + entry.Inode + "_generation_" + entry.Generation + extension;
            string relative = "files/" + name, destination = Path.Combine(c.Root, "files", name), temporary = destination + ".partial";
            NoLinks(destination); byte[] buffer = new byte[1024 * 1024];
            try {
                using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) using (var sha = SHA256.Create()) {
                    foreach (Extent extent in entry.Extents) {
                        c.Input.Position = extent.ImageOffset; long remaining = extent.Length;
                        while (remaining > 0) {
                            c.Cancel.ThrowIfCancellationRequested(); int count = c.Input.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                            if (count == 0) throw new EndOfStreamException("Неполное чтение ext4");
                            output.Write(buffer, 0, count); sha.TransformBlock(buffer, 0, count, buffer, 0); remaining -= count;
                        }
                    }
                    sha.TransformFinalBlock(new byte[0], 0, 0); output.Flush(true); entry.Sha256 = Hex(sha.Hash);
                }
                c.Cancel.ThrowIfCancellationRequested(); File.Move(temporary, destination);
                entry.Output = relative; entry.RecoveredBytes = entry.DeclaredSize; entry.Status = "deleted_inode_candidate";
                c.Report.RecoveredFiles++; c.Report.OutputBytes += entry.RecoveredBytes;
            } finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }

        static bool InodeChecksum(Volume v, uint number, byte[] bytes)
        {
            if (!v.Csum) return true;
            if (bytes.Length > 128 && (U16(bytes, 128) > bytes.Length - 128 || (U16(bytes, 128) & 3) != 0)) return false;
            bool high = bytes.Length >= 132 && U16(bytes, 128) >= 4;
            uint expected = U16(bytes, 124) | (high ? (uint)U16(bytes, 130) << 16 : 0);
            byte[] copy = (byte[])bytes.Clone(); copy[124] = copy[125] = 0; if (high) copy[130] = copy[131] = 0;
            uint actual = Crc(InodeSeed(v, number, U32(bytes, 100)), copy, 0, copy.Length);
            return (high ? actual : actual & 0xffff) == expected;
        }
        static uint InodeSeed(Volume v, uint inode, uint generation)
        { return Crc(Crc(v.Seed, BitConverter.GetBytes(inode), 0, 4), BitConverter.GetBytes(generation), 0, 4); }
        static bool GroupChecksum(Volume v, uint number, byte[] desc)
        {
            if (!v.Csum && !v.GdtCsum) return true;
            if (v.Csum) { byte[] copy = (byte[])desc.Clone(); copy[30] = copy[31] = 0; return (Crc(Crc(v.Seed, BitConverter.GetBytes(number), 0, 4), copy, 0, copy.Length) & 0xffff) == U16(desc, 30); }
            ushort crc = Crc16(0xffff, v.Uuid ?? new byte[0], 0, v.Uuid == null ? 0 : 16);
            crc = Crc16(crc, BitConverter.GetBytes(number), 0, 4); crc = Crc16(crc, desc, 0, 30);
            if (desc.Length > 32) crc = Crc16(crc, desc, 32, desc.Length - 32);
            return crc == U16(desc, 30);
        }
        static bool BitmapChecksum(Volume v, Group group, byte[] bytes, bool inode)
        {
            if (bytes == null) return false; if (!v.Csum) return true;
            int size = (int)((inode ? v.InodesPerGroup : v.BlocksPerGroup) + 7) / 8;
            if (size > bytes.Length) return false;
            int low = inode ? 26 : 24, high = inode ? 58 : 56;
            uint expected = U16(group.Descriptor, low); bool full = group.Descriptor.Length >= high + 2;
            if (full) expected |= (uint)U16(group.Descriptor, high) << 16;
            uint actual = Crc(v.Seed, bytes, 0, size); return (full ? actual : actual & 0xffff) == expected;
        }
        static bool HasSuper(byte[] sb, Volume v, uint group)
        {
            if ((v.Compat & 0x200) != 0) return group == U32(sb, 0x24c) || group == U32(sb, 0x250);
            if ((v.RoCompat & 1) == 0 || group == 1) return true;
            foreach (uint basis in new uint[] { 3, 5, 7 }) { uint n = group; while (n > 1 && n % basis == 0) n /= basis; if (n == 1) return true; }
            return false;
        }
        static bool BlockRange(Volume v, ulong start, ulong count) { return start >= v.FirstData && count > 0 && start < v.Blocks && count <= v.Blocks - start; }
        static bool Overlap(Range area, ulong block, ulong count) { return block < area.Start + area.Length && area.Start < block + count; }
        static bool Reserved(Volume v, ulong block, ulong count) { return v.Reserved.Any(x => Overlap(x, block, count)); }
        static string SignatureExtension(byte[] header)
        {
            if (header == null) return ".bin";
            if (header.Length >= 3 && header[0] == 255 && header[1] == 216 && header[2] == 255) return ".jpg";
            if (header.Length >= 8 && header.Take(8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 })) return ".png";
            if (header.Length >= 6 && (Encoding.ASCII.GetString(header, 0, 6) == "GIF87a" || Encoding.ASCII.GetString(header, 0, 6) == "GIF89a")) return ".gif";
            if (header.Length >= 12 && Encoding.ASCII.GetString(header, 0, 4) == "RIFF" && Encoding.ASCII.GetString(header, 8, 4) == "WEBP") return ".webp";
            if (header.Length >= 5 && Encoding.ASCII.GetString(header, 0, 5) == "%PDF-") return ".pdf";
            if (header.Length >= 4 && header[0] == 80 && header[1] == 75 && ((header[2] == 3 && header[3] == 4) || (header[2] == 5 && header[3] == 6) || (header[2] == 7 && header[3] == 8))) return ".zip";
            return ".bin";
        }
        static byte[] Block(Context c, Volume v, ulong number)
        {
            if (!BlockRange(v, number, 1)) return null;
            byte[] cached;
            if (v.Overlay != null && v.Overlay.TryGetValue(number, out cached)) return cached;
            return Read(c, v.Offset + (long)number * v.BlockBytes, v.BlockBytes);
        }
        static ushort Be16(byte[] b, int at) { if (b == null || at < 0 || at + 2 > b.Length) return 0; return (ushort)((b[at] << 8) | b[at + 1]); }
        static uint Be32(byte[] b, int at) { if (b == null || at < 0 || at + 4 > b.Length) return 0; return (uint)((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]); }
        static ulong Be64(byte[] b, int at) { return ((ulong)Be32(b, at) << 32) | (ulong)Be32(b, at + 4); }
        static uint NextJournalBlock(uint current, uint first, uint maxLen)
        {
            current++;
            return current >= maxLen ? first : current;
        }

        static void PopulateFeatures(Volume v, VolumeReport vr, uint supported, uint supportedRo)
        {
            var incompatNames = new Dictionary<uint, string>
            {
                { 0x1, "compression" }, { 0x2, "filetype" }, { 0x4, "recover" }, { 0x8, "journal_dev" },
                { 0x10, "meta_bg" }, { 0x40, "extents" }, { 0x80, "64bit" }, { 0x100, "mmp" },
                { 0x200, "flex_bg" }, { 0x400, "ea_inode" }, { 0x1000, "dirdata" }, { 0x2000, "csum_seed" },
                { 0x4000, "largedir" }, { 0x8000, "inline_data" }, { 0x10000, "encrypt" }, { 0x20000, "casefold" }
            };
            var roCompatNames = new Dictionary<uint, string>
            {
                { 0x1, "sparse_super" }, { 0x2, "large_file" }, { 0x4, "btree_dir" }, { 0x8, "huge_file" },
                { 0x10, "gdt_csum" }, { 0x20, "dir_nlink" }, { 0x40, "extra_isize" }, { 0x80, "has_snapshot" },
                { 0x100, "quota" }, { 0x200, "bigalloc" }, { 0x400, "metadata_csum" }, { 0x800, "replica" },
                { 0x1000, "readonly" }, { 0x2000, "project" }, { 0x8000, "verity" }, { 0x10000, "orphan_present" }
            };
            var compatNames = new Dictionary<uint, string>
            {
                { 0x1, "dir_prealloc" }, { 0x2, "imagic_inodes" }, { 0x4, "has_journal" }, { 0x8, "ext_attr" },
                { 0x10, "resize_inode" }, { 0x20, "dir_index" }, { 0x200, "sparse_super2" }, { 0x400, "fast_commit" },
                { 0x1000, "orphan_file" }
            };

            for (int bit = 0; bit < 32; bit++)
            {
                uint mask = 1U << bit;
                if ((v.Incompat & mask) != 0)
                {
                    string name;
                    if (!incompatNames.TryGetValue(mask, out name)) name = "incompat_0x" + mask.ToString("x");
                    if ((mask & supported) != 0) vr.HandledFeatures.Add(name);
                    else vr.UnsupportedFeatures.Add(name);
                }
                if ((v.RoCompat & mask) != 0)
                {
                    string name;
                    if (!roCompatNames.TryGetValue(mask, out name)) name = "ro_compat_0x" + mask.ToString("x");
                    if ((mask & supportedRo) != 0) vr.HandledFeatures.Add(name);
                    else vr.UnsupportedFeatures.Add(name);
                }
                if ((v.Compat & mask) != 0)
                {
                    string name;
                    if (!compatNames.TryGetValue(mask, out name)) name = "compat_0x" + mask.ToString("x");
                    vr.HandledFeatures.Add(name);
                }
            }
            if ((v.Incompat & 0x2000) != 0 && !v.Csum)
                vr.UnsupportedFeatures.Add("csum_seed_without_metadata_csum");
        }

        static JournalContext LoadJournal(Context c, Volume v, byte[] sb)
        {
            if (v.JournalLoaded) return v.Journal;
            v.JournalLoaded = true;
            if (sb == null) return JournalFailure(c, v, "journal_superblock_unavailable");
            uint journalIno = U32(sb, 0xE0);
            if (journalIno == 0) return JournalFailure(c, v, "external_or_missing_journal");
            if (journalIno > v.Inodes) return JournalFailure(c, v, "journal_inode_bounds");

            uint groupIndex = (journalIno - 1) / v.InodesPerGroup, at = (journalIno - 1) % v.InodesPerGroup;
            if (groupIndex >= v.Groups.Count || !v.Groups[(int)groupIndex].Valid) return JournalFailure(c, v, "journal_inode_group_invalid");
            ulong tableBlock = v.Groups[(int)groupIndex].InodeTable + (ulong)(((long)at * v.InodeBytes) / v.BlockBytes);
            int offsetInBlock = (int)(((long)at * v.InodeBytes) % v.BlockBytes);
            byte[] blockData = Block(c, v, tableBlock);
            if (blockData == null || blockData.Length < offsetInBlock + v.InodeBytes) return null;
            byte[] inodeBytes = new byte[v.InodeBytes];
            Buffer.BlockCopy(blockData, offsetInBlock, inodeBytes, 0, v.InodeBytes);

            if (!InodeChecksum(v, journalIno, inodeBytes)) return null;
            ushort mode = U16(inodeBytes, 0);
            if ((mode & 0xF000) != 0x8000) return null;

            var journalInode = new Inode
            {
                Number = journalIno,
                Bytes = inodeBytes,
                Flags = U32(inodeBytes, 0x20),
                Generation = U32(inodeBytes, 0x64),
                Size = U32(inodeBytes, 4) | ((ulong)U32(inodeBytes, 0x6C) << 32)
            };

            Mapping map = Map(c, v, journalInode);
            if (map.Failure != null || map.Runs.Count == 0) return JournalFailure(c, v, "journal_mapping_invalid");
            ulong journalBlocks = map.Runs.Aggregate(0UL, (total, run) => total + run.Count);
            if (journalBlocks > (ulong)c.Limits.MaximumJournalBlocks || journalInode.Size > (ulong)c.Limits.MaximumJournalBytes) {
                c.Report.Limited = true; return JournalFailure(c, v, "journal_size_limit");
            }

            var jc = new JournalContext { Volume = v, BlockBytes = (uint)v.BlockBytes };
            foreach (var run in map.Runs)
                for (ulong i = 0; i < run.Count; i++)
                    jc.Blocks.Add(run.Physical + i);

            if (jc.Blocks.Count < 2) return null;

            byte[] jsb = Block(c, v, jc.Blocks[0]);
            if (jsb == null || jsb.Length < 1024) return null;
            if (Be32(jsb, 0) != 0xC03B3998U) return null;
            uint blockType = Be32(jsb, 4);
            if (blockType != 3 && blockType != 4) return null;
            if (Be32(jsb, 0x0C) != (uint)v.BlockBytes) return null;

            jc.MaxLen = Be32(jsb, 0x10);
            jc.First = Be32(jsb, 0x14);
            jc.Sequence = Be32(jsb, 0x18);
            jc.Start = Be32(jsb, 0x1C);
            jc.Incompat = blockType == 4 ? Be32(jsb, 0x28) : 0;
            if (jc.First < 1 || jc.First >= jc.MaxLen || jc.MaxLen > (ulong)jc.Blocks.Count ||
                (jc.Start != 0 && (jc.Start < jc.First || jc.Start >= jc.MaxLen))) return JournalFailure(c, v, "journal_geometry_invalid");
            uint compat = blockType == 4 ? Be32(jsb, 0x24) : 0;
            uint roCompat = blockType == 4 ? Be32(jsb, 0x2c) : 0;
            if ((jc.Incompat & 0x20) != 0) return JournalFailure(c, v, "journal_fast_commit_unsupported");
            if ((jc.Incompat & ~0x1fU) != 0 || (compat & ~1U) != 0 || roCompat != 0)
                return JournalFailure(c, v, "journal_unknown_features");

            jc.Is64Bit = (jc.Incompat & 0x2) != 0;
            jc.HasCsumV1 = (compat & 1) != 0;
            jc.HasCsumV2 = (jc.Incompat & 0x8) != 0;
            jc.HasCsumV3 = (jc.Incompat & 0x10) != 0;
            if ((jc.HasCsumV2 && jc.HasCsumV3) || (jc.HasCsumV1 && (jc.HasCsumV2 || jc.HasCsumV3)) ||
                ((jc.Incompat & 4) != 0 && !jc.HasCsumV2 && !jc.HasCsumV3)) return JournalFailure(c, v, "journal_feature_combination_invalid");

            jc.Uuid = new byte[16];
            Buffer.BlockCopy(jsb, 0x30, jc.Uuid, 0, 16);
            if (!jc.Uuid.SequenceEqual(v.Uuid)) return JournalFailure(c, v, "journal_uuid_mismatch");
            jc.Seed = Crc(0xffffffff, jc.Uuid, 0, 16);

            if (jc.HasCsumV2 || jc.HasCsumV3)
            {
                if (jsb[0x50] != 4) return JournalFailure(c, v, "journal_checksum_type_unsupported");
                byte[] copy = new byte[1024];
                Buffer.BlockCopy(jsb, 0, copy, 0, 1024);
                copy[0xFC] = copy[0xFD] = copy[0xFE] = copy[0xFF] = 0;
                uint calcCsum = Crc(0xFFFFFFFF, copy, 0, 1024);
                if (calcCsum != Be32(jsb, 0xFC)) return JournalFailure(c, v, "journal_superblock_checksum_invalid");
            }

            v.Report.JournalStatus = "validated_superblock";
            v.Journal = jc;
            return v.Journal;
        }

        static JournalContext JournalFailure(Context c, Volume v, string reason)
        {
            v.Report.JournalStatus = reason;
            if (reason.EndsWith("_unsupported", StringComparison.Ordinal) || reason == "journal_unknown_features")
                v.Report.UnsupportedFeatures.Add(reason);
            Skip(c, reason);
            return null;
        }

        static byte[] JournalBlock(Context c, JournalContext jc, uint logical)
        {
            if (logical >= jc.MaxLen) return null;
            return Read(c, jc.Volume.Offset + (long)jc.Blocks[(int)logical] * jc.BlockBytes, (int)jc.BlockBytes);
        }

        static bool JournalMetadataChecksum(JournalContext jc, byte[] block, int checksumOffset)
        {
            if (!jc.HasCsumV2 && !jc.HasCsumV3) return true;
            uint provided = Be32(block, checksumOffset);
            byte[] copy = (byte[])block.Clone();
            Array.Clear(copy, checksumOffset, 4);
            return Crc(jc.Seed, copy, 0, copy.Length) == provided;
        }

        static List<JournalTag> ParseDescriptorTags(byte[] descBlock, JournalContext jc)
        {
            var tags = new List<JournalTag>();
            int offset = 12;
            int limit = (int)jc.BlockBytes - (jc.HasCsumV3 || jc.HasCsumV2 ? 4 : 0);
            while (offset < limit)
            {
                ulong destBlock;
                uint flags, checksum = 0;
                int tagSize;
                if (jc.HasCsumV3)
                {
                    if (offset + 16 > limit) break;
                    uint blockLow = Be32(descBlock, offset);
                    // Linux recovery reads the shared be16 t_flags at +6,
                    // including for tag3. Its upper 16 bits are reserved; the
                    // native e2fsprogs writer can leave nonzero bytes there.
                    flags = (uint)(descBlock[offset + 6] << 8 | descBlock[offset + 7]);
                    uint blockHigh = Be32(descBlock, offset + 8);
                    if (!jc.Is64Bit && blockHigh != 0) return null;
                    destBlock = ((ulong)blockHigh << 32) | (ulong)blockLow;
                    checksum = Be32(descBlock, offset + 12);
                    tagSize = 16;
                    if ((flags & 2) == 0) tagSize += 16;
                }
                else if (jc.HasCsumV2)
                {
                    int baseSize = jc.Is64Bit ? 12 : 8;
                    if (offset + baseSize > limit) break;
                    uint blockLow = Be32(descBlock, offset);
                    flags = (uint)(descBlock[offset + 6] << 8 | descBlock[offset + 7]);
                    checksum = (uint)(descBlock[offset + 4] << 8 | descBlock[offset + 5]);
                    uint blockHigh = jc.Is64Bit ? Be32(descBlock, offset + 8) : 0;
                    destBlock = jc.Is64Bit ? (((ulong)blockHigh << 32) | (ulong)blockLow) : (ulong)blockLow;
                    tagSize = baseSize;
                    if ((flags & 2) == 0) tagSize += 16;
                }
                else
                {
                    int baseSize = jc.Is64Bit ? 12 : 8;
                    if (offset + baseSize > limit) break;
                    uint blockLow = Be32(descBlock, offset);
                    flags = Be32(descBlock, offset + 4);
                    uint blockHigh = jc.Is64Bit ? Be32(descBlock, offset + 8) : 0;
                    destBlock = jc.Is64Bit ? (((ulong)blockHigh << 32) | (ulong)blockLow) : (ulong)blockLow;
                    tagSize = baseSize;
                    if ((flags & 2) == 0) tagSize += 16;
                }
                if (offset + tagSize > limit || (flags & ~11U) != 0 || !BlockRange(jc.Volume, destBlock, 1)) return null;
                // Linux recovery skips the optional per-tag UUID. The journal
                // superblock UUID and checksum seed bind this internal journal.
                tags.Add(new JournalTag { DestinationBlock = destBlock, Flags = flags, Checksum = checksum });
                offset += tagSize;
                if ((flags & 8) != 0) return tags;
            }
            // A completely filled descriptor needs no LAST_TAG: JBD2 continues
            // in another descriptor after these data blocks (Linux count_tags).
            int minimumTag = jc.HasCsumV3 ? 16 : jc.Is64Bit ? 12 : 8;
            return tags.Count > 0 && limit - offset < minimumTag ? tags : null;
        }

        static uint Crc32BigEndian(uint crc, byte[] bytes)
        {
            foreach (byte value in bytes) {
                crc ^= (uint)value << 24;
                for (int bit = 0; bit < 8; bit++) crc = (crc << 1) ^ ((crc & 0x80000000) != 0 ? 0x04c11db7U : 0);
            }
            return crc;
        }

        static bool TryJournalTransaction(Context c, JournalContext jc, uint start, out JournalTransaction trans,
            out uint next, out string failure, ref long budget)
        {
            trans = new JournalTransaction(); next = start; failure = "journal_transaction_uncommitted";
            var visited = new HashSet<uint>(); uint oldChecksum = 0xffffffff;
            byte[] first = JournalBlock(c, jc, start);
            if (first == null) return false;
            trans.Sequence = Be32(first, 8);
            while (true) {
                c.Cancel.ThrowIfCancellationRequested();
                if (--budget < 0) { c.Report.Limited = true; failure = "journal_work_limit"; return false; }
                if (!visited.Add(next)) { failure = "journal_transaction_cycle"; return false; }
                byte[] block = JournalBlock(c, jc, next);
                if (block == null || Be32(block, 0) != 0xc03b3998 || Be32(block, 8) != trans.Sequence) return false;
                uint current = next, type = Be32(block, 4); next = NextJournalBlock(next, jc.First, jc.MaxLen);
                if (type == 2) {
                    if (!JournalMetadataChecksum(jc, block, 16) || (jc.HasCsumV1 &&
                        !(block[12] == 1 && block[13] == 4 && Be32(block, 16) == oldChecksum))) {
                        failure = "journal_commit_checksum_invalid"; return false;
                    }
                    trans.Committed = true; return true;
                }
                if (type == 5) {
                    trans.HeaderBlocks.Add(current);
                    if ((jc.Incompat & 1) == 0) { failure = "journal_revoke_feature_missing"; return false; }
                    if (!JournalMetadataChecksum(jc, block, block.Length - 4)) { failure = "journal_revoke_checksum_invalid"; return false; }
                    uint count = Be32(block, 12); int width = jc.Is64Bit ? 8 : 4;
                    int limit = block.Length - (jc.HasCsumV2 || jc.HasCsumV3 ? 4 : 0);
                    if (count < 16 || count > limit || (count - 16) % width != 0) { failure = "journal_revoke_bounds"; return false; }
                    for (int at = 16; at < count; at += width) {
                        ulong revoked = jc.Is64Bit ? Be64(block, at) : Be32(block, at);
                        if (!BlockRange(jc.Volume, revoked, 1)) { failure = "journal_revoke_bounds"; return false; }
                        trans.RevokedBlocks.Add(revoked);
                    }
                    continue;
                }
                if (type != 1) return false;
                trans.HeaderBlocks.Add(current);
                if (!JournalMetadataChecksum(jc, block, block.Length - 4)) { failure = "journal_descriptor_checksum_invalid"; return false; }
                var tags = ParseDescriptorTags(block, jc);
                if (tags == null || tags.Count == 0) { failure = "journal_descriptor_tags_invalid"; return false; }
                if (jc.HasCsumV1) oldChecksum = Crc32BigEndian(oldChecksum, block);
                foreach (JournalTag tag in tags) {
                    if (--budget < 0) { c.Report.Limited = true; failure = "journal_work_limit"; return false; }
                    if (!visited.Add(next)) { failure = "journal_transaction_cycle"; return false; }
                    byte[] data = JournalBlock(c, jc, next);
                    if (data == null) return false;
                    if (jc.HasCsumV2 || jc.HasCsumV3) {
                        byte[] sequence = { (byte)(trans.Sequence >> 24), (byte)(trans.Sequence >> 16), (byte)(trans.Sequence >> 8), (byte)trans.Sequence };
                        uint checksum = Crc(Crc(jc.Seed, sequence, 0, 4), data, 0, data.Length);
                        if ((jc.HasCsumV3 ? checksum : checksum & 65535) != tag.Checksum) { failure = "journal_data_checksum_invalid"; return false; }
                    }
                    if (jc.HasCsumV1) oldChecksum = Crc32BigEndian(oldChecksum, data);
                    trans.DataBlocks.Add(Tuple.Create(tag, jc.Blocks[(int)next]));
                    next = NextJournalBlock(next, jc.First, jc.MaxLen);
                }
            }
        }

        static bool SequenceAtOrAfter(uint sequence, uint other) { return unchecked((int)(sequence - other)) >= 0; }

        static Dictionary<ulong, uint> JournalRevokes(IEnumerable<JournalTransaction> transactions)
        {
            var revokes = new Dictionary<ulong, uint>();
            foreach (var transaction in transactions) foreach (ulong block in transaction.RevokedBlocks) {
                uint previous;
                if (!revokes.TryGetValue(block, out previous) || SequenceAtOrAfter(transaction.Sequence, previous)) revokes[block] = transaction.Sequence;
            }
            return revokes;
        }

        static void ReplayJournal(Context c, JournalContext jc)
        {
            Volume v = jc.Volume;
            v.JournalReplayAttempted = true;
            v.Report.JournalReplayAttempted = true;
            if (jc.Start == 0 || jc.Start >= jc.MaxLen) return;

            uint cur = jc.Start;
            uint expectedSeq = jc.Sequence;
            var committed = new List<JournalTransaction>();
            int maxScan = (int)(jc.MaxLen - jc.First);
            long budget = (long)maxScan * 2;

            for (int step = 0; step < maxScan && cur < (uint)jc.Blocks.Count; step++)
            {
                c.Cancel.ThrowIfCancellationRequested();
                byte[] blk = JournalBlock(c, jc, cur);
                if (blk == null || Be32(blk, 0) != 0xC03B3998U) break;
                uint seq = Be32(blk, 8);
                if (seq != expectedSeq) break;

                JournalTransaction trans; string failure; uint next;
                if (!TryJournalTransaction(c, jc, cur, out trans, out next, out failure, ref budget)) {
                    Skip(c, failure); v.Report.JournalStatus = failure;
                    // An unfinished tail is normal; a damaged committed log cannot
                    // establish authoritative current allocation state.
                    if (failure != "journal_transaction_uncommitted") { v.Overlay.Clear(); return; }
                    break;
                }
                cur = next;
                committed.Add(trans);
                expectedSeq++;
            }

            if (committed.Count == 0) return;

            var revokeTable = JournalRevokes(committed);

            foreach (var trans in committed)
            {
                foreach (var item in trans.DataBlocks)
                {
                    ulong dest = item.Item1.DestinationBlock;
                    uint flags = item.Item1.Flags;
                    ulong phys = item.Item2;

                    uint revSeq;
                    if (revokeTable.TryGetValue(dest, out revSeq) && SequenceAtOrAfter(revSeq, trans.Sequence))
                        continue;

                    if (!BlockRange(v, dest, 1)) continue;
                    byte[] data = Read(c, v.Offset + (long)phys * v.BlockBytes, v.BlockBytes);
                    if (data == null) continue;

                    byte[] replayed = (byte[])data.Clone();
                    if ((flags & 1) != 0)
                    {
                        replayed[0] = 0xC0; replayed[1] = 0x3B; replayed[2] = 0x39; replayed[3] = 0x98;
                    }
                    v.Overlay[dest] = replayed;
                }
            }
            v.JournalReplayApplied = true;
            v.Report.JournalReplayApplied = true;
            v.Report.JournalStatus = "committed_transactions_replayed_in_memory";
        }

        static Group FindInodeTableGroup(Volume v, ulong block)
        {
            foreach (Group g in v.Groups)
            {
                if (!g.Valid) continue;
                ulong tableBlocks = ((ulong)v.InodesPerGroup * (uint)v.InodeBytes + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes;
                if (block >= g.InodeTable && block < g.InodeTable + tableBlocks) return g;
            }
            return null;
        }

        static void SweepJournalHistory(Context c, Volume v, JournalContext jc,
            out Dictionary<uint, HistoricalCandidate> historicalInodes,
            out List<Tuple<ulong, byte[]>> journalDirBlocks)
        {
            historicalInodes = new Dictionary<uint, HistoricalCandidate>();
            journalDirBlocks = new List<Tuple<ulong, byte[]>>();
            if (jc == null || jc.Blocks.Count < 2) return;

            var starts = new Dictionary<uint, List<uint>>();
            for (uint logBlk = jc.First; logBlk < jc.MaxLen; logBlk++)
            {
                c.Cancel.ThrowIfCancellationRequested();
                byte[] hblk = JournalBlock(c, jc, logBlk);
                if (hblk == null || Be32(hblk, 0) != 0xc03b3998 || (Be32(hblk, 4) != 1 && Be32(hblk, 4) != 5)) continue;
                uint sequence = Be32(hblk, 8); List<uint> positions;
                if (!starts.TryGetValue(sequence, out positions)) starts[sequence] = positions = new List<uint>();
                positions.Add(logBlk);
            }
            var transactions = new List<JournalTransaction>();
            long budget = (long)(jc.MaxLen - jc.First) * 4;
            foreach (var candidate in starts) {
                foreach (uint start in candidate.Value) {
                    JournalTransaction transaction; uint next; string failure;
                    if (TryJournalTransaction(c, jc, start, out transaction, out next, out failure, ref budget) &&
                        transaction.HeaderBlocks.SetEquals(candidate.Value)) {
                        transactions.Add(transaction); break;
                    }
                    if (budget < 0) { Skip(c, "journal_work_limit"); return; }
                    Skip(c, failure);
                }
            }
            var revokes = JournalRevokes(transactions);
            foreach (JournalTransaction transaction in transactions) {
                uint seq = transaction.Sequence;

                foreach (var item in transaction.DataBlocks)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    JournalTag tag = item.Item1;
                    ulong dataPhys = item.Item2;
                    ulong targetDiskBlk = tag.DestinationBlock;
                    uint revokedAt;
                    if (revokes.TryGetValue(targetDiskBlk, out revokedAt) && SequenceAtOrAfter(revokedAt, seq)) continue;
                    bool isEscaped = (tag.Flags & 1) != 0;

                    Group ownerGroup = FindInodeTableGroup(v, targetDiskBlk);
                    if (ownerGroup != null)
                    {
                        byte[] data = Read(c, v.Offset + (long)dataPhys * v.BlockBytes, v.BlockBytes);
                        if (data == null) continue;
                        if (isEscaped)
                        {
                            data = (byte[])data.Clone();
                            data[0] = 0xC0; data[1] = 0x3B; data[2] = 0x39; data[3] = 0x98;
                        }

                        ulong blkOffset = targetDiskBlk - ownerGroup.InodeTable;
                        uint inodesPerBlock = (uint)(v.BlockBytes / v.InodeBytes);
                        uint firstIno = ownerGroup.Number * v.InodesPerGroup + (uint)blkOffset * inodesPerBlock + 1;
                        uint count = Math.Min(inodesPerBlock, v.InodesPerGroup - (uint)blkOffset * inodesPerBlock);

                        for (uint m = 0; m < count; m++)
                        {
                            uint inoNumber = firstIno + m;
                            if (inoNumber < Math.Max(11, v.FirstInode) || inoNumber > v.Inodes) continue;

                            int inoAt = (int)(m * v.InodeBytes);
                            byte[] inoBytes = new byte[v.InodeBytes];
                            Buffer.BlockCopy(data, inoAt, inoBytes, 0, v.InodeBytes);

                            ushort mode = U16(inoBytes, 0);
                            if ((mode & 0xF000) != 0x8000) continue;
                            if (!InodeChecksum(v, inoNumber, inoBytes)) continue;

                            ulong size = U32(inoBytes, 4) | ((ulong)U32(inoBytes, 0x6C) << 32);
                            if (size == 0 || size > (ulong)c.Limits.MaximumFileBytes) continue;

                            uint flags = U32(inoBytes, 0x20);
                            if ((flags & (0x800U | 0x10000000U | 4U | 0x100000U | 0x200000U)) != 0) continue;

                            bool hasExtents = (flags & 0x80000) != 0;
                            if (hasExtents)
                            {
                                if (U16(inoBytes, 0x28) != 0xF30A || U16(inoBytes, 0x28 + 2) == 0) continue;
                            }
                            else
                            {
                                if (U32(inoBytes, 0x28) == 0) continue;
                            }

                            HistoricalCandidate existing;
                            if (!historicalInodes.TryGetValue(inoNumber, out existing) || SequenceAtOrAfter(seq, existing.TransactionSeq))
                            {
                                historicalInodes[inoNumber] = new HistoricalCandidate
                                {
                                    Number = inoNumber,
                                    TransactionSeq = seq,
                                    JournalBlock = dataPhys,
                                    TargetDiskBlock = targetDiskBlk,
                                    OffsetInBlock = inoAt,
                                    Mode = mode,
                                    Links = U16(inoBytes, 0x1A),
                                    Dtime = U32(inoBytes, 0x14),
                                    Flags = flags,
                                    Generation = U32(inoBytes, 0x64),
                                    Size = size,
                                    InodeBytes = inoBytes
                                };
                            }
                        }
                    }
                    else
                    {
                        byte[] data = Read(c, v.Offset + (long)dataPhys * v.BlockBytes, v.BlockBytes);
                        if (data == null) continue;
                        if (isEscaped)
                        {
                            data = (byte[])data.Clone();
                            data[0] = 0xC0; data[1] = 0x3B; data[2] = 0x39; data[3] = 0x98;
                        }
                        if (IsDirectoryBlock(data))
                        {
                            journalDirBlocks.Add(Tuple.Create(targetDiskBlk, data));
                        }
                    }
                }
            }
        }

        static bool IsDirectoryBlock(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 24) return false;
            if (bytes[6] == 1 && bytes[8] == '.' && bytes[18] == 2 && bytes[20] == '.' && bytes[21] == '.') return true;
            int tail = bytes.Length - 12;
            if (U32(bytes, tail) == 0 && U16(bytes, tail + 4) == 12 && bytes[tail + 6] == 0 && bytes[tail + 7] == 0xDE) return true;
            return false;
        }

        static bool IsCandidateDeletedInLiveFs(Context c, Volume v, HistoricalCandidate candidate)
        {
            uint grpIdx = (candidate.Number - 1) / v.InodesPerGroup;
            uint idxInGrp = (candidate.Number - 1) % v.InodesPerGroup;
            if (grpIdx >= (uint)v.Groups.Count) return false;
            Group group = v.Groups[(int)grpIdx];
            if (!group.Valid || !group.InodeMapValid) return false;

            if (!Bit(group.Inodes, idxInGrp)) return true;

            ulong tableBlock = group.InodeTable + (ulong)(((long)idxInGrp * v.InodeBytes) / v.BlockBytes);
            int offsetInBlock = (int)(((long)idxInGrp * v.InodeBytes) % v.BlockBytes);
            byte[] blockData = Block(c, v, tableBlock);
            if (blockData != null && blockData.Length >= offsetInBlock + v.InodeBytes)
            {
                byte[] liveBytes = new byte[v.InodeBytes];
                Buffer.BlockCopy(blockData, offsetInBlock, liveBytes, 0, v.InodeBytes);
                if (!InodeChecksum(v, candidate.Number, liveBytes)) return false;
                uint liveGen = U32(liveBytes, 0x64);
                // Truncation/zero links in an allocated inode do not prove that
                // a historical incarnation was deleted. Reuse needs a valid
                // current inode checksum and a different generation.
                return liveGen != candidate.Generation;
            }
            return false;
        }
        static byte[] Read(Context c, long offset, int bytes)
        {
            c.Cancel.ThrowIfCancellationRequested(); if (offset < 0 || bytes < 0 || offset > c.Input.Length - bytes) return null;
            byte[] buffer = new byte[bytes]; c.Input.Position = offset; int at = 0;
            while (at < bytes) { int n = c.Input.Read(buffer, at, bytes - at); if (n == 0) return null; at += n; } return buffer;
        }
        static List<long> Discover(FileStream input)
        {
            var positions = new List<long> { 0 }; byte[] mbr = new byte[512]; input.Position = 0;
            if (input.Read(mbr, 0, 512) != 512 || U16(mbr, 510) != 0xaa55) return positions;
            for (int i = 0; i < 4; i++) { long offset = (long)U32(mbr, 446 + i * 16 + 8) * 512; if (offset > 0 && offset <= input.Length - 2048) positions.Add(offset); }
            // GPT entries are merely candidate locations; the ext4 superblock,
            // descriptor and inode checksums still validate every read target.
            byte[] header = new byte[512]; input.Position = 512;
            if (input.Read(header, 0, 512) == 512 && Encoding.ASCII.GetString(header, 0, 8) == "EFI PART") {
                ulong table = U64(header, 72); uint count = U32(header, 80), size = U32(header, 84);
                if (table <= (ulong)(input.Length / 512) && count <= 16384 && size >= 128 && size <= 4096 && (ulong)count * size <= (ulong)input.Length - table * 512) {
                    byte[] entry = new byte[size];
                    for (uint i = 0; i < count; i++) { input.Position = (long)table * 512 + (long)i * size; if (input.Read(entry, 0, entry.Length) != entry.Length) break;
                        ulong lba = U64(entry, 32); if (entry.Take(16).Any(x => x != 0) && lba > 0 && lba <= (ulong)((input.Length - 2048) / 512)) positions.Add((long)lba * 512); }
                }
            }
            return positions.Distinct().ToList();
        }
        static string LocalFile(string file)
        {
            string path = Path.GetFullPath(file); if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.IndexOf(':', 2) >= 0 || !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.Directory) != 0) throw new IOException("Требуется обычный локальный образ ext4");
            NoLinks(path); return path;
        }
        static void NoLinks(string path)
        {
            string current = Path.GetFullPath(path);
            while (!String.IsNullOrEmpty(current)) {
                try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Ссылки в пути ext4 запрещены"); }
                catch (FileNotFoundException) { } catch (DirectoryNotFoundException) { }
                string parent = Path.GetDirectoryName(current); if (parent == current) break; current = parent; }
        }
        static string HashStream(FileStream stream, CancellationToken cancel)
        {
            stream.Position = 0; using (var hash = SHA256.Create()) { byte[] b = new byte[1024 * 1024]; int n;
                while ((n = stream.Read(b, 0, b.Length)) > 0) { cancel.ThrowIfCancellationRequested(); hash.TransformBlock(b, 0, n, b, 0); }
                hash.TransformFinalBlock(new byte[0], 0, 0); return Hex(hash.Hash); }
        }
        static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
        static void Skip(Context c, string reason) { int n; c.Report.Skipped.TryGetValue(reason, out n); c.Report.Skipped[reason] = n + 1; }
        static bool Bit(byte[] bytes, uint bit) { return bytes != null && bit / 8 < bytes.Length && (bytes[bit / 8] & (1 << (int)(bit & 7))) != 0; }
        static ushort U16(byte[] b, int at) { return BitConverter.ToUInt16(b, at); }
        static uint U32(byte[] b, int at) { return BitConverter.ToUInt32(b, at); }
        static ulong U64(byte[] b, int at) { return BitConverter.ToUInt64(b, at); }
        static ulong Wide(byte[] b, int low, int high) { return U32(b, low) | (b.Length >= high + 4 ? (ulong)U32(b, high) << 32 : 0); }
        static uint[] MakeCrcTable() { var table = new uint[256]; for (uint i = 0; i < 256; i++) { uint x = i; for (int n = 0; n < 8; n++) x = (x >> 1) ^ ((x & 1) != 0 ? 0x82f63b78U : 0); table[i] = x; } return table; }
        static uint Crc(uint seed, byte[] bytes, int start, int count) { for (int i = start; i < start + count; i++) seed = CrcTable[(seed ^ bytes[i]) & 255] ^ (seed >> 8); return seed; }
        static ushort Crc16(ushort seed, byte[] bytes, int start, int count) { uint crc = seed; for (int i = start; i < start + count; i++) { crc ^= bytes[i]; for (int n = 0; n < 8; n++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xa001U : 0); } return (ushort)crc; }
    }
}
