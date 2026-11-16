using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class JournalDirectoryBlock
        {
            public ulong TargetDiskBlock, JournalBlock;
            public uint TransactionSequence;
            public byte[] Bytes;
        }

        static bool AddDirectoryLink(Context c, Dictionary<uint, List<NameLink>> links, NameLink link, bool historical)
        {
            List<NameLink> existing;
            links.TryGetValue(link.TargetInode, out existing);
            if (historical && existing != null && existing.Any(x =>
                x.Status == link.Status && x.DirectoryInode == link.DirectoryInode &&
                x.EntryOffset == link.EntryOffset && x.TargetBlockOffset == link.TargetBlockOffset &&
                x.JournalTransactionSequence == link.JournalTransactionSequence && x.Name == link.Name))
                return true;
            if (c.NameCount >= c.Limits.MaximumNames)
            {
                c.Report.Limited = true;
                Skip(c, "directory_name_limit");
                return false;
            }
            if (existing == null)
            {
                existing = new List<NameLink>();
                links.Add(link.TargetInode, existing);
            }
            existing.Add(link);
            c.NameCount++;
            return true;
        }
        static Dictionary<uint, List<NameLink>> DirectoryNames(Context c, Volume v, Dictionary<uint, Inode> directories, List<JournalDirectoryBlock> journalDirBlocks = null)
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
                        if (!AddDirectoryLink(c, links, link, false)) return links;
                    }
                }
            }
            if (journalDirBlocks != null)
            {
                foreach (var jdb in journalDirBlocks)
                {
                    c.Cancel.ThrowIfCancellationRequested();
                    byte[] bytes = jdb.Bytes;
                    if (bytes == null || bytes.Length < 12) continue;
                    int end = bytes.Length;
                    if (v.Csum)
                    {
                        int tail = bytes.Length - 12;
                        if (U32(bytes, tail) == 0 && U16(bytes, tail + 4) == 12 && bytes[tail + 6] == 0 && bytes[tail + 7] == 0xDE)
                        {
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
                        c.Cancel.ThrowIfCancellationRequested();
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
                                    var link = new NameLink
                                    {
                                        DirectoryInode = dirIno,
                                        TargetInode = target,
                                        Name = name,
                                        EntryOffset = v.Offset + (long)jdb.JournalBlock * v.BlockBytes + at,
                                        JournalBlockOffset = v.Offset + (long)jdb.JournalBlock * v.BlockBytes,
                                        TargetBlockOffset = v.Offset + (long)jdb.TargetDiskBlock * v.BlockBytes,
                                        JournalTransactionSequence = jdb.TransactionSequence,
                                        // JBD2 checksums cover journal bytes, not the separate
                                        // inode/generation-seeded ext4 directory checksum.
                                        DirectoryChecksumVerified = false,
                                        Status = "historical_journal_directory_reference"
                                    };
                                    if (!AddDirectoryLink(c, links, link, true)) return links;
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
                    if (!links.TryGetValue(number, out names)) continue;
                    names = names.Where(x => x.Status == "validated_directory_reference_no_inode_generation").ToList();
                    if (names.Count != 1 || !directoryPaths.ContainsKey(names[0].DirectoryInode)) continue;
                    string path = directoryPaths[names[0].DirectoryInode] + names[0].Name + "/"; if (path.Length > 32768) continue;
                    directoryPaths[number] = path; changed = true;
                }
                if (!changed) break;
            }
            foreach (List<NameLink> names in links.Values) foreach (NameLink name in names) {
                string path;
                if (name.Status != "historical_journal_directory_reference" && directoryPaths.TryGetValue(name.DirectoryInode, out path)) name.DirectoryPath = path;
            }
            return links;
        }

    }
}
