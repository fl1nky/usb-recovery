using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        // A complete group is the initialization unit. Reading/checksumming it
        // must not acknowledge a half-read group or change shared counters.
        sealed class GroupMetadataUnit
        {
            public Group Group;
            public readonly List<string> Diagnostics = new List<string>();
        }

        static GroupMetadataUnit ReadGroupMetadata(Context c, Volume v, ulong gdStart,
            uint number, List<Range> fixedReserved)
        {
            c.Cancel.ThrowIfCancellationRequested();
            var unit = new GroupMetadataUnit { Group = new Group { Number = number } };
            Group group = unit.Group;
            byte[] desc = GroupDescriptor(c, v, gdStart, number);
            group.Descriptor = desc;
            if (desc == null) throw new EndOfStreamException("EXT4_GROUP_DESCRIPTOR_SHORT_READ");
            if (!GroupChecksum(v, number, desc))
            {
                unit.Diagnostics.Add("group_descriptor_checksum_invalid");
                return unit;
            }
            group.BlockBitmap = Wide(desc, 0, 0x20);
            group.InodeBitmap = Wide(desc, 4, 0x24);
            group.InodeTable = Wide(desc, 8, 0x28);
            group.Flags = U16(desc, 0x12);
            if ((group.Flags & ~7) != 0)
            {
                unit.Diagnostics.Add("group_flags_unsupported");
                return unit;
            }
            ulong tableBlocks = ((ulong)v.InodesPerGroup * (uint)v.InodeBytes + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes;
            if (group.BlockBitmap == 0 || group.InodeBitmap == 0 || group.InodeTable == 0 ||
                !BlockRange(v, group.BlockBitmap, 1) || !BlockRange(v, group.InodeBitmap, 1) ||
                !BlockRange(v, group.InodeTable, tableBlocks) || group.BlockBitmap == group.InodeBitmap ||
                (group.BlockBitmap >= group.InodeTable && group.BlockBitmap - group.InodeTable < tableBlocks) ||
                (group.InodeBitmap >= group.InodeTable && group.InodeBitmap - group.InodeTable < tableBlocks))
            {
                unit.Diagnostics.Add("group_metadata_bounds_or_overlap");
                return unit;
            }
            if (fixedReserved.Any(x => Overlap(x, group.BlockBitmap, 1) ||
                Overlap(x, group.InodeBitmap, 1) || Overlap(x, group.InodeTable, tableBlocks)))
            {
                unit.Diagnostics.Add("group_metadata_overlaps_super_or_gdt");
                return unit;
            }
            group.Valid = true;
            if ((group.Flags & 1) == 0)
            {
                group.Inodes = RequiredGroupBlock(c, v, group.InodeBitmap);
                group.InodeMapValid = BitmapChecksum(v, group, group.Inodes, true);
            }
            if ((group.Flags & 2) == 0)
            {
                group.Blocks = RequiredGroupBlock(c, v, group.BlockBitmap);
                group.BlockMapValid = BitmapChecksum(v, group, group.Blocks, false);
            }
            if (!group.InodeMapValid) unit.Diagnostics.Add("inode_bitmap_uninitialized_or_invalid");
            if (!group.BlockMapValid) unit.Diagnostics.Add("block_bitmap_uninitialized_or_invalid");
            c.Cancel.ThrowIfCancellationRequested();
            return unit;
        }

        static byte[] RequiredGroupBlock(Context c, Volume v, ulong block)
        {
            byte[] bytes = Block(c, v, block);
            if (bytes == null) throw new EndOfStreamException("EXT4_GROUP_BITMAP_SHORT_READ");
            return bytes;
        }

        static void ApplyGroupMetadata(Context c, Volume v, GroupMetadataUnit unit)
        {
            c.Cancel.ThrowIfCancellationRequested();
            Group group = unit.Group;
            if (group.Number != (uint)v.Groups.Count) throw new InvalidOperationException("EXT4_GROUP_PREFIX_INVALID");
            v.Groups.Add(group);
            if (group.Valid)
            {
                v.Report.CheckedGroups++;
                v.Reserved.Add(new Range { Start = group.BlockBitmap, Length = 1 });
                v.Reserved.Add(new Range { Start = group.InodeBitmap, Length = 1 });
                v.Reserved.Add(new Range { Start = group.InodeTable,
                    Length = ((ulong)v.InodesPerGroup * (uint)v.InodeBytes + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes });
            }
            foreach (string diagnostic in unit.Diagnostics) Skip(c, diagnostic);
        }

        static void ValidateGroupOverlaps(Context c, Volume v)
        {
            var areas = new List<MetadataArea>();
            foreach (Group group in v.Groups.Where(x => x.Valid))
            {
                areas.Add(new MetadataArea { Owner = group, Start = group.BlockBitmap, Length = 1 });
                areas.Add(new MetadataArea { Owner = group, Start = group.InodeBitmap, Length = 1 });
                areas.Add(new MetadataArea { Owner = group, Start = group.InodeTable,
                    Length = ((ulong)v.InodesPerGroup * (uint)v.InodeBytes + (uint)v.BlockBytes - 1) / (uint)v.BlockBytes });
            }
            MetadataArea previous = null;
            foreach (MetadataArea area in areas.OrderBy(x => x.Start))
            {
                c.Cancel.ThrowIfCancellationRequested();
                if (previous != null && area.Start < previous.Start + previous.Length)
                {
                    area.Owner.Valid = previous.Owner.Valid = false;
                    Skip(c, "cross_group_metadata_overlap");
                }
                if (previous == null || area.Start + area.Length > previous.Start + previous.Length) previous = area;
            }
        }
    }
}
