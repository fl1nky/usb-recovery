using System;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        // Current and journal candidates share mapping, allocation and output
        // budget checks. Their deletion evidence and names remain distinct.
        static bool PrepareMappedEntry(Context c, Volume v, Inode inode, Entry entry)
        {
            Mapping map = Map(c, v, inode);
            entry.Mapping = map.Kind;
            entry.MappingIntegrity = map.Kind == "direct_indirect"
                ? "inode_only_indirect_blocks_have_no_checksum"
                : v.Csum ? "inode_and_extent_nodes_crc32c" : "structural_only_no_metadata_checksum";
            if (map.Failure != null)
            {
                entry.Reason = map.Failure;
                Skip(c, map.Failure);
                return false;
            }

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
                return false;
            }
            if ((long)inode.Size > c.Limits.MaximumOutputBytes - c.Report.OutputBytes)
            {
                c.Report.Limited = true;
                entry.Reason = "output_limit";
                return false;
            }
            return true;
        }
    }
}
