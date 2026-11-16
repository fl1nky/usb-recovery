using System;
using System.Collections.Generic;
using System.IO;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        const int MaximumAllocationUnitBlocks = 4096;
        sealed class AllocationSpan { public long At; public ulong Block, Count; public bool Tree; }
        sealed class AllocationCheck { public long Start; public int Count; public string Failure; }

        static List<AllocationSpan> AllocationSpans(Mapping map, out long total)
        {
            var spans = new List<AllocationSpan>(); total = 0;
            foreach (ulong block in map.TreeBlocks)
            { spans.Add(new AllocationSpan { At = total, Block = block, Count = 1, Tree = true }); total++; }
            foreach (var run in map.Runs)
            {
                if (run.Count == 0 || run.Count > (ulong)(Int64.MaxValue - total)) throw new IOException("EXT4_ALLOCATION_RANGE_INVALID");
                spans.Add(new AllocationSpan { At = total, Block = run.Physical, Count = run.Count }); total += (long)run.Count;
            }
            return spans;
        }
        // The already validated bitmap is in memory. Scan bytes with boundary
        // masks rather than doing a group lookup for every individual block.
        static string CheckFreeSpan(Context c, Volume v, ulong block, ulong count, out ulong passed)
        {
            passed = 0;
            if (v.BlocksPerGroup == 0 || !BlockRange(v, block, count)) throw new IOException("EXT4_ALLOCATION_RANGE_INVALID");
            while (passed < count)
            {
                c.Cancel.ThrowIfCancellationRequested(); ulong current = block + passed;
                ulong groupIndex = (current - v.FirstData) / v.BlocksPerGroup;
                if (groupIndex >= (ulong)v.Groups.Count) return "allocation_group_out_of_bounds";
                var group = v.Groups[(int)groupIndex];
                if (!group.Valid || !group.BlockMapValid || group.Blocks == null) return "allocation_bitmap_unknown_or_invalid";
                ulong bit = (current - v.FirstData) % v.BlocksPerGroup;
                ulong take = Math.Min(count - passed, v.BlocksPerGroup - bit), consumed = 0;
                while (consumed < take)
                {
                    c.Cancel.ThrowIfCancellationRequested(); ulong at = bit + consumed; int first = (int)(at & 7);
                    int bits = (int)Math.Min(8 - first, (long)(take - consumed));
                    if (at / 8 >= (ulong)group.Blocks.Length) { passed += consumed; return "allocation_bitmap_unknown_or_invalid"; }
                    int set = group.Blocks[(int)(at / 8)] & (((1 << bits) - 1) << first);
                    if (set != 0)
                    {
                        int offset = 0; while ((set & (1 << (first + offset))) == 0) offset++;
                        passed += consumed + (uint)offset; return "currently_allocated_block_conflict";
                    }
                    consumed += (uint)bits;
                }
                passed += take;
            }
            return null;
        }
        static AllocationCheck CheckAllocationUnit(Context c, Volume v, List<AllocationSpan> spans, long total, long start, int maximum)
        {
            if (start < 0 || start >= total || maximum < 1 || maximum > MaximumAllocationUnitBlocks)
                throw new IOException("EXT4_ALLOCATION_CURSOR_INVALID");
            var result = new AllocationCheck { Start = start }; long next = start;
            int low = 0, high = spans.Count - 1;
            while (low < high) { int middle = low + (high - low + 1) / 2; if (spans[middle].At <= start) low = middle; else high = middle - 1; }
            for (int index = low; index < spans.Count && result.Count < maximum; index++)
            {
                var span = spans[index]; ulong within = (ulong)(next - span.At);
                int count = (int)Math.Min(span.Count - within, (ulong)(maximum - result.Count)); ulong passed;
                string failure = CheckFreeSpan(c, v, span.Block + within, (uint)count, out passed);
                if (failure != null)
                {
                    result.Count += (int)passed + 1;
                    result.Failure = span.Tree ? "mapping_" + failure : failure; return result;
                }
                result.Count += count; next += count;
            }
            if (result.Count < 1 || next > total) throw new IOException("EXT4_ALLOCATION_CURSOR_INVALID");
            return result;
        }
        static string CheckCandidateAllocation(Context c, Volume v, Mapping map, CandidatePreparationCheckpoint checkpoint)
        {
            int maximum = c.Limits.AllocationBlocksPerCheckpoint;
            if (maximum < 1 || maximum > MaximumAllocationUnitBlocks) throw new IOException("EXT4_ALLOCATION_UNIT_LIMIT_INVALID");
            long total; var spans = AllocationSpans(map, out total); long next = 0;
            while (next < total)
            {
                // Revalidate saved results against bound, cached bitmap bytes.
                // Neither saved units nor new checks read the source bitmap again.
                var result = CheckAllocationUnit(c, v, spans, total, next, maximum);
                if (checkpoint != null) checkpoint.ConfirmAllocation(result);
                next += result.Count; if (result.Failure != null) return result.Failure;
            }
            return v.Csum ? "currently_free" : "currently_free_unchecksummed_bitmap";
        }
    }
}
