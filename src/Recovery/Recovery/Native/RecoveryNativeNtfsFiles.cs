// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    internal sealed class RecoveryNativeNtfsFilePart
    {
        internal long LogicalOffset;
        internal RecoveryMappedFilePlan Plan;
    }
    internal sealed class RecoveryNativeNtfsFile
    {
        internal string Status;
        internal long LogicalBytes, MappedBytes, MissingBytes;
        internal readonly List<RecoveryNativeNtfsFilePart> Parts = new List<RecoveryNativeNtfsFilePart>();
    }

    // Unknown run segments become gaps in the result map, never fabricated
    // zero-filled messages or photos. Known sparse/uninitialized bytes are zeroes.
    // Partial streams retain every available logical interval as a separate file.
    internal static class RecoveryNativeNtfsFiles
    {
        internal static RecoveryNativeNtfsFile Build(RecoveryNativeNtfsRecord record, RecoveryNativeNtfsStream stream,
            long volumeOffset, long volumeBytes, int clusterBytes, string archiveRoot, string outputRoot, long maximumBytes)
        {
            if (record == null || stream == null || record.Ordinal != stream.Ordinal || stream.Index >= record.Streams ||
                stream.Length < 0 || stream.Length > maximumBytes || maximumBytes < 0 || stream.Initialized < 0 ||
                stream.Initialized > stream.Length || clusterBytes < 512 || (clusterBytes & (clusterBytes - 1)) != 0 ||
                volumeOffset < 0 || volumeBytes < clusterBytes || volumeOffset > Int64.MaxValue - volumeBytes)
                throw new IOException("NATIVE_NTFS_FILE_PLAN_INVALID");
            var result = new RecoveryNativeNtfsFile { LogicalBytes = stream.Length, Status = "candidate" };
            if ((stream.Flags & 6) != 0) {
                result.Status = (stream.Flags & 4) != 0 ? "encrypted-unavailable" : "compressed-unavailable";
                result.MissingBytes = stream.Length;
                return result;
            }
            string id = "record-" + record.Ordinal.ToString(CultureInfo.InvariantCulture) + "-" + record.Sequence.ToString(CultureInfo.InvariantCulture) +
                "-stream-" + stream.Index.ToString(CultureInfo.InvariantCulture);
            string extension = Regex.Match(record.Name ?? "", @"\.[a-zA-Z0-9]{1,10}$").Value.ToLowerInvariant();
            string provenance = "ntfs:" + RecoveryNativeWorker.Number(volumeOffset) + ":" + id;
            var ranges = new List<RecoveryMappedRange>();
            if ((stream.Flags & 1) != 0) {
                if (stream.Resident == null || stream.Resident.LongLength != stream.Length || stream.Runs.Count != 0)
                    throw new IOException("NATIVE_NTFS_FILE_PLAN_INVALID");
                result.Parts.Add(new RecoveryNativeNtfsFilePart { Plan = new RecoveryMappedFilePlan { ArchiveRoot = archiveRoot,
                    OutputRoot = outputRoot, RelativeOutput = id + extension, Provenance = provenance,
                    Resident = (byte[])stream.Resident.Clone(), Length = stream.Length } });
                result.MappedBytes = stream.Length; return result;
            }
            long next = 0;
            foreach (var run in stream.Runs) {
                if (run == null || run.Vcn != next || run.Clusters <= 0 || run.Clusters > Int64.MaxValue / clusterBytes - next || run.Lcn < -2 ||
                    run.Lcn >= 0 && (run.Lcn > volumeBytes / clusterBytes || run.Clusters > volumeBytes / clusterBytes - run.Lcn))
                    throw new IOException("NATIVE_NTFS_FILE_PLAN_INVALID");
                next += run.Clusters;
                long at = run.Vcn * clusterBytes;
                if (at >= stream.Length) continue;
                long count = Math.Min(run.Clusters * clusterBytes, stream.Length - at);
                // Native initialized_size is meaningful only for nonresident data.
                long initialized = Math.Max(0, Math.Min(count, stream.Initialized - at));
                if (initialized > 0 && run.Lcn != -2)
                    ranges.Add(new RecoveryMappedRange { LogicalOffset = at, Length = initialized,
                        ImageOffset = run.Lcn == -1 ? -1 : volumeOffset + run.Lcn * clusterBytes });
                if (initialized < count) ranges.Add(new RecoveryMappedRange { LogicalOffset = at + initialized,
                    Length = count - initialized, ImageOffset = -1 });
            }
            // Missing final runs are unknown only within initialized data.
            long covered = Math.Min(stream.Length, next * clusterBytes);
            if (covered < stream.Length && stream.Initialized < stream.Length) {
                long at = Math.Max(covered, stream.Initialized);
                ranges.Add(new RecoveryMappedRange { LogicalOffset = at, Length = stream.Length - at, ImageOffset = -1 });
            }
            long known = 0;
            foreach (var range in ranges) known += range.Length;
            result.MappedBytes = known; result.MissingBytes = stream.Length - known;
            result.Status = result.MissingBytes == 0 ? "candidate" : "missing-segments";
            if (stream.Length == 0) ranges.Add(new RecoveryMappedRange { LogicalOffset = 0, Length = 0, ImageOffset = -1 });
            for (int at = 0; at < ranges.Count;) {
                long begin = ranges[at].LogicalOffset, length = 0;
                var mapped = new List<RecoveryMappedRange>();
                do {
                    var range = ranges[at++];
                    if (range.Length != 0) mapped.Add(new RecoveryMappedRange { LogicalOffset = length, Length = range.Length, ImageOffset = range.ImageOffset });
                    length += range.Length;
                } while (at < ranges.Count && ranges[at].LogicalOffset == begin + length);
                string name = id + (result.MissingBytes == 0 ? "" : "-part-" + result.Parts.Count.ToString("D4",CultureInfo.InvariantCulture)) + extension;
                result.Parts.Add(new RecoveryNativeNtfsFilePart { LogicalOffset = begin, Plan = new RecoveryMappedFilePlan {
                    ArchiveRoot = archiveRoot, OutputRoot = outputRoot, RelativeOutput = name, Provenance = provenance + ":logical:" + RecoveryNativeWorker.Number(begin),
                    Length = length, Ranges = mapped } });
            }
            return result;
        }
    }
}
