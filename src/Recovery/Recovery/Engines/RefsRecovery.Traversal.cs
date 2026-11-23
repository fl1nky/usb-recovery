// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Linq;

namespace UsbRecovery
{
    public static partial class RefsRecovery
    {
        static void RunVolumes(Context c, IEnumerable<long> offsets, Action<string> progress)
        {
            var input = c.Input; var report = c.Report; var limits = c.Limits; var cancel = c.Cancel;
            var locations = offsets == null ? Discover(c) : offsets.Distinct().ToList();
            foreach (long offset in locations)
            {
                cancel.ThrowIfCancellationRequested();
                if (report.Volumes.Count >= limits.MaximumVolumes)
                {
                    report.Limited = true;
                    Skip(c, "volume_limit");
                    break;
                }
                if (offset < 0 || (offset & 511) != 0 || offset > input.Length - 1024)
                {
                    Skip(c, "invalid_partition_offset");
                    continue;
                }

                VolumeGeometry geom = ReadVbr(c, offset);
                if (geom == null) continue;

                var vr = new VolumeReport
                {
                    Offset = offset,
                    Bytes = (long)(geom.NumberOfSectors * geom.BytesPerSector),
                    Version = string.Format("{0}.{1}", geom.MajorVersion, geom.MinorVersion),
                    SectorSize = geom.BytesPerSector,
                    ClusterSize = geom.ClusterBlockSize,
                    BlockSize = geom.MetadataBlockSize,
                    ContainerSize = geom.ContainerSize,
                    Status = "rejected"
                };
                report.Volumes.Add(vr);

                // Check supported versions
                if (geom.MajorVersion != 1 && geom.MajorVersion != 3)
                {
                    vr.Reason = string.Format("unsupported_refs_major_version_{0}", geom.MajorVersion);
                    vr.Capabilities.UnsupportedFeatures.Add(vr.Reason);
                    report.Capabilities.UnsupportedFeatures.Add(vr.Reason);
                    continue;
                }

                vr.Capabilities.ReFSVersion = vr.Version;
                vr.Capabilities.BytesPerSector = geom.BytesPerSector;
                vr.Capabilities.ClusterBlockSize = geom.ClusterBlockSize;
                vr.Capabilities.MetadataBlockSize = geom.MetadataBlockSize;
                vr.Capabilities.ContainerSize = geom.ContainerSize;
                vr.Capabilities.PrimaryVbrValid = geom.PrimaryVbrValid;
                vr.Capabilities.BackupVbrUsed = geom.BackupVbrUsed;
                vr.Capabilities.SupportedFeatures.Add("vbr_fsrs_parsed");
                if (geom.BackupVbrUsed) vr.Capabilities.SupportedFeatures.Add("backup_vbr_fallback");

                // Update top-level report capabilities
                report.Capabilities.ReFSVersion = vr.Capabilities.ReFSVersion;
                report.Capabilities.BytesPerSector = vr.Capabilities.BytesPerSector;
                report.Capabilities.ClusterBlockSize = vr.Capabilities.ClusterBlockSize;
                report.Capabilities.MetadataBlockSize = vr.Capabilities.MetadataBlockSize;
                report.Capabilities.ContainerSize = vr.Capabilities.ContainerSize;
                report.Capabilities.PrimaryVbrValid = vr.Capabilities.PrimaryVbrValid;
                report.Capabilities.BackupVbrUsed = vr.Capabilities.BackupVbrUsed;

                if (progress != null) progress(string.Format("ReFS: разбор метаданных, раздел {0}", offset));
                ScanVolume(c, geom, vr, progress);
            }
        }
    }
}
