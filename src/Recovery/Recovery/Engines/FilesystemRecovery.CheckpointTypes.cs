using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UsbRecovery
{
    public static partial class FilesystemRecovery
    {
        const int ClusterBatch = 4096;
        const int MaximumMetadataRecords = MaxCandidates + 4 * MaxDirectories + 2 * (MaxClusters / ClusterBatch + 1) + 32;
        const int MaximumPlanBytes = 16 * 1024 * 1024;

        sealed class DirectoryQueue : Queue<DirectoryTask>
        {
            public readonly List<DirectoryTask> Added = new List<DirectoryTask>();
            public new void Enqueue(DirectoryTask value) { base.Enqueue(value); Added.Add(value); }
            public void Restore(DirectoryTask value) { base.Enqueue(value); }
        }

        sealed class FsGeometry
        {
            public long Offset, Length, FatOffset, FatLength, DataOffset, RootOffset, RootBytes, ClusterBytes;
            public uint ClusterCount, RootCluster;
            public int Bits, ActiveFat;
            public string Kind;
            public bool Exfat;

            public static FsGeometry From(Volume v)
            {
                return new FsGeometry { Offset = v.Offset, Length = v.Length, FatOffset = v.FatOffset,
                    FatLength = v.FatLength, DataOffset = v.DataOffset, RootOffset = v.RootOffset,
                    RootBytes = v.RootBytes, ClusterBytes = v.ClusterBytes, ClusterCount = v.ClusterCount,
                    RootCluster = v.RootCluster, Bits = v.Bits, ActiveFat = v.ActiveFat, Kind = v.Kind, Exfat = v.Exfat };
            }
            public Volume Create()
            {
                return new Volume { Offset = Offset, Length = Length, FatOffset = FatOffset, FatLength = FatLength,
                    DataOffset = DataOffset, RootOffset = RootOffset, RootBytes = RootBytes, ClusterBytes = ClusterBytes,
                    ClusterCount = ClusterCount, RootCluster = RootCluster, Bits = Bits, ActiveFat = ActiveFat,
                    Kind = Kind, Exfat = Exfat };
            }
        }

        sealed class FsVolumeProgress
        {
            public string Phase = "initialize";
            public int QueueCursor, MainVisited, MainEntries, OrphanVisited, OrphanEntries, OrphanFound, ExportCursor;
            public long OrphanCluster, BitmapLength;
            public uint BitmapStart;
            public bool AllocationComplete = true, BitmapValid;
            public RecoveryOutputHead Metadata;
            public List<string> Notes = new List<string>();
        }
        sealed class FsState
        {
            public List<FsGeometry> Volumes;
            public List<string> DiscoveryNotes;
            public FsVolumeProgress Current = new FsVolumeProgress();
            public RecoveryOutputHead Exports;
            public int VolumeIndex, Number, Recovered;
            public long RecoveredBytes;
            public bool Limited, Complete;
        }
        sealed class FsMetadataEvent
        {
            public string Kind;
            public DirectoryTask Directory;
            public Candidate Candidate;
            public uint[] Clusters;
        }
        sealed class FsExportEvent
        {
            public string Kind, PlanPath, PlanSha256;
            public int VolumeIndex, CandidateIndex;
            public FsVolumeProgress FinishedVolume;
        }
        sealed class FsCandidatePlan
        {
            public int Schema = 1, VolumeIndex, CandidateIndex, Number;
            public Candidate Candidate;
            public string FileSystem, Method, Status, Reason, Path, Sha256;
            public long VolumeOffset, Bytes, InitializedBytes;
            public bool MappingComplete = true;
            public List<FileExtent> Ranges = new List<FileExtent>();
        }

        static bool FsHash(string value)
        {
            return value != null && value.Length == 64 && value.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f');
        }
        static bool SameCandidate(Candidate a, Candidate b)
        {
            return a != null && b != null && a.Name == b.Name && a.OriginalPath == b.OriginalPath &&
                a.NameNote == b.NameNote && a.Start == b.Start && a.Length == b.Length &&
                a.ValidLength == b.ValidLength && a.Contiguous == b.Contiguous;
        }
        static bool SamePlan(FsCandidatePlan a, FsCandidatePlan b)
        {
            // JSON member order is not part of the repair identity. Every
            // value, including ordered source extents, still has to agree.
            return a != null && b != null && a.Schema == b.Schema && a.VolumeIndex == b.VolumeIndex &&
                a.CandidateIndex == b.CandidateIndex && a.Number == b.Number && SameCandidate(a.Candidate, b.Candidate) &&
                a.FileSystem == b.FileSystem && a.Method == b.Method && a.Status == b.Status && a.Reason == b.Reason &&
                a.Path == b.Path && a.Sha256 == b.Sha256 && a.VolumeOffset == b.VolumeOffset && a.Bytes == b.Bytes &&
                a.InitializedBytes == b.InitializedBytes && a.MappingComplete == b.MappingComplete &&
                a.Ranges != null && b.Ranges != null && a.Ranges.Count == b.Ranges.Count &&
                a.Ranges.Zip(b.Ranges, (left, right) => left != null && right != null &&
                    left.Offset == right.Offset && left.Length == right.Length).All(equal => equal);
        }
        static void ValidateCandidate(Volume v, Candidate candidate)
        {
            if (candidate == null || String.IsNullOrEmpty(candidate.Name) || candidate.Name.Length > 512 ||
                candidate.OriginalPath == null || candidate.OriginalPath.Length > 32700 || candidate.NameNote == null ||
                candidate.NameNote.Length > 1024 || candidate.Length <= 0 || candidate.Length > MaxFileBytes ||
                candidate.ValidLength < 0 || candidate.ValidLength > candidate.Length || !ClusterValid(v, candidate.Start))
                throw new IOException("FAT_METADATA_CANDIDATE_INVALID");
        }
    }
}
