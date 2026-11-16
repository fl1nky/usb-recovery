using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class MetadataRescue
    {
        const int ScanUnitBytes = 4 * 1024 * 1024, MaximumBlobBytes = 16 * 1024 * 1024;
        const int MaximumFacts = MaximumCandidates + MaximumDirectoryRecords + 128;

        sealed class RescueState
        {
            public string Phase = "scan", ReadMapIdentity;
            public bool Initialized, AllocationUntrusted;
            public long ScanOffset;
            public int ExportCursor, TotalRuns;
            public Report Counters = InitialReport();
            public RecoveryOutputHead Metadata, Outputs;
        }
        sealed class RescueVolume
        {
            public bool BoundaryUnknown;
            public long Offset, Length, MftLcn, Clusters;
            public int ClusterBytes, RecordBytes;
            public static RescueVolume From(Volume v)
            {
                return new RescueVolume { BoundaryUnknown = v.BoundaryUnknown, Offset = v.Offset, Length = v.Length,
                    MftLcn = v.MftLcn, Clusters = v.Clusters, ClusterBytes = v.ClusterBytes, RecordBytes = v.RecordBytes };
            }
            public Volume Create(long length)
            {
                if (Offset < 0 || Length < 512 || Offset > length - Length || !Power(ClusterBytes) ||
                    ClusterBytes < 512 || ClusterBytes > 4096 * 128 || Clusters != Length / ClusterBytes ||
                    MftLcn < 1 || MftLcn >= Clusters || !Power(RecordBytes) || RecordBytes < 512 || RecordBytes > MaximumRecordBytes ||
                    MftLcn > (Length - RecordBytes) / ClusterBytes) throw new IOException("NTFS_RECORD_VOLUME_INVALID");
                return new Volume { BoundaryUnknown = BoundaryUnknown, Offset = Offset, Length = Length, MftLcn = MftLcn,
                    Clusters = Clusters, ClusterBytes = ClusterBytes, RecordBytes = RecordBytes };
            }
        }
        sealed class RescueBlob
        {
            public string Path, Sha256;
            public int Index;
        }
        sealed class RescueFact
        {
            public string Kind;
            public RescueVolume Volume;
            public RescueBlob Candidate;
            public Record InlineCandidate;
            public int VolumeIndex;
            public PathNode Node;
            public long InvalidNode;
        }
        sealed class RescuePlan
        {
            public int Schema = 1, CandidateIndex;
            public Entry Item;
        }

        static Report InitialReport()
        {
            var report = new Report();
            report.Warnings.Add("Просматриваются записи FILE на границах 512 байт. Проверка USA обнаруживает повреждённую запись, но не является контрольной суммой содержимого файла.");
            report.Warnings.Add("Поддерживаются заголовки NTFS 3.1 с отдельным номером записи; старые заголовки с USA до смещения 48 пропускаются.");
            report.Warnings.Add("Сжатие, шифрование, разреженные потоки, ATTRIBUTE_LIST и потоки из нескольких записей не восстанавливаются. Путь строится только по однозначной текущей карте MFT и совпавшим sequence родительских ссылок; прежние перемещения не угадываются.");
            report.Warnings.Add("OriginalPath — виртуальный путь из снимка метаданных, он не используется как путь записи. RecordOffset в DirectoryChain обозначает начало записи; для фрагментированной MFT запись читается по всей карте потоков.");
            return report;
        }
        static string RescueJson(object value)
        {
            return new JavaScriptSerializer { MaxJsonLength = MaximumBlobBytes, RecursionLimit = 64 }.Serialize(value);
        }
        static bool RescueHash(string value)
        {
            return value != null && value.Length == 64 && value.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f');
        }
        static RescueBlob StoreRescueBlob(string root, string kind, int index, object value, CancellationToken cancel)
        {
            var blob = new RescueBlob { Path = "ntfs-records.state/" + kind + "/blob-" + Guid.NewGuid().ToString("N") + ".json", Index = index };
            string path = RecoveryCatalog.SafeFile(root, blob.Path); Directory.CreateDirectory(Path.GetDirectoryName(path));
            RecoveryCore.SaveJsonBounded(path, value, MaximumBlobBytes);
            blob.Sha256 = RecoveryCore.HashFile(path, cancel, (a, b) => { });
            return blob;
        }
        static T ReadRescueBlob<T>(string root, string kind, RescueBlob blob, CancellationToken cancel) where T : class
        {
            string prefix = "ntfs-records.state/" + kind + "/blob-";
            if (blob == null || blob.Index < 0 || blob.Path == null || !blob.Path.StartsWith(prefix, StringComparison.Ordinal) ||
                blob.Path.Length != prefix.Length + 37 || !blob.Path.EndsWith(".json", StringComparison.Ordinal) || !RescueHash(blob.Sha256) ||
                blob.Path.Substring(prefix.Length, 32).Any(c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')))
                throw new IOException("NTFS_RECORD_BLOB_INVALID");
            string path = RecoveryCatalog.SafeFile(root, blob.Path);
            using (var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (guard.Length <= 0 || guard.Length > MaximumBlobBytes || RecoveryCore.HashFile(path, cancel, (a, b) => { }) != blob.Sha256)
                    throw new IOException("NTFS_RECORD_BLOB_CHANGED");
                try
                {
                    T value = new JavaScriptSerializer { MaxJsonLength = MaximumBlobBytes, RecursionLimit = 64 }
                        .Deserialize<T>(File.ReadAllText(path, new System.Text.UTF8Encoding(false, true)));
                    if (value == null) throw new IOException("NTFS_RECORD_BLOB_INVALID");
                    return value;
                }
                catch (ArgumentException) { throw new IOException("NTFS_RECORD_BLOB_INVALID"); }
                catch (InvalidOperationException) { throw new IOException("NTFS_RECORD_BLOB_INVALID"); }
            }
        }
    }
}
