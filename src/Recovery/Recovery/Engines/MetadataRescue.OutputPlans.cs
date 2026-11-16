using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class MetadataRescue
    {
        static string RescueScratch(string root, int index)
        {
            string file = RecoveryCatalog.SafeFile(root, "ntfs-records.state/work/record-" + index.ToString("D6", System.Globalization.CultureInfo.InvariantCulture) + ".partial");
            Directory.CreateDirectory(Path.GetDirectoryName(file));
            return file;
        }
        static void CopyAttribution(Entry from, Entry to)
        {
            to.OriginalPath = from.OriginalPath; to.PathStatus = from.PathStatus; to.PathEvidence = from.PathEvidence;
            to.DirectoryChainComplete = from.DirectoryChainComplete; to.PathVolumeOffset = from.PathVolumeOffset;
            to.DirectoryChain = from.DirectoryChain;
        }
        static Entry PrepareRescueEntry(FileStream input, IList<Volume> volumes, Record record, string root,
            int candidateIndex, Report report, bool allocationUntrusted, bool allowUnknownAllocation, long remainingBudget,
            CancellationToken cancel, Entry attribution = null)
        {
            Entry item = new Entry { RecordOffset = record.Offset, RecordNumber = record.Number, Sequence = record.Sequence,
                Name = record.Name, ParentRecordNumber = record.Parent & 0x0000ffffffffffffL, ParentSequence = record.ParentSequence,
                DeclaredSize = record.Data.FileSize, InitializedBytes = record.Data.ValidLength, Status = "not_extracted", UsaFixupsRestored = record.Data.Resident };
            if (allocationUntrusted) item.Note += "; у образа есть пропуски чтения или недостоверная карта ошибок: сохранность байтов записи не подтверждена";
            if (attribution == null) ResolvePath(input, volumes, record, item, report, allocationUntrusted, cancel);
            else CopyAttribution(attribution, item);
            if (record.AttributeList) { item.Reason = "attribute_list_unsupported"; return item; }
            if (record.Data.Unsupported != null) { item.Reason = record.Data.Unsupported; return item; }
            if (record.Data.FileSize == 0) { item.Reason = "empty_stream"; return item; }
            if (record.Data.FileSize > MaximumFileBytes) { item.Reason = "file_size_limit"; return item; }
            byte[] fixedRecord = null;
            bool unknownAllocation = false;
            long available = record.Data.FileSize;
            if (record.Data.Resident) {
                fixedRecord = FixedRecord(input, record.Offset);
                if (fixedRecord == null) { item.Reason = "record_changed_or_damaged"; return item; }
                item.Note += "; Extents задают позиции содержимого до восстановления USA: заменённые слова в конце секторов берутся из массива USA, поэтому это не точная побайтовая карта источника";
                item.Extents.Add(new Extent { ImageOffset = record.Offset + record.Data.ValueOffset, LogicalOffset = 0, Length = available });
            } else {
                if (allocationUntrusted) { item.Reason = "source_read_errors_allocation_untrusted"; return item; }
                List<Volume> matches = volumes.Where(v => record.Offset >= v.Offset && record.Offset < v.Offset + v.Length && (v.Bitmap != null || allowUnknownAllocation)).ToList();
                if (matches.Count != 1) { item.Reason = matches.Count > 1 ? "ambiguous_volume" : "current_bitmap_unavailable"; return item; }
                Volume volume = matches[0]; item.VolumeOffset = volume.Offset;
                if (!CheckRuns(record.Data, volume)) { item.Reason = "invalid_cluster_bounds"; return item; }
                available = Math.Min(record.Data.FileSize, record.Data.ValidLength);
                unknownAllocation = volume.Bitmap == null;
                long prefix = unknownAllocation ? available : FreePrefix(input, volume, record.Data, available, cancel);
                if (unknownAllocation) {
                    item.Reason = "allocation_unknown";
                    item.Note += "; карта занятости недоступна: байты прочитаны по уцелевшим экстентам, но могли принадлежать другому файлу или быть перезаписаны";
                }
                if (prefix < available) { available = prefix; item.Reason = "allocated_cluster_stop"; }
                if (available == 0) { if (item.Reason == null) item.Reason = "no_initialized_bytes"; return item; }
                if (available < record.Data.FileSize && item.Reason == null) item.Reason = "uninitialized_tail_not_invented";
                AddExtents(item.Extents, record.Data, volume, available);
            }
            if (available > remainingBudget) {
                item.Reason = "output_budget"; report.OutputLimitReached = true; return item;
            }
            bool partial = available < record.Data.FileSize;
            string relative = "files/" + (partial ? "PARTIAL_" : "") + "record-" + record.Offset.ToString("x") + "-" + SafeName(record.Name);
            if (relative.EndsWith(".partial", StringComparison.OrdinalIgnoreCase)) relative += ".recovered";
            string pending = RescueScratch(root, candidateIndex);
            if (File.Exists(pending)) File.Delete(pending);
            try {
                using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    if (fixedRecord != null) {
                        cancel.ThrowIfCancellationRequested();
                        output.Write(fixedRecord, record.Data.ValueOffset, checked((int)available));
                    } else CopyExtents(input, output, item.Extents, cancel);
                    output.Flush(true);
                }
                cancel.ThrowIfCancellationRequested();
            } catch { if (File.Exists(pending)) File.Delete(pending); throw; }
            item.Output = relative; item.RecoveredBytes = available;
            item.Sha256 = RecoveryCore.HashFile(pending, cancel, (a, b) => { });
            item.Status = partial ? "partial_candidate" : fixedRecord != null ? "resident_candidate" : unknownAllocation ? "allocation_unknown_candidate" : "unallocated_candidate";
            if (item.Reason == null) item.Reason = fixedRecord != null ? "validated_record_resident_data" : "all_copied_clusters_currently_free";
            return item;
        }
        static string RescueOutputName(Record record, long bytes)
        {
            string name = "files/" + (bytes < record.Data.FileSize ? "PARTIAL_" : "") + "record-" +
                record.Offset.ToString("x", System.Globalization.CultureInfo.InvariantCulture) + "-" + SafeName(record.Name);
            return name.EndsWith(".partial", StringComparison.OrdinalIgnoreCase) ? name + ".recovered" : name;
        }
        static bool RescueMatches(string path, Entry item, CancellationToken cancel)
        {
            return File.Exists(path) && new FileInfo(path).Length == item.RecoveredBytes &&
                RecoveryCore.HashFile(path, cancel, (a, b) => { }) == item.Sha256;
        }
        static void PublishRescue(string root, RescuePlan plan, CancellationToken cancel)
        {
            if (plan.Item.Output == null) return;
            string target = RecoveryCatalog.SafeFile(root, "metadata-rescue/" + plan.Item.Output);
            string scratch = RescueScratch(root, plan.CandidateIndex);
            if (File.Exists(target))
            {
                if (!RescueMatches(target, plan.Item, cancel)) throw new IOException("NTFS_RECORD_OUTPUT_CHANGED");
                if (File.Exists(scratch)) File.Delete(scratch);
                return;
            }
            if (!RescueMatches(scratch, plan.Item, cancel)) throw new IOException("NTFS_RECORD_OUTPUT_REPAIR_REQUIRED");
            cancel.ThrowIfCancellationRequested();
            Directory.CreateDirectory(Path.GetDirectoryName(target));
            RecoveryCatalog.SafeFile(root, "metadata-rescue/" + plan.Item.Output);
            File.Move(scratch, target);
        }
        static void WriteRescueReport(string root, RescueState state, List<RescuePlan> plans, IList<Volume> volumes,
            bool allowUnknown, bool failed, bool cancelled, CancellationToken cancel)
        {
            var json = new JavaScriptSerializer { MaxJsonLength = MaximumBlobBytes, RecursionLimit = 64 };
            var report = json.Deserialize<Report>(RescueJson(state.Counters));
            report.Failed = failed; report.Cancelled = cancelled || cancel.IsCancellationRequested;
            report.ReportsPending = report.Cancelled;
            report.Completed = state.Phase == "complete" && !failed && !report.Cancelled &&
                !report.CandidateLimitReached && !report.OutputLimitReached;
            if (report.CandidateLimitReached) report.Warnings.Add("Достигнут предел кандидатов или экстентов; остальные подписи проверены без добавления результатов.");
            foreach (Volume volume in volumes.Where(v => v.Bitmap == null))
                report.Warnings.Add("Том " + volume.Offset + (allowUnknown ? ": занятость nonresident-потоков неизвестна (" : ": nonresident-потоки пропущены (") + volume.BitmapProblem + ")");
            string target = RecoveryCatalog.SafeFile(root, "metadata-rescue/report.json");
            if (report.Cancelled)
            {
                RecoveryCore.SaveJsonBounded(target, report, MaximumBlobBytes);
                if (!cancelled) throw new OperationCanceledException(cancel);
                return;
            }
            string pending = RecoveryCatalog.SafeFile(root, "metadata-rescue/.report-" + Guid.NewGuid().ToString("N") + ".partial");
            try
            {
                // Keep the report's historical 128-MiB character bound, but
                // serialize entries individually so cancellation remains bounded.
                var header = json.Deserialize<Dictionary<string, object>>(RescueJson(report)); header.Remove("Entries");
                string prefix = RescueJson(header); prefix = prefix.Substring(0, prefix.Length - 1) + ",\"Entries\":[";
                long characters = prefix.Length + 2;
                using (var file = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                using (var writer = new StreamWriter(file, new UTF8Encoding(false), 4096, true))
                {
                    writer.Write(prefix); bool first = true;
                    foreach (RescuePlan plan in plans)
                    {
                        cancel.ThrowIfCancellationRequested(); string row = RescueJson(plan.Item);
                        characters += row.Length + (first ? 0 : 1);
                        if (characters > 128L * 1024 * 1024) throw new IOException("NTFS_RECORD_REPORT_LIMIT");
                        if (!first) writer.Write(','); writer.Write(row); first = false;
                    }
                    writer.Write("]}"); writer.Flush(); file.Flush(true);
                }
                cancel.ThrowIfCancellationRequested();
                if (File.Exists(target)) File.Replace(pending, target, null); else File.Move(pending, target);
            }
            catch (OperationCanceledException)
            {
                report.Cancelled = true; report.Completed = false; report.ReportsPending = true;
                RecoveryCore.SaveJsonBounded(target, report, MaximumBlobBytes);
                throw;
            }
            finally { if (File.Exists(pending)) File.Delete(pending); }
        }
    }
}
