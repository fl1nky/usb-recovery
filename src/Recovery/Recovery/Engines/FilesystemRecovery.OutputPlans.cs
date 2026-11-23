using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class FilesystemRecovery
    {
        static string FsScratch(string root, int number)
        {
            string path = RecoveryCatalog.SafeFile(root, "fat.state/work/file-" + number.ToString("D6", CultureInfo.InvariantCulture) + ".partial");
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            return path;
        }
        static FsCandidatePlan PrepareCandidate(ImageReader image, Volume v, Candidate candidate, string root,
            int volumeIndex, int candidateIndex, int number, CancellationToken cancel)
        {
            bool contiguous = candidate.Contiguous;
            var plan = new FsCandidatePlan { VolumeIndex = volumeIndex, CandidateIndex = candidateIndex, Number = number,
                Candidate = candidate, FileSystem = v.Kind, VolumeOffset = v.Offset, Status = "candidate", Reason = "", Path = "" };
            if (candidate.Length <= 0 || candidate.Length > MaxFileBytes || candidate.Length > v.Length) plan.Reason = "invalid size";
            else if (v.Exfat && v.BitmapChain == null) plan.Reason = "allocation bitmap unavailable";
            if (candidate.LiveEntry)
            {
                contiguous = false;
                plan.Method = "live-fat-chain";
            }
            else if (v.Exfat) plan.Method = contiguous ? "exfat-contiguous" : "exfat-fat-chain";
            else
            {
                contiguous = Fat(image, v, candidate.Start) == 0;
                plan.Method = contiguous ? "contiguous-guess" : "retained-fat-uncertain";
                if (!contiguous && !v.AllocationComplete) plan.Reason = "current ownership incomplete; retained FAT allocation not safe to attribute";
            }
            if (plan.Reason.Length == 0)
            {
                bool complete;
                List<uint> chain = Chain(image, v, candidate.Start, candidate.Length, contiguous, out complete, cancel);
                var accepted = new List<uint>();
                foreach (uint cluster in chain)
                {
                    cancel.ThrowIfCancellationRequested();
                    if (candidate.LiveEntry && (!v.LiveClusters.Contains(cluster) || Fat(image, v, cluster) == 0))
                    { plan.Reason = "live file chain contains an unallocated cluster"; break; }
                    if (!candidate.LiveEntry && v.LiveClusters.Contains(cluster)) { plan.Reason = "cluster currently owned by a live file/directory"; break; }
                    if (v.Exfat && BitmapAllocated(image, v, cluster)) { plan.Reason = "cluster marked allocated in active exFAT bitmap"; break; }
                    if (!v.Exfat && contiguous && Fat(image, v, cluster) != 0)
                    { plan.Reason = "cluster currently allocated in FAT; contiguous reconstruction stopped"; break; }
                    accepted.Add(cluster);
                }
                if (accepted.Count == 0) plan.Status = "skipped";
                else
                {
                    bool partial = !complete || accepted.Count != chain.Count || (long)accepted.Count * v.ClusterBytes < candidate.Length;
                    plan.Status = partial ? "partial" : plan.Method == "contiguous-guess" || plan.Method == "retained-fat-uncertain" ? "uncertain" : "candidate";
                    if (plan.Reason.Length == 0 && !complete) plan.Reason = "incomplete/corrupt cluster chain";
                    if (candidate.OriginalPath.StartsWith("/orphan-directory-", StringComparison.Ordinal)) plan.Method = "orphan-" + plan.Method;
                    string leaf = number.ToString("D6", CultureInfo.InvariantCulture) + (partial ? "_PARTIAL_" : "_") + SafeName(candidate.Name);
                    // A source name must not turn a finished result into a private
                    // scratch file hidden by the common .partial filter.
                    if (leaf.EndsWith(".partial", StringComparison.OrdinalIgnoreCase)) leaf += ".recovered";
                    plan.Path = "filesystem/files/volume-" + (volumeIndex + 1).ToString("D3", CultureInfo.InvariantCulture) + "-" + v.Kind + "/" + plan.Method + "/" + leaf;
                    string temporary = FsScratch(root, number);
                    if (File.Exists(temporary)) File.Delete(temporary);
                    try
                    {
                        using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                        using (var hash = SHA256.Create())
                        {
                            byte[] buffer = new byte[(int)Math.Min(1024 * 1024, v.ClusterBytes)];
                            foreach (uint cluster in accepted)
                            {
                                cancel.ThrowIfCancellationRequested();
                                long offset = ClusterOffset(v, cluster), amount = Math.Min(v.ClusterBytes, candidate.Length - plan.Bytes);
                                for (long position = 0; position < amount; )
                                {
                                    int count = (int)Math.Min(buffer.Length, amount - position);
                                    long valid = Math.Max(0, Math.Min(count, candidate.ValidLength - plan.Bytes));
                                    if (valid > 0)
                                    {
                                        image.Read(offset + position, buffer, (int)valid);
                                        long start = offset + position;
                                        if (plan.Ranges.Count > 0 && plan.Ranges[plan.Ranges.Count - 1].Offset + plan.Ranges[plan.Ranges.Count - 1].Length == start)
                                            plan.Ranges[plan.Ranges.Count - 1].Length += valid;
                                        else if (plan.Ranges.Count < 100000) plan.Ranges.Add(new FileExtent { Offset = start, Length = valid });
                                        else plan.MappingComplete = false;
                                    }
                                    if (valid < count) Array.Clear(buffer, (int)valid, count - (int)valid);
                                    file.Write(buffer, 0, count); hash.TransformBlock(buffer, 0, count, null, 0);
                                    plan.Bytes += count; position += count;
                                }
                            }
                            hash.TransformFinalBlock(new byte[0], 0, 0);
                            plan.Sha256 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
                            file.Flush(true);
                        }
                    }
                    catch { if (File.Exists(temporary)) File.Delete(temporary); throw; }
                    plan.InitializedBytes = Math.Min(candidate.ValidLength, plan.Bytes);
                }
            }
            else plan.Status = "skipped";
            if (plan.Method == "retained-fat-uncertain" && plan.Reason.Length == 0)
                plan.Reason = "FAT chain retained but allocation is ambiguous; no known live owner; content not validated";
            if (plan.Method == "contiguous-guess" && plan.Reason.Length == 0)
                plan.Reason = "FAT chain erased; consecutive free clusters assumed; fragmentation cannot be reconstructed";
            if (v.Exfat && plan.Reason.Length == 0) plan.Reason = "metadata checksum and allocation checked; content may still be overwritten";
            return plan;
        }

        static string FsPlanFile(string root, FsExportEvent entry)
        {
            const string prefix = "fat.state/plans/plan-";
            if (entry.PlanPath == null || !entry.PlanPath.StartsWith(prefix, StringComparison.Ordinal) ||
                entry.PlanPath.Length != prefix.Length + 37 || !entry.PlanPath.EndsWith(".json", StringComparison.Ordinal) ||
                entry.PlanPath.Substring(prefix.Length, 32).Any(c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) || !FsHash(entry.PlanSha256))
                throw new IOException("FAT_OUTPUT_PLAN_INVALID");
            return RecoveryCatalog.SafeFile(root, entry.PlanPath);
        }
        static FsExportEvent StorePlan(string root, FsCandidatePlan plan, CancellationToken cancel)
        {
            var entry = new FsExportEvent { Kind = "candidate", VolumeIndex = plan.VolumeIndex, CandidateIndex = plan.CandidateIndex,
                PlanPath = "fat.state/plans/plan-" + Guid.NewGuid().ToString("N") + ".json" };
            string path = RecoveryCatalog.SafeFile(root, entry.PlanPath);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            RecoveryCore.SaveJsonBounded(path, plan, MaximumPlanBytes);
            entry.PlanSha256 = RecoveryCore.HashFile(path, cancel, (a, b) => { });
            return entry;
        }
        static FsCandidatePlan ReadPlan(string root, FsExportEvent entry, CancellationToken cancel)
        {
            string path = FsPlanFile(root, entry);
            using (var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (guard.Length <= 0 || guard.Length > MaximumPlanBytes || RecoveryCore.HashFile(path, cancel, (a, b) => { }) != entry.PlanSha256)
                    throw new IOException("FAT_OUTPUT_PLAN_CHANGED");
                try
                {
                    var plan = new JavaScriptSerializer { MaxJsonLength = MaximumPlanBytes }.Deserialize<FsCandidatePlan>(File.ReadAllText(path, new UTF8Encoding(false, true)));
                    if (plan == null || plan.Schema != 1 || plan.VolumeIndex != entry.VolumeIndex || plan.CandidateIndex != entry.CandidateIndex)
                        throw new IOException("FAT_OUTPUT_PLAN_INVALID");
                    return plan;
                }
                catch (ArgumentException) { throw new IOException("FAT_OUTPUT_PLAN_INVALID"); }
                catch (InvalidOperationException) { throw new IOException("FAT_OUTPUT_PLAN_INVALID"); }
            }
        }
        static void PublishPlan(string root, FsCandidatePlan plan, CancellationToken cancel)
        {
            if (plan.Bytes == 0) return;
            string output = RecoveryCatalog.SafeFile(root, plan.Path), temporary = FsScratch(root, plan.Number);
            if (File.Exists(output))
            {
                if (new FileInfo(output).Length != plan.Bytes || RecoveryCore.HashFile(output, cancel, (a, b) => { }) != plan.Sha256)
                    throw new IOException("FAT_OUTPUT_CHANGED");
                if (File.Exists(temporary)) File.Delete(temporary);
                return;
            }
            if (!File.Exists(temporary) || new FileInfo(temporary).Length != plan.Bytes || RecoveryCore.HashFile(temporary, cancel, (a, b) => { }) != plan.Sha256)
                throw new IOException("FAT_OUTPUT_REPAIR_REQUIRED");
            cancel.ThrowIfCancellationRequested();
            Directory.CreateDirectory(Path.GetDirectoryName(output));
            RecoveryCatalog.SafeFile(root, plan.Path);
            File.Move(temporary, output);
        }

        static void WriteFsReports(string root, IEnumerable<FsExportEvent> records, List<string> notes, int volumes,
            int recovered, long bytes, bool completed, bool limited, CancellationToken cancel)
        {
            string folder = RecoveryCatalog.SafeFile(root, "filesystem/guard"); folder = Path.GetDirectoryName(folder);
            Directory.CreateDirectory(folder);
            string csvPartial = RecoveryCatalog.SafeFile(root, "filesystem/.metadata-" + Guid.NewGuid().ToString("N") + ".partial");
            string evidencePartial = RecoveryCatalog.SafeFile(root, "filesystem/.extents-" + Guid.NewGuid().ToString("N") + ".partial");
            bool reportCancelled = cancel.IsCancellationRequested;
            if (!reportCancelled)
            {
                try
                {
                    using (var csvFile = new FileStream(csvPartial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                    using (var evidenceFile = new FileStream(evidencePartial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                    using (var csv = new StreamWriter(csvFile, new UTF8Encoding(true), 4096, true))
                    using (var evidence = new StreamWriter(evidenceFile, new UTF8Encoding(false), 4096, true))
                    {
                        csv.WriteLine("filesystem,volume_offset,original_path,start_cluster,expected_bytes,recovered_bytes,method,status,reason,name_evidence,output_path");
                        foreach (FsExportEvent entry in records.Where(x => x.Kind == "candidate"))
                        {
                            cancel.ThrowIfCancellationRequested();
                            var plan = ReadPlan(root, entry, cancel);
                            string output = plan.Bytes == 0 ? "" : RecoveryCatalog.SafeFile(root, plan.Path);
                            csv.WriteLine(Quote(plan.FileSystem) + "," + plan.VolumeOffset + "," + Quote(plan.Candidate.OriginalPath) + "," +
                                plan.Candidate.Start + "," + plan.Candidate.Length + "," + plan.Bytes + "," + Quote(plan.Method) + "," +
                                Quote(plan.Status) + "," + Quote(plan.Reason) + "," + Quote(plan.Candidate.NameNote) + "," + Quote(output));
                            if (plan.Bytes > 0) evidence.WriteLine(new JavaScriptSerializer { MaxJsonLength = MaximumPlanBytes }.Serialize(new {
                                path = plan.Path, ranges = plan.Ranges, mappingComplete = plan.MappingComplete, status = plan.Status,
                                expectedBytes = plan.Candidate.Length, bytes = plan.Bytes, sha256 = plan.Sha256,
                                originalPath = plan.Candidate.OriginalPath, volumeOffset = plan.VolumeOffset,
                                nameEvidence = plan.Candidate.NameNote, initializedBytes = plan.InitializedBytes,
                                note = "Ranges identify source bytes copied, not proof of original content. Bytes after exFAT valid-data length are logical zeroes." }));
                        }
                        csv.Flush(); evidence.Flush(); csvFile.Flush(true); evidenceFile.Flush(true);
                    }
                    ReplaceReport(csvPartial, RecoveryCatalog.SafeFile(root, "filesystem/metadata.csv"));
                    ReplaceReport(evidencePartial, RecoveryCatalog.SafeFile(root, "filesystem/file-extents.jsonl"));
                }
                catch (OperationCanceledException) { reportCancelled = true; }
                finally
                {
                    if (File.Exists(csvPartial)) File.Delete(csvPartial);
                    if (File.Exists(evidencePartial)) File.Delete(evidencePartial);
                }
            }
            RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(root, "filesystem/report.json"), new {
                supportedVolumes = volumes, recovered = recovered, recoveredBytes = bytes, limited = limited,
                completed = completed && !reportCancelled, cancelled = reportCancelled, reportsPending = reportCancelled });
            string explanation = "ПОИСК ПО ЗАПИСЯМ ФАЙЛОВОЙ СИСТЕМЫ\r\n\r\n" +
                "Образ открыт только для чтения. metadata.csv содержит сохранившиеся имена, пути, метод и причины ограничений.\r\n" +
                "contiguous-guess: предполагаются последовательные свободные кластеры; фрагментация так не восстанавливается.\r\n" +
                "retained-fat-uncertain: цепочка сохранилась, принадлежность неоднозначна; текущие владельцы исключены.\r\n" +
                "exfat-contiguous / exfat-fat-chain: используются проверенные метаданные и карта занятости. После ValidDataLength записаны логические нули.\r\n" +
                "PARTIAL содержит безопасный префикс. Candidate/uncertain не доказывают целостность или факт удаления.\r\n" +
                "При продолжении проверяются исходный образ, параметры, служебные страницы и опубликованные файлы.\r\n\r\n" + String.Join("\r\n", notes.ToArray());
            RecoveryCore.SaveJsonBounded(RecoveryCatalog.SafeFile(root, "filesystem/notes.json"), new { notes = notes }, MaximumPlanBytes);
            string text = RecoveryCatalog.SafeFile(root, "filesystem/ПРОЧИТАЙ О РЕЗУЛЬТАТАХ.txt");
            string partialText = Path.Combine(folder, ".notes-" + Guid.NewGuid().ToString("N") + ".partial");
            File.WriteAllText(partialText, explanation, new UTF8Encoding(true));
            ReplaceReport(partialText, text);
            if (reportCancelled) throw new OperationCanceledException(cancel);
        }
        static void ReplaceReport(string temporary, string target)
        {
            if (File.Exists(target)) File.Replace(temporary, target, null);
            else File.Move(temporary, target);
        }
    }
}
