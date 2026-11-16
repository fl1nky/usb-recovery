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
    public static partial class FragmentedZipRecovery
    {
        const int MaximumPlanBytes = 16 * 1024 * 1024;
        const int MaximumReportBytes = 32 * 1024 * 1024, ReportEnvelopeAllowance = 256 * 1024;

        // The small root pins one event chain. Large provenance records use
        // separately hashed, bounded plans, never an unbounded root/page.
        sealed class ZipScanState
        {
            public long Position, ChargedWorkBytes, ExpandedWorkBytes;
            public int Headers, LocalRecords, Directories, NextDirectory;
            public bool ScanComplete, DirectoryStarted, Complete, Limited;
            public RecoveryOutputHead Head;
            public Dictionary<string, int> Skipped = new Dictionary<string, int>(StringComparer.Ordinal);
        }
        sealed class ZipEvent
        {
            public string Kind, RawSha256, PlanPath, PlanSha256;
            public long Offset;
            public bool Valid;
        }

        static bool IsHash(string value)
        {
            return value != null && value.Length == 64 && value.All(c =>
                c >= '0' && c <= '9' || c >= 'a' && c <= 'f');
        }

        static string FileHash(string file, CancellationToken cancel)
        {
            return RecoveryCore.HashFile(file, cancel, (a, b) => { });
        }

        static void CommitZip(ZipScanState state, Report report, RecoveryMethodJournal<ZipScanState> journal,
            RecoveryOutputLedger<ZipEvent> ledger, IList<ZipEvent> events)
        {
            state.Headers = report.Headers;
            state.LocalRecords = report.LocalRecords;
            state.Directories = report.Directories;
            state.ExpandedWorkBytes = report.ExpandedWorkBytes;
            state.Skipped = report.Skipped;
            report.ChargedWorkBytes = state.ChargedWorkBytes;
            state.Head = ledger.Append(state.Head, events);
            journal.Save(state);
            ledger.Accept(events);
        }

        static void CommitZip(ZipScanState state, Report report, RecoveryMethodJournal<ZipScanState> journal,
            RecoveryOutputLedger<ZipEvent> ledger)
        {
            CommitZip(state, report, journal, ledger, new ZipEvent[0]);
        }

        static void ValidateState(ZipScanState state, long length)
        {
            if (state.Position < 0 || state.Position > length ||
                state.ScanComplete != (state.Position == length) ||
                state.Headers < 0 || state.Headers > MaximumHeaders + 1 ||
                state.LocalRecords < 0 || state.LocalRecords > MaximumLocals + 1 ||
                state.Directories < 0 || state.Directories > MaximumDirectories ||
                state.NextDirectory < 0 || state.NextDirectory > MaximumDirectories ||
                state.Directories > state.NextDirectory + (state.DirectoryStarted ? 1 : 0) ||
                state.ExpandedWorkBytes < 0 || state.ChargedWorkBytes < state.ExpandedWorkBytes ||
                state.ChargedWorkBytes > MaximumWorkBytes || state.Skipped == null ||
                state.Skipped.Count > 128 || state.Skipped.Any(x => x.Key == null || x.Key.Length > 128 || x.Value < 1) ||
                !state.ScanComplete && (state.NextDirectory != 0 || state.DirectoryStarted || state.ExpandedWorkBytes != 0) ||
                state.Complete && (!state.ScanComplete || state.Limited || state.DirectoryStarted))
                throw new IOException("FRAGMENTED_ZIP_CHECKPOINT_INVALID");
        }

        static string PlanFile(string run, ZipEvent entry)
        {
            const string prefix = "fragmented-zip.state/plans/plan-";
            string name = entry.PlanPath;
            if (name == null || !name.StartsWith(prefix, StringComparison.Ordinal) ||
                name.Length != prefix.Length + 37 || !name.EndsWith(".json", StringComparison.Ordinal) ||
                name.Substring(prefix.Length, 32).Any(c => !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) ||
                !IsHash(entry.PlanSha256))
                throw new IOException("FRAGMENTED_ZIP_PLAN_INVALID");
            return RecoveryCatalog.SafeFile(run, name);
        }

        static Result ReadPlan(string run, ZipEvent entry, CancellationToken cancel)
        {
            string path = PlanFile(run, entry);
            using (var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (guard.Length <= 0 || guard.Length > MaximumPlanBytes || FileHash(path, cancel) != entry.PlanSha256)
                    throw new IOException("FRAGMENTED_ZIP_PLAN_CHANGED");
                try
                {
                    var result = new JavaScriptSerializer { MaxJsonLength = MaximumPlanBytes }
                        .Deserialize<Result>(File.ReadAllText(path, StrictUtf8));
                    if (result == null || result.EocdOffset != entry.Offset) throw new IOException("FRAGMENTED_ZIP_PLAN_INVALID");
                    return result;
                }
                catch (ArgumentException) { throw new IOException("FRAGMENTED_ZIP_PLAN_INVALID"); }
                catch (InvalidOperationException) { throw new IOException("FRAGMENTED_ZIP_PLAN_INVALID"); }
            }
        }

        static string ResultName(long end, string extension)
        {
            return "reassembled-" + end.ToString("D16", CultureInfo.InvariantCulture) + extension;
        }

        static int DescriptionBytes(Result result)
        {
            try
            {
                string json = new JavaScriptSerializer { MaxJsonLength = MaximumPlanBytes }.Serialize(result);
                int bytes = Encoding.UTF8.GetByteCount(json);
                return bytes <= MaximumPlanBytes ? bytes : MaximumReportBytes;
            }
            catch (ArgumentException) { return MaximumReportBytes; }
            catch (InvalidOperationException) { return MaximumReportBytes; }
        }

        static void ValidatePlan(FileStream input, Result result, Dictionary<long, Local> byOffset)
        {
            if (result.Status != "zip_crc_reassembled" || !IsHash(result.Sha256) || result.Bytes < 1 ||
                result.Bytes > MaximumArchiveBytes || result.MemberSources == null || result.Extents == null ||
                result.Members < 1 || result.Members > MaximumEntries ||
                result.MemberSources.Count != result.Members || result.Extents.Count != result.Members + 1)
                throw new IOException("FRAGMENTED_ZIP_PLAN_INVALID");
            DirectoryRecord central;
            try { central = DirectoryAt(input, result.EocdOffset); }
            catch (Reject) { throw new IOException("FRAGMENTED_ZIP_PLAN_SOURCE_CHANGED"); }
            var entries = central.Entries.OrderBy(x => x.LogicalOffset).ToArray();
            if (entries.Length != result.Members || central.Offset != result.CentralOffset ||
                result.Path != "fragmented-archives/" + ResultName(result.EocdOffset, Extension(entries)))
                throw new IOException("FRAGMENTED_ZIP_PLAN_SOURCE_CHANGED");
            long logical = 0;
            var chosen = new List<Local>();
            for (int i = 0; i < entries.Length; i++)
            {
                Member member = result.MemberSources[i];
                Extent extent = result.Extents[i];
                Local item;
                if (member == null || extent == null || !byOffset.TryGetValue(member.ImageOffset, out item) ||
                    !item.Checked || !item.Valid || item.Key != entries[i].Key || item.RawSha != member.RecordSha256 ||
                    member.Name != item.Name || member.Crc32 != item.ExpectedCrc.ToString("x8", CultureInfo.InvariantCulture) ||
                    member.CompressedBytes != item.Packed || member.Bytes != item.Unpacked || member.LogicalOffset != logical ||
                    extent.ImageOffset != item.Offset || extent.LogicalOffset != logical || extent.Length != item.RecordBytes ||
                    entries[i].LogicalOffset != logical || member.EquivalentRecordOffsets == null ||
                    member.EquivalentRecordOffsets.Count < 1 || member.EquivalentRecordOffsets.Count > 256 ||
                    member.EquivalentRecordOffsets.Distinct().Count() != member.EquivalentRecordOffsets.Count ||
                    !member.EquivalentRecordOffsets.Contains(item.Offset) ||
                    chosen.Any(x => item.Offset < x.Offset + x.RecordBytes && x.Offset < item.Offset + item.RecordBytes) ||
                    item.Offset < central.Offset + central.Bytes + central.EocdBytes && central.Offset < item.Offset + item.RecordBytes)
                    throw new IOException("FRAGMENTED_ZIP_PLAN_SOURCE_CHANGED");
                foreach (long offset in member.EquivalentRecordOffsets)
                {
                    Local alternative;
                    if (!byOffset.TryGetValue(offset, out alternative) || !alternative.Checked || !alternative.Valid ||
                        alternative.Key != item.Key || alternative.RecordBytes != item.RecordBytes || alternative.RawSha != item.RawSha)
                        throw new IOException("FRAGMENTED_ZIP_PLAN_SOURCE_CHANGED");
                }
                chosen.Add(item);
                logical += item.RecordBytes;
            }
            Extent tail = result.Extents[result.Members];
            if (tail == null || logical != central.LogicalOffset || tail.ImageOffset != central.Offset ||
                tail.LogicalOffset != logical || tail.Length != central.Bytes + central.EocdBytes || result.Bytes != logical + tail.Length)
                throw new IOException("FRAGMENTED_ZIP_PLAN_SOURCE_CHANGED");
        }

        static bool PrivatePartialName(string file)
        {
            string name = Path.GetFileName(file);
            const string prefix = "reassembled-";
            if (!name.StartsWith(prefix, StringComparison.Ordinal) || name.Length < prefix.Length + 16 + 12) return false;
            if (name.Substring(prefix.Length, 16).Any(c => c < '0' || c > '9')) return false;
            string suffix = name.Substring(prefix.Length + 16);
            return suffix == ".zip.partial" || suffix == ".docx.partial" || suffix == ".xlsx.partial" || suffix == ".pptx.partial";
        }

        static void ValidateInventory(string run, string folder, IEnumerable<Result> results)
        {
            if (Directory.EnumerateDirectories(folder).Any()) throw new IOException("FRAGMENTED_ZIP_OUTPUT_UNEXPECTED");
            var known = new HashSet<string>(results.Select(x => RecoveryCatalog.SafeFile(run, x.Path)), StringComparer.OrdinalIgnoreCase);
            foreach (string path in Directory.EnumerateFiles(folder))
            {
                NoLinks(path);
                if (!known.Contains(path) && !PrivatePartialName(path)) throw new IOException("FRAGMENTED_ZIP_OUTPUT_UNEXPECTED");
            }
        }

        static void PublishZip(FileStream input, string run, Result result, CancellationToken cancel)
        {
            string path = RecoveryCatalog.SafeFile(run, result.Path), partial = path + ".partial";
            NoLinks(partial);
            if (File.Exists(path))
            {
                if (new FileInfo(path).Length != result.Bytes || FileHash(path, cancel) != result.Sha256)
                    throw new IOException("FRAGMENTED_ZIP_OUTPUT_CHANGED");
                if (File.Exists(partial)) File.Delete(partial);
                return;
            }
            if (Directory.Exists(path) || Directory.Exists(partial)) throw new IOException("FRAGMENTED_ZIP_OUTPUT_UNEXPECTED");
            if (File.Exists(partial) && (new FileInfo(partial).Length != result.Bytes || FileHash(partial, cancel) != result.Sha256))
                File.Delete(partial); // Unlink private data; never truncate a linked file.
            if (!File.Exists(partial))
            {
                using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                using (var sha = SHA256.Create())
                {
                    foreach (Extent extent in result.Extents) Copy(input, output, sha, extent.ImageOffset, extent.Length, cancel);
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    if (output.Length != result.Bytes || BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant() != result.Sha256)
                        throw new IOException("FRAGMENTED_ZIP_REPAIR_SOURCE_CHANGED");
                    output.Flush(true);
                }
            }
            cancel.ThrowIfCancellationRequested();
            File.Move(partial, path);
        }

        static Result AssembleZip(FileStream input, DirectoryRecord central, Dictionary<string, List<Local>> locals,
            string folder, Report report, ZipScanState state, RecoveryMethodJournal<ZipScanState> journal,
            RecoveryOutputLedger<ZipEvent> ledger, CancellationToken cancel, ZipMemberVerifier verifier)
        {
            var ordered = central.Entries.OrderBy(e => e.LogicalOffset).ToArray();
            var chosen = new List<Local>();
            var alternatives = new List<List<Local>>();
            long logical = 0;
            for (int index = 0; index < ordered.Length; index++)
            {
                cancel.ThrowIfCancellationRequested();
                Entry entry = ordered[index];
                if (entry.LogicalOffset != logical) throw new Reject("logical_gaps_or_overlap_unsupported");
                long next = index + 1 < ordered.Length ? ordered[index + 1].LogicalOffset : central.LogicalOffset;
                long recordBytes = next - logical;
                if (recordBytes < 30 + entry.RawName.Length + entry.Packed || recordBytes > 30 + entry.RawName.Length + 32768L + entry.Packed)
                    throw new Reject("logical_record_bounds");
                List<Local> candidates;
                if (!locals.TryGetValue(entry.Key, out candidates)) throw new Reject("member_missing");
                if (candidates.Count > 256) throw new Reject("member_ambiguity_limit");
                var valid = new List<Local>();
                foreach (Local item in candidates)
                {
                    if (item.RecordBytes == recordBytes && verifier.Verify(item)) valid.Add(item);
                }
                if (valid.Count == 0) throw new Reject("member_crc_or_length");
                if (valid.Select(x => x.RawSha).Distinct(StringComparer.Ordinal).Take(2).Count() != 1)
                    throw new Reject("member_ambiguous_raw_versions");
                Local selected = valid.OrderBy(x => x.Offset).FirstOrDefault(v =>
                    !chosen.Any(x => v.Offset < x.Offset + x.RecordBytes && x.Offset < v.Offset + v.RecordBytes) &&
                    !(v.Offset < central.Offset + central.Bytes + central.EocdBytes && central.Offset < v.Offset + v.RecordBytes));
                if (selected == null) throw new Reject("physical_overlap");
                chosen.Add(selected); alternatives.Add(valid); logical = next;
            }
            if (logical != central.LogicalOffset) throw new Reject("logical_directory_offset");
            verifier.Flush();
            long length = logical + central.Bytes + central.EocdBytes;
            if (length > MaximumArchiveBytes) throw new Reject("archive_limit");
            bool contiguous = true;
            long physical = chosen[0].Offset;
            foreach (Local item in chosen) { if (item.Offset != physical) contiguous = false; physical = item.Offset + item.RecordBytes; }
            if (physical != central.Offset) contiguous = false;
            if (contiguous) throw new Reject("already_contiguous");
            if (report.Recovered >= MaximumArchives || length > MaximumOutputBytes - report.OutputBytes)
            {
                state.Limited = true; report.Status = "limited";
                CommitZip(state, report, journal, ledger);
                throw new IOException("Достигнут предел вывода собранных ZIP.");
            }
            string name = ResultName(central.EocdOffset, Extension(central.Entries));
            var result = new Result { Path = "fragmented-archives/" + name, Bytes = length,
                CentralOffset = central.Offset, EocdOffset = central.EocdOffset, Members = chosen.Count };
            logical = 0;
            for (int i = 0; i < chosen.Count; i++)
            {
                Local item = chosen[i];
                result.Extents.Add(new Extent { ImageOffset = item.Offset, LogicalOffset = logical, Length = item.RecordBytes });
                result.MemberSources.Add(new Member { Name = item.Name, Crc32 = item.ExpectedCrc.ToString("x8", CultureInfo.InvariantCulture),
                    RecordSha256 = item.RawSha, LogicalOffset = logical, ImageOffset = item.Offset, CompressedBytes = item.Packed,
                    Bytes = item.Unpacked, EquivalentRecordOffsets = alternatives[i].Select(x => x.Offset).ToList() });
                logical += item.RecordBytes;
            }
            result.Extents.Add(new Extent { ImageOffset = central.Offset, LogicalOffset = logical, Length = central.Bytes + central.EocdBytes });
            string partial = Path.Combine(folder, name) + ".partial";
            NoLinks(partial);
            if (File.Exists(partial)) File.Delete(partial);
            using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            using (var hash = SHA256.Create())
            {
                foreach (Extent extent in result.Extents) Copy(input, output, hash, extent.ImageOffset, extent.Length, cancel);
                hash.TransformFinalBlock(new byte[0], 0, 0);
                result.Sha256 = BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
                if (output.Length != result.Bytes) throw new IOException("FRAGMENTED_ZIP_OUTPUT_LENGTH_CHANGED");
                output.Flush(true);
            }
            return result;
        }

        static int RecoverWithCheckpoints(string image, string runDirectory, CancellationToken cancel,
            Action<long, long> progress, RecoveryCheckpointContext checkpoint)
        {
            cancel.ThrowIfCancellationRequested();
            string source = FullPath(image), run = FullPath(runDirectory), folder = Path.Combine(run, "fragmented-archives");
            string reportPath = Path.Combine(run, "fragmented-zip.json");
            if (source.StartsWith("\\\\", StringComparison.Ordinal) || source.IndexOf(':', 2) >= 0 ||
                run.StartsWith("\\\\", StringComparison.Ordinal) || run.IndexOf(':', 2) >= 0 || !File.Exists(source))
                throw new IOException("Для сборки ZIP нужен обычный локальный образ и локальная папка.");
            NoLinks(source); NoLinks(run); NoLinks(folder); NoLinks(reportPath);
            bool resume = checkpoint != null && checkpoint.Resume != null;
            if (source.Equals(reportPath, StringComparison.OrdinalIgnoreCase) || source.Equals(folder, StringComparison.OrdinalIgnoreCase) ||
                source.StartsWith(folder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || File.Exists(folder) ||
                !resume && (File.Exists(reportPath) || Directory.Exists(folder)))
                throw new IOException("Нужна новая папка результата сборки ZIP, отдельно от исходного образа.");
            Directory.CreateDirectory(run); Directory.CreateDirectory(folder);
            var journal = new RecoveryMethodJournal<ZipScanState>(source,
                new ZipScanState { ScanComplete = new FileInfo(source).Length == 0 }, checkpoint, cancel);
            var state = journal.Payload;
            var report = new Report { InputBytes = new FileInfo(source).Length, Headers = state.Headers,
                LocalRecords = state.LocalRecords, Directories = state.Directories,
                ExpandedWorkBytes = state.ExpandedWorkBytes, ChargedWorkBytes = state.ChargedWorkBytes, Skipped = state.Skipped };
            var ledger = new RecoveryOutputLedger<ZipEvent>(checkpoint, state.Head,
                MaximumHeaders + MaximumLocals + MaximumArchives, cancel);
            try
            {
                using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, BlockBytes))
                {
                    ValidateState(state, input.Length);
                    var locals = new Dictionary<string, List<Local>>(StringComparer.Ordinal);
                    var byOffset = new Dictionary<long, Local>();
                    var ends = new List<long>();
                    long prior = -1;
                    long describedBytes = 0;
                    bool decoding = false;
                    foreach (ZipEvent entry in ledger.Records)
                    {
                        cancel.ThrowIfCancellationRequested();
                        if (entry.Kind == "local" || entry.Kind == "end")
                        {
                            if (decoding || entry.Offset <= prior || entry.Offset < 0 || entry.Offset >= state.Position)
                                throw new IOException("FRAGMENTED_ZIP_INDEX_INVALID");
                            prior = entry.Offset;
                            if (entry.Kind == "end") { ends.Add(entry.Offset); continue; }
                            Local local;
                            try { local = LocalAt(input, entry.Offset); }
                            catch (Reject) { throw new IOException("FRAGMENTED_ZIP_INDEX_SOURCE_CHANGED"); }
                            List<Local> group;
                            if (!locals.TryGetValue(local.Key, out group)) { group = new List<Local>(); locals.Add(local.Key, group); }
                            group.Add(local); byOffset.Add(local.Offset, local);
                        }
                        else if (entry.Kind == "verified")
                        {
                            decoding = true;
                            Local local;
                            if (!state.ScanComplete || !byOffset.TryGetValue(entry.Offset, out local) || local.Checked ||
                                entry.Valid && !IsHash(entry.RawSha256) || !entry.Valid && entry.RawSha256 != null)
                                throw new IOException("FRAGMENTED_ZIP_VERIFICATION_INVALID");
                            local.Checked = true; local.Valid = entry.Valid; local.RawSha = entry.RawSha256;
                        }
                        else if (entry.Kind == "archive")
                        {
                            decoding = true;
                            if (!state.ScanComplete || report.Files.Count >= MaximumArchives ||
                                !ends.Take(state.NextDirectory).Contains(entry.Offset))
                                throw new IOException("FRAGMENTED_ZIP_PLAN_INVALID");
                            Result result = ReadPlan(run, entry, cancel);
                            ValidatePlan(input, result, byOffset);
                            if (report.Files.Any(x => x.Path == result.Path || x.Sha256 == result.Sha256) || result.Bytes > MaximumOutputBytes - report.OutputBytes)
                                throw new IOException("FRAGMENTED_ZIP_PLAN_INVALID");
                            report.Files.Add(result); report.OutputBytes += result.Bytes;
                            describedBytes += DescriptionBytes(result) + 1L;
                            if (describedBytes > MaximumReportBytes - ReportEnvelopeAllowance)
                                throw new IOException("FRAGMENTED_ZIP_PLAN_METADATA_LIMIT");
                        }
                        else throw new IOException("FRAGMENTED_ZIP_EVENT_INVALID");
                    }
                    if (ends.Count > MaximumDirectories || byOffset.Count > MaximumLocals ||
                        report.Headers < ends.Count + byOffset.Count || state.NextDirectory > ends.Count ||
                        report.LocalRecords != byOffset.Count + (state.Limited && report.LocalRecords == MaximumLocals + 1 ? 1 : 0) ||
                        state.Complete && state.NextDirectory != ends.Count)
                        throw new IOException("FRAGMENTED_ZIP_INDEX_INVALID");
                    report.Recovered = report.Files.Count;
                    ValidateInventory(run, folder, report.Files);
                    foreach (Result result in report.Files) PublishZip(input, run, result, cancel);
                    if (state.Limited) { report.Status = "limited"; throw new IOException("Предыдущий поиск ZIP достиг предела; проход неполный."); }
                    if (progress != null) progress(state.Position, input.Length);
                    byte[] block = new byte[BlockBytes + 3];
                    while (!state.ScanComplete)
                    {
                        cancel.ThrowIfCancellationRequested();
                        long position = state.Position;
                        int count = (int)Math.Min(BlockBytes, input.Length - position);
                        int total = (int)Math.Min(block.Length, input.Length - position);
                        byte[] bytes = Read(input, position, total);
                        Buffer.BlockCopy(bytes, 0, block, 0, total);
                        var events = new List<ZipEvent>();
                        for (int at = 0; at < count && at + 3 < total; at++)
                        {
                            if (block[at] != 80 || block[at + 1] != 75) continue;
                            int type = block[at + 2] | block[at + 3] << 8;
                            if (type != 0x0403 && type != 0x0605) continue;
                            if (++report.Headers > MaximumHeaders || type == 0x0605 && ends.Count >= MaximumDirectories)
                            { state.Limited = true; state.Position = position + at + 1; break; }
                            long offset = position + at;
                            if (type == 0x0605) { ends.Add(offset); events.Add(new ZipEvent { Kind = "end", Offset = offset }); continue; }
                            try
                            {
                                Local local = LocalAt(input, offset);
                                if (++report.LocalRecords > MaximumLocals) { state.Limited = true; state.Position = offset + 1; break; }
                                List<Local> group;
                                if (!locals.TryGetValue(local.Key, out group)) { group = new List<Local>(); locals.Add(local.Key, group); }
                                group.Add(local); byOffset.Add(offset, local);
                                events.Add(new ZipEvent { Kind = "local", Offset = offset });
                            }
                            catch (Reject error) { Skip(report, error.Code); }
                        }
                        if (!state.Limited) state.Position = position + count;
                        state.ScanComplete = state.Position == input.Length;
                        CommitZip(state, report, journal, ledger, events);
                        if (state.Limited) { report.Status = "limited"; throw new IOException("Достигнут предел ZIP-заголовков или каталогов."); }
                        if (progress != null) progress(state.Position, input.Length);
                    }
                    var verifier = new ZipMemberVerifier(input, report, state, journal, ledger, cancel, progress);
                    while (state.NextDirectory < ends.Count)
                    {
                        cancel.ThrowIfCancellationRequested();
                        Result result = null;
                        string rejection = null;
                        try
                        {
                            DirectoryRecord central = DirectoryAt(input, ends[state.NextDirectory]);
                            if (!state.DirectoryStarted)
                            {
                                report.Directories++; state.DirectoryStarted = true;
                                CommitZip(state, report, journal, ledger);
                            }
                            result = AssembleZip(input, central, locals, folder, report, state, journal, ledger, cancel, verifier);
                            if (report.Files.Any(x => x.Sha256 == result.Sha256))
                            {
                                File.Delete(RecoveryCatalog.SafeFile(run, result.Path) + ".partial");
                                Skip(report, "duplicate_archive_bytes"); result = null;
                            }
                        }
                        catch (Reject error) { rejection = error.Code; }
                        verifier.Flush(false);
                        if (rejection != null) Skip(report, rejection);
                        int descriptionBytes = result == null ? 0 : DescriptionBytes(result) + 1;
                        if (descriptionBytes > MaximumReportBytes - ReportEnvelopeAllowance - describedBytes)
                        {
                            // Keep the old report bound, but stop before accepting
                            // a plan that could never be described on completion.
                            state.Limited = true; report.Status = "limited";
                            CommitZip(state, report, journal, ledger);
                            throw new IOException("Достигнут предел описания источников ZIP; проход неполный.");
                        }
                        state.NextDirectory++; state.DirectoryStarted = false;
                        var events = new List<ZipEvent>();
                        if (result != null)
                        {
                            var entry = new ZipEvent { Kind = "archive", Offset = result.EocdOffset };
                            if (journal.Enabled)
                            {
                                entry.PlanPath = "fragmented-zip.state/plans/plan-" + Guid.NewGuid().ToString("N") + ".json";
                                string path = RecoveryCatalog.SafeFile(run, entry.PlanPath);
                                Directory.CreateDirectory(Path.GetDirectoryName(path));
                                RecoveryCore.SaveJsonBounded(path, result, MaximumPlanBytes);
                                entry.PlanSha256 = FileHash(path, cancel);
                            }
                            events.Add(entry);
                        }
                        CommitZip(state, report, journal, ledger, events);
                        if (result != null)
                        {
                            report.Files.Add(result); report.Recovered++; report.OutputBytes += result.Bytes;
                            describedBytes += descriptionBytes;
                            PublishZip(input, run, result, cancel);
                        }
                        if (progress != null) progress(state.Position, input.Length);
                    }
                    state.Complete = true;
                    CommitZip(state, report, journal, ledger);
                }
                report.Status = "complete";
                return report.Recovered;
            }
            catch (OperationCanceledException) { report.Status = "cancelled"; throw; }
            catch (IOException) { if (report.Status != "limited") report.Status = "incomplete"; throw; }
            finally { RecoveryCore.SaveJsonBounded(reportPath, report, MaximumReportBytes); }
        }
    }
}
