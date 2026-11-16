using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class FatCheckpointTests
{
    public sealed class Expected { public long bytes, offset; public string sha256; public int directory, member; }
    public sealed class Manifest { public string image_sha256; public List<Expected> files; }
    static int checks;
    static string phase = "setup";
    static string work, fixtures;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static void RunCase(string name, Action action) { phase = name; action(); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static RecoveryOptions Options() { return new RecoveryOptions { FatMetadata = true, NtfsMetadata = false,
        LostPartitions = false, Signatures = false, EmbeddedPhotos = false, Containers = false }; }
    static Dictionary<string, object> Payload(string root)
    {
        var stage = RecoverySession.Read(root).Stages.Single();
        Check(stage.CheckpointPath != null && stage.CheckpointSequence > 0, "FAT pins an internal checkpoint");
        string path = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
        Check(Hash(path) == stage.CheckpointSha256, "parent pins exact FAT cursor bytes");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8))["Payload"];
    }
    static Dictionary<string, object> Current(string root) { return (Dictionary<string, object>)Payload(root)["Current"]; }
    static void Validate(string root, bool alternate = false, bool orphan = false)
    {
        var expected = Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures, "directories.json"), Encoding.UTF8));
        var index = RecoveryCatalog.Load(root);
        Check(index.Items.Count == expected.files.Count + (orphan ? 1 : 0) && index.Candidates == expected.files.Count * (alternate ? 2 : 1) + (orphan ? 1 : 0), "all and only expected owned payloads recovered");
        foreach (var wanted in expected.files)
        {
            var item = index.Items.Single(x => x.Sha256 == wanted.sha256);
            Check(item.Bytes == wanted.bytes && Hash(RecoveryCatalog.SafeFile(root, item.Path)) == wanted.sha256, "exact independent payload bytes");
            Check((alternate ? item.SourceOffset == null && item.SourceMapGroups.Count == 2 : item.SourceOffset == wanted.offset) &&
                item.SourceRanges.Count == 1 && item.SourceRanges[0].Offset == wanted.offset && item.SourceRanges[0].Length == wanted.bytes,
                "exact metadata-derived source range");
        }
        string csv = File.ReadAllText(Path.Combine(root, "filesystem", "metadata.csv"), Encoding.UTF8);
        Check(csv.Contains("cluster currently owned by a live file/directory"), "late-discovered live owner remains excluded");
        if (orphan) Check(index.Items.Any(x => x.Sha256 == Hash(Path.Combine(fixtures, "orphan-original.bin"))) && csv.Contains("orphan-contiguous-guess"), "unlinked directory bytes recovered with explicit uncertain origin");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "same FAT attempt resumes");
        string report = Hash(Path.Combine(root, "filesystem", "report.json"));
        Check(RecoveryPipeline.Resume(root, CancellationToken.None, m => { }).ResumedStages == 1 &&
            Hash(Path.Combine(root, "filesystem", "report.json")) == report, "completed FAT stage reused unchanged");
    }
    static void CancelResume(bool duringExport, bool missing)
    {
        string image = Path.Combine(fixtures, "directories.dd"), root = Path.Combine(work, Guid.NewGuid().ToString("N"));
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, Options(), cancel.Token, message =>
            {
                if (duringExport)
                { if (message.StartsWith("По метаданным сохранено:", StringComparison.Ordinal)) cancel.Cancel(); }
                else if (message.StartsWith("FAT/exFAT: каталоги 2;", StringComparison.Ordinal)) cancel.Cancel();
            }, image + ".sha256"); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && !File.Exists(Path.Combine(root, "files-index.json")), "cancelled FAT pass has no successful catalog");
        var current = Current(root);
        if (!duringExport) Check(Convert.ToInt32(current["MainVisited"]) == 2 && Convert.ToInt32(current["QueueCursor"]) == 2,
            "directory cursor commits the actual consumed queue prefix");
        else
        {
            Check(Convert.ToInt32(current["ExportCursor"]) == 1, "export cursor advances only for a committed output plan");
            if (missing) File.Delete(Directory.GetFiles(Path.Combine(root, "filesystem", "files"), "*", SearchOption.AllDirectories).Single());
        }
        string first = null;
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { if (first == null && m.StartsWith("FAT/exFAT: каталоги", StringComparison.Ordinal)) first = m; });
        Check(first != null && first.StartsWith(duringExport ? "FAT/exFAT: каталоги 11;" : "FAT/exFAT: каталоги 2;", StringComparison.Ordinal),
            "resume begins at the saved traversal unit rather than the root");
        Validate(root);
    }
    static void Rejected(string kind)
    {
        string image = Path.Combine(work, "source-" + kind + ".dd"), root = Path.Combine(work, "tamper-" + kind);
        File.Copy(Path.Combine(fixtures, "directories.dd"), image); File.Copy(Path.Combine(fixtures, "directories.dd.sha256"), image + ".sha256");
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, Options(), cancel.Token,
                m => { if (m.StartsWith("По метаданным сохранено:", StringComparison.Ordinal)) cancel.Cancel(); }, image + ".sha256"); }
            catch (OperationCanceledException) { }
        }
        string target;
        if (kind == "source") target = image;
        else if (kind == "output") target = Directory.GetFiles(Path.Combine(root, "filesystem", "files"), "*", SearchOption.AllDirectories).Single();
        else if (kind == "plan") target = Directory.GetFiles(Path.Combine(root, "fat.state", "plans")).First();
        else if (kind == "ledger") target = RecoveryCatalog.SafeFile(root, (string)((Dictionary<string, object>)Current(root)["Metadata"])["Path"]);
        else if (kind == "checkpoint") target = RecoveryCatalog.SafeFile(root, RecoverySession.Read(root).Stages.Single().CheckpointPath);
        else target = Path.Combine(root, "filesystem", "files", "unknown.bin");
        if (kind == "unknown") File.WriteAllText(target, "owned unrelated file");
        else using (var file = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            { int value = file.ReadByte(); file.Position = 0; file.WriteByte((byte)(value ^ 1)); }
        string changed = Hash(target); bool rejected = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(target) == changed && !File.Exists(Path.Combine(root, "files-index.json")), "reject and preserve changed " + kind);
    }
    static void FailedParent()
    {
        string image = Path.Combine(fixtures, "directories.dd"), root = Path.Combine(work, "denied-parent"), parent = Path.Combine(root, RecoverySession.FileName);
        bool failed = false;
        try { RecoveryPipeline.Run(image, root, Options(), CancellationToken.None,
            m => { if (m.StartsWith("FAT/exFAT: каталоги 2;", StringComparison.Ordinal)) File.SetAttributes(parent, FileAttributes.ReadOnly); }, image + ".sha256"); }
        catch (IOException) { failed = true; } catch (UnauthorizedAccessException) { failed = true; }
        finally { if (File.Exists(parent)) File.SetAttributes(parent, FileAttributes.Normal); }
        Check(failed && Convert.ToInt32(Current(root)["MainVisited"]) == 2, "failed parent write cannot advance directory cursor");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root);
    }
    static object Context(string root, string image, RecoverySession session, Action<RecoveryMethodCheckpoint> commit)
    {
        var type = typeof(FilesystemRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true);
        object context = Activator.CreateInstance(type, true);
        type.GetField("Directory").SetValue(context, root); type.GetField("Method").SetValue(context, "fat");
        type.GetField("SourceSha256").SetValue(context, Hash(image));
        type.GetField("Settings").SetValue(context, Json.Serialize(new { alternateFat = false, orphanDirectories = false, discovered = (List<BootCandidate>)null }));
        type.GetField("Commit").SetValue(context, commit); return context;
    }
    static void Invoke(string image, string root, object context)
    {
        typeof(FilesystemRecovery).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(x => x.Name == "Recover" && x.GetParameters().Length == 8)
            .Invoke(null, new object[] { image, root, CancellationToken.None, (Action<string>)(m => { }), null, false, false, context });
    }
    static void FailedIo(bool publication, bool deleteScratch)
    {
        string image = Path.Combine(fixtures, "directories.dd"), root = Path.Combine(work, "io-" + publication + "-" + deleteScratch);
        Directory.CreateDirectory(root);
        var session = RecoverySession.Start(root, image, Hash(image), Options(), CancellationToken.None); session.Begin("fat");
        FileStream lease = null; long lockOffset = 0; bool locked = false;
        Action<RecoveryMethodCheckpoint> commit = value =>
        {
            session.CaptureMethodCheckpoint("fat", value);
            if (lease != null) return;
            var payload = (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(value.Path, Encoding.UTF8))["Payload"];
            var current = (Dictionary<string, object>)payload["Current"];
            if (publication && Convert.ToInt32(payload["Number"]) == 1)
                lease = new FileStream(Path.Combine(root, "fat.state", "work", "file-000001.partial"), FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!publication && (string)current["Phase"] == "export")
            {
                var manifest = Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures, "directories.json"), Encoding.UTF8));
                lockOffset = manifest.files.First().offset;
                lease = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read); lease.Lock(lockOffset, 1); locked = true;
            }
        };
        bool failed = false;
        try { Invoke(image, root, Context(root, image, session, commit)); }
        catch (TargetInvocationException error) { if (!(error.InnerException is IOException)) throw; failed = true; }
        finally { if (lease != null) { if (locked) lease.Unlock(lockOffset, 1); lease.Dispose(); } }
        string namedRoot = Path.Combine(root, "filesystem", "files");
        Check(failed && lease != null && (!Directory.Exists(namedRoot) || Directory.GetFiles(namedRoot, "*", SearchOption.AllDirectories).Length == 0),
            "real source/publication I/O failure leaves named files unpublished");
        var saved = Payload(root);
        Check(Convert.ToInt32(saved["Number"]) == (publication ? 1 : 0), "only write-ahead-confirmed output affects durable counters");
        if (deleteScratch) File.Delete(Path.Combine(root, "fat.state", "work", "file-000001.partial"));
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root);
    }
    static void KilledProcess()
    {
        string image = Path.Combine(fixtures, "directories.dd"), root = Path.Combine(work, "killed"), ready = root + ".ready";
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "child \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var watch = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned FAT worker reaches a committed directory boundary");
                child.Kill(); Check(child.WaitForExit(10000), "owned worker terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Check(Convert.ToInt32(Current(root)["MainVisited"]) == 2, "crash retains directory progress");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root);
    }
    static void OrphanResume()
    {
        string image = Path.Combine(fixtures, "directories.dd"), root = Path.Combine(work, "orphans");
        var options = Options(); options.OrphanDirectories = true;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, options, cancel.Token,
                m => { if (m.StartsWith("Потерянные каталоги FAT:", StringComparison.Ordinal)) cancel.Cancel(); }, image + ".sha256"); }
            catch (OperationCanceledException) { }
        }
        var before = Current(root);
        Check((string)before["Phase"] == "orphan" && Convert.ToInt64(before["OrphanCluster"]) > 0 && Convert.ToInt32(before["OrphanFound"]) == 1,
            "orphan sweep commits the physical scan cursor and pending directory");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root, false, true);
    }
    static void AlternateFat()
    {
        string image = Path.Combine(fixtures, "directories.dd"), root = Path.Combine(work, "alternate");
        var options = Options(); options.AlternateFat = true;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, options, cancel.Token,
                m => { if (m.StartsWith("По метаданным сохранено:", StringComparison.Ordinal) && Convert.ToInt32(Payload(root)["VolumeIndex"]) == 1) cancel.Cancel(); }, image + ".sha256"); }
            catch (OperationCanceledException) { }
        }
        Check(Convert.ToInt32(Payload(root)["VolumeIndex"]) == 1, "first independent FAT interpretation is already committed");
        string previous = Directory.GetFiles(Path.Combine(root, "filesystem", "files", "volume-001-FAT16"), "*", SearchOption.AllDirectories).First();
        File.Delete(previous);
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        Check(File.Exists(previous), "missing previous-volume output repaired using that volume's pinned ownership metadata");
        Validate(root, true);
    }
    static void AlternateFreshProcess()
    {
        string root = Path.Combine(work, "alternate-fresh-process");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
            "alternate \"" + root + "\" \"" + fixtures + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try {
                Check(child.WaitForExit(60000), "fresh-process alternate FAT repair completes within the test deadline");
                string output = child.StandardOutput.ReadToEnd(), error = child.StandardError.ReadToEnd();
                if (child.ExitCode != 0) { Console.Error.WriteLine(output); Console.Error.WriteLine(error); }
                Check(child.ExitCode == 0, "alternate FAT missing output is repaired in a clean en-US process");
            } finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
    }
    static void PlanIdentity()
    {
        Type type = typeof(FilesystemRecovery).GetNestedType("FsCandidatePlan", BindingFlags.NonPublic);
        MethodInfo compare = typeof(FilesystemRecovery).GetMethod("SamePlan", BindingFlags.NonPublic | BindingFlags.Static);
        string sample = "{\"Schema\":1,\"VolumeIndex\":0,\"CandidateIndex\":1,\"Number\":2,\"Candidate\":{\"Name\":\"photo.jpg\",\"OriginalPath\":\"/photo.jpg\",\"NameNote\":\"owned identity control\",\"Start\":10,\"Length\":1024,\"ValidLength\":1024,\"Contiguous\":true},\"FileSystem\":\"FAT16\",\"Method\":\"contiguous-guess\",\"Status\":\"uncertain\",\"Reason\":\"owned control\",\"Path\":\"filesystem/files/control.bin\",\"Sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"VolumeOffset\":0,\"Bytes\":1024,\"InitializedBytes\":1024,\"MappingComplete\":true,\"Ranges\":[{\"Offset\":4096,\"Length\":512},{\"Offset\":8192,\"Length\":512}]}";
        object original = Json.Deserialize(sample, type);
        Check((bool)compare.Invoke(null, new[] { original, Json.Deserialize(sample, type) }), "independent objects with identical plan values have the same repair identity");
        foreach (FieldInfo field in type.GetFields())
        {
            object changed = Json.Deserialize(sample, type), value = field.GetValue(changed);
            if (field.FieldType == typeof(int)) field.SetValue(changed, (int)value + 1);
            else if (field.FieldType == typeof(long)) field.SetValue(changed, (long)value + 1);
            else if (field.FieldType == typeof(bool)) field.SetValue(changed, !(bool)value);
            else if (field.FieldType == typeof(string)) field.SetValue(changed, (string)value + "changed");
            else field.SetValue(changed, null);
            Check(!(bool)compare.Invoke(null, new[] { original, changed }), "repair identity rejects changed plan field " + field.Name);
        }
        var candidateField = type.GetField("Candidate");
        foreach (FieldInfo field in candidateField.FieldType.GetFields())
        {
            object changed = Json.Deserialize(sample, type), candidate = candidateField.GetValue(changed), value = field.GetValue(candidate);
            if (field.FieldType == typeof(uint)) field.SetValue(candidate, (uint)value + 1);
            else if (field.FieldType == typeof(long)) field.SetValue(candidate, (long)value + 1);
            else if (field.FieldType == typeof(bool)) field.SetValue(candidate, !(bool)value);
            else field.SetValue(candidate, (string)value + "changed");
            Check(!(bool)compare.Invoke(null, new[] { original, changed }), "repair identity rejects changed candidate field " + field.Name);
        }
        object moved = Json.Deserialize(sample, type);
        var ranges = (List<FileExtent>)type.GetField("Ranges").GetValue(moved); ranges.Reverse();
        Check(!(bool)compare.Invoke(null, new[] { original, moved }), "repair identity preserves source extent order");
        moved = Json.Deserialize(sample, type); ((List<FileExtent>)type.GetField("Ranges").GetValue(moved))[0].Length--;
        Check(!(bool)compare.Invoke(null, new[] { original, moved }), "repair identity preserves each source extent length");
    }
    static byte[] Pattern(int size, int seed) { byte[] bytes = new byte[size]; new Random(seed).NextBytes(bytes); return bytes; }
    static void Exfat()
    {
        var producer = new FilesystemRecoveryTests.ExFixture();
        byte[] zeroTail = Pattern(700, 111), fragmented = Pattern(1100, 222), partial = Pattern(700, 333), suffix = Pattern(100, 444);
        int slot = producer.Entry(1, "zero-tail.bin", 10, zeroTail, true, true, 100);
        slot = producer.Entry(slot, "fragmented.bin", 30, fragmented, true, false, fragmented.Length);
        slot = producer.Entry(slot, "reallocated.bin", 50, partial, true, true, partial.Length); producer.Allocated(51, true);
        producer.Entry(slot, "private.partial", 70, suffix, true, true, suffix.Length);
        string image = Path.Combine(work, "exfat.dd"), root = Path.Combine(work, "exfat"); File.WriteAllBytes(image, producer.Bytes); File.WriteAllText(image + ".sha256", Hash(image));
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, Options(), cancel.Token, m => { if (m.StartsWith("По метаданным сохранено:", StringComparison.Ordinal)) cancel.Cancel(); }, image + ".sha256"); }
            catch (OperationCanceledException) { }
        }
        Check((bool)Current(root)["BitmapValid"], "exFAT active allocation bitmap is durably preserved");
        File.Delete(Directory.GetFiles(Path.Combine(root, "filesystem", "files"), "*", SearchOption.AllDirectories).Single());
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        var items = RecoveryCatalog.Load(root).Items;
        Check(items.Count == 4, "exFAT outputs and partial-suffixed original remain visible");
        var zero = items.Single(x => x.Name.EndsWith("zero-tail.bin")); byte[] actual = File.ReadAllBytes(RecoveryCatalog.SafeFile(root, zero.Path));
        Check(actual.Take(100).SequenceEqual(zeroTail.Take(100)) && actual.Skip(100).All(x => x == 0) && actual.Length == 700, "repaired exFAT uninitialized tail stays logical zeroes");
        Check(items.Any(x => x.Name.EndsWith("fragmented.bin") && File.ReadAllBytes(RecoveryCatalog.SafeFile(root, x.Path)).SequenceEqual(fragmented)), "retained exFAT fragmentation restored byte exactly");
        Check(items.Any(x => x.Name.Contains("PARTIAL") && File.ReadAllBytes(RecoveryCatalog.SafeFile(root, x.Path)).SequenceEqual(partial.Take(512))), "exFAT reallocation remains a safe partial prefix");
        Check(items.Any(x => x.Name.EndsWith("private.partial.recovered")), "a finished source .partial name is not hidden as scratch");
    }
    static void ReportsAfterFailure()
    {
        string image = Path.Combine(fixtures, "directories.dd"), root = Path.Combine(work, "report-publish");
        FileStream lease = null; bool failed = false;
        try
        {
            RecoveryPipeline.Run(image, root, Options(), CancellationToken.None, message =>
            {
                if (lease != null || !message.StartsWith("По метаданным сохранено:", StringComparison.Ordinal)) return;
                string path = Path.Combine(root, "filesystem", "metadata.csv"); File.WriteAllText(path, "owned pre-existing derived report");
                lease = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            }, image + ".sha256");
        }
        catch (IOException) { failed = true; }
        finally { if (lease != null) lease.Dispose(); }
        Check(failed && lease != null && (bool)Payload(root)["Complete"], "report publication failure preserves the fully traversed/exported checkpoint");
        string sample = Directory.GetFiles(Path.Combine(root, "filesystem", "files"), "*", SearchOption.AllDirectories).First();
        DateTime stamp = File.GetLastWriteTimeUtc(sample); bool traversal = false;
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { if (m.StartsWith("FAT/exFAT: каталоги", StringComparison.Ordinal)) traversal = true; });
        Check(!traversal && File.GetLastWriteTimeUtc(sample) == stamp, "report repair neither restarts traversal nor rewrites confirmed data");
        Validate(root);
    }
    static void TruncatedEvidenceRepair()
    {
        string image = Path.Combine(fixtures, "map-limit.dd"), root = Path.Combine(work, "map-limit");
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, Options(), cancel.Token, m => { if (m.StartsWith("По метаданным сохранено:", StringComparison.Ordinal)) cancel.Cancel(); }, image + ".sha256"); }
            catch (OperationCanceledException) { }
        }
        string plan = Directory.GetFiles(Path.Combine(root, "fat.state", "plans")).Single();
        var recorded = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(plan, Encoding.UTF8));
        Check(!(bool)recorded["MappingComplete"] && Json.ConvertToType<List<FileExtent>>(recorded["Ranges"]).Count == 100000,
            "large retained chain explicitly records a capped/incomplete source map");
        string file = Directory.GetFiles(Path.Combine(root, "filesystem", "files"), "*", SearchOption.AllDirectories).Single();
        File.Delete(file);
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        string original = Path.Combine(fixtures, "map-limit-original.bin");
        Check(File.Exists(file) && Hash(file) == Hash(original) && new FileInfo(file).Length == new FileInfo(original).Length,
            "repair re-derives the full retained chain instead of copying a truncated saved map");
        Check(Hash(image) == File.ReadAllText(image + ".sha256").Trim(), "large map fixture remains unchanged");
    }
    public static int Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "alternate")
        {
            try {
                Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
                work = Path.GetFullPath(args[1]); fixtures = Path.GetFullPath(args[2]); Directory.CreateDirectory(work);
                AlternateFat(); Console.WriteLine("PASS isolated alternate FAT repair: " + checks); return 0;
            } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        }
        if (args.Length == 4 && args[0] == "child")
        {
            RecoveryPipeline.Run(args[1], args[2], Options(), CancellationToken.None,
                m => { if (m.StartsWith("FAT/exFAT: каталоги 2;", StringComparison.Ordinal)) { File.WriteAllText(args[3], "ready"); Thread.Sleep(Timeout.Infinite); } }, args[1] + ".sha256");
            return 3;
        }
        try
        {
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "fat-checkpoints-" + Guid.NewGuid().ToString("N"));
            fixtures = Path.GetFullPath(args[1]); Directory.CreateDirectory(work);
            RunCase("directory-cancel", () => CancelResume(false, false));
            RunCase("export-cancel", () => CancelResume(true, false));
            RunCase("missing-export", () => CancelResume(true, true));
            RunCase("parent-write-denied", FailedParent);
            RunCase("publish-denied", () => FailedIo(true, false));
            RunCase("publish-denied-missing-scratch", () => FailedIo(true, true));
            RunCase("source-read-denied", () => FailedIo(false, false));
            RunCase("worker-killed", KilledProcess);
            RunCase("orphan-cancel", OrphanResume);
            RunCase("alternate-fat", AlternateFat);
            RunCase("alternate-fat-fresh-process", AlternateFreshProcess);
            RunCase("plan-identity-fields", PlanIdentity);
            RunCase("exfat", Exfat);
            RunCase("report-publish-denied", ReportsAfterFailure);
            RunCase("large-map-repair", TruncatedEvidenceRepair);
            foreach (string kind in new[] { "source", "output", "plan", "ledger", "checkpoint", "unknown" })
                RunCase("changed-" + kind, () => Rejected(kind));
            phase = "source-unchanged";
            Check(Hash(Path.Combine(fixtures, "directories.dd")) == File.ReadAllText(Path.Combine(fixtures, "directories.dd.sha256")).Trim(), "owned FAT image unchanged");
            Console.WriteLine("PASS FatCheckpoint: " + checks + " checks; real directory/export/orphan cursors, cancel/kill, owned OS read/rename failures, parent denial, exFAT/alternate ownership, repair and tamper; structural owned images only");
            return 0;
        }
        catch (Exception error)
        {
            if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true")
            {
                // Only owned case labels, counters and method identifiers: no
                // exception values, source bytes, filesystem paths or locals.
                var frames = new StackTrace(error, false).GetFrames() ?? new StackFrame[0];
                string location = String.Join(" > ", frames.Take(6).Select(frame =>
                {
                    var method = frame.GetMethod();
                    return method == null ? "unknown" : method.DeclaringType == null ? method.Name : method.DeclaringType.Name + "." + method.Name;
                }));
                Console.WriteLine("::error title=FAT checkpoint failure location::" + phase + "; check=" + checks +
                    "; " + error.GetType().Name + "; hr=" + error.HResult.ToString("x8") + "; " + location);
            }
            Console.Error.WriteLine(error); return 1;
        }
    }
}
