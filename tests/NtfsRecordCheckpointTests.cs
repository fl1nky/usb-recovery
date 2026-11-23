using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class NtfsRecordCheckpointTests
{
    static int checks;
    static string project, fixtures, work;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 128 * 1024 * 1024 };
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static string Fresh() { return Path.Combine(work, Guid.NewGuid().ToString("N")); }
    static RecoveryOptions Options() { return new RecoveryOptions { FatMetadata = false, NtfsMetadata = false,
        LostPartitions = false, Signatures = false, Containers = false, EmbeddedPhotos = false, MetadataRescue = true }; }
    static Dictionary<string, object> Object(string path) { return Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8)); }
    static Dictionary<string, object> Payload(string root)
    {
        var stage = RecoverySession.Read(root).Stages.Single();
        Check(stage.Key == "ntfs-records" && stage.CheckpointPath != null && stage.CheckpointSequence > 0, "NTFS records have an actual parent-pinned inner cursor");
        string path = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
        Check(Hash(path) == stage.CheckpointSha256, "parent pins exact checkpoint bytes");
        return (Dictionary<string, object>)Object(path)["Payload"];
    }
    static void Run(string image, string root, CancellationToken token, Action<string> progress)
    { RecoveryPipeline.Run(image, root, Options(), token, progress); }
    static void Validate(string root)
    {
        var expected = (System.Collections.IList)Object(Path.Combine(fixtures, "manifest.json"))["files"];
        var report = Json.Deserialize<MetadataRescue.Report>(File.ReadAllText(Path.Combine(root, "metadata-rescue", "report.json"), Encoding.UTF8));
        var catalog = RecoveryCatalog.Load(root);
        Check(report.RecoveredFiles == 80 && report.Entries.Count == 80 && catalog.Items.Count == 80, "all and only eighty resident originals survive");
        foreach (Dictionary<string, object> wanted in expected)
        {
            string sha = (string)wanted["sha256"];
            var item = catalog.Items.Single(x => x.Sha256 == sha);
            Check(item.Bytes == Convert.ToInt64(wanted["bytes"]) && Hash(RecoveryCatalog.SafeFile(root, item.Path)) == sha, "independent original bytes including USA-tail substitutions");
            var entry = report.Entries.Single(x => x.Sha256 == sha);
            Check(entry.UsaFixupsRestored && entry.RecordOffset == Convert.ToInt64(wanted["record_offset"]) &&
                entry.Name == (string)wanted["name"] && entry.OriginalPath == null, "record identity retained; unknown parent path stays unknown");
        }
        Check(report.Entries.Single(x => x.Name == "private.partial").Output.EndsWith(".partial.recovered", StringComparison.Ordinal), "original name cannot hide a completed output as scratch");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "unfinished method resumes the same attempt");
        Check(Convert.ToBoolean(Object(Path.Combine(root, "metadata-rescue", "report.json"))["Completed"]), "derived report declares completed traversal");
        string before = Hash(Path.Combine(root, "metadata-rescue", "report.json"));
        Check(RecoveryPipeline.Resume(root, CancellationToken.None, m => { }).ResumedStages == 1 &&
            Hash(Path.Combine(root, "metadata-rescue", "report.json")) == before, "completed stage reused without rewriting reports");
    }
    static string Cancelled(bool export, string image = null)
    {
        string root = Fresh(); bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { Run(image ?? Path.Combine(fixtures, "records.dd"), root, cancel.Token, m =>
            {
                if (export ? m.StartsWith("Записи NTFS: сохранено 1;", StringComparison.Ordinal) :
                    m.StartsWith("Записи NTFS: просмотрено 4 МБ", StringComparison.Ordinal)) cancel.Cancel();
            }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && !File.Exists(Path.Combine(root, "files-index.json")), "cancelled search publishes no successful catalog");
        return root;
    }
    static void CancelResume(bool export, bool missing)
    {
        string root = Cancelled(export); var payload = Payload(root);
        Check(Convert.ToInt64(payload["ScanOffset"]) == (export ? 16 : 4) * 1024 * 1024 &&
            Convert.ToInt32(payload["ExportCursor"]) == (export ? 1 : 0), "cursor consumes the actual scan/export prefix");
        CandidateStorage(root, true);
        if (missing) File.Delete(Directory.GetFiles(Path.Combine(root, "metadata-rescue", "files")).Single());
        int first = -1;
        RecoveryPipeline.Resume(root, CancellationToken.None, m =>
        {
            const string prefix = "Записи NTFS: просмотрено ";
            if (first < 0 && m.StartsWith(prefix, StringComparison.Ordinal)) first = Int32.Parse(m.Substring(prefix.Length).Split(' ')[0]);
        });
        Check(first == (export ? 16 : 4), "resume starts at saved byte position, never rescans the image prefix"); Validate(root);
    }
    static void Kill(bool export)
    {
        string root = Fresh(), ready = root + ".ready";
        string args = "worker \"" + project + "\" \"" + fixtures + "\" \"" + root + "\" \"" + ready + "\" " + (export ? "export" : "scan");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, args)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var clock = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && clock.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned worker reaches committed scan/export boundary"); child.Kill();
                Check(child.WaitForExit(10000), "owned worker really terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Payload(root); RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root);
    }
    static void ParentAndReadFailures(bool read)
    {
        string image = Path.Combine(fixtures, "records.dd"), root = Fresh(); FileStream lease = null; bool failed = false;
        try
        {
            Run(image, root, CancellationToken.None, m =>
            {
                if (lease != null || !m.StartsWith("Записи NTFS: просмотрено 4 МБ", StringComparison.Ordinal)) return;
                lease = new FileStream(read ? image : Path.Combine(root, RecoverySession.FileName), FileMode.Open, FileAccess.Read, FileShare.Read);
                if (read) lease.Lock(8 * 1024 * 1024, 512);
            });
        }
        catch (IOException) { failed = true; }
        finally { if (lease != null) { if (read) lease.Unlock(8 * 1024 * 1024, 512); lease.Dispose(); } }
        Check(failed, read ? "actual owned Windows range lock interrupts source reading" : "actual parent replacement denial interrupts checkpoint publication");
        Check(Convert.ToInt64(Payload(root)["ScanOffset"]) >= 4 * 1024 * 1024, "previous committed position remains authoritative after I/O failure");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root);
    }
    static void InternalRun(string image, string root, Action<RecoveryMethodCheckpoint> boundary)
    {
        Directory.CreateDirectory(root);
        var session = RecoverySession.Start(root, image, Hash(image), Options(), CancellationToken.None); session.Begin("ntfs-records");
        var type = typeof(MetadataRescue).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true);
        var context = Activator.CreateInstance(type, true);
        type.GetField("Directory").SetValue(context, root); type.GetField("Method").SetValue(context, "ntfs-records");
        type.GetField("SourceSha256").SetValue(context, Hash(image));
        type.GetField("Settings").SetValue(context, Json.Serialize(new { unknownAllocation = false, discovered = (object)null }));
        type.GetField("Commit").SetValue(context, new Action<RecoveryMethodCheckpoint>(value =>
        { session.CaptureMethodCheckpoint("ntfs-records", value); boundary(value); }));
        var method = typeof(MetadataRescue).GetMethods(BindingFlags.Static | BindingFlags.NonPublic).Single(m => m.Name == "Recover" && m.GetParameters().Length == 7);
        try { method.Invoke(null, new object[] { image, root, CancellationToken.None, new Action<string>(m => { }), null, false, context }); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }
    static void PublicationFailure(bool report)
    {
        string image = Path.Combine(fixtures, "records.dd"), root = Fresh(); FileStream lease = null; bool failed = false;
        try
        {
            InternalRun(image, root, checkpoint =>
            {
                if (lease != null) return;
                var payload = (Dictionary<string, object>)Object(checkpoint.Path)["Payload"];
                if (report ? (string)payload["Phase"] != "complete" : Convert.ToInt32(payload["ExportCursor"]) != 1) return;
                string path = report ? Path.Combine(root, "metadata-rescue", "report.json") : Path.Combine(root, "ntfs-records.state", "work", "record-000000.partial");
                if (report) File.WriteAllText(path, "owned previous report");
                lease = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            });
        }
        catch (IOException) { failed = true; }
        finally { if (lease != null) lease.Dispose(); }
        Check(failed && Convert.ToInt32(Payload(root)["ExportCursor"]) == (report ? 80 : 1), "actual rename/report denial leaves committed output plans");
        if (!report)
        {
            Check(Directory.GetFiles(Path.Combine(root, "metadata-rescue", "files")).Length == 0, "unpublished scratch is not a recovered named file");
            File.Delete(Path.Combine(root, "ntfs-records.state", "work", "record-000000.partial"));
        }
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root);
    }
    static void NativeAndCaches()
    {
        string image = Path.Combine(fixtures, "legacy-usa-fixed.dd"), before = Hash(image), root = Cancelled(true, image);
        File.Delete(Directory.GetFiles(Path.Combine(root, "metadata-rescue", "files")).Single());
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        var catalog = RecoveryCatalog.Load(root);
        Check(catalog.Items.Count == 1 && catalog.Items.Single().Sha256 == Hash(Path.Combine(fixtures, "legacy-expected.jpg")) && Hash(image) == before,
            "historical native-format fragmented JPEG repaired exactly from source metadata");
        image = Path.Combine(fixtures, "paths.dd"); root = Cancelled(true, image);
        var counters = (Dictionary<string, object>)Payload(root)["Counters"];
        Check(Convert.ToInt32(counters["DirectoryRecordsChecked"]) == 3, "first path pins three actual current-MFT parent nodes");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        var report = Json.Deserialize<MetadataRescue.Report>(File.ReadAllText(Path.Combine(root, "metadata-rescue", "report.json"), Encoding.UTF8));
        Check(report.RecoveredFiles == 5 && report.ResolvedPaths == 3 && report.UnresolvedPaths == 2 && report.DirectoryRecordsChecked == 4,
            "valid and invalid shared parent caches survive resume without resetting or double charging read budget");
        Check(report.Entries.Take(3).All(x => x.OriginalPath != null && x.OriginalPath.StartsWith("/Архив/Предки/", StringComparison.Ordinal)) &&
            report.Entries.Skip(3).All(x => x.OriginalPath == null), "verified ancestry retained; missing parent remains unknown");
    }
    static void Tamper(string kind)
    {
        string root = Cancelled(kind == "output" || kind == "plan" || kind == "extra"); var payload = Payload(root);
        if (kind == "output") File.WriteAllText(Directory.GetFiles(Path.Combine(root, "metadata-rescue", "files")).Single(), "changed");
        else if (kind == "extra") File.WriteAllText(Path.Combine(root, "metadata-rescue", "files", "unexpected.bin"), "unknown");
        else if (kind == "checkpoint") File.AppendAllText(RecoveryCatalog.SafeFile(root, RecoverySession.Read(root).Stages.Single().CheckpointPath), " ");
        else if (kind == "plan")
        {
            var head = (Dictionary<string, object>)payload["Outputs"];
            var row = (Dictionary<string, object>)((System.Collections.IList)Object(RecoveryCatalog.SafeFile(root, (string)head["Path"]))["Records"])[0];
            File.AppendAllText(RecoveryCatalog.SafeFile(root, (string)row["Path"]), " ");
        }
        else
        {
            var head = (Dictionary<string, object>)payload["Metadata"];
            File.AppendAllText(RecoveryCatalog.SafeFile(root, (string)head["Path"]), " ");
        }
        bool failed = false; try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); } catch (IOException) { failed = true; }
        Check(failed, "changed " + kind + " cannot be silently accepted or replaced");
    }
    static void MapAndShortRead()
    {
        string source = Fresh() + ".dd"; File.Copy(Path.Combine(fixtures, "records.dd"), source);
        File.WriteAllText(source + ".sha256", Hash(source));
        string root = Cancelled(false, source);
        File.WriteAllText(source + ".read-errors.json", Json.Serialize(new { unreadBytes = 0, ranges = new object[0], size = new FileInfo(source).Length, status = "complete" }));
        bool failed = false; try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); } catch (IOException) { failed = true; }
        Check(failed, "changed allocation-trust map identity invalidates resume even with unchanged image bytes");
        var method = typeof(MetadataRescue).GetMethod("ReadScanUnit", BindingFlags.Static | BindingFlags.NonPublic);
        using (var stream = new MemoryStream(new byte[10]))
        {
            failed = false; try { method.Invoke(null, new object[] { stream, new byte[16], 16 }); }
            catch (TargetInvocationException error) { failed = error.InnerException is IOException; }
            Check(failed, "unexpected short scan read propagates as I/O error; injected stream, not a USB disconnection claim");
        }
    }
    static void PersistentBudgets(bool runs)
    {
        string image = Path.Combine(fixtures, runs ? "run-limit.dd" : "candidate-limit.dd"), root = Fresh();
        long previous = 0, length = new FileInfo(image).Length;
        while (previous < length)
        {
            bool stopped = false;
            using (var cancel = new CancellationTokenSource())
            {
                Action<string> progress = message =>
                {
                    const string prefix = "Записи NTFS: просмотрено ";
                    if (message.StartsWith(prefix, StringComparison.Ordinal) &&
                        Int64.Parse(message.Substring(prefix.Length).Split(' ')[0]) * 1024 * 1024 > previous) cancel.Cancel();
                };
                try { if (previous == 0) Run(image, root, cancel.Token, progress); else RecoveryPipeline.Resume(root, cancel.Token, progress); }
                catch (OperationCanceledException) { stopped = true; }
            }
            var payload = Payload(root); long current = Convert.ToInt64(payload["ScanOffset"]);
            Check(stopped && current > previous && current <= length, "bounded scan unit advances over repeated cancellation"); previous = current;
        }
        var saved = Payload(root); var counters = (Dictionary<string, object>)saved["Counters"];
        var head = (Dictionary<string, object>)saved["Metadata"];
        Check(Convert.ToBoolean(counters["CandidateLimitReached"]) && Convert.ToInt32(head["Count"]) == (runs ? 125 : 20000) &&
            Convert.ToInt32(saved["TotalRuns"]) == (runs ? 250000 : 0) && Convert.ToInt32(counters["DeletedCandidates"]) == (runs ? 126 : 20001),
            "actual candidate/run budget persists and excludes the overflow record");
        CandidateStorage(root, !runs);
        using (var cancel = new CancellationTokenSource())
        {
            bool stopped = false;
            try { RecoveryPipeline.Resume(root, cancel.Token, message => cancel.Cancel()); } catch (OperationCanceledException) { stopped = true; }
            Check(stopped && Convert.ToInt32(Payload(root)["TotalRuns"]) == (runs ? 250000 : 0), "restart does not reset a fully consumed budget");
        }
        Check(!File.Exists(Path.Combine(root, "files-index.json")), "budget/cancel control never creates a successful archive");
    }
    static void CandidateStorage(string root, bool inline)
    {
        var head = (Dictionary<string, object>)Payload(root)["Metadata"]; int count = 0;
        while (head != null)
        {
            var page = Object(RecoveryCatalog.SafeFile(root, (string)head["Path"]));
            foreach (Dictionary<string, object> row in (System.Collections.IList)page["Records"])
            {
                if ((string)row["Kind"] != "candidate") continue;
                if (inline ? row["InlineCandidate"] == null || row["Candidate"] != null : row["InlineCandidate"] != null || row["Candidate"] == null)
                    throw new Exception("Candidate must use one acknowledged bounded storage representation");
                count++;
            }
            head = page["Previous"] as Dictionary<string, object>;
        }
        Check(count > 0 && (inline ? !Directory.Exists(Path.Combine(root, "ntfs-records.state", "candidates")) :
            Directory.GetFiles(Path.Combine(root, "ntfs-records.state", "candidates")).Length == count),
            "small metadata shares verified pages; large run lists retain separately verified blobs");
    }
    static void InvalidPinnedState(string field)
    {
        string root = Cancelled(false); var stage = RecoverySession.Read(root).Stages.Single();
        string checkpoint = RecoveryCatalog.SafeFile(root, stage.CheckpointPath); var document = Object(checkpoint);
        if (field == "phase") ((Dictionary<string, object>)document["Payload"])["Phase"] = "unknown-phase";
        else if (field == "schema") document["Schema"] = 999;
        else if (field == "budget") ((Dictionary<string, object>)((Dictionary<string, object>)document["Payload"])["Counters"])["OutputBytes"] = Int64.MaxValue;
        else document["SourceSha256"] = new string('0', 64);
        File.WriteAllText(checkpoint, Json.Serialize(document), new UTF8Encoding(false));
        string parent = Path.Combine(root, RecoverySession.FileName); var session = Object(parent);
        var pinned = (Dictionary<string, object>)((System.Collections.IList)session["Stages"])[0];
        pinned["CheckpointSha256"] = Hash(checkpoint); pinned["CheckpointBytes"] = new FileInfo(checkpoint).Length;
        File.WriteAllText(parent, Json.Serialize(session), new UTF8Encoding(false));
        bool failed = false; try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); } catch (IOException) { failed = true; }
        Check(failed, "structurally invalid " + field + " rejected even after test repins checksum");
    }
    static void OutputBudgetBoundary()
    {
        string root = Fresh(); var assembly = typeof(MetadataRescue).Assembly;
        var volume = assembly.GetType("UsbRecovery.MetadataRescue+Volume", true);
        object volumes = Activator.CreateInstance(typeof(List<>).MakeGenericType(volume));
        var parse = typeof(MetadataRescue).GetMethod("ParseAt", BindingFlags.Static | BindingFlags.NonPublic);
        var prepare = typeof(MetadataRescue).GetMethod("PrepareRescueEntry", BindingFlags.Static | BindingFlags.NonPublic);
        var report = new MetadataRescue.Report();
        using (var source = File.OpenRead(Path.Combine(fixtures, "records.dd")))
        {
            object record = parse.Invoke(null, new object[] { source, 2L * 1024 * 1024 });
            var entry = (MetadataRescue.Entry)prepare.Invoke(null, new object[] { source, volumes, record, root, 0, report, false, false, 1L, CancellationToken.None, null });
            Check(report.OutputLimitReached && entry.Output == null && entry.RecoveredBytes == 0 && entry.Reason == "output_budget" &&
                !Directory.Exists(root), "real output planner enforces remaining budget before scratch creation; no 32-GiB throughput claim");
        }
    }
    static void SourceNamespaceGuard()
    {
        string root = Fresh(), privateFiles = Path.Combine(root, "ntfs-records.state", "work"); Directory.CreateDirectory(privateFiles);
        string source = Path.Combine(privateFiles, "record-000000.partial"); File.Copy(Path.Combine(fixtures, "records.dd"), source);
        string before = Hash(source); bool failed = false;
        try { MetadataRescue.Recover(source, root, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && Hash(source) == before && !Directory.Exists(Path.Combine(root, "metadata-rescue")),
            "source inside private scratch namespace is rejected before any output creation or deletion");
    }
    public static int Main(string[] args)
    {
        try
        {
            if (args[0] == "worker")
            {
                project = args[1]; fixtures = args[2];
                Run(Path.Combine(fixtures, "records.dd"), args[3], CancellationToken.None, m =>
                {
                    if (args[5] == "export" ? m.StartsWith("Записи NTFS: сохранено 1;", StringComparison.Ordinal) : m.StartsWith("Записи NTFS: просмотрено 4 МБ", StringComparison.Ordinal))
                    { File.WriteAllText(args[4], "parent committed"); Thread.Sleep(Timeout.Infinite); }
                });
                return 3;
            }
            project = Path.GetFullPath(args[0]); fixtures = Path.GetFullPath(args[1]); work = Path.Combine(project, ".build", "ntfs-record-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            CancelResume(false, false);
            if (args.Length == 2)
            {
                CancelResume(true, false); CancelResume(true, true); Kill(false); Kill(true);
                ParentAndReadFailures(false); ParentAndReadFailures(true); PublicationFailure(false); PublicationFailure(true);
                Console.WriteLine("PASS NTFS cursor and failure prefix: " + checks + " checks; remaining native/cache/tamper controls pending");
                NativeAndCaches(); foreach (string kind in new[] { "checkpoint", "metadata", "plan", "output", "extra" }) Tamper(kind);
                MapAndShortRead();
                PersistentBudgets(false); PersistentBudgets(true);
                foreach (string field in new[] { "phase", "schema", "budget", "source" }) InvalidPinnedState(field);
                OutputBudgetBoundary();
                SourceNamespaceGuard();
            }
            Check(Hash(Path.Combine(fixtures, "records.dd")) == (string)Object(Path.Combine(fixtures, "manifest.json"))["image_sha256"], "original fixture remains unchanged");
            Console.WriteLine("PASS NtfsRecordCheckpoint: " + checks + " checks; real scan/export cursor, USA/nonresident repair, parent-cache budgets, cancel/kill, owned OS I/O failures and tamper; structural and pinned historical controls, no device claim"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
