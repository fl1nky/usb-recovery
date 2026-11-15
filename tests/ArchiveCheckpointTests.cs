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

// Python ZIP originals, real public pipeline and an owned console child.
public static class ArchiveCheckpointTests
{
    public sealed class Wanted
    {
        public long offset, bytes;
        public string name, sha256, original;
        public int method;
    }
    public sealed class Manifest
    {
        public string image_sha256;
        public long expected_decoded_work;
        public int expected_headers;
        public List<Wanted> files;
    }
    static int checks;
    static string work, fixtures;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static RecoveryOptions Options()
    {
        return new RecoveryOptions { FatMetadata = false, NtfsMetadata = false, LostPartitions = false,
            Signatures = false, EmbeddedPhotos = false, Containers = false, ArchiveMembers = true };
    }
    static int Percent(string message)
    {
        const string prefix = "Части архивов: ";
        return message.StartsWith(prefix, StringComparison.Ordinal) ? Int32.Parse(message.Substring(prefix.Length).TrimEnd('%')) : -1;
    }
    static string Source(string name, string label)
    {
        string source = Path.Combine(work, name + ".dd");
        File.Copy(Path.Combine(fixtures, label + ".dd"), source);
        File.Copy(Path.Combine(fixtures, label + ".dd.sha256"), source + ".sha256");
        return source;
    }
    static Dictionary<string, object> Object(string path)
    {
        return Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
    }
    static Dictionary<string, object> Payload(string root)
    {
        var stage = RecoverySession.Read(root).Stages.Single();
        Check(stage.CheckpointPath != null && stage.CheckpointSequence > 0, "ZIP member scan pins an internal checkpoint");
        string path = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
        Check(Hash(path) == stage.CheckpointSha256, "parent pins checkpoint bytes");
        return (Dictionary<string, object>)Object(path)["Payload"];
    }
    static long Cancel(string source, string root)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(source, root, Options(), cancel.Token, message =>
                { if (Percent(message) >= 20) cancel.Cancel(); }, source + ".sha256"); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && !File.Exists(Path.Combine(root, "files-index.json")), "cancelled ZIP scan creates no successful catalog");
        long position = Convert.ToInt64(Payload(root)["Position"]);
        Check(position == 8 * 1024 * 1024, "ZIP cursor commits the consumed prefix");
        return position;
    }
    static void Resume(string source, string root, long position, string label, bool repair)
    {
        var manifest = Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures, label + ".json"), Encoding.UTF8));
        string before = Hash(source);
        int first = -1;
        RecoveryPipeline.Resume(root, CancellationToken.None, message =>
            { int percent = Percent(message); if (percent >= 0 && first < 0) first = percent; });
        Check(first == position * 100 / new FileInfo(source).Length, "ZIP resumes the committed cursor");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "ZIP resume keeps the same attempt");
        var report = Object(Path.Combine(root, "archive-salvage.json"));
        var records = Json.ConvertToType<List<SalvagedArchiveMember>>(report["files"]);
        Check((string)report["status"] == "complete" && records.Count == manifest.files.Count, "all independent ZIP members recovered exactly once");
        Check(Convert.ToInt64(report["decodedWorkBytes"]) == manifest.expected_decoded_work,
            "failed CRC decoding remains charged exactly once across continuation");
        Check(Convert.ToInt32(report["candidates"]) == manifest.expected_headers, "header counter survives continuation");
        if (repair) Check(Convert.ToInt64(report["repairWorkBytes"]) > 0, "missing decoded output uses a separate bounded repair budget");
        foreach (var expected in manifest.files)
        {
            var record = records.Single(x => x.HeaderOffset == expected.offset);
            string path = RecoveryCatalog.SafeFile(root, record.Path);
            Check(Hash(path) == expected.sha256 && record.Sha256 == expected.sha256 &&
                File.ReadAllBytes(path).SequenceEqual(File.ReadAllBytes(Path.Combine(fixtures, expected.original))), "exact independent decoded bytes");
            Check(record.OriginalMemberName == expected.name && record.Bytes == expected.bytes &&
                record.CompressionMethod == expected.method && record.Status == "member_crc_verified", "member provenance and evidence category preserved");
            if (expected.name.EndsWith(".html", StringComparison.Ordinal)) Check(path.EndsWith(".untrusted.bin"), "active extension stays neutralized");
        }
        Check(!Directory.GetFiles(Path.Combine(root, "salvage-content"), "*.partial").Any(), "no pending partial remains after repair");
        Check(Hash(source) == before && before == manifest.image_sha256, "source remains unchanged");
        string reportHash = Hash(Path.Combine(root, "archive-salvage.json"));
        Check(RecoveryPipeline.Resume(root, CancellationToken.None, message => { }).ResumedStages == 1 &&
            Hash(Path.Combine(root, "archive-salvage.json")) == reportHash, "completed ZIP pass reused unchanged");
    }
    static void Cancellation(bool missing)
    {
        string source = Source(missing ? "missing" : "cancel", "normal"), root = source + ".job";
        long position = Cancel(source, root);
        var saved = Directory.GetFiles(Path.Combine(root, "salvage-content"));
        Check(saved.Length == 2, "stored and deflated early members survive cancellation");
        string before = Hash(saved[0]);
        if (missing) File.Delete(saved[0]);
        Resume(source, root, position, "normal", missing);
        Check(Hash(saved[0]) == before, "missing member reconstructed exactly");
    }
    static void ManyLongNames()
    {
        string source = Source("long-names", "long-names"), root = source + ".job";
        long position = Cancel(source, root);
        string pages = Path.Combine(root, "archive-members.state", "outputs");
        string[] files = Directory.GetFiles(pages, "page-*.json");
        Check(files.Length >= 4 && files.All(x => new FileInfo(x).Length <= 256 * 1024),
            "JSON-escaped long source names use adaptive byte-bounded pages");
        string orphan = Path.Combine(pages, "page-00000000000000000000000000000000.json");
        File.WriteAllText(orphan, "owned unacknowledged page control");
        string before = Hash(orphan);
        Resume(source, root, position, "long-names", false);
        Check(Hash(orphan) == before, "unacknowledged page neither becomes a result nor gets overwritten");
    }
    static void Rejected(string kind)
    {
        string source = Source("tamper-" + kind, "normal"), root = source + ".job";
        Cancel(source, root);
        string changed;
        if (kind == "source") changed = source;
        else if (kind == "ledger")
        {
            var head = (Dictionary<string, object>)Payload(root)["Output"];
            changed = RecoveryCatalog.SafeFile(root, (string)head["Path"]);
        }
        else if (kind == "unknown")
        {
            changed = Path.Combine(root, "salvage-content", "unexpected.txt");
            File.WriteAllText(changed, "owned unexpected result");
        }
        else changed = Directory.GetFiles(Path.Combine(root, "salvage-content")).First();
        if (kind != "unknown") using (var stream = new FileStream(changed, FileMode.Open, FileAccess.ReadWrite))
        { int value = stream.ReadByte(); stream.Position = 0; stream.WriteByte((byte)(value ^ 1)); }
        string before = Hash(changed); bool rejected = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, message => { }); }
        catch (IOException) { rejected = true; }
        Check(rejected && Hash(changed) == before, "changed " + kind + " rejected without overwriting evidence");
    }
    static void FailedParent()
    {
        string source = Source("parent-failure", "normal"), root = source + ".job";
        string parent = Path.Combine(root, RecoverySession.FileName);
        bool failed = false;
        try { RecoveryPipeline.Run(source, root, Options(), CancellationToken.None, message =>
            { if (Percent(message) >= 20) File.SetAttributes(parent, FileAttributes.ReadOnly); }, source + ".sha256"); }
        catch (UnauthorizedAccessException) { failed = true; }
        catch (IOException) { failed = true; }
        finally { if (File.Exists(parent)) File.SetAttributes(parent, FileAttributes.Normal); }
        Check(failed, "real denied parent write interrupts ZIP scan");
        long position = Convert.ToInt64(Payload(root)["Position"]);
        Check(position == 8 * 1024 * 1024, "orphan generation cannot advance parent cursor");
        Resume(source, root, position, "normal", false);
    }
    static void FailedPublication()
    {
        string source = Source("publication-failure", "normal"), root = source + ".job";
        Directory.CreateDirectory(root);
        var session = RecoverySession.Start(root, source, Hash(source), Options(), CancellationToken.None);
        session.Begin("archive-members");
        var assembly = typeof(ArchiveSalvage).Assembly;
        var contextType = assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true);
        object context = Activator.CreateInstance(contextType, true);
        contextType.GetField("Directory").SetValue(context, root);
        contextType.GetField("Method").SetValue(context, "archive-members");
        contextType.GetField("SourceSha256").SetValue(context, Hash(source));
        contextType.GetField("Settings").SetValue(context, "zip32-local-members-v1");
        FileStream lease = null;
        Action<RecoveryMethodCheckpoint> commit = value =>
        {
            session.CaptureMethodCheckpoint("archive-members", value);
            var payload = (Dictionary<string, object>)Object(value.Path)["Payload"];
            if (payload["Output"] == null || lease != null) return;
            var head = (Dictionary<string, object>)payload["Output"];
            var page = Object(RecoveryCatalog.SafeFile(root, (string)head["Path"]));
            var records = Json.ConvertToType<List<SalvagedArchiveMember>>(page["Records"]);
            // A real Windows file lease denies rename, after the parent anchor.
            lease = new FileStream(RecoveryCatalog.SafeFile(root, records[0].Path + ".partial"),
                FileMode.Open, FileAccess.Read, FileShare.Read);
        };
        contextType.GetField("Commit").SetValue(context, commit);
        bool failed = false;
        try
        {
            var entry = typeof(ArchiveSalvage).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                .Single(x => x.Name == "Recover" && x.GetParameters().Length == 5);
            entry.Invoke(null, new object[] { source, root, CancellationToken.None, (Action<long, long>)((a, b) => { }), context });
        }
        catch (TargetInvocationException error) { if (!(error.InnerException is IOException)) throw; failed = true; }
        finally { if (lease != null) lease.Dispose(); }
        Check(failed && lease != null, "named ZIP output publication fails after durable write-ahead plan");
        long position = Convert.ToInt64(Payload(root)["Position"]);
        Check(position == 2 * 1024 * 1024 && Directory.GetFiles(Path.Combine(root, "salvage-content")).All(x => x.EndsWith(".partial")),
            "confirmed output plan remains even while only the private partial exists");
        Resume(source, root, position, "normal", false);
    }
    static void KilledProcess()
    {
        string source = Source("killed", "normal"), root = source + ".job", ready = source + ".ready";
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
            "child \"" + source + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var watch = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(25)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned ZIP worker reaches durable boundary");
                child.Kill(); Check(child.WaitForExit(10000), "owned worker terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Resume(source, root, Convert.ToInt64(Payload(root)["Position"]), "normal", false);
    }
    static void WorkBudget()
    {
        string source = Source("work-budget", "work-budget"), root = source + ".job";
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(source, root, Options(), cancel.Token, message =>
                { if (Percent(message) >= 7) cancel.Cancel(); }, source + ".sha256"); }
            catch (OperationCanceledException) { }
        }
        long charged = Convert.ToInt64(Payload(root)["DecodedWorkBytes"]);
        Check(charged > 0 && charged < ArchiveSalvage.MaximumTotalBytes, "failed candidates consume persisted decoding budget before cancellation");
        bool limited = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, message => { }); }
        catch (IOException) { limited = true; }
        Check(limited && Convert.ToInt64(Payload(root)["DecodedWorkBytes"]) == ArchiveSalvage.MaximumTotalBytes,
            "continuation reaches the original shared work cap without resetting it");
        string checkpoint = RecoverySession.Read(root).Stages.Single().CheckpointPath;
        string before = Hash(RecoveryCatalog.SafeFile(root, checkpoint));
        limited = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, message => { }); }
        catch (IOException) { limited = true; }
        Check(limited && Hash(RecoveryCatalog.SafeFile(root, checkpoint)) == before &&
            !Directory.GetFiles(Path.Combine(root, "salvage-content")).Any(), "limited state remains incomplete and publishes no corrupt member");
    }
    public static int Main(string[] args)
    {
        if (args.Length == 4 && args[0] == "child")
        {
            RecoveryPipeline.Run(args[1], args[2], Options(), CancellationToken.None, message =>
                { if (Percent(message) >= 20) { File.WriteAllText(args[3], "ready"); Thread.Sleep(Timeout.Infinite); } }, args[1] + ".sha256");
            return 3;
        }
        try
        {
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "archive-checkpoints-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work); fixtures = Path.GetFullPath(args[1]);
            Cancellation(false);
            if (args.Length == 2)
            {
                Cancellation(true); ManyLongNames(); FailedParent(); FailedPublication(); KilledProcess();
                foreach (string kind in new[] { "source", "output", "ledger", "unknown" }) Rejected(kind);
                WorkBudget();
            }
            Console.WriteLine("PASS ArchiveCheckpoint: " + checks + " checks; stored/deflate CRC, true cursor, cancel/kill, denied publication, repair, budgets, byte-bounded pages and tamper; no GUI/devices");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
