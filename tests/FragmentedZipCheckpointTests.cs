using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class FragmentedZipCheckpointTests
{
    static int checks;
    static string work, fixtures;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024 };
    public sealed class Expected { public string sha256, original; public long bytes; public int members; public List<FragmentedZipRecovery.Extent> extents; }
    public sealed class Manifest { public string image_sha256; public List<Expected> files; }
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static RecoveryOptions Options()
    {
        return new RecoveryOptions { FatMetadata = false, NtfsMetadata = false, LostPartitions = false,
            Signatures = false, EmbeddedPhotos = false, Containers = false, FragmentedArchives = true };
    }
    static int Percent(string message)
    {
        const string prefix = "Сборка ZIP: ";
        return message.StartsWith(prefix, StringComparison.Ordinal) ? Int32.Parse(message.Substring(prefix.Length).TrimEnd('%')) : -1;
    }
    static Dictionary<string, object> Payload(string root)
    {
        var stage = RecoverySession.Read(root).Stages.Single();
        Check(stage.CheckpointPath != null && stage.CheckpointSequence > 0, "fragmented ZIP pins an internal cursor");
        string path = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
        Check(Hash(path) == stage.CheckpointSha256, "parent pins exact fragmented ZIP state");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8))["Payload"];
    }
    static string Root(string name) { return Path.Combine(work, name + "-" + Guid.NewGuid().ToString("N")); }
    static FragmentedZipRecovery.Report Report(string root)
    {
        return Json.Deserialize<FragmentedZipRecovery.Report>(File.ReadAllText(Path.Combine(root, "fragmented-zip.json"), Encoding.UTF8));
    }
    static void Validate(string root, string label)
    {
        Manifest manifest = Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures, label + ".json"), Encoding.UTF8));
        var report = Report(root);
        Check(report.Status == "complete" && report.Files.Count == manifest.files.Count && report.Recovered == manifest.files.Count, "only expected complete archives");
        Check(report.ChargedWorkBytes >= report.ExpandedWorkBytes && report.ChargedWorkBytes <= FragmentedZipRecovery.MaximumWorkBytes, "decode reservation stays bounded");
        foreach (Expected expected in manifest.files)
        {
            var actual = report.Files.Single(x => x.Sha256 == expected.sha256);
            string file = RecoveryCatalog.SafeFile(root, actual.Path);
            Check(Hash(file) == expected.sha256 && File.ReadAllBytes(file).SequenceEqual(File.ReadAllBytes(Path.Combine(fixtures, expected.original))), "byte-exact independent ZIP original");
            Check(actual.Bytes == expected.bytes && actual.Members == expected.members && actual.Extents.Count == expected.extents.Count, "size/member count and complete map");
            long logical = 0;
            for (int i = 0; i < actual.Extents.Count; i++)
            {
                var a = actual.Extents[i]; var e = expected.extents[i];
                Check(a.ImageOffset == e.ImageOffset && a.LogicalOffset == e.LogicalOffset && a.Length == e.Length && a.LogicalOffset == logical, "exact source/logical extent");
                logical += a.Length;
            }
            Check(logical == actual.Bytes && ContentVerifier.Verify(file, CancellationToken.None).Code == "container_crc", "full coverage and independent content verification");
        }
        Check(!Directory.EnumerateFiles(Path.Combine(root, "fragmented-archives"), "*.partial").Any(), "no unfinished public data after completion");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "same attempt retained");
        string reportHash = Hash(Path.Combine(root, "fragmented-zip.json"));
        Check(RecoveryPipeline.Resume(root, CancellationToken.None, m => { }).ResumedStages == 1 && Hash(Path.Combine(root, "fragmented-zip.json")) == reportHash, "completed pass reused unchanged");
    }
    static void CancelAndResume()
    {
        string image = Path.Combine(fixtures, "normal.dd"), root = Root("cancel");
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, Options(), cancel.Token, m => { if (Percent(m) >= 20) cancel.Cancel(); }, image + ".sha256"); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped, "owned image scan cancelled");
        long position = Convert.ToInt64(Payload(root)["Position"]);
        Check(position == 8 * 1024 * 1024, "scan commits the consumed prefix");
        int first = -1;
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { int p = Percent(m); if (p >= 0 && first < 0) first = p; });
        Check(first == 20 && !Directory.Exists(Path.Combine(root, "attempt-history")), "same attempt resumes the real index cursor");
        var report = Json.Deserialize<FragmentedZipRecovery.Report>(File.ReadAllText(Path.Combine(root, "fragmented-zip.json"), Encoding.UTF8));
        Check(report.Status == "complete" && report.Recovered == 3, "three independent fragmented ZIPs recovered");
        Check(Hash(image) == File.ReadAllText(image + ".sha256").Trim(), "source unchanged");
        Validate(root, "normal");
    }
    static string CancelDuringAssembly(string label, bool afterOutput)
    {
        string image = Path.Combine(fixtures, label + ".dd"), root = Root("assembly");
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(image, root, Options(), cancel.Token, m =>
            {
                if (Percent(m) != 100) return;
                var state = Payload(root);
                if (afterOutput ? Convert.ToInt32(state["NextDirectory"]) > 0 : Convert.ToInt64(state["ExpandedWorkBytes"]) > 0) cancel.Cancel();
            }, image + ".sha256"); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && !File.Exists(Path.Combine(root, "files-index.json")), "assembly cancellation has no successful catalog");
        return root;
    }
    static void AssemblyResume(bool repair, string label)
    {
        string root = CancelDuringAssembly(label, true);
        var before = Report(root);
        Check(before.Files.Count == 1, "exactly one archive was committed before cancellation");
        string first = RecoveryCatalog.SafeFile(root, before.Files[0].Path);
        DateTime stamp = File.GetLastWriteTimeUtc(first);
        if (repair) File.Delete(first);
        if (label == "long-names") Check(Directory.EnumerateFiles(Path.Combine(root, "fragmented-zip.state", "plans")).Any(x => new FileInfo(x).Length > 256 * 1024), "large provenance uses a bounded plan outside small ledger pages");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        Check(Report(root).ExpandedWorkBytes >= before.ExpandedWorkBytes, "verified work retained");
        if (!repair) Check(File.GetLastWriteTimeUtc(first) == stamp, "existing valid output not rewritten");
        Validate(root, label);
    }
    static void CachedVerification()
    {
        string root = CancelDuringAssembly("normal", false);
        long workBefore = Convert.ToInt64(Payload(root)["ExpandedWorkBytes"]);
        Check(workBefore > 0 && Report(root).Recovered == 0, "member cache committed before archive publication");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        string clean = Root("clean");
        string image = Path.Combine(fixtures, "normal.dd");
        RecoveryPipeline.Run(image, clean, Options(), CancellationToken.None, m => { }, image + ".sha256");
        Check(Report(root).ExpandedWorkBytes == Report(clean).ExpandedWorkBytes, "committed members are not decoded or charged twice");
        Validate(root, "normal");
    }
    static void Rejected(string kind)
    {
        string root = CancelDuringAssembly("normal", true);
        string original = Path.Combine(fixtures, "normal.dd"), image = Path.Combine(work, kind + ".dd");
        string target;
        if (kind == "source")
        {
            // Use its own session to avoid altering another test's image.
            File.Copy(original, image); File.Copy(original + ".sha256", image + ".sha256");
            root = Root("source-tamper");
            using (var cancel = new CancellationTokenSource())
            {
                try { RecoveryPipeline.Run(image, root, Options(), cancel.Token, m => { if (Percent(m) >= 20) cancel.Cancel(); }, image + ".sha256"); }
                catch (OperationCanceledException) { }
            }
            target = image;
        }
        else if (kind == "output") target = RecoveryCatalog.SafeFile(root, Report(root).Files[0].Path);
        else if (kind == "plan") target = Directory.GetFiles(Path.Combine(root, "fragmented-zip.state", "plans")).First();
        else if (kind == "ledger") target = Directory.GetFiles(Path.Combine(root, "fragmented-zip.state", "outputs")).First();
        else if (kind == "checkpoint") target = RecoveryCatalog.SafeFile(root, RecoverySession.Read(root).Stages.Single().CheckpointPath);
        else target = Path.Combine(root, "fragmented-archives", "unknown.bin");
        if (kind == "unknown") File.WriteAllText(target, "owned unrelated file");
        else using (var file = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { int value = file.ReadByte(); file.Position = 0; file.WriteByte((byte)(value ^ 1)); }
        string changed = Hash(target);
        bool rejected = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); }
        catch (IOException) { rejected = true; }
        Check(rejected && Hash(target) == changed, "reject and preserve changed " + kind);
        Check(!File.Exists(Path.Combine(root, "files-index.json")), "tamper cannot become successful archive");
    }
    static void FailedParent()
    {
        string image = Path.Combine(fixtures, "normal.dd"), root = Root("parent");
        string parent = Path.Combine(root, RecoverySession.FileName);
        bool failed = false;
        try { RecoveryPipeline.Run(image, root, Options(), CancellationToken.None,
            m => { if (Percent(m) >= 20) File.SetAttributes(parent, FileAttributes.ReadOnly); }, image + ".sha256"); }
        catch (UnauthorizedAccessException) { failed = true; }
        catch (IOException) { failed = true; }
        finally { if (File.Exists(parent)) File.SetAttributes(parent, FileAttributes.Normal); }
        Check(failed && Convert.ToInt64(Payload(root)["Position"]) == 8 * 1024 * 1024, "denied parent write cannot advance durable index");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root, "normal");
    }
    static void FailedPublication(bool removePartial)
    {
        string image = Path.Combine(fixtures, "normal.dd"), root = Root("publication");
        Directory.CreateDirectory(root);
        var session = RecoverySession.Start(root, image, Hash(image), Options(), CancellationToken.None);
        session.Begin("fragmented-zip");
        var type = typeof(FragmentedZipRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true);
        object context = Activator.CreateInstance(type, true);
        type.GetField("Directory").SetValue(context, root); type.GetField("Method").SetValue(context, "fragmented-zip");
        type.GetField("SourceSha256").SetValue(context, Hash(image)); type.GetField("Settings").SetValue(context, "zip32-between-members-v1");
        FileStream lease = null;
        Action<RecoveryMethodCheckpoint> commit = value =>
        {
            session.CaptureMethodCheckpoint("fragmented-zip", value);
            if (lease == null && Convert.ToInt32(Payload(root)["NextDirectory"]) > 0)
                lease = new FileStream(Directory.GetFiles(Path.Combine(root, "fragmented-archives"), "*.partial").Single(), FileMode.Open, FileAccess.Read, FileShare.Read);
        };
        type.GetField("Commit").SetValue(context, commit);
        bool failed = false;
        try
        {
            typeof(FragmentedZipRecovery).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                .Single(x => x.Name == "Recover" && x.GetParameters().Length == 5)
                .Invoke(null, new object[] { image, root, CancellationToken.None, (Action<long, long>)((a, b) => { }), context });
        }
        catch (TargetInvocationException error) { if (!(error.InnerException is IOException)) throw; failed = true; }
        finally { if (lease != null) lease.Dispose(); }
        Check(failed && lease != null, "real no-delete lease prevents publication after durable plan");
        Check(!Directory.GetFiles(Path.Combine(root, "fragmented-archives")).Any(x => !x.EndsWith(".partial")), "named file remains unpublished");
        if (removePartial) File.Delete(Directory.GetFiles(Path.Combine(root, "fragmented-archives"), "*.partial").Single());
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root, "normal");
    }
    static void KilledProcess()
    {
        string image = Path.Combine(fixtures, "normal.dd"), root = Root("killed"), ready = root + ".ready";
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
            "child \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var watch = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(25)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned child reaches committed index boundary");
                child.Kill(); Check(child.WaitForExit(10000), "owned worker terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Check(Convert.ToInt64(Payload(root)["Position"]) == 8 * 1024 * 1024, "kill leaves pinned index");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); Validate(root, "normal");
    }
    static void WorkBudget()
    {
        string root = CancelDuringAssembly("work-budget", false);
        long before = Convert.ToInt64(Payload(root)["ExpandedWorkBytes"]);
        bool limited = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); } catch (IOException) { limited = true; }
        var report = Report(root);
        Check(limited && report.Status == "limited" && report.ExpandedWorkBytes > before && report.Recovered == 0, "failed CRC candidates retain cumulative work after resume");
        Check(report.ChargedWorkBytes == FragmentedZipRecovery.MaximumWorkBytes && report.ExpandedWorkBytes <= report.ChargedWorkBytes, "original global cap retained");
        bool again = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); } catch (IOException) { again = true; }
        Check(again && Report(root).ExpandedWorkBytes == report.ExpandedWorkBytes, "limited pass is not reset into a success");
    }
    static void FailedReservedUnit()
    {
        string image = Path.Combine(fixtures, "normal.dd"), root = Root("reserved");
        Directory.CreateDirectory(root);
        var session = RecoverySession.Start(root, image, Hash(image), Options(), CancellationToken.None);
        session.Begin("fragmented-zip");
        var type = typeof(FragmentedZipRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true);
        object context = Activator.CreateInstance(type, true);
        type.GetField("Directory").SetValue(context, root); type.GetField("Method").SetValue(context, "fragmented-zip");
        type.GetField("SourceSha256").SetValue(context, Hash(image)); type.GetField("Settings").SetValue(context, "zip32-between-members-v1");
        bool injected = false;
        Action<RecoveryMethodCheckpoint> commit = value =>
        {
            session.CaptureMethodCheckpoint("fragmented-zip", value);
            if (Convert.ToInt64(Payload(root)["ChargedWorkBytes"]) > 0)
            { injected = true; throw new IOException("OWNED_RESERVED_UNIT_FAILURE"); }
        };
        type.GetField("Commit").SetValue(context, commit);
        try
        {
            typeof(FragmentedZipRecovery).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                .Single(x => x.Name == "Recover" && x.GetParameters().Length == 5)
                .Invoke(null, new object[] { image, root, CancellationToken.None, (Action<long, long>)((a, b) => { }), context });
        }
        catch (TargetInvocationException error) { if (!(error.InnerException is IOException) || !injected) throw; }
        Check(injected && Report(root).Recovered == 0, "fault after reservation publishes no archive");
        long reserved = Convert.ToInt64(Payload(root)["ChargedWorkBytes"]);
        Check(reserved > 0 && Convert.ToInt64(Payload(root)["ExpandedWorkBytes"]) == 0, "in-flight verification is charged before reading");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        Check(Report(root).ChargedWorkBytes == Report(root).ExpandedWorkBytes + reserved, "interrupted unit cannot silently reset work budget");
        Validate(root, "normal");
    }
    sealed class UnexpectedEnd : FileStream
    {
        public UnexpectedEnd(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.Read) { }
        public override int Read(byte[] bytes, int offset, int count) { return 0; }
    }
    static void IoErrors()
    {
        string image = Path.Combine(fixtures, "normal.dd");
        using (var input = new UnexpectedEnd(image))
        {
            var engine = typeof(FragmentedZipRecovery);
            foreach (string method in new[] { "Read", "HashRange" })
            {
                bool io = false;
                object[] args = method == "Read" ? new object[] { input, 0L, 30 } : new object[] { input, 0L, 30L, CancellationToken.None };
                try { engine.GetMethod(method, BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, args); }
                catch (TargetInvocationException error) { io = error.InnerException is IOException; }
                Check(io, "in-bounds " + method + " failure propagates as I/O, not a malformed candidate");
            }
            var constructor = engine.GetNestedType("Slice", BindingFlags.NonPublic).GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).Single();
            using (var slice = (Stream)constructor.Invoke(new object[] { input, 0L, 16L }))
            {
                Check(slice.Read(new byte[0], 0, 0) == 0, "zero-length slice read follows stream contract");
                bool io = false; try { slice.Read(new byte[16], 0, 16); } catch (IOException) { io = true; }
                Check(io, "in-bounds member stream failure is not skipped");
            }
            using (var output = new FileStream(Path.Combine(work, "io.partial"), FileMode.CreateNew))
            using (var sha = SHA256.Create())
            {
                bool io = false;
                try { engine.GetMethod("Copy", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null,
                    new object[] { input, output, sha, 0L, 30L, CancellationToken.None }); }
                catch (TargetInvocationException error) { io = error.InnerException is IOException; }
                Check(io && output.Length == 0, "source copy failure cannot publish invented zero bytes");
            }
        }
    }
    static void ReportBudget()
    {
        string image = Path.Combine(fixtures, "report-budget.dd"), root = Root("report-budget");
        bool limited = false;
        try { RecoveryPipeline.Run(image, root, Options(), CancellationToken.None, m => { }, image + ".sha256"); }
        catch (IOException) { limited = true; }
        var report = Report(root);
        var expected = Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures, "report-budget.json"), Encoding.UTF8));
        Check(limited && report.Status == "limited" && report.Recovered > 0 && report.Recovered < expected.files.Count, "large provenance stops explicitly within the existing report bound");
        foreach (var result in report.Files)
            Check(expected.files.Any(x => x.sha256 == result.Sha256) && Hash(RecoveryCatalog.SafeFile(root, result.Path)) == result.Sha256, "metadata-limited pass retains only exact confirmed archives");
        Check(new FileInfo(Path.Combine(root, "fragmented-zip.json")).Length <= 32 * 1024 * 1024 && !File.Exists(Path.Combine(root, "files-index.json")), "bounded report remains readable, without false complete catalog");
        bool again = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, m => { }); } catch (IOException) { again = true; }
        Check(again && Report(root).Recovered == report.Recovered && Report(root).Status == "limited", "report limit cannot silently accept the pending archive after resume");
    }
    static void FailedMemberRead()
    {
        string image = Path.Combine(fixtures, "normal.dd"), root = Root("member-read");
        var manifest = Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures, "normal.json"), Encoding.UTF8));
        long offset = manifest.files[0].extents[1].ImageOffset, lockedOffset;
        using (var reader = new BinaryReader(new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read)))
        {
            reader.BaseStream.Position = offset + 26;
            int names = reader.ReadUInt16(), extras = reader.ReadUInt16();
            lockedOffset = offset + 30 + names + extras;
        }
        Directory.CreateDirectory(root);
        var session = RecoverySession.Start(root, image, Hash(image), Options(), CancellationToken.None);
        session.Begin("fragmented-zip");
        var type = typeof(FragmentedZipRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true);
        object context = Activator.CreateInstance(type, true);
        type.GetField("Directory").SetValue(context, root); type.GetField("Method").SetValue(context, "fragmented-zip");
        type.GetField("SourceSha256").SetValue(context, Hash(image)); type.GetField("Settings").SetValue(context, "zip32-between-members-v1");
        FileStream lease = null;
        bool locked = false;
        Action<RecoveryMethodCheckpoint> commit = value =>
        {
            session.CaptureMethodCheckpoint("fragmented-zip", value);
            if (lease != null || Convert.ToInt64(Payload(root)["ChargedWorkBytes"]) == 0) return;
            lease = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
            lease.Lock(lockedOffset, 1); locked = true;
        };
        type.GetField("Commit").SetValue(context, commit);
        bool failed = false;
        try
        {
            typeof(FragmentedZipRecovery).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                .Single(x => x.Name == "Recover" && x.GetParameters().Length == 5)
                .Invoke(null, new object[] { image, root, CancellationToken.None, (Action<long, long>)((a, b) => { }), context });
        }
        catch (TargetInvocationException error) { if (!(error.InnerException is IOException)) throw; failed = true; }
        finally
        {
            if (lease != null) { if (locked) lease.Unlock(lockedOffset, 1); lease.Dispose(); }
        }
        Check(locked && failed && Report(root).ExpandedWorkBytes > 0 && Report(root).Recovered == 0, "real byte-range lock interrupts a verification unit after earlier decoded data");
        long reserved = Convert.ToInt64(Payload(root)["ChargedWorkBytes"]);
        Check(reserved > 0 && Convert.ToInt64(Payload(root)["ExpandedWorkBytes"]) == 0, "unfinished unit remains reserved without trusting its uncommitted cache");
        RecoveryPipeline.Resume(root, CancellationToken.None, m => { });
        Check(Report(root).ChargedWorkBytes == Report(root).ExpandedWorkBytes + reserved, "read-failed unit is not refunded after resume");
        Validate(root, "normal");
    }
    public static int Main(string[] args)
    {
        if (args.Length == 4 && args[0] == "child")
        {
            RecoveryPipeline.Run(args[1], args[2], Options(), CancellationToken.None,
                m => { if (Percent(m) >= 20) { File.WriteAllText(args[3], "ready"); Thread.Sleep(Timeout.Infinite); } }, args[1] + ".sha256");
            return 3;
        }
        try
        {
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "fragmented-zip-checkpoints-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work); fixtures = Path.GetFullPath(args[1]);
            CancelAndResume();
            AssemblyResume(false, "normal"); AssemblyResume(true, "normal"); AssemblyResume(true, "long-names");
            CachedVerification(); FailedParent(); FailedPublication(false); FailedPublication(true); KilledProcess();
            foreach (string kind in new[] { "source", "output", "plan", "ledger", "checkpoint", "unknown" }) Rejected(kind);
            WorkBudget(); FailedReservedUnit(); IoErrors(); FailedMemberRead(); ReportBudget();
            foreach (string label in new[] { "normal", "long-names", "work-budget", "report-budget" })
                Check(Hash(Path.Combine(fixtures, label + ".dd")) == File.ReadAllText(Path.Combine(fixtures, label + ".dd.sha256")).Trim(), "all owned sources unchanged");
            Console.WriteLine("PASS FragmentedZipCheckpoint: " + checks + " checks; owned files only, no GUI/devices");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
