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

// Storage durability over owned files. The 100000 binary placeholders are
// explicitly not a claim of recovering 100000 photographs.
public static class SessionInventoryTests
{
    sealed class Job { public string Root, Source; public RecoverySession Session; }
    static int checks;
    static string project, fixtures, work;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static RecoveryOptions Options()
    {
        return new RecoveryOptions { FatMetadata = false, NtfsMetadata = false, LostPartitions = false,
            Signatures = false, EmbeddedPhotos = true, Containers = false };
    }
    static string NewRoot(string label) { return Path.Combine(work, label + "-" + Guid.NewGuid().ToString("N").Substring(0, 8)); }
    static Dictionary<string, object> Object(string path)
    {
        return Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
    }
    static Dictionary<string, object> RawStage(string root)
    {
        return Json.ConvertToType<List<Dictionary<string, object>>>(Object(Path.Combine(root, RecoverySession.FileName))["Stages"]).Single();
    }
    static Job Small(string label, int count = 1100)
    {
        string root = NewRoot(label); Directory.CreateDirectory(root);
        string source = Path.Combine(root, "usb.dd"); File.WriteAllBytes(source, new byte[4096]);
        var session = RecoverySession.Start(root, source, Hash(source), Options(), CancellationToken.None);
        session.Begin("photos");
        string output = Path.Combine(root, "extra-photos"); Directory.CreateDirectory(output);
        for (int i = 0; i < count; i++) File.WriteAllBytes(Path.Combine(output, "owned-" + i.ToString("D6") + ".bin"), BitConverter.GetBytes(i));
        RecoveryCore.SaveJson(Path.Combine(root, "extra-photo-search.json"), new { status = "complete", scope = "inventory_only" });
        return new Job { Root = root, Source = source, Session = session };
    }
    static RecoveryOutputHead Head(string root)
    {
        return RecoverySession.Read(root).Stages.Single().ArtifactIndex;
    }
    static void Finish(Job job, int count = 1100)
    {
        job.Session.Finish("photos", count, false, CancellationToken.None);
    }
    static void VerifyCompact(Job job, int count)
    {
        var raw = Object(Path.Combine(job.Root, RecoverySession.FileName));
        Check(Convert.ToInt32(raw["Schema"]) == 2 && Json.ConvertToType<List<object>>(RawStage(job.Root)["Artifacts"]).Count == 0, "new paged schema stores a head, not the expanded row list");
        var state = RecoverySession.Read(job.Root);
        Check(state.Schema == 2 && state.Stages.Single().Artifacts.Count == count && state.Stages.Single().ArtifactIndex.Count == count, "public reader materializes every pinned artifact");
        Check(new FileInfo(Path.Combine(job.Root, RecoverySession.FileName)).Length < 16 * 1024, "parent stays small independent of output count");
        Check(Directory.GetFiles(Path.Combine(job.Root, "session-inventories", "photos")).All(x => new FileInfo(x).Length <= 256 * 1024), "index pages remain byte bounded");
    }
    static void MovePrepared(string fixture, string root)
    {
        foreach (string name in new[] { "extra-photos", "photos.state", "extra-photo-search.json" })
        {
            string from = RecoveryCatalog.SafeFile(fixture, "prepared/" + name);
            string to = RecoveryCatalog.SafeFile(root, name);
            if (Directory.Exists(from))
            {
                RecoveryCatalog.SafeFile(fixture, "prepared/" + name + "/guard");
                RecoveryCatalog.SafeFile(root, name + "/guard");
                Directory.Move(from, to);
            }
            else File.Move(from, to);
        }
    }
    static void LargeBoundary()
    {
        string root = Path.Combine(fixtures, "large"), source = Path.Combine(fixtures, "source.dd");
        Directory.CreateDirectory(root);
        RecoverySession session;
        if (File.Exists(Path.Combine(root, RecoverySession.FileName))) session = RecoverySession.Open(root, source, Options(), CancellationToken.None, null);
        else
        {
            session = RecoverySession.Start(root, source, Hash(source), Options(), CancellationToken.None);
            session.Begin("photos"); MovePrepared(fixtures, root);
        }
        string before = Hash(source);
        session.Finish("photos", 100000, false, CancellationToken.None);
        var job = new Job { Root = root, Source = source, Session = session };
        VerifyCompact(job, 100018);
        var stage = RecoverySession.Read(root).Stages.Single();
        foreach (int i in new[] { 0, 49999, 99999 })
        {
            string relative = "extra-photos/owned-" + i.ToString("D6") + ".bin";
            var row = stage.Artifacts.Single(x => x.Path == relative);
            Check(row.Bytes == 4 && row.Sha256 == Hash(RecoveryCatalog.SafeFile(root, relative)) &&
                File.ReadAllBytes(RecoveryCatalog.SafeFile(root, relative)).SequenceEqual(BitConverter.GetBytes(i)), "original binary placeholder and hash retained at boundary " + i);
        }
        session = RecoverySession.Open(root, source, Options(), CancellationToken.None, null);
        Check(session.Completed("photos").Artifacts.Count == 100018 && session.Completed("photos").Candidates == 100000, "full public reopen verifies 100000 outputs plus bookkeeping");
        Check(new FileInfo(Path.Combine(root, RecoverySession.FileName)).Length < 16 * 1024, "subsequent saves never expand the inventory into parent JSON");
        Check(Hash(source) == before, "large inventory leaves source unchanged");
        Console.WriteLine("PASS large inventory boundary: 100000 placeholders + 18 artifacts and full reopen");
    }
    static void LargeArchive()
    {
        string root = Path.Combine(fixtures, "large"), source = Path.Combine(fixtures, "source.dd");
        string before = Hash(source);
        var session = RecoverySession.Open(root, source, Options(), CancellationToken.None, null);
        session.Begin("photos"); session.Begin("photos");
        string history = Path.Combine(root, "attempt-history");
        Check(Directory.GetFiles(history, "*", SearchOption.AllDirectories).Length == 100019 && !Directory.Exists(Path.Combine(root, "extra-photos")), "retry archival retains the full large attempt including metadata and history note");
        Check(Hash(source) == before, "large inventory and archival leave source unchanged");
        Console.WriteLine("PASS large archival: full retained 100000-file attempt");
    }
    static void Tamper()
    {
        var job = Small("tamper"); Finish(job);
        string parent = Path.Combine(job.Root, RecoverySession.FileName), parentHash = Hash(parent);
        string page = RecoveryCatalog.SafeFile(job.Root, Head(job.Root).Path);
        File.AppendAllText(page, "changed"); string changed = Hash(page);
        bool rejected = false; try { RecoverySession.Read(job.Root); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(page) == changed && Hash(parent) == parentHash, "changed selected page is rejected and preserved");

        job = Small("mutations"); Finish(job);
        foreach (string kind in new[] { "schema", "mixed", "path", "count", "key" })
        {
            parent = Path.Combine(job.Root, RecoverySession.FileName); byte[] saved = File.ReadAllBytes(parent);
            var raw = Object(parent); var stages = Json.ConvertToType<List<Dictionary<string, object>>>(raw["Stages"]);
            var head = (Dictionary<string, object>)stages[0]["ArtifactIndex"];
            if (kind == "schema") raw["Schema"] = 3;
            if (kind == "mixed") stages[0]["Artifacts"] = new[] { new SessionArtifact { Path = "extra-photos/owned-000000.bin", Bytes = 4, Sha256 = new string('0', 64) } };
            if (kind == "path") head["Path"] = "extra-photos/owned-000000.bin";
            if (kind == "count") head["Count"] = 250001;
            if (kind == "key") stages[0]["Key"] = "containers";
            raw["Stages"] = stages; RecoveryCore.SaveJson(parent, raw); string invalid = Hash(parent);
            rejected = false; try { RecoverySession.Read(job.Root); } catch (IOException) { rejected = true; }
            Check(rejected && Hash(parent) == invalid, "reject malformed inventory " + kind + " without rewriting it");
            File.WriteAllBytes(parent, saved);
        }
        string orphan = Path.Combine(job.Root, "session-inventories", "photos", "page-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(orphan, "{\"Schema\":999,\"Records\":[\"not a result\"]}");
        Check(RecoverySession.Open(job.Root, job.Source, Options(), CancellationToken.None, null).Completed("photos").Artifacts.Count == 1101,
            "unacknowledged metadata page never becomes a result or a new head");
        string foreign = Path.Combine(job.Root, "extra-photos", "unknown.bin"); File.WriteAllText(foreign, "owned unrelated");
        rejected = false; try { RecoverySession.Open(job.Root, job.Source, Options(), CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && File.ReadAllText(foreign) == "owned unrelated", "additional data is rejected, unlike private orphan metadata");
    }
    static void FailedPersistence()
    {
        var job = Small("denied-parent");
        string parent = Path.Combine(job.Root, RecoverySession.FileName), before = Hash(parent), updated = job.Session.State.UpdatedUtc;
        File.SetAttributes(parent, FileAttributes.ReadOnly);
        bool failed = false;
        try { Finish(job); } catch (IOException) { failed = true; } catch (UnauthorizedAccessException) { failed = true; }
        finally { File.SetAttributes(parent, FileAttributes.Normal); }
        Check(failed && Hash(parent) == before && job.Session.State.UpdatedUtc == updated, "denied parent write preserves durable state and timestamp");
        Check(job.Session.State.Schema == 1 && job.Session.Completed("photos") == null && job.Session.State.Stages.Single().Artifacts.Count == 0,
            "failed finish rolls back in-memory completion, schema and expanded list");
        var orphanFiles = Directory.GetFiles(Path.Combine(job.Root, "session-inventories", "photos"));
        Check(orphanFiles.Length > 0 && RecoverySession.Read(job.Root).Stages.Single().ArtifactIndex == null, "written pages remain unacknowledged after denied commit");
        job.Session = RecoverySession.Open(job.Root, job.Source, Options(), CancellationToken.None, null); Finish(job);
        VerifyCompact(job, 1101);
        Check(!orphanFiles.Contains(RecoveryCatalog.SafeFile(job.Root, Head(job.Root).Path)), "retry commits a new head without selecting orphan pages");

        job = Small("denied-index"); parent = Path.Combine(job.Root, RecoverySession.FileName); before = Hash(parent);
        string blocked = Path.Combine(job.Root, "session-inventories"); File.WriteAllText(blocked, "owned blocker");
        failed = false; try { Finish(job); } catch (IOException) { failed = true; }
        Check(failed && Hash(parent) == before && File.ReadAllText(blocked) == "owned blocker", "index write failure leaves the original parent and blocker intact");
        File.Delete(blocked); Finish(job); VerifyCompact(job, 1101);
    }
    static void LegacyAndCancellation()
    {
        var small = Small("inline", 3); Finish(small, 3);
        Check(RecoverySession.Read(small.Root).Schema == 1 && Head(small.Root) == null && RawStage(small.Root)["ArtifactIndex"] == null, "small jobs retain the inline version1 representation");
        var job = Small("legacy-large"); Finish(job);
        var legacy = RecoverySession.Read(job.Root); legacy.Schema = 1; legacy.Stages.Single().ArtifactIndex = null;
        RecoveryCore.SaveJson(Path.Combine(job.Root, RecoverySession.FileName), legacy);
        Check(RecoverySession.Open(job.Root, job.Source, Options(), CancellationToken.None, null).Completed("photos").Artifacts.Count == 1101,
            "existing large inline version1 sessions remain readable");
        var pending = Small("cancelled"); string parent = Path.Combine(pending.Root, RecoverySession.FileName), before = Hash(parent);
        using (var cancel = new CancellationTokenSource())
        {
            cancel.Cancel(); bool stopped = false;
            try { pending.Session.Finish("photos", 1100, false, cancel.Token); } catch (OperationCanceledException) { stopped = true; }
            Check(stopped && Hash(parent) == before && pending.Session.Completed("photos") == null, "cancelled finalization never publishes completion");
            stopped = false; try { RecoverySession.Read(job.Root, cancel.Token); } catch (OperationCanceledException) { stopped = true; }
            Check(stopped, "inventory loading obeys cancellation");
        }
        Finish(pending); VerifyCompact(pending, 1101);
    }
    static void CopyTree(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (string file in Directory.GetFiles(from)) File.Copy(file, Path.Combine(to, Path.GetFileName(file)));
        foreach (string folder in Directory.GetDirectories(from))
        {
            RecoveryCatalog.SafeFile(from, Path.GetFileName(folder) + "/guard");
            CopyTree(folder, Path.Combine(to, Path.GetFileName(folder)));
        }
    }
    static void RelocationAndSourceMapping()
    {
        string root = NewRoot("real-png"); Directory.CreateDirectory(root);
        string source = Path.Combine(root, "usb.dd"); File.Copy(Path.Combine(fixtures, "mapping.dd"), source);
        File.Copy(Path.Combine(fixtures, "mapping.dd.sha256"), source + ".sha256");
        bool injected = false;
        RecoveryPipeline.Run(source, root, Options(), CancellationToken.None, message =>
        {
            string photos = Path.Combine(root, "extra-photos");
            if (injected || !Directory.Exists(photos) || !Directory.GetFiles(photos).Any(x => !x.EndsWith(".partial"))) return;
            Check(RecoverySession.Read(root).Stages.Single().Status == "running", "metadata pressure is added before public pipeline finish");
            injected = true;
            string state = Path.Combine(root, "photos.state"); Directory.CreateDirectory(state);
            for (int i = 0; i < 1100; i++) File.WriteAllText(Path.Combine(state, "owned-inventory-pressure-" + i.ToString("D4") + ".json"), "{}");
        }, source + ".sha256");
        var item = RecoveryCatalog.Load(root).Items.Single();
        Check(injected && RecoverySession.Read(root).Schema == 2, "actual image pipeline finishes with the paged session format");
        Check(item.SourceOffset == 8192 && item.SourceRanges.Count == 1 && item.SourceRanges[0].Offset == 8192 &&
            item.Sha256 == Hash(Path.Combine(fixtures, "original.png")), "version2 preserves verified PNG source mapping and exact bytes");
        string moved = NewRoot("relocated"); CopyTree(root, moved);
        var result = RecoveryPipeline.Resume(moved, CancellationToken.None, message => { });
        item = RecoveryCatalog.Load(moved).Items.Single();
        Check(result.ResumedStages == 1 && RecoverySession.Read(moved).SourcePath == Path.Combine(moved, "usb.dd") &&
            item.SourceOffset == 8192 && item.SourceRanges.Count == 1, "relative inventory pages and working image survive relocation");
    }
    static void HashControls()
    {
        foreach (int bytes in new[] { 0, 1, 4095, 65536, RecoveryCore.ChunkSize + 17 })
        {
            string file = Path.Combine(work, "hash-" + bytes + ".bin");
            byte[] data = Enumerable.Range(0, bytes).Select(x => (byte)(x * 31)).ToArray(); File.WriteAllBytes(file, data);
            string expected; using (var sha = SHA256.Create()) expected = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
            long last = 0;
            Check(RecoveryCore.HashFile(file, CancellationToken.None, (a, b) => { Check(a >= last && b == bytes, "monotone byte progress"); last = a; }) == expected && last == bytes,
                "adaptive hashing remains byte exact at length " + bytes);
        }
    }
    static List<SessionArtifact> OwnedRows(string root)
    {
        var rows = Directory.GetFiles(Path.Combine(root, "extra-photos")).Select(file =>
            new SessionArtifact { Path = "extra-photos/" + Path.GetFileName(file), Bytes = new FileInfo(file).Length, Sha256 = Hash(file) }).ToList();
        string report = Path.Combine(root, "extra-photo-search.json");
        rows.Add(new SessionArtifact { Path = "extra-photo-search.json", Bytes = new FileInfo(report).Length, Sha256 = Hash(report) });
        return rows;
    }
    static void KillBeforeCommit()
    {
        var job = Small("killed"); string parent = Path.Combine(job.Root, RecoverySession.FileName), before = Hash(parent), ready = job.Root + ".ready";
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "orphan-worker \"" + job.Root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var watch = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned index worker reaches pre-parent-commit boundary");
                child.Kill(); Check(child.WaitForExit(10000), "owned worker terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Check(Hash(parent) == before && RecoverySession.Read(job.Root).Stages.Single().ArtifactIndex == null,
            "crash after immutable page writes leaves the previous parent authoritative");
        string[] orphans = Directory.GetFiles(Path.Combine(job.Root, "session-inventories", "photos"));
        Check(orphans.Length > 1, "unacknowledged index spans several actual pages");
        Finish(job); VerifyCompact(job, 1101);
        Check(!orphans.Contains(RecoveryCatalog.SafeFile(job.Root, Head(job.Root).Path)), "resumption never selects orphan pages as the committed inventory");
    }
    static void ByteBudgets()
    {
        var job = Small("page-budgets"); Finish(job);
        var assembly = typeof(RecoverySession).Assembly;
        var contextType = assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true);
        object context = Activator.CreateInstance(contextType, true);
        contextType.GetField("Directory").SetValue(context, job.Root); contextType.GetField("Method").SetValue(context, "photos");
        var type = assembly.GetType("UsbRecovery.RecoveryOutputLedger`1", true).MakeGenericType(typeof(SessionArtifact));
        object scope = Enum.Parse(assembly.GetType("UsbRecovery.RecoveryLedgerScope", true), "SessionArtifacts");
        var ctor = type.GetConstructors().Single();
        bool rejected = false;
        try { ctor.Invoke(new object[] { context, Head(job.Root), 5000, CancellationToken.None, scope, 1024L }); }
        catch (TargetInvocationException error) { rejected = error.InnerException is IOException; }
        Check(rejected, "reader stops before hashing a page chain above its configured byte budget");
        object ledger = ctor.Invoke(new object[] { context, null, 5000, CancellationToken.None, scope, 1024L });
        string parent = Path.Combine(job.Root, RecoverySession.FileName), before = Hash(parent);
        rejected = false;
        try { type.GetMethod("Append").Invoke(ledger, new object[] { null, OwnedRows(job.Root) }); }
        catch (TargetInvocationException error) { rejected = error.InnerException is IOException; }
        Check(rejected && Hash(parent) == before, "write budget failure cannot publish a new inventory head");
    }
    static void FatInventoryBound()
    {
        string root = NewRoot("fat-inventory-bound"); Directory.CreateDirectory(root);
        var type = typeof(RecoverySession).Assembly.GetType("UsbRecovery.RecoveryArtifactInventory", true);
        const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
        var maximum = type.GetMethod("MaximumFor", flags);
        Check((int)maximum.Invoke(null, new object[] { "fat" }) == 400000 &&
            (int)maximum.Invoke(null, new object[] { "photos" }) == 250000,
            "FAT has room for data, plans and pages; other method bounds are preserved");
        var write = type.GetMethod("Write", flags);
        var read = type.GetMethod("Read", flags);
        string hash = new string('a', 64);
        var rows = new List<SessionArtifact>(300003);
        for (int i = 0; i < 300003; i++) rows.Add(new SessionArtifact {
            Path = "fat.state/plans/owned-" + i.ToString("D6") + ".json", Bytes = 4, Sha256 = hash });
        bool rejected = false;
        try { write.Invoke(null, new object[] { root, "photos", rows, CancellationToken.None }); }
        catch (TargetInvocationException error) { rejected = error.InnerException is IOException; }
        Check(rejected, "larger FAT inventory does not relax another method's row limit");
        var head = (RecoveryOutputHead)write.Invoke(null, new object[] { root, "fat", rows, CancellationToken.None });
        var loaded = (List<SessionArtifact>)read.Invoke(null, new object[] { root, "fat", head, CancellationToken.None });
        Check(head.Count == rows.Count && loaded.Count == rows.Count &&
            loaded.Zip(rows, (a, b) => a.Path == b.Path && a.Bytes == b.Bytes && a.Sha256 == b.Sha256).All(x => x),
            "actual 300003-row FAT index round-trips data/plan/page capacity; rows are metadata, not recovered files");
        rows.Clear();
        rows.AddRange(new SessionArtifact[400001]);
        rejected = false;
        try { write.Invoke(null, new object[] { root, "fat", rows, CancellationToken.None }); }
        catch (TargetInvocationException error) { rejected = error.InnerException is IOException; }
        Check(rejected, "FAT inventory writer rejects rows above its finite bound");
        head.Count = 400001; rejected = false;
        try { read.Invoke(null, new object[] { root, "fat", head, CancellationToken.None }); }
        catch (TargetInvocationException error) { rejected = error.InnerException is IOException; }
        Check(rejected, "FAT inventory reader rejects excessive count before reading pages");
    }
    public static int Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "orphan-worker")
        {
            var writer = typeof(RecoverySession).Assembly.GetType("UsbRecovery.RecoveryArtifactInventory", true)
                .GetMethod("Write", BindingFlags.NonPublic | BindingFlags.Static);
            writer.Invoke(null, new object[] { args[1], "photos", OwnedRows(args[1]), CancellationToken.None });
            File.WriteAllText(args[2], "pages durable; parent not committed");
            Thread.Sleep(Timeout.Infinite);
            return 3;
        }
        try
        {
            project = Path.GetFullPath(args[0]); fixtures = Path.GetFullPath(args[1]);
            work = Path.Combine(project, ".build", "session-inventory-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            if (args.Length == 2) LargeBoundary();
            Tamper(); FailedPersistence(); LegacyAndCancellation(); RelocationAndSourceMapping(); HashControls(); KillBeforeCommit(); ByteBudgets(); FatInventoryBound();
            Check(Hash(Path.Combine(fixtures, "source.dd")) == (string)Object(Path.Combine(fixtures, "inventory-fixture.json"))["source_sha256"], "fixture source remains unchanged");
            if (args.Length == 2) LargeArchive();
            string scope = args.Length == 2 ? "actual 100000-file inventory and archival; " : "focused controls only; large corpus not rerun; ";
            Console.WriteLine("PASS SessionInventory: " + checks + " checks; " + scope + "version1/2, page integrity, denied commits, cancellation, owned crash, byte budgets and real PNG mapping/relocation; not photo quality/device evidence");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
