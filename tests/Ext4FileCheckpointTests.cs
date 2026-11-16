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

// Supplied mapped-copy plans on owned regular files; native metadata-derived
// plan is checked separately. This does not claim whole ext4 engine resume.
public static class Ext4FileCheckpointTests
{
    const int MiB = 1024 * 1024;
    static int checks;
    static string work, fixtures;
    static List<Tuple<long, int>> reads;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * MiB };
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static void Set(object value, string name, object field) { value.GetType().GetField(name).SetValue(value, field); }
    static string Hash(string file) { return RecoveryCore.HashFile(file, CancellationToken.None, (a,b) => { }); }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long, int>> Reads = new List<Tuple<long, int>>();
        public Source(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1) { }
        public override int Read(byte[] bytes, int at, int count)
        { Reads.Add(Tuple.Create(Position, count)); return ZeroNext ? 0 : base.Read(bytes, at, count); }
    }
    sealed class Result { public Ext4Recovery.Entry Entry; public int Files; public long Bytes; public List<Tuple<long,int>> Reads; }
    static string Parent(string root) { return Path.Combine(root, "anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root), Encoding.UTF8)) : null; }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint value)
    {
        string temporary = Parent(root) + "." + Guid.NewGuid().ToString("N") + ".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value));
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { own = true; output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temporary, Parent(root), null); else File.Move(temporary, Parent(root));
        } finally { if (own && File.Exists(temporary)) File.Delete(temporary); }
    }
    static Dictionary<string, object> State(string root)
    {
        var a = Anchor(root); Check(a != null && Hash(a.Path) == a.Sha256, "caller pins exact mapped-file state");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(a.Path, Encoding.UTF8))["Payload"];
    }
    static string Scratch(string root)
    { return Path.Combine(root, "ext4.state", "work", "copy-" + (string)State(root)["WorkId"] + ".partial"); }
    static string Output(string root) { return Path.Combine(root, "ext4", "files", "volume_0_inode_13_generation_7.bin"); }
    static string Image(string name, out string root)
    {
        root = Path.Combine(work, name + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); byte[] bytes = new byte[10 * MiB]; uint seed = 0x2468ace1;
        for (int i = 0; i < bytes.Length; i++) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; bytes[i] = (byte)seed; }
        File.WriteAllBytes(image, bytes); return image;
    }
    static Ext4Recovery.Entry Plan()
    {
        return new Ext4Recovery.Entry { Inode = 13, Generation = 7, DeclaredSize = 4L * MiB + 39, Status = "not_recovered",
            Mapping = "supplied_test_mapping", MappingIntegrity = "test_copy_only", AllocationStatus = "not_an_allocation_proof",
            Names = { new Ext4Recovery.NameLink { Name = "семейный рецепт.bin", TargetInode = 13, DirectoryInode = 2 } },
            Extents = {
                new Ext4Recovery.Extent { ImageOffset = 4096, LogicalOffset = 0, Length = MiB + 17 },
                new Ext4Recovery.Extent { ImageOffset = 4L * MiB, LogicalOffset = MiB + 17, Length = MiB + 13 },
                new Ext4Recovery.Extent { ImageOffset = 6L * MiB, LogicalOffset = 2L * MiB + 30, Length = 2L * MiB + 9 } } };
    }
    static byte[] Expected(string image, Ext4Recovery.Entry plan)
    {
        using (var input = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var output = new MemoryStream()) {
            foreach (var extent in plan.Extents) {
                input.Position = extent.ImageOffset; byte[] bytes = new byte[(int)extent.Length]; int done = 0;
                while (done < bytes.Length) { int n = input.Read(bytes, done, bytes.Length - done); if (n == 0) throw new EndOfStreamException(); done += n; }
                output.Write(bytes, 0, bytes.Length);
            }
            return output.ToArray();
        }
    }
    static Result Run(string image, string root, string sha, CancellationToken token, Action<string> progress,
        string change = null, bool zero = false, Ext4Recovery.Entry supplied = null)
    {
        using (var input = new Source(image)) {
            object c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            var plan = supplied ?? Plan(); var report = new Ext4Recovery.Report { RecoveredFiles = 2, OutputBytes = 123, Candidates = 3 };
            report.Entries.Add(plan); var limits = new Ext4Recovery.Limits();
            if (change == "mapping") plan.Extents[0].ImageOffset++;
            if (change == "name") plan.Names[0].Name += " changed";
            if (change == "baseline") report.OutputBytes++;
            if (change == "limits") limits.MaximumOutputBytes--;
            if (change == "gap") plan.Extents[0].LogicalOffset = 1;
            if (change == "overlap") plan.Extents[1].ImageOffset = plan.Extents[0].ImageOffset + 17;
            if (change == "size") plan.DeclaredSize++;
            if (change == "extent-limit") limits.MaximumExtents = 1;
            if (change == "null-names") plan.Names = null;
            if (change == "null-extent") plan.Extents[0] = null;
            if (change == "output-budget") limits.MaximumOutputBytes = 123;
            if (change == "negative-output-limit") limits.MaximumOutputBytes = Int64.MinValue;
            Set(c, "Input", input); Set(c, "Root", Path.Combine(root, "ext4")); Set(c, "Cancel", token);
            if (change == "root") Set(c, "Root", root);
            Set(c, "Report", report); Set(c, "Limits", limits);
            object checkpoint = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
            Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", sha);
            Set(checkpoint, "Settings", "owned-mapped-file-v1"); Set(checkpoint, "Resume", Anchor(root));
            Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(root, a)));
            reads = input.Reads;
            Action<string> notify = m => {
                if (zero && Convert.ToInt64(State(root)["Next"]) > 32) input.ZeroNext = true;
                if (change == "mid-limits") limits.MaximumOutputBytes--;
                if (change == "mid-plan") plan.Generation++;
                if (progress != null) progress(m);
            };
            try { typeof(Ext4Recovery).GetMethod("WriteFileCheckpointed", Private).Invoke(null, new[] { c, plan, checkpoint, notify }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return new Result { Entry = plan, Files = report.RecoveredFiles, Bytes = report.OutputBytes, Reads = reads };
        }
    }
    static void Compare(string image, string root, string sha, Result result)
    {
        string output = Path.Combine(root, "ext4", result.Entry.Output.Replace('/', Path.DirectorySeparatorChar));
        Check(File.ReadAllBytes(output).SequenceEqual(Expected(image, result.Entry)), "mapped output matches independent exact byte assembly across all fragmented ranges");
        Check(result.Entry.Sha256 == Hash(output) && result.Entry.RecoveredBytes == result.Entry.DeclaredSize && result.Entry.Status == "deleted_inode_candidate", "published output has the correct size, SHA and candidate status");
        Check(result.Files == 3 && result.Bytes == 123 + result.Entry.DeclaredSize && Hash(image) == sha, "copy preserves source and adds output counters exactly once to the prior baseline");
    }
    static List<Tuple<long,int>> Cancel(string image, string root, string sha)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, sha, cancel.Token, m => { if (Convert.ToInt64(State(root)["Next"]) > 32) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Convert.ToInt64(State(root)["Next"]) == MiB + 32 && !File.Exists(Output(root)), "cancel retains a real acknowledged prefix inside a multi-megabyte mapped file");
        return reads.ToList();
    }
    static void Complete(string image, string root, string sha, List<Tuple<long,int>> prefix = null)
    {
        var result = Run(image, root, sha, CancellationToken.None, null); Compare(image, root, sha, result);
        if (prefix != null) Check(!result.Reads.Any(x => prefix.Any(p => p.Item1 < x.Item1 + x.Item2 && x.Item1 < p.Item1 + p.Item2)), "resume does not reread confirmed source ranges through the copy stream");
        var repeat = Run(image, root, sha, CancellationToken.None, m => { throw new Exception("completed mapped copy restarted"); });
        Compare(image, root, sha, repeat); Check(repeat.Reads.Count == 0 && (string)State(root)["Phase"] == "published", "completed output is validated and reused with zero source-copy reads");
    }
    static void CancelResume()
    { string root, image = Image("cancel", out root), sha = Hash(image); Complete(image, root, sha, Cancel(image, root, sha)); }
    static void ParentFailure(bool publication)
    {
        string root, image = Image("parent-failure", out root), sha = Hash(image), prior = null; FileStream held = null; bool failed = false; List<Tuple<long,int>> prefix = null;
        try { Run(image, root, sha, CancellationToken.None, m => {
            var state = State(root);
            if (held == null && (publication ? (string)state["Phase"] == "ready" : Convert.ToInt64(state["Next"]) > 32)) {
                prior = Hash(Parent(root)); prefix = reads.ToList(); held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read);
            }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && prior != null && Hash(Parent(root)) == prior, "OS parent replacement denial never advances the acknowledged copy/publication state");
        if (publication) Check(File.Exists(Output(root)) && (string)State(root)["Phase"] == "ready", "rename before failed parent ack leaves a planned verifiable output");
        else Check(new FileInfo(Scratch(root)).Length > Convert.ToInt64(State(root)["WorkBytes"]), "failed parent ack leaves a real unconfirmed tail for safe validation");
        Complete(image, root, sha, prefix);
    }
    static void IoFailure(string kind)
    {
        string root, image = Image("io-" + kind, out root), sha = Hash(image), prior = null; FileStream held = null;
        long lockAt = 0, lockLength = 0; bool failed = false; List<Tuple<long,int>> prefix = null;
        try { Run(image, root, sha, CancellationToken.None, m => {
            var state = State(root); if (held != null || prior != null) return;
            if (kind == "rename" ? (string)state["Phase"] != "ready" : Convert.ToInt64(state["Next"]) <= 32) return;
            prior = Hash(Parent(root)); prefix = reads.ToList();
            if (kind == "read") { held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read); lockLength = held.Length; held.Lock(0, lockLength); }
            if (kind == "write") { held = new FileStream(Scratch(root), FileMode.Open, FileAccess.Read, FileShare.ReadWrite); lockAt = Convert.ToInt64(state["WorkBytes"]); lockLength = MiB; held.Lock(lockAt, lockLength); }
            if (kind == "rename") held = new FileStream(Scratch(root), FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        }, null, kind == "zero"); } catch (IOException) { failed = true; }
        finally { if (held != null) { if (lockLength != 0) held.Unlock(lockAt, lockLength); held.Dispose(); } }
        Check(failed && prior != null && Hash(Parent(root)) == prior, "actual " + kind + " failure preserves the last confirmed copy state");
        Complete(image, root, sha, prefix);
    }
    static void Repair(bool finished)
    {
        string root, image = Image("repair", out root), sha = Hash(image);
        if (finished) { var first = Run(image, root, sha, CancellationToken.None, null); Compare(image, root, sha, first); File.Delete(Output(root)); }
        else { Cancel(image, root, sha); File.Delete(Scratch(root)); }
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, sha, cancel.Token, m => { if (Convert.ToInt64(State(root)["WorkBytes"]) > 32) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        var prefix = reads.ToList(); Check(stopped && File.Exists(Scratch(root)), "missing work/output repair itself has a durable chunk position");
        Complete(image, root, sha, prefix);
    }
    static void Flip(string path)
    {
        using (var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) {
            file.Position = file.Length - 1; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value ^ 1));
        }
    }
    static void Tamper(string kind)
    {
        string root, image = Image("tamper-" + kind, out root), sha = Hash(image);
        if (kind == "output") Run(image, root, sha, CancellationToken.None, null); else Cancel(image, root, sha);
        string target = kind == "source" ? image : kind == "output" ? Output(root) :
            kind == "cursor" || kind == "workid" || kind == "header" || kind == "work-cursor" ? Anchor(root).Path :
            kind == "ledger" ? Path.Combine(root, (string)((Dictionary<string,object>)State(root)["Facts"])["Path"]) : Scratch(root);
        if (kind == "cursor" || kind == "workid" || kind == "header" || kind == "work-cursor") {
            var envelope = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target, Encoding.UTF8)); var payload = (Dictionary<string,object>)envelope["Payload"];
            if (kind == "cursor") payload["Next"] = Convert.ToInt64(payload["Next"]) + 1;
            if (kind == "workid") payload["WorkId"] = "../outside";
            if (kind == "work-cursor") { payload["WorkBytes"] = 17; payload["Repairing"] = true; }
            if (kind == "header") { byte[] header = Convert.FromBase64String((string)payload["Header"]); header[0] ^= 1; payload["Header"] = Convert.ToBase64String(header); }
            File.WriteAllText(target, Json.Serialize(envelope), new UTF8Encoding(false)); var a = Anchor(root); a.Sha256 = Hash(target); SaveAnchor(root, a);
        } else Flip(target);
        string parent = Hash(Parent(root)), altered = Hash(target); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && Hash(Parent(root)) == parent && Hash(target) == altered, "changed " + kind + " is preserved and rejected before source-copy reads or parent writes");
    }
    static void Binding(string kind)
    {
        string root, image = Image("binding-" + kind, out root), sha = Hash(image); Cancel(image, root, sha);
        string parent = Hash(Parent(root)); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null, kind); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && Hash(Parent(root)) == parent, "changed " + kind + " plan cannot reuse copy progress");
    }
    static void InvalidInput(string kind)
    {
        string root, image = Image("invalid-" + kind, out root), sha = Hash(image); bool failed = false;
        if (kind == "state-source") {
            string folder = Path.Combine(root, "ext4.state"); Directory.CreateDirectory(folder);
            string moved = Path.Combine(folder, "owned.dd"); File.Move(image, moved); image = moved;
        }
        try { Run(image, root, sha, CancellationToken.None, null, kind); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && !File.Exists(Parent(root)) && Hash(image) == sha,
            "invalid " + kind + " input is rejected before copy reads or creation of a caller checkpoint");
    }
    static void MidRunChange(string kind)
    {
        string root, image = Image(kind, out root), sha = Hash(image); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null, kind); } catch (IOException) { failed = true; }
        Check(failed && !File.Exists(Output(root)), "mid-run input change cannot publish a file under altered metadata or limits");
        Complete(image, root, sha);
    }
    static void UnknownTail()
    {
        string root, image = Image("unknown-tail", out root), sha = Hash(image); Cancel(image, root, sha);
        string scratch = Scratch(root); long at = Convert.ToInt64(State(root)["WorkBytes"]);
        byte[] tail = Expected(image, Plan()).Skip((int)at).Take(3).ToArray(); tail[0] ^= 1;
        using (var file = new FileStream(scratch, FileMode.Append, FileAccess.Write, FileShare.None)) file.Write(tail, 0, tail.Length);
        string parent = Hash(Parent(root)), altered = Hash(scratch); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && Hash(Parent(root)) == parent && Hash(scratch) == altered && !File.Exists(Output(root)),
            "unknown unconfirmed tail is preserved instead of blindly truncating another writer's data");
    }
    static void ForeignOutputs()
    {
        string root, image = Image("foreign-output", out root), sha = Hash(image); Directory.CreateDirectory(Path.GetDirectoryName(Output(root)));
        File.WriteAllText(Output(root), "existing unrelated user output"); string protectedHash = Hash(Output(root)); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && Hash(Output(root)) == protectedHash, "pre-existing unplanned final output is never replaced");
        string parent = Hash(Parent(root));
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { }
        Check(reads.Count == 0 && Hash(Parent(root)) == parent && Hash(Output(root)) == protectedHash,
            "retry refuses the same foreign output before copy reads or parent writes");
        File.Move(Output(root), Path.Combine(root, "preserved.user"));
        string partial = Output(root) + ".partial"; File.WriteAllText(partial, "existing unrelated user partial"); string partialHash = Hash(partial);
        Complete(image, root, sha); Check(Hash(partial) == partialHash && Hash(Path.Combine(root, "preserved.user")) == protectedHash,
            "successful copy also leaves unrelated legacy partials and preserved user output intact");
    }
    static void CancelPublished()
    {
        string root, image = Image("cancel-published", out root), sha = Hash(image); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, sha, cancel.Token, m => { if ((string)State(root)["Phase"] == "published") cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && File.Exists(Output(root)) && (string)State(root)["Phase"] == "published",
            "cancel after publication keeps the pinned result without claiming a returned report");
        Complete(image, root, sha, reads.ToList());
    }
    static void SmallAndNative()
    {
        string root, image = Image("small", out root), sha = Hash(image); var small = Plan(); small.DeclaredSize = 1;
        small.Extents = new List<Ext4Recovery.Extent> { new Ext4Recovery.Extent { ImageOffset = 4096, Length = 1 } };
        Compare(image, root, sha, Run(image, root, sha, CancellationToken.None, null, null, false, small));
        string native = Path.Combine(fixtures, "extent-deleted.dd"); string reference = Path.Combine(work, "native-reference"); Directory.CreateDirectory(reference);
        Ext4Recovery.Recover(native, reference, CancellationToken.None, m => { });
        var report = Json.Deserialize<Ext4Recovery.Report>(File.ReadAllText(Path.Combine(reference, "ext4", "report.json"), Encoding.UTF8));
        var entry = report.Entries.Single(x => x.Output != null); string expected = entry.Sha256;
        entry.Output = entry.Sha256 = null; entry.RecoveredBytes = 0; entry.Status = "not_recovered";
        string destination = Path.Combine(work, "native-copy"); Directory.CreateDirectory(destination);
        var result = Run(native, destination, Hash(native), CancellationToken.None, null, null, false, entry); Compare(native, destination, Hash(native), result);
        Check(result.Entry.Sha256 == expected, "native metadata-derived plan retains exact recovered payload SHA");
    }
    static void FragmentedHeader()
    {
        string root, image = Image("fragmented-header", out root);
        using (var file = new FileStream(image, FileMode.Open, FileAccess.Write, FileShare.None)) {
            file.Position = 4096; file.Write(new byte[] { 0xff, 0xd8 }, 0, 2);
            file.Position = 4L * MiB; file.Write(new byte[] { 0xff, 0xe0 }, 0, 2);
        }
        var plan = Plan(); plan.DeclaredSize = 40;
        plan.Extents = new List<Ext4Recovery.Extent> {
            new Ext4Recovery.Extent { ImageOffset = 4096, Length = 2 },
            new Ext4Recovery.Extent { ImageOffset = 4L * MiB, LogicalOffset = 2, Length = 38 } };
        string sha = Hash(image); var result = Run(image, root, sha, CancellationToken.None, null, null, false, plan);
        Compare(image, root, sha, result);
        Check(result.Entry.Output.EndsWith(".jpg", StringComparison.Ordinal) && result.Entry.ContentTypeHint == "jpg_signature_only" &&
            !result.Entry.ContentAuthenticityVerified, "signature spanning physical ranges is read logically and remains a hint, not a decoded-photo or authenticity claim");
    }
    static void Relocated()
    {
        string root, image = Image("relocated", out root), sha = Hash(image); var prefixReads = Cancel(image, root, sha);
        var anchor = Anchor(root); string destination = Path.Combine(work, "moved-" + Guid.NewGuid().ToString("N"));
        string prefix = Path.GetFullPath(work) + Path.DirectorySeparatorChar;
        Check(Path.GetFullPath(root).StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            Path.GetFullPath(destination).StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !Directory.Exists(destination),
            "both directory move targets are unique owned paths under the verified workspace");
        Directory.Move(root, destination); anchor.Path = Path.Combine(destination, "ext4.state", Path.GetFileName(anchor.Path));
        SaveAnchor(destination, anchor); Complete(Path.Combine(destination, "owned.dd"), destination, sha, prefixReads);
    }
    static void KilledProcess(bool repair)
    {
        string root, image = Image("worker", out root), sha = Hash(image), ready = Path.Combine(root, "ready.json");
        if (repair) { Run(image, root, sha, CancellationToken.None, null); File.Delete(Output(root)); }
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned worker reaches an acknowledged copy chunk"); child.Kill(); Check(child.WaitForExit(10000), "copy worker is stopped without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        var prefix = Json.Deserialize<List<Dictionary<string,object>>>(File.ReadAllText(ready)).Select(x => Tuple.Create(Convert.ToInt64(x["Item1"]), Convert.ToInt32(x["Item2"]))).ToList();
        Complete(image, root, sha, prefix);
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("WriteFileCheckpointed", Private) == null) { Console.WriteLine("FAIL: baseline lacks checkpointed mapped file output"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1], args[2], Hash(args[1]), CancellationToken.None, m => { if (Convert.ToInt64(State(args[2])["WorkBytes"]) > 32) { File.WriteAllText(args[3], Json.Serialize(reads)); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-file-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            CancelResume(); ParentFailure(false); ParentFailure(true);
            foreach (string kind in new[] { "read", "write", "rename", "zero" }) IoFailure(kind);
            Repair(false); Repair(true);
            foreach (string kind in new[] { "source", "work", "output", "cursor", "workid", "ledger", "header", "work-cursor" }) Tamper(kind);
            foreach (string kind in new[] { "mapping", "name", "baseline", "limits" }) Binding(kind);
            foreach (string kind in new[] { "gap", "overlap", "size", "extent-limit", "root", "state-source", "null-names", "null-extent", "output-budget", "negative-output-limit" }) InvalidInput(kind);
            MidRunChange("mid-limits"); MidRunChange("mid-plan"); UnknownTail(); ForeignOutputs(); CancelPublished();
            SmallAndNative(); FragmentedHeader(); Relocated(); KilledProcess(false); KilledProcess(true);
            Console.WriteLine("PASS Ext4FileCheckpoint: " + checks + " checks; mapped output component only, not whole-engine resume or real devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
