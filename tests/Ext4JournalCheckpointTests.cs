using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class Ext4JournalCheckpointTests
{
    static int checks;
    static string work, fixtures;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static object Get(object obj, string name) { return obj.GetType().GetField(name).GetValue(obj); }
    static void Set(object obj, string name, object value) { obj.GetType().GetField(name).SetValue(obj, value); }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long, int>> Reads = new List<Tuple<long, int>>();
        public Source(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1) { }
        public override int Read(byte[] bytes, int start, int count)
        { Reads.Add(Tuple.Create(Position, count)); if (ZeroNext) return 0; return base.Read(bytes, start, count); }
    }
    sealed class Result
    {
        public string Transaction, Failure;
        public bool Committed, Limited;
        public uint Next;
        public uint Sequence;
        public int Revoked;
        public long Budget;
        public List<Tuple<long, int>> Reads;
    }
    static List<Tuple<long, int>> lastReads;
    static long[] ringOffsets;
    static string Parent(string root) { return Path.Combine(root, "anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root), Encoding.UTF8)) : null; }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint value)
    {
        string temp = Parent(root) + "." + Guid.NewGuid().ToString("N") + ".partial"; bool own = false;
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value));
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { own = true; output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temp, Parent(root), null); else File.Move(temp, Parent(root));
        }
        finally { if (own && File.Exists(temp)) File.Delete(temp); }
    }
    static Dictionary<string, object> State(string root)
    {
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "parent pins exact transaction state bytes");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8))["Payload"];
    }
    static string Image(string name, out string root, string file = "native-journal-v3-multiple-descriptors")
    {
        root = Path.Combine(work, name + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); File.Copy(Path.Combine(fixtures, file + ".dd"), image);
        File.SetAttributes(image, File.GetAttributes(image) & ~FileAttributes.ReadOnly); return image;
    }
    static string Transaction(object value)
    {
        var data = ((IEnumerable)Get(value, "DataBlocks")).Cast<object>().Select(item => {
            object tag = item.GetType().GetProperty("Item1").GetValue(item, null);
            return Get(tag, "DestinationBlock") + ":" + Get(tag, "Flags") + ":" + Get(tag, "Checksum") + ":" + item.GetType().GetProperty("Item2").GetValue(item, null);
        }).ToArray();
        return Json.Serialize(new { Sequence = Get(value, "Sequence"), Committed = Get(value, "Committed"),
            Headers = ((IEnumerable)Get(value, "HeaderBlocks")).Cast<uint>().OrderBy(x => x).ToArray(),
            Revoked = ((IEnumerable)Get(value, "RevokedBlocks")).Cast<ulong>().ToArray(), Data = data });
    }
    static Result Run(string image, string root, string sha, CancellationToken token, Action<string> progress,
        long budget = 10000, bool injectReadFailure = false, uint? requestedStart = null)
    {
        using (var input = new Source(image))
        {
            var context = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            var report = new Ext4Recovery.Report(); Set(context, "Input", input); Set(context, "Root", Path.Combine(root, "ext4"));
            Set(context, "Cancel", token); Set(context, "Report", report); Set(context, "Limits", new Ext4Recovery.Limits());
            object volume = typeof(Ext4Recovery).GetMethod("OpenVolume", Private).Invoke(null, new[] { context, (object)0L });
            object jc = typeof(Ext4Recovery).GetMethod("LoadJournal", Private).Invoke(null, new[] { context, volume, Get(volume, "Superblock") });
            Check(jc != null, "native-format journal opens");
            uint start = (uint)Get(jc, "Start"); if (start == 0) start = (uint)Get(jc, "First");
            if (requestedStart.HasValue) start = requestedStart.Value;
            ringOffsets = ((IEnumerable)Get(jc, "Blocks")).Cast<ulong>().Select(block =>
                (long)Get(volume, "Offset") + (long)block * (uint)Get(jc, "BlockBytes")).ToArray();
            input.Reads.Clear(); lastReads = input.Reads;
            var checkpoint = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
            Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", sha);
            Set(checkpoint, "Settings", "owned-journal-transaction-v1"); Set(checkpoint, "Resume", Anchor(root));
            Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(value => SaveAnchor(root, value)));
            Action<string> notify = m => { if (injectReadFailure) input.ZeroNext = true; if (progress != null) progress(m); };
            object[] args = { context, jc, start, null, 0U, null, budget, checkpoint, notify };
            bool committed;
            try { committed = (bool)typeof(Ext4Recovery).GetMethod("TryJournalTransactionCheckpointed", Private).Invoke(null, args); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return new Result { Transaction = Transaction(args[3]), Committed = committed, Next = (uint)args[4], Failure = (string)args[5],
                Sequence = (uint)Get(args[3], "Sequence"), Revoked = ((IList)Get(args[3], "RevokedBlocks")).Count,
                Budget = (long)args[6], Limited = report.Limited, Reads = input.Reads };
        }
    }
    static Result Reference(string image, string sha, long budget = 10000)
    { string root = Path.Combine(work, "reference-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image, root, sha, CancellationToken.None, null, budget); }
    static void Compare(Result left, Result right)
    {
        Check(left.Committed == right.Committed && left.Next == right.Next && left.Failure == right.Failure, "resumed transaction verdict and next ring position match uninterrupted parsing");
        Check(left.Budget == right.Budget && left.Limited == right.Limited, "journal budget survives continuation exactly");
        Check(left.Transaction == right.Transaction, "descriptor tags, checksums, physical data blocks and revokes survive continuation exactly");
    }
    static void Cancel(string image, string root, string sha, long budget = 10000)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        { try { Run(image, root, sha, cancel.Token, m => cancel.Cancel(), budget); } catch (OperationCanceledException) { stopped = true; } }
        var state = State(root);
        Check(stopped && !(bool)state["Complete"] && Convert.ToInt64(state["Budget"]) == budget - 64,
            "cancel interrupts a real native transaction after its first 64 one-KiB blocks");
    }
    static void Resumed(string image, string root, string sha, long budget = 10000)
    {
        var prefix = lastReads.ToArray();
        var result = Run(image, root, sha, CancellationToken.None, null, budget); Compare(Reference(image, sha, budget), result);
        Check(!result.Reads.Any(x => prefix.Any(p => x.Item1 < p.Item1 + p.Item2 && p.Item1 < x.Item1 + x.Item2)),
            "phase input stream never rereads the acknowledged transaction prefix");
        var repeat = Run(image, root, sha, CancellationToken.None, m => { throw new Exception("completed transaction restarted"); }, budget);
        Compare(result, repeat); Check(repeat.Reads.Count == 0, "completed transaction revalidates stored blocks without reading the journal through its phase stream");
        Check(Hash(image) == sha, "source is unchanged");
    }
    static void CancelResume()
    { string root, image = Image("cancel", out root), sha = Hash(image); Cancel(image, root, sha); Resumed(image, root, sha); }
    static void ParentFailure()
    {
        string root, image = Image("parent-denial", out root), sha = Hash(image); FileStream held = null; bool failed = false; string parent = null;
        try { Run(image, root, sha, CancellationToken.None, m => { if (held == null) { parent = Hash(Parent(root)); held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read); } }); }
        catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && held != null && Hash(Parent(root)) == parent && !(bool)State(root)["Complete"], "real OS parent replacement denial preserves the acknowledged transaction prefix");
        Run(image, root, sha, CancellationToken.None, null);
        Compare(Reference(image, sha), Run(image, root, sha, CancellationToken.None, null));
    }
    static void ShortRead()
    {
        string root, image = Image("short-read", out root), sha = Hash(image); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null, 10000, true); } catch (EndOfStreamException) { failed = true; }
        Check(failed && !(bool)State(root)["Complete"], "zero source read fails instead of publishing an uncommitted-log verdict");
        Compare(Reference(image, sha), Run(image, root, sha, CancellationToken.None, null));
    }
    static void SourceReadDenied()
    {
        string root, image = Image("source-read-denied", out root), sha = Hash(image), parent = null;
        FileStream held = null; long lockedAt = 0; bool failed = false;
        try
        {
            Run(image, root, sha, CancellationToken.None, m => {
                if (held != null) return;
                uint next = Convert.ToUInt32(State(root)["Next"]); lockedAt = ringOffsets[next];
                parent = Hash(Parent(root)); held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
                held.Lock(lockedAt, 1);
            });
        }
        catch (IOException) { failed = true; }
        finally { if (held != null) { held.Unlock(lockedAt, 1); held.Dispose(); } }
        Check(failed && held != null && Hash(Parent(root)) == parent && !(bool)State(root)["Complete"],
            "actual OS source range lock fails after the durable prefix without advancing it");
        Compare(Reference(image, sha), Run(image, root, sha, CancellationToken.None, null));
    }
    static void Budget()
    {
        string root, image = Image("budget", out root), sha = Hash(image); Cancel(image, root, sha, 70);
        using (var cancel = new CancellationTokenSource())
        { try { Run(image, root, sha, cancel.Token, m => cancel.Cancel(), 70); } catch (OperationCanceledException) { } }
        var result = Run(image, root, sha, CancellationToken.None, null, 70);
        Check(!result.Committed && result.Limited && result.Failure == "journal_work_limit" && result.Budget == -1,
            "actual 70-block work limit remains exhausted across repeated cancellation");
        Compare(Reference(image, sha, 70), result);
        string parent = Hash(Parent(root)); bool rejected = false;
        try { Run(image, root, sha, CancellationToken.None, null, 71); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(Parent(root)) == parent, "changed initial work budget cannot reopen the same transaction cursor");
    }
    static void Tamper(bool source)
    {
        string root, image = Image(source ? "source-change" : "blob-change", out root), sha = Hash(image); Cancel(image, root, sha);
        string target = source ? image : Directory.GetFiles(Path.Combine(root, "ext4.state", "journal-blobs"), "blob-*.json")[0];
        using (var file = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        { file.Position = source ? file.Length - 1 : 0; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value ^ 1)); }
        string changed = Hash(target), parent = Hash(Parent(root)); bool rejected = false;
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(target) == changed && Hash(Parent(root)) == parent, "changed source or raw journal facts are rejected and preserved");
    }
    static void NativeVariants()
    {
        foreach (string file in new[] { "native-journal-v2-replay", "native-journal-v3-ring-wrap", "native-journal-v3-escape", "native-journal-bad-descriptor-crc", "native-journal-bad-data-crc", "native-journal-bad-commit-crc" })
        {
            string root, image = Image(file, out root, file), sha = Hash(image);
            var result = Run(image, root, sha, CancellationToken.None, null);
            Compare(result, Run(image, root, sha, CancellationToken.None, null));
            Check(result.Committed == !file.Contains("bad-"), "native v2/ring/revoke verdict or deliberately corrupted checksum: " + file);
        }
        foreach (string file in new[] { "native-journal-v3-revoked", "native-journal-v3-sequence-wrap-revoked" })
        {
            string root, image = Image(file, out root, file), sha = Hash(image);
            var first = Run(image, root, sha, CancellationToken.None, null);
            string secondRoot = Path.Combine(root, "next-transaction"); Directory.CreateDirectory(secondRoot);
            var second = Run(image, secondRoot, sha, CancellationToken.None, null, 10000, false, first.Next);
            Check(first.Committed && second.Committed && second.Revoked > 0 && second.Sequence == unchecked(first.Sequence + 1),
                "native subsequent revoke transaction preserves sequence, including uint32 wrap: " + file);
            Compare(second, Run(image, secondRoot, sha, CancellationToken.None, null, 10000, false, first.Next));
        }
    }
    static void CursorTamper()
    {
        string root, image = Image("repinned-cursor", out root), sha = Hash(image); Cancel(image, root, sha);
        var anchor = Anchor(root);
        var envelope = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8));
        var state = (Dictionary<string, object>)envelope["Payload"]; state["Budget"] = Convert.ToInt64(state["Budget"]) + 1;
        File.WriteAllText(anchor.Path, Json.Serialize(envelope), new UTF8Encoding(false)); anchor.Sha256 = Hash(anchor.Path); SaveAnchor(root, anchor);
        string parent = Hash(Parent(root)); bool rejected = false;
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(Parent(root)) == parent, "rehashed but inconsistent transaction cursor is rejected by raw-fact replay");
    }
    static void KilledProcess()
    {
        string root, image = Image("worker", out root), sha = Hash(image), ready = Path.Combine(root, "ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned worker reaches a persisted transaction boundary"); child.Kill(); Check(child.WaitForExit(10000), "owned transaction worker is killed without graceful cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Compare(Reference(image, sha), Run(image, root, sha, CancellationToken.None, null));
    }
    public static int Main(string[] args)
    {
        try
        {
            if (typeof(Ext4Recovery).GetMethod("TryJournalTransactionCheckpointed", Private) == null)
            { Console.WriteLine("FAIL: no durable journal transaction parser in baseline"); return 1; }
            if (args.Length == 4 && args[0] == "--worker")
            { Run(args[1], args[2], Hash(args[1]), CancellationToken.None, m => { File.WriteAllText(args[3], "acknowledged"); Thread.Sleep(Timeout.Infinite); }); return 3; }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-journal-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            CancelResume(); ParentFailure(); ShortRead(); SourceReadDenied(); Budget(); Tamper(true); Tamper(false); CursorTamper(); NativeVariants(); KilledProcess();
            Console.WriteLine("PASS Ext4JournalCheckpoint: " + checks + " checks; transaction component, not whole-engine resume or devices"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
