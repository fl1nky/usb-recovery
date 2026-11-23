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

public static class Ext4JournalHistoryCheckpointTests
{
    static int checks;
    static string work, fixtures;
    static long[] ring;
    static List<Tuple<long, int>> reads;
    static Ext4Recovery.Limits activeLimits;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static object Get(object value, string name) { return value.GetType().GetField(name).GetValue(value); }
    static void Set(object value, string name, object field) { value.GetType().GetField(name).SetValue(value, field); }
    sealed class Source : FileStream
    {
        public readonly List<Tuple<long, int>> Trace = new List<Tuple<long, int>>();
        // The coordinator's additional lease must protect even this permissive
        // test stream. Production Recover itself opens with FileShare.Read.
        public Source(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1) { }
        public override int Read(byte[] bytes, int at, int count) { Trace.Add(Tuple.Create(Position, count)); return base.Read(bytes, at, count); }
    }
    sealed class Result
    {
        public string[] Transactions;
        public string Skipped;
        public bool Limited;
        public int Revoked;
        public List<Tuple<long, int>> Reads;
    }
    static string Parent(string root) { return Path.Combine(root, "anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root), Encoding.UTF8)) : null; }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint anchor)
    {
        string temp = Parent(root) + "." + Guid.NewGuid().ToString("N") + ".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(anchor));
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { own = true; output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temp, Parent(root), null); else File.Move(temp, Parent(root));
        } finally { if (own && File.Exists(temp)) File.Delete(temp); }
    }
    static Dictionary<string, object> Payload(string path)
    { return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8))["Payload"]; }
    static Dictionary<string, object> State(string root)
    { var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "whole scan parent pins exact state"); return Payload(anchor.Path); }
    static string Image(string label, out string root, string fixture = "native-journal-v3-multiple-descriptors")
    {
        root = Path.Combine(work, label + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); File.Copy(Path.Combine(fixtures, fixture + ".dd"), image);
        File.SetAttributes(image, File.GetAttributes(image) & ~FileAttributes.ReadOnly); return image;
    }
    static Result Run(string image, string root, string hash, CancellationToken token, Action<string> progress, bool durable = true)
    {
        using (var input = new Source(image)) {
            var c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            var report = new Ext4Recovery.Report(); Set(c, "Input", input); Set(c, "Root", Path.Combine(root, "ext4"));
            activeLimits = new Ext4Recovery.Limits();
            Set(c, "Report", report); Set(c, "Cancel", token); Set(c, "Limits", activeLimits);
            var volume = typeof(Ext4Recovery).GetMethod("OpenVolume", Private).Invoke(null, new[] { c, (object)0L });
            var jc = typeof(Ext4Recovery).GetMethod("LoadJournal", Private).Invoke(null, new[] { c, volume, Get(volume, "Superblock") });
            Check(jc != null, "native journal metadata loads");
            ring = ((IEnumerable)Get(jc, "Blocks")).Cast<ulong>().Select(block => (long)Get(volume, "Offset") + (long)block * (uint)Get(jc, "BlockBytes")).ToArray();
            object checkpoint = null;
            if (durable) {
                checkpoint = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
                Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", hash);
                Set(checkpoint, "Settings", "owned-history-scan-v1"); Set(checkpoint, "Resume", Anchor(root));
                Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(value => SaveAnchor(root, value)));
            }
            input.Trace.Clear(); reads = input.Trace; object result;
            try { result = typeof(Ext4Recovery).GetMethod("ReadJournalHistoryTransactionsCheckpointed", Private).Invoke(null, new[] { c, jc, checkpoint, progress }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            var transactions = result == null ? null : ((IEnumerable)result).Cast<object>().ToArray();
            return new Result { Transactions = transactions == null ? null : transactions.Select(tx => Json.Serialize(tx)).ToArray(),
                Revoked = transactions == null ? 0 : transactions.Sum(tx => ((IList)Get(tx, "RevokedBlocks")).Count),
                Skipped = Json.Serialize(report.Skipped.OrderBy(x => x.Key).ToArray()), Limited = report.Limited, Reads = input.Trace };
        }
    }
    static Result Reference(string image, string hash)
    { string root = Path.Combine(work, "reference-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image, root, hash, CancellationToken.None, null, false); }
    static void Compare(Result a, Result b)
    {
        Check((a.Transactions == null) == (b.Transactions == null), "truncated history is not promoted to a complete transaction list");
        Check(a.Transactions == null || a.Transactions.SequenceEqual(b.Transactions), "all verified transactions and their source blocks match uninterrupted scanning");
        Check(a.Skipped == b.Skipped && a.Limited == b.Limited && a.Revoked == b.Revoked, "rejected attempts, revokes and coverage budget survive exactly once");
    }
    static void Cancel(string image, string root, string hash, string boundary)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        { try { Run(image, root, hash, cancel.Token, m => { if (m.StartsWith(boundary, StringComparison.Ordinal)) cancel.Cancel(); }); } catch (OperationCanceledException) { stopped = true; } }
        Check(stopped, "cancellation propagates after durable boundary " + boundary);
    }
    static void Complete(string image, string root, string hash)
    {
        var result = Run(image, root, hash, CancellationToken.None, null); Compare(Reference(image, hash), result);
        var repeat = Run(image, root, hash, CancellationToken.None, m => { throw new Exception("completed journal scan restarted"); });
        Compare(result, repeat); Check(repeat.Reads.Count == 0, "completed header and transaction phases read no journal bytes through the phase stream");
        Check((string)State(root)["Phase"] == "complete" && Hash(image) == hash, "whole journal scan completes without changing the source");
    }
    static void ResumeBoundaries()
    {
        foreach (string boundary in new[] { "ext4: journal headers", "ext4: journal blocks", "ext4: journal transactions" }) {
            string root, image = Image("cancel", out root), hash = Hash(image);
            Cancel(image, root, hash, boundary); var prefix = reads.Where(x => x.Item2 == (boundary.EndsWith("headers") ? 12 : 1024)).ToArray();
            Check(prefix.Length > 0, "a real source prefix was processed before cancellation");
            var result = Run(image, root, hash, CancellationToken.None, null); Compare(Reference(image, hash), result);
            Check(!result.Reads.Where(x => x.Item2 == (boundary.EndsWith("headers") ? 12 : 1024)).Any(x => prefix.Any(p => x.Item1 == p.Item1)),
                "acknowledged header or transaction prefix is reused at " + boundary);
            Complete(image, root, hash);
        }
    }
    static void ParentFailure()
    {
        string root, image = Image("parent-denied", out root), hash = Hash(image), parent = null; FileStream held = null; bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, m => { if (held == null) { parent = Hash(Parent(root)); held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read); } }); }
        catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && held != null && Hash(Parent(root)) == parent, "OS parent replacement denial does not acknowledge a later child cursor");
        Complete(image, root, hash);
    }
    static void SourceLease()
    {
        string root, image = Image("source-lease", out root), hash = Hash(image); bool denied = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, hash, cancel.Token, m => { try { using (var writer = new FileStream(image, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)) { } }
                catch (IOException) { denied = true; } cancel.Cancel(); }); } catch (OperationCanceledException) { }
        }
        Check(denied && Hash(image) == hash, "owned scan lease blocks source writers even when the supplied phase stream allows them"); Complete(image, root, hash);
    }
    static void SourceReadDenied()
    {
        string root, image = Image("source-read-denied", out root), hash = Hash(image), parent = null;
        FileStream held = null; long at = 0; bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, m => {
            if (held != null) return; var state = State(root); var child = (Dictionary<string, object>)state["Headers"];
            uint next = Convert.ToUInt32(Payload(Path.Combine(root, (string)child["Path"]))["Next"]); at = ring[next];
            parent = Hash(Parent(root)); held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read); held.Lock(at, 1);
        }); } catch (IOException) { failed = true; } finally { if (held != null) { held.Unlock(at, 1); held.Dispose(); } }
        Check(failed && held != null && Hash(Parent(root)) == parent, "OS source range denial keeps the last acknowledged header prefix"); Complete(image, root, hash);
    }
    static void Tamper(bool source)
    {
        string root, image = Image(source ? "source-tamper" : "blob-tamper", out root), hash = Hash(image); Cancel(image, root, hash, "ext4: journal blocks");
        string file = source ? image : Directory.GetFiles(Path.Combine(root, "ext4.state", "history"), "blob-*.json", SearchOption.AllDirectories)[0];
        using (var output = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        { output.Position = source ? output.Length - 1 : 0; int value = output.ReadByte(); output.Position--; output.WriteByte((byte)(value ^ 1)); }
        string changed = Hash(file), parent = Hash(Parent(root)); bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && Hash(file) == changed && Hash(Parent(root)) == parent, "changed source or descendant facts are rejected and preserved");
    }
    static void RepinnedPhase()
    {
        string root, image = Image("repinned-phase", out root), hash = Hash(image); Cancel(image, root, hash, "ext4: journal headers");
        var anchor = Anchor(root); var envelope = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8));
        ((Dictionary<string, object>)envelope["Payload"])["Phase"] = "complete";
        File.WriteAllText(anchor.Path, Json.Serialize(envelope), new UTF8Encoding(false)); anchor.Sha256 = Hash(anchor.Path); SaveAnchor(root, anchor);
        string parent = Hash(Parent(root)); bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && Hash(Parent(root)) == parent, "repinned completed phase with incomplete headers is rejected before source sweep or parent mutation");
    }
    static void NativeVariants()
    {
        foreach (string fixture in new[] { "native-journal-v2-replay", "native-journal-v3-ring-wrap", "native-journal-v3-escape", "native-journal-v3-revoked", "native-journal-v3-sequence-wrap-revoked", "native-journal-bad-commit-crc" }) {
            string root, image = Image(fixture, out root, fixture), hash = Hash(image);
            var result = Run(image, root, hash, CancellationToken.None, null); Compare(Reference(image, hash), result);
            if (fixture.Contains("revoked")) Check(result.Transactions.Length == 2 && result.Revoked > 0, "later native revoke transaction is retained before history candidates are processed");
            Complete(image, root, hash);
        }
    }
    static void ChangedLimits()
    {
        string root, image = Image("changed-limits", out root), hash = Hash(image); bool failed = false, changed = false;
        try { Run(image, root, hash, CancellationToken.None, m => { if (!changed) { activeLimits.MaximumNames--; changed = true; } }); }
        catch (IOException error) { failed = error.Message == "EXT4_JOURNAL_LIMITS_CHANGED"; }
        Check(changed && failed && Hash(image) == hash, "cached journal binding does not hide changed public work limits");
        Complete(image, root, hash);
    }
    static void Relocated()
    {
        string root, image = Image("relocated", out root), hash = Hash(image); Cancel(image, root, hash, "ext4: journal blocks");
        var anchor = Anchor(root); string relative = anchor.Path.Substring(root.Length + 1), target = root + "-moved";
        string prefix = Path.GetFullPath(work).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        Check(Path.GetFullPath(root).StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            Path.GetFullPath(target).StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !Directory.Exists(target),
            "move is limited to two checked absolute paths inside this test's owned workspace");
        Directory.Move(root, target); anchor.Path = Path.Combine(target, relative); SaveAnchor(target, anchor);
        Complete(Path.Combine(target, "owned.dd"), target, hash);
    }
    static uint BigEndian(byte[] bytes, int at)
    { return (uint)(bytes[at] << 24 | bytes[at + 1] << 16 | bytes[at + 2] << 8 | bytes[at + 3]); }
    static void PutBigEndian(byte[] bytes, int at, uint value)
    { for (int index = 3; index >= 0; index--) { bytes[at + index] = (byte)value; value >>= 8; } }
    static void BudgetAcrossAttempts()
    {
        string root, image = Image("overlapping-attempt-budget", out root, "native-journal-v3-replay");
        Reference(image, Hash(image)); // Obtain the native journal's physical map.
        byte[] bytes = File.ReadAllBytes(image); int super = checked((int)ring[0]);
        int block = checked((int)BigEndian(bytes, super + 12));
        Check(block == 1024 && BigEndian(bytes, checked((int)ring[1]) + 4) == 1 && BigEndian(bytes, checked((int)ring[3]) + 4) == 2,
            "budget derivative starts from the native one-descriptor v3 transaction");
        byte[] descriptor = bytes.Skip((int)ring[1]).Take(block).ToArray(), data = bytes.Skip((int)ring[2]).Take(block).ToArray(), commit = bytes.Skip((int)ring[3]).Take(block).ToArray();
        // Explicit synthetic derivative: twenty valid descriptor/data pairs,
        // one commit and a stale extra descriptor with the same sequence. No
        // start covers all same-sequence headers, so attempts share one budget.
        for (int index = 1; index < 64; index++) Array.Clear(bytes, (int)ring[index], block);
        for (int index = 0; index < 20; index++) {
            Buffer.BlockCopy(descriptor, 0, bytes, (int)ring[1 + index * 2], block);
            Buffer.BlockCopy(data, 0, bytes, (int)ring[2 + index * 2], block);
        }
        Buffer.BlockCopy(commit, 0, bytes, (int)ring[41], block);
        Buffer.BlockCopy(descriptor, 0, bytes, (int)ring[43], block);
        PutBigEndian(bytes, super + 16, 64); Array.Clear(bytes, super + 0xfc, 4);
        uint crc = 0xffffffff;
        for (int at = super; at < super + 1024; at++) {
            crc ^= bytes[at]; for (int bit = 0; bit < 8; bit++) crc = crc >> 1 ^ ((crc & 1) != 0 ? 0x82f63b78U : 0);
        }
        PutBigEndian(bytes, super + 0xfc, crc); File.WriteAllBytes(image, bytes); string hash = Hash(image);
        long previous = 4 * 63; int attempts = 0;
        for (int turn = 0; turn < 16; turn++) {
            Cancel(image, root, hash, "ext4: journal transactions"); var state = State(root);
            long remaining = Convert.ToInt64(state["Budget"]);
            Check(remaining < previous, "each cancelled completed attempt consumes the same cumulative budget"); previous = remaining; attempts++;
            if ((string)state["Phase"] == "complete") break;
        }
        Check(attempts > 1 && previous == -1 && (bool)State(root)["Limited"], "real overlapping transaction attempts exhaust 252 blocks across repeated cancellations");
        var result = Run(image, root, hash, CancellationToken.None, null);
        Check(result.Transactions == null && result.Limited && result.Skipped.Contains("journal_work_limit"), "limited scan does not publish a complete history list");
        Compare(Reference(image, hash), result); Complete(image, root, hash);
    }
    static void KilledProcess()
    {
        string root, image = Image("killed-worker", out root), hash = Hash(image), ready = Path.Combine(root, "ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned worker reaches an acknowledged partial transaction inside the whole scan"); child.Kill(); Check(child.WaitForExit(10000), "owned scan worker is killed without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Complete(image, root, hash);
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("ReadJournalHistoryTransactionsCheckpointed", Private) == null)
            { Console.WriteLine("FAIL: baseline has no durable whole journal transaction scan"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1], args[2], Hash(args[1]), CancellationToken.None, m => { if (m.StartsWith("ext4: journal blocks", StringComparison.Ordinal)) { File.WriteAllText(args[3], "acknowledged"); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-history-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            ResumeBoundaries(); ParentFailure(); SourceLease(); SourceReadDenied(); Tamper(true); Tamper(false); RepinnedPhase(); NativeVariants(); ChangedLimits(); Relocated(); BudgetAcrossAttempts(); KilledProcess();
            Console.WriteLine("PASS Ext4JournalHistoryCheckpoint: " + checks + " checks; journal discovery/transaction controller only, full ext4 engine resume not claimed"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
