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

public static class Ext4ReplayCheckpointTests
{
    static int checks;
    static string work, fixtures;
    static object lastVolume;
    static long journalSuperblock;
    static List<Read> lastReads;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static object Get(object value, string name) { return value.GetType().GetField(name).GetValue(value); }
    static void Set(object value, string name, object field) { value.GetType().GetField(name).SetValue(value, field); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    sealed class Read { public long At; public int Count; public string Phase; }
    sealed class Source : FileStream
    {
        readonly string root;
        public readonly List<Read> Reads = new List<Read>();
        public Source(string image, string state) : base(image, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1) { root = state; }
        public override int Read(byte[] bytes, int at, int count)
        {
            string phase = "scan"; var anchor = Anchor(root);
            if (anchor != null) phase = (string)Payload(anchor.Path)["Phase"];
            Reads.Add(new Read { At = Position, Count = count, Phase = phase }); return base.Read(bytes, at, count);
        }
    }
    sealed class Result
    {
        public string[] Overlay;
        public string Status, Skipped;
        public bool Attempted, Applied, Limited;
        public int ReplayRejections;
        public List<Read> Reads;
    }
    static string Parent(string root) { return Path.Combine(root, "anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root), Encoding.UTF8)) : null; }
    static Dictionary<string, object> Payload(string path)
    { return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8))["Payload"]; }
    static Dictionary<string, object> State(string root)
    { var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "parent pins exact replay state bytes"); return Payload(anchor.Path); }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint value)
    {
        string temp = Parent(root) + "." + Guid.NewGuid().ToString("N") + ".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value));
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { own = true; output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temp, Parent(root), null); else File.Move(temp, Parent(root));
        } finally { if (own && File.Exists(temp)) File.Delete(temp); }
    }
    static string Image(string name, out string root, string fixture = "native-journal-v3-multiple-descriptors")
    {
        root = Path.Combine(work, name + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); File.Copy(Path.Combine(fixtures, fixture + ".dd"), image);
        File.SetAttributes(image, File.GetAttributes(image) & ~FileAttributes.ReadOnly); return image;
    }
    static string[] Overlay(object volume)
    {
        var overlay = (IDictionary)Get(volume, "Overlay"); var rows = new List<string>();
        foreach (DictionaryEntry entry in overlay)
            using (var sha = System.Security.Cryptography.SHA256.Create())
                rows.Add(entry.Key + ":" + BitConverter.ToString(sha.ComputeHash((byte[])entry.Value)));
        return rows.OrderBy(row => row, StringComparer.Ordinal).ToArray();
    }
    static Result Run(string image, string root, string hash, CancellationToken token, Action<string> progress, bool durable = true)
    {
        using (var input = new Source(image, root)) {
            var c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            var report = new Ext4Recovery.Report(); Set(c, "Input", input); Set(c, "Root", Path.Combine(root, "ext4"));
            Set(c, "Report", report); Set(c, "Cancel", token); Set(c, "Limits", new Ext4Recovery.Limits());
            object volume = typeof(Ext4Recovery).GetMethod("OpenVolumeHeader", Private).Invoke(null, new[] { c, (object)0L });
            var vr = (Ext4Recovery.VolumeReport)Get(volume, "Report"); Check(vr.Status == "header_ready", "native header validates before any replay");
            var reserved = (IList)Activator.CreateInstance(Get(volume, "Reserved").GetType());
            foreach (object area in (IEnumerable)Get(volume, "Reserved")) reserved.Add(area);
            ulong gdStart = (uint)Get(volume, "FirstData") + 1UL;
            typeof(Ext4Recovery).GetMethod("ReadGroups", Private).Invoke(null, new[] { c, volume, (object)(ulong)vr.Groups, gdStart, reserved });
            object jc = typeof(Ext4Recovery).GetMethod("LoadJournal", Private).Invoke(null, new[] { c, volume, Get(volume, "Superblock") });
            Check(jc != null && ((IDictionary)Get(volume, "Overlay")).Count == 0, "native journal loads without prematurely applying its data");
            journalSuperblock = (long)Get(volume, "Offset") + (long)(ulong)((IList)Get(jc, "Blocks"))[0] * (uint)Get(jc, "BlockBytes");
            object checkpoint = null;
            if (durable) {
                checkpoint = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
                Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", hash);
                Set(checkpoint, "Settings", "owned-replay-v1"); Set(checkpoint, "Resume", Anchor(root));
                Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(value => SaveAnchor(root, value)));
            }
            input.Reads.Clear(); lastReads = input.Reads; lastVolume = volume;
            int baselineRejections = report.Skipped.Values.Sum();
            try { typeof(Ext4Recovery).GetMethod("ReplayJournalCheckpointed", Private).Invoke(null, new[] { c, jc, checkpoint, progress }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return new Result { Overlay = Overlay(volume), Status = vr.JournalStatus, Attempted = vr.JournalReplayAttempted,
                Applied = vr.JournalReplayApplied, Limited = report.Limited, Reads = input.Reads,
                ReplayRejections = report.Skipped.Values.Sum() - baselineRejections,
                Skipped = Json.Serialize(report.Skipped.OrderBy(row => row.Key).ToArray()) };
        }
    }
    static Result Reference(string image, string hash)
    { string root = Path.Combine(work, "reference-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image, root, hash, CancellationToken.None, null, false); }
    static void Compare(Result a, Result b)
    {
        Check(a.Overlay.SequenceEqual(b.Overlay), "resumed overlay matches uninterrupted block destinations and exact byte hashes");
        Check(a.Status == b.Status && a.Attempted == b.Attempted && a.Applied == b.Applied && a.Limited == b.Limited && a.Skipped == b.Skipped,
            "replay status, rejection counts and coverage budget are preserved exactly");
    }
    static void Cancel(string image, string root, string hash, string boundary)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, hash, cancel.Token, m => { if (m.StartsWith(boundary, StringComparison.Ordinal)) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped, "cancellation propagates after durable " + boundary);
    }
    static void Complete(string image, string root, string hash)
    {
        var result = Run(image, root, hash, CancellationToken.None, null); Compare(Reference(image, hash), result);
        var repeat = Run(image, root, hash, CancellationToken.None, m => { throw new Exception("completed replay restarted"); });
        Compare(result, repeat); Check(repeat.Reads.Count == 0, "completed replay restores verified facts and overlay without phase-stream source reads");
        Check((string)State(root)["Phase"] == "complete" && Hash(image) == hash, "replay completes without changing the source image");
    }
    static void Boundaries()
    {
        foreach (string boundary in new[] { "ext4: journal blocks", "ext4: replay transactions", "ext4: replay overlay" }) {
            string root, image = Image("cancel", out root), hash = Hash(image); Cancel(image, root, hash, boundary);
            bool overlay = boundary.EndsWith("overlay"); var prefix = lastReads.Where(row => row.Count == 1024 && row.Phase == (overlay ? "overlay" : "scan")).Select(row => row.At).ToArray();
            Check(prefix.Length > 0, "real source prefix precedes the cancellation boundary");
            var result = Run(image, root, hash, CancellationToken.None, null); Compare(Reference(image, hash), result);
            Check(!result.Reads.Any(row => row.Count == 1024 && row.Phase == (overlay ? "overlay" : "scan") && prefix.Contains(row.At)),
                "resumption does not reread the acknowledged prefix within the same replay phase");
            Complete(image, root, hash);
        }
    }
    static void ParentFailure(bool overlay)
    {
        string root, image = Image("parent-failure", out root), hash = Hash(image), parent = null; FileStream held = null; bool failed = false; int prefix = 0;
        try { Run(image, root, hash, CancellationToken.None, m => {
            if (held != null || !m.StartsWith(overlay ? "ext4: replay overlay" : "ext4: journal blocks", StringComparison.Ordinal)) return;
            parent = Hash(Parent(root)); prefix = ((IDictionary)Get(lastVolume, "Overlay")).Count;
            held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read);
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && held != null && Hash(Parent(root)) == parent && ((IDictionary)Get(lastVolume, "Overlay")).Count == prefix,
            "OS parent replace denial preserves the acknowledged cursor and in-memory overlay prefix");
        Complete(image, root, hash);
    }
    static void SourceReadDenied()
    {
        string root, image = Image("source-read-denied", out root), hash = Hash(image), parent = null; FileStream held = null; bool failed = false;
        try { Run(image, root, hash, CancellationToken.None, m => {
            if (held != null) return; parent = Hash(Parent(root)); held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read); held.Lock(0, held.Length);
        }); } catch (IOException) { failed = true; } finally { if (held != null) { held.Unlock(0, held.Length); held.Dispose(); } }
        Check(failed && held != null && Hash(Parent(root)) == parent, "actual OS source read denial preserves the last acknowledged replay state"); Complete(image, root, hash);
    }
    static void Tamper(bool source)
    {
        string root, image = Image("tamper", out root), hash = Hash(image); Cancel(image, root, hash, "ext4: replay overlay");
        string file = image;
        if (!source)
        {
            var head = (Dictionary<string, object>)State(root)["Overlay"];
            string page = Path.Combine(root, "ext4.state", "replay", "overlay", (string)head["Path"]);
            var envelope = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(page, Encoding.UTF8));
            var records = ((IEnumerable)envelope["Records"]).Cast<object>().ToArray();
            string blob = (string)((Dictionary<string, object>)records[0])["BlobSha256"];
            file = Path.Combine(root, "ext4.state", "journal-blobs", "blob-" + blob + ".json");
        }
        using (var output = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        { output.Position = source ? output.Length - 1 : 0; int value = output.ReadByte(); output.Position--; output.WriteByte((byte)(value ^ 1)); }
        string parent = Hash(Parent(root)), changed = Hash(file); bool rejected = false;
        try { Run(image, root, hash, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(Parent(root)) == parent && Hash(file) == changed, "source or overlay fact changes are rejected and preserved");
    }
    static void NativeCases()
    {
        foreach (string fixture in new[] { "native-journal-v2-replay", "native-journal-v3-ring-wrap", "native-journal-v3-escape", "native-journal-v3-revoked", "native-journal-v3-sequence-wrap-revoked", "native-journal-v3-uncommitted", "native-journal-v3-uncommitted-revoke", "native-journal-bad-descriptor-crc", "native-journal-bad-data-crc", "native-journal-bad-commit-crc", "native-journal-bad-revoke-crc", "native-journal-v3-history" }) {
            string root, image = Image(fixture, out root, fixture), hash = Hash(image); var result = Run(image, root, hash, CancellationToken.None, null);
            Compare(Reference(image, hash), result);
            if (fixture.Contains("bad-")) Check(!result.Applied && result.Overlay.Length == 0, "corrupted committed log is never partially replayed: " + fixture);
            if (fixture.EndsWith("-revoked")) Check(result.Applied && result.Overlay.Length == 0, "later committed revoke removes earlier data, including wrapped sequence");
            if (fixture.EndsWith("-history")) Check(!result.Applied && result.Overlay.Length == 0, "clean zero-start journal is not replayed");
            if (fixture.EndsWith("-escape")) Check(((IDictionary)Get(lastVolume, "Overlay")).Values.Cast<byte[]>().Any(bytes =>
                bytes.Take(4).SequenceEqual(new byte[] { 0xc0, 0x3b, 0x39, 0x98 })), "escaped journal magic is restored in replayed bytes");
            Complete(image, root, hash);
        }
    }
    static void RepinnedState(bool removeProbe)
    {
        string root, image = Image("repinned", out root), hash = Hash(image); Cancel(image, root, hash, "ext4: journal blocks");
        var anchor = Anchor(root); var envelope = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8));
        var state = (Dictionary<string, object>)envelope["Payload"];
        if (removeProbe) state["PendingProbe"] = null; else state["Budget"] = Convert.ToInt64(state["Budget"]) + 1;
        File.WriteAllText(anchor.Path, Json.Serialize(envelope), new UTF8Encoding(false)); anchor.Sha256 = Hash(anchor.Path); SaveAnchor(root, anchor);
        string parent = Hash(Parent(root)); bool rejected = false;
        try { Run(image, root, hash, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && lastReads.Count == 0 && Hash(Parent(root)) == parent, "repinned budget or active child without its probe is rejected before source reads/parent writes");
    }
    static void SourceLease()
    {
        string root, image = Image("source-lease", out root), hash = Hash(image); bool denied = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, hash, cancel.Token, m => {
                try { using (var writer = new FileStream(image, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)) { } }
                catch (IOException) { denied = true; } cancel.Cancel();
            }); } catch (OperationCanceledException) { }
        }
        Check(denied && Hash(image) == hash, "owned replay lease prevents source writes even with a permissive supplied phase stream"); Complete(image, root, hash);
    }
    static void PutBigEndian(byte[] bytes, int at, uint value)
    { for (int index = 3; index >= 0; index--) { bytes[at + index] = (byte)value; value >>= 8; } }
    static void WrongSequence()
    {
        string root, image = Image("wrong-sequence", out root, "native-journal-v3-replay"); Reference(image, Hash(image));
        byte[] bytes = File.ReadAllBytes(image); int at = checked((int)journalSuperblock);
        uint expected = (uint)(bytes[at + 24] << 24 | bytes[at + 25] << 16 | bytes[at + 26] << 8 | bytes[at + 27]);
        PutBigEndian(bytes, at + 24, unchecked(expected + 1)); Array.Clear(bytes, at + 0xfc, 4);
        uint crc = 0xffffffff;
        for (int index = at; index < at + 1024; index++) {
            crc ^= bytes[index]; for (int bit = 0; bit < 8; bit++) crc = crc >> 1 ^ ((crc & 1) != 0 ? 0x82f63b78U : 0);
        }
        PutBigEndian(bytes, at + 0xfc, crc); File.WriteAllBytes(image, bytes); string hash = Hash(image);
        var result = Run(image, root, hash, CancellationToken.None, null);
        Check(!result.Applied && result.Overlay.Length == 0 && result.Status == "validated_superblock" && result.ReplayRejections == 0,
            "independently repinned journal-superblock sequence mismatch terminates normally without replay or a false checksum verdict; " +
            Json.Serialize(new { result.Applied, result.Status, result.ReplayRejections, result.Skipped }));
        Complete(image, root, hash);
    }
    static void KilledProcess()
    {
        string root, image = Image("worker", out root), hash = Hash(image), ready = Path.Combine(root, "ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var watch = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned replay worker reaches a persisted partial overlay"); child.Kill(); Check(child.WaitForExit(10000), "owned worker killed without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Complete(image, root, hash);
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("ReplayJournalCheckpointed", Private) == null)
            { Console.WriteLine("FAIL: baseline lacks durable replay controller"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1], args[2], Hash(args[1]), CancellationToken.None, m => { if (m.StartsWith("ext4: replay overlay", StringComparison.Ordinal)) { File.WriteAllText(args[3], "acknowledged"); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-replay-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            Boundaries(); ParentFailure(false); ParentFailure(true); SourceReadDenied(); SourceLease(); Tamper(true); Tamper(false);
            RepinnedState(false); RepinnedState(true); NativeCases(); WrongSequence(); KilledProcess();
            Console.WriteLine("PASS Ext4ReplayCheckpoint: " + checks + " checks; replay component only, full ext4 engine and devices not claimed"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
