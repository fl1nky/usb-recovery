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

// Native current directories plus explicitly synthetic journal-name records.
// Mapping controls reuse native extent/indirect nodes as a supplied directory
// candidate; this is not a new filesystem produced by an independent writer.
public static class Ext4DirectoryCheckpointTests
{
    static int checks;
    static string work, fixtures;
    static List<Tuple<long, int>> reads;
    static long forbiddenStart, forbiddenLength;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
    static object Get(object value, string name) { return value.GetType().GetField(name).GetValue(value); }
    static void Set(object value, string name, object data) { value.GetType().GetField(name).SetValue(value, data); }
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long, int>> Reads = new List<Tuple<long, int>>();
        public Source(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1) { }
        public override int Read(byte[] bytes, int at, int count)
        { Reads.Add(Tuple.Create(Position, count)); return ZeroNext ? 0 : base.Read(bytes, at, count); }
    }
    sealed class Result
    {
        public int Directories, Names;
        public long Bytes;
        public bool Limited;
        public string[] Rows;
        public List<Ext4Recovery.NameLink> Links;
        public List<Tuple<long, int>> Reads;
        public Dictionary<string, int> Skipped;
    }
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
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "caller pins exact directory-phase state");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8))["Payload"];
    }
    static string Image(string name, out string root, string fixture = "unicode-retained-link")
    {
        root = Path.Combine(work, name + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); File.Copy(Path.Combine(fixtures, fixture + ".dd"), image);
        File.SetAttributes(image, File.GetAttributes(image) & ~FileAttributes.ReadOnly); return image;
    }
    static void Put16(byte[] data, int at, int value) { Buffer.BlockCopy(BitConverter.GetBytes((ushort)value), 0, data, at, 2); }
    static void Put32(byte[] data, int at, uint value) { Buffer.BlockCopy(BitConverter.GetBytes(value), 0, data, at, 4); }
    static byte[] DirectoryBytes(uint parent, uint target, string name, int block)
    {
        byte[] bytes = new byte[block]; int at = 0;
        var rows = new[] { Tuple.Create(parent, "."), Tuple.Create(2U, ".."), Tuple.Create(target, name) };
        for (int index = 0; index < rows.Length; index++) {
            byte[] encoded = Encoding.UTF8.GetBytes(rows[index].Item2);
            int length = index == rows.Length - 1 ? block - 12 - at : (8 + encoded.Length + 3) & ~3;
            Put32(bytes, at, rows[index].Item1); Put16(bytes, at + 4, length); bytes[at + 6] = (byte)encoded.Length; bytes[at + 7] = 1;
            Buffer.BlockCopy(encoded, 0, bytes, at + 8, encoded.Length); at += length;
        }
        Put16(bytes, block - 8, 12); bytes[block - 5] = 0xde; Put32(bytes, block - 4, 0xdeadbeef); return bytes;
    }
    static object History(object volume, bool changed)
    {
        var type = typeof(Ext4Recovery).GetNestedType("JournalDirectoryBlock", BindingFlags.NonPublic);
        var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(type));
        for (int index = 0; index < 4; index++) {
            object row = Activator.CreateInstance(type, true);
            Set(row, "TargetDiskBlock", 21UL); Set(row, "JournalBlock", index < 2 ? 23UL : (ulong)(22 + index));
            Set(row, "TransactionSequence", index < 2 ? 7U : (uint)(6 + index));
            uint parent = index == 3 ? 42U : 2U, target = index == 3 ? 43U : 42U;
            Set(row, "Bytes", DirectoryBytes(parent, target, index == 3 ? "семейный рецепт.jpg" : changed ? "changed" : "old-parent", (int)Get(volume, "BlockBytes")));
            list.Add(row);
        }
        return list;
    }
    static Result Run(string image, string root, string sha, CancellationToken token, Action<string> progress,
        bool durable = true, Ext4Recovery.Limits limits = null, string change = null, bool mapping = false, bool zero = false)
    {
        using (var input = new Source(image)) {
            var c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            var report = new Ext4Recovery.Report(); Set(c, "Input", input); Set(c, "Root", Path.Combine(root, "ext4"));
            Set(c, "Report", report); Set(c, "Cancel", token); Set(c, "Limits", limits ?? new Ext4Recovery.Limits());
            object volume = typeof(Ext4Recovery).GetMethod("OpenVolume", Private).Invoke(null, new[] { c, (object)0L });
            Check(((Ext4Recovery.VolumeReport)Get(volume, "Report")).Status == "ready", "native filesystem initialization validates");
            object[] scan = { c, volume, null, null, null, null };
            typeof(Ext4Recovery).GetMethod("ScanInodesCheckpointed", Private).Invoke(null, scan);
            var directories = (IDictionary)scan[5];
            if (mapping) {
                object candidate = ((IList)scan[4])[0]; directories.Add(Get(candidate, "Number"), candidate);
            }
            if (change == "directory") {
                object first = directories.Values.Cast<object>().First(); Set(first, "Generation", (uint)Get(first, "Generation") + 1);
            }
            if (change == "shrink") {
                object inode = directories.Values.Cast<object>().First(x => (ulong)Get(x, "Size") > (ulong)(int)Get(volume, "BlockBytes"));
                byte[] bytes = (byte[])Get(inode, "Bytes"); int block = (int)Get(volume, "BlockBytes");
                Check((uint)Get(inode, "Flags") == 0x80000 && BitConverter.ToUInt16(bytes, 0x2e) == 0 && BitConverter.ToUInt16(bytes, 0x38) > 1,
                    "native directory has a direct multi-block extent for independent bounds control");
                ulong physical = BitConverter.ToUInt32(bytes, 0x3c) | (ulong)BitConverter.ToUInt16(bytes, 0x3a) << 32;
                forbiddenStart = ((long)physical + 1) * block; forbiddenLength = (BitConverter.ToUInt16(bytes, 0x38) - 1L) * block;
                Set(inode, "Size", (ulong)block);
            }
            if (change == "empty") directories.Clear();
            Set(c, "DirectoryCount", 0); Set(c, "NameCount", change == "baseline" ? 2 : 1); Set(c, "DirectoryBytes", 1024L);
            report.Skipped["prior_volume_control"] = 7;
            object history = change == "empty" ? null : History(volume, change == "history");
            object checkpoint = null;
            if (durable) {
                checkpoint = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
                Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", sha);
                Set(checkpoint, "Settings", "owned-directory-phase-v1"); Set(checkpoint, "Resume", Anchor(root));
                Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(value => SaveAnchor(root, value)));
            }
            input.Reads.Clear(); reads = input.Reads; if (change == "zero-legacy") input.ZeroNext = true;
            Action<string> notify = message => { if (zero && message.Contains("(data)")) input.ZeroNext = true; if (progress != null) progress(message); };
            object[] args = { c, volume, scan[5], history, checkpoint, notify }; object found;
            try { found = typeof(Ext4Recovery).GetMethod(change == "shrink" || change == "zero-legacy" ? "DirectoryNames" : "DirectoryNamesCheckpointed", Private)
                .Invoke(null, change == "shrink" || change == "zero-legacy" ? args.Take(4).ToArray() : args); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            var links = ((Dictionary<uint, List<Ext4Recovery.NameLink>>)found).Values.SelectMany(x => x).ToList();
            return new Result { Directories = (int)Get(c, "DirectoryCount"), Names = (int)Get(c, "NameCount"), Bytes = (long)Get(c, "DirectoryBytes"),
                Limited = report.Limited, Rows = links.Select(x => Json.Serialize(x)).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
                Links = links, Reads = input.Reads, Skipped = report.Skipped };
        }
    }
    static Result Reference(string image, string sha, Ext4Recovery.Limits limits = null, bool mapping = false)
    { string root = Path.Combine(work, "reference-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image, root, sha, CancellationToken.None, null, false, limits, null, mapping); }
    static void Compare(Result a, Result b)
    {
        Check(a.Rows.SequenceEqual(b.Rows), "restored names, current paths, statuses, CRC evidence and journal provenance match uninterrupted parsing");
        Check(a.Directories == b.Directories && a.Names == b.Names && a.Bytes == b.Bytes && a.Limited == b.Limited,
            "directory, byte and name budgets survive resume without resetting");
        Check(Json.Serialize(a.Skipped.OrderBy(x => x.Key).ToArray()) == Json.Serialize(b.Skipped.OrderBy(x => x.Key).ToArray()), "skip diagnostics are neither lost nor doubled");
    }
    static void Cancel(string image, string root, string sha, string kind = "data", bool mapping = false)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image, root, sha, cancel.Token, m => { if (m.Contains("(" + kind + ")")) cancel.Cancel(); }, true, null, null, mapping); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && !(bool)State(root)["Complete"] && Convert.ToInt32(State(root)["Next"]) > 1, "cancel pins a real raw metadata prefix before completion");
    }
    static void Complete(string image, string root, string sha, bool mapping = false)
    {
        var prefix = reads.ToArray(); var result = Run(image, root, sha, CancellationToken.None, null, true, null, null, mapping);
        Compare(Reference(image, sha, null, mapping), result);
        Check(!result.Reads.Any(x => prefix.Any(p => p.Item1 < x.Item1 + x.Item2 && x.Item1 < p.Item1 + p.Item2)), "resume does not reread the acknowledged directory/map prefix through the phase stream");
        var repeat = Run(image, root, sha, CancellationToken.None, m => { throw new Exception("completed directory phase restarted"); }, true, null, null, mapping);
        Compare(result, repeat); Check(repeat.Reads.Count == 0 && (bool)State(root)["Complete"] && Hash(image) == sha, "completed phase reconstructs all names with zero scan-stream reads and preserves source");
    }
    static void CancelResume(string fixture = "unicode-retained-link", string kind = "data", bool mapping = false)
    { string root, image = Image("cancel-" + kind, out root, fixture), sha = Hash(image); Cancel(image, root, sha, kind, mapping); Complete(image, root, sha, mapping); }
    static void Evidence()
    {
        string root, image = Image("evidence", out root), sha = Hash(image); var result = Run(image, root, sha, CancellationToken.None, null);
        var historical = result.Links.Where(x => x.Status == "historical_journal_directory_reference").ToList();
        Check(historical.Count == 3 && historical.All(x => !x.DirectoryChecksumVerified && x.DirectoryPath == null), "exact historical duplicates merge while distinct sequence/location records stay separate and unverified");
        Check(historical.Any(x => x.Name == "семейный рецепт.jpg" && x.DirectoryInode == 42 && x.JournalBlockOffset == 25 * 1024 && x.TargetBlockOffset == 21 * 1024 && x.JournalTransactionSequence == 9), "Unicode and exact journal/target/sequence evidence survive durable parsing");
        Check(result.Links.Any(x => x.Status != "historical_journal_directory_reference" && x.DirectoryChecksumVerified && x.DirectoryPath != null), "native current names retain verified directory CRC and connected path");
        Check(result.Skipped["prior_volume_control"] == 7 && result.Names == result.Links.Count + 1, "earlier volume counters are retained without duplication");
    }
    static void Bounds()
    {
        string root, image = Image("declared-size", out root), sha = Hash(image);
        var result = Run(image, root, sha, CancellationToken.None, null, false, null, "shrink");
        Check(!result.Reads.Any(x => x.Item1 < forbiddenStart + forbiddenLength && forbiddenStart < x.Item1 + x.Item2),
            "directory extent allocation beyond declared inode size is never parsed as names");
    }
    static void LegacyReadFailure()
    {
        string root, image = Image("legacy-read-failure", out root), sha = Hash(image); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null, false, null, "zero-legacy"); } catch (EndOfStreamException) { failed = true; }
        Check(failed && Hash(image) == sha, "legacy path also rejects short directory reads instead of reporting absent names");
    }
    static void Empty()
    {
        string root, image = Image("empty", out root), sha = Hash(image);
        var result = Run(image, root, sha, CancellationToken.None, null, true, null, "empty");
        Check(result.Reads.Count == 0 && result.Links.Count == 0 && result.Names == 1 && result.Bytes == 1024 &&
            (bool)State(root)["Complete"] && Convert.ToInt32(State(root)["Next"]) == 1, "empty input still confirms an explicit terminal unit and preserves prior-volume counters");
        Compare(result, Run(image, root, sha, CancellationToken.None, m => { throw new Exception("empty completed phase restarted"); }, true, null, "empty"));
    }
    static void Relocated()
    {
        string root, image = Image("relocated", out root), sha = Hash(image); Cancel(image, root, sha);
        var anchor = Anchor(root); string destination = Path.Combine(work, "moved-" + Guid.NewGuid().ToString("N"));
        string prefix = Path.GetFullPath(work) + Path.DirectorySeparatorChar;
        Check(Path.GetFullPath(root).StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            Path.GetFullPath(destination).StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !Directory.Exists(destination),
            "both move targets are unique owned test directories under the verified workspace");
        Directory.Move(root, destination); anchor.Path = Path.Combine(destination, "ext4.state", Path.GetFileName(anchor.Path));
        SaveAnchor(destination, anchor); Complete(Path.Combine(destination, "owned.dd"), destination, sha);
    }
    static void ParentFailure()
    {
        string root, image = Image("parent-denial", out root), sha = Hash(image); FileStream held = null; int next = 0; bool failed = false;
        List<Tuple<long, int>> prefix = null;
        try { Run(image, root, sha, CancellationToken.None, m => {
            if (held == null && m.Contains("(data)")) { next = Convert.ToInt32(State(root)["Next"]); prefix = reads.ToList(); held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read); }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && next > 0 && Convert.ToInt32(State(root)["Next"]) == next, "actual OS parent replacement denial preserves the old confirmed prefix");
        reads = prefix; Complete(image, root, sha);
    }
    static void ReadFailure(bool zero)
    {
        string root, image = Image("read-failure", out root), sha = Hash(image), parent = null; FileStream held = null; bool failed = false;
        List<Tuple<long, int>> prefix = null;
        try { Run(image, root, sha, CancellationToken.None, m => {
            if (parent == null && !m.Contains("(data)")) return;
            if (!zero && held == null) { held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read); held.Lock(0, held.Length); }
            // A later directory-start marker may be confirmed without a source
            // read. The failed read must retain that latest confirmed marker.
            parent = Hash(Parent(root)); prefix = reads.ToList();
        }, true, null, null, false, zero); } catch (IOException) { failed = true; }
        finally { if (held != null) { held.Unlock(0, held.Length); held.Dispose(); } }
        Check(failed && parent != null && Hash(Parent(root)) == parent && !(bool)State(root)["Complete"], "zero read or actual source byte-range denial cannot become successful empty names");
        reads = prefix; Complete(image, root, sha);
    }
    static void Budgets()
    {
        foreach (string kind in new[] { "names", "bytes", "directories" }) {
            string root, image = Image("budget-" + kind, out root), sha = Hash(image);
            var limits = new Ext4Recovery.Limits();
            if (kind == "names") limits.MaximumNames = 2;
            if (kind == "bytes") limits.MaximumDirectoryBytes = 3072;
            if (kind == "directories") limits.MaximumDirectories = 1;
            for (int turn = 0; turn < 40; turn++) {
                using (var cancel = new CancellationTokenSource()) {
                    try { Run(image, root, sha, cancel.Token, m => cancel.Cancel(), true, limits); }
                    catch (OperationCanceledException) { }
                }
                if ((bool)State(root)["Complete"]) break;
            }
            var result = Run(image, root, sha, CancellationToken.None, null, true, limits); Compare(Reference(image, sha, limits), result);
            Check(result.Limited && (bool)State(root)["Complete"], "real " + kind + " limit survives repeated cancellation and remains explicit");
        }
    }
    static void Tamper(string kind)
    {
        string root, image = Image("tamper-" + kind, out root), sha = Hash(image); Cancel(image, root, sha);
        string target = kind == "source" ? image : kind == "blob" ? Directory.GetFiles(Path.Combine(root, "ext4.state", "directory-blobs"), "blob-*.json")[0] : Anchor(root).Path;
        if (kind == "cursor" || kind == "complete") {
            var envelope = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(target, Encoding.UTF8));
            var payload = (Dictionary<string, object>)envelope["Payload"];
            if (kind == "cursor") payload["Next"] = Convert.ToInt32(payload["Next"]) + 1; else payload["Complete"] = true;
            File.WriteAllText(target, Json.Serialize(envelope), new UTF8Encoding(false)); var anchor = Anchor(root); anchor.Sha256 = Hash(target); SaveAnchor(root, anchor);
        } else using (var file = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) {
            file.Position = kind == "source" ? file.Length - 1 : 0; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value ^ 1));
        }
        string parent = Hash(Parent(root)), changed = Hash(target); bool failed = false;
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && Hash(Parent(root)) == parent && Hash(target) == changed, "changed " + kind + " is rejected before phase reads or parent writes and preserved");
    }
    static void Binding(string kind)
    {
        string root, image = Image("binding-" + kind, out root), sha = Hash(image); Cancel(image, root, sha);
        string parent = Hash(Parent(root)); bool failed = false; var limits = new Ext4Recovery.Limits(); if (kind == "limits") limits.MaximumNames--;
        try { Run(image, root, sha, CancellationToken.None, null, true, limits, kind); } catch (IOException) { failed = true; }
        Check(failed && reads.Count == 0 && Hash(Parent(root)) == parent, "changed " + kind + " input cannot reuse old directory facts");
    }
    static void KilledProcess()
    {
        string root, image = Image("worker", out root), sha = Hash(image), ready = Path.Combine(root, "ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned worker reaches an acknowledged directory-data unit"); child.Kill(); Check(child.WaitForExit(10000), "owned worker is stopped without graceful cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        reads = new List<Tuple<long, int>>(); Complete(image, root, sha);
    }
    public static int Main(string[] args)
    {
        try {
            if (args.Length == 3 && args[0].StartsWith("--legacy-", StringComparison.Ordinal)) {
                fixtures = Path.GetFullPath(args[2]); work = Path.Combine(Path.GetFullPath(args[1]), ".build", "ext4-directory-legacy-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
                if (args[0] == "--legacy-bounds") Bounds(); else LegacyReadFailure();
                Console.WriteLine("PASS legacy directory control " + args[0] + ": " + checks); return 0;
            }
            if (typeof(Ext4Recovery).GetMethod("DirectoryNamesCheckpointed", Private) == null) { Console.WriteLine("FAIL: baseline has no durable directory-name phase"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1], args[2], Hash(args[1]), CancellationToken.None, m => { if (m.Contains("(data)")) { File.WriteAllText(args[3], "acknowledged"); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-directory-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            Bounds(); LegacyReadFailure(); Evidence(); Empty(); Relocated(); CancelResume(); CancelResume("unicode-retained-link", "history");
            CancelResume("extent-tree-fragmented", "map", true); CancelResume("legacy-indirect-deleted", "map", true);
            ParentFailure(); ReadFailure(false); ReadFailure(true); Budgets();
            foreach (string kind in new[] { "source", "blob", "cursor", "complete" }) Tamper(kind);
            foreach (string kind in new[] { "directory", "history", "baseline", "limits" }) Binding(kind);
            KilledProcess();
            Console.WriteLine("PASS Ext4DirectoryCheckpoint: " + checks + " checks; native current directories, derived mapping and synthetic history controls; not full-engine resume or devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
