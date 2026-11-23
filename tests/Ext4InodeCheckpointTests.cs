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

public static class Ext4InodeCheckpointTests
{
    static int checks;
    static string work, fixture;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static object Get(object obj, string name) { return obj.GetType().GetField(name).GetValue(obj); }
    static void Set(object obj, string name, object value) { obj.GetType().GetField(name).SetValue(obj, value); }
    sealed class Source : FileStream
    {
        public readonly List<Tuple<long, int>> Reads = new List<Tuple<long, int>>();
        public Source(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1) { }
        public override int Read(byte[] bytes, int start, int count) { Reads.Add(Tuple.Create(Position, count)); return base.Read(bytes, start, count); }
    }
    sealed class Result
    {
        public int Attempts, Checked, Live;
        public bool Limited;
        public string[] Deleted, Directories;
        public List<Tuple<long, int>> Reads;
        public Dictionary<string, int> Skipped;
    }
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
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "caller pins exact inode cursor bytes");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8))["Payload"];
    }
    static string Image(string name, out string root)
    {
        root = Path.Combine(work, name + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); File.Copy(fixture, image);
        File.SetAttributes(image, File.GetAttributes(image) & ~FileAttributes.ReadOnly); return image;
    }
    static string[] Facts(object value)
    {
        return ((IEnumerable)value).Cast<object>().Select(item =>
        {
            if (item.GetType().IsGenericType) item = item.GetType().GetProperty("Value").GetValue(item, null);
            byte[] bytes = (byte[])Get(item, "Bytes");
            using (var sha = System.Security.Cryptography.SHA256.Create())
                return Get(item, "Number") + ":" + Get(item, "Generation") + ":" + BitConverter.ToString(sha.ComputeHash(bytes));
        }).OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }
    static Result Run(string image, string root, string sha, CancellationToken token, Action<string> progress, int limit = 1000000, int unit = 16)
    {
        using (var input = new Source(image))
        {
            var context = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            var report = new Ext4Recovery.Report(); Set(context, "Input", input); Set(context, "Root", Path.Combine(root, "ext4"));
            Set(context, "Cancel", token); Set(context, "Report", report); Set(context, "Limits", new Ext4Recovery.Limits { MaximumInodes = limit, InodesPerCheckpoint = unit });
            object volume = typeof(Ext4Recovery).GetMethod("OpenVolume", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, new[] { context, (object)0L });
            var vr = (Ext4Recovery.VolumeReport)Get(volume, "Report"); Check(vr.Status == "ready", "native metadata initialization is valid");
            input.Reads.Clear();
            var checkpoint = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
            Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", sha);
            Set(checkpoint, "Settings", "owned-inode-phase-v1"); Set(checkpoint, "Resume", Anchor(root));
            Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(value => SaveAnchor(root, value)));
            object[] args = { context, volume, checkpoint, progress, null, null };
            try { typeof(Ext4Recovery).GetMethod("ScanInodesCheckpointed", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, args); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return new Result { Attempts = (int)Get(context, "InodesRead"), Checked = vr.CheckedInodes, Live = vr.LiveInodes,
                Limited = report.Limited, Deleted = Facts(args[4]), Directories = Facts(args[5]), Reads = input.Reads, Skipped = report.Skipped };
        }
    }
    static void Cancel(string image, string root, string sha, int limit = 1000000)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        { try { Run(image, root, sha, cancel.Token, m => cancel.Cancel(), limit); } catch (OperationCanceledException) { stopped = true; } }
        Check(stopped && Convert.ToInt32(State(root)["NextInode"]) > 0, "cancel preserves a real position inside the inode table");
    }
    static void Compare(Result left, Result right)
    {
        Check(left.Attempts == right.Attempts && left.Checked == right.Checked && left.Live == right.Live && left.Limited == right.Limited, "restored inode counters match an uninterrupted scan");
        Check(left.Deleted.SequenceEqual(right.Deleted) && left.Directories.SequenceEqual(right.Directories), "restored candidate and live-directory bytes match the uninterrupted scan");
        Check(Json.Serialize(left.Skipped.OrderBy(x => x.Key).ToArray()) == Json.Serialize(right.Skipped.OrderBy(x => x.Key).ToArray()), "restored skipped counters are neither lost nor doubled");
    }
    static Result Reference(string image, string sha, int limit = 1000000)
    { string root = Path.Combine(work, "reference-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image, root, sha, CancellationToken.None, null, limit, 256); }
    static Tuple<long, long> FirstTableRange(string image, int slots)
    {
        using (var input = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            byte[] sb = new byte[1024]; input.Position = 1024; if (input.Read(sb, 0, sb.Length) != sb.Length) throw new EndOfStreamException();
            int block = 1024 << (int)BitConverter.ToUInt32(sb, 0x18); bool wide = (BitConverter.ToUInt32(sb, 0x60) & 0x80) != 0;
            byte[] descriptor = new byte[wide ? BitConverter.ToUInt16(sb, 0xfe) : 32];
            input.Position = ((long)BitConverter.ToUInt32(sb, 0x14) + 1) * block;
            if (input.Read(descriptor, 0, descriptor.Length) != descriptor.Length) throw new EndOfStreamException();
            ulong table = BitConverter.ToUInt32(descriptor, 8) | (wide ? (ulong)BitConverter.ToUInt32(descriptor, 0x28) << 32 : 0);
            int inode = BitConverter.ToUInt32(sb, 0x4c) == 0 ? 128 : BitConverter.ToUInt16(sb, 0x58);
            return Tuple.Create((long)table * block, (long)slots * inode);
        }
    }
    static void Resumed(string image, string root, string sha)
    {
        var before = State(root); Check(Convert.ToInt32(before["GroupIndex"]) == 0, "native control stopped inside the first inode table");
        var range = FirstTableRange(image, Convert.ToInt32(before["NextInode"]));
        var result = Run(image, root, sha, CancellationToken.None, null); Compare(Reference(image, sha), result);
        Check(!result.Reads.Any(x => x.Item1 < range.Item1 + range.Item2 && range.Item1 < x.Item1 + x.Item2),
            "resume does not reread the acknowledged inode-table prefix through its phase stream");
        Check(result.Deleted.Length > 0 && result.Directories.Length > 0, "native retained deleted inode and live directories remain available");
        var repeat = Run(image, root, sha, CancellationToken.None, m => { throw new Exception("completed inode phase restarted"); });
        Compare(result, repeat); Check(repeat.Reads.Count == 0, "completed phase does not read inode tables through its scan stream");
        Check((bool)State(root)["Complete"] && Hash(image) == sha, "complete inode checkpoint preserves the source");
    }
    static void CancelResume()
    { string root, image = Image("cancel", out root), sha = Hash(image); Cancel(image, root, sha); Resumed(image, root, sha); }
    static void ParentFailure()
    {
        string root, image = Image("parent-denial", out root), sha = Hash(image); FileStream held = null; bool failed = false; int prefix = 0;
        try { Run(image, root, sha, CancellationToken.None, m => { if (held == null) { prefix = Convert.ToInt32(State(root)["NextInode"]); held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read); } }); }
        catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && held != null && prefix > 0 && Convert.ToInt32(State(root)["NextInode"]) == prefix, "OS parent replace denial preserves the prior inode prefix");
        Resumed(image, root, sha);
    }
    static void Budget()
    {
        string root, image = Image("budget", out root), sha = Hash(image); Result result = null;
        for (int turn = 0; turn < 5; turn++)
        {
            using (var cancel = new CancellationTokenSource())
            { try { result = Run(image, root, sha, cancel.Token, m => cancel.Cancel(), 30); } catch (OperationCanceledException) { } }
            if ((bool)State(root)["Complete"]) break;
        }
        result = Run(image, root, sha, CancellationToken.None, null, 30);
        Check(result.Attempts == 30 && result.Limited && result.Skipped["inode_limit"] == 1, "actual inode budget survives repeated cancellation without resetting or duplicating the limit");
        Compare(Reference(image, sha, 30), result);
    }
    static void Tamper(bool source)
    {
        string root, image = Image(source ? "source-change" : "blob-change", out root), sha = Hash(image); Cancel(image, root, sha);
        string target = source ? image : Directory.GetFiles(Path.Combine(root, "ext4.state", "inode-blobs"), "blob-*.json")[0];
        using (var file = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        { file.Position = source ? file.Length - 1 : 0; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value ^ 1)); }
        string changed = Hash(target), parent = Hash(Parent(root)); bool rejected = false;
        try { Run(image, root, sha, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(target) == changed && Hash(Parent(root)) == parent, "changed source or inode blob is rejected and preserved");
    }
    static void KilledProcess()
    {
        string root, image = Image("worker", out root), sha = Hash(image), ready = Path.Combine(root, "ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned worker reaches a persisted inode boundary"); child.Kill(); Check(child.WaitForExit(10000), "owned inode worker is killed without graceful cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Resumed(image, root, sha);
    }
    public static int Main(string[] args)
    {
        try
        {
            if (typeof(Ext4Recovery).GetMethod("ScanInodesCheckpointed", BindingFlags.NonPublic | BindingFlags.Static) == null)
            { Console.WriteLine("FAIL: no durable inode scan phase in baseline"); return 1; }
            if (args.Length == 4 && args[0] == "--worker")
            { Run(args[1], args[2], Hash(args[1]), CancellationToken.None, m => { File.WriteAllText(args[3], "acknowledged"); Thread.Sleep(Timeout.Infinite); }); return 3; }
            fixture = Path.Combine(Path.GetFullPath(args[1]), "extent-deleted.dd"); work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-inode-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            CancelResume(); ParentFailure(); Budget(); Tamper(true); Tamper(false); KilledProcess();
            Console.WriteLine("PASS Ext4InodeCheckpoint: " + checks + " checks; inode phase only, full ext4 engine resume and devices not claimed"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
