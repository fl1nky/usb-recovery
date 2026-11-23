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

// Exercises the reusable initialization phase with a durable caller-owned
// anchor. The full ext4 RecoveryPipeline is deliberately not claimed here.
public static class Ext4GroupCheckpointTests
{
    static int checks;
    static string work, fixture;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
    static void Check(bool value, string label) { checks++; if (!value) throw new Exception(label); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static void Set(object obj, string name, object value) { obj.GetType().GetField(name).SetValue(obj, value); }
    static object Get(object obj, string name) { return obj.GetType().GetField(name).GetValue(obj); }
    sealed class Source : FileStream
    {
        public readonly List<Tuple<long, int>> Reads = new List<Tuple<long, int>>();
        public Source(string path) : base(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1) { }
        public override int Read(byte[] bytes, int start, int count) { Reads.Add(Tuple.Create(Position, count)); return base.Read(bytes, start, count); }
    }
    static string Image(string label, out string root)
    {
        root = Path.Combine(work, label + "-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root, "owned.dd"); File.Copy(fixture, image);
        // The fixture bundle is read-only. Only this newly created owned copy
        // may be changed by the explicit source-tamper negative control.
        File.SetAttributes(image, File.GetAttributes(image) & ~FileAttributes.ReadOnly);
        return image;
    }
    static string Parent(string root) { return Path.Combine(root, "anchor.json"); }
    static long[] FirstBitmaps(string image)
    {
        using (var input = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var sb = new byte[1024]; input.Position = 1024; if (input.Read(sb, 0, sb.Length) != sb.Length) throw new EndOfStreamException();
            int block = 1024 << (int)BitConverter.ToUInt32(sb, 0x18);
            bool wide = (BitConverter.ToUInt32(sb, 0x60) & 0x80) != 0;
            var descriptor = new byte[wide ? BitConverter.ToUInt16(sb, 0xfe) : 32];
            input.Position = ((long)BitConverter.ToUInt32(sb, 0x14) + 1) * block;
            if (input.Read(descriptor, 0, descriptor.Length) != descriptor.Length) throw new EndOfStreamException();
            return new[] { 0, 4 }.Select(at => (long)(BitConverter.ToUInt32(descriptor, at) |
                (wide ? (ulong)BitConverter.ToUInt32(descriptor, at + 0x20) << 32 : 0)) * block).ToArray();
        }
    }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root), Encoding.UTF8)) : null; }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint value)
    {
        string temporary = Parent(root) + "." + Guid.NewGuid().ToString("N") + ".partial";
        try
        {
            byte[] bytes = new UTF8Encoding(false).GetBytes(Json.Serialize(value));
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { output.Write(bytes, 0, bytes.Length); output.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temporary, Parent(root), null); else File.Move(temporary, Parent(root));
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    static Dictionary<string, object> State(string root)
    {
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256, "caller pins exact initialization state bytes");
        return (Dictionary<string, object>)Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(anchor.Path, Encoding.UTF8))["Payload"];
    }
    static void Run(string image, string root, string expectedSha, CancellationToken token,
        Action<string> progress, out List<Tuple<long, int>> reads)
    {
        var assembly = typeof(Ext4Recovery).Assembly;
        using (var input = new Source(image))
        {
            reads = input.Reads;
            var context = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context", BindingFlags.NonPublic), true);
            Set(context, "Input", input); Set(context, "Cancel", token); Set(context, "Limits", new Ext4Recovery.Limits());
            Set(context, "Root", Path.Combine(root, "ext4")); Set(context, "Report", new Ext4Recovery.Report());
            object volume = typeof(Ext4Recovery).GetMethod("OpenVolumeHeader", BindingFlags.NonPublic | BindingFlags.Static)
                .Invoke(null, new object[] { context, 0L });
            var report = (Ext4Recovery.VolumeReport)Get(volume, "Report"); Check(report.Status == "header_ready", "native source header validates");
            object checkpoint = Activator.CreateInstance(assembly.GetType("UsbRecovery.RecoveryCheckpointContext", true), true);
            Set(checkpoint, "Directory", root); Set(checkpoint, "Method", "ext4"); Set(checkpoint, "SourceSha256", expectedSha);
            Set(checkpoint, "Settings", "owned-group-initialization-v1"); Set(checkpoint, "Resume", Anchor(root));
            Set(checkpoint, "Commit", (Action<RecoveryMethodCheckpoint>)(value => SaveAnchor(root, value)));
            var reserved = (IList)Activator.CreateInstance(Get(volume, "Reserved").GetType());
            foreach (object item in (IEnumerable)Get(volume, "Reserved")) reserved.Add(item);
            try
            {
                typeof(Ext4Recovery).GetMethod("ReadGroupsCheckpointed", BindingFlags.NonPublic | BindingFlags.Static)
                    .Invoke(null, new object[] { context, volume, (ulong)report.Groups, (ulong)(uint)Get(volume, "FirstData") + 1,
                        reserved, checkpoint, progress });
            }
            catch (TargetInvocationException error) { throw error.InnerException; }
        }
    }
    static void Cancel(string image, string root, string sha)
    {
        List<Tuple<long, int>> reads; bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { Run(image, root, sha, cancel.Token, m => { if (m.StartsWith("ext4: groups 2/", StringComparison.Ordinal)) cancel.Cancel(); }, out reads); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Convert.ToUInt32(State(root)["NextGroup"]) == 2, "cancel preserves the actual committed group prefix");
    }
    static void ResumeAndCheck(string image, string root, string sha, int prefix)
    {
        List<Tuple<long, int>> reads; string first = null;
        Run(image, root, sha, CancellationToken.None, m => { if (first == null) first = m; }, out reads);
        Check(first != null && first.StartsWith("ext4: groups " + (prefix + 1) + "/", StringComparison.Ordinal), "resume starts at the saved group cursor");
        var state = State(root); Check((bool)state["Complete"] && Convert.ToUInt64(state["NextGroup"]) == Convert.ToUInt64(state["Groups"]), "all expected groups are committed exactly once");
        // Source SHA is revalidated through a separate stream. This checks that
        // the phase itself does not rescan acknowledged bitmap bodies.
        long[] bitmaps = FirstBitmaps(image);
        Check(!reads.Any(x => bitmaps.Any(at => x.Item1 <= at && at < x.Item1 + x.Item2)), "acknowledged first-group bitmaps are not read again by the phase");
        Run(image, root, sha, CancellationToken.None, m => { throw new Exception("completed phase restarted source traversal"); }, out reads);
        Check(reads.Count == 1 && reads[0].Item1 == 1024 && reads[0].Item2 == 1024, "completed phase reuses metadata with only a header read through the phase stream");
        Check(Hash(image) == sha, "initialization resume preserves source bytes");
    }
    static void CancelResume()
    {
        string root, image = Image("cancel", out root), sha = Hash(image);
        Cancel(image, root, sha); ResumeAndCheck(image, root, sha, 2);
    }
    static void ParentFailure()
    {
        string root, image = Image("parent-denial", out root), sha = Hash(image); FileStream held = null; bool failed = false;
        List<Tuple<long, int>> reads;
        try { Run(image, root, sha, CancellationToken.None, m => { if (held == null) held = new FileStream(Parent(root), FileMode.Open, FileAccess.Read, FileShare.Read); }, out reads); }
        catch (IOException) { failed = true; }
        finally { if (held != null) held.Dispose(); }
        Check(failed && held != null && Convert.ToUInt32(State(root)["NextGroup"]) == 1, "OS parent replace denial cannot advance the durable cursor");
        ResumeAndCheck(image, root, sha, 1);
        Check(Directory.GetFiles(Path.Combine(root, "ext4.state", "group-blobs"), "blob-*.json").Length == Convert.ToInt32(State(root)["Groups"]), "retry reuses content-addressed unacknowledged metadata blobs");
    }
    static void Tamper(bool source)
    {
        string root, image = Image(source ? "source-change" : "blob-change", out root), sha = Hash(image);
        Cancel(image, root, sha); string target = source ? image : Directory.GetFiles(Path.Combine(root, "ext4.state", "group-blobs"), "blob-*.json")[0];
        using (var file = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        { file.Position = source ? file.Length - 1 : 0; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value ^ 1)); }
        string changed = Hash(target), parent = Hash(Parent(root)); bool rejected = false; List<Tuple<long, int>> reads;
        try { Run(image, root, sha, CancellationToken.None, null, out reads); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(target) == changed && Hash(Parent(root)) == parent, "changed source/blob is rejected and preserved with the old caller anchor");
    }
    static void KilledProcess()
    {
        string root, image = Image("worker", out root), sha = Hash(image), ready = Path.Combine(root, "ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--worker \"" + image + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned group worker reaches the persisted boundary"); child.Kill(); Check(child.WaitForExit(10000), "owned group worker is killed without graceful cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Check(Convert.ToUInt32(State(root)["NextGroup"]) == 2, "killed worker retains exactly two committed groups");
        ResumeAndCheck(image, root, sha, 2);
    }
    public static int Main(string[] args)
    {
        try
        {
            if (typeof(Ext4Recovery).GetMethod("ReadGroupsCheckpointed", BindingFlags.NonPublic | BindingFlags.Static) == null)
            { Console.WriteLine("FAIL: no durable ext4 group phase in baseline"); return 1; }
            if (args.Length == 4 && args[0] == "--worker")
            {
                List<Tuple<long, int>> reads; Run(args[1], args[2], Hash(args[1]), CancellationToken.None,
                    m => { if (m.StartsWith("ext4: groups 2/", StringComparison.Ordinal)) { File.WriteAllText(args[3], "acknowledged"); Thread.Sleep(Timeout.Infinite); } }, out reads); return 3;
            }
            fixture = Path.Combine(Path.GetFullPath(args[1]), "extent-deleted.dd");
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ext4-group-checkpoints-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            CancelResume(); ParentFailure(); Tamper(true); Tamper(false); KilledProcess();
            Console.WriteLine("PASS Ext4GroupCheckpoint: " + checks + " checks; persisted initialization phase only, full ext4 engine resume/device behavior not claimed"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
