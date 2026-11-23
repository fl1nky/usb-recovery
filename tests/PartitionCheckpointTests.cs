using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Public pipeline, owned ordinary files, and our own console child only.
public static class PartitionCheckpointTests
{
    static int checks;
    static string work;
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static RecoveryOptions Options()
    {
        return new RecoveryOptions { FatMetadata = false, NtfsMetadata = false,
            LostPartitions = true, Signatures = false, EmbeddedPhotos = true, Containers = false };
    }
    static string Image(string name)
    {
        string path = Path.Combine(work, name + ".dd");
        byte[] bytes = new byte[40 * 1024 * 1024];
        foreach (int offset in new[] { 1024 * 1024, 29 * 1024 * 1024 })
        {
            bytes[offset] = 0xeb; bytes[offset + 1] = 0x3c; bytes[offset + 2] = 0x90;
            Array.Copy(System.Text.Encoding.ASCII.GetBytes("MSDOS5.0"), 0, bytes, offset + 3, 8);
            bytes[offset + 12] = 2; bytes[offset + 13] = 1; bytes[offset + 14] = 1;
            bytes[offset + 16] = 2; bytes[offset + 18] = 2; bytes[offset + 20] = 8;
            bytes[offset + 22] = 6;
            Array.Copy(BitConverter.GetBytes(offset / 512), 0, bytes, offset + 28, 4);
            bytes[offset + 510] = 0x55; bytes[offset + 511] = 0xaa;
        }
        File.WriteAllBytes(path, bytes);
        File.WriteAllText(path + ".sha256", Hash(path).ToUpperInvariant());
        return path;
    }
    static int Percent(string message)
    {
        const string prefix = "Поиск разделов: ";
        return message.StartsWith(prefix, StringComparison.Ordinal) ?
            Int32.Parse(message.Substring(prefix.Length).TrimEnd('%')) : -1;
    }
    static long Cursor(string root)
    {
        var stage = RecoverySession.Read(root).Stages.Single(x => x.Key == "partitions");
        Check(stage.CheckpointPath != null && stage.CheckpointSequence > 0,
            "partition scan has a parent-anchored internal checkpoint");
        string file = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
        Check(Hash(file) == stage.CheckpointSha256, "parent pins the exact generation");
        var envelope = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(file));
        var payload = (Dictionary<string, object>)envelope["Payload"];
        return Convert.ToInt64(payload["Position"]);
    }
    static long Cancel(string source, string root)
    {
        bool cancelled = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(source, root, Options(), cancel.Token, message =>
                { if (Percent(message) >= 20) cancel.Cancel(); }, source + ".sha256"); }
            catch (OperationCanceledException) { cancelled = true; }
        }
        Check(cancelled && !File.Exists(Path.Combine(root, "files-index.json")),
            "cancelled scan creates no successful catalog");
        long cursor = Cursor(root);
        Check(cursor == 8 * 1024 * 1024, "cursor commits the two consumed blocks");
        return cursor;
    }
    static void Resume(string source, string root, long position)
    {
        string sourceHash = Hash(source);
        var expected = BootScout.Find(source, CancellationToken.None, (a, b) => { });
        int first = -1;
        RecoveryPipeline.Resume(root, CancellationToken.None, message =>
            { int percent = Percent(message); if (percent >= 0 && first < 0) first = percent; });
        Check(first == position * 100 / new FileInfo(source).Length,
            "first resumed scan update is the committed position, not the first block");
        var report = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(
            File.ReadAllText(Path.Combine(root, "partition-search.json")));
        var candidates = new JavaScriptSerializer().ConvertToType<List<BootCandidate>>(report["candidates"]);
        Check(candidates.Count == 2 && candidates.Select(x => x.Offset).SequenceEqual(expected.Select(x => x.Offset)),
            "candidate before and after the checkpoint both match a fresh uninterrupted pass");
        Check(RecoverySession.Read(root).Stages.Single(x => x.Key == "partitions").Status == "complete",
            "resumed partition stage reaches durable completion");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "cursor resume retains the original attempt");
        string reportHash = Hash(Path.Combine(root, "partition-search.json"));
        Check(RecoveryPipeline.Resume(root, CancellationToken.None, message => { }).ResumedStages == 2 &&
            Hash(Path.Combine(root, "partition-search.json")) == reportHash, "completed methods are reused unchanged");
        Check(Hash(source) == sourceHash, "source remains unchanged");
    }
    static void Cancellation()
    {
        string source = Image("cancel"), root = Path.Combine(work, "cancel-job");
        long position = Cancel(source, root);
        string unknown = Path.Combine(root, "partitions.state", "checkpoint-+00000000001.json");
        File.WriteAllText(unknown, "owned noncanonical control");
        string before = Hash(unknown);
        Resume(source, root, position);
        Check(Hash(unknown) == before, "cleanup preserves noncanonical files");
    }
    static void FailedParentSave()
    {
        string source = Image("failed-save"), root = Path.Combine(work, "failed-save-job");
        string parent = Path.Combine(root, RecoverySession.FileName);
        bool failed = false;
        try
        {
            RecoveryPipeline.Run(source, root, Options(), CancellationToken.None, message =>
                { if (Percent(message) >= 20) File.SetAttributes(parent, FileAttributes.ReadOnly); }, source + ".sha256");
        }
        catch (UnauthorizedAccessException) { failed = true; }
        catch (IOException) { failed = true; }
        finally { if (File.Exists(parent)) File.SetAttributes(parent, FileAttributes.Normal); }
        Check(failed, "real denied parent write interrupts the pass");
        long position = Cursor(root);
        Check(position == 8 * 1024 * 1024, "unacknowledged generation does not advance parent cursor");
        Resume(source, root, position);
    }
    static void Tamper(bool sourceChanged)
    {
        string source = Image(sourceChanged ? "source-tamper" : "checkpoint-tamper");
        string root = Path.Combine(work, sourceChanged ? "source-tamper-job" : "checkpoint-tamper-job");
        Cancel(source, root);
        string changed = sourceChanged ? source : RecoveryCatalog.SafeFile(root,
            RecoverySession.Read(root).Stages.Single(x => x.Key == "partitions").CheckpointPath);
        using (var stream = new FileStream(changed, FileMode.Open, FileAccess.ReadWrite))
        { stream.Position = 0; int value = stream.ReadByte(); stream.Position = 0; stream.WriteByte((byte)(value ^ 1)); }
        string before = Hash(changed); bool rejected = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, message => { }); }
        catch (IOException) { rejected = true; }
        Check(rejected && Hash(changed) == before && !File.Exists(Path.Combine(root, "partition-search.json")),
            "changed source/checkpoint is rejected without overwriting evidence");
    }
    static void KilledProcess()
    {
        string source = Image("killed"), root = Path.Combine(work, "killed-job"), ready = Path.Combine(work, "ready");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
            "child \"" + source + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var watch = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(25)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned console child reached a durable scan boundary");
                child.Kill(); Check(child.WaitForExit(10000), "owned recovery child terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Resume(source, root, Cursor(root));
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
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "partition-checkpoints-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            Cancellation();
            if (args.Length == 1) { FailedParentSave(); Tamper(false); Tamper(true); KilledProcess(); }
            Console.WriteLine("PASS PartitionCheckpoint: " + checks + " checks; cancel, owned process kill, denied writes, source/checkpoint tamper and true cursor resume; no GUI/devices");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
