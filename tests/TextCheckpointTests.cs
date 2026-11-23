using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Actual pipeline, owned regular images and our own console child only.
public static class TextCheckpointTests
{
    static int checks;
    static string work;
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static RecoveryOptions Options()
    {
        return new RecoveryOptions { FatMetadata = false, NtfsMetadata = false, LostPartitions = false,
            Signatures = false, EmbeddedPhotos = false, Containers = false, TextFragments = true, TextQuery = "needle" };
    }
    static string Image(string name)
    {
        string path = Path.Combine(work, name + ".dd");
        byte[] bytes = new byte[24 * 1024 * 1024];
        foreach (int offset in new[] { 2 * 1024 * 1024 + 32, 18 * 1024 * 1024 + 32 })
        {
            byte[] text = Encoding.UTF8.GetBytes("needle owned exact fragment at " + offset + " recipe\n");
            Array.Copy(text, 0, bytes, offset, text.Length);
        }
        File.WriteAllBytes(path, bytes);
        File.WriteAllText(path + ".sha256", Hash(path));
        return path;
    }
    static long Position(string root)
    {
        var stage = RecoverySession.Read(root).Stages.Single(x => x.Key == "text");
        Check(stage.CheckpointPath != null && stage.CheckpointSequence > 0, "text has a durable parent-anchored within-method checkpoint");
        string path = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
        Check(Hash(path) == stage.CheckpointSha256, "checkpoint bytes match their saved parent reference");
        var state = new JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string, object>>(File.ReadAllText(path));
        return Convert.ToInt64(state["Position"]);
    }
    static void VerifyResume(string root, string source, long position)
    {
        long first = -1;
        bool observedCheckpointResume = false;
        var result = RecoveryPipeline.Resume(root, CancellationToken.None, message => { }, update =>
        {
            if (update.Key == "text" && update.State == "running" && update.Completed > 0 && first < 0)
                first = update.Completed;
            if (update.Key == "text" && update.ResumingCheckpoint && update.CheckpointSequence > 0)
                observedCheckpointResume = true;
        });
        Check(first >= position && position > 1024 * 1024, "text resumes its saved cursor rather than scanning again from the first chunk");
        Check(observedCheckpointResume, "UI receives confirmed checkpoint resume rather than an invented progress status");
        Check(result.UniqueFiles == 2, "both source fragments are recovered exactly once");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "verified continuation retains the active attempt");
        Check(RecoverySession.Read(root).Stages.Single().Status == "complete", "resumed method reaches durable completion");
        string[] files = RecoveryCore.RecoveredFiles(root).ToArray();
        Check(files.Length == 2 && files.All(p => File.ReadAllText(p).Contains("needle owned exact fragment")), "only original text candidates reach the catalog");
        string report = Hash(Path.Combine(root, "text-search.json"));
        Check(RecoveryPipeline.Resume(root, CancellationToken.None, message => { }).ResumedStages == 1 &&
              Hash(Path.Combine(root, "text-search.json")) == report, "completed text pass is reused unchanged");
    }
    static void CancelResume(bool removePendingOutput)
    {
        string source = Image(removePendingOutput ? "repair" : "cancel"), before = Hash(source);
        if (removePendingOutput) File.WriteAllText(source + ".sha256", before.ToUpperInvariant());
        string root = Path.Combine(work, removePendingOutput ? "repair-job" : "cancel-job");
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try
            {
                RecoveryPipeline.Run(source, root, Options(), cancel.Token, message => { }, source + ".sha256", update =>
                {
                    if (update.Key == "text" && update.State == "running" && update.Completed >= 10 * 1024 * 1024)
                        cancel.Cancel();
                });
            }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && !File.Exists(Path.Combine(root, "files-index.json")), "cancelled pass publishes no successful final catalog");
        long position = Position(root);
        string[] saved = RecoveryCore.RecoveredFiles(root).ToArray();
        Check(saved.Length == 1, "earlier committed fragment survives cancellation");
        string savedHash = Hash(saved[0]);
        string unknownState = Path.Combine(root, "text.state", "checkpoint-+00000000100.json");
        File.WriteAllText(unknownState, "owned non-checkpoint control");
        string unknownHash = Hash(unknownState);
        if (removePendingOutput) File.Delete(saved[0]);
        VerifyResume(root, source, position);
        Check(Hash(unknownState) == unknownHash, "generation cleanup preserves noncanonical filenames");
        Check(File.Exists(saved[0]) && Hash(saved[0]) == savedHash, "missing write-ahead output can be rebuilt from source-bound byte evidence");
        Check(Hash(source) == before, "cancellation and resume never modify source bytes");
    }
    static void TamperedOutput()
    {
        string source = Image("tamper"), root = Path.Combine(work, "tamper-job");
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(source, root, Options(), cancel.Token, message => { }, source + ".sha256", update =>
                { if (update.Key == "text" && update.Completed >= 10 * 1024 * 1024) cancel.Cancel(); }); }
            catch (OperationCanceledException) { }
        }
        Position(root);
        string file = RecoveryCore.RecoveredFiles(root).Single();
        File.WriteAllText(file, "changed owned fixture");
        string tampered = Hash(file);
        bool rejected = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, message => { }); }
        catch (IOException) { rejected = true; }
        Check(rejected && Hash(file) == tampered, "changed checkpoint output is rejected without overwriting it");
    }
    static void KilledProcess()
    {
        string source = Image("killed"), root = Path.Combine(work, "killed-job"), ready = Path.Combine(work, "child.ready");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
            "child \"" + source + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var watch = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(25)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned child reached the uncommitted scan tail");
                child.Kill();
                Check(child.WaitForExit(10000), "owned recovery process terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        long position = Position(root);
        VerifyResume(root, source, position);
    }
    static void ChangedSource()
    {
        string source = Image("changed-source"), root = Path.Combine(work, "changed-source-job");
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(source, root, Options(), cancel.Token, message => { }, source + ".sha256", update =>
                { if (update.Key == "text" && update.Completed >= 10 * 1024 * 1024) cancel.Cancel(); }); }
            catch (OperationCanceledException) { }
        }
        Position(root);
        string stateHash = Hash(Path.Combine(root, RecoverySession.FileName));
        string[] files = RecoveryCore.RecoveredFiles(root).ToArray();
        string[] hashes = files.Select(Hash).ToArray();
        DateTime oldTime = File.GetLastWriteTimeUtc(source);
        using (var stream = new FileStream(source, FileMode.Open, FileAccess.Write))
        { stream.Position = 20 * 1024 * 1024; stream.WriteByte(0x42); }
        File.SetLastWriteTimeUtc(source, oldTime);
        bool rejected = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, message => { }); }
        catch (IOException) { rejected = true; }
        Check(rejected, "Same-size source changed beyond saved cursor is rejected even with original timestamp");
        Check(Hash(Path.Combine(root, RecoverySession.FileName)) == stateHash, "Source rejection leaves durable session unchanged");
        Check(files.Select(Hash).SequenceEqual(hashes), "Source rejection leaves saved output unchanged");
    }
    public static int Main(string[] args)
    {
        if (args.Length == 4 && args[0] == "child")
        {
            RecoveryPipeline.Run(args[1], args[2], Options(), CancellationToken.None, message => { }, args[1] + ".sha256", update =>
            {
                if (update.Key == "text" && update.Completed >= 10 * 1024 * 1024)
                { File.WriteAllText(args[3], "ready"); Thread.Sleep(Timeout.Infinite); }
            });
            return 3;
        }
        try
        {
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "text-checkpoints-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            if (args.Length > 1 && args[1] == "uppercase") CancelResume(true);
            else { CancelResume(false); CancelResume(true); TamperedOutput(); KilledProcess(); ChangedSource(); }
            Console.WriteLine("PASS TextCheckpoint: " + checks + " checks; actual cancellation/kill/cursor resume, source-bound repair, tamper rejection; no GUI or physical device");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
