// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using UsbRecovery;

// Real public Pipeline/Session APIs on owned images; no screen or USB access.
public static class ApfsSessionCheckpointTests
{
    static int checks;
    static string work,fixture;
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b) => { }); }
    static RecoveryOptions Options()
    { return new RecoveryOptions { ApfsMetadata = true, Ext4Metadata = false, FatMetadata = false, NtfsMetadata = false, LostPartitions = false, Signatures = false, EmbeddedPhotos = false, Containers = false }; }
    static string Folder(string label)
    {
        string root = Path.Combine(work,label+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root,"usb.dd"); File.Copy(fixture,image); File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly);
        File.WriteAllText(Path.Combine(root,"input.sha256"),Hash(image).ToUpperInvariant(),Encoding.ASCII); return root;
    }
    static void Start(string root,CancellationToken token,Action<string> progress)
    { RecoveryPipeline.Run(Path.Combine(root,"usb.dd"),root,Options(),token,progress,Path.Combine(root,"input.sha256")); }
    static bool Inner(string message)
    {
        return message.StartsWith("apfs: metadata unit ",StringComparison.Ordinal) || message.StartsWith("apfs: mapped bytes ",StringComparison.Ordinal);
    }
    static void Verify(string root,string sourceSha)
    {
        var model = RecoverySession.Read(root); var stage = model.Stages.Single();
        Check(stage.Key == "apfs" && stage.Status == "complete" && stage.Candidates == 2 && stage.CheckpointSequence > 0,
            "real session persists apfs completion and its actual engine root checkpoint");
        Check(stage.Artifacts.Any(x => x.Path.StartsWith("apfs.state/",StringComparison.Ordinal)) &&
            stage.Artifacts.Any(x => x.Path == "apfs/report.json"),"session verifies engine metadata and the final report as stage artifacts");
        var items = RecoveryCatalog.Load(root).Items;
        Check(items.Count == 2 && items.All(x => x.Method == "APFS" && x.SourceRanges.Count == 0),
            "managed APFS candidates reach the catalog without an invented physical provenance proof");
        Check(RecoveryCore.RecoveredFiles(root).Count() == 2 && Hash(Path.Combine(root,"usb.dd")) == sourceSha,
            "state pages never become recovered payloads and the source remains unchanged");
        string report = Hash(Path.Combine(root,"apfs","report.json")); var again = RecoveryPipeline.Resume(root,CancellationToken.None,s => { });
        Check(again.ResumedStages == 1 && Hash(Path.Combine(root,"apfs","report.json")) == report,"completed session reuses apfs only after verification");
    }
    static void CancelResume(string phase)
    {
        string root = Folder("cancel"),sha = Hash(Path.Combine(root,"usb.dd")); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Start(root,cancel.Token,m => { if (m.StartsWith(phase,StringComparison.Ordinal)) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        var stage = RecoverySession.Read(root).Stages.Single();
        Check(stopped && stage.Status == "cancelled" && stage.CheckpointSequence > 0 && stage.CheckpointPath.StartsWith("apfs.state/",StringComparison.Ordinal),
            "public pipeline cancellation records a durable inner apfs checkpoint at "+phase);
        bool reportOnly = phase == "apfs: report pending" || phase == "apfs: report ready" || phase == "apfs: engine complete";
        RecoveryPipeline.Resume(root,CancellationToken.None,m => { if (reportOnly && Inner(m)) throw new Exception("completed source phase repeated during session resume: "+m); });
        Check(!Directory.Exists(Path.Combine(root,"attempt-history")),"checkpoint continuation retains the same working attempt"); Verify(root,sha);
    }
    static void ParentFailure()
    {
        string root = Folder("parent"),sha = Hash(Path.Combine(root,"usb.dd")); FileStream held = null; bool failed = false; long sequence = 0;
        try { Start(root,CancellationToken.None,m => {
            if (held == null && m == "apfs: report ready") {
                sequence = RecoverySession.Read(root).Stages.Single().CheckpointSequence;
                held = new FileStream(Path.Combine(root,RecoverySession.FileName),FileMode.Open,FileAccess.Read,FileShare.Read);
            }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && sequence > 0 && RecoverySession.Read(root).Stages.Single().CheckpointSequence == sequence,
            "OS session-file replacement denial preserves the last acknowledged root after report rename");
        Check(File.Exists(Path.Combine(root,"apfs","report.json")),"rename succeeded before denied session acknowledgement, leaving a planned verifiable report");
        RecoveryPipeline.Resume(root,CancellationToken.None,m => { if (Inner(m)) throw new Exception("report acknowledgement retry repeated source phases"); }); Verify(root,sha);
    }
    static void SourceFailure()
    {
        string root = Folder("source-io"),image = Path.Combine(root,"usb.dd"),sha = Hash(image); FileStream held = null; bool failed = false;
        try { Start(root,CancellationToken.None,m => {
            if (held == null && m == "apfs: metadata unit 1") {
                held = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read); held.Lock(0,held.Length);
            }
        }); } catch (IOException) { failed = true; }
        finally { if (held != null) { held.Unlock(0,held.Length); held.Dispose(); } }
        var stage = RecoverySession.Read(root).Stages.Single();
        Check(failed && stage.Status == "incomplete" && stage.CheckpointSequence > 0,"actual source I/O failure remains an incomplete resumable stage");
        RecoveryPipeline.Resume(root,CancellationToken.None,s => { }); Verify(root,sha);
    }
    static void TamperedChild()
    {
        string root = Folder("tamper"),sha = Hash(Path.Combine(root,"usb.dd"));
        using (var cancel = new CancellationTokenSource()) {
            try { Start(root,cancel.Token,m => { if (m == "apfs: report pending") cancel.Cancel(); }); } catch (OperationCanceledException) { }
        }
        var stage = RecoverySession.Read(root).Stages.Single();
        string blob = Directory.GetFiles(Path.Combine(root,"apfs.state"),"blob-*.json",SearchOption.AllDirectories).First();
        File.AppendAllText(blob,"changed",Encoding.ASCII); bool denied = false;
        try { RecoveryPipeline.Resume(root,CancellationToken.None,s => { }); } catch (IOException) { denied = true; }
        // Begin/Fail may update status, but cannot advance the damaged engine.
        Check(denied && RecoverySession.Read(root).Stages.Single().CheckpointSequence == stage.CheckpointSequence &&
            !Directory.Exists(Path.Combine(root,"attempt-history")) && Hash(Path.Combine(root,"usb.dd")) == sha,
            "session cannot bypass a changed metadata child by silently restarting or archiving the attempt");
    }
    static void RestartWithoutAnchor()
    {
        string root = Folder("old-unanchored"),image = Path.Combine(root,"usb.dd"),sha = Hash(image);
        var session = RecoverySession.Start(root,image,sha,Options(),CancellationToken.None); session.Begin("apfs");
        string payload = Path.Combine(root,"apfs","files","old-owned.bin"),state = Path.Combine(root,"apfs.state","orphan.json");
        Directory.CreateDirectory(Path.GetDirectoryName(payload)); Directory.CreateDirectory(Path.GetDirectoryName(state));
        File.WriteAllText(payload,"retained previous attempt"); File.WriteAllText(state,"unacknowledged engine data"); string prior = Hash(payload),metadata = Hash(state);
        session.Fail("apfs","cancelled",null); RecoveryPipeline.Resume(root,CancellationToken.None,s => { });
        string history = Path.Combine(root,"attempt-history");
        Check(Directory.Exists(history) && Hash(Directory.GetFiles(history,"old-owned.bin",SearchOption.AllDirectories).Single()) == prior &&
            Hash(Directory.GetFiles(history,"orphan.json",SearchOption.AllDirectories).Single()) == metadata,"unanchored retry archives both old output and engine state without losing either");
        Check(RecoverySession.Read(root).Stages.Single().Status == "complete" && Hash(image) == sha,"archived retry starts an independent completed apfs attempt");
    }
    static void KilledWorker()
    {
        string root = Folder("worker"),sha = Hash(Path.Combine(root,"usb.dd")),signal = Path.Combine(root,"ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+root+"\" \""+signal+"\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(signal) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(signal),"owned public-pipeline worker reaches a captured file-copy checkpoint"); child.Kill(); Check(child.WaitForExit(10000),"owned worker is terminated without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        var stage = RecoverySession.Read(root).Stages.Single(); Check(stage.Status == "running" && stage.CheckpointSequence > 0,"forced termination leaves an honest running stage with a pinned cursor");
        RecoveryPipeline.Resume(root,CancellationToken.None,s => { }); Verify(root,sha);
    }
    public static int Main(string[] args)
    {
        try {
            if (!(bool)typeof(RecoverySession).GetMethod("CheckpointSupported",BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,new object[] { "apfs" }))
            { Console.WriteLine("FAIL: baseline session does not support apfs checkpoints"); return 1; }
            if (args.Length == 3 && args[0] == "--worker") {
                Start(args[1],CancellationToken.None,m => { if (m.StartsWith("apfs: mapped bytes ",StringComparison.Ordinal)) { File.WriteAllText(args[2],m); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            fixture = Path.Combine(Path.GetFullPath(args[1]),"apfs-deleted-single.dd");
            work = Path.Combine(Path.GetFullPath(args[0]),".build","apfs-session-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            foreach (string phase in new[] { "apfs: metadata unit ","apfs: mapped bytes ","apfs: report pending","apfs: report ready","apfs: engine complete" }) CancelResume(phase);
            ParentFailure(); SourceFailure(); TamperedChild(); RestartWithoutAnchor(); KilledWorker();
            Console.WriteLine("PASS ApfsSessionCheckpoint: "+checks+" checks; actual managed Pipeline/Session and catalog on owned images; not portable package or real devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
