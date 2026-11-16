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

// Publication of supplied report metadata, not filesystem scan or device tests.
public static class Ext4ReportCheckpointTests
{
    static int checks, sourceReads;
    static string work;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a,b) => { }); }
    static void Set(object owner, string field, object value) { owner.GetType().GetField(field).SetValue(owner,value); }
    static string Parent(string root) { return Path.Combine(root,"anchor.json"); }
    static string Output(string root) { return Path.Combine(root,"ext4","report.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)) : null; }
    static void SaveAnchor(string root, RecoveryMethodCheckpoint value)
    {
        string temporary = Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value));
            using (var file = new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
            { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temporary,Parent(root),null); else File.Move(temporary,Parent(root));
        } finally { if (own && File.Exists(temporary)) File.Delete(temporary); }
    }
    static Dictionary<string,object> State(string root)
    {
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256,"parent pins exact report generation");
        return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(anchor.Path,Encoding.UTF8))["Payload"];
    }
    static string Scratch(string root)
    { return Path.Combine(root,"ext4.state","report-work",(string)State(root)["WorkId"]+".partial"); }
    sealed class Source : FileStream
    {
        public Source(string file) : base(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1) { }
        public override int Read(byte[] bytes,int offset,int count) { sourceReads++; return base.Read(bytes,offset,count); }
    }
    static string Image(string name, out string root)
    {
        root = Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root,"owned.dd"); File.WriteAllText(image,"owned report storage source, not an ext4 filesystem",Encoding.UTF8); return image;
    }
    static Ext4Recovery.Report Report(bool large = false)
    {
        var result = new Ext4Recovery.Report { Status = "complete", Candidates = 3, RecoveredFiles = 1,
            OutputBytes = 12345, InputBytes = 65536, SourceSha256 = new string('a',64), SourceUnchanged = true };
        result.Warnings.Add("Текст\n<script src='https://invalid.example/x'> & \"цитата\" 😀");
        result.Skipped.Add("z",2); result.Skipped.Add("a",1);
        result.Volumes.Add(new Ext4Recovery.VolumeReport { Offset = 4096, Uuid = "volume-α", Status = "complete",
            JournalStatus = "committed", JournalReplayApplied = true, MetadataChecksums = true });
        var entry = new Ext4Recovery.Entry { Inode = UInt32.MaxValue, Generation = 7, VolumeOffset = 4096,
            Status = "deleted_inode_candidate", DeclaredSize = 12345, RecoveredBytes = 12345,
            Output = "files/candidate.bin", Sha256 = new string('b',64), InodeChecksumVerified = true,
            Mapping = "extent", MappingIntegrity = "metadata_crc", AllocationStatus = "free" };
        entry.Extents.Add(new Ext4Recovery.Extent { ImageOffset = 1048576, LogicalOffset = 0, Length = 12345 });
        string path = large ? "/"+new string('x',9000) : "/семья/рецепты";
        for (int i = 0; i < (large ? 2000 : 2); i++) entry.Names.Add(new Ext4Recovery.NameLink { Name = "пирожки-"+i,
            DirectoryPath = path, DirectoryInode = 2, TargetInode = UInt32.MaxValue, EntryOffset = 4096+i,
            JournalBlockOffset = i % 2 == 0 ? (long?)65536 : null, TargetBlockOffset = 131072,
            JournalTransactionSequence = i % 2 == 0 ? (uint?)UInt32.MaxValue : null, DirectoryChecksumVerified = true });
        result.Entries.Add(entry); return result;
    }
    static bool SameJson(object left, object right)
    {
        var a = left as Dictionary<string,object>; var b = right as Dictionary<string,object>;
        if (a != null || b != null) return a != null && b != null && a.Count == b.Count &&
            a.All(row => b.ContainsKey(row.Key) && SameJson(row.Value,b[row.Key]));
        var x = left as object[]; var y = right as object[];
        if (x != null || y != null) return x != null && y != null && x.Length == y.Length &&
            x.Select((value,index) => SameJson(value,y[index])).All(value => value);
        return Object.Equals(left,right);
    }
    static void Run(string image,string root,string sha,CancellationToken token,Action<string> progress,
        Ext4Recovery.Report report = null,string change = null)
    {
        sourceReads = 0;
        using (var input = new Source(image)) {
            object c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            var limits = new Ext4Recovery.Limits(); if (change == "limits") limits.MaximumInodes--;
            Set(c,"Input",input); Set(c,"Root",change == "root" ? root : Path.Combine(root,"ext4"));
            Set(c,"Cancel",token); Set(c,"Limits",limits); Set(c,"Report",report ?? Report());
            object context = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
            Set(context,"Directory",root); Set(context,"Method","ext4"); Set(context,"SourceSha256",sha);
            Set(context,"Settings","owned-report-v1"); Set(context,"Resume",Anchor(root));
            Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(root,a)));
            Action<string> notify = message => { if (change == "mid-limits") limits.MaximumInodes--; if (progress != null) progress(message); };
            try { typeof(Ext4Recovery).GetMethod("WriteReportCheckpointed",Private).Invoke(null,new[] { c,context,notify }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
        }
    }
    static void Compare(string image,string root,string sha,Ext4Recovery.Report expected = null)
    {
        var actual = Json.Deserialize<Ext4Recovery.Report>(File.ReadAllText(Output(root),Encoding.UTF8));
        Check(SameJson(Json.DeserializeObject(Json.Serialize(actual)),Json.DeserializeObject(Json.Serialize(expected ?? Report()))),
            "report round trip preserves every public field, Unicode, null provenance and list order");
        Check(Hash(Output(root)) == (string)State(root)["Identity"] && (bool)State(root)["Published"],"published report size and full digest are acknowledged");
        Check(Hash(image) == sha && sourceReads == 0,"report publication never repeats source-phase reads or modifies the source");
    }
    static string Cancel(string image,string root,string sha,string phase)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (m == "ext4: report "+phase) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Anchor(root) != null,"cancel at "+phase+" leaves an acknowledged report state"); return Scratch(root);
    }
    static void CancelResume(string phase)
    {
        string root,image = Image("cancel-"+phase,out root),sha = Hash(image),scratch = Cancel(image,root,sha,phase);
        string prior = File.Exists(scratch) ? Hash(scratch) : null;
        Run(image,root,sha,CancellationToken.None,null); Compare(image,root,sha);
        if (phase == "pending") Check(File.Exists(scratch) && Hash(scratch) == prior && Scratch(root) != scratch,"unconfirmed partial is preserved while re-emission uses a new file");
        if (phase == "ready") Check(Scratch(root) == scratch && !File.Exists(scratch),"ready report is published from the exact prior work file");
        string parent = Hash(Parent(root));
        Run(image,root,sha,CancellationToken.None,m => { throw new Exception("published report restarted"); }); Compare(image,root,sha);
        Check(Hash(Parent(root)) == parent,"already published report does not advance or rewrite the parent");
    }
    static void ParentFailure(bool afterRename)
    {
        string root,image = Image("parent",out root),sha = Hash(image),prior = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held == null && m == "ext4: report "+(afterRename ? "ready" : "pending"))
            { prior = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && prior != null && Hash(Parent(root)) == prior,"actual OS parent replacement denial preserves the acknowledged generation");
        Check(File.Exists(Output(root)) == afterRename && (bool)State(root)["Ready"] == afterRename,"failed parent acknowledgement does not misrepresent publication");
        Run(image,root,sha,CancellationToken.None,null); Compare(image,root,sha);
    }
    static void IoFailure(bool rename)
    {
        string root,image = Image("io",out root),sha = Hash(image),prior = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held != null || m != "ext4: report "+(rename ? "ready" : "pending")) return;
            prior = Hash(Parent(root)); held = new FileStream(Scratch(root),FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
            if (!rename) held.Lock(0,65536);
        }); } catch (IOException) { failed = true; }
        finally { if (held != null) { if (!rename) held.Unlock(0,65536); held.Dispose(); } }
        Check(failed && prior != null && Hash(Parent(root)) == prior && !File.Exists(Output(root)),"actual report "+(rename ? "rename denial" : "byte-range write denial")+" retains pending work");
        Run(image,root,sha,CancellationToken.None,null); Compare(image,root,sha);
    }
    static void Flip(string path)
    {
        using (var file = new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
        { file.Position = file.Length-1; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value^1)); }
    }
    static void Tamper(string kind)
    {
        string root,image = Image("tamper-"+kind,out root),sha = Hash(image);
        if (kind == "output") Run(image,root,sha,CancellationToken.None,null); else Cancel(image,root,sha,"ready");
        string target = kind == "source" ? image : kind == "output" ? Output(root) : kind == "work" ? Scratch(root) : Anchor(root).Path;
        if (kind == "source" || kind == "output" || kind == "work" || kind == "state") Flip(target);
        else {
            var envelope = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target,Encoding.UTF8));
            var payload = (Dictionary<string,object>)envelope["Payload"];
            if (kind == "bytes") payload["Bytes"] = Convert.ToInt64(payload["Bytes"])+1;
            if (kind == "schema") payload["Schema"] = 9;
            if (kind == "workid") payload["WorkId"] = "../outside";
            if (kind == "missing-id") payload["WorkId"] = null;
            if (kind == "phase") { payload["Ready"] = false; payload["Published"] = true; }
            if (kind == "pending-bytes") payload["Ready"] = false;
            File.WriteAllText(target,Json.Serialize(envelope),new UTF8Encoding(false));
            var anchor = Anchor(root); anchor.Sha256 = Hash(target); SaveAnchor(root,anchor);
        }
        string prior = Hash(Parent(root)),changed = Hash(target); bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,null); } catch (IOException) { failed = true; }
        Check(failed && Hash(Parent(root)) == prior && Hash(target) == changed,"changed "+kind+" is refused without rewriting evidence or parent state");
    }
    static void Binding(string kind)
    {
        string root,image = Image("binding",out root),sha = Hash(image); Cancel(image,root,sha,"ready");
        var report = Report(); if (kind == "report") report.Entries[0].Names[0].Name += " changed";
        string prior = Hash(Parent(root)); bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,null,report,kind); } catch (IOException) { failed = true; }
        Check(failed && Hash(Parent(root)) == prior && !File.Exists(Output(root)),"different "+kind+" cannot reuse the report checkpoint");
    }
    static void MidRunChange(bool limits)
    {
        string root,image = Image("mid-run",out root),sha = Hash(image); var report = Report(); bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (m == "ext4: report ready" && !limits) report.Entries[0].Note += " changed";
        },report,limits ? "mid-limits" : null); } catch (IOException) { failed = true; }
        Check(failed && !File.Exists(Output(root)),"mid-run "+(limits ? "limits" : "report")+" mutation cannot publish a stale snapshot");
    }
    static void MissingAndForeign()
    {
        foreach (bool published in new[] { false,true }) {
            string root,image = Image("missing",out root),sha = Hash(image);
            if (published) { Run(image,root,sha,CancellationToken.None,null); File.Delete(Output(root)); }
            else File.Delete(Cancel(image,root,sha,"ready"));
            Run(image,root,sha,CancellationToken.None,null); Compare(image,root,sha);
        }
        string foreignRoot,foreignImage = Image("foreign",out foreignRoot),foreignSha = Hash(foreignImage);
        Directory.CreateDirectory(Path.GetDirectoryName(Output(foreignRoot))); File.WriteAllText(Output(foreignRoot),"foreign report");
        string before = Hash(Output(foreignRoot)); bool failed = false;
        try { Run(foreignImage,foreignRoot,foreignSha,CancellationToken.None,null); } catch (IOException) { failed = true; }
        Check(failed && Anchor(foreignRoot) == null && Hash(Output(foreignRoot)) == before,"pre-existing unrelated report is preserved");
        bool denied = false;
        string leaseRoot,leaseImage = Image("lease",out leaseRoot),leaseSha = Hash(leaseImage);
        Run(leaseImage,leaseRoot,leaseSha,CancellationToken.None,m => {
            if (m == "ext4: report pending") {
                try { using (var writer = new FileStream(leaseImage,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)) { writer.WriteByte(7); } }
                catch (IOException) { denied = true; }
            }
        }); Check(denied && Hash(leaseImage) == leaseSha,"source read lease denies a concurrent write during report publication");
    }
    static void LargeAndRelocated()
    {
        string root,image = Image("large",out root),sha = Hash(image); var large = Report(true);
        Run(image,root,sha,CancellationToken.None,null,large); Compare(image,root,sha,large);
        Check(new FileInfo(Output(root)).Length > 16L*1024*1024 && new FileInfo(Anchor(root).Path).Length < 4096,"large report streams beyond the root checkpoint limit while its journal remains bounded");
        string moveRoot,moveImage = Image("move",out moveRoot),moveSha = Hash(moveImage); Cancel(moveImage,moveRoot,moveSha,"ready");
        string destination = Path.Combine(work,"moved-"+Guid.NewGuid().ToString("N")),prefix = Path.GetFullPath(work)+Path.DirectorySeparatorChar;
        Check(Path.GetFullPath(moveRoot).StartsWith(prefix,StringComparison.OrdinalIgnoreCase) && Path.GetFullPath(destination).StartsWith(prefix,StringComparison.OrdinalIgnoreCase) && !Directory.Exists(destination),"recursive move uses unique owned paths under the verified test workspace");
        var anchor = Anchor(moveRoot); Directory.Move(moveRoot,destination);
        anchor.Path = Path.Combine(destination,"ext4.state",Path.GetFileName(anchor.Path)); SaveAnchor(destination,anchor);
        Run(Path.Combine(destination,"owned.dd"),destination,moveSha,CancellationToken.None,null); Compare(Path.Combine(destination,"owned.dd"),destination,moveSha);
    }
    static void KilledWorker(string phase)
    {
        string root,image = Image("worker",out root),sha = Hash(image),signal = Path.Combine(root,"ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+image+"\" \""+root+"\" \""+signal+"\" "+phase)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try {
                var timer = Stopwatch.StartNew(); while (!File.Exists(signal) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(signal),"owned child reached acknowledged report "+phase); child.Kill(); Check(child.WaitForExit(10000),"owned report worker exits after forced termination");
            } finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Run(image,root,sha,CancellationToken.None,null); Compare(image,root,sha);
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("WriteReportCheckpointed",Private) == null) { Console.WriteLine("FAIL: baseline lacks checkpointed report publication"); return 1; }
            if (args.Length == 5 && args[0] == "--worker") {
                Run(args[1],args[2],Hash(args[1]),CancellationToken.None,m => { if (m == "ext4: report "+args[4]) { File.WriteAllText(args[3],m); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            work = Path.Combine(Path.GetFullPath(args[0]),".build","ext4-report-checkpoints-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            foreach (string phase in new[] { "pending","ready","published" }) CancelResume(phase);
            ParentFailure(false); ParentFailure(true); IoFailure(false); IoFailure(true);
            foreach (string kind in new[] { "source","work","output","state","bytes","schema","workid","missing-id","phase","pending-bytes" }) Tamper(kind);
            foreach (string kind in new[] { "report","limits","root" }) Binding(kind);
            MidRunChange(false); MidRunChange(true); MissingAndForeign(); LargeAndRelocated(); KilledWorker("pending"); KilledWorker("ready");
            Console.WriteLine("PASS Ext4ReportCheckpoint: "+checks+" checks; supplied report publication, not whole-engine resume or real devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
