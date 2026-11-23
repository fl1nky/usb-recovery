using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// One complete volume initialization, including dirty journal replay. This
// still does not claim inode/history/export or RecoverySession integration.
public static class Ext4InitializationCheckpointTests
{
    static int checks;
    static string work,fixtures;
    static List<int> readPhases;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16*1024*1024 };
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static object Get(object owner,string field) { return owner.GetType().GetField(field).GetValue(owner); }
    static void Set(object owner,string field,object value) { owner.GetType().GetField(field).SetValue(owner,value); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b) => { }); }
    static string Bytes(object value)
    { if (value == null) return null; using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash((byte[])value)); }
    static string Parent(string root) { return Path.Combine(root,"anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)) : null; }
    static Dictionary<string,object> Payload(string file)
    { return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file,Encoding.UTF8))["Payload"]; }
    static Dictionary<string,object> State(string root)
    { var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256,"caller pins exact volume initialization state"); return Payload(anchor.Path); }
    static void SaveAnchor(string root,RecoveryMethodCheckpoint anchor)
    {
        string temporary = Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial"; bool own = false;
        try {
            byte[] data = Encoding.UTF8.GetBytes(Json.Serialize(anchor));
            using (var file = new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; file.Write(data,0,data.Length); file.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temporary,Parent(root),null); else File.Move(temporary,Parent(root));
        } finally { if (own && File.Exists(temporary)) File.Delete(temporary); }
    }
    sealed class Source : FileStream
    {
        readonly string root;
        public bool ZeroNext;
        public readonly List<int> Phases = new List<int>();
        public Source(string image,string folder) : base(image,FileMode.Open,FileAccess.Read,FileShare.Read,1) { root = folder; }
        public override int Read(byte[] data,int offset,int count)
        { Phases.Add(File.Exists(Parent(root)) ? Convert.ToInt32(Payload(Anchor(root).Path)["Phase"]) : -1); return ZeroNext ? 0 : base.Read(data,offset,count); }
    }
    static string Image(string label,out string root,string fixture = "native-journal-v3-replay")
    {
        root = Path.Combine(work,label+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root,"owned.dd"); File.Copy(Path.Combine(fixtures,fixture+".dd"),image);
        File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly); return image;
    }
    static string Snapshot(object volume,Ext4Recovery.Report report)
    {
        if (volume == null) return Json.Serialize(new { Empty = true, Limited = report.Limited, Skips = report.Skipped.OrderBy(x => x.Key).ToArray() });
        var groups = ((IEnumerable)Get(volume,"Groups")).Cast<object>().Select(g => new {
            Number = Get(g,"Number"), Valid = Get(g,"Valid"), Inodes = Get(g,"InodeMapValid"), Blocks = Get(g,"BlockMapValid"),
            Descriptor = Bytes(Get(g,"Descriptor")), InodeBitmap = Bytes(Get(g,"Inodes")), BlockBitmap = Bytes(Get(g,"Blocks")) }).ToArray();
        var overlay = ((IDictionary)Get(volume,"Overlay")).Keys.Cast<ulong>().OrderBy(x => x)
            .Select(block => block+":"+Bytes(((IDictionary)Get(volume,"Overlay"))[block])).ToArray();
        var reserved = ((IEnumerable)Get(volume,"Reserved")).Cast<object>().Select(x => Get(x,"Start")+":"+Get(x,"Length")).ToArray();
        return Json.Serialize(new { Volume = Get(volume,"Report"), Groups = groups, Overlay = overlay, Reserved = reserved,
            Limited = report.Limited, Skips = report.Skipped.OrderBy(x => x.Key).ToArray(), JournalLoaded = Get(volume,"JournalLoaded") });
    }
    static string Run(string image,string root,string sha,CancellationToken token,Action<string> progress,bool durable = true,string change = null)
    {
        using (var input = new Source(image,root)) {
            object c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            var report = new Ext4Recovery.Report(); report.Skipped.Add("prior_volume",7);
            if (change == "baseline") report.OutputBytes++;
            var limits = new Ext4Recovery.Limits(); if (change == "limits") limits.MaximumGroups--;
            Set(c,"Input",input); Set(c,"Cancel",token); Set(c,"Root",Path.Combine(root,"ext4")); Set(c,"Report",report); Set(c,"Limits",limits);
            object context = null;
            if (durable) {
                context = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
                Set(context,"Directory",root); Set(context,"Method","ext4"); Set(context,"SourceSha256",sha); Set(context,"Settings","owned-volume-initialization-v1");
                Set(context,"Resume",Anchor(root)); Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(root,a)));
            }
            readPhases = input.Phases; if (change == "zero-first") input.ZeroNext = true;
            Action<string> notify = m => { if (change == "zero-next") input.ZeroNext = true; if (change == "mid-limits") limits.MaximumGroups--; if (progress != null) progress(m); };
            object v;
            try { v = typeof(Ext4Recovery).GetMethod(durable ? "OpenVolumeCheckpointed" : "OpenVolume",Private)
                .Invoke(null,durable ? new[] { c,(object)0L,context,notify } : new[] { c,(object)0L }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return Snapshot(v,report);
        }
    }
    static string Reference(string image,string sha)
    { string root = Path.Combine(work,"reference-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image,root,sha,CancellationToken.None,null,false); }
    static int Cancel(string image,string root,string sha,string phase)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => {
                int current = Convert.ToInt32(State(root)["Phase"]);
                if (phase == "header" && m == "ext4: volume header saved" ||
                    phase == "groups" && current == 0 && m.StartsWith("ext4: groups ",StringComparison.Ordinal) ||
                    phase == "load" && current == 1 && m.StartsWith("ext4: journal mapping ",StringComparison.Ordinal) ||
                    phase == "replay" && current == 2 && m.StartsWith("ext4: replay ",StringComparison.Ordinal) ||
                    phase == "post" && current == 3 && m.StartsWith("ext4: groups ",StringComparison.Ordinal) ||
                    phase == "closed" && current == 4) cancel.Cancel();
            }); } catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Anchor(root) != null,"cancel interrupts actual volume initialization at "+phase); return Convert.ToInt32(State(root)["Phase"]);
    }
    static void Complete(string image,string root,string sha,int savedPhase = 0)
    {
        string result = Run(image,root,sha,CancellationToken.None,null); int[] phases = readPhases.ToArray();
        Check(result == Reference(image,sha),"resumed header, groups, reserved ranges, overlay and diagnostics match the unchanged legacy initialization");
        Check(phases.All(phase => phase >= savedPhase),"closed phases and the pinned header perform no source-phase reads during resume");
        Check(Convert.ToInt32(State(root)["Phase"]) == 4 && Hash(image) == sha,"initialization closes all phases and leaves the source unchanged");
        Check(Run(image,root,sha,CancellationToken.None,m => { throw new Exception("completed initialization restarted"); }) == result && readPhases.Count == 0,
            "completed volume initialization reconstructs entirely from verified child checkpoints");
    }
    static void ParentFailure(bool betweenPhases)
    {
        string root,image = Image("parent",out root),sha = Hash(image),prior = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held == null && m == (betweenPhases ? "ext4: initialization groups-before complete" : "ext4: volume header saved"))
            { prior = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && prior != null && Hash(Parent(root)) == prior,"actual outer parent replacement denial preserves its last pinned child links");
        Complete(image,root,sha,Convert.ToInt32(State(root)["Phase"]));
    }
    static void ReadFailure()
    {
        string root,image = Image("read",out root),sha = Hash(image); bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,null,true,"zero-first"); } catch (IOException) { failed = true; }
        Check(failed && Anchor(root) == null,"failed header read cannot create a successful empty initialization");
        failed = false;
        try { Run(image,root,sha,CancellationToken.None,null,true,"zero-next"); } catch (IOException) { failed = true; }
        Check(failed && Convert.ToInt32(State(root)["Phase"]) == 0,"group read failure keeps the verified header and active initialization phase");
        Complete(image,root,sha);
    }
    static void Tamper(string kind)
    {
        string root,image = Image("tamper",out root),sha = Hash(image); Cancel(image,root,sha,kind == "child" ? "groups" : "header");
        string target = kind == "source" ? image : Anchor(root).Path;
        if (kind == "header") target = Path.Combine(root,"ext4.state","group-blobs","blob-"+(string)State(root)["Header"]+".json");
        if (kind == "child") { var children = (Dictionary<string,object>)State(root)["Children"]; target = Path.Combine(root,(string)((Dictionary<string,object>)children["groups-before"])["Path"]); }
        if (kind == "phase" || kind == "offset" || kind == "role") {
            var envelope = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target,Encoding.UTF8)); var payload = (Dictionary<string,object>)envelope["Payload"];
            if (kind == "phase") payload["Phase"] = 4;
            if (kind == "offset") payload["Offset"] = 512;
            if (kind == "role") ((Dictionary<string,object>)payload["Children"])["unknown-role"] = null;
            File.WriteAllText(target,Json.Serialize(envelope),new UTF8Encoding(false)); var anchor = Anchor(root); anchor.Sha256 = Hash(target); SaveAnchor(root,anchor);
        } else using (var file = new FileStream(target,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) {
            file.Position = file.Length-1; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value^1));
        }
        string prior = Hash(Parent(root)),changed = Hash(target); bool denied = false;
        try { Run(image,root,sha,CancellationToken.None,null); } catch (IOException) { denied = true; }
        Check(denied && Hash(Parent(root)) == prior && Hash(target) == changed,"changed initialization "+kind+" is refused without overwriting evidence");
    }
    static void Bindings()
    {
        foreach (string kind in new[] { "limits","baseline" }) {
            string root,image = Image("binding",out root),sha = Hash(image); Cancel(image,root,sha,"header"); string prior = Hash(Parent(root)); bool denied = false;
            try { Run(image,root,sha,CancellationToken.None,null,true,kind); } catch (IOException) { denied = true; }
            Check(denied && readPhases.Count == 0 && Hash(Parent(root)) == prior,"different "+kind+" cannot reuse initialization state");
        }
        string midRoot,midImage = Image("mid-limits",out midRoot),midSha = Hash(midImage); bool failed = false;
        try { Run(midImage,midRoot,midSha,CancellationToken.None,null,true,"mid-limits"); } catch (IOException) { failed = true; }
        Check(failed && Convert.ToInt32(State(midRoot)["Phase"]) == 0,"limits changed after the pinned header cannot close a later phase");
    }
    static void Corpus()
    {
        foreach (string fixture in Directory.GetFiles(fixtures,"*.dd").Select(Path.GetFileNameWithoutExtension)) {
            string root,image = Image("corpus",out root,fixture),sha = Hash(image);
            string result = Run(image,root,sha,CancellationToken.None,null);
            Check(result == Reference(image,sha),"uninterrupted initialization preserves legacy native-format verdict: "+fixture);
            Complete(image,root,sha,4);
        }
    }
    static void KilledWorker()
    {
        string root,image = Image("worker",out root),sha = Hash(image),signal = Path.Combine(root,"ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+image+"\" \""+root+"\" \""+signal+"\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(signal) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(signal),"owned worker reaches a committed inner replay cursor"); child.Kill(); Check(child.WaitForExit(10000),"owned initialization worker terminates without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Complete(image,root,sha,Convert.ToInt32(State(root)["Phase"]));
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("OpenVolumeCheckpointed",Private) == null) { Console.WriteLine("FAIL: baseline lacks checkpointed volume initialization"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1],args[2],Hash(args[1]),CancellationToken.None,m => { if (Convert.ToInt32(State(args[2])["Phase"]) == 2 && m.StartsWith("ext4: replay ",StringComparison.Ordinal))
                    { File.WriteAllText(args[3],m); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]),".build","ext4-initialization-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            foreach (string phase in new[] { "header","groups","load","replay","post","closed" }) {
                string root,image = Image("cancel",out root),sha = Hash(image); Complete(image,root,sha,Cancel(image,root,sha,phase));
            }
            ParentFailure(false); ParentFailure(true); ReadFailure();
            foreach (string kind in new[] { "source","state","header","child","phase","offset","role" }) Tamper(kind);
            Bindings(); Corpus(); KilledWorker();
            Console.WriteLine("PASS Ext4InitializationCheckpoint: "+checks+" checks; complete volume opening, not whole-engine scan/export or real devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
