// SPDX-License-Identifier: AGPL-3.0-or-later
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

public static class ApfsEngineCheckpointTests
{
    static int checks;
    static string work,fixtures;
    static List<Tuple<long,int>> reads;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64*1024*1024 };
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b) => { }); }
    static void Set(object value,string name,object field) { value.GetType().GetField(name).SetValue(value,field); }
    static string Parent(string root) { return Path.Combine(root,"anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)) : null; }
    static void Save(string root,RecoveryMethodCheckpoint value)
    {
        string path = Parent(root),temp = path+"."+Guid.NewGuid().ToString("N")+".partial";
        byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value)); bool own = false;
        try {
            using (var file = new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
            if (File.Exists(path)) File.Replace(temp,path,null); else File.Move(temp,path);
        } finally { if (own && File.Exists(temp)) File.Delete(temp); }
    }
    static Dictionary<string,object> State(string root)
    {
        var a = Anchor(root); Check(a != null && Hash(a.Path) == a.Sha256,"whole ReFS state is parent-anchored");
        return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(a.Path,Encoding.UTF8))["Payload"];
    }
    sealed class Source : FileStream
    {
        public bool Zero;
        public readonly List<Tuple<long,int>> Reads = new List<Tuple<long,int>>();
        public Source(string file) : base(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1) { }
        public override int Read(byte[] bytes,int at,int count) { Reads.Add(Tuple.Create(Position,count)); return Zero ? 0 : base.Read(bytes,at,count); }
    }
    static string Image(string name,out string root,string fixture = "apfs-deleted-single.dd")
    {
        root = Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root,"owned.dd"); File.Copy(Path.Combine(fixtures,fixture),image);
        File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly); return image;
    }
    static ApfsRecovery.Report Run(string image,string root,string sha,CancellationToken token,Action<string> progress,
        IEnumerable<long> offsets = null,ApfsRecovery.Limits limits = null,string change = null)
    {
        using (var input = new Source(image)) {
            object c = Activator.CreateInstance(typeof(ApfsRecovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            limits = limits ?? new ApfsRecovery.Limits { MaximumBlocks = 64 }; if (change == "limits") limits.MaximumEntries--;
            Set(c,"Stream",input); Set(c,"Destination",Path.Combine(root,change == "root" ? "other" : "apfs")); Set(c,"Cancel",token); Set(c,"Limits",limits);
            object context = Activator.CreateInstance(typeof(ApfsRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
            Set(context,"Directory",root); Set(context,"Method","apfs"); Set(context,"SourceSha256",sha); Set(context,"Settings",change == "settings" ? "changed" : "whole-apfs-v1");
            Set(context,"Resume",Anchor(root)); Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a => Save(root,a)));
            reads = input.Reads;
            Action<string> notify = m => {
                if (change == "zero" && m.StartsWith("apfs: metadata unit ",StringComparison.Ordinal)) input.Zero = true;
                if (change == "mid-limits") limits.MaximumEntries--;
                if (change == "mid-publisher") Set(c,"PublishFile",null);
                if (progress != null) progress(m);
            };
            try { typeof(ApfsRecovery).GetMethod("RecoverCheckpointedCore",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[] { c,context,offsets,notify }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return (ApfsRecovery.Report)c.GetType().GetField("Report").GetValue(c);
        }
    }
    static void Compare(string image,string root,string sha,ApfsRecovery.Report actual,IEnumerable<long> offsets = null,ApfsRecovery.Limits limits = null)
    {
        string control = Path.Combine(root,"control-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(control);
        ApfsRecovery.Recover(image,control,CancellationToken.None,null,offsets,limits ?? new ApfsRecovery.Limits { MaximumBlocks = 64 });
        string legacy = File.ReadAllText(Path.Combine(control,"apfs","report.json"),Encoding.UTF8);
        Check(Json.Serialize(actual) == legacy,"whole report matches legacy geometry, capabilities, budgets, dates, provenance and counters");
        Check(File.ReadAllText(Path.Combine(root,"apfs","report.json"),Encoding.UTF8) == legacy,"published report bytes match canonical whole result");
        foreach (var entry in actual.Entries.Where(x => x.Output != null)) {
            string relative = entry.Output.Replace('/',Path.DirectorySeparatorChar);
            Check(Hash(Path.Combine(root,"apfs",relative)) == Hash(Path.Combine(control,"apfs",relative)),"every published candidate matches legacy payload bytes");
        }
        Check(Hash(image) == sha && actual.SourceUnchanged,"whole engine preserves source");
    }
    static List<Tuple<long,int>> Cancel(string image,string root,string sha,string phase)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (m.StartsWith(phase,StringComparison.Ordinal)) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Anchor(root) != null,"cancellation is anchored at "+phase); return reads.ToList();
    }
    static void Complete(string image,string root,string sha,List<Tuple<long,int>> prefix = null)
    {
        var actual = Run(image,root,sha,CancellationToken.None,null); var suffix = reads.ToList();
        Compare(image,root,sha,actual);
        var again = Run(image,root,sha,CancellationToken.None,m => { if (m.StartsWith("apfs:",StringComparison.Ordinal)) throw new Exception("completed durable phase restarted: "+m); });
        Check(reads.Count == 0 && Json.Serialize(again) == Json.Serialize(actual) && Convert.ToInt32(State(root)["Phase"]) == 2,
            "completed engine reconstructs/verifies all results with zero source-phase reads");
        if (prefix != null) {
            string control = Path.Combine(root,"trace-control"); Directory.CreateDirectory(control);
            Run(image,control,sha,CancellationToken.None,null); var all = reads;
            Check(prefix.Concat(suffix).Select(x => x.Item1+":"+x.Item2).SequenceEqual(all.Select(x => x.Item1+":"+x.Item2)),"cancel/resume physical read trace is exactly uninterrupted trace with acknowledged prefix omitted");
        }
    }
    static void Fault(string mode)
    {
        string root,image = Image(mode,out root),sha = Hash(image),before = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held != null || !m.StartsWith("apfs: metadata unit ",StringComparison.Ordinal)) return;
            if (mode == "parent") { before = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); }
            if (mode == "read") { held = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read); held.Lock(0,held.Length); }
        },null,null,mode == "zero" ? mode : null); } catch (IOException) { failed = true; }
        finally { if (held != null) { if (mode == "read") held.Unlock(0,held.Length); held.Dispose(); } }
        Check(failed,"actual whole-engine "+mode+" failure propagates"); if (before != null) Check(Hash(Parent(root)) == before,"failed parent save retains exact prior anchor");
        Complete(image,root,sha);
    }
    static void Tamper(string mode)
    {
        string root,image = Image(mode,out root),sha = Hash(image); Cancel(image,root,sha,"apfs: metadata unit ");
        if (mode == "source") using (var file = new FileStream(image,FileMode.Open,FileAccess.Write)) file.WriteByte(13);
        if (mode == "state") File.AppendAllText(Anchor(root).Path,"changed");
        if (mode == "map") File.WriteAllText(Path.Combine(root,"source-read-errors.json"),"{}");
        bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,null,null,null,mode); } catch (IOException) { failed = true; }
        Check(failed,"changed "+mode+" is refused by whole controller");
    }
    static void ReportFailure()
    {
        string root,image = Image("report-ack",out root),sha = Hash(image),before = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held == null && m == "apfs: report pending") { before = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && Hash(Parent(root)) == before && File.Exists(Path.Combine(root,"apfs","report.json")),"report publication before failed parent ack retains recoverable report-pending state");
        Complete(image,root,sha);
    }
    static void RepairsAndRelocation()
    {
        string root,image = Image("repair",out root),sha = Hash(image); var report = Run(image,root,sha,CancellationToken.None,null);
        var entry = report.Entries.First(x => x.Output != null); string payload = Path.Combine(root,"apfs",entry.Output.Replace('/',Path.DirectorySeparatorChar));
        File.Delete(payload); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (m.Contains("/repair")) cancel.Cancel(); }); } catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped,"completed-file repair is durably linked from whole parent"); Complete(image,root,sha);
        File.Delete(payload); Complete(image,root,sha);
        File.Delete(Path.Combine(root,"apfs","report.json")); Complete(image,root,sha);
        string moved = root+"-moved"; Directory.Move(root,moved); var anchor = Anchor(moved);
        anchor.Path = Path.Combine(moved,"apfs.state",Path.GetFileName(anchor.Path)); Save(moved,anchor);
        Complete(Path.Combine(moved,"owned.dd"),moved,sha);
    }
    static void MultiVolume()
    {
        string root,image = Image("multi",out root),sha; byte[] volume = File.ReadAllBytes(image),disk = new byte[volume.Length*2+4096];
        Buffer.BlockCopy(volume,0,disk,4096,volume.Length); Buffer.BlockCopy(volume,0,disk,4096+volume.Length,volume.Length); File.WriteAllBytes(image,disk); sha = Hash(image);
        long[] offsets = { -512,4096,4096+volume.LongLength,Int64.MaxValue };
        var limits = new ApfsRecovery.Limits { MaximumOutputBytes = 20, MaximumBlocks = 64 };
        var actual = Run(image,root,sha,CancellationToken.None,null,offsets,limits); Compare(image,root,sha,actual,offsets,limits);
        Check(actual.Volumes.Count == 2 && actual.Limited && actual.OutputBytes <= 20,"multi-volume replay preserves global output budget and invalid offset diagnostics");
        Run(image,root,sha,CancellationToken.None,null,offsets,limits); Check(reads.Count == 0,"completed multi-volume engine has no source-phase reads");
        bool changed = false; try { Run(image,root,sha,CancellationToken.None,null,offsets.Reverse(),limits); } catch (IOException) { changed = true; }
        Check(changed,"different requested partition order is refused");
    }
    static void Kill()
    {
        string root,image = Image("kill",out root),sha = Hash(image),ready = Path.Combine(root,"worker-ready");
        using (var child = Process.Start(new ProcessStartInfo { FileName = Assembly.GetExecutingAssembly().Location,
            Arguments = "worker \""+image+"\" \""+root+"\" "+sha+" \""+ready+"\"",UseShellExecute = false,CreateNoWindow = true })) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(ready) && !child.HasExited && timer.ElapsedMilliseconds < 15000) Thread.Sleep(25);
                Check(File.Exists(ready) && !child.HasExited,"owned whole-engine worker reaches durable metadata cursor"); child.Kill(); child.WaitForExit(); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(); } }
        }
        Complete(image,root,sha);
    }
    static void ReportTamper()
    {
        string root,image = Image("report-changed",out root),sha = Hash(image); Run(image,root,sha,CancellationToken.None,null);
        string report = Path.Combine(root,"apfs","report.json"); File.AppendAllText(report,"changed"); string before = Hash(report); bool refused = false;
        try { Run(image,root,sha,CancellationToken.None,null); } catch (IOException) { refused = true; }
        Check(refused && Hash(report) == before,"changed existing report is retained and cannot be accepted as complete");
    }
    public static int Main(string[] args)
    {
        try {
            if (args[0] == "worker") { Run(args[1],args[2],args[3],CancellationToken.None,m => { if (m.StartsWith("apfs: metadata unit ",StringComparison.Ordinal)) { File.WriteAllText(args[4],"ready"); Thread.Sleep(Timeout.Infinite); } }); return 0; }
            if (args[0] == "default-resume") {
                string root = Path.GetFullPath(args[1]),image = Path.Combine(root,"owned.dd"),sha = Hash(image);
                var actual = Run(image,root,sha,CancellationToken.None,null,null,new ApfsRecovery.Limits());
                Check(reads.Count == 0,"existing completed default4096-block run replays without source-phase I/O");
                Compare(image,root,sha,actual,null,new ApfsRecovery.Limits());
                Console.WriteLine("PASS ApfsEngineDefaultResume: "+checks+" checks; prior completed4096-block run reused"); return 0;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]),".build","apfs-engine-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            foreach (string fixture in Directory.GetFiles(fixtures,"*.dd")) { string root,image = Image("fixture",out root,Path.GetFileName(fixture)),sha = Hash(image); Complete(image,root,sha); }
            foreach (string phase in new[] { "apfs: metadata unit ","apfs: mapped bytes ","apfs: file ","apfs: report pending","apfs: engine complete" }) {
                string root,image = Image("cancel",out root),sha = Hash(image); Complete(image,root,sha,Cancel(image,root,sha,phase));
            }
            foreach (string mode in new[] { "parent","read","zero" }) Fault(mode);
            foreach (string mode in new[] { "source","state","map","limits","root","settings" }) Tamper(mode);
            foreach (string mode in new[] { "mid-limits","mid-publisher" }) { string root,image = Image(mode,out root); bool failed = false;
                try { Run(image,root,Hash(image),CancellationToken.None,null,null,null,mode); } catch (IOException) { failed = true; }
                Check(failed,"mid-run ownership/settings mutation fails closed"); }
            ReportFailure(); RepairsAndRelocation(); MultiVolume(); Kill(); ReportTamper();
            Console.WriteLine("PASS ApfsEngineCheckpoint: "+checks+" checks; managed full controller on owned regular images"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
