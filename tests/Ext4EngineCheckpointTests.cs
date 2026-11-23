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

// Full managed engine on owned regular images. Actual RecoverySession wiring
// and the offline packaged application are separate acceptance gates.
public static class Ext4EngineCheckpointTests
{
    static int checks;
    static string work,fixtures;
    static List<Read> reads;
    static readonly BindingFlags Private = BindingFlags.NonPublic|BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64*1024*1024 };
    public sealed class Read { public int Phase; public long At; public int Bytes; }
    sealed class Source : FileStream
    {
        readonly string root;
        public bool ZeroNext;
        public readonly List<Read> Reads = new List<Read>();
        public Source(string image,string folder) : base(image,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1) { root = folder; }
        public override int Read(byte[] bytes,int offset,int count)
        {
            var anchor = Anchor(root);
            Reads.Add(new Read { Phase = anchor == null ? -1 : Convert.ToInt32(Payload(anchor.Path)["Phase"]), At = Position, Bytes = count });
            return ZeroNext ? 0 : base.Read(bytes,offset,count);
        }
    }
    sealed class Result { public int Files; public Ext4Recovery.Report Report; public List<Read> Reads; }
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b) => { }); }
    static void Set(object owner,string field,object value) { owner.GetType().GetField(field).SetValue(owner,value); }
    static string Parent(string root) { return Path.Combine(root,"anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)) : null; }
    static Dictionary<string,object> Payload(string file)
    { return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file,Encoding.UTF8))["Payload"]; }
    static Dictionary<string,object> State(string root)
    { var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256,"parent pins exact whole-engine generation"); return Payload(anchor.Path); }
    static void SaveAnchor(string root,RecoveryMethodCheckpoint anchor)
    {
        string temporary = Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(anchor));
            using (var output = new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; output.Write(bytes,0,bytes.Length); output.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temporary,Parent(root),null); else File.Move(temporary,Parent(root));
        } finally { if (own && File.Exists(temporary)) File.Delete(temporary); }
    }
    static string Image(string name,out string root,string fixture = "extent-deleted", bool privateImage = false)
    {
        root = Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string source = Path.Combine(fixtures,fixture+".dd");
        if (!privateImage) return source;
        string image = Path.Combine(root,"owned.dd"); File.Copy(source,image);
        File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly); return image;
    }
    static bool Same(object left,object right)
    {
        var a = left as Dictionary<string,object>; var b = right as Dictionary<string,object>;
        if (a != null || b != null) return a != null && b != null && a.Count == b.Count && a.All(row => b.ContainsKey(row.Key) && Same(row.Value,b[row.Key]));
        var x = left as object[]; var y = right as object[];
        if (x != null || y != null) return x != null && y != null && x.Length == y.Length && x.Select((value,index) => Same(value,y[index])).All(value => value);
        return Object.Equals(left,right);
    }
    static Result Run(string image,string root,string sha,CancellationToken token,Action<string> progress,
        IEnumerable<long> offsets = null,Ext4Recovery.Limits supplied = null,string change = null)
    {
        using (var input = new Source(image,root)) {
            object c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            var limits = supplied ?? new Ext4Recovery.Limits(); if (change == "limits") limits.MaximumNames--;
            Set(c,"Input",input); Set(c,"Root",Path.Combine(root,change == "root" ? "other" : "ext4")); Set(c,"Cancel",token); Set(c,"Limits",limits);
            object context = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
            Set(context,"Directory",root); Set(context,"Method","ext4"); Set(context,"SourceSha256",sha); Set(context,"Settings","owned-whole-engine-v1");
            Set(context,"Resume",Anchor(root)); Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(root,a)));
            reads = input.Reads;
            Action<string> notify = m => {
                if (change == "zero" && m == "ext4: volume 0 initialize complete") input.ZeroNext = true;
                if (change == "mid-limits") limits.MaximumNames--;
                if (progress != null) progress(m);
            };
            int found;
            try { found = (int)typeof(Ext4Recovery).GetMethod("RecoverCheckpointedCore",Private).Invoke(null,new[] { c,context,offsets,notify }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            return new Result { Files = found, Report = (Ext4Recovery.Report)c.GetType().GetField("Report").GetValue(c), Reads = input.Reads };
        }
    }
    static Ext4Recovery.Report Reference(string image,IEnumerable<long> offsets = null,Ext4Recovery.Limits limits = null)
    {
        string root = Path.Combine(work,"reference-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        Ext4Recovery.Recover(image,root,CancellationToken.None,null,offsets,limits);
        return Json.Deserialize<Ext4Recovery.Report>(File.ReadAllText(Path.Combine(root,"ext4","report.json"),Encoding.UTF8));
    }
    static void Compare(string image,string root,string sha,Result result,Ext4Recovery.Report expected)
    {
        Check(Same(Json.DeserializeObject(Json.Serialize(result.Report)),Json.DeserializeObject(Json.Serialize(expected))),"whole-engine report matches the independent unchanged legacy flow, including all fields and diagnostics");
        var published = Json.Deserialize<Ext4Recovery.Report>(File.ReadAllText(Path.Combine(root,"ext4","report.json"),Encoding.UTF8));
        Check(Same(Json.DeserializeObject(Json.Serialize(result.Report)),Json.DeserializeObject(Json.Serialize(published))),"returned and atomically published reports agree");
        foreach (var entry in published.Entries.Where(x => x.Output != null)) {
            string file = Path.Combine(root,"ext4",entry.Output.Replace('/',Path.DirectorySeparatorChar));
            Check(new FileInfo(file).Length == entry.RecoveredBytes && Hash(file) == entry.Sha256,"every recovered payload matches its recorded size and whole SHA");
        }
        Check(Hash(image) == sha && Convert.ToInt32(State(root)["Phase"]) == 3 && result.Files == published.RecoveredFiles,"source preserved, engine completed explicitly and counters agree");
    }
    static void Complete(string image,string root,string sha,IEnumerable<long> offsets = null,Ext4Recovery.Limits limits = null)
    {
        var expected = Reference(image,offsets,limits);
        var result = Run(image,root,sha,CancellationToken.None,null,offsets,limits); Compare(image,root,sha,result,expected);
        string parent = Hash(Parent(root));
        var repeat = Run(image,root,sha,CancellationToken.None,m => { throw new Exception("completed engine restarted: "+m); },offsets,limits);
        Compare(image,root,sha,repeat,expected);
        Check(repeat.Reads.Count == 0 && Hash(Parent(root)) == parent,"completed whole engine does no source-phase reads and never advances the parent");
    }
    static bool Match(string message,string phase)
    {
        if (phase == "discovery") return message.StartsWith("ext4: partition metadata ",StringComparison.Ordinal);
        if (phase == "initialize") return message.StartsWith("ext4: groups ",StringComparison.Ordinal);
        if (phase == "inodes") return message.StartsWith("ext4: inode ",StringComparison.Ordinal);
        if (phase == "history") return message.StartsWith("ext4: journal headers ",StringComparison.Ordinal);
        if (phase == "names") return message.StartsWith("ext4: directory metadata unit ",StringComparison.Ordinal);
        if (phase == "copy") return message.StartsWith("ext4: file bytes ",StringComparison.Ordinal);
        if (phase == "volume") return message.StartsWith("ext4: finished volume ",StringComparison.Ordinal);
        return message == "ext4: "+phase;
    }
    static void CancelResume(string phase)
    {
        string root,image = Image("cancel-"+phase,out root,"native-journal-v3-history"),sha = Hash(image); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (Match(m,phase)) cancel.Cancel(); }); } catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Anchor(root) != null,"cancel at "+phase+" leaves a real pinned internal cursor"); Complete(image,root,sha);
    }
    static void Corpus()
    {
        foreach (string fixture in Directory.GetFiles(fixtures,"*.dd").Select(Path.GetFileNameWithoutExtension)) {
            string root,image = Image("corpus",out root,fixture),sha = Hash(image); Complete(image,root,sha);
        }
    }
    static void ParentFailure(string phase)
    {
        string root,image = Image("parent",out root),sha = Hash(image),prior = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held == null && Match(m,phase)) { prior = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && prior != null && Hash(Parent(root)) == prior,"actual root parent replacement denial at "+phase+" preserves its acknowledged child graph");
        var result = Run(image,root,sha,CancellationToken.None,null);
        if (phase == "reports pending" || phase == "report ready") Check(result.Reads.Count == 0,"retry after a report parent failure never rereads discovery, metadata or payload source ranges");
        Compare(image,root,sha,result,Reference(image)); Complete(image,root,sha);
    }
    static void SourceFailure(bool zero)
    {
        string root,image = Image("source-io",out root, privateImage: true),sha = Hash(image); bool failed = false; FileStream held = null;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (!zero && held == null && m == "ext4: volume 0 initialize complete")
            { held = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read); held.Lock(0,held.Length); }
        },null,null,zero ? "zero" : null); } catch (IOException) { failed = true; }
        finally { if (held != null) { held.Unlock(0,held.Length); held.Dispose(); } }
        var active = (Dictionary<string,object>)State(root)["Active"];
        Check(failed && Convert.ToInt32(active["Phase"]) == 1 && !File.Exists(Path.Combine(root,"ext4","report.json")),
            (zero ? "short read" : "actual OS source read lock")+" remains an incomplete inode scan");
        Complete(image,root,sha);
    }
    static void ReportRenameFailure()
    {
        string root,image = Image("report-rename",out root),sha = Hash(image),prior = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held == null && m == "ext4: report ready") {
                prior = Hash(Parent(root)); var report = (Dictionary<string,object>)State(root)["Report"];
                string anchor = Path.Combine(root,(string)report["Path"]),workId = (string)Payload(anchor)["WorkId"];
                held = new FileStream(Path.Combine(Path.GetDirectoryName(anchor),"report-work",workId+".partial"),FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
            }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && prior != null && Hash(Parent(root)) == prior && Convert.ToInt32(State(root)["Phase"]) == 2,
            "actual report rename denial preserves ReportsPending and its ready file");
        var result = Run(image,root,sha,CancellationToken.None,null); Check(result.Reads.Count == 0,"report rename retry performs zero source-phase reads");
        Compare(image,root,sha,result,Reference(image));
    }
    static void CancelAt(string image,string root,string sha,string phase)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (Match(m,phase)) cancel.Cancel(); }); } catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Anchor(root) != null,"test setup stops at the acknowledged "+phase+" cursor");
    }
    static void RepairOutput()
    {
        string root,image = Image("repair-output",out root),sha = Hash(image); var initial = Run(image,root,sha,CancellationToken.None,null);
        string path = Path.Combine(root,"ext4",initial.Report.Entries.Single(e => e.Output != null).Output.Replace('/',Path.DirectorySeparatorChar));
        string payload = Hash(path),report = Hash(Path.Combine(root,"ext4","report.json")); File.Delete(path);
        CancelAt(image,root,sha,"copy");
        Check(Convert.ToInt32(State(root)["Phase"]) == 3 && !File.Exists(path),"missing finished output repair has a durable child cursor while immutable volume facts stay closed");
        var result = Run(image,root,sha,CancellationToken.None,null); Compare(image,root,sha,result,Reference(image));
        Check(Hash(path) == payload && Hash(Path.Combine(root,"ext4","report.json")) == report,"repaired bytes and report are identical without mutating a finished volume fact");
        Complete(image,root,sha);
        File.Delete(Path.Combine(root,"ext4","report.json"));
        var restored = Run(image,root,sha,CancellationToken.None,null);
        Check(restored.Reads.Count == 0 && Hash(Path.Combine(root,"ext4","report.json")) == report,"missing final report is rebuilt from verified facts without rereading source phases");
    }
    static void Flip(string file)
    {
        using (var input = new FileStream(file,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
        { input.Position = input.Length-1; int value = input.ReadByte(); input.Position--; input.WriteByte((byte)(value^1)); }
    }
    static void Tamper(string kind)
    {
        string root,image = Image("tamper-"+kind,out root, privateImage: kind == "source"),sha = Hash(image); CancelAt(image,root,sha,"reports pending");
        string target = kind == "source" ? image : Anchor(root).Path;
        if (kind == "output") target = RecoveryCore.RecoveredFiles(root).Single();
        if (kind == "ledger") target = Path.Combine(root,(string)((Dictionary<string,object>)State(root)["Finished"])["Path"]);
        if (kind == "source" || kind == "state" || kind == "output" || kind == "ledger") Flip(target);
        else {
            var envelope = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target,Encoding.UTF8));
            var state = (Dictionary<string,object>)envelope["Payload"];
            if (kind == "cursor") state["NextLocation"] = Convert.ToInt32(state["NextLocation"])+1;
            if (kind == "phase") { state["Phase"] = 3; state["Report"] = null; }
            if (kind == "report") state["ReportIdentity"] = new string('0',64);
            if (kind == "export") ((Dictionary<string,object>)state["Exports"]).Clear();
            if (kind == "outcome") {
                var head = (Dictionary<string,object>)state["Finished"]; string pagePath = Path.Combine(root,(string)head["Path"]);
                var page = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(pagePath,Encoding.UTF8));
                ((Dictionary<string,object>)((System.Collections.IList)page["Records"])[0])["Outcome"] = new string('0',64);
                File.WriteAllText(pagePath,Json.Serialize(page),new UTF8Encoding(false)); head["Sha256"] = Hash(pagePath);
            }
            File.WriteAllText(target,Json.Serialize(envelope),new UTF8Encoding(false)); var anchor = Anchor(root); anchor.Sha256 = Hash(target); SaveAnchor(root,anchor);
        }
        string before = Hash(Parent(root)),changed = Hash(target); bool denied = false;
        try { Run(image,root,sha,CancellationToken.None,null); } catch (IOException) { denied = true; }
        Check(denied && Hash(Parent(root)) == before && Hash(target) == changed,"changed "+kind+" is refused without overwriting data or the parent");
    }
    static void WriteReadMap(string root,string image)
    { File.WriteAllText(Path.Combine(root,"source-read-errors.json"),Json.Serialize(new { size = new FileInfo(image).Length, copied = new FileInfo(image).Length, status = "complete", unreadBytes = 0, ranges = new object[0] }),Encoding.UTF8); }
    static void BindingsAndMaps()
    {
        foreach (string kind in new[] { "limits","root","offsets","map" }) {
            string root,image = Image("binding",out root),sha = Hash(image); CancelAt(image,root,sha,"reports pending");
            if (kind == "map") WriteReadMap(root,image);
            string prior = Hash(Parent(root)); bool denied = false;
            try { Run(image,root,sha,CancellationToken.None,null,kind == "offsets" ? new long[] { 0 } : null,null,kind); } catch (IOException) { denied = true; }
            Check(denied && reads.Count == 0 && Hash(Parent(root)) == prior,"changed "+kind+" cannot resume an earlier complete scan");
        }
        string mapRoot,mapImage = Image("map-create",out mapRoot),mapSha = Hash(mapImage); bool stopped = false;
        try { Run(mapImage,mapRoot,mapSha,CancellationToken.None,m => { if (m == "ext4: reports pending") WriteReadMap(mapRoot,mapImage); }); } catch (IOException) { stopped = true; }
        Check(stopped && Convert.ToInt32(State(mapRoot)["Phase"]) == 2 && !File.Exists(Path.Combine(mapRoot,"ext4","report.json")),"a new read map during the operation prevents report publication");
        File.Delete(Path.Combine(mapRoot,"source-read-errors.json")); Complete(mapImage,mapRoot,mapSha);
        string leaseRoot,leaseImage = Image("map-lease",out leaseRoot),leaseSha = Hash(leaseImage); WriteReadMap(leaseRoot,leaseImage); string map = Path.Combine(leaseRoot,"source-read-errors.json"),before = Hash(map); bool blocked = false;
        Run(leaseImage,leaseRoot,leaseSha,CancellationToken.None,m => {
            if (m == "ext4: reports pending") {
                try { using (var writer = new FileStream(map,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)) { writer.WriteByte(7); } } catch (IOException) { blocked = true; }
            }
        }); Check(blocked && Hash(map) == before,"read-map lease denies concurrent modification throughout the operation");
    }
    static void MultiVolume()
    {
        string root = Path.Combine(work,"multi-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root,"owned.dd"),fixture = Path.Combine(fixtures,"extent-deleted.dd"); long second = new FileInfo(fixture).Length+8192;
        using (var output = new FileStream(image,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
            output.Position = 4096; using (var input = File.OpenRead(fixture)) input.CopyTo(output);
            output.Position = second; using (var input = File.OpenRead(fixture)) input.CopyTo(output);
        }
        var offsets = new long[] { 0,4096,second,1,-512,4096 }; string sha = Hash(image); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => {
                if (m.StartsWith("ext4: inode ",StringComparison.Ordinal) && Convert.ToInt32(State(root)["NextLocation"]) == 2) cancel.Cancel();
            },offsets); } catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Convert.ToInt32(State(root)["NextLocation"]) == 2,"multi-volume cancellation preserves completed earlier volumes and global budgets");
        var result = Run(image,root,sha,CancellationToken.None,null,offsets); Compare(image,root,sha,result,Reference(image,offsets));
        Check(result.Reads.All(row => row.At >= second) && result.Report.RecoveredFiles == 2,"multi-volume resume reads only the unfinished volume and counts each payload once");
        Complete(image,root,sha,offsets);
        string limited = Path.Combine(work,"multi-limit-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(limited);
        Complete(image,limited,sha,offsets,new Ext4Recovery.Limits { MaximumVolumes = 1 });
    }
    static void Relocated()
    {
        string root,image = Image("relocate",out root, privateImage: true),sha = Hash(image); CancelAt(image,root,sha,"reports pending"); var anchor = Anchor(root);
        string destination = Path.Combine(work,"moved-"+Guid.NewGuid().ToString("N")),prefix = Path.GetFullPath(work)+Path.DirectorySeparatorChar;
        Check(Path.GetFullPath(root).StartsWith(prefix,StringComparison.OrdinalIgnoreCase) && Path.GetFullPath(destination).StartsWith(prefix,StringComparison.OrdinalIgnoreCase) && !Directory.Exists(destination),"recursive move is limited to unique owned paths under the verified workspace");
        Directory.Move(root,destination); anchor.Path = Path.Combine(destination,"ext4.state",Path.GetFileName(anchor.Path)); SaveAnchor(destination,anchor);
        var result = Run(Path.Combine(destination,"owned.dd"),destination,sha,CancellationToken.None,null);
        Check(result.Reads.Count == 0,"relocated report-pending operation retains all relative metadata and export links"); Complete(Path.Combine(destination,"owned.dd"),destination,sha);
    }
    static void Put32(byte[] bytes,int at,uint value) { Buffer.BlockCopy(BitConverter.GetBytes(value),0,bytes,at,4); }
    static void Put64(byte[] bytes,int at,ulong value) { Buffer.BlockCopy(BitConverter.GetBytes(value),0,bytes,at,8); }
    // GPT structures are supplied address-discovery controls. Their CRC is not
    // a filesystem authenticity claim; each candidate still needs an ext4 SB.
    static void Discovery(bool wide)
    {
        string root = Path.Combine(work,"gpt-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); string image = Path.Combine(root,"owned.dd");
        int size = wide ? 4096 : 128,count = wide ? 33 : 1300;
        using (var output = new FileStream(image,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
            output.SetLength(4*1024*1024); byte[] mbr = new byte[512],gpt = new byte[512]; mbr[510] = 0x55; mbr[511] = 0xaa;
            Put32(mbr,454,1); Buffer.BlockCopy(Encoding.ASCII.GetBytes("EFI PART"),0,gpt,0,8); Put64(gpt,72,2); Put32(gpt,80,(uint)count); Put32(gpt,84,(uint)size);
            output.Write(mbr,0,mbr.Length); output.Write(gpt,0,gpt.Length);
            foreach (int index in new[] { 3,count-1 }) { byte[] entry = new byte[size]; entry[0] = 1; Put64(entry,32,index == 3 ? 2048UL : 4096UL); output.Position = 1024+(long)index*size; output.Write(entry,0,entry.Length); }
        }
        string sha = Hash(image); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => {
                if (!m.StartsWith("ext4: partition metadata ",StringComparison.Ordinal)) return;
                var discovery = (Dictionary<string,object>)State(root)["Discovery"];
                if (Convert.ToInt32(Payload(Path.Combine(root,(string)discovery["Path"]))["Next"]) > 0) cancel.Cancel();
            }); } catch (OperationCanceledException) { stopped = true; }
        }
        var prefix = reads.Where(row => row.Phase == 0).ToArray();
        Check(stopped && prefix.Any(row => row.Bytes == 64*1024),"GPT discovery cancellation pins an actual bounded table batch");
        var resumed = Run(image,root,sha,CancellationToken.None,null); Compare(image,root,sha,resumed,Reference(image));
        Check(!resumed.Reads.Where(row => row.Phase == 0).Any(row => prefix.Any(old => old.At < row.At+row.Bytes && row.At < old.At+old.Bytes)),"GPT continuation never rereads its acknowledged header or entry batch");
        Complete(image,root,sha);
        foreach (int bytes in new[] { 10,600 }) {
            string tinyRoot = Path.Combine(work,"short-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(tinyRoot);
            string tiny = Path.Combine(tinyRoot,"owned.dd"); byte[] data = new byte[bytes]; if (bytes > 512) { data[510] = 0x55; data[511] = 0xaa; }
            File.WriteAllBytes(tiny,data); Complete(tiny,tinyRoot,Hash(tiny));
        }
    }
    static void ChecksumCasing()
    {
        string root,image = Image("uppercase-sha",out root),sha = Hash(image);
        var result = Run(image,root,sha.ToUpperInvariant(),CancellationToken.None,null);
        Compare(image,root,sha,result,Reference(image));
        Check(result.Report.SourceSha256 == sha,"an uppercase supplied checksum is normalized without changing the source identity");
        Complete(image,root,sha);
    }
    static void KilledWorker(string phase)
    {
        string root,image = Image("worker",out root),sha = Hash(image),signal = Path.Combine(root,"ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+image+"\" \""+root+"\" \""+signal+"\" \""+phase+"\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(signal) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(signal),"owned worker reaches the acknowledged "+phase+" point"); child.Kill(); Check(child.WaitForExit(10000),"owned engine worker terminates without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Complete(image,root,sha);
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("RecoverCheckpointedCore",Private) == null) { Console.WriteLine("FAIL: baseline lacks a checkpointed whole ext4 engine"); return 1; }
            if (args.Length == 5 && args[0] == "--worker") {
                Run(args[1],args[2],Hash(args[1]),CancellationToken.None,m => { if (Match(m,args[4])) { File.WriteAllText(args[3],m); Thread.Sleep(Timeout.Infinite); } }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]),".build","ext4-engine-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            if (args.Contains("--uppercase-only")) { ChecksumCasing(); Console.WriteLine("PASS Ext4EngineChecksumCasing: "+checks+" checks"); return 0; }
            if (!args.Contains("--failure-only")) {
                foreach (string phase in new[] { "discovery","initialize","inodes","history","names","copy","volume","reports pending","report pending","report ready","report published","engine complete" }) CancelResume(phase);
                Corpus();
            }
            ParentFailure("copy"); ParentFailure("reports pending"); ParentFailure("report ready"); SourceFailure(false); SourceFailure(true); ReportRenameFailure(); RepairOutput();
            foreach (string kind in new[] { "source","state","output","ledger","cursor","phase","report","export","outcome" }) Tamper(kind);
            BindingsAndMaps(); MultiVolume(); Relocated(); Discovery(false); Discovery(true); ChecksumCasing(); KilledWorker("copy"); KilledWorker("reports pending");
            Console.WriteLine("PASS Ext4EngineCheckpoint: "+checks+" checks; full managed engine, not RecoverySession/offline package or real devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
