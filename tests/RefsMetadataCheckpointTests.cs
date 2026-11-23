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

// Durable raw-read ordering and actual ReFS anchor parsing. This is a metadata
// component, not whole-engine/output-copy/RecoverySession acceptance.
public static class RefsMetadataCheckpointTests
{
    static int checks;
    static string work,fixtures;
    static long volumeOffset;
    static List<Tuple<long,int>> reads;
    static readonly List<string> leafRows = new List<string>();
    static Dictionary<ulong,ulong> containers;
    static object activeGeometry;
    static bool collectingContainers;
    static readonly BindingFlags Private = BindingFlags.NonPublic|BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024*1024 };
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static void Set(object owner,string field,object value) { owner.GetType().GetField(field).SetValue(owner,value); }
    static object Get(object owner,string field) { return owner.GetType().GetField(field).GetValue(owner); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b) => { }); }
    static object Call(string name,params object[] values)
    { try { return typeof(RefsRecovery).GetMethod(name,Private).Invoke(null,values); } catch (TargetInvocationException error) { throw error.InnerException; } }
    static void Collect<T>(List<T> records)
    {
        foreach (object record in records) {
            byte[] key = (byte[])Get(record,"KeyData"),value = (byte[])Get(record,"ValueData");
            using (var hash = System.Security.Cryptography.SHA256.Create())
                leafRows.Add(BitConverter.ToString(hash.ComputeHash(key))+":"+BitConverter.ToString(hash.ComputeHash(value))+":"+Get(record,"MetadataChecksumVerified"));
            if (collectingContainers && key.Length >= 8 && value.Length >= 160) {
                ulong id = BitConverter.ToUInt64(key,0),physical = BitConverter.ToUInt64(value,value.Length-16),size = BitConverter.ToUInt32(value,24);
                if (size != 0 && (size&(size-1)) == 0) Set(activeGeometry,"ContainerSize",size);
                containers[id] = physical;
            }
        }
    }
    static void Tree(object c,object geometry,object reference,bool physical,HashSet<ulong> visited)
    {
        if ((ulong)Get(reference,"BlockNumber") == 0) return;
        Type row = typeof(RefsRecovery).GetNestedType("MinistoreNodeRecord",BindingFlags.NonPublic);
        Type list = typeof(List<>).MakeGenericType(row),action = typeof(Action<>).MakeGenericType(list);
        var method = typeof(RefsMetadataCheckpointTests).GetMethod("Collect",BindingFlags.NonPublic|BindingFlags.Static).MakeGenericMethod(row);
        Delegate collect = Delegate.CreateDelegate(action,method);
        try { typeof(RefsRecovery).GetMethods(Private).Single(x => x.Name == "TraverseBTree" && x.GetParameters().Length == 7)
            .Invoke(null,new object[] { c,geometry,reference,visited,0,collect,physical }); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long,int>> Reads = new List<Tuple<long,int>>();
        public Source(string image) : base(image,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1) { }
        public override int Read(byte[] bytes,int offset,int count) { Reads.Add(Tuple.Create(Position,count)); return ZeroNext ? 0 : base.Read(bytes,offset,count); }
    }
    static string Parent(string root) { return Path.Combine(root,"anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)) : null; }
    static void SaveAnchor(string root,RecoveryMethodCheckpoint anchor)
    {
        string temp = Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(anchor));
            using (var file = new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temp,Parent(root),null); else File.Move(temp,Parent(root));
        } finally { if (own && File.Exists(temp)) File.Delete(temp); }
    }
    static Dictionary<string,object> State(string root)
    {
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256,"caller pins the exact ReFS metadata generation");
        return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(anchor.Path,Encoding.UTF8))["Payload"];
    }
    static string Image(string label,out string root,string fixture = null)
    {
        root = Path.Combine(work,label+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); string image = Path.Combine(root,"owned.dd");
        if (fixture != null) { File.Copy(Path.Combine(fixtures,fixture+".dd"),image); File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly); }
        else {
            byte[] bytes = new byte[3*1024*1024]; uint value = 0x2468ace1;
            for (int i = 0; i < bytes.Length; i++) { value ^= value<<13; value ^= value>>17; value ^= value<<5; bytes[i] = (byte)value; }
            File.WriteAllBytes(image,bytes);
        }
        return image;
    }
    static object Context(Source input,string root,CancellationToken token,RefsRecovery.Limits limits)
    {
        object c = Activator.CreateInstance(typeof(RefsRecovery).GetNestedType("Context",BindingFlags.NonPublic),true);
        Set(c,"Input",input); Set(c,"Root",Path.Combine(root,"refs")); Set(c,"Cancel",token); Set(c,"Limits",limits); Set(c,"Report",new RefsRecovery.Report()); return c;
    }
    static string Exercise(object c,string change,bool native)
    {
        if (native) {
            collectingContainers = false;
            object geometry = Call("ReadVbr",c,volumeOffset); Check(geometry != null,"fixture/native VBR parses through the real ReFS read path at its declared volume offset");
            object super = Call("ReadSuperblock",c,geometry); if (super == null) return "no-super";
            object first = Call("ReadCheckpoint",c,geometry,Get(super,"PrimaryCheckpoint"),0);
            object second = Call("ReadCheckpoint",c,geometry,Get(super,"SecondaryCheckpoint"),1);
            object selected = first == null ? second : second == null || (ulong)Get(first,"SequenceClock") >= (ulong)Get(second,"SequenceClock") ? first : second;
            leafRows.Clear(); containers = new Dictionary<ulong,ulong>(); activeGeometry = geometry;
            var visited = new HashSet<ulong> { 30 };
            if (selected != null) {
                collectingContainers = true; Set(geometry,"ContainerMap",null);
                if ((byte)Get(geometry,"MajorVersion") >= 3) Tree(c,geometry,Get(selected,"Tree7Root"),true,visited);
                collectingContainers = false; Set(geometry,"ContainerMap",containers);
                Tree(c,geometry,Get(selected,"Tree0Root"),false,visited);
            }
            return Json.Serialize(new { Version = Get(geometry,"MajorVersion"), Minor = Get(geometry,"MinorVersion"),
                Super = Get(super,"SequenceNumber"), First = first == null ? null : Get(first,"SequenceClock"), Second = second == null ? null : Get(second,"SequenceClock"),
                Leaves = leafRows.ToArray(), Skipped = ((RefsRecovery.Report)Get(c,"Report")).Skipped.OrderBy(x => x.Key).ToArray() });
        }
        using (var hash = System.Security.Cryptography.SHA256.Create()) using (var output = new MemoryStream()) {
            foreach (var request in new[] { Tuple.Create(change == "order" ? 8193L : 8192L,200000),Tuple.Create(1024L*1024,512),Tuple.Create(8192L,200000) }) {
                byte[] bytes = (byte[])Call("Read",c,request.Item1,request.Item2); output.Write(bytes,0,bytes.Length);
            }
            Check(Call("Read",c,-1L,10) == null && Call("Read",c,Int64.MaxValue,10) == null,"out-of-image metadata ranges remain absent without zero padding");
            return BitConverter.ToString(hash.ComputeHash(output.ToArray()));
        }
    }
    static string Run(string image,string root,string sha,CancellationToken token,Action<string> progress,string change = null,bool native = false,bool durable = true)
    {
        using (var input = new Source(image)) {
            var limits = new RefsRecovery.Limits(); if (change == "limits") limits.MaximumEntries--;
            object c = Context(input,root,token,limits); reads = input.Reads;
            if (!durable) return Exercise(c,change,native);
            object context = Activator.CreateInstance(typeof(RefsRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
            Set(context,"Directory",root); Set(context,"Method","refs"); Set(context,"SourceSha256",sha); Set(context,"Settings","owned-refs-metadata-v1");
            Set(context,"Resume",Anchor(root)); Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(root,a)));
            Action<string> notify = m => { if (change == "zero") input.ZeroNext = true; if (change == "mid-limits") limits.MaximumEntries--; if (progress != null) progress(m); };
            object checkpoint;
            try { checkpoint = Activator.CreateInstance(typeof(RefsRecovery).GetNestedType("MetadataReadCheckpoint",BindingFlags.NonPublic),new[] { c,context,notify }); }
            catch (TargetInvocationException error) { throw error.InnerException; }
            using ((IDisposable)checkpoint) {
                string result = Exercise(c,change,native);
                try { checkpoint.GetType().GetMethod("Finish").Invoke(checkpoint,null); } catch (TargetInvocationException error) { throw error.InnerException; }
                return result;
            }
        }
    }
    static List<Tuple<long,int>> Cancel(string image,string root,string sha)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => cancel.Cancel()); } catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && Convert.ToInt32(State(root)["Next"]) == 1 && !(bool)State(root)["Complete"],"cancel preserves a true64KiB position inside a larger metadata request"); return reads.ToList();
    }
    static void Complete(string image,string root,string sha,List<Tuple<long,int>> prefix = null,bool native = false)
    {
        string value = Run(image,root,sha,CancellationToken.None,null,null,native); var actual = reads.ToArray();
        string expected = Run(image,root,sha,CancellationToken.None,null,null,native,false);
        Check(value == expected,"cached metadata bytes and actual parser verdict match independent uninterrupted reads");
        // Repeated source addresses are legitimate separate parser requests.
        // Only the very first physical64KiB unit is pinned by Cancel().
        if (prefix != null) Check(actual.Count(row => row.Item1 == prefix[0].Item1 && row.Item2 == prefix[0].Item2) == 1,
            "resume skips the first acknowledged unit but still performs the later intentional repeated request");
        Check(Run(image,root,sha,CancellationToken.None,m => { throw new Exception("completed metadata trace restarted"); },null,native) == value && reads.Count == 0,
            "completed metadata trace is replayed with zero source-phase reads");
        Check((bool)State(root)["Complete"] && Hash(image) == sha,"metadata trace closes explicitly and leaves source unchanged");
    }
    static void ParentFailure()
    {
        string root,image = Image("parent",out root),sha = Hash(image),before = null; FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => { if (held == null) { before = Hash(Parent(root)); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); } }); }
        catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && before != null && Hash(Parent(root)) == before,"actual parent replacement denial cannot advance the acknowledged metadata cursor"); Complete(image,root,sha);
    }
    static void IoFailure(bool zero)
    {
        string root,image = Image("read",out root),sha = Hash(image); FileStream held = null; bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (!zero && held == null) { held = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read); held.Lock(0,held.Length); }
        },zero ? "zero" : null); } catch (IOException) { failed = true; }
        finally { if (held != null) { held.Unlock(0,held.Length); held.Dispose(); } }
        Check(failed && Convert.ToInt32(State(root)["Next"]) == 1,"actual lock/short read is not accepted as absent metadata"); Complete(image,root,sha);
    }
    static void Tamper(string kind)
    {
        string root,image = Image("tamper",out root),sha = Hash(image); Cancel(image,root,sha);
        string target = kind == "source" ? image : kind == "blob" ? Directory.GetFiles(Path.Combine(root,"refs.state","metadata-blobs"),"blob-*.json").Single() : Anchor(root).Path;
        if (kind == "cursor" || kind == "phase") {
            var envelope = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target,Encoding.UTF8)); var payload = (Dictionary<string,object>)envelope["Payload"];
            if (kind == "cursor") payload["Next"] = 0; else payload["Complete"] = true;
            File.WriteAllText(target,Json.Serialize(envelope),new UTF8Encoding(false)); var anchor = Anchor(root); anchor.Sha256 = Hash(target); SaveAnchor(root,anchor);
        } else File.AppendAllText(target,"changed");
        string parent = Hash(Parent(root)),changed = Hash(target); bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,null); } catch (IOException) { failed = true; }
        Check(failed && Hash(Parent(root)) == parent && Hash(target) == changed,"changed "+kind+" is refused without overwriting evidence");
    }
    static void Bindings()
    {
        foreach (string kind in new[] { "order","limits" }) {
            string root,image = Image("binding",out root),sha = Hash(image); Cancel(image,root,sha); string before = Hash(Parent(root)); bool denied = false;
            try { Run(image,root,sha,CancellationToken.None,null,kind); } catch (IOException) { denied = true; }
            Check(denied && reads.Count == 0 && Hash(Parent(root)) == before,"different "+kind+" cannot reuse a metadata trace");
        }
        string midRoot,midImage = Image("mid-limits",out midRoot),midSha = Hash(midImage); bool failed = false;
        try { Run(midImage,midRoot,midSha,CancellationToken.None,null,"mid-limits"); } catch (IOException) { failed = true; }
        Check(failed && !(bool)State(midRoot)["Complete"],"limits changed during metadata capture cannot advance completion");
    }
    static void KilledWorker()
    {
        string root,image = Image("worker",out root),sha = Hash(image),signal = Path.Combine(root,"ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+image+"\" \""+root+"\" \""+signal+"\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(signal) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(signal),"owned worker reaches a captured metadata unit"); child.Kill(); Check(child.WaitForExit(10000),"owned metadata worker terminates without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Complete(image,root,sha);
    }
    static void TreeContinuation()
    {
        string root,image = Image("tree-cancel",out root,"refs-container"),sha = Hash(image); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (collectingContainers) cancel.Cancel(); },null,true); }
            catch (OperationCanceledException) { stopped = true; }
        }
        var prefix = reads.ToArray(); Check(stopped && prefix.Length > 3,"cancel reaches an actual container B+ tree after VBR/checkpoint parsing");
        string reference = Run(image,root,sha,CancellationToken.None,null,null,true,false); var all = reads.ToArray();
        string result = Run(image,root,sha,CancellationToken.None,null,null,true); var suffix = reads.ToArray();
        Check(result == reference && prefix.SequenceEqual(all.Take(prefix.Length)) && suffix.SequenceEqual(all.Skip(prefix.Length)),
            "real container/object tree continuation skips exactly the acknowledged physical read prefix and preserves leaf hashes and diagnostics");
        Complete(image,root,sha,null,true);
    }
    static void NativeVolume(string image)
    {
        volumeOffset = 16777216;
        string expected = "246d3c2f969ff6a67d6a9879723de50c20152b0e11d61034e38c4c7851c24ffc";
        Check(new FileInfo(image).Length == 8589934592L && (File.GetAttributes(image)&FileAttributes.SparseFile) == 0,
            "native anchor/tree control uses the existing fully materialized8GiB image");
        Check(Hash(image) == expected,"independent native image matches the pinned source digest before parsing");
        string root = Path.Combine(work,"native-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,expected,cancel.Token,m => { if (collectingContainers) cancel.Cancel(); },null,true); }
            catch (OperationCanceledException) { stopped = true; }
        }
        var prefix = reads.ToArray(); Check(stopped,"native ReFS container-map parsing stops at a real acknowledged read");
        string reference = Run(image,root,expected,CancellationToken.None,null,null,true,false); var all = reads.ToArray();
        string result = Run(image,root,expected,CancellationToken.None,null,null,true); var suffix = reads.ToArray();
        Check(result == reference && prefix.SequenceEqual(all.Take(prefix.Length)) && suffix.SequenceEqual(all.Skip(prefix.Length)),
            "native metadata continuation preserves the parser verdict and skips the exact acknowledged physical prefix");
        Check(Run(image,root,expected,CancellationToken.None,m => { throw new Exception("native metadata restarted"); },null,true) == reference && reads.Count == 0,
            "completed native anchor/container/object-tree trace requires zero source-phase reads");
        Check(Hash(image) == expected,"native metadata controls preserve source bytes; no full-volume file-recovery claim");
        volumeOffset = 0;
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(RefsRecovery).GetNestedType("MetadataReadCheckpoint",BindingFlags.NonPublic) == null) { Console.WriteLine("FAIL: baseline lacks a ReFS metadata cursor"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1],args[2],Hash(args[1]),CancellationToken.None,m => { File.WriteAllText(args[3],m); Thread.Sleep(Timeout.Infinite); }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]),".build","refs-metadata-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            string root,image = Image("cancel",out root),sha = Hash(image); Complete(image,root,sha,Cancel(image,root,sha));
            ParentFailure(); IoFailure(false); IoFailure(true);
            foreach (string kind in new[] { "source","state","blob","cursor","phase" }) Tamper(kind);
            Bindings(); KilledWorker(); TreeContinuation();
            foreach (string path in Directory.GetFiles(fixtures,"*.dd")) { string nativeRoot,native = Image("anchors",out nativeRoot,Path.GetFileNameWithoutExtension(path)); Complete(native,nativeRoot,Hash(native),null,true); }
            int external = Array.IndexOf(args,"--native-image"); if (external >= 0) NativeVolume(Path.GetFullPath(args[external+1]));
            Console.WriteLine("PASS RefsMetadataCheckpoint: "+checks+" checks; raw metadata cursor and actual anchor parsing, not whole-engine resume or devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
