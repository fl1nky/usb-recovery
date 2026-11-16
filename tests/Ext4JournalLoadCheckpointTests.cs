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

public static class Ext4JournalLoadCheckpointTests
{
    static int checks;
    static string work,fixtures;
    static List<Tuple<long,int>> reads;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 1024*1024 };
    static void Check(bool value,string why) { checks++; if (!value) throw new Exception(why); }
    static object Get(object owner,string field) { return owner.GetType().GetField(field).GetValue(owner); }
    static void Set(object owner,string field,object value) { owner.GetType().GetField(field).SetValue(owner,value); }
    static string Hash(string path) { return RecoveryCore.HashFile(path,CancellationToken.None,(a,b) => { }); }
    static object Call(string name,params object[] args)
    { try { return typeof(Ext4Recovery).GetMethod(name,Private).Invoke(null,args); } catch (TargetInvocationException error) { throw error.InnerException; } }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long,int>> Reads = new List<Tuple<long,int>>();
        public Source(string file) : base(file,FileMode.Open,FileAccess.Read,FileShare.Read,1) { }
        public override int Read(byte[] bytes,int offset,int count) { Reads.Add(Tuple.Create(Position,count)); return ZeroNext ? 0 : base.Read(bytes,offset,count); }
    }
    static string Parent(string root) { return Path.Combine(root,"anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root)) ? Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)) : null; }
    static void SaveAnchor(string root,RecoveryMethodCheckpoint anchor)
    {
        string temporary = Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial"; bool own = false;
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(anchor));
            using (var file = new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own = true; file.Write(bytes,0,bytes.Length); file.Flush(true); }
            if (File.Exists(Parent(root))) File.Replace(temporary,Parent(root),null); else File.Move(temporary,Parent(root));
        } finally { if (own && File.Exists(temporary)) File.Delete(temporary); }
    }
    static Dictionary<string,object> State(string root)
    {
        var anchor = Anchor(root); Check(anchor != null && Hash(anchor.Path) == anchor.Sha256,"parent pins exact journal initialization state");
        return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(anchor.Path,Encoding.UTF8))["Payload"];
    }
    static string Image(string label,out string root,string fixture = "native-journal-v3-multiple-descriptors")
    {
        root = Path.Combine(work,label+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        string image = Path.Combine(root,"owned.dd"); File.Copy(Path.Combine(fixtures,fixture+".dd"),image);
        File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly); return image;
    }
    static string Snapshot(object journal,Ext4Recovery.Report report,Ext4Recovery.VolumeReport volume)
    {
        var fields = new SortedDictionary<string,object>(StringComparer.Ordinal);
        if (journal != null) foreach (var field in journal.GetType().GetFields()) if (field.Name != "Volume") fields.Add(field.Name,field.GetValue(journal));
        return Json.Serialize(new { Found = journal != null, Fields = fields, Limited = report.Limited,
            Skipped = report.Skipped.OrderBy(x => x.Key).ToArray(), Status = volume.JournalStatus, Unsupported = volume.UnsupportedFeatures });
    }
    static string Run(string image,string root,string sha,CancellationToken token,Action<string> progress,bool durable = true,string change = null)
    {
        using (var input = new Source(image)) {
            object c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            var report = new Ext4Recovery.Report(); report.Skipped.Add("prior_volume",3);
            var limits = new Ext4Recovery.Limits(); if (change == "limits") limits.MaximumTreeBlocks--;
            Set(c,"Input",input); Set(c,"Root",Path.Combine(root,"ext4")); Set(c,"Cancel",token); Set(c,"Limits",limits); Set(c,"Report",report);
            object v = Call("OpenVolumeHeader",c,0L); var vr = (Ext4Recovery.VolumeReport)Get(v,"Report");
            Check(vr.Status == "header_ready","native-format source header validates before journal initialization");
            var reserved = (IList)Activator.CreateInstance(Get(v,"Reserved").GetType()); foreach (var range in (IEnumerable)Get(v,"Reserved")) reserved.Add(range);
            Call("ReadGroups",c,v,(ulong)vr.Groups,(ulong)(uint)Get(v,"FirstData")+1,reserved);
            if (change == "groups") Set(((IList)Get(v,"Groups"))[0],"BlockMapValid",false);
            if (change == "baseline") report.Skipped["prior_volume"]++;
            object context = null;
            if (durable) {
                context = Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
                Set(context,"Directory",root); Set(context,"Method","ext4"); Set(context,"SourceSha256",sha); Set(context,"Settings","owned-journal-initialization-v1");
                Set(context,"Resume",Anchor(root)); Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a => SaveAnchor(root,a)));
            }
            input.Reads.Clear(); reads = input.Reads; if (change == "zero-first") input.ZeroNext = true;
            Action<string> notify = m => { if (change == "zero-next") input.ZeroNext = true; if (change == "mid-limits") limits.MaximumTreeBlocks--; if (progress != null) progress(m); };
            object result = durable ? Call("LoadJournalCheckpointed",c,v,context,notify) : Call("LoadJournal",c,v,Get(v,"Superblock"));
            return Snapshot(result,report,vr);
        }
    }
    static string Reference(string image,string sha)
    { string root = Path.Combine(work,"reference-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); return Run(image,root,sha,CancellationToken.None,null,false); }
    static List<Tuple<long,int>> Cancel(string image,string root,string sha,bool terminal = false)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (!terminal || m.EndsWith(" complete",StringComparison.Ordinal)) cancel.Cancel(); }); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && (bool)State(root)["Complete"] == terminal && Convert.ToInt32(State(root)["Next"]) > 0,"cancel retains an actual acknowledged journal initialization unit");
        return reads.ToList();
    }
    static void Complete(string image,string root,string sha,List<Tuple<long,int>> prefix = null)
    {
        string result = Run(image,root,sha,CancellationToken.None,null); var actual = reads.ToArray();
        Check(result == Reference(image,sha),"journal mapping, checksums, flags and diagnostics match the unchanged legacy parser");
        if (prefix != null) Check(!actual.Any(x => prefix.Any(p => p.Item1 < x.Item1+x.Item2 && x.Item1 < p.Item1+p.Item2)),"resumed mapping never rereads its acknowledged source-phase prefix");
        Check(Run(image,root,sha,CancellationToken.None,m => { throw new Exception("completed journal initialization restarted"); }) == result && reads.Count == 0,
            "completed initialization reconstructs its journal and verdict with zero phase source reads");
        Check((bool)State(root)["Complete"] && Hash(image) == sha,"journal initialization completes explicitly without changing the source");
    }
    static void ParentFailure()
    {
        string root,image = Image("parent",out root),sha = Hash(image),prior = null; FileStream held = null; bool failed = false; List<Tuple<long,int>> prefix = null;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (held == null) { prior = Hash(Parent(root)); prefix = reads.ToList(); held = new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read); }
        }); } catch (IOException) { failed = true; } finally { if (held != null) held.Dispose(); }
        Check(failed && prior != null && Hash(Parent(root)) == prior,"OS parent replacement denial never advances the initialization cursor"); Complete(image,root,sha,prefix);
    }
    static void ReadFailure(string kind)
    {
        string root,image = Image("read-failure",out root),sha = Hash(image); bool failed = false; FileStream held = null; List<Tuple<long,int>> prefix = null;
        try { Run(image,root,sha,CancellationToken.None,m => {
            if (prefix == null) { prefix = reads.ToList(); if (kind == "lock") { held = new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read); held.Lock(0,held.Length); } }
        },true,kind == "lock" ? null : "zero-next"); } catch (IOException) { failed = true; }
        finally { if (held != null) { held.Unlock(0,held.Length); held.Dispose(); } }
        Check(failed && prefix != null && !(bool)State(root)["Complete"],"actual "+kind+" read failure is not misreported as a missing journal"); Complete(image,root,sha,prefix);
    }
    static void Tamper(string kind)
    {
        string root,image = Image("tamper",out root),sha = Hash(image); Cancel(image,root,sha);
        string target = kind == "source" ? image : Anchor(root).Path;
        if (kind == "ledger") { var head = (Dictionary<string,object>)State(root)["Facts"]; target = Path.Combine(root,(string)head["Path"]); }
        if (kind == "blob") target = Directory.GetFiles(Path.Combine(root,"ext4.state","journal-blobs"),"blob-*.json").Single();
        if (kind == "cursor" || kind == "phase") {
            var envelope = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target,Encoding.UTF8)); var payload = (Dictionary<string,object>)envelope["Payload"];
            if (kind == "cursor") payload["Next"] = 0; else payload["Complete"] = true;
            File.WriteAllText(target,Json.Serialize(envelope),new UTF8Encoding(false)); var anchor = Anchor(root); anchor.Sha256 = Hash(target); SaveAnchor(root,anchor);
        } else using (var file = new FileStream(target,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) {
            file.Position = file.Length-1; int value = file.ReadByte(); file.Position--; file.WriteByte((byte)(value^1));
        }
        string prior = Hash(Parent(root)),changed = Hash(target); bool failed = false;
        try { Run(image,root,sha,CancellationToken.None,null); } catch (IOException) { failed = true; }
        Check(failed && Hash(Parent(root)) == prior && Hash(target) == changed,"changed "+kind+" is refused while evidence remains intact");
    }
    static void Bindings()
    {
        foreach (string kind in new[] { "limits","groups","baseline" }) {
            string root,image = Image("binding",out root),sha = Hash(image); Cancel(image,root,sha); string prior = Hash(Parent(root)); bool failed = false;
            try { Run(image,root,sha,CancellationToken.None,null,true,kind); } catch (IOException) { failed = true; }
            Check(failed && reads.Count == 0 && Hash(Parent(root)) == prior,"changed "+kind+" cannot reuse a journal mapping");
        }
        string midRoot,midImage = Image("mid-limits",out midRoot),midSha = Hash(midImage); bool denied = false;
        try { Run(midImage,midRoot,midSha,CancellationToken.None,null,true,"mid-limits"); } catch (IOException) { denied = true; }
        Check(denied && !(bool)State(midRoot)["Complete"],"limits changed during journal loading cannot advance completion");
    }
    static void Corpus()
    {
        foreach (string fixture in Directory.GetFiles(fixtures,"*.dd").Select(Path.GetFileNameWithoutExtension)
            .Where(x => x.StartsWith("native-journal-",StringComparison.Ordinal) || x.StartsWith("journal-",StringComparison.Ordinal) || x == "extent-deleted")) {
            string root,image = Image("corpus",out root,fixture),sha = Hash(image); Complete(image,root,sha);
        }
    }
    static uint Crc(uint seed,byte[] data,int count)
    {
        for (int i = 0; i < count; i++) { seed ^= data[i]; for (int bit = 0; bit < 8; bit++) seed = (seed>>1)^((seed&1) == 0 ? 0U : 0x82f63b78U); }
        return seed;
    }
    static void Put16(byte[] data,int offset,ushort value) { Buffer.BlockCopy(BitConverter.GetBytes(value),0,data,offset,2); }
    static void Put32(byte[] data,int offset,uint value) { Buffer.BlockCopy(BitConverter.GetBytes(value),0,data,offset,4); }
    // Derived parser control: promote the journal's inline extent root into a
    // checksummed external leaf on an owned copy. This is not a newly generated
    // e2fsprogs filesystem or evidence of physical-device recovery.
    static void JournalTree(bool badChecksum)
    {
        string root,image = Image("derived-tree",out root); long inodeOffset; ulong leafBlock = 0; int blockBytes,inodeBytes; uint inodeNumber,seed;
        using (var input = new Source(image)) {
            object c = Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            Set(c,"Input",input); Set(c,"Cancel",CancellationToken.None); Set(c,"Limits",new Ext4Recovery.Limits()); Set(c,"Report",new Ext4Recovery.Report());
            object v = Call("OpenVolumeHeader",c,0L); var vr = (Ext4Recovery.VolumeReport)Get(v,"Report");
            var reserved = (IList)Activator.CreateInstance(Get(v,"Reserved").GetType()); foreach (var range in (IEnumerable)Get(v,"Reserved")) reserved.Add(range);
            Call("ReadGroups",c,v,(ulong)vr.Groups,(ulong)(uint)Get(v,"FirstData")+1,reserved);
            byte[] sb = (byte[])Get(v,"Superblock"); inodeNumber = BitConverter.ToUInt32(sb,0xe0);
            blockBytes = (int)Get(v,"BlockBytes"); inodeBytes = (int)Get(v,"InodeBytes");
            uint perGroup = (uint)Get(v,"InodesPerGroup"),groupIndex = (inodeNumber-1)/perGroup,at = (inodeNumber-1)%perGroup;
            var groups = (IList)Get(v,"Groups"); object group = groups[(int)groupIndex];
            inodeOffset = (long)(ulong)Get(group,"InodeTable")*blockBytes+(long)at*inodeBytes;
            Check((bool)Get(v,"Csum"),"derived external journal tree starts from a metadata-checksummed fixture");
            byte[] uuid = sb.Skip(0x68).Take(16).ToArray();
            seed = ((uint)Get(v,"Incompat")&0x2000) != 0 ? BitConverter.ToUInt32(sb,0x270) : Crc(UInt32.MaxValue,uuid,uuid.Length);
            ulong blocks = (ulong)Get(v,"Blocks"); uint blocksPerGroup = (uint)Get(v,"BlocksPerGroup"),first = (uint)Get(v,"FirstData");
            for (ulong block = blocks-1; block > first; block--) {
                if ((bool)Call("Reserved",v,block,1UL)) continue;
                ulong bit = (block-first)%blocksPerGroup; object owner = groups[(int)((block-first)/blocksPerGroup)];
                byte[] bitmap = (byte[])Get(owner,"Blocks");
                if ((bool)Get(owner,"BlockMapValid") && (bitmap[bit/8]&(1<<(int)(bit%8))) == 0) { leafBlock = block; break; }
            }
            Check(leafBlock != 0,"derived leaf occupies a nonreserved block that was free in the source bitmap");
        }
        using (var file = new FileStream(image,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) {
            byte[] inode = new byte[inodeBytes]; file.Position = inodeOffset; if (file.Read(inode,0,inode.Length) != inode.Length) throw new EndOfStreamException();
            Check((BitConverter.ToUInt32(inode,0x20)&0x80000) != 0 && BitConverter.ToUInt16(inode,0x2e) == 0,"native journal begins with an inline extent root");
            byte[] leaf = new byte[blockBytes]; Buffer.BlockCopy(inode,0x28,leaf,0,60); int maximum = (blockBytes-12)/12;
            Put16(leaf,4,(ushort)maximum); uint generation = BitConverter.ToUInt32(inode,0x64);
            uint inodeSeed = Crc(Crc(seed,BitConverter.GetBytes(inodeNumber),4),BitConverter.GetBytes(generation),4);
            Put32(leaf,12+maximum*12,Crc(inodeSeed,leaf,12+maximum*12)); if (badChecksum) leaf[12+maximum*12] ^= 1;
            Array.Clear(inode,0x28,60); Put16(inode,0x28,0xf30a); Put16(inode,0x2a,1); Put16(inode,0x2c,4); Put16(inode,0x2e,1);
            Put32(inode,0x34,BitConverter.ToUInt32(leaf,12)); Put32(inode,0x38,(uint)leafBlock); Put16(inode,0x3c,(ushort)(leafBlock>>32));
            inode[124] = inode[125] = inode[130] = inode[131] = 0; uint crc = Crc(inodeSeed,inode,inode.Length);
            Put16(inode,124,(ushort)crc); Put16(inode,130,(ushort)(crc>>16));
            file.Position = inodeOffset; file.Write(inode,0,inode.Length); file.Position = (long)leafBlock*blockBytes; file.Write(leaf,0,leaf.Length); file.Flush(true);
        }
        string sha = Hash(image); bool stopped = false;
        using (var cancel = new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m => { if (Convert.ToInt32(State(root)["Next"]) == 2) cancel.Cancel(); }); } catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && reads.Any(row => row.Item1 == (long)leafBlock*blockBytes),"cancel reaches the actual external mapping leaf before journal-superblock parsing");
        var prefix = reads.ToList(); string reference = Reference(image,sha);
        Check(reference.Contains(badChecksum ? "journal_mapping_invalid" : "validated_superblock"),"independent checksum construction yields the expected mapping verdict");
        Complete(image,root,sha,prefix);
    }
    static void KilledWorker()
    {
        string root,image = Image("worker",out root),sha = Hash(image),signal = Path.Combine(root,"ready.txt");
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+image+"\" \""+root+"\" \""+signal+"\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start)) {
            try { var timer = Stopwatch.StartNew(); while (!File.Exists(signal) && !child.HasExited && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(10);
                Check(File.Exists(signal),"owned child reaches a persisted journal initialization read"); child.Kill(); Check(child.WaitForExit(10000),"owned journal loader terminates without cleanup"); }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        var prefix = Json.Deserialize<List<Dictionary<string,object>>>(File.ReadAllText(signal)).Select(x => Tuple.Create(Convert.ToInt64(x["Item1"]),Convert.ToInt32(x["Item2"]))).ToList();
        Complete(image,root,sha,prefix);
    }
    public static int Main(string[] args)
    {
        try {
            if (typeof(Ext4Recovery).GetMethod("LoadJournalCheckpointed",Private) == null) { Console.WriteLine("FAIL: baseline lacks checkpointed journal initialization"); return 1; }
            if (args.Length == 4 && args[0] == "--worker") {
                Run(args[1],args[2],Hash(args[1]),CancellationToken.None,m => { File.WriteAllText(args[3],Json.Serialize(reads)); Thread.Sleep(Timeout.Infinite); }); return 3;
            }
            fixtures = Path.GetFullPath(args[1]); work = Path.Combine(Path.GetFullPath(args[0]),".build","ext4-journal-load-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            foreach (bool terminal in new[] { false,true }) { string root,image = Image("cancel",out root),sha = Hash(image); Complete(image,root,sha,Cancel(image,root,sha,terminal)); }
            ParentFailure(); ReadFailure("lock"); ReadFailure("zero");
            foreach (string kind in new[] { "source","state","ledger","blob","cursor","phase" }) Tamper(kind);
            Bindings(); Corpus(); JournalTree(false); JournalTree(true); KilledWorker();
            Console.WriteLine("PASS Ext4JournalLoadCheckpoint: "+checks+" checks; journal initialization only, not whole-engine resume or real devices"); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
