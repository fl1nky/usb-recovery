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

public static class Ext4CandidateCheckpointTests
{
    static int checks;
    static string work, fixtures;
    static List<Tuple<long,int>> reads;
    static readonly BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
    static object Get(object o,string field) { return o.GetType().GetField(field).GetValue(o); }
    static void Set(object o,string field,object value) { o.GetType().GetField(field).SetValue(o,value); }
    static void Check(bool value,string label) { checks++;if(!value)throw new Exception(label); }
    static string Hash(string file) { return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{}); }
    sealed class Source : FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long,int>> Reads=new List<Tuple<long,int>>();
        public Source(string image):base(image,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1){}
        public override int Read(byte[] bytes,int at,int count) { Reads.Add(Tuple.Create(Position,count));return ZeroNext?0:base.Read(bytes,at,count); }
    }
    sealed class Result { public bool Accepted,Limited;public string Entry,Skipped;public List<Tuple<long,int>> Reads; }
    static string Parent(string root) { return Path.Combine(root,"anchor.json"); }
    static RecoveryMethodCheckpoint Anchor(string root)
    { return File.Exists(Parent(root))?Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)):null; }
    static void SaveAnchor(string root,RecoveryMethodCheckpoint value)
    {
        string temporary=Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial";bool own=false;
        try { byte[] bytes=Encoding.UTF8.GetBytes(Json.Serialize(value));
            using(var output=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { own=true;output.Write(bytes,0,bytes.Length);output.Flush(true); }
            if(File.Exists(Parent(root)))File.Replace(temporary,Parent(root),null);else File.Move(temporary,Parent(root));
        } finally { if(own&&File.Exists(temporary))File.Delete(temporary); }
    }
    static Dictionary<string,object> State(string root)
    {
        var a=Anchor(root);Check(a!=null&&Hash(a.Path)==a.Sha256,"caller pins exact candidate preparation state");
        return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(a.Path,Encoding.UTF8))["Payload"];
    }
    static string Image(string name,out string root,string fixture="legacy-indirect-deleted")
    {
        root=Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        string image=Path.Combine(root,"owned.dd");File.Copy(Path.Combine(fixtures,fixture+".dd"),image);
        File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly);return image;
    }
    static object Setup(Source input,string root,CancellationToken token,Ext4Recovery.Limits limits,out object volume,out object inode,out Ext4Recovery.Entry entry)
    {
        object c=Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);
        var report=new Ext4Recovery.Report();Set(c,"Input",input);Set(c,"Root",Path.Combine(root,"ext4"));Set(c,"Cancel",token);Set(c,"Limits",limits);Set(c,"Report",report);
        volume=typeof(Ext4Recovery).GetMethod("OpenVolume",Private).Invoke(null,new[]{c,(object)0L});
        Check(((Ext4Recovery.VolumeReport)Get(volume,"Report")).Status=="ready","native filesystem metadata initializes");
        object[] scan={c,volume,null,null,null,null};typeof(Ext4Recovery).GetMethod("ScanInodesCheckpointed",Private).Invoke(null,scan);
        inode=((IList)scan[4])[0];
        entry=new Ext4Recovery.Entry { VolumeOffset=(long)Get(volume,"Offset"),InodeOffset=(long)Get(inode,"Offset"),
            Inode=(uint)Get(inode,"Number"),Generation=(uint)Get(inode,"Generation"),DeletionTime=(uint)Get(inode,"Dtime"),
            DeclaredSize=(long)(ulong)Get(inode,"Size"),InodeChecksumVerified=(bool)Get(volume,"Csum"),Status="not_recovered" };
        entry.Names.Add(new Ext4Recovery.NameLink { Name="provided test reference",TargetInode=entry.Inode });
        report.RecoveredFiles=2;report.OutputBytes=123;report.Candidates=3;report.Entries.Add(entry);report.Skipped["prior_volume_control"]=7;
        return c;
    }
    static Result Run(string image,string root,string sha,CancellationToken token,Action<string> progress,bool durable=true,
        string change=null,bool zero=false,int unit=16)
    {
        using(var input=new Source(image)) {
            var limits=new Ext4Recovery.Limits();var field=limits.GetType().GetField("AllocationBlocksPerCheckpoint");if(field!=null)field.SetValue(limits,unit);
            object volume,inode;Ext4Recovery.Entry entry;object c=Setup(input,root,token,limits,out volume,out inode,out entry);
            if(change=="inode")Set(inode,"Generation",(uint)Get(inode,"Generation")+1);
            if(change=="name")entry.Names[0].Name+=" changed";
            if(change=="groups")Set(((IList)Get(volume,"Groups"))[0],"BlockMapValid",false);
            if(change=="baseline")((Ext4Recovery.Report)Get(c,"Report")).OutputBytes++;
            if(change=="limits")limits.MaximumExtents--;
            if(change=="output-budget")limits.MaximumOutputBytes=123+entry.DeclaredSize-1;
            object checkpoint=null;
            if(durable) {
                checkpoint=Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
                Set(checkpoint,"Directory",root);Set(checkpoint,"Method","ext4");Set(checkpoint,"SourceSha256",sha);Set(checkpoint,"Settings","owned-candidate-preparation-v1");
                Set(checkpoint,"Resume",Anchor(root));Set(checkpoint,"Commit",(Action<RecoveryMethodCheckpoint>)(a=>SaveAnchor(root,a)));
            }
            input.Reads.Clear();reads=input.Reads;if(change=="legacy-zero")input.ZeroNext=true;
            Action<string> notify=m=>{if(zero&&m.Contains("candidate tree"))input.ZeroNext=true;if(progress!=null)progress(m);};
            object[] args=durable?new object[]{c,volume,inode,entry,checkpoint,notify}:new object[]{c,volume,inode,entry};bool accepted;
            try { accepted=(bool)typeof(Ext4Recovery).GetMethod(durable?"PrepareMappedEntryCheckpointed":"PrepareMappedEntry",Private).Invoke(null,args); }
            catch(TargetInvocationException error) { throw error.InnerException; }
            var report=(Ext4Recovery.Report)Get(c,"Report");
            return new Result { Accepted=accepted,Limited=report.Limited,Entry=Json.Serialize(entry),
                Skipped=Json.Serialize(report.Skipped.OrderBy(x=>x.Key).ToArray()),Reads=reads };
        }
    }
    static void Compare(Result a,Result b)
    {
        Check(a.Accepted==b.Accepted&&a.Limited==b.Limited&&a.Entry==b.Entry,"mapping, clipped extents, allocation status, failure reason and evidence match an uninterrupted legacy preparation");
        Check(a.Skipped==b.Skipped,"prior-volume and new skip counters are neither lost nor doubled");
    }
    static Result Reference(string image,string sha,string change=null)
    { string root=Path.Combine(work,"reference-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);return Run(image,root,sha,CancellationToken.None,null,false,change,false,4096); }
    static List<Tuple<long,int>> Cancel(string image,string root,string sha,string phase)
    {
        bool stopped=false;using(var cancel=new CancellationTokenSource()) {
            try { Run(image,root,sha,cancel.Token,m=>{if(m.Contains("candidate "+phase))cancel.Cancel();}); }catch(OperationCanceledException){stopped=true;}
        }
        var state=State(root);Check(stopped&&!(bool)state["Complete"]&&Convert.ToInt32(state["Next"])>0,"cancel pins an internal "+phase+" unit before candidate completion");
        if(phase=="allocation")Check(Convert.ToInt64(state["CheckedBlocks"])==16,"native allocation stops at a real position inside the file's block checks");
        return reads.ToList();
    }
    static void Complete(string image,string root,string sha,List<Tuple<long,int>> prefix=null)
    {
        var result=Run(image,root,sha,CancellationToken.None,null);Compare(Reference(image,sha),result);
        if(prefix!=null)Check(!result.Reads.Any(x=>prefix.Any(p=>p.Item1<x.Item1+x.Item2&&x.Item1<p.Item1+p.Item2)),"resume never rereads the confirmed mapping-node prefix through the phase stream");
        var repeat=Run(image,root,sha,CancellationToken.None,m=>{throw new Exception("completed candidate preparation restarted");});Compare(result,repeat);
        Check(repeat.Reads.Count==0&&(bool)State(root)["Complete"]&&Hash(image)==sha,"completed candidate reconstructs from facts and cached bitmap with zero phase source reads");
    }
    static void CancelResume(string phase)
    {string root,image=Image("cancel-"+phase,out root),sha=Hash(image);Complete(image,root,sha,Cancel(image,root,sha,phase));}
    static void ParentFailure()
    {
        string root,image=Image("parent-denial",out root),sha=Hash(image),prior=null;FileStream held=null;List<Tuple<long,int>> prefix=null;bool failed=false;
        try { Run(image,root,sha,CancellationToken.None,m=>{if(held==null&&m.Contains("candidate tree")) {
            prior=Hash(Parent(root));prefix=reads.ToList();held=new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read);
        }}); }catch(IOException){failed=true;}finally{if(held!=null)held.Dispose();}
        Check(failed&&prior!=null&&Hash(Parent(root))==prior,"actual OS parent replacement denial retains the previous mapping prefix");Complete(image,root,sha,prefix);
    }
    static void ReadFailure(bool zero)
    {
        string root,image=Image("read-denial",out root),sha=Hash(image),prior=null;FileStream held=null;List<Tuple<long,int>> prefix=null;bool failed=false;
        try { Run(image,root,sha,CancellationToken.None,m=>{if(prior==null&&m.Contains("candidate tree")) {
            prior=Hash(Parent(root));prefix=reads.ToList();if(!zero){held=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read);held.Lock(0,held.Length);}
        }},true,null,zero); }catch(IOException){failed=true;}finally{if(held!=null){held.Unlock(0,held.Length);held.Dispose();}}
        Check(failed&&prior!=null&&Hash(Parent(root))==prior,"actual locked or synthetic zero node read cannot become a normal rejected candidate");Complete(image,root,sha,prefix);
    }
    static void RejectedAndBudgets()
    {
        foreach(string fixture in new[]{"bad-extent-node-checksum","cyclic-extent-tree-valid-crc","extent-bounds-valid-inode-crc","allocated-data-conflict","bad-block-bitmap-checksum"}) {
            string root,image=Image("rejected",out root,fixture),sha=Hash(image);var result=Run(image,root,sha,CancellationToken.None,null);
            Check(!result.Accepted&&(bool)State(root)["Complete"],"a rejected "+fixture+" candidate has a durable terminal result");Compare(Reference(image,sha),result);
            Compare(result,Run(image,root,sha,CancellationToken.None,m=>{throw new Exception("rejected candidate restarted");}));
        }
        string folder,source=Image("output-budget",out folder),hash=Hash(source);Result completed=null;
        for(int turn=0;turn<40;turn++) {
            using(var cancel=new CancellationTokenSource()) {try{completed=Run(source,folder,hash,cancel.Token,m=>cancel.Cancel(),true,"output-budget");}catch(OperationCanceledException){}}
            if((bool)State(folder)["Complete"])break;
        }
        completed=Run(source,folder,hash,CancellationToken.None,null,true,"output-budget");Compare(Reference(source,hash,"output-budget"),completed);
        Check(!completed.Accepted&&completed.Limited&&completed.Entry.Contains("output_limit"),"output budget survives repeated cancellation without resetting");
    }
    static void Tamper(string kind)
    {
        string root,image=Image("tamper-"+kind,out root),sha=Hash(image);Cancel(image,root,sha,"allocation");
        string target=kind=="source"?image:kind=="blob"?Directory.GetFiles(Path.Combine(root,"ext4.state","candidate-blobs"),"blob-*.json")[0]:Anchor(root).Path;
        if(kind=="cursor"||kind=="allocation-cursor") {
            var envelope=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target,Encoding.UTF8));var payload=(Dictionary<string,object>)envelope["Payload"];
            string field=kind=="cursor"?"Next":"CheckedBlocks";payload[field]=Convert.ToInt64(payload[field])+1;
            File.WriteAllText(target,Json.Serialize(envelope),new UTF8Encoding(false));var anchor=Anchor(root);anchor.Sha256=Hash(target);SaveAnchor(root,anchor);
        } else using(var file=new FileStream(target,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) {
            file.Position=kind=="source"?file.Length-1:0;int b=file.ReadByte();file.Position--;file.WriteByte((byte)(b^1));
        }
        string parent=Hash(Parent(root)),changed=Hash(target);bool failed=false;
        try{Run(image,root,sha,CancellationToken.None,null);}catch(IOException){failed=true;}
        Check(failed&&reads.Count==0&&Hash(Parent(root))==parent&&Hash(target)==changed,"changed "+kind+" is preserved and refused before phase reads or parent writes");
    }
    static void Binding(string kind)
    {
        string root,image=Image("binding-"+kind,out root),sha=Hash(image);Cancel(image,root,sha,"allocation");string parent=Hash(Parent(root));bool failed=false;
        try{Run(image,root,sha,CancellationToken.None,null,true,kind);}catch(IOException){failed=true;}
        Check(failed&&reads.Count==0&&Hash(Parent(root))==parent,"changed "+kind+" input cannot reuse candidate preparation facts");
    }
    static void BitmapOracle()
    {
        string root,image=Image("bitmap-oracle",out root);using(var input=new Source(image)) {
            object volume,inode;Ext4Recovery.Entry entry;object c=Setup(input,root,CancellationToken.None,new Ext4Recovery.Limits(),out volume,out inode,out entry);
            uint first=(uint)Get(volume,"FirstData");ulong blocks=(ulong)Get(volume,"Blocks");var random=new Random(741);input.Reads.Clear();
            for(int trial=0;trial<500;trial++) {
                int count=random.Next(1,258);ulong start=(ulong)random.Next((int)first,(int)blocks-count);string expected=null;ulong passed=0;
                for(;passed<(ulong)count;passed++){expected=(string)typeof(Ext4Recovery).GetMethod("FreeBlock",Private).Invoke(null,new[]{volume,(object)(start+passed)});if(expected!=null)break;}
                object[] args={c,volume,start,(ulong)count,0UL};string actual=(string)typeof(Ext4Recovery).GetMethod("CheckFreeSpan",Private).Invoke(null,args);
                Check(actual==expected&&(ulong)args[4]==passed,"byte masks and group boundaries match independent per-block allocation checks");
            }
            Check(input.Reads.Count==0,"bitmap checks use validated memory snapshots without source reads");
            object group=((IList)Get(volume,"Groups"))[0];byte[] original=(byte[])Get(group,"Blocks");Set(group,"Blocks",new byte[1]);
            object[] truncated={c,volume,(ulong)first,16UL,0UL};string failure=(string)typeof(Ext4Recovery).GetMethod("CheckFreeSpan",Private).Invoke(null,truncated);
            Check(failure=="allocation_bitmap_unknown_or_invalid"&&(ulong)truncated[4]==8,"truncated in-memory bitmap cannot certify missing bits as free; structural control only");
            Set(group,"Blocks",original);
        }
    }
    static void LegacyShortRead()
    {
        string root,image=Image("legacy-zero",out root),sha=Hash(image);bool failed=false;
        try{Run(image,root,sha,CancellationToken.None,null,false,"legacy-zero");}catch(EndOfStreamException){failed=true;}
        Check(failed&&Hash(image)==sha,"legacy mapping also reports a short metadata read as failure, not an ordinary rejected file");
    }
    static void KilledProcess()
    {
        string root,image=Image("worker",out root),sha=Hash(image),ready=Path.Combine(root,"ready.json");
        var start=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+image+"\" \""+root+"\" \""+ready+"\"")
            {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var child=Process.Start(start)) {
            try{var timer=Stopwatch.StartNew();while(!File.Exists(ready)&&!child.HasExited&&timer.Elapsed<TimeSpan.FromSeconds(30))Thread.Sleep(10);
                Check(File.Exists(ready),"owned worker reaches a confirmed allocation cursor");child.Kill();Check(child.WaitForExit(10000),"candidate worker is killed without graceful cleanup");}
            finally{if(!child.HasExited){child.Kill();child.WaitForExit(10000);}}
        }
        var prefix=Json.Deserialize<List<Dictionary<string,object>>>(File.ReadAllText(ready)).Select(x=>Tuple.Create(Convert.ToInt64(x["Item1"]),Convert.ToInt32(x["Item2"]))).ToList();Complete(image,root,sha,prefix);
    }
    public static int Main(string[] args)
    {
        try {
            if(args.Length==3&&args[0]=="--legacy-short-read") {
                fixtures=Path.GetFullPath(args[2]);work=Path.Combine(Path.GetFullPath(args[1]),".build","ext4-candidate-legacy-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
                LegacyShortRead();Console.WriteLine("PASS legacy candidate short read: "+checks);return 0;
            }
            if(typeof(Ext4Recovery).GetMethod("PrepareMappedEntryCheckpointed",Private)==null){Console.WriteLine("FAIL: baseline lacks checkpointed candidate preparation");return 1;}
            if(args.Length==4&&args[0]=="--worker") {
                Run(args[1],args[2],Hash(args[1]),CancellationToken.None,m=>{if(m.Contains("candidate allocation")){File.WriteAllText(args[3],Json.Serialize(reads));Thread.Sleep(Timeout.Infinite);}});return 3;
            }
            fixtures=Path.GetFullPath(args[1]);work=Path.Combine(Path.GetFullPath(args[0]),".build","ext4-candidate-checkpoints-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            LegacyShortRead();BitmapOracle();CancelResume("tree");CancelResume("allocation");ParentFailure();ReadFailure(false);ReadFailure(true);RejectedAndBudgets();
            foreach(string kind in new[]{"source","blob","cursor","allocation-cursor"})Tamper(kind);
            foreach(string kind in new[]{"inode","name","groups","baseline","limits"})Binding(kind);
            KilledProcess();Console.WriteLine("PASS Ext4CandidateCheckpoint: "+checks+" checks; preparation component only, not whole-engine resume or devices");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
