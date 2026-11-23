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

public static class Ext4ExportCheckpointTests
{
    static int checks;
    static string work,fixtures;
    static List<Tuple<long,int>> reads;
    static readonly BindingFlags Private=BindingFlags.NonPublic|BindingFlags.Static;
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};
    static object Get(object o,string field){return o.GetType().GetField(field).GetValue(o);}
    static void Set(object o,string field,object value){o.GetType().GetField(field).SetValue(o,value);}
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string file){return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{});}
    static string Identity(object entry){return (string)typeof(Ext4Recovery).GetMethod("Ext4EntryIdentity",Private).Invoke(null,new[]{entry,(object)CancellationToken.None});}
    sealed class Source:FileStream
    {
        public bool ZeroNext;
        public readonly List<Tuple<long,int>> Reads=new List<Tuple<long,int>>();
        public Source(string file):base(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1){}
        public override int Read(byte[] bytes,int at,int count){Reads.Add(Tuple.Create(Position,count));return ZeroNext?0:base.Read(bytes,at,count);}
    }
    sealed class Result{public int Candidates,Files;public long Bytes;public bool Limited;public string[] Entries;public string Skipped;public List<Tuple<long,int>> Reads;public Ext4Recovery.Report Report;}
    static string Parent(string root){return Path.Combine(root,"anchor.json");}
    static RecoveryMethodCheckpoint Anchor(string root){return File.Exists(Parent(root))?Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)):null;}
    static void SaveAnchor(string root,RecoveryMethodCheckpoint value)
    {
        string temp=Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial";bool own=false;
        try{byte[] bytes=Encoding.UTF8.GetBytes(Json.Serialize(value));using(var output=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){own=true;output.Write(bytes,0,bytes.Length);output.Flush(true);}
            if(File.Exists(Parent(root)))File.Replace(temp,Parent(root),null);else File.Move(temp,Parent(root));}
        finally{if(own&&File.Exists(temp))File.Delete(temp);}
    }
    static Dictionary<string,object> State(string root)
    {
        var a=Anchor(root);Check(a!=null&&Hash(a.Path)==a.Sha256,"caller pins exact volume-export state");
        return (Dictionary<string,object>)Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(a.Path,Encoding.UTF8))["Payload"];
    }
    static string Image(string name,out string root,string fixture="legacy-indirect-deleted")
    {
        root=Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);string image=Path.Combine(root,"owned.dd");
        File.Copy(Path.Combine(fixtures,fixture+".dd"),image);File.SetAttributes(image,File.GetAttributes(image)&~FileAttributes.ReadOnly);return image;
    }
    static object SuppliedHistory(object inode,object volume)
    {
        var type=typeof(Ext4Recovery).GetNestedType("HistoricalCandidate",BindingFlags.NonPublic);object old=Activator.CreateInstance(type,true);
        foreach(string name in new[]{"Number","Mode","Links","Dtime","Flags","Generation","Size"})Set(old,name,Get(inode,name));
        Set(old,"InodeBytes",Get(inode,"Bytes"));int block=(int)Get(volume,"BlockBytes");long at=(long)Get(inode,"Offset")-(long)Get(volume,"Offset");
        Set(old,"TargetDiskBlock",(ulong)(at/block));Set(old,"JournalBlock",(ulong)(at/block+2));Set(old,"OffsetInBlock",(int)(at%block));Set(old,"TransactionSeq",7U);
        var map=(IDictionary)Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(typeof(uint),type));map.Add(Get(old,"Number"),old);return map;
    }
    static Result Run(string image,string root,string sha,CancellationToken token,Action<string> progress,bool durable=true,string mode=null,bool zero=false)
    {
        using(var input=new Source(image)){
            object c=Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Context",BindingFlags.NonPublic),true);var report=new Ext4Recovery.Report();var limits=new Ext4Recovery.Limits();
            Set(c,"Input",input);Set(c,"Root",Path.Combine(root,"ext4"));Set(c,"Cancel",token);Set(c,"Limits",limits);Set(c,"Report",report);
            Directory.CreateDirectory(Path.Combine(root,"ext4","files"));
            object volume=typeof(Ext4Recovery).GetMethod("OpenVolume",Private).Invoke(null,new[]{c,(object)0L});
            Check(((Ext4Recovery.VolumeReport)Get(volume,"Report")).Status=="ready","native volume initializes");
            object[] scan={c,volume,null,null,null,null};typeof(Ext4Recovery).GetMethod("ScanInodesCheckpointed",Private).Invoke(null,scan);
            object jc=typeof(Ext4Recovery).GetMethod("LoadJournal",Private).Invoke(null,new[]{c,volume,Get(volume,"Superblock")});
            object history=null,historyDirectories=null;
            if(jc!=null){object[] sweep={c,volume,jc,null,null};typeof(Ext4Recovery).GetMethod("SweepJournalHistory",Private).Invoke(null,sweep);history=sweep[3];historyDirectories=sweep[4];}
            object names=typeof(Ext4Recovery).GetMethod("DirectoryNames",Private).Invoke(null,new[]{c,volume,scan[5],historyDirectories});
            if(mode=="empty"){((IList)scan[4]).Clear();if(history!=null)((IDictionary)history).Clear();}
            if(mode=="already")history=SuppliedHistory(((IList)scan[4])[0],volume);
            if(mode=="live-history"){
                object group=((IList)Get(volume,"Groups"))[0];int block=(int)Get(volume,"BlockBytes"),width=(int)Get(volume,"InodeBytes");
                long at=(long)(ulong)Get(group,"InodeTable")*block+12L*width;byte[] bytes=new byte[width];input.Position=at;
                if(input.Read(bytes,0,width)!=width)throw new EndOfStreamException();
                object live=Activator.CreateInstance(typeof(Ext4Recovery).GetNestedType("Inode",BindingFlags.NonPublic),true);
                Set(live,"Number",13U);Set(live,"Offset",at);Set(live,"Mode",BitConverter.ToUInt16(bytes,0));Set(live,"Links",BitConverter.ToUInt16(bytes,0x1a));
                Set(live,"Dtime",BitConverter.ToUInt32(bytes,0x14));Set(live,"Flags",BitConverter.ToUInt32(bytes,0x20));Set(live,"Generation",BitConverter.ToUInt32(bytes,0x64));
                Set(live,"Size",(ulong)BitConverter.ToUInt32(bytes,4)|((ulong)BitConverter.ToUInt32(bytes,0x6c)<<32));Set(live,"Bytes",bytes);history=SuppliedHistory(live,volume);
            }
            if(mode=="fallback"||mode=="history-limit"){
                object old=((IDictionary)history).Values.Cast<object>().First();Type inodeType=typeof(Ext4Recovery).GetNestedType("Inode",BindingFlags.NonPublic);object bad=Activator.CreateInstance(inodeType,true);
                foreach(string field in new[]{"Number","Mode","Links","Dtime","Generation","Size"})Set(bad,field,Get(old,field));
                Set(bad,"Flags",(uint)Get(old,"Flags")|4U);Set(bad,"Bytes",Get(old,"InodeBytes"));
                Set(bad,"Offset",(long)(ulong)Get(old,"TargetDiskBlock")*(int)Get(volume,"BlockBytes")+(int)Get(old,"OffsetInBlock"));((IList)scan[4]).Add(bad);
            }
            if(mode=="history-limit")limits.MaximumCandidates=1;
            if(mode=="name"){
                var map=(IDictionary)names;uint target=(uint)Get(((IList)scan[4])[0],"Number");
                if(map.Contains(target))((Ext4Recovery.NameLink)((IList)map[target])[0]).Name+=" changed";
                else map.Add(target,new List<Ext4Recovery.NameLink>{new Ext4Recovery.NameLink{Name="changed candidate reference",TargetInode=target}});
            }
            if(mode=="groups")Set(((IList)Get(volume,"Groups"))[0],"BlockMapValid",false);
            if(mode=="baseline")report.OutputBytes=1;
            if(mode=="output-root")Set(c,"Root",Path.Combine(root,"another-output"));
            if(mode=="source-root")Set(c,"Root",root);
            object checkpoint=null;
            if(durable){checkpoint=Activator.CreateInstance(typeof(Ext4Recovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
                Set(checkpoint,"Directory",root);Set(checkpoint,"Method","ext4");Set(checkpoint,"SourceSha256",sha);Set(checkpoint,"Settings","owned-volume-export-v1");Set(checkpoint,"Resume",Anchor(root));
                Set(checkpoint,"Commit",(Action<RecoveryMethodCheckpoint>)(a=>SaveAnchor(root,a)));}
            input.Reads.Clear();reads=input.Reads;
            Action<string> notify=m=>{if(zero&&m.Contains("candidate tree"))input.ZeroNext=true;if(progress!=null)progress(m);};
            object[] args=durable?new[]{c,volume,scan[4],history,names,checkpoint,notify}:new[]{c,volume,scan[4],history,names};
            try{typeof(Ext4Recovery).GetMethod(durable?"ExportVolumeCandidatesCheckpointed":"ExportVolumeCandidatesLegacy",Private).Invoke(null,args);}catch(TargetInvocationException error){throw error.InnerException;}
            return new Result{Candidates=report.Candidates,Files=report.RecoveredFiles,Bytes=report.OutputBytes,Limited=report.Limited,
                Entries=report.Entries.Select(x=>Identity(x)).ToArray(),Skipped=Json.Serialize(report.Skipped.OrderBy(x=>x.Key).ToArray()),Reads=reads,Report=report};
        }
    }
    static Result Reference(string image,string sha,string mode=null)
    {string root=Path.Combine(work,"reference-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);return Run(image,root,sha,CancellationToken.None,null,false,mode);}
    static void Compare(Result a,Result b)
    {
        Check(a.Candidates==b.Candidates&&a.Files==b.Files&&a.Bytes==b.Bytes&&a.Limited==b.Limited,"export counters and limits match the uninterrupted legacy loop");
        Check(a.Entries.SequenceEqual(b.Entries)&&a.Skipped==b.Skipped,"every recovered/rejected entry, name, provenance and skip reason is retained exactly once");
    }
    static void Payloads(string image,string root,Result result)
    {
        foreach(var entry in result.Report.Entries.Where(x=>x.Output!=null)){
            string output=Path.Combine(root,"ext4",entry.Output.Replace('/',Path.DirectorySeparatorChar));Check(Hash(output)==entry.Sha256,"published output matches the pinned final plan");
            using(var file=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))using(var target=new FileStream(output,FileMode.Open,FileAccess.Read,FileShare.Read)){
                foreach(var extent in entry.Extents){byte[] expected=new byte[(int)extent.Length],actual=new byte[(int)extent.Length];file.Position=extent.ImageOffset;target.Position=extent.LogicalOffset;
                    int n=0;while(n<expected.Length){int got=file.Read(expected,n,expected.Length-n);if(got==0)throw new EndOfStreamException();n+=got;}
                    n=0;while(n<actual.Length){int got=target.Read(actual,n,actual.Length-n);if(got==0)throw new EndOfStreamException();n+=got;}
                    Check(expected.SequenceEqual(actual),"native mapped payload equals independent source bytes");}
            }
        }
    }
    static List<Tuple<long,int>> Cancel(string image,string root,string sha,string phase)
    {
        bool stopped=false;using(var cancel=new CancellationTokenSource()){
            try{Run(image,root,sha,cancel.Token,m=>{if(m.Contains(phase))cancel.Cancel();});}catch(OperationCanceledException){stopped=true;}
        }
        Check(stopped&&Anchor(root)!=null,"cancel preserves a real parent-anchored "+phase+" position");return reads.ToList();
    }
    static void Complete(string image,string root,string sha,List<Tuple<long,int>> prefix=null,string mode=null)
    {
        var result=Run(image,root,sha,CancellationToken.None,null,true,mode);Compare(Reference(image,sha,mode),result);Payloads(image,root,result);
        if(prefix!=null)Check(!result.Reads.Any(x=>prefix.Any(p=>p.Item1<x.Item1+x.Item2&&x.Item1<p.Item1+p.Item2)),"resume does not reread confirmed metadata or copied source ranges");
        var repeat=Run(image,root,sha,CancellationToken.None,m=>{throw new Exception("completed volume export restarted");},true,mode);Compare(result,repeat);
        Check(repeat.Reads.Count==0&&(bool)State(root)["Complete"]&&Hash(image)==sha,"completed export reconstructs without phase source reads and preserves the image");
    }
    static void CancelResume(string phase)
    {string root,image=Image("cancel",out root),sha=Hash(image);Complete(image,root,sha,Cancel(image,root,sha,phase));}
    static void Histories()
    {
        foreach(string fixture in new[]{"journal-historical-deleted","journal-historical-conflict","native-journal-v3-history"}){
            string root,image=Image("history",out root,fixture),sha=Hash(image);Complete(image,root,sha);
        }
        string folder,source=Image("fallback",out folder,"journal-historical-deleted"),hash=Hash(source);
        var result=Run(source,folder,hash,CancellationToken.None,null,true,"fallback");Compare(Reference(source,hash,"fallback"),result);
        Check(result.Report.Entries.Count==2&&result.Report.Entries[0].Output==null&&result.Report.Entries[1].Output!=null,
            "supplied derived current-map failure never suppresses a valid native historical fallback");Complete(source,folder,hash,null,"fallback");
        string limited,limitedImage=Image("history-limit",out limited,"journal-historical-deleted"),limitedSha=Hash(limitedImage);
        var cap=Run(limitedImage,limited,limitedSha,CancellationToken.None,null,true,"history-limit");Compare(Reference(limitedImage,limitedSha,"history-limit"),cap);
        Check(cap.Limited&&cap.Report.Entries.Count==1&&cap.Files==0,"historical candidate limit remains explicit and never resets after a rejected current entry");Complete(limitedImage,limited,limitedSha,null,"history-limit");
        string same,sameImage=Image("already",out same),sameSha=Hash(sameImage);Complete(sameImage,same,sameSha,null,"already");
        string live,liveImage=Image("live",out live,"live-control"),liveSha=Hash(liveImage);
        var untouched=Run(liveImage,live,liveSha,CancellationToken.None,null,true,"live-history");Compare(Reference(liveImage,liveSha,"live-history"),untouched);
        Check(untouched.Candidates==0&&untouched.Files==0,"supplied same-generation history of a native live inode is not treated as deleted");Complete(liveImage,live,liveSha,null,"live-history");
    }
    static void Repair()
    {
        string root,image=Image("repair",out root),sha=Hash(image);var result=Run(image,root,sha,CancellationToken.None,null);
        string output=Path.Combine(root,"ext4",result.Report.Entries.Single(x=>x.Output!=null).Output.Replace('/',Path.DirectorySeparatorChar));File.Delete(output);
        bool stopped=false;using(var cancel=new CancellationTokenSource()){
            try{Run(image,root,sha,cancel.Token,m=>{if(m.Contains("file bytes"))cancel.Cancel();});}catch(OperationCanceledException){stopped=true;}
        }
        var prefix=reads.ToList();Check(stopped&&Convert.ToInt32(State(root)["Repair"])==0,"missing completed output repair has its own parent-anchored copy cursor");Complete(image,root,sha,prefix);
    }
    static void Tamper(string kind)
    {
        string root,image=Image("tamper-"+kind,out root),sha=Hash(image);string target;
        if(kind=="output"){
            var result=Run(image,root,sha,CancellationToken.None,null);target=Path.Combine(root,"ext4",result.Report.Entries.Single(x=>x.Output!=null).Output.Replace('/',Path.DirectorySeparatorChar));
        }else{Cancel(image,root,sha,"file bytes");target=kind=="source"?image:Anchor(root).Path;}
        if(kind=="cursor"){
            var envelope=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(target,Encoding.UTF8));var payload=(Dictionary<string,object>)envelope["Payload"];
            payload["Next"]=1;payload["Complete"]=true;File.WriteAllText(target,Json.Serialize(envelope),new UTF8Encoding(false));var anchor=Anchor(root);anchor.Sha256=Hash(target);SaveAnchor(root,anchor);
        }else using(var file=new FileStream(target,FileMode.Open,FileAccess.ReadWrite,FileShare.None)){file.Position=file.Length-1;int b=file.ReadByte();file.Position--;file.WriteByte((byte)(b^1));}
        string parent=Hash(Parent(root)),changed=Hash(target);bool failed=false;try{Run(image,root,sha,CancellationToken.None,null);}catch(IOException){failed=true;}
        Check(failed&&reads.Count==0&&Hash(Parent(root))==parent&&Hash(target)==changed,"changed "+kind+" is preserved and rejected before source-phase reads or parent writes");
    }
    static void Binding(string kind)
    {
        string root,image=Image("binding-"+kind,out root),sha=Hash(image);Cancel(image,root,sha,"file bytes");string parent=Hash(Parent(root));bool failed=false;
        try{Run(image,root,sha,CancellationToken.None,null,true,kind);}catch(IOException){failed=true;}
        Check(failed&&reads.Count==0&&Hash(Parent(root))==parent,"changed "+kind+" cannot reuse earlier volume export");
    }
    static void ParentFailure()
    {
        string root,image=Image("parent-failure",out root),sha=Hash(image),prior=null;FileStream held=null;List<Tuple<long,int>> prefix=null;bool failed=false;
        try{Run(image,root,sha,CancellationToken.None,m=>{if(held==null&&m.Contains("file bytes")){prior=Hash(Parent(root));prefix=reads.ToList();held=new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read);}});}
        catch(IOException){failed=true;}finally{if(held!=null)held.Dispose();}
        Check(failed&&prior!=null&&Hash(Parent(root))==prior,"actual outer parent denial cannot advance the inner copy anchor");Complete(image,root,sha,prefix);
    }
    static void KilledProcess()
    {
        string root,image=Image("worker",out root),sha=Hash(image),ready=Path.Combine(root,"ready.json");
        var start=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker \""+image+"\" \""+root+"\" \""+ready+"\"")
            {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var child=Process.Start(start)){
            try{var timer=Stopwatch.StartNew();while(!File.Exists(ready)&&!child.HasExited&&timer.Elapsed<TimeSpan.FromSeconds(30))Thread.Sleep(10);
                Check(File.Exists(ready),"owned export worker reaches an acknowledged copy unit");child.Kill();Check(child.WaitForExit(10000),"export worker is killed without cleanup");}
            finally{if(!child.HasExited){child.Kill();child.WaitForExit(10000);}}
        }
        var prefix=Json.Deserialize<List<Dictionary<string,object>>>(File.ReadAllText(ready)).Select(x=>Tuple.Create(Convert.ToInt64(x["Item1"]),Convert.ToInt32(x["Item2"]))).ToList();Complete(image,root,sha,prefix);
    }
    static void EmptyAndNamespace()
    {
        string root,image=Image("empty",out root),sha=Hash(image);var result=Run(image,root,sha,CancellationToken.None,null,true,"empty");
        Check(result.Candidates==0&&result.Files==0&&(bool)State(root)["Complete"],"empty candidate list has explicit durable completion");
        Compare(result,Run(image,root,sha,CancellationToken.None,m=>{throw new Exception("empty export restarted");},true,"empty"));
        string folder,source=Image("source-root",out folder),hash=Hash(source);bool failed=false;
        try{Run(source,folder,hash,CancellationToken.None,null,true,"source-root");}catch(IOException){failed=true;}
        Check(failed&&reads.Count==0&&Anchor(folder)==null&&Hash(source)==hash,"export root cannot contain its source, even before a copy child exists");
    }
    static void Relocated()
    {
        string root,image=Image("relocate",out root),sha=Hash(image);var prefixReads=Cancel(image,root,sha,"file bytes");var anchor=Anchor(root);
        string destination=Path.Combine(work,"moved-"+Guid.NewGuid().ToString("N")),prefix=Path.GetFullPath(work)+Path.DirectorySeparatorChar;
        Check(Path.GetFullPath(root).StartsWith(prefix,StringComparison.OrdinalIgnoreCase)&&Path.GetFullPath(destination).StartsWith(prefix,StringComparison.OrdinalIgnoreCase)&&!Directory.Exists(destination),
            "both recursive move targets are unique owned paths under the verified workspace");
        Directory.Move(root,destination);anchor.Path=Path.Combine(destination,"ext4.state",Path.GetFileName(anchor.Path));SaveAnchor(destination,anchor);
        Complete(Path.Combine(destination,"owned.dd"),destination,sha,prefixReads);
    }
    public static int Main(string[] args)
    {
        try{
            if(typeof(Ext4Recovery).GetMethod("ExportVolumeCandidatesCheckpointed",Private)==null){Console.WriteLine("FAIL: baseline lacks a candidate export controller");return 1;}
            if(args.Length==4&&args[0]=="--worker"){
                Run(args[1],args[2],Hash(args[1]),CancellationToken.None,m=>{if(m.Contains("file bytes")){File.WriteAllText(args[3],Json.Serialize(reads));Thread.Sleep(Timeout.Infinite);}});return 3;
            }
            fixtures=Path.GetFullPath(args[1]);work=Path.Combine(Path.GetFullPath(args[0]),".build","ext4-export-checkpoints-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            foreach(string phase in new[]{"candidate tree","entry plan","file bytes","finished candidate"})CancelResume(phase);
            Histories();Repair();ParentFailure();foreach(string kind in new[]{"source","output","cursor"})Tamper(kind);
            foreach(string kind in new[]{"name","groups","baseline","output-root"})Binding(kind);EmptyAndNamespace();Relocated();KilledProcess();
            Console.WriteLine("PASS Ext4ExportCheckpoint: "+checks+" checks; volume candidate export only, not whole-engine resume or devices");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
