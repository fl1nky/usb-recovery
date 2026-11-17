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

public static class FragmentedMediaCheckpointTests
{
    static int checks;
    static string work,fixtures;
    static List<Tuple<long,int>> reads;
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string file){return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{});}
    static void Set(object owner,string name,object value){owner.GetType().GetField(name).SetValue(owner,value);}
    static string Parent(string root){return Path.Combine(root,"anchor.json");}
    static RecoveryMethodCheckpoint Anchor(string root)
    {return File.Exists(Parent(root))?Json.Deserialize<RecoveryMethodCheckpoint>(File.ReadAllText(Parent(root),Encoding.UTF8)):null;}
    static void Save(string root,RecoveryMethodCheckpoint value)
    {
        string temp=Parent(root)+"."+Guid.NewGuid().ToString("N")+".partial";byte[] bytes=Encoding.UTF8.GetBytes(Json.Serialize(value));bool own=false;
        try{using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){own=true;file.Write(bytes,0,bytes.Length);file.Flush(true);}
            if(File.Exists(Parent(root)))File.Replace(temp,Parent(root),null);else File.Move(temp,Parent(root));}
        finally{if(own&&File.Exists(temp))File.Delete(temp);}
    }
    sealed class Source:FileStream
    {
        public bool Zero;
        public readonly List<Tuple<long,int>> Reads=new List<Tuple<long,int>>();
        public Source(string path):base(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1){}
        public override int Read(byte[] bytes,int at,int count){Reads.Add(Tuple.Create(Position,count));return Zero?0:base.Read(bytes,at,count);}
    }
    static string Image(string label,out string root,string fixture="avc-scattered.dd")
    {root=Path.Combine(work,label+"-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);string image=Path.Combine(root,"owned.dd");File.Copy(Path.Combine(fixtures,fixture),image);return image;}
    static FragmentedMediaRecovery.Report Run(string image,string root,string sha,CancellationToken token,Action<string> progress,string change=null)
    {
        using(var input=new Source(image)){
            var limits=new FragmentedMediaRecovery.Limits();if(change=="limits")limits.MaxCandidates--;
            object c=Activator.CreateInstance(typeof(FragmentedMediaRecovery).GetNestedType("Context",BindingFlags.NonPublic),true);
            Set(c,"Input",input);Set(c,"Cancel",token);Set(c,"Limits",limits);
            object context=Activator.CreateInstance(typeof(FragmentedMediaRecovery).Assembly.GetType("UsbRecovery.RecoveryCheckpointContext",true),true);
            Set(context,"Directory",root);Set(context,"Method","fragmented-media");Set(context,"SourceSha256",sha);Set(context,"Settings",change=="settings"?"changed":"owned-media-v1");
            Set(context,"Resume",Anchor(root));Set(context,"Commit",(Action<RecoveryMethodCheckpoint>)(a=>Save(root,a)));
            reads=input.Reads;
            Action<string> notify=m=>{
                if(change=="zero")input.Zero=true;
                if(change=="mid-limits")limits.MaxCandidates--;
                if(change=="mid-owner")Set(c,"PublishCandidate",null);
                if(progress!=null)progress(m);
            };
            try{typeof(FragmentedMediaRecovery).GetMethod("RecoverCheckpointedCore",BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,new object[]{c,context,null,notify});}
            catch(TargetInvocationException error){throw error.InnerException;}
            return (FragmentedMediaRecovery.Report)c.GetType().GetField("Report").GetValue(c);
        }
    }
    static void Compare(string image,string root,string sha,FragmentedMediaRecovery.Report report)
    {
        string control=Path.Combine(root,"legacy-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(control);
        FragmentedMediaRecovery.Recover(image,control,CancellationToken.None,null);
        string expected=File.ReadAllText(Path.Combine(control,"fragmented-media.json"),Encoding.UTF8);
        Check(File.ReadAllText(Path.Combine(root,"fragmented-media.json"),Encoding.UTF8)==expected,"complete report preserves legacy budgets, source-read accounting, decisions and source maps");
        Check(Json.Serialize(report)==Json.Serialize(Json.Deserialize<FragmentedMediaRecovery.Report>(expected)),"in-memory report matches the legacy report including separately serialized source binding");
        foreach(var result in report.Files){Check(Hash(Path.Combine(root,result.Path.Replace('/',Path.DirectorySeparatorChar)))==Hash(Path.Combine(control,result.Path.Replace('/',Path.DirectorySeparatorChar))),"published assembly matches legacy bytes");Check(!result.PayloadAuthenticated&&!result.DeletionConfirmed,"structural assembly retains unknown ownership/deletion");}
        Check(Hash(image)==sha,"media continuation leaves source unchanged");
    }
    static void Complete(string image,string root,string sha)
    {
        var result=Run(image,root,sha,CancellationToken.None,null);Compare(image,root,sha,result);
        var again=Run(image,root,sha,CancellationToken.None,m=>{throw new Exception("completed durable phase repeated: "+m);});
        Check(reads.Count==0&&Json.Serialize(result)==Json.Serialize(again),"completed media source phases replay from verified state with zero copy/search source reads");
    }
    static void Cancel(string phase,string fixture="avc-scattered.dd")
    {
        string root,image=Image("cancel",out root,fixture),sha=Hash(image);bool stopped=false;
        using(var cancel=new CancellationTokenSource()){
            try{Run(image,root,sha,cancel.Token,m=>{if(m.StartsWith(phase,StringComparison.Ordinal))cancel.Cancel();});}catch(OperationCanceledException){stopped=true;}
        }
        Check(stopped&&Anchor(root)!=null,"cancellation anchors actual inner position at "+phase);Complete(image,root,sha);
    }
    static void Failure(string mode)
    {
        string root,image=Image(mode,out root),sha=Hash(image),before=null;FileStream held=null;bool failed=false,lockEstablished=false;long locked=0;
        try{Run(image,root,sha,CancellationToken.None,m=>{
            if(held!=null)return;
            if(mode=="parent"){before=Hash(Parent(root));held=new FileStream(Parent(root),FileMode.Open,FileAccess.Read,FileShare.Read);}
            if(mode=="read"){held=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read);locked=held.Length;held.Lock(0,locked);lockEstablished=true;}
            if(mode=="write"&&m.StartsWith("fragmented-media: mapped bytes 0 ",StringComparison.Ordinal)) {
                string partial=Directory.GetFiles(Path.Combine(root,"fragmented-media.state"),"copy-*.partial",SearchOption.AllDirectories).Single();
                held=new FileStream(partial,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);locked=4L*1024*1024;held.Lock(0,locked);lockEstablished=true;
            }
        },mode=="zero"?"zero":null);}catch(IOException){failed=true;}
        finally{if(held!=null){if(locked!=0)held.Unlock(0,locked);held.Dispose();}}
        if(mode=="write"||mode=="read")Check(lockEstablished,"actual byte-range lock is established before the engine fails");
        Check(failed,"real "+mode+" failure propagates without a successful archive");if(before!=null)Check(Hash(Parent(root))==before,"parent acknowledgement cannot advance on replacement denial");Complete(image,root,sha);
    }
    static void Repairs()
    {
        string root,image=Image("repair",out root),sha=Hash(image);var report=Run(image,root,sha,CancellationToken.None,null);
        string payload=Path.Combine(root,report.Files.Single().Path.Replace('/',Path.DirectorySeparatorChar));File.Delete(payload);Complete(image,root,sha);
        File.Delete(payload);Complete(image,root,sha);File.Delete(Path.Combine(root,"fragmented-media.json"));Complete(image,root,sha);
        File.AppendAllText(payload,"foreign");string before=Hash(payload);bool failed=false;try{Run(image,root,sha,CancellationToken.None,null);}catch(IOException){failed=true;}
        Check(failed&&Hash(payload)==before,"changed existing candidate is preserved and not accepted");
    }
    static void Tamper(string mode)
    {
        string root,image=Image(mode,out root),sha=Hash(image);
        using(var cancel=new CancellationTokenSource()){try{Run(image,root,sha,cancel.Token,m=>cancel.Cancel());}catch(OperationCanceledException){}}
        if(mode=="source")using(var file=new FileStream(image,FileMode.Open,FileAccess.Write))file.WriteByte(7);
        if(mode=="state")File.AppendAllText(Anchor(root).Path,"changed");
        if(mode=="map")File.WriteAllText(Path.Combine(root,"source-read-errors.json"),"{}");
        bool failed=false;try{Run(image,root,sha,CancellationToken.None,null,mode);}catch(IOException){failed=true;}
        Check(failed,"changed "+mode+" is rejected");
    }
    static void Kill()
    {
        string root,image=Image("kill",out root),sha=Hash(image),ready=Path.Combine(root,"ready");
        using(var child=Process.Start(new ProcessStartInfo{FileName=Assembly.GetExecutingAssembly().Location,Arguments="worker \""+image+"\" \""+root+"\" "+sha+" \""+ready+"\"",UseShellExecute=false,CreateNoWindow=true})){
            try{var timer=Stopwatch.StartNew();while(!File.Exists(ready)&&!child.HasExited&&timer.ElapsedMilliseconds<15000)Thread.Sleep(25);Check(File.Exists(ready)&&!child.HasExited,"owned worker reaches an acknowledged inner metadata unit");child.Kill();child.WaitForExit();}
            finally{if(!child.HasExited){child.Kill();child.WaitForExit();}}
        }
        Complete(image,root,sha);
    }
    public static int Main(string[] args)
    {
        try{
            if(args[0]=="worker"){Run(args[1],args[2],args[3],CancellationToken.None,m=>{File.WriteAllText(args[4],"ready");Thread.Sleep(Timeout.Infinite);});return 0;}
            fixtures=Path.GetFullPath(args[1]);work=Path.Combine(Path.GetFullPath(args[0]),".build","media-checkpoint-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            if(args.Contains("--profile-faults-only")) {
                Failure("write");
                foreach(string path in args.Skip(2).Where(p=>!p.StartsWith("--",StringComparison.Ordinal))) {
                    Cancel("fragmented-media: mapped bytes ",Path.GetFullPath(path));
                }
                Console.WriteLine("PASS FragmentedMediaProfileCheckpoint: "+checks+" checks; format-specific copy interruption and actual output byte-range lock");return 0;
            }
            foreach(string fixture in Directory.GetFiles(fixtures,"*.dd")){string root,image=Image("fixture",out root,Path.GetFileName(fixture));Complete(image,root,Hash(image));}
            foreach(string path in args.Skip(2)) {
                string image=Path.GetFullPath(path),root=Path.Combine(work,"additional-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
                Complete(image,root,Hash(image));
            }
            foreach(string phase in new[]{"fragmented-media: metadata unit ","fragmented-media: mapped bytes ","fragmented-media: file ","fragmented-media: report pending","fragmented-media: report ready","fragmented-media: engine complete"})Cancel(phase);
            foreach(string mode in new[]{"parent","read","zero","write"})Failure(mode);
            foreach(string path in args.Skip(2).Where(p=>new[]{"image.dd","front-4k-zero.dd","avc-aac-faststart-chunk-islands.dd","main-hvc1-scattered.dd"}.Contains(Path.GetFileName(p))))
                Cancel("fragmented-media: mapped bytes ",Path.GetFullPath(path));
            foreach(string mode in new[]{"source","state","map","limits","settings"})Tamper(mode);
            foreach(string mode in new[]{"mid-limits","mid-owner"}){string root,image=Image(mode,out root);bool failed=false;try{Run(image,root,Hash(image),CancellationToken.None,null,mode);}catch(IOException){failed=true;}Check(failed,"mid-operation owner/limits change fails closed");}
            Repairs();Kill();Console.WriteLine("PASS FragmentedMediaCheckpoint: "+checks+" checks; owned independent QTFF images, managed continuation only");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
