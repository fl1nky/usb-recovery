using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using UsbRecovery;

public static class RecoveryContinuityTests
{
    static int checks;static string work;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string Folder(string name){string path=Path.Combine(work,name);Directory.CreateDirectory(path);return path;}
    static RecoveryOptions TextOptions(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,TextFragments=true,TextQuery="needle"};}
    static void BoundedAtomicState()
    {
        string folder=Folder("bounded"),file=Path.Combine(folder,"state.json");RecoveryCore.SaveJson(file,new{previous="durable"});string before=Hash(file);bool rejected=false;
        try{RecoveryCore.SaveJsonBounded(file,new{value=new string('Я',100)},64);}catch(IOException){rejected=true;}
        Check(rejected&&Hash(file)==before&&!Directory.GetFiles(folder,"*.partial").Any(),"oversize UTF8 metadata never replaces the prior named checkpoint");
    }
    static void Availability(string source)
    {
        string folder=Folder("io");string before=Hash(source);
        using(var guard=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read))using(var run=RecoverySession.AcquireRunLock(folder)){
            var health=new RecoveryIoHealth(source,guard,run);health.Check(CancellationToken.None);health.Check(CancellationToken.None);
            bool writesDenied=false;try{using(var writer=new FileStream(source,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)){} }catch(IOException){writesDenied=true;}
            Check(writesDenied&&Hash(source)==before,"source lease denies concurrent source writes; health only touches the owned run lock");
            guard.Dispose();bool failed=false;try{health.Check(CancellationToken.None);}catch(RecoveryIoUnavailableException error){failed=error.Code=="RECOVERY_SOURCE_UNAVAILABLE";}
            Check(failed,"lost source lease produces an explicit source interruption, not an empty successful pass");
        }
        folder=Folder("output-io");using(var guard=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read)){
            var run=RecoverySession.AcquireRunLock(folder);var health=new RecoveryIoHealth(source,guard,run);run.Dispose();bool failed=false;
            try{health.Check(CancellationToken.None);}catch(RecoveryIoUnavailableException error){failed=error.Code=="RECOVERY_OUTPUT_UNAVAILABLE";}
            Check(failed&&Hash(source)==before,"lost output lease is distinguished and source bytes remain untouched");
        }
    }
    static void CompletionContracts()
    {
        foreach(var item in new[]{new{Key="refs",File="refs/report.json"},new{Key="partitions",File="partition-search.json"},new{Key="fragmented-media",File="fragmented-media.json"}}){
            string root=Folder("completion-"+item.Key),file=Path.Combine(root,item.File.Replace('/',Path.DirectorySeparatorChar));Directory.CreateDirectory(Path.GetDirectoryName(file));
            foreach(string state in new[]{"limited","partial","running","cancelled","incomplete"}){
                RecoveryCore.SaveJson(file,new{status=state});bool rejected=false;try{RecoveryStageCompletion.RequireComplete(root,item.Key);}catch(IOException){rejected=true;}Check(rejected,"unfinished "+item.Key+" status "+state+" is never reusable completion");}
            RecoveryCore.SaveJson(file,new{Status="complete",Limited=true});bool limit=false;try{RecoveryStageCompletion.RequireComplete(root,item.Key);}catch(IOException){limit=true;}Check(limit,"explicit limit flag overrides a complete label");
            RecoveryCore.SaveJson(file,new{status="complete"});RecoveryStageCompletion.RequireComplete(root,item.Key);Check(true,"finished report accepted only after complete coverage");
        }
    }
    static void AllMethodBoundaries(string source)
    {
        // These are the public method output contracts, not fabricated recovered files.
        var scopes=new Dictionary<string,string>{
            {"partitions","partition-search.json"},{"fat","filesystem/unit.bin"},{"ntfs","ntfs/unit.bin"},
            {"ext4","ext4/unit.bin"},{"refs","refs/unit.bin"},{"ntfs-records","metadata-rescue/unit.bin"},
            {"photorec","files.1/unit.bin"},{"photos","extra-photos/unit.bin"},{"containers","containers/unit.bin"},
            {"archive-members","salvage-content/unit.bin"},{"fragmented-zip","fragmented-archives/unit.bin"},
            {"fragmented-photos","fragmented-photos/unit.bin"},{"fragmented-media","fragmented-media/unit.bin"},
            {"user-signatures","user-signatures/unit.bin"},{"text","text-fragments/unit.bin"}};
        string sourceSha=Hash(source);
        foreach(var pair in scopes){string root=Folder("boundary-"+pair.Key),path=Path.Combine(root,pair.Value.Replace('/',Path.DirectorySeparatorChar));
            var session=RecoverySession.Start(root,source,sourceSha,TextOptions(),CancellationToken.None);session.Begin(pair.Key);Directory.CreateDirectory(Path.GetDirectoryName(path));File.WriteAllText(path,"owned completed output before simulated interruption");string original=Hash(path);
            session.Fail(pair.Key,"cancelled",null);session.Status("cancelled");var reopened=RecoverySession.Open(root,source,TextOptions(),CancellationToken.None,message=>{});reopened.Begin(pair.Key);
            Check(!File.Exists(path),pair.Key+": unfinished workspace is isolated before retry");string[] retained=Directory.GetFiles(Path.Combine(root,"attempt-history"),Path.GetFileName(path),SearchOption.AllDirectories);
            Check(retained.Length==1&&Hash(retained[0])==original,pair.Key+": all prior completed payload bytes survive a retry");
            Directory.CreateDirectory(Path.GetDirectoryName(path));File.WriteAllText(path,"fresh completed unit");reopened.Finish(pair.Key,1,false,CancellationToken.None);reopened.Status("finished");
            var completed=RecoverySession.Open(root,source,TextOptions(),CancellationToken.None,message=>{});Check(completed.Completed(pair.Key)!=null,pair.Key+": durable source-bound completed unit is reusable");
            File.AppendAllText(path,"tamper");bool rejected=false;try{RecoverySession.Open(root,source,TextOptions(),CancellationToken.None,message=>{});}catch(IOException){rejected=true;}Check(rejected,pair.Key+": changed saved output cannot be silently reused");
        }
    }
    static void LegacyLimitedCompletion(string source)
    {
        string root=Folder("legacy-limited-text");var session=RecoverySession.Start(root,source,Hash(source),TextOptions(),CancellationToken.None);session.Begin("text");
        int count=RawTextSearch.Recover(source,root,TextOptions().TextQuery,CancellationToken.None,(a,b)=>{});
        string report=Path.Combine(root,"text-search.json");RecoveryCore.SaveJson(report,new{status="limited"});string limitedHash=Hash(report);
        session.Finish("text",count,false,CancellationToken.None);session.Status("finished");
        var result=RecoveryPipeline.Resume(root,CancellationToken.None,message=>{});
        Check(result.ResumedStages==0&&result.UniqueFiles>0,"legacy source-bound limited report is rerun instead of reused as completed");
        RecoveryStageCompletion.RequireComplete(root,"text");Check(Hash(report)!=limitedHash,"actual rerun replaces limited report with current completed result");
        Check(Directory.GetFiles(Path.Combine(root,"attempt-history"),"text-search.json",SearchOption.AllDirectories).Any(path=>Hash(path)==limitedHash),"legacy limited report and prior results remain in attempt history");
    }
    static void ActualCancelAndResume(string source,bool denyEngineReport)
    {
        string root=Folder(denyEngineReport?"actual-text-report":"actual-text-session"),checksum=Path.Combine(work,"source.sha256");File.WriteAllText(checksum,Hash(source));string sessionPath=Path.Combine(root,RecoverySession.FileName),deniedPath=denyEngineReport?Path.Combine(root,"text-search.json"):sessionPath,prior=null;bool stopped=false;
        using(var cancel=new CancellationTokenSource()){
            try{RecoveryPipeline.Run(source,root,TextOptions(),cancel.Token,message=>{},checksum,update=>{
                if(update.Key=="text"&&update.State=="running"&&update.Completed>0&&!cancel.IsCancellationRequested){
                    if(!File.Exists(deniedPath))File.WriteAllText(deniedPath,"{\"status\":\"running\"}");prior=Hash(deniedPath);File.SetAttributes(deniedPath,File.GetAttributes(deniedPath)|FileAttributes.ReadOnly);cancel.Cancel();}
            });}catch(OperationCanceledException){stopped=true;}
            finally{if(File.Exists(deniedPath))File.SetAttributes(deniedPath,File.GetAttributes(deniedPath)&~FileAttributes.ReadOnly);}
        }
        Check(stopped&&prior!=null&&Hash(deniedPath)==prior,"actual cancellation stays OperationCanceledException even if stopped-state persistence is denied; named state unchanged");
        Check(!File.Exists(Path.Combine(root,"files-index.json")),"cancelled only-method run publishes no successful final catalog");
        var result=RecoveryPipeline.Resume(root,CancellationToken.None,message=>{});Check(result.UniqueFiles>0&&RecoverySession.Read(root).Stages.Single().Status=="complete","actual method restarts safely from its durable boundary after output access returns");
        string report=Hash(Path.Combine(root,"text-search.json"));var resumed=RecoveryPipeline.Resume(root,CancellationToken.None,message=>{});
        Check(resumed.ResumedStages==1&&Hash(Path.Combine(root,"text-search.json"))==report,"completed actual text pass is reused without redoing recovery");
    }
    public static int Main(string[] args)
    {
        try{work=Path.Combine(Path.GetFullPath(args[0]),".build","recovery-continuity-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            string source=Path.Combine(work,"source.dd");byte[] data=new byte[8*1024*1024];for(int at=4096;at<data.Length;at+=1024*1024){byte[] text=System.Text.Encoding.UTF8.GetBytes("needle owned synthetic recoverable text fragment\n");Array.Copy(text,0,data,at,text.Length);}File.WriteAllBytes(source,data);string before=Hash(source);
            BoundedAtomicState();Availability(source);CompletionContracts();AllMethodBoundaries(source);LegacyLimitedCompletion(source);ActualCancelAndResume(source,false);ActualCancelAndResume(source,true);Check(Hash(source)==before,"all controlled workflows preserve source bytes");
            Console.WriteLine("PASS RecoveryContinuity: "+checks+" checks;15 method boundaries, immutable completed reuse and interrupted-output retention, explicit source/output lease failures, bounded atomic state, actual text cancellation with failed persistence and successful resume. Synthetic ordinary files/closed handles only; no physical-device claim.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
