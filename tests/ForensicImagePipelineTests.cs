using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ForensicImagePipelineTests
{
    static int checks;
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=8*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,Containers=false,EmbeddedPhotos=true};}
    static string work,native;
    static void Native()
    {
        var manifest=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(native,"manifest.json")));
        foreach(string name in new[]{"encase6-fast.E01","ex01-fast.Ex01","encase6-split.E01"}){
            string input=Path.Combine(native,name),run=Path.Combine(work,name),before=Hash(input);
            var found=RecoveryPipeline.Run(input,run,Options(),CancellationToken.None,null);
            var session=RecoverySession.Read(run);string raw=ForensicImageSource.WorkingPath(run);
            Check(session.SourcePath==raw&&Hash(raw)==Convert.ToString(manifest["sha256"]),"Pipeline uses independently expected logical RAW, not container bytes");
            Check(found.UniqueFiles>=3&&Hash(input)==before,"Ordinary photo engine finds native payloads without modifying source");
            var catalog=RecoveryCatalog.Load(run);
            foreach(var item in catalog.Items){
                Check(item.SourceRanges.Count>0&&item.SourceRanges.All(r=>r.Offset>=0&&r.Length>0&&r.Offset<=new FileInfo(raw).Length-r.Length),"Catalog offsets are bounded logical RAW offsets");
                using(var expected=File.OpenRead(raw))using(var bytes=new MemoryStream()){
                    foreach(var range in item.SourceRanges){expected.Position=range.Offset;var block=new byte[checked((int)range.Length)];int done=0;while(done<block.Length){int n=expected.Read(block,done,block.Length-done);if(n==0)throw new EndOfStreamException();done+=n;}bytes.Write(block,0,block.Length);}
                    Check(bytes.ToArray().SequenceEqual(File.ReadAllBytes(RecoveryCatalog.SafeFile(run,item.Path))),"Replaying logical source extents reproduces exact extracted bytes");
                }
            }
            Check(RecoveryPipeline.Resume(run,CancellationToken.None,null).ResumedStages>=1,"Completed preparation and scan stages are verified and reused");
            if(name=="ex01-fast.Ex01"){
                string moved=run+"-moved";
                Check(Path.GetFullPath(moved).StartsWith(Path.GetFullPath(work)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),"Fixture move stays inside the owned test workspace");
                Directory.Move(run,moved);
                Check(RecoveryPipeline.Resume(moved,CancellationToken.None,null).ResumedStages>=1&&RecoverySession.Read(moved).SourcePath==ForensicImageSource.WorkingPath(moved),"A relocated job resolves its registered logical source relative to the new folder");
            }
        }
    }
    static void ReadMap()
    {
        string source=ForensicImageSource.WorkingPath(Path.Combine(work,"encase6-fast.E01")),map=Path.Combine(work,"holes.map"),run=Path.Combine(work,"mapped");
        File.WriteAllText(map,"0x0 + 1\n0 65536 -\n65536 "+(new FileInfo(source).Length-65536)+" +\n");
        var options=Options();options.ReadMapPath=map;
        var found=RecoveryPipeline.Run(source,run,options,CancellationToken.None,null);
        string raw=ForensicImageSource.WorkingPath(run);byte[] prefix=new byte[65536];
        using(var file=File.OpenRead(raw))Check(file.Read(prefix,0,prefix.Length)==prefix.Length&&prefix.All(b=>b==0),"Nonrescued bytes are masked only in the derivative copy");
        Check(FileEvidence.HasUnreadSource(run,raw)&&found.HasWarnings,"Read-map uncertainty reaches the catalog and metadata guards");
        var health=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(run,"source-read-errors.json")));
        Check(Convert.ToInt64(health["unreadBytes"])==65536&&Convert.ToString(health["sha256"])==Hash(raw),"Read map is bound to actual materialized bytes");
        File.AppendAllText(map,"# changed map\n");bool rejected=false;
        try{RecoveryPipeline.Resume(run,CancellationToken.None,null);}catch(IOException){rejected=true;}
        Check(rejected,"Changed external map cannot silently reuse an older prepared result");
    }
    static void Cancel()
    {
        string source=Path.Combine(work,"cancel.dd"),map=source+".map",run=Path.Combine(work,"cancelled");
        using(var file=new FileStream(source,FileMode.CreateNew,FileAccess.Write))file.SetLength(64L*1024*1024);
        File.WriteAllText(map,"0x0 + 1\n0 67108864 +\n");var options=Options();options.ReadMapPath=map;
        bool cancelled=false,observed=false;
        using(var stop=new CancellationTokenSource()){
            try{RecoveryPipeline.Run(source,run,options,stop.Token,null,null,state=>{if(state.Key=="source-preparation:materialize"){observed=true;stop.Cancel();}});}catch(OperationCanceledException){cancelled=true;}
        }
        Check(cancelled&&observed&&ForensicImageSource.HasRequest(run),"Actual worker cancellation preserves a resumable preparation request");
        var result=RecoveryPipeline.Resume(run,CancellationToken.None,null);
        Check(Hash(ForensicImageSource.WorkingPath(run))==Hash(source)&&result.UniqueFiles==0,"Resume publishes exact complete RAW and runs the saved scan");
    }
    public static int Main(string[] args)
    {
        try{string root=Path.GetFullPath(args[0]);native=Path.Combine(root,".build","forensic-image-fixtures");work=Path.Combine(root,".build","forensic-pipeline-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            Native();ReadMap();Cancel();Console.WriteLine("PASS ForensicImagePipeline: "+checks+" checks; actual helper/C# E01, Ex01, split segments, logical evidence, map masking/tamper, cancellation/resume and immutable controlled sources. No devices.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
