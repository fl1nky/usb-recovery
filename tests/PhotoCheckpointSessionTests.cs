using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class PhotoCheckpointSessionTests
{
    static int checks;static string work,source,sourceSha;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static bool Io(Action action){try{action();return false;}catch(IOException){return true;}}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};}
    static string Folder(string name){string path=Path.Combine(work,name);Directory.CreateDirectory(path);return path;}
    static RecoverySession Start(string root){return RecoverySession.Start(root,source,sourceSha,Options(),CancellationToken.None);}
    static PhotoRecoveryCheckpoint Checkpoint(string root,long sequence,string body="{\"Schema\":1}")
    {
        string path=Path.Combine(root,"fragmented-photos.state","checkpoint-"+sequence.ToString("D12")+".json");Directory.CreateDirectory(Path.GetDirectoryName(path));File.WriteAllText(path,body);
        return new PhotoRecoveryCheckpoint{Path=path,Sha256=Hash(path),Sequence=sequence};
    }
    static string Payload(string root)
    {string path=Path.Combine(root,"fragmented-photos","owned.jpg.partial");Directory.CreateDirectory(Path.GetDirectoryName(path));File.WriteAllText(path,"owned partial candidate");return path;}
    static void Preserved()
    {
        string root=Folder("preserve");var session=Start(root);session.Begin("fragmented-photos");var first=Checkpoint(root,1);session.CapturePhotoCheckpoint(first);string payload=Payload(root),before=Hash(payload);
        session.Fail("fragmented-photos","cancelled",null);session.Status("cancelled");
        var saved=RecoverySession.Read(root).Stages.Single();Check(saved.CheckpointSequence==1&&saved.CheckpointPath=="fragmented-photos.state/checkpoint-000000000001.json","persisted anchor is relative and generation-bound");
        var reopened=RecoverySession.Open(root,source,Options(),CancellationToken.None,null);Check(reopened.PhotoCheckpoint().Path==first.Path&&reopened.PhotoCheckpoint().Sha256==first.Sha256,"reopened session returns only the acknowledged checkpoint");
        reopened.Begin("fragmented-photos",true);Check(File.Exists(payload)&&Hash(payload)==before&&!Directory.Exists(Path.Combine(root,"attempt-history")),"continuation preserves interrupted candidate and index without a method restart");
        var second=Checkpoint(root,2,"{\"Schema\":1,\"generation\":2}");reopened.CapturePhotoCheckpoint(second);string state=Hash(Path.Combine(root,RecoverySession.FileName));
        Check(Io(()=>reopened.CapturePhotoCheckpoint(first)),"older progress cannot replace a newer acknowledged generation");Check(Hash(Path.Combine(root,RecoverySession.FileName))==state,"rejected rewind leaves persisted session unchanged");
        reopened.CapturePhotoCheckpoint(second);Check(Hash(Path.Combine(root,RecoverySession.FileName))==state,"duplicate identical progress is idempotent");
        var crashed=RecoverySession.Open(root,source,Options(),CancellationToken.None,null);Check(crashed.PhotoCheckpoint().Sequence==2,"hard parent interruption keeps its last durable acknowledged generation");
        crashed.Begin("fragmented-photos",true);Check(Hash(payload)==before,"reopening running stage preserves unfinished bytes");
        var completed=Path.Combine(root,"fragmented-photos","owned.jpg");File.Move(payload,completed);crashed.Finish("fragmented-photos",1,false,CancellationToken.None);
        Check(crashed.State.Stages.Single().Artifacts.Any(x=>x.Path.StartsWith("fragmented-photos.state/",StringComparison.Ordinal)),"completed stage includes immutable checkpoint files in artifact hashes");
        Check(RecoveryCore.RecoveredFiles(root).Count()==1&&!RecoveryCore.RecoveredFiles(root).Any(x=>x.EndsWith(".json",StringComparison.Ordinal)),"checkpoint metadata never appears as recovered payload");
        RecoverySession.Open(root,source,Options(),CancellationToken.None,null);File.AppendAllText(second.Path,"mutated");
        Check(Io(()=>RecoverySession.Open(root,source,Options(),CancellationToken.None,null)),"changed checkpoint invalidates even a completed saved stage");
    }
    static void Rejections()
    {
        string root=Folder("rejections");var session=Start(root);session.Begin("fragmented-photos");var valid=Checkpoint(root,1);session.CapturePhotoCheckpoint(valid);session.Fail("fragmented-photos","cancelled",null);
        string state=Hash(Path.Combine(root,RecoverySession.FileName));File.AppendAllText(valid.Path,"different");
        Check(Io(()=>RecoverySession.Open(root,source,Options(),CancellationToken.None,null)),"cancelled checkpoint tampering is rejected before any output moves");Check(Hash(Path.Combine(root,RecoverySession.FileName))==state&&!Directory.Exists(Path.Combine(root,"attempt-history")),"failed verification preserves current state and source candidates");
        root=Folder("capture-validation");session=Start(root);session.Begin("fragmented-photos");valid=Checkpoint(root,1);state=Hash(Path.Combine(root,RecoverySession.FileName));
        Check(Io(()=>session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint{Path=valid.Path,Sha256=new string('0',64),Sequence=1})),"callback hash must match durable checkpoint bytes");
        Check(Io(()=>session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint{Path=valid.Path,Sha256=valid.Sha256,Sequence=2})),"filename must encode the reported generation");
        Check(Io(()=>session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint{Path=source,Sha256=sourceSha,Sequence=1})),"callback cannot read an anchor outside the recovery run");
        Check(Hash(Path.Combine(root,RecoverySession.FileName))==state,"all rejected callback envelopes leave saved state unchanged");
        session.CapturePhotoCheckpoint(valid);session.Fail("fragmented-photos","cancelled",null);Check(Io(()=>session.CapturePhotoCheckpoint(Checkpoint(root,2))),"late helper progress cannot mutate a cancelled stage");
        var model=RecoverySession.Read(root);var stage=model.Stages.Single();stage.Key="photos";RecoveryCore.SaveJson(Path.Combine(root,RecoverySession.FileName),model);Check(Io(()=>RecoverySession.Read(root)),"other methods cannot borrow a photo checkpoint");
        stage.Key="fragmented-photos";stage.CheckpointPath="../checkpoint-000000000001.json";RecoveryCore.SaveJson(Path.Combine(root,RecoverySession.FileName),model);Check(Io(()=>RecoverySession.Read(root)),"stored traversal cannot become a checkpoint source");
    }
    static void RestartWithoutAnchor()
    {
        string root=Folder("old-job");var session=Start(root);session.Begin("fragmented-photos");var unacknowledged=Checkpoint(root,1);string candidate=Payload(root),before=Hash(candidate);session.Fail("fragmented-photos","cancelled",null);
        string quarantined=Path.Combine(root,"fragmented-photos.state","orphan-owned");Directory.CreateDirectory(quarantined);using(var bitmap=new Bitmap(4,4))bitmap.Save(Path.Combine(quarantined,"unacknowledged.png"),ImageFormat.Png);
        Check(session.PhotoCheckpoint()==null,"unacknowledged local checkpoint is never implicitly trusted");Check(Io(()=>session.Begin("fragmented-photos",true)),"explicit continuation requires a parent anchor");
        session.Begin("fragmented-photos");Check(!File.Exists(candidate)&&!File.Exists(unacknowledged.Path),"unanchored job is moved before an independent restart");
        var attempts=Directory.GetDirectories(Path.Combine(root,"attempt-history"));Check(attempts.Length==1&&Hash(Directory.GetFiles(attempts[0],"owned.jpg.partial",SearchOption.AllDirectories).Single())==before,"old partial candidate remains intact in previous-attempt history");
        PhotoCatalog.Build(root,CancellationToken.None,null);var gallery=new JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string,object>>(File.ReadAllText(Path.Combine(root,"photo-catalog.json")));Check(Convert.ToInt64(gallery["candidates"])==0,"quarantined unacknowledged state images remain outside the gallery after history moves");
    }
    public static int Main(string[] args)
    {
        try{string project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","photo-checkpoint-session-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);source=Path.Combine(work,"own-image.dd");File.WriteAllBytes(source,new byte[65536]);sourceSha=Hash(source);
            Preserved();Rejections();RestartWithoutAnchor();Check(Hash(source)==sourceSha,"session checkpoints never modify source image");
            Console.WriteLine("PASS PhotoCheckpointSession: "+checks+" checks; acknowledged immutable generations, cancellation/crash continuation, fail-closed source paths and hashes, unchanged state on rejection, payload filtering and previous-attempt retention. Synthetic regular files only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
