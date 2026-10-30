using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class PhotoCheckpointPortableTests
{
    public sealed class Fixture {public string Name,Image,Sha256;}
    public sealed class Manifest {public List<Fixture> Cases;}
    static int checks;static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};}
    static long Position(string checkpoint)
    {var data=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(checkpoint));object value;if(!data.TryGetValue("Index",out value)||value==null)return -1;return Convert.ToInt64(((Dictionary<string,object>)value)["Position"]);}
    static void Copy(string from,string to)
    {
        Directory.CreateDirectory(to);foreach(string file in Directory.GetFiles(from,"*",SearchOption.AllDirectories)){
            string relative=file.Substring(from.Length+1);string target=RecoveryCatalog.SafeFile(to,relative);Directory.CreateDirectory(Path.GetDirectoryName(target));File.Copy(file,target);
        }
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),fixtures=Path.Combine(project,".build","photo-portable-fixtures"),work=Path.Combine(project,".build","photo-checkpoint-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            var fixture=Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json"))).Cases.First(x=>x.Name.StartsWith("png-",StringComparison.Ordinal));
            string image=Path.Combine(work,"owned-image.dd");File.Copy(Path.Combine(fixtures,fixture.Image),image);using(var file=new FileStream(image,FileMode.Open,FileAccess.Write))file.SetLength(70L*1024*1024);
            string before=Hash(image),run=Path.Combine(work,"interrupted");Directory.CreateDirectory(run);var session=RecoverySession.Start(run,image,before,Options(),CancellationToken.None);session.Begin("fragmented-photos");long savedBytes=0;bool stopped=false;
            using(var stop=new CancellationTokenSource()){
                try{FragmentedPhotoRecovery.Recover(image,run,stop.Token,(a,b)=>{},null,checkpoint=>{
                    if(stop.IsCancellationRequested)return;session.CapturePhotoCheckpoint(checkpoint);long position=Position(checkpoint.Path);
                    if(position>0&&position<new FileInfo(image).Length){savedBytes=position;stop.Cancel();}
                });}catch(OperationCanceledException){stopped=true;}
            }
            Check(stopped&&savedBytes>=32L*1024*1024&&savedBytes<new FileInfo(image).Length,"actual frozen helper interrupted after a positive durable index checkpoint");
            session.Fail("fragmented-photos","cancelled",null);session.Status("cancelled");var saved=RecoverySession.Read(run);Check(saved.Stages.Single().CheckpointSequence>1&&saved.Stages.Single().Status=="cancelled","parent persisted acknowledged generation before actual child cancellation");
            string damaged=Path.Combine(work,"tampered");Copy(run,damaged);string damagedPoint=RecoveryCatalog.SafeFile(damaged,saved.Stages.Single().CheckpointPath);File.AppendAllText(damagedPoint,"tampered");string state=Hash(Path.Combine(damaged,RecoverySession.FileName));bool rejected=false;
            try{RecoveryPipeline.Resume(damaged,CancellationToken.None,s=>{});}catch(IOException){rejected=true;}
            Check(rejected&&Hash(Path.Combine(damaged,RecoverySession.FileName))==state&&!File.Exists(Path.Combine(damaged,"files-index.json")),"tampered real checkpoint is rejected before a successful archive or state mutation");
            string relocated=Path.Combine(work,"relocated");Directory.Move(run,relocated);var logs=new List<string>();var result=RecoveryPipeline.Resume(relocated,CancellationToken.None,logs.Add);
            var report=Json.Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(Path.Combine(relocated,"fragmented-photo-search.json")));
            Check(report.ResumedFromCheckpoint&&report.ResumedIndexBytes==savedBytes&&report.ReusedCandidates==0,"actual frozen worker reports exact saved parser position after whole-session relocation");
            Check(report.Status=="complete"&&report.SourceUnchanged&&report.SourceSha256==before&&report.Candidates==1,"source-verified resumed method completes exactly one candidate");
            Check(result.UniqueFiles==1&&result.Candidates==1&&!Directory.Exists(Path.Combine(relocated,"attempt-history")),"pipeline continues existing method instead of manufacturing a restarted attempt");
            var item=RecoveryCatalog.Load(relocated).Items.Single();Check(item.Sha256==fixture.Sha256&&item.Quality=="structural_candidate"&&item.SourceRanges.Count>1,"resumed candidate matches independent original and retains structural source mapping");
            Check(!File.Exists(Path.Combine(relocated,"fragmented-photos","job.incomplete"))&&!Directory.GetFiles(Path.Combine(relocated,"fragmented-photos"),"*.partial").Any(),"successful source-checked publication removes unfinished markers");
            var completed=RecoverySession.Read(relocated).Stages.Single();Check(completed.Status=="complete"&&completed.Artifacts.Any(x=>x.Path.StartsWith("fragmented-photos.state/",StringComparison.Ordinal)),"all acknowledged state is part of completed-stage evidence");
            string prior=Hash(Path.Combine(relocated,"fragmented-photo-search.json"));Check(RecoveryPipeline.Resume(relocated,CancellationToken.None,s=>{}).ResumedStages==1&&Hash(Path.Combine(relocated,"fragmented-photo-search.json"))==prior,"subsequent resume reuses verified completed stage without running helper again");
            Check(Hash(image)==before,"cancellation, relocation, tamper rejection and all resumes preserve source bytes");
            Console.WriteLine("PASS PhotoCheckpointPortable: "+checks+" checks; actual frozen helper cancellation and within-index continuation, relocated immutable anchor, tamper rejection, exact PNG/source mapping and completed-stage reuse. Synthetic70MiB image only; full source SHA is still reread.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
