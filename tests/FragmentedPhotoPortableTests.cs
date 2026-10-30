using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class FragmentedPhotoPortableTests
{
    public sealed class Fixture {public string Name,Image,Original,Sha256,Status;public long Bytes;}
    public sealed class Manifest {public int Schema;public string LimitedImage;public List<Fixture> Cases;}
    static string project,fixtures,work;static int checks;
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=32*1024*1024};}
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string Output(string name){return Path.Combine(work,name+"-"+Guid.NewGuid().ToString("N").Substring(0,6));}
    static FragmentedPhotoRecovery.Report Report(string path){return Json().Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(path));}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,SmallBlocks=false,EmbeddedPhotos=false,Containers=false,MetadataRescue=false,ArchiveMembers=false,FragmentedArchives=false,CustomSignatures=false,FragmentedPhotos=true,FragmentedVideo=false};}
    static void SourceRanges(string image,string file,IEnumerable<FileExtent> extents,long expected)
    {
        long total=0;using(var source=File.OpenRead(image))using(var output=File.OpenRead(file)){
            foreach(var extent in extents){Check(extent.Offset>=0&&extent.Length>0&&extent.Offset<=source.Length-extent.Length,"catalog range within source image");source.Position=extent.Offset;long remaining=extent.Length;
                byte[] a=new byte[4096],b=new byte[4096];while(remaining>0){int amount=(int)Math.Min(a.Length,remaining);Check(source.Read(a,0,amount)==amount&&output.Read(b,0,amount)==amount,"catalog range exact read");Check(a.Take(amount).SequenceEqual(b.Take(amount)),"concatenating catalog ranges reproduces output bytes");remaining-=amount;total+=amount;}
            }
            Check(total==expected&&output.Position==output.Length,"catalog ranges cover complete emitted candidate");
        }
    }
    static void Wrapper(Fixture fixture)
    {
        string image=Path.Combine(fixtures,fixture.Image),before=Hash(image),run=Output("wrapper");int progress=0;
        int count=FragmentedPhotoRecovery.Recover(image,run,CancellationToken.None,(done,total)=>{progress++;Check(done>=0&&done<=total,"actual frozen helper byte progress");});
        var report=Report(Path.Combine(run,"fragmented-photo-search.json"));
        Check(count==1&&report.Candidates==1&&report.Status=="complete"&&report.Files.Count==1,fixture.Name+": real frozen helper -> wrapper publishes one candidate");
        Check(progress>0&&Hash(image)==before,fixture.Name+": helper progress and source preservation");var candidate=report.Files[0];string file=RecoveryCatalog.SafeFile(run,candidate.Path);
        Check(candidate.Sha256==fixture.Sha256&&Hash(file)==fixture.Sha256&&candidate.Bytes==fixture.Bytes,fixture.Name+": exact independent original bytes");
        Check(candidate.Status==fixture.Status,fixture.Name+": explicit structural provenance status");
        long logical=0;foreach(var extent in candidate.Extents){Check(extent.LogicalOffset==logical,"report logical ranges preserve order");logical+=extent.Length;}Check(logical==fixture.Bytes,"report complete logical extent coverage");
        var index=RecoveryCatalog.Build(run,CancellationToken.None,null);Check(index.Items.Count==1&&index.Candidates==1,"catalog excludes helper report metadata");var item=index.Items[0];
        Check(item.Quality=="structural_candidate"&&item.Status=="Кандидат сборки","image decoding never upgrades structural ownership/integrity evidence");
        Check(item.SourceRanges.Count>1&&item.Sha256==fixture.Sha256,"catalog imports actual reassembly source mapping");SourceRanges(image,file,item.SourceRanges,fixture.Bytes);
        File.WriteAllText(Path.Combine(run,"fragmented-photos","job.incomplete"),"synthetic marker only");
        var rebuilt=RecoveryCatalog.Build(run,CancellationToken.None,null);Check(rebuilt.Items.Count==1&&rebuilt.Candidates==1&&!rebuilt.Items.Any(x=>x.Name=="report.json"||x.Name=="job.incomplete"),"report and incomplete marker are never recovered files");
        Check(Hash(image)==before,"catalog and marker tests preserve source");
    }
    static void Pipeline(Fixture fixture)
    {
        string image=Path.Combine(fixtures,fixture.Image),before=Hash(image),run=Output("pipeline");var stages=new List<RecoveryStageProgress>();
        Directory.CreateDirectory(run);
        var result=RecoveryPipeline.Run(image,run,Options(),CancellationToken.None,s=>{},null,stages.Add);
        var index=RecoveryCatalog.Load(run);Check(result.UniqueFiles==1&&result.Candidates==1&&index.Items.Count==1,"pipeline retains only emitted photo");
        Check(stages.Any(x=>x.Key=="fragmented-photos"&&x.State=="complete"),"pipeline emits completed reassembly stage");var saved=RecoverySession.Read(run);var photo=saved.Stages.Single(x=>x.Key=="fragmented-photos");
        Check(photo.Status=="complete"&&photo.Candidates==1&&photo.Artifacts.Count>=3,"session binds report plus emitted candidate artifacts");
        Check(index.Items[0].Sha256==fixture.Sha256&&index.Items[0].Quality=="structural_candidate","pipeline catalog preserves reference hash and structural uncertainty");SourceRanges(image,RecoveryCatalog.SafeFile(run,index.Items[0].Path),index.Items[0].SourceRanges,fixture.Bytes);
        string reportHash=Hash(Path.Combine(run,"fragmented-photo-search.json"));var resumedStages=new List<RecoveryStageProgress>();var resumed=RecoveryPipeline.Resume(run,CancellationToken.None,s=>{},resumedStages.Add);
        Check(resumed.ResumedStages==1&&resumedStages.Any(x=>x.Key=="fragmented-photos"&&x.State=="reused"),"resume reuses verified completed photo method");Check(Hash(Path.Combine(run,"fragmented-photo-search.json"))==reportHash,"resume does not rerun or overwrite completed helper results");Check(Hash(image)==before,"pipeline/resume preserve original source");
    }
    static void Failures(Manifest manifest)
    {
        string image=Path.Combine(fixtures,manifest.Cases[0].Image),run=Output("precancel");var cancelled=new CancellationTokenSource();cancelled.Cancel();bool stopped=false;
        try{FragmentedPhotoRecovery.Recover(image,run,cancelled.Token,(a,b)=>{});}catch(OperationCanceledException){stopped=true;}Check(stopped&&!Directory.Exists(run),"pre-cancelled wrapper publishes no success");
        run=Output("cancel");cancelled=new CancellationTokenSource();stopped=false;
        Directory.CreateDirectory(run);
        try{RecoveryPipeline.Run(image,run,Options(),cancelled.Token,s=>{},null,delegate(RecoveryStageProgress update){if(update.Key=="fragmented-photos"&&update.State=="running"&&update.Completed>0)cancelled.Cancel();});}catch(OperationCanceledException){stopped=true;}
        Check(stopped&&RecoverySession.Read(run).Status=="cancelled","cancellation from actual frozen-helper progress is not successful pipeline completion");Check(RecoverySession.Read(run).Stages.Single(x=>x.Key=="fragmented-photos").Status=="cancelled","cancelled method never becomes reusable completed stage");
        string limited=Path.Combine(fixtures,manifest.LimitedImage),before=Hash(limited);run=Output("limited");bool failed=false;
        Directory.CreateDirectory(run);
        try{RecoveryPipeline.Run(limited,run,Options(),CancellationToken.None,s=>{});}catch(IOException){failed=true;}
        Check(failed,"a limited only-method pipeline does not claim successful completion");var saved=RecoverySession.Read(run);Check(saved.Status=="error"&&saved.Stages.Single(x=>x.Key=="fragmented-photos").Status=="incomplete","limited method remains incomplete in persisted session");
        Check(Report(Path.Combine(run,"fragmented-photo-search.json")).Status=="limited","actual helper index budget is exposed in wrapper report");Check(!File.Exists(Path.Combine(run,"files-index.json")),"limited only-method search never publishes final catalog");Check(Hash(limited)==before,"limited helper preserves source bytes");
    }
    public static int Main(string[] args)
    {
        try{project=Path.GetFullPath(args[0]);fixtures=args.Length>1?Path.GetFullPath(args[1]):Path.Combine(project,".build","photo-portable-fixtures");work=Path.Combine(project,".build","photo-portable-"+Guid.NewGuid().ToString("N").Substring(0,6));Directory.CreateDirectory(work);
            Check(File.Exists(HelperClient.Executable),"real frozen helper exists");var manifest=Json().Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));Check(manifest.Schema==1&&manifest.Cases.Count==3,"independently generated PNG/JPEG fixtures exist");
            foreach(var fixture in manifest.Cases)Wrapper(fixture);Pipeline(manifest.Cases[1]);Pipeline(manifest.Cases[2]);Failures(manifest);
            Console.WriteLine("PASS FragmentedPhotoPortable: "+checks+" checks; actual frozen helper, PNG/JPEG exact reference bytes, catalog source ranges, structural uncertainty, report filtering, cancellation/limits and verified stage resume. Synthetic ordinary image files only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
