using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using UsbRecovery;

public static class RecoveryStageProgressTests
{
    static int checks;
    static string project,work;
    static byte[] photo,image;
    sealed class Case { public string Source,Output,Before; }
    static void Check(bool value,string text){checks++;if(!value)throw new Exception(text);}
    static string Hash(string path){using(var file=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static RecoveryOptions OnlyPhotos(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=true,Containers=false,MetadataRescue=false,ArchiveMembers=false,FragmentedArchives=false,CustomSignatures=false,TextFragments=false};}
    static Case Fixture(string name,bool output)
    {
        string directory=Path.Combine(work,name);Directory.CreateDirectory(directory);var value=new Case{Source=Path.Combine(directory,"source.dd"),Output=Path.Combine(directory,"results")};File.WriteAllBytes(value.Source,image);value.Before=Hash(value.Source);File.WriteAllText(value.Source+".sha256",value.Before);if(output)Directory.CreateDirectory(value.Output);return value;
    }
    static void Events(IList<RecoveryStageProgress> updates,long length)
    {
        Check(updates.Count>0,"typed stage observations were delivered");
        Check(updates.All(x=>x!=null&&!String.IsNullOrWhiteSpace(x.Key)&&!String.IsNullOrWhiteSpace(x.Title)&&new[]{"running","complete","reused","cancelled","incomplete"}.Contains(x.State)),"all observations have a meaningful phase and state");
        Check(updates.All(x=>x.Completed>=0&&x.Total>=0&&x.Candidates>=-1&&(x.Total==0||x.Completed<=x.Total)),"counts are finite, bounded and use -1 only for unknown candidates");
        Check(updates.Where(x=>x.Total>0).All(x=>(x.Key=="verify"||x.Key=="photos")&&x.Total==length),"known totals are actual image bytes, never synthetic percent units");
        foreach(string key in new[]{"verify","photos"}){
            long prior=-1;foreach(var update in updates.Where(x=>x.Key==key&&x.Total>0)){Check(update.Completed>=prior,"observed bytes do not move backwards within "+key);prior=update.Completed;}
        }
        Check(updates.Where(x=>x.Key=="catalog"||x.Key=="finished"||x.State=="reused").All(x=>x.Total==0&&x.Completed==0),"unmeasured catalog/completion/reuse work has no fabricated byte percentage");
    }
    static void CompleteAndReuse()
    {
        var sample=Fixture("complete-and-reuse",true);var updates=new List<RecoveryStageProgress>();bool published=false;
        var result=RecoveryPipeline.Run(sample.Source,sample.Output,OnlyPhotos(),CancellationToken.None,null,null,update=>{updates.Add(update);if(update.Key=="finished")published=File.Exists(Path.Combine(sample.Output,"files-index.json"))&&File.Exists(Path.Combine(sample.Output,"scan-stages.json"));});
        Events(updates,image.LongLength);
        Check(updates.First().Key=="verify"&&updates.First().State=="running","source verification precedes extraction");
        Check(updates.Any(x=>x.Key=="verify"&&x.Total==image.LongLength&&x.Completed==image.LongLength),"source verification reports actual complete image length");
        Check(updates.Any(x=>x.Key=="photos"&&x.State=="running"&&x.Total==image.LongLength&&x.Completed==image.LongLength),"embedded scan reaches the real image end");
        Check(updates.Select(x=>x.Key).Distinct().SequenceEqual(new[]{"verify","photos","catalog","finished"}),"only enabled extraction phase and actual catalog phase are reported");
        Check(updates.Count(x=>x.Key=="finished")==1&&updates.Last().Key=="finished"&&updates.Last().State=="complete"&&published,"finished is observed only after successful final publication");
        var files=RecoveryCatalog.Load(sample.Output);Check(result.Candidates==1&&result.UniqueFiles==1&&files.Candidates==1&&files.Items.Count==1,"one independently generated photo corresponds to actual candidates and unique output");
        Check(updates.Last().Candidates==result.Candidates&&updates.Single(x=>x.Key=="photos"&&x.State=="complete").Candidates==result.Candidates,"typed candidate totals equal the completed scan result");
        string output=RecoveryCatalog.SafeFile(sample.Output,files.Items.Single().Path);Check(File.ReadAllBytes(output).SequenceEqual(photo),"found photo is byte exact");Check(Hash(sample.Source)==sample.Before,"successful observed recovery never changes source");
        string outputHash=Hash(output);DateTime outputTime=File.GetLastWriteTimeUtc(output);updates.Clear();
        var resumed=RecoveryPipeline.Resume(sample.Output,CancellationToken.None,null,updates.Add);Events(updates,image.LongLength);
        Check(resumed.ResumedStages==1&&resumed.Candidates==result.Candidates,"resume really reuses the completed extraction stage");
        Check(updates.Single(x=>x.State=="reused").Key=="photos"&&updates.Single(x=>x.State=="reused").Candidates==1,"reused phase reports its verified saved candidates");
        Check(!updates.Any(x=>x.Key=="photos"&&x.Total>0),"reuse does not fabricate a new image scan percentage");
        Check(Hash(output)==outputHash&&File.GetLastWriteTimeUtc(output)==outputTime,"reused photo bytes and write time remain unchanged");
        Check(updates.Any(x=>x.Key=="verify"&&x.Completed==image.LongLength&&x.Total==image.LongLength)&&updates.Last().Key=="finished","resumed source is verified before final completion");
        string session=Path.Combine(sample.Output,RecoverySession.FileName),sessionHash=Hash(session);File.AppendAllText(output,"changed recovered output");updates.Clear();bool rejected=false;
        try{RecoveryPipeline.Resume(sample.Output,CancellationToken.None,null,updates.Add);}catch(IOException){rejected=true;}
        Check(rejected&&!updates.Any(x=>x.State=="reused"||x.Key=="finished"),"tampered output cannot be called verified reuse or successful finish");Check(Hash(session)==sessionHash&&Hash(sample.Source)==sample.Before,"failed reuse preserves the session and original image");
    }
    static void CancelledScan()
    {
        var sample=Fixture("cancelled-scan",true);var updates=new List<RecoveryStageProgress>();bool middle=false,stopped=false;
        using(var cancellation=new CancellationTokenSource()){
            try{RecoveryPipeline.Run(sample.Source,sample.Output,OnlyPhotos(),cancellation.Token,null,null,update=>{
                updates.Add(update);
                // Let the callback throttle interval elapse before the first
                // real scan block, so cancellation is driven by measured bytes.
                if(update.Key=="photos"&&update.State=="running"&&update.Total==0)Thread.Sleep(120);
                if(update.Key=="photos"&&update.State=="running"&&update.Total>0&&update.Completed>0&&update.Completed<update.Total){middle=true;cancellation.Cancel();}
            });}catch(OperationCanceledException){stopped=true;}
        }
        Events(updates,image.LongLength);Check(middle&&stopped,"cancellation happens during a measured partial scan");
        Check(updates.Any(x=>x.Key=="photos"&&x.State=="cancelled")&&!updates.Any(x=>x.Key=="finished"),"cancelled method has explicit cancelled state and never announces finished");
        Check(!File.Exists(Path.Combine(sample.Output,"files-index.json")),"cancelled scan does not publish successful final catalog");
        Check(RecoverySession.Read(sample.Output).Status=="cancelled"&&RecoverySession.Read(sample.Output).Stages.Single().Status=="cancelled","saved session agrees with observed cancellation");Check(Hash(sample.Source)==sample.Before,"cancelled observed scan preserves source bytes");
    }
    static void EarlyStops()
    {
        var sample=Fixture("pre-cancelled",false);var updates=new List<RecoveryStageProgress>();bool stopped=false;
        using(var cancellation=new CancellationTokenSource()){cancellation.Cancel();try{RecoveryPipeline.Run(sample.Source,sample.Output,OnlyPhotos(),cancellation.Token,null,null,updates.Add);}catch(OperationCanceledException){stopped=true;}}
        Check(stopped&&updates.Count==0&&!Directory.Exists(sample.Output),"pre-cancelled request starts no stage and creates no result");Check(Hash(sample.Source)==sample.Before,"pre-cancellation leaves original unchanged");
        sample=Fixture("bad-checksum",false);File.WriteAllText(sample.Source+".sha256",new string('f',64));updates.Clear();bool rejected=false;
        try{RecoveryPipeline.Run(sample.Source,sample.Output,OnlyPhotos(),CancellationToken.None,null,null,updates.Add);}catch(IOException){rejected=true;}
        Check(rejected&&updates.All(x=>x.Key=="verify")&&!updates.Any(x=>x.Key=="finished"),"failed image verification never starts extraction or announces finished");Check(Hash(sample.Source)==sample.Before&&!Directory.Exists(sample.Output),"checksum failure preserves input and publishes no results");
    }
    public static int Main(string[] args)
    {
        try{
            project=Path.GetFullPath(args.Length>0?args[0]:Directory.GetCurrentDirectory());work=Path.Combine(project,".build","recovery-stage-progress-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(work);
            using(var bitmap=new Bitmap(48,32))using(var stream=new MemoryStream()){using(var graphics=Graphics.FromImage(bitmap))graphics.Clear(Color.FromArgb(79,117,181));bitmap.Save(stream,ImageFormat.Png);photo=stream.ToArray();}
            image=new byte[12*1024*1024];Buffer.BlockCopy(photo,0,image,123,photo.Length);
            CompleteAndReuse();CancelledScan();EarlyStops();Console.WriteLine("PASS RecoveryStageProgress: "+checks+" checks; measured byte totals, real candidates, catalog publication, cancellation, verified reuse and tamper rejection; synthetic regular images only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
        finally{
            if(work!=null&&project!=null&&Path.GetFullPath(work).StartsWith(Path.Combine(project,".build","recovery-stage-progress-"),StringComparison.OrdinalIgnoreCase)&&Directory.Exists(work))try{Directory.Delete(work,true);}catch(IOException){}catch(UnauthorizedAccessException){}
        }
    }
}
