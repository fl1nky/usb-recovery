using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ProgressivePhotoPortableTests
{
    public sealed class Fixture {public string name,image,original,sha256,status;}
    public sealed class Manifest {public int schema;public List<Fixture> cases;}
    static int checks;static string fixtures,work;
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=32*1024*1024};}
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string file){return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{});}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};}
    static void Mapping(string image,string file,IEnumerable<FileExtent> extents)
    {
        using(var source=File.OpenRead(image))using(var output=File.OpenRead(file)){
            foreach(var extent in extents){Check(extent.Offset>=0&&extent.Length>0&&extent.Offset<=source.Length-extent.Length,"physical source bounds");source.Position=extent.Offset;long left=extent.Length;
                while(left>0){int n=(int)Math.Min(4096,left);byte[] a=new byte[n],b=new byte[n];Check(source.Read(a,0,n)==n&&output.Read(b,0,n)==n&&a.SequenceEqual(b),"source extents reproduce emitted bytes exactly");left-=n;}
            }Check(output.Position==output.Length,"mapping covers entire candidate");
        }
    }
    static void Run(Fixture fixture,bool pipeline)
    {
        string image=RecoveryCatalog.SafeFile(fixtures,fixture.image),before=Hash(image),run=Path.Combine(work,fixture.name+(pipeline?"-pipeline":"-helper"));Directory.CreateDirectory(run);
        if(pipeline){string checksum=Path.Combine(work,fixture.name+".sha256");File.WriteAllText(checksum,before);RecoveryPipeline.Run(image,run,Options(),CancellationToken.None,s=>{},checksum);}
        else FragmentedPhotoRecovery.Recover(image,run,CancellationToken.None,(a,b)=>{});
        var report=Json().Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(Path.Combine(run,"fragmented-photo-search.json")));
        Check(report.Status=="complete"&&report.Files.Count==1,"one complete bounded progressive recovery");var entry=report.Files.Single();string output=RecoveryCatalog.SafeFile(run,entry.Path);
        Check(entry.Status==fixture.status&&entry.Sha256==fixture.sha256&&Hash(output)==fixture.sha256,"original bytes and explicit progressive status");
        var index=RecoveryCatalog.Build(run,CancellationToken.None,null);Check(index.Items.Count==1,"report and job marker excluded from recovered files");var item=index.Items.Single();
        Check(item.Quality=="structural_candidate"&&item.Status=="Кандидат сборки"&&item.OriginalPath==null,"decoding never establishes original ownership/path");
        Check(item.SourceRanges.Count>1&&item.SourceRanges.Sum(x=>x.Length)==item.Bytes,"catalog imports complete fragmented mapping");Mapping(image,output,item.SourceRanges);
        Check((item.QualityLabel=="JPEG с частичной точностью")== (fixture.status=="progressive_partial_precision_candidate"),"partial precision is visible without a false full-image claim");
        if(pipeline){string prior=Hash(Path.Combine(run,"fragmented-photo-search.json"));var resumed=RecoveryPipeline.Resume(run,CancellationToken.None,s=>{});Check(resumed.ResumedStages==1&&Hash(Path.Combine(run,"fragmented-photo-search.json"))==prior,"verified progressive stage reused on resume");}
        Check(Hash(image)==before,"helper/catalog/resume preserve input image");
    }
    public static int Main(string[] args)
    {
        try{string project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","progressive-jpeg-fixtures");work=Path.Combine(project,".build","progressive-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            var manifest=Json().Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));Check(manifest.schema==1&&manifest.cases.Count==7,"independent Pillow progressive corpus exists");
            foreach(var fixture in manifest.cases)Run(fixture,false);Run(manifest.cases.First(x=>x.name=="nonrst-two-entropy-gaps"),true);Run(manifest.cases.Single(x=>x.status=="progressive_partial_precision_candidate"),true);
            Console.WriteLine("PASS ProgressivePhotoPortable: "+checks+" checks; frozen helper, seven independent progressive JPEG cases, entropy gaps, partial precision, exact originals, source maps and stage resume. Synthetic regular images only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
