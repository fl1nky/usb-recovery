using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class JpegVideoExpansionPortableTests
{
    public sealed class Range {public long ImageOffset,LogicalOffset,Length;}
    public sealed class PhotoCase {public string Name,Path,SourceSha256;public List<Range> Extents;}
    public sealed class PhotoManifest {public long OriginalBytes;public string OriginalSha256,AlternateSha256;public List<PhotoCase> Cases;}
    public sealed class VideoCase {public string Name,ExpandedImage,Original,OriginalSha256,SourceSha256;public long OriginalBytes,SourceBytes;public List<Range> Extents;}
    public sealed class VideoManifest {public int Schema;public string Generator;public List<VideoCase> Cases;}
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static readonly CancellationTokenSource Deadline=new CancellationTokenSource(TimeSpan.FromMinutes(12));
    static int checks,calls;static string work,photos,videos;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){return RecoveryCore.HashFile(path,Deadline.Token,(a,b)=>{});}
    static void Replay(string source,string output,IEnumerable<Range> map)
    {
        long logical=0;var ordered=map.ToList();
        using(var input=File.OpenRead(source))using(var candidate=File.OpenRead(output))foreach(var e in ordered){
            Check(e.LogicalOffset==logical&&e.Length>0&&e.ImageOffset>=0&&e.ImageOffset<=input.Length-e.Length,"complete bounded source map");
            input.Position=e.ImageOffset;long left=e.Length;byte[] a=new byte[65536],b=new byte[65536];
            while(left>0){Deadline.Token.ThrowIfCancellationRequested();int n=(int)Math.Min(left,a.Length);Check(input.Read(a,0,n)==n&&candidate.Read(b,0,n)==n&&a.Take(n).SequenceEqual(b.Take(n)),"every output byte replays the named source extent");left-=n;}
            logical+=e.Length;
            if(logical==candidate.Length)Check(candidate.Position==candidate.Length,"map covers actual file exactly");
        }
        Check(logical==new FileInfo(output).Length,"no missing or invented output bytes");
        long end=-1;foreach(var e in ordered.OrderBy(e=>e.ImageOffset)){Check(e.ImageOffset>=end,"source extents disjoint");end=e.ImageOffset+e.Length;}
    }
    static FragmentedPhotoRecovery.Report PhotoReport(string run){return Json.Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(Path.Combine(run,"fragmented-photo-search.json")));}
    static void VerifyPhoto(string run,string source,PhotoManifest manifest,PhotoCase fixture,int expected)
    {
        var report=PhotoReport(run);Check(report.SourceUnchanged&&report.SourceSha256==fixture.SourceSha256&&Hash(source)==fixture.SourceSha256,"actual helper binds unchanged photo source");
        Check(report.Files.Count==expected&&report.Candidates==expected,"actual photo candidate count");
        if(expected>0)Check(report.Status=="complete","complete bounded photo coverage");
        foreach(var row in report.Files){
            string file=RecoveryCatalog.SafeFile(run,row.Path);Check(Hash(file)==row.Sha256&&row.Bytes==new FileInfo(file).Length,"actual photo bytes and hash");
            Check(row.Status==(expected==2?"jpeg_gap_ambiguous_candidate":"jpeg_gap_structural_candidate"),"structural/ambiguity evidence preserved");
            Replay(source,file,row.Extents.Select(e=>new Range{ImageOffset=e.ImageOffset,LogicalOffset=e.LogicalOffset,Length=e.Length}));
            using(var image=new Bitmap(file))Check(image.Width==2560&&image.Height==2560,"actual native photo decode has independent dimensions");
        }
        if(expected==1)Check(report.Files[0].Sha256==manifest.OriginalSha256&&report.Files[0].Bytes==manifest.OriginalBytes,"large photo exact independent original");
        if(expected==2)Check(new HashSet<string>(report.Files.Select(r=>r.Sha256)).SetEquals(new[]{manifest.OriginalSha256,manifest.AlternateSha256}),"both independently encoded large unknown-original witnesses");
        if(expected>0){var catalog=RecoveryCatalog.Build(run,Deadline.Token,null);Check(catalog.Items.Count==expected&&catalog.Items.All(i=>i.Quality==(expected==2?"ambiguous_candidate":"structural_candidate")),"successful decode does not erase uncertainty");}
    }
    static void Photos()
    {
        var manifest=Json.Deserialize<PhotoManifest>(File.ReadAllText(Path.Combine(photos,"manifest.json")));
        Check(manifest.OriginalBytes>5L*1024*1024,"independent photo exceeds five MiB");
        foreach(string name in new[]{"exact","late-alternative","overwritten","missing-eoi"}){
            var fixture=manifest.Cases.Single(c=>c.Name==name);string source=Path.Combine(photos,fixture.Path),run=Path.Combine(work,"p"+calls);Directory.CreateDirectory(run);Check(Hash(source)==fixture.SourceSha256,"pinned photo fixture input");
            int expected=name=="exact"?1:name=="late-alternative"?2:0;bool limited=false;int actual=-1;
            try{calls++;actual=FragmentedPhotoRecovery.Recover(source,run,Deadline.Token,(a,b)=>{});}catch(IOException){limited=true;}
            Deadline.Token.ThrowIfCancellationRequested();Check(expected==0||!limited&&actual==expected,"actual packaged photo helper count");VerifyPhoto(run,source,manifest,fixture,expected);
        }
        var exact=manifest.Cases.Single(c=>c.Name=="exact");string imagePath=Path.Combine(photos,exact.Path),continuedRun=Path.Combine(work,"pr");Directory.CreateDirectory(continuedRun);
        var options=new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};
        var session=RecoverySession.Start(continuedRun,imagePath,exact.SourceSha256,options,Deadline.Token);session.Begin("fragmented-photos");bool cancelled=false,acknowledged=false;
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(Deadline.Token)){
            try{calls++;FragmentedPhotoRecovery.Recover(imagePath,continuedRun,stop.Token,(a,b)=>{},null,checkpoint=>{
                session.CapturePhotoCheckpoint(checkpoint);var state=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(checkpoint.Path));object search;
                if(state.TryGetValue("JpegSearch",out search)&&search is Dictionary<string,object>){acknowledged=true;stop.Cancel();}
            });}catch(OperationCanceledException){cancelled=true;}
        }
        Deadline.Token.ThrowIfCancellationRequested();Check(cancelled&&acknowledged,"actual helper cancelled after acknowledged inner JPEG state");
        Check(!Directory.GetFiles(Path.Combine(continuedRun,"fragmented-photos"),"*.jpg").Any(),"no early photo published before full search");
        session.Fail("fragmented-photos","cancelled",null);session.Status("cancelled");calls++;var continued=RecoveryPipeline.Resume(continuedRun,Deadline.Token,s=>{});
        Check(continued.UniqueFiles==1&&PhotoReport(continuedRun).ResumedFromCheckpoint,"actual parent pipeline continues the same large JPEG head");VerifyPhoto(continuedRun,imagePath,manifest,exact,1);
    }
    static void Videos()
    {
        var manifest=Json.Deserialize<VideoManifest>(File.ReadAllText(Path.Combine(videos,"manifest.json")));
        Check(manifest.Schema==1&&manifest.Generator=="pinned-ffmpeg-native-bframes-v1"&&manifest.Cases.Count==2,"native independent B-frame corpus");
        foreach(var fixture in manifest.Cases)foreach(string mode in new[]{"exact","alias","missing","distinct"}){
            byte[] data=File.ReadAllBytes(Path.Combine(videos,fixture.ExpandedImage));Check(Hash(Path.Combine(videos,fixture.ExpandedImage))==fixture.SourceSha256,"pinned native video source");var first=fixture.Extents[2];
            if(mode=="missing")for(long i=0;i<first.Length;i++)data[first.ImageOffset+i]=0xa7;
            if(mode=="alias"||mode=="distinct"){Buffer.BlockCopy(data,(int)first.ImageOffset,data,65536,(int)first.Length);if(mode=="distinct")data[65536+first.Length-8]^=1;}
            string source=Path.Combine(work,"v"+calls+".dd"),run=Path.Combine(work,"v"+calls);File.WriteAllBytes(source,data);string before=Hash(source);bool partial=false;int actual=-1;
            try{calls++;actual=FragmentedMediaRecovery.Recover(source,run,Deadline.Token,null);}catch(IOException){partial=true;}
            var report=Json.Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Path.Combine(run,"fragmented-media.json")));int expected=mode=="exact"||mode=="alias"?1:0;
            Check(Hash(source)==before&&report.Files.Count==expected&&(expected==0||!partial&&actual==1),"actual native video count and unchanged source");
            if(mode=="missing")Check(partial&&report.Status=="partial","missing fragment remains explicitly incomplete");
            if(mode=="distinct")Check(report.Skipped.ContainsKey("fmp4_payload_ambiguous"),"distinct compatible video bytes remain ambiguous");
            foreach(var row in report.Files){string file=RecoveryCatalog.SafeFile(run,row.Path);Check(Hash(file)==fixture.OriginalSha256&&row.Bytes==fixture.OriginalBytes&&!row.PayloadAuthenticated&&!row.DeletionConfirmed,"exact independent native B-frame bytes, no authenticity claim");
                Replay(source,file,row.Extents.Select(e=>new Range{ImageOffset=e.ImageOffset,LogicalOffset=e.LogicalOffset,Length=e.Length}));Check(row.AlternateExtents.Count==(mode=="alias"?1:0),"identical video source alias retained");
                foreach(var map in row.AlternateExtents)Replay(source,file,map.Select(e=>new Range{ImageOffset=e.ImageOffset,LogicalOffset=e.LogicalOffset,Length=e.Length}));}
        }
    }
    public static int Main(string[] args)
    {
        try{string project=Path.GetFullPath(args[0]);photos=Path.Combine(project,".build","jpeg-large-portable-fixtures");videos=Path.Combine(project,".build","video-bframes-fixtures");work=Path.Combine(project,".build","jv4p-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(work);
            Check(File.Exists(HelperClient.Executable),"fresh packaged helper exists");Photos();Videos();Console.WriteLine("PASS JpegVideoExpansionPortable: "+checks+" checks / "+calls+" actual calls; native large JPEG exact/ambiguity/damage/checkpoint-resume and indexed B-frame layouts with full source maps. Synthetic source files only.");return 0;
        }catch(Exception e){Console.Error.WriteLine(e);return 1;}finally{Deadline.Dispose();}
    }
}
