using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class JpegTwoGapPortableTests
{
    public sealed class Fixture
    {
        public string Name,Image,SourceSha256,ExpectedStatus,ExactSha256;
        public long SourceBytes;
        public int ExpectedCandidates,Width,Height;
    }
    public sealed class Manifest { public int Schema;public string Generator;public List<Fixture> Cases; }
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static int checks;
    static readonly CancellationTokenSource Deadline=new CancellationTokenSource(TimeSpan.FromMinutes(5));
    static string fixtures,work;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string file){return RecoveryCore.HashFile(file,Deadline.Token,(a,b)=>{});}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};}
    static FragmentedPhotoRecovery.Report Report(string run){return Json.Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(RecoveryCatalog.SafeFile(run,"fragmented-photo-search.json")));}
    static List<Dictionary<string,object>> Photos(string run)
    {
        var data=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(RecoveryCatalog.SafeFile(run,"photo-catalog.json")));
        return ((IEnumerable)data["items"]).Cast<Dictionary<string,object>>().ToList();
    }
    static string Pixels(string file,Fixture fixture)
    {
        using(var image=new Bitmap(file)){
            Check(image.Width==fixture.Width&&image.Height==fixture.Height,"actual candidate decodes with independent fixture dimensions");
            var bytes=new byte[image.Width*image.Height*3];int at=0;
            for(int y=0;y<image.Height;y++)for(int x=0;x<image.Width;x++){Color color=image.GetPixel(x,y);bytes[at++]=color.R;bytes[at++]=color.G;bytes[at++]=color.B;}
            using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();
        }
    }
    static void Replay(string image,string file,FragmentedPhotoRecovery.Candidate row)
    {
        Check(row.Extents.Count==3,"actual helper returned three physical runs for this bounded two-gap control");
        long logical=0,previous=-1,logicalEnd=-1;
        using(var source=File.OpenRead(image))using(var output=File.OpenRead(file)){
            foreach(var extent in row.Extents){
                Check(extent.LogicalOffset==logical&&extent.ImageOffset>=0&&extent.Length>0&&extent.ImageOffset<=source.Length-extent.Length,"helper map has contiguous logical offsets and bounded source ranges");
                Check(logicalEnd<0||extent.ImageOffset!=logicalEnd,"each logical transition crosses a physical gap in this independent two-gap control");
                logicalEnd=extent.ImageOffset+extent.Length;
                source.Position=extent.ImageOffset;long remaining=extent.Length;
                while(remaining>0){int count=(int)Math.Min(4096,remaining);byte[] left=new byte[count],right=new byte[count];Check(source.Read(left,0,count)==count&&output.Read(right,0,count)==count&&left.SequenceEqual(right),"independent stream replay reproduces actual emitted bytes");remaining-=count;}
                logical+=extent.Length;
            }
            Check(logical==row.Bytes&&logical==output.Length&&output.Position==output.Length,"helper map covers the entire actual candidate");
        }
        foreach(var extent in row.Extents.OrderBy(x=>x.ImageOffset)){Check(extent.ImageOffset>=previous,"physical source ranges do not overlap");previous=extent.ImageOffset+extent.Length;}
        Check(Hash(file)==row.Sha256&&new FileInfo(file).Length==row.Bytes,"actual candidate size and SHA agree with helper report");
    }
    static void Verify(string run,string image,Fixture fixture,bool ambiguous)
    {
        var report=Report(run);
        Check(report.Schema==1&&report.Status=="complete"&&report.SourceUnchanged&&report.SourceSha256==fixture.SourceSha256,"public wrapper accepted a complete report bound to unchanged actual source bytes");
        Check(report.Candidates==fixture.ExpectedCandidates&&report.Files.Count==fixture.ExpectedCandidates,"actual packaged helper returned the expected bounded number of content witnesses");
        Check(report.Files.Select(x=>x.Sha256).Distinct().Count()==fixture.ExpectedCandidates,"retained witnesses have distinct content hashes");
        var pixels=new HashSet<string>(StringComparer.Ordinal);
        foreach(var row in report.Files){
            Check(row.Status==fixture.ExpectedStatus,"actual helper and public wrapper preserve explicit structural or ambiguous status");
            string file=RecoveryCatalog.SafeFile(run,row.Path);Replay(image,file,row);pixels.Add(Pixels(file,fixture));
            if(!ambiguous)Check(row.Sha256==fixture.ExactSha256,"gray result equals independently encoded exact control; reference hash was never passed to helper");
            else Check(row.Note.Contains("not exhaustively enumerated")&&row.Note.Contains("unknown"),"RGB ambiguity states bounded alternatives and unknown original placement");
        }
        if(ambiguous)Check(pixels.Count==2,"two actual RGB witnesses decode to different pixels; neither is authenticated as original");
        var index=RecoveryCatalog.Build(run,Deadline.Token,null);
        Check(index.Items.Count==fixture.ExpectedCandidates&&index.Items.All(x=>x.OriginalPath==null),"catalog excludes reports and does not invent an original filename");
        Check(index.Items.All(x=>x.Quality==(ambiguous?"ambiguous_candidate":"structural_candidate")),"content decoding does not promote reconstruction evidence to authenticated bytes");
        foreach(var item in index.Items){
            var row=report.Files.Single(x=>x.Sha256==item.Sha256);
            Check(item.SourceRanges.Count==row.Extents.Count&&item.SourceRanges.Select(x=>x.Offset).SequenceEqual(row.Extents.Select(x=>x.ImageOffset))&&item.SourceRanges.Select(x=>x.Length).SequenceEqual(row.Extents.Select(x=>x.Length)),"catalog retains the exact actual helper source mapping");
        }
        PhotoCatalog.Build(run,Deadline.Token,null);var photos=Photos(run);
        Check(photos.Count==fixture.ExpectedCandidates&&photos.All(x=>(string)x["Status"]==(ambiguous?"ambiguous":"decoded")),"gallery exposes decoded structural controls and unknown-original ambiguous witnesses");
        index=RecoveryCatalog.Build(run,Deadline.Token,null);
        Check(index.Items.All(x=>x.Quality==(ambiguous?"ambiguous_candidate":"structural_candidate")),"successful gallery decoding preserves structural or ambiguous file evidence");
        Check(!File.Exists(RecoveryCatalog.SafeFile(run,"fragmented-photos/job.incomplete"))&&!Directory.GetFiles(RecoveryCatalog.SafeFile(run,"fragmented-photos"),"*.partial").Any(),"successful actual publication leaves no incomplete marker or candidate partials");
    }
    static void Exact(Fixture fixture)
    {
        string image=RecoveryCatalog.SafeFile(fixtures,fixture.Image),run=Path.Combine(work,"gray-public-wrapper");Directory.CreateDirectory(run);int progress=0;
        Check(Hash(image)==fixture.SourceSha256&&new FileInfo(image).Length==fixture.SourceBytes,"independent gray input matches its fixture manifest");
        int count=FragmentedPhotoRecovery.Recover(image,run,Deadline.Token,(a,b)=>{progress++;Check(a>=0&&a<=b,"actual helper reports bounded progress");});
        Check(count==1&&progress>0,"public wrapper ran the actual packaged helper for exact two-gap gray control");
        Verify(run,image,fixture,false);Check(Hash(image)==fixture.SourceSha256,"gray recovery and catalogs preserve source bytes");
    }
    static void AmbiguousResume(Fixture fixture)
    {
        string image=RecoveryCatalog.SafeFile(fixtures,fixture.Image),run=Path.Combine(work,"rgb-checkpoint-resume");Directory.CreateDirectory(run);
        Check(Hash(image)==fixture.SourceSha256&&new FileInfo(image).Length==fixture.SourceBytes&&fixture.ExactSha256==null,"RGB source identity is known while authenticated original bytes are deliberately unspecified");
        var session=RecoverySession.Start(run,image,fixture.SourceSha256,Options(),Deadline.Token);session.Begin("fragmented-photos");
        bool stopped=false,acknowledged=false;
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(Deadline.Token)){
            try{FragmentedPhotoRecovery.Recover(image,run,stop.Token,(a,b)=>{},null,checkpoint=>{
                if(stop.IsCancellationRequested)return;
                session.CapturePhotoCheckpoint(checkpoint);
                var state=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(checkpoint.Path));
                var cursor=(Dictionary<string,object>)state["Cursor"];
                if((string)state["Phase"]=="candidates"&&Convert.ToInt64(cursor["Jpeg"])==1){acknowledged=true;stop.Cancel();}
            });}catch(OperationCanceledException){stopped=true;}
        }
        Deadline.Token.ThrowIfCancellationRequested();
        Check(stopped&&acknowledged,"actual helper is cancelled after parent acknowledges the whole ambiguous JPEG-start checkpoint");
        session.Fail("fragmented-photos","cancelled",null);session.Status("cancelled");
        var interrupted=RecoverySession.Read(run);
        Check(interrupted.Stages.Single().CheckpointSequence>0&&interrupted.Status=="cancelled"&&!File.Exists(Path.Combine(run,"files-index.json")),"cancelled actual search retains its bound checkpoint without publishing a successful file catalog");
        Check(Hash(image)==fixture.SourceSha256,"actual helper cancellation preserves RGB source bytes");
        var continued=RecoveryPipeline.Resume(run,Deadline.Token,s=>{});var report=Report(run);
        Check(report.ResumedFromCheckpoint&&report.ReusedCandidates==2,"actual packaged helper validates and reuses both retained ambiguous witnesses on resume");
        Check(continued.UniqueFiles==2&&continued.Candidates==2&&!Directory.Exists(Path.Combine(run,"attempt-history")),"pipeline continues the acknowledged ambiguous search instead of restarting or choosing one candidate");
        Verify(run,image,fixture,true);
        Check(RecoverySession.Read(run).Stages.Single().Status=="complete","continued ambiguous method finishes while candidate uncertainty stays explicit");
        string prior=Hash(Path.Combine(run,"fragmented-photo-search.json"));var resumed=RecoveryPipeline.Resume(run,Deadline.Token,s=>{});
        Check(resumed.ResumedStages==1&&Hash(Path.Combine(run,"fragmented-photo-search.json"))==prior,"later pipeline resume reuses the source-bound completed method without rerunning or rewriting helper output");
        Check(RecoveryCatalog.Load(run).Items.All(x=>x.Quality=="ambiguous_candidate")&&Hash(image)==fixture.SourceSha256,"completed-stage reuse and final catalogs preserve ambiguity and source bytes");
        string candidate=RecoveryCatalog.SafeFile(run,report.Files[0].Path);Directory.CreateDirectory(Path.Combine(run,"files.1"));File.Copy(candidate,Path.Combine(run,"files.1","same-content.jpg"));
        PhotoCatalog.Build(run,Deadline.Token,null);var photos=Photos(run);
        Check(photos.Count==2&&photos.All(x=>(string)x["Status"]=="ambiguous")&&photos.Any(x=>Convert.ToInt64(x["Copies"])==2),"gallery content dedup retains ambiguity and the extra physical output copy");
        var index=RecoveryCatalog.Build(run,Deadline.Token,null);
        Check(index.Items.Count==2&&index.Candidates==3&&index.Items.All(x=>x.Quality=="ambiguous_candidate")&&index.Items.Any(x=>x.Copies.Count==1),"file catalog preserves unknown-original status and all copy paths after dedup");
        var evidence=FileEvidence.Load(run);var first=index.Items[0];
        foreach(string problem in new[]{"damaged","partial","changed","read_errors","encrypted","mapping_unknown"}){
            var item=new RecoveredItem{Path=first.Path,Sha256=first.Sha256,Bytes=first.Bytes,Quality=problem,QualityLabel="existing problem",IntegrityDetail="",Note=""};item.Copies.AddRange(first.Copies);evidence.Apply(item);
            Check(item.Quality==problem&&item.QualityLabel=="existing problem"&&item.Status=="Неоднозначная сборка","actual ambiguous extraction does not erase a known "+problem+" problem");
        }
        string sessionHash=Hash(Path.Combine(run,RecoverySession.FileName));bool foreignRejected=false;
        try{RecoveryPipeline.Resume(run,Deadline.Token,s=>{});}catch(IOException){foreignRejected=true;}
        Check(foreignRejected&&Hash(Path.Combine(run,RecoverySession.FileName))==sessionHash&&Hash(Path.Combine(run,"fragmented-photo-search.json"))==prior&&Hash(image)==fixture.SourceSha256,"unrecorded foreign PhotoRec output is refused without changing the completed session, source or helper report");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","jpeg-two-gap-portable-fixtures");work=Path.Combine(project,".build","jpeg-two-gap-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            Check(File.Exists(HelperClient.Executable),"actual packaged helper exists");
            var manifest=Json.Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));
            Check(manifest.Schema==1&&manifest.Generator=="independent-pillow-sector-scatter-v1"&&manifest.Cases.Count==2,"independent bounded gray/RGB fixture corpus exists");
            Exact(manifest.Cases.Single(x=>x.Name=="gray-exact-two-gap"));AmbiguousResume(manifest.Cases.Single(x=>x.Name=="rgb-ambiguous-two-gap"));
            Console.WriteLine("PASS JpegTwoGapPortable: "+checks+" checks; actual packaged helper and public wrapper, independent gray exact control, two unknown RGB witnesses, disjoint source replay, decoder/dedup uncertainty and acknowledged checkpoint/pipeline resume. Synthetic 256KiB regular images only; no authenticated RGB original, physical device or broad corpus claim.");return 0;
        }catch(Exception error){if(Deadline.IsCancellationRequested)Console.Error.WriteLine("FAIL JpegTwoGapPortable: five-minute watchdog expired; no successful checkpoint or recovery claim.");Console.Error.WriteLine(error);return 1;}
        finally{Deadline.Dispose();}
    }
}
