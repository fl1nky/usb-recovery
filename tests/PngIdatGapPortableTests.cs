using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using UsbRecovery;

// Compilation alone is not portable acceptance. Run against the actual helper.
public static class PngIdatGapPortableTests
{
    public sealed class Oracle { public int Width,Height;public string Mode,PixelsSha256; }
    public sealed class Extent { public long ImageOffset,LogicalOffset,Length; }
    public sealed class Fixture
    {
        public string Name,Image,Original,Sha256,ExpectedSha256,SourceSha256;
        public long Bytes,SourceBytes,LogicalCut;
        public int ExpectedCandidates;
        public bool AllOriginalBytesPresent,SourceCutIsAbsolute512;
        public Oracle Oracle;
        public List<Extent> PhysicalExtents;
    }
    public sealed class Manifest
    {
        public int Schema;
        public bool IndependentEncoder;
        public string GeneratorSha256,SourceSpec;
        public List<Fixture> Cases;
    }
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static readonly string[] Names={"contiguous","whole-idat","cut-512","cut-4k","cut-32k","cut-128k","cut-1280k",
        "unaligned-head","reversed","zero-padding","random-padding","ancillary-prefix","ancillary-tail","indexed-palette",
        "multi-idat-middle","crc-split","duplicate-tail","false-anchor","corrupt-crc","invalid-adler","missing-payload",
        "overlap","forbidden-tail-context","invalid-filter","ambiguous-tail","mixed-intact-gap-ambiguous"};
    static readonly string[] Positives={"whole-idat","cut-512","cut-4k","cut-32k","cut-128k","cut-1280k","unaligned-head",
        "reversed","zero-padding","random-padding","ancillary-prefix","ancillary-tail","indexed-palette","multi-idat-middle",
        "crc-split","duplicate-tail","false-anchor"};
    static int checks,analyses;
    static string fixtures,work;
    static CancellationToken phase;
    static Stopwatch phaseClock;

    static void Check(bool value,string why){Interlocked.Increment(ref checks);if(!value)throw new Exception(why);}
    static string Hash(string path){return RecoveryCore.HashFile(path,phase,(a,b)=>{});}
    static string Safe(string root,string relative){return RecoveryCatalog.SafeFile(root,relative);}
    static bool Digest(string value){return value!=null&&value.Length==64&&value.All(c=>c>='0'&&c<='9'||c>='a'&&c<='f');}
    static string Hex(byte[] value){return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();}
    static T Guard<T>(Func<CancellationToken,T> action)
    {
        using(var stop=CancellationTokenSource.CreateLinkedTokenSource(phase)){
            stop.CancelAfter(TimeSpan.FromMinutes(4)+TimeSpan.FromSeconds(45));
            int waitMilliseconds=(int)Math.Min(300000,1200000-phaseClock.ElapsedMilliseconds);
            if(waitMilliseconds<=0)throw new TimeoutException("Hard twenty-minute portable phase watchdog; no successful result inferred.");
            var task=Task.Run(()=>action(stop.Token));
            if(Task.WaitAny(new Task[]{task},waitMilliseconds)<0){
                stop.Cancel();throw new TimeoutException("Hard call/phase watchdog; worker completion is unconfirmed, no recovery success inferred.");
            }
            return task.GetAwaiter().GetResult();
        }
    }
    static Dictionary<string,string> Binding(string root)
    {
        root=Path.GetFullPath(root).TrimEnd('\\','/');
        for(var parent=new DirectoryInfo(root);parent!=null;parent=parent.Parent)
            if((parent.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked fixture ancestor");
        var answer=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        var pending=new Stack<string>();pending.Push(root);
        while(pending.Count>0){
            string directory=pending.Pop();
            if((File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked fixture directory");
            foreach(string path in Directory.GetFileSystemEntries(directory)){
                var attributes=File.GetAttributes(path);
                if((attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked fixture entry");
                if((attributes&FileAttributes.Directory)!=0)pending.Push(path);
                else answer.Add(path.Substring(root.TrimEnd('\\','/').Length+1),Hash(path));
            }
        }return answer;
    }
    static bool Same(Dictionary<string,string> first,Dictionary<string,string> second)
    {return first.Count==second.Count&&first.All(item=>second.ContainsKey(item.Key)&&second[item.Key]==item.Value);}
    static FragmentedPhotoRecovery.Report Report(string run)
    {return Json.Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(Safe(run,"fragmented-photo-search.json")));}
    static RecoveryOptions Options()
    {return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};}
    static string Output(string name){string path=Path.Combine(work,name);if(Directory.Exists(path)||File.Exists(path))throw new IOException("Fresh test output required");Directory.CreateDirectory(path);return path;}
    static void Sources(string image,string file,FragmentedPhotoRecovery.Candidate row,Fixture fixture)
    {
        Check(row.Extents!=null&&row.Extents.Count>=2,"helper supplies physical reconstruction ranges");
        long logical=0,physicalEnd=-1;
        using(var source=File.OpenRead(image))using(var actual=File.OpenRead(file)){
            byte[] left=new byte[65536],right=new byte[65536];
            foreach(var range in row.Extents){
                Check(range.LogicalOffset==logical&&range.ImageOffset>=0&&range.Length>0&&range.ImageOffset<=source.Length-range.Length,
                    "source map has exact logical order and bounded physical bytes");
                if(fixture.Name!="duplicate-tail")Check(fixture.PhysicalExtents.Any(expected=>
                    expected.LogicalOffset<=range.LogicalOffset&&range.LogicalOffset+range.Length<=expected.LogicalOffset+expected.Length&&
                    range.ImageOffset==expected.ImageOffset+range.LogicalOffset-expected.LogicalOffset),
                    "actual source map agrees with independent physical placement, allowing harmless subdivision");
                source.Position=range.ImageOffset;long remaining=range.Length;
                while(remaining>0){
                    phase.ThrowIfCancellationRequested();int amount=(int)Math.Min(left.Length,remaining),a=0,b=0;
                    while(a<amount){int read=source.Read(left,a,amount-a);if(read==0)throw new EndOfStreamException();a+=read;}
                    while(b<amount){int read=actual.Read(right,b,amount-b);if(read==0)throw new EndOfStreamException();b+=read;}
                    Check(left.Take(amount).SequenceEqual(right.Take(amount)),"replaying real source ranges reproduces every emitted byte");remaining-=amount;
                }logical+=range.Length;
            }
            Check(logical==row.Bytes&&logical==actual.Length&&actual.Position==actual.Length,"source ranges cover the entire output");
        }
        foreach(var range in row.Extents.OrderBy(x=>x.ImageOffset)){
            Check(range.ImageOffset>=physicalEnd,"source ranges are disjoint, including reversed physical placement");physicalEnd=range.ImageOffset+range.Length;
        }
        Check(Hash(file)==row.Sha256&&new FileInfo(file).Length==row.Bytes,"actual bytes match helper SHA and size");
    }
    static string Pixels(string file,Fixture expected)
    {
        using(var bitmap=new Bitmap(file)){
            Check(bitmap.Width==expected.Oracle.Width&&bitmap.Height==expected.Oracle.Height,"independent decoder sees exact expected dimensions");
            var pixels=new byte[bitmap.Width*bitmap.Height*3];int at=0;
            for(int y=0;y<bitmap.Height;y++){
                phase.ThrowIfCancellationRequested();
                for(int x=0;x<bitmap.Width;x++){Color value=bitmap.GetPixel(x,y);pixels[at++]=value.R;pixels[at++]=value.G;pixels[at++]=value.B;}
            }
            using(var hash=SHA256.Create())return Hex(hash.ComputeHash(pixels));
        }
    }
    static void ExactReport(string run,string image,Fixture fixture)
    {
        var report=Report(run);
        Check(report.Schema==1&&report.Status=="complete"&&report.SourceUnchanged&&report.SourceSha256==fixture.SourceSha256,
            "actual public wrapper confirms complete source-bound analysis");
        Check(report.Candidates==1&&report.Files.Count==1&&report.OutputBytes==fixture.Bytes,"exactly one complete candidate is published");
        var row=report.Files[0];string file=Safe(run,row.Path);
        Check(row.Sha256==fixture.Sha256&&row.Bytes==fixture.Bytes&&Hash(file)==fixture.Sha256,"result equals the independent original byte-for-byte");
        Check(row.Status=="png_crc_zlib_reassembled_candidate"&&row.Note!=null&&row.Note.Contains("not authenticated"),
            "PNG structure is not upgraded to original ownership or deletion authentication");
        Sources(image,file,row,fixture);
        string actualPixels=Pixels(file,fixture),originalPixels=Pixels(Safe(fixtures,fixture.Original),fixture);
        Check(actualPixels==originalPixels,"all decoded RGB colors agree with independent original, including indexed palettes");
        if(fixture.Oracle.Mode=="RGB")Check(actualPixels==fixture.Oracle.PixelsSha256,"decoded RGB matches independent reverse-filter oracle digest");
        var index=RecoveryCatalog.Build(run,phase,null);
        Check(index.Items.Count==1&&index.Candidates==1&&index.Items[0].Quality=="structural_candidate"&&index.Items[0].OriginalPath==null,
            "catalog excludes metadata and keeps structural quality and unknown original name");
        var item=index.Items[0];
        Check(item.Sha256==fixture.Sha256&&item.SourceRanges.Count==row.Extents.Count&&
            item.SourceRanges.Select(x=>x.Offset).SequenceEqual(row.Extents.Select(x=>x.ImageOffset))&&
            item.SourceRanges.Select(x=>x.Length).SequenceEqual(row.Extents.Select(x=>x.Length)),"catalog keeps actual full physical map");
        PhotoCatalog.Build(run,phase,null);
        var gallery=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Safe(run,"photo-catalog.json")));
        var photos=((IEnumerable)gallery["items"]).Cast<Dictionary<string,object>>().ToList();
        Check(photos.Count==1&&(string)photos[0]["Status"]=="decoded","gallery decodes the actual reconstructed PNG");
        Check(RecoveryCatalog.Build(run,phase,null).Items.Single().Quality=="structural_candidate","gallery decoding preserves structural uncertainty");
        Check(!File.Exists(Safe(run,"fragmented-photos/job.incomplete"))&&!Directory.GetFiles(Safe(run,"fragmented-photos"),"*.partial").Any(),
            "complete helper publication leaves no unfinished marker or candidate partial");
    }
    static void Wrapper(Fixture fixture)
    {
        string image=Safe(fixtures,fixture.Image),run=Output("wrapper-"+fixture.Name);int progress=0;
        int count=Guard(token=>FragmentedPhotoRecovery.Recover(image,run,token,(done,total)=>{
            Interlocked.Increment(ref progress);Check(done>=0&&done<=total,"actual helper progress is bounded");}));analyses++;
        var report=Report(run);
        Check(count==fixture.ExpectedCandidates&&report.Candidates==fixture.ExpectedCandidates&&report.Status=="complete"&&report.SourceUnchanged&&report.SourceSha256==fixture.SourceSha256,
            "mandatory independent case through actual helper/public wrapper: "+fixture.Name);
        Check(progress>0&&Hash(image)==fixture.SourceSha256,"source remains unchanged after actual helper: "+fixture.Name);
        if(fixture.ExpectedCandidates==1)ExactReport(run,image,fixture);
        else {
            Check(report.Files.Count==0&&RecoveryCatalog.Build(run,phase,null).Items.Count==0,"negative/control case does not publish a recovered image: "+fixture.Name);
            Check(!Directory.GetFiles(Safe(run,"fragmented-photos"),"*.png").Any(),"negative case has no hidden successful PNG artifact");
            if(fixture.Name=="ambiguous-tail"||fixture.Name=="mixed-intact-gap-ambiguous")Check(report.Skipped!=null&&report.Skipped.ContainsKey("png_ambiguous")&&report.Skipped["png_ambiguous"]>0,
                "two distinct valid native tails are rejected instead of selecting the first image");
        }
    }
    static void Pipeline(Fixture fixture)
    {
        string image=Safe(fixtures,fixture.Image),run=Output("pipeline-"+fixture.Name);
        var updates=new List<RecoveryStageProgress>();
        string checksum=Safe(run,"baseline.sha256");
        File.WriteAllText(checksum,fixture.SourceSha256,new System.Text.UTF8Encoding(false));
        var result=Guard(token=>RecoveryPipeline.Run(image,run,Options(),token,message=>{},checksum,updates.Add));analyses++;
        Check(result.UniqueFiles==1&&result.Candidates==1&&updates.Any(x=>x.Key=="fragmented-photos"&&x.State=="complete"),
            "actual pipeline publishes only the complete photo stage: "+fixture.Name);
        ExactReport(run,image,fixture);
        var saved=RecoverySession.Read(run);var stage=saved.Stages.Single(x=>x.Key=="fragmented-photos");
        Check(stage.Status=="complete"&&stage.Candidates==1&&stage.Artifacts.Count>=3,"completed stage binds report, source maps, output and checkpoint artifacts");
        string before=Hash(Safe(run,"fragmented-photo-search.json"));
        var resumed=Guard(token=>RecoveryPipeline.Resume(run,token,message=>{}));
        Check(resumed.ResumedStages==1&&Hash(Safe(run,"fragmented-photo-search.json"))==before&&Hash(image)==fixture.SourceSha256,
            "completed-stage resume reuses verified output without rerunning helper or changing source");
    }
    static void Copy(string source,string destination)
    {
        var before=Binding(source);Directory.CreateDirectory(destination);
        foreach(var file in before){string target=Safe(destination,file.Key);Directory.CreateDirectory(Path.GetDirectoryName(target));File.Copy(Safe(source,file.Key),target);}
        Check(Same(before,Binding(destination)),"disposable checkpoint test is an exact owned copy");
    }
    static void CancelResume(Fixture fixture)
    {
        string image=Safe(fixtures,fixture.Image),run=Output("cancel-resume");
        var session=RecoverySession.Start(run,image,fixture.SourceSha256,Options(),phase);session.Begin("fragmented-photos");
        bool acknowledged=false;
        bool cancelled=Guard(token=>{
            using(var stop=CancellationTokenSource.CreateLinkedTokenSource(token)){
                bool stopped=false;
                try {FragmentedPhotoRecovery.Recover(image,run,stop.Token,(a,b)=>{},null,checkpoint=>{
                    if(stop.IsCancellationRequested)return;
                    session.CapturePhotoCheckpoint(checkpoint);
                    var state=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(checkpoint.Path));
                    var cursor=(Dictionary<string,object>)state["Cursor"];
                    if((string)state["Phase"]=="candidates"&&Convert.ToInt64(cursor["Png"])==1){acknowledged=true;stop.Cancel();}
                });}catch(OperationCanceledException){stopped=true;}
                token.ThrowIfCancellationRequested();return stopped;
            }
        });analyses++;
        Check(cancelled&&acknowledged,"actual helper cancellation follows an acknowledged completed-PNG checkpoint");
        session.Fail("fragmented-photos","cancelled",null);session.Status("cancelled");
        var interrupted=RecoverySession.Read(run);var saved=interrupted.Stages.Single();
        Check(interrupted.Status=="cancelled"&&saved.CheckpointSequence>0&&!File.Exists(Safe(run,"files-index.json")),
            "cancelled parent never publishes successful final catalog");
        string changed=Path.Combine(work,"code-mismatch-copy");Copy(run,changed);
        string point=Safe(changed,saved.CheckpointPath);
        var value=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(point));
        var binding=(Dictionary<string,object>)value["Binding"];
        Check(Digest(binding["CodeSha256"] as string),"actual checkpoint contains code fingerprint");
        binding["CodeSha256"]=new string((string)binding["CodeSha256"]==new string('0',64)?'f':'0',64);
        File.WriteAllText(point,Json.Serialize(value),new System.Text.UTF8Encoding(false));
        var forged=new PhotoRecoveryCheckpoint{Path=point,Sha256=Hash(point),Sequence=saved.CheckpointSequence};
        var changedBefore=Binding(changed);
        var rejected=Guard(token=>HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="fragmented_photos",source=image,
            destination=Safe(changed,"fragmented-photos"),options=new{resume_checkpoint=forged}},token,message=>{}));analyses++;
        Check(rejected.Status=="error"&&rejected.Code=="PHOTO_CHECKPOINT_BINDING_MISMATCH"&&Same(changedBefore,Binding(changed)),
            "actual worker rejects changed CodeSHA even with a correctly recomputed external anchor hash, preserving copied output");
        Guard(token=>RecoveryPipeline.Resume(run,token,message=>{}));analyses++;
        var report=Report(run);
        Check(report.ResumedFromCheckpoint&&report.ResumedIndexBytes==fixture.SourceBytes&&report.ReusedCandidates==1,
            "actual resume verifies indexed source and reuses the acknowledged PNG candidate");
        ExactReport(run,image,fixture);
        Check(Hash(image)==fixture.SourceSha256&&RecoverySession.Read(run).Stages.Single().Status=="complete",
            "cancel, code mismatch and resume preserve immutable source and complete only verified stage");
    }
    static void Limits(Fixture fixture)
    {
        string image=Safe(fixtures,fixture.Image),run=Output("limited-gap");PhotoRecoveryCheckpoint last=null;
        var result=Guard(token=>HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="fragmented_photos",source=image,
            destination=Safe(run,"fragmented-photos"),options=new{max_states=1}},token,message=>{},update=>{
                if(update.Phase=="photo_checkpoint")last=new PhotoRecoveryCheckpoint{Path=update.CheckpointPath,Sha256=update.CheckpointSha256,Sequence=update.CheckpointSequence};
            }));analyses++;
        var report=Json.Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(Safe(run,"fragmented-photos/report.json")));
        Check(result.Status=="partial"&&result.Files==0&&report.Status=="limited"&&report.Candidates==0&&report.SourceUnchanged,
            "first valid splice followed by unexplored alternatives is partial, never successful recovery or uniqueness");
        Check(report.Skipped.ContainsKey("png_gap_attempts_incomplete")&&File.Exists(Safe(run,"fragmented-photos/job.incomplete"))&&last!=null,
            "new gap-specific state limit is explicit and retains an acknowledged point");
        var state=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(last.Path));
        Check(Convert.ToInt64(((Dictionary<string,object>)state["Cursor"])["Png"])==0&&Hash(image)==fixture.SourceSha256,
            "incomplete search does not advance PNG cursor or change source");
        string bounded=Path.Combine(work,"owned-index-limit.dd");
        using(var file=File.Create(bounded))for(int i=0;i<2001;i++)file.Write(new byte[]{137,80,78,71,13,10,26,10,0,0,0,0,0,0,0,0},0,16);
        string before=Hash(bounded),limitedRun=Output("limited-pipeline");
        string checksum=Safe(limitedRun,"baseline.sha256");
        File.WriteAllText(checksum,before,new System.Text.UTF8Encoding(false));
        bool failed=Guard(token=>{
            bool incomplete=false;try{RecoveryPipeline.Run(bounded,limitedRun,Options(),token,message=>{},checksum);}catch(IOException){incomplete=true;}
            token.ThrowIfCancellationRequested();return incomplete;
        });analyses++;
        var saved=RecoverySession.Read(limitedRun);
        Check(failed&&saved.Status=="error"&&saved.Stages.Single(x=>x.Key=="fragmented-photos").Status=="incomplete"&&
            Report(limitedRun).Status=="limited"&&!File.Exists(Safe(limitedRun,"files-index.json"))&&Hash(bounded)==before,
            "public only-method pipeline cannot turn a bounded incomplete analysis into a successful catalog");
    }
    public static int Main(string[] args)
    {
        try {
            if(args.Length!=1)throw new ArgumentException("Usage: PngIdatGapPortableTests.exe <project>");
            using(var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(20))){
                phase=timeout.Token;phaseClock=Stopwatch.StartNew();
                string project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","png-idat-gap-fixtures-current");
                work=Path.Combine(project,".build","png-idat-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
                var allBefore=Binding(fixtures);
                var manifest=Json.Deserialize<Manifest>(File.ReadAllText(Safe(fixtures,"manifest.json")));
                Check(manifest.Schema==1&&manifest.IndependentEncoder&&manifest.SourceSpec=="https://www.w3.org/TR/2025/REC-png-3-20250624/"&&
                    Digest(manifest.GeneratorSha256)&&manifest.GeneratorSha256==Hash(Path.Combine(project,"tests","build_png_idat_gap_fixtures.py")),
                    "independent native encoder fixture manifest is bound to current generator");
                Check(manifest.Cases!=null&&manifest.Cases.Count==26&&manifest.Cases.Select(x=>x.Name).Distinct().Count()==26&&
                    Names.All(name=>manifest.Cases.Any(x=>x.Name==name))&&manifest.Cases.All(x=>Names.Contains(x.Name)),
                    "all 26 declared cases are mandatory; large cuts, both ambiguities and negatives cannot be silently skipped");
                foreach(var item in manifest.Cases){
                    Check(item.Image==item.Name+"/image.dd"&&item.Original==item.Name+"/original.png"&&Digest(item.SourceSha256)&&Digest(item.Sha256)&&
                        Hash(Safe(fixtures,item.Image))==item.SourceSha256&&new FileInfo(Safe(fixtures,item.Image)).Length==item.SourceBytes&&
                        Hash(Safe(fixtures,item.Original))==item.Sha256&&new FileInfo(Safe(fixtures,item.Original)).Length==item.Bytes,
                        "independent input and original byte hashes match manifest: "+item.Name);
                    Check(item.ExpectedCandidates==(Positives.Contains(item.Name)?1:0)&&item.Oracle!=null&&item.Oracle.Width>0&&item.Oracle.Height>0&&
                        (item.ExpectedCandidates==0||item.ExpectedSha256==item.Sha256&&item.AllOriginalBytesPresent),"expected data is independent and valid for mandatory case: "+item.Name);
                    Check(item.PhysicalExtents!=null&&item.PhysicalExtents.Count>=1&&item.PhysicalExtents.All(x=>
                        x.LogicalOffset>=0&&x.ImageOffset>=0&&x.Length>0&&x.ImageOffset<=item.SourceBytes-x.Length),
                        "independent source ranges are present and physically bounded: "+item.Name);
                    if(item.ExpectedCandidates==1){
                        long logical=0;
                        foreach(var extent in item.PhysicalExtents){Check(extent.LogicalOffset==logical,"independent ranges cover positive logical file in order");logical+=extent.Length;}
                        Check(logical==item.Bytes,"independent positive range length equals the complete native PNG");
                    }
                    if(item.Name=="ambiguous-tail"||item.Name=="mixed-intact-gap-ambiguous"){
                        string alternate=Safe(fixtures,item.Name+"/alternative.png");
                        Check(item.AllOriginalBytesPresent&&File.Exists(alternate)&&Hash(alternate)!=item.Sha256&&
                            Pixels(alternate,item)!=Pixels(Safe(fixtures,item.Original),item),
                            "ambiguity fixture contains two independently decodable native PNGs with different pixels");
                    }
                }
                foreach(var expected in new[]{new{Key="cut-32k",Cut=32768L},new{Key="cut-128k",Cut=131072L},new{Key="cut-1280k",Cut=1310720L}}){
                    var item=manifest.Cases.Single(x=>x.Name==expected.Key);
                    Check(item.LogicalCut>=expected.Cut&&item.SourceCutIsAbsolute512,"mandatory late physical cut is present: "+expected.Key);
                }
                Check(File.Exists(HelperClient.Executable),"actual packaged helper exists");
                string helperBefore=Hash(HelperClient.Executable),appBefore=Hash(typeof(RecoveryCore).Assembly.Location);
                File.WriteAllText(Path.Combine(work,"inputs-before.json"),Json.Serialize(new{
                    Schema=1,GeneratorSha256=manifest.GeneratorSha256,App=typeof(RecoveryCore).Assembly.Location,AppSha256=appBefore,
                    Helper=HelperClient.Executable,HelperSha256=helperBefore,SourceFiles=allBefore}),new System.Text.UTF8Encoding(false));
                foreach(var fixture in manifest.Cases)Wrapper(fixture);
                foreach(string name in new[]{"cut-128k","ancillary-tail","indexed-palette"})Pipeline(manifest.Cases.Single(x=>x.Name==name));
                CancelResume(manifest.Cases.Single(x=>x.Name=="cut-1280k"));
                Limits(manifest.Cases.Single(x=>x.Name=="cut-512"));
                var allAfter=Binding(fixtures);string helperAfter=Hash(HelperClient.Executable),appAfter=Hash(typeof(RecoveryCore).Assembly.Location);
                Check(Same(allBefore,allAfter)&&helperAfter==helperBefore&&appAfter==appBefore,
                    "all source fixtures and actual app/helper remain byte-identical throughout portable phase");
                File.WriteAllText(Path.Combine(work,"acceptance.json"),Json.Serialize(new{
                    Schema=1,Status="PASS",RuntimeExecuted=true,ActualHelperExecuted=true,Checks=checks,Analyses=analyses,
                    Cases=manifest.Cases.Select(x=>new{x.Name,x.ExpectedCandidates,x.SourceSha256,x.Sha256}).ToArray(),
                    GeneratorSha256=manifest.GeneratorSha256,AppSha256Before=appBefore,AppSha256After=appAfter,
                    HelperSha256Before=helperBefore,HelperSha256After=helperAfter,SourceFilesBefore=allBefore,SourceFilesAfter=allAfter,
                    RealDevicesTested=false,AuthenticatesOriginalOwnership=false}),new System.Text.UTF8Encoding(false));
                Console.WriteLine("PASS PngIdatGapPortable: "+checks+" checks; "+analyses+" actual helper/public analyses, mandatory 26 native PNG cases, 17 exact originals, all-byte physical replay, late sector cuts, palette/ancillary/multi-IDAT/CRC splits, both ambiguity controls/overlap/corruption, catalog uncertainty, cancellation/code binding/resume and incomplete limits. Own regular images only; no devices, new paid comparison or authenticated original claim.");
            }return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
