using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Uses only known fixture bytes/placements; no recovery code constructs expectations.
public static class PngStreamingPortableTests
{
    public sealed class Range { public long ImageOffset,LogicalOffset,Length; }
    public sealed class KnownMap { public string Sha256;public List<Range> Extents; }
    public sealed class Fixture { public string Name,Sha256,Image,Original;public List<KnownMap> KnownMaps; }
    public sealed class Manifest { public int Schema;public List<Fixture> Cases; }
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    const long SourceBytes=132L*1024*1024, Late=129L*1024*1024+8192;
    const string ManifestSha="92e8a0bb8f2e4446184b07a41e7a2f7d8e5a966c44793f83ec8a40f9658c4e3b";
    const string OriginalSha="29caa93faa24cd91f0b88dab2d81722441a217d5796e9a3d559a7e15ef77bcdc";
    static int checks,analyses;static string project,fixtures,work;static CancellationToken cancel;
    static void Check(bool value,string why){checks++;if(!value)throw new IOException(why);}
    static string Hash(string file){using(var stream=File.OpenRead(file))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
    static string Safe(string root,string relative){return RecoveryCatalog.SafeFile(root,relative);}
    static void Save(string file,object value){File.WriteAllText(file,Json.Serialize(value),new System.Text.UTF8Encoding(false));}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true,StreamingPngIndex=true};}
    static FragmentedPhotoRecovery.Report Report(string run){return Json.Deserialize<FragmentedPhotoRecovery.Report>(File.ReadAllText(Safe(run,"fragmented-photo-search.json")));}
    static string Map(IEnumerable<Range> ranges)
    {
        var result=new List<Range>();long logical=0;
        foreach(var range in ranges){Check(range.LogicalOffset==logical&&range.Length>0,"known map has exact logical coverage");logical+=range.Length;
            if(result.Count>0&&result.Last().ImageOffset+result.Last().Length==range.ImageOffset)result.Last().Length+=range.Length;
            else result.Add(new Range{ImageOffset=range.ImageOffset,Length=range.Length});}
        return String.Join(";",result.Select(row=>row.ImageOffset+":"+row.Length));
    }
    static byte[] Replay(string source,List<Range> ranges)
    {
        using(var output=new MemoryStream())using(var input=File.OpenRead(source)){
            foreach(var range in ranges){cancel.ThrowIfCancellationRequested();Check(range.Length>0&&range.Length<2*1024*1024&&range.ImageOffset>=0&&range.ImageOffset<=input.Length-range.Length,"known source extent is bounded");
                input.Position=range.ImageOffset;byte[] bytes=new byte[(int)range.Length];int done=0;
                while(done<bytes.Length){int read=input.Read(bytes,done,bytes.Length-done);if(read==0)throw new EndOfStreamException();done+=read;}output.Write(bytes,0,bytes.Length);}
            return output.ToArray();}
    }
    static string BytesHash(byte[] raw){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(raw)).Replace("-","").ToLowerInvariant();}
    static void Place(string source,byte[] raw,List<Range> ranges)
    {
        using(var output=new FileStream(source,FileMode.Open,FileAccess.Write,FileShare.None)){
            foreach(var range in ranges){Check(range.Length>0&&range.LogicalOffset>=0&&range.LogicalOffset<=raw.Length-range.Length&&range.ImageOffset>=0&&range.ImageOffset<=output.Length-range.Length,"independent placement is bounded");
                output.Position=range.ImageOffset;output.Write(raw,(int)range.LogicalOffset,(int)range.Length);}output.Flush(true);}
        Check(Replay(source,ranges).SequenceEqual(raw),"independent placement reproduces all original bytes before recovery");
    }
    static string NewSource(string name){string path=Safe(work,name+".dd");using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){file.SetLength(SourceBytes);file.Flush(true);}return path;}
    static object Run(string name,string source,int expected,string original,List<Range> known)
    {
        string before=Hash(source),run=Safe(work,name+"-output");int attempts=0,limited=0;bool resumed=false;
        Directory.CreateDirectory(run);string checksum=Safe(run,"source.sha256");
        File.WriteAllText(checksum,before,new System.Text.UTF8Encoding(false));ScanResult result=null;
        for(;attempts<12;attempts++){
            cancel.ThrowIfCancellationRequested();var watch=Stopwatch.StartNew();
            try{
                result=attempts==0?RecoveryPipeline.Run(source,run,Options(),cancel,message=>{},checksum):RecoveryPipeline.Resume(run,cancel,message=>{});analyses++;
            }catch(IOException){
                analyses++;string reportPath=Safe(run,"fragmented-photo-search.json");if(!File.Exists(reportPath))throw;
                var partial=Report(run);if(partial.Status!="limited")throw;
                var stage=RecoverySession.Read(run).Stages.Single(row=>row.Key=="fragmented-photos");
                Check(stage.Status=="incomplete"&&stage.CheckpointSequence>0,"bounded pass keeps a durable unfinished stage");
                Check(partial.Candidates==0&&!Directory.GetFiles(Safe(run,"fragmented-photos"),"*.png").Any(),"unfinished global pool never publishes an early unique image");
                Check(!File.Exists(Safe(run,"files-index.json")),"unfinished only-method run never publishes final catalog");limited++;continue;
            }
            Check(watch.Elapsed<TimeSpan.FromMinutes(5),"native call stays within bounded test interval");resumed=attempts>0;break;
        }
        Check(result!=null&&attempts<12,"global search actually completes within bounded attempts");
        var report=Report(run);Check(report.Status=="complete"&&report.StreamingPng&&report.SourceUnchanged&&report.SourceSha256==before,"public pipeline uses requested source-bound streaming mode");
        Check(report.IndexBytes==(SourceBytes/512+1)*4&&new FileInfo(Safe(run,"fragmented-photos.index/sector-crcs.bin")).Length==report.IndexBytes,"disk index covers the whole large source");
        Check(report.Candidates==expected&&result.Candidates==expected&&Hash(source)==before,"actual recovered count and original source identity match independent expectation");
        var catalog=RecoveryCatalog.Build(run,cancel,null);Check(!catalog.Items.Any(item=>item.Path.IndexOf(".index/",StringComparison.OrdinalIgnoreCase)>=0),"working CRC index is excluded from recovered files");
        if(expected==1){var candidate=report.Files.Single();string file=Safe(run,candidate.Path);
            Check(Hash(file)==OriginalSha&&File.ReadAllBytes(file).SequenceEqual(File.ReadAllBytes(original)),"large-source candidate exactly matches independent known PNG");
            var maps=new List<List<FragmentedPhotoRecovery.Extent>>{candidate.Extents};maps.AddRange(candidate.AlternateExtents);
            Check(maps.Any(map=>Map(map.Select(row=>new Range{ImageOffset=row.ImageOffset,LogicalOffset=row.LogicalOffset,Length=row.Length}))==Map(known)),"output retains independently placed large-source map");
            foreach(var map in maps)Check(Replay(source,map.Select(row=>new Range{ImageOffset=row.ImageOffset,LogicalOffset=row.LogicalOffset,Length=row.Length}).ToList()).SequenceEqual(File.ReadAllBytes(file)),"every published physical map replays exact output bytes");
        }else Check(report.Files.Count==0&&report.Skipped.ContainsKey("png_ambiguous")&&report.Skipped["png_ambiguous"]>0&&!Directory.GetFiles(Safe(run,"fragmented-photos"),"*.png").Any(),"late different valid content is ambiguous, not a successful unique recovery");
        string reportSha=Hash(Safe(run,"fragmented-photo-search.json"));var reuse=RecoveryPipeline.Resume(run,cancel,message=>{});analyses++;
        Check(reuse.ResumedStages==1&&Hash(Safe(run,"fragmented-photo-search.json"))==reportSha,"completed public session reuses exact source/index-bound artifacts");
        return new{Name=name,SourceSha256=before,Bytes=SourceBytes,ExpectedCandidates=expected,Attempts=attempts+1,LimitedPasses=limited,Resumed=resumed,ReportSha256=reportSha,IndexBytes=report.IndexBytes};
    }
    public static int Main(string[] args)
    {
        try{if(args.Length!=1)throw new ArgumentException("Expected project path");using(var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(18))){cancel=timeout.Token;
            project=Path.GetFullPath(args[0]);fixtures=Safe(project,".build/png-two-gap-fixtures-current");work=Safe(project,".build/png-streaming-portable-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            string manifest=Safe(fixtures,"manifest.json");Check(Hash(manifest)==ManifestSha,"fixture corpus is independently pinned");
            var corpus=Json.Deserialize<Manifest>(File.ReadAllText(manifest));Check(corpus.Schema==1&&corpus.Cases.Count==20,"all independent baseline cases remain available");
            string appBefore=Hash(typeof(RecoveryCore).Assembly.Location),helperBefore=Hash(HelperClient.Executable);
            var original=corpus.Cases.Single(row=>row.Name=="two-gap-rgb");string png=Safe(Safe(fixtures,original.Name),original.Original);Check(Hash(png)==OriginalSha,"large-source original has immutable baseline hash");
            byte[] raw=File.ReadAllBytes(png);var seam=new List<Range>{new Range{ImageOffset=8192,LogicalOffset=0,Length=32768},new Range{ImageOffset=134168576,LogicalOffset=32768,Length=98304},new Range{ImageOffset=65536,LogicalOffset=131072,Length=raw.Length-131072}};
            string source=NewSource("page-seam");Place(source,raw,seam);
            var ambiguous=corpus.Cases.Single(row=>row.Name=="two-gap-ambiguous");Check(ambiguous.KnownMaps.Select(row=>row.Sha256).Distinct().Count()==2,"late ambiguity has two independently known contents");
            string ambiguousSource=Safe(fixtures,ambiguous.Image),late=NewSource("late-different-content");
            foreach(var known in ambiguous.KnownMaps){byte[] bytes=Replay(ambiguousSource,known.Extents);Check(BytesHash(bytes)==known.Sha256,"known ambiguity content replays frozen source bytes");
                var moved=known.Extents.Select(row=>new Range{ImageOffset=row.ImageOffset,LogicalOffset=row.LogicalOffset,Length=row.Length}).ToList();
                if(known.Sha256!=ambiguous.Sha256)moved.Last().ImageOffset=Late;Place(late,bytes,moved);}
            Save(Safe(work,"inputs-before.json"),new{ManifestSha256=ManifestSha,AppSha256=appBefore,HelperSha256=helperBefore,OriginalSha256=OriginalSha,Seam=seam,SourceSha256=Hash(source),LateSourceSha256=Hash(late),NoRecoveryCodeInPlacement=true});
            var rows=new[]{Run("page-seam",source,1,png,seam),Run("late-different-content",late,0,null,null)};
            Check(Hash(manifest)==ManifestSha&&Hash(png)==OriginalSha&&Hash(typeof(RecoveryCore).Assembly.Location)==appBefore&&Hash(HelperClient.Executable)==helperBefore,"original fixture and actual app/helper bytes remain unchanged");
            Save(Safe(work,"acceptance.json"),new{Schema=1,Status="PASS",Checks=checks,Analyses=analyses,Cases=rows,ActualPackagedHelperExecuted=true,AppSha256=appBefore,HelperSha256=helperBefore,RealDevicesTested=false,NewPaidComparisonRun=false});
            Console.WriteLine("PASS PngStreamingPortable: "+checks+" checks; actual packaged pipeline, 132 MiB CRC-page seam exact reconstruction, late different-content ambiguity, complete coverage/index binding and persisted resume. Controlled regular images only.");return 0;}
        }catch(Exception error){if(work!=null)Save(Safe(work,"failure.json"),new{Status="FAIL",Error=error.ToString(),Checks=checks,Analyses=analyses,NoSuccessfulAcceptanceInferred=true});Console.Error.WriteLine(error);return 1;}
    }
}
