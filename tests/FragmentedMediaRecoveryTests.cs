using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Text;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class FragmentedMediaRecoveryTests
{
    static int checks;static string fixtures,work;
    public sealed class AudioFixture {public string Name,Image,Original,Sha256,VideoDecodedSha256,AudioDecodedSha256;public int Expected;public bool Exact;public long Bytes;}
    public sealed class AudioManifest {public int Schema;public string FfmpegSha256;public List<AudioFixture> Cases;}
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=32*1024*1024};}
    static string Hash(string path){using(var file=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Output(string name){return Path.Combine(work,name.Substring(0,Math.Min(12,name.Length))+"-"+Guid.NewGuid().ToString("N").Substring(0,8));}
    static FragmentedMediaRecovery.Report Report(string run){return Json().Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Path.Combine(run,"fragmented-media.json")));}
    static bool Io(Action action){try{action();return false;}catch(IOException){return true;}}
    static string HashBytes(byte[] raw){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(raw)).Replace("-","").ToLowerInvariant();}
    static string Decode(string decoder,string path,bool audio)
    {
        string args="-hide_banner -v error -xerror -protocol_whitelist file,pipe -i \""+path+"\" "+(audio?"-map 0:a:0 -c:a pcm_s16le -f s16le -":"-map 0:v:0 -f framemd5 -");
        using(var output=new MemoryStream())using(var process=new Process{StartInfo=new ProcessStartInfo(decoder,args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
            process.Start();var error=process.StandardError.ReadToEndAsync();var copy=process.StandardOutput.BaseStream.CopyToAsync(output);if(!process.WaitForExit(30000)){try{process.Kill();}catch(InvalidOperationException){}throw new IOException("Independent decoder timeout");}copy.GetAwaiter().GetResult();error.GetAwaiter().GetResult();if(process.ExitCode!=0)throw new IOException("Independent decoder rejected media");byte[] raw=output.ToArray();
            if(audio)return HashBytes(raw);string rows=String.Join("\n",Encoding.UTF8.GetString(raw).Split('\n').Select(x=>x.TrimEnd('\r')).Where(x=>x.Length>0&&!x.StartsWith("#",StringComparison.Ordinal)));return HashBytes(Encoding.UTF8.GetBytes(rows));
        }
    }
    static IEnumerable<Dictionary<string,object>> Rows(object value){return ((IEnumerable)value).Cast<object>().Select(x=>(Dictionary<string,object>)x);}
    static void Cases()
    {
        var cases=Rows(Json().DeserializeObject(File.ReadAllText(Path.Combine(fixtures,"manifest.json")))).ToArray();
        foreach(var fixture in cases){
            string name=(string)fixture["name"],image=Path.Combine(fixtures,name+".dd"),before=Hash(image),run=Output(name);int expected=Convert.ToInt32(fixture["expected"]),ticks=0;
            int count=FragmentedMediaRecovery.Recover(image,run,CancellationToken.None,(done,total)=>{ticks++;Check(done>0&&done<=total,name+": bounded progress");});var report=Report(run);
            Check(count==expected&&report.Candidates==expected&&report.Recovered==expected,name+": expected candidates, got "+count+" skips="+Json().Serialize(report.Skipped));
            Check(report.Status=="complete"&&report.Schema==1&&report.InputBytes==new FileInfo(image).Length,name+": complete inspected-source report");
            Check(Hash(image)==before&&ticks>0,name+": source unchanged");Check(!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),name+": no partial output");
            Check(report.VerifiedBytes>=0&&report.VerifiedBytes<=FragmentedMediaRecovery.MaximumVerifiedBytes,name+": bounded structural work");
            if(expected==0){Check(report.Files.Count==0&&Directory.GetFiles(Path.Combine(run,"fragmented-media")).Length==0,name+": rejected assembly publishes no file");continue;}
            Check(report.Files.Count==1,name+": one distinct output");var result=report.Files[0];string file=Path.Combine(run,result.Path.Replace('/',Path.DirectorySeparatorChar));
            bool exact=Convert.ToBoolean(fixture["exact"]);Check((Hash(file)==(string)fixture["sha256"])==exact&&result.Sha256==Hash(file),name+": independent SHA256 truth including intentionally undecidable payload corruption");Check(result.Bytes==Convert.ToInt64(fixture["bytes"])&&new FileInfo(file).Length==result.Bytes,name+": exact original length");
            Check(result.Tracks==Convert.ToInt32(fixture["tracks"])&&result.Chunks==Convert.ToInt32(fixture["chunks"]),name+": track and chunk accounting");
            Check(result.Status=="iso_bmff_structural_candidate"&&!result.PayloadAuthenticated&&!result.DeletionConfirmed,name+": structural match never becomes authentication/deletion proof");
            Check(result.Path=="fragmented-media/candidate-"+result.Sha256+".mp4",name+": generated safe content-addressed filename");
            var expectedExtents=Rows(fixture["extents"]).OrderBy(x=>Convert.ToInt64(x["LogicalOffset"])).ToArray();Check(result.Extents.Count==expectedExtents.Length,name+": complete provenance mapping");
            long logical=0;using(var source=File.OpenRead(image))using(var original=File.OpenRead(Path.Combine(fixtures,name+".original.mp4"))){
                foreach(var extent in result.Extents){Check(extent.LogicalOffset==logical&&extent.Length>0&&extent.ImageOffset>=0&&extent.ImageOffset<=source.Length-extent.Length,name+": exact logical coverage and physical bounds");
                    byte[] actual=new byte[(int)extent.Length],reference=new byte[(int)extent.Length];source.Position=extent.ImageOffset;original.Position=extent.LogicalOffset;source.Read(actual,0,actual.Length);original.Read(reference,0,reference.Length);if(exact)Check(actual.SequenceEqual(reference),name+": provenance bytes agree with independent original");Check(extent.EquivalentOffsets.Contains(extent.ImageOffset),name+": selected source recorded among equivalents");logical+=extent.Length;
                }
            }
            Check(logical==result.Bytes,name+": no fabricated gaps");
            if(name=="identical-duplicate")Check(result.Extents.Any(x=>x.Kind=="sample_chunk"&&x.EquivalentOffsets.Count>=2),name+": equal copies kept as alternative sources");
        }
        Check(cases.Length>=13,"independent positive/negative corpus present");
    }
    static void Guards()
    {
        string image=Path.Combine(fixtures,"avc-scattered.dd"),before=Hash(image),run=Output("cancel");var cancellation=new CancellationTokenSource();bool cancelled=false;
        try{FragmentedMediaRecovery.Recover(image,run,cancellation.Token,(a,b)=>cancellation.Cancel());}catch(OperationCanceledException){cancelled=true;}
        Check(cancelled&&Report(run).Status=="cancelled"&&Report(run).Files.Count==0,"cancelled scan never publishes a media candidate");
        Check(!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),"cancel removes only owned partial files");
        run=Output("pre-cancel");cancelled=false;try{FragmentedMediaRecovery.Recover(image,run,cancellation.Token,null);}catch(OperationCanceledException){cancelled=true;}Check(cancelled&&!Directory.Exists(run),"pre-cancel does not create output");
        foreach(var limits in new[]{new FragmentedMediaRecovery.Limits{MaxCandidates=1},new FragmentedMediaRecovery.Limits{MaxVerifiedBytes=1},new FragmentedMediaRecovery.Limits{MaxOutputBytes=1}}){
            run=Output("limits");string captured=run;Check(Io(()=>FragmentedMediaRecovery.Recover(image,captured,CancellationToken.None,null,limits)),"configured limit fails explicitly");var report=Report(run);Check(report.Status=="limited"&&report.Files.Count==0,"limit is never complete/success");Check(!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),"limit leaves no partial file");
        }
        run=Output("existing");Directory.CreateDirectory(Path.Combine(run,"fragmented-media"));string keep=Path.Combine(run,"fragmented-media","keep.txt");File.WriteAllText(keep,"original");string existing=run;Check(Io(()=>FragmentedMediaRecovery.Recover(image,existing,CancellationToken.None,null))&&File.ReadAllText(keep)=="original","existing destination is preserved");
        run=Output("existing-report");Directory.CreateDirectory(run);keep=Path.Combine(run,"fragmented-media.json");File.WriteAllText(keep,"original");existing=run;Check(Io(()=>FragmentedMediaRecovery.Recover(image,existing,CancellationToken.None,null))&&File.ReadAllText(keep)=="original","existing report is preserved");
        Check(Io(()=>FragmentedMediaRecovery.Recover(@"\\.\PhysicalDrive0",Output("device"),CancellationToken.None,null)),"raw device rejected without reading it");Check(Io(()=>FragmentedMediaRecovery.Recover(image+":stream",Output("ads"),CancellationToken.None,null)),"alternate stream rejected");
        bool locked=false;run=Output("locked");FragmentedMediaRecovery.Recover(image,run,CancellationToken.None,(a,b)=>{try{using(var write=new FileStream(image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)){} }catch(IOException){locked=true;}});Check(locked,"source is held under read lock");
        Check(Hash(image)==before,"all guard cases preserve source bytes");
    }
    static void AudioCases(string project)
    {
        string directory=Path.Combine(project,".build","fragmented-media-audio-tests"),decoder=Directory.EnumerateFiles(Path.Combine(project,"tools","benchmarks","ffmpeg"),"ffmpeg.exe",SearchOption.AllDirectories).Single();
        var manifest=Json().Deserialize<AudioManifest>(File.ReadAllText(Path.Combine(directory,"manifest.json")));Check(manifest.Schema==1&&manifest.Cases.Count==10,"real FFmpeg AVC/AAC positive/negative controls exist");Check(Hash(decoder)==manifest.FfmpegSha256,"decoded comparisons use exact recorded independent FFmpeg binary");
        foreach(var fixture in manifest.Cases){
            string image=Path.Combine(directory,fixture.Image),before=Hash(image),run=Output("audio");int count=FragmentedMediaRecovery.Recover(image,run,CancellationToken.None,null);var report=Report(run);
            Check(count==fixture.Expected&&report.Candidates==fixture.Expected,fixture.Name+": expected bounded AAC geometry candidate count");Check(report.Status=="complete"&&Hash(image)==before,fixture.Name+": completed bounded inspection preserves source");
            if(fixture.Expected==0){Check(report.Files.Count==0,fixture.Name+": ambiguous/missing AAC is never synthesized");continue;}
            var result=report.Files.Single();string file=Path.Combine(run,result.Path.Replace('/',Path.DirectorySeparatorChar));Check((result.Sha256==fixture.Sha256)==fixture.Exact&&Hash(file)==result.Sha256,fixture.Name+": exact/overwritten reference truth preserved");
            Check(result.AudioGeometryInferred&&result.AudioChunks>0&&result.Extents.Any(x=>x.Kind=="aac_geometry_chunk"),fixture.Name+": AAC provenance explicitly names inferred source geometry");Check(!result.PayloadAuthenticated&&!result.DeletionConfirmed&&result.Status=="iso_bmff_structural_candidate",fixture.Name+": AAC decoding is never authentication");
            Check(Decode(decoder,file,false)==fixture.VideoDecodedSha256,fixture.Name+": all independently decoded video frames match reference");
            if(fixture.Exact){Check(result.Bytes==fixture.Bytes&&Decode(decoder,file,true)==fixture.AudioDecodedSha256,fixture.Name+": complete decoded PCM audio matches independent reference");}
            else {string actual=null;try{actual=Decode(decoder,file,true);}catch(IOException){}Check(actual!=fixture.AudioDecodedSha256,fixture.Name+": structural AAC agreement cannot hide altered audio payload");}
            long logical=0;using(var source=File.OpenRead(image))using(var output=File.OpenRead(file))foreach(var extent in result.Extents){Check(extent.LogicalOffset==logical&&extent.ImageOffset>=0&&extent.Length>0&&extent.ImageOffset<=source.Length-extent.Length,fixture.Name+": coherent original byte ranges");byte[] a=new byte[(int)extent.Length],b=new byte[(int)extent.Length];source.Position=extent.ImageOffset;source.Read(a,0,a.Length);output.Read(b,0,b.Length);Check(a.SequenceEqual(b),fixture.Name+": AAC/container bytes copied exactly without remux or synthesized data");logical+=extent.Length;}Check(logical==result.Bytes,fixture.Name+": extents cover complete output");
        }
    }
    public static int Main(string[] args)
    {
        try{string project=Path.GetFullPath(args[0]);fixtures=args.Length>1&&!args[1].StartsWith("--",StringComparison.Ordinal)?Path.GetFullPath(args[1]):Path.Combine(project,".build","fragmented-media-tests");work=Path.Combine(project,".build","media-runs-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(work);Cases();Guards();bool externalAudio=args.Contains("--audio-external");if(externalAudio)AudioCases(project);Console.WriteLine("PASS FragmentedMediaRecovery: "+checks+" checks; independent QTFF, AVC/MJPEG chunk islands, strict geometry and corruption negatives. "+(externalAudio?"External FFmpeg AVC/AAC video+PCM comparisons included. ":"")+"Structural candidates remain unauthenticated.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
