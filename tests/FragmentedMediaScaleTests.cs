using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using UsbRecovery;

// Developer integration corpus is generated outside Git by the pinned encoder.
// A source map/original reference is test ground truth, never recovery input.
public static class FragmentedMediaScaleTests
{
    static int checks;static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Sha(byte[] raw){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(raw)).Replace("-","").ToLowerInvariant();}
    static string Hash(string path){using(var hash=SHA256.Create())using(var file=File.OpenRead(path))return BitConverter.ToString(hash.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static async Task Drain(Stream input,MemoryStream output,long maximum)
    {
        byte[] buffer=new byte[65536];int count;while((count=await input.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false))>0){if(count>maximum-output.Length)throw new IOException("Independent decoder output limit");output.Write(buffer,0,count);}
    }
    static string Decode(string ffmpeg,string path,bool audio)
    {
        if(path.Contains("\"")||ffmpeg.Contains("\""))throw new IOException("Unexpected quoted fixture path");
        var info=new ProcessStartInfo(ffmpeg,"-v error -nostdin -i \""+path+"\" -map 0:"+(audio?"a -c:a pcm_s16le -f s16le":"v -an -f framemd5")+" -"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var process=Process.Start(info))using(var output=new MemoryStream())using(var errors=new MemoryStream()){
            Task payload=Drain(process.StandardOutput.BaseStream,output,64L*1024*1024),diagnostics=Drain(process.StandardError.BaseStream,errors,1024*1024);var clock=Stopwatch.StartNew();
            try{
                while(!process.WaitForExit(100)){if(payload.IsFaulted||diagnostics.IsFaulted)throw new IOException("Independent decoder output failed");if(clock.ElapsedMilliseconds>=60000)throw new IOException("Independent decoder timed out");}
                int left=(int)Math.Max(1,60000-clock.ElapsedMilliseconds);if(!Task.WhenAll(payload,diagnostics).Wait(left))throw new IOException("Independent decoder pipe timed out");
            }finally{if(!process.HasExited)process.Kill();}
            if(process.ExitCode!=0||errors.Length!=0)throw new IOException("Independent decoder rejected candidate");byte[] raw=output.ToArray();if(audio)return Sha(raw);
            return Sha(Encoding.UTF8.GetBytes(String.Join("\n",Encoding.UTF8.GetString(raw).Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Where(x=>!x.StartsWith("#",StringComparison.Ordinal)))));
        }
    }
    static FragmentedMediaRecovery.Report Report(string output){return Json.Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Path.Combine(output,"fragmented-media.json")));}
    static void SourceMap(string image,string path,FragmentedMediaRecovery.Result result)
    {
        long logical=0;byte[] a=new byte[65536],b=new byte[65536];using(var source=File.OpenRead(image))using(var output=File.OpenRead(path))foreach(var e in result.Extents){
            Check(e.LogicalOffset==logical&&e.Length>0&&e.ImageOffset>=0&&e.ImageOffset<=source.Length-e.Length,"Bounded complete logical/physical mapping");source.Position=e.ImageOffset;output.Position=logical;long left=e.Length;
            while(left>0){int bytes=(int)Math.Min(left,a.Length);Check(source.Read(a,0,bytes)==bytes&&output.Read(b,0,bytes)==bytes&&a.Take(bytes).SequenceEqual(b.Take(bytes)),"Every published large-file byte matches its declared source range");left-=bytes;}
            Check(result.Extents.All(other=>Object.ReferenceEquals(other,e)||e.ImageOffset>=other.ImageOffset+other.Length||other.ImageOffset>=e.ImageOffset+e.Length),"Physical source units never reused");logical+=e.Length;
        }Check(logical==result.Bytes,"Full output coverage without invented bytes");
    }
    static void Controls(string image,string work)
    {
        string before=Hash(image),limited=Path.Combine(work,"verification-limit");bool stopped=false;
        try{FragmentedMediaRecovery.Recover(image,limited,CancellationToken.None,null,new FragmentedMediaRecovery.Limits{MaxVerifiedBytes=1});}catch(IOException error){stopped=error.Message=="MEDIA_SEARCH_LIMIT_REACHED";}
        Check(stopped&&Report(limited).Status=="limited"&&!Directory.GetFiles(Path.Combine(limited,"fragmented-media")).Any(),"Verification exhaustion cannot publish a unique result");
        string cancelled=Path.Combine(work,"range-cancel");using(var cancel=new CancellationTokenSource()){
            stopped=false;try{FragmentedMediaRecovery.Recover(image,cancelled,cancel.Token,(a,b)=>{if(a==b)cancel.CancelAfter(100);});}catch(OperationCanceledException){stopped=true;}
            Check(stopped&&Report(cancelled).Status=="cancelled","Cancellation after metadata scan interrupts source-backed work");Check(!Directory.GetFiles(Path.Combine(cancelled,"fragmented-media")).Any()&&!Directory.GetFiles(cancelled,"*.partial",SearchOption.AllDirectories).Any(),"Cancellation removes owned partials and publishes nothing");
        }Check(Hash(image)==before,"Control paths leave source unchanged");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),fixtures=args.Length>1&&!args[1].StartsWith("--",StringComparison.Ordinal)?Path.GetFullPath(args[1]):Path.Combine(project,".build","media-scale-fixtures-01"),work=Path.Combine(project,".build","media-scale-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);bool decode=args.Contains("--decode");
            var manifest=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));var cases=((IEnumerable)manifest["cases"]).Cast<Dictionary<string,object>>().ToArray();Check(cases.Length==9,"Nine real large/missing/ambiguous/phase cases");
            string ffmpeg=null;if(decode){ffmpeg=Directory.EnumerateFiles(Path.Combine(project,"tools","benchmarks","ffmpeg"),"ffmpeg.exe",SearchOption.AllDirectories).Single();Check(Hash(ffmpeg)==(string)manifest["ffmpeg_sha256"],"Fixed independent encoder/decoder identity");}bool over32=false;var evidence=new List<object>();
            foreach(var fixture in cases){
                string name=(string)fixture["name"],image=Path.Combine(fixtures,(string)fixture["image"]),run=Path.Combine(work,name),before=Hash(image);Check(before==(string)fixture["sha256"]&&new FileInfo(image).Length==Convert.ToInt64(fixture["bytes"]),name+": independent large image binding");var clock=Stopwatch.StartNew();int count;
                using(var cancel=new CancellationTokenSource(TimeSpan.FromMinutes(3)))try{count=FragmentedMediaRecovery.Recover(image,run,cancel.Token,null);}catch(IOException error){if(Convert.ToInt32(fixture["expected"])!=0||error.Message!="MEDIA_SEARCH_LIMIT_REACHED")throw;count=0;}clock.Stop();var report=Report(run);
                Check(count==Convert.ToInt32(fixture["expected"])&&report.Files.Count==count,name+": expected source assignments; skips="+Json.Serialize(report.Skipped));Check((report.Status=="complete"||count==0&&report.Status=="limited")&&Hash(image)==before,name+": truthful bounded result/source immutable");Check(report.SourceReadBytes>=report.InputBytes&&report.SourceReadBytes>=report.VerifiedBytes,name+": scan/index reads reported separately from verification");Check(!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),name+": no orphan spool or partial output");
                if((string)fixture["action"]=="foreign-choice")Check(report.Status=="complete"&&report.Skipped.ContainsKey("unit_mapping_ambiguous"),"Different valid complete byte assignments are explicitly ambiguous");
                string frames=null,pcm=null;if(count>0){
                    var result=report.Files.Single();string file=Path.Combine(run,result.Path.Replace('/',Path.DirectorySeparatorChar));Check(Hash(file)==(string)fixture["expected_output_sha256"]&&Hash(file)==result.Sha256,name+": all source bytes reproduce the independent original");Check(result.Bytes>16*1024*1024,name+": actual output exceeds previous whole-output cap");over32|=result.Bytes>32*1024*1024;
                    Check(result.Status=="iso_bmff_structural_candidate"&&!result.PayloadAuthenticated&&!result.DeletionConfirmed,name+": no entropy/ownership/deletion authentication");SourceMap(image,file,result);
                    if(name=="identical-unit-copy")Check(result.Extents.Any(e=>e.EquivalentOffsets.Count>1),"Identical physical alternatives retained");
                    if(decode){frames=Decode(ffmpeg,file,false);pcm=Decode(ffmpeg,file,true);Check(frames==(string)fixture["expected_video_sha256"]&&pcm==(string)fixture["expected_audio_sha256"],name+": all real decoded frames and PCM match independent truth");}
                }else Check(!Directory.GetFiles(Path.Combine(run,"fragmented-media")).Any(),name+": no guessed full output");
                var self=Process.GetCurrentProcess();self.Refresh();evidence.Add(new{name=name,candidates=count,status=report.Status,source_unchanged=true,elapsed_ms=clock.ElapsedMilliseconds,peak_working_set=self.PeakWorkingSet64,source_read_bytes=report.SourceReadBytes,verified_bytes=report.VerifiedBytes,frame_sha256=frames,pcm_sha256=pcm,skips=report.Skipped});Console.WriteLine(name+": "+count+", "+report.Status+", "+clock.ElapsedMilliseconds+" ms");
            }
            Check(over32,"At least one exact real output exceeds the old32MiB retained-payload cap");Controls(Path.Combine(fixtures,(string)cases[0]["image"]),work);File.WriteAllText(Path.Combine(work,"verification.json"),Json.Serialize(new{checks=checks,pipeline_used=false,application_sha256=Hash(typeof(FragmentedMediaRecovery).Assembly.Location),manifest_sha256=Hash(Path.Combine(fixtures,"manifest.json")),independent_decode=decode,cases=evidence}),new UTF8Encoding(false));Console.WriteLine("PASS FragmentedMediaScale: "+checks+" checks; real >16/>32MiB movies, range-backed maps, honest ambiguity/missing/phase controls. "+work);return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
