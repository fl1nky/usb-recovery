using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class FragmentedMediaUnitRecoveryTests
{
    static int checks;static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Sha(byte[] raw){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(raw)).Replace("-","").ToLowerInvariant();}
    static string Hash(string path){using(var hash=SHA256.Create())using(var input=File.OpenRead(path))return BitConverter.ToString(hash.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static byte[] Read(FileStream input,long at,int bytes){input.Position=at;var raw=new byte[bytes];int done=0;while(done<bytes){int n=input.Read(raw,done,bytes-done);if(n==0)throw new EndOfStreamException();done+=n;}return raw;}
    static string Decode(string ffmpeg,string file,bool audio)
    {
        if(ffmpeg.Contains("\"")||file.Contains("\""))throw new IOException("Unexpected quoted test path");
        var info=new ProcessStartInfo(ffmpeg,"-v error -nostdin -i \""+file+"\" -map 0:"+(audio?"a -c:a pcm_s16le -f s16le":"v -an -f framemd5")+" -"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var process=Process.Start(info))using(var output=new MemoryStream()){
            var errors=process.StandardError.ReadToEndAsync();process.StandardOutput.BaseStream.CopyTo(output);if(!process.WaitForExit(30000)){process.Kill();throw new IOException("Independent decoder timeout");}
            if(process.ExitCode!=0||errors.Result.Length!=0)throw new IOException("Independent decoder rejected candidate");byte[] raw=output.ToArray();if(audio)return Sha(raw);
            var rows=Encoding.UTF8.GetString(raw).Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Where(x=>!x.StartsWith("#",StringComparison.Ordinal));return Sha(Encoding.UTF8.GetBytes(String.Join("\n",rows)));
        }
    }
    static FragmentedMediaRecovery.Report Report(string run){return Json.Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Path.Combine(run,"fragmented-media.json")));}
    static void Limits(string image,string work)
    {
        string before=Hash(image);
        foreach(bool verification in new[]{false,true}){
            string run=Path.Combine(work,verification?"verification-limit":"output-limit");var limits=new FragmentedMediaRecovery.Limits();if(verification)limits.MaxVerifiedBytes=1;else limits.MaxOutputBytes=1;
            bool rejected=false;try{FragmentedMediaRecovery.Recover(image,run,CancellationToken.None,null,limits);}catch(IOException error){rejected=error.Message=="MEDIA_SEARCH_LIMIT_REACHED";}
            var report=Report(run);Check(rejected&&report.Status=="limited"&&report.Files.Count==0,"Budget exhaustion never claims complete/unique");Check(!Directory.GetFiles(Path.Combine(run,"fragmented-media")).Any(),"Limited job publishes no complete or partial candidate");
        }
        using(var cancel=new CancellationTokenSource()){
            string run=Path.Combine(work,"cancel-before");cancel.Cancel();bool stopped=false;try{FragmentedMediaRecovery.Recover(image,run,cancel.Token,null);}catch(OperationCanceledException){stopped=true;}Check(stopped&&!Directory.Exists(run),"Pre-cancel preserves no-output invariant");
        }
        using(var cancel=new CancellationTokenSource()){
            string run=Path.Combine(work,"cancel-during");bool stopped=false;try{FragmentedMediaRecovery.Recover(image,run,cancel.Token,(a,b)=>cancel.Cancel());}catch(OperationCanceledException){stopped=true;}Check(stopped&&Report(run).Status=="cancelled","In-flight cancellation remains cancelled");Check(!Directory.GetFiles(Path.Combine(run,"fragmented-media")).Any(),"Cancelled scan has no published media");
        }
        Check(Hash(image)==before,"Limits/cancellation leave source unchanged");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),fixtures=args.Length>1&&!args[1].StartsWith("--",StringComparison.Ordinal)?Path.GetFullPath(args[1]):Path.Combine(project,".build","media-unit-fixtures-current");
            string work=Path.Combine(project,".build","media-unit-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);bool decode=args.Contains("--decode");
            var manifest=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));var cases=((IEnumerable)manifest["cases"]).Cast<Dictionary<string,object>>().ToArray();Check(cases.Length==17,"Independent varied real-muxer and negative corpus complete");
            string ffmpeg=null;if(decode){ffmpeg=Directory.EnumerateFiles(Path.Combine(project,"tools","benchmarks","ffmpeg"),"ffmpeg.exe",SearchOption.AllDirectories).Single();Check(Hash(ffmpeg)==(string)manifest["ffmpeg_sha256"],"Independent decoder binary provenance");}
            var evidence=new List<object>();
            foreach(var sample in cases){
                string name=(string)sample["name"],image=Path.Combine(fixtures,(string)sample["image"]),run=Path.Combine(work,name),before=Hash(image);Check(before==(string)sample["sha256"]&&new FileInfo(image).Length==Convert.ToInt64(sample["bytes"]),name+": pinned independent image hash and size");
                int count=FragmentedMediaRecovery.Recover(image,run,CancellationToken.None,null),expected=Convert.ToInt32(sample["expected"]);var report=Report(run);
                Check(count==expected&&report.Files.Count==expected,name+": expected complete assignments; skips="+Json.Serialize(report.Skipped));Check(report.Status=="complete"&&Hash(image)==before,name+": complete bounded pass/source unchanged");
                Check(!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),name+": no partial publication");string reason=sample["reason"] as string;if(reason!=null)Check(report.Skipped.ContainsKey(reason),name+": correct explicit ambiguity");
                if(expected==0){Check(!Directory.GetFiles(Path.Combine(run,"fragmented-media")).Any(),name+": unsupported/ambiguous sources publish nothing");evidence.Add(new{name=name,candidates=0,source_unchanged=true,skipped=report.Skipped});continue;}
                var result=report.Files.Single();string output=Path.Combine(run,result.Path.Replace('/',Path.DirectorySeparatorChar));Check(result.Sha256==(string)sample["expected_output_sha256"]&&Hash(output)==result.Sha256,name+": complete expected current bytes, not decoder concealment");
                Check(result.Status=="iso_bmff_structural_candidate"&&!result.PayloadAuthenticated&&!result.DeletionConfirmed,name+": never authenticates ownership/deletion/entropy");Check(result.AudioSyntaxChecked&&result.AudioSearch=="allocation_unit_syntax"&&result.Extents.All(e=>e.Kind=="allocation_unit"),name+": bounded new provenance scope");
                long logical=0;using(var source=File.OpenRead(image))using(var file=File.OpenRead(output))foreach(var extent in result.Extents){
                    Check(extent.LogicalOffset==logical&&extent.Length>0&&extent.ImageOffset>=0&&extent.ImageOffset<=source.Length-extent.Length,name+": complete bounded logical map");byte[] actual=Read(file,logical,(int)extent.Length),raw=Read(source,extent.ImageOffset,(int)extent.Length);Check(actual.SequenceEqual(raw),name+": every output byte comes from declared physical source");
                    foreach(long equivalent in extent.EquivalentOffsets)Check(equivalent>=0&&equivalent<=source.Length-extent.Length&&Read(source,equivalent,(int)extent.Length).SequenceEqual(actual),name+": equivalent copy is actually byte-identical");logical+=extent.Length;
                }
                Check(logical==result.Bytes&&report.OutputBytes==logical,name+": exact declared output coverage/aggregate");Check(!result.Extents.Any(a=>result.Extents.Any(b=>!Object.ReferenceEquals(a,b)&&a.ImageOffset<b.ImageOffset+b.Length&&b.ImageOffset<a.ImageOffset+a.Length)),name+": physical source spans never reused");
                if(name=="identical-all-units")Check(result.Extents.Any(x=>x.EquivalentOffsets.Count>1),name+": identical alternatives retained without false ambiguity");if(name=="two-video-tracks-8k")Check(result.Tracks==3,name+": both video tracks and audio retained");
                bool exact=result.Sha256==(string)sample["original_sha256"];Check(exact==Convert.ToBoolean(sample["all_original_bytes_present"]),name+": changed current bytes distinguished from original content");
                string frames=null,pcm=null;if(decode&&Convert.ToBoolean(sample["decode"])){frames=Decode(ffmpeg,output,false);pcm=Decode(ffmpeg,output,true);Check(frames==(string)sample["expected_video_sha256"]&&pcm==(string)sample["expected_audio_sha256"],name+": every decoded video frame and full PCM match independent truth");}
                evidence.Add(new{name=name,candidates=count,sha256=result.Sha256,exact_original=exact,source_unchanged=true,frames_sha256=frames,pcm_sha256=pcm,scope=result.AudioSearch});
            }
            Limits(Path.Combine(fixtures,(string)cases[0]["image"]),work);File.WriteAllText(Path.Combine(work,"verification.json"),Json.Serialize(new{checks=checks,independent_decode=decode,cases=evidence}),new UTF8Encoding(false));Console.WriteLine("PASS FragmentedMediaUnits: "+checks+" checks; 17 independent real AVC+B-frame/AAC cases, exact maps, ambiguity/foreign/missing controls, limits/cancellation. "+work);return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
