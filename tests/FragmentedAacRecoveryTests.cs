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

public static class FragmentedAacRecoveryTests
{
    static int checks;static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Sha(byte[] bytes){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
    static string Hash(string path){using(var hash=SHA256.Create())using(var file=File.OpenRead(path))return BitConverter.ToString(hash.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static string Decode(string ffmpeg,string file,bool audio)
    {
        if(file.Contains("\"")||ffmpeg.Contains("\""))throw new IOException("Unexpected quoted test path");
        var start=new ProcessStartInfo(ffmpeg,"-v error -nostdin -i \""+file+"\" -map 0:"+(audio?"a -c:a pcm_s16le -f s16le":"v -an -f framemd5")+" -"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var process=Process.Start(start))using(var output=new MemoryStream()){
            var errors=process.StandardError.ReadToEndAsync();process.StandardOutput.BaseStream.CopyTo(output);
            if(!process.WaitForExit(30000)){process.Kill();throw new IOException("Independent decoder time limit");}
            if(process.ExitCode!=0||errors.Result.Length!=0)throw new IOException("Independent decoder rejected candidate");
            byte[] bytes=output.ToArray();if(audio)return Sha(bytes);
            var lines=Encoding.UTF8.GetString(bytes).Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Where(x=>!x.StartsWith("#",StringComparison.Ordinal));return Sha(Encoding.UTF8.GetBytes(String.Join("\n",lines)));
        }
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),fixtures=args.Length>1&&!args[1].StartsWith("--",StringComparison.Ordinal)?Path.GetFullPath(args[1]):Path.Combine(project,".build","aac-recovery-fixtures-current");
            string work=Path.Combine(project,".build","aac-recovery-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            var manifest=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));var cases=((IEnumerable)manifest["cases"]).Cast<Dictionary<string,object>>().ToArray();
            Check(cases.Length==16,"Independent real-muxer positive, damaged, ambiguous, duplicated and unsupported-layout cases present");
            bool decode=args.Contains("--decode");string ffmpeg=null;if(decode){ffmpeg=Directory.EnumerateFiles(Path.Combine(project,"tools","benchmarks","ffmpeg"),"ffmpeg.exe",SearchOption.AllDirectories).Single();Check(Hash(ffmpeg)==(string)manifest["ffmpeg_sha256"],"Independent decoder binary matches fixture provenance");}
            var evidence=new List<object>();
            foreach(var sample in cases){
                string name=(string)sample["name"],image=Path.Combine(fixtures,(string)sample["image"]),before=Hash(image),run=Path.Combine(work,name);
                Check(before==(string)sample["image_sha256"]&&new FileInfo(image).Length==Convert.ToInt64(sample["image_bytes"]),name+": independent input hash/size");
                int count=FragmentedMediaRecovery.Recover(image,run,CancellationToken.None,null),expected=Convert.ToInt32(sample["expected"]);
                var report=Json.Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Path.Combine(run,"fragmented-media.json")));
                Check(count==expected&&report.Files.Count==expected,name+": expected uniquely supported assignments, got "+count+" skips="+Json.Serialize(report.Skipped));
                Check(report.Status=="complete"&&Hash(image)==before,name+": source untouched and pass complete");
                Check(!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),name+": no partial output published");
                string reason=sample["reason"] as string;if(reason!=null)Check(report.Skipped.ContainsKey(reason),name+": exact rejected evidence condition");
                if(expected==0){Check(!Directory.GetFiles(Path.Combine(run,"fragmented-media")).Any(),name+": no invented complete media");evidence.Add(new{name=name,recovered=0,source_unchanged=true,skipped=report.Skipped});continue;}
                var result=report.Files.Single();string output=Path.Combine(run,result.Path.Replace('/',Path.DirectorySeparatorChar));
                Check(Hash(output)==(string)sample["expected_output_sha256"]&&result.Sha256==Hash(output),name+": all current bytes match independent expected assembly");
                Check(result.AudioSyntaxChecked&&result.AudioSearch=="sector_and_video_delta_syntax"&&result.Extents.Any(x=>x.Kind=="aac_syntax_chunk"),name+": exact syntax-search scope in provenance");
                Check(!result.PayloadAuthenticated&&!result.DeletionConfirmed&&result.Status=="iso_bmff_structural_candidate",name+": valid syntax never proves original audio or deletion");
                if(name=="aac-identical-duplicate")Check(result.Extents.Any(x=>x.Kind=="aac_syntax_chunk"&&x.EquivalentOffsets.Count>1),name+": identical sources retained without false content ambiguity");
                long logical=0;using(var source=File.OpenRead(image))using(var file=File.OpenRead(output))foreach(var extent in result.Extents){
                    Check(extent.LogicalOffset==logical&&extent.ImageOffset>=0&&extent.Length>0&&extent.ImageOffset<=source.Length-extent.Length,name+": full source-bounded logical mapping");
                    byte[] a=new byte[(int)extent.Length],b=new byte[(int)extent.Length];source.Position=extent.ImageOffset;Check(source.Read(a,0,a.Length)==a.Length&&file.Read(b,0,b.Length)==b.Length&&a.SequenceEqual(b),name+": actual image bytes copied without remux/synthesis");logical+=extent.Length;}
                Check(logical==result.Bytes,name+": exact output coverage");
                string video=null,audio=null;if(decode){video=Decode(ffmpeg,output,false);audio=Decode(ffmpeg,output,true);Check(video==(string)sample["expected_video_sha256"]&&audio==(string)sample["expected_audio_sha256"],name+": all independent decoded frames and PCM match truth");}
                evidence.Add(new{name=name,recovered=1,source_unchanged=true,sha256=result.Sha256,exact_original=sample["exact_original"],audio_search=result.AudioSearch,video_decoded_sha256=video,audio_decoded_sha256=audio});
            }
            File.WriteAllText(Path.Combine(work,"verification.json"),Json.Serialize(new{checks=checks,independent_decode=decode,cases=evidence}),new UTF8Encoding(false));
            Console.WriteLine("PASS FragmentedAacRecovery: "+checks+" checks; 16 real-FFmpeg corpus/adversarial cases, exact original/candidate bytes, AAC ambiguity and missing-byte negatives, source provenance. "+(decode?"Independent complete video+PCM comparisons included. ":"")+work);return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
