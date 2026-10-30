using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class HevcRecoveryTests
{
    public sealed class Fixture{public string Name,Image,ImageSha256,Original,Sha256,DecodedSha256;public long Bytes;public int Expected,Chunks,Tracks;public bool Exact;}
    public sealed class Manifest{public int Schema;public string FfmpegSha256;public List<Fixture> Cases;}
    static int checks;static string fixtures,work,decoder;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(byte[] value){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(value)).Replace("-","").ToLowerInvariant();}
    static string HashFile(string path){using(var source=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(source)).Replace("-","").ToLowerInvariant();}
    static string Decode(string path)
    {
        using(var output=new MemoryStream())using(var process=new Process{StartInfo=new ProcessStartInfo(decoder,"-v error -xerror -nostdin -protocol_whitelist file,pipe -i \""+path+"\" -map 0:v -an -f framemd5 -"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
            process.Start();var error=process.StandardError.ReadToEndAsync();var copy=process.StandardOutput.BaseStream.CopyToAsync(output);if(!process.WaitForExit(30000)){try{process.Kill();}catch(InvalidOperationException){}throw new IOException("Independent HEVC decoder timeout");}copy.GetAwaiter().GetResult();if(process.ExitCode!=0||error.GetAwaiter().GetResult().Trim().Length!=0)throw new IOException("Independent HEVC decode rejected candidate");string frames=String.Join("\n",Encoding.UTF8.GetString(output.ToArray()).Split('\n').Select(line=>line.TrimEnd('\r')).Where(line=>line.Length>0&&!line.StartsWith("#",StringComparison.Ordinal)));return Hash(Encoding.UTF8.GetBytes(frames));
        }
    }
    static void Cases(Manifest manifest)
    {
        var json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
        foreach(var fixture in manifest.Cases){
            string image=Path.Combine(fixtures,fixture.Image),original=Path.Combine(fixtures,fixture.Original),before=HashFile(image),run=Path.Combine(work,fixture.Name);Check(before==fixture.ImageSha256&&HashFile(original)==fixture.Sha256,"Independent fixture source/original inventory: "+fixture.Name);
            var clock=Stopwatch.StartNew();int count=FragmentedMediaRecovery.Recover(image,run,CancellationToken.None,null);clock.Stop();var report=json.Deserialize<FragmentedMediaRecovery.Report>(File.ReadAllText(Path.Combine(run,"fragmented-media.json")));
            Check(count==fixture.Expected&&report.Files.Count==fixture.Expected,fixture.Name+": expected "+fixture.Expected+" actual "+count+" skip="+json.Serialize(report.Skipped));Check(report.Status=="complete"&&HashFile(image)==before,fixture.Name+": bounded scan completes without changing source");
            Check(report.VerifiedBytes<=FragmentedMediaRecovery.MaximumVerifiedBytes,fixture.Name+": explicit validation IO bounds");Check(!Directory.GetFiles(run,"*.partial",SearchOption.AllDirectories).Any(),fixture.Name+": no torn output publication");
            if(count==0){Check(!Directory.GetFiles(Path.Combine(run,"fragmented-media")).Any(),fixture.Name+": rejected foreign/ambiguous/corrupt input publishes nothing");continue;}
            var result=report.Files.Single();string file=Path.Combine(run,result.Path.Replace('/',Path.DirectorySeparatorChar));Check((HashFile(file)==fixture.Sha256)==fixture.Exact&&HashFile(file)==result.Sha256,fixture.Name+": exact/opaque overwrite truth checked independently");Check(result.Bytes==fixture.Bytes&&result.Tracks==fixture.Tracks&&result.Chunks==fixture.Chunks,fixture.Name+": complete original container, track and chunk counts");Check(result.Status=="iso_bmff_structural_candidate"&&!result.PayloadAuthenticated&&!result.DeletionConfirmed,fixture.Name+": structural HEVC is never presented as authenticated/deleted content");
            if(fixture.Exact&&decoder!=null)Check(Decode(file)==fixture.DecodedSha256,fixture.Name+": every independently decoded frame on all tracks equals original");
            long logical=0;using(var source=File.OpenRead(image))using(var output=File.OpenRead(file))foreach(var extent in result.Extents){Check(extent.LogicalOffset==logical&&extent.Length>0&&extent.ImageOffset>=0&&extent.ImageOffset<=source.Length-extent.Length,fixture.Name+": physical bounds and gap-free logical provenance");byte[] a=new byte[(int)extent.Length],b=new byte[(int)extent.Length];source.Position=extent.ImageOffset;output.Position=extent.LogicalOffset;source.Read(a,0,a.Length);output.Read(b,0,b.Length);Check(a.SequenceEqual(b)&&extent.EquivalentOffsets.Contains(extent.ImageOffset),fixture.Name+": every published byte comes from recorded source extent");logical+=extent.Length;}Check(logical==fixture.Bytes,fixture.Name+": no synthesized bytes");
            if(fixture.Name=="identical-chunk-duplicate")Check(result.Extents.Any(extent=>extent.Kind=="sample_chunk"&&extent.EquivalentOffsets.Count>=2),"Identical physical alternatives preserve provenance instead of false ambiguity");
            Console.WriteLine(fixture.Name+": "+(fixture.Exact?(decoder!=null?"exact original + all decoded frames":"exact original; decoding not run"):"unverified structural overwrite candidate")+", "+result.Chunks+" chunks, "+clock.ElapsedMilliseconds+" ms");
        }
    }
    public static int Main(string[] args)
    {
        try{string project=Path.GetFullPath(args[0]);fixtures=args.Length>1?Path.GetFullPath(args[1]):Path.Combine(project,".build","hevc-recovery-fixtures-current");decoder=args.Length>2?Path.GetFullPath(args[2]):null;work=Path.Combine(project,".build","hevc-engine-runs-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);var manifest=new JavaScriptSerializer().Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));Check(manifest.Schema==1&&manifest.Cases.Count==10&&manifest.FfmpegSha256=="3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec"&&(decoder==null||HashFile(decoder)==manifest.FfmpegSha256),"Ten independently encoded/scattered owned HEVC cases and pinned encoder/optional decoder");Cases(manifest);Console.WriteLine("PASS HevcRecovery: "+checks+" checks; complete actual hvc1/hev1/Main10/multislice and two-track HEVC originals reassembled; ambiguity/foreign config/NAL overwrite rejected, identical alternatives preserved, opaque CABAC overwrite remains unauthenticated. "+(decoder!=null?"External FFmpeg verifies every frame on all positive tracks. ":"No decoder invoked; byte/hash/map verification only. ")+"No devices.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
