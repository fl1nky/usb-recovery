using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class MediaFoundationValidationTests
{
    public sealed class Extent {public long ImageOffset,LogicalOffset,Length;}
    public sealed class Fixture {public string Name,Image,Original,Sha256;public int Expected;public bool Exact;public List<Extent> Extents;}
    public sealed class Manifest {public List<Fixture> Cases;}
    static string project,work,fixtures;static int checks;static readonly List<object> evidence=new List<object>();
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var file=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static MediaFoundationValidator.DecodeReport Decode(string path,MediaFoundationValidator.DecodeLimits limits=null,Action<MediaFoundationValidator.DecodeProgress> progress=null)
    {
        string before=File.Exists(path)?Hash(path):null;var report=MediaFoundationValidator.Validate(path,limits??new MediaFoundationValidator.DecodeLimits(),CancellationToken.None,progress);
        Check(!report.StrictIntegrityEstablished&&!report.OwnershipAuthenticated,"MF never authenticates recovered ownership or original integrity");Check(report.LimitsAreCooperative,"native-call hard limit remains isolated-worker responsibility");if(before!=null)Check(Hash(path)==before,"read-only MF leaves original bytes unchanged");evidence.Add(new{test=Path.GetFileName(path),report=report});return report;
    }
    static MediaFoundationValidator.DecodedStream Stream(MediaFoundationValidator.DecodeReport report,string kind){return report.Streams.Single(x=>x.Kind==kind);}
    static string Assemble(Fixture fixture,string name)
    {
        string path=Path.Combine(work,name+".mp4");using(var source=File.OpenRead(Path.Combine(fixtures,fixture.Image)))using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None))foreach(var extent in fixture.Extents.OrderBy(x=>x.LogicalOffset)){
            Check(output.Position==extent.LogicalOffset,"independent fixture extents have no logical gaps");source.Position=extent.ImageOffset;byte[] b=new byte[(int)extent.Length];Check(source.Read(b,0,b.Length)==b.Length,"independent fixture range is available");output.Write(b,0,b.Length);
        }return path;
    }
    static int Find(byte[] data,string text,int start=0){byte[] pattern=Encoding.ASCII.GetBytes(text);for(int at=start;at<=data.Length-pattern.Length;at++){bool match=true;for(int n=0;n<pattern.Length;n++)if(data[at+n]!=pattern[n]){match=false;break;}if(match)return at;}throw new Exception("Fixture marker missing: "+text);}
    static uint U32(byte[] b,int p){return (uint)b[p]<<24|(uint)b[p+1]<<16|(uint)b[p+2]<<8|b[p+3];}
    static string Mutate(string original,string name,Action<byte[]> change){byte[] raw=File.ReadAllBytes(original);change(raw);string path=Path.Combine(work,name+".mp4");File.WriteAllBytes(path,raw);return path;}
    static void PositiveAndCorruption(Manifest manifest)
    {
        string original=Path.Combine(fixtures,"phone-fast.mp4"),tail=Path.Combine(fixtures,"phone-tail.mp4");var good=Decode(original);Check(good.Status=="decoded_soft"&&good.Code=="MF_ALL_STREAMS_DECODED_SOFT","real AVC/AAC uses actual OS decoders");
        Check(good.SourceUnchanged&&good.AllStreamsEnded&&good.Streams.Count==2,"all compressed and decoded streams end explicitly");
        foreach(var stream in good.Streams){Check(stream.CompressedEndOfStream&&stream.EndOfStream,"EOS belongs to each individual stream");Check(stream.CompressedPacketsRead==stream.MetadataPackets&&stream.CompressedPacketsRead>0,"all declared source packets actually read");Check(stream.DecodedSamples>0&&stream.DecodedBytes>0&&stream.DecodedSha256.Length==64&&stream.CompressedSha256.Length==64,"full compressed/decode hashes recorded");Check(stream.UnknownCorruptionFlags>0,"zero/absent corruption attributes are explicitly unknown");}
        var video=Stream(good,"video");var audio=Stream(good,"audio");Check(video.VideoFrames==12&&video.Width==96&&video.Height==64,"all twelve real H.264 frames decoded");Check(audio.Channels==1&&audio.SampleRate==48000&&audio.BitsPerSample==16&&audio.PcmFrames>0,"audio output is actual PCM16 with recorded format");
        var repeat=Decode(original);Check(Stream(repeat,"video").DecodedSha256==video.DecodedSha256&&Stream(repeat,"audio").DecodedSha256==audio.DecodedSha256,"same OS decoder produces repeatable canonical hashes");
        var other=Decode(tail);Check(other.Status=="decoded_soft"&&Stream(other,"video").DecodedSha256==video.DecodedSha256&&Stream(other,"audio").DecodedSha256==audio.DecodedSha256,"moov position does not alter full decoded audio/video hashes");
        var exact=manifest.Cases.Single(x=>x.Name=="aac-fast-scattered-boxes");string assembled=Assemble(exact,"known-exact");Check(Hash(assembled)==exact.Sha256,"independent scattered original is byte exact");var exactReport=Decode(assembled);Check(exactReport.Status=="decoded_soft"&&Stream(exactReport,"video").DecodedSha256==video.DecodedSha256&&Stream(exactReport,"audio").DecodedSha256==audio.DecodedSha256,"reassembled byte-exact file decodes identically with native OS codecs");
        var unknown=manifest.Cases.Single(x=>x.Name=="aac-fast-audio-payload-unknown");string audioBad=Assemble(unknown,"aac-body-corrupt");Check(Hash(audioBad)!=unknown.Sha256,"corrupt AAC source is not the reference");var bad=Decode(audioBad);
        if(bad.Status=="decoded_soft")Check(Stream(bad,"audio").DecodedSha256!=audio.DecodedSha256,"MF can conceal corrupted AAC: full EOS is not integrity proof");else Check(bad.Status=="corrupt","AAC damage is decoder corruption or explicitly soft decoding");
        string nalBad=Mutate(original,"nal-length-corrupt",raw=>{int stco=Find(raw,"stco"),at=checked((int)U32(raw,stco+12));raw[at]=0x7f;raw[at+1]=0xff;raw[at+2]=0xff;raw[at+3]=0xff;});var nal=Decode(nalBad);Check(nal.Status=="corrupt"||nal.Status=="decoded_soft","damaged NAL is never strict-valid even with decoder concealment");
        string bodyBad=Mutate(original,"nal-body-corrupt",raw=>{int stco=Find(raw,"stco"),stsz=Find(raw,"stsz"),at=checked((int)U32(raw,stco+12)),fixedSize=checked((int)U32(raw,stsz+8)),size=fixedSize==0?checked((int)U32(raw,stsz+16)):fixedSize,end=at+size;bool damaged=false;while(at+5<end){int length=checked((int)U32(raw,at)),kind=raw[at+4]&31;if((kind==1||kind==5)&&length>64){Array.Clear(raw,at+4+length/2,Math.Min(32,length/2));damaged=true;break;}at+=4+length;}Check(damaged,"actual H.264 VCL payload chosen independently of codec parser");});var body=Decode(bodyBad);Check(body.Status=="corrupt"||body.Status=="decoded_soft","damaged VCL body is corrupt or explicitly soft");if(body.Status=="decoded_soft")Check(Stream(body,"video").DecodedSha256!=video.DecodedSha256,"native error concealment cannot turn altered VCL pixels into original-frame evidence");
        string wrong=Mutate(original,"wrong-range-assembly",raw=>{int stco=Find(raw,"stco"),at=checked((int)U32(raw,stco+12));byte[] first=new byte[64];Buffer.BlockCopy(raw,at+16,first,0,64);Buffer.BlockCopy(raw,at+160,raw,at+16,64);Buffer.BlockCopy(first,0,raw,at+160,64);});var misplaced=Decode(wrong);Check(misplaced.Status=="corrupt"||misplaced.Status=="decoded_soft","wrong byte-range assembly is corrupt or only soft-decodable");if(misplaced.Status=="decoded_soft")Check(Stream(misplaced,"video").CompressedSha256!=video.CompressedSha256,"decoded pixels cannot authenticate changed compressed metadata/range bytes");
    }
    static void LimitsAndIsolation()
    {
        string original=Path.Combine(fixtures,"phone-fast.mp4");
        var input=Decode(original,new MediaFoundationValidator.DecodeLimits{MaxInputBytes=64});Check(input.Status=="limited"&&input.Code=="MF_INPUT_BYTES_LIMIT"&&!input.AllStreamsEnded,"input cap blocks decoder startup");
        var pixels=Decode(original,new MediaFoundationValidator.DecodeLimits{MaxPixels=1});Check(pixels.Status=="limited"&&pixels.Code=="MF_PIXEL_LIMIT"&&!pixels.AllStreamsEnded,"huge declared/output dimensions are bounded before decoding");
        var output=Decode(original,new MediaFoundationValidator.DecodeLimits{MaxDecodedBytes=16});Check(output.Status=="limited"&&output.Code=="MF_OUTPUT_BYTES_LIMIT"&&!output.AllStreamsEnded,"decoded output budget is not successful EOS");
        var packets=Decode(original,new MediaFoundationValidator.DecodeLimits{MaxDecodedSamples=1});Check(packets.Status=="limited"&&!packets.AllStreamsEnded,"packet/sample work limit enforced");
        var frames=Decode(original,new MediaFoundationValidator.DecodeLimits{MaxVideoFrames=1});Check(frames.Status=="limited"&&frames.Code=="MF_FRAME_COUNT_LIMIT"&&!frames.AllStreamsEnded,"video frame budget enforced");
        var timed=Decode(original,new MediaFoundationValidator.DecodeLimits{MaxMilliseconds=5},p=>{if(p.Phase=="preflight")Thread.Sleep(20);});Check(timed.Status=="limited"&&timed.Code=="MF_TIME_LIMIT"&&!timed.AllStreamsEnded,"cooperative deadline never creates full decode success");
        var cancellation=new CancellationTokenSource();cancellation.Cancel();var cancelled=MediaFoundationValidator.Validate(original,new MediaFoundationValidator.DecodeLimits(),cancellation.Token);Check(cancelled.Status=="cancelled"&&cancelled.Streams.Count==0,"pre-cancel does not start native decoders");
        cancellation=new CancellationTokenSource();var during=MediaFoundationValidator.Validate(original,new MediaFoundationValidator.DecodeLimits(),cancellation.Token,p=>{if(p.Phase=="decode")cancellation.Cancel();});Check(during.Status=="cancelled"&&!during.AllStreamsEnded,"cancellation between actual decode calls is not successful EOS");
        foreach(string path in new[]{"https://example.invalid/movie.mp4",@"\\server\share\movie.mp4",@"\\.\PhysicalDrive0","file:///C:/movie.mp4",original+":stream"}){var denied=Decode(path);Check(denied.Status=="unsupported"&&denied.Code=="MF_LOCAL_FILE_REQUIRED","network/device/alternate streams rejected before source resolver");}
        string playlist=Path.Combine(work,"playlist.m3u");File.WriteAllText(playlist,"#EXTM3U\nhttps://example.invalid/movie.mp4\n");var list=Decode(playlist);Check(list.Status=="unsupported"&&list.Code=="MF_CONTAINER_EXTENSION_UNSUPPORTED","playlists never reach the OS source resolver");
        string external=Mutate(original,"external-data-reference",raw=>{int at=Find(raw,"url ");raw[at+7]=0;});var reference=Decode(external);Check(reference.Status=="unsupported"&&reference.Code=="MF_EXTERNAL_DATA_REFERENCE","external dref is rejected before native parsing");
        string unknown=Mutate(original,"unknown-codec",raw=>{int at=Find(raw,"stsd")+16;Buffer.BlockCopy(Encoding.ASCII.GetBytes("zzzz"),0,raw,at,4);});var codec=Decode(unknown);Check(codec.Status=="unsupported"||codec.Status=="corrupt","missing/unknown codec never becomes decoded success");
        MediaFoundationValidator.DecodeReport sta=null;var thread=new Thread(()=>sta=MediaFoundationValidator.Validate(original,new MediaFoundationValidator.DecodeLimits(),CancellationToken.None));thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();Check(sta.Status=="unsupported"&&sta.Code=="MF_MTA_WORKER_REQUIRED","UI STA thread cannot accidentally run the decoder core");
    }
    [MTAThread]public static int Main(string[] args)
    {
        try{project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","fragmented-media-audio-tests");work=Path.Combine(project,".build","mf-tests-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(work);var manifest=new JavaScriptSerializer().Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));PositiveAndCorruption(manifest);LimitsAndIsolation();
            File.WriteAllText(Path.Combine(work,"decode-evidence.json"),new JavaScriptSerializer{MaxJsonLength=32*1024*1024}.Serialize(new{checks=checks,scope="Actual Windows Media Foundation OS decoding on owned synthetic reference movies; soft decoding only, no ownership/integrity authentication",cases=evidence}));Console.WriteLine("PASS MediaFoundationValidation: "+checks+" checks; native software RGB32/PCM, full per-stream compressed/decode EOS, real corruption concealment negatives, hashes, local-only source preflight and cooperative worker limits. No hard-isolation or integrity guarantee claimed.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
