using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class HevcSampleValidatorTests
{
    public sealed class Packet{public string path,sha256;public int bytes;}
    public sealed class Movie{public string name,tag,hvcc,hvcc_sha256,original,original_sha256;public int width,height,decoded_frames;public List<Packet> samples;}
    public sealed class Manifest{public int schema;public string ffmpeg_sha256;public List<Movie> files;}
    static string fixtures;static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Sha(byte[] value){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(value)).Replace("-","").ToLowerInvariant();}
    static byte[] Read(string path){return File.ReadAllBytes(Path.Combine(fixtures,path.Replace('/',Path.DirectorySeparatorChar)));}
    static HevcSampleValidator.Configuration Config(Movie movie,string entry=null)
    {
        var bytes=Read(movie.hvcc);HevcSampleValidator.Configuration result;string code;bool valid=HevcSampleValidator.TryParseConfiguration(bytes,entry??movie.tag,movie.width,movie.height,out result,out code);Check(valid,"Independent libx265 config accepted "+movie.name+": "+code);Check(Sha(bytes)==movie.hvcc_sha256,"Config input unchanged");return result;
    }
    static void Bad(byte[] bytes,HevcSampleValidator.Configuration config,string reason)
    {
        HevcSampleValidator.SampleInfo info;string code;Check(!HevcSampleValidator.TryValidateSample(bytes,config,out info,out code)&&info==null&&!String.IsNullOrEmpty(code),reason);
    }
    static void BadConfig(byte[] bytes,Movie movie,string reason)
    {
        HevcSampleValidator.Configuration config;string code;Check(!HevcSampleValidator.TryParseConfiguration(bytes,movie.tag,movie.width,movie.height,out config,out code)&&config==null&&!String.IsNullOrEmpty(code),reason);
    }
    static List<byte[]> Nals(byte[] sample,int lengthBytes=4)
    {
        var result=new List<byte[]>();for(int at=0;at<sample.Length;){int bytes=0;for(int i=0;i<lengthBytes;i++)bytes=(bytes<<8)|sample[at++];result.Add(sample.Skip(at).Take(bytes).ToArray());at+=bytes;}return result;
    }
    static byte[] Pack(IEnumerable<byte[]> nals,int lengthBytes=4)
    {
        var result=new List<byte>();foreach(var nal in nals){for(int i=lengthBytes-1;i>=0;i--)result.Add((byte)(nal.Length>>(i*8)));result.AddRange(nal);}return result.ToArray();
    }
    static List<byte[]> Parameters(byte[] hvcc)
    {
        int at=23;var result=new List<byte[]>();for(int i=0;i<hvcc[22];i++){int kind=hvcc[at++]&63,count=hvcc[at]<<8|hvcc[at+1];at+=2;for(int j=0;j<count;j++){int bytes=hvcc[at]<<8|hvcc[at+1];at+=2;if(kind>=32&&kind<=34)result.Add(hvcc.Skip(at).Take(bytes).ToArray());at+=bytes;}}return result;
    }
    static void Originals(Manifest manifest)
    {
        foreach(var movie in manifest.files){Check(Sha(Read(movie.original))==movie.original_sha256&&movie.decoded_frames==12,"Genuine independently decoded original retained");var config=Config(movie);var kinds=new HashSet<int>();int maximumSlices=0;
            foreach(var sample in movie.samples){byte[] raw=Read(sample.path);Check(raw.Length==sample.bytes&&Sha(raw)==sample.sha256,"Independent packet SHA and length");HevcSampleValidator.SampleInfo info;string code;bool valid=HevcSampleValidator.TryValidateSample(raw,config,out info,out code);Check(valid,"Independent actual sample accepted "+movie.name+"/"+sample.path+": "+code);Check(!info.Decoded&&!info.PayloadAuthenticated&&!info.OwnershipConfirmed&&info.Status=="hevc_structural_sample_candidate","Syntax never becomes a decode/authentication claim");Check(info.ConfigurationFingerprint==config.Fingerprint&&info.Width==movie.width&&info.Height==movie.height,"Sample binds exact supplied parameter configuration/dimensions");Check(HevcSampleValidator.IsPossibleSampleStart(raw,0,raw.Length,config.NalLengthBytes),"Actual supported sample is indexable");Check(Sha(raw)==sample.sha256,"Sample input unchanged");kinds.Add(info.NalUnitType);maximumSlices=Math.Max(maximumSlices,info.VclNalUnits);}
            Check(kinds.Count>1,"Actual IDR and inter-picture samples exercised");if(movie.name=="two-slices-hvc1")Check(maximumSlices>=2,"Real encoder emitted multiple independently validated slices");
        }
    }
    static void Adversarial(Manifest manifest)
    {
        var movie=manifest.files.Single(item=>item.name=="main-hvc1");var config=Config(movie);byte[] original=Read(movie.samples[0].path),hvcc=Read(movie.hvcc);
        for(int size=0;size<hvcc.Length;size++)BadConfig(hvcc.Take(size).ToArray(),movie,"All hvcC prefix truncations rejected");
        byte[] changed=(byte[])hvcc.Clone();changed[21]=(byte)((changed[21]&252)|2);BadConfig(changed,movie,"Reserved three-byte NAL length rejected");
        changed=(byte[])hvcc.Clone();changed[13]&=15;BadConfig(changed,movie,"hvcC reserved bits checked");
        changed=(byte[])hvcc.Clone();changed[7]|=16;BadConfig(changed,movie,"hvcC cannot assert absent single-picture parameter constraint");
        changed=(byte[])hvcc.Clone();changed[6]|=64;BadConfig(changed,movie,"hvcC source constraints must agree with supplied parameter sets");
        changed=(byte[])hvcc.Clone();changed[23]&=127;BadConfig(changed,movie,"hvc1 incomplete parameter arrays rejected");
        BadConfig(hvcc.Concat(new byte[]{0}).ToArray(),movie,"Trailing config garbage rejected");BadConfig(new byte[HevcSampleValidator.MaximumConfigurationBytes+1],movie,"Config allocation bounded");
        HevcSampleValidator.Configuration ignored;string ignoredCode;Check(!HevcSampleValidator.TryParseConfiguration(hvcc,"hvc1",movie.width+1,movie.height,out ignored,out ignoredCode),"Foreign sample-entry dimensions rejected");
        var vcl=Nals(original).Where(nal=>((nal[0]>>1)&63)<32).ToList();Check(vcl.Count>0,"Real VCL available for corruption audit");byte[] picture=Pack(vcl);
        for(int length=0;length<Math.Min(picture.Length,80);length++)Bad(picture.Take(length).ToArray(),config,"NAL length prefix/truncation bounds");
        foreach(int index in new[]{0,1,2,3}){changed=(byte[])picture.Clone();changed[index]=255;Bad(changed,config,"Declared NAL length overflow");}
        changed=(byte[])picture.Clone();changed[4]|=128;Bad(changed,config,"Forbidden-zero bit rejected");
        changed=(byte[])picture.Clone();changed[5]|=8;Bad(changed,config,"Foreign layer rejected");
        changed=(byte[])picture.Clone();changed[5]&=248;Bad(changed,config,"Zero temporal-id-plus-one rejected");
        changed=(byte[])picture.Clone();changed[4]=(byte)(50<<1);Bad(changed,config,"Unknown/reserved NAL type rejected");
        changed=(byte[])picture.Clone();changed[6]&=127;Bad(changed,config,"Missing first-slice flag rejected");
        Bad(picture.Concat(picture).ToArray(),config,"Two pictures cannot masquerade as one sample");
        Bad(new byte[HevcSampleValidator.MaximumSampleBytes+1],config,"Sample allocation bounded");
        var escaped=vcl.Select(nal=>(byte[])nal.Clone()).ToList();Check(escaped[0].Length>20,"Independent picture has genuine CABAC bytes");escaped[0][escaped[0].Length-6]=0;escaped[0][escaped[0].Length-5]=0;escaped[0][escaped[0].Length-4]=1;Bad(Pack(escaped),config,"Unescaped embedded start code rejected");
        escaped=vcl.Select(nal=>(byte[])nal.Clone()).ToList();escaped[0][escaped[0].Length-6]=0;escaped[0][escaped[0].Length-5]=0;escaped[0][escaped[0].Length-4]=3;escaped[0][escaped[0].Length-3]=4;Bad(Pack(escaped),config,"Invalid emulation-prevention next byte rejected");
        var known=Parameters(hvcc);Bad(Pack(known.Concat(vcl)),config,"hvc1 inband parameter sets rejected");var hev1=Config(movie,"hev1");HevcSampleValidator.SampleInfo info;string code;Check(HevcSampleValidator.TryValidateSample(Pack(known.Concat(vcl)),hev1,out info,out code),"hev1 exact known parameter duplicates accepted");
        var foreign=manifest.files.Single(item=>item.name=="foreign-parameters-hev1");Bad(Pack(Parameters(Read(foreign.hvcc)).Concat(vcl)),hev1,"Same numeric IDs with foreign parameter bytes rejected");
        Bad(Pack(known),hev1,"Only parameter sets do not constitute a picture");
        for(int size=1;size<=2;size++){changed=(byte[])hvcc.Clone();changed[21]=(byte)((changed[21]&252)|(size-1));if(vcl.All(nal=>nal.Length<(1<<(size*8)))){HevcSampleValidator.Configuration shorter;Check(HevcSampleValidator.TryParseConfiguration(changed,"hvc1",movie.width,movie.height,out shorter,out code),"Alternative length-size config accepted");Check(HevcSampleValidator.TryValidateSample(Pack(vcl,size),shorter,out info,out code),"Exact shorter length-prefixed sample accepted");}}
        for(int at=-2;at<=picture.Length+2;at++)Check(!HevcSampleValidator.IsPossibleSampleStart(picture,at,Int32.MaxValue,4),"Index helper safely rejects impossible windows");
        Check(!HevcSampleValidator.IsPossibleSampleStart(null,0,0)&&!HevcSampleValidator.IsPossibleSampleStart(picture,0,picture.Length,3),"Index helper handles null/reserved length size");
        var tiny=manifest.files.Single(item=>item.name=="tiny-hvc1");byte[] shortConfig=Read(tiny.hvcc);shortConfig[21]=(byte)(shortConfig[21]&252);HevcSampleValidator.Configuration oneByte;
        Check(HevcSampleValidator.TryParseConfiguration(shortConfig,"hvc1",tiny.width,tiny.height,out oneByte,out code),"Actual tiny-picture config permits one-byte NAL prefixes");
        foreach(var packet in tiny.samples){var tinyNals=Nals(Read(packet.path));Check(tinyNals.All(nal=>nal.Length<256)&&HevcSampleValidator.TryValidateSample(Pack(tinyNals,1),oneByte,out info,out code),"Genuine independently decoded tiny picture works with one-byte prefixes");}
        byte[] eos={72,1,128},eob={74,1,128};Check(HevcSampleValidator.TryValidateSample(Pack(vcl.Concat(new[]{eos,eob})),config,out info,out code)&&info.EndOfSequence,"EOS then EOB retained as explicit structural end markers");
        Bad(Pack(vcl.Concat(new[]{eos,eos})),config,"Repeated EOS rejected");Bad(Pack(vcl.Concat(new[]{eob,eos})),config,"EOS after end-of-bitstream rejected");
        var opaque=vcl.Select(nal=>(byte[])nal.Clone()).ToList();int mutation=opaque[0].Length-5;while(mutation>20&&(opaque[0][mutation]<16||opaque[0][mutation-1]==0||opaque[0][mutation-2]==0))mutation--;Check(mutation>20,"Actual CABAC byte available for explicit validation-limit control");opaque[0][mutation]^=1;
        Check(HevcSampleValidator.TryValidateSample(Pack(opaque),config,out info,out code)&&!info.Decoded&&!info.PayloadAuthenticated,"Opaque CABAC corruption remains an unverified syntax candidate, never authenticated content");
        var random=new Random(862931);for(int i=0;i<300;i++){var noise=new byte[random.Next(0,256)];random.NextBytes(noise);HevcSampleValidator.TryValidateSample(noise,config,out info,out code);HevcSampleValidator.TryParseConfiguration(noise,"hev1",160,96,out ignored,out ignoredCode);checks++;}
    }
    public static int Main(string[] args)
    {
        try{fixtures=Path.GetFullPath(args[0]);var manifest=new JavaScriptSerializer().Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));Check(manifest.schema==1&&manifest.files.Count==7&&manifest.ffmpeg_sha256=="3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec","Independent official FFmpeg fixture provenance pinned");Originals(manifest);Adversarial(manifest);Console.WriteLine("PASS HevcSampleValidator: "+checks+" checks; independently encoded Main/Main10, real I/P/B, temporal layers, HRD/AUD/WPP and multislice samples, parameter identities, framing/bitstream bounds and rejected foreign sets. Structural candidates only; no CABAC decode/authenticity claim or devices.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
