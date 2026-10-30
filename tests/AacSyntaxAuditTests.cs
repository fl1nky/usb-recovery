using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Security.Cryptography;
using UsbRecovery;

public static class AacSyntaxAuditTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    sealed class W
    {
        public readonly List<int> Bits=new List<int>();
        public W P(int value,int count){for(int at=count-1;at>=0;at--)Bits.Add((value>>at)&1);return this;}
        public byte[] Bytes(){var copy=new List<int>(Bits);while(copy.Count%8!=0)copy.Add(0);var bytes=new byte[copy.Count/8];for(int i=0;i<copy.Count;i++)bytes[i/8]|=(byte)(copy[i]<<(7-i%8));return bytes;}
    }
    static W Ics(W w,int maximum=0,int sequence=0,int reserved=0,int predict=0)
    {w.P(reserved,1).P(sequence,2).P(0,1).P(maximum,sequence==2?4:6);if(sequence==2)w.P(127,7);else w.P(predict,1);return w;}
    static W Mono(W w,int maximum=0,int sequence=0,int reserved=0,int predict=0,int gain=100)
    {w.P(0,3).P(0,4).P(gain,8);return Ics(w,maximum,sequence,reserved,predict);}
    static byte[] Silent(){return Mono(new W()).P(0,3).P(7,3).Bytes();}
    static bool Valid(byte[] bytes,int channels=1,int frequency=3){string code;return AacLcValidator.TryValidate(bytes,channels,frequency,out code);}
    static void No(byte[] bytes,string why,int channels=1,int frequency=3){string code;Check(!AacLcValidator.TryValidate(bytes,channels,frequency,out code),why+" accepted malformed syntax");Check(!String.IsNullOrEmpty(code),why+" has own failure code");}
    static byte[] Join(params byte[][] parts){return parts.SelectMany(x=>x).ToArray();}
    static byte[] Box(string type,byte[] body){int n=body.Length+8;return Join(new[]{(byte)(n>>24),(byte)(n>>16),(byte)(n>>8),(byte)n},Encoding.ASCII.GetBytes(type),body);}
    static byte[] Desc(int kind,byte[] body){Check(body.Length<128,"Independent short descriptor bounded");return Join(new[]{(byte)kind,(byte)body.Length},body);}
    static object Object(string name){return Activator.CreateInstance(typeof(FragmentedMediaRecovery).GetNestedType(name,BindingFlags.NonPublic),true);}
    static void Set(object value,string name,object content){value.GetType().GetField(name,BindingFlags.Public|BindingFlags.Instance).SetValue(value,content);}
    static string Rejected(Action operation){try{operation();return null;}catch(TargetInvocationException error){var field=error.InnerException.GetType().GetField("Code");return field==null?error.InnerException.GetType().Name:Convert.ToString(field.GetValue(error.InnerException));}}
    static string Config(byte[] asc,int decoderFlags=21)
    {
        var entry=new byte[28];entry[7]=1;entry[17]=1;entry[19]=16;entry[24]=187;entry[25]=128;
        var decoder=Join(new byte[]{64,(byte)decoderFlags},new byte[11],Desc(5,asc));
        byte[] raw=Box("mp4a",Join(entry,Box("esds",Join(new byte[4],Desc(3,Join(new byte[]{0,1,0},Desc(4,decoder),Desc(6,new byte[]{2})))))));
        var box=Object("Box");Set(box,"At",0);Set(box,"Bytes",raw.Length);Set(box,"Header",8);Set(box,"Type","mp4a");
        return Rejected(()=>typeof(FragmentedMediaRecovery).GetMethod("AudioConfig",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[]{raw,box,0}));
    }
    static void ConfigurationGuards()
    {
        byte[] lc=new byte[]{17,136};Check(Config(lc)==null,"Independent ordinary LC ASC accepted");
        Func<int,int,int,int,byte[]> asc=(a,f,c,flags)=>{int bits=a<<11|f<<7|c<<3|flags;return new[]{(byte)(bits>>8),(byte)bits};};
        foreach(int objectType in Enumerable.Range(0,32).Where(x=>x!=2))Check(Config(asc(objectType,3,1,0))!=null,"Unsupported ASC audio object type rejected");
        foreach(int frequency in new[]{13,14,15})Check(Config(asc(2,frequency,1,0))!=null,"Reserved or explicit ASC sampling frequency unsupported");
        foreach(int channels in Enumerable.Range(0,16).Where(x=>x!=1&&x!=2))Check(Config(asc(2,3,channels,0))!=null,"Unknown/PCE/multichannel ASC does not enter mono/stereo recovery");
        foreach(int flags in Enumerable.Range(1,7))Check(Config(asc(2,3,1,flags))!=null,"Unsupported 960-frame/core-coder/extension GASpecificConfig rejected");
        Check(Config(lc,20)!=null,"DecoderConfigDescriptor reserved bit must be one");
        byte[] noSbr=new W().P(0x2b7,11).P(5,5).P(0,1).Bytes();Check(Config(Join(lc,noSbr))==null,"Explicit absent-SBR sync extension accepted");
        byte[] sbr=new W().P(0x2b7,11).P(5,5).P(1,1).P(6,4).Bytes();Check(Config(Join(lc,sbr))!=null,"Implicit HE-AAC ASC must not enter LC-only recovery");
        Check(Config(Join(lc,new byte[]{255,255,255}))!=null,"Unknown trailing ASC syntax is not silently ignored");
    }
    static void CachedGeometry(string project)
    {
        string fixture=Path.Combine(project,"tests","fixtures","aac-lc");byte[] a=File.ReadAllBytes(Path.Combine(fixture,"aac-lc-96000-1ch-006.rawaac")),b=File.ReadAllBytes(Path.Combine(fixture,"aac-lc-96000-1ch-008.rawaac"));
        Check(a.Length==b.Length&&!a.SequenceEqual(b)&&Valid(a,1,0)&&Valid(b,1,0),"Independent equal-size foreign real AAC controls");
        string work=Path.Combine(project,".build","aac-syntax-audit-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);string image=Path.Combine(work,"provided.dd");var data=Enumerable.Repeat((byte)204,16384).ToArray();Array.Copy(a,0,data,512,a.Length);Array.Copy(b,0,data,12345,b.Length);File.WriteAllBytes(image,data);
        using(var input=File.OpenRead(image)){
            Func<object> context=()=>{var value=Object("Context");Set(value,"Input",input);Set(value,"Report",new FragmentedMediaRecovery.Report());Set(value,"Limits",new FragmentedMediaRecovery.Limits());return value;};
            object chunk=Object("Chunk");Set(chunk,"Logical",1L);Set(chunk,"Bytes",(long)a.Length);Set(chunk,"Samples",new[]{a.Length});Set(chunk,"Channels",1);Set(chunk,"AudioFrequency",0);Set(chunk,"Codec","mp4a");
            Array chunks=Array.CreateInstance(chunk.GetType(),1);chunks.SetValue(chunk,0);
            var method=typeof(FragmentedMediaRecovery).GetMethod("SyntaxAudio",BindingFlags.Static|BindingFlags.NonPublic);
            var first=new List<FragmentedMediaRecovery.Extent>{new FragmentedMediaRecovery.Extent{ImageOffset=0,LogicalOffset=0,Length=1}};
            var later=new List<FragmentedMediaRecovery.Extent>{new FragmentedMediaRecovery.Extent{ImageOffset=12344,LogicalOffset=0,Length=1}};
            object shared=context();Check(Rejected(()=>method.Invoke(null,new object[]{shared,first,chunks}))==null,"Initial geometry has only aligned AAC control");
            string fresh=Rejected(()=>method.Invoke(null,new object[]{context(),later,chunks}));Check(fresh=="chunk_payload_ambiguous","Fresh later geometry sees distinct aligned and affine real AAC choices");
            string reused=Rejected(()=>method.Invoke(null,new object[]{shared,later,chunks}));Check(reused==fresh,"Cached AAC discovery must include the current geometry scope and preserve ambiguity");
        }
    }
    static void Guards()
    {
        Check(Valid(Silent()),"Independent empty-spectrum mono control");
        No(Silent(),"mono cannot satisfy stereo configuration",2);
        foreach(int bad in new[]{-1,13,14,15,Int32.MaxValue})No(Silent(),"unknown frequency index",1,bad);
        foreach(int bad in new[]{0,3,7,Int32.MaxValue})No(Silent(),"unsupported channel count",bad);
        No(Mono(new W(),reserved:1).P(0,3).P(7,3).Bytes(),"reserved ICS bit");
        No(Mono(new W(),predict:1).P(0,3).P(7,3).Bytes(),"LC prediction forbidden");
        No(Mono(new W(),maximum:63).P(0,3).P(7,3).Bytes(),"scalefactor frequency-band overflow");
        No(Mono(new W(),maximum:1).P(0,4).P(0,5).P(0,3).P(7,3).Bytes(),"empty section run");
        No(Mono(new W(),maximum:1).P(0,4).P(2,5).P(0,3).P(7,3).Bytes(),"section runs beyond max_sfb");
        No(Mono(new W(),maximum:2).P(0,4).P(31,5).P(0,5).P(0,3).P(7,3).Bytes(),"escaped section run beyond max_sfb");
        No(Mono(new W(),maximum:1,sequence:2).P(0,4).P(2,3).P(0,3).P(7,3).Bytes(),"short section run overflow");
        No(Mono(new W(),maximum:1).P(12,4).P(1,5).P(0,3).P(7,3).Bytes(),"reserved codebook12");
        // Independent minimal codebook1: SF difference0='0', zero quadruple='0'.
        Check(Valid(Mono(new W(),maximum:1).P(1,4).P(1,5).P(0,1).P(0,3).P(0,1).P(7,3).Bytes()),"Complete minimal Huffman spectral tuple");
        No(Mono(new W(),maximum:1,gain:255).P(1,4).P(1,5).P(10,4).P(0,3).P(0,1).P(7,3).Bytes(),"Scalefactor+1 over global_gain255");
        // AAC book11 symbol(16,16): code00100, two sign bits, then escape unary.
        No(Mono(new W(),maximum:1).P(11,4).P(1,5).P(0,1).P(0,3).P(4,5).P(0,2).P(511,9).P(0,16).P(7,3).Bytes(),"spectral escape unary overflow");
        No(Mono(new W()).P(1,1).P(0,2).P(63,6).P(0,9).P(0,2).P(7,3).Bytes(),"pulse start band outside scalefactor table");
        No(Mono(new W(),sequence:2).P(1,1).P(0,20).P(7,3).Bytes(),"pulse forbidden in short windows");
        No(Mono(new W()).P(0,1).P(1,1).P(1,2).P(0,1).P(0,6).P(13,5).P(0,64).P(0,1).P(7,3).Bytes(),"LC TNS order13 rejected");
        No(Mono(new W()).P(0,2).P(1,1).P(7,3).Bytes(),"gain control unsupported");
        var stereo=new W().P(1,3).P(0,4).P(1,1);Ics(stereo);No(stereo.P(3,2).P(0,16).P(7,3).Bytes(),"reserved common-window stereo mask",2);
        byte[] silent=Silent();foreach(int length in Enumerable.Range(0,silent.Length))No(silent.Take(length).ToArray(),"every independent mono byte truncation");
        foreach(int kind in new[]{2,3,5}){var unsupported=(byte[])silent.Clone();unsupported[0]=(byte)((unsupported[0]&31)|(kind<<5));No(unsupported,"unsupported coupling/LFE/program configuration element");}
        byte[] otherGain=Mono(new W(),gain:101).P(0,3).P(7,3).Bytes();Check(Valid(otherGain)&&!otherGain.SequenceEqual(silent),"Different valid AAC bytes remain structurally possible; syntax supplies no payload identity");
        foreach(byte tail in new byte[]{0,1,224,255})No(silent.Concat(new[]{tail}).ToArray(),"trailing bytes outside raw_data_block");
        var padded=Mono(new W().P(6,3).P(0,4)).P(0,3).P(7,3).Bytes();Check(Valid(padded),"Zero-size fill with exact zero alignment control");
        var nonzero=(byte[])padded.Clone();nonzero[nonzero.Length-1]|=1;No(nonzero,"nonzero END alignment");
        // EXT_DYNAMIC_RANGE needs at least flags plus one dyn_rng byte.
        var shortDrc=new W().P(6,3).P(1,4).P(11,4).P(0,4);Mono(shortDrc).P(0,3).P(7,3);
        No(shortDrc.Bytes(),"dynamic-range payload truncated inside fill count");
    }
    static void Tables()
    {
        // Canonical numeric arrays independently extracted from pinned n8.0
        // aactab.c; upstream source SHA is recorded beside AacSyntaxTables.
        var type=typeof(AacLcValidator).Assembly.GetType("UsbRecovery.AacSyntaxTables");
        var fields=type.GetFields(BindingFlags.NonPublic|BindingFlags.Static).Where(x=>x.FieldType==typeof(int[])).OrderBy(x=>x.Name,StringComparer.Ordinal).ToArray();
        Check(fields.Length==36,"All primary numerical Huffman/SFB arrays present");
        string canonical=String.Join("",fields.Select(field=>field.Name+"="+String.Join(",",(int[])field.GetValue(null))+"\n"));
        using(var sha=SHA256.Create())Check(BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(canonical))).Replace("-","").ToLowerInvariant()=="a078285dada0375b38d76f58a61fdb05652a8057030bf231b34fbf9f508fcce3","Numerical tables match independent pinned primary-source extraction");
    }
    public static int Main(string[] args)
    {
        try{Tables();if(!args.Contains("--geometry")){if(!args.Contains("--syntax"))ConfigurationGuards();Guards();}if(args.Length>0)CachedGeometry(Path.GetFullPath(args[0]));Console.WriteLine("PASS AacSyntaxAudit: "+checks+" checks; independent bit envelopes, complete Huffman control, codebook/section/escape/pulse/TNS/channel/rate limits, exact END/ASC/fill framing and geometry-scoped foreign AAC ambiguity. Syntax only, no audio identity claim.");return 0;}
        catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
