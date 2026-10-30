using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class AacLcValidatorTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Sha(byte[] bytes){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
    static bool Valid(byte[] bytes,int channels,int frequency){string code;return AacLcValidator.TryValidate(bytes,channels,frequency,out code);}
    sealed class Writer
    {
        readonly List<int> bits=new List<int>();
        public Writer Put(int value,int count){for(int i=count-1;i>=0;i--)bits.Add((value>>i)&1);return this;}
        public byte[] Bytes(){while(bits.Count%8!=0)bits.Add(0);var result=new byte[bits.Count/8];for(int i=0;i<bits.Count;i++)result[i/8]|=(byte)(bits[i]<<(7-i%8));return result;}
    }
    static byte[] Silent(bool shortWindow=false,int reserved=0,int predictor=0,int section=-1,int drc=0)
    {
        var w=new Writer().Put(0,3).Put(0,4).Put(100,8).Put(reserved,1).Put(shortWindow?2:0,2).Put(0,1).Put(section<0?0:1,shortWindow?4:6);
        if(shortWindow)w.Put(127,7);else w.Put(predictor,1);
        if(section>=0)w.Put(section,4).Put(1,shortWindow?3:5);
        w.Put(0,1).Put(0,1).Put(0,1);
        if(drc==1||drc==2)w.Put(6,3).Put(drc==1?2:1,4).Put(11,4).Put(0,4).Put(0,8);
        if(drc==3)w.Put(6,3).Put(9,4).Put(11,4).Put(1,1).Put(0,4).Put(0,4).Put(1,1).Put(0,7).Put(0,1).Put(1,1).Put(1,4).Put(0,4).Put(16,8).Put(32,8).Put(1,1).Put(64,7).Put(0,1).Put(0,8).Put(0,8);
        return w.Put(7,3).Bytes();
    }
    static void SyntaxGuards()
    {
        Check(Valid(Silent(),1,3),"Independently written empty-spectrum mono block is syntactically complete");
        Check(Valid(Silent(true),1,3),"Short-window grouping with empty spectrum is bounded and complete");
        Check(!Valid(Silent(false,1),1,3),"Reserved ICS bit rejected");
        Check(!Valid(Silent(false,0,1),1,3),"AAC-LC prediction forbidden");
        Check(!Valid(Silent(false,0,0,12),1,3),"Reserved spectral codebook rejected");
        Check(!Valid(new byte[]{224,0},1,3),"END without channel data rejected");
        Check(!Valid(null,1,3)&&!Valid(Silent(),3,3)&&!Valid(Silent(),1,13),"Unknown channels/frequency/null rejected");
        Check(!Valid(new byte[AacLcValidator.MaximumSampleBytes+1],1,3),"Sample work limit enforced");
        Check(Valid(Silent(false,0,0,-1,1),1,3),"Bounded single-band dynamic-range extension parsed");
        Check(!Valid(Silent(false,0,0,-1,2),1,3),"Declared FIL size cannot borrow DRC bytes from following elements");
        Check(Valid(Silent(false,0,0,-1,3),1,3),"DRC tags, exclusions, two band tops and program level parsed within declared bytes");
        foreach(byte fill in new byte[]{0,165,204,255})foreach(int length in new[]{2,3,8,32,128})Check(!Valid(Enumerable.Repeat(fill,length).ToArray(),2,3),"Filler cannot become a complete stereo sample");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),folder=args.Length>1?Path.GetFullPath(args[1]):Path.Combine(project,"tests","fixtures","aac-lc");
            SyntaxGuards();var json=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};var manifest=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(folder,"manifest.json")));
            var cases=((IEnumerable)manifest["cases"]).Cast<Dictionary<string,object>>().ToArray();Check(cases.Length>=100,"Independent real-encoder fixture corpus present");var formats=new HashSet<string>();
            foreach(Dictionary<string,object> row in cases){
                string name=(string)row["path"];int channels=Convert.ToInt32(row["channels"]),frequency=Convert.ToInt32(row["frequency_index"]);byte[] bytes=File.ReadAllBytes(Path.Combine(folder,name));formats.Add(channels+":"+frequency);
                Check(bytes.Length==Convert.ToInt32(row["bytes"])&&Sha(bytes)==(string)row["sha256"],name+": exact independently generated packet");
                string code;Check(AacLcValidator.TryValidate(bytes,channels,frequency,out code),name+": full channel/section/scalefactor/spectral walk, code="+code);
                Check(!Valid(bytes.Take(bytes.Length-1).ToArray(),channels,frequency),name+": truncation is never silently padded");
                Check(!Valid(bytes.Concat(new byte[]{0}).ToArray(),channels,frequency),name+": trailing bytes do not hide inside padding");
                var end=(byte[])bytes.Clone();end[0]=(byte)((end[0]&31)|224);Check(!Valid(end,channels,frequency),name+": false leading END cannot hide remaining bytes");
            }
            Check(formats.Count==26,"All thirteen AAC frequency indexes and mono/stereo configurations exercised");
            Console.WriteLine("PASS AacLcValidator: "+checks+" checks; independent FFmpeg LC mono/stereo at all13frequencies, exact packet framing, reserved fields, truncation and opaque filler. No PCM/authenticity claim.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
