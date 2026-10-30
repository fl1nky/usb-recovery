using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using UsbRecovery;

namespace UsbRecovery
{
    // Test-only partial access to a seed stage. This does not decode a video or publish a candidate.
    public static partial class FragmentedMediaRecovery
    {
        public static bool[] AuditNearBoundaryRangeSeeds(string path)
        {
            const int unit=4096,length=3*unit;
            var logical=Enumerable.Repeat((byte)0xcc,length).ToArray();
            for(int n=0;n<1000;n++)logical[n]=0x22;
            var chunk=new Chunk{Codec="avc1"};
            var samples=new List<UnitSample>{
                new UnitSample{Logical=1000,Bytes=7185,Chunk=chunk},
                new UnitSample{Logical=8185,Bytes=2000,Chunk=chunk},
                new UnitSample{Logical=10185,Bytes=length-10185,Chunk=chunk}};
            foreach(var sample in samples){int at=(int)sample.Logical;uint nal=(uint)sample.Bytes-4;logical[at]=(byte)(nal>>24);logical[at+1]=(byte)(nal>>16);logical[at+2]=(byte)(nal>>8);logical[at+3]=(byte)nal;logical[at+4]=0x65;}
            long[] physical={16384,32768,49152};var image=new byte[65536];
            for(int cell=0;cell<3;cell++)Buffer.BlockCopy(logical,cell*unit,image,(int)physical[cell],unit);
            File.WriteAllBytes(path,image);
            byte[] before;using(var hash=SHA256.Create())before=hash.ComputeHash(image);
            HashSet<long>[] seeds;
            using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){
                var context=new Context{Input=input,Report=new Report(),Limits=new Limits(),Cancel=CancellationToken.None};
                var known=new List<UnitFixed>{new UnitFixed{Logical=0,Raw=logical.Take(1000).ToArray()}};
                var metadata=new List<Extent>{new Extent{LogicalOffset=0,ImageOffset=physical[0],Length=1000,Kind="test_metadata"}};
                seeds=RangeUnitSeeds(context,unit,length,known,samples,metadata,0);
            }
            bool unchanged;using(var hash=SHA256.Create())using(var source=File.OpenRead(path))unchanged=before.SequenceEqual(hash.ComputeHash(source));
            return new[]{
                samples[1].Logical%unit==unit-7&&samples[1].Bytes>7,
                seeds!=null,
                seeds!=null&&seeds.Length==3&&Enumerable.Range(0,3).All(cell=>seeds[cell].SetEquals(new[]{physical[cell]})),
                unchanged};
        }
    }
}

public static class MediaRangeAnchorAuditTests
{
    public static int Main()
    {
        string directory=Path.Combine(Path.GetTempPath(),"owned-media-range-audit-"+Guid.NewGuid().ToString("N")),image=Path.Combine(directory,"source.dd");
        Directory.CreateDirectory(directory);
        try{
            bool[] checks=FragmentedMediaRecovery.AuditNearBoundaryRangeSeeds(image);
            string[] labels={"control has only7 bytes before cell end for5-byte AVC header","near-boundary mandatory anchor is retained","all3 source-backed seed sets match physical truth","source bytes remain unchanged"};
            for(int n=0;n<checks.Length;n++){Console.WriteLine((checks[n]?"PASS: ":"FAIL: ")+labels[n]);if(!checks[n])return 1;}
            Console.WriteLine("Media range anchor independent audit: "+checks.Length+" checks; seed structure only, no decoding/authenticity claim.");return 0;
        }catch(Exception failure){Console.WriteLine(failure);return 2;}
        finally{if(File.Exists(image))File.Delete(image);Directory.Delete(directory);}
    }
}
