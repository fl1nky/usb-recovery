using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// No controls/forms, physical devices, services or privileged operations.
public static class Raid10LayoutTests
{
    public sealed class InputFile { public string name {get;set;} public long offset {get;set;} public long bytes {get;set;} public string sha256 {get;set;} }
    public sealed class Case { public string name {get;set;} public string layout {get;set;} public int members {get;set;} public int copies {get;set;} public long chunk {get;set;} public long component {get;set;} public long bytes {get;set;} public string sha256 {get;set;} public List<InputFile> files {get;set;} }
    public sealed class Manifest { public int schema {get;set;} public string origin {get;set;} public List<Case> cases {get;set;} }
    static string fixtures, work; static int checks, number, assemblies;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Digest(byte[] bytes){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
    static string Digest(string path){return Digest(File.ReadAllBytes(path));}
    static RaidConfiguration Clone(RaidConfiguration config){var json=new JavaScriptSerializer();return json.Deserialize<RaidConfiguration>(json.Serialize(config));}
    static string Output(){return Path.Combine(work,"result-"+(++number));}
    static void Fails(Action action,string code,string output=null)
    {
        string actual=null;try{action();}catch(RaidRecoveryException e){actual=e.Code;}
        Check(actual==code,"controlled rejection "+code+", observed "+actual);
        if(output!=null)Check(!File.Exists(Path.Combine(output,"raid.dd")),"failed assembly never publishes an image");
    }
    static void Build(RaidConfiguration config,byte[] expected)
    {
        long previous=-1;var result=RaidImageBuilder.Build(config,Output(),CancellationToken.None,(done,total)=>{Check(done>=previous&&done<=total&&total==expected.LongLength,"monotonic measured byte progress");previous=done;});
        Check(result.Bytes==expected.LongLength&&result.Sha256==Digest(expected)&&Digest(result.ImagePath)==result.Sha256,"all reconstructed bytes match independent inverse oracle");
        Check(result.Degraded==config.Members.Any(m=>m.Missing),"degraded state follows explicit missing members");
        Check(File.ReadAllText(result.ReportPath).Contains("\"component_bytes\":"+config.ComponentSize),"known data boundary is recorded");
        assemblies++;
    }
    static int[] CopyMasks(Case entry)
    {
        // Kernel inverse mapping, independent from product forward locations.
        int near=entry.layout.Contains("near")?entry.copies:1,far=near==1?entry.copies:1;
        long stripe=entry.component/entry.chunk/far;var result=new int[entry.bytes/entry.chunk];
        for(int disk=0;disk<entry.members;disk++)for(long physical=0;physical<entry.component/entry.chunk;physical++){
            long copy, row;
            if(entry.layout.Contains("offset")){copy=physical%far;row=physical/far;}
            else{copy=physical/stripe;row=physical%stripe;}
            int device=(int)((disk-copy*near)%entry.members+entry.members)%entry.members;
            long logical=(row*entry.members+device)/near;
            if(copy<far&&logical<result.Length)result[logical]|=1<<disk;
        }
        foreach(int mask in result)Check(Enumerable.Range(0,entry.members).Count(d=>(mask&(1<<d))!=0)==entry.copies,"inverse oracle has every copy on distinct devices");
        return result;
    }
    static uint U32(byte[] bytes,int at){return BitConverter.ToUInt32(bytes,at);}
    static void Set32(byte[] bytes,int at,uint value){Buffer.BlockCopy(BitConverter.GetBytes(value),0,bytes,at,4);}
    static void MetadataRejections(Case entry)
    {
        string source=Path.Combine(fixtures,entry.name,entry.files[0].name);
        foreach(uint layout in new[]{0x202U,0x20201U,0x40201U,0x104U,0x101U}){
            byte[] bytes=File.ReadAllBytes(source);Set32(bytes,4096+76,layout);Set32(bytes,4096+216,0);
            int length=256+(int)U32(bytes,4096+220)*2;ulong total=0;for(int i=0;i+4<=length;i+=4)total+=U32(bytes,4096+i);if(length%4==2)total+=BitConverter.ToUInt16(bytes,4096+length-2);
            Set32(bytes,4096+216,(uint)((total&0xffffffffUL)+(total>>32)));
            string path=Path.Combine(work,"unsupported-"+layout+".bin");File.WriteAllBytes(path,bytes);
            var report=RaidMetadataProbe.Probe(new[]{path},CancellationToken.None);
            Check(report.Members.Single().ChecksumValid&&report.Groups.All(g=>g.Configuration==null)&&report.Members.Single().Reasons.Contains("MD_RAID10_LAYOUT_UNSUPPORTED"),"checksum-correct mixed/far-set/unknown-copy layout remains unsupported");
        }
    }
    static void Exercise(Case entry)
    {
        string directory=Path.Combine(fixtures,entry.name);byte[] expected=File.ReadAllBytes(Path.Combine(directory,"expected.bin"));
        Check(expected.LongLength==entry.bytes&&Digest(expected)==entry.sha256,"fixture independent payload hash");
        string[] paths=entry.files.Select(f=>Path.Combine(directory,f.name)).ToArray();
        for(int i=0;i<paths.Length;i++)Check(new FileInfo(paths[i]).Length==entry.files[i].bytes&&Digest(paths[i])==entry.files[i].sha256,"derived input byte inventory");
        var report=RaidMetadataProbe.Probe(paths.Reverse(),CancellationToken.None);Check(report.Groups.Count==1,"single derived array identity");var group=report.Groups.Single();
        Check(group.Status=="candidate"&&group.Configuration!=null,"clean supported MD RAID10 metadata produces reviewable parameters: "+entry.name+" "+String.Join(",",group.Reasons));
        Check(!group.DataIntegrityEstablished&&group.MetadataOnly&&group.RequiresReview,"candidate never authenticates data");
        Check(group.Configuration.ComponentSize==entry.component&&group.Configuration.LogicalSize==entry.bytes,"precise component boundary and floor-divided capacity");
        Check(group.Configuration.Members.Select(m=>m.Path).SequenceEqual(paths),"roles determine image order");
        var config=group.Configuration;config.ExpectedSha256=entry.sha256;int[] coverage=CopyMasks(entry);
        for(int missing=0;missing<(1<<entry.members);missing++){
            var current=Clone(config);for(int disk=0;disk<entry.members;disk++)current.Members[disk].Missing=(missing&(1<<disk))!=0;
            bool possible=coverage.All(mask=>(mask&~missing)!=0);
            if(possible)Build(current,expected);
            else Fails(()=>RaidImageBuilder.Validate(current),"RAID10_COPY_SET_MISSING");
        }
        var prefix=Clone(config);prefix.LogicalSize-=37;prefix.ExpectedSha256=Digest(expected.Take((int)prefix.LogicalSize).ToArray());Build(prefix,expected.Take((int)prefix.LogicalSize).ToArray());
        var automatic=Clone(config);automatic.LogicalSize=0;Build(automatic,expected);
        var firstBlock=Clone(config);firstBlock.LogicalSize=entry.chunk-37;firstBlock.ExpectedSha256=Digest(expected.Take((int)firstBlock.LogicalSize).ToArray());
        for(int disk=1;disk<entry.members;disk++)firstBlock.Members[disk].Missing=true;
        Build(firstBlock,expected.Take((int)firstBlock.LogicalSize).ToArray());
        if(entry.layout.Contains("far")){
            var unknown=Clone(config);unknown.ComponentSize=0;string outdir=Output();Fails(()=>RaidImageBuilder.Build(unknown,outdir,CancellationToken.None,null),"RAID_COMPONENT_SIZE_REQUIRED",outdir);
        }
        var bad=Clone(config);bad.ComponentSize=entry.component+1;Fails(()=>RaidImageBuilder.Validate(bad),"RAID_COMPONENT_SIZE_INVALID");
        bad=Clone(config);bad.ComponentSize=entry.component*3;string bounds=Output();Fails(()=>RaidImageBuilder.Build(bad,bounds,CancellationToken.None,null),"RAID_COMPONENT_SIZE_INVALID",bounds);

        // Corrupt a non-primary copy of the first logical block. The whole
        // image must remain unpublished, even when an expected hash exists.
        string corrupt=Path.Combine(work,"corrupt-"+entry.name);Directory.CreateDirectory(corrupt);var mismatch=Clone(config);
        for(int disk=0;disk<paths.Length;disk++){string copy=Path.Combine(corrupt,entry.files[disk].name);File.Copy(paths[disk],copy);mismatch.Members[disk].Path=copy;}
        int victim=1;long stride=entry.layout.Contains("far")?entry.component/entry.chunk/entry.copies*entry.chunk:entry.layout.Contains("offset")?entry.chunk:0;
        using(var file=File.Open(mismatch.Members[victim].Path,FileMode.Open,FileAccess.ReadWrite)){file.Position=entry.files[victim].offset+stride+7;int value=file.ReadByte();file.Position--;file.WriteByte((byte)(value^0xa5));}
        string failed=Output();Fails(()=>RaidImageBuilder.Build(mismatch,failed,CancellationToken.None,null),"RAID_MIRROR_MISMATCH",failed);

        string interrupted=Output();using(var stop=new CancellationTokenSource()){
            bool cancelled=false;try{RaidImageBuilder.Build(config,interrupted,stop.Token,(done,total)=>{if(done>0)stop.Cancel();});}catch(OperationCanceledException){cancelled=true;}
            Check(cancelled&&!File.Exists(Path.Combine(interrupted,"raid.dd")),"cancellation retains unpublished partial");
        }
        var saved=RaidImageBuilder.ReadResumeConfiguration(interrupted);Check(saved.ComponentSize==entry.component&&saved.Layout==config.Layout,"checkpoint keeps full component boundary");
        var changed=Clone(saved);changed.ComponentSize+=entry.chunk;Fails(()=>RaidImageBuilder.Resume(changed,interrupted,CancellationToken.None,null),"RAID_RESUME_CONFIG_CHANGED",interrupted);
        var resumed=RaidImageBuilder.Resume(saved,interrupted,CancellationToken.None,null);Check(resumed.ResumedBytes>0&&Digest(resumed.ImagePath)==entry.sha256,"resume checks retained prefix and reconstructs exact bytes");
        for(int i=0;i<paths.Length;i++)Check(Digest(paths[i])==entry.files[i].sha256,"source component unchanged after all builds");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]);fixtures=args.Length>1?Path.GetFullPath(args[1]):Path.Combine(project,".build","raid10-layout-fixtures");work=Path.Combine(project,".build","raid10-layout-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            string manifestText=File.ReadAllText(Path.Combine(fixtures,"manifest.json"));
            Check(manifestText==File.ReadAllText(Path.Combine(project,"tests","fixtures","raid10","manifest.json")),"all derived fixture hashes match pinned source inventory");
            var manifest=new JavaScriptSerializer().Deserialize<Manifest>(manifestText);
            Check(manifest.schema==1&&manifest.origin=="owned_derived_inverse_mapping_not_native"&&manifest.cases.Count==12,"explicit derived evidence boundary");
            foreach(var entry in manifest.cases)Exercise(entry);
            MetadataRejections(manifest.cases[0]);
            string ui=File.ReadAllText(Path.Combine(project,"src","Recovery","UI","StorageRecoveryPanel.cs"));
            Check(ui.Contains("ComponentSize=componentSize")&&ui.Contains("raidComponentSize.Text=config.ComponentSize.ToString")&&ui.Contains("raid-component-size"),"headless source check: visible component boundary survives metadata and resume UI paths");
            Console.WriteLine("PASS Raid10Layout: "+checks+" checks; "+assemblies+" exact derived assemblies; 12 inverse-mapped near2/3 far2/3 offset2/3 cases, odd members, all missing masks, mirror conflicts, bounds, prefix/resume, unchanged sources; no native device or GUI run");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
