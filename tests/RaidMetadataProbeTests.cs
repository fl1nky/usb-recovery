using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class RaidMetadataProbeTests
{
    public sealed class Fixture {public string name,sha256,origin;public long bytes;}
    public sealed class Manifest {public int schema;public string upstream_commit;public List<Fixture> files;}
    static string project,fixtures,work;static int checks,number;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static uint U32(byte[] b,int at){return (uint)b[at]|(uint)b[at+1]<<8|(uint)b[at+2]<<16|(uint)b[at+3]<<24;}
    static void Set32(byte[] b,int at,uint value){for(int i=0;i<4;i++)b[at+i]=(byte)(value>>(8*i));}
    static void Set64(byte[] b,int at,ulong value){for(int i=0;i<8;i++)b[at+i]=(byte)(value>>(8*i));}
    static void Checksum(byte[] b,int at=4096)
    {
        int bytes=256+checked((int)U32(b,at+220))*2;Set32(b,at+216,0);ulong sum=0;for(int n=0;n+4<=bytes;n+=4)sum+=U32(b,at+n);if(bytes%4==2)sum+=(uint)(b[at+bytes-2]|b[at+bytes-1]<<8);Set32(b,at+216,unchecked((uint)((sum&0xffffffffUL)+(sum>>32))));
    }
    static string Source(string relative){return Path.Combine(fixtures,relative.Replace('/',Path.DirectorySeparatorChar));}
    static string Copy(string source,string name=null){string path=Path.Combine(work,(++number).ToString("D3")+"-"+(name??Path.GetFileName(source)));File.Copy(source,path);return path;}
    static RaidMetadataProbe.Report Probe(params string[] paths){var before=paths.Where(File.Exists).Distinct().ToDictionary(p=>p,Hash);var result=RaidMetadataProbe.Probe(paths,CancellationToken.None);foreach(var pair in before)Check(Hash(pair.Key)==pair.Value,"probe leaves supplied image bytes unchanged");Check(result.MetadataBytesRead<=32768L*paths.Length,"only documented bounded metadata ranges read");return result;}
    static RaidMetadataProbe.Group Group(string directory)
    {
        string[] files=Directory.GetFiles(Source(directory),"*.bin").OrderByDescending(p=>p).ToArray();var report=Probe(files);Check(report.Groups.Count==1,"one array identity in coherent family");return report.Groups[0];
    }
    static void NoConfiguration(RaidMetadataProbe.Report report,string reason)
    {
        Check(report.Groups.All(g=>g.Configuration==null),"invalid/ambiguous metadata never yields a configuration");Check(report.Members.Any(m=>m.Code==reason||m.Reasons.Contains(reason))||report.Groups.Any(g=>g.Reasons.Contains(reason)),"specific rejection is retained: "+reason);
    }
    static string Mutate(string source,string name,Action<byte[]> action,bool checksum=true)
    {
        byte[] data=File.ReadAllBytes(source);action(data);if(checksum)Checksum(data);string path=Path.Combine(work,(++number)+"-"+name+".bin");File.WriteAllBytes(path,data);return path;
    }
    static void IndependentPublished()
    {
        var report=Probe(Directory.GetFiles(Source("upstream"),"*.bin"));Check(report.Images==23&&report.Members.Count==23,"all23 independent published MD component images inspected");Check(report.Members.All(m=>m.ChecksumValid&&m.SourceUnchanged),"all published MD additive checksums and immutable identities validate");Check(report.Groups.Count==9,"independent families grouped by UUID");
        var md90=report.Groups.Single(g=>g.Uuid=="7b53af09-6ee5-6ca9-6ae8-99361087e917");Check(md90.Format=="0.90"&&md90.Level=="1"&&md90.Status=="candidate"&&md90.Configuration.LogicalSize==5056L*1024,"published clean legacy geometry decoded exactly");Check(md90.Configuration.Members.Select(m=>m.Offset).All(v=>v==0),"legacy payload offsets start atzero");
        var mirror=report.Groups.Single(g=>g.Uuid=="914306a9-ed9f-19b3-c26b-9d1f5a37ddcf");Check(mirror.Format=="1.2"&&mirror.Events==14&&mirror.Status=="candidate"&&mirror.Configuration.LogicalSize==2L*1024*1024,"published v1.2 RAID1 UUID/event/logical size");Check(mirror.Configuration.Members.All(m=>m.Offset==1024*1024),"explicit v1 data offset retained");
        var parity=report.Groups.Single(g=>g.Uuid=="04285eaf-4cf2-4b78-dbf9-550e7430ac94");Check(parity.Level=="5"&&parity.Layout=="left-symmetric"&&parity.ChunkBytes==524288&&parity.Status=="candidate","published RAID5 scheme/block size recognized");Check(parity.Configuration.Members[2].Path.EndsWith("md-raid5-3.bin",StringComparison.Ordinal)&&parity.Members.Single(m=>m.Role==2).DeviceNumber==3,"role order is distinct from permanent device number and input order");
        foreach(var group in report.Groups){Check(group.MetadataOnly&&group.RequiresReview&&!group.DataIntegrityEstablished,"metadata candidates never authenticate array data");if(group.Configuration!=null)RaidImageBuilder.Validate(group.Configuration);}
        Check(report.Groups.Single(g=>g.Level=="0").Configuration==null,"published variable RAID0 zones not reduced to uniform striping");Check(report.Groups.Single(g=>g.Level=="6").Configuration==null,"published incomplete resync never treated as clean RAID6");Check(report.Groups.Single(g=>g.Level=="10").Configuration==null,"two-member/pending-sync RAID10 not promoted to supported four-member topology");Check(report.Groups.Single(g=>g.Level=="4").Configuration==null&&report.Groups.Single(g=>g.Level=="-1").Configuration==null,"unsupported RAID4/linear metadata remains inspectable only");
        // Payload recovery below is additional real-data evidence for the
        // published clean RAID1 and RAID5; expected bytes come from upstream
        // tests/md/test_md.py, not our metadata writer or array builder.
        foreach(var group in new[]{mirror,parity}){
            string output=Path.Combine(work,"assembled-"+group.Level);var built=RaidImageBuilder.Build(group.Configuration,output,CancellationToken.None,delegate(long done,long total){});Check(built.Bytes==group.Configuration.LogicalSize,"metadata suggested logical size honored by existing assembler");using(var file=File.OpenRead(built.ImagePath)){byte[] b=new byte[4096];for(int index=1;index<=512;index++){Check(file.Read(b,0,b.Length)==b.Length,"independent published block available");for(int at=0;at<b.Length;at+=2)if(b[at]!=(byte)index||b[at+1]!=(byte)(index>>8))throw new Exception("Independent upstream block content mismatch at"+index);checks++;}}
        }
    }
    static void DerivedGeometry()
    {
        foreach(string family in new[]{"version1-0","version1-1","legacy-big-endian","raid0-uniform-zone","raid6-synced-state","raid10-four-member"}){
            var group=Group(family);Check(group.Status=="candidate"&&group.Configuration!=null,"explicit derived format geometry is a reviewable candidate: "+family);Check(!group.DataIntegrityEstablished,"derived metadata does not prove data recovery");if(family=="version1-0")Check(group.Format=="1.0"&&group.Configuration.Members.All(m=>m.Offset==0),"v1.0 end-superblock/data geometry");if(family=="version1-1")Check(group.Format=="1.1"&&group.Configuration.Members.All(m=>m.Offset==8192),"v1.1 start-superblock/data geometry");if(family=="legacy-big-endian")Check(group.Format=="0.90-be"&&group.Events==18&&group.Uuid=="7b53af09-6ee5-6ca9-6ae8-99361087e917","legacy host-endian event/UUID conversion");if(family=="raid10-four-member")Check(group.Layout=="adjacent-pairs"&&group.RaidDisks==4,"only Linux near2/far1 maps to adjacent mirrors");
        }
    }
    static void NegativeMetadata()
    {
        string source=Source("upstream/md-raid1-1.bin");
        string corrupted=Mutate(source,"checksum",b=>b[4096+32]^=1,false);NoConfiguration(Probe(corrupted),"MD_CHECKSUM_INVALID");
        NoConfiguration(Probe(Mutate(source,"maxdev",b=>Set32(b,4096+220,UInt32.MaxValue),false)),"MD_ROLE_TABLE_BOUNDS");
        NoConfiguration(Probe(Mutate(source,"super-offset",b=>Set64(b,4096+144,0))),"MD_DATA_OR_SUPER_OFFSET_INVALID");
        NoConfiguration(Probe(Mutate(source,"offset-overflow",b=>Set64(b,4096+128,UInt64.MaxValue))),"MD_SECTOR_OVERFLOW");
        NoConfiguration(Probe(Mutate(source,"data-overrun",b=>Set64(b,4096+136,UInt64.MaxValue))),"MD_SECTOR_OVERFLOW");
        NoConfiguration(Probe(Mutate(source,"component-overrun",b=>Set64(b,4096+80,4097))),"MD_DATA_OR_SUPER_OFFSET_INVALID");
        NoConfiguration(Probe(Mutate(source,"overlap",b=>Set64(b,4096+128,0))),"MD_METADATA_DATA_OVERLAP");
        NoConfiguration(Probe(Mutate(source,"resync",b=>Set64(b,4096+208,0))),"MD_ARRAY_NOT_FULLY_SYNCED");
        foreach(uint feature in new[]{2U,4U,8U,16U,32U,64U,128U,256U,512U,1024U,2048U,0x80000000U})NoConfiguration(Probe(Mutate(source,"feature-"+feature,b=>Set32(b,4096+8,feature))),"MD_FEATURES_UNSUPPORTED");
        NoConfiguration(Probe(Mutate(source,"device",b=>Set32(b,4096+160,128))),"MD_DEVICE_NUMBER_INVALID");
        NoConfiguration(Probe(Mutate(source,"duplicate-role",b=>{b[4096+258]=0;b[4096+259]=0;})),"MD_ROLE_TABLE_INCONSISTENT");
        NoConfiguration(Probe(Mutate(Source("upstream/md-raid5-1.bin"),"layout",b=>Set32(b,4096+76,99))),"MD_PARITY_LAYOUT_UNSUPPORTED");
        NoConfiguration(Probe(Mutate(Source("upstream/md-raid5-1.bin"),"chunk",b=>Set32(b,4096+88,3))),"MD_CHUNK_UNSUPPORTED");
        NoConfiguration(Probe(Mutate(source,"reserved",b=>Set32(b,4096+12,1))),"MD_RESERVED_FIELDS_UNSUPPORTED");
        string first=Copy(source),second=Copy(Source("upstream/md-raid1-2.bin"));byte[] raw=File.ReadAllBytes(second);Set64(raw,4096+200,15);Checksum(raw);File.WriteAllBytes(second,raw);NoConfiguration(Probe(first,second),"MD_EVENT_COUNTER_MISMATCH");
        second=Mutate(Source("upstream/md-raid1-2.bin"),"changed-name",b=>b[4096+32]=(byte)'X');NoConfiguration(Probe(first,second),"MD_ARRAY_GEOMETRY_MISMATCH");
        second=Copy(source);NoConfiguration(Probe(first,second),"MD_DUPLICATE_DEVICE_OR_ROLE");NoConfiguration(Probe(first,first),"MD_DUPLICATE_IMAGE");
        byte[] two=File.ReadAllBytes(source),old=File.ReadAllBytes(Source("upstream/md-90-raid1-1.bin"));Buffer.BlockCopy(old,old.Length-65536,two,two.Length-65536,4096);string ambiguous=Path.Combine(work,"multiple-metadata.bin");File.WriteAllBytes(ambiguous,two);NoConfiguration(Probe(ambiguous),"MD_MULTIPLE_SUPERBLOCKS");
    }
    static void DegradedAndBoundaries()
    {
        var mirror=Probe(Source("upstream/md-raid1-2.bin")).Groups.Single();Check(mirror.Status=="candidate"&&mirror.MissingRoles.SequenceEqual(new[]{0})&&mirror.Configuration.Members[0].Missing,"one known mirror role may be missing without inventing an image");
        var five=Probe(Source("upstream/md-raid5-1.bin"),Source("upstream/md-raid5-3.bin")).Groups.Single();Check(five.Status=="candidate"&&five.MissingRoles.SequenceEqual(new[]{1}),"one missing clean RAID5 member represented explicitly");NoConfiguration(Probe(Source("upstream/md-raid5-1.bin")),"RAID_TOO_MANY_MISSING");
        // For RAID0 Linux uses per-device data_size, even if the generic
        // component-size field is nonzero. It must not hide unequal zones.
        var nonzeroSizes=new List<string>();foreach(string source in Directory.GetFiles(Source("upstream"),"md-raid0-*.bin"))nonzeroSizes.Add(Mutate(source,"raid0-nonzero-generic-size",b=>Set64(b,4096+80,2048)));
        NoConfiguration(Probe(nonzeroSizes.ToArray()),"MD_ARRAY_GEOMETRY_MISMATCH");
        string partial=Copy(Source("upstream/md-raid1-1.bin"),"image.partial");NoConfiguration(Probe(partial),"MD_COMPLETE_RAW_REQUIRED");string unaligned=Path.Combine(work,"unaligned.bin");File.WriteAllBytes(unaligned,new byte[513]);NoConfiguration(Probe(unaligned),"MD_RAW_LENGTH_INVALID");
        string empty=Path.Combine(work,"not-md.bin");File.WriteAllBytes(empty,new byte[131072]);var none=Probe(empty);Check(none.Groups.Count==0&&none.Members.Single().Status=="not_found","absence of MD metadata does not claim unsupported or recoverable RAID");
        bool cancelled=false;using(var token=new CancellationTokenSource()){token.Cancel();try{RaidMetadataProbe.Probe(new[]{empty},token.Token);}catch(OperationCanceledException){cancelled=true;}}Check(cancelled,"pre-cancel prevents source probing");
        bool limited=false;try{RaidMetadataProbe.Probe(Enumerable.Repeat(empty,RaidMetadataProbe.MaximumImages+1),CancellationToken.None);}catch(ArgumentException){limited=true;}Check(limited,"provided-image count is bounded");
        int updates=0;RaidMetadataProbe.Probe(new[]{empty},CancellationToken.None,(done,total)=>{Check(done==1&&total==1,"progress uses supplied-image count only");updates++;});Check(updates==1,"one progress publication per supplied image");
        foreach(string path in new[]{"//localhost/RecoveryAudit-NoSuchShare/member.bin",@"\\.\PhysicalDrive0","https://example.invalid/member.bin",empty+":stream"}){var report=RaidMetadataProbe.Probe(new[]{path},CancellationToken.None);NoConfiguration(report,"MD_LOCAL_RAW_REQUIRED");}
    }
    public static int Main(string[] args)
    {
        try{project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","raid-metadata-fixtures");work=Path.Combine(project,".build","raid-metadata-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);var manifest=new JavaScriptSerializer().Deserialize<Manifest>(File.ReadAllText(Path.Combine(fixtures,"manifest.json")));Check(manifest.schema==1&&manifest.upstream_commit=="d2da189112cae3a627f96d9de78341193eb6dc52"&&manifest.files.Count==40,"independent/derived fixture provenance is pinned and explicit");foreach(var file in manifest.files){string path=Source(file.name);Check(new FileInfo(path).Length==file.bytes&&Hash(path)==file.sha256,"prepared fixture matches SHA256 inventory");}IndependentPublished();DerivedGeometry();NegativeMetadata();DegradedAndBoundaries();Console.WriteLine("PASS RaidMetadataProbe: "+checks+" checks; published pinned MD0.90/1.2 images, explicitly derived1.0/1.1/bigendian/geometry, exact upstream RAID1/5 payloads, checksums/roles/events/offsets/ambiguity/bounds and read-only inputs. No mdadm, device or system-service invocation.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}