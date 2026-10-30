using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using UsbRecovery;

// Independent adversarial audit. Inputs are copies of pinned public fixtures;
// no production metadata writer or physical device is used.
public static class RaidMetadataAuditTests
{
    static string project,fixtures,work;static int checks,sequence;
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool CreateHardLink(string alias,string original,IntPtr reserved);
    static void Check(bool value,string reason){checks++;if(!value)throw new Exception(reason);}
    static uint Word(byte[] bytes,int at){return (uint)bytes[at]|(uint)bytes[at+1]<<8|(uint)bytes[at+2]<<16|(uint)bytes[at+3]<<24;}
    static void Put(byte[] bytes,int at,uint value){for(int n=0;n<4;n++)bytes[at+n]=(byte)(value>>(n*8));}
    static void Wide(byte[] bytes,int at,ulong value){for(int n=0;n<8;n++)bytes[at+n]=(byte)(value>>(n*8));}
    static string Hash(string path){using(var stream=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","");}
    static string Source(string relative){return Path.Combine(fixtures,relative.Replace('/',Path.DirectorySeparatorChar));}
    static string Edit(string relative,Action<byte[],int> mutation,bool legacy=false)
    {
        byte[] bytes=File.ReadAllBytes(Source(relative));int offset=legacy?(bytes.Length/65536-1)*65536:relative.StartsWith("version1-0/")?((bytes.Length/512-16)&~7)*512:4096;
        mutation(bytes,offset);int field=legacy?152:216;int length=legacy?4096:checked(256+(int)Word(bytes,offset+220)*2);
        Put(bytes,offset+field,0);ulong sum=0;for(int n=0;n+4<=length;n+=4)sum+=Word(bytes,offset+n);if(length%4==2)sum+=(uint)(bytes[offset+length-2]|bytes[offset+length-1]<<8);
        Put(bytes,offset+field,unchecked((uint)((sum&0xffffffffUL)+(sum>>32))));string output=Path.Combine(work,"case-"+(++sequence)+".raw");File.WriteAllBytes(output,bytes);return output;
    }
    static RaidMetadataProbe.Report Probe(params string[] paths)
    {
        var hashes=paths.Distinct().ToDictionary(path=>path,Hash);var report=RaidMetadataProbe.Probe(paths,CancellationToken.None);
        foreach(var pair in hashes)Check(Hash(pair.Key)==pair.Value,"Audit source remains byte-identical");
        Check(report.MetadataBytesRead<=32768L*paths.Length,"Metadata reader stays bounded");return report;
    }
    static void Rejected(RaidMetadataProbe.Report report,string reason)
    {
        Check(report.Groups.All(group=>group.Configuration==null),reason+": no automatic configuration");
    }
    static void MetadataMutations()
    {
        string first=Source("upstream/md-raid1-1.bin"),second=Source("upstream/md-raid1-2.bin");
        var control=Probe(second,first);var group=control.Groups.Single();Check(group.Status=="candidate"&&group.Configuration.Members[0].Path==first&&group.Configuration.Members[1].Path==second,"Input ordering cannot replace metadata role ordering");
        Check(group.MetadataOnly&&group.RequiresReview&&!group.DataIntegrityEstablished,"Matching metadata is not authenticated payload");
        string duplicateUuid=Edit("upstream/md-raid1-2.bin",(bytes,at)=>Buffer.BlockCopy(File.ReadAllBytes(first),4096+168,bytes,at+168,16));
        Rejected(Probe(first,duplicateUuid),"Distinct role/device number with duplicate device UUID");
        string differentMap=Edit("upstream/md-raid1-2.bin",(bytes,at)=>{bytes[at+256]=1;bytes[at+258]=0;});
        Rejected(Probe(first,differentMap),"Same event/UUID with incompatible global role maps");
        string badGeometry=Edit("upstream/md-raid1-2.bin",(bytes,at)=>Wide(bytes,at+80,4095));
        Rejected(Probe(first,badGeometry),"Different per-array component sizes");
        string highEvent=Edit("upstream/md-raid1-2.bin",(bytes,at)=>Wide(bytes,at+200,UInt64.MaxValue));
        Rejected(Probe(first,highEvent),"Unsigned maximum event cannot silently select newer member");
        string shortData=Edit("upstream/md-raid1-1.bin",(bytes,at)=>{Wide(bytes,at+80,1);Wide(bytes,at+136,1);});
        Rejected(Probe(shortData),"Kernel-invalid data_size below ten sectors");
        string v10Overlap=Edit("version1-0/member1.bin",(bytes,at)=>Wide(bytes,at+136,(ulong)(at/512+1)));
        Rejected(Probe(v10Overlap),"Version1.0 declared available data extends into superblock");
        string v10Offset=Edit("version1-0/member1.bin",(bytes,at)=>{Wide(bytes,at+128,1);Wide(bytes,at+80,(ulong)(at/512-1));});
        // A nonzero offset is not guessed away: the exact declared range may
        // still be usable, if it ends before metadata and fits data_size.
        var shifted=Probe(v10Offset).Groups.Single();Check(shifted.Configuration!=null&&shifted.Configuration.Members[0].Offset==512,"A valid nonzero legacy-end data offset is retained");
        Check(Probe(Source("upstream/md-90-1.bin")).Groups.Single().Configuration!=null,"Legacy descriptor mutations start with a clean usable mirror");
        foreach(uint flag in new[]{16U,32U,1U<<18,0x80000000U}){
            string unknown=Edit("upstream/md-90-1.bin",(bytes,at)=>{Put(bytes,at+3984,Word(bytes,at+3984)|flag);int number=(int)Word(bytes,at+3968);Put(bytes,at+512+number*128+16,Word(bytes,at+512+number*128+16)|flag);},true);
            Rejected(Probe(unknown),"Legacy active descriptor contains unsupported device-state bit "+flag);
        }
        foreach(uint flag in new[]{512U,1024U}){
            string known=Edit("upstream/md-90-1.bin",(bytes,at)=>{Put(bytes,at+3984,Word(bytes,at+3984)|flag);int number=(int)Word(bytes,at+3968);Put(bytes,at+512+number*128+16,Word(bytes,at+512+number*128+16)|flag);},true);
            Check(Probe(known).Groups.Single().Configuration!=null,"Known write-mostly/failfast flags do not change mirror mapping");
        }
        var zero=Probe(Edit("upstream/md-raid1-1.bin",(bytes,at)=>Array.Clear(bytes,at+16,16)));
        Rejected(zero,"Zero array UUID does not identify an array");
    }
    static void TopologyAndPaths()
    {
        var four=Directory.GetFiles(Source("raid10-four-member"),"*.bin").OrderBy(path=>path).ToArray();
        var pairMissing=Probe(four[2],four[3]);Rejected(pairMissing,"Both copies of one near2 RAID10 pair missing");
        var degraded=Probe(four[0],four[2]).Groups.Single();Check(degraded.Configuration!=null&&degraded.MissingRoles.SequenceEqual(new[]{1,3}),"One survivor from each known near2 pair stays explicit degraded candidate");
        string hard=Edit("upstream/md-raid1-1.bin",delegate{});string alias=Path.Combine(work,"alias.raw");
        Check(CreateHardLink(alias,hard,IntPtr.Zero),"Owned fixture hardlink can be created for identity audit");
        Rejected(Probe(hard,alias),"Hardlink aliases cannot become separate members");
        Check(RaidMetadataProbe.Probe(new string[0],CancellationToken.None).Groups.Count==0,"Empty source list does not invent a group");
        string unknown=Path.Combine(work,"not-md.raw");File.WriteAllBytes(unknown,new byte[131072]);
        var absent=Probe(unknown);Check(absent.Members.Single().Status=="not_found"&&absent.Groups.Count==0,"Random complete RAW is not classified as recoverable RAID");
        var token=new CancellationTokenSource();int updates=0;bool cancelled=false;
        try{RaidMetadataProbe.Probe(new[]{unknown,unknown},token.Token,(done,total)=>{updates++;token.Cancel();});}catch(OperationCanceledException){cancelled=true;}finally{token.Dispose();}
        Check(cancelled&&updates==1,"Cancellation between images does not publish a partial final report");
    }
    public static int Main(string[] args)
    {
        try{project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","raid-metadata-fixtures");work=Path.Combine(project,".build","raid-metadata-audit-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);MetadataMutations();TopologyAndPaths();Console.WriteLine("PASS RaidMetadataAudit: "+checks+" independent checks; adversarial identity/role maps/geometry/device state, degraded near2 pairs, bounded read-only inputs and cancellation. Public pinned MD fixtures only; no devices.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
