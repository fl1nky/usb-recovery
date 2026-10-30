using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class Ext4IntegrationAuditTests
{
    const string Candidate="ext4/files/volume_0_inode_13.bin";
    static int checks;static string work,source,sourceSha;static byte[] payload=Encoding.UTF8.GetBytes("owned ext4 audit payload");
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static string Folder(string name){string root=Path.Combine(work,name);Directory.CreateDirectory(Path.Combine(root,"ext4","files"));return root;}
    static Ext4Recovery.Report Report(string root)
    {
        string file=RecoveryCatalog.SafeFile(root,Candidate);File.WriteAllBytes(file,payload);
        return new Ext4Recovery.Report{Status="complete",SourceUnchanged=true,InputBytes=new FileInfo(source).Length,SourceSha256=sourceSha,
            RecoveredFiles=1,OutputBytes=payload.Length,Candidates=1,
            Volumes={new Ext4Recovery.VolumeReport{Offset=0,Bytes=4096,BlockBytes=1024,InodeBytes=256,Status="complete",MetadataChecksums=true}},
            Entries={new Ext4Recovery.Entry{
                VolumeOffset=0,InodeOffset=1024,Inode=13,Generation=3,DeletionTime=1700000000,DeclaredSize=payload.Length,RecoveredBytes=payload.Length,
                Status="deleted_inode_candidate",Output="files/volume_0_inode_13.bin",Sha256=Hash(file),
                Mapping="extent_tree",MappingIntegrity="inode_and_extent_nodes_crc32c",AllocationStatus="currently_free",InodeChecksumVerified=true,
                Extents={new Ext4Recovery.Extent{ImageOffset=512,LogicalOffset=0,Length=payload.Length}},
                Names={new Ext4Recovery.NameLink{Name="unproven.jpg",DirectoryPath="unproven-folder",TargetInode=13}}}}};
    }
    static void Save(string root,Ext4Recovery.Report report)
    {
        RecoveryCore.SaveJson(Path.Combine(root,"ext4","report.json"),report);
        RecoveryCore.SaveJson(Path.Combine(root,RecoverySession.FileName),new{SourceBytes=new FileInfo(source).Length,SourceSha256=sourceSha});
    }
    static void Duplicate()
    {
        string root=Folder("duplicate");var report=Report(root);Save(root,report);
        Directory.CreateDirectory(Path.Combine(root,"files.1"));File.WriteAllBytes(Path.Combine(root,"files.1","generic.bin"),payload);
        var index=RecoveryCatalog.Build(root,CancellationToken.None,null);Check(index.Candidates==2&&index.Items.Count==1,"Equal contents deduplicate without dropping candidates");
        var item=index.Items.Single();
        Check(item.Method=="ext4 · запись inode"&&item.Quality=="metadata_candidate","A PhotoRec duplicate must not hide ext4 metadata evidence");
        Check(item.SourceRanges.Count==1&&item.SourceRanges[0].Offset==512&&item.SourceRanges[0].Length==payload.Length,"Metadata source ranges survive content deduplication");
        Check(item.SourceCandidatePath==Candidate,"Source map links to actual ext4 origin rather than generic PhotoRec path");
        Check(new[]{item.Path}.Concat(item.Copies).Count()==2,"Both source candidate links survive grouping");
        Check(item.OriginalPath==null&&item.OriginalLocations.Count==0,"Generation-free directory link never becomes an original path");
    }
    static void Rejection(string name,Action<Ext4Recovery.Report> mutate)
    {
        string root=Folder(name);var report=Report(root);mutate(report);Save(root,report);
        Check(FileEvidence.Load(root).For(Candidate)==null,name+": invalid report cannot supply source provenance");
    }
    static void ChangedPayload()
    {
        string root=Folder("changed-payload");var report=Report(root);Save(root,report);
        File.WriteAllText(RecoveryCatalog.SafeFile(root,Candidate),"changed after extraction",Encoding.UTF8);
        var item=RecoveryCatalog.Build(root,CancellationToken.None,null).Items.Single();
        Check(item.Quality=="changed"&&item.SourceRanges.Count==0&&item.SourceCandidatePath==null,"Changed payload never inherits the prior inode map or confidence");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","ext4-integration-audit-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            source=Path.Combine(work,"own-source.dd");var bytes=new byte[4096];Array.Copy(payload,0,bytes,512,payload.Length);File.WriteAllBytes(source,bytes);sourceSha=Hash(source);
            string positive=Folder("positive");var control=Report(positive);Save(positive,control);Check(FileEvidence.Load(positive).For(Candidate)!=null,"Independently constructed positive report accepted");
            Rejection("foreign-sha",r=>r.SourceSha256=new string('a',64));
            Rejection("foreign-size",r=>r.InputBytes++);
            Rejection("unknown-schema",r=>r.Schema=2);
            Rejection("unknown-method",r=>r.Method="other-parser");
            Rejection("source-changed",r=>r.SourceUnchanged=false);
            Rejection("partial-stage",r=>r.Status="limited");
            Rejection("limited-flag",r=>r.Limited=true);
            Rejection("failed-flag",r=>r.Failed=true);
            Rejection("cancelled-flag",r=>r.Cancelled=true);
            Rejection("partial-entry",r=>r.Entries[0].Status="not_recovered");
            Rejection("unknown-allocation",r=>r.Entries[0].AllocationStatus="unknown");
            Rejection("unknown-integrity",r=>r.Entries[0].MappingIntegrity="unknown");
            Rejection("unknown-mapping",r=>r.Entries[0].Mapping="unknown");
            Rejection("negative-volume",r=>r.Entries[0].VolumeOffset=-1);
            Rejection("outside-volume",r=>r.Entries[0].VolumeOffset=4096);
            Rejection("size-mismatch",r=>r.Entries[0].RecoveredBytes--);
            Rejection("range-overflow",r=>r.Entries[0].Extents[0].ImageOffset=4090);
            Rejection("logical-hole",r=>r.Entries[0].Extents[0].LogicalOffset=1);
            Rejection("physical-overlap",r=>{long half=payload.Length/2;r.Entries[0].Extents[0].Length=half;r.Entries[0].Extents.Add(new Ext4Recovery.Extent{ImageOffset=512,LogicalOffset=half,Length=payload.Length-half});});
            ChangedPayload();Duplicate();Check(Hash(source)==sourceSha,"Integration auditing preserves the supplied source image");
            Console.WriteLine("PASS Ext4IntegrationAudit: "+checks+" checks; independent report envelopes, source binding, full extent coverage, candidate-only original paths and PhotoRec/ext4 deduplication. Synthetic ordinary files only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
