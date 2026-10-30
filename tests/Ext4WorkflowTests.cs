using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class Ext4WorkflowTests
{
    static int checks;static string project,fixtures,work;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static RecoveryOptions Options(){return new RecoveryOptions{Ext4Metadata=true,FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false};}
    public static int Main(string[] args)
    {
        try{project=Path.GetFullPath(args[0]);fixtures=Path.Combine(project,".build","ext4-fixtures-current");work=Path.Combine(project,".build","ext4-workflow-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            string image=Path.Combine(fixtures,"extent-deleted.dd"),before=Hash(image),run=Path.Combine(work,"pipeline");Directory.CreateDirectory(run);
            string checksum=Path.Combine(work,"source.sha256");File.WriteAllText(checksum,before);
            var result=RecoveryPipeline.Run(image,run,Options(),CancellationToken.None,s=>{},checksum);var session=RecoverySession.Read(run);
            Check(result.UniqueFiles==1&&session.Stages.Single().Key=="ext4"&&session.Stages.Single().Status=="complete","ext4 method produces one persisted completed stage");
            var item=RecoveryCatalog.Load(run).Items.Single();Check(item.Method=="ext4 · запись inode"&&item.Status=="Кандидат ext4"&&item.Quality=="metadata_candidate","catalog retains metadata confidence independent of file decoding");
            Check(item.OriginalPath==null&&item.OriginalLocations.Count==0,"directory references without inode generations never become confirmed original paths");
            Check(item.SourceVolumeOffset==0&&item.SourceRanges.Count>0&&item.SourceRanges.Sum(x=>x.Length)==item.Bytes,"ext4 source mapping and volume retained");
            Check(RecoveryCore.RecoveredFiles(run).Count()==1&&!RecoveryCore.RecoveredFiles(run).Any(x=>x.EndsWith("report.json",StringComparison.OrdinalIgnoreCase)),"metadata report excluded from export/catalog payload");
            string report=Path.Combine(run,"ext4","report.json"),prior=Hash(report);var resumed=RecoveryPipeline.Resume(run,CancellationToken.None,s=>{});
            Check(resumed.ResumedStages==1&&Hash(report)==prior,"completed ext4 stage reused only after verification");Check(Hash(image)==before,"pipeline and resume leave source unchanged");
            var json=new JavaScriptSerializer{MaxJsonLength=64*1024*1024};var proof=json.Deserialize<Ext4Recovery.Report>(File.ReadAllText(report));
            proof.SourceUnchanged=false;RecoveryCore.SaveJson(report,proof);Check(FileEvidence.Load(run).For(item.Path)==null,"failed final source preservation invalidates metadata provenance");
            proof.SourceUnchanged=true;proof.Entries[0].Extents[0].LogicalOffset=1;RecoveryCore.SaveJson(report,proof);Check(FileEvidence.Load(run).For(item.Path)==null,"invalid logical coverage never becomes a verified source map");
            string damaged=Path.Combine(work,"read-errors");Directory.CreateDirectory(damaged);RecoveryCore.SaveJson(Path.Combine(damaged,"source-read-errors.json"),new{status="complete_with_read_errors",size=new FileInfo(image).Length,copied=new FileInfo(image).Length,unreadBytes=512,ranges=new[]{new{Offset=0,Length=512}}});
            bool stopped=false;try{RecoveryPipeline.Run(image,damaged,Options(),CancellationToken.None,s=>{},checksum);}catch(IOException){stopped=true;}
            Check(stopped&&!Directory.Exists(Path.Combine(damaged,"ext4")),"unread allocation metadata prevents ext4 extraction");
            Check(RecoverySession.Read(damaged).Stages.Single().Status=="incomplete","blocked only-method stage never reports reusable completion");
            using(var settings=new RecoverySettingsPanel()){settings.ApplyProfile("maximum");Check(settings.Selection().Ext4Metadata,"maximum profile enables ext4");settings.ApplyProfile("quick");Check(!settings.Selection().Ext4Metadata,"quick profile remains bounded to selected standard methods");}
            var storage=StorageRecovery.SearchOptions(true,false);storage.Validate();Check(storage.Ext4Metadata&&storage.FragmentedPhotos&&storage.FragmentedVideo,"maximum search after storage preparation includes new metadata/photo/video methods");
            var partial=StorageRecovery.SearchOptions(true,true);partial.Validate();Check(!partial.Ext4Metadata&&!partial.FatMetadata&&!partial.NtfsMetadata&&!partial.MetadataRescue&&!partial.OrphanDirectories,"partial storage images never enable allocation-based metadata recovery");
            Check(partial.FragmentedPhotos&&partial.FragmentedVideo,"partial storage images can still run content-only fragment methods");Check(!StorageRecovery.SearchOptions(false,false).Ext4Metadata,"standard storage search retains deliberate method selection");
            Check(Hash(image)==before,"all workflow checks preserve original bytes");
            Console.WriteLine("PASS Ext4Workflow: "+checks+" checks; actual pipeline/catalog/session, metadata uncertainty, maps, source identity, read-error guard and UI options. Synthetic e2fsprogs image only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
