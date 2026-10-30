using System;
using System.IO;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using System.Linq;
using System.Threading;
using UsbRecovery;

public static class MediaWorkflowTests
{
    static int checks;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]);
            string image=Path.Combine(project,".build","fragmented-media-tests","mjpeg-scattered.dd");
            string original=Path.Combine(project,".build","fragmented-media-tests","mjpeg-scattered.original.mp4");
            string run=Path.Combine(project,".build","media-workflow-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(run);
            string before=RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{});
            string checksum=Path.Combine(run,"fixture.sha256");File.WriteAllText(checksum,before);
            var options=new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedVideo=true};options.Validate();
            var first=RecoveryPipeline.Run(image,run,options,CancellationToken.None,s=>{},checksum);
            var catalog=RecoveryCatalog.Load(run);Check(catalog.Items.Count==1,"Reassembled video missing in catalog or helper reports leaked into files");
            var item=catalog.Items[0];string payload=RecoveryCatalog.SafeFile(run,item.Path);
            Check(File.ReadAllBytes(payload).SequenceEqual(File.ReadAllBytes(original)),"Pipeline failed exact source fixture");
            Check(item.Quality=="structural_candidate"&&item.Status=="Кандидат сборки","Structural candidate was promoted to original authenticity");
            Check(item.SourceRanges.Count>2&&item.SourceRanges.Sum(x=>x.Length)==item.Bytes,"Full disjoint extent map not retained");
            Check(item.OriginalPath==null&&item.OriginalLocations.Count==0,"Original filename or directory invented");
            using(var input=File.OpenRead(image))using(var assembled=new MemoryStream()){
                foreach(var range in item.SourceRanges){input.Position=range.Offset;var buffer=new byte[(int)range.Length];Check(input.Read(buffer,0,buffer.Length)==buffer.Length,"Extent truncated");assembled.Write(buffer,0,buffer.Length);}
                Check(assembled.ToArray().SequenceEqual(File.ReadAllBytes(payload)),"Source extent map disagrees with actual output bytes");
            }
            var second=RecoveryPipeline.Resume(run,CancellationToken.None,s=>{});
            Check(second.ResumedStages>=1,"Finished reassembly cannot resume from verified stage");
            Check(RecoveryCatalog.Load(run).Items.Count==1,"Resume duplicated media candidate");
            Check(RecoveryCore.RecoveredFiles(run).All(x=>!x.EndsWith("report.json")),"Internal helper report became recovered user data");
            Check(before==RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{}),"Source image changed");
            Check(first.Candidates==1,"Pipeline candidate count incorrect");
            string manifest=Path.Combine(run,"fragmented-media.json");string valid=File.ReadAllText(manifest);var serializer=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};
            var report=serializer.Deserialize<FragmentedMediaRecovery.Report>(valid);report.Files[0].Extents[1].ImageOffset=report.Files[0].Extents[0].ImageOffset+1;File.WriteAllText(manifest,serializer.Serialize(report));
            var invalid=FileEvidence.Load(run).For(item.Path);Check(invalid!=null&&!invalid.MappingComplete&&invalid.Ranges.Count==0,"Overlapping saved extent map accepted");
            File.WriteAllText(manifest,valid);report=serializer.Deserialize<FragmentedMediaRecovery.Report>(valid);report.Files[0].Extents[0].ImageOffset=new FileInfo(image).Length;File.WriteAllText(manifest,serializer.Serialize(report));
            invalid=FileEvidence.Load(run).For(item.Path);Check(invalid!=null&&!invalid.MappingComplete&&invalid.Ranges.Count==0,"Out-of-source saved extent map accepted");File.WriteAllText(manifest,valid);
            Console.WriteLine("PASS MediaWorkflow: "+checks+" checks; actual pipeline, candidate provenance, byte-exact source extents, catalog and verified resume; synthetic only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
