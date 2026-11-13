using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using UsbRecovery;

// Real helper protocol on hash-pinned public native LVM2 PV images. No UI,
// device, mounting, credentials, network access or simulated crypto worker.
public static class LvmPipelineTests
{
    static int checks;static string work,fixture;
    static readonly Dictionary<string,string[]> Pins=new Dictionary<string,string[]>{
        {"lvm",new[]{"35759d311d34a51c3b911ebfc518e48c2d5ce8c7bc8ee0b11dea6d5f713667b4","3f43cf87e6b97a6ae541703e98a1535e481f1b30a2653fcf51fcf73cae45fde1"}},
        {"lvm-mirror-1",new[]{"a031b1d83c9f69eae37fce849ab553ec18c58b09f9a05f2c0e4263b98790357d","72b614c72f655bf63fa5eb19d695fa332387ea380bdd41486e06314d11ba0f14"}},
        {"lvm-mirror-2",new[]{"c67254aa86288b97496160a08802e12fcbd417caf3fa279024f93bd1fcdb65ed","34fa132513ac74a51515ae99f3b240649b9c580f3f282ae19199e661246e332e"}},
        {"lvm-thin",new[]{"bf1fa447d43f768e04b93ef60774424f5bec5e138179f967e5269c7343ecd08b","3839cc5bcc7791ca602915994590348b0f9f2f96b907de85e778181df809af3f"}}
    };
    static void Check(bool value,string text){checks++;if(!value)throw new IOException(text);}
    static string Hash(string path){using(var sha=SHA256.Create())using(var input=File.OpenRead(path))return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string Load(string name)
    {
        string encoded=Path.Combine(fixture,name+".bin.gz"),output=Path.Combine(work,name+".dd");
        Check(Hash(encoded)==Pins[name][0],"native compressed source SHA");
        using(var gzip=new GZipStream(File.OpenRead(encoded),CompressionMode.Decompress))using(var file=File.Create(output)){
            byte[] buffer=new byte[1048576];long size=0;int count;
            while((count=gzip.Read(buffer,0,buffer.Length))>0){size+=count;if(size>32*1024*1024)throw new IOException("Expansion budget");file.Write(buffer,0,count);}
        }
        Check(Hash(output)==Pins[name][1],"native raw source SHA");return output;
    }
    static StorageRecoveryRequest Request(string[] sources,StorageVolumeInfo volume)
    {
        return new StorageRecoveryRequest{Kind="LVM",Source=sources[0],LvmSources=sources,Volume=volume,MaximumOutputBytes=32*1024*1024,
            OutputDirectory=work,Secrets=new Dictionary<string,string>(),SearchAfterPreparation=false};
    }
    static void Case(string[] sources,string expected,bool resume)
    {
        var hashes=sources.ToDictionary(p=>p,Hash);
        var probe=StorageRecovery.ProbeLvm(sources,CancellationToken.None);
        Check(probe.Status!="error"&&probe.Volumes.Length>0,"actual helper detects native logical volumes");
        foreach(var volume in probe.Volumes){
            var request=Request(sources,volume);var execution=StorageRecoveryWorkflow.Create(request);
            if(resume){
                using(var stopped=new CancellationTokenSource()){
                    bool cancelled=false;
                    try{StorageRecoveryWorkflow.Execute(request,execution,stopped.Token,p=>{if(p.Total==volume.LengthBytes&&p.Completed==p.Total&&File.Exists(Path.Combine(execution.Directory,"lvm","lvm-resume.json")))stopped.Cancel();});}
                    catch(OperationCanceledException){cancelled=true;}
                    Check(cancelled&&stopped.IsCancellationRequested,"actual helper cancellation follows durable LVM checkpoint");
                }
                request=StorageRecoveryWorkflow.ReadResumeRequest(execution.Directory);
                Check(request.Kind=="LVM"&&request.LvmSources.SequenceEqual(sources)&&request.Secrets==null,"resume restores member identity without secrets");
                execution=StorageRecoveryWorkflow.Resume(request,execution.Directory);
            }
            StorageRecoveryWorkflow.Execute(request,execution,CancellationToken.None,p=>{});
            Check(execution.Prepared!=null&&!execution.Prepared.Partial&&Hash(execution.Prepared.Image)==expected,"entire native logical image has expected SHA");
            Check(File.Exists(execution.Prepared.Checksum)&&File.Exists(Path.Combine(execution.Prepared.Directory,"lvm-report.json")),"published image is bound to checksum and source report");
            Check(!Directory.GetFiles(execution.Prepared.Directory,"*.partial").Any(),"no unfinished output advertised");
            Check(hashes.All(row=>Hash(row.Key)==row.Value),"every physical source unchanged");
        }
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","lvm-pipeline-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            fixture=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"tests","StorageFixtures","lvm");
            if(!Directory.Exists(fixture))fixture=Path.Combine(project,"tests","StorageFixtures","lvm");
            string linear=Load("lvm"),mirror1=Load("lvm-mirror-1"),mirror2=Load("lvm-mirror-2"),thin=Load("lvm-thin");
            Case(new[]{linear},"dffad29594c30648611f56c4122ed557bdfd08bb178ce28d22436009bd7c4a1a",true);
            Case(new[]{mirror1,mirror2},"748cc990c523e324606fe74cd5b780539369a7f93a42d6a9ea57a4b61ad613c2",false);
            Case(new[]{thin},"748cc990c523e324606fe74cd5b780539369a7f93a42d6a9ea57a4b61ad613c2",false);
            Console.WriteLine("PASS LvmPipeline: "+checks+" checks; actual helper, native linear/mirror/two thin volumes, full hashes, cancellation/resume and source preservation; no devices or UI.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
