using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// A local benchmark driver, not the product UI. Never enumerates disks.
public static class CommercialComparisonBaseline
{
    public sealed class Case { public string Id,Image;public List<string> ExpectedHashes; }
    static string Hash(string file){return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{});}
    public static int Main(string[] args)
    {
        string project=Path.GetFullPath(args[0]);
        if(!Path.GetFullPath(ApplicationPaths.RuntimeRoot).TrimEnd('\\').Equals(project.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)){
            var domain=AppDomain.CreateDomain("Recovery comparison regular-images only",null,new AppDomainSetup{ApplicationBase=project});
            try{return domain.ExecuteAssembly(Assembly.GetExecutingAssembly().Location,args);}finally{AppDomain.Unload(domain);}
        }
        try {
            Environment.SetEnvironmentVariable("__COMPAT_LAYER","RunAsInvoker");var json=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};
            string folder=Path.Combine(project,".build","competitors"),manifest=Path.Combine(folder,"baseline-cases.json");
            var cases=json.Deserialize<List<Case>>(File.ReadAllText(manifest));var results=new List<object>();
            foreach(var sample in cases){
                string source=RecoveryCatalog.SafeFile(folder,sample.Image),before=Hash(source),run=Path.Combine(folder,"ours-"+sample.Id+"-"+DateTime.UtcNow.ToString("yyyyMMddHHmmssfff"));Directory.CreateDirectory(run);
                string baseline=Path.Combine(run,"baseline.sha256");File.WriteAllText(baseline,before,new UTF8Encoding(false));
                var options=new RecoveryOptions{FatMetadata=true,NtfsMetadata=true,LostPartitions=true,AlternateFat=true,OrphanDirectories=true,MetadataRescue=true,Signatures=true,EmbeddedPhotos=true,Containers=true,ArchiveMembers=true,SmallBlocks=true,JpegFragments=true,KeepCorrupted=false};
                var timer=Stopwatch.StartNew();ScanResult scan;using(var stop=new CancellationTokenSource(90000))scan=RecoveryPipeline.Run(source,run,options,stop.Token,s=>{},baseline);timer.Stop();
                var files=RecoveryCatalog.Load(run);int exact=sample.ExpectedHashes.Count(expected=>files.Items.Any(item=>item.Sha256.Equals(expected,StringComparison.OrdinalIgnoreCase)));
                if(before!=Hash(source))throw new IOException("Benchmark changed source image");
                results.Add(new{sample=sample.Id,input_sha256=before,expected_hashes=sample.ExpectedHashes,expected=sample.ExpectedHashes.Count,exact=exact,candidates=scan.Candidates,unique_files=scan.UniqueFiles,elapsed_ms=timer.ElapsedMilliseconds,unmatched_candidates="unscored; do not treat as false positives without a complete artifact truth set",configuration=options,result_directory=run,source_unchanged=true});
                Console.WriteLine(sample.Id+": exact "+exact+" / "+sample.ExpectedHashes.Count+"; unique candidates "+scan.UniqueFiles);
            }
            RecoveryCore.SaveJson(Path.Combine(project,"tests",args.Length>1?Path.GetFileName(args[1]):"CommercialComparison-baseline.json"),new{date_utc=DateTime.UtcNow.ToString("o"),status="complete",scope="Synthetic regular files only, no physical disk enumeration",application_sha256=Hash(typeof(RecoveryCore).Assembly.Location),commercial_comparison_performed=false,note="This is our baseline; competitor results are recorded separately. Times are diagnostic and not a cross-tool performance comparison.",results=results});return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
