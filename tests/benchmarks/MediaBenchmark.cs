using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Only opens manifest-listed regular files. Never enumerates drives.
public static class MediaBenchmark
{
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=32*1024*1024};
    public static int Main(string[] args)
    {
        try{
            if(args.Length<3)throw new ArgumentException("Usage: corpus-directory output-directory run-label [case-name]");
            string corpus=Path.GetFullPath(args[0]),output=Path.GetFullPath(args[1]);
            if(Directory.Exists(output)||File.Exists(output))throw new IOException("Benchmark output already exists");
            Directory.CreateDirectory(output);
            string manifestPath=Path.Combine(corpus,"manifest.json"),manifestBefore=Hash(manifestPath);
            var manifest=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(manifestPath));
            string applicationBefore=Hash(typeof(RecoveryCore).Assembly.Location);
            string helperBefore=File.Exists(HelperClient.Executable)?Hash(HelperClient.Executable):null;
            string carver=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"tools","testdisk-7.2","photorec_win.exe");
            string carverBefore=File.Exists(carver)?Hash(carver):null;
            var results=new List<object>();
            foreach(Dictionary<string,object> item in (IEnumerable)manifest["cases"]){
                string name=(string)item["name"];if(args.Length>3&&name!=args[3])continue;
                string image=RecoveryCatalog.SafeFile(corpus,(string)item["image"]);
                if((File.GetAttributes(image)&FileAttributes.ReparsePoint)!=0)throw new IOException("Image is a link");
                string before=Hash(image);if(before!=(string)item["sha256"])throw new IOException("Corpus image checksum mismatch");
                string run=Path.Combine(output,name);Directory.CreateDirectory(run);
                string baseline=Path.Combine(run,"baseline.sha256");File.WriteAllText(baseline,before);
                var options=new RecoveryOptions{FatMetadata=true,NtfsMetadata=true,LostPartitions=true,AlternateFat=true,OrphanDirectories=true,MetadataRescue=true,Signatures=true,EmbeddedPhotos=true,Containers=true,ArchiveMembers=true,SmallBlocks=true,JpegFragments=true,KeepCorrupted=true};
                // Add future optional media stages without requiring the old baseline
                // assembly to know those fields. Actual configuration is serialized.
                foreach(string field in new[]{"FragmentedPhotos","FragmentedMedia","FragmentedVideo"}){
                    var property=typeof(RecoveryOptions).GetField(field);if(property!=null&&property.FieldType==typeof(bool))property.SetValue(options,true);
                }
                var clock=Stopwatch.StartNew();string failure=null;var candidates=new List<object>();
                try{
                    using(var cancel=new CancellationTokenSource(TimeSpan.FromMinutes(5)))RecoveryPipeline.Run(image,run,options,cancel.Token,s=>{},baseline);
                    var catalog=RecoveryCatalog.Load(run);
                    foreach(var candidate in catalog.Items){
                        string file=RecoveryCatalog.SafeFile(run,candidate.Path);
                        candidates.Add(new{path=file,sha256=Hash(file),bytes=new FileInfo(file).Length,method=candidate.Method,status=candidate.Status,category=candidate.Category,original_path=candidate.OriginalPath});
                    }
                }catch(Exception error){failure=error.GetType().Name+": "+error.Message;}
                clock.Stop();string after=Hash(image);if(before!=after)throw new IOException("Recovery modified corpus image");
                results.Add(new{name=name,image=(string)item["image"],image_sha256=before,source_unchanged=true,elapsed_ms=clock.ElapsedMilliseconds,status=failure==null?"completed":"failed",error=failure,configuration=options,files=candidates});
                Console.WriteLine(name+": "+(failure??("completed, candidates="+candidates.Count)));
            }
            if(results.Count==0)throw new IOException("No selected corpus case");
            string manifestAfter=Hash(manifestPath),applicationAfter=Hash(typeof(RecoveryCore).Assembly.Location);
            string helperAfter=File.Exists(HelperClient.Executable)?Hash(HelperClient.Executable):null;
            string carverAfter=File.Exists(carver)?Hash(carver):null;
            if(manifestBefore!=manifestAfter)throw new IOException("Corpus manifest changed during benchmark");
            if(applicationBefore!=applicationAfter||helperBefore!=helperAfter)throw new IOException("Runtime changed during benchmark");
            if(carverBefore!=carverAfter)throw new IOException("Signature carver changed during benchmark");
            File.WriteAllText(Path.Combine(output,"run.json"),Json.Serialize(new{
                schema=1,label=args[2],tool="Recovery",edition="source build",
                application_sha256=applicationAfter,application_sha256_before=applicationBefore,application_sha256_after=applicationAfter,
                helper_sha256=helperAfter,helper_sha256_before=helperBefore,helper_sha256_after=helperAfter,
                carver_sha256_before=carverBefore,carver_sha256_after=carverAfter,
                manifest_sha256=manifestBefore,manifest_sha256_before=manifestBefore,manifest_sha256_after=manifestAfter,
                harness_sha256=Hash(Assembly.GetExecutingAssembly().Location),started_from_regular_files_only=true,results=results
            }));
            return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
