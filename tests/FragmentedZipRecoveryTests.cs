using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class FragmentedZipRecoveryTests
{
    static int checks;
    static string root;
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=32*1024*1024};}
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string file){using(var input=File.OpenRead(file))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static IEnumerable<Dictionary<string,object>> Rows(object array){return ((IEnumerable)array).Cast<object>().Cast<Dictionary<string,object>>();}
    static string RunPath(string name){return Path.Combine(root,name+"-"+Guid.NewGuid().ToString("N"));}
    static bool ThrowsIo(Action action){try{action();return false;}catch(IOException){return true;}}
    static FragmentedZipRecovery.Report Report(string output){return Json().Deserialize<FragmentedZipRecovery.Report>(File.ReadAllText(Path.Combine(output,"fragmented-zip.json")));}

    static void Fixtures()
    {
        var fixtures=Json().Deserialize<List<Dictionary<string,object>>>(File.ReadAllText(Path.Combine(root,"fixtures.json")));
        foreach(var fixture in fixtures){
            string name=(string)fixture["case"],image=Path.Combine(root,(string)fixture["file"]),output=RunPath(name);var expected=Rows(fixture["expected"]).ToArray();
            int count=FragmentedZipRecovery.Recover(image,output,CancellationToken.None,null);var report=Report(output);
            Check(count==expected.Length&&report.Recovered==expected.Length,name+": only expected verified archives published");
            Check(report.Status=="complete"&&report.Schema==1&&report.InputBytes==new FileInfo(image).Length,name+": complete report and input bounds");
            Check(Hash(image)==(string)fixture["image_sha256"],name+": original image unchanged");
            Check(!Directory.GetFiles(output,"*.partial",SearchOption.AllDirectories).Any(),name+": unverified partials never published");
            Check(Directory.GetFiles(Path.Combine(output,"fragmented-archives")).Length==expected.Length,name+": report matches only result files");
            string reason=fixture["reason"] as string;if(reason!=null)Check(report.Skipped.ContainsKey(reason),name+": explicit rejection reason "+reason+" actual "+String.Join(",",report.Skipped.Keys));
            Check(report.Files.Count==expected.Length,name+": report row count");
            for(int i=0;i<expected.Length;i++){
                var wanted=expected[i];var actual=report.Files[i];string path=Path.Combine(output,actual.Path.Replace('/',Path.DirectorySeparatorChar));
                Check(actual.Sha256==(string)wanted["sha256"]&&Hash(path)==(string)wanted["sha256"],name+": exact SHA256 against independent original ZIP");
                Check(actual.Bytes==Convert.ToInt64(wanted["size"])&&new FileInfo(path).Length==actual.Bytes,name+": byte-exact archive size");
                Check(actual.Members==Convert.ToInt32(wanted["members"])&&actual.MemberSources.Count==actual.Members,name+": every member accounted");
                Check(actual.Status=="zip_crc_reassembled"&&ContentVerifier.Verify(path,CancellationToken.None).Code=="container_crc",name+": separate content verifier confirms CRC");
                Check(actual.Path.StartsWith("fragmented-archives/reassembled-",StringComparison.Ordinal)&&Path.GetExtension(actual.Path)==(string)wanted["extension"],name+": safe generated path and format hint");
                var extents=Rows(wanted["extents"]).ToArray();Check(actual.Extents.Count==extents.Length,name+": source extent count includes directory");
                object originalName;string originalFile=wanted.TryGetValue("original_file",out originalName)?(string)originalName:name+".original.zip";
                using(var source=File.OpenRead(image))using(var original=File.OpenRead(Path.Combine(root,originalFile))){
                    long logical=0;
                    for(int e=0;e<extents.Length;e++){
                        var proof=actual.Extents[e];Check(proof.ImageOffset==Convert.ToInt64(extents[e]["ImageOffset"])&&proof.LogicalOffset==Convert.ToInt64(extents[e]["LogicalOffset"])&&proof.Length==Convert.ToInt64(extents[e]["Length"]),name+": exact physical/logical extent "+e);
                        Check(proof.LogicalOffset==logical&&proof.ImageOffset>=0&&proof.ImageOffset<=source.Length-proof.Length,name+": contiguous logical coverage and source bounds");
                        byte[] expectedBytes=new byte[(int)proof.Length],sourceBytes=new byte[(int)proof.Length];source.Position=proof.ImageOffset;source.Read(sourceBytes,0,sourceBytes.Length);original.Position=proof.LogicalOffset;original.Read(expectedBytes,0,expectedBytes.Length);Check(sourceBytes.SequenceEqual(expectedBytes),name+": extent independently matches original bytes");logical+=proof.Length;
                    }
                    Check(logical==actual.Bytes,name+": extents cover whole reconstructed file");
                }
                var names=((IEnumerable)wanted["names"]).Cast<object>().Select(Convert.ToString).ToArray();
                Check(actual.MemberSources.Select(x=>x.Name).SequenceEqual(names),name+": exact original member names retained as metadata");
                for(int m=0;m<actual.MemberSources.Count;m++){
                    var member=actual.MemberSources[m];Check(member.ImageOffset==actual.Extents[m].ImageOffset&&member.LogicalOffset==actual.Extents[m].LogicalOffset&&member.EquivalentRecordOffsets.Contains(member.ImageOffset),name+": member provenance agrees with selected source record");
                    Check(member.RecordSha256!=null&&member.RecordSha256.Length==64&&member.Crc32.Length==8,name+": hashes and CRC recorded");
                    if(name=="duplicate-identical-record"&&m==0)Check(member.EquivalentRecordOffsets.Count==2,name+": identical alternatives retained without ambiguity");
                }
            }
        }
        Console.WriteLine("Independent Python ZIP cases: "+fixtures.Count);
    }

    static void Guards()
    {
        string image=Path.Combine(root,"stored.dd"),before=Hash(image),output=RunPath("cancel");var cancellation=new CancellationTokenSource();bool cancelled=false;
        try{FragmentedZipRecovery.Recover(image,output,cancellation.Token,(a,b)=>cancellation.Cancel());}catch(OperationCanceledException){cancelled=true;}
        Check(cancelled&&Report(output).Status=="cancelled"&&Report(output).Files.Count==0,"cancellation after source scan publishes no archive");
        Check(!Directory.GetFiles(output,"*.partial",SearchOption.AllDirectories).Any()&&Hash(image)==before,"cancel keeps source and removes temporary output");
        output=RunPath("pre-cancel");cancelled=false;try{FragmentedZipRecovery.Recover(image,output,cancellation.Token,null);}catch(OperationCanceledException){cancelled=true;}
        Check(cancelled&&!Directory.Exists(output),"pre-cancel never creates output");
        foreach(string file in new[]{"header-limit.dd","directory-limit.dd","local-limit.dd"}){
            output=RunPath(file);string limitedImage=Path.Combine(root,file),hash=Hash(limitedImage);bool failed=ThrowsIo(()=>FragmentedZipRecovery.Recover(limitedImage,output,CancellationToken.None,null));
            Check(failed&&Report(output).Status=="limited"&&Report(output).Recovered==0,file+": explicit limited result without false success");
            Check(Hash(limitedImage)==hash&&!Directory.GetFiles(Path.Combine(output,"fragmented-archives")).Any(),file+": bounded work leaves source unchanged");
        }
        output=RunPath("expanded-work-limit");string budgetImage=Path.Combine(root,"expanded-work-limit.dd"),budgetHash=Hash(budgetImage);
        Check(ThrowsIo(()=>FragmentedZipRecovery.Recover(budgetImage,output,CancellationToken.None,null))&&Report(output).Status=="limited","total inflated work is capped even for individually valid members");
        Check(Report(output).ExpandedWorkBytes==FragmentedZipRecovery.MaximumWorkBytes&&Report(output).Recovered==0&&!Directory.GetFiles(Path.Combine(output,"fragmented-archives")).Any(),"work limit exposes exact budget without a partial successful archive");
        Check(Hash(budgetImage)==budgetHash,"work-limited validation preserves source");
        output=RunPath("existing");Directory.CreateDirectory(Path.Combine(output,"fragmented-archives"));string marker=Path.Combine(output,"fragmented-archives","keep.txt");File.WriteAllText(marker,"keep");
        Check(ThrowsIo(()=>FragmentedZipRecovery.Recover(image,output,CancellationToken.None,null))&&File.ReadAllText(marker)=="keep","existing output folder never overwritten");
        output=RunPath("report-exists");Directory.CreateDirectory(output);marker=Path.Combine(output,"fragmented-zip.json");File.WriteAllText(marker,"keep");
        Check(ThrowsIo(()=>FragmentedZipRecovery.Recover(image,output,CancellationToken.None,null))&&File.ReadAllText(marker)=="keep","existing report never overwritten");
        output=RunPath("source-report-collision");Directory.CreateDirectory(output);string collision=Path.Combine(output,"fragmented-zip.json");File.Copy(image,collision);string collisionHash=Hash(collision);
        Check(ThrowsIo(()=>FragmentedZipRecovery.Recover(collision,output,CancellationToken.None,null))&&Hash(collision)==collisionHash,"report/source collision rejected before mutation");
        Check(ThrowsIo(()=>FragmentedZipRecovery.Recover(@"\\.\PhysicalDrive0",RunPath("invalid-device"),CancellationToken.None,null)),"raw device path rejected without opening source");
        Check(ThrowsIo(()=>FragmentedZipRecovery.Recover(image+":stream",RunPath("invalid-ads"),CancellationToken.None,null)),"alternate data stream path rejected");
        Check(ThrowsIo(()=>FragmentedZipRecovery.Recover(@"\\localhost\unavailable\image.dd",RunPath("invalid-network"),CancellationToken.None,null)),"network path rejected");
        Check(Hash(image)==before&&!File.Exists(Path.Combine(root,"outside.exe")),"path-like member names never extracted or executed");
    }

    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,MetadataRescue=false,ArchiveMembers=false,TextFragments=false,FragmentedArchives=true};}
    static void Pipeline()
    {
        string image=Path.Combine(root,"docx.dd"),before=Hash(image),work=RunPath("pipeline"),checksum=RunPath("checksum")+".sha256";Directory.CreateDirectory(work);File.WriteAllText(checksum,before);
        var result=RecoveryPipeline.Run(image,work,Options(),CancellationToken.None,null,checksum);var item=RecoveryCatalog.Load(work).Items.Single();var proof=Report(work).Files.Single();
        Check(result.Candidates==1&&result.UniqueFiles==1&&File.Exists(result.FileCatalog)&&File.Exists(result.Gallery),"actual pipeline publishes reconstructed archive and catalogs");
        Check(item.Sha256==proof.Sha256&&item.Quality=="container_crc"&&item.Method=="Сборка ZIP / Office","catalog assigns exact hash, method and verified content state");
        Check(item.SourceCandidatePath==proof.Path&&item.SourceRanges.Count==proof.Extents.Count&&item.SourceOffset==proof.Extents[0].ImageOffset,"catalog binds complete extent mapping to unchanged output");
        Check(item.SourceRanges.Select(x=>x.Offset).SequenceEqual(proof.Extents.Select(x=>x.ImageOffset))&&item.SourceRanges.Select(x=>x.Length).SequenceEqual(proof.Extents.Select(x=>x.Length)),"catalog preserves logical source extent order and lengths");
        Check(item.OriginalPath==null&&item.OriginalLocations.Count==0,"central member names never invented as original archive filename");
        var session=RecoverySession.Read(work);var stage=session.Stages.Single();
        Check(stage.Key=="fragmented-zip"&&stage.Status=="complete"&&stage.Candidates==1&&stage.Artifacts.Count==2,"session captures new method report plus archive");
        Check(stage.Artifacts.Any(x=>x.Path=="fragmented-zip.json"&&x.Sha256==Hash(Path.Combine(work,"fragmented-zip.json")))&&stage.Artifacts.Any(x=>x.Path==proof.Path&&x.Sha256==proof.Sha256),"session retains hashes for both archive and extent report");
        DateTime archiveTime=File.GetLastWriteTimeUtc(Path.Combine(work,proof.Path));string reportHash=Hash(Path.Combine(work,"fragmented-zip.json"));
        result=RecoveryPipeline.Resume(work,CancellationToken.None,null);
        Check(result.ResumedStages==1&&result.UniqueFiles==1&&File.GetLastWriteTimeUtc(Path.Combine(work,proof.Path))==archiveTime&&Hash(Path.Combine(work,"fragmented-zip.json"))==reportHash,"resume verifies and reuses completed stage without rewriting results");
        string output=RecoveryCatalog.SafeFile(work,item.Path);File.AppendAllText(output,"modified after extraction");var changed=RecoveryCatalog.Build(work,CancellationToken.None,null).Items.Single();
        Check(changed.Quality=="changed"&&changed.SourceOffset==null&&changed.SourceCandidatePath==null&&changed.SourceRanges.Count==0,"changed output loses source mapping and verified status");
        Check(ThrowsIo(()=>RecoveryPipeline.Resume(work,CancellationToken.None,null)),"resume rejects changed reconstruction without silently reusing it");
        Check(Hash(image)==before,"integrated scan, resume and catalog never modify source");
    }

    public static int Main(string[] args)
    {
        root=Path.GetFullPath(args[0]);Fixtures();Guards();Pipeline();Console.WriteLine("PASS FragmentedZipRecovery: "+checks+" checks");return 0;
    }
}
