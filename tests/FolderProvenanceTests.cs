using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class FolderProvenanceTests
{
    static string root,fixtures;static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string file){using(var input=File.OpenRead(file))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=128*1024*1024};}
    static RecoveryOptions Options(bool fat=false){return new RecoveryOptions{FatMetadata=fat,NtfsMetadata=false,LostPartitions=true,MetadataRescue=true,Signatures=false,EmbeddedPhotos=false,Containers=false,ArchiveMembers=false};}
    static string Run(string label,string image,RecoveryOptions options)
    {
        string before=Hash(image),output=Path.Combine(root,label);Directory.CreateDirectory(output);string checksum=Path.Combine(output,"baseline.sha256");File.WriteAllText(checksum,before);
        var result=RecoveryPipeline.Run(image,output,options,CancellationToken.None,null,checksum);
        Check(result.UniqueFiles>0&&File.Exists(result.FileCatalog),label+" publishes actual pipeline catalog");Check(Hash(image)==before,label+" keeps source image unchanged");return output;
    }
    static string CopyImage(string name,string fixture)
    {
        string source=Path.Combine(fixtures,fixture),before=Hash(source),image=Path.Combine(root,name+".dd");File.Copy(source,image);Check(Hash(source)==before&&Hash(image)==before,"copy preserves independent fixture "+fixture);return image;
    }
    static string Export(string folder,IEnumerable<RecoveredItem> items)
    {
        try{return (string)typeof(RecoveryCatalog).GetMethod("ExportFiles",BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,new object[]{folder,root,items,CancellationToken.None});}
        catch(TargetInvocationException error){throw error.InnerException;}
    }
    static IEnumerable<Dictionary<string,object>> Rows(object value){return ((IEnumerable)value).Cast<object>().Cast<Dictionary<string,object>>();}
    static void NativePathsAndExport()
    {
        string image=CopyImage("native-verified","path-verified.dd"),output=Run("native-verified-result",image,Options());var item=RecoveryCatalog.Load(output).Items.Single();
        Check(item.OriginalPath=="/Семья/Рецепты/Пирожки.txt"&&item.OriginalPathStatus=="verified_parent_chain","strict NTFS path reaches catalog unchanged");
        Check(item.SourceVolumeOffset==0&&item.OriginalLocations.Count==1&&item.OriginalLocations[0].VolumeOffset==0,"path source-volume zero is known rather than missing");
        Check(item.Name=="Пирожки.txt"&&!item.Name.StartsWith("record-",StringComparison.Ordinal),"display basename uses strict original filename");
        Check(item.OriginalLocations[0].CandidatePath==item.Path&&!String.IsNullOrEmpty(item.OriginalPathEvidence),"path evidence bound to actual candidate");
        string csv=File.ReadAllText(Path.Combine(output,"files-index.csv"));Check(csv.Contains("original_path")&&csv.Contains(item.OriginalPath)&&csv.Contains("original_volume_offset"),"CSV includes path and source volume");
        var export=Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(Export(output,new[]{item}),"export-manifest.json")));var record=Rows(export["files"]).Single();
        Check(Convert.ToString(export["status"])=="complete"&&Convert.ToString(record["originalPath"])==item.OriginalPath,"completed export retains strict original path");
        Check(Rows(record["originalLocations"]).Count()==1&&Convert.ToInt64(Rows(record["originalLocations"]).Single()["VolumeOffset"])==0,"export retains source-volume evidence");
        image=CopyImage("native-stale","path-stale_parent_reference.dd");output=Run("native-stale-result",image,Options());item=RecoveryCatalog.Load(output).Items.Single();
        Check(item.OriginalPath==null&&item.OriginalLocations.Count==0&&item.SourceVolumeOffset==null,"stale parent never promoted to catalog path");
        Check(item.Name.StartsWith("record-",StringComparison.Ordinal),"unknown name path leaves safe generated output name");
    }
    static void DuplicatePathsAndChangedOutputs()
    {
        string image=CopyImage("duplicate-paths","path-verified.dd");byte[] bytes=File.ReadAllBytes(image),record=new byte[1024];const int mft=4*4096;
        Buffer.BlockCopy(bytes,mft+42*1024,record,0,record.Length);Buffer.BlockCopy(BitConverter.GetBytes(43U),0,record,44,4);
        Buffer.BlockCopy(BitConverter.GetBytes(20L|(9L<<48)),0,record,80,8);Buffer.BlockCopy(record,0,bytes,mft+43*1024,record.Length);File.WriteAllBytes(image,bytes);
        string output=Run("duplicate-paths-result",image,Options());var index=RecoveryCatalog.Load(output);var item=index.Items.Single();
        Check(index.Candidates==2&&item.Copies.Count==1,"same content grouped without losing separate candidates");
        var paths=new HashSet<string>(item.OriginalLocations.Select(x=>x.Path),StringComparer.Ordinal);
        Check(paths.SetEquals(new[]{"/Семья/Рецепты/Пирожки.txt","/Семья/Пирожки.txt"}),"equal content retains both verified original directories");
        Check(item.OriginalLocations.All(x=>x.Status=="verified_parent_chain"&&x.VolumeOffset==0)&&item.OriginalLocations.Select(x=>x.CandidatePath).Distinct().Count()==2,"each alias retains candidate/volume/strictness");
        string csv=File.ReadAllText(Path.Combine(output,"files-index.csv"));Check(csv.Contains("all_original_paths")&&paths.All(csv.Contains),"CSV preserves every original alias path");
        string html=File.ReadAllText(Path.Combine(output,"Все файлы.html"));Check(html.Contains("OriginalLocations"),"offline HTML contains alias-aware search data");
        var export=Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(Export(output,new[]{item}),"export-manifest.json")));var exported=Rows(export["files"]).Single();
        Check(new HashSet<string>(Rows(exported["originalLocations"]).Select(x=>Convert.ToString(x["Path"]))).SetEquals(paths),"export manifest preserves all aliases");
        var evidence=FileEvidence.Load(output);evidence.Apply(item);evidence.Apply(item);Check(item.OriginalLocations.Count==2,"repeated evidence apply does not duplicate path claims");
        item.Sha256=new string('0',64);evidence.Apply(item);Check(item.OriginalPath==null&&item.OriginalLocations.Count==0&&item.SourceVolumeOffset==null&&!item.SourceOffset.HasValue&&item.SourceRanges.Count==0,"reused item cannot retain stale claims after changed hash");
        index=RecoveryCatalog.Load(output);item=index.Items.Single();string changed=item.Path;File.AppendAllText(RecoveryCatalog.SafeFile(output,changed)," changed after extraction");index=RecoveryCatalog.Build(output,CancellationToken.None,null);
        var altered=index.Items.Single(x=>x.Path==changed);Check(altered.Quality=="changed"&&altered.OriginalPath==null&&altered.OriginalLocations.Count==0,"changed output loses original folder proof");
        var untouched=index.Items.Single(x=>x.Path!=changed);Check(untouched.OriginalPathStatus=="verified_parent_chain"&&untouched.OriginalLocations.Count==1,"unchanged alias keeps only its current candidate proof");
    }
    static byte[] FatImage()
    {
        var image=new byte[256*512];image[0]=0xeb;image[1]=0x3c;image[2]=0x90;Encoding.ASCII.GetBytes("MSDOS5.0").CopyTo(image,3);
        BitConverter.GetBytes((ushort)512).CopyTo(image,11);image[13]=1;BitConverter.GetBytes((ushort)1).CopyTo(image,14);image[16]=1;BitConverter.GetBytes((ushort)32).CopyTo(image,17);BitConverter.GetBytes((ushort)256).CopyTo(image,19);image[21]=0xf8;BitConverter.GetBytes((ushort)1).CopyTo(image,22);image[510]=0x55;image[511]=0xaa;image[512]=0xf8;image[513]=0xff;image[514]=0xff;
        const int entry=1024;Encoding.ASCII.GetBytes("RECIPE  TXT").CopyTo(image,entry);image[entry]=0xe5;image[entry+11]=0x20;BitConverter.GetBytes((ushort)4).CopyTo(image,entry+26);BitConverter.GetBytes(700).CopyTo(image,entry+28);
        // Erased FAT chain: the real method must label consecutive free-cluster
        // reconstruction and unknown first filename character as candidates.
        for(int i=0;i<700;i++)image[4*512+(4-2)*512+i]=(byte)(i*37+11);return image;
    }
    static void FatAndPreferredStrictPath()
    {
        byte[] fat=FatImage();string image=Path.Combine(root,"fat-path.dd");File.WriteAllBytes(image,fat);var options=Options(true);options.MetadataRescue=false;string output=Run("fat-path-result",image,options);var item=RecoveryCatalog.Load(output).Items.Single();
        Check(item.OriginalPathStatus=="filesystem_candidate"&&item.OriginalPath!=null&&item.OriginalPath.EndsWith("ECIPE.TXT",StringComparison.Ordinal),"FAT recovered name stays a candidate with missing first character");
        Check(item.SourceVolumeOffset==0&&item.OriginalLocations.Single().Status!="verified_parent_chain"&&!String.IsNullOrEmpty(item.OriginalPathEvidence),"FAT name/volume evidence does not become strict NTFS proof");
        Check(item.Name.StartsWith("000001_",StringComparison.Ordinal),"candidate-only FAT path does not silently replace generated display basename");
        string before=Hash(Path.Combine(fixtures,"path-verified.dd"));byte[] native=File.ReadAllBytes(Path.Combine(fixtures,"path-verified.dd")),mixed=new byte[1024*1024+native.Length];Buffer.BlockCopy(fat,0,mixed,0,fat.Length);Buffer.BlockCopy(native,0,mixed,1024*1024,native.Length);image=Path.Combine(root,"mixed-paths.dd");File.WriteAllBytes(image,mixed);
        output=Run("mixed-paths-result",image,Options(true));var index=RecoveryCatalog.Load(output);item=index.Items.Single();
        Check(index.Candidates==2&&item.OriginalLocations.Count==2&&item.Copies.Count==1,"two-volume duplicate retains both independent metadata origins");
        Check(item.OriginalPath=="/Семья/Рецепты/Пирожки.txt"&&item.OriginalPathStatus=="verified_parent_chain"&&item.SourceVolumeOffset==1024*1024,"strict NTFS path preferred to earlier FAT candidate");
        Check(item.Name=="Пирожки.txt"&&item.OriginalLocations.Any(x=>x.Status=="filesystem_candidate"&&x.VolumeOffset==0),"preferred basename and alternate FAT path remain separately classified");
        Check(Hash(Path.Combine(fixtures,"path-verified.dd"))==before,"combined-image construction never changes reference fixture");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args.Length==0?Directory.GetCurrentDirectory():args[0]);fixtures=Directory.GetDirectories(Path.Combine(project,".build"),"metadata-rescue-tests-*").Where(x=>File.Exists(Path.Combine(x,"path-verified.dd"))).OrderByDescending(x=>x,StringComparer.Ordinal).First();
            root=Path.Combine(project,".build","folder-provenance-tests-"+DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ"));Directory.CreateDirectory(root);NativePathsAndExport();DuplicatePathsAndChangedOutputs();FatAndPreferredStrictPath();
            string summary="PASS FolderProvenance: "+checks+" assertions; real NTFS/FAT pipeline, strict vs candidate paths, hash-dedup aliases, source volumes, preferred names, changed-output proof removal, idempotent evidence, CSV/HTML/export provenance; synthetic regular image files only. Fixtures: "+root;
            Console.WriteLine(summary);File.WriteAllText(Path.Combine(project,"tests","FolderProvenanceTests.result.txt"),summary,new UTF8Encoding(false));return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
