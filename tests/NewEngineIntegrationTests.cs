using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class NewEngineIntegrationTests
{
    static int checks;
    static string project, root, archive, metadata;
    static void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
    static string Hash(string path) { using (var file = File.OpenRead(path)) using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant(); }
    static RecoveryOptions Only(bool archiveOnly)
    {
        return new RecoveryOptions { FatMetadata=false, NtfsMetadata=false, LostPartitions=false, Signatures=false, EmbeddedPhotos=false, Containers=false, TextFragments=false, MetadataRescue=!archiveOnly, ArchiveMembers=archiveOnly };
    }
    static string Input(string source, string directory, string name = "image.dd")
    {
        Directory.CreateDirectory(directory); string image = Path.Combine(directory, name); File.Copy(source, image); File.SetAttributes(image, FileAttributes.Normal);
        File.WriteAllText(image + ".sha256", Hash(image) + "  image.dd\n", new UTF8Encoding(false)); return image;
    }
    static RecoveryFileIndex Run(string name, string source, bool archiveOnly, out string output)
    {
        string test = Path.Combine(root, name), image = Input(source, Path.Combine(test, "input")), before = Hash(image); output = Path.Combine(test, "result"); Directory.CreateDirectory(output);
        ScanResult result = RecoveryPipeline.Run(image, output, Only(archiveOnly), CancellationToken.None, s => {});
        Check(Hash(image) == before, name + " source image unchanged");
        Check(File.Exists(result.Gallery) && File.Exists(result.FileCatalog) && File.Exists(Path.Combine(output, "Все файлы.html")), name + " local catalogs published");
        Check(!Directory.Exists(Path.Combine(output, "filesystem")) && !Directory.Exists(Path.Combine(output, "ntfs")) && !Directory.Exists(Path.Combine(output, "files.1")), name + " disabled methods not run");
        var index = RecoveryCatalog.Load(output);
        Check(index.Candidates == result.Candidates && index.Items.Count == result.UniqueFiles, name + " count consistency");
        Check(!Directory.GetFiles(output,"*.partial",SearchOption.AllDirectories).Any(), name + " no partial artifact exposed");
        return index;
    }
    static void Archives()
    {
        string output; var index = Run("archive-only", Path.Combine(archive,"mixed-no-central.dd"), true, out output);
        Check(index.Candidates == 4 && index.Items.Count == 4, "archive member outputs included");
        Check(index.Items.All(x => x.Path.StartsWith("salvage-content/",StringComparison.Ordinal) && x.Method=="Часть ZIP / Office" && x.Quality=="member_crc"), "archive source and CRC part status retained");
        Check(index.Items.Where(x=>x.Bytes>0).All(x=>x.SourceOffset.HasValue && x.SourceRanges.Count==1), "compressed source ranges retained");
        Check(index.Items.Any(x=>x.Extension==".txt"&&x.Category=="Документы"), "archive text categorized as document");
        var evidence=FileEvidence.Load(output); Check(index.Items.Where(x=>x.Bytes>0).All(x=>evidence.For(x.Path)!=null),"archive provenance readable");
        string changedRelative=index.Items.First(x=>x.Bytes>0&&x.Extension==".txt").Path;
        File.WriteAllText(RecoveryCatalog.SafeFile(output,changedRelative),"modified after extraction",new UTF8Encoding(false));
        var rebuilt=RecoveryCatalog.Build(output,CancellationToken.None,s=>{});
        Check(rebuilt.Items.Single(x=>x.Path==changedRelative).Quality!="member_crc","changed member cannot inherit stale CRC success from its directory name");
        index = Run("bad-archive",Path.Combine(archive,"bad-crc.dd"),true,out output);
        Check(index.Candidates==0&&index.Items.Count==0,"bad archive CRC never becomes successful member");
    }
    static void Metadata()
    {
        string output; var index=Run("resident-only",Path.Combine(metadata,"resident.dd"),false,out output);
        Check(index.Candidates==1&&index.Items.Count==1,"resident output included");var resident=index.Items.Single();
        Check(resident.Path.StartsWith("metadata-rescue/files/",StringComparison.Ordinal)&&resident.Method=="Независимые записи NTFS"&&resident.Category=="Документы","resident category and method");
        Check(resident.SourceOffset==8*1024*1024,"resident record offset provenance");
        var parsed=new JavaScriptSerializer().Deserialize<MetadataRescue.Report>(File.ReadAllText(Path.Combine(output,"metadata-rescue","report.json")));
        Check(parsed.Entries.Single().Status=="resident_candidate"&&resident.Quality!="container_crc", "resident record never promoted to verified original content");
        Check(resident.SourceRanges.Count==0 || !FileEvidence.Load(output).For(resident.Path).MappingComplete,"resident USA transformations not asserted as exact byte mapping");
        index=Run("nonresident-only",Path.Combine(metadata,"fragmented.dd"),false,out output);
        var file=index.Items.Single();Check(file.Bytes==5500&&file.SourceRanges.Count==2,"fragmented stream and both image ranges included");
        Check(file.SourceRanges[0].Offset==45*4096&&file.SourceRanges[1].Offset==40*4096&&file.SourceRanges.Sum(x=>x.Length)==5500,"physical extents exact and logical bytes conserved");
        Check(File.ReadAllBytes(RecoveryCatalog.SafeFile(output,file.Path)).SequenceEqual(Enumerable.Range(0,5500).Select(i=>(byte)(i*37+11))),"fragmented payload exact known independent bytes");
        index=Run("allocated-cluster",Path.Combine(metadata,"reused-first.dd"),false,out output);
        Check(index.Candidates==0&&index.Items.Count==0,"currently allocated first cluster never published");
        index=Run("partial-cluster",Path.Combine(metadata,"reused-second.dd"),false,out output);
        Check(index.Items.Single().Quality=="partial"&&index.Items.Single().Bytes==4096,"free prefix explicitly partial in catalog");
        index=Run("torn-record",Path.Combine(metadata,"bad-usa-tail.dd"),false,out output);
        Check(index.Candidates==0&&index.Items.Count==0,"torn record never successful candidate");
    }
    static void SourceCollisions()
    {
        foreach(string name in new[]{"search-options.json","files-index.json","photo-catalog.json"}) {
            string directory=Path.Combine(root,"collision-"+name),image=Input(Path.Combine(archive,"mixed-no-central.dd"),directory,name),before=Hash(image);bool rejected=false;
            try { RecoveryPipeline.Run(image,directory,Only(true),CancellationToken.None,s=>{}); } catch(IOException) { rejected=true; }
            Check(rejected,"colliding source/report operation rejected: "+name);Check(Hash(image)==before,"source unchanged through all report publication: "+name);
        }
    }
    static void Cancellation()
    {
        string test=Path.Combine(root,"cancel"),image=Input(Path.Combine(archive,"block-boundary.dd"),Path.Combine(test,"input")),before=Hash(image),output=Path.Combine(test,"result");Directory.CreateDirectory(output);var cancellation=new CancellationTokenSource();bool cancelled=false;
        try { RecoveryPipeline.Run(image,output,Only(true),cancellation.Token,s=>{if(s.StartsWith("Части архивов:",StringComparison.Ordinal))cancellation.Cancel();}); } catch(OperationCanceledException) { cancelled=true; }
        Check(cancelled&&Hash(image)==before,"pipeline cancellation preserves original");
        Check(File.ReadAllText(Path.Combine(output,"scan-stages.json")).Contains("cancelled"),"pipeline cancellation checkpoint");
        Check(!File.Exists(Path.Combine(output,"files-index.json"))&&!Directory.GetFiles(output,"*.partial",SearchOption.AllDirectories).Any(),"cancelled pipeline publishes no successful final catalog or partial member");
    }
    static string ErrorInput(string source,string name,long at,int bytes,out string output)
    {
        string test=Path.Combine(root,name),image=Input(source,Path.Combine(test,"input"));
        // These zeroed bytes and their error map are fixture construction,
        // performed before the read-only recovery run and its source digest.
        using(var file=new FileStream(image,FileMode.Open,FileAccess.Write,FileShare.None)){file.Position=at;file.Write(new byte[bytes],0,bytes);}
        File.WriteAllText(image+".sha256",Hash(image)+"  image.dd\n",new UTF8Encoding(false));
        File.WriteAllText(image+".read-errors.json",new JavaScriptSerializer().Serialize(new{unreadBytes=bytes,ranges=new[]{new{Offset=at,Length=bytes}}}),new UTF8Encoding(false));
        output=Path.Combine(test,"result");Directory.CreateDirectory(output);return image;
    }
    static void ReadErrorMetadata()
    {
        string output;
        // In this independent fixture $Bitmap is resident in MFT record6.
        // Byte5 contains cluster45's allocated bit. Its zero replacement
        // would falsely turn the live first data cluster into a free cluster.
        long bitmapByte=4*4096+6*1024+184+5;
        string image=ErrorInput(Path.Combine(metadata,"reused-first.dd"),"bitmap-hole",bitmapByte,1,out output),before=Hash(image);
        var result=RecoveryPipeline.Run(image,output,Only(false),CancellationToken.None,s=>{});var index=RecoveryCatalog.Load(output);
        Check(result.HasWarnings&&result.Candidates==0&&index.Items.Count==0,"unread bitmap cannot establish a free cluster or successful nonresident recovery");
        Check(Hash(image)==before,"bitmap-hole source unchanged");
        image=ErrorInput(Path.Combine(metadata,"resident.dd"),"resident-hole",8*1024*1024+225,12,out output);before=Hash(image);
        result=RecoveryPipeline.Run(image,output,Only(false),CancellationToken.None,s=>{});index=RecoveryCatalog.Load(output);var resident=index.Items.Single();
        Check(result.HasWarnings&&resident.SourceRanges.Count==0&&resident.UnreadBytes==null,"resident USA source map remains explicitly unknown on image holes");
        Check(resident.Quality=="mapping_unknown"&&resident.IntegrityDetail.Contains("не установлено"),"resident output never asserts absence of holes");
        Check(Hash(image)==before,"resident-hole source unchanged");
        image=ErrorInput(Path.Combine(archive,"mixed-no-central.dd"),"archive-header-hole",53+10,2,out output);before=Hash(image);
        result=RecoveryPipeline.Run(image,output,Only(true),CancellationToken.None,s=>{});index=RecoveryCatalog.Load(output);
        Check(index.Items.Any(x=>x.SourceOffset==53&&x.Quality=="read_errors"&&x.UnreadBytes==2),"archive header holes intersect encoded ZIP member provenance");
        Check(index.Items.Where(x=>x.Bytes==0).All(x=>x.SourceOffset.HasValue&&x.SourceRanges.Count>0),"empty ZIP member retains encoded-header provenance");
        Check(Hash(image)==before,"archive-header-hole source unchanged");
    }
    public static int Main(string[] args)
    {
        try {
            project=Path.GetFullPath(args.Length>0?args[0]:Directory.GetCurrentDirectory());archive=Path.Combine(project,".build","archive-salvage-tests");
            metadata=Directory.GetDirectories(Path.Combine(project,".build"),"metadata-rescue-tests-*").Where(d=>File.Exists(Path.Combine(d,"fragmented.dd"))).OrderByDescending(d=>d,StringComparer.Ordinal).First();
            root=Path.Combine(project,".build","new-engine-integration-"+DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ"));Directory.CreateDirectory(root);
            Archives();Metadata();SourceCollisions();Cancellation();ReadErrorMetadata();
            string summary="PASS NewEngineIntegration: "+checks+" checks; standalone-only pipeline selection, catalogs/provenance/categories, archive CRC rejection, resident/fragmented/allocated/partial/torn NTFS, report-source name collisions, cancellation; synthetic regular images only. Results: "+root;
            Console.WriteLine(summary);File.WriteAllText(Path.Combine(root,"result.txt"),summary,Encoding.UTF8);File.WriteAllText(Path.Combine(project,"tests","NewEngineIntegrationTests.result.txt"),summary,Encoding.UTF8);return 0;
        } catch(Exception error) { Console.Error.WriteLine(error);return 1; }
    }
}
