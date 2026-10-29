using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ContentQualityTests
{
    static int checks;static string output;
    static void Check(bool value,string text){checks++;if(!value)throw new Exception(text);}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static string ExportSynthetic(string run,string destination,IEnumerable<RecoveredItem> items)
    {
        try{return (string)typeof(RecoveryCatalog).GetMethod("ExportFiles",System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.Public|System.Reflection.BindingFlags.NonPublic).Invoke(null,new object[]{run,destination,items,CancellationToken.None});}
        catch(System.Reflection.TargetInvocationException error){throw error.InnerException;}
    }
    public static int Main(string[] args)
    {
        try{
            string fixtures=Path.Combine(args[0],"tests","QualityFixtures");output=Path.Combine(args[0],"tests","QualityResults-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));Directory.CreateDirectory(output);
            var cases=new JavaScriptSerializer().Deserialize<List<Dictionary<string,string>>>(File.ReadAllText(Path.Combine(fixtures,"cases.json")));
            foreach(var row in cases){string path=Path.Combine(fixtures,row["path"]),before=Hash(path);var result=ContentVerifier.Verify(path,CancellationToken.None);Check(result.Code==row["expected"],row["path"]+": "+result.Code+" != "+row["expected"]);Check(before==Hash(path),"verification does not write "+row["path"]);Check(!String.IsNullOrEmpty(result.Detail),"explicit evidence/limit");}
            using(var token=new CancellationTokenSource()){token.Cancel();bool stopped=false;try{ContentVerifier.Verify(Path.Combine(fixtures,"deflate.docx"),token.Token);}catch(OperationCanceledException){stopped=true;}Check(stopped,"validation cancels before file read");}
            var fat=new FilesystemRecoveryTests.FatFixture(12);byte[] bytes=Encoding.UTF8.GetBytes(new string('A',700));fat.Entry(0,"RECIPE  TXT",4,bytes.Length,true,false);fat.SetFat(4,6);fat.SetFat(6,fat.End);Buffer.BlockCopy(bytes,0,fat.Bytes,fat.Cluster(4),512);Buffer.BlockCopy(bytes,512,fat.Bytes,fat.Cluster(6),188);
            string image=Path.Combine(output,"fragmented.dd"),run=Path.Combine(output,"filesystem-test");File.WriteAllBytes(image,fat.Bytes);Directory.CreateDirectory(run);string original=Hash(image);FilesystemRecovery.Recover(image,run,CancellationToken.None,null);
            var found=RecoveryCore.RecoveredFiles(run).ToList();Check(found.Count==1,"fragmented FAT fixture produces one candidate");Check(File.ReadAllBytes(found[0]).SequenceEqual(bytes),"FAT payload reconstructed by retained chain");
            File.Copy(Path.Combine(fixtures,"stored.zip"),Path.Combine(Path.GetDirectoryName(found[0]),"additional.zip"));
            RecoveryCore.SaveJson(Path.Combine(run,"source-read-errors.json"),new{unreadBytes=10,ranges=new[]{new UnreadRange{Offset=fat.Cluster(6)+10,Length=10}}});PhotoCatalog.Build(run,CancellationToken.None,null);var index=RecoveryCatalog.Build(run,CancellationToken.None,null);var item=index.Items.First(x=>x.Extension==".TXT"||x.Extension==".txt");
            Check(item.SourceRanges.Count==2,"file has two physical source ranges");Check(item.SourceRanges[0].Offset==fat.Cluster(4)&&item.SourceRanges[0].Length==512&&item.SourceRanges[1].Offset==fat.Cluster(6)&&item.SourceRanges[1].Length==188,"range lengths follow exact logical file length");Check(item.UnreadBytes==10&&item.Quality=="read_errors","only intersecting unread bytes reported");Check(index.Items.First(x=>x.Extension==".zip").UnreadBytes==null,"unknown mapping never reported as no overlap");Check(item.IntegrityDetail.Contains("Подтверждено пересечение"),"explicit mapped provenance");
            RecoveryCore.SaveJson(Path.Combine(run,"source-read-errors.json"),new{unreadBytes=10,ranges=new[]{new UnreadRange{Offset=fat.Cluster(6)+300,Length=10}}});index=RecoveryCatalog.Build(run,CancellationToken.None,null);item=index.Items.First(x=>x.Extension.Equals(".txt",StringComparison.OrdinalIgnoreCase));Check(item.UnreadBytes==0,"sector slack outside logical bytes does not taint file");Check(item.Quality!="read_errors","file outside holes not given read-error verdict");Check(Hash(image)==original,"mapping never writes source image");
            string exported=ExportSynthetic(run,output,new[]{item});Check(File.ReadAllText(Path.Combine(exported,"export-manifest.json")).Contains("sourceRanges"),"export keeps verification and extent evidence");
            RecoveryCore.SaveJson(Path.Combine(run,"source-read-errors.json"),new{unreadBytes=10,ranges=new[]{new UnreadRange{Offset=fat.Cluster(6)+10,Length=10},new UnreadRange{Offset=fat.Cluster(6)+10,Length=10}}});var evidence=FileEvidence.Load(run);Check(evidence.Intersections(new[]{new FileExtent{Offset=fat.Cluster(6),Length=188},new FileExtent{Offset=fat.Cluster(6),Length=188}})==10,"overlapping map/source ranges counted once");
            RecoveryCore.SaveJson(Path.Combine(run,"source-read-errors.json"),new{unreadBytes=99,ranges=new[]{new UnreadRange{Offset=fat.Cluster(6)+10,Length=10}}});index=RecoveryCatalog.Build(run,CancellationToken.None,null);Check(index.Items.First(x=>x.Extension.Equals(".txt",StringComparison.OrdinalIgnoreCase)).UnreadBytes==null,"inconsistent error map cannot produce exact byte verdict");
            File.AppendAllText(RecoveryCatalog.SafeFile(run,item.Path),"changed after recovery");index=RecoveryCatalog.Build(run,CancellationToken.None,null);var changed=index.Items.First(x=>x.Extension.Equals(".txt",StringComparison.OrdinalIgnoreCase));Check(changed.Quality=="changed"&&changed.SourceRanges.Count==0&&!changed.SourceOffset.HasValue,"modified filesystem file loses stale provenance map");Check(Hash(image)==original,"changing synthetic output cannot change image");
            string journal=Path.Combine(output,"atomic.json");for(int i=0;i<25;i++)RecoveryCore.SaveJson(journal,new{counter=i,status="valid"});Check(File.ReadAllText(journal).Contains("24"),"atomic reports replace last complete snapshot");Check(Directory.GetFiles(output,"*.partial").Length==0,"atomic reports leave no temporary file");
            Console.WriteLine("Content quality: "+checks+" checks passed; "+output);return 0;
        }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
    }
}
