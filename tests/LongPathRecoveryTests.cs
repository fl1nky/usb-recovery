using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class LongPathRecoveryTests
{
    static int checks;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Hash(string path){using(var stream=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args[0]),deep=Path.Combine(project,".build","long-path-"+Guid.NewGuid().ToString("N"));
            while(deep.Length<320)deep=Path.Combine(deep,new string('d',40));
            Directory.CreateDirectory(deep);
            byte[] payload=Encoding.UTF8.GetBytes("Synthetic family recipe\n"+new string('A',700));
            string original;using(var sha=SHA256.Create())original=BitConverter.ToString(sha.ComputeHash(payload)).Replace("-","").ToLowerInvariant();
            var fixture=new FilesystemRecoveryTests.FatFixture(12);
            fixture.Entry(0,"RECIPE  TXT",4,payload.Length,true,false);fixture.SetFat(4,6);fixture.SetFat(6,fixture.End);
            Buffer.BlockCopy(payload,0,fixture.Bytes,fixture.Cluster(4),512);Buffer.BlockCopy(payload,512,fixture.Bytes,fixture.Cluster(6),payload.Length-512);
            string image=Path.Combine(deep,"source.dd"),run=Path.Combine(deep,"result");File.WriteAllBytes(image,fixture.Bytes);string before=Hash(image);
            Check(image.Length>260,"test source exceeds classic Windows path limit");
            FilesystemRecovery.Recover(image,run,CancellationToken.None,null);
            string found=Directory.GetFiles(Path.Combine(run,"filesystem","files"),"*",SearchOption.AllDirectories).Single(x=>Hash(x)==original);
            Check(found.Length>260&&File.ReadAllBytes(found).SequenceEqual(payload),"fragmented FAT content is recovered through a long destination");
            PhotoCatalog.Build(run,CancellationToken.None,null);var catalog=RecoveryCatalog.Build(run,CancellationToken.None,null);
            var item=catalog.Items.Single(x=>x.Sha256==original);
            Check(item.SourceRanges.Count==2,"long path preserves both physical source ranges");
            string exported;
            try{exported=(string)typeof(RecoveryCatalog).GetMethod("ExportFiles",BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic).Invoke(null,new object[]{run,Path.Combine(deep,"export"),new[]{item},CancellationToken.None});}
            catch(TargetInvocationException error){throw error.InnerException;}
            string copied=Directory.GetFiles(exported,"*",SearchOption.AllDirectories).Single(x=>Hash(x)==original);
            Check(copied.Length>260&&File.ReadAllBytes(copied).SequenceEqual(payload),"long export contains exact original bytes");
            Check(File.Exists(Path.Combine(exported,"export-manifest.json")),"long export publishes provenance manifest");
            item.Name="a."+new string('x',200);
            string longNameExport;
            try{longNameExport=(string)typeof(RecoveryCatalog).GetMethod("ExportFiles",BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic).Invoke(null,new object[]{run,Path.Combine(deep,"long-extension"),new[]{item},CancellationToken.None});}
            catch(TargetInvocationException error){throw error.InnerException;}
            string longNameFile=Directory.GetFiles(longNameExport,"*",SearchOption.AllDirectories).Single(x=>Hash(x)==original);
            Check(Path.GetFileName(longNameFile).Length<=255&&File.ReadAllBytes(longNameFile).SequenceEqual(payload),"valid long extension never creates an oversized output component");
            Check(Hash(image)==before,"long source image remains unchanged");
            Console.WriteLine("PASS LongPathRecovery: "+checks+" checks; actual fragmented FAT recovery, source ranges, export and immutable regular image at paths over 320 characters; no system policy changes.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
