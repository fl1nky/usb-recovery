using System;
using System.IO;
using System.Linq;
using System.Threading;
using UsbRecovery;

public static class UsbPackagedTests
{
    static int checks;
    static void Check(bool value,string label){checks++;if(!value)throw new Exception(label);}
    static string Hash(string file){return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{});}
    static string Run(string image,string directory,RecoveryOptions options)
    {
        Directory.CreateDirectory(directory);string checksum=Path.Combine(directory,"baseline.sha256");File.WriteAllText(checksum,Hash(image));using(var cancel=new CancellationTokenSource(45000)){var result=RecoveryPipeline.Run(image,directory,options,cancel.Token,s=>{},checksum);Check(result.Candidates>0&&result.UniqueFiles>0,"bundled pipeline produces files");Check(result.HasWarnings,"external baseline never claims original capture completeness");Check(File.Exists(result.Gallery)&&File.Exists(result.FileCatalog),"photo and general catalogs published");}return directory;
    }
    public static int Main(string[] args)
    {
        string old=Environment.GetEnvironmentVariable("__COMPAT_LAYER");Environment.SetEnvironmentVariable("__COMPAT_LAYER","RunAsInvoker");string root=Path.Combine(Path.GetTempPath(),"UsbPackaged-synthetic-"+Guid.NewGuid().ToString("N"));
        try {
            string project=Path.GetFullPath(args[0]),image=Path.Combine(project,"tests","DeepRecoveryWork","containers.dd"),before=Hash(image);
            var options=new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,EmbeddedPhotos=false,Signatures=true,Containers=true,Other=false,Photos=true,Documents=true,Video=false,Audio=false,Archives=false};string output=Run(image,Path.Combine(root,"containers"),options);
            var files=RecoveryCatalog.Load(output);Check(files.Items.Any(x=>x.Extension==".docx")&&files.Items.Any(x=>x.Extension==".pdf")&&files.Items.Any(x=>x.Extension==".webp"),"unaligned document/photo containers present");Check(Hash(image)==before,"container input unchanged");
            image=Path.Combine(project,"tests","AdvancedNtfs.dd");before=Hash(image);output=Run(image,Path.Combine(root,"ntfs"),new RecoveryOptions{FatMetadata=false,NtfsMetadata=true,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false});
            string expected=Path.Combine(project,"tests","photorec-20261011T231546120952Z","fixtures","expected.jpg");Check(RecoveryCore.RecoveredFiles(output).Any(p=>Hash(p)==Hash(expected)),"bundled NTFS undelete exact fragmented JPEG");Check(Hash(image)==before,"NTFS input unchanged");Check(!File.Exists(image+".sha256")||File.Exists(Path.Combine(output,"baseline.sha256")),"checksums retained in output");
            string textImage=Path.Combine(root,"text-image.dd");File.WriteAllBytes(textImage,new byte[]{0,0,255,255,0,0}.Concat(System.Text.Encoding.UTF8.GetBytes("Важный семейный рецепт пирожков")).Concat(new byte[]{0,0,255,255,0,0}).ToArray());before=Hash(textImage);
            output=Run(textImage,Path.Combine(root,"text-result"),new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,TextFragments=true,TextQuery="рецепт пирожков"});Check(RecoveryCatalog.Load(output).Items.Single().Status=="Фрагмент, не документ","packaged raw-text method and explicit uncertainty");Check(Hash(textImage)==before,"packaged text source unchanged");
            Console.WriteLine("PASS "+checks+" packaged USB assertions; actual bundled PhotoRec/TestDisk, synthetic files only. Results: "+root);return 0;
        }catch(Exception error){Console.WriteLine("FAIL "+error);return 1;}finally{Environment.SetEnvironmentVariable("__COMPAT_LAYER",old);}
    }
}
