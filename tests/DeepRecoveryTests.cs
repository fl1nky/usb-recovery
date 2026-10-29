using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class DeepRecoveryTests
{
    static string root;static int checks;
    static void Check(bool v,string name){checks++;if(!v)throw new Exception(name);}
    static string Hash(string p){return RecoveryCore.HashFile(p,CancellationToken.None,(a,b)=>{});}
    static string Hash(byte[] b){using(var s=SHA256.Create())return BitConverter.ToString(s.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
    static void W16(byte[] b,int p,int v){BitConverter.GetBytes((ushort)v).CopyTo(b,p);}
    static void W32(byte[] b,int p,uint v){BitConverter.GetBytes(v).CopyTo(b,p);}
    static string Save(string name,byte[] data){string p=Path.Combine(root,name);File.WriteAllBytes(p,data);return p;}
    static byte[] Payload(){byte[] b=new byte[1700];new Random(135).NextBytes(b);return b;}
    static string RunFs(string image,string label,bool alternate){string output=Path.Combine(root,label);Directory.CreateDirectory(output);var boots=BootScout.Find(image,CancellationToken.None,null);FilesystemRecovery.Recover(image,output,CancellationToken.None,null,boots,alternate);return output;}
    static void Metadata()
    {
        byte[] content=Payload();var fat=new FilesystemRecoveryTests.FatFixture(12);fat.Put(content,30,true);fat.Entry(0,"RECIPE  TXT",30,content.Length,true,false);
        int prefix=4*1024*1024;byte[] wrapped=new byte[prefix+fat.Bytes.Length];Buffer.BlockCopy(fat.Bytes,0,wrapped,prefix,fat.Bytes.Length);string image=Save("lost-fat.dd",wrapped),before=Hash(image);
        var boots=BootScout.Find(image,CancellationToken.None,null);Check(boots.Any(b=>b.Offset==prefix),"full sweep finds FAT beyond old 1MiB fallback");string output=RunFs(image,"lost-fat",false);Check(RecoveryCore.RecoveredFiles(output).Any(p=>Hash(p)==Hash(content)),"lost FAT fragmented payload exact");Check(Hash(image)==before,"FAT source unchanged");
        var f32=new FilesystemRecoveryTests.FatFixture(32);f32.Put(content,30,true);f32.Entry(0,"BACKUP  TXT",30,content.Length,true,false);W16(f32.Bytes,50,6);W32(f32.Bytes,28,(uint)(prefix/512));Buffer.BlockCopy(f32.Bytes,0,f32.Bytes,6*512,512);Array.Clear(f32.Bytes,0,512);wrapped=new byte[prefix+f32.Bytes.Length];Buffer.BlockCopy(f32.Bytes,0,wrapped,prefix,f32.Bytes.Length);image=Save("backup-fat.dd",wrapped);boots=BootScout.Find(image,CancellationToken.None,null);Check(boots.Any(x=>x.Offset==prefix&&x.BootOffset==prefix+3072),"backup FAT32 boot detected without source repair");output=RunFs(image,"backup-fat",false);Check(RecoveryCore.RecoveredFiles(output).Any(p=>Hash(p)==Hash(content)),"FAT32 backup restores exact fragmented file");
        var ex=new FilesystemRecoveryTests.ExFixture();ex.Entry(1,"Семейный рецепт.txt",30,content,true,false,content.Length);BitConverter.GetBytes((ulong)(prefix/512)).CopyTo(ex.Bytes,64);ex.UpdateBootChecksum();Buffer.BlockCopy(ex.Bytes,0,ex.Bytes,12*512,12*512);Array.Clear(ex.Bytes,0,512);wrapped=new byte[prefix+ex.Bytes.Length];Buffer.BlockCopy(ex.Bytes,0,wrapped,prefix,ex.Bytes.Length);image=Save("backup-exfat.dd",wrapped);output=RunFs(image,"backup-exfat",false);Check(RecoveryCore.RecoveredFiles(output).Any(p=>Hash(p)==Hash(content)),"exFAT backup checksum and original data-base offset respected");
        var f16=new FilesystemRecoveryTests.FatFixture(16);f16.Put(content,30,true);f16.Entry(0,"SECOND  TXT",30,content.Length,true,false);int fatBytes=f16.FatSectors*512;byte[] second=new byte[f16.Bytes.Length+fatBytes];Buffer.BlockCopy(f16.Bytes,0,second,0,f16.RootStart);Buffer.BlockCopy(f16.Bytes,f16.FatStart,second,f16.RootStart,fatBytes);Buffer.BlockCopy(f16.Bytes,f16.RootStart,second,f16.RootStart+fatBytes,f16.Bytes.Length-f16.RootStart);second[16]=2;W16(second,19,second.Length/512);W16(second,f16.FatStart+30*2,1);image=Save("fat-second.dd",second);before=Hash(image);output=RunFs(image,"fat-second",true);Check(RecoveryCore.RecoveredFiles(output).Any(p=>Hash(p)==Hash(content)),"second FAT copy restores chain when first copy is broken");Check(Hash(image)==before,"alternative FAT never written to original");
    }
    static void Containers(string project)
    {
        string image=Path.Combine(project,"tests","DeepRecoveryWork","containers.dd"),before=Hash(image),output=Path.Combine(root,"containers-result");Directory.CreateDirectory(output);
        int found=ContainerCarver.Recover(image,output,new RecoveryOptions(),CancellationToken.None,null);var expected=new JavaScriptSerializer().Deserialize<List<Dictionary<string,object>>>(File.ReadAllText(Path.Combine(project,"tests","DeepRecoveryWork","containers-expected.json")));
        Check(found==expected.Count,"unaligned containers recovered, false/truncated headers rejected");foreach(var e in expected){string file=Path.Combine(output,"containers","offset-"+Convert.ToInt64(e["offset"]).ToString("D16")+Convert.ToString(e["extension"]));Check(File.Exists(file)&&Hash(file)==Convert.ToString(e["sha256"]),"container exact bytes "+e["extension"]);}
        Check(Hash(image)==before,"container source unchanged");Check(File.ReadAllText(Path.Combine(output,"container-search.json")).Contains("structure_only"),"container structure not claimed payload validity");
        var options=new RecoveryOptions{Other=false,Photos=false,Video=false,Audio=false,Archives=false,Documents=true};string narrow=Path.Combine(root,"only-documents");Directory.CreateDirectory(narrow);Check(ContainerCarver.Recover(image,narrow,options,CancellationToken.None,null)==2,"container type selection works");
        var mp4=expected.First(x=>Convert.ToString(x["extension"])==".mp4");long start=Convert.ToInt64(mp4["offset"]);byte[] all=File.ReadAllBytes(image);string exact=Save("video-at-image-end.dd",all.Skip((int)start).Take(Convert.ToInt32(mp4["bytes"])).ToArray());string endOutput=Path.Combine(root,"video-end");Directory.CreateDirectory(endOutput);Check(ContainerCarver.Recover(exact,endOutput,new RecoveryOptions(),CancellationToken.None,null)==1,"BMFF eight-byte terminal atom at image EOF");
        bool cancelled=false;using(var token=new CancellationTokenSource()){token.Cancel();try{ContainerCarver.Recover(image,Path.Combine(root,"cancel-container"),options,token.Token,null);}catch(OperationCanceledException){cancelled=true;}}Check(cancelled,"container cancellation");
    }
    sealed class FaultyStream:MemoryStream
    {
        public bool Once;int failures;public FaultyStream(byte[] b):base(b,false){}
        public override int Read(byte[] b,int at,int count){if(Position<1536&&Position+count>1024&&(!Once||failures++<3))throw new IOException("synthetic bad sector");return base.Read(b,at,count);}
    }
    static void Rescue()
    {
        byte[] data=new byte[65536];new Random(22).NextBytes(data);string partial=Path.Combine(root,"rescue.partial"),map=Path.Combine(root,"rescue-map.json");
        using(var input=new FaultyStream(data)){var result=ResilientCapture.Copy(input,partial,data.Length,512,map,CancellationToken.None,null,()=>true);Check(result.UnreadBytes==512&&result.Ranges.Count==1&&result.Ranges[0].Offset==1024,"unread sector precisely mapped");var expected=(byte[])data.Clone();Array.Clear(expected,1024,512);Check(Hash(partial)==Hash(expected)&&Hash(partial)==result.Sha256,"only unread sector zero-filled and digest matches");Check(File.ReadAllText(map).Contains("complete_with_read_errors"),"unread copy never called complete original");}
        using(var input=new FaultyStream(data){Once=true}){var result=ResilientCapture.Copy(input,Path.Combine(root,"transient.partial"),data.Length,512,Path.Combine(root,"transient-map.json"),CancellationToken.None,null,()=>true);Check(result.UnreadBytes==0&&result.Sha256==Hash(data),"transient sector succeeds on bounded retry");}
        bool disconnected=false;using(var input=new FaultyStream(data))try{ResilientCapture.Copy(input,Path.Combine(root,"disconnect.partial"),data.Length,512,Path.Combine(root,"disconnect-map.json"),CancellationToken.None,null,()=>false);}catch(IOException){disconnected=true;}Check(disconnected,"disconnect cannot become fabricated full image");
        bool truncated=false;using(var input=new MemoryStream(data,false))try{ResilientCapture.Copy(input,Path.Combine(root,"short.partial"),data.Length+512,512,Path.Combine(root,"short-map.json"),CancellationToken.None,null,null);}catch(EndOfStreamException){truncated=true;}Check(truncated,"EOF is hard failure, not zero fill");
        using(var input=new MemoryStream(data,false))using(var token=new CancellationTokenSource()){bool stopped=false;try{ResilientCapture.Copy(input,Path.Combine(root,"cancel.partial"),data.Length,512,Path.Combine(root,"cancel-map.json"),token.Token,(a,b)=>token.Cancel(),null);}catch(OperationCanceledException){stopped=true;}Check(stopped&&File.ReadAllText(Path.Combine(root,"cancel-map.json")).Contains("cancelled"),"cancelled imaging has explicit map state");}
    }
    static void Catalog()
    {
        string output=Path.Combine(root,"catalog");Directory.CreateDirectory(Path.Combine(output,"files.1"));Directory.CreateDirectory(Path.Combine(output,"filesystem","files"));byte[] bytes=Encoding.UTF8.GetBytes("Семейный рецепт");Save("unused",bytes);File.WriteAllBytes(Path.Combine(output,"files.1","f001.txt"),bytes);File.WriteAllBytes(Path.Combine(output,"filesystem","files","recipe.txt"),bytes);File.WriteAllBytes(Path.Combine(output,"files.1","=formula.csv"),new byte[]{1,2,3});
        PhotoCatalog.Build(output,CancellationToken.None,null);var index=RecoveryCatalog.Build(output,CancellationToken.None,null);Check(index.Candidates==3&&index.Items.Count==2,"deduplicate by SHA only, retain copies");Check(index.Items.Any(i=>i.Copies.Count==1),"all aliases retained");Check(File.ReadAllText(Path.Combine(output,"files-index.csv")).Contains("'=formula.csv"),"CSV cells cannot execute formulas");Check(File.ReadAllText(Path.Combine(output,"Все файлы.html")).Contains("connect-src 'none'"),"catalog HTML offline and no active input");
        Check(index.Items.First(i=>i.Copies.Count==1).Name=="recipe.txt","metadata filename preferred over PhotoRec name");
        string export=RecoveryCatalog.ExportFiles(output,root,index.Items,CancellationToken.None);Check(Directory.GetFiles(export).Length==3&&File.ReadAllText(Path.Combine(export,"export-manifest.json")).Contains("complete"),"selected copies and provenance manifest exported");Check(RecoveryCore.RecoveredFiles(output).Count()==3,"export never deletes or renames originals");File.AppendAllText(Path.Combine(output,index.Items[0].Path.Replace('/',Path.DirectorySeparatorChar)),"changed");bool rejected=false;try{RecoveryCatalog.ExportFiles(output,root,new[]{index.Items[0]},CancellationToken.None);}catch(IOException){rejected=true;}Check(rejected,"changed payload blocked before export success");bool traversal=false;try{RecoveryCatalog.SafeFile(output,"../private.txt");}catch(IOException){traversal=true;}Check(traversal,"archive path traversal rejected");
        File.WriteAllText(Path.Combine(output,"files-index.json"),"{broken");bool malformed=false;try{RecoveryCatalog.Load(output);}catch(IOException){malformed=true;}Check(malformed,"incomplete catalog reported as controlled error");
    }
    static void NativeFormats(string project)
    {
        string old=Environment.GetEnvironmentVariable("__COMPAT_LAYER");Environment.SetEnvironmentVariable("__COMPAT_LAYER","RunAsInvoker");try{
            string image=Path.Combine(project,"tests","DeepRecoveryWork","containers.dd");
            foreach(string group in new[]{"photos","video","audio","documents","archives","all"}) {
                var options=new RecoveryOptions{Other=group=="all",Photos=group=="photos",Video=group=="video",Audio=group=="audio",Documents=group=="documents",Archives=group=="archives",SmallBlocks=true};string output=Path.Combine(root,"native-"+group);Directory.CreateDirectory(output);using(var cancel=new CancellationTokenSource(30000)){RecoveryCore.Recover(image,output,false,cancel.Token,n=>{},options);Check(!File.ReadAllText(Path.Combine(output,"photorec.log")).Contains("Syntax error"),"actual PhotoRec command group "+group);}
            }
        }finally{Environment.SetEnvironmentVariable("__COMPAT_LAYER",old);}
    }
    static void LostNtfs(string project)
    {
        string original=Path.Combine(project,"tests","AdvancedNtfs.dd");int prefix=4*1024*1024;byte[] content=File.ReadAllBytes(original);W32(content,28,(uint)(prefix/512));W32(content,content.Length-512+28,(uint)(prefix/512));byte[] wrapped=new byte[prefix+content.Length];Buffer.BlockCopy(content,0,wrapped,prefix,content.Length);string source=Save("lost-ntfs.dd",wrapped),before=Hash(source);var boots=BootScout.Find(source,CancellationToken.None,null);Check(boots.Any(b=>b.Kind=="NTFS"&&b.Offset==prefix&&b.Length==content.Length),"lost NTFS boot and sector-count semantics");
        string compatibility=Environment.GetEnvironmentVariable("__COMPAT_LAYER");Environment.SetEnvironmentVariable("__COMPAT_LAYER","RunAsInvoker");try{
            using(var cancel=new CancellationTokenSource(30000)){string output=Path.Combine(root,"lost-ntfs");Check(AdvancedEngines.RecoverNtfs(source,output,cancel.Token,null,boots)==1,"lost NTFS copied to disposable view and undeleted");string expected=Path.Combine(project,"tests","photorec-20261011T231546120952Z","fixtures","expected.jpg");Check(AdvancedEngines.NtfsRecoveredFiles(output).Any(p=>Hash(p)==Hash(expected)),"lost NTFS fragmented JPEG exact hash");Check(!Directory.GetFiles(output,"working-partition.dd",SearchOption.AllDirectories).Any(),"working NTFS views cleaned");}
            Check(Hash(source)==before,"lost NTFS source unchanged");Array.Clear(wrapped,prefix,512);source=Save("backup-ntfs.dd",wrapped);before=Hash(source);boots=BootScout.Find(source,CancellationToken.None,null);Check(boots.Any(b=>b.Kind=="NTFS"&&b.Offset==prefix&&b.BootOffset>prefix),"NTFS backup identifies lost base");using(var cancel=new CancellationTokenSource(30000)){string output=Path.Combine(root,"backup-ntfs");Check(AdvancedEngines.RecoverNtfs(source,output,cancel.Token,null,boots)==1,"NTFS backup applied only to working view");}Check(Hash(source)==before,"backup recovery never repairs source");
        }finally{Environment.SetEnvironmentVariable("__COMPAT_LAYER",compatibility);}
    }
    static void Pipeline()
    {
        string source=Path.Combine(root,"lost-fat.dd");File.WriteAllText(source+".sha256",Hash(source));string output=Path.Combine(root,"pipeline");Directory.CreateDirectory(output);var options=new RecoveryOptions{FatMetadata=true,NtfsMetadata=false,LostPartitions=true,Signatures=false,EmbeddedPhotos=false,Containers=false};var result=RecoveryPipeline.Run(source,output,options,CancellationToken.None,s=>{});Check(result.Candidates==1&&result.UniqueFiles==1,"selected-method pipeline produces complete file catalog");string stages=File.ReadAllText(Path.Combine(output,"scan-stages.json"));Check(!stages.Contains("PhotoRec")&&!Directory.Exists(Path.Combine(output,"ntfs")),"disabled engines not run");Check(File.Exists(result.FileCatalog)&&File.Exists(Path.Combine(output,"search-options.json")),"selected options and file index retained");
        string external=Path.Combine(root,"external.img");File.Copy(source,external);string externalResult=Path.Combine(root,"external-result");Directory.CreateDirectory(externalResult);string check=Path.Combine(externalResult,"source-image.sha256");File.WriteAllText(check,Hash(external));result=RecoveryPipeline.Run(external,externalResult,options,CancellationToken.None,s=>{},check);Check(result.HasWarnings&&result.Candidates==1&&!File.Exists(external+".sha256"),"external IMG baseline checksum written only in result and quality unknown");
        RecoveryCore.SaveJson(source+".read-errors.json",new{status="complete_with_read_errors",unreadBytes=512,ranges=new[]{new UnreadRange{Offset=512,Length=512}}});string mapped=Path.Combine(root,"mapped-result");Directory.CreateDirectory(mapped);bool metadataBlocked=false;try{RecoveryPipeline.Run(source,mapped,options,CancellationToken.None,s=>{});}catch(IOException){metadataBlocked=true;}Check(metadataBlocked&&!Directory.Exists(Path.Combine(mapped,"filesystem"))&&File.ReadAllText(Path.Combine(mapped,"scan-stages.json")).Contains("skipped_read_errors"),"unread allocation metadata cannot manufacture verified-free clusters");
        byte[] mappedData=File.ReadAllBytes(source),photo;using(var bitmap=new System.Drawing.Bitmap(32,32))using(var stream=new MemoryStream()){bitmap.Save(stream,System.Drawing.Imaging.ImageFormat.Png);photo=stream.ToArray();}Buffer.BlockCopy(photo,0,mappedData,2048,photo.Length);string mappedImage=Save("mapped-source.dd",mappedData);File.WriteAllText(mappedImage+".sha256",Hash(mappedImage));RecoveryCore.SaveJson(mappedImage+".read-errors.json",new{status="complete_with_read_errors",unreadBytes=512,ranges=new[]{new UnreadRange{Offset=512,Length=512}}});mapped=Path.Combine(root,"mapped-carving-result");Directory.CreateDirectory(mapped);options.EmbeddedPhotos=true;result=RecoveryPipeline.Run(mappedImage,mapped,options,CancellationToken.None,s=>{});Check(result.HasWarnings&&RecoveryCatalog.Load(mapped).Items.Single().Status=="Образ с пропусками","content carving continues and map warning survives reanalysis");
        bool partial=false;try{RecoveryPipeline.Run(source+".partial",output,options,CancellationToken.None,s=>{});}catch(IOException){partial=true;}Check(partial,"partial image never accepted by pipeline");
    }
    public static int Main(string[] args)
    {
        root=Path.Combine(Path.GetFullPath(args[0]),"tests","Deep-results-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));Directory.CreateDirectory(root);
        try{Metadata();Containers(args[0]);Rescue();Catalog();NativeFormats(args[0]);LostNtfs(args[0]);Pipeline();Console.WriteLine("PASS "+checks+" deep-recovery assertions. Synthetic images/streams only. Results: "+root);return 0;}catch(Exception e){Console.WriteLine("FAIL "+e);return 1;}
    }
}
