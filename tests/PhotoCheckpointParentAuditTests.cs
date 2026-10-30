using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class PhotoCheckpointParentAuditTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static bool Io(Action run){try{run();return false;}catch(IOException){return true;}}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true};}
    static PhotoRecoveryCheckpoint Cp(string root,long sequence,string content)
    {
        string path=Path.Combine(root,"fragmented-photos.state","checkpoint-"+sequence.ToString("D12")+".json");Directory.CreateDirectory(Path.GetDirectoryName(path));File.WriteAllText(path,content,new UTF8Encoding(false));return new PhotoRecoveryCheckpoint{Path=path,Sha256=Hash(path),Sequence=sequence};
    }
    static void CallbackFailure()
    {
        using(var stop=new CancellationTokenSource(TimeSpan.FromSeconds(2))){
            var watch=Stopwatch.StartNew();bool cancelled=false,failed=false;
            try{HelperClient.Run(Assembly.GetExecutingAssembly().Location,new{operation="audit_callback_fault"},stop.Token,s=>{},update=>{throw new IOException("PRIVATE_CALLBACK_DIAGNOSTIC");});}
            catch(OperationCanceledException){cancelled=true;}catch(IOException error){failed=true;Check(!error.Message.Contains("PRIVATE"),"Rejected callback diagnostics are scrubbed");}
            Check(failed&&!cancelled&&watch.ElapsedMilliseconds<1500,"A rejected checkpoint callback must stop its child promptly, without waiting for cancellation/pipe deadlock");
        }
    }
    static void TerminalProgress()
    {
        int callbacks=0;var result=HelperClient.Run(Assembly.GetExecutingAssembly().Location,new{operation="audit_late_progress"},CancellationToken.None,s=>{},update=>callbacks++);
        Check(result.Status=="complete"&&callbacks==0,"Progress arriving after terminal helper result cannot mutate a completed operation's checkpoint state");
    }
    static void Envelope(string work,string source)
    {
        string root=Path.Combine(work,"envelope");Directory.CreateDirectory(root);var session=RecoverySession.Start(root,source,Hash(source),Options(),CancellationToken.None);session.Begin("fragmented-photos");
        var first=Cp(root,1,"{\"owned\":1}");session.CapturePhotoCheckpoint(first);string state=Hash(Path.Combine(root,RecoverySession.FileName));
        foreach(string unsafePath in new[]{Path.Combine(work,"elsewhere.json"),Path.Combine(root,"fragmented-photos.state","checkpoint-000000000001.json:stream"),Path.Combine(root,"fragmented-photos.state","CHECKPOINT-000000000001.json"),first.Path+"\0"}){
            bool rejected=false;try{session.CapturePhotoCheckpoint(new PhotoRecoveryCheckpoint{Path=unsafePath,Sha256=first.Sha256,Sequence=1});}catch(IOException){rejected=true;}catch(ArgumentException){rejected=true;}catch(NotSupportedException){rejected=true;}
            Check(rejected&&Hash(Path.Combine(root,RecoverySession.FileName))==state,"Malformed/external callback never changes acknowledged state");
        }
        session.Fail("fragmented-photos","cancelled",null);var next=Cp(root,2,"{\"owned\":2}");Check(Io(()=>session.CapturePhotoCheckpoint(next)),"Delayed callback after cancellation rejected");
        var reopened=RecoverySession.Open(root,source,Options(),CancellationToken.None,null);reopened.Begin("fragmented-photos",true);Check(reopened.PhotoCheckpoint().Sequence==1,"Unacknowledged generation2 never supersedes external anchor1");
        string payload=Path.Combine(root,"fragmented-photos","owned.jpg.partial");Directory.CreateDirectory(Path.GetDirectoryName(payload));File.WriteAllText(payload,"owned partial");string before=Hash(payload);
        File.AppendAllText(first.Path,"tamper");Check(Io(()=>reopened.Begin("fragmented-photos",true)),"Tampered anchor rejects Begin before output moves");Check(File.Exists(payload)&&Hash(payload)==before&&!Directory.Exists(Path.Combine(root,"attempt-history")),"Rejected continuation preserves unfinished payload and history state");
    }
    static void ReportBindingLocal(string root,string source)
    {
        string helper=HelperClient.Executable;Directory.CreateDirectory(Path.GetDirectoryName(helper));
        if(File.Exists(helper))throw new IOException("Independent audit requires an isolated helper directory");
        File.Copy(Assembly.GetExecutingAssembly().Location,helper);
        string library=typeof(RecoverySession).Assembly.Location;File.Copy(library,Path.Combine(Path.GetDirectoryName(helper),Path.GetFileName(library)));
        Directory.CreateDirectory(root);string before=Hash(source);
        foreach(string mode in new[]{"valid","source-changed","foreign-source-sha","report-limited-result-complete","report-complete-result-partial","complete-marker-present","candidate-sha","candidate-size","candidate-map-bytes","candidate-map-bounds","candidate-map-overlap","candidate-map-gap","candidate-output-total","valid-limited"}){
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(helper),"own-audit-mode.txt"),mode);
            string output=Path.Combine(root,mode);Directory.CreateDirectory(output);bool failed=false;int candidates=-1;
            try{candidates=FragmentedPhotoRecovery.Recover(source,output,CancellationToken.None,null);}catch(IOException error){failed=true;Check(!error.Message.Contains("PRIVATE"),mode+": child diagnostics scrubbed");}
            Check(failed==(mode!="valid"),mode+": contradictory helper report cannot complete parent stage");
            string manifest=Path.Combine(output,"fragmented-photo-search.json");
            if(mode=="valid")Check(candidates==1&&File.Exists(manifest),"Coherent source-bound candidate report published");
            else if(mode=="valid-limited")Check(File.Exists(manifest)&&File.ReadAllText(manifest).Contains("limited"),"Coherent partial report retained while parent stage remains incomplete");
            else Check(!File.Exists(manifest),mode+": invalid evidence not promoted to parent manifest");
            Check(Hash(source)==before,mode+": source bytes unchanged");
        }
        Console.WriteLine("REPORT_CHECKS="+checks);
    }
    static void ReportBinding(string work,string source)
    {
        string runtime=Path.Combine(work,"isolated-runtime"),root=Path.Combine(work,"report-binding");Directory.CreateDirectory(runtime);
        string executable=Path.Combine(runtime,"PhotoCheckpointParentAuditTests.exe");File.Copy(Assembly.GetExecutingAssembly().Location,executable);
        string library=typeof(RecoverySession).Assembly.Location;File.Copy(library,Path.Combine(runtime,Path.GetFileName(library)));
        using(var process=Process.Start(new ProcessStartInfo(executable,"--isolated-report-probe \""+root+"\" \""+source+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true})){
            if(!process.WaitForExit(10000)){process.Kill();throw new IOException("Owned report-binding probe timed out");}
            string diagnostic=process.StandardError.ReadToEnd(),output=process.StandardOutput.ReadToEnd();Check(process.ExitCode==0,"Isolated report binding failed: "+diagnostic);
            string count=output.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Single(x=>x.StartsWith("REPORT_CHECKS=",StringComparison.Ordinal));checks+=Int32.Parse(count.Substring("REPORT_CHECKS=".Length));
        }
    }
    static void GalleryIsolation(string work)
    {
        string root=Path.Combine(work,"gallery");Directory.CreateDirectory(root);
        string[] names={"fragmented-photos/owned.png","fragmented-photos.state/orphan-1/unacknowledged.png","attempt-history/prior/fragmented-photos/previous.png","attempt-history/prior/fragmented-photos.state/orphan-2/unacknowledged.png"};
        foreach(string name in names){string path=Path.Combine(root,name.Replace('/',Path.DirectorySeparatorChar));Directory.CreateDirectory(Path.GetDirectoryName(path));using(var bitmap=new Bitmap(4,4))bitmap.Save(path,ImageFormat.Png);}
        var json=new JavaScriptSerializer();PhotoCatalog.Build(root,CancellationToken.None,null);var catalog=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(root,"photo-catalog.json")));
        Check(Convert.ToInt32(catalog["candidates"])==2,"Active/history metadata orphans never enter photo candidate count");
        Check(RecoveryCore.RecoveredFiles(root).Count()==2&&!RecoveryCore.RecoveredFiles(root).Any(x=>x.Contains("fragmented-photos.state")),"Export file enumeration excludes active and historical checkpoint storage");
    }
    static int Child()
    {
        Console.InputEncoding=Encoding.UTF8;Console.OutputEncoding=new UTF8Encoding(false);var json=new JavaScriptSerializer();var request=json.Deserialize<Dictionary<string,object>>(Console.ReadLine());
        if(Convert.ToString(request["operation"])=="audit_late_progress"){
            Console.WriteLine("{\"type\":\"result\",\"status\":\"complete\",\"code\":\"OK\"}");Console.WriteLine("{\"type\":\"progress\",\"phase\":\"photo_checkpoint\",\"checkpoint_path\":\"late-checkpoint\",\"checkpoint_sequence\":7}");return 0;
        }
        if(Convert.ToString(request["operation"])=="fragmented_photos"){
            string output=Convert.ToString(request["destination"]),source=Convert.ToString(request["source"]),mode=File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"own-audit-mode.txt"));Directory.CreateDirectory(output);
            byte[] image=File.ReadAllBytes(source);int length=Int32.Parse(File.ReadAllText(source+".owned-fixture-length")),cut=length/2;
            byte[] payload=new byte[length];Array.Copy(image,1024,payload,0,cut);Array.Copy(image,8192,payload,cut,length-cut);string filename="png-"+HashBytes(payload)+".png";File.WriteAllBytes(Path.Combine(output,filename),payload);
            bool limited=mode=="report-limited-result-complete"||mode=="valid-limited";
            if(mode=="complete-marker-present"||mode=="valid-limited")File.WriteAllText(Path.Combine(output,"job.incomplete"),"");
            int second=mode=="candidate-map-bytes"?8200:mode=="candidate-map-bounds"?image.Length+1:mode=="candidate-map-overlap"?1024:8192;
            File.WriteAllText(Path.Combine(output,"report.json"),json.Serialize(new{Schema=1,Status=limited?"limited":"complete",SourceSha256=mode=="foreign-source-sha"?new string('0',64):Hash(source),SourceUnchanged=mode!="source-changed",Candidates=1,OutputBytes=mode=="candidate-output-total"?payload.Length+1:payload.Length,
                Files=new[]{new{Path=filename,Sha256=mode=="candidate-sha"?new string('0',64):HashBytes(payload),Bytes=mode=="candidate-size"?payload.Length+1:payload.Length,Status="png_crc_zlib_reassembled_candidate",Extents=new[]{new{ImageOffset=1024,LogicalOffset=0,Length=cut},new{ImageOffset=second,LogicalOffset=mode=="candidate-map-gap"?cut+1:cut,Length=length-cut}}}}}));
            Console.Error.WriteLine("PRIVATE_CHILD_DIAGNOSTIC");Console.WriteLine(json.Serialize(new{type="result",status=mode=="report-complete-result-partial"||mode=="valid-limited"?"partial":"complete",code="OK"}));return 0;
        }
        Console.WriteLine("{\"type\":\"progress\",\"phase\":\"photo_checkpoint\",\"checkpoint_path\":\"invalid-checkpoint\",\"checkpoint_sha256\":\"bad\",\"checkpoint_sequence\":1}");Console.Out.Flush();Thread.Sleep(30000);return 0;
    }
    static string HashBytes(byte[] bytes){using(var hash=System.Security.Cryptography.SHA256.Create())return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
    public static int Main(string[] args)
    {
        if(args.Length==0)return Child();
        if(args.Length==3&&args[0]=="--isolated-report-probe"){try{ReportBindingLocal(args[1],args[2]);return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}}
        try{
            string project=Path.GetFullPath(args[0]),work=Path.Combine(project,".build","photo-parent-audit-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);string source=Path.Combine(work,"owned-source.dd");var sourceBytes=new byte[65536];int payloadLength;
            using(var image=new Bitmap(4,4))using(var memory=new MemoryStream()){image.Save(memory,ImageFormat.Png);byte[] png=memory.ToArray();payloadLength=png.Length;int cut=png.Length/2;Array.Copy(png,0,sourceBytes,1024,cut);Array.Copy(png,cut,sourceBytes,8192,png.Length-cut);}
            File.WriteAllBytes(source,sourceBytes);File.WriteAllText(source+".owned-fixture-length",payloadLength.ToString());string sourceSha=Hash(source);
            if(args.Contains("--callback")){CallbackFailure();return 0;}
            if(args.Contains("--terminal")){TerminalProgress();return 0;}
            if(args.Contains("--report")){ReportBinding(work,source);return 0;}
            Envelope(work,source);CallbackFailure();TerminalProgress();GalleryIsolation(work);ReportBinding(work,source);Check(Hash(source)==sourceSha,"All parent audit operations preserve source bytes");
            Console.WriteLine("PASS PhotoCheckpointParentAudit: "+checks+" independent checks; callback failure lifecycle, immutable external anchor, malformed paths, late events and unchanged interrupted output.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
