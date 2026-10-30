using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class MediaDecodeWorkerTests
{
    static int checks;static string project,work,input;static readonly List<object> evidence=new List<object>();
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=256*1024,RecursionLimit=16};
    static void Check(bool pass,string why){checks++;if(!pass)throw new Exception(why);}
    static string Hash(string path){using(var file=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static MediaFoundationValidator.DecodeLimits Limits(){return new MediaFoundationValidator.DecodeLimits();}
    static string Request(string source){return Json.Serialize(new{protocol=1,operation="media_decode",source=source,limits=Limits()});}
    static MediaFoundationValidator.DecodeReport Decode(string path,MediaFoundationValidator.DecodeLimits limits=null,CancellationToken token=default(CancellationToken),Action<MediaFoundationValidator.DecodeProgress> progress=null)
    {
        var report=MediaDecodeWorker.Validate(path,limits??Limits(),token,progress);Check(!report.StrictIntegrityEstablished&&!report.OwnershipAuthenticated,"worker cannot elevate decoding into authenticated recovery");Check(!report.LimitsAreCooperative,"worker reports hard process boundary in addition to cooperative decode limits");evidence.Add(new{test=Path.GetFileName(path),report=report});return report;
    }
    static MediaFoundationValidator.DecodeReport Fake(string mode,int milliseconds=800,string request="go",long memory=768L*1024*1024)
    {
        var method=typeof(MediaDecodeWorker).GetMethod("RunTransport",BindingFlags.Static|BindingFlags.NonPublic);Check(method!=null,"internal transport can test a separate fake executable without a product test switch");var clock=Stopwatch.StartNew();
        var report=(MediaFoundationValidator.DecodeReport)method.Invoke(null,new object[]{Assembly.GetExecutingAssembly().Location,"--fake-"+mode,request,milliseconds,memory,Limits(),CancellationToken.None,null});Check(clock.ElapsedMilliseconds<milliseconds+4000,"hard worker result returns within deadline and bounded cleanup");Check(report.Status!="decoded_soft"&&!report.OwnershipAuthenticated&&!report.StrictIntegrityEstablished,"adversarial worker never creates success");evidence.Add(new{test="fake-"+mode,report=report,wall_ms=clock.ElapsedMilliseconds});return report;
    }
    static int FakeMain(string mode)
    {
        if(mode=="grandchild"){Thread.Sleep(20000);return 4;}
        if(mode=="no-read"){Thread.Sleep(20000);return 4;}
        string request=Console.ReadLine();
        if(mode=="hang"){File.WriteAllText(request,Process.GetCurrentProcess().Id.ToString());Thread.Sleep(20000);return 4;}
        if(mode=="tree"){
            using(var child=Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--fake-grandchild"){UseShellExecute=false,CreateNoWindow=true})){
                File.WriteAllText(request,Process.GetCurrentProcess().Id+"\n"+child.Id);Thread.Sleep(20000);return 4;
            }
        }
        if(mode=="memory"){
            try{var allocated=new List<byte[]>();for(int n=0;n<40;n++){byte[] bytes=new byte[8*1024*1024];for(int at=0;at<bytes.Length;at+=4096)bytes[at]=1;allocated.Add(bytes);}GC.KeepAlive(allocated);File.WriteAllText(request,"LIMIT_NOT_ENFORCED");return 4;}
            catch(OutOfMemoryException){File.WriteAllText(request,"LIMIT_ENFORCED");Console.WriteLine("{}");return 0;}
        }
        if(mode=="stderr"){string chunk=new string('x',4080)+"PRIVATE_CANARY";for(int n=0;n<1024;n++)Console.Error.Write(chunk);Console.Error.Flush();Console.WriteLine("{}");return 0;}
        if(mode=="large-line"){Console.WriteLine(new string('x',50000));Console.Out.Flush();Thread.Sleep(20000);return 4;}
        if(mode=="too-many"){for(int n=0;n<2000;n++)Console.WriteLine("{\"protocol\":1,\"type\":\"progress\",\"phase\":\"decode\",\"stream\":0,\"samples\":0,\"bytes\":0}");Thread.Sleep(20000);return 4;}
        if(mode=="duplicate"){Console.WriteLine("{\"protocol\":1,\"protoc\\u006fl\":1,\"type\":\"result\",\"report\":{}}");return 0;}
        if(mode=="strict"){
            var report=new MediaFoundationValidator.DecodeReport{Status="decoded_soft",Code="MF_ALL_STREAMS_DECODED_SOFT",StrictIntegrityEstablished=true};Console.WriteLine(Json.Serialize(new{protocol=1,type="result",report=report}));return 0;
        }
        if(mode=="after-result"){
            var report=new MediaFoundationValidator.DecodeReport{Status="error",Code="MF_TEST_ERROR"};Console.WriteLine(Json.Serialize(new{protocol=1,type="result",report=report}));Console.WriteLine("{}");return 0;
        }
        if(mode=="bad-phase"){Console.WriteLine("{\"protocol\":1,\"type\":\"progress\",\"phase\":\"PRIVATE_CANARY\",\"stream\":0,\"samples\":0,\"bytes\":0}");return 0;}
        Console.WriteLine("{}");return 0;
    }
    static void ProductProtocol(string request,string expected="MF_PROTOCOL_INVALID",string extra="")
    {
        using(var process=new Process{StartInfo=new ProcessStartInfo(typeof(Program).Assembly.Location,"--media-decode-worker"+extra){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=new UTF8Encoding(false,true)}}){
            Check(process.Start(),"actual product early worker route started");byte[] bytes=new UTF8Encoding(false).GetBytes(request+"\n");try{process.StandardInput.BaseStream.Write(bytes,0,bytes.Length);}catch(IOException){}finally{try{process.StandardInput.Close();}catch(IOException){}}bool ended=process.WaitForExit(5000);if(!ended){process.Kill();throw new Exception("Malformed worker protocol must not enter UI or hang");}
            string output=process.StandardOutput.ReadToEnd(),error=process.StandardError.ReadToEnd();Check(output.Length<32768&&error.Length==0&&!output.Contains("PRIVATE_CANARY"),"bounded protocol error emits own code without input or diagnostics");var row=Json.DeserializeObject(output.Trim()) as Dictionary<string,object>;Check(row!=null&&(string)row["type"]=="result","invalid request produces exactly one terminal result");var report=Json.ConvertToType<MediaFoundationValidator.DecodeReport>(row["report"]);Check(report.Status=="error"&&report.Code==expected&&!report.AllStreamsEnded&&!report.OwnershipAuthenticated&&!report.StrictIntegrityEstablished,"invalid protocol cannot claim decode success");Check(process.ExitCode==0,"handled protocol rejection exits cleanly");
        }
    }
    static void ActualProduct()
    {
        string before=Hash(input);var report=Decode(input);Check(report.Status=="decoded_soft"&&report.Code=="MF_ALL_STREAMS_DECODED_SOFT","real AVC+AAC decodes in actual child product executable");Check(report.SourceUnchanged&&report.AllStreamsEnded&&report.SourceSha256==before,"all child streams reach EOS and source hash is recorded");Check(report.Streams.Single(s=>s.Kind=="video").VideoFrames==12,"actual child decodes twelve H.264 frames");Check(report.Streams.Single(s=>s.Kind=="audio").PcmFrames==97280,"actual child decodes all AAC packets to PCM");Check(Hash(input)==before,"input unchanged after actual child decode");
        string unicode=Path.Combine(work,"пирожки прабабушки.mp4");File.Copy(input,unicode);var repeat=Decode(unicode);Check(repeat.Status=="decoded_soft"&&repeat.SourceSha256==report.SourceSha256,"UTF8 stdin preserves Unicode source path");foreach(var stream in report.Streams)Check(repeat.Streams.Single(s=>s.Kind==stream.Kind).DecodedSha256==stream.DecodedSha256,"child decode hashes stable across Unicode copy");
        var bytes=Decode(input,new MediaFoundationValidator.DecodeLimits{MaxInputBytes=64});Check(bytes.Status=="limited"&&bytes.Code=="MF_INPUT_BYTES_LIMIT","child source byte cap is retained as limited");
        var decoded=Decode(input,new MediaFoundationValidator.DecodeLimits{MaxDecodedBytes=16});Check(decoded.Status=="limited"&&decoded.Code=="MF_OUTPUT_BYTES_LIMIT"&&!decoded.AllStreamsEnded,"child decoded-byte cap cannot become complete");
        var pixels=Decode(input,new MediaFoundationValidator.DecodeLimits{MaxPixels=1});Check(pixels.Status=="limited"&&pixels.Code=="MF_PIXEL_LIMIT","child pixel cap remains distinct from process protocol failure");
        var frames=Decode(input,new MediaFoundationValidator.DecodeLimits{MaxVideoFrames=1});Check(frames.Status=="limited"&&frames.Code=="MF_FRAME_COUNT_LIMIT","child frame cap remains limited");
        using(var cancel=new CancellationTokenSource()){cancel.Cancel();var cancelled=Decode(input,null,cancel.Token);Check(cancelled.Status=="cancelled"&&cancelled.Code=="MF_CANCELLED","pre-cancel avoids child source work");}
        using(var cancel=new CancellationTokenSource()){bool signalled=false;var cancelled=Decode(input,null,cancel.Token,p=>{if(p.Phase=="preflight"){signalled=true;cancel.Cancel();}});Check(signalled&&cancelled.Status=="cancelled"&&cancelled.Code=="MF_CANCELLED"&&!cancelled.AllStreamsEnded,"cancellation after actual child progress kills job and cannot claim complete");}
        var bad=Decode(input,Limits(),CancellationToken.None,p=>{throw new InvalidOperationException("PRIVATE_CANARY");});Check(bad.Status=="error"&&bad.Code=="MF_WORKER_PROTOCOL_ERROR"&&!Json.Serialize(bad).Contains("PRIVATE_CANARY"),"callback failure stops isolated child without diagnostic leak");
        Check(Hash(input)==before,"limits and cancellation leave source unchanged");Check(Limits().MaxDecodedBytes==64L*1024*1024*1024,"default streaming output budget supports more than a few HD frames");bool rejected=false;try{Decode(input,new MediaFoundationValidator.DecodeLimits{MaxDecodedBytes=256L*1024*1024*1024+1});}catch(ArgumentException){rejected=true;}Check(rejected,"decoded-byte ceiling remains bounded at256GiB");
    }
    static void AdversarialTransport()
    {
        string marker=Path.Combine(work,"hang-pid.txt");var hang=Fake("hang",800,marker);Check(hang.Status=="limited"&&hang.Code=="MF_WORKER_TIMEOUT","non-cooperative fake worker is hard-terminated");Check(File.Exists(marker),"timeout child reached stdin barrier only after job attached");int pid=Int32.Parse(File.ReadAllText(marker));bool alive;try{using(var p=Process.GetProcessById(pid))alive=!p.HasExited;}catch(ArgumentException){alive=false;}Check(!alive,"timed-out process is not left running");
        var blocked=Fake("no-read",300,new string('x',16000));Check(blocked.Code=="MF_WORKER_TIMEOUT","blocked stdin write cannot bypass hard deadline");
        string tree=Path.Combine(work,"tree-pids.txt");var descendants=Fake("tree",1200,tree);Check(descendants.Code=="MF_WORKER_TIMEOUT"&&File.Exists(tree),"inherited child tree reaches bounded deadline");foreach(string value in File.ReadAllLines(tree)){try{using(var p=Process.GetProcessById(Int32.Parse(value)))alive=!p.HasExited;}catch(ArgumentException){alive=false;}Check(!alive,"job terminates all descendant processes");}
        foreach(string mode in new[]{"large-line","too-many","duplicate","strict","after-result","bad-phase"}){var report=Fake(mode,1500);Check(report.Status=="error"&&report.Code=="MF_WORKER_PROTOCOL_ERROR","malformed/oversized/false-strict child result rejected: "+mode);}
        var stderr=Fake("stderr",5000);Check(stderr.Code=="MF_WORKER_PROTOCOL_ERROR"&&!Json.Serialize(stderr).Contains("PRIVATE_CANARY"),"megabytes of stderr drained in discarded chunks without content leaks");
        string memory=Path.Combine(work,"memory-result.txt");var limited=Fake("memory",5000,memory,96L*1024*1024);Check(limited.Status=="error"&&File.Exists(memory)&&File.ReadAllText(memory)=="LIMIT_ENFORCED","actual Windows committed-memory cap stops controlled allocation");
    }
    static void ProtocolCases()
    {
        foreach(string bad in new[]{"not-json","[]","{}","{\"protocol\":1,\"protocol\":1}","{\"protocol\":1,\"protoc\\u006fl\":1}",new string('x',17000),new string('\r',17000),Request("PRIVATE_CANARY").Replace("protocol","proto\rcol"),Request("PRIVATE_CANARY")+"\n{}"})ProductProtocol(bad);
        string request=Request("PRIVATE_CANARY");ProductProtocol(request.Replace("\"protocol\":1","\"protocol\":2"));ProductProtocol(request.Replace("\"protocol\":1","\"protocol\":\"1\""));ProductProtocol(request.Replace("\"media_decode\"","\"unknown\""));ProductProtocol(request.Replace("\"MaxPixels\":16000000","\"MaxPixels\":0"));ProductProtocol(request.Replace("\"MaxDecodedBytes\":68719476736","\"MaxDecodedBytes\":274877906945"));ProductProtocol(request.Replace("\"MaxPixels\":16000000","\"MaxPixels\":16000000.5"));ProductProtocol(request.Replace("\"source\":","\"unexpected\":0,\"source\":"));ProductProtocol(request,"MF_PROTOCOL_INVALID"," --extra");
        foreach(string path in new[]{"//invalid.invalid/share/a.mp4","\\\\invalid.invalid\\share\\a.mp4","\\\\?\\GLOBALROOT\\Device\\Harddisk0\\a.mp4","https://invalid.invalid/a.mp4"}){var clock=Stopwatch.StartNew();var report=Decode(path);Check(report.Status=="unsupported"&&!report.AllStreamsEnded&&clock.ElapsedMilliseconds<3000,"network/device source rejected before file probes");}
    }
    public static int Main(string[] args)
    {
        if(args.Length>0&&args[0].StartsWith("--fake-",StringComparison.Ordinal))return FakeMain(args[0].Substring(7));
        try{project=args.Length>0?Path.GetFullPath(args[0]):Directory.GetCurrentDirectory();work=Path.Combine(project,".build","mf-worker-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);input=Path.Combine(project,".build","fragmented-media-audio-tests","phone-fast.mp4");Check(File.Exists(input),"independent real FFmpeg AVC/AAC fixture is available");ActualProduct();ProtocolCases();AdversarialTransport();File.WriteAllText(Path.Combine(work,"worker-evidence.json"),Json.Serialize(evidence),new UTF8Encoding(false));Console.WriteLine("PASS MediaDecodeWorker: "+checks+" checks; actual isolated product, native H264/AAC, cancellation, hard timeout/tree kill, memory cap, hostile protocol. Soft evidence only.");Console.WriteLine(work);return 0;}
        catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
