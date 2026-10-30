using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // One local decode per isolated process. No input path, limits or media
    // metadata is passed on the command line, logged or written to a job file.
    public static class MediaDecodeWorker
    {
        const int MaximumRequest=16384,MaximumLine=32768,MaximumOutput=256*1024,MaximumEvents=1024;
        const long ProcessMemory=768L*1024*1024;
        static readonly string Note="Decoded in a separate process with a Windows memory job and hard wall deadline. EOS and decoded hashes are soft evidence: codecs may conceal damage. Original integrity, ownership and deletion remain unauthenticated.";
        static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=MaximumOutput,RecursionLimit=16};}
        sealed class ProtocolFailure:Exception {}
        static bool Digest(string value){return value!=null&&Regex.IsMatch(value,"\\A[a-f0-9]{64}\\z",RegexOptions.CultureInvariant);}
        static bool OwnCode(string value){return value!=null&&Regex.IsMatch(value,"\\AMF_[A-Z0-9_]{1,80}\\z",RegexOptions.CultureInvariant);}
        static MediaFoundationValidator.DecodeReport Failed(string status,string code)
        {return new MediaFoundationValidator.DecodeReport{Status=status,Code=code,LimitsAreCooperative=false,Note=Note};}
        static void UniqueKeys(string json)
        {
            var objects=new Stack<HashSet<string>>();for(int at=0;at<json.Length;at++){
                char current=json[at];if(current=='{'){objects.Push(new HashSet<string>(StringComparer.Ordinal));continue;}if(current=='}'){if(objects.Count>0)objects.Pop();continue;}if(current!='"')continue;
                int start=at++;bool closed=false;for(;at<json.Length;at++){if(json[at]=='\\'){at++;continue;}if(json[at]=='"'){closed=true;break;}}
                if(!closed)throw new ProtocolFailure();int next=at+1;while(next<json.Length&&Char.IsWhiteSpace(json[next]))next++;
                if(next<json.Length&&json[next]==':'&&objects.Count>0){string key=Json().Deserialize<string>(json.Substring(start,at-start+1));if(!objects.Peek().Add(key))throw new ProtocolFailure();}
            }
        }
        static Dictionary<string,object> Object(string text)
        {
            UniqueKeys(text);var row=Json().DeserializeObject(text) as Dictionary<string,object>;if(row==null)throw new ProtocolFailure();return row;
        }
        static void Fields(Dictionary<string,object> row,params string[] fields){if(row.Count!=fields.Length||row.Keys.Any(key=>!fields.Contains(key,StringComparer.Ordinal)))throw new ProtocolFailure();}
        static long Number(Dictionary<string,object> row,string name)
        {
            object value;if(!row.TryGetValue(name,out value)||!(value is int||value is long))throw new ProtocolFailure();return Convert.ToInt64(value,System.Globalization.CultureInfo.InvariantCulture);
        }
        static string Text(Dictionary<string,object> row,string name){object value;if(!row.TryGetValue(name,out value)||!(value is string))throw new ProtocolFailure();return (string)value;}
        static string ReadLine(TextReader input,int maximum,ref int total)
        {
            var line=new StringBuilder();int value,characters=0;bool carriage=false;while((value=input.Read())>=0){if(++total>MaximumOutput)throw new ProtocolFailure();if(value==10)return line.ToString();if(++characters>maximum||carriage)throw new ProtocolFailure();if(value==13){carriage=true;continue;}line.Append((char)value);}if(carriage)throw new ProtocolFailure();return line.Length==0?null:line.ToString();
        }
        static MediaFoundationValidator.DecodeLimits Request(string input,out string source)
        {
            if(String.IsNullOrWhiteSpace(input)||input.Length>MaximumRequest)throw new ProtocolFailure();var row=Object(input);Fields(row,"protocol","operation","source","limits");if(Number(row,"protocol")!=1||Text(row,"operation")!="media_decode")throw new ProtocolFailure();source=Text(row,"source");if(source.Length<1||source.Length>4096||source.Any(Char.IsControl))throw new ProtocolFailure();var limits=row["limits"] as Dictionary<string,object>;if(limits==null)throw new ProtocolFailure();
            Fields(limits,"MaxInputBytes","MaxDecodedBytes","MaxVideoFrames","MaxDecodedSamples","MaxMilliseconds","MaxPixels");
            var parsed=new MediaFoundationValidator.DecodeLimits{MaxInputBytes=Number(limits,"MaxInputBytes"),MaxDecodedBytes=Number(limits,"MaxDecodedBytes"),MaxVideoFrames=checked((int)Number(limits,"MaxVideoFrames")),MaxDecodedSamples=checked((int)Number(limits,"MaxDecodedSamples")),MaxMilliseconds=checked((int)Number(limits,"MaxMilliseconds")),MaxPixels=checked((int)Number(limits,"MaxPixels"))};parsed.Validate();return parsed;
        }
        static void Emit(TextWriter output,object record)
        {
            string line=Json().Serialize(record);if(line.Length>MaximumLine)throw new ProtocolFailure();output.WriteLine(line);output.Flush();
        }
        public static int RunConsole(string[] arguments)
        {
            int result=2;var thread=new Thread(delegate(){
                try{using(var input=new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false,true),false,4096))using(var output=new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false),4096)){
                    MediaFoundationValidator.DecodeReport report;try{
                        if(arguments==null||arguments.Length!=1||arguments[0]!="--media-decode-worker")throw new ProtocolFailure();int total=0;string line=ReadLine(input,MaximumRequest,ref total);if(input.Read()!=-1)throw new ProtocolFailure();string source;var limits=Request(line,out source);
                        var clock=Stopwatch.StartNew();long last=-1000;string phase=null;int stream=-2,events=0;
                        report=MediaFoundationValidator.Validate(source,limits,CancellationToken.None,delegate(MediaFoundationValidator.DecodeProgress progress){
                            if(events>=MaximumEvents-1)return;long now=clock.ElapsedMilliseconds;if(phase==progress.Phase&&stream==progress.StreamIndex&&now-last<100)return;phase=progress.Phase;stream=progress.StreamIndex;last=now;events++;Emit(output,new{protocol=1,type="progress",phase=progress.Phase,stream=progress.StreamIndex,samples=progress.Samples,bytes=progress.Bytes});
                        });
                    }catch(ProtocolFailure){report=Failed("error","MF_PROTOCOL_INVALID");}catch(ArgumentException){report=Failed("error","MF_PROTOCOL_INVALID");}catch(InvalidOperationException){report=Failed("error","MF_PROTOCOL_INVALID");}catch(OverflowException){report=Failed("error","MF_PROTOCOL_INVALID");}catch{report=Failed("error","MF_WORKER_FAILED");}
                    Emit(output,new{protocol=1,type="result",report=report});result=0;
                }}catch{result=2;}
            });
            thread.IsBackground=false;thread.SetApartmentState(ApartmentState.MTA);thread.Start();thread.Join();return result;
        }
        static void ValidateReport(MediaFoundationValidator.DecodeReport report,MediaFoundationValidator.DecodeLimits limits)
        {
            if(report==null||report.Schema!=1||!new[]{"decoded_soft","unsupported","corrupt","limited","cancelled","error"}.Contains(report.Status)||!OwnCode(report.Code)||report.StrictIntegrityEstablished||report.OwnershipAuthenticated||report.SourceBytes<0||report.DecodedBytes<0||report.DecodedBytes>limits.MaxDecodedBytes||report.ElapsedMilliseconds<0||report.ElapsedMilliseconds>123000||report.Streams==null||report.Streams.Count>8)throw new ProtocolFailure();
            if(report.NativeCode!=null&&!Regex.IsMatch(report.NativeCode,"\\A0x[a-f0-9]{8}\\z",RegexOptions.CultureInvariant))throw new ProtocolFailure();
            if(report.SourceSha256!=null&&!Digest(report.SourceSha256))throw new ProtocolFailure();var indexes=new HashSet<int>();long decoded=0;
            foreach(var stream in report.Streams){
                if(stream==null||stream.Index<0||stream.Index>7||!indexes.Add(stream.Index)||stream.Kind!="audio"&&stream.Kind!="video"||stream.MetadataPackets<0||stream.MetadataPackets>1000000||stream.CompressedPacketsRead<0||stream.CompressedPacketsRead>limits.MaxDecodedSamples+1L||stream.DecodedSamples<0||stream.DecodedSamples>limits.MaxDecodedSamples+1L||stream.DecodedBytes<0||stream.DecodedBytes>limits.MaxDecodedBytes||stream.CompressedBytes<0||stream.CompressedBytes>limits.MaxInputBytes||stream.VideoFrames<0||stream.VideoFrames>limits.MaxVideoFrames+1L||stream.PcmFrames<0||stream.CorruptionSignals<0||stream.UnknownCorruptionFlags<0||stream.Discontinuities<0||stream.NullSamples<0||stream.StreamTicks<0)throw new ProtocolFailure();
                if(stream.DecodedSha256!=null&&!Digest(stream.DecodedSha256)||stream.CompressedSha256!=null&&!Digest(stream.CompressedSha256)||stream.PartialSha256!=null&&!Digest(stream.PartialSha256))throw new ProtocolFailure();Guid ignored;if(stream.NativeSubtype!=null&&!Guid.TryParse(stream.NativeSubtype,out ignored)||stream.OutputSubtype!=null&&!Guid.TryParse(stream.OutputSubtype,out ignored))throw new ProtocolFailure();
                if(stream.Kind=="video"&&(stream.Width<1||stream.Height<1||(long)stream.Width*stream.Height>limits.MaxPixels)&&report.Status=="decoded_soft")throw new ProtocolFailure();
                if(stream.Kind=="audio"&&(stream.Channels<1||stream.Channels>8||stream.SampleRate<8000||stream.SampleRate>192000||stream.BitsPerSample!=16||stream.BlockAlign!=stream.Channels*2)&&report.Status=="decoded_soft")throw new ProtocolFailure();
                if(report.Status=="decoded_soft"){
                    if(!stream.EndOfStream||!stream.CompressedEndOfStream||stream.MetadataPackets==0||stream.CompressedPacketsRead!=stream.MetadataPackets||stream.DecodedSamples==0||stream.DecodedBytes==0||stream.CompressedBytes==0||stream.PartialSha256!=null||!Digest(stream.DecodedSha256)||!Digest(stream.CompressedSha256)||stream.CorruptionSignals!=0)throw new ProtocolFailure();
                    if(stream.Kind=="video"){
                        long pitch=Math.Abs((long)stream.Stride),minimum=pitch*(stream.Height-1)+stream.Width*4L;
                        if(!String.Equals(stream.OutputSubtype,"00000016-0000-0010-8000-00aa00389b71",StringComparison.OrdinalIgnoreCase)||stream.VideoFrames!=stream.MetadataPackets||stream.VideoFrames!=stream.DecodedSamples||stream.PcmFrames!=0||pitch<stream.Width*4L||pitch*stream.Height>64L*1024*1024||stream.DecodedBytes<minimum*stream.VideoFrames)throw new ProtocolFailure();
                    }else if(!String.Equals(stream.OutputSubtype,"00000001-0000-0010-8000-00aa00389b71",StringComparison.OrdinalIgnoreCase)||stream.PcmFrames==0||stream.VideoFrames!=0||stream.DecodedBytes%stream.BlockAlign!=0||stream.DecodedBytes/stream.BlockAlign!=stream.PcmFrames)throw new ProtocolFailure();
                }decoded+=stream.DecodedBytes;
                stream.DecodedHashLayout=stream.Kind=="video"?"MF RGB32 memory rows normalized to RGB24 using recorded stride, X bytes/padding omitted":"MF PCM S16LE timeline, OS priming/padding retained";
            }
            if(decoded!=report.DecodedBytes)throw new ProtocolFailure();if(report.Status=="decoded_soft"&&(report.Code!="MF_ALL_STREAMS_DECODED_SOFT"||!report.SourceUnchanged||!Digest(report.SourceSha256)||report.SourceBytes<24||report.SourceBytes>limits.MaxInputBytes||!report.AllStreamsEnded||report.Streams.Count==0))throw new ProtocolFailure();report.Note=Note;report.LimitsAreCooperative=false;
        }
        // Testable transport is internal, not a runtime command-line escape hatch.
        // Production Validate always launches this assembly with one fixed flag.
        internal static MediaFoundationValidator.DecodeReport RunTransport(string executable,string arguments,string request,int hardMilliseconds,long maximumProcessBytes,MediaFoundationValidator.DecodeLimits limits,CancellationToken cancel,Action<MediaFoundationValidator.DecodeProgress> progress)
        {
            if(hardMilliseconds<1||hardMilliseconds>123000||maximumProcessBytes<32L*1024*1024||maximumProcessBytes>1536L*1024*1024)throw new ArgumentOutOfRangeException("worker limits");limits.Validate();if(request==null||request.Length>MaximumRequest)throw new ArgumentException("MF_REQUEST_TOO_LARGE");
            if(cancel.IsCancellationRequested)return Failed("cancelled","MF_CANCELLED");if(!File.Exists(executable))return Failed("error","MF_WORKER_MISSING");
            using(var process=new Process())using(var job=new ProcessJob(maximumProcessBytes)){
                process.StartInfo=new ProcessStartInfo(executable,arguments){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=new UTF8Encoding(false,true),WorkingDirectory=Path.GetDirectoryName(executable)};
                try{process.Start();job.Attach(process);}catch{return Failed("error","MF_WORKER_START_FAILED");}
                var clock=Stopwatch.StartNew();MediaFoundationValidator.DecodeReport result=null;int events=0;Task reader=null,errors=null,writer=null;
                using(cancel.Register(()=>job.Stop()))try{
                    errors=Task.Run(delegate(){byte[] chunk=new byte[4096];while(process.StandardError.BaseStream.Read(chunk,0,chunk.Length)>0){} });
                    reader=Task.Run(delegate(){int total=0;string line;bool ended=false;while((line=ReadLine(process.StandardOutput,MaximumLine,ref total))!=null){
                        if(ended||++events>MaximumEvents)throw new ProtocolFailure();var row=Object(line);if(!row.ContainsKey("protocol")||Number(row,"protocol")!=1)throw new ProtocolFailure();string type=Text(row,"type");
                        if(type=="progress"){
                            Fields(row,"protocol","type","phase","stream","samples","bytes");string phase=Text(row,"phase");long stream=Number(row,"stream"),samples=Number(row,"samples"),bytes=Number(row,"bytes");if(!new[]{"preflight","packets","decode"}.Contains(phase)||stream< -1||stream>7||samples<0||samples>1000001||bytes<0||bytes>256L*1024*1024*1024)throw new ProtocolFailure();if(progress!=null)progress(new MediaFoundationValidator.DecodeProgress{Phase=phase,StreamIndex=(int)stream,Samples=samples,Bytes=bytes});
                        }else if(type=="result"){
                            Fields(row,"protocol","type","report");var serialized=Json().Serialize(row["report"]);result=Json().Deserialize<MediaFoundationValidator.DecodeReport>(serialized);ValidateReport(result,limits);ended=true;
                        }else throw new ProtocolFailure();
                    }});
                    writer=Task.Run(delegate(){byte[] bytes=new UTF8Encoding(false).GetBytes(request+"\n");try{process.StandardInput.BaseStream.Write(bytes,0,bytes.Length);process.StandardInput.BaseStream.Flush();}finally{Array.Clear(bytes,0,bytes.Length);process.StandardInput.Close();}});
                    while(true){
                        if(cancel.IsCancellationRequested){job.Stop();return Failed("cancelled","MF_CANCELLED");}
                        if(clock.ElapsedMilliseconds>=hardMilliseconds){job.Stop();return Failed("limited","MF_WORKER_TIMEOUT");}
                        if(reader.IsFaulted||errors.IsFaulted){job.Stop();return Failed("error","MF_WORKER_PROTOCOL_ERROR");}
                        if(writer.IsFaulted){job.Stop();return Failed("error","MF_WORKER_STDIN_FAILED");}
                        if(process.WaitForExit(20))break;
                    }
                    int remaining=Math.Max(1,hardMilliseconds-(int)clock.ElapsedMilliseconds);if(!Task.WaitAll(new[]{reader,errors,writer},remaining))return Failed("error","MF_WORKER_PIPES_NOT_CLOSED");if(reader.IsFaulted||errors.IsFaulted||writer.IsFaulted)return Failed("error","MF_WORKER_PROTOCOL_ERROR");if(cancel.IsCancellationRequested)return Failed("cancelled","MF_CANCELLED");if(process.ExitCode!=0||result==null)return Failed("error",process.ExitCode!=0?"MF_WORKER_ABORTED":"MF_WORKER_PROTOCOL_ERROR");return result;
                }catch{return Failed(cancel.IsCancellationRequested?"cancelled":"error",cancel.IsCancellationRequested?"MF_CANCELLED":"MF_WORKER_PROTOCOL_ERROR");}
                finally{job.Stop();try{Task.WaitAll(new[]{reader,errors,writer}.Where(t=>t!=null).ToArray(),1000);}catch{}}
            }
        }
        public static MediaFoundationValidator.DecodeReport Validate(string path,MediaFoundationValidator.DecodeLimits limits,CancellationToken cancel,Action<MediaFoundationValidator.DecodeProgress> progress=null)
        {
            if(limits==null)throw new ArgumentNullException("limits");limits=new MediaFoundationValidator.DecodeLimits{MaxInputBytes=limits.MaxInputBytes,MaxDecodedBytes=limits.MaxDecodedBytes,MaxVideoFrames=limits.MaxVideoFrames,MaxDecodedSamples=limits.MaxDecodedSamples,MaxMilliseconds=limits.MaxMilliseconds,MaxPixels=limits.MaxPixels};limits.Validate();if(path==null||path.Length>4096)throw new ArgumentException("MF_SOURCE_PATH_INVALID");string request=Json().Serialize(new{protocol=1,operation="media_decode",source=path,limits=limits});
            return RunTransport(typeof(Program).Assembly.Location,"--media-decode-worker",request,checked(limits.MaxMilliseconds+3000),ProcessMemory,limits,cancel,progress);
        }
    }
}
