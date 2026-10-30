using System;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Owned fixture copies and real MF media-type attributes only. No network
// share, mapped drive, user media or GUI is opened by this suite.
public static class MediaFoundationAuditTests
{
    static int checks;static string project,work,original;
    [DllImport("mfplat.dll")]static extern int MFCreateMediaType(out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Set64(IntPtr self,ref Guid key,ulong value);
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Sha(string path){using(var file=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static int Find(byte[] data,string text){byte[] marker=Encoding.ASCII.GetBytes(text);for(int i=0;i<=data.Length-marker.Length;i++){bool found=true;for(int j=0;j<marker.Length;j++)if(data[i+j]!=marker[j]){found=false;break;}if(found)return i;}throw new Exception("Owned fixture atom not found: "+text);}
    static void Set32(byte[] b,int at,uint value){b[at]=(byte)(value>>24);b[at+1]=(byte)(value>>16);b[at+2]=(byte)(value>>8);b[at+3]=(byte)value;}
    static MediaFoundationValidator.DecodeReport Decode(string file,Action<MediaFoundationValidator.DecodeProgress> progress=null,CancellationToken token=default(CancellationToken))
    {
        var report=MediaFoundationValidator.Validate(file,new MediaFoundationValidator.DecodeLimits(),token,progress);
        Check(!report.StrictIntegrityEstablished&&!report.OwnershipAuthenticated,"decode never authenticates source ownership/integrity");return report;
    }
    static void LocalPathGuards()
    {
        foreach(string path in new[]{"//localhost/RecoveryAudit-NoSuchShare/movie.mp4","/\\localhost/RecoveryAudit-NoSuchShare/movie.mp4",@"\\localhost\RecoveryAudit-NoSuchShare\movie.mp4","https://example.invalid/movie.mp4","file:///C:/movie.mp4",@"\\.\PhysicalDrive0",original+":owned-stream"}){
            int calls=0;var report=Decode(path,p=>calls++);Check(report.Status=="unsupported"&&report.Code=="MF_LOCAL_FILE_REQUIRED","normalized network/device/ADS path blocked lexically before source access");Check(report.SourceBytes==0&&report.SourceSha256==null&&report.Streams.Count==0&&calls==0,"denied source never hashes or reaches preflight/native reader");
        }
        bool checkedUnavailable=false;
        for(char drive='Z';drive>='A';drive--){string root=drive+@":\";DriveType type;try{type=new DriveInfo(root).DriveType;}catch(IOException){continue;}if(type!=DriveType.NoRootDirectory&&type!=DriveType.Unknown&&type!=DriveType.Network&&type!=DriveType.CDRom)continue;
            // DriveType is local metadata. The source file must be rejected
            // before any File.Exists/Directory.Exists on this drive.
            var report=Decode(Path.Combine(root,"RecoveryAudit-NoSuchFile-"+Guid.NewGuid().ToString("N")+".mp4"));Check(report.Status=="unsupported"&&report.Code=="MF_LOCAL_DRIVE_REQUIRED","unavailable/nonlocal drive rejected before file probes");Check(report.SourceBytes==0&&report.SourceSha256==null,"unavailable/nonlocal drive never hashes");checkedUnavailable=true;break;
        }
        Check(checkedUnavailable,"test environment provides an unavailable/nonlocal drive letter");
    }
    static void LocalJunctionGuard()
    {
        string target=Path.Combine(work,"local-junction-target"),link=Path.Combine(work,"local-junction-link");Directory.CreateDirectory(target);
        string powershell=Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe");
        string command="$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path '"+link.Replace("'","''")+"' -Value '"+target.Replace("'","''")+"' | Out-Null";
        using(var child=new Process{StartInfo=new ProcessStartInfo(powershell,"-NoLogo -NoProfile -NonInteractive -Command \""+command+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}}){
            Check(child.Start(),"local junction setup process started without profiles");if(!child.WaitForExit(10000)){try{child.Kill();}catch(InvalidOperationException){}throw new Exception("Local junction creation timed out");}Check(child.ExitCode==0,"owned local directory junction created");
        }
        Check((File.GetAttributes(link)&FileAttributes.ReparsePoint)!=0,"test junction is an actual local reparse point");
        int phases=0;var report=Decode(Path.Combine(link,"not-created-inner-directory","movie.mp4"),p=>phases++);
        Check(report.Status=="unsupported"&&report.Code=="MF_LINKED_SOURCE","parent junction rejected before probing its nonexistent descendant");
        Check(report.SourceSha256==null&&report.SourceBytes==0&&report.Streams.Count==0&&phases==0,"linked ancestor prevents hashing, preflight and native decoding");
        Check(Directory.GetFileSystemEntries(target).Length==0,"owned local junction target remains empty and unchanged");
    }
    static void AttributeBounds()
    {
        Type validator=typeof(MediaFoundationValidator),context=validator.GetNestedType("Context",BindingFlags.NonPublic);
        object c=Activator.CreateInstance(context,true);context.GetField("Limits").SetValue(c,new MediaFoundationValidator.DecodeLimits());MethodInfo method=validator.GetMethod("CheckFormat",BindingFlags.NonPublic|BindingFlags.Static);
        foreach(ulong packed in new[]{UInt64.MaxValue,((ulong)UInt32.MaxValue<<32)|1,((ulong)1<<32)|UInt32.MaxValue,((ulong)4000<<32)|4001,0UL,((ulong)96<<32)|64}){
            IntPtr media;int hr=MFCreateMediaType(out media);if(hr<0)Marshal.ThrowExceptionForHR(hr);try{
                var setter=(Set64)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(media),22*IntPtr.Size),typeof(Set64));Guid key=new Guid("1652c33d-d6b2-4012-b834-72030849a37d");hr=setter(media,ref key,packed);if(hr<0)Marshal.ThrowExceptionForHR(hr);
                var stream=new MediaFoundationValidator.DecodedStream{Kind="video"};bool rejected=false;try{method.Invoke(null,new object[]{media,stream,c,false});}catch(TargetInvocationException error){FieldInfo code=error.InnerException.GetType().GetField("Code");Check(code!=null&&(string)code.GetValue(error.InnerException)=="MF_PIXEL_LIMIT","bad native dimensions fail bounded pixel guard");rejected=true;}
                bool valid=packed==(((ulong)96<<32)|64);Check(valid?!rejected:rejected,"wide native dimensions cannot wrap into valid pixels");if(valid)Check(stream.Width==96&&stream.Height==64,"normal native dimensions preserved");
            }finally{Marshal.Release(media);}
        }
    }
    static void PreflightBounds()
    {
        foreach(string mutation in new[]{"huge-top","zero-samples","description-index","encrypted-description","external-url"}){
            byte[] bytes=File.ReadAllBytes(original);string expected;
            if(mutation=="huge-top"){Set32(bytes,0,0x7fffffff);expected="MF_CONTAINER_BOUNDS";}
            else if(mutation=="zero-samples"){Set32(bytes,Find(bytes,"stsz")+12,0);expected="MF_SAMPLE_COUNT_INVALID";}
            else if(mutation=="description-index"){bytes[Find(bytes,"stsd")+27]=2;expected="MF_EXTERNAL_SAMPLE_DESCRIPTION";}
            else if(mutation=="encrypted-description"){Buffer.BlockCopy(Encoding.ASCII.GetBytes("encv"),0,bytes,Find(bytes,"stsd")+16,4);expected="MF_ENCRYPTED_MEDIA_UNSUPPORTED";}
            else {Set32(bytes,Find(bytes,"url ")+4,0);expected="MF_EXTERNAL_DATA_REFERENCE";}
            string file=Path.Combine(work,mutation+".mp4");File.WriteAllBytes(file,bytes);string before=Sha(file);int phases=0;var report=Decode(file,p=>phases++);
            Check(report.Status!="decoded_soft"&&report.Code==expected,"malformed/self-external container rejected by preflight: "+mutation+" / "+report.Code);Check(report.Streams.Count==0&&phases==0,"invalid preflight never reaches native readers");Check(Sha(file)==before,"invalid input bytes unchanged");
        }
    }
    static void CancellationAndSourceIdentity()
    {
        string before=Sha(original);var token=new CancellationTokenSource();token.Cancel();int calls=0;var report=Decode(original,p=>calls++,token.Token);Check(report.Status=="cancelled"&&report.Code=="MF_CANCELLED"&&report.Streams.Count==0&&calls==0,"pre-cancel performs no source/native work");Check(report.SourceSha256==null,"pre-cancel does not report an uncomputed source hash");
        token=new CancellationTokenSource();report=Decode(original,p=>{if(p.Phase=="preflight")token.Cancel();},token.Token);Check(report.Status=="cancelled"&&report.Code=="MF_CANCELLED"&&report.Streams.Count==0&&!report.AllStreamsEnded,"preflight cancellation never becomes decode success");Check(report.SourceSha256==before&&Sha(original)==before,"real preflight hashes source without changing it");
    }
    static MediaFoundationValidator.DecodeReport SyntheticReport(string mode)
    {
        var stream=new MediaFoundationValidator.DecodedStream{Index=0,Kind="video",Width=1,Height=1,Stride=4,NativeSubtype="34363248-0000-0010-8000-00aa00389b71",OutputSubtype="00000016-0000-0010-8000-00aa00389b71",MetadataPackets=1,CompressedPacketsRead=1,CompressedBytes=1,DecodedSamples=1,DecodedBytes=4,VideoFrames=1,EndOfStream=true,CompressedEndOfStream=true,DecodedSha256=new string('a',64),CompressedSha256=new string('b',64)};
        if(mode=="zero-frames")stream.VideoFrames=0;
        else if(mode=="extra-frames")stream.VideoFrames=2;
        else if(mode=="zero-bytes")stream.DecodedBytes=0;
        else if(mode=="bad-output")stream.OutputSubtype="00000001-0000-0010-8000-00aa00389b71";
        else if(mode=="empty-audio"){
            stream.Kind="audio";stream.Width=stream.Height=stream.Stride=0;stream.VideoFrames=0;stream.Channels=1;stream.SampleRate=48000;stream.BitsPerSample=16;stream.BlockAlign=2;stream.DecodedBytes=2;stream.PcmFrames=0;stream.OutputSubtype="00000001-0000-0010-8000-00aa00389b71";
        }
        var report=new MediaFoundationValidator.DecodeReport{Status="decoded_soft",Code="MF_ALL_STREAMS_DECODED_SOFT",SourceBytes=24,SourceSha256=new string('c',64),SourceUnchanged=true,AllStreamsEnded=true,DecodedBytes=stream.DecodedBytes};report.Streams.Add(stream);return report;
    }
    static int SyntheticChild(string mode)
    {
        Console.ReadLine();string line=new JavaScriptSerializer().Serialize(new{protocol=1,type="result",report=SyntheticReport(mode)});if(mode=="embedded-cr")line=line.Replace(new string('c',64),new string('c',32)+"\r"+new string('c',32));Console.WriteLine(line);return 0;
    }
    static void ReportProtocolConsistency()
    {
        MethodInfo transport=typeof(MediaDecodeWorker).GetMethod("RunTransport",BindingFlags.NonPublic|BindingFlags.Static);Check(transport!=null,"worker transport independently testable");
        foreach(string mode in new[]{"consistent","zero-frames","extra-frames","zero-bytes","bad-output","empty-audio","embedded-cr"}){
            var report=(MediaFoundationValidator.DecodeReport)transport.Invoke(null,new object[]{Assembly.GetExecutingAssembly().Location,"--audit-synthetic-"+mode,"synthetic input",3000,768L*1024*1024,new MediaFoundationValidator.DecodeLimits(),CancellationToken.None,null});
            if(mode=="consistent")Check(report.Status=="decoded_soft"&&!report.LimitsAreCooperative&&!report.StrictIntegrityEstablished&&!report.OwnershipAuthenticated,"consistent synthetic protocol is soft evidence only, not a real decoder test");
            else Check(report.Status=="error"&&report.Code=="MF_WORKER_PROTOCOL_ERROR","inconsistent forged decoded result rejected: "+mode);
        }
    }
    [MTAThread]public static int Main(string[] args)
    {
        if(args.Length>0&&args[0].StartsWith("--audit-synthetic-",StringComparison.Ordinal))return SyntheticChild(args[0].Substring(18));
        try{project=Path.GetFullPath(args[0]);original=Path.Combine(project,".build","fragmented-media-audio-tests","phone-fast.mp4");work=Path.Combine(project,".build","media-foundation-audit","cases-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);Check(File.Exists(original),"owned media fixture exists");LocalPathGuards();LocalJunctionGuard();AttributeBounds();PreflightBounds();CancellationAndSourceIdentity();ReportProtocolConsistency();Console.WriteLine("PASS MediaFoundationAudit: "+checks+" checks; normalized local-only guards, real MF native attribute overflow, sample/dref preflight bounds and cancellation; no network or user media opened.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}