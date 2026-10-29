using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ResumableCaptureTests
{
    static int checks;static string root;static byte[] data;
    const string Identity="USB|SERIAL-SYNTHETIC|UNIQUE-SYNTHETIC|sector512";
    sealed class ReadTrace { public long Offset;public int Count; }
    sealed class TestSource:MemoryStream
    {
        public readonly List<ReadTrace> Reads=new List<ReadTrace>();
        public Func<long,int,bool> Fault,Zero;public Action<long,int> BeforeRead;public bool Misaligned;public int Writes;
        public TestSource(byte[] b):base(b,false){}
        public override int Read(byte[] b,int p,int n){Reads.Add(new ReadTrace{Offset=Position,Count=n});if(BeforeRead!=null)BeforeRead(Position,n);if(Fault!=null&&Fault(Position,n))throw new IOException("synthetic unreadable area");if(Zero!=null&&Zero(Position,n))return 0;if(Misaligned&&n>4096)return base.Read(b,p,257);return base.Read(b,p,n);}
        public override void Write(byte[] b,int p,int n){Writes++;throw new Exception("Source write forbidden");}
    }
    sealed class Run
    {
        public string Folder,Partial,Head,Map;
        public Run(string name){Folder=Path.Combine(root,name+"-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(Folder);Partial=Path.Combine(Folder,"usb.dd.partial");Head=Path.Combine(Folder,"capture-resume.json");Map=Path.Combine(Folder,"usb.dd.read-errors.json");}
    }
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Hash(byte[] b){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
    static string Hash(string file){return Hash(File.ReadAllBytes(file));}
    static bool Overlap(long p,int n,long bad,long length){return p<bad+length&&bad<p+n;}
    static ResumableCaptureResult Copy(TestSource input,Run run,bool resume=false,bool rescue=false,bool retry=true,Action<long,long> progress=null,CancellationToken? token=null,Func<bool> available=null,string identity=Identity)
    {return ResumableCapture.Copy(input,run.Partial,data.Length,512,identity,run.Head,run.Map,token??CancellationToken.None,progress,available??(()=>true),resume,rescue,retry);}
    static Run Cancelled(string name)
    {
        var run=new Run(name);using(var input=new TestSource(data))using(var cancel=new CancellationTokenSource()){
            bool stopped=false;try{Copy(input,run,progress:(done,total)=>{if(done>=ResumableCapture.ChunkBytes)cancel.Cancel();},token:cancel.Token);}catch(OperationCanceledException){stopped=true;}
            Check(stopped,"cancellation propagated");Check(new FileInfo(run.Partial).Length==ResumableCapture.ChunkBytes,"only durable chunk retained");Check(ResumableCapture.Inspect(run.Head).Status=="cancelled","cancel status persisted");Check(input.Writes==0,"source never written");
        }return run;
    }
    static void ExactAndResume()
    {
        var run=new Run("exact");using(var input=new TestSource(data)){
            long last=-1;var result=Copy(input,run,progress:(done,total)=>{Check(done>=last&&done<=total,"bounded monotonic progress");last=done;});
            Check(result.Sha256==Hash(data)&&Hash(run.Partial)==Hash(data),"exact output digest independently matches");Check(result.UnreadBytes==0&&result.Ranges.Count==0&&result.CopiedBytes==data.Length,"exact capture no invented gaps");Check(ResumableCapture.Inspect(run.Head).CompletedBytes==data.Length&&ResumableCapture.Inspect(run.Head).Status=="complete","completed checkpoint can survive promotion interruption");Check(input.Writes==0,"exact source remains read only");
        }
        run=Cancelled("resume");using(var input=new TestSource(data)){
            var result=Copy(input,run,true);Check(result.ResumedBytes==ResumableCapture.ChunkBytes&&result.Sha256==Hash(data),"resume starts from completed chunk and matches exact digest");Check(!input.Reads.Any(x=>x.Offset==0&&x.Count==ResumableCapture.ChunkBytes),"resume does not reread completed source body");Check(input.Reads.Count(x=>x.Count<=4096)>=ResumableCapture.MaximumSamples,"source identity samples rechecked");
        }
        using(var input=new TestSource(data)){var result=Copy(input,run,true);Check(result.ResumedBytes==data.Length&&result.Sha256==Hash(data),"completed checkpoint resumes without recopy");Check(input.Reads.All(x=>x.Count<=4096),"completed image only rereads source samples");}
        var noOverwrite=Hash(run.Partial);using(var input=new TestSource(data)){bool rejected=false;try{Copy(input,run);}catch(IOException){rejected=true;}Check(rejected&&Hash(run.Partial)==noOverwrite,"new mode never overwrites existing copy");}
        var cancelled=new Run("pre-cancel");using(var input=new TestSource(data))using(var token=new CancellationTokenSource()){token.Cancel();bool rejected=false;try{Copy(input,cancelled,token:token.Token);}catch(OperationCanceledException){rejected=true;}Check(rejected&&Directory.GetFiles(cancelled.Folder).Length==0&&input.Reads.Count==0,"pre-cancel touches neither source nor working files");}
        var relocated=Cancelled("move");string moved=Path.Combine(root,"moved-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(moved);foreach(string file in Directory.GetFiles(relocated.Folder))File.Copy(file,Path.Combine(moved,Path.GetFileName(file)));relocated.Folder=moved;relocated.Partial=Path.Combine(moved,"usb.dd.partial");relocated.Head=Path.Combine(moved,"capture-resume.json");relocated.Map=Path.Combine(moved,"usb.dd.read-errors.json");using(var input=new TestSource(data))Check(Copy(input,relocated,true).Sha256==Hash(data),"entire run folder can move without losing resume");
    }
    static void Rejections()
    {
        var run=Cancelled("identity");string head=Hash(run.Head),partial=Hash(run.Partial);using(var input=new TestSource(data)){bool rejected=false;try{Copy(input,run,true,identity:"OTHER USB");}catch(IOException){rejected=true;}Check(rejected&&input.Reads.Count==0&&Hash(run.Head)==head&&Hash(run.Partial)==partial,"wrong identity rejected without writes or source reads");}
        byte[] changed=(byte[])data.Clone();changed[0]^=1;using(var input=new TestSource(changed)){bool rejected=false;try{Copy(input,run,true);}catch(IOException){rejected=true;}Check(rejected&&Hash(run.Head)==head&&Hash(run.Partial)==partial,"changed source sample prevents mixing captures");}
        run=Cancelled("output-tamper");using(var file=new FileStream(run.Partial,FileMode.Open,FileAccess.ReadWrite)){file.Position=8192;file.WriteByte(77);}partial=Hash(run.Partial);head=Hash(run.Head);using(var input=new TestSource(data)){bool rejected=false;try{Copy(input,run,true);}catch(IOException){rejected=true;}Check(rejected&&Hash(run.Partial)==partial&&Hash(run.Head)==head,"modified durable output rejected before resume mutation");}
        run=Cancelled("journal-tamper");string journal=run.Head+".chunks.jsonl";byte[] bytes=File.ReadAllBytes(journal);bytes[20]^=1;File.WriteAllBytes(journal,bytes);partial=Hash(run.Partial);using(var input=new TestSource(data)){bool rejected=false;try{Copy(input,run,true);}catch(IOException){rejected=true;}Check(rejected&&input.Reads.Count==0&&Hash(run.Partial)==partial,"journal chain tamper rejected before source reads");}
        run=Cancelled("head-tamper");File.WriteAllText(run.Head,File.ReadAllText(run.Head).Replace("\"SectorSize\":512","\"SectorSize\":4096"));using(var input=new TestSource(data)){bool rejected=false;try{Copy(input,run,true);}catch(IOException){rejected=true;}Check(rejected&&input.Reads.Count==0,"header checksum catches geometry edit");}
        run=Cancelled("uncommitted-tail");using(var file=new FileStream(run.Partial,FileMode.Append))file.Write(new byte[]{1,2,3,4,5},0,5);File.AppendAllText(run.Head+".chunks.jsonl","uncommitted invalid JSON");using(var input=new TestSource(data)){Check(Copy(input,run,true).Sha256==Hash(data),"uncommitted output/journal tails discarded only after verification");Check(new FileInfo(run.Partial).Length==data.Length,"tail cannot leak into final digest");}
        var same=new Run("samepath");string sourceFile=Path.Combine(same.Folder,"source.dd");File.WriteAllBytes(sourceFile,data);using(var input=new FileStream(sourceFile,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){bool rejected=false;try{ResumableCapture.Copy(input,sourceFile,data.Length,512,Identity,same.Head,same.Map,CancellationToken.None,null,null);}catch(IOException){rejected=true;}Check(rejected&&Hash(sourceFile)==Hash(data),"source/output path alias rejected");}
        run=Cancelled("hardlink");sourceFile=Path.Combine(run.Folder,"source.dd");File.WriteAllBytes(sourceFile,data);File.Delete(run.Partial);if(CreateHardLink(run.Partial,sourceFile,IntPtr.Zero))using(var input=new FileStream(sourceFile,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){bool rejected=false;try{ResumableCapture.Copy(input,run.Partial,data.Length,512,Identity,run.Head,run.Map,CancellationToken.None,null,null,true);}catch(IOException){rejected=true;}Check(rejected&&Hash(sourceFile)==Hash(data),"hardlink source/output alias rejected by file identity");}else throw new Exception("Synthetic hardlink setup failed");
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateHardLink(string path,string existing,IntPtr reserved);
    static void ReadErrors()
    {
        var run=new Run("permanent-sector");using(var input=new TestSource(data){Fault=(p,n)=>Overlap(p,n,1024,512)}){
            var result=Copy(input,run,rescue:true);byte[] expected=(byte[])data.Clone();Array.Clear(expected,1024,512);Check(result.UnreadBytes==512&&result.Ranges.Count==1&&result.Ranges[0].Offset==1024,"exact permanent bad sector mapped after late retry");Check(Hash(run.Partial)==Hash(expected)&&result.Sha256==Hash(expected),"only unread sector replaced with explicit zeros");int sectorAt=input.Reads.FindIndex(x=>x.Count==512);Check(sectorAt>=0&&input.Reads.Take(sectorAt).Any(x=>x.Offset>=ResumableCapture.ChunkBytes&&x.Count>4096),"healthy later data copied before sector retries");Check(ResumableCapture.Inspect(run.Head).Status=="complete_with_read_errors"&&File.ReadAllText(run.Map).Contains("zero-filled"),"holes never reported as intact original");Check(input.Writes==0,"rescue never writes source");
        }
        run=new Run("transient-large-read");using(var input=new TestSource(data){Fault=(p,n)=>n>=65536&&Overlap(p,n,1024,512)}){var result=Copy(input,run,rescue:true);Check(result.UnreadBytes==0&&result.Sha256==Hash(data),"late sector reads recover transient/coarse read failures exactly");}
        run=new Run("retry-budget");using(var input=new TestSource(data){Fault=(p,n)=>Overlap(p,n,0,ResumableCapture.ChunkBytes)}){var result=Copy(input,run,rescue:true);Check(result.CopiedBytes==data.Length&&result.UnreadBytes==ResumableCapture.ChunkBytes,"large bad region cannot prevent later healthy blocks");Check(input.Reads.Count(x=>x.Count==512&&x.Offset<ResumableCapture.ChunkBytes)==ResumableCapture.MaximumRetrySectors,"sector retry work bounded without infinite retry");}
        run=new Run("disconnect");using(var input=new TestSource(data){Fault=(p,n)=>n>4096}){bool failed=false;try{Copy(input,run,rescue:true,available:()=>false);}catch(IOException){failed=true;}Check(failed&&new FileInfo(run.Partial).Length==0&&ResumableCapture.Inspect(run.Head).Status=="incomplete","disconnect is hard failure, not fabricated all-zero image");}
        run=new Run("exact-read-error");using(var input=new TestSource(data){Fault=(p,n)=>n>4096&&p>=ResumableCapture.ChunkBytes}){bool failed=false;try{Copy(input,run);}catch(IOException){failed=true;}Check(failed&&new FileInfo(run.Partial).Length==ResumableCapture.ChunkBytes,"exact error retains only completed blocks");}using(var input=new TestSource(data))Check(Copy(input,run,true).Sha256==Hash(data),"exact error can resume once source is readable");
        run=new Run("short-read");using(var input=new TestSource(data){Zero=(p,n)=>n>4096&&p>=ResumableCapture.ChunkBytes}){bool failed=false;try{Copy(input,run,rescue:true);}catch(EndOfStreamException){failed=true;}Check(failed&&ResumableCapture.Inspect(run.Head).Status=="incomplete","EOF never silently zero-filled");}
        run=new Run("misaligned");using(var input=new TestSource(data){Misaligned=true}){bool failed=false;try{Copy(input,run,rescue:true);}catch(EndOfStreamException){failed=true;}Check(failed&&new FileInfo(run.Partial).Length==0,"misaligned sector return is a hard failure");}
        run=new Run("probe-read-error");using(var input=new TestSource(data){Fault=(p,n)=>n==4096}){var result=Copy(input,run,rescue:true,retry:false);Check(result.Sha256==Hash(data),"rescue may acquire while sample probes fail");}using(var input=new TestSource(data))Check(Copy(input,run,true).Sha256==Hash(data),"successful bulk copy derives previously unreadable sample fingerprints");
        run=new Run("all-samples-unreadable");var sampleOffsets=Enumerable.Range(0,16).Select(i=>(long)(data.Length-4096)*i/15/4096*4096).Distinct().ToArray();using(var input=new TestSource(data){Fault=(p,n)=>sampleOffsets.Any(at=>Overlap(p,n,at,4096))})Copy(input,run,rescue:true,retry:false);using(var input=new TestSource(data)){bool failed=false;try{Copy(input,run,true);}catch(IOException){failed=true;}Check(failed,"zero retained readable fingerprints cannot authorize resume");}
        run=new Run("change-during-capture");byte[] changed=(byte[])data.Clone();bool changedOnce=false;using(var input=new TestSource(changed){BeforeRead=(p,n)=>{if(n==ResumableCapture.ChunkBytes&&!changedOnce){changedOnce=true;changed[0]^=1;}}}){bool failed=false;try{Copy(input,run);}catch(IOException){failed=true;}Check(failed&&new FileInfo(run.Partial).Length==0,"sampled source mutation during acquisition prevents publishing mixed chunk");}
    }
    static object PrivateLoad(string file){return typeof(ResumableCapture).GetMethod("Load",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[]{file});}
    static void Set(object value,string field,object dataValue){value.GetType().GetField(field).SetValue(value,dataValue);}
    static void SavePrivateHead(string file,object head){typeof(ResumableCapture).GetMethod("SaveHead",BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,new object[]{file,head});}
    static void FreshProcessInspect(string checkpoint)
    {
        var start=new System.Diagnostics.ProcessStartInfo(typeof(ResumableCaptureTests).Assembly.Location,"--inspect \""+checkpoint+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var process=System.Diagnostics.Process.Start(start)){if(!process.WaitForExit(5000)){process.Kill();throw new Exception("Fresh process inspect timeout");}Check(process.ExitCode==0&&process.StandardOutput.ReadToEnd().Contains("INSPECT OK"),"checkpoint checksum stable across fresh process/reflection order");}
    }
    static void PendingRepair(bool corrupt,bool sourceChanged)
    {
        var run=new Run("pending-repair");using(var input=new TestSource(data){Fault=(p,n)=>Overlap(p,n,0,65536)})Copy(input,run,rescue:true,retry:false);
        string oldSha=Hash(File.ReadAllBytes(run.Partial).Take(ResumableCapture.ChunkBytes).ToArray());byte[] repaired=File.ReadAllBytes(run.Partial).Take(ResumableCapture.ChunkBytes).ToArray();Buffer.BlockCopy(data,1024,repaired,1024,512);
        var chunkType=typeof(ResumableCapture).GetNestedType("Chunk",BindingFlags.NonPublic);object chunk=Activator.CreateInstance(chunkType,true);Set(chunk,"Kind","repair");Set(chunk,"Offset",0L);Set(chunk,"Length",ResumableCapture.ChunkBytes);Set(chunk,"Sha256",Hash(repaired));Set(chunk,"Missing",new List<ResumableRange>{new ResumableRange{Offset=0,Length=1024},new ResumableRange{Offset=1536,Length=65536-1536}});
        var pendingType=typeof(ResumableCapture).GetNestedType("Pending",BindingFlags.NonPublic);object pending=Activator.CreateInstance(pendingType,true);Set(pending,"OldSha256",oldSha);Set(pending,"Next",chunk);object head=PrivateLoad(run.Head);Set(head,"Pending",pending);SavePrivateHead(run.Head,head);FreshProcessInspect(run.Head);
        string patch=run.Head+".repair.partial";File.WriteAllBytes(patch,repaired);using(var file=new FileStream(run.Partial,FileMode.Open,FileAccess.Write)){file.Position=1024;file.Write(repaired,1024,137);}if(corrupt){repaired[9000]^=17;File.WriteAllBytes(patch,repaired);}
        bool pendingRejected=false;try{ResumableCapture.VerifyCompletedImage(run.Head,run.Partial,CancellationToken.None);}catch(IOException){pendingRejected=true;}Check(pendingRejected,"pending repair cannot masquerade as completed image verification");
        byte[] source=(byte[])data.Clone();if(sourceChanged)source[1024]^=3;
        using(var input=new TestSource(source)){
            if(corrupt||sourceChanged){bool failed=false;try{Copy(input,run,true,true,false);}catch(IOException){failed=true;}Check(failed&&File.Exists(patch),"corrupt or changed-source pending repair cannot publish success");}
            else{var result=Copy(input,run,true,true,false);byte[] expected=(byte[])data.Clone();Array.Clear(expected,0,65536);Buffer.BlockCopy(data,1024,expected,1024,512);Check(result.Sha256==Hash(expected)&&Hash(run.Partial)==Hash(expected),"torn pending repair resumes transaction exactly");Check(result.UnreadBytes==65536-512&&!File.Exists(patch),"pending commit updates gap map and removes staging file");}
        }
    }
    public static int Main(string[] args)
    {
        try{
            if(args.Length==2&&args[0]=="--inspect"){var info=ResumableCapture.Inspect(args[1]);Console.WriteLine("INSPECT OK "+info.Status);return 0;}
            string project=Path.GetFullPath(args.Length>0?args[0]:Directory.GetCurrentDirectory());root=Path.Combine(project,".build","resume-capture-tests-"+DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ"));Directory.CreateDirectory(root);data=new byte[ResumableCapture.ChunkBytes*2+512];new Random(3301).NextBytes(data);string original=Hash(data);
            ExactAndResume();Rejections();ReadErrors();PendingRepair(false,false);PendingRepair(true,false);PendingRepair(false,true);SmallGeometry();CompletedVerification();Check(Hash(data)==original,"all synthetic source bytes remain unchanged");
            string summary="PASS ResumableCapture: "+checks+" checks; exact/rescue resume, output hashes and journal/source identity,16x4KiB sampled source checks (not arbitrary-write detection), good-first late bounded retry, bad ranges, transactional torn repair, cancellation/disconnect/EOF/alignment, tamper/path/hardlink rejection; synthetic regular files/streams only. Results: "+root;
            Console.WriteLine(summary);File.WriteAllText(Path.Combine(project,"tests","ResumableCaptureTests.result.txt"),summary,Encoding.UTF8);return 0;
        }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
    }
    static void SmallGeometry()
    {
        foreach(int sector in new[]{512,1024,2048,4096}){
            var run=new Run("geometry"+sector);byte[] bytes=new byte[sector];new Random(sector).NextBytes(bytes);using(var input=new TestSource(bytes)){
                var result=ResumableCapture.Copy(input,run.Partial,bytes.Length,sector,Identity,run.Head,run.Map,CancellationToken.None,null,null);Check(result.Sha256==Hash(bytes)&&new FileInfo(run.Partial).Length==bytes.Length,"small aligned source "+sector+" exact");Check(ResumableCapture.Inspect(run.Head).SectorSize==sector,"geometry stored "+sector);
            }
        }
        foreach(int sector in new[]{0,256,513,8192}){var run=new Run("invalid-geometry"+sector);using(var input=new TestSource(data)){bool failed=false;try{ResumableCapture.Copy(input,run.Partial,data.Length,sector,Identity,run.Head,run.Map,CancellationToken.None,null,null);}catch(IOException){failed=true;}Check(failed&&Directory.GetFiles(run.Folder).Length==0,"invalid geometry rejected before files "+sector);}}
    }
    static void CompletedVerification()
    {
        var run=new Run("verify-promoted");using(var input=new TestSource(data))Copy(input,run);string image=Path.Combine(run.Folder,"usb.dd");File.Move(run.Partial,image);var snapshots=Directory.GetFiles(run.Folder).ToDictionary(x=>x,Hash);var result=ResumableCapture.VerifyCompletedImage(run.Head,image,CancellationToken.None);Check(result.Sha256==Hash(data)&&result.CopiedBytes==data.Length&&result.UnreadBytes==0,"promoted complete image verified without source device or loose SHA sidecar");Check(snapshots.All(x=>File.Exists(x.Key)&&Hash(x.Key)==x.Value),"completed verifier writes no image/control file");
        using(var input=new FileStream(image,FileMode.Open,FileAccess.Write)){input.Position=9000;input.WriteByte(123);}string changed=Hash(image),head=Hash(run.Head);bool rejected=false;try{ResumableCapture.VerifyCompletedImage(run.Head,image,CancellationToken.None);}catch(IOException){rejected=true;}Check(rejected&&Hash(image)==changed&&Hash(run.Head)==head,"changed completed image rejected without overwriting proof");
        using(var input=new FileStream(image,FileMode.Open,FileAccess.Write))input.SetLength(data.Length-512);changed=Hash(image);rejected=false;try{ResumableCapture.VerifyCompletedImage(run.Head,image,CancellationToken.None);}catch(IOException){rejected=true;}Check(rejected&&Hash(image)==changed,"truncated promoted image rejected unchanged");
        run=Cancelled("verify-incomplete");rejected=false;try{ResumableCapture.VerifyCompletedImage(run.Head,run.Partial,CancellationToken.None);}catch(IOException){rejected=true;}Check(rejected,"cancelled/incomplete capture cannot be verified as complete");
        run=new Run("verify-holes");using(var input=new TestSource(data){Fault=(p,n)=>Overlap(p,n,1024,512)})Copy(input,run,rescue:true);result=ResumableCapture.VerifyCompletedImage(run.Head,run.Partial,CancellationToken.None);byte[] expected=(byte[])data.Clone();Array.Clear(expected,1024,512);Check(result.Sha256==Hash(expected)&&result.UnreadBytes==512&&result.Ranges.Count==1,"completed verification retains holes instead of claiming intact image");
        using(var token=new CancellationTokenSource()){token.Cancel();rejected=false;try{ResumableCapture.VerifyCompletedImage(run.Head,run.Partial,token.Token);}catch(OperationCanceledException){rejected=true;}Check(rejected,"completed verification cancels before reads");}
    }
}
