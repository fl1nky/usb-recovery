using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using UsbRecovery;

public static class RecoverySessionTests
{
    static int checks,folders;static string root;static byte[] imageData;
    sealed class Run { public string Source,Folder,SourceHash,Photo;public DateTime PhotoTime;public RecoveryOptions Options; }
    static string Hash(string file){using(var input=File.OpenRead(file))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static bool Io(Action action){try{action();return false;}catch(IOException){return true;}}
    static string Dir(string name){string path=Path.Combine(root,"r"+(++folders).ToString("D2"));Directory.CreateDirectory(path);return path;}
    static RecoveryOptions Options(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=true,Containers=false,MetadataRescue=false,ArchiveMembers=true,TextFragments=false};}
    static byte[] Image()
    {
        byte[] bytes=new byte[12*1024*1024];byte[] photo;using(var bitmap=new Bitmap(32,24))using(var stream=new MemoryStream()){using(var g=Graphics.FromImage(bitmap))g.Clear(Color.CornflowerBlue);bitmap.Save(stream,ImageFormat.Png);photo=stream.ToArray();}Buffer.BlockCopy(photo,0,bytes,123,photo.Length);
        byte[] content=Encoding.UTF8.GetBytes("Family recipe recovered from ZIP\nСекрет пирожков — яблоки"),name=Encoding.UTF8.GetBytes("docs/recipe.txt");uint crc=0xffffffff;foreach(byte b in content){crc^=b;for(int i=0;i<8;i++)crc=(crc&1)==0?crc>>1:(crc>>1)^0xedb88320;}
        using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)){
            writer.Write(0x04034b50U);writer.Write((ushort)20);writer.Write((ushort)0x800);writer.Write((ushort)0);writer.Write(0U);writer.Write(~crc);writer.Write((uint)content.Length);writer.Write((uint)content.Length);writer.Write((ushort)name.Length);writer.Write((ushort)0);writer.Write(name);writer.Write(content);writer.Flush();byte[] zip=stream.ToArray();Buffer.BlockCopy(zip,0,bytes,2*1024*1024+17,zip.Length);
        }return bytes;
    }
    static Run Cancelled(string name,bool sourceMap=false)
    {
        string work=Dir(name);var run=new Run{Source=Path.Combine(work,"source.dd"),Folder=Path.Combine(work,"results"),Options=Options()};Directory.CreateDirectory(run.Folder);File.WriteAllBytes(run.Source,imageData);run.SourceHash=Hash(run.Source);File.WriteAllText(run.Source+".sha256",run.SourceHash);
        if(sourceMap)RecoveryCore.SaveJson(run.Source+".read-errors.json",new{status="complete",size=(long)imageData.Length,copied=(long)imageData.Length,unreadBytes=0,ranges=new ResumableRange[0]});
        using(var cancel=new CancellationTokenSource()){
            bool stopped=false;try{RecoveryPipeline.Run(run.Source,run.Folder,run.Options,cancel.Token,message=>{string members=Path.Combine(run.Folder,"salvage-content");if(message.StartsWith("Части архивов:",StringComparison.Ordinal)&&Directory.Exists(members)&&Directory.GetFiles(members).Any(p=>!p.EndsWith(".partial",StringComparison.OrdinalIgnoreCase)))cancel.Cancel();});}catch(OperationCanceledException){stopped=true;}
            Check(stopped,"cancelled after second method saved a candidate");
        }
        var state=RecoverySession.Read(run.Folder);Check(state.Status=="cancelled"&&state.Stages.Single(x=>x.Key=="photos").Status=="complete"&&state.Stages.Single(x=>x.Key=="archive-members").Status=="cancelled","session distinguishes complete and interrupted methods");run.Photo=Directory.GetFiles(Path.Combine(run.Folder,"extra-photos")).Single();run.PhotoTime=File.GetLastWriteTimeUtc(run.Photo);Check(Hash(run.Source)==run.SourceHash,"cancelled scan leaves source unchanged");return run;
    }
    static void ResumeAndHistory()
    {
        var run=Cancelled("resume-history");string photoHash=Hash(run.Photo);var logs=new List<string>();var result=RecoveryPipeline.Resume(run.Folder,CancellationToken.None,logs.Add);
        Check(result.ResumedStages==1&&logs.Any(x=>x.Contains("повторный проход не нужен")),"completed method reused with explicit progress");Check(File.GetLastWriteTimeUtc(run.Photo)==run.PhotoTime&&Hash(run.Photo)==photoHash,"reused output neither rewritten nor moved");
        var state=RecoverySession.Read(run.Folder);Check(state.Stages.All(x=>x.Status=="complete")&&state.Status=="finished_with_warnings","resumed session retains all completed stages and history warning");
        string history=Path.Combine(run.Folder,"attempt-history");Check(Directory.Exists(history)&&Directory.GetDirectories(history).Length==1,"interrupted method retained in one history attempt");Check(Directory.GetFiles(history,"member-*",SearchOption.AllDirectories).Length==1,"previous completed ZIP member retained");Check(Directory.GetFiles(history,"archive-salvage.json",SearchOption.AllDirectories).Length==1,"previous provenance report retained");
        var index=RecoveryCatalog.Load(run.Folder);Check(index.Items.Count==2&&index.Candidates==3,"old and new equal members deduplicate by content with candidates retained");var member=index.Items.Single(x=>x.Name.Contains("recipe"));Check(member.Copies.Count==1&&member.Copies.Concat(new[]{member.Path}).Any(x=>x.StartsWith("attempt-history/",StringComparison.Ordinal)),"history path kept as provenance alias");Check(member.Quality=="member_crc","history-aware member retains manifest-backed CRC proof");Check(Hash(run.Source)==run.SourceHash,"resume leaves source immutable");
        string before=Hash(Path.Combine(run.Folder,RecoverySession.FileName));using(var cancel=new CancellationTokenSource()){cancel.Cancel();bool stopped=false;try{RecoveryPipeline.Resume(run.Folder,cancel.Token,null);}catch(OperationCanceledException){stopped=true;}Check(stopped&&Hash(Path.Combine(run.Folder,RecoverySession.FileName))==before,"pre-cancelled resume changes no manifest");}
        result=RecoveryPipeline.Resume(run.Folder,CancellationToken.None,null);Check(result.ResumedStages==2&&RecoveryCatalog.Load(run.Folder).Items.Count==2,"finished session can rebuild catalog while reusing both methods");Check(Directory.GetDirectories(history).Length==1,"reopening completed session does not manufacture extra history");
    }
    static void Invalidated(string name,Action<Run> mutate)
    {
        var run=Cancelled(name);mutate(run);string head=Hash(Path.Combine(run.Folder,RecoverySession.FileName)),source=Hash(run.Source),photo=Hash(run.Photo);bool rejected=Io(()=>RecoveryPipeline.Resume(run.Folder,CancellationToken.None,null));Check(rejected,"resume rejects "+name);Check(Hash(Path.Combine(run.Folder,RecoverySession.FileName))==head&&Hash(run.Source)==source&&Hash(run.Photo)==photo,"rejected "+name+" preserves session/source/output");Check(!Directory.Exists(Path.Combine(run.Folder,"attempt-history")),"rejected "+name+" moves no interrupted output");
    }
    static void RejectionCases()
    {
        Invalidated("source-changed",run=>{using(var file=new FileStream(run.Source,FileMode.Open,FileAccess.Write)){file.Position=8000;file.WriteByte(31);}});
        Invalidated("output-changed",run=>File.AppendAllText(run.Photo,"output changed after checkpoint"));
        Invalidated("extra-completed-file",run=>File.WriteAllText(Path.Combine(run.Folder,"extra-photos","foreign.txt"),"not produced by this completed stage"));
        Invalidated("untracked-method-root",run=>{string path=Path.Combine(run.Folder,"filesystem","files");Directory.CreateDirectory(path);File.WriteAllText(Path.Combine(path,"foreign.txt"),"not produced by any tracked method");});
        Invalidated("changed-run-map",run=>RecoveryCore.SaveJson(Path.Combine(run.Folder,"source-read-errors.json"),new{status="complete",size=(long)imageData.Length,copied=(long)imageData.Length,unreadBytes=0,ranges=new ResumableRange[0]}));
        Invalidated("added-source-map",run=>RecoveryCore.SaveJson(run.Source+".read-errors.json",new{status="complete_with_read_errors",size=(long)imageData.Length,copied=(long)imageData.Length,unreadBytes=512,ranges=new[]{new ResumableRange{Offset=8192,Length=512}}}));
        var mapped=Cancelled("removed-source-map",true);File.Delete(mapped.Source+".read-errors.json");Check(Io(()=>RecoveryPipeline.Resume(mapped.Folder,CancellationToken.None,null)),"removed adjacent source map rejected");
        mapped=Cancelled("changed-source-map",true);File.AppendAllText(mapped.Source+".read-errors.json"," ");Check(Io(()=>RecoveryPipeline.Resume(mapped.Folder,CancellationToken.None,null)),"changed adjacent source map rejected even with valid semantics");
        var scenario=Cancelled("invalid-schema");var state=RecoverySession.Read(scenario.Folder);state.Schema=99;RecoveryCore.SaveJson(Path.Combine(scenario.Folder,RecoverySession.FileName),state);Check(Io(()=>RecoverySession.Read(scenario.Folder)),"unknown session schema rejected");
        scenario=Cancelled("traversal-artifact");state=RecoverySession.Read(scenario.Folder);state.Stages.First(x=>x.Status=="complete").Artifacts[0].Path="../outside-file";RecoveryCore.SaveJson(Path.Combine(scenario.Folder,RecoverySession.FileName),state);Check(Io(()=>RecoverySession.Read(scenario.Folder)),"artifact traversal rejected before file reads");
        scenario=Cancelled("unsafe-source-path");state=RecoverySession.Read(scenario.Folder);state.SourcePath=Path.Combine(scenario.Folder,"search-options.json");RecoveryCore.SaveJson(Path.Combine(scenario.Folder,RecoverySession.FileName),state);Check(Io(()=>RecoverySession.Read(scenario.Folder)),"source/report collision rejected by manifest source location");
        scenario=Cancelled("duplicate-stage");state=RecoverySession.Read(scenario.Folder);state.Stages.Add(state.Stages[0]);RecoveryCore.SaveJson(Path.Combine(scenario.Folder,RecoverySession.FileName),state);Check(Io(()=>RecoverySession.Read(scenario.Folder)),"duplicate stage rejected");
        scenario=Cancelled("options-changed");var options=Options();options.ArchiveMembers=false;Check(Io(()=>RecoverySession.Open(scenario.Folder,scenario.Source,options,CancellationToken.None,null)),"changed options rejected instead of silently mixing methods");
    }
    static DiskInfo Device(int number){return new DiskInfo{Number=number,Name="Synthetic USB",Serial="SERIAL-TEST",UniqueId="UNIQUE-TEST",Size=imageData.Length,SectorSize=512,BusType="USB"};}
    static void PureDeviceIdentity()
    {
        var old=Device(4);var current=Device(15);Check(RecoveryCore.ResumeDeviceMatches(old,current),"physical number may change after reconnect");Check(RecoveryCore.CaptureIdentity(old)==RecoveryCore.CaptureIdentity(current),"durable identity omits physical number");current.Serial="OTHER";Check(!RecoveryCore.ResumeDeviceMatches(old,current),"changed serial rejected");current=Device(15);current.UniqueId="OTHER";Check(!RecoveryCore.ResumeDeviceMatches(old,current),"changed unique id rejected");current=Device(15);current.Size+=512;Check(!RecoveryCore.ResumeDeviceMatches(old,current),"changed size rejected");current=Device(15);current.SectorSize=4096;Check(!RecoveryCore.ResumeDeviceMatches(old,current),"changed sector geometry rejected");current=Device(15);current.IsSystem=true;Check(!RecoveryCore.ResumeDeviceMatches(old,current),"system device never selected for resume");current=Device(15);current.IsBoot=true;Check(!RecoveryCore.ResumeDeviceMatches(old,current),"boot device never selected for resume");current=Device(15);current.IsOffline=true;Check(!RecoveryCore.ResumeDeviceMatches(old,current),"offline device never selected");current=Device(15);current.Serial=current.UniqueId=null;Check(!RecoveryCore.ResumeDeviceMatches(old,current),"identity-less device rejected");Check(!RecoveryCore.ResumeDeviceMatches(null,current)&&!RecoveryCore.ResumeDeviceMatches(old,null),"missing device rejected");
    }
    static T Field<T>(object instance,string name)where T:class{return instance.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(instance)as T;}
    static void UiCase(string name,Func<RecoveryForm,Task> action)
    {
        Exception error=null;using(var form=new RecoveryForm(false))using(var watchdog=new System.Windows.Forms.Timer()){
            form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.ShowInTaskbar=false;watchdog.Interval=15000;watchdog.Tick+=delegate{error=new Exception("UI case timed out: "+name);form.Close();Application.ExitThread();};
            form.Shown+=async delegate{watchdog.Start();try{await action(form);}catch(Exception ex){error=ex;}finally{watchdog.Stop();form.Close();}};Application.Run(form);
        }if(error!=null)throw error;
    }
    static void UiResume()
    {
        var run=Cancelled("ui-resume");UiCase("resume",async form=>{bool completed=await form.ContinueSavedJobAsync(run.Folder);Check(completed&&!form.IsBusy,"real message-loop resume completes and returns idle");Check(Field<Button>(form,"continueJob").Enabled&&!Field<Button>(form,"stop").Enabled,"continue/stop button states restored");Check(RecoveryCatalog.Load(run.Folder).Items.Count==2,"UI exposes resumed catalog");});Check(Hash(run.Source)==run.SourceHash,"UI resume source immutable");
        run=Cancelled("ui-cancel");UiCase("cancel",async form=>{var pending=form.ContinueSavedJobAsync(run.Folder);Check(form.IsBusy,"resume sets busy before async verification");Field<Button>(form,"stop").PerformClick();bool completed=await pending;Check(!completed&&!form.IsBusy,"stopped resume returns false and idle");Check(File.ReadAllText(Path.Combine(run.Folder,"result.json")).Contains("cancelled"),"UI records cancellation separately from completed state");});
        string bad=Dir("truncated-promoted");var request=new CaptureRequestInfo{Disk=Device(999),TolerateErrors=false};RecoveryCore.SaveJson(Path.Combine(bad,"capture-request.json"),request);RecoveryCore.SaveJson(Path.Combine(bad,"search-options.json"),new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,TextFragments=true,TextQuery="family"});string image=Path.Combine(bad,"usb.dd");File.WriteAllText(image,"Family recipe is only a truncated candidate, never a completed acquisition.");string original=Hash(image);UiCase("truncated capture",async form=>{bool completed=await form.ContinueSavedJobAsync(bad);Check(!completed&&!form.IsBusy,"existing incomplete usb.dd cannot bypass saved capture size/proof");Check(!File.Exists(Path.Combine(bad,RecoverySession.FileName))&&!File.Exists(image+".sha256"),"unverified promoted image produces no successful session/SHA baseline");});Check(Hash(image)==original,"invalid promoted image left unchanged");
        string captured=Dir("verified-promoted");request=new CaptureRequestInfo{Disk=Device(999),TolerateErrors=false};RecoveryCore.SaveJson(Path.Combine(captured,"capture-request.json"),request);var onlyPhotos=Options();onlyPhotos.ArchiveMembers=false;RecoveryCore.SaveJson(Path.Combine(captured,"search-options.json"),onlyPhotos);string partial=Path.Combine(captured,"usb.dd.partial"),head=Path.Combine(captured,"capture-resume.json");using(var input=new MemoryStream(imageData,false))ResumableCapture.Copy(input,partial,imageData.Length,512,RecoveryCore.CaptureIdentity(request.Disk),head,Path.Combine(captured,"usb.dd.read-errors.json"),CancellationToken.None,null,null);image=Path.Combine(captured,"usb.dd");File.Move(partial,image);original=Hash(image);UiCase("verified promoted capture",async form=>{bool completed=await form.ContinueSavedJobAsync(captured);Check(completed&&!form.IsBusy,"verified completed image resumes without physical device reconnect");Check(File.Exists(image+".sha256")&&File.ReadAllText(image+".sha256").Contains(original),"missing sidecar reconstructed only from verified completed journal");Check(RecoveryCatalog.Load(captured).Items.Count==1,"verified promoted capture reaches correct file catalog");});Check(Hash(image)==original,"verified promoted image remains immutable");
        string moved=Dir("moved-session");foreach(string file in Directory.GetFiles(captured,"*",SearchOption.AllDirectories)){string relative=file.Substring(captured.Length+1),target=RecoveryCatalog.SafeFile(moved,relative);Directory.CreateDirectory(Path.GetDirectoryName(target));File.Copy(file,target);}var relocated=RecoverySession.Read(moved);Check(relocated.SourcePath==Path.Combine(moved,"usb.dd"),"in-folder image binding resolves after whole session is copied");var resumed=RecoveryPipeline.Resume(moved,CancellationToken.None,null);Check(resumed.ResumedStages==1&&RecoveryCatalog.Load(moved).Items.Count==1,"whole moved working folder reuses verified stage");Check(Hash(Path.Combine(moved,"usb.dd"))==original&&Hash(image)==original,"moving session preserves original and copied images");
        captured=Dir("completed-partial");RecoveryCore.SaveJson(Path.Combine(captured,"capture-request.json"),request);RecoveryCore.SaveJson(Path.Combine(captured,"search-options.json"),onlyPhotos);partial=Path.Combine(captured,"usb.dd.partial");head=Path.Combine(captured,"capture-resume.json");using(var input=new MemoryStream(imageData,false))ResumableCapture.Copy(input,partial,imageData.Length,512,RecoveryCore.CaptureIdentity(request.Disk),head,Path.Combine(captured,"usb.dd.read-errors.json"),CancellationToken.None,null,null);UiCase("complete before promotion",async form=>{bool completed=await form.ContinueSavedJobAsync(captured);Check(completed&&!form.IsBusy,"fully committed partial can finalize without reconnecting source");Check(File.Exists(Path.Combine(captured,"usb.dd"))&&!File.Exists(partial),"verified complete partial promoted only after journal verification");Check(RecoveryCatalog.Load(captured).Items.Count==1,"completed partial finalization reaches usable catalog");});
    }
    [STAThread]public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args.Length>0?args[0]:Directory.GetCurrentDirectory());root=Path.Combine(project,".build","rs-"+DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ"));Directory.CreateDirectory(root);imageData=Image();Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            ResumeAndHistory();RejectionCases();PureDeviceIdentity();UiResume();string summary="PASS RecoverySession: "+checks+" checks; completed-method reuse, interrupted-history provenance/dedup, source/output/file-set/map/schema/traversal/option rejection, pure reconnect identity, proper-message-loop UI resume/cancel and verified promoted acquisition; synthetic regular images only, physical discovery disabled. Results: "+root;
            Console.WriteLine(summary);File.WriteAllText(Path.Combine(project,"tests","RecoverySessionTests.result.txt"),summary,Encoding.UTF8);return 0;
        }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}
    }
}
