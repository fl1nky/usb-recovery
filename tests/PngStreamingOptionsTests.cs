using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using UsbRecovery;

public static class PngStreamingOptionsTests
{
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string file){using(var input=File.OpenRead(file))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static Control Find(Control parent,string name){if(parent.Name==name)return parent;foreach(Control child in parent.Controls){var found=Find(child,name);if(found!=null)return found;}return null;}
    static int Worker()
    {
        Console.InputEncoding=Encoding.UTF8;Console.OutputEncoding=new UTF8Encoding(false);
        string line=Console.ReadLine();var request=Json.Deserialize<Dictionary<string,object>>(line);
        var options=(Dictionary<string,object>)request["options"];
        string source=(string)request["source"],destination=(string)request["destination"];
        bool streaming=options.ContainsKey("streaming_png")&&(bool)options["streaming_png"];
        Directory.CreateDirectory(destination);File.WriteAllText(Path.Combine(destination,"received.json"),line,new UTF8Encoding(false));
        if(streaming){string index=destination+".index";if(Directory.Exists(index))throw new IOException("Fixture refused a stranded index.");Directory.CreateDirectory(index);File.WriteAllBytes(Path.Combine(index,"sector-crcs.bin"),new byte[(new FileInfo(source).Length/512+1)*4]);}
        bool emitMode=streaming&&!Path.GetFileName(source).StartsWith("old-component",StringComparison.Ordinal);
        bool partial=Path.GetFileName(source).StartsWith("partial",StringComparison.Ordinal);
        File.WriteAllText(Path.Combine(destination,"report.json"),Json.Serialize(new{Schema=1,Status=partial?"limited":"complete",Candidates=0,Files=new object[0],OutputBytes=0,VerifiedBytes=0,SourceUnchanged=true,SourceSha256=Hash(source),StreamingPng=emitMode,IndexBytes=emitMode?(new FileInfo(source).Length/512+1)*4:0}),new UTF8Encoding(false));
        Console.WriteLine(Json.Serialize(new{type="progress",completed=765432,total=1000000}));
        Console.WriteLine(Json.Serialize(new{type="result",status=partial?"partial":"complete",files=0,bytes=0}));return 0;
    }
    static RecoveryOptions Options(bool enabled){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,FragmentedPhotos=true,StreamingPngIndex=enabled};}
    [STAThread]
    public static int Main(string[] args)
    {
        if(args.Length==0)return Worker();
        try{
            string root=Path.GetFullPath(args[0]);Directory.CreateDirectory(root);
            Check(!Json.Deserialize<RecoveryOptions>("{}").StreamingPngIndex,"old session JSON defaults to original bounded mode");
            var saved=Json.Deserialize<RecoveryOptions>(Json.Serialize(Options(true)));
            Check(saved.StreamingPngIndex,"explicit new option survives JSON roundtrip");
            using(var panel=new RecoverySettingsPanel()){
                var big=(CheckBox)Find(panel,"usb-option-streaming-png");var photos=(CheckBox)Find(panel,"usb-option-reassemble-photos");
                Check(big!=null&&big.Checked&&!big.Enabled,"new control is selected but disabled until photo assembly is chosen");
                photos.Checked=true;Check(big.Enabled&&panel.Selection().StreamingPngIndex,"new Analyze selection enables persisted large PNG mode");
                big.Checked=false;Check(!panel.Selection().StreamingPngIndex,"user can preserve original bounded mode");
                panel.ApplyProfile("photos");Check(panel.Selection().FragmentedPhotos&&panel.Selection().StreamingPngIndex,"photos profile exposes large-source search");
                panel.ApplyProfile("maximum");Check(panel.Selection().StreamingPngIndex,"maximum profile also exposes it without increasing state caps");
            }
            foreach(bool enabled in new[]{false,true}){
                string source=Path.Combine(root,enabled?"streaming.dd":"bounded.dd"),output=Path.Combine(root,enabled?"streaming":"bounded");
                File.WriteAllBytes(source,new byte[4096]);string original=Hash(source);File.WriteAllText(source+".sha256",original,new UTF8Encoding(false));
                var result=RecoveryPipeline.Run(source,output,Options(enabled),CancellationToken.None,message=>{});
                Check(!result.HasWarnings,"actual pipeline accepts matching controlled helper mode");
                var request=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(output,"fragmented-photos","received.json")));
                var sent=(Dictionary<string,object>)request["options"];
                Check(enabled?sent.ContainsKey("streaming_png")&&(bool)sent["streaming_png"]:!sent.ContainsKey("streaming_png"),"actual child stdin contains exactly selected mode");
                Check(Hash(source)==original,"protocol test source remains unchanged");
                var session=RecoverySession.Read(output);Check(session.Options.StreamingPngIndex==enabled,"saved session retains mode used by actual pipeline");
                if(enabled){
                    Check(session.Stages.Single(s=>s.Key=="fragmented-photos").Artifacts.Any(a=>a.Path=="fragmented-photos.index/sector-crcs.bin"),"completed stage owns and hashes its disk index");
                    Check(!RecoveryCore.RecoveredFiles(output).Any(path=>path.Contains("fragmented-photos.index")),"working index is excluded from recovered files");
                    string index=Path.Combine(output,"fragmented-photos.index","sector-crcs.bin");var bytes=File.ReadAllBytes(index);bytes[0]^=1;File.WriteAllBytes(index,bytes);
                    bool tampered=false;try{RecoveryPipeline.Resume(output,CancellationToken.None,message=>{});}catch(IOException){tampered=true;}Check(tampered,"completed index tampering is rejected before stage reuse");
                }else{
                    string file=Path.Combine(output,RecoverySession.FileName);var old=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(file));((Dictionary<string,object>)old["Options"]).Remove("StreamingPngIndex");File.WriteAllText(file,Json.Serialize(old),new UTF8Encoding(false));
                    Check(!RecoverySession.Read(output).Options.StreamingPngIndex,"actual pre-feature session defaults to original mode");
                    var resumed=RecoveryPipeline.Resume(output,CancellationToken.None,message=>{});Check(resumed.ResumedStages==1,"actual old session reuses its completed original-mode stage");
                }
            }
            string legacySource=Path.Combine(root,"old-component.dd"),legacyOutput=Path.Combine(root,"old-component");File.WriteAllBytes(legacySource,new byte[4096]);File.WriteAllText(legacySource+".sha256",Hash(legacySource),new UTF8Encoding(false));
            bool rejected=false;try{RecoveryPipeline.Run(legacySource,legacyOutput,Options(true),CancellationToken.None,message=>{});}catch(IOException){rejected=true;}
            Check(rejected,"component that ignores new mode cannot report completed photo stage");
            var failed=RecoverySession.Read(legacyOutput).Stages.Single(s=>s.Key=="fragmented-photos");Check(failed.Status!="complete","incompatible helper remains explicitly incomplete");
            string partialSource=Path.Combine(root,"partial.dd"),partialOutput=Path.Combine(root,"partial");File.WriteAllBytes(partialSource,new byte[4096]);File.WriteAllText(partialSource+".sha256",Hash(partialSource),new UTF8Encoding(false));
            var updates=new List<string>();rejected=false;try{RecoveryPipeline.Run(partialSource,partialOutput,Options(true),CancellationToken.None,updates.Add);}catch(IOException){rejected=true;}
            Check(rejected,"limited helper remains incomplete in actual pipeline");
            Check(updates.Any(value=>value=="Фрагменты фотографий: 76%"),"CPU join progress reaches actual pipeline");
            Check(!updates.Any(value=>value=="Фрагменты фотографий: 100%"),"bounded partial pass never emits a synthetic full progress update");
            rejected=false;try{RecoveryPipeline.Resume(partialOutput,CancellationToken.None,message=>{});}catch(IOException){rejected=true;}
            Check(rejected,"second bounded fixture interval remains incomplete");
            var previous=Directory.GetDirectories(Path.Combine(partialOutput,"attempt-history")).Single();
            Check(File.Exists(Path.Combine(previous,"fragmented-photos.index","sector-crcs.bin")),"retry without acknowledged checkpoint preserves previous index with prior attempt");
            Check(File.Exists(Path.Combine(partialOutput,"fragmented-photos.index","sector-crcs.bin")),"retry has a fresh owned index");
            Check(!RecoveryCore.RecoveredFiles(partialOutput).Any(path=>path.Contains("fragmented-photos.index")),"archived index is excluded from recovered files too");
            Console.WriteLine("PASS PngStreamingOptions: "+checks+" checks; actual pipeline/stdin/session, selectable UI and incompatible component rejection. Controlled protocol fixture only; no PNG decoding or device claim.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
