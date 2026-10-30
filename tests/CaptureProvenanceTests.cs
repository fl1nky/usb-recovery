using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Exercises the real managed pipeline with synthetic ordinary images only.
public static class CaptureProvenanceTests
{
    static string root;
    static int checks,sequence;
    const string Serial="SYNTHETIC USB · Семейные рецепты";
    static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=4*1024*1024};}
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(done,total)=>{});}
    static Dictionary<string,object> Read(string path){return Json().Deserialize<Dictionary<string,object>>(File.ReadAllText(path,Encoding.UTF8));}
    static Dictionary<string,object> Report(string sha,long size,string status="complete",long unread=0)
    {return new Dictionary<string,object>{{"status",status},{"size",size},{"sha256",sha},{"unreadBytes",unread},{"sourceDisk",987},{"sourceSerial",Serial},{"sourceUniqueId","SYNTHETIC-IDENTITY"},{"access","GENERIC_READ"}};}
    static void Analyze(string label,Action<Dictionary<string,object>> mutate,bool expectCapture,bool storage=false,bool malformed=false,bool oversized=false,bool present=true,bool external=true,bool readErrors=false,bool missingMap=false)
    {
        string directory=Path.Combine(root,(++sequence).ToString("D2")+"-"+label),source=Path.Combine(directory,"input"),output=Path.Combine(directory,"output");Directory.CreateDirectory(source);Directory.CreateDirectory(output);
        string image=Path.Combine(source,"external.dd"),capture=Path.Combine(source,"capture.json"),metadata=Path.Combine(output,"source-image.json"),checksum=external?Path.Combine(output,"source.sha256"):image+".sha256";
        byte[] bytes=new byte[8192];Encoding.UTF8.GetBytes("familyrecipe · Секрет пирожков 🥟\n").CopyTo(bytes,1024);File.WriteAllBytes(image,bytes);string imageHash=Hash(image);File.WriteAllText(checksum,imageHash,new UTF8Encoding(false));
        var report=Report(imageHash,bytes.Length,readErrors?"complete_with_read_errors":"complete",readErrors?512:0);if(mutate!=null)mutate(report);
        if(oversized)report["padding"]=new string('x',1024*1024);
        if(present){if(malformed)File.WriteAllText(capture,"{broken JSON",new UTF8Encoding(false));else RecoveryCore.SaveJson(capture,report);}
        string captureHash=present?Hash(capture):null;
        if(readErrors&&!missingMap)RecoveryCore.SaveJson(image+".read-errors.json",new{status="complete_with_read_errors",size=(long)bytes.Length,copied=(long)bytes.Length,unreadBytes=512,ranges=new[]{new ResumableRange{Offset=4096,Length=512}}});
        if(storage)RecoveryCore.SaveJson(metadata,new{origin="prepared_storage_image",sourcePath=image,completeness="prepared_under_reported_parameters",preparationReportDirectory=source});
        string storageHash=storage?Hash(metadata):null;var progress=new List<string>();
        var options=new RecoveryOptions{FatMetadata=true,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,TextFragments=true,TextQuery="familyrecipe"};
        ScanResult result=RecoveryPipeline.Run(image,output,options,CancellationToken.None,progress.Add,external?checksum:null);
        Check(File.Exists(Path.Combine(output,"files-index.json"))&&File.Exists(Path.Combine(output,RecoverySession.FileName)),"analysis completes with its catalog and session: "+label);
        Check(Hash(image)==imageHash,"analysis preserves the source image: "+label);
        if(present)Check(Hash(capture)==captureHash,"analysis preserves the original sidecar: "+label);
        var row=Read(metadata);
        if(storage){Check(Hash(metadata)==storageHash,"storage preparation provenance is not overwritten by a neighboring capture: "+label);Check(Convert.ToString(row["origin"])=="prepared_storage_image"&&!row.ContainsKey("sourceSerial"),"storage provenance does not gain unrelated device identity: "+label);}
        else if(expectCapture){Check(Convert.ToString(row["sha256"])==Convert.ToString(report["sha256"])&&Convert.ToString(row["sourceSerial"])==Serial,"only a matching completed capture retains its device identity: "+label);Check(Convert.ToInt64(row["size"])==bytes.Length&&Convert.ToString(row["status"])==Convert.ToString(report["status"]),"matching capture retains checked size and acquisition state: "+label);}
        else{Check(Convert.ToString(row["origin"])=="external_image"&&Convert.ToString(row["completeness"])=="unknown","unconfirmed external completeness remains unknown: "+label);Check(!row.ContainsKey("sourceSerial")&&!row.ContainsKey("sourceDisk")&&!row.ContainsKey("sourceUniqueId"),"an unrelated or malformed sidecar cannot claim an originating USB: "+label);}
        if(external)Check(result.HasWarnings,"external image retains its explicit uncertainty: "+label);
        if(present&&!storage&&!expectCapture)Check(progress.Any(line=>line.Contains("capture.json")),"rejected optional sidecar is explained without aborting the scan: "+label);
        Check(RecoverySession.Read(output).SourceSha256==imageHash,"session binds the actual verified image: "+label);
        bool unsafeExpected=readErrors&&(!missingMap||expectCapture&&!storage);
        Check(FileEvidence.HasUnreadSource(output,image)==unsafeExpected&&FileEvidence.Load(output).HasReadErrors==unsafeExpected,"read-error state follows matching source evidence even if its range map was lost: "+label);
        Check(RecoverySession.Read(output).Stages.Any(stage=>stage.Key=="fat")==!unsafeExpected,"only safe sources run allocation-metadata recovery: "+label);
        if(readErrors&&missingMap&&expectCapture&&!storage){
            Check(FileEvidence.Load(output).Unread.Count==0,"lost error map never invents exact unread ranges");
            row["sha256"]=new string('3',64);RecoveryCore.SaveJson(metadata,row);Check(!FileEvidence.HasUnreadSource(output,image),"a changed capture hash cannot establish source read errors");
            row["sha256"]=imageHash;row["size"]=bytes.Length+1;RecoveryCore.SaveJson(metadata,row);Check(!FileEvidence.HasUnreadSource(output,image),"a changed capture length cannot establish source read errors");
        }
    }
    static void WorkingCaptureWithoutMap()
    {
        string output=Path.Combine(root,(++sequence).ToString("D2")+"-working-capture");Directory.CreateDirectory(output);
        string image=Path.Combine(output,"usb.dd");File.WriteAllText(image,"familyrecipe synthetic original\n"+new string('x',4096),new UTF8Encoding(false));string sha=Hash(image);
        File.WriteAllText(image+".sha256",sha,new UTF8Encoding(false));RecoveryCore.SaveJson(Path.Combine(output,"capture.json"),Report(sha,new FileInfo(image).Length,"complete_with_read_errors",512));
        var options=new RecoveryOptions{FatMetadata=true,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,TextFragments=true,TextQuery="familyrecipe"};
        ScanResult result=RecoveryPipeline.Run(image,output,options,CancellationToken.None,line=>{});
        Check(result.HasWarnings&&FileEvidence.HasUnreadSource(output,image),"in-place acquisition report remains unsafe after its map is lost");
        Check(!RecoverySession.Read(output).Stages.Any(stage=>stage.Key=="fat"),"in-place acquisition skips allocation metadata without a map");
        Check(FileEvidence.Load(output).HasReadErrors&&FileEvidence.Load(output).Unread.Count==0,"catalog records missing error ranges instead of treating zeroes as evidence");
        Check(Hash(image)==sha,"lost-map handling preserves the actual image");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args.Length==0?Directory.GetCurrentDirectory():args[0]);root=Path.Combine(project,".build","audit-cleanup","capture-provenance-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(root);
            Analyze("matching",null,true);Analyze("uppercase-hash",row=>row["sha256"]=Convert.ToString(row["sha256"]).ToUpperInvariant(),true);
            Analyze("matching-read-errors",null,true,readErrors:true);Analyze("matching-internal",null,true,external:false);
            Analyze("matching-lost-map",null,true,readErrors:true,missingMap:true);
            Analyze("mismatched-lost-map",row=>row["sha256"]=new string('1',64),false,readErrors:true,missingMap:true);
            Analyze("storage-lost-map-neighbor",null,false,storage:true,readErrors:true,missingMap:true);
            Analyze("wrong-sha",row=>row["sha256"]=new string('1',64),false);Analyze("wrong-size",row=>row["size"]=8193L,false);
            Analyze("incomplete",row=>row["status"]="incomplete",false);Analyze("unknown-status",row=>row["status"]="future_format",false);
            Analyze("inconsistent-complete",row=>row["unreadBytes"]=512L,false);Analyze("inconsistent-read-errors",row=>row["status"]="complete_with_read_errors",false);
            Analyze("invalid-unread",row=>row["unreadBytes"]=-1L,false);Analyze("missing-sha",row=>row.Remove("sha256"),false);
            Analyze("malformed",null,false,malformed:true);Analyze("oversized",null,false,oversized:true);Analyze("no-sidecar",null,false,present:false);
            Analyze("storage-matching-neighbor",null,false,storage:true);Analyze("storage-unrelated-neighbor",row=>row["sha256"]=new string('2',64),false,storage:true);
            WorkingCaptureWithoutMap();
            string summary="PASS CaptureProvenance: "+checks+" assertions; real image pipeline, matching acquisition identity, SHA/length/status/read-error validation, lost-map allocation safeguards, unknown external completeness, malformed and oversized sidecars, unchanged storage provenance and source files. Synthetic ordinary files only. "+root;
            Console.WriteLine(summary);File.WriteAllText(Path.Combine(root,"result.txt"),summary,new UTF8Encoding(false));return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
