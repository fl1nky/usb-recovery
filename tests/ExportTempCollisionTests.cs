using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Ordinary owned files only; no physical disks or user data.
public static class ExportTempCollisionTests
{
    static string root;
    static int checks,sequence;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Hash(string path){using(var input=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();}
    static string Case(){string path=Path.Combine(root,(++sequence).ToString("D3"));Directory.CreateDirectory(path);return path;}
    static RecoveredItem Write(string directory,string filename,string name,string body)
    {
        string path=Path.Combine(directory,filename);File.WriteAllText(path,body,new UTF8Encoding(false));
        return new RecoveredItem{Path=filename,Name=name,Bytes=new FileInfo(path).Length,Sha256=Hash(path)};
    }
    static RecoveredItem Origin(RecoveredItem item,string path,bool apfs)
    {
        item.OriginalLocations.Add(new OriginalLocation{Path="/"+path,Status=apfs?"apfs_referenced_path":"verified_parent_chain",Evidence="Own synthetic metadata path",CandidatePath=item.Path,VolumeOffset=0,FileSystem=apfs?"APFS":"NTFS",VolumeId=apfs?"test":null,Components=apfs?path.Split('/').ToList():null});return item;
    }
    static object Invoke(string method,params object[] arguments)
    {
        try{return typeof(RecoveryCatalog).GetMethod(method,BindingFlags.Static|BindingFlags.NonPublic).Invoke(null,arguments);}
        catch(TargetInvocationException error){throw error.InnerException;}
    }
    static Exception Failure(Action action){try{action();return null;}catch(Exception error){return error;}}
    static void NoTemporary(string directory){Check(!Directory.GetFiles(directory,".export-*.partial",SearchOption.AllDirectories).Any(),"owned temporary files are cleaned");}
    static void HierarchyCollision(bool apfs,bool reversed,bool directoryCollision)
    {
        string folder=Case(),source=Path.Combine(folder,"source"),destination=Path.Combine(folder,"out");Directory.CreateDirectory(source);Directory.CreateDirectory(destination);
        var original=Origin(Write(source,"one.bin","a.partial","FIRST VALID FILE · Пирожки 🥟"),"a.partial"+(directoryCollision?"/child.txt":""),apfs);
        var second=Origin(Write(source,"two.bin","a","SECOND VALID FILE"),"a",apfs);
        var items=reversed?new[]{second,original}:new[]{original,second};
        string output=(string)Invoke("ExportFilesPreservingFolders",source,destination,items,CancellationToken.None);
        var manifest=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(output,"export-manifest.json"),Encoding.UTF8));
        var rows=((IEnumerable)manifest["files"]).Cast<object>().Cast<Dictionary<string,object>>().ToArray();
        Check(Convert.ToString(manifest["status"])=="complete"&&rows.Length==2,"both originals publish a complete manifest");
        foreach(var row in rows){string file=RecoveryCatalog.SafeFile(output,Convert.ToString(row["file"]));Check(File.Exists(file)&&Hash(file)==Convert.ToString(row["sha256"]),"every published final file still exists with its expected bytes");}
        foreach(var item in items)Check(Hash(Path.Combine(source,item.Path))==item.Sha256,"source bytes preserved through filename collisions");
        NoTemporary(output);
    }
    static void Copy(string source,string target,string temporary,RecoveredItem item,CancellationToken token)
    {Invoke("CopyExportFile",source,target,temporary,item,token);}
    static void ExistingTemporary(bool readOnly)
    {
        string directory=Case(),source=Path.Combine(directory,"source.bin"),temporary=Path.Combine(directory,"existing.partial"),target=Path.Combine(directory,"target.bin");
        var item=Write(directory,"source.bin","source.bin","SOURCE MUST SURVIVE");File.WriteAllText(temporary,"PREEXISTING FILE",new UTF8Encoding(false));string before=Hash(temporary);
        if(readOnly)File.SetAttributes(temporary,FileAttributes.ReadOnly);
        try{
            Exception error=Failure(()=>Copy(source,target,temporary,item,CancellationToken.None));
            Check(error is IOException||error is UnauthorizedAccessException,"CreateNew rejects the existing temporary path");
            Check(File.Exists(temporary)&&Hash(temporary)==before,"failed CreateNew never deletes or overwrites another file");
            Check(Hash(source)==item.Sha256&&!File.Exists(target),"failed temporary creation preserves source and publishes no result");
            if(readOnly)Check((File.GetAttributes(temporary)&FileAttributes.ReadOnly)!=0,"existing read-only attributes preserved");
        }finally{if(readOnly)File.SetAttributes(temporary,FileAttributes.Normal);}
    }
    static void ExistingDestination(bool readOnly,bool directoryTarget)
    {
        string directory=Case(),source=Path.Combine(directory,"source.bin"),temporary=Path.Combine(directory,"own.partial"),target=Path.Combine(directory,"target.bin");
        var item=Write(directory,"source.bin","source.bin","SOURCE ORIGINAL");
        if(directoryTarget)Directory.CreateDirectory(target);else{File.WriteAllText(target,"EXISTING DESTINATION",new UTF8Encoding(false));if(readOnly)File.SetAttributes(target,FileAttributes.ReadOnly);}
        string before=directoryTarget?null:Hash(target);
        try{
            Exception error=Failure(()=>Copy(source,target,temporary,item,CancellationToken.None));
            Check(error is IOException||error is UnauthorizedAccessException,"existing final path rejects publication");
            Check(directoryTarget?Directory.Exists(target):File.Exists(target)&&Hash(target)==before,"existing destination stays untouched");
            Check(!File.Exists(temporary)&&Hash(source)==item.Sha256,"only the created temporary is removed after a failed move");
            if(readOnly)Check((File.GetAttributes(target)&FileAttributes.ReadOnly)!=0,"existing destination remains read-only");
        }finally{if(readOnly)File.SetAttributes(target,FileAttributes.Normal);}
    }
    static void SourceFailure(bool hashMismatch,bool sizeMismatch,bool cancel)
    {
        string directory=Case(),source=Path.Combine(directory,"source.bin"),temporary=Path.Combine(directory,"own.partial"),target=Path.Combine(directory,"target.bin");
        var item=Write(directory,"source.bin","source.bin","НЕ МЕНЯТЬ ИСХОДНИК");string before=Hash(source);File.SetAttributes(source,FileAttributes.ReadOnly);
        if(hashMismatch)item.Sha256=new string('0',64);if(sizeMismatch)item.Bytes++;
        try{
            using(var cancellation=new CancellationTokenSource()){
                if(cancel)cancellation.Cancel();Exception error=Failure(()=>Copy(source,target,temporary,item,cancellation.Token));
                Check(cancel?error is OperationCanceledException:error is IOException,"invalid input or cancellation never reports success");
                Check(!File.Exists(target)&&!File.Exists(temporary),"failed verification leaves no final file or owned partial");
                Check(Hash(source)==before&&(File.GetAttributes(source)&FileAttributes.ReadOnly)!=0,"read-only source bytes and attributes preserved");
            }
        }finally{File.SetAttributes(source,FileAttributes.Normal);}
    }
    static void UnavailableSource()
    {
        string directory=Case(),source=Path.Combine(directory,"source.bin"),temporary=Path.Combine(directory,"existing.partial"),target=Path.Combine(directory,"target.bin");
        var item=Write(directory,"source.bin","source.bin","LOCKED ORIGINAL");File.WriteAllText(temporary,"PREEXISTING TEMPORARY",new UTF8Encoding(false));string before=Hash(temporary);
        using(var locked=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.None)){
            Check(Failure(()=>Copy(source,target,temporary,item,CancellationToken.None)) is IOException,"locked source fails before creating a temporary");
            Check(File.Exists(temporary)&&Hash(temporary)==before&&!File.Exists(target),"opening a source unsuccessfully cannot delete an unrelated file");
        }
        Check(Hash(source)==item.Sha256,"locked source remains intact");
    }
    public static int Main(string[] args)
    {
        try{
            string project=Path.GetFullPath(args.Length==0?Directory.GetCurrentDirectory():args[0]);root=Path.Combine(project,".build","audit-cleanup","export-temp-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(root);
            foreach(bool apfs in new[]{false,true})foreach(bool reversed in new[]{false,true})foreach(bool directoryCollision in new[]{false,true})HierarchyCollision(apfs,reversed,directoryCollision);
            ExistingTemporary(false);ExistingTemporary(true);ExistingDestination(false,false);ExistingDestination(true,false);ExistingDestination(false,true);SourceFailure(true,false,false);SourceFailure(false,true,false);SourceFailure(false,false,true);UnavailableSource();
            string summary="PASS ExportTempCollision: "+checks+" assertions; APFS/NTFS .partial names in both orders, file/directory collisions, failed CreateNew, read-only files, final-path collision, verification failures, cancellation, source preservation. Ordinary owned files only. "+root;
            Console.WriteLine(summary);File.WriteAllText(Path.Combine(root,"result.txt"),summary,new UTF8Encoding(false));return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
