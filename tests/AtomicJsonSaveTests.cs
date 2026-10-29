using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Real Windows sharing violations against fresh, owned test files only.
public static class AtomicJsonSaveTests
{
    static string root;
    static int checks,folders;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static string Case(){string directory=Path.Combine(root,(++folders).ToString("D2"));Directory.CreateDirectory(directory);return directory;}
    static string Text(string file){return File.ReadAllText(file,Encoding.UTF8);}
    static object Document(int version,string body){return new{version=version,body=body};}
    static Dictionary<string,object> Parse(string text){return new JavaScriptSerializer{MaxJsonLength=4*1024*1024}.Deserialize<Dictionary<string,object>>(text);}
    static Exception Capture(Action action){try{action();return null;}catch(Exception error){return error;}}
    static bool NativeReplaceError(Exception error)
    {
        uint code=unchecked((uint)error.HResult);
        return error is IOException&&(code==0x80070020U||code==0x80070021U||code==0x80070497U)&&Environment.StackTrace.Contains("System.IO.File.InternalReplace");
    }
    static void NativeErrorHook(Action<IOException> callback,Action operation)
    {
        bool inside=false;Exception callbackError=null;
        EventHandler<FirstChanceExceptionEventArgs> handler=delegate(object sender,FirstChanceExceptionEventArgs args){
            if(inside||!NativeReplaceError(args.Exception))return;
            inside=true;try{callback((IOException)args.Exception);}catch(Exception error){callbackError=error;}finally{inside=false;}
        };
        AppDomain.CurrentDomain.FirstChanceException+=handler;
        try{operation();}finally{AppDomain.CurrentDomain.FirstChanceException-=handler;}
        if(callbackError!=null)throw new Exception("Test fault callback failed",callbackError);
    }
    static void NormalPublication()
    {
        string directory=Case(),file=Path.Combine(directory,"state.json");
        RecoveryCore.SaveJson(file,Document(0,"original"));Check(Convert.ToInt32(Parse(Text(file))["version"])==0,"initial create publishes valid JSON");
        RecoveryCore.SaveJson(file,Document(1,"Семья · Ω · \"quoted\"\nnext"));var parsed=Parse(Text(file));
        Check(Convert.ToInt32(parsed["version"])==1&&Convert.ToString(parsed["body"])=="Семья · Ω · \"quoted\"\nnext","replacement preserves actual Unicode and escapes");
        Check(!Directory.GetFiles(directory,"*.partial").Any(),"successful save leaves no temporary file");
    }
    static void TransientReader()
    {
        string directory=Case(),file=Path.Combine(directory,"state.json");RecoveryCore.SaveJson(file,Document(0,"original"));
        FileStream reader=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read);int failures=0;string observed=null;Exception failure=null;
        try{
            NativeErrorHook(error=>{failures++;observed=Text(file);reader.Dispose();reader=null;},()=>failure=Capture(()=>RecoveryCore.SaveJson(file,Document(1,"new complete state"))));
            Check(failure==null,"released real Windows reader allows atomic retry");
            Check(failures==1&&Convert.ToInt32(Parse(observed)["version"])==0,"old snapshot remains intact during the failed native replacement");
            Check(Convert.ToInt32(Parse(Text(file))["version"])==1,"successful retry publishes new snapshot");
            Check(!Directory.GetFiles(directory,"*.partial").Any(),"successful retry consumes original temporary file");
        }finally{if(reader!=null)reader.Dispose();}
    }
    static void PermanentReader()
    {
        string directory=Case(),file=Path.Combine(directory,"state.json");RecoveryCore.SaveJson(file,Document(0,"original"));string before=Text(file);
        using(var reader=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read)){
            int failures=0;Exception failure=null;var clock=Stopwatch.StartNew();
            NativeErrorHook(error=>failures++,()=>failure=Capture(()=>RecoveryCore.SaveJson(file,Document(1,"never published"))));clock.Stop();
            Check(failure is IOException,"permanent sharing violation is returned to caller");
            Check(failures==4,"retry bound is four actual native attempts");
            Check(clock.ElapsedMilliseconds>=150&&clock.ElapsedMilliseconds<3000,"retry waits are short and bounded");
            Check(Text(file)==before,"permanent failure preserves original complete snapshot");
            Check(!Directory.GetFiles(directory,"*.partial").Any(),"only own temporary file is cleaned after failure");
        }
    }
    static void MissingTemporaryStopsRetry()
    {
        string directory=Case(),file=Path.Combine(directory,"state.json"),preserved=Path.Combine(directory,"preserved-new-json.txt");
        RecoveryCore.SaveJson(file,Document(0,"original"));FileStream reader=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read);int failures=0;Exception failure=null;
        try{
            NativeErrorHook(error=>{
                failures++;string partial=Directory.GetFiles(directory,"*.partial").Single();File.Move(partial,preserved);reader.Dispose();reader=null;
            },()=>failure=Capture(()=>RecoveryCore.SaveJson(file,Document(1,"new document"))));
            Check(failure is IOException&&failures==1,"missing original temporary file cannot be reported as success or retried");
            Check(Convert.ToInt32(Parse(Text(file))["version"])==0,"target untouched when temporary vanished");
            Check(Convert.ToInt32(Parse(Text(preserved))["version"])==1,"test moved only its own complete temporary document");
        }finally{if(reader!=null)reader.Dispose();}
    }
    static void ExactFailureCodes()
    {
        // The real Windows lock produces32. Change only this test exception's
        // HRESULT before the catch to exercise33/1175 and reject1176/1177.
        // This is explicit fault injection, not a claim of native1175 capture.
        foreach(uint code in new[]{0x80070021U,0x80070497U,0x80070498U,0x80070499U,0x80130020U}){
            string directory=Case(),file=Path.Combine(directory,"state.json");RecoveryCore.SaveJson(file,Document(0,"original"));
            FileStream reader=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read);Exception failure=null;int failures=0;
            try{
                NativeErrorHook(error=>{failures++;typeof(Exception).GetProperty("HResult",BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic).GetSetMethod(true).Invoke(error,new object[]{unchecked((int)code)});reader.Dispose();reader=null;},()=>failure=Capture(()=>RecoveryCore.SaveJson(file,Document(1,"new"))));
                bool allowed=code==0x80070021U||code==0x80070497U;
                Check(failures==1,"exact HRESULT test starts from one real failed replacement");
                Check(allowed?failure==null:failure is IOException&&unchecked((uint)failure.HResult)==code,"only declared exact Win32 HRESULTs may retry: "+code.ToString("X8"));
                Check(Convert.ToInt32(Parse(Text(file))["version"])==(allowed?1:0),"non-retryable or indeterminate code cannot publish success: "+code.ToString("X8"));
            }finally{if(reader!=null)reader.Dispose();}
        }
    }
    static void NonTransientFailures()
    {
        string directory=Case(),target=Path.Combine(directory,"directory-not-file");Directory.CreateDirectory(target);
        var clock=Stopwatch.StartNew();Exception failure=Capture(()=>RecoveryCore.SaveJson(target,Document(1,"no")));clock.Stop();
        Check(failure!=null&&Directory.Exists(target),"directory target remains an error without destructive fallback");
        Check(clock.ElapsedMilliseconds<150,"unrelated native error is not retried");
        Check(!Directory.GetFiles(directory,"*.partial").Any(),"non-transient failure cleans its own temporary file");
        string file=Path.Combine(directory,"readonly.json");RecoveryCore.SaveJson(file,Document(0,"preserve"));string before=Text(file);File.SetAttributes(file,File.GetAttributes(file)|FileAttributes.ReadOnly);
        try{failure=Capture(()=>RecoveryCore.SaveJson(file,Document(1,"no")));Check(failure!=null&&Text(file)==before,"read-only target is not removed or overwritten");}
        finally{File.SetAttributes(file,FileAttributes.Normal);}
    }
    static void ReadersSeeWholeSnapshots()
    {
        string directory=Case(),file=Path.Combine(directory,"state.json"),body=String.Concat(Enumerable.Repeat("Проверяем полную запись Ω\n",8000));
        RecoveryCore.SaveJson(file,Document(0,"original"));int oldSeen=0,newSeen=0;Exception readerError=null;
        using(var stop=new ManualResetEvent(false))using(var ready=new ManualResetEvent(false)){
            var reader=new Thread(()=>{
                try{while(!stop.WaitOne(0)){
                    string text;
                    try{using(var source=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var stream=new StreamReader(source,Encoding.UTF8))text=stream.ReadToEnd();}
                    catch(IOException error){uint code=unchecked((uint)error.HResult);if(code==0x80070002U||code==0x80070020U||code==0x80070021U){Thread.Yield();continue;}throw;}
                    var value=Parse(text);int version=Convert.ToInt32(value["version"]);string content=Convert.ToString(value["body"]);
                    if(version==0&&content=="original")Interlocked.Increment(ref oldSeen);else if(version==1&&content==body)Interlocked.Increment(ref newSeen);else throw new Exception("Reader saw a mixed/truncated snapshot");ready.Set();
                }}catch(Exception error){readerError=error;ready.Set();}
            });reader.Start();
            try{Check(ready.WaitOne(3000),"concurrent reader started");RecoveryCore.SaveJson(file,Document(1,body));Thread.Sleep(40);}
            finally{stop.Set();Check(reader.Join(3000),"concurrent reader terminates");}
            Check(readerError==null,"reader observes valid complete JSON while publication races: "+readerError);
            Check(oldSeen>0&&newSeen>0,"both original and newly published snapshots observed");
        }
    }
    public static int Main(string[] args)
    {
        string parent=Path.Combine(Path.GetFullPath(args.Length==0?Directory.GetCurrentDirectory():args[0]),".build");
        root=Path.Combine(parent,"atomic-json-save-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try{NormalPublication();TransientReader();PermanentReader();MissingTemporaryStopsRetry();ExactFailureCodes();NonTransientFailures();ReadersSeeWholeSnapshots();Console.WriteLine("PASS AtomicJsonSave: "+checks+" checks; real Windows delete-sharing locks, bounded native retries, explicit33/1175 HRESULT injection and1176/1177 rejection, original preservation, vanished temporary and non-transient failures, concurrent complete snapshots; synthetic owned files only.");return 0;}
        catch(Exception error){Console.Error.WriteLine(error);return 1;}
        finally{string full=Path.GetFullPath(root);if(full.StartsWith(Path.GetFullPath(parent).TrimEnd('\\')+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)&&Path.GetFileName(full).StartsWith("atomic-json-save-",StringComparison.Ordinal)&&Directory.Exists(full))try{Directory.Delete(full,true);}catch(IOException){}catch(UnauthorizedAccessException){}}
    }
}
