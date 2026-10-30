using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using UsbRecovery;

public static class RecoveryRunLockTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static bool Io(Action action){try{action();return false;}catch(IOException){return true;}}
    static int Child(string root,string mode="--child")
    {
        using(var process=Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,mode+" \""+root+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true})){
            if(!process.WaitForExit(10000)){process.Kill();throw new IOException("Owned lock probe timed out");}
            Check(String.IsNullOrWhiteSpace(process.StandardError.ReadToEnd()),"isolated child emits no raw diagnostics");return process.ExitCode;
        }
    }
    public static int Main(string[] args)
    {
        if(args.Length==2&&args[0]=="--child"){try{using(RecoverySession.AcquireRunLock(args[1]))return 0;}catch(IOException){return 2;}}
        if(args.Length==2&&args[0]=="--crash"){using(RecoverySession.AcquireRunLock(args[1])){Environment.Exit(77);return 0;}}
        try{
            string project=Path.GetFullPath(args[0]),root=Path.Combine(project,".build","run-lock-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
            string marker=Path.Combine(root,"recovery-run.lock");File.WriteAllText(marker,"existing owned lock content");string before=RecoveryCore.HashFile(marker,CancellationToken.None,(a,b)=>{});
            using(RecoverySession.AcquireRunLock(root)){
                Check(Io(()=>{using(RecoverySession.AcquireRunLock(root)) {}}),"same-process duplicate run rejected by the actual file handle");
                Check(Child(root)==2,"separate process cannot start a second run in the same folder");
            }
            Check(Child(root)==0,"released handle permits a new process even though lock filename remains");
            Check(Child(root,"--crash")==77,"owned process terminates without releasing its managed lock normally");Check(Child(root)==0,"operating system releases the run lock after a real process exit");
            Check(RecoveryCore.HashFile(marker,CancellationToken.None,(a,b)=>{})==before,"locking never changes pre-existing file bytes");
            string image=Path.Combine(root,"source.dd");File.WriteAllBytes(image,new byte[65536]);string original=RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{});
            File.WriteAllText(image+".sha256",original);
            var options=new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,Containers=false,EmbeddedPhotos=true};
            using(RecoverySession.AcquireRunLock(root))Check(Io(()=>RecoveryPipeline.Run(image,root,options,CancellationToken.None,s=>{})),"pipeline refuses a concurrent run before parsing or writing a session");
            Check(!File.Exists(Path.Combine(root,RecoverySession.FileName))&&RecoveryCore.HashFile(image,CancellationToken.None,(a,b)=>{})==original,"rejected concurrency creates no successful session and leaves source intact");
            Check(Io(()=>RecoveryPipeline.Run(marker,root,options,CancellationToken.None,s=>{})),"source cannot alias the run lock filename");
            Check(RecoveryCore.HashFile(marker,CancellationToken.None,(a,b)=>{})==before,"reserved-source rejection preserves original lock bytes");
            Console.WriteLine("PASS RecoveryRunLock: "+checks+" checks; actual cross-process run isolation, released/crashed-handle semantics, no stale filename lock and preserved source/state bytes. Owned regular files only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
