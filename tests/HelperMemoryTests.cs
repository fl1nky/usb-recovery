using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using UsbRecovery;
public static class HelperMemoryTests
{
    static int checks;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    public static int Main(string[] args)
    {
        if(args.Length>0&&args[0]=="--worker"){
            Console.ReadLine();try{var buffers=new List<byte[]>();for(int i=0;i<32;i++){var bytes=new byte[8*1024*1024];for(int at=0;at<bytes.Length;at+=4096)bytes[at]=1;buffers.Add(bytes);}GC.KeepAlive(buffers);Console.WriteLine("LIMIT_NOT_ENFORCED");return 3;}catch(OutOfMemoryException){Console.WriteLine("LIMIT_ENFORCED");return 0;}
        }
        try{
            var type=typeof(HelperClient).Assembly.GetType("UsbRecovery.ProcessJob",true);var constructor=type.GetConstructor(new[]{typeof(long)});Check(constructor!=null,"memory budget is explicit and testable");
            foreach(long invalid in new[]{0L,16L*1024*1024,9L*1024*1024*1024}){bool rejected=false;try{using((IDisposable)constructor.Invoke(new object[]{invalid})){} }catch(TargetInvocationException error){rejected=error.InnerException is ArgumentOutOfRangeException;}Check(rejected,"invalid job memory budget rejected");}
            using(var job=(IDisposable)constructor.Invoke(new object[]{96L*1024*1024}))
            using(var process=new Process{StartInfo=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--worker"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true}}){
                Check(process.Start(),"controlled child started");type.GetMethod("Attach").Invoke(job,new object[]{process});process.StandardInput.WriteLine("go");process.StandardInput.Close();Check(process.WaitForExit(15000),"bounded child exits without hanging");
                string text=process.StandardOutput.ReadToEnd();Check(process.ExitCode==0&&text.Trim()=="LIMIT_ENFORCED","Windows enforces committed memory limit on actual child, no mock");Check(String.IsNullOrWhiteSpace(process.StandardError.ReadToEnd()),"controlled allocation has no diagnostic leak");
            }
            Console.WriteLine("PASS HelperMemory: "+checks+" checks; actual Windows child memory enforcement, bounded allocation, no input data or devices");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
