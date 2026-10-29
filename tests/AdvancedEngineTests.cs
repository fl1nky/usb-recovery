using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class AdvancedEngineTests
{
    static void Assert(bool test, string message) { if (!test) throw new Exception(message); }
    static string Hash(string path) { using (var input=File.OpenRead(path)) using (var hash=SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(input)); }
    static void Throws<T>(Action action, string message) where T:Exception { try { action(); } catch(T) { return; } throw new Exception(message); }
    static string Q(string path) { return "\""+path+"\""; }
    static void Set(byte[] bytes,int offset,ushort value) { Buffer.BlockCopy(BitConverter.GetBytes(value),0,bytes,offset,2); }
    static void Set(byte[] bytes,int offset,uint value) { Buffer.BlockCopy(BitConverter.GetBytes(value),0,bytes,offset,4); }
    static void Set(byte[] bytes,int offset,ulong value) { Buffer.BlockCopy(BitConverter.GetBytes(value),0,bytes,offset,8); }
    static uint Crc(byte[] bytes) { uint c=UInt32.MaxValue;foreach(byte b in bytes) {c^=b;for(int j=0;j<8;j++)c=(c&1)!=0?(c>>1)^0xedb88320:c>>1;}return ~c; }
    static string Wrap(string input,string path,bool gpt)
    {
        const uint start=2048;uint length=checked((uint)(new FileInfo(input).Length/512));
        ulong sectors=(ulong)start+length+(gpt?34UL:0UL);
        byte[] mbr=new byte[512];mbr[510]=0x55;mbr[511]=0xaa;mbr[450]=gpt?(byte)0xee:(byte)7;
        Set(mbr,454,gpt?1U:start);Set(mbr,458,gpt?(uint)(sectors-1):length);
        using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {
            output.SetLength(checked((long)sectors*512));output.Write(mbr,0,mbr.Length);
            if(gpt)
            {
                byte[] entries=new byte[128*128];Buffer.BlockCopy(new Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").ToByteArray(),0,entries,0,16);
                Buffer.BlockCopy(Guid.NewGuid().ToByteArray(),0,entries,16,16);Set(entries,32,(ulong)start);Set(entries,40,(ulong)start+length-1);
                byte[] header=new byte[512];Buffer.BlockCopy(Encoding.ASCII.GetBytes("EFI PART"),0,header,0,8);Set(header,8,0x00010000U);Set(header,12,92U);
                Set(header,24,1UL);Set(header,32,sectors-1);Set(header,40,34UL);Set(header,48,sectors-34);
                Buffer.BlockCopy(Guid.NewGuid().ToByteArray(),0,header,56,16);Set(header,72,2UL);Set(header,80,128U);Set(header,84,128U);Set(header,88,Crc(entries));Set(header,16,Crc(header.Take(92).ToArray()));
                output.Position=512;output.Write(header,0,512);output.Write(entries,0,entries.Length);
                Set(header,16,0U);Set(header,24,sectors-1);Set(header,32,1UL);Set(header,72,sectors-33);Set(header,16,Crc(header.Take(92).ToArray()));
                output.Position=checked((long)(sectors-33)*512);output.Write(entries,0,entries.Length);output.Write(header,0,512);
            }
            output.Position=start*512L;using(var source=File.OpenRead(input))source.CopyTo(output);
        }
        return path;
    }
    public static int Main()
    {
        string baseDir=AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        if (Path.GetFileName(baseDir)=="tests")
        {
            var domain=AppDomain.CreateDomain("Advanced engine integration",null,new AppDomainSetup{ ApplicationBase=Directory.GetParent(baseDir).FullName });
            try { return domain.ExecuteAssembly(typeof(AdvancedEngineTests).Assembly.Location); } finally { AppDomain.Unload(domain); }
        }
        string testDir=Path.Combine(baseDir,"tests"), run=Path.Combine(testDir,"Advanced run "+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        string compatibility=Environment.GetEnvironmentVariable("__COMPAT_LAYER");
        try
        {
            Directory.CreateDirectory(run); Environment.SetEnvironmentVariable("__COMPAT_LAYER","RunAsInvoker");
            string image=Path.Combine(testDir,"AdvancedNtfs.dd"), expected=Path.Combine(testDir,"photorec-20261011T231546120952Z","fixtures","expected.jpg");
            string before=Hash(image);
            var partitions=AdvancedEngines.FindNtfs(image,CancellationToken.None);
            Assert(partitions.Count==1 && partitions[0].Table=="partition_none","Superfloppy NTFS not detected");
            using (var cancel=new CancellationTokenSource(20000))
            using (var guard=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))
            {
                int count=AdvancedEngines.RecoverNtfs(image,run,cancel.Token,delegate(string message) { });
                Assert(count==1,"Expected one NTFS candidate, got "+count);
                string restored=AdvancedEngines.NtfsRecoveredFiles(run).Single();
                Assert(Path.GetFileName(restored)=="grandma-photo.jpg","Original NTFS name not restored");
                Assert(Hash(restored)==Hash(expected),"Fragmented NTFS JPEG hash mismatch");
                Assert(Hash(image)==before,"NTFS source image was changed");
                Assert(File.ReadAllText(Path.Combine(run,"ntfs","report.json")).Contains("complete"),"NTFS completion report missing");
                foreach(bool gpt in new[]{false,true})
                {
                    string wrapped=Wrap(image,Path.Combine(run,gpt?"gpt.dd":"mbr.dd"),gpt), wrappedHash=Hash(wrapped);
                    var detected=AdvancedEngines.FindNtfs(wrapped,cancel.Token);
                    Assert(detected.Count==1 && detected[0].Number==1 && detected[0].Offset==1048576 && detected[0].Table==(gpt?"partition_gpt":"partition_i386"),"Partition table detection failed");
                    string partitionRun=Path.Combine(run,gpt?"gpt-result":"mbr-result");
                    Assert(AdvancedEngines.RecoverNtfs(wrapped,partitionRun,cancel.Token,null)==1,"Partitioned NTFS recovery failed");
                    Assert(Hash(AdvancedEngines.NtfsRecoveredFiles(partitionRun).Single())==Hash(expected),"Partitioned NTFS JPEG hash mismatch");
                    Assert(Hash(wrapped)==wrappedHash,"Partitioned source changed");
                }
                string output=Path.Combine(run,"deep"); Directory.CreateDirectory(output);
                string fixture=Path.Combine(testDir,"photorec-20261011T231546120952Z","synthetic-usb.dd"), deepBefore=Hash(fixture);
                string log=Path.Combine(output,"photorec.log");
                var start=new ProcessStartInfo(Path.Combine(baseDir,"tools","testdisk-7.2","photorec_win.exe"),"/logname "+Q(log)+" /log /d "+Q(Path.Combine(output,"files"))+" /cmd "+Q(fixture)+" "+AdvancedEngines.DeepPhotoRecCommand);
                start.UseShellExecute=false;start.CreateNoWindow=true;start.WorkingDirectory=output;
                start.EnvironmentVariables["CYGWIN"]="noglob";start.EnvironmentVariables["LANG"]="C.UTF-8";start.EnvironmentVariables["LC_ALL"]="C.UTF-8";
                using(var readGuard=new FileStream(fixture,FileMode.Open,FileAccess.Read,FileShare.Read))
                using(var process=Process.Start(start))
                {
                    try { while(!process.WaitForExit(250)) cancel.Token.ThrowIfCancellationRequested(); Assert(process.ExitCode==0,"Deep PhotoRec exit failure"); }
                    catch { if(!process.HasExited) {process.Kill();process.WaitForExit();} throw; }
                }
                string[] found=Directory.EnumerateDirectories(output,"files.*").SelectMany(d=>Directory.EnumerateFiles(d,"*",SearchOption.AllDirectories)).ToArray();
                string png=Path.Combine(testDir,"photorec-20261011T231546120952Z","fixtures","expected.png");
                Assert(found.Any(p=>Hash(p)==Hash(expected)),"Deep PhotoRec JPEG absent");
                Assert(found.Any(p=>Hash(p)==Hash(png)),"Deep PhotoRec PNG absent");
                string contents=File.ReadAllText(log);
                Assert(contents.Contains("PhotoRec exited normally.") && contents.Contains("Total: ") && !contents.Contains("Syntax error"),"Deep PhotoRec completion evidence absent");
                Assert(!File.Exists(Path.Combine(output,"photorec.ses")),"Deep PhotoRec incomplete session remains");
                Assert(Hash(fixture)==deepBefore,"Deep PhotoRec source changed");
            }
            using(var cancel=new CancellationTokenSource())
            {
                cancel.Cancel();Throws<OperationCanceledException>(delegate { AdvancedEngines.RecoverNtfs(image,run,cancel.Token,null); },"Pre-cancel ignored");
            }
            string canceled=Path.Combine(run,"cancelled");
            using(var cancel=new CancellationTokenSource(30))
                Throws<OperationCanceledException>(delegate { AdvancedEngines.RecoverNtfs(image,canceled,cancel.Token,null); },"Running cancellation ignored");
            Assert(Hash(image)==before,"Canceled NTFS attempt changed image");
            Throws<IOException>(delegate { AdvancedEngines.RecoverNtfs(@"\\.\PhysicalDrive0",run,CancellationToken.None,null); },"Physical device accepted");
            string damaged=Path.Combine(run,"damaged.dd");using(var stream=new FileStream(damaged,FileMode.CreateNew,FileAccess.Write)) {stream.SetLength(64*1024*1024);byte[] boot=File.ReadAllBytes(image).Take(512).ToArray();stream.Write(boot,0,boot.Length);}
            string damagedRun=Path.Combine(run,"damaged-result");
            Throws<IOException>(delegate {AdvancedEngines.RecoverNtfs(damaged,damagedRun,CancellationToken.None,null);},"Damaged NTFS silently reported complete");
            Assert(File.ReadAllText(Path.Combine(damagedRun,"ntfs","report.json")).Contains("unavailable"),"Damaged NTFS warning missing");
            Console.WriteLine("PASS: fragmented deleted NTFS JPEG restored with original name and SHA256 (superfloppy, MBR, GPT); deep PhotoRec JPEG+PNG exact hashes; read-only guards; real NTFS cancellation; physical path rejected; damaged NTFS warning; report/logs separate from user files. Results="+run);
            File.WriteAllText(Path.Combine(testDir,"AdvancedEngineTests.result.txt"),"PASS\r\nResults="+run+"\r\n",new UTF8Encoding(false));return 0;
        }
        catch(Exception ex) { Console.WriteLine("FAIL: "+ex+"\r\nResults="+run);return 1; }
        finally { Environment.SetEnvironmentVariable("__COMPAT_LAYER",compatibility); }
    }
}
