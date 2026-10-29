using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using UsbRecovery;

public static class RecoveryCoreTests
{
    static string root;
    static int passed, failed;
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static void Test(string name, Action body)
    {
        try { body(); passed++; Console.WriteLine("PASS " + name); }
        catch (Exception ex) { failed++; Console.WriteLine("FAIL " + name + ": " + ex.GetType().Name + ": " + ex.Message); }
    }
    static T Throws<T>(Action body) where T : Exception
    {
        try { body(); } catch (T ex) { return ex; }
        throw new Exception("Expected " + typeof(T).Name);
    }
    static string PathFor(string name) { return Path.Combine(root, name); }
    static byte[] Bytes(int size)
    {
        byte[] bytes = new byte[size];
        for (int i=0; i<size; i++) bytes[i] = (byte)((i * 31 + i / 97) % 256);
        return bytes;
    }
    static string Hash(byte[] bytes)
    {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
    }
    static void Progress(long a, long b) { }
    static DiskInfo Disk()
    {
        return new DiskInfo {Number=7,Name="synthetic",Serial="serial",UniqueId="unique",BusType="USB",Size=1024*1024,SectorSize=512};
    }
    sealed class ShortReadStream : MemoryStream
    {
        readonly int limit;
        public ShortReadStream(byte[] b, int limit) : base(b) { this.limit=limit; }
        public override int Read(byte[] b, int off, int count) { return base.Read(b,off,Math.Min(count,limit)); }
    }
    public static int Main(string[] args)
    {
        root=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"test-data-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(root);
        Console.WriteLine("Synthetic test directory: " + root);
        Test("Copy exact bytes, SHA256 and progress",delegate {
            byte[] bytes=Bytes(RecoveryCore.ChunkSize*2+1024); string path=PathFor("exact.partial"); long last=0; int callbacks=0;
            string hash=RecoveryCore.CopyExact(new MemoryStream(bytes),path,bytes.Length,512,CancellationToken.None,delegate(long done,long total) { Assert(done>last && total==bytes.Length,"Invalid progress"); last=done; callbacks++; });
            Assert(hash==Hash(bytes),"SHA256 mismatch"); Assert(File.ReadAllBytes(path).SequenceEqual(bytes),"Byte mismatch"); Assert(last==bytes.Length && callbacks==3,"Wrong progress count");
        });
        Test("Aligned short reads are accepted",delegate {
            byte[] bytes=Bytes(4096); string path=PathFor("short.partial");
            string hash=RecoveryCore.CopyExact(new ShortReadStream(bytes,512),path,bytes.Length,512,CancellationToken.None,Progress);
            Assert(hash==Hash(bytes),"SHA mismatch after short reads");
        });
        Test("Truncation retains incomplete copy and fails",delegate {
            string path=PathFor("truncated.partial");
            Throws<IOException>(delegate { RecoveryCore.CopyExact(new MemoryStream(Bytes(2048)),path,4096,512,CancellationToken.None,Progress); });
            Assert(new FileInfo(path).Length==2048,"Partial data length is wrong");
        });
        Test("Misaligned sector read is rejected before output",delegate {
            string path=PathFor("misaligned.partial");
            Throws<IOException>(delegate { RecoveryCore.CopyExact(new ShortReadStream(Bytes(1024),513),path,1024,512,CancellationToken.None,Progress); });
            Assert(new FileInfo(path).Length==0,"Misaligned data was written");
        });
        Test("Cancelled before copy writes no data",delegate {
            string path=PathFor("cancel-before.partial"); var cancel=new CancellationTokenSource(); cancel.Cancel();
            Throws<OperationCanceledException>(delegate { RecoveryCore.CopyExact(new MemoryStream(Bytes(1024)),path,1024,512,cancel.Token,Progress); });
            Assert(!File.Exists(path) || new FileInfo(path).Length==0,"Data written after cancellation");
        });
        Test("Cancelled between chunks retains only first chunk",delegate {
            string path=PathFor("cancel-mid.partial"); var cancel=new CancellationTokenSource(); byte[] bytes=Bytes(RecoveryCore.ChunkSize+512);
            Throws<OperationCanceledException>(delegate { RecoveryCore.CopyExact(new MemoryStream(bytes),path,bytes.Length,512,cancel.Token,delegate(long a,long b) { cancel.Cancel(); }); });
            Assert(new FileInfo(path).Length==RecoveryCore.ChunkSize,"Unexpected partial length");
        });
        Test("Copy honors cancellation from final progress",delegate {
            string path=PathFor("cancel-final.partial"); var cancel=new CancellationTokenSource(); byte[] bytes=Bytes(1024);
            Throws<OperationCanceledException>(delegate { RecoveryCore.CopyExact(new MemoryStream(bytes),path,bytes.Length,512,cancel.Token,delegate(long a,long b) { cancel.Cancel(); }); });
            Assert(new FileInfo(path).Length==bytes.Length,"Unexpected preserved partial length");
        });
        Test("Copy does not overwrite existing file",delegate {
            string path=PathFor("existing.partial"); File.WriteAllText(path,"preserve");
            Throws<IOException>(delegate { RecoveryCore.CopyExact(new MemoryStream(Bytes(1024)),path,1024,512,CancellationToken.None,Progress); });
            Assert(File.ReadAllText(path)=="preserve","Existing file overwritten");
        });
        Test("Invalid sizes are rejected before creating file",delegate {
            string path=PathFor("invalid.partial");
            Throws<IOException>(delegate { RecoveryCore.CopyExact(new MemoryStream(Bytes(1024)),path,1023,512,CancellationToken.None,Progress); });
            Assert(!File.Exists(path),"Invalid copy created output");
        });
        Test("HashFile agrees with independent SHA256",delegate {
            byte[] bytes=Bytes(12345); string path=PathFor("hash.dd"); File.WriteAllBytes(path,bytes);
            Assert(RecoveryCore.HashFile(path,CancellationToken.None,Progress)==Hash(bytes),"SHA256 differs");
        });
        Test("VerifyImage accepts matching sidecar",delegate {
            byte[] bytes=Bytes(1024); string path=PathFor("valid.dd"); File.WriteAllBytes(path,bytes); File.WriteAllText(path+".sha256",Hash(bytes)+"  usb.dd\r\n");
            RecoveryCore.VerifyImage(path,CancellationToken.None,Progress);
        });
        Test("VerifyImage rejects changed bytes",delegate {
            byte[] bytes=Bytes(1024); string path=PathFor("changed.dd"); File.WriteAllBytes(path,bytes); File.WriteAllText(path+".sha256",Hash(bytes)+"  usb.dd\r\n"); bytes[512]^=1; File.WriteAllBytes(path,bytes);
            Throws<IOException>(delegate { RecoveryCore.VerifyImage(path,CancellationToken.None,Progress); });
        });
        Test("VerifyImage rejects missing sidecar",delegate {
            string path=PathFor("missing.dd"); File.WriteAllBytes(path,Bytes(1024));
            Throws<IOException>(delegate { RecoveryCore.VerifyImage(path,CancellationToken.None,Progress); });
        });
        Test("VerifyImage reports empty checksum as IOException",delegate {
            string path=PathFor("empty-checksum.dd"); File.WriteAllBytes(path,Bytes(1024)); File.WriteAllText(path+".sha256","");
            Throws<IOException>(delegate { RecoveryCore.VerifyImage(path,CancellationToken.None,Progress); });
        });
        Test("VerifyImage rejects non-hexadecimal checksum",delegate {
            string path=PathFor("invalid-checksum.dd"); File.WriteAllBytes(path,Bytes(1024)); File.WriteAllText(path+".sha256",new string('z',64)+"  usb.dd");
            Throws<IOException>(delegate { RecoveryCore.VerifyImage(path,CancellationToken.None,Progress); });
        });
        Test("HashFile honors cancellation from final progress",delegate {
            string path=PathFor("hash-cancel.dd"); File.WriteAllBytes(path,Bytes(1024)); var cancel=new CancellationTokenSource();
            Throws<OperationCanceledException>(delegate { RecoveryCore.HashFile(path,cancel.Token,delegate(long a,long b) { cancel.Cancel(); }); });
        });
        Test("HashFile honors pre-cancelled empty file",delegate {
            string path=PathFor("empty.dd"); File.WriteAllBytes(path,new byte[0]); var cancel=new CancellationTokenSource(); cancel.Cancel();
            Throws<OperationCanceledException>(delegate { RecoveryCore.HashFile(path,cancel.Token,Progress); });
        });
        Test("Eligibility excludes system, boot, offline and unknown identity",delegate {
            var d=Disk(); Assert(d.Eligible,"USB unexpectedly ineligible"); d.IsBoot=true; Assert(!d.Eligible,"Boot allowed"); d.IsBoot=false; d.IsSystem=true; Assert(!d.Eligible,"System allowed"); d.IsSystem=false; d.IsOffline=true; Assert(!d.Eligible,"Offline allowed"); d.IsOffline=false; d.UniqueId=""; d.Serial=" "; Assert(!d.Eligible,"Unknown identity allowed"); d=Disk(); d.BusType="SATA"; Assert(!d.Eligible,"SATA allowed");
        });
        Test("Identity requires number, size, sector size, serial and unique ID",delegate {
            var a=Disk(); var b=Disk(); Assert(a.SameDevice(b),"Identical device differs"); b.Number++; Assert(!a.SameDevice(b),"Changed number accepted"); b=Disk(); b.Size+=512; Assert(!a.SameDevice(b),"Changed size accepted"); b=Disk(); b.SectorSize=4096; Assert(!a.SameDevice(b),"Changed sector accepted"); b=Disk(); b.Serial="changed"; Assert(!a.SameDevice(b),"Changed serial accepted"); b=Disk(); b.UniqueId="changed"; Assert(!a.SameDevice(b),"Changed ID accepted");
        });
        Test("Destination rejects same physical disk and bad sector size",delegate {
            var d=Disk(); Throws<IOException>(delegate { RecoveryCore.ValidateDestination(d,7); }); RecoveryCore.ValidateDestination(d,8); d.SectorSize=513; Throws<IOException>(delegate { RecoveryCore.ValidateDestination(d,8); });
        });
        if (args.Contains("--metadata"))
        {
            Test("Windows disk enumeration metadata",delegate {
                var disks=RecoveryCore.ListDisks(); Assert(disks.Count>0,"No disks returned"); Assert(disks.All(d => d.Number>=0 && d.Size>0),"Invalid metadata");
                Console.WriteLine("Metadata only: disk count="+disks.Count+", eligible USB count="+disks.Count(d=>d.Eligible));
            });
            Test("Destination physical disk mapping for artifact folder",delegate {
                string folder=Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
                string canonical=RecoveryCore.CanonicalDirectory(folder); int disk=RecoveryCore.DiskForDirectory(folder);
                Assert(disk>=0,"Negative disk number"); Assert(RecoveryCore.ListDisks().Any(d=>d.Number==disk),"Destination disk absent from metadata");
                Console.WriteLine("Destination mapping: "+canonical+" -> disk "+disk);
            });
        }
        Console.WriteLine("Results: "+passed+" passed, "+failed+" failed.");
        return failed==0 ? 0 : 1;
    }
}
