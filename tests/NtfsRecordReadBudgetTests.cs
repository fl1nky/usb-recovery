using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Resource budget over the real engine, not an assertion about its buffer size.
public static class NtfsRecordReadBudgetTests
{
    [StructLayout(LayoutKind.Sequential)] struct IoCounters
    { public ulong Reads, Writes, Other, ReadBytes, WriteBytes, OtherBytes; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessIoCounters(IntPtr process, out IoCounters counters);
    public static int Main(string[] args)
    {
        try
        {
            string work = Path.Combine(Path.GetFullPath(args[0]), ".build", "ntfs-read-budget-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work); string source = Path.Combine(work, "source.dd");
            byte[] image = new byte[4 * 1024 * 1024];
            using (var original = File.OpenRead(Path.Combine(args[1], "candidate-limit.dd")))
            {
                int wanted = 1024 * 1024 + 1000 * 1024, copied = 0;
                while (copied < wanted) { int got = original.Read(image, copied, wanted - copied); if (got == 0) throw new IOException("Incomplete owned corpus"); copied += got; }
            }
            File.WriteAllBytes(source, image);
            string before = RecoveryCore.HashFile(source, CancellationToken.None, (a, b) => { });
            string output = Path.Combine(work, "result");
            IoCounters initial, final; var process = Process.GetCurrentProcess();
            if (!GetProcessIoCounters(process.Handle, out initial)) throw new IOException("Cannot read owned process I/O counters");
            var clock = Stopwatch.StartNew();
            int recovered = MetadataRescue.Recover(source, output, CancellationToken.None, null);
            clock.Stop();
            if (!GetProcessIoCounters(process.Handle, out final)) throw new IOException("Cannot read final I/O counters");
            ulong requested = final.ReadBytes - initial.ReadBytes;
            var report = new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024 }.Deserialize<MetadataRescue.Report>(
                File.ReadAllText(Path.Combine(output, "metadata-rescue", "report.json")));
            if (recovered != 1000 || report.RecoveredFiles != 1000 || report.ScannedBytes != image.Length ||
                Directory.GetFiles(Path.Combine(output, "metadata-rescue", "files")).Length != 1000 ||
                RecoveryCore.HashFile(source, CancellationToken.None, (a, b) => { }) != before)
                throw new Exception("Read budget fixture lost recovered records or changed its source");
            Console.WriteLine("NTFS_READ_METRICS records=1000; source_bytes=" + image.Length + "; requested_bytes=" + requested +
                "; read_operations=" + (final.Reads - initial.Reads) + "; elapsed_ms=" + clock.ElapsedMilliseconds);
            if (requested > 128UL * 1024 * 1024) throw new Exception("NTFS_READ_AMPLIFICATION_BUDGET_EXCEEDED");
            Console.WriteLine("PASS NtfsRecordReadBudget: actual1000-record recovery within128MiB process read-request budget; cached Windows I/O, not physical-media throughput");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
