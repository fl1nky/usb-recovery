using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using UsbRecovery;

public static class PhotoRecRunnerTests
{
    static void ExpectFailure(Action action, string description)
    {
        try { action(); }
        catch (IOException) { return; }
        throw new Exception("Accepted " + description);
    }

    static void CompletionEvidence(string root)
    {
        string log = Path.Combine(root, "photorec.log");
        const string pass = "Pass 1 (blocksize=512) STATUS_EXT2_OFF\n";
        const string total = "Total: 0 files found\n";
        const string trailer = "PhotoRec exited normally.\n";
        Action verify = () => PhotoRecRunner.VerifyCompletion(root, CancellationToken.None);
        File.WriteAllText(log, pass + total + trailer);
        verify();
        foreach (string failure in new[] { "Cannot create file x", "Cannot write to file x", "Syntax error in command line" })
        {
            File.WriteAllText(log, pass + failure + "\n" + total + trailer);
            ExpectFailure(verify, failure);
        }
        foreach (string incomplete in new[] { total + trailer, pass + trailer + total, pass + total + pass + trailer })
        {
            File.WriteAllText(log, incomplete);
            ExpectFailure(verify, "incomplete scan log");
        }
        File.WriteAllText(log, pass + total + trailer);
        File.WriteAllText(Path.Combine(root, "photorec.ses"), "pending");
        ExpectFailure(verify, "unfinished native session");
    }

    static void ActualScan(string root)
    {
        string output = Directory.CreateDirectory(Path.Combine(root, "Поиск фото")).FullName;
        string image = Path.Combine(root, "Мой образ.dd");
        byte[] jpeg;
        using (var bitmap = new Bitmap(128, 128))
        using (var encoded = new MemoryStream())
        {
            using (var graphics = Graphics.FromImage(bitmap)) graphics.Clear(Color.OrangeRed);
            bitmap.Save(encoded, ImageFormat.Jpeg);
            jpeg = encoded.ToArray();
        }
        byte[] bytes = new byte[2 * 1024 * 1024];
        jpeg.CopyTo(bytes, 4096);
        File.WriteAllBytes(image, bytes);
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45)))
        {
            var options = new RecoveryOptions { Other=false, Photos=true, Video=false, Audio=false, Documents=false, Archives=false };
            int count = RecoveryCore.Recover(image, output, false, timeout.Token, null, options);
            if (count < 1 || !Directory.GetFiles(output, "*.jpg", SearchOption.AllDirectories)
                    .Any(path => File.ReadAllBytes(path).SequenceEqual(jpeg)))
                throw new Exception("Expected JPEG bytes missing");
            string log = Path.Combine(output, "photorec.log");
            byte[] prior = File.ReadAllBytes(log);
            ExpectFailure(() => RecoveryCore.Recover(image, output, timeout.Token, null), "reuse of old PhotoRec output");
            if (!prior.SequenceEqual(File.ReadAllBytes(log)) || !bytes.SequenceEqual(File.ReadAllBytes(image)))
                throw new Exception("Retry modified source or previous log");
        }
    }

    static void ParentCrash(string root)
    {
        // Only the stand-in worker below is eligible for termination by this test.
        string runtime = Directory.CreateDirectory(Path.Combine(root, "crash")).FullName;
        string worker = Path.Combine(runtime, "tools/testdisk-7.2/photorec_win.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(worker));
        string host = Path.Combine(runtime, "host.exe");
        string self = Assembly.GetExecutingAssembly().Location;
        File.Copy(self, host);
        File.Copy(self, worker);
        File.WriteAllBytes(Path.Combine(runtime, "image.dd"), new byte[512]);
        using (var owner = Process.Start(new ProcessStartInfo(host, "host") {
            WorkingDirectory=runtime, UseShellExecute=false, CreateNoWindow=true }))
        {
            try
            {
                if (!SpinWait.SpinUntil(() => File.Exists(Path.Combine(runtime, "attached")) || owner.HasExited, 15000) || owner.HasExited)
                    throw new Exception("Host failed to reach attached worker");
                int pid = Int32.Parse(File.ReadAllText(Path.Combine(runtime, "worker.pid")));
                using (var child = Process.GetProcessById(pid))
                {
                    if (!String.Equals(child.MainModule.FileName, Path.GetFullPath(worker), StringComparison.OrdinalIgnoreCase))
                        throw new Exception("Unexpected worker path");
                    owner.Kill();
                    if (!child.WaitForExit(5000)) { child.Kill(); throw new Exception("Orphaned PhotoRec worker"); }
                }
            }
            finally { if (!owner.HasExited) owner.Kill(); owner.WaitForExit(); }
        }
    }

    public static int Main(string[] args)
    {
        if (args[0] == "/log")
        {
            File.WriteAllText("worker.pid", Process.GetCurrentProcess().Id.ToString());
            Thread.Sleep(30000);
            return 1;
        }
        if (args[0] == "host")
        {
            RecoveryCore.Recover("image.dd", ".", CancellationToken.None, count => {
                if (File.Exists("worker.pid")) File.WriteAllText("attached", "");
            });
            return 1;
        }
        string root = Directory.CreateDirectory(Path.Combine(args[0], ".build", "photorec-run-" + Guid.NewGuid().ToString("N"))).FullName;
        CompletionEvidence(root);
        ActualScan(root);
        ParentCrash(root);
        Console.WriteLine("PASS PhotoRec log validation, native JPEG, preserved prior run and owned worker termination");
        return 0;
    }
}
