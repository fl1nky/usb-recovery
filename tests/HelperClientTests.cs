using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using UsbRecovery;

public static class HelperClientTests
{
    static int assertions;
    static void Check(bool condition, string description) { if (!condition) throw new Exception(description); assertions++; Console.WriteLine("PASS " + description); }
    public static int Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory, helper = Path.Combine(root, "HelperProtocolFixture.exe");
        string canary = "SYNTHETIC_SECRET_CANARY_пирожки";
        string progress = "";
        var good = HelperClient.Run(helper, new { mode = "good", secret = canary }, CancellationToken.None, text => progress += text);
        Check(good.Status == "complete" && good.Messages == canary.Length, "UTF8 stdin and terminal result");
        Check(!progress.Contains(canary), "worker diagnostics and progress cannot expose secret");
        var bad = HelperClient.Run(helper, new { mode = "error", secret = "SYNTHETIC_SECRET_CANARY" }, CancellationToken.None, text => { });
        Check(bad.Status == "error" && bad.Code == "HELPER_FAILED", "unrecognized secret-bearing error code suppressed");
        foreach (string mode in new[] { "invalid", "mismatch" }) {
            bool rejected = false; try { HelperClient.Run(helper, new { mode = mode, secret = canary }, CancellationToken.None, text => { }); } catch (IOException ex) { rejected = !ex.Message.Contains(canary); }
            Check(rejected, "reject " + mode + " without raw diagnostics");
        }
        string marker = Path.Combine(root, "HelperChild.pid"); if (File.Exists(marker)) File.Delete(marker);
        using (var cancel = new CancellationTokenSource()) {
            var task = Task.Run(() => { try { HelperClient.Run(helper, new { mode = "cancel", secret = canary, marker = marker }, cancel.Token, text => { }); return false; } catch (OperationCanceledException) { return true; } });
            var timeout = Stopwatch.StartNew(); while (!File.Exists(marker) && timeout.ElapsedMilliseconds < 10000) Thread.Sleep(50);
            Check(File.Exists(marker), "native child started for cancellation fixture");
            int pid = Int32.Parse(File.ReadAllText(marker)); cancel.Cancel(); Check(task.Wait(10000) && task.Result, "cancellation returned promptly");
            bool gone; try { using (var child = Process.GetProcessById(pid)) gone = child.WaitForExit(3000); } catch (ArgumentException) { gone = true; }
            Check(gone, "Windows job terminates descendant helper"); File.Delete(marker);
        }
        string toolFolder = Path.Combine(root, "tools", "recovery-helper");
        Check(!File.Exists(HelperClient.Executable), "scratch test avoids replacing any existing helper");
        Directory.CreateDirectory(toolFolder); File.Copy(helper, HelperClient.Executable);
        string scratchResult = Path.Combine(root, "HelperScratchResult");
        try {
            var goodScratch = HelperClient.Scan(root, scratchResult, new Dictionary<string, string> { { "ios_password", "good" } }, false, CancellationToken.None, null);
            Check(goodScratch.Status == "complete" && !Directory.Exists(scratchResult + ".work"), "private plaintext scratch removed after completed helper");
            string pidFile = scratchResult + ".pid"; if (File.Exists(pidFile)) File.Delete(pidFile);
            using (var cancel = new CancellationTokenSource()) {
                var task = Task.Run(() => { try { HelperClient.Scan(root, scratchResult, new Dictionary<string, string> { { "ios_password", "cancel-scratch" } }, false, cancel.Token, null); return false; } catch (OperationCanceledException) { return true; } });
                var timeout = Stopwatch.StartNew(); while (!File.Exists(pidFile) && timeout.ElapsedMilliseconds < 10000) Thread.Sleep(50);
                Check(File.Exists(pidFile) && Directory.Exists(scratchResult + ".work"), "cancel fixture has plaintext private scratch");
                cancel.Cancel(); Check(task.Wait(10000) && task.Result && !Directory.Exists(scratchResult + ".work"), "cancel kills helpers and removes plaintext scratch"); File.Delete(pidFile);
            }
        } finally { File.Delete(HelperClient.Executable); Directory.Delete(toolFolder); Directory.Delete(Path.GetDirectoryName(toolFolder)); }
        Console.WriteLine("HelperClient: " + assertions + " assertions passed"); return 0;
    }
}
