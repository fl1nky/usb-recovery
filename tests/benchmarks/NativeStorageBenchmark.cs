using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// One owned, manifest-verified regular image per process. No device enumeration,
// UI, external recovery helper or privileged operations are used here.
public static class NativeStorageBenchmark
{
    public sealed class Request
    {
        public string image, destination, engine, source_sha256;
        public int timeout_seconds;
    }

    static string Hash(string path)
    {
        return RecoveryCore.HashFile(path, CancellationToken.None, (done, total) => { });
    }

    static void NoLinks(string path)
    {
        if ((File.Exists(path) || Directory.Exists(path)) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("LINKED_PATH");
        for (var parent = new FileInfo(path).Directory; parent != null; parent = parent.Parent)
            if (parent.Exists && (parent.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("LINKED_PATH");
    }

    static int FatWithResume(string source, string output, string sourceHash, CancellationToken cancel,
        out bool interrupted, out int firstResumeDirectory)
    {
        var options = new RecoveryOptions { FatMetadata = true, NtfsMetadata = false, LostPartitions = false,
            Signatures = false, EmbeddedPhotos = false, Containers = false };
        string checksum = Path.Combine(output, "native-source.sha256"); File.WriteAllText(checksum, sourceHash);
        bool requested = false;
        interrupted = false; firstResumeDirectory = -1;
        using (var stop = CancellationTokenSource.CreateLinkedTokenSource(cancel))
        {
            try
            {
                var result = RecoveryPipeline.Run(source, output, options, stop.Token, message =>
                {
                    if (message.StartsWith("FAT/exFAT: каталоги 1;", StringComparison.Ordinal)) { requested = true; stop.Cancel(); }
                }, checksum);
                return result.Candidates; // The complete negative image has no FAT directory unit.
            }
            catch (OperationCanceledException)
            {
                if (!requested || cancel.IsCancellationRequested) throw;
                var stage = RecoverySession.Read(output, cancel).Stages.Single();
                if (stage.Key != "fat" || stage.CheckpointPath == null) throw new IOException("NATIVE_FAT_CHECKPOINT_MISSING");
                interrupted = true;
            }
        }
        int first = -1;
        var resumed = RecoveryPipeline.Resume(output, cancel, message =>
        {
            const string prefix = "FAT/exFAT: каталоги ";
            if (first >= 0 || !message.StartsWith(prefix, StringComparison.Ordinal)) return;
            string number = message.Substring(prefix.Length).Split(';')[0];
            first = Int32.Parse(number, System.Globalization.CultureInfo.InvariantCulture);
        });
        if (first != 1 || Directory.Exists(Path.Combine(output, "attempt-history"))) throw new IOException("NATIVE_FAT_CURSOR_NOT_REUSED");
        firstResumeDirectory = first;
        return resumed.Candidates;
    }

    public static int Main()
    {
        Console.InputEncoding = System.Text.Encoding.UTF8;
        Console.OutputEncoding = new System.Text.UTF8Encoding(false);
        var json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
        try
        {
            string line = Console.ReadLine();
            if (line == null || line.Length > 65536) throw new IOException("INVALID_REQUEST");
            var request = json.Deserialize<Request>(line);
            if (request == null || request.timeout_seconds < 1 || request.timeout_seconds > 300)
                throw new IOException("INVALID_REQUEST");
            string source = Path.GetFullPath(request.image), output = Path.GetFullPath(request.destination);
            NoLinks(source);
            NoLinks(output);
            if (source.StartsWith("\\\\", StringComparison.Ordinal) || source.IndexOf(':', 2) >= 0 ||
                !File.Exists(source) || Directory.Exists(output) || File.Exists(output) ||
                source.Equals(output, StringComparison.OrdinalIgnoreCase))
                throw new IOException("INVALID_SOURCE_OR_OUTPUT");

            string before = Hash(source);
            if (before != request.source_sha256) throw new IOException("SOURCE_HASH_MISMATCH");
            Directory.CreateDirectory(output);
            var clock = Stopwatch.StartNew();
            string failure = null;
            int recovered = 0;
            bool checkpointInterrupted = false;
            int firstResumeDirectory = -1;
            using (var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(request.timeout_seconds)))
            {
                try
                {
                    switch (request.engine)
                    {
                        case "fat": recovered = FatWithResume(source, output, before, cancel.Token, out checkpointInterrupted, out firstResumeDirectory); break;
                        case "ntfs": recovered = AdvancedEngines.RecoverNtfs(source, output, cancel.Token, text => { }); break;
                        case "ext4": recovered = Ext4Recovery.Recover(source, output, cancel.Token, null); break;
                        default: throw new IOException("UNKNOWN_ENGINE");
                    }
                }
                catch (OperationCanceledException) { failure = "TIMEOUT"; }
                catch (IOException) { failure = "RECOVERY_IO_ERROR"; }
                catch (UnauthorizedAccessException) { failure = "RECOVERY_ACCESS_ERROR"; }
            }
            clock.Stop();
            string after = Hash(source);
            if (before != after) throw new IOException("SOURCE_CHANGED");
            var files = new List<object>();
            foreach (string file in RecoveryCore.RecoveredFiles(output))
            {
                NoLinks(file);
                files.Add(new { path = file, bytes = new FileInfo(file).Length, sha256 = Hash(file) });
            }
            Console.WriteLine(json.Serialize(new
            {
                schema = 1, status = failure == null ? "complete" : "error", code = failure,
                recovered = recovered, files = files, engine = request.engine,
                source_sha256 = before, source_unchanged = true,
                elapsed_ms = clock.ElapsedMilliseconds,
                peak_working_set_bytes = Process.GetCurrentProcess().PeakWorkingSet64,
                memory_scope = "single_process_no_recovery_children",
                checkpoint_interrupted = checkpointInterrupted, first_resume_directory = firstResumeDirectory,
                checkpoint_scope = request.engine == "fat"
                    ? checkpointInterrupted ? "actual_pipeline_cancel_after_native_directory_then_resume" : "no_fat_directory_available"
                    : "not_exercised",
                application_sha256 = Hash(typeof(RecoveryCore).Assembly.Location),
                driver_sha256 = Hash(typeof(NativeStorageBenchmark).Assembly.Location)
            }));
            return failure == null ? 0 : 2;
        }
        catch (Exception error)
        {
            Console.WriteLine(json.Serialize(new { schema = 1, status = "error", code = error.GetType().Name }));
            return 2;
        }
    }
}
