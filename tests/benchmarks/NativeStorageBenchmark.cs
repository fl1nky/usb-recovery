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
            using (var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(request.timeout_seconds)))
            {
                try
                {
                    switch (request.engine)
                    {
                        case "fat": recovered = FilesystemRecovery.Recover(source, output, cancel.Token, text => { }); break;
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
