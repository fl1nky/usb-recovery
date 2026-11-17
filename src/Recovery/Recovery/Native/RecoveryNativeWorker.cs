// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace UsbRecovery
{
    internal sealed class RecoveryNativeToolFile
    { internal string Path, Sha256; }

    // The caller supplies public arguments only. Secrets do not belong in this
    // protocol. Tool and DLL leases deny replacement for the complete invocation.
    internal static class RecoveryNativeWorker
    {
        static string Quote(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0 || value.IndexOf('\r') >= 0 || value.IndexOf('\n') >= 0)
                throw new IOException("NATIVE_ARGUMENT_INVALID");
            var result = new StringBuilder("\""); int slashes = 0;
            foreach (char ch in value) {
                if (ch == '\\') { slashes++; continue; }
                result.Append('\\', ch == '"' ? slashes * 2 + 1 : slashes); result.Append(ch); slashes = 0;
            }
            result.Append('\\', slashes * 2); return result.Append('"').ToString();
        }
        internal static void Run(IList<RecoveryNativeToolFile> tools, IList<string> arguments, TimeSpan maximumTime,
            CancellationToken cancel, Action<RecoveryNativeProtocol> consume)
        {
            if (tools == null || tools.Count < 1 || tools.Count > 32 || arguments == null || arguments.Count > 32 ||
                consume == null || maximumTime < TimeSpan.FromMilliseconds(100) || maximumTime > TimeSpan.FromDays(7))
                throw new IOException("NATIVE_WORKER_CONTEXT_INVALID");
            var leases = new List<FileStream>();
            try {
                var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var tool in tools) {
                    cancel.ThrowIfCancellationRequested();
                    if (tool == null || String.IsNullOrEmpty(tool.Path) || tool.Sha256 == null || tool.Sha256.Length != 64 ||
                        tool.Sha256.Any(ch => !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f')) || !paths.Add(Path.GetFullPath(tool.Path)))
                        throw new IOException("NATIVE_TOOL_BINDING_INVALID");
                    var lease = new FileStream(tool.Path, FileMode.Open, FileAccess.Read, FileShare.Read); leases.Add(lease);
                    if (RecoveryCore.HashFile(tool.Path, cancel, (n,total) => { }) != tool.Sha256)
                        throw new IOException("NATIVE_TOOL_CHANGED");
                }
                var start = new ProcessStartInfo { FileName = Path.GetFullPath(tools[0].Path),
                    Arguments = String.Join(" ", arguments.Select(Quote)), WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(tools[0].Path)),
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                    RedirectStandardOutput = true, RedirectStandardError = true };
                using (var job = new ProcessJob())
                using (var process = new Process { StartInfo = start })
                using (var deadline = new CancellationTokenSource()) {
                    cancel.ThrowIfCancellationRequested();
                    if (!process.Start()) throw new IOException("NATIVE_WORKER_START_FAILED");
                    Task errors = null; long diagnosticBytes = 0;
                    try {
                        job.Attach(process);
                        errors = Task.Run(() => {
                            byte[] bytes = new byte[4096]; int count;
                            while ((count = process.StandardError.BaseStream.Read(bytes, 0, bytes.Length)) != 0)
                                diagnosticBytes = Math.Min(1024 * 1024 + 1, diagnosticBytes + count);
                        });
                        deadline.CancelAfter(maximumTime);
                        using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancel,deadline.Token))
                        using (var stop = cancel.Register(job.Stop))
                        using (var timeout = deadline.Token.Register(job.Stop)) {
                            consume(new RecoveryNativeProtocol(process.StandardOutput.BaseStream, process.StandardInput.BaseStream, linked.Token));
                            process.StandardInput.Close();
                            while (!process.WaitForExit(50)) {
                                cancel.ThrowIfCancellationRequested();
                                if (deadline.IsCancellationRequested) throw new IOException("NATIVE_WORKER_TIMEOUT");
                            }
                            cancel.ThrowIfCancellationRequested();
                            if (deadline.IsCancellationRequested) throw new IOException("NATIVE_WORKER_TIMEOUT");
                            if (!errors.Wait(5000) || process.ExitCode != 0 || diagnosticBytes > 1024 * 1024 ||
                                process.StandardOutput.BaseStream.ReadByte() != -1) throw new IOException("NATIVE_WORKER_FAILED");
                        }
                    } catch (Exception error) {
                        cancel.ThrowIfCancellationRequested();
                        if (deadline.IsCancellationRequested) throw new IOException("NATIVE_WORKER_TIMEOUT");
                        if (error is IOException || error is OperationCanceledException) throw;
                        throw new IOException("NATIVE_WORKER_FAILED");
                    } finally {
                        job.Stop();
                        if (!process.HasExited) process.WaitForExit(5000);
                        if (errors != null) { try { errors.Wait(5000); } catch (AggregateException) { } }
                    }
                }
            } finally { foreach (var lease in leases) lease.Dispose(); }
        }
        internal static string Number(long value) { return value.ToString(CultureInfo.InvariantCulture); }
    }
}
