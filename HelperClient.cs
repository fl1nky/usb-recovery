using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class HelperResult
    {
        public string Status, Code;
        public long Messages, Media;
        public string Archive;
        public long DiscoveredSources, ReadableSources, EncryptedSources, BlockedSources;
        public long HistoryMessages, NotificationRecords, FragmentRecords, NativeRecords, PreviousRecords;
        public string[] Warnings;
    }

    // Only the controlled protocol is exposed to the UI. Worker stderr and exception
    // text can include third-party diagnostics, and must never enter user reports.
    public static class HelperClient
    {
        public static string Executable { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "recovery-helper", "recovery-helper.exe"); } }
        public static HelperResult Scan(string snapshot, string output, Dictionary<string, string> secrets, bool deep, CancellationToken cancel, Action<string> progress)
        {
            return Analyze("scan", snapshot, output, secrets, deep, cancel, progress);
        }
        public static HelperResult Photos(string source, string output, CancellationToken cancel) { return Analyze("photos", source, output, new Dictionary<string, string>(), false, cancel, null); }
        static HelperResult Analyze(string operation, string source, string output, Dictionary<string, string> secrets, bool deep, CancellationToken cancel, Action<string> progress)
        {
            cancel.ThrowIfCancellationRequested();
            string scratch = Path.GetFullPath(output) + ".work";
            var folder = new DirectoryInfo(scratch);
            for (var ancestor = folder; ancestor != null; ancestor = ancestor.Parent) if (ancestor.Exists && (ancestor.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("HELPER_WORK_PATH_INVALID");
            if (folder.Exists || File.Exists(scratch)) throw new IOException("HELPER_WORK_PATH_EXISTS");
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            folder.Create(acl);
            try { return Run(Executable, new { protocol = 1, operation = operation, source = source, destination = output, secrets = secrets, options = new { deep = deep, scratch = scratch, telegram_only = true } }, cancel, progress); }
            finally { try { RemoveWork(folder); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
        }
        internal static void RemoveWork(DirectoryInfo folder)
        {
            folder.Refresh(); if (!folder.Exists) return;
            if ((folder.Attributes & FileAttributes.ReparsePoint) != 0) { folder.Delete(false); return; }
            foreach (var file in folder.GetFiles()) file.Delete();
            foreach (var child in folder.GetDirectories()) RemoveWork(child);
            folder.Delete(false);
        }

        public static HelperResult Run(string executable, object request, CancellationToken cancel, Action<string> progress)
        {
            cancel.ThrowIfCancellationRequested();
            if (!File.Exists(executable)) throw new IOException("HELPER_MISSING");
            var serializer = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024 };
            using (var process = new Process())
            using (var job = new ProcessJob())
            {
                process.StartInfo = new ProcessStartInfo(executable) {
                    Arguments = "", WorkingDirectory = Path.GetDirectoryName(executable), UseShellExecute = false,
                    RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8, CreateNoWindow = true
                };
                try { process.Start(); job.Attach(process); }
                catch { throw new IOException("HELPER_START_FAILED"); }
                HelperResult result = null;
                // Drain without retaining third-party messages. This also prevents pipe deadlocks.
                Task errors = Task.Run(() => { var chars = new char[4096]; while (process.StandardError.Read(chars, 0, chars.Length) > 0) { } });
                Task reader = Task.Run(() => {
                    string line;
                    while ((line = ReadLine(process.StandardOutput)) != null)
                    {
                        Dictionary<string, object> record;
                        try { record = serializer.Deserialize<Dictionary<string, object>>(line); }
                        catch { continue; }
                        if (record == null || !record.ContainsKey("type")) continue;
                        if (Convert.ToString(record["type"]) == "progress") { if (progress != null) progress("Анализ рабочей копии…"); continue; }
                        if (Convert.ToString(record["type"]) != "result" || result != null) continue;
                        string state = Value(record, "status"), code = Value(record, "code");
                        if (state != "complete" && state != "partial" && state != "error") continue;
                        if (!SafeCode(code)) code = "HELPER_FAILED";
                        object notices; var values = record.TryGetValue("warnings", out notices) ? notices as object[] : null;
                        result = new HelperResult { Status = state, Code = code, Messages = Count(record, "messages"), Media = Count(record, "media"), Archive = Value(record, "archive"), FragmentRecords = Count(record, "fragment_records"), HistoryMessages = Count(record, "history_messages"), NativeRecords = Count(record, "native_records"), PreviousRecords = Count(record, "previous_records"), NotificationRecords = Count(record, "notification_records"), DiscoveredSources = Count(record, "discovered_sources"), ReadableSources = Count(record, "readable_sources"), EncryptedSources = Count(record, "encrypted_sources"), BlockedSources = Count(record, "blocked_sources"), Warnings = values == null ? new string[0] : System.Linq.Enumerable.ToArray(System.Linq.Enumerable.Select(values, Convert.ToString)) };
                    }
                });
                using (cancel.Register(() => job.Stop()))
                {
                    try
                    {
                        // No secret-bearing command line, environment variable or job file.
                        byte[] input = new UTF8Encoding(false).GetBytes(serializer.Serialize(request) + "\n");
                        try { process.StandardInput.BaseStream.Write(input, 0, input.Length); process.StandardInput.BaseStream.Flush(); }
                        finally { Array.Clear(input, 0, input.Length); process.StandardInput.Close(); }
                        while (!process.WaitForExit(200)) cancel.ThrowIfCancellationRequested();
                        Task.WaitAll(reader, errors);
                        cancel.ThrowIfCancellationRequested();
                        if (result == null || (process.ExitCode != 0 && result.Status != "error")) throw new IOException("HELPER_PROTOCOL_ERROR");
                        return result;
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { cancel.ThrowIfCancellationRequested(); throw new IOException("HELPER_FAILED"); }
                    finally { job.Stop(); try { Task.WaitAll(new[] { reader, errors }, 3000); } catch { } }
                }
            }
        }

        static string ReadLine(StreamReader stream)
        {
            var line = new StringBuilder(); int value;
            while ((value = stream.Read()) >= 0) {
                if (value == 10) return line.ToString();
                if (value != 13 && line.Length < 1024 * 1024) line.Append((char)value);
                else if (line.Length >= 1024 * 1024) { while ((value = stream.Read()) >= 0 && value != 10) { } return ""; }
            }
            return line.Length > 0 ? line.ToString() : null;
        }
        static string Value(Dictionary<string, object> record, string key) { object value; return record.TryGetValue(key, out value) ? Convert.ToString(value) : ""; }
        static long Count(Dictionary<string, object> record, string key) { long value; return Int64.TryParse(Value(record, key), out value) && value >= 0 ? value : 0; }
        static bool SafeCode(string code) { return new HashSet<string>(new[] { "OK", "COMPLETE", "PARTIAL", "PARTIAL_DATA", "SOURCE_UNAVAILABLE", "AUTH_FAILED", "AUTHENTICATION_FAILED", "DECRYPTION_FAILED", "WRONG_KEY", "UNSUPPORTED_VERSION", "UNSUPPORTED_FORMAT", "SECRET_REQUIRED", "KEY_REQUIRED", "PASSWORD_REQUIRED", "INVALID_SOURCE", "SOURCE_ERROR", "CANCELLED", "HELPER_FAILED", "DEPENDENCY_MISSING", "NO_DATA", "NO_READABLE_TELEGRAM_HISTORY", "REGEX_INVALID", "REGEX_TIMEOUT", "INVALID_REQUEST", "IO_ERROR" }, StringComparer.Ordinal).Contains(code ?? ""); }
    }

    // Closing the job also terminates native importers started by the Python worker.
    sealed class ProcessJob : IDisposable
    {
        IntPtr handle;
        [StructLayout(LayoutKind.Sequential)] struct Basic { public long PerProcess, PerJob; public uint Flags; public UIntPtr Min, Max; public uint Active; public UIntPtr Affinity; public uint Priority, Scheduling; }
        [StructLayout(LayoutKind.Sequential)] struct Io { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
        [StructLayout(LayoutKind.Sequential)] struct Limits { public Basic Basic; public Io Io; public UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr job, int info, IntPtr data, uint length);
        [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll")] static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        public ProcessJob()
        {
            handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero) throw new IOException("HELPER_START_FAILED");
            var limits = new Limits { Basic = new Basic { Flags = 0x2000 } };
            IntPtr data = Marshal.AllocHGlobal(Marshal.SizeOf(limits));
            try { Marshal.StructureToPtr(limits, data, false); if (!SetInformationJobObject(handle, 9, data, (uint)Marshal.SizeOf(limits))) throw new IOException("HELPER_START_FAILED"); }
            finally { Marshal.FreeHGlobal(data); }
        }
        public void Attach(Process process) { if (!AssignProcessToJobObject(handle, process.Handle)) { try { process.Kill(); } catch { } throw new IOException("HELPER_START_FAILED"); } }
        public void Stop() { if (handle != IntPtr.Zero) TerminateJobObject(handle, 1); }
        public void Dispose() { if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; } }
    }
}
