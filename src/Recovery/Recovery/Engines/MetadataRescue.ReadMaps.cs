using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace UsbRecovery
{
    public static partial class MetadataRescue
    {
        // Existing regular maps stay read-locked for this pass. A map appearing
        // at a previously absent path invalidates the captured trust context.
        sealed class RescueReadMaps : IDisposable
        {
            readonly List<FileStream> guards = new List<FileStream>();
            readonly List<string> missing = new List<string>();
            public readonly string Identity;
            public bool Untrusted { get; private set; }

            public RescueReadMaps(string image, string root, CancellationToken cancel)
            {
                var identities = new List<string>();
                try
                {
                    foreach (string path in new[] { Path.Combine(root, "source-read-errors.json"), image + ".read-errors.json" })
                    {
                        cancel.ThrowIfCancellationRequested();
                        if (!File.Exists(path) && !Directory.Exists(path))
                        { missing.Add(path); identities.Add("absent"); continue; }
                        try
                        {
                            var attributes = File.GetAttributes(path);
                            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                            { Untrusted = true; identities.Add("unsafe-kind"); continue; }
                            var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                            guards.Add(guard);
                            if (guard.Length > 2 * 1024 * 1024)
                            { Untrusted = true; identities.Add("oversized:" + guard.Length); continue; }
                            identities.Add(RecoveryCore.HashFile(path, cancel, (a, b) => { }));
                        }
                        catch (IOException) { Untrusted = true; identities.Add("unreadable"); }
                        catch (UnauthorizedAccessException) { Untrusted = true; identities.Add("unreadable"); }
                    }
                    Identity = RescueJson(identities);
                }
                catch { Dispose(); throw; }
            }
            public void Verify()
            {
                foreach (string path in missing)
                    if (File.Exists(path) || Directory.Exists(path)) throw new IOException("NTFS_RECORD_READ_MAP_CHANGED");
            }
            public void Dispose()
            {
                foreach (var guard in guards) guard.Dispose();
                guards.Clear();
            }
        }
    }
}
