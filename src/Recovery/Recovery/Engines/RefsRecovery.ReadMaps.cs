// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class RefsRecovery
    {
        sealed class RefsReadMapLease : IDisposable
        {
            readonly List<FileStream> leases = new List<FileStream>();
            readonly List<KeyValuePair<string,bool>> paths = new List<KeyValuePair<string,bool>>();
            public readonly string Identity;
            public RefsReadMapLease(Context c, RecoveryCheckpointContext context)
            {
                try {
                    using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,sha,CryptoStreamMode.Write))
                    using (var writer = new BinaryWriter(stream,Encoding.UTF8)) {
                        foreach (string path in new[] { RecoveryCatalog.SafeFile(context.Directory,"source-read-errors.json"), RecoveryCatalog.SafeFile(context.Directory,"capture.json"),
                            RecoveryCatalog.SafeFile(context.Directory,"source-image.json"),c.Input.Name+".read-errors.json" }) {
                            NoLinks(path); if (Directory.Exists(path)) throw new IOException("REFS_READ_MAP_INVALID");
                            bool exists = File.Exists(path); paths.Add(new KeyValuePair<string,bool>(path,exists)); writer.Write(exists);
                            if (!exists) continue;
                            var file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read); leases.Add(file);
                            if (file.Length > 2L*1024*1024) throw new IOException("REFS_READ_MAP_LIMIT");
                            writer.Write(file.Length); writer.Write(HashStream(file,c.Cancel));
                        }
                        writer.Flush(); stream.FlushFinalBlock(); Identity = Hex(sha.Hash);
                    }
                    if (FileEvidence.HasUnreadSource(context.Directory,c.Input.Name)) throw new IOException("REFS_READ_MAP_UNREAD_SOURCE");
                } catch { Dispose(); throw; }
            }
            public void Validate()
            { foreach (var row in paths) { NoLinks(row.Key); if (Directory.Exists(row.Key) || File.Exists(row.Key) != row.Value) throw new IOException("REFS_READ_MAP_CHANGED"); } }
            public void Dispose() { foreach (var lease in leases) lease.Dispose(); }
        }
    }
}
