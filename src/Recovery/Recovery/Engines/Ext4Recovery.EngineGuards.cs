using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        sealed class EngineReadMaps : IDisposable
        {
            readonly List<FileStream> leases = new List<FileStream>();
            readonly List<KeyValuePair<string,bool>> paths = new List<KeyValuePair<string,bool>>();
            public readonly string Identity;
            public EngineReadMaps(Context c,RecoveryCheckpointContext context)
            {
                try {
                    using (var hash = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,hash,CryptoStreamMode.Write))
                    using (var writer = new BinaryWriter(stream,Encoding.UTF8)) {
                        string[] names = { RecoveryCatalog.SafeFile(context.Directory,"source-read-errors.json"),
                            RecoveryCatalog.SafeFile(context.Directory,"capture.json"), RecoveryCatalog.SafeFile(context.Directory,"source-image.json"),
                            c.Input.Name+".read-errors.json" };
                        foreach (string path in names) {
                            NoLinks(path); if (Directory.Exists(path)) throw new IOException("EXT4_READ_MAP_INVALID");
                            bool exists = File.Exists(path); paths.Add(new KeyValuePair<string,bool>(path,exists)); writer.Write(exists);
                            if (!exists) continue;
                            var lease = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read); leases.Add(lease);
                            if (lease.Length > 2L*1024*1024) throw new IOException("EXT4_READ_MAP_LIMIT");
                            writer.Write(lease.Length); writer.Write(HashStream(lease,c.Cancel));
                        }
                        writer.Flush(); stream.FlushFinalBlock(); Identity = Hex(hash.Hash);
                    }
                    if (FileEvidence.HasUnreadSource(context.Directory,c.Input.Name)) throw new IOException("EXT4_READ_MAP_UNREAD_SOURCE");
                } catch { Dispose(); throw; }
            }
            public void Validate()
            {
                foreach (var row in paths) {
                    NoLinks(row.Key);
                    if (Directory.Exists(row.Key) || File.Exists(row.Key) != row.Value) throw new IOException("EXT4_READ_MAP_CHANGED");
                }
            }
            public void Dispose() { foreach (var lease in leases) lease.Dispose(); }
        }
        static string EngineRequestIdentity(List<long> offsets)
        {
            using (var hash = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,hash,CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream,Encoding.UTF8)) {
                writer.Write(offsets != null);
                if (offsets != null) { writer.Write(offsets.Count); foreach (long offset in offsets) writer.Write(offset); }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(hash.Hash);
            }
        }
        static string EngineOutcomeIdentity(Context c)
        {
            using (var hash = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,hash,CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream,Encoding.UTF8)) {
                writer.Write(c.InodesRead); writer.Write(c.DirectoryCount); writer.Write(c.NameCount); writer.Write(c.DirectoryBytes);
                writer.Write(c.Report.Candidates); writer.Write(c.Report.RecoveredFiles); writer.Write(c.Report.OutputBytes);
                writer.Write(c.Report.Entries.Count); writer.Write(c.Report.Limited); writer.Flush();
                using (var text = new StreamWriter(stream,new UTF8Encoding(false,true),4096,true)) {
                    WriteReportValue(text,c.Report.Volumes,c); WriteReportValue(text,c.Report.Skipped,c); text.Flush();
                }
                stream.FlushFinalBlock(); return Hex(hash.Hash);
            }
        }
    }
}
