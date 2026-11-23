// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class ApfsRecovery
    {
        static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant(); }
        static string MetadataHash(byte[] bytes) { using (var hash = SHA256.Create()) return Hex(hash.ComputeHash(bytes)); }
        static bool MetadataDigest(string value)
        { return value != null && value.Length == 64 && value.All(ch => ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f'); }
        static string MetadataLimitsIdentity(Limits limits)
        {
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,sha,CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream,Encoding.UTF8)) {
                foreach (var field in typeof(Limits).GetFields(BindingFlags.Instance|BindingFlags.Public).OrderBy(x => x.Name,StringComparer.Ordinal)) {
                    writer.Write(field.Name); writer.Write(field.FieldType.FullName); long value;
                    if (field.FieldType == typeof(int)) { int number = (int)field.GetValue(limits); writer.Write(number); value = number; }
                    else if (field.FieldType == typeof(long)) { value = (long)field.GetValue(limits); writer.Write(value); }
                    else throw new IOException("APFS_LIMIT_TYPE_UNSUPPORTED");
                    if (value <= 0) throw new ArgumentException("APFS limits must be positive");
                }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
        static byte[] ReadMetadata(Context ctx,long offset,int length)
        {
            if (offset < 0 || ctx.ContainerOffset < 0 || offset > Int64.MaxValue-ctx.ContainerOffset) return null;
            offset += ctx.ContainerOffset;
            if (ctx.MetadataRead != null) return ctx.MetadataRead(offset,length);
            ctx.Cancel.ThrowIfCancellationRequested();
            if (offset < 0 || length <= 0 || offset > ctx.Stream.Length-length) return null;
            byte[] bytes = new byte[length]; ctx.Stream.Position = offset; int done = 0;
            while (done < length) { ctx.Cancel.ThrowIfCancellationRequested(); int n = ctx.Stream.Read(bytes,done,length-done); if (n == 0) throw new EndOfStreamException("APFS_METADATA_SHORT_READ"); done += n; }
            return bytes;
        }
        internal sealed class MetadataReadCheckpoint : IDisposable
        {
            readonly Context owner;
            readonly RecoveryMetadataReads.MetadataReadCheckpoint reader;
            readonly Func<long,int,byte[]> callback;
            public MetadataReadCheckpoint(Context ctx,RecoveryCheckpointContext context,Action<string> progress)
            {
                if (context == null || context.Method != "apfs" || ctx.Stream == null || ctx.Stream.CanWrite || ctx.MetadataRead != null)
                    throw new IOException("APFS_METADATA_CONTEXT_INVALID");
                owner = ctx; var input = ctx.Stream; var verified = ctx.VerifiedImage;
                var source = new RecoveryMetadataReads.Context(input,ctx.Cancel,verified,() => MetadataLimitsIdentity(ctx.Limits),() => {
                    if (ctx.Stream != input || ctx.VerifiedImage != verified || ctx.MetadataRead != callback) throw new IOException("APFS_METADATA_OWNER_CHANGED");
                });
                reader = new RecoveryMetadataReads.MetadataReadCheckpoint(source,context,progress);
                callback = reader.ReadBytes; ctx.MetadataRead = callback;
            }
            public void Finish() { reader.Finish(); }
            public void Dispose() { reader.Dispose(); owner.MetadataRead = null; }
        }
    }
}
