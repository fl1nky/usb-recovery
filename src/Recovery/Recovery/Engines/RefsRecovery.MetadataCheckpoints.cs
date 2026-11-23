// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static partial class RefsRecovery
    {
        static string MetadataLimitsIdentity(Limits limits)
        {
            using (var hash = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null,hash,CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream,Encoding.UTF8)) {
                foreach (var field in typeof(Limits).GetFields(BindingFlags.Instance|BindingFlags.Public).OrderBy(x => x.Name,StringComparer.Ordinal)) {
                    writer.Write(field.Name); writer.Write(field.FieldType.FullName);
                    long value;
                    if (field.FieldType == typeof(int)) { int number = (int)field.GetValue(limits); writer.Write(number); value = number; }
                    else if (field.FieldType == typeof(long)) { value = (long)field.GetValue(limits); writer.Write(value); }
                    else throw new IOException("REFS_LIMIT_TYPE_UNSUPPORTED");
                    if (value < 0 || value == 0 && field.Name != "MaximumSalvageBlocks") throw new ArgumentException("Неверные ограничения ReFS");
                }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(hash.Hash);
            }
        }
        static bool MetadataDigest(string value)
        { return value != null && value.Length == 64 && value.All(ch => ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f'); }
        static string MetadataHash(byte[] bytes)
        { using (var hash = SHA256.Create()) return Hex(hash.ComputeHash(bytes)); }
        internal sealed class MetadataReadCheckpoint : IDisposable
        {
            readonly Context owner;
            readonly RecoveryMetadataReads.MetadataReadCheckpoint reader;
            readonly Func<long,int,byte[]> callback;
            public MetadataReadCheckpoint(Context c, RecoveryCheckpointContext context, Action<string> notify)
            {
                if (context == null || context.Method != "refs" || c.Input == null || c.Input.CanWrite || c.MetadataRead != null)
                    throw new IOException("REFS_METADATA_CONTEXT_INVALID");
                owner = c; var input = c.Input; var verified = c.VerifiedImage;
                var source = new RecoveryMetadataReads.Context(input,c.Cancel,verified,() => MetadataLimitsIdentity(c.Limits),() => {
                    if (c.Input != input || c.VerifiedImage != verified || c.MetadataRead != callback)
                        throw new IOException("REFS_METADATA_CONTEXT_CHANGED");
                });
                reader = new RecoveryMetadataReads.MetadataReadCheckpoint(source,context,notify);
                callback = reader.ReadBytes; c.MetadataRead = callback;
            }
            public byte[] ReadBytes(long offset,int count) { return reader.ReadBytes(offset,count); }
            public void Finish() { reader.Finish(); }
            public void Dispose() { reader.Dispose(); owner.MetadataRead = null; }
        }
    }
}
