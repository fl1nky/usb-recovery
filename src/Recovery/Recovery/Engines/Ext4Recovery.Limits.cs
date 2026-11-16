using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    public static partial class Ext4Recovery
    {
        // Reflection/serializer field order can change after member-cache
        // priming. Bind every field by sorted name, type and exact scalar value.
        static string Ext4LimitsIdentity(Limits limits)
        {
            if (limits == null) throw new IOException("EXT4_LIMITS_MISSING");
            using (var sha = SHA256.Create()) using (var stream = new CryptoStream(Stream.Null, sha, CryptoStreamMode.Write))
            using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true)))
            {
                var fields = typeof(Limits).GetFields(BindingFlags.Public | BindingFlags.Instance).OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
                writer.Write(fields.Length);
                foreach (var field in fields)
                {
                    writer.Write(field.Name);
                    if (field.FieldType == typeof(int)) { writer.Write((byte)1); writer.Write((int)field.GetValue(limits)); }
                    else if (field.FieldType == typeof(long)) { writer.Write((byte)2); writer.Write((long)field.GetValue(limits)); }
                    else throw new IOException("EXT4_LIMIT_TYPE_UNSUPPORTED");
                }
                writer.Flush(); stream.FlushFinalBlock(); return Hex(sha.Hash);
            }
        }
    }
}
