using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public enum ShellbagItemType
    {
        Unknown = 0,
        Root = 1,
        Drive = 2,
        Directory = 3,
        File = 4,
        NetworkShare = 5
    }

    /// <summary>
    /// Represents a parsed Windows Explorer Shellbag folder access artifact.
    /// Proves access, presence, and timestamps of folders on local, network, and removable USB drives.
    /// </summary>
    public sealed class ShellbagRecord
    {
        public int FolderIndex { get; set; }
        public string MruPath { get; set; }
        public int NodeSlot { get; set; }
        public string FullPath { get; set; }
        public string FolderName { get; set; }
        public ShellbagItemType ItemType { get; set; }
        public DateTime CreatedTimeUtc { get; set; }
        public DateTime ModifiedTimeUtc { get; set; }
        public DateTime AccessedTimeUtc { get; set; }
        public DateTime KeyLastWriteTimeUtc { get; set; }
        public string RegistrySource { get; set; }

        public ShellbagRecord()
        {
            MruPath = String.Empty;
            FullPath = String.Empty;
            FolderName = String.Empty;
            RegistrySource = String.Empty;
            ItemType = ShellbagItemType.Unknown;
            CreatedTimeUtc = DateTime.MinValue;
            ModifiedTimeUtc = DateTime.MinValue;
            AccessedTimeUtc = DateTime.MinValue;
            KeyLastWriteTimeUtc = DateTime.MinValue;
        }

        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "[{0}] {1} (Type: {2}, Modified: {3:yyyy-MM-dd HH:mm:ss} UTC)",
                KeyLastWriteTimeUtc != DateTime.MinValue ? KeyLastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss") : "N/A",
                FullPath, ItemType, ModifiedTimeUtc);
        }
    }

    /// <summary>
    /// Forensic parser for Windows Shellbags from UsrClass.dat and NTUSER.DAT registry hives.
    /// Decodes SHITEMID binary structures, extension blocks, FAT/FILETIME dates, and folder MRU trees.
    /// 100% offline, zero network telemetry, strictly bounded memory.
    /// </summary>
    public static class ShellbagsParser
    {
        private static readonly Dictionary<string, string> KnownFolderGuids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "20D04FE0-3AEA-1069-A2D8-08002B30309D", "This PC" },
            { "450D8FBA-AD25-11D0-98A8-0800361B1103", "My Documents" },
            { "F02C1A0D-BE21-4350-88B0-7367FC96EF3C", "Network" },
            { "645FF040-5081-101B-9F08-00AA002F954E", "Recycle Bin" },
            { "59031A47-3F72-44A7-89C5-5595FE6B30EE", "Shared Users" },
            { "21EC2020-3AEA-1069-A2DD-08002B30309D", "Control Panel" },
            { "031E4825-7B94-4DC3-B131-E946B44C8DD5", "Libraries" }
        };

        // =========================================================================
        // Main Parser Entry Points
        // =========================================================================

        public static List<ShellbagRecord> Parse(RegistryHive hive, string hiveName = "UsrClass.dat")
        {
            var records = new List<ShellbagRecord>();
            if (hive == null) return records;

            // Search paths in UsrClass.dat
            var candidatePaths = new string[]
            {
                "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
                "BagMRU"
            };

            for (int i = 0; i < candidatePaths.Length; i++)
            {
                var bagMruKey = hive.GetKey(candidatePaths[i]);
                if (bagMruKey != null)
                {
                    TraverseBagMru(bagMruKey, "", "0", records, hiveName);
                    break;
                }
            }

            return records;
        }

        public static List<ShellbagRecord> Parse(Stream stream, string hiveName = "UsrClass.dat")
        {
            if (stream == null || !stream.CanRead) return new List<ShellbagRecord>();
            try
            {
                using (var hive = RegistryHive.Open(stream))
                {
                    return Parse(hive, hiveName);
                }
            }
            catch
            {
                return new List<ShellbagRecord>();
            }
        }

        public static List<ShellbagRecord> Parse(string filePath)
        {
            if (String.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return new List<ShellbagRecord>();
            string hiveName = Path.GetFileName(filePath);
            try
            {
                using (var hive = RegistryHive.Open(filePath))
                {
                    return Parse(hive, hiveName);
                }
            }
            catch
            {
                return new List<ShellbagRecord>();
            }
        }

        // =========================================================================
        // BagMRU Tree Traversal
        // =========================================================================

        private static void TraverseBagMru(RegistryKey mruKey, string parentPath, string mruPath, List<ShellbagRecord> records, string hiveName)
        {
            if (mruKey == null) return;

            // Values with numeric names (0, 1, 2, ...) represent SHITEMID data
            if (mruKey.Values != null)
            {
                for (int v = 0; v < mruKey.Values.Count; v++)
                {
                    var val = mruKey.Values[v];
                    int slotIndex;
                    if (int.TryParse(val.Name, NumberStyles.Integer, CultureInfo.InvariantCulture, out slotIndex))
                    {
                        byte[] itemBytes = val.RawData ?? (val.Value as byte[]);
                        if (itemBytes != null && itemBytes.Length >= 2)
                        {
                            var rec = DecodeShItemId(itemBytes);
                            rec.FolderIndex = records.Count + 1;
                            rec.NodeSlot = slotIndex;
                            rec.MruPath = string.IsNullOrEmpty(mruPath) ? slotIndex.ToString() : (mruPath + "\\" + slotIndex);
                            rec.KeyLastWriteTimeUtc = mruKey.LastWriteTimeUtc;
                            rec.RegistrySource = hiveName;

                            string currentFullPath;
                            if (rec.ItemType == ShellbagItemType.Drive || string.IsNullOrEmpty(parentPath))
                            {
                                currentFullPath = rec.FolderName;
                            }
                            else
                            {
                                currentFullPath = parentPath.TrimEnd('\\') + "\\" + rec.FolderName;
                            }
                            rec.FullPath = currentFullPath;

                            records.Add(rec);

                            // Check if a corresponding subkey exists for this slot (e.g. subkey "0", "1")
                            var subMruKey = mruKey.GetSubkey(slotIndex.ToString());
                            if (subMruKey != null)
                            {
                                TraverseBagMru(subMruKey, currentFullPath, rec.MruPath, records, hiveName);
                            }
                        }
                    }
                }
            }
        }

        // =========================================================================
        // SHITEMID Binary Decoding
        // =========================================================================

        public static ShellbagRecord DecodeShItemId(byte[] rawData)
        {
            var rec = new ShellbagRecord();
            if (rawData == null || rawData.Length < 2) return rec;

            int cursor = 0;
            ushort cb = ReadUInt16Le(rawData, cursor);
            if (cb < 2 || cb > rawData.Length) cb = (ushort)rawData.Length;

            byte type = rawData[cursor + 2];
            byte typeGroup = (byte)(type & 0x70);

            // 1. Root / CLSID Shell Folder (type 0x1F)
            if (type == 0x1F && cb >= 20)
            {
                rec.ItemType = ShellbagItemType.Root;
                byte[] clsidBytes = new byte[16];
                Array.Copy(rawData, cursor + 4, clsidBytes, 0, 16);
                string clsid = FormatGuid(clsidBytes);

                string friendlyName;
                if (KnownFolderGuids.TryGetValue(clsid, out friendlyName))
                {
                    rec.FolderName = friendlyName;
                }
                else
                {
                    rec.FolderName = "::{" + clsid + "}";
                }
                rec.FullPath = rec.FolderName;
                return rec;
            }

            // 2. Drive Letter (type 0x20..0x2F)
            if ((type & 0xF0) == 0x20)
            {
                rec.ItemType = ShellbagItemType.Drive;
                // String starts at offset 3
                string driveStr = ReadAsciiZ(rawData, cursor + 3, cb - 3);
                if (String.IsNullOrEmpty(driveStr))
                {
                    driveStr = ReadUnicodeZ(rawData, cursor + 3, cb - 3);
                }
                rec.FolderName = !String.IsNullOrEmpty(driveStr) ? driveStr : "Drive";
                rec.FullPath = rec.FolderName;
                return rec;
            }

            // 3. Network Share (type 0x40..0x4F)
            if (typeGroup == 0x40)
            {
                rec.ItemType = ShellbagItemType.NetworkShare;
                string shareStr = ReadAsciiZ(rawData, cursor + 5, cb - 5);
                if (String.IsNullOrEmpty(shareStr)) shareStr = ReadUnicodeZ(rawData, cursor + 5, cb - 5);
                rec.FolderName = !String.IsNullOrEmpty(shareStr) ? shareStr : "Network";
                rec.FullPath = rec.FolderName;
                return rec;
            }

            // 4. Directory or File (type 0x30..0x3F)
            if (typeGroup == 0x30)
            {
                rec.ItemType = (type == 0x32) ? ShellbagItemType.File : ShellbagItemType.Directory;

                // DOS modified date and time at offset 8 and 10 (if cb >= 14)
                if (cb >= 14)
                {
                    ushort dosDate = ReadUInt16Le(rawData, cursor + 8);
                    ushort dosTime = ReadUInt16Le(rawData, cursor + 10);
                    rec.ModifiedTimeUtc = DosDateTimeToUtc(dosDate, dosTime);
                }

                // Short filename ASCII starts at offset 14 (or offset 4 if small entry)
                int nameOffset = (cb >= 14) ? (cursor + 14) : (cursor + 4);
                string shortName = ReadAsciiZ(rawData, nameOffset, cb - (nameOffset - cursor));
                rec.FolderName = shortName;

                // Check for BEEF0004 / 0x0004 Extension Block containing Unicode long name and file dates
                ParseExtensionBlock(rawData, cursor, cb, rec);

                if (String.IsNullOrEmpty(rec.FolderName))
                {
                    rec.FolderName = "Folder";
                }

                return rec;
            }

            // Fallback generic string extraction
            string genericName = ReadUnicodeZ(rawData, cursor + 2, cb - 2);
            if (String.IsNullOrEmpty(genericName)) genericName = ReadAsciiZ(rawData, cursor + 2, cb - 2);
            rec.FolderName = !String.IsNullOrEmpty(genericName) ? genericName : "Unknown";
            rec.ItemType = ShellbagItemType.Unknown;
            return rec;
        }

        private static void ParseExtensionBlock(byte[] buf, int start, int length, ShellbagRecord rec)
        {
            // Extension block search for signature: size (2 bytes), version (2 bytes), signature 0xBEEF0004 (4 bytes)
            // or 0x04 0x00 0xEF 0xBE
            for (int i = start + 14; i + 16 <= start + length; i++)
            {
                ushort extSize = ReadUInt16Le(buf, i);
                if (extSize >= 16 && i + extSize <= start + length)
                {
                    ushort extSig = ReadUInt16Le(buf, i + 2); // often 0x0004 or 0x0008
                    ushort extBeef = ReadUInt16Le(buf, i + 4); // 0xBEEF

                    if (extBeef == 0xBEEF || extSig == 0x0004 || extSig == 0x0003 || extSig == 0x0008)
                    {
                        // Creation date (offset 8): DOS date/time or FILETIME
                        if (i + 12 <= start + length)
                        {
                            ushort crDate = ReadUInt16Le(buf, i + 8);
                            ushort crTime = ReadUInt16Le(buf, i + 10);
                            DateTime cr = DosDateTimeToUtc(crDate, crTime);
                            if (cr != DateTime.MinValue) rec.CreatedTimeUtc = cr;
                        }

                        // Access date (offset 12)
                        if (i + 16 <= start + length)
                        {
                            ushort acDate = ReadUInt16Le(buf, i + 12);
                            ushort acTime = ReadUInt16Le(buf, i + 14);
                            DateTime ac = DosDateTimeToUtc(acDate, acTime);
                            if (ac != DateTime.MinValue) rec.AccessedTimeUtc = ac;
                        }

                        // Long Unicode folder name starts at offset i + 24 or i + 28
                        int unicodeOffset = -1;
                        for (int u = i + 16; u + 4 <= i + extSize; u += 2)
                        {
                            if (buf[u] >= 32 && buf[u + 1] == 0)
                            {
                                unicodeOffset = u;
                                break;
                            }
                        }

                        if (unicodeOffset > 0)
                        {
                            string longName = ReadUnicodeZ(buf, unicodeOffset, i + extSize - unicodeOffset);
                            if (!String.IsNullOrEmpty(longName))
                            {
                                rec.FolderName = longName;
                            }
                        }

                        break;
                    }
                }
            }
        }

        // =========================================================================
        // String and Binary Helpers
        // =========================================================================

        private static string ReadAsciiZ(byte[] b, int offset, int maxLen)
        {
            if (offset < 0 || offset >= b.Length || maxLen <= 0) return String.Empty;
            int end = offset;
            int limit = Math.Min(b.Length, offset + maxLen);
            while (end < limit && b[end] != 0 && b[end] >= 32 && b[end] < 127)
            {
                end++;
            }
            if (end == offset) return String.Empty;
            return Encoding.ASCII.GetString(b, offset, end - offset);
        }

        private static string ReadUnicodeZ(byte[] b, int offset, int maxLen)
        {
            if (offset < 0 || offset + 1 >= b.Length || maxLen <= 1) return String.Empty;
            int end = offset;
            int limit = Math.Min(b.Length - 1, offset + maxLen);
            while (end + 1 <= limit)
            {
                char c = (char)(b[end] | (b[end + 1] << 8));
                if (c == '\0') break;
                end += 2;
            }
            if (end == offset) return String.Empty;
            return Encoding.Unicode.GetString(b, offset, end - offset);
        }

        private static DateTime DosDateTimeToUtc(ushort fatDate, ushort fatTime)
        {
            if (fatDate == 0) return DateTime.MinValue;
            try
            {
                int year = 1980 + ((fatDate >> 9) & 0x7F);
                int month = (fatDate >> 5) & 0x0F;
                int day = fatDate & 0x1F;

                int hour = (fatTime >> 11) & 0x1F;
                int minute = (fatTime >> 5) & 0x3F;
                int second = (fatTime & 0x1F) * 2;

                if (month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
                    hour < 24 && minute < 60 && second < 60)
                {
                    return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
                }
            }
            catch { }

            return DateTime.MinValue;
        }

        private static ushort ReadUInt16Le(byte[] b, int offset)
        {
            return (ushort)(b[offset] | (b[offset + 1] << 8));
        }

        private static string FormatGuid(byte[] bytes)
        {
            if (bytes == null || bytes.Length != 16) return String.Empty;
            try
            {
                return new Guid(bytes).ToString("D").ToUpperInvariant();
            }
            catch
            {
                return String.Empty;
            }
        }
    }
}
