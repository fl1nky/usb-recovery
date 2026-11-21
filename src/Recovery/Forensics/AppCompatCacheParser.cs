using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public sealed class AppCompatCacheEntry
    {
        public int EntryIndex { get; set; }
        public string Path { get; set; }
        public DateTime LastModifiedTimeUtc { get; set; }
        public bool Executed { get; set; }
        public uint DataSize { get; set; }

        public AppCompatCacheEntry()
        {
            Path = String.Empty;
            LastModifiedTimeUtc = DateTime.MinValue;
            Executed = false;
            DataSize = 0;
        }

        public override string ToString()
        {
            return string.Format(System.Globalization.CultureInfo.InvariantCulture,
                "[{0}] {1} (Modified: {2:yyyy-MM-dd HH:mm:ss} UTC, Executed: {3})",
                EntryIndex, Path, LastModifiedTimeUtc, Executed);
        }
    }

    /// <summary>
    /// Pure C# parser for Windows AppCompatCache (Shimcache) artifacts from the SYSTEM registry hive.
    /// Extracts full execution history, paths, and timestamps across Windows 7, 8, 10, and 11 formats.
    /// </summary>
    public static class AppCompatCacheParser
    {
        private const uint Win10Magic = 0x30307374U; // "00ts" / "10ts"
        private const uint Win10MagicAlt = 0x31307374U; // "10ts"
        private const uint Win8Magic = 0x00000002U;
        private const uint Win7Magic = 0xBADC0FFEU;

        private const long MinValidFileTime = 124339200000000000L; // 1995-01-01 UTC
        private const long MaxValidFileTime = 141704640000000000L; // 2050-01-01 UTC

        /// <summary>
        /// Automatically extracts and parses AppCompatCache from an open SYSTEM RegistryHive.
        /// </summary>
        public static List<AppCompatCacheEntry> ExtractFromSystemHive(RegistryHive systemHive)
        {
            var results = new List<AppCompatCacheEntry>();
            if (systemHive == null) return results;

            var summary = systemHive.ExtractSystemSummary();
            string ccs = !String.IsNullOrEmpty(summary.CurrentControlSet) ? summary.CurrentControlSet : "ControlSet001";

            var key = systemHive.GetKey(ccs + "\\Control\\Session Manager\\AppCompatCache")
                   ?? systemHive.GetKey("CurrentControlSet\\Control\\Session Manager\\AppCompatCache");

            if (key == null) return results;

            var val = key.GetValue("AppCompatCache");
            if (val == null || val.RawData == null || val.RawData.Length < 16) return results;

            return Parse(val.RawData);
        }

        /// <summary>
        /// Parses raw AppCompatCache binary data.
        /// </summary>
        public static List<AppCompatCacheEntry> Parse(byte[] data)
        {
            var results = new List<AppCompatCacheEntry>();
            if (data == null || data.Length < 16) return results;

            uint magic = BitConverter.ToUInt32(data, 0);

            // Windows 10/11 format ("10ts" / "00ts")
            if (magic == Win10Magic || magic == Win10MagicAlt || (data.Length > 52 && BitConverter.ToUInt32(data, 48) == Win10MagicAlt))
            {
                return ParseWindows10(data);
            }

            // Windows 7 format
            if (magic == Win7Magic || magic == 0x00000002U)
            {
                return ParseWindows7(data);
            }

            // Generic scan for "10ts" signature within data
            return ParseGenericSignatureScan(data);
        }

        private static List<AppCompatCacheEntry> ParseWindows10(byte[] data)
        {
            var results = new List<AppCompatCacheEntry>();
            int cursor = 0;

            // Search for first "10ts" signature
            while (cursor + 14 <= data.Length)
            {
                if (data[cursor] == 0x31 && data[cursor + 1] == 0x30 && data[cursor + 2] == 0x73 && data[cursor + 3] == 0x74)
                {
                    break;
                }
                cursor += 4;
            }

            if (cursor + 14 > data.Length) return results;

            int entryIndex = 0;
            while (cursor + 14 <= data.Length)
            {
                uint sig = BitConverter.ToUInt32(data, cursor);
                if (sig != Win10MagicAlt)
                {
                    // Scan forward to next 10ts
                    cursor += 2;
                    while (cursor + 14 <= data.Length)
                    {
                        if (data[cursor] == 0x31 && data[cursor + 1] == 0x30 && data[cursor + 2] == 0x73 && data[cursor + 3] == 0x74)
                            break;
                        cursor += 2;
                    }
                    if (cursor + 14 > data.Length) break;
                }

                uint dataSize = BitConverter.ToUInt32(data, cursor + 8);
                ushort pathLen = BitConverter.ToUInt16(data, cursor + 12);

                if (pathLen == 0 || pathLen > 2048 || cursor + 14 + pathLen > data.Length)
                {
                    cursor += 4;
                    continue;
                }

                string path = Encoding.Unicode.GetString(data, cursor + 14, pathLen);
                int timeOffset = cursor + 14 + pathLen;

                DateTime lastMod = DateTime.MinValue;
                if (timeOffset + 8 <= data.Length)
                {
                    long ft = BitConverter.ToInt64(data, timeOffset);
                    if (ft >= MinValidFileTime && ft <= MaxValidFileTime)
                    {
                        try { lastMod = DateTime.FromFileTimeUtc(ft); } catch { }
                    }
                }

                bool executed = true;
                if (dataSize > 0)
                {
                    executed = true; // Presence in 10ts table indicates execution
                }

                if (!String.IsNullOrEmpty(path))
                {
                    results.Add(new AppCompatCacheEntry
                    {
                        EntryIndex = ++entryIndex,
                        Path = CleanPath(path),
                        LastModifiedTimeUtc = lastMod,
                        Executed = executed,
                        DataSize = dataSize
                    });
                }

                // Advance cursor past entry
                int entryTotalLen = 14 + pathLen + 8 + (int)dataSize;
                if (entryTotalLen <= 0 || cursor + entryTotalLen > data.Length)
                {
                    cursor += 14 + pathLen;
                }
                else
                {
                    cursor += entryTotalLen;
                }
            }

            return results;
        }

        private static List<AppCompatCacheEntry> ParseWindows7(byte[] data)
        {
            var results = new List<AppCompatCacheEntry>();
            if (data.Length < 128) return results;

            uint numEntries = BitConverter.ToUInt32(data, 4);
            if (numEntries == 0 || numEntries > 5000) numEntries = 1024;

            int headerSize = 128;
            int cursor = headerSize;
            int entryIndex = 0;

            for (uint i = 0; i < numEntries; i++)
            {
                if (cursor + 32 > data.Length) break;

                ushort pathLen = BitConverter.ToUInt16(data, cursor);
                ushort maxLen = BitConverter.ToUInt16(data, cursor + 2);
                uint pathOff = BitConverter.ToUInt32(data, cursor + 4);
                long ft = BitConverter.ToInt64(data, cursor + 8);
                uint flags = BitConverter.ToUInt32(data, cursor + 16);

                if (pathLen > 0 && pathLen < 2048 && pathOff < data.Length && pathOff + pathLen <= data.Length)
                {
                    string path = Encoding.Unicode.GetString(data, (int)pathOff, pathLen);
                    DateTime lastMod = DateTime.MinValue;
                    if (ft >= MinValidFileTime && ft <= MaxValidFileTime)
                    {
                        try { lastMod = DateTime.FromFileTimeUtc(ft); } catch { }
                    }

                    results.Add(new AppCompatCacheEntry
                    {
                        EntryIndex = ++entryIndex,
                        Path = CleanPath(path),
                        LastModifiedTimeUtc = lastMod,
                        Executed = (flags & 0x02) != 0,
                        DataSize = flags
                    });
                }

                cursor += 32; // Windows 7 entry descriptor size
            }

            return results;
        }

        private static List<AppCompatCacheEntry> ParseGenericSignatureScan(byte[] data)
        {
            var results = new List<AppCompatCacheEntry>();
            int cursor = 0;
            int entryIndex = 0;

            while (cursor + 24 <= data.Length)
            {
                // Look for "10ts"
                if (data[cursor] == 0x31 && data[cursor + 1] == 0x30 && data[cursor + 2] == 0x73 && data[cursor + 3] == 0x74)
                {
                    ushort pathLen = BitConverter.ToUInt16(data, cursor + 12);
                    if (pathLen > 4 && pathLen < 1024 && cursor + 14 + pathLen <= data.Length)
                    {
                        string path = Encoding.Unicode.GetString(data, cursor + 14, pathLen);
                        if (path.Contains("\\") && !path.Contains("\0"))
                        {
                            DateTime lastMod = DateTime.MinValue;
                            int timeOff = cursor + 14 + pathLen;
                            if (timeOff + 8 <= data.Length)
                            {
                                long ft = BitConverter.ToInt64(data, timeOff);
                                if (ft >= MinValidFileTime && ft <= MaxValidFileTime)
                                {
                                    try { lastMod = DateTime.FromFileTimeUtc(ft); } catch { }
                                }
                            }

                            results.Add(new AppCompatCacheEntry
                            {
                                EntryIndex = ++entryIndex,
                                Path = CleanPath(path),
                                LastModifiedTimeUtc = lastMod,
                                Executed = true
                            });
                        }
                    }
                }
                cursor += 2;
            }

            return results;
        }

        private static string CleanPath(string raw)
        {
            if (String.IsNullOrEmpty(raw)) return String.Empty;
            string p = raw.TrimEnd('\0').Trim();
            if (p.StartsWith("\\??\\")) p = p.Substring(4);
            return p;
        }
    }
}
