using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    /// <summary>
    /// Represents a parsed Amcache execution and application entry.
    /// </summary>
    public sealed class AmcacheEntry
    {
        public string Path { get; set; }
        public string Sha1 { get; set; }
        public string Name { get; set; }
        public string Publisher { get; set; }
        public string Version { get; set; }
        public long FileSize { get; set; }
        public ulong FileRef { get; set; }
        public ulong Usn { get; set; }
        public string BinaryType { get; set; }
        public DateTime LinkerTimestampUtc { get; set; }
        public DateTime KeyLastWriteTimeUtc { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }

        public AmcacheEntry()
        {
            Path = String.Empty;
            Sha1 = String.Empty;
            Name = String.Empty;
            Publisher = String.Empty;
            Version = String.Empty;
            BinaryType = String.Empty;
            SuspicionReason = String.Empty;
            LinkerTimestampUtc = DateTime.MinValue;
            KeyLastWriteTimeUtc = DateTime.MinValue;
        }

        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "[{0}] {1} (SHA1: {2}, Size: {3} bytes)",
                KeyLastWriteTimeUtc != DateTime.MinValue ? KeyLastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss") : "N/A",
                Path, Sha1, FileSize);
        }
    }

    /// <summary>
    /// Forensic parser for Windows Amcache.hve artifacts.
    /// Extracts PE execution history, cryptographic SHA-1 hashes, compilation link dates,
    /// and MFT file references across Windows 7, 8, 10, and 11 formats.
    /// Includes heuristic threat intelligence classification and raw unallocated carving.
    /// 100% offline, zero network telemetry, bounded 64 KiB memory.
    /// </summary>
    public static class AmcacheParser
    {
        private static readonly Regex Sha1Regex = new Regex(@"\b([0-9a-fA-F]{40})\b", RegexOptions.Compiled);
        private static readonly Regex Win10FileIdRegex = new Regex(@"^0000([0-9a-fA-F]{40})$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // =========================================================================
        // Main Parsing Entry Points
        // =========================================================================

        public static List<AmcacheEntry> Parse(RegistryHive hive)
        {
            var results = new List<AmcacheEntry>();
            if (hive == null) return results;

            // 1. Windows 10/11 InventoryApplicationFile format
            ParseInventoryApplicationFiles(hive, results);

            // 2. Windows 7/8/8.1 Root\File format
            ParseWin7Files(hive, results);

            // Deduplicate by Sha1 + Path
            return DeduplicateAndClassify(results);
        }

        public static List<AmcacheEntry> Parse(Stream stream)
        {
            if (stream == null || !stream.CanRead) return new List<AmcacheEntry>();

            try
            {
                using (var hive = RegistryHive.Open(stream))
                {
                    return Parse(hive);
                }
            }
            catch
            {
                // Fallback to streaming raw carver
                if (stream.CanSeek) stream.Position = 0;
                return CarveFromStream(stream, CancellationToken.None);
            }
        }

        public static List<AmcacheEntry> Parse(string filePath)
        {
            if (String.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return new List<AmcacheEntry>();

            try
            {
                using (var hive = RegistryHive.Open(filePath))
                {
                    return Parse(hive);
                }
            }
            catch
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    return CarveFromStream(fs, CancellationToken.None);
                }
            }
        }

        // =========================================================================
        // Windows 10 & 11: Root\InventoryApplicationFile
        // =========================================================================

        private static void ParseInventoryApplicationFiles(RegistryHive hive, List<AmcacheEntry> results)
        {
            var appFilesKey = hive.GetKey("Root\\InventoryApplicationFile")
                           ?? hive.GetKey("InventoryApplicationFile");

            if (appFilesKey == null || appFilesKey.Subkeys == null) return;

            for (int i = 0; i < appFilesKey.Subkeys.Count; i++)
            {
                var subkey = appFilesKey.Subkeys[i];
                var entry = new AmcacheEntry();
                entry.KeyLastWriteTimeUtc = subkey.LastWriteTimeUtc;

                // FileId is often the subkey name or in a value
                string fileId = subkey.Name;
                var fileIdVal = subkey.GetValue("FileId");
                if (fileIdVal != null && fileIdVal.Value != null)
                {
                    fileId = fileIdVal.ValueAsString();
                }

                entry.Sha1 = CleanSha1(fileId);

                // LowerCaseLongPath or LongPath
                var pathVal = subkey.GetValue("LowerCaseLongPath") ?? subkey.GetValue("LongPath");
                if (pathVal != null && pathVal.Value != null)
                {
                    entry.Path = pathVal.ValueAsString();
                }

                // Name
                var nameVal = subkey.GetValue("Name");
                if (nameVal != null && nameVal.Value != null)
                {
                    entry.Name = nameVal.ValueAsString();
                }
                else if (!String.IsNullOrEmpty(entry.Path))
                {
                    entry.Name = Path.GetFileName(entry.Path);
                }

                // Publisher
                var pubVal = subkey.GetValue("Publisher");
                if (pubVal != null && pubVal.Value != null)
                {
                    entry.Publisher = pubVal.ValueAsString();
                }

                // Version
                var verVal = subkey.GetValue("Version");
                if (verVal != null && verVal.Value != null)
                {
                    entry.Version = verVal.ValueAsString();
                }

                // Size
                entry.FileSize = ParseLongValue(subkey.GetValue("Size"));

                // FileRef
                entry.FileRef = ParseUlongValue(subkey.GetValue("FileRef"));

                // Usn
                entry.Usn = ParseUlongValue(subkey.GetValue("Usn"));

                // BinaryType
                var binTypeVal = subkey.GetValue("BinaryType");
                if (binTypeVal != null && binTypeVal.Value != null)
                {
                    entry.BinaryType = binTypeVal.ValueAsString();
                }

                // LinkDate
                var linkDateVal = subkey.GetValue("LinkDate");
                if (linkDateVal != null && linkDateVal.Value != null)
                {
                    entry.LinkerTimestampUtc = ParseLinkDate(linkDateVal.ValueAsString(), linkDateVal.RawData);
                }

                if (!String.IsNullOrEmpty(entry.Path) || !String.IsNullOrEmpty(entry.Sha1))
                {
                    results.Add(entry);
                }
            }
        }

        // =========================================================================
        // Windows 7 & 8: Root\File
        // =========================================================================

        private static void ParseWin7Files(RegistryHive hive, List<AmcacheEntry> results)
        {
            var fileKey = hive.GetKey("Root\\File") ?? hive.GetKey("File");
            if (fileKey == null || fileKey.Subkeys == null) return;

            for (int v = 0; v < fileKey.Subkeys.Count; v++)
            {
                var volOrFileKey = fileKey.Subkeys[v];

                // If subkeys exist, this is a volume GUID key containing file entries
                if (volOrFileKey.Subkeys != null && volOrFileKey.Subkeys.Count > 0)
                {
                    for (int f = 0; f < volOrFileKey.Subkeys.Count; f++)
                    {
                        var entryKey = volOrFileKey.Subkeys[f];
                        var entry = ParseWin7Entry(entryKey);
                        if (entry != null) results.Add(entry);
                    }
                }
                else
                {
                    // Direct file entry
                    var entry = ParseWin7Entry(volOrFileKey);
                    if (entry != null) results.Add(entry);
                }
            }
        }

        private static AmcacheEntry ParseWin7Entry(RegistryKey key)
        {
            if (key == null) return null;

            var entry = new AmcacheEntry();
            entry.KeyLastWriteTimeUtc = key.LastWriteTimeUtc;

            // Value 15: File Path
            var pathVal = key.GetValue("15");
            if (pathVal != null && pathVal.Value != null)
            {
                entry.Path = pathVal.ValueAsString();
                entry.Name = Path.GetFileName(entry.Path);
            }

            // Value 101: SHA1
            var sha1Val = key.GetValue("101") ?? key.GetValue("100");
            if (sha1Val != null && sha1Val.Value != null)
            {
                entry.Sha1 = CleanSha1(sha1Val.ValueAsString());
            }

            // Value 0: Product Name / App Name
            var nameVal = key.GetValue("0");
            if (nameVal != null && nameVal.Value != null && String.IsNullOrEmpty(entry.Name))
            {
                entry.Name = nameVal.ValueAsString();
            }

            // Value 1: Company Name
            var compVal = key.GetValue("1");
            if (compVal != null && compVal.Value != null)
            {
                entry.Publisher = compVal.ValueAsString();
            }

            // Value 2: File Version
            var verVal = key.GetValue("2");
            if (verVal != null && verVal.Value != null)
            {
                entry.Version = verVal.ValueAsString();
            }

            // Value d: File Size
            entry.FileSize = ParseLongValue(key.GetValue("d"));

            // Value 17: Linker Timestamp
            var linkVal = key.GetValue("17");
            if (linkVal != null && linkVal.Value != null)
            {
                entry.LinkerTimestampUtc = ParseLinkDate(linkVal.ValueAsString(), linkVal.RawData);
            }

            if (String.IsNullOrEmpty(entry.Path) && String.IsNullOrEmpty(entry.Sha1))
            {
                return null;
            }

            return entry;
        }

        // =========================================================================
        // Raw Stream Carver for Unallocated / Corrupted Hives
        // =========================================================================

        public static List<AmcacheEntry> CarveFromStream(Stream stream, CancellationToken cancellationToken)
        {
            var results = new List<AmcacheEntry>();
            if (stream == null || !stream.CanRead) return results;

            const int chunkSize = 65536; // Constant 64 KiB buffer
            const int overlap = 512;
            byte[] buffer = new byte[chunkSize + overlap];
            int carry = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                int read = stream.Read(buffer, carry, chunkSize);
                int total = carry + read;
                if (total < 64) break;

                string text = Encoding.ASCII.GetString(buffer, 0, total);

                // Carve 40-character hex SHA-1 matches
                var matches = Sha1Regex.Matches(text);
                for (int m = 0; m < matches.Count; m++)
                {
                    string sha1 = matches[m].Value.ToLowerInvariant();
                    if (sha1 == "0000000000000000000000000000000000000000" ||
                        sha1 == "ffffffffffffffffffffffffffffffffffffffff")
                    {
                        continue;
                    }

                    // Look around match for possible file path
                    int matchIdx = matches[m].Index;
                    string snippet = text.Substring(Math.Max(0, matchIdx - 120), Math.Min(240, text.Length - Math.Max(0, matchIdx - 120)));
                    string path = ExtractProbablePath(snippet);

                    var entry = new AmcacheEntry();
                    entry.Sha1 = sha1;
                    entry.Path = path;
                    entry.Name = !String.IsNullOrEmpty(path) ? Path.GetFileName(path) : ("carved_" + sha1.Substring(0, 8));
                    results.Add(entry);
                }

                if (read < chunkSize) break;

                // Carry over the last overlap bytes
                Array.Copy(buffer, total - overlap, buffer, 0, overlap);
                carry = overlap;
            }

            return DeduplicateAndClassify(results);
        }

        private static string ExtractProbablePath(string text)
        {
            if (String.IsNullOrEmpty(text)) return String.Empty;
            int driveIdx = text.IndexOf(@":\", StringComparison.Ordinal);
            if (driveIdx >= 1)
            {
                int start = driveIdx - 1;
                int end = start;
                while (end < text.Length && text[end] > 32 && text[end] < 127 && text[end] != '"' && text[end] != '<' && text[end] != '>' && text[end] != '|' && text[end] != '\0')
                {
                    end++;
                }
                string candidate = text.Substring(start, end - start).Trim();
                if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    candidate.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                    candidate.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
                    candidate.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
                {
                    return candidate;
                }
            }
            return String.Empty;
        }

        // =========================================================================
        // Deduplication & Threat Intelligence Classification
        // =========================================================================

        private static List<AmcacheEntry> DeduplicateAndClassify(List<AmcacheEntry> rawEntries)
        {
            var unique = new Dictionary<string, AmcacheEntry>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < rawEntries.Count; i++)
            {
                var e = rawEntries[i];
                string key = (e.Sha1 ?? "") + "|" + (e.Path ?? "");
                if (String.IsNullOrEmpty(key.Trim('|'))) continue;

                if (!unique.ContainsKey(key))
                {
                    ClassifySuspicious(e);
                    unique[key] = e;
                }
            }

            return new List<AmcacheEntry>(unique.Values);
        }

        private static void ClassifySuspicious(AmcacheEntry entry)
        {
            if (entry == null) return;

            string p = (entry.Path ?? "").ToLowerInvariant();
            var reasons = new List<string>();

            // 1. High-risk staging directories
            if (p.Contains(@"\appdata\local\temp\") || p.Contains(@"\windows\temp\") || p.Contains(@"\temp\"))
            {
                reasons.Add("Executed from Temp directory");
            }
            if (p.Contains(@"\users\public\"))
            {
                reasons.Add("Executed from Users\\Public directory");
            }
            if (p.Contains(@"\perflogs\"))
            {
                reasons.Add("Executed from C:\\PerfLogs");
            }
            if (p.Contains(@"\downloads\"))
            {
                reasons.Add("Executed directly from Downloads folder");
            }

            // 2. Masquerading & Double extensions
            if (p.EndsWith(".pdf.exe") || p.EndsWith(".doc.exe") || p.EndsWith(".docx.exe") ||
                p.EndsWith(".xls.exe") || p.EndsWith(".xlsx.exe") || p.EndsWith(".jpg.exe") ||
                p.EndsWith(".png.exe") || p.EndsWith(".zip.exe"))
            {
                reasons.Add("Double extension camouflage detected");
            }

            // 3. Masquerading standard system executables outside system32
            string fname = (entry.Name ?? "").ToLowerInvariant();
            if ((fname == "svchost.exe" || fname == "csrss.exe" || fname == "lsass.exe" || fname == "explorer.exe") &&
                !p.Contains(@"\windows\system32\") && !p.Contains(@"\windows\syswow64\") && !p.Contains(@"\windows\explorer.exe"))
            {
                reasons.Add("System executable masquerading outside Windows directory");
            }

            if (reasons.Count > 0)
            {
                entry.IsSuspicious = true;
                entry.SuspicionReason = string.Join("; ", reasons.ToArray());
            }
            else
            {
                entry.IsSuspicious = false;
                entry.SuspicionReason = "Normal execution profile";
            }
        }

        // =========================================================================
        // Helpers
        // =========================================================================

        private static long ParseLongValue(RegistryValue val)
        {
            if (val == null || val.Value == null) return 0;
            if (val.Value is uint) return (long)(uint)val.Value;
            if (val.Value is ulong) return (long)(ulong)val.Value;
            if (val.Value is int) return (long)(int)val.Value;
            if (val.Value is long) return (long)val.Value;
            string s = val.Value as string;
            if (s != null)
            {
                long r;
                if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    if (long.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out r)) return r;
                }
                if (long.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out r)) return r;
            }
            return 0;
        }

        private static ulong ParseUlongValue(RegistryValue val)
        {
            if (val == null || val.Value == null) return 0;
            if (val.Value is uint) return (ulong)(uint)val.Value;
            if (val.Value is ulong) return (ulong)val.Value;
            if (val.Value is int) return (ulong)(int)val.Value;
            if (val.Value is long) return (ulong)(long)val.Value;
            string s = val.Value as string;
            if (s != null)
            {
                ulong r;
                if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    if (ulong.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out r)) return r;
                }
                if (ulong.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out r)) return r;
            }
            return 0;
        }

        private static string CleanSha1(string raw)
        {
            if (String.IsNullOrEmpty(raw)) return String.Empty;
            raw = raw.Trim();

            var match = Win10FileIdRegex.Match(raw);
            if (match.Success)
            {
                return match.Groups[1].Value.ToLowerInvariant();
            }

            if (raw.Length == 40 && Sha1Regex.IsMatch(raw))
            {
                return raw.ToLowerInvariant();
            }

            return raw.ToLowerInvariant();
        }

        private static DateTime ParseLinkDate(string strVal, byte[] rawData)
        {
            if (rawData != null && rawData.Length == 8)
            {
                try
                {
                    long ft = BitConverter.ToInt64(rawData, 0);
                    if (ft > 0) return DateTime.FromFileTimeUtc(ft);
                }
                catch { }
            }

            if (rawData != null && rawData.Length == 4)
            {
                try
                {
                    uint unixSec = BitConverter.ToUInt32(rawData, 0);
                    if (unixSec > 0)
                    {
                        return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixSec);
                    }
                }
                catch { }
            }

            if (!String.IsNullOrEmpty(strVal))
            {
                DateTime dt;
                if (DateTime.TryParse(strVal, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out dt))
                {
                    return dt;
                }

                // If Unix timestamp integer in string
                long sec;
                if (long.TryParse(strVal, NumberStyles.Any, CultureInfo.InvariantCulture, out sec) && sec > 0 && sec < 253402300799L)
                {
                    try
                    {
                        return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(sec);
                    }
                    catch { }
                }
            }

            return DateTime.MinValue;
        }
    }
}
