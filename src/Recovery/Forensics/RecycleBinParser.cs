using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    /// <summary>
    /// Represents a single deleted file artifact from Windows Recycle Bin ($Recycle.Bin / $I / $R).
    /// </summary>
    public sealed class RecycleBinEntry
    {
        public string IndexFileName { get; set; }
        public string DataFileName { get; set; }
        public string DataFilePath { get; set; }
        public bool HasDataFile { get; set; }
        public string OriginalFileName { get; set; }
        public string OriginalFilePath { get; set; }
        public string OriginalDirectory { get; set; }
        public long OriginalFileSize { get; set; }
        public long ActualDataFileSize { get; set; }
        public DateTime DeletionTimeUtc { get; set; }
        public string UserSid { get; set; }
        public int FormatVersion { get; set; }
        public bool IsSuspicious { get; set; }
        public string ThreatDescription { get; set; }
        public bool IsCarved { get; set; }

        public RecycleBinEntry()
        {
            IndexFileName = String.Empty;
            DataFileName = String.Empty;
            DataFilePath = String.Empty;
            OriginalFileName = String.Empty;
            OriginalFilePath = String.Empty;
            OriginalDirectory = String.Empty;
            UserSid = String.Empty;
            ThreatDescription = String.Empty;
        }
    }

    /// <summary>
    /// Forensic summary report for Windows Recycle Bin artifacts.
    /// </summary>
    public sealed class RecycleBinReport
    {
        public string SourcePath { get; set; }
        public int TotalRecords { get; set; }
        public long TotalBytesDeleted { get; set; }
        public int AvailablePayloads { get; set; }
        public int SuspiciousCount { get; set; }
        public List<RecycleBinEntry> Entries { get; set; }
        public List<string> Warnings { get; set; }

        public RecycleBinReport()
        {
            SourcePath = String.Empty;
            Entries = new List<RecycleBinEntry>();
            Warnings = new List<string>();
        }

        public string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"SourcePath\":\"{0}\",", EscapeJson(SourcePath));
            sb.AppendFormat("\"TotalRecords\":{0},", TotalRecords);
            sb.AppendFormat("\"TotalBytesDeleted\":{0},", TotalBytesDeleted);
            sb.AppendFormat("\"AvailablePayloads\":{0},", AvailablePayloads);
            sb.AppendFormat("\"SuspiciousCount\":{0},", SuspiciousCount);
            sb.Append("\"Entries\":[");
            for (int i = 0; i < Entries.Count; i++)
            {
                if (i > 0) sb.Append(",");
                var e = Entries[i];
                sb.Append("{");
                sb.AppendFormat("\"IndexFileName\":\"{0}\",", EscapeJson(e.IndexFileName));
                sb.AppendFormat("\"DataFileName\":\"{0}\",", EscapeJson(e.DataFileName));
                sb.AppendFormat("\"HasDataFile\":{0},", e.HasDataFile ? "true" : "false");
                sb.AppendFormat("\"OriginalFileName\":\"{0}\",", EscapeJson(e.OriginalFileName));
                sb.AppendFormat("\"OriginalFilePath\":\"{0}\",", EscapeJson(e.OriginalFilePath));
                sb.AppendFormat("\"OriginalDirectory\":\"{0}\",", EscapeJson(e.OriginalDirectory));
                sb.AppendFormat("\"OriginalFileSize\":{0},", e.OriginalFileSize);
                sb.AppendFormat("\"ActualDataFileSize\":{0},", e.ActualDataFileSize);
                sb.AppendFormat("\"DeletionTimeUtc\":\"{0:O}\",", e.DeletionTimeUtc);
                sb.AppendFormat("\"UserSid\":\"{0}\",", EscapeJson(e.UserSid));
                sb.AppendFormat("\"FormatVersion\":{0},", e.FormatVersion);
                sb.AppendFormat("\"IsSuspicious\":{0},", e.IsSuspicious ? "true" : "false");
                sb.AppendFormat("\"ThreatDescription\":\"{0}\",", EscapeJson(e.ThreatDescription));
                sb.AppendFormat("\"IsCarved\":{0}", e.IsCarved ? "true" : "false");
                sb.Append("}");
            }
            sb.Append("]");
            sb.Append("}");
            return sb.ToString();
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return String.Empty;
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }
    }

    /// <summary>
    /// Forensic parser for Windows Recycle Bin artifacts:
    /// - Windows Vista / 7 / 8 / 8.1 (Format Version 1: 544 bytes, fixed 260 WCHAR path)
    /// - Windows 10 / 11 (Format Version 2: variable length Unicode path)
    /// - Associating $I metadata with $R data payloads
    /// - Carving deleted $I records from unallocated space / slack
    /// - Restoring deleted files with their original filenames
    /// </summary>
    public static class RecycleBinParser
    {
        // 2006-01-01 FILETIME: ~127806528000000000L
        // 2035-01-01 FILETIME: ~136975200000000000L
        private const long MinValidFileTime = 127806528000000000L;
        private const long MaxValidFileTime = 136975200000000000L;

        /// <summary>
        /// Parse a single $I file, a $Recycle.Bin directory, or carve a raw byte buffer.
        /// </summary>
        public static RecycleBinReport Parse(string path)
        {
            if (path == null) throw new ArgumentNullException("path");

            var report = new RecycleBinReport { SourcePath = path };

            if (Directory.Exists(path))
            {
                return ParseDirectory(path);
            }

            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Recycle Bin target not found", path);
            }

            string fileName = Path.GetFileName(path);
            if (fileName.StartsWith("$I", StringComparison.OrdinalIgnoreCase))
            {
                byte[] data = File.ReadAllBytes(path);
                string dir = Path.GetDirectoryName(path);
                string userSid = ExtractSidFromPath(dir);
                var entry = ParseIndexBuffer(data, 0, data.Length, fileName, userSid);
                if (entry != null)
                {
                    // Check for matching $R payload
                    string suffix = fileName.Substring(2);
                    string dataFileName = "$R" + suffix;
                    string dataFilePath = Path.Combine(dir, dataFileName);
                    if (File.Exists(dataFilePath))
                    {
                        entry.DataFileName = dataFileName;
                        entry.DataFilePath = dataFilePath;
                        entry.HasDataFile = true;
                        try { entry.ActualDataFileSize = new FileInfo(dataFilePath).Length; } catch { }
                    }

                    EvaluateThreat(entry);
                    report.Entries.Add(entry);
                }
            }
            else
            {
                // Raw buffer carving
                byte[] data = File.ReadAllBytes(path);
                return Carve(data, path);
            }

            FinalizeReport(report);
            return report;
        }

        public static RecycleBinReport ParseDirectory(string directoryPath)
        {
            var report = new RecycleBinReport { SourcePath = directoryPath };

            try
            {
                var files = Directory.GetFiles(directoryPath, "$I*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    try
                    {
                        string fileName = Path.GetFileName(file);
                        string dir = Path.GetDirectoryName(file);
                        string userSid = ExtractSidFromPath(dir);

                        byte[] data = File.ReadAllBytes(file);
                        var entry = ParseIndexBuffer(data, 0, data.Length, fileName, userSid);
                        if (entry != null)
                        {
                            // Match with $R data payload
                            if (fileName.Length > 2)
                            {
                                string suffix = fileName.Substring(2);
                                string dataFileName = "$R" + suffix;
                                string dataFilePath = Path.Combine(dir, dataFileName);
                                if (File.Exists(dataFilePath))
                                {
                                    entry.DataFileName = dataFileName;
                                    entry.DataFilePath = dataFilePath;
                                    entry.HasDataFile = true;
                                    try { entry.ActualDataFileSize = new FileInfo(dataFilePath).Length; } catch { }
                                }
                            }

                            EvaluateThreat(entry);
                            report.Entries.Add(entry);
                        }
                    }
                    catch (Exception ex)
                    {
                        report.Warnings.Add("Failed to parse " + Path.GetFileName(file) + ": " + ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                report.Warnings.Add("Directory scan error: " + ex.Message);
            }

            FinalizeReport(report);
            return report;
        }

        public static RecycleBinReport ParseBuffer(byte[] buffer, string sourceName = null, string userSid = null)
        {
            if (buffer == null || buffer.Length < 28)
            {
                return new RecycleBinReport { SourcePath = sourceName ?? "Buffer" };
            }

            var entry = ParseIndexBuffer(buffer, 0, buffer.Length, sourceName ?? "$I_Buffer", userSid);
            if (entry != null)
            {
                var report = new RecycleBinReport { SourcePath = sourceName ?? "Buffer" };
                EvaluateThreat(entry);
                report.Entries.Add(entry);
                FinalizeReport(report);
                return report;
            }

            return Carve(buffer, sourceName);
        }

        /// <summary>
        /// Carves deleted $I index records from arbitrary unallocated disk space or memory dumps.
        /// </summary>
        public static RecycleBinReport Carve(byte[] buffer, string sourceName = null)
        {
            var report = new RecycleBinReport { SourcePath = sourceName ?? "Carved Buffer" };
            if (buffer == null || buffer.Length < 28) return report;

            int cursor = 0;
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while (cursor + 28 <= buffer.Length)
            {
                ulong version = BitConverter.ToUInt64(buffer, cursor);
                if (version == 1 && cursor + 544 <= buffer.Length)
                {
                    long ft = BitConverter.ToInt64(buffer, cursor + 16);
                    if (ft >= MinValidFileTime && ft <= MaxValidFileTime)
                    {
                        // Check if valid Unicode path at cursor + 24
                        if (IsUnicodePathAt(buffer, cursor + 24))
                        {
                            var entry = ParseIndexBuffer(buffer, cursor, 544, "$I_Carved_" + cursor, "S-1-5-Carved");
                            if (entry != null && !string.IsNullOrEmpty(entry.OriginalFilePath) && !seenPaths.Contains(entry.OriginalFilePath))
                            {
                                seenPaths.Add(entry.OriginalFilePath);
                                entry.IsCarved = true;
                                EvaluateThreat(entry);
                                report.Entries.Add(entry);
                                cursor += 544;
                                continue;
                            }
                        }
                    }
                }
                else if (version == 2 && cursor + 28 <= buffer.Length)
                {
                    long ft = BitConverter.ToInt64(buffer, cursor + 16);
                    if (ft >= MinValidFileTime && ft <= MaxValidFileTime)
                    {
                        uint charCount = BitConverter.ToUInt32(buffer, cursor + 24);
                        if (charCount > 0 && charCount < 1024 && cursor + 28 + (int)(charCount * 2) <= buffer.Length)
                        {
                            if (IsUnicodePathAt(buffer, cursor + 28))
                            {
                                int recLen = 28 + (int)(charCount * 2);
                                var entry = ParseIndexBuffer(buffer, cursor, recLen, "$I_Carved_" + cursor, "S-1-5-Carved");
                                if (entry != null && !string.IsNullOrEmpty(entry.OriginalFilePath) && !seenPaths.Contains(entry.OriginalFilePath))
                                {
                                    seenPaths.Add(entry.OriginalFilePath);
                                    entry.IsCarved = true;
                                    EvaluateThreat(entry);
                                    report.Entries.Add(entry);
                                    cursor += recLen;
                                    continue;
                                }
                            }
                        }
                    }
                }

                cursor += 4;
            }

            FinalizeReport(report);
            return report;
        }

        /// <summary>
        /// Parses a single $I buffer record.
        /// </summary>
        public static RecycleBinEntry ParseIndexBuffer(byte[] buffer, int offset, int length, string indexFileName = null, string userSid = null)
        {
            if (buffer == null || offset < 0 || length < 28 || offset + length > buffer.Length) return null;

            ulong version = BitConverter.ToUInt64(buffer, offset);
            long originalSize = BitConverter.ToInt64(buffer, offset + 8);
            long deletionFt = BitConverter.ToInt64(buffer, offset + 16);

            DateTime deletionUtc = DateTime.MinValue;
            try
            {
                if (deletionFt >= MinValidFileTime && deletionFt <= MaxValidFileTime)
                {
                    deletionUtc = DateTime.FromFileTimeUtc(deletionFt);
                }
            }
            catch { }

            string originalPath = String.Empty;

            if (version == 1)
            {
                // Windows Vista / 7 / 8 / 8.1 format: fixed 260 WCHARs (520 bytes) at offset 24
                int pathOffset = offset + 24;
                int maxBytes = Math.Min(520, length - 24);
                if (maxBytes >= 4)
                {
                    originalPath = ReadNullTerminatedUnicode(buffer, pathOffset, maxBytes / 2);
                }
            }
            else if (version == 2)
            {
                // Windows 10 / 11 format: uint32 char count at offset 24, followed by UTF-16LE characters
                uint charCount = BitConverter.ToUInt32(buffer, offset + 24);
                if (charCount > 0 && charCount < 16384)
                {
                    int pathOffset = offset + 28;
                    int availableChars = (length - 28) / 2;
                    int charsToRead = Math.Min((int)charCount, availableChars);
                    if (charsToRead > 0)
                    {
                        originalPath = Encoding.Unicode.GetString(buffer, pathOffset, charsToRead * 2).TrimEnd('\0');
                    }
                }
            }
            else
            {
                return null;
            }

            if (string.IsNullOrEmpty(originalPath)) return null;

            string originalFileName = Path.GetFileName(originalPath);
            string originalDir = Path.GetDirectoryName(originalPath) ?? String.Empty;

            var entry = new RecycleBinEntry
            {
                IndexFileName = indexFileName ?? String.Empty,
                OriginalFileName = originalFileName,
                OriginalFilePath = originalPath,
                OriginalDirectory = originalDir,
                OriginalFileSize = Math.Max(0, originalSize),
                DeletionTimeUtc = deletionUtc,
                UserSid = userSid ?? String.Empty,
                FormatVersion = (int)version
            };

            return entry;
        }

        /// <summary>
        /// Restore deleted file with its original filename and directory structure.
        /// </summary>
        public static bool RestoreFile(RecycleBinEntry entry, string destinationFolder, bool recreateSubdirectories = false)
        {
            if (entry == null || !entry.HasDataFile || string.IsNullOrEmpty(entry.DataFilePath) || !File.Exists(entry.DataFilePath))
            {
                return false;
            }

            try
            {
                string targetDir = destinationFolder;
                if (recreateSubdirectories && !string.IsNullOrEmpty(entry.OriginalDirectory))
                {
                    // Strip drive letter if present
                    string rel = entry.OriginalDirectory;
                    if (rel.Length >= 2 && rel[1] == ':') rel = rel.Substring(2);
                    rel = rel.TrimStart('\\', '/');
                    targetDir = Path.Combine(destinationFolder, rel);
                }

                if (!Directory.Exists(targetDir)) Directory.CreateDirectory(targetDir);

                string destPath = Path.Combine(targetDir, entry.OriginalFileName);
                File.Copy(entry.DataFilePath, destPath, true);

                if (entry.DeletionTimeUtc != DateTime.MinValue)
                {
                    try { File.SetLastWriteTimeUtc(destPath, entry.DeletionTimeUtc); } catch { }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        #region Helper Methods

        private static void FinalizeReport(RecycleBinReport report)
        {
            report.TotalRecords = report.Entries.Count;
            long totalBytes = 0;
            int payloads = 0;
            int suspicious = 0;

            foreach (var e in report.Entries)
            {
                totalBytes += e.OriginalFileSize;
                if (e.HasDataFile) payloads++;
                if (e.IsSuspicious) suspicious++;
            }

            report.TotalBytesDeleted = totalBytes;
            report.AvailablePayloads = payloads;
            report.SuspiciousCount = suspicious;
        }

        private static string ExtractSidFromPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return String.Empty;
            var match = Regex.Match(path, @"(S-1-5-21-\d+-\d+-\d+-\d+)", RegexOptions.IgnoreCase);
            if (match.Success) return match.Groups[1].Value;
            var match500 = Regex.Match(path, @"(S-1-5-\d+)", RegexOptions.IgnoreCase);
            if (match500.Success) return match500.Groups[1].Value;
            return String.Empty;
        }

        private static bool IsUnicodePathAt(byte[] buffer, int offset)
        {
            if (offset + 6 > buffer.Length) return false;
            if (char.IsLetter((char)buffer[offset]) && buffer[offset + 1] == 0 &&
                buffer[offset + 2] == ':' && buffer[offset + 3] == 0 &&
                (buffer[offset + 4] == '\\' || buffer[offset + 4] == '/') && buffer[offset + 5] == 0)
            {
                return true;
            }
            if (buffer[offset] == '\\' && buffer[offset + 1] == 0 &&
                buffer[offset + 2] == '\\' && buffer[offset + 3] == 0)
            {
                return true;
            }
            return false;
        }

        private static string ReadNullTerminatedUnicode(byte[] buffer, int offset, int maxChars)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < maxChars && offset + (i * 2) + 1 < buffer.Length; i++)
            {
                char c = (char)BitConverter.ToUInt16(buffer, offset + (i * 2));
                if (c == '\0') break;
                sb.Append(c);
            }
            return sb.ToString();
        }

        public static void EvaluateThreat(RecycleBinEntry entry)
        {
            if (entry == null || string.IsNullOrEmpty(entry.OriginalFilePath)) return;

            string path = entry.OriginalFilePath.ToLowerInvariant();
            var reasons = new List<string>();

            // 1. Temporary, Downloads, or Public execution locations
            bool inTemp = path.Contains(@"\appdata\local\temp\") || path.Contains(@"\windows\temp\") || path.Contains(@"\temp\");
            bool inDownloads = path.Contains(@"\downloads\");
            bool inPublic = path.Contains(@"\users\public\");

            // 2. High-risk extensions
            bool isScript = path.EndsWith(".bat") || path.EndsWith(".cmd") || path.EndsWith(".ps1") ||
                            path.EndsWith(".vbs") || path.EndsWith(".vbe") || path.EndsWith(".js") ||
                            path.EndsWith(".wsf") || path.EndsWith(".hta");

            bool isExecutable = path.EndsWith(".exe") || path.EndsWith(".scr") || path.EndsWith(".pif") ||
                               path.EndsWith(".com") || path.EndsWith(".cpl") || path.EndsWith(".dll") || path.EndsWith(".sys");

            if (inTemp && (isExecutable || isScript))
            {
                reasons.Add("Executable/script deleted from Temporary directory (malware self-deletion)");
            }

            if (inDownloads && (isExecutable || isScript))
            {
                reasons.Add("Executable/script deleted from Downloads folder");
            }

            if (inPublic && (isExecutable || isScript))
            {
                reasons.Add("Executable/script deleted from Users\\Public");
            }

            // 3. Masquerading double extension
            if (Regex.IsMatch(path, @"\.(pdf|docx?|xlsx?|pptx?|jpg|png|txt|rtf|csv)\.(exe|scr|pif|cmd|bat|vbs|ps1|js|hta)$"))
            {
                reasons.Add("Masquerading double extension deleted");
            }

            // 4. Anti-forensics tampering: File wiping / zeroing before deletion
            if (entry.HasDataFile && entry.OriginalFileSize > 4096 && entry.ActualDataFileSize == 0)
            {
                reasons.Add("Anti-forensics zero-truncation (Original size: " + entry.OriginalFileSize + " B, Payload size: 0 B)");
            }

            // 5. Sensitive evidence destruction (Logs, Wallets, SAM)
            if (path.EndsWith(".evtx") || path.EndsWith(".log") || path.EndsWith("wallet.dat") || path.Contains(@"\system32\config\sam"))
            {
                reasons.Add("Evidence destruction: security log, database, or credentials file deleted");
            }

            if (reasons.Count > 0)
            {
                entry.IsSuspicious = true;
                entry.ThreatDescription = string.Join("; ", reasons.ToArray());
            }
        }

        #endregion
    }
}
