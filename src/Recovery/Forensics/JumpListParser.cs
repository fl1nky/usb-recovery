using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    /// <summary>
    /// Represents a single artifact entry extracted from a Windows Jump List
    /// (.automaticDestinations-ms or .customDestinations-ms).
    /// </summary>
    public sealed class JumpListEntry
    {
        public string AppId { get; set; }
        public string AppName { get; set; }
        public int EntryId { get; set; }
        public string TargetPath { get; set; }
        public int AccessCount { get; set; }
        public DateTime LastAccessUtc { get; set; }
        public string PinStatus { get; set; }
        public string NetBiosName { get; set; }
        public Guid VolumeDroid { get; set; }
        public Guid FileDroid { get; set; }
        public Guid BirthVolumeDroid { get; set; }
        public Guid BirthFileDroid { get; set; }
        public long TargetFileSize { get; set; }
        public DateTime TargetCreationUtc { get; set; }
        public DateTime TargetWriteUtc { get; set; }
        public string DriveType { get; set; }
        public string VolumeSerialNumber { get; set; }
        public string VolumeLabel { get; set; }
        public string MachineId { get; set; }
        public string MacAddress { get; set; }
        public string Arguments { get; set; }
        public string Category { get; set; }
        public bool IsSuspicious { get; set; }
        public string ThreatDescription { get; set; }
        public bool IsCarved { get; set; }

        public JumpListEntry()
        {
            AppId = String.Empty;
            AppName = String.Empty;
            TargetPath = String.Empty;
            PinStatus = "Unpinned";
            NetBiosName = String.Empty;
            DriveType = String.Empty;
            VolumeSerialNumber = String.Empty;
            VolumeLabel = String.Empty;
            MachineId = String.Empty;
            MacAddress = String.Empty;
            Arguments = String.Empty;
            Category = "AutomaticDestinations";
            ThreatDescription = String.Empty;
        }
    }

    /// <summary>
    /// Summary report of parsed Jump List artifacts.
    /// </summary>
    public sealed class JumpListReport
    {
        public string SourcePath { get; set; }
        public string FileType { get; set; }
        public string AppId { get; set; }
        public string AppName { get; set; }
        public int TotalEntries { get; set; }
        public int PinnedCount { get; set; }
        public int SuspiciousCount { get; set; }
        public List<JumpListEntry> Entries { get; set; }
        public List<string> Warnings { get; set; }

        public JumpListReport()
        {
            SourcePath = String.Empty;
            FileType = "Unknown";
            AppId = String.Empty;
            AppName = String.Empty;
            Entries = new List<JumpListEntry>();
            Warnings = new List<string>();
        }

        public string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"SourcePath\":\"{0}\",", EscapeJson(SourcePath));
            sb.AppendFormat("\"FileType\":\"{0}\",", EscapeJson(FileType));
            sb.AppendFormat("\"AppId\":\"{0}\",", EscapeJson(AppId));
            sb.AppendFormat("\"AppName\":\"{0}\",", EscapeJson(AppName));
            sb.AppendFormat("\"TotalEntries\":{0},", TotalEntries);
            sb.AppendFormat("\"PinnedCount\":{0},", PinnedCount);
            sb.AppendFormat("\"SuspiciousCount\":{0},", SuspiciousCount);
            sb.Append("\"Entries\":[");
            for (int i = 0; i < Entries.Count; i++)
            {
                if (i > 0) sb.Append(",");
                var e = Entries[i];
                sb.Append("{");
                sb.AppendFormat("\"AppId\":\"{0}\",", EscapeJson(e.AppId));
                sb.AppendFormat("\"AppName\":\"{0}\",", EscapeJson(e.AppName));
                sb.AppendFormat("\"EntryId\":{0},", e.EntryId);
                sb.AppendFormat("\"TargetPath\":\"{0}\",", EscapeJson(e.TargetPath));
                sb.AppendFormat("\"AccessCount\":{0},", e.AccessCount);
                sb.AppendFormat("\"LastAccessUtc\":\"{0:O}\",", e.LastAccessUtc);
                sb.AppendFormat("\"PinStatus\":\"{0}\",", EscapeJson(e.PinStatus));
                sb.AppendFormat("\"NetBiosName\":\"{0}\",", EscapeJson(e.NetBiosName));
                sb.AppendFormat("\"VolumeDroid\":\"{0}\",", e.VolumeDroid);
                sb.AppendFormat("\"FileDroid\":\"{0}\",", e.FileDroid);
                sb.AppendFormat("\"TargetFileSize\":{0},", e.TargetFileSize);
                sb.AppendFormat("\"TargetCreationUtc\":\"{0:O}\",", e.TargetCreationUtc);
                sb.AppendFormat("\"TargetWriteUtc\":\"{0:O}\",", e.TargetWriteUtc);
                sb.AppendFormat("\"DriveType\":\"{0}\",", EscapeJson(e.DriveType));
                sb.AppendFormat("\"VolumeSerialNumber\":\"{0}\",", EscapeJson(e.VolumeSerialNumber));
                sb.AppendFormat("\"VolumeLabel\":\"{0}\",", EscapeJson(e.VolumeLabel));
                sb.AppendFormat("\"MachineId\":\"{0}\",", EscapeJson(e.MachineId));
                sb.AppendFormat("\"MacAddress\":\"{0}\",", EscapeJson(e.MacAddress));
                sb.AppendFormat("\"Arguments\":\"{0}\",", EscapeJson(e.Arguments));
                sb.AppendFormat("\"Category\":\"{0}\",", EscapeJson(e.Category));
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
    /// Forensic parser for Windows Jump Lists:
    /// - AutomaticDestinations (*.automaticDestinations-ms in CFBF/OLE compound format)
    /// - CustomDestinations (*.customDestinations-ms with categories and sequential LNK streams)
    /// - Deep Carving of damaged or unallocated Jump List streams
    /// </summary>
    public static class JumpListParser
    {
        private static readonly byte[] CfbfMagic = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
        private static readonly byte[] LnkMagic = new byte[] { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };

        private static readonly Dictionary<string, string> KnownAppIds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "1b4dd67f29cb1962", "Windows Explorer (Recent Documents)" },
            { "f015240351311529", "Windows Explorer (Frequent Folders)" },
            { "9839aec31243a928", "Microsoft Word 2016/2019/365" },
            { "adecfb853d77462a", "Microsoft Word 2013" },
            { "fb3b0dbfee58fac8", "Microsoft Word 2010" },
            { "23646679aacc8eab", "Microsoft Excel 2016/2019/365" },
            { "918e0ecb43d17e23", "Windows Notepad" },
            { "a7bd71699e144a13", "Notepad++ / Visual Studio Code" },
            { "5d696d521de238c3", "Command Prompt (cmd.exe)" },
            { "cdf30b95c55fd78d", "Windows PowerShell" },
            { "12dc1ea8e34b5a34", "Google Chrome" },
            { "9b9cdc69c1c12404", "Mozilla Firefox" },
            { "28c8b86deab549a1", "Internet Explorer / Microsoft Edge" },
            { "7e4dca80246863e3", "Windows Paint (mspaint.exe)" },
            { "d00655d2aa12bc6d", "Windows Media Player" },
            { "c705141973cf9704", "Microsoft WordPad" },
            { "854e4ae677e1ab27", "Remote Desktop Connection (mstsc.exe)" },
            { "904e5782782b2d64", "VLC Media Player" },
            { "7458cd1716386629", "7-Zip File Manager" },
            { "4a8f9e61234b6e51", "Adobe Acrobat Reader" },
            { "50df580ec187a9",   "WinRAR Archiver" },
            { "d690a4269d03c621", "PuTTY SSH Client" },
            { "b5a61d8481ff7188", "Git Bash / MinTTY" },
            { "7d5668b8e01087ff", "Windows Subsystem for Linux (WSL)" },
            { "2bb92bbd29c8e104", "Microsoft PowerPoint 2016/2019/365" }
        };

        public static string ResolveAppName(string appId)
        {
            if (string.IsNullOrEmpty(appId)) return "Unknown Application";
            string name;
            if (KnownAppIds.TryGetValue(appId.Trim().ToLowerInvariant(), out name))
            {
                return name;
            }
            return "Application (" + appId + ")";
        }

        /// <summary>
        /// Parse a Jump List file, directory of Jump Lists, or stream.
        /// </summary>
        public static JumpListReport Parse(string path)
        {
            if (path == null) throw new ArgumentNullException("path");

            var report = new JumpListReport { SourcePath = path };

            if (Directory.Exists(path))
            {
                return ParseDirectory(path);
            }

            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Jump list file or directory not found", path);
            }

            byte[] buffer = File.ReadAllBytes(path);
            string fileName = Path.GetFileName(path);
            string appId = ExtractAppIdFromFileName(fileName);
            report.AppId = appId;
            report.AppName = ResolveAppName(appId);

            return Parse(buffer, path, appId);
        }

        public static JumpListReport Parse(byte[] buffer, string sourcePath = null, string explicitAppId = null)
        {
            if (buffer == null || buffer.Length == 0)
            {
                return new JumpListReport { SourcePath = sourcePath ?? "Buffer" };
            }

            string appId = explicitAppId;
            if (string.IsNullOrEmpty(appId) && !string.IsNullOrEmpty(sourcePath))
            {
                appId = ExtractAppIdFromFileName(Path.GetFileName(sourcePath));
            }

            // Check for CFBF (AutomaticDestinations)
            if (IsCfbf(buffer))
            {
                var report = ParseAutomaticDestinations(buffer, appId);
                report.SourcePath = sourcePath ?? "AutomaticDestinations";
                return report;
            }

            // Check for CustomDestinations
            if (sourcePath != null && sourcePath.IndexOf(".customDestinations-ms", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var report = ParseCustomDestinations(buffer, appId);
                report.SourcePath = sourcePath;
                return report;
            }

            // If buffer contains LNK or DestList signatures, carve it
            return CarveJumpLists(buffer, sourcePath, appId);
        }

        public static JumpListReport ParseDirectory(string directoryPath)
        {
            var combinedReport = new JumpListReport
            {
                SourcePath = directoryPath,
                FileType = "JumpList Directory"
            };

            var files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                string ext = Path.GetExtension(file);
                if (string.Equals(ext, ".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(ext, ".customDestinations-ms", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var rep = Parse(file);
                        if (rep != null && rep.Entries != null)
                        {
                            combinedReport.Entries.AddRange(rep.Entries);
                        }
                    }
                    catch (Exception ex)
                    {
                        combinedReport.Warnings.Add("Failed to parse " + Path.GetFileName(file) + ": " + ex.Message);
                    }
                }
            }

            combinedReport.TotalEntries = combinedReport.Entries.Count;
            int pinned = 0;
            int suspicious = 0;
            foreach (var e in combinedReport.Entries)
            {
                if (e.PinStatus == "Pinned") pinned++;
                if (e.IsSuspicious) suspicious++;
            }
            combinedReport.PinnedCount = pinned;
            combinedReport.SuspiciousCount = suspicious;

            return combinedReport;
        }

        private static bool IsCfbf(byte[] buffer)
        {
            if (buffer == null || buffer.Length < 512) return false;
            for (int i = 0; i < 8; i++)
            {
                if (buffer[i] != CfbfMagic[i]) return false;
            }
            return true;
        }

        private static string ExtractAppIdFromFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return String.Empty;
            int dot = fileName.IndexOf('.');
            if (dot > 0)
            {
                return fileName.Substring(0, dot).Trim().ToLowerInvariant();
            }
            return fileName.Trim().ToLowerInvariant();
        }

        #region AutomaticDestinations (CFBF) Parser

        private sealed class CfbfDirectoryEntry
        {
            public string Name { get; set; }
            public byte ObjectType { get; set; }
            public uint StartingSector { get; set; }
            public ulong StreamSize { get; set; }
            public DateTime CreationTimeUtc { get; set; }
            public DateTime ModificationTimeUtc { get; set; }
        }

        public static JumpListReport ParseAutomaticDestinations(byte[] buffer, string appId)
        {
            var report = new JumpListReport
            {
                FileType = "AutomaticDestinations (CFBF)",
                AppId = appId ?? String.Empty,
                AppName = ResolveAppName(appId)
            };

            if (buffer.Length < 512)
            {
                report.Warnings.Add("Buffer smaller than CFBF header");
                return report;
            }

            try
            {
                ushort sectorShift = BitConverter.ToUInt16(buffer, 30);
                int sectorSize = 1 << sectorShift;
                if (sectorSize < 512 || sectorSize > 65536) sectorSize = 512;

                ushort miniSectorShift = BitConverter.ToUInt16(buffer, 32);
                int miniSectorSize = 1 << miniSectorShift;
                if (miniSectorSize < 16 || miniSectorSize > 4096) miniSectorSize = 64;

                uint numFatSectors = BitConverter.ToUInt32(buffer, 44);
                uint firstDirSector = BitConverter.ToUInt32(buffer, 48);
                uint miniStreamCutoff = BitConverter.ToUInt32(buffer, 56);
                if (miniStreamCutoff == 0) miniStreamCutoff = 4096;

                uint firstMiniFatSector = BitConverter.ToUInt32(buffer, 60);
                uint numMiniFatSectors = BitConverter.ToUInt32(buffer, 64);

                // Build FAT
                List<uint> fat = BuildFat(buffer, sectorSize, numFatSectors);

                // Read Directory Entries
                List<CfbfDirectoryEntry> dirEntries = ReadDirectoryEntries(buffer, sectorSize, fat, firstDirSector);

                // Find Root Storage Entry (ObjectType == 5)
                CfbfDirectoryEntry rootEntry = null;
                CfbfDirectoryEntry destListEntry = null;
                Dictionary<string, CfbfDirectoryEntry> numberedStreams = new Dictionary<string, CfbfDirectoryEntry>(StringComparer.OrdinalIgnoreCase);

                foreach (var de in dirEntries)
                {
                    if (de.ObjectType == 5 && rootEntry == null)
                    {
                        rootEntry = de;
                    }
                    else if (string.Equals(de.Name, "DestList", StringComparison.OrdinalIgnoreCase))
                    {
                        destListEntry = de;
                    }
                    else if (de.ObjectType == 2)
                    {
                        numberedStreams[de.Name] = de;
                    }
                }

                // Read Mini Stream Container and Mini-FAT if present
                byte[] miniStreamContainer = null;
                List<uint> miniFat = null;
                if (rootEntry != null && rootEntry.StreamSize > 0)
                {
                    miniStreamContainer = ReadStreamBytes(buffer, sectorSize, fat, rootEntry.StartingSector, (long)rootEntry.StreamSize);
                    if (numMiniFatSectors > 0 && firstMiniFatSector < 0xFFFFFFFD)
                    {
                        byte[] miniFatBytes = ReadStreamBytes(buffer, sectorSize, fat, firstMiniFatSector, (long)(numMiniFatSectors * sectorSize));
                        miniFat = new List<uint>();
                        for (int i = 0; i + 4 <= miniFatBytes.Length; i += 4)
                        {
                            miniFat.Add(BitConverter.ToUInt32(miniFatBytes, i));
                        }
                    }
                }

                // Read DestList stream
                byte[] destListBytes = null;
                if (destListEntry != null)
                {
                    if (destListEntry.StreamSize < miniStreamCutoff && miniStreamContainer != null && miniFat != null)
                    {
                        destListBytes = ReadMiniStreamBytes(miniStreamContainer, miniSectorSize, miniFat, destListEntry.StartingSector, (long)destListEntry.StreamSize);
                    }
                    else
                    {
                        destListBytes = ReadStreamBytes(buffer, sectorSize, fat, destListEntry.StartingSector, (long)destListEntry.StreamSize);
                    }
                }

                // Parse DestList entries
                if (destListBytes != null && destListBytes.Length >= 32)
                {
                    ParseDestListStream(destListBytes, report, appId, buffer, sectorSize, fat, miniStreamContainer, miniSectorSize, miniFat, miniStreamCutoff, numberedStreams);
                }
                else
                {
                    // Fallback: carve streams
                    CarveStreamsFromBuffer(buffer, report, appId);
                }
            }
            catch (Exception ex)
            {
                report.Warnings.Add("CFBF parsing exception: " + ex.Message + ". Falling back to carving.");
                CarveStreamsFromBuffer(buffer, report, appId);
            }

            report.TotalEntries = report.Entries.Count;
            int pin = 0;
            int susp = 0;
            foreach (var e in report.Entries)
            {
                if (e.PinStatus == "Pinned") pin++;
                if (e.IsSuspicious) susp++;
            }
            report.PinnedCount = pin;
            report.SuspiciousCount = susp;

            return report;
        }

        private static List<uint> BuildFat(byte[] buffer, int sectorSize, uint numFatSectors)
        {
            var fat = new List<uint>();
            int maxSectors = (buffer.Length / sectorSize);
            List<uint> fatSectorIndices = new List<uint>();

            // First 109 DIFAT sectors in header
            for (int i = 0; i < 109; i++)
            {
                int offset = 76 + (i * 4);
                if (offset + 4 > buffer.Length) break;
                uint sec = BitConverter.ToUInt32(buffer, offset);
                if (sec < 0xFFFFFFFD)
                {
                    fatSectorIndices.Add(sec);
                }
                else break;
            }

            // Traversal of chained DIFAT sectors if numFatSectors > 109
            uint nextDifatSector = BitConverter.ToUInt32(buffer, 68);
            uint numDifatSectors = BitConverter.ToUInt32(buffer, 72);
            int difatCount = 0;
            while (nextDifatSector < 0xFFFFFFFD && difatCount < numDifatSectors && difatCount < 1000)
            {
                difatCount++;
                long off = (long)(nextDifatSector + 1) * sectorSize;
                if (off + sectorSize > buffer.Length) break;

                int entriesInDifat = (sectorSize / 4) - 1;
                for (int i = 0; i < entriesInDifat; i++)
                {
                    uint sec = BitConverter.ToUInt32(buffer, (int)off + (i * 4));
                    if (sec < 0xFFFFFFFD) fatSectorIndices.Add(sec);
                    else break;
                }
                nextDifatSector = BitConverter.ToUInt32(buffer, (int)off + (entriesInDifat * 4));
            }

            // Now read all FAT sectors
            foreach (var fatSec in fatSectorIndices)
            {
                long off = (long)(fatSec + 1) * sectorSize;
                if (off + sectorSize > buffer.Length) break;
                for (int i = 0; i < sectorSize; i += 4)
                {
                    fat.Add(BitConverter.ToUInt32(buffer, (int)off + i));
                }
            }

            return fat;
        }

        private static List<CfbfDirectoryEntry> ReadDirectoryEntries(byte[] buffer, int sectorSize, List<uint> fat, uint firstDirSector)
        {
            var entries = new List<CfbfDirectoryEntry>();
            if (firstDirSector >= 0xFFFFFFFD) return entries;

            byte[] dirData = ReadStreamBytes(buffer, sectorSize, fat, firstDirSector, -1);
            if (dirData == null || dirData.Length < 128) return entries;

            for (int offset = 0; offset + 128 <= dirData.Length; offset += 128)
            {
                ushort nameLen = BitConverter.ToUInt16(dirData, offset + 64);
                byte objType = dirData[offset + 66];
                if (objType == 0) continue; // Unallocated

                string name = String.Empty;
                if (nameLen >= 2 && nameLen <= 64)
                {
                    int charLen = (nameLen / 2) - 1; // remove trailing null wchar
                    if (charLen > 0)
                    {
                        name = Encoding.Unicode.GetString(dirData, offset, charLen * 2);
                    }
                }

                uint startSector = BitConverter.ToUInt32(dirData, offset + 116);
                ulong streamSize = BitConverter.ToUInt64(dirData, offset + 120);

                long createFt = BitConverter.ToInt64(dirData, offset + 100);
                long modFt = BitConverter.ToInt64(dirData, offset + 108);

                var de = new CfbfDirectoryEntry
                {
                    Name = name,
                    ObjectType = objType,
                    StartingSector = startSector,
                    StreamSize = streamSize
                };

                try { de.CreationTimeUtc = createFt > 0 ? DateTime.FromFileTimeUtc(createFt) : DateTime.MinValue; } catch { }
                try { de.ModificationTimeUtc = modFt > 0 ? DateTime.FromFileTimeUtc(modFt) : DateTime.MinValue; } catch { }

                entries.Add(de);
            }

            return entries;
        }

        private static byte[] ReadStreamBytes(byte[] buffer, int sectorSize, List<uint> fat, uint startSector, long expectedSize)
        {
            if (startSector >= 0xFFFFFFFD) return new byte[0];

            using (var ms = new MemoryStream())
            {
                uint current = startSector;
                int count = 0;
                int maxIterations = fat.Count > 0 ? fat.Count + 10 : 10000;

                while (current < 0xFFFFFFFD && count++ < maxIterations)
                {
                    long off = (long)(current + 1) * sectorSize;
                    if (off + sectorSize > buffer.Length)
                    {
                        int remaining = (int)(buffer.Length - off);
                        if (remaining > 0) ms.Write(buffer, (int)off, remaining);
                        break;
                    }

                    ms.Write(buffer, (int)off, sectorSize);

                    if (expectedSize > 0 && ms.Length >= expectedSize) break;

                    if (current < fat.Count)
                    {
                        current = fat[(int)current];
                    }
                    else
                    {
                        break;
                    }
                }

                byte[] result = ms.ToArray();
                if (expectedSize > 0 && result.Length > expectedSize)
                {
                    byte[] trimmed = new byte[expectedSize];
                    Buffer.BlockCopy(result, 0, trimmed, 0, (int)expectedSize);
                    return trimmed;
                }
                return result;
            }
        }

        private static byte[] ReadMiniStreamBytes(byte[] miniStreamContainer, int miniSectorSize, List<uint> miniFat, uint startMiniSector, long expectedSize)
        {
            if (miniStreamContainer == null || startMiniSector >= 0xFFFFFFFD) return new byte[0];

            using (var ms = new MemoryStream())
            {
                uint current = startMiniSector;
                int count = 0;
                int maxIterations = miniFat.Count > 0 ? miniFat.Count + 10 : 10000;

                while (current < 0xFFFFFFFD && count++ < maxIterations)
                {
                    long off = (long)current * miniSectorSize;
                    if (off + miniSectorSize > miniStreamContainer.Length)
                    {
                        int remaining = (int)(miniStreamContainer.Length - off);
                        if (remaining > 0) ms.Write(miniStreamContainer, (int)off, remaining);
                        break;
                    }

                    ms.Write(miniStreamContainer, (int)off, miniSectorSize);

                    if (expectedSize > 0 && ms.Length >= expectedSize) break;

                    if (current < miniFat.Count)
                    {
                        current = miniFat[(int)current];
                    }
                    else
                    {
                        break;
                    }
                }

                byte[] result = ms.ToArray();
                if (expectedSize > 0 && result.Length > expectedSize)
                {
                    byte[] trimmed = new byte[expectedSize];
                    Buffer.BlockCopy(result, 0, trimmed, 0, (int)expectedSize);
                    return trimmed;
                }
                return result;
            }
        }

        private static void ParseDestListStream(
            byte[] destList,
            JumpListReport report,
            string appId,
            byte[] fileBuffer,
            int sectorSize,
            List<uint> fat,
            byte[] miniStreamContainer,
            int miniSectorSize,
            List<uint> miniFat,
            uint miniStreamCutoff,
            Dictionary<string, CfbfDirectoryEntry> numberedStreams)
        {
            if (destList == null || destList.Length < 32) return;

            uint version = BitConverter.ToUInt32(destList, 0);
            uint totalEntries = BitConverter.ToUInt32(destList, 4);
            uint pinnedEntries = BitConverter.ToUInt32(destList, 8);

            int cursor = 32;
            int entryIndex = 0;

            while (cursor + 110 <= destList.Length && (totalEntries == 0 || report.Entries.Count < totalEntries))
            {
                entryIndex++;

                // Fixed DestList record fields:
                // 0: Checksum (8 bytes)
                // 8: Volume DROID (16 bytes)
                // 24: File DROID (16 bytes)
                // 40: Birth Volume DROID (16 bytes)
                // 56: Birth File DROID (16 bytes)
                // 72: NetBIOS Name (16 bytes)
                // 88: Entry ID (4 bytes)
                // 92: Access Count (4 bytes float/uint)
                // 96: Last Access FILETIME (8 bytes)
                // 104: Pin Status (4 bytes)

                byte[] volDroidBytes = new byte[16];
                Buffer.BlockCopy(destList, cursor + 8, volDroidBytes, 0, 16);
                Guid volDroid = new Guid(volDroidBytes);

                byte[] fileDroidBytes = new byte[16];
                Buffer.BlockCopy(destList, cursor + 24, fileDroidBytes, 0, 16);
                Guid fileDroid = new Guid(fileDroidBytes);

                byte[] birthVolDroidBytes = new byte[16];
                Buffer.BlockCopy(destList, cursor + 40, birthVolDroidBytes, 0, 16);
                Guid birthVolDroid = new Guid(birthVolDroidBytes);

                byte[] birthFileDroidBytes = new byte[16];
                Buffer.BlockCopy(destList, cursor + 56, birthFileDroidBytes, 0, 16);
                Guid birthFileDroid = new Guid(birthFileDroidBytes);

                string netbios = Encoding.ASCII.GetString(destList, cursor + 72, 16).TrimEnd('\0', ' ');
                uint entryId = BitConverter.ToUInt32(destList, cursor + 88);

                // Access count can be stored as float or uint
                float accessCountFloat = BitConverter.ToSingle(destList, cursor + 92);
                int accessCount = (accessCountFloat > 0 && accessCountFloat < 1000000) ? (int)accessCountFloat : (int)BitConverter.ToUInt32(destList, cursor + 92);

                long lastAccessFt = BitConverter.ToInt64(destList, cursor + 96);
                DateTime lastAccessUtc = DateTime.MinValue;
                try
                {
                    if (lastAccessFt > 0) lastAccessUtc = DateTime.FromFileTimeUtc(lastAccessFt);
                }
                catch { }

                uint pinStatusVal = BitConverter.ToUInt32(destList, cursor + 104);
                string pinStatus = (pinStatusVal != 0xFFFFFFFF) ? "Pinned" : "Unpinned";

                // Resolve Target Path:
                // Test for string length at offset 108 (Win7/8) vs 112/128/130 (Win10)
                int pathLen = 0;
                int stringOffset = 0;
                int recordSize = 0;

                ushort candidateLen108 = BitConverter.ToUInt16(destList, cursor + 108);
                if (candidateLen108 > 0 && candidateLen108 < 1024 && cursor + 110 + (candidateLen108 * 2) <= destList.Length)
                {
                    pathLen = candidateLen108;
                    stringOffset = cursor + 110;
                    recordSize = 110 + (pathLen * 2);
                }
                else if (cursor + 114 <= destList.Length)
                {
                    ushort candidateLen112 = BitConverter.ToUInt16(destList, cursor + 112);
                    if (candidateLen112 > 0 && candidateLen112 < 1024 && cursor + 114 + (candidateLen112 * 2) <= destList.Length)
                    {
                        pathLen = candidateLen112;
                        stringOffset = cursor + 114;
                        recordSize = 114 + (pathLen * 2);
                    }
                }

                if (recordSize == 0 && cursor + 130 <= destList.Length)
                {
                    ushort candidateLen128 = BitConverter.ToUInt16(destList, cursor + 128);
                    if (candidateLen128 > 0 && candidateLen128 < 1024 && cursor + 130 + (candidateLen128 * 2) <= destList.Length)
                    {
                        pathLen = candidateLen128;
                        stringOffset = cursor + 130;
                        recordSize = 130 + (pathLen * 2);
                    }
                }

                string targetPath = String.Empty;
                if (stringOffset > 0 && pathLen > 0)
                {
                    targetPath = Encoding.Unicode.GetString(destList, stringOffset, pathLen * 2).TrimEnd('\0');
                }

                var entry = new JumpListEntry
                {
                    AppId = appId ?? String.Empty,
                    AppName = ResolveAppName(appId),
                    EntryId = (int)entryId,
                    TargetPath = targetPath,
                    AccessCount = accessCount,
                    LastAccessUtc = lastAccessUtc,
                    PinStatus = pinStatus,
                    NetBiosName = netbios,
                    VolumeDroid = volDroid,
                    FileDroid = fileDroid,
                    BirthVolumeDroid = birthVolDroid,
                    BirthFileDroid = birthFileDroid,
                    Category = "AutomaticDestinations"
                };

                // Link with embedded LNK stream
                LinkWithNumberedStream(entry, entryId, numberedStreams, fileBuffer, sectorSize, fat, miniStreamContainer, miniSectorSize, miniFat, miniStreamCutoff);

                // Run threat heuristics
                EvaluateThreat(entry);

                // If record has no valid path, no timestamp, and entryId == 0, it is zero padding/slack
                if (string.IsNullOrEmpty(entry.TargetPath) && entryId == 0 && lastAccessFt == 0)
                {
                    break;
                }

                report.Entries.Add(entry);

                if (recordSize > 0)
                {
                    cursor += recordSize;
                }
                else
                {
                    // Scan forward to next valid record or step by 114
                    cursor += 114;
                }
            }
        }

        private static void LinkWithNumberedStream(
            JumpListEntry entry,
            uint entryId,
            Dictionary<string, CfbfDirectoryEntry> numberedStreams,
            byte[] fileBuffer,
            int sectorSize,
            List<uint> fat,
            byte[] miniStreamContainer,
            int miniSectorSize,
            List<uint> miniFat,
            uint miniStreamCutoff)
        {
            if (numberedStreams == null || numberedStreams.Count == 0) return;

            // Search for matching stream by hex or decimal
            string[] candidateKeys = new string[]
            {
                entryId.ToString("x"),
                entryId.ToString("X"),
                entryId.ToString(),
                entryId.ToString("x2"),
                entryId.ToString("X2")
            };

            CfbfDirectoryEntry streamEntry = null;
            foreach (var k in candidateKeys)
            {
                if (numberedStreams.TryGetValue(k, out streamEntry)) break;
            }

            if (streamEntry != null && streamEntry.StreamSize >= 76)
            {
                byte[] streamBytes = null;
                if (streamEntry.StreamSize < miniStreamCutoff && miniStreamContainer != null && miniFat != null)
                {
                    streamBytes = ReadMiniStreamBytes(miniStreamContainer, miniSectorSize, miniFat, streamEntry.StartingSector, (long)streamEntry.StreamSize);
                }
                else
                {
                    streamBytes = ReadStreamBytes(fileBuffer, sectorSize, fat, streamEntry.StartingSector, (long)streamEntry.StreamSize);
                }

                if (streamBytes != null && streamBytes.Length >= 76)
                {
                    try
                    {
                        var lnk = LnkParser.Parse(streamBytes);
                        if (lnk != null)
                        {
                            if (string.IsNullOrEmpty(entry.TargetPath))
                            {
                                if (!string.IsNullOrEmpty(lnk.TargetPath)) entry.TargetPath = lnk.TargetPath;
                                else if (!string.IsNullOrEmpty(lnk.RelativePath)) entry.TargetPath = lnk.RelativePath;
                            }
                            entry.TargetFileSize = lnk.TargetFileSize;
                            entry.TargetCreationUtc = lnk.CreationTimeUtc;
                            entry.TargetWriteUtc = lnk.WriteTimeUtc;
                            entry.DriveType = lnk.DriveType;
                            entry.VolumeSerialNumber = lnk.DriveSerialNumber;
                            entry.VolumeLabel = lnk.VolumeLabel;
                            entry.MachineId = lnk.MachineId;
                            entry.MacAddress = lnk.MacAddress;
                            entry.Arguments = lnk.CommandLineArguments;
                        }
                    }
                    catch { }
                }
            }
        }

        #endregion

        #region CustomDestinations Parser

        public static JumpListReport ParseCustomDestinations(byte[] buffer, string appId)
        {
            var report = new JumpListReport
            {
                FileType = "CustomDestinations",
                AppId = appId ?? String.Empty,
                AppName = ResolveAppName(appId)
            };

            if (buffer == null || buffer.Length < 4)
            {
                report.Warnings.Add("Buffer too small for CustomDestinations");
                return report;
            }

            try
            {
                int cursor = 0;
                uint version = BitConverter.ToUInt32(buffer, 0);
                cursor = 4;

                int entryIdCounter = 1;
                string currentCategory = "Custom";

                while (cursor + 4 <= buffer.Length)
                {
                    // Check category separator / footer: 0xAB, 0xFB, 0xBF, 0xBA
                    if (buffer[cursor] == 0xAB && buffer[cursor + 1] == 0xFB && buffer[cursor + 2] == 0xBF && buffer[cursor + 3] == 0xBA)
                    {
                        cursor += 4;
                        continue;
                    }

                    // Check for Category Header:
                    // Category type: 0 = Custom, 1 = Known, 2 = Destination
                    uint categoryType = BitConverter.ToUInt32(buffer, cursor);
                    if (categoryType == 0 && cursor + 6 <= buffer.Length)
                    {
                        cursor += 4;
                        ushort nameLen = BitConverter.ToUInt16(buffer, cursor);
                        cursor += 2;
                        if (nameLen > 0 && cursor + (nameLen * 2) <= buffer.Length)
                        {
                            currentCategory = Encoding.Unicode.GetString(buffer, cursor, nameLen * 2).TrimEnd('\0');
                            cursor += nameLen * 2;
                        }
                        continue;
                    }
                    else if (categoryType == 1 && cursor + 8 <= buffer.Length)
                    {
                        cursor += 4;
                        uint knownId = BitConverter.ToUInt32(buffer, cursor);
                        cursor += 4;
                        if (knownId == 1) currentCategory = "Frequent";
                        else if (knownId == 2) currentCategory = "Recent";
                        else if (knownId == 3) currentCategory = "Tasks";
                        else currentCategory = "Known (" + knownId + ")";
                        continue;
                    }

                    // Check for LNK Magic
                    if (cursor + 76 <= buffer.Length && IsLnkAt(buffer, cursor))
                    {
                        int lnkStart = cursor;
                        byte[] lnkSlice = SliceLnkFromBuffer(buffer, lnkStart);
                        if (lnkSlice != null && lnkSlice.Length >= 76)
                        {
                            try
                            {
                                var lnk = LnkParser.Parse(lnkSlice);
                                if (lnk != null)
                                {
                                    string target = !string.IsNullOrEmpty(lnk.TargetPath) ? lnk.TargetPath : lnk.RelativePath;
                                    var entry = new JumpListEntry
                                    {
                                        AppId = appId ?? String.Empty,
                                        AppName = ResolveAppName(appId),
                                        EntryId = entryIdCounter++,
                                        TargetPath = target,
                                        AccessCount = 1,
                                        LastAccessUtc = lnk.AccessTimeUtc != DateTime.MinValue ? lnk.AccessTimeUtc : lnk.WriteTimeUtc,
                                        PinStatus = "Unpinned",
                                        TargetFileSize = lnk.TargetFileSize,
                                        TargetCreationUtc = lnk.CreationTimeUtc,
                                        TargetWriteUtc = lnk.WriteTimeUtc,
                                        DriveType = lnk.DriveType,
                                        VolumeSerialNumber = lnk.DriveSerialNumber,
                                        VolumeLabel = lnk.VolumeLabel,
                                        MachineId = lnk.MachineId,
                                        MacAddress = lnk.MacAddress,
                                        Arguments = lnk.CommandLineArguments,
                                        Category = currentCategory
                                    };
                                    EvaluateThreat(entry);
                                    report.Entries.Add(entry);
                                }
                            }
                            catch { }

                            cursor += lnkSlice.Length;
                            continue;
                        }
                    }

                    cursor++;
                }
            }
            catch (Exception ex)
            {
                report.Warnings.Add("CustomDestinations parsing exception: " + ex.Message);
            }

            // Fallback: if no entries found, carve LNKs
            if (report.Entries.Count == 0)
            {
                CarveStreamsFromBuffer(buffer, report, appId);
            }

            report.TotalEntries = report.Entries.Count;
            int pin = 0;
            int susp = 0;
            foreach (var e in report.Entries)
            {
                if (e.PinStatus == "Pinned") pin++;
                if (e.IsSuspicious) susp++;
            }
            report.PinnedCount = pin;
            report.SuspiciousCount = susp;

            return report;
        }

        #endregion

        #region Carving & Resiliency

        public static JumpListReport CarveJumpLists(byte[] buffer, string sourcePath = null, string appId = null)
        {
            var report = new JumpListReport
            {
                SourcePath = sourcePath ?? "Carved Buffer",
                FileType = "Carved Stream",
                AppId = appId ?? String.Empty,
                AppName = ResolveAppName(appId)
            };

            CarveStreamsFromBuffer(buffer, report, appId);

            report.TotalEntries = report.Entries.Count;
            int pin = 0;
            int susp = 0;
            foreach (var e in report.Entries)
            {
                if (e.PinStatus == "Pinned") pin++;
                if (e.IsSuspicious) susp++;
            }
            report.PinnedCount = pin;
            report.SuspiciousCount = susp;

            return report;
        }

        private static void CarveStreamsFromBuffer(byte[] buffer, JumpListReport report, string appId)
        {
            if (buffer == null || buffer.Length < 76) return;

            int carvedCount = 0;
            int cursor = 0;
            var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while (cursor + 76 <= buffer.Length)
            {
                // Look for LNK magic header: 4C 00 00 00 01 14 02 00 ...
                if (IsLnkAt(buffer, cursor))
                {
                    byte[] lnkBytes = SliceLnkFromBuffer(buffer, cursor);
                    if (lnkBytes != null && lnkBytes.Length >= 76)
                    {
                        try
                        {
                            var lnk = LnkParser.Parse(lnkBytes);
                            if (lnk != null && (!string.IsNullOrEmpty(lnk.TargetPath) || lnk.TargetFileSize > 0))
                            {
                                string target = !string.IsNullOrEmpty(lnk.TargetPath) ? lnk.TargetPath : lnk.RelativePath;
                                string key = target ?? ("Lnk_" + cursor);
                                if (!seenTargets.Contains(key))
                                {
                                    seenTargets.Add(key);
                                    carvedCount++;
                                    var entry = new JumpListEntry
                                    {
                                        AppId = appId ?? String.Empty,
                                        AppName = ResolveAppName(appId),
                                        EntryId = carvedCount,
                                        TargetPath = target,
                                        AccessCount = 1,
                                        LastAccessUtc = lnk.AccessTimeUtc != DateTime.MinValue ? lnk.AccessTimeUtc : lnk.WriteTimeUtc,
                                        PinStatus = "Unpinned",
                                        TargetFileSize = lnk.TargetFileSize,
                                        TargetCreationUtc = lnk.CreationTimeUtc,
                                        TargetWriteUtc = lnk.WriteTimeUtc,
                                        DriveType = lnk.DriveType,
                                        VolumeSerialNumber = lnk.DriveSerialNumber,
                                        VolumeLabel = lnk.VolumeLabel,
                                        MachineId = lnk.MachineId,
                                        MacAddress = lnk.MacAddress,
                                        Arguments = lnk.CommandLineArguments,
                                        Category = "Carved LNK",
                                        IsCarved = true
                                    };
                                    EvaluateThreat(entry);
                                    report.Entries.Add(entry);
                                }
                            }
                        }
                        catch { }

                        cursor += lnkBytes.Length;
                        continue;
                    }
                }

                // Look for DestList entry pattern:
                // Scan for valid FILETIME (between 2009-01-01 and 2035-01-01) followed by Unicode path pattern (?:\\ or \\\\)
                if (cursor + 114 <= buffer.Length)
                {
                    long candidateFt = BitConverter.ToInt64(buffer, cursor);
                    // 2009-01-01 FILETIME: ~128752320000000000L
                    // 2035-01-01 FILETIME: ~136975200000000000L
                    if (candidateFt >= 128752320000000000L && candidateFt <= 136975200000000000L)
                    {
                        // Check if a path follows at cursor + 12 or cursor + 14 or cursor + 16
                        int[] pathOffsets = new int[] { 12, 14, 16, 20, 32 };
                        foreach (int po in pathOffsets)
                        {
                            if (cursor + po + 6 <= buffer.Length)
                            {
                                if (IsUnicodePathAt(buffer, cursor + po))
                                {
                                    string path = ReadNullTerminatedUnicode(buffer, cursor + po, 512);
                                    if (!string.IsNullOrEmpty(path) && !seenTargets.Contains(path))
                                    {
                                        seenTargets.Add(path);
                                        carvedCount++;
                                        DateTime accessUtc = DateTime.MinValue;
                                        try { accessUtc = DateTime.FromFileTimeUtc(candidateFt); } catch { }

                                        var entry = new JumpListEntry
                                        {
                                            AppId = appId ?? String.Empty,
                                            AppName = ResolveAppName(appId),
                                            EntryId = carvedCount,
                                            TargetPath = path,
                                            AccessCount = 1,
                                            LastAccessUtc = accessUtc,
                                            Category = "Carved DestList",
                                            IsCarved = true
                                        };
                                        EvaluateThreat(entry);
                                        report.Entries.Add(entry);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                cursor += 4;
            }
        }

        private static bool IsLnkAt(byte[] buffer, int offset)
        {
            if (offset + 20 > buffer.Length) return false;
            if (BitConverter.ToUInt32(buffer, offset) != 0x0000004C) return false;
            for (int i = 0; i < 16; i++)
            {
                if (buffer[offset + 4 + i] != LnkMagic[4 + i]) return false;
            }
            return true;
        }

        private static byte[] SliceLnkFromBuffer(byte[] buffer, int offset)
        {
            if (offset + 76 > buffer.Length) return null;

            // Attempt to determine LNK length from flags and structures
            uint linkFlags = BitConverter.ToUInt32(buffer, offset + 20);
            int cursor = offset + 76;

            // HasLinkTargetIDList (0x01)
            if ((linkFlags & 0x01) != 0 && cursor + 2 <= buffer.Length)
            {
                ushort idListSize = BitConverter.ToUInt16(buffer, cursor);
                cursor += 2 + idListSize;
            }

            // HasLinkInfo (0x02)
            if ((linkFlags & 0x02) != 0 && cursor + 4 <= buffer.Length)
            {
                uint linkInfoSize = BitConverter.ToUInt32(buffer, cursor);
                if (linkInfoSize >= 28 && linkInfoSize < 1048576)
                {
                    cursor += (int)linkInfoSize;
                }
            }

            // String Data Blocks: Name(0x04), RelativePath(0x08), WorkingDir(0x10), Arguments(0x20), IconLocation(0x40)
            uint[] stringMasks = new uint[] { 0x04, 0x08, 0x10, 0x20, 0x40 };
            bool isUnicode = (linkFlags & 0x80) != 0;
            int charSize = isUnicode ? 2 : 1;

            foreach (var mask in stringMasks)
            {
                if ((linkFlags & mask) != 0 && cursor + 2 <= buffer.Length)
                {
                    ushort charCount = BitConverter.ToUInt16(buffer, cursor);
                    cursor += 2 + (charCount * charSize);
                }
            }

            // Extra Data Blocks: size (uint32) followed by signature (uint32) until size == 0
            while (cursor + 4 <= buffer.Length)
            {
                uint blockSize = BitConverter.ToUInt32(buffer, cursor);
                if (blockSize < 4 || blockSize > 1048576) break;
                cursor += (int)blockSize;
            }

            int length = cursor - offset;
            if (length < 76) length = 76;
            if (offset + length > buffer.Length) length = buffer.Length - offset;

            byte[] result = new byte[length];
            Buffer.BlockCopy(buffer, offset, result, 0, length);
            return result;
        }

        private static bool IsUnicodePathAt(byte[] buffer, int offset)
        {
            if (offset + 6 > buffer.Length) return false;
            // Matches "C:\" or "\\Server" in UTF-16LE
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

        #endregion

        #region Threat Detection Heuristics

        public static void EvaluateThreat(JumpListEntry entry)
        {
            if (entry == null || string.IsNullOrEmpty(entry.TargetPath)) return;

            string path = entry.TargetPath.ToLowerInvariant();
            string args = (entry.Arguments ?? String.Empty).ToLowerInvariant();

            var reasons = new List<string>();

            // 1. Temporary, Downloads, or Public execution locations
            bool inTemp = path.Contains(@"\appdata\local\temp\") || path.Contains(@"\windows\temp\") || path.Contains(@"\temp\");
            bool inDownloads = path.Contains(@"\downloads\");
            bool inPublic = path.Contains(@"\users\public\");
            bool inProgramDataRoot = Regex.IsMatch(path, @"c:\\programdata\\[^\\]+\.(exe|dll|bat|vbs|ps1|cmd)");

            // 2. High-risk extensions
            bool isScript = path.EndsWith(".bat") || path.EndsWith(".cmd") || path.EndsWith(".ps1") ||
                            path.EndsWith(".vbs") || path.EndsWith(".vbe") || path.EndsWith(".js") ||
                            path.EndsWith(".jse") || path.EndsWith(".wsf") || path.EndsWith(".hta");

            bool isExecutable = path.EndsWith(".exe") || path.EndsWith(".scr") || path.EndsWith(".pif") ||
                               path.EndsWith(".com") || path.EndsWith(".cpl") || path.EndsWith(".dll");

            if (inTemp && (isExecutable || isScript))
            {
                reasons.Add("Execution from Temporary directory");
            }

            if (inDownloads && (isExecutable || isScript))
            {
                reasons.Add("Execution from Downloads folder");
            }

            if (inPublic && (isExecutable || isScript))
            {
                reasons.Add("Execution from Users\\Public directory");
            }

            if (inProgramDataRoot)
            {
                reasons.Add("Direct executable located in ProgramData root");
            }

            // 3. Double extensions (e.g. document.pdf.exe, invoice.xlsx.vbs)
            if (Regex.IsMatch(path, @"\.(pdf|docx?|xlsx?|pptx?|jpg|png|txt|rtf|csv)\.(exe|scr|pif|cmd|bat|vbs|ps1|js|hta)$"))
            {
                reasons.Add("Masquerading double extension");
            }

            // 4. Suspicious command line arguments
            if (args.Contains("-enc") || args.Contains("-encodedcommand") || args.Contains("downloadstring") ||
                args.Contains("iex") || args.Contains("bypass") || args.Contains("-w hidden") || args.Contains("/c powershell"))
            {
                reasons.Add("Suspicious obfuscated CLI arguments");
            }

            // 5. PowerShell or CMD Jump List launching scripts
            if ((entry.AppId == "cdf30b95c55fd78d" || entry.AppId == "5d696d521de238c3") && (inTemp || inDownloads || inPublic))
            {
                reasons.Add("Command shell launched payload from untrusted path");
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
