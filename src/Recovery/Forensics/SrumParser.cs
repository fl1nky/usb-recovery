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
    /// Represents a parsed SRUM network data usage record.
    /// Tracks application network communications, bytes uploaded/downloaded,
    /// interface LUIDs, and exact timestamps for exfiltration analysis.
    /// </summary>
    public sealed class SrumNetworkEntry
    {
        public uint AppId { get; set; }
        public string AppName { get; set; }
        public string UserSid { get; set; }
        public ulong InterfaceLuid { get; set; }
        public string InterfaceType { get; set; }
        public ulong BytesSent { get; set; }
        public ulong BytesReceived { get; set; }
        public ulong TotalBytes { get; set; }
        public DateTime TimestampUtc { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }

        public SrumNetworkEntry()
        {
            AppName = String.Empty;
            UserSid = String.Empty;
            InterfaceType = "Unknown";
            SuspicionReason = String.Empty;
            TimestampUtc = DateTime.MinValue;
        }

        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "[{0}] {1} — Sent: {2:N0} bytes, Recv: {3:N0} bytes (Interface: {4})",
                TimestampUtc != DateTime.MinValue ? TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "N/A",
                AppName, BytesSent, BytesReceived, InterfaceType);
        }
    }

    /// <summary>
    /// Represents a parsed SRUM application execution and resource usage record.
    /// Tracks CPU cycles, execution duration (foreground/background), and read/write I/O.
    /// </summary>
    public sealed class SrumAppUsageEntry
    {
        public uint AppId { get; set; }
        public string AppName { get; set; }
        public string UserSid { get; set; }
        public ulong ForegroundCycleTime { get; set; }
        public ulong BackgroundCycleTime { get; set; }
        public ulong FaceTimeMs { get; set; }
        public ulong CpuCycles { get; set; }
        public ulong BytesRead { get; set; }
        public ulong BytesWritten { get; set; }
        public DateTime TimestampUtc { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }

        public SrumAppUsageEntry()
        {
            AppName = String.Empty;
            UserSid = String.Empty;
            SuspicionReason = String.Empty;
            TimestampUtc = DateTime.MinValue;
        }

        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "[{0}] {1} — Foreground: {2} ms, CPU Cycles: {3:N0}",
                TimestampUtc != DateTime.MinValue ? TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "N/A",
                AppName, FaceTimeMs, CpuCycles);
        }
    }

    /// <summary>
    /// Comprehensive forensic report of parsed SRUM artifacts.
    /// </summary>
    public sealed class SrumReport
    {
        public string DatabasePath { get; set; }
        public int PageSize { get; set; }
        public int TotalPages { get; set; }
        public int IdMapCount { get; set; }
        public List<SrumNetworkEntry> NetworkEntries { get; set; }
        public List<SrumAppUsageEntry> AppUsageEntries { get; set; }
        public ulong TotalBytesExfiltrated { get; set; }
        public ulong TotalBytesReceived { get; set; }
        public int SuspiciousAlertCount { get; set; }

        public SrumReport()
        {
            DatabasePath = String.Empty;
            NetworkEntries = new List<SrumNetworkEntry>();
            AppUsageEntries = new List<SrumAppUsageEntry>();
        }

        public string ToJson()
        {
            var serializer = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
            return serializer.Serialize(this);
        }
    }

    /// <summary>
    /// Forensic parser for Windows System Resource Usage Monitor (SRUM) artifacts.
    /// Parses Microsoft Extensible Storage Engine (ESE / JET Blue) SRUDB.dat databases,
    /// reconstructs IdMap associations, and carves network/application usage tables.
    /// Identifies data exfiltration, execution timelines, and suspicious binary behavior.
    /// 100% offline, zero network telemetry, strictly bounded 64 KiB sliding memory.
    /// </summary>
    public static class SrumParser
    {
        // ESE Database Magic: 0x89ABCDEF (Little Endian: EF CD AB 89)
        public const uint EseMagic = 0x89ABCDEFU;

        // Known SRUM Table GUID Strings
        public const string NetworkTableGuid = "{973F5D5C-1D90-4944-BE81-70B51431B5E0}";
        public const string AppUsageTableGuid = "{D10CA2FE-6FCF-4F6D-848E-B2E9939E74C6}";
        public const string IdMapTableName = "SruDbIdMapTable";

        // Heuristic threat patterns
        private static readonly Regex SuspiciousPathRegex = new Regex(
            @"(\\temp\\|\\appdata\\local\\temp\\|\\users\\public\\|\\programdata\\|\\recycle\.bin\\)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex SuspiciousBinaryRegex = new Regex(
            @"\b(powershell|cmd|psexec|mimikatz|nc|ncat|netcat|tor|rclone|chisel|procdump|curl|wget)\.exe$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex DoubleExtensionRegex = new Regex(
            @"\.[a-zA-Z0-9]+\.(exe|dll|scr|bat|ps1|vbs|cmd)$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // =========================================================================
        // Public API
        // =========================================================================

        public static SrumReport Parse(string srumPath)
        {
            if (string.IsNullOrEmpty(srumPath) || !File.Exists(srumPath))
                return new SrumReport { DatabasePath = srumPath };

            using (var stream = new FileStream(srumPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return ParseStream(stream, srumPath, CancellationToken.None);
            }
        }

        public static SrumReport ParseStream(Stream stream, string sourceName, CancellationToken ct)
        {
            var report = new SrumReport { DatabasePath = sourceName ?? "Stream" };
            if (stream == null || !stream.CanRead) return report;

            // 1. Verify ESE Header
            byte[] header = new byte[4096];
            stream.Seek(0, SeekOrigin.Begin);
            int read = stream.Read(header, 0, header.Length);
            if (read < 256) return report;

            uint magic = BitConverter.ToUInt32(header, 4);
            int pageSize = 4096;

            if (magic == EseMagic)
            {
                uint rawPageSize = BitConverter.ToUInt32(header, 236);
                if (rawPageSize == 4096 || rawPageSize == 8192 || rawPageSize == 16384 || rawPageSize == 32768)
                {
                    pageSize = (int)rawPageSize;
                }
            }
            report.PageSize = pageSize;
            report.TotalPages = (int)(stream.Length / pageSize);

            // 2. Recover SruDbIdMapTable (Mapping uint IdIndex -> AppPath/Sid)
            var idMap = RecoverIdMap(stream, pageSize, ct);
            report.IdMapCount = idMap.Count;

            // 3. Carve Network Usage Records ({973F5D5C-1D90-4944-BE81-70B51431B5E0})
            var networkEntries = CarveNetworkEntries(stream, pageSize, idMap, ct);
            report.NetworkEntries = networkEntries;

            // 4. Carve Application Usage Records ({D10CA2FE-6FCF-4F6D-848E-B2E9939E74C6})
            var appUsageEntries = CarveAppUsageEntries(stream, pageSize, idMap, ct);
            report.AppUsageEntries = appUsageEntries;

            // 5. Compute Statistics & Threat Heuristics
            ulong totalSent = 0;
            ulong totalRecv = 0;
            int alertCount = 0;

            for (int i = 0; i < networkEntries.Count; i++)
            {
                var entry = networkEntries[i];
                totalSent += entry.BytesSent;
                totalRecv += entry.BytesReceived;
                if (entry.IsSuspicious) alertCount++;
            }

            for (int i = 0; i < appUsageEntries.Count; i++)
            {
                if (appUsageEntries[i].IsSuspicious) alertCount++;
            }

            report.TotalBytesExfiltrated = totalSent;
            report.TotalBytesReceived = totalRecv;
            report.SuspiciousAlertCount = alertCount;

            return report;
        }

        // =========================================================================
        // IdMap Recovery (SruDbIdMapTable)
        // =========================================================================

        public static Dictionary<uint, string> RecoverIdMap(Stream stream, int pageSize, CancellationToken ct)
        {
            var idMap = new Dictionary<uint, string>();
            if (stream == null || !stream.CanRead) return idMap;

            // In SRUDB.dat, IdMap entries are stored as:
            // IdType (uint16/32: 1=SID, 2=App, 3=UserName), IdIndex (uint32), Length (uint16), String (UTF-16LE)
            byte[] buffer = new byte[65536];
            long streamLen = stream.Length;
            long step = buffer.Length - 512;

            for (long pos = 0; pos < streamLen; pos += step)
            {
                if (ct.IsCancellationRequested) break;
                stream.Seek(pos, SeekOrigin.Begin);
                int r = stream.Read(buffer, 0, buffer.Length);
                if (r < 64) break;

                for (int i = 0; i <= r - 40; i += 2)
                {
                    // Check for IdType == 1, 2, or 3
                    ushort idType = BitConverter.ToUInt16(buffer, i);
                    if (idType >= 1 && idType <= 3)
                    {
                        uint idIndex = BitConverter.ToUInt32(buffer, i + 2);
                        if (idIndex > 0 && idIndex < 1000000 && !idMap.ContainsKey(idIndex))
                        {
                            // Look for candidate UTF-16 string within next 4..12 bytes
                            for (int strOff = i + 6; strOff <= i + 16 && strOff + 10 <= r; strOff += 2)
                            {
                                string candidate = ExtractUnicodeString(buffer, strOff, r - strOff);
                                if (!string.IsNullOrEmpty(candidate) && candidate.Length >= 3)
                                {
                                    if (candidate.StartsWith("S-1-") || candidate.Contains("\\") || candidate.Contains("."))
                                    {
                                        idMap[idIndex] = candidate;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return idMap;
        }

        // =========================================================================
        // Network Usage Carving ({973F5D5C-1D90-4944-BE81-70B51431B5E0})
        // =========================================================================

        public static List<SrumNetworkEntry> CarveNetworkEntries(Stream stream, int pageSize, Dictionary<uint, string> idMap, CancellationToken ct)
        {
            var entries = new List<SrumNetworkEntry>();
            if (stream == null || !stream.CanRead) return entries;

            byte[] buffer = new byte[65536];
            long streamLen = stream.Length;
            long step = buffer.Length - 512;

            for (long pos = 0; pos < streamLen; pos += step)
            {
                if (ct.IsCancellationRequested) break;
                stream.Seek(pos, SeekOrigin.Begin);
                int r = stream.Read(buffer, 0, buffer.Length);
                if (r < 48) break;

                for (int i = 0; i <= r - 48; i += 4)
                {
                    // Network usage records contain:
                    // uint AppId (0..4)
                    // uint UserId (4..8)
                    // ulong InterfaceLuid (8..16)
                    // ulong BytesSent (16..24)
                    // ulong BytesRecv (24..32)
                    // long FileTimeUtc (32..40)

                    long fileTime = BitConverter.ToInt64(buffer, i + 32);
                    if (fileTime > 116444736000000000L && fileTime < 2650467743990000000L) // Valid Win32 FILETIME
                    {
                        DateTime ts = DateTime.FromFileTimeUtc(fileTime);
                        if (ts.Year >= 2012 && ts.Year <= 2035)
                        {
                            uint appId = BitConverter.ToUInt32(buffer, i);
                            uint userId = BitConverter.ToUInt32(buffer, i + 4);
                            ulong ifLuid = BitConverter.ToUInt64(buffer, i + 8);
                            ulong sent = BitConverter.ToUInt64(buffer, i + 16);
                            ulong recv = BitConverter.ToUInt64(buffer, i + 24);

                            // Sanity bounds: transfer under 10 Terabytes, AppId non-zero
                            if (appId > 0 && sent < 10995116277760UL && recv < 10995116277760UL && (sent > 0 || recv > 0))
                            {
                                string appName = "";
                                if (idMap != null && idMap.ContainsKey(appId))
                                {
                                    appName = idMap[appId];
                                }
                                else
                                {
                                    appName = "AppId_" + appId;
                                }

                                string userSid = "";
                                if (idMap != null && idMap.ContainsKey(userId))
                                {
                                    userSid = idMap[userId];
                                }
                                else if (userId > 0)
                                {
                                    userSid = "UserId_" + userId;
                                }

                                string ifType = ResolveInterfaceType(ifLuid);

                                var entry = new SrumNetworkEntry
                                {
                                    AppId = appId,
                                    AppName = appName,
                                    UserSid = userSid,
                                    InterfaceLuid = ifLuid,
                                    InterfaceType = ifType,
                                    BytesSent = sent,
                                    BytesReceived = recv,
                                    TotalBytes = sent + recv,
                                    TimestampUtc = ts
                                };

                                EvaluateNetworkThreat(entry);
                                entries.Add(entry);
                            }
                        }
                    }
                }
            }

            return entries;
        }

        // =========================================================================
        // Application Usage Carving ({D10CA2FE-6FCF-4F6D-848E-B2E9939E74C6})
        // =========================================================================

        public static List<SrumAppUsageEntry> CarveAppUsageEntries(Stream stream, int pageSize, Dictionary<uint, string> idMap, CancellationToken ct)
        {
            var entries = new List<SrumAppUsageEntry>();
            if (stream == null || !stream.CanRead) return entries;

            byte[] buffer = new byte[65536];
            long streamLen = stream.Length;
            long step = buffer.Length - 512;

            for (long pos = 0; pos < streamLen; pos += step)
            {
                if (ct.IsCancellationRequested) break;
                stream.Seek(pos, SeekOrigin.Begin);
                int r = stream.Read(buffer, 0, buffer.Length);
                if (r < 56) break;

                for (int i = 0; i <= r - 56; i += 4)
                {
                    // App usage records contain:
                    // uint AppId (0..4)
                    // uint UserId (4..8)
                    // ulong ForegroundDuration (8..16)
                    // ulong BackgroundDuration (16..24)
                    // ulong CpuCycles (24..32)
                    // ulong BytesRead (32..40)
                    // ulong BytesWritten (40..48)
                    // long FileTimeUtc (48..56)

                    long fileTime = BitConverter.ToInt64(buffer, i + 48);
                    if (fileTime > 116444736000000000L && fileTime < 2650467743990000000L)
                    {
                        DateTime ts = DateTime.FromFileTimeUtc(fileTime);
                        if (ts.Year >= 2012 && ts.Year <= 2035)
                        {
                            uint appId = BitConverter.ToUInt32(buffer, i);
                            uint userId = BitConverter.ToUInt32(buffer, i + 4);
                            ulong fgDur = BitConverter.ToUInt64(buffer, i + 8);
                            ulong bgDur = BitConverter.ToUInt64(buffer, i + 16);
                            ulong cpu = BitConverter.ToUInt64(buffer, i + 24);
                            ulong rBytes = BitConverter.ToUInt64(buffer, i + 32);
                            ulong wBytes = BitConverter.ToUInt64(buffer, i + 40);

                            if (appId > 0 && (fgDur > 0 || bgDur > 0 || cpu > 0 || rBytes > 0 || wBytes > 0))
                            {
                                string appName = "";
                                if (idMap != null && idMap.ContainsKey(appId))
                                {
                                    appName = idMap[appId];
                                }
                                else
                                {
                                    appName = "AppId_" + appId;
                                }

                                string userSid = "";
                                if (idMap != null && idMap.ContainsKey(userId))
                                {
                                    userSid = idMap[userId];
                                }

                                var entry = new SrumAppUsageEntry
                                {
                                    AppId = appId,
                                    AppName = appName,
                                    UserSid = userSid,
                                    ForegroundCycleTime = fgDur,
                                    BackgroundCycleTime = bgDur,
                                    FaceTimeMs = fgDur / 10000, // Conversion to approximate ms
                                    CpuCycles = cpu,
                                    BytesRead = rBytes,
                                    BytesWritten = wBytes,
                                    TimestampUtc = ts
                                };

                                EvaluateAppUsageThreat(entry);
                                entries.Add(entry);
                            }
                        }
                    }
                }
            }

            return entries;
        }

        // =========================================================================
        // Threat Heuristics
        // =========================================================================

        private static void EvaluateNetworkThreat(SrumNetworkEntry entry)
        {
            if (entry == null || string.IsNullOrEmpty(entry.AppName)) return;

            // 1. Double extensions (e.g. invoice.pdf.exe)
            if (DoubleExtensionRegex.IsMatch(entry.AppName))
            {
                entry.IsSuspicious = true;
                entry.SuspicionReason = "Masqueraded double extension binary communicating over network.";
                return;
            }

            // 2. Suspicious directory paths
            if (SuspiciousPathRegex.IsMatch(entry.AppName))
            {
                entry.IsSuspicious = true;
                entry.SuspicionReason = "Execution from temporary or public folder communicating externally.";
                return;
            }

            // 3. Known malicious or dual-use CLI tools
            if (SuspiciousBinaryRegex.IsMatch(entry.AppName))
            {
                entry.IsSuspicious = true;
                entry.SuspicionReason = "Dual-use administration or offensive utility active on network.";
                return;
            }

            // 4. Massive exfiltration (> 500 MB outbound from non-browser)
            if (entry.BytesSent > 524288000UL)
            {
                string lower = entry.AppName.ToLowerInvariant();
                if (!lower.Contains("chrome") && !lower.Contains("firefox") && !lower.Contains("edge") && !lower.Contains("onedrive"))
                {
                    entry.IsSuspicious = true;
                    entry.SuspicionReason = string.Format(CultureInfo.InvariantCulture,
                        "High-volume outbound data transfer ({0:N0} MB). Potential exfiltration.", entry.BytesSent / (1024 * 1024));
                    return;
                }
            }
        }

        private static void EvaluateAppUsageThreat(SrumAppUsageEntry entry)
        {
            if (entry == null || string.IsNullOrEmpty(entry.AppName)) return;

            if (DoubleExtensionRegex.IsMatch(entry.AppName))
            {
                entry.IsSuspicious = true;
                entry.SuspicionReason = "Execution of double extension executable.";
            }
            else if (SuspiciousPathRegex.IsMatch(entry.AppName))
            {
                entry.IsSuspicious = true;
                entry.SuspicionReason = "Execution from temporary or public directory.";
            }
            else if (SuspiciousBinaryRegex.IsMatch(entry.AppName))
            {
                entry.IsSuspicious = true;
                entry.SuspicionReason = "Execution of dual-use or offensive binary.";
            }
        }

        // =========================================================================
        // Helpers
        // =========================================================================

        public static string ResolveInterfaceType(ulong ifLuid)
        {
            // Windows Interface LUID: Bits 48-63 encode the interface type (IF_TYPE)
            ulong ifType = (ifLuid >> 48) & 0xFFFF;
            switch (ifType)
            {
                case 6: return "Ethernet";
                case 71: return "Wireless (802.11)";
                case 23: return "PPP";
                case 24: return "Loopback";
                case 131: return "Tunnel";
                case 243: return "Mobile Broadband (WWAN)";
                default:
                    if (ifLuid == 0) return "Loopback/Local";
                    return "Interface_" + ifType;
            }
        }

        public static string ExtractUnicodeString(byte[] buffer, int offset, int maxLen)
        {
            if (buffer == null || offset >= buffer.Length || maxLen <= 0) return "";
            int available = Math.Min(maxLen, buffer.Length - offset);
            int len = 0;

            while (len + 1 < available)
            {
                ushort ch = BitConverter.ToUInt16(buffer, offset + len);
                if (ch == 0) break;
                if (ch < 32 && ch != '\t' && ch != '\r' && ch != '\n') break;
                len += 2;
                if (len >= 512) break;
            }

            if (len >= 2)
            {
                try
                {
                    return Encoding.Unicode.GetString(buffer, offset, len).Trim();
                }
                catch { }
            }
            return "";
        }
    }
}
