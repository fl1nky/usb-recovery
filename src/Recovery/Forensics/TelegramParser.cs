using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UsbRecovery
{
    // A decoded SQLite value is not proof of a Telegram message or of deletion.
    // Row/column coordinates identify evidence, not a chat, author or message ID.
    public sealed class TelegramTextFragment
    {
        public string Text { get; set; }
        public string SourcePath { get; set; }
        public string SourceOrigin { get; set; }
        public long Offset { get; set; }
        public uint PageNumber { get; set; }
        public long? SqliteRowId { get; set; }
        public int ColumnIndex { get; set; }
        public string EvidenceKind { get { return "UnattributedSqliteText"; } }
    }

    public sealed class TelegramMessageRecord
    {
        public long MessageId { get; set; }
        public long PeerId { get; set; }
        public string PeerType { get; set; }
        public DateTime TimestampUtc { get; set; }
        public bool IsOut { get; set; }
        public string Text { get; set; }
        public bool IsDeletedOrCarved { get; set; }
        public string SourceOrigin { get; set; }
        public long Offset { get; set; }

        public TelegramMessageRecord()
        {
            PeerType = "User";
            Text = String.Empty;
            SourceOrigin = "ActiveCell";
        }
    }

    public sealed class TelegramDesktopProfile
    {
        public string Path { get; set; }
        public bool HasKeyData { get; set; }
        public bool? HasPasscode { get; set; }
        public int AccountsCount { get; set; }
        public int MediaFilesCount { get; set; }
        public int TotalTdfFiles { get; set; }
        public List<string> DiscoveredFiles { get; set; }
        public DateTime LastActivityUtc { get; set; }

        public TelegramDesktopProfile()
        {
            Path = String.Empty;
            DiscoveredFiles = new List<string>();
            LastActivityUtc = DateTime.MinValue;
        }
    }

    public sealed class TelegramForensicReport
    {
        public string TargetPath { get; set; }
        public List<TelegramDesktopProfile> DesktopProfiles { get; set; }
        public List<TelegramMessageRecord> Messages { get; set; }
        public List<TelegramTextFragment> TextFragments { get; set; }
        public int ActiveMessagesCount { get; set; }
        public int CarvedMessagesCount { get; set; }
        public int TotalTdfContainersFound { get; set; }

        public TelegramForensicReport()
        {
            TargetPath = String.Empty;
            DesktopProfiles = new List<TelegramDesktopProfile>();
            Messages = new List<TelegramMessageRecord>();
            TextFragments = new List<TelegramTextFragment>();
        }
    }

    public static class TelegramParser
    {
        private static readonly byte[] TdfMagic = new byte[] { 0x54, 0x44, 0x46, 0x24 }; // "TDF$"

        public static bool TryParseTdfPayload(byte[] data, out byte[] body, out uint version)
        {
            body = null;
            version = 0;
            if (data == null || data.Length < 28 || data.Length > 32 * 1024 * 1024)
                return false;

            if (data[0] != TdfMagic[0] || data[1] != TdfMagic[1] || data[2] != TdfMagic[2] || data[3] != TdfMagic[3])
                return false;

            version = BitConverter.ToUInt32(data, 4);
            if (version < 1 || version > 100000)
                return false;

            int bodyLen = data.Length - 24; // 8 header + 16 MD5 footer
            if (bodyLen <= 0)
                return false;

            byte[] bodyBytes = new byte[bodyLen];
            Buffer.BlockCopy(data, 8, bodyBytes, 0, bodyLen);

            // MD5 digest = md5(body + struct.pack("<II", len(body), version) + b"TDF$")
            byte[] toHash = new byte[bodyLen + 12];
            Buffer.BlockCopy(bodyBytes, 0, toHash, 0, bodyLen);
            byte[] lenBytes = BitConverter.GetBytes((uint)bodyLen);
            Buffer.BlockCopy(lenBytes, 0, toHash, bodyLen, 4);
            byte[] verBytes = BitConverter.GetBytes(version);
            Buffer.BlockCopy(verBytes, 0, toHash, bodyLen + 4, 4);
            toHash[bodyLen + 8] = TdfMagic[0];
            toHash[bodyLen + 9] = TdfMagic[1];
            toHash[bodyLen + 10] = TdfMagic[2];
            toHash[bodyLen + 11] = TdfMagic[3];

            byte[] expectedHash;
            using (var md5 = MD5.Create())
            {
                expectedHash = md5.ComputeHash(toHash);
            }

            for (int i = 0; i < 16; i++)
            {
                if (data[data.Length - 16 + i] != expectedHash[i])
                    return false;
            }

            body = bodyBytes;
            return true;
        }

        public static byte[] CreateTdfContainer(byte[] body, uint version)
        {
            if (body == null) body = new byte[0];
            int totalLen = 8 + body.Length + 16;
            byte[] result = new byte[totalLen];

            // Header
            Buffer.BlockCopy(TdfMagic, 0, result, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(version), 0, result, 4, 4);

            // Body
            Buffer.BlockCopy(body, 0, result, 8, body.Length);

            // Hash
            byte[] toHash = new byte[body.Length + 12];
            Buffer.BlockCopy(body, 0, toHash, 0, body.Length);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)body.Length), 0, toHash, body.Length, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(version), 0, toHash, body.Length + 4, 4);
            toHash[body.Length + 8] = TdfMagic[0];
            toHash[body.Length + 9] = TdfMagic[1];
            toHash[body.Length + 10] = TdfMagic[2];
            toHash[body.Length + 11] = TdfMagic[3];

            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(toHash);
                Buffer.BlockCopy(hash, 0, result, 8 + body.Length, 16);
            }

            return result;
        }

        public static TelegramDesktopProfile InspectTdata(string tdataDirectory)
        {
            if (String.IsNullOrEmpty(tdataDirectory) || !Directory.Exists(tdataDirectory))
                return null;

            var profile = new TelegramDesktopProfile
            {
                Path = tdataDirectory
            };

            var files = Directory.GetFiles(tdataDirectory, "*", SearchOption.TopDirectoryOnly);
            int accounts = 0;
            DateTime maxActivity = DateTime.MinValue;

            for (int i = 0; i < files.Length; i++)
            {
                string fn = Path.GetFileName(files[i]).ToUpperInvariant();
                FileInfo fi = new FileInfo(files[i]);
                if (fi.LastWriteTimeUtc > maxActivity)
                    maxActivity = fi.LastWriteTimeUtc;

                if (fn == "KEY_DATAS" || fn.StartsWith("KEY_DATAS"))
                {
                    profile.HasKeyData = true;
                    profile.DiscoveredFiles.Add(Path.GetFileName(files[i]));

                    // File size does not establish whether a local passcode is set.
                    profile.HasPasscode = null;
                }
                else if (fn.StartsWith("D877F783D5D3EF8C") || fn.StartsWith("SETTINGS") || fn.StartsWith("MAP"))
                {
                    profile.DiscoveredFiles.Add(Path.GetFileName(files[i]));
                    profile.TotalTdfFiles++;
                }
            }

            // Count account subdirectories
            var subdirs = Directory.GetDirectories(tdataDirectory);
            for (int d = 0; d < subdirs.Length; d++)
            {
                string dirName = Path.GetFileName(subdirs[d]).ToLowerInvariant();
                if (dirName == "user_data" || dirName.StartsWith("user_data#") || dirName.StartsWith("d877f783d5d3ef8c"))
                {
                    accounts++;
                }
                else if (dirName == "media_cache")
                {
                    try
                    {
                        profile.MediaFilesCount = Directory.GetFiles(subdirs[d], "*", SearchOption.AllDirectories).Length;
                    }
                    catch { }
                }
            }

            profile.AccountsCount = Math.Max(1, accounts);
            profile.LastActivityUtc = maxActivity;
            return profile;
        }

        public static List<TelegramTextFragment> ParseDatabase(string sqlitePath)
        {
            if (String.IsNullOrEmpty(sqlitePath) || !File.Exists(sqlitePath))
                return new List<TelegramTextFragment>();

            using (var fs = new FileStream(sqlitePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                var fragments = CarveDatabase(fs);
                foreach (var fragment in fragments)
                    fragment.SourcePath = Path.GetFullPath(sqlitePath);
                return fragments;
            }
        }

        public static List<TelegramTextFragment> CarveDatabase(Stream stream)
        {
            var results = new List<TelegramTextFragment>();
            if (stream == null || !stream.CanRead || !stream.CanSeek || stream.Length < 100)
                return results;

            List<CarvedSqliteRecord> rawRecords = SqliteCarver.CarveDatabase(stream);
            for (int i = 0; i < rawRecords.Count; i++)
            {
                var r = rawRecords[i];
                if (r.Columns == null)
                    continue;
                // Preserve every text column. Column order and integer ranges are
                // insufficient to identify a Telegram schema, even on an active page.
                for (int c = 0; c < r.Columns.Count; c++)
                {
                    var col = r.Columns[c];
                    if (col.Type != SqliteColumnType.Text) continue;
                    string text = col.AsString();
                    if (String.IsNullOrEmpty(text) || text.Length >= 65536) continue;
                    results.Add(new TelegramTextFragment
                    {
                        Text = text,
                        SourcePath = null,
                        SourceOrigin = r.Origin.ToString(),
                        Offset = r.AbsoluteOffset,
                        PageNumber = r.PageNumber,
                        SqliteRowId = r.RowId,
                        ColumnIndex = c
                    });
                }
            }

            return results;
        }

        public static List<byte[]> CarveTdfContainers(Stream stream, long maxScanBytes = 256 * 1024 * 1024)
        {
            var results = new List<byte[]>();
            if (stream == null || !stream.CanRead)
                return results;

            long totalScan = Math.Min(stream.Length, maxScanBytes);
            byte[] buffer = new byte[65536];
            stream.Position = 0;
            long scanned = 0;

            while (scanned < totalScan)
            {
                int toRead = (int)Math.Min(buffer.Length, totalScan - scanned);
                int read = stream.Read(buffer, 0, toRead);
                if (read <= 28) break;

                for (int i = 0; i <= read - 28; i++)
                {
                    if (buffer[i] == TdfMagic[0] && buffer[i + 1] == TdfMagic[1] &&
                        buffer[i + 2] == TdfMagic[2] && buffer[i + 3] == TdfMagic[3])
                    {
                        uint ver = BitConverter.ToUInt32(buffer, i + 4);
                        if (ver >= 1 && ver <= 10000)
                        {
                            // Found candidate TDF header at position: scanned + i
                            long hitOffset = scanned + i;
                            long savePos = stream.Position;
                            try
                            {
                                stream.Position = hitOffset;
                                int maxProbe = (int)Math.Min(65536L, stream.Length - hitOffset);
                                byte[] probe = new byte[maxProbe];
                                int probeRead = stream.Read(probe, 0, maxProbe);
                                if (probeRead >= 28)
                                {
                                    byte[] body;
                                    uint candidateVer;
                                    if (TryParseTdfPayload(probe, out body, out candidateVer))
                                    {
                                        results.Add(probe);
                                        if (results.Count >= 200) break;
                                    }
                                    else
                                    {
                                        bool matched = false;
                                        // 1. Check Qt length prefix if present
                                        uint qtLen = BitConverter.ToUInt32(probe, 8);
                                        if (qtLen > 0 && qtLen < 65536)
                                        {
                                            int qtTotal = (int)(8 + qtLen + 16);
                                            if (qtTotal <= probeRead)
                                            {
                                                byte[] qtCand = new byte[qtTotal];
                                                Buffer.BlockCopy(probe, 0, qtCand, 0, qtTotal);
                                                if (TryParseTdfPayload(qtCand, out body, out candidateVer))
                                                {
                                                    results.Add(qtCand);
                                                    matched = true;
                                                }
                                            }
                                        }

                                        // 2. Scan candidate lengths up to 4096 bytes
                                        if (!matched)
                                        {
                                            int maxScanLen = Math.Min(probeRead, 4096);
                                            for (int clen = 28; clen <= maxScanLen; clen++)
                                            {
                                                byte[] cand = new byte[clen];
                                                Buffer.BlockCopy(probe, 0, cand, 0, clen);
                                                if (TryParseTdfPayload(cand, out body, out candidateVer))
                                                {
                                                    results.Add(cand);
                                                    break;
                                                }
                                            }
                                        }

                                        if (results.Count >= 200) break;
                                    }
                                }
                            }
                            catch { }
                            finally
                            {
                                stream.Position = savePos;
                            }
                        }
                    }
                }

                scanned += (read - 28);
                if (stream.CanSeek)
                    stream.Position = scanned;
            }

            return results;
        }

        public static TelegramForensicReport Analyze(string path)
        {
            var report = new TelegramForensicReport
            {
                TargetPath = path
            };

            if (String.IsNullOrEmpty(path))
                return report;

            if (File.Exists(path))
            {
                // Single file: could be SQLite (cache4.db, tg_user.db) or TDF container
                try
                {
                    using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        byte[] head = new byte[16];
                        int r = fs.Read(head, 0, 16);
                        fs.Position = 0;

                        if (r >= 16 && Encoding.ASCII.GetString(head).StartsWith("SQLite format 3"))
                        {
                            report.TextFragments = CarveDatabase(fs);
                        }
                        else if (r >= 4 && head[0] == TdfMagic[0] && head[1] == TdfMagic[1] && head[2] == TdfMagic[2] && head[3] == TdfMagic[3])
                        {
                            byte[] data = new byte[Math.Min(fs.Length, 16 * 1024 * 1024)];
                            fs.Read(data, 0, data.Length);
                            byte[] body;
                            uint ver;
                            if (TryParseTdfPayload(data, out body, out ver))
                            {
                                report.TotalTdfContainersFound = 1;
                            }
                        }
                        else
                        {
                            // Raw carve disk or binary image
                            report.TextFragments = CarveDatabase(fs);
                            var containers = CarveTdfContainers(fs);
                            report.TotalTdfContainersFound = containers.Count;
                        }
                    }
                    foreach (var fragment in report.TextFragments)
                        fragment.SourcePath = Path.GetFullPath(path);
                }
                catch { }
            }
            else if (Directory.Exists(path))
            {
                // Check if this directory itself is a tdata folder
                var profile = InspectTdata(path);
                if (profile != null && (profile.HasKeyData || profile.TotalTdfFiles > 0))
                {
                    report.DesktopProfiles.Add(profile);
                    report.TotalTdfContainersFound += profile.TotalTdfFiles;
                }

                // Also search subdirectories for tdata folders
                try
                {
                    var tdataDirs = Directory.GetDirectories(path, "*tdata*", SearchOption.AllDirectories);
                    for (int td = 0; td < tdataDirs.Length; td++)
                    {
                        if (string.Equals(tdataDirs[td], path, StringComparison.OrdinalIgnoreCase))
                            continue;

                        var subProfile = InspectTdata(tdataDirs[td]);
                        if (subProfile != null && (subProfile.HasKeyData || subProfile.TotalTdfFiles > 0))
                        {
                            report.DesktopProfiles.Add(subProfile);
                            report.TotalTdfContainersFound += subProfile.TotalTdfFiles;
                        }
                    }
                }
                catch { }

                // Search for SQLite databases in directory (cache4.db, *.db, *.sqlite)
                try
                {
                    var dbFiles = Directory.GetFiles(path, "*.db", SearchOption.AllDirectories);
                    for (int i = 0; i < Math.Min(dbFiles.Length, 20); i++)
                    {
                        try
                        {
                            var msgs = ParseDatabase(dbFiles[i]);
                            report.TextFragments.AddRange(msgs);
                        }
                        catch { }
                    }
                }
                catch { }
            }

            for (int i = 0; i < report.Messages.Count; i++)
            {
                if (report.Messages[i].IsDeletedOrCarved)
                    report.CarvedMessagesCount++;
                else
                    report.ActiveMessagesCount++;
            }

            return report;
        }
    }
}
