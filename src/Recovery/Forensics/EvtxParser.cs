using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace UsbRecovery
{
    public sealed class EvtxRecord
    {
        public long RecordId { get; set; }
        public DateTime TimestampUtc { get; set; }
        public int EventId { get; set; }
        public string ProviderName { get; set; }
        public string Channel { get; set; }
        public string ComputerName { get; set; }
        public string XmlContent { get; set; }
        public Dictionary<string, string> Properties { get; set; }

        public EvtxRecord()
        {
            ProviderName = String.Empty;
            Channel = String.Empty;
            ComputerName = String.Empty;
            XmlContent = String.Empty;
            Properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public sealed class EvtxAuditReport
    {
        public string SourcePath { get; set; }
        public int TotalRecords { get; set; }
        public int LogonCount { get; set; }
        public int FailedLogonCount { get; set; }
        public int ProcessCreationCount { get; set; }
        public int ServiceInstallCount { get; set; }
        public int LogClearCount { get; set; }
        public int ThreatAlertCount { get; set; }
        public List<EvtxRecord> Records { get; set; }

        public EvtxAuditReport()
        {
            SourcePath = String.Empty;
            Records = new List<EvtxRecord>();
        }

        public string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"SourcePath\":\"{0}\",", EscapeJson(SourcePath));
            sb.AppendFormat("\"TotalRecords\":{0},", TotalRecords);
            sb.AppendFormat("\"LogonCount\":{0},", LogonCount);
            sb.AppendFormat("\"FailedLogonCount\":{0},", FailedLogonCount);
            sb.AppendFormat("\"ProcessCreationCount\":{0},", ProcessCreationCount);
            sb.AppendFormat("\"ServiceInstallCount\":{0},", ServiceInstallCount);
            sb.AppendFormat("\"LogClearCount\":{0},", LogClearCount);
            sb.AppendFormat("\"ThreatAlertCount\":{0},", ThreatAlertCount);
            sb.Append("\"Records\":[");
            int show = Math.Min(100, Records.Count);
            for (int i = 0; i < show; i++)
            {
                if (i > 0) sb.Append(",");
                var r = Records[i];
                sb.Append("{");
                sb.AppendFormat("\"RecordId\":{0},", r.RecordId);
                sb.AppendFormat("\"EventId\":{0},", r.EventId);
                sb.AppendFormat("\"TimestampUtc\":\"{0:O}\",", r.TimestampUtc);
                sb.AppendFormat("\"Channel\":\"{0}\",", EscapeJson(r.Channel));
                sb.AppendFormat("\"ProviderName\":\"{0}\",", EscapeJson(r.ProviderName));
                sb.AppendFormat("\"ComputerName\":\"{0}\"", EscapeJson(r.ComputerName));
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

    public sealed class EvtxChunkHeader
    {
        public long FirstRecordNumber { get; set; }
        public long LastRecordNumber { get; set; }
        public long FirstRecordId { get; set; }
        public long LastRecordId { get; set; }
        public uint HeaderSize { get; set; }
        public uint LastRecordOffset { get; set; }
        public uint FreeSpaceOffset { get; set; }
        public uint EventRecordsChecksum { get; set; }
        public uint HeaderChecksum { get; set; }
        public bool IsValid { get; set; }

        public EvtxChunkHeader()
        {
            HeaderSize = 512;
            IsValid = true;
        }
    }

    public static class EvtxParser
    {
        private const uint RecordMagic = 0x00002A2A; // 0x2A2A0000 little-endian
        private const int ChunkSize = 65536; // 64 KiB
        private const int FileHeaderSize = 4096;

        public static EvtxAuditReport Audit(string path)
        {
            if (path == null) throw new ArgumentNullException("path");
            var report = new EvtxAuditReport { SourcePath = path };

            List<EvtxRecord> allRecords = new List<EvtxRecord>();

            if (Directory.Exists(path))
            {
                var files = Directory.GetFiles(path, "*.evtx", SearchOption.AllDirectories);
                foreach (var f in files)
                {
                    try
                    {
                        var recs = ParseFile(f);
                        if (recs != null) allRecords.AddRange(recs);
                    }
                    catch { }
                }
            }
            else if (File.Exists(path))
            {
                allRecords = ParseFile(path);
            }

            report.Records = allRecords;
            report.TotalRecords = allRecords.Count;

            foreach (var r in allRecords)
            {
                if (r.EventId == 4624) report.LogonCount++;
                else if (r.EventId == 4625) { report.FailedLogonCount++; report.ThreatAlertCount++; }
                else if (r.EventId == 4688) report.ProcessCreationCount++;
                else if (r.EventId == 4697 || r.EventId == 7045) report.ServiceInstallCount++;
                else if (r.EventId == 1102 || r.EventId == 104) { report.LogClearCount++; report.ThreatAlertCount++; }
                else if (r.EventId == 1116 || r.EventId == 1117 || r.EventId == 4104) report.ThreatAlertCount++;
            }

            return report;
        }

        public static List<EvtxRecord> ParseFile(string filePath)
        {
            if (filePath == null) throw new ArgumentNullException("filePath");
            if (!File.Exists(filePath)) throw new FileNotFoundException("EVTX file not found", filePath);

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return Parse(fs);
            }
        }

        public static List<EvtxRecord> Parse(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException("stream");

            if (stream is MemoryStream)
            {
                return Parse(((MemoryStream)stream).ToArray());
            }

            if (stream.CanSeek)
            {
                List<EvtxRecord> records = new List<EvtxRecord>();
                long streamLen = stream.Length;
                if (streamLen < 512) return records;

                stream.Position = 0;
                byte[] header = new byte[FileHeaderSize];
                int hRead = stream.Read(header, 0, FileHeaderSize);

                bool hasFileHeader = (hRead >= FileHeaderSize &&
                    header[0] == 0x45 && header[1] == 0x6C && header[2] == 0x66 && header[3] == 0x46 &&
                    header[4] == 0x69 && header[5] == 0x6C && header[6] == 0x65 && header[7] == 0x00);

                if (hasFileHeader)
                {
                    stream.Position = FileHeaderSize;
                }
                else
                {
                    stream.Position = 0;
                }

                byte[] chunkBuffer = new byte[ChunkSize];
                while (stream.Position + 512 <= streamLen)
                {
                    long chunkStartPos = stream.Position;
                    int toRead = (int)Math.Min((long)ChunkSize, streamLen - chunkStartPos);
                    int bytesRead = ReadFully(stream, chunkBuffer, 0, toRead);
                    if (bytesRead < 512) break;

                    bool isChunk = chunkBuffer[0] == 0x45 && chunkBuffer[1] == 0x6C &&
                                   chunkBuffer[2] == 0x66 && chunkBuffer[3] == 0x43 &&
                                   chunkBuffer[4] == 0x68 && chunkBuffer[5] == 0x6E &&
                                   chunkBuffer[6] == 0x6B && chunkBuffer[7] == 0x00;

                    if (isChunk)
                    {
                        ParseChunk(chunkBuffer, 0, bytesRead, records);
                        if (bytesRead < ChunkSize) break;
                    }
                    else
                    {
                        long nextPos = chunkStartPos + 512;
                        if (nextPos >= streamLen) break;
                        stream.Position = nextPos;
                    }
                }
                return records;
            }
            else
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    byte[] temp = new byte[65536];
                    int bytesRead;
                    while ((bytesRead = stream.Read(temp, 0, temp.Length)) > 0)
                    {
                        ms.Write(temp, 0, bytesRead);
                        if (ms.Length > 64 * 1024 * 1024) break;
                    }
                    return Parse(ms.ToArray());
                }
            }
        }

        private static int ReadFully(Stream stream, byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int r = stream.Read(buffer, offset + total, count - total);
                if (r <= 0) break;
                total += r;
            }
            return total;
        }

        public static List<EvtxRecord> Parse(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            List<EvtxRecord> records = new List<EvtxRecord>();
            if (buffer.Length < 512) return records;

            int chunkStart = 0;

            // Check for ElfFile\0 file header
            if (buffer.Length >= FileHeaderSize &&
                buffer[0] == 0x45 && buffer[1] == 0x6C && buffer[2] == 0x66 && buffer[3] == 0x46 &&
                buffer[4] == 0x69 && buffer[5] == 0x6C && buffer[6] == 0x65 && buffer[7] == 0x00)
            {
                chunkStart = FileHeaderSize;
            }

            while (chunkStart + 512 <= buffer.Length)
            {
                int currentChunkSize = Math.Min(ChunkSize, buffer.Length - chunkStart);

                // Check for ElfChnk\0 signature
                bool isChunk = buffer[chunkStart] == 0x45 && buffer[chunkStart + 1] == 0x6C &&
                               buffer[chunkStart + 2] == 0x66 && buffer[chunkStart + 3] == 0x43 &&
                               buffer[chunkStart + 4] == 0x68 && buffer[chunkStart + 5] == 0x6E &&
                               buffer[chunkStart + 6] == 0x6B && buffer[chunkStart + 7] == 0x00;

                if (isChunk)
                {
                    ParseChunk(buffer, chunkStart, currentChunkSize, records);
                    chunkStart += ChunkSize;
                }
                else
                {
                    chunkStart += 512;
                }
            }

            return records;
        }

        private static void ParseChunk(byte[] buffer, int chunkOffset, int chunkSize, List<EvtxRecord> records)
        {
            if (chunkSize < 512) return;

            uint freeSpaceOffset = BitConverter.ToUInt32(buffer, chunkOffset + 48);
            if (freeSpaceOffset < 512 || freeSpaceOffset > chunkSize)
            {
                freeSpaceOffset = (uint)chunkSize;
            }

            Dictionary<uint, BinXmlTemplate> templateCache = new Dictionary<uint, BinXmlTemplate>();

            // Parse allocated event records starting at offset 512
            int cursor = chunkOffset + 512;
            int allocatedEnd = chunkOffset + (int)freeSpaceOffset;

            while (cursor + 24 <= allocatedEnd)
            {
                uint magic = BitConverter.ToUInt32(buffer, cursor);
                if (magic != RecordMagic)
                {
                    cursor += 4;
                    continue;
                }

                uint recordSize = BitConverter.ToUInt32(buffer, cursor + 4);
                if (recordSize < 28 || cursor + recordSize > chunkOffset + chunkSize)
                {
                    cursor += 4;
                    continue;
                }

                uint trailingSize = BitConverter.ToUInt32(buffer, cursor + (int)recordSize - 4);
                if (trailingSize != recordSize)
                {
                    cursor += 4;
                    continue;
                }

                EvtxRecord record = ParseRecord(buffer, cursor, (int)recordSize, chunkOffset, templateCache);
                if (record != null)
                {
                    records.Add(record);
                }

                cursor += (int)recordSize;
            }

            // Slack-space carving: scan remainder of chunk up to chunkSize for residual deleted records
            int slackCursor = allocatedEnd;
            int chunkLimit = chunkOffset + chunkSize;

            while (slackCursor + 28 <= chunkLimit)
            {
                uint magic = BitConverter.ToUInt32(buffer, slackCursor);
                if (magic == RecordMagic)
                {
                    uint recordSize = BitConverter.ToUInt32(buffer, slackCursor + 4);
                    if (recordSize >= 28 && slackCursor + recordSize <= chunkLimit)
                    {
                        uint trailingSize = BitConverter.ToUInt32(buffer, slackCursor + (int)recordSize - 4);
                        if (trailingSize == recordSize)
                        {
                            EvtxRecord record = ParseRecord(buffer, slackCursor, (int)recordSize, chunkOffset, templateCache);
                            if (record != null)
                            {
                                records.Add(record);
                            }
                            slackCursor += (int)recordSize;
                            continue;
                        }
                    }
                }
                slackCursor += 4;
            }
        }

        private static EvtxRecord ParseRecord(byte[] buffer, int offset, int size, int chunkOffset, Dictionary<uint, BinXmlTemplate> templateCache)
        {
            try
            {
                long recordId = BitConverter.ToInt64(buffer, offset + 8);
                long fileTime = BitConverter.ToInt64(buffer, offset + 16);

                DateTime timestampUtc;
                try
                {
                    timestampUtc = (fileTime > 0) ? DateTime.FromFileTimeUtc(fileTime) : DateTime.MinValue;
                }
                catch
                {
                    timestampUtc = DateTime.MinValue;
                }

                EvtxRecord record = new EvtxRecord();
                record.RecordId = recordId;
                record.TimestampUtc = timestampUtc;

                // BinXml payload starts at offset + 24 and extends to offset + size - 4
                int binXmlOffset = offset + 24;
                int binXmlLength = size - 28;

                if (binXmlLength > 0 && binXmlOffset + binXmlLength <= buffer.Length)
                {
                    BinXmlDecoder.Decode(buffer, binXmlOffset, binXmlLength, chunkOffset, templateCache, record);
                }

                return record;
            }
            catch
            {
                return null;
            }
        }
    }

    public sealed class BinXmlTemplate
    {
        public uint TemplateId { get; set; }
        public uint DataLength { get; set; }
        public byte[] TokenStream { get; set; }
    }

    public static class BinXmlDecoder
    {
        public static void Decode(byte[] buffer, int offset, int length, int chunkOffset, Dictionary<uint, BinXmlTemplate> templateCache, EvtxRecord record)
        {
            if (buffer == null || length <= 0 || offset + length > buffer.Length) return;

            int cursor = offset;
            int end = offset + length;

            // Optional FragmentHeader check: 0x0F 0x01 0x01 0x00
            if (cursor < end && buffer[cursor] == 0x0F)
            {
                cursor += 4; // skip fragment header
            }

            StringBuilder xmlBuilder = new StringBuilder();

            while (cursor < end)
            {
                byte token = buffer[cursor];

                if (token == 0x00) // EOF
                {
                    break;
                }
                else if (token == 0x0C) // TemplateInstanceToken
                {
                    cursor++;
                    if (cursor >= end) break;

                    byte templateHeader = buffer[cursor++];
                    if (cursor + 4 > end) break;
                    uint templateOffsetVal = BitConverter.ToUInt32(buffer, cursor);
                    cursor += 4;

                    BinXmlTemplate templateDef = null;
                    if (templateHeader == 0x01) // Inline template definition
                    {
                        if (cursor + 8 > end) break;
                        uint tmplId = BitConverter.ToUInt32(buffer, cursor);
                        uint tmplLen = BitConverter.ToUInt32(buffer, cursor + 4);
                        cursor += 8;

                        if (cursor + tmplLen <= end)
                        {
                            byte[] tmplTokens = new byte[tmplLen];
                            Buffer.BlockCopy(buffer, cursor, tmplTokens, 0, (int)tmplLen);
                            cursor += (int)tmplLen;

                            templateDef = new BinXmlTemplate();
                            templateDef.TemplateId = tmplId;
                            templateDef.DataLength = tmplLen;
                            templateDef.TokenStream = tmplTokens;

                            templateCache[templateOffsetVal] = templateDef;
                        }
                    }
                    else
                    {
                        if (templateCache.ContainsKey(templateOffsetVal))
                        {
                            templateDef = templateCache[templateOffsetVal];
                        }
                    }

                    // Parse substitution array
                    if (cursor + 4 <= end)
                    {
                        uint valueCount = BitConverter.ToUInt32(buffer, cursor);
                        cursor += 4;

                        List<SubstitutionValue> values = ParseSubstitutionValues(buffer, ref cursor, end, (int)valueCount);

                        if (templateDef != null && templateDef.TokenStream != null)
                        {
                            ExpandTemplate(templateDef.TokenStream, values, xmlBuilder, record);
                        }
                    }
                    break;
                }
                else if (token == 0x01 || (token & 0x0F) == 0x01) // OpenStartElement
                {
                    cursor++;
                    if (cursor + 6 <= end)
                    {
                        cursor += 2; // skip depId
                        uint elemLen = BitConverter.ToUInt32(buffer, cursor);
                        cursor += 4;
                        string elemName = ReadString(buffer, ref cursor, end);
                        xmlBuilder.Append("<").Append(elemName).Append(">");
                    }
                    else
                    {
                        break;
                    }
                }
                else if (token == 0x04) // EndElement
                {
                    cursor++;
                    xmlBuilder.Append("</Element>");
                }
                else
                {
                    cursor++;
                }
            }

            record.XmlContent = xmlBuilder.ToString();
        }

        private sealed class SubstitutionValue
        {
            public ushort ValueType { get; set; }
            public string Formatted { get; set; }
        }

        private static List<SubstitutionValue> ParseSubstitutionValues(byte[] buffer, ref int cursor, int end, int count)
        {
            List<SubstitutionValue> result = new List<SubstitutionValue>();
            if (count <= 0 || cursor >= end) return result;

            ushort[] types = new ushort[count];
            ushort[] sizes = new ushort[count];

            for (int i = 0; i < count; i++)
            {
                if (cursor + 4 > end) return result;
                types[i] = BitConverter.ToUInt16(buffer, cursor);
                sizes[i] = BitConverter.ToUInt16(buffer, cursor + 2);
                cursor += 4;
            }

            for (int i = 0; i < count; i++)
            {
                SubstitutionValue sv = new SubstitutionValue();
                sv.ValueType = types[i];
                int sz = sizes[i];

                if (cursor + sz > end)
                {
                    sv.Formatted = String.Empty;
                    result.Add(sv);
                    continue;
                }

                sv.Formatted = FormatValue(buffer, cursor, sz, types[i]);
                cursor += sz;
                result.Add(sv);
            }

            return result;
        }

        private static string FormatValue(byte[] buffer, int offset, int size, ushort type)
        {
            if (size <= 0) return String.Empty;

            try
            {
                switch (type)
                {
                    case 0x00: // Null
                        return String.Empty;

                    case 0x01: // Unicode string
                        string ustr = Encoding.Unicode.GetString(buffer, offset, size);
                        int nullIdx = ustr.IndexOf('\0');
                        return (nullIdx >= 0) ? ustr.Substring(0, nullIdx) : ustr;

                    case 0x02: // Ansi string
                        string astr = Encoding.ASCII.GetString(buffer, offset, size);
                        int aNullIdx = astr.IndexOf('\0');
                        return (aNullIdx >= 0) ? astr.Substring(0, aNullIdx) : astr;

                    case 0x03: // Int8
                        return ((sbyte)buffer[offset]).ToString();

                    case 0x04: // UInt8
                        return buffer[offset].ToString();

                    case 0x05: // Int16
                        return BitConverter.ToInt16(buffer, offset).ToString();

                    case 0x06: // UInt16
                        return BitConverter.ToUInt16(buffer, offset).ToString();

                    case 0x07: // Int32
                        return BitConverter.ToInt32(buffer, offset).ToString();

                    case 0x08: // UInt32
                        return BitConverter.ToUInt32(buffer, offset).ToString();

                    case 0x09: // Int64
                        return BitConverter.ToInt64(buffer, offset).ToString();

                    case 0x0A: // UInt64
                        return BitConverter.ToUInt64(buffer, offset).ToString();

                    case 0x0B: // Float
                        return BitConverter.ToSingle(buffer, offset).ToString();

                    case 0x0C: // Double
                        return BitConverter.ToDouble(buffer, offset).ToString();

                    case 0x0D: // Boolean
                        return (BitConverter.ToUInt32(buffer, offset) != 0) ? "true" : "false";

                    case 0x0E: // Binary
                        StringBuilder hex = new StringBuilder(size * 2);
                        for (int i = 0; i < size; i++) hex.Append(buffer[offset + i].ToString("X2"));
                        return hex.ToString();

                    case 0x0F: // Guid
                        byte[] guidBytes = new byte[16];
                        Buffer.BlockCopy(buffer, offset, guidBytes, 0, Math.Min(16, size));
                        return new Guid(guidBytes).ToString();

                    case 0x11: // FileTime
                        long ft = BitConverter.ToInt64(buffer, offset);
                        return (ft > 0) ? DateTime.FromFileTimeUtc(ft).ToString("o") : String.Empty;

                    case 0x13: // SID
                        return FormatSid(buffer, offset, size);

                    case 0x14: // Hex32
                        return "0x" + BitConverter.ToUInt32(buffer, offset).ToString("X");

                    case 0x15: // Hex64
                        return "0x" + BitConverter.ToUInt64(buffer, offset).ToString("X");

                    default:
                        return Encoding.ASCII.GetString(buffer, offset, size).TrimEnd('\0');
                }
            }
            catch
            {
                return String.Empty;
            }
        }

        private static string FormatSid(byte[] buffer, int offset, int size)
        {
            if (size < 8) return String.Empty;
            byte revision = buffer[offset];
            byte subAuthCount = buffer[offset + 1];
            if (size < 8 + subAuthCount * 4) return String.Empty;

            long authority = 0;
            for (int i = 0; i < 6; i++)
            {
                authority = (authority << 8) | buffer[offset + 2 + i];
            }

            StringBuilder sb = new StringBuilder();
            sb.Append("S-").Append(revision).Append("-").Append(authority);

            for (int i = 0; i < subAuthCount; i++)
            {
                uint subAuth = BitConverter.ToUInt32(buffer, offset + 8 + i * 4);
                sb.Append("-").Append(subAuth);
            }

            return sb.ToString();
        }

        private static void ExpandTemplate(byte[] tokens, List<SubstitutionValue> values, StringBuilder xml, EvtxRecord record)
        {
            int cursor = 0;
            int length = tokens.Length;
            Stack<string> openElements = new Stack<string>();
            string currentElement = String.Empty;
            string currentAttribute = String.Empty;
            string lastDataName = String.Empty;

            while (cursor < length)
            {
                byte token = tokens[cursor++];

                if (token == 0x00) // EOF
                {
                    break;
                }
                else if (token == 0x01 || (token & 0x0F) == 0x01) // OpenStartElement
                {
                    if (cursor + 6 <= length)
                    {
                        cursor += 2; // depId
                        uint elemLen = BitConverter.ToUInt32(tokens, cursor);
                        cursor += 4;
                        string elemName = ReadString(tokens, ref cursor, length);
                        currentElement = elemName;
                        currentAttribute = String.Empty;
                        openElements.Push(elemName);
                        xml.Append("<").Append(elemName);
                    }
                }
                else if (token == 0x02) // CloseStartElement
                {
                    if (!String.IsNullOrEmpty(currentAttribute))
                    {
                        xml.Append("\"");
                        currentAttribute = String.Empty;
                    }
                    xml.Append(">");
                }
                else if (token == 0x03) // CloseEmptyElement
                {
                    if (!String.IsNullOrEmpty(currentAttribute))
                    {
                        xml.Append("\"");
                        currentAttribute = String.Empty;
                    }
                    xml.Append("/>");
                    if (openElements.Count > 0) openElements.Pop();
                }
                else if (token == 0x04) // EndElement
                {
                    string elem = (openElements.Count > 0) ? openElements.Pop() : "Element";
                    xml.Append("</").Append(elem).Append(">");
                    currentElement = (openElements.Count > 0) ? openElements.Peek() : String.Empty;
                }
                else if (token == 0x05) // ValueText
                {
                    if (cursor < length)
                    {
                        byte valType = tokens[cursor++];
                        string text = ReadString(tokens, ref cursor, length);
                        xml.Append(text);
                        if (String.Equals(currentElement, "Data", StringComparison.OrdinalIgnoreCase) &&
                            String.Equals(currentAttribute, "Name", StringComparison.OrdinalIgnoreCase))
                        {
                            lastDataName = text;
                        }
                    }
                }
                else if (token == 0x06) // Attribute
                {
                    if (!String.IsNullOrEmpty(currentAttribute))
                    {
                        xml.Append("\"");
                    }
                    string attrName = ReadString(tokens, ref cursor, length);
                    currentAttribute = attrName;
                    xml.Append(" ").Append(attrName).Append("=\"");
                }
                else if (token == 0x0D || token == 0x0E) // NormalSubstitution or OptionalSubstitution
                {
                    if (cursor + 2 <= length)
                    {
                        ushort index = BitConverter.ToUInt16(tokens, cursor);
                        cursor += 2;
                        byte valType = (cursor < length) ? tokens[cursor++] : (byte)0;

                        string valStr = (index < values.Count) ? values[index].Formatted : String.Empty;
                        xml.Append(valStr);

                        // Extract core properties into EvtxRecord
                        if (!String.IsNullOrEmpty(valStr))
                        {
                            if (!String.IsNullOrEmpty(lastDataName))
                            {
                                record.Properties[lastDataName] = valStr;
                                lastDataName = String.Empty;
                            }
                            else if (String.Equals(currentElement, "EventID", StringComparison.OrdinalIgnoreCase))
                            {
                                int eid;
                                if (Int32.TryParse(valStr, out eid)) record.EventId = eid;
                            }
                            else if (String.Equals(currentElement, "Channel", StringComparison.OrdinalIgnoreCase))
                            {
                                record.Channel = valStr;
                            }
                            else if (String.Equals(currentElement, "Computer", StringComparison.OrdinalIgnoreCase))
                            {
                                record.ComputerName = valStr;
                            }
                            else if (String.Equals(currentAttribute, "Name", StringComparison.OrdinalIgnoreCase) &&
                                     String.Equals(currentElement, "Provider", StringComparison.OrdinalIgnoreCase))
                            {
                                record.ProviderName = valStr;
                            }
                            else if (!String.IsNullOrEmpty(currentAttribute))
                            {
                                record.Properties[currentAttribute] = valStr;
                            }
                            else if (!String.IsNullOrEmpty(currentElement))
                            {
                                record.Properties[currentElement] = valStr;
                            }
                        }
                    }
                }
                else
                {
                    // Skip unrecognized token
                }
            }

            while (openElements.Count > 0)
            {
                xml.Append("</").Append(openElements.Pop()).Append(">");
            }
        }

        private static string ReadString(byte[] buffer, ref int cursor, int end)
        {
            if (cursor + 4 > end) return String.Empty;
            ushort hash = BitConverter.ToUInt16(buffer, cursor);
            ushort charLen = BitConverter.ToUInt16(buffer, cursor + 2);
            cursor += 4;

            int byteLen = charLen * 2;
            if (cursor + byteLen > end) byteLen = end - cursor;

            string s = Encoding.Unicode.GetString(buffer, cursor, byteLen);
            cursor += byteLen;
            if (cursor + 2 <= end && buffer[cursor] == 0 && buffer[cursor + 1] == 0)
            {
                cursor += 2; // skip null terminator
            }

            return s;
        }
    }
}
