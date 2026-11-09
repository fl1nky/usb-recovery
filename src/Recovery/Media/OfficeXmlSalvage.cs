using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    public enum OfficeDocumentKind
    {
        Unknown = 0,
        WordDocx = 1,
        ExcelXlsx = 2,
        PowerPointPptx = 3,
        OpenDocumentText = 4,
        OpenDocumentSpreadsheet = 5
    }

    public sealed class OfficeSalvagePart
    {
        public string PartName { get; set; }
        public byte[] Data { get; set; }
        public bool TruncatedOrRepaired { get; set; }
        public string ContentType { get; set; }

        public OfficeSalvagePart()
        {
            PartName = String.Empty;
            Data = new byte[0];
            ContentType = "application/xml";
        }

        public OfficeSalvagePart(string name, byte[] data, bool repaired, string contentType)
        {
            PartName = name ?? String.Empty;
            Data = data ?? new byte[0];
            TruncatedOrRepaired = repaired;
            ContentType = contentType ?? "application/xml";
        }
    }

    public sealed class OfficeSalvageResult
    {
        public OfficeDocumentKind Kind { get; set; }
        public string DetectedTypeName { get; set; }
        public List<OfficeSalvagePart> Parts { get; set; }
        public string ExtractedText { get; set; }
        public byte[] ReconstructedPackage { get; set; }
        public int PartsRecovered { get { return Parts != null ? Parts.Count : 0; } }
        public bool HasRepairedXml { get; set; }
        public string PrimaryTextSummary { get; set; }

        public OfficeSalvageResult()
        {
            Kind = OfficeDocumentKind.Unknown;
            DetectedTypeName = "Unknown Document";
            Parts = new List<OfficeSalvagePart>();
            ExtractedText = String.Empty;
            ReconstructedPackage = new byte[0];
            PrimaryTextSummary = String.Empty;
        }
    }

    // High-precision carver and reconstructor for damaged Office Open XML
    // (DOCX, XLSX, PPTX) and OpenDocument (ODT, ODS) files.
    // Handles missing Central Directory, severed ZIP structures, truncated Deflate
    // streams, and malformed/unclosed XML tag trees.
    public static class OfficeXmlSalvage
    {
        private static readonly Encoding Utf8Encoding = new UTF8Encoding(false, false);
        private static readonly uint[] Crc32Table = MakeCrcTable();

        private static uint[] MakeCrcTable()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int j = 0; j < 8; j++)
                {
                    if ((c & 1) != 0) c = 0xEDB88320u ^ (c >> 1);
                    else c >>= 1;
                }
                table[i] = c;
            }
            return table;
        }

        public static uint ComputeCrc32(byte[] data, int offset, int length)
        {
            if (data == null || length <= 0) return 0;
            uint crc = 0xFFFFFFFFu;
            int end = offset + length;
            for (int i = offset; i < end; i++)
            {
                crc = Crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFFu;
        }

        public static OfficeSalvageResult SalvageFromBytes(byte[] buffer)
        {
            if (buffer == null || buffer.Length < 30)
            {
                return new OfficeSalvageResult();
            }

            using (MemoryStream ms = new MemoryStream(buffer, false))
            {
                return SalvageFromStream(ms, 0, buffer.Length);
            }
        }

        public static OfficeSalvageResult SalvageFromStream(Stream stream, long startOffset, long maxSpan)
        {
            OfficeSalvageResult result = new OfficeSalvageResult();
            if (stream == null || !stream.CanRead) return result;

            long streamLength = stream.Length;
            long endOffset = Math.Min(streamLength, startOffset + maxSpan);
            long searchLimit = Math.Max(0, endOffset - 30);

            // Scan for local ZIP headers: PK\x03\x04 (0x04034B50)
            List<OfficeSalvagePart> discoveredParts = new List<OfficeSalvagePart>();
            byte[] block = new byte[65536];
            long currentPos = startOffset;

            while (currentPos < searchLimit)
            {
                stream.Position = currentPos;
                int bytesRead = stream.Read(block, 0, (int)Math.Min(block.Length, searchLimit - currentPos + 30));
                if (bytesRead < 30) break;

                int scanLen = bytesRead - 29;
                for (int i = 0; i < scanLen; i++)
                {
                    if (block[i] == 0x50 && block[i + 1] == 0x4B && block[i + 2] == 0x03 && block[i + 3] == 0x04)
                    {
                        long headerOffset = currentPos + i;
                        OfficeSalvagePart part;
                        long nextOffset;
                        if (TryExtractPart(stream, headerOffset, endOffset, out part, out nextOffset))
                        {
                            if (part != null && !String.IsNullOrEmpty(part.PartName))
                            {
                                discoveredParts.Add(part);
                            }
                            if (nextOffset > currentPos + i)
                            {
                                int advance = (int)(nextOffset - (currentPos + i));
                                i += Math.Max(0, advance - 1);
                            }
                        }
                    }
                }
                currentPos += Math.Max(1, bytesRead - 32);
            }

            if (discoveredParts.Count == 0) return result;

            result.Parts = discoveredParts;
            result.Kind = DetectKind(discoveredParts);
            result.DetectedTypeName = GetKindDisplayName(result.Kind);

            // Sanitize / repair XML parts if corrupted or truncated
            foreach (OfficeSalvagePart p in result.Parts)
            {
                if (p.PartName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
                    p.PartName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                {
                    bool wasRepaired;
                    byte[] repaired = RepairAndBalanceXml(p.Data, out wasRepaired);
                    if (wasRepaired)
                    {
                        p.Data = repaired;
                        p.TruncatedOrRepaired = true;
                        result.HasRepairedXml = true;
                    }
                }
            }

            // Extract plain text content
            result.ExtractedText = ExtractPlainText(result.Kind, result.Parts);
            if (!String.IsNullOrEmpty(result.ExtractedText))
            {
                result.PrimaryTextSummary = result.ExtractedText.Length > 200
                    ? result.ExtractedText.Substring(0, 200).Trim() + "..."
                    : result.ExtractedText.Trim();
            }

            // Build reconstructed, healthy ZIP container
            result.ReconstructedPackage = BuildRepairedZipPackage(result.Kind, result.Parts);

            return result;
        }

        private static bool TryExtractPart(Stream stream, long headerOffset, long maxBound, out OfficeSalvagePart part, out long nextOffset)
        {
            part = null;
            nextOffset = headerOffset + 30;

            if (headerOffset + 30 > maxBound) return false;

            byte[] hdr = new byte[30];
            stream.Position = headerOffset;
            int r = stream.Read(hdr, 0, 30);
            if (r < 30) return false;

            ushort compressionMethod = BitConverter.ToUInt16(hdr, 8);
            uint compressedSize = BitConverter.ToUInt32(hdr, 18);
            uint uncompressedSize = BitConverter.ToUInt32(hdr, 22);
            ushort fileNameLen = BitConverter.ToUInt16(hdr, 26);
            ushort extraLen = BitConverter.ToUInt16(hdr, 28);

            if (fileNameLen == 0 || fileNameLen > 1024) return false;
            if (headerOffset + 30 + fileNameLen + extraLen > maxBound) return false;

            byte[] nameBytes = new byte[fileNameLen];
            stream.Position = headerOffset + 30;
            if (stream.Read(nameBytes, 0, fileNameLen) < fileNameLen) return false;

            string partName = Utf8Encoding.GetString(nameBytes).Replace('\\', '/');
            if (String.IsNullOrEmpty(partName) || partName.IndexOf('\0') >= 0) return false;

            // Only recognize relevant Office / XML / Media / Rel parts
            if (!IsLikelyOfficePartName(partName)) return false;

            long dataOffset = headerOffset + 30 + fileNameLen + extraLen;
            long dataLimit = maxBound - dataOffset;
            if (dataLimit <= 0) return false;

            byte[] uncompressedData = null;
            bool wasTruncated = false;

            if (compressionMethod == 0) // Stored
            {
                long size = compressedSize > 0 ? Math.Min(compressedSize, dataLimit) : Math.Min(uncompressedSize, dataLimit);
                if (size > 32 * 1024 * 1024) size = 32 * 1024 * 1024;
                uncompressedData = new byte[size];
                stream.Position = dataOffset;
                int readBytes = stream.Read(uncompressedData, 0, (int)size);
                if (readBytes < size)
                {
                    byte[] truncated = new byte[readBytes];
                    Array.Copy(uncompressedData, truncated, readBytes);
                    uncompressedData = truncated;
                    wasTruncated = true;
                }
                nextOffset = dataOffset + readBytes;
            }
            else if (compressionMethod == 8) // Deflated
            {
                long deflatedSpan = compressedSize > 0 ? Math.Min(compressedSize, dataLimit) : Math.Min(dataLimit, 16 * 1024 * 1024);
                byte[] rawDeflated = new byte[deflatedSpan];
                stream.Position = dataOffset;
                int readSpan = stream.Read(rawDeflated, 0, (int)deflatedSpan);

                uncompressedData = ResilientDeflateDecompress(rawDeflated, readSpan, out wasTruncated);
                nextOffset = dataOffset + (compressedSize > 0 ? (long)compressedSize : (long)readSpan);
            }
            else
            {
                return false;
            }

            if (uncompressedData == null || uncompressedData.Length == 0) return false;

            string contentType = DetermineContentType(partName);
            part = new OfficeSalvagePart(partName, uncompressedData, wasTruncated, contentType);
            return true;
        }

        private static bool IsLikelyOfficePartName(string name)
        {
            if (String.IsNullOrEmpty(name)) return false;
            string lower = name.ToLowerInvariant();

            return lower.StartsWith("word/") ||
                   lower.StartsWith("xl/") ||
                   lower.StartsWith("ppt/") ||
                   lower.StartsWith("_rels/") ||
                   lower.StartsWith("docprops/") ||
                   lower.StartsWith("customxml/") ||
                   lower == "[content_types].xml" ||
                   lower == "mimetype" ||
                   lower == "content.xml" ||
                   lower == "meta.xml" ||
                   lower == "styles.xml" ||
                   lower == "settings.xml" ||
                   lower == "manifest.rdf" ||
                   lower.StartsWith("meta-inf/");
        }

        private static string DetermineContentType(string partName)
        {
            string lower = partName.ToLowerInvariant();
            if (lower == "[content_types].xml") return "application/xml";
            if (lower.EndsWith(".rels")) return "application/vnd.openxmlformats-package.relationships+xml";
            if (lower == "word/document.xml") return "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
            if (lower == "word/styles.xml") return "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml";
            if (lower == "word/settings.xml") return "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml";
            if (lower == "xl/workbook.xml") return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
            if (lower.StartsWith("xl/worksheets/sheet")) return "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
            if (lower == "xl/sharedstrings.xml") return "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml";
            if (lower == "ppt/presentation.xml") return "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml";
            if (lower.StartsWith("ppt/slides/slide")) return "application/vnd.openxmlformats-officedocument.presentationml.slide+xml";
            if (lower.EndsWith(".png")) return "image/png";
            if (lower.EndsWith(".jpeg") || lower.EndsWith(".jpg")) return "image/jpeg";
            return "application/xml";
        }

        private static byte[] ResilientDeflateDecompress(byte[] compressed, int length, out bool truncated)
        {
            truncated = false;
            if (compressed == null || length <= 0) return new byte[0];

            using (MemoryStream src = new MemoryStream(compressed, 0, length, false))
            using (DeflateStream deflate = new DeflateStream(src, CompressionMode.Decompress))
            using (MemoryStream dest = new MemoryStream())
            {
                byte[] chunk = new byte[8192];
                try
                {
                    int r;
                    while ((r = deflate.Read(chunk, 0, chunk.Length)) > 0)
                    {
                        dest.Write(chunk, 0, r);
                        if (dest.Length > 64 * 1024 * 1024) break; // sanity limit
                    }
                }
                catch (Exception)
                {
                    // Deflate stream was clipped or corrupted at the end
                    truncated = true;
                }

                return dest.ToArray();
            }
        }

        public static OfficeDocumentKind DetectKind(IEnumerable<OfficeSalvagePart> parts)
        {
            if (parts == null) return OfficeDocumentKind.Unknown;

            bool hasWord = false;
            bool hasExcel = false;
            bool hasPowerPoint = false;
            bool hasOdt = false;
            bool hasOds = false;

            foreach (OfficeSalvagePart part in parts)
            {
                string name = part.PartName.ToLowerInvariant();
                if (name.StartsWith("word/")) hasWord = true;
                if (name.StartsWith("xl/")) hasExcel = true;
                if (name.StartsWith("ppt/")) hasPowerPoint = true;

                if (name == "mimetype" && part.Data != null)
                {
                    string mime = Utf8Encoding.GetString(part.Data).Trim();
                    if (mime.IndexOf("opendocument.text", StringComparison.OrdinalIgnoreCase) >= 0) hasOdt = true;
                    if (mime.IndexOf("opendocument.spreadsheet", StringComparison.OrdinalIgnoreCase) >= 0) hasOds = true;
                }
                if (name == "content.xml")
                {
                    string contentXml = Utf8Encoding.GetString(part.Data);
                    if (contentXml.IndexOf("office:spreadsheet", StringComparison.OrdinalIgnoreCase) >= 0) hasOds = true;
                    else if (contentXml.IndexOf("office:text", StringComparison.OrdinalIgnoreCase) >= 0) hasOdt = true;
                }
            }

            if (hasWord) return OfficeDocumentKind.WordDocx;
            if (hasExcel) return OfficeDocumentKind.ExcelXlsx;
            if (hasPowerPoint) return OfficeDocumentKind.PowerPointPptx;
            if (hasOdt) return OfficeDocumentKind.OpenDocumentText;
            if (hasOds) return OfficeDocumentKind.OpenDocumentSpreadsheet;

            return OfficeDocumentKind.Unknown;
        }

        public static string GetKindDisplayName(OfficeDocumentKind kind)
        {
            switch (kind)
            {
                case OfficeDocumentKind.WordDocx: return "Microsoft Word (.docx)";
                case OfficeDocumentKind.ExcelXlsx: return "Microsoft Excel (.xlsx)";
                case OfficeDocumentKind.PowerPointPptx: return "Microsoft PowerPoint (.pptx)";
                case OfficeDocumentKind.OpenDocumentText: return "OpenDocument Text (.odt)";
                case OfficeDocumentKind.OpenDocumentSpreadsheet: return "OpenDocument Spreadsheet (.ods)";
                default: return "Unknown Office Document";
            }
        }

        // Repairs broken XML streams caused by truncation or corruption.
        // Strips partial trailing tags, closes unclosed XML elements in reverse order,
        // and guarantees well-formedness for standard XML parsers.
        public static byte[] RepairAndBalanceXml(byte[] rawXmlBytes, out bool wasRepaired)
        {
            wasRepaired = false;
            if (rawXmlBytes == null || rawXmlBytes.Length == 0) return new byte[0];

            string text = Utf8Encoding.GetString(rawXmlBytes);
            if (String.IsNullOrEmpty(text)) return new byte[0];

            // 1. Check if there is an unclosed trailing tag '<...' without '>' at the end
            int lastClose = text.LastIndexOf('>');
            int lastOpen = text.LastIndexOf('<');
            if (lastOpen == -1 && lastClose == -1)
            {
                wasRepaired = true;
                return Utf8Encoding.GetBytes("<root>" + System.Security.SecurityElement.Escape(text) + "</root>");
            }
            if (lastOpen > lastClose)
            {
                // Trailing unclosed tag at the end (e.g. "<w:t>Hello<w:"): strip the partial tag
                text = text.Substring(0, lastOpen);
                wasRepaired = true;
            }

            // 2. Track open elements using a tag stack
            Stack<string> openTags = new Stack<string>();
            int pos = 0;
            int length = text.Length;

            while (pos < length)
            {
                int openIdx = text.IndexOf('<', pos);
                if (openIdx == -1) break;

                int closeIdx = text.IndexOf('>', openIdx);
                if (closeIdx == -1)
                {
                    // Truncated tag at the end: strip it
                    text = text.Substring(0, openIdx);
                    wasRepaired = true;
                    break;
                }

                string tagContent = text.Substring(openIdx + 1, closeIdx - openIdx - 1).Trim();
                pos = closeIdx + 1;

                // Skip processing instructions <?xml ... ?>, comments <!-- ... -->, CDATA
                if (tagContent.StartsWith("?") || tagContent.StartsWith("!--") || tagContent.StartsWith("!DOCTYPE"))
                {
                    continue;
                }

                // Self-closing tag <tag ... />
                if (tagContent.EndsWith("/"))
                {
                    continue;
                }

                // Closing tag </tag>
                if (tagContent.StartsWith("/"))
                {
                    string closeTagName = tagContent.Substring(1).Trim();
                    int spaceIdx = closeTagName.IndexOfAny(new[] { ' ', '\t', '\r', '\n' });
                    if (spaceIdx > 0) closeTagName = closeTagName.Substring(0, spaceIdx);

                    if (openTags.Count > 0 && openTags.Peek().Equals(closeTagName, StringComparison.OrdinalIgnoreCase))
                    {
                        openTags.Pop();
                    }
                    continue;
                }

                // Opening tag <tag attr="val">
                int spaceIndex = tagContent.IndexOfAny(new[] { ' ', '\t', '\r', '\n' });
                string tagName = spaceIndex > 0 ? tagContent.Substring(0, spaceIndex) : tagContent;
                if (!String.IsNullOrEmpty(tagName) && !tagName.StartsWith("!"))
                {
                    openTags.Push(tagName);
                }
            }

            // 3. Close remaining open tags in reverse order
            if (openTags.Count > 0)
            {
                wasRepaired = true;
                StringBuilder closer = new StringBuilder();
                while (openTags.Count > 0)
                {
                    string tagToClose = openTags.Pop();
                    closer.Append("</").Append(tagToClose).Append(">");
                }
                text += closer.ToString();
            }

            return Utf8Encoding.GetBytes(text);
        }

        // Deep plain-text extraction from office parts.
        // Pulls legible text even from severely mangled documents where XML is incomplete.
        public static string ExtractPlainText(OfficeDocumentKind kind, IEnumerable<OfficeSalvagePart> parts)
        {
            if (parts == null) return String.Empty;

            StringBuilder sb = new StringBuilder();

            if (kind == OfficeDocumentKind.WordDocx)
            {
                foreach (OfficeSalvagePart part in parts)
                {
                    string lower = part.PartName.ToLowerInvariant();
                    if (lower == "word/document.xml" || lower.StartsWith("word/header") || lower.StartsWith("word/footer"))
                    {
                        string xml = Utf8Encoding.GetString(part.Data);
                        AppendWordText(sb, xml);
                    }
                }
            }
            else if (kind == OfficeDocumentKind.ExcelXlsx)
            {
                // In XLSX, text is primarily in sharedStrings.xml, while numbers/formulas are in sheet*.xml
                foreach (OfficeSalvagePart part in parts)
                {
                    string lower = part.PartName.ToLowerInvariant();
                    if (lower == "xl/sharedstrings.xml")
                    {
                        string xml = Utf8Encoding.GetString(part.Data);
                        AppendSharedStringsText(sb, xml);
                    }
                }
                foreach (OfficeSalvagePart part in parts)
                {
                    string lower = part.PartName.ToLowerInvariant();
                    if (lower.StartsWith("xl/worksheets/sheet"))
                    {
                        string xml = Utf8Encoding.GetString(part.Data);
                        AppendSheetValuesText(sb, xml);
                    }
                }
            }
            else if (kind == OfficeDocumentKind.PowerPointPptx)
            {
                foreach (OfficeSalvagePart part in parts)
                {
                    string lower = part.PartName.ToLowerInvariant();
                    if (lower.StartsWith("ppt/slides/slide"))
                    {
                        string xml = Utf8Encoding.GetString(part.Data);
                        AppendPowerPointText(sb, xml);
                    }
                }
            }
            else if (kind == OfficeDocumentKind.OpenDocumentText || kind == OfficeDocumentKind.OpenDocumentSpreadsheet)
            {
                foreach (OfficeSalvagePart part in parts)
                {
                    if (part.PartName.Equals("content.xml", StringComparison.OrdinalIgnoreCase))
                    {
                        string xml = Utf8Encoding.GetString(part.Data);
                        AppendOpenDocumentText(sb, xml);
                    }
                }
            }
            else
            {
                // Generic extraction from all xml parts
                foreach (OfficeSalvagePart part in parts)
                {
                    if (part.PartName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) &&
                        !part.PartName.Equals("[Content_Types].xml", StringComparison.OrdinalIgnoreCase))
                    {
                        string xml = Utf8Encoding.GetString(part.Data);
                        AppendGenericXmlText(sb, xml);
                    }
                }
            }

            return sb.ToString().Trim();
        }

        private static void AppendWordText(StringBuilder sb, string xml)
        {
            if (String.IsNullOrEmpty(xml)) return;

            // Word text is contained in <w:t> elements.
            // Paragraph breaks are signaled by </w:p>.
            // Tabs are <w:tab/>.
            // Cell breaks are </w:tc>.
            MatchCollection matches = Regex.Matches(xml, @"<w:t(?:\s+[^>]*)?>([\s\S]*?)</w:t>|<w:tab/>|</w:p>|</w:tc>");
            foreach (Match m in matches)
            {
                string val = m.Value;
                if (val == "</w:p>")
                {
                    sb.AppendLine();
                }
                else if (val == "<w:tab/>" || val == "</w:tc>")
                {
                    sb.Append("\t");
                }
                else if (m.Groups[1].Success)
                {
                    sb.Append(DecodeXmlEntities(m.Groups[1].Value));
                }
            }
        }

        private static void AppendSharedStringsText(StringBuilder sb, string xml)
        {
            if (String.IsNullOrEmpty(xml)) return;
            MatchCollection matches = Regex.Matches(xml, @"<t(?:\s+[^>]*)?>([\s\S]*?)</t>");
            foreach (Match m in matches)
            {
                if (m.Groups[1].Success)
                {
                    string text = DecodeXmlEntities(m.Groups[1].Value);
                    if (!String.IsNullOrEmpty(text))
                    {
                        sb.AppendLine(text);
                    }
                }
            }
        }

        private static void AppendSheetValuesText(StringBuilder sb, string xml)
        {
            if (String.IsNullOrEmpty(xml)) return;
            MatchCollection rowMatches = Regex.Matches(xml, @"<row(?:\s+[^>]*)?>([\s\S]*?)</row>");
            foreach (Match rowMatch in rowMatches)
            {
                string rowXml = rowMatch.Groups[1].Value;
                MatchCollection valMatches = Regex.Matches(rowXml, @"<v(?:\s+[^>]*)?>([\s\S]*?)</v>");
                bool first = true;
                foreach (Match v in valMatches)
                {
                    if (!first) sb.Append("\t");
                    sb.Append(DecodeXmlEntities(v.Groups[1].Value));
                    first = false;
                }
                if (!first) sb.AppendLine();
            }
        }

        private static void AppendPowerPointText(StringBuilder sb, string xml)
        {
            if (String.IsNullOrEmpty(xml)) return;
            MatchCollection matches = Regex.Matches(xml, @"<a:t(?:\s+[^>]*)?>([\s\S]*?)</a:t>|</a:p>");
            foreach (Match m in matches)
            {
                string val = m.Value;
                if (val == "</a:p>")
                {
                    sb.AppendLine();
                }
                else if (m.Groups[1].Success)
                {
                    sb.Append(DecodeXmlEntities(m.Groups[1].Value));
                }
            }
        }

        private static void AppendOpenDocumentText(StringBuilder sb, string xml)
        {
            if (String.IsNullOrEmpty(xml)) return;
            MatchCollection matches = Regex.Matches(xml, @"<text:p(?:\s+[^>]*)?>([\s\S]*?)</text:p>");
            foreach (Match m in matches)
            {
                string pXml = m.Groups[1].Value;
                string cleanText = Regex.Replace(pXml, @"<[^>]+>", String.Empty);
                sb.AppendLine(DecodeXmlEntities(cleanText));
            }
        }

        private static void AppendGenericXmlText(StringBuilder sb, string xml)
        {
            if (String.IsNullOrEmpty(xml)) return;
            string clean = Regex.Replace(xml, @"<[^>]+>", " ");
            string decoded = DecodeXmlEntities(clean);
            string[] lines = decoded.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                string trimmed = line.Trim();
                if (trimmed.Length > 2)
                {
                    sb.AppendLine(trimmed);
                }
            }
        }

        private static string DecodeXmlEntities(string raw)
        {
            if (String.IsNullOrEmpty(raw)) return String.Empty;
            string s = raw.Replace("&amp;", "&")
                          .Replace("&lt;", "<")
                          .Replace("&gt;", ">")
                          .Replace("&quot;", "\"")
                          .Replace("&apos;", "'");

            // Decode numeric character references &#1234; or &#xABCD;
            if (s.IndexOf("&#") >= 0)
            {
                s = Regex.Replace(s, @"&#(\d+);", delegate(Match m)
                {
                    int code;
                    if (int.TryParse(m.Groups[1].Value, out code) && code > 0 && code < 0x10FFFF)
                    {
                        return char.ConvertFromUtf32(code);
                    }
                    return m.Value;
                });
                s = Regex.Replace(s, @"&#x([0-9a-fA-F]+);", delegate(Match m)
                {
                    int code;
                    if (int.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out code) && code > 0 && code < 0x10FFFF)
                    {
                        return char.ConvertFromUtf32(code);
                    }
                    return m.Value;
                });
            }

            return s;
        }

        // Constructs a pristine, compliant ZIP container combining all surviving
        // and repaired parts, with generated [Content_Types].xml and _rels/.rels if missing.
        public static byte[] BuildRepairedZipPackage(OfficeDocumentKind kind, IEnumerable<OfficeSalvagePart> parts)
        {
            Dictionary<string, OfficeSalvagePart> map = new Dictionary<string, OfficeSalvagePart>(StringComparer.OrdinalIgnoreCase);
            if (parts != null)
            {
                foreach (OfficeSalvagePart part in parts)
                {
                    map[part.PartName] = part;
                }
            }

            // Ensure minimal required OPC scaffolding
            if (!map.ContainsKey("[Content_Types].xml"))
            {
                string contentTypesXml = GenerateDefaultContentTypesXml(kind, map.Values);
                byte[] ctBytes = Utf8Encoding.GetBytes(contentTypesXml);
                map["[Content_Types].xml"] = new OfficeSalvagePart("[Content_Types].xml", ctBytes, true, "application/xml");
            }

            if (!map.ContainsKey("_rels/.rels"))
            {
                string relsXml = GenerateDefaultRelsXml(kind);
                byte[] relsBytes = Utf8Encoding.GetBytes(relsXml);
                map["_rels/.rels"] = new OfficeSalvagePart("_rels/.rels", relsBytes, true, "application/vnd.openxmlformats-package.relationships+xml");
            }

            using (MemoryStream output = new MemoryStream())
            {
                List<ZipEntryMetadata> entries = new List<ZipEntryMetadata>();

                foreach (KeyValuePair<string, OfficeSalvagePart> kvp in map)
                {
                    string name = kvp.Key;
                    byte[] rawData = kvp.Value.Data ?? new byte[0];

                    long localHeaderOffset = output.Position;
                    byte[] nameBytes = Utf8Encoding.GetBytes(name);
                    uint crc = ComputeCrc32(rawData, 0, rawData.Length);

                    // Use Deflate compression for efficiency and compatibility
                    byte[] compressedData;
                    ushort method = 8;
                    using (MemoryStream compMs = new MemoryStream())
                    {
                        using (DeflateStream def = new DeflateStream(compMs, CompressionMode.Compress, true))
                        {
                            def.Write(rawData, 0, rawData.Length);
                        }
                        compressedData = compMs.ToArray();
                    }

                    // Write Local Header: PK\x03\x04
                    output.Write(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, 0, 4);
                    output.Write(BitConverter.GetBytes((ushort)20), 0, 2); // Version needed (2.0)
                    output.Write(BitConverter.GetBytes((ushort)0x0800), 0, 2); // UTF-8 name flag
                    output.Write(BitConverter.GetBytes(method), 0, 2);
                    output.Write(BitConverter.GetBytes((ushort)0x4821), 0, 2); // Mod time
                    output.Write(BitConverter.GetBytes((ushort)0x5821), 0, 2); // Mod date
                    output.Write(BitConverter.GetBytes(crc), 0, 4);
                    output.Write(BitConverter.GetBytes((uint)compressedData.Length), 0, 4);
                    output.Write(BitConverter.GetBytes((uint)rawData.Length), 0, 4);
                    output.Write(BitConverter.GetBytes((ushort)nameBytes.Length), 0, 2);
                    output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Extra len

                    output.Write(nameBytes, 0, nameBytes.Length);
                    output.Write(compressedData, 0, compressedData.Length);

                    ZipEntryMetadata meta = new ZipEntryMetadata();
                    meta.Name = name;
                    meta.NameBytes = nameBytes;
                    meta.LocalHeaderOffset = (uint)localHeaderOffset;
                    meta.Crc32 = crc;
                    meta.CompressedSize = (uint)compressedData.Length;
                    meta.UncompressedSize = (uint)rawData.Length;
                    meta.Method = method;
                    entries.Add(meta);
                }

                // Write Central Directory: PK\x01\x02
                long centralDirOffset = output.Position;
                foreach (ZipEntryMetadata meta in entries)
                {
                    output.Write(new byte[] { 0x50, 0x4B, 0x01, 0x02 }, 0, 4);
                    output.Write(BitConverter.GetBytes((ushort)20), 0, 2); // Made by
                    output.Write(BitConverter.GetBytes((ushort)20), 0, 2); // Version needed
                    output.Write(BitConverter.GetBytes((ushort)0x0800), 0, 2); // UTF-8
                    output.Write(BitConverter.GetBytes(meta.Method), 0, 2);
                    output.Write(BitConverter.GetBytes((ushort)0x4821), 0, 2); // Mod time
                    output.Write(BitConverter.GetBytes((ushort)0x5821), 0, 2); // Mod date
                    output.Write(BitConverter.GetBytes(meta.Crc32), 0, 4);
                    output.Write(BitConverter.GetBytes(meta.CompressedSize), 0, 4);
                    output.Write(BitConverter.GetBytes(meta.UncompressedSize), 0, 4);
                    output.Write(BitConverter.GetBytes((ushort)meta.NameBytes.Length), 0, 2);
                    output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Extra
                    output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Comment
                    output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Disk start
                    output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Internal attr
                    output.Write(BitConverter.GetBytes((uint)0), 0, 4);   // External attr
                    output.Write(BitConverter.GetBytes(meta.LocalHeaderOffset), 0, 4);

                    output.Write(meta.NameBytes, 0, meta.NameBytes.Length);
                }
                long centralDirLength = output.Position - centralDirOffset;

                // Write End of Central Directory: PK\x05\x06
                output.Write(new byte[] { 0x50, 0x4B, 0x05, 0x06 }, 0, 4);
                output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Disk number
                output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Start disk
                output.Write(BitConverter.GetBytes((ushort)entries.Count), 0, 2); // Entries on disk
                output.Write(BitConverter.GetBytes((ushort)entries.Count), 0, 2); // Total entries
                output.Write(BitConverter.GetBytes((uint)centralDirLength), 0, 4);
                output.Write(BitConverter.GetBytes((uint)centralDirOffset), 0, 4);
                output.Write(BitConverter.GetBytes((ushort)0), 0, 2); // Comment len

                return output.ToArray();
            }
        }

        private sealed class ZipEntryMetadata
        {
            public string Name;
            public byte[] NameBytes;
            public uint LocalHeaderOffset;
            public uint Crc32;
            public uint CompressedSize;
            public uint UncompressedSize;
            public ushort Method;
        }

        private static string GenerateDefaultContentTypesXml(OfficeDocumentKind kind, IEnumerable<OfficeSalvagePart> parts)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
            sb.Append("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n");
            sb.Append("  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n");
            sb.Append("  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n");
            sb.Append("  <Default Extension=\"png\" ContentType=\"image/png\"/>\n");
            sb.Append("  <Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/>\n");
            sb.Append("  <Default Extension=\"jpg\" ContentType=\"image/jpeg\"/>\n");

            foreach (OfficeSalvagePart part in parts)
            {
                if (part.PartName.Equals("[Content_Types].xml", StringComparison.OrdinalIgnoreCase)) continue;
                if (!String.IsNullOrEmpty(part.ContentType))
                {
                    string partPath = part.PartName.StartsWith("/") ? part.PartName : "/" + part.PartName;
                    sb.AppendFormat("  <Override PartName=\"{0}\" ContentType=\"{1}\"/>\n", partPath, part.ContentType);
                }
            }

            sb.Append("</Types>");
            return sb.ToString();
        }

        private static string GenerateDefaultRelsXml(OfficeDocumentKind kind)
        {
            string target = "word/document.xml";
            string type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";

            if (kind == OfficeDocumentKind.ExcelXlsx)
            {
                target = "xl/workbook.xml";
            }
            else if (kind == OfficeDocumentKind.PowerPointPptx)
            {
                target = "ppt/presentation.xml";
            }

            return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
                   "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n" +
                   "  <Relationship Id=\"rId1\" Type=\"" + type + "\" Target=\"" + target + "\"/>\n" +
                   "</Relationships>";
        }
    }
}
