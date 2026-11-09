using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using UsbRecovery;

public static class OfficeXmlSalvageTests
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
        {
            throw new Exception("Check failed: " + message);
        }
    }

    public static void Main(string[] args)
    {
        TestCrc32();
        TestDetectKind();
        TestRepairAndBalanceXml();
        TestExtractPlainText();
        TestBuildRepairedZipPackage();
        TestSalvageFromBytes();
        TestTruncatedDeflateSalvage();

        Console.WriteLine("PASS OfficeXmlSalvage: {0} checks; DOCX/XLSX/PPTX/ODT salvage, XML balancing, and plain-text extraction verified.", checks);
    }

    private static void TestCrc32()
    {
        byte[] data = Encoding.ASCII.GetBytes("123456789");
        uint crc = OfficeXmlSalvage.ComputeCrc32(data, 0, data.Length);
        Check(crc == 0xCBF43926u, "CRC32 standard check vector 123456789");

        byte[] empty = new byte[0];
        Check(OfficeXmlSalvage.ComputeCrc32(empty, 0, 0) == 0, "CRC32 empty data is 0");
    }

    private static void TestDetectKind()
    {
        List<OfficeSalvagePart> wordParts = new List<OfficeSalvagePart>();
        wordParts.Add(new OfficeSalvagePart("word/document.xml", new byte[10], false, "application/xml"));
        Check(OfficeXmlSalvage.DetectKind(wordParts) == OfficeDocumentKind.WordDocx, "Detected Word document");

        List<OfficeSalvagePart> excelParts = new List<OfficeSalvagePart>();
        excelParts.Add(new OfficeSalvagePart("xl/workbook.xml", new byte[10], false, "application/xml"));
        Check(OfficeXmlSalvage.DetectKind(excelParts) == OfficeDocumentKind.ExcelXlsx, "Detected Excel spreadsheet");

        List<OfficeSalvagePart> pptParts = new List<OfficeSalvagePart>();
        pptParts.Add(new OfficeSalvagePart("ppt/presentation.xml", new byte[10], false, "application/xml"));
        Check(OfficeXmlSalvage.DetectKind(pptParts) == OfficeDocumentKind.PowerPointPptx, "Detected PowerPoint presentation");

        List<OfficeSalvagePart> odtParts = new List<OfficeSalvagePart>();
        odtParts.Add(new OfficeSalvagePart("mimetype", Encoding.ASCII.GetBytes("application/vnd.oasis.opendocument.text"), false, "text/plain"));
        odtParts.Add(new OfficeSalvagePart("content.xml", new byte[10], false, "application/xml"));
        Check(OfficeXmlSalvage.DetectKind(odtParts) == OfficeDocumentKind.OpenDocumentText, "Detected OpenDocument Text");

        List<OfficeSalvagePart> odsParts = new List<OfficeSalvagePart>();
        odsParts.Add(new OfficeSalvagePart("mimetype", Encoding.ASCII.GetBytes("application/vnd.oasis.opendocument.spreadsheet"), false, "text/plain"));
        odsParts.Add(new OfficeSalvagePart("content.xml", new byte[10], false, "application/xml"));
        Check(OfficeXmlSalvage.DetectKind(odsParts) == OfficeDocumentKind.OpenDocumentSpreadsheet, "Detected OpenDocument Spreadsheet");

        Check(OfficeXmlSalvage.DetectKind(null) == OfficeDocumentKind.Unknown, "Null parts is unknown");
        Check(OfficeXmlSalvage.GetKindDisplayName(OfficeDocumentKind.WordDocx).Contains("Word"), "Word display name");
        Check(OfficeXmlSalvage.GetKindDisplayName(OfficeDocumentKind.ExcelXlsx).Contains("Excel"), "Excel display name");
    }

    private static void TestRepairAndBalanceXml()
    {
        // 1. Intact XML
        string intact = "<?xml version=\"1.0\"?><w:document><w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body></w:document>";
        bool repaired;
        byte[] out1 = OfficeXmlSalvage.RepairAndBalanceXml(Encoding.UTF8.GetBytes(intact), out repaired);
        Check(!repaired, "Intact XML does not require repair");
        Check(Encoding.UTF8.GetString(out1) == intact, "Intact XML content matches");

        // 2. Severed / unclosed XML tags
        string unclosed = "<w:document><w:body><w:p><w:r><w:t>Important forensic statement";
        byte[] out2 = OfficeXmlSalvage.RepairAndBalanceXml(Encoding.UTF8.GetBytes(unclosed), out repaired);
        Check(repaired, "Unclosed XML is flagged as repaired");
        string res2 = Encoding.UTF8.GetString(out2);
        Check(res2.EndsWith("</w:t></w:r></w:p></w:body></w:document>"), "Unclosed tags balanced in reverse order: " + res2);
        Check(res2.Contains("Important forensic statement"), "Payload text preserved");

        // 3. Broken partial tag at the end: <w:p><w:r><w:t>Hello<w:br/></w:t><w:
        string brokenTag = "<w:document><w:body><w:p><w:r><w:t>Hello</w:t><w:";
        byte[] out3 = OfficeXmlSalvage.RepairAndBalanceXml(Encoding.UTF8.GetBytes(brokenTag), out repaired);
        Check(repaired, "Broken trailing tag flagged as repaired");
        string res3 = Encoding.UTF8.GetString(out3);
        Check(!res3.Contains("Hello</w:t><w:"), "Trailing partial tag stripped: " + res3);
        Check(res3.EndsWith("</w:r></w:p></w:body></w:document>"), "Tags properly closed: " + res3);

        // 4. Edge cases
        Check(OfficeXmlSalvage.RepairAndBalanceXml(null, out repaired).Length == 0, "Null XML returns empty");
        Check(OfficeXmlSalvage.RepairAndBalanceXml(new byte[0], out repaired).Length == 0, "Empty XML returns empty");
    }

    private static void TestExtractPlainText()
    {
        // Word Docx extraction
        string wordXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                         "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n" +
                         "  <w:body>\n" +
                         "    <w:p><w:r><w:t>First line of text</w:t></w:r></w:p>\n" +
                         "    <w:p><w:r><w:t>Column 1</w:t></w:r><w:tab/><w:r><w:t>Column 2 &amp; &#x41;</w:t></w:r></w:p>\n" +
                         "  </w:body>\n" +
                         "</w:document>";

        List<OfficeSalvagePart> wordParts = new List<OfficeSalvagePart>();
        wordParts.Add(new OfficeSalvagePart("word/document.xml", Encoding.UTF8.GetBytes(wordXml), false, "application/xml"));

        string extractedWord = OfficeXmlSalvage.ExtractPlainText(OfficeDocumentKind.WordDocx, wordParts);
        Check(extractedWord.Contains("First line of text"), "Word extraction contains first line");
        Check(extractedWord.Contains("Column 1\tColumn 2 & A"), "Word extraction decoded tab, &amp;, and hex entity: " + extractedWord);

        // Excel Xlsx extraction
        string sharedStringsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                                  "<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\n" +
                                  "  <si><t>Revenue 2026</t></si>\n" +
                                  "  <si><t>Net Income &lt;Est&gt;</t></si>\n" +
                                  "</sst>";
        string sheet1Xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                           "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\n" +
                           "  <sheetData>\n" +
                           "    <row r=\"1\"><c r=\"A1\"><v>100000</v></c><c r=\"B1\"><v>25000</v></c></row>\n" +
                           "  </sheetData>\n" +
                           "</worksheet>";

        List<OfficeSalvagePart> excelParts = new List<OfficeSalvagePart>();
        excelParts.Add(new OfficeSalvagePart("xl/sharedStrings.xml", Encoding.UTF8.GetBytes(sharedStringsXml), false, "application/xml"));
        excelParts.Add(new OfficeSalvagePart("xl/worksheets/sheet1.xml", Encoding.UTF8.GetBytes(sheet1Xml), false, "application/xml"));

        string extractedExcel = OfficeXmlSalvage.ExtractPlainText(OfficeDocumentKind.ExcelXlsx, excelParts);
        Check(extractedExcel.Contains("Revenue 2026"), "Excel extraction contains shared strings");
        Check(extractedExcel.Contains("Net Income <Est>"), "Excel extraction decoded &lt; and &gt;");
        Check(extractedExcel.Contains("100000\t25000"), "Excel extraction formatted sheet values table");

        // PowerPoint Pptx extraction
        string slideXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                          "<p:sld xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\">\n" +
                          "  <a:p><a:r><a:t>Slide Headline</a:t></a:r></a:p>\n" +
                          "  <a:p><a:r><a:t>Bullet point one</a:t></a:r></a:p>\n" +
                          "</p:sld>";

        List<OfficeSalvagePart> pptParts = new List<OfficeSalvagePart>();
        pptParts.Add(new OfficeSalvagePart("ppt/slides/slide1.xml", Encoding.UTF8.GetBytes(slideXml), false, "application/xml"));

        string extractedPpt = OfficeXmlSalvage.ExtractPlainText(OfficeDocumentKind.PowerPointPptx, pptParts);
        Check(extractedPpt.Contains("Slide Headline"), "PowerPoint extraction contains headline");
        Check(extractedPpt.Contains("Bullet point one"), "PowerPoint extraction contains bullet text");
    }

    private static void TestBuildRepairedZipPackage()
    {
        List<OfficeSalvagePart> parts = new List<OfficeSalvagePart>();
        parts.Add(new OfficeSalvagePart("word/document.xml", Encoding.UTF8.GetBytes("<w:document><w:body><w:p><w:t>Test Package Content</w:t></w:p></w:body></w:document>"), false, "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"));

        byte[] zipPackage = OfficeXmlSalvage.BuildRepairedZipPackage(OfficeDocumentKind.WordDocx, parts);
        Check(zipPackage != null && zipPackage.Length > 100, "Zip package built with valid size");
        Check(zipPackage[0] == 0x50 && zipPackage[1] == 0x4B, "Zip header signature PK");

        // Verify package can be read back and decompressed cleanly using System.IO.Compression
        using (MemoryStream ms = new MemoryStream(zipPackage))
        using (ZipArchive archive = new ZipArchive(ms, ZipArchiveMode.Read))
        {
            Check(archive.Entries.Count >= 3, "Contains document.xml, [Content_Types].xml, and _rels/.rels: " + archive.Entries.Count);

            ZipArchiveEntry docEntry = archive.GetEntry("word/document.xml");
            Check(docEntry != null, "word/document.xml entry found in zip");

            using (StreamReader sr = new StreamReader(docEntry.Open(), Encoding.UTF8))
            {
                string readText = sr.ReadToEnd();
                Check(readText.Contains("Test Package Content"), "Decompressed payload matches original bytes");
            }

            ZipArchiveEntry ctEntry = archive.GetEntry("[Content_Types].xml");
            Check(ctEntry != null, "[Content_Types].xml automatically generated and present");

            ZipArchiveEntry relsEntry = archive.GetEntry("_rels/.rels");
            Check(relsEntry != null, "_rels/.rels automatically generated and present");
        }
    }

    private static void TestSalvageFromBytes()
    {
        // Construct a synthetic damaged raw image:
        // Local file header PK\x03\x04 with deflated word/document.xml,
        // but NO Central Directory and NO EOCD at the end (severed archive).
        byte[] docXmlBytes = Encoding.UTF8.GetBytes("<w:document><w:body><w:p><w:t>Confidential Recovery Target</w:t></w:p></w:body></w:document>");
        byte[] compressedDocXml;
        using (MemoryStream compMs = new MemoryStream())
        {
            using (DeflateStream def = new DeflateStream(compMs, CompressionMode.Compress, true))
            {
                def.Write(docXmlBytes, 0, docXmlBytes.Length);
            }
            compressedDocXml = compMs.ToArray();
        }

        byte[] nameBytes = Encoding.UTF8.GetBytes("word/document.xml");
        uint crc = OfficeXmlSalvage.ComputeCrc32(docXmlBytes, 0, docXmlBytes.Length);

        byte[] rawDamagedImage = new byte[30 + nameBytes.Length + compressedDocXml.Length + 64];
        // 16 bytes leading noise
        int offset = 16;
        rawDamagedImage[offset] = 0x50;
        rawDamagedImage[offset + 1] = 0x4B;
        rawDamagedImage[offset + 2] = 0x03;
        rawDamagedImage[offset + 3] = 0x04;
        BitConverter.GetBytes((ushort)20).CopyTo(rawDamagedImage, offset + 4);
        BitConverter.GetBytes((ushort)0x0800).CopyTo(rawDamagedImage, offset + 6);
        BitConverter.GetBytes((ushort)8).CopyTo(rawDamagedImage, offset + 8); // Deflate
        BitConverter.GetBytes(crc).CopyTo(rawDamagedImage, offset + 14);
        BitConverter.GetBytes((uint)compressedDocXml.Length).CopyTo(rawDamagedImage, offset + 18);
        BitConverter.GetBytes((uint)docXmlBytes.Length).CopyTo(rawDamagedImage, offset + 22);
        BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(rawDamagedImage, offset + 26);
        BitConverter.GetBytes((ushort)0).CopyTo(rawDamagedImage, offset + 28);
        nameBytes.CopyTo(rawDamagedImage, offset + 30);
        compressedDocXml.CopyTo(rawDamagedImage, offset + 30 + nameBytes.Length);
        // Trailing garbage, no EOCD!

        OfficeSalvageResult result = OfficeXmlSalvage.SalvageFromBytes(rawDamagedImage);
        Check(result.Kind == OfficeDocumentKind.WordDocx, "Salvage recognized WordDocx from severed stream");
        Check(result.PartsRecovered >= 1, "At least 1 part recovered");
        Check(result.ExtractedText.Contains("Confidential Recovery Target"), "Extracted plain text matches: " + result.ExtractedText);
        Check(result.ReconstructedPackage.Length > 100, "Reconstructed full zip package available");
    }

    private static void TestTruncatedDeflateSalvage()
    {
        // Test an archive with unclosed tags in document.xml (e.g. truncated during save)
        byte[] unclosedXml = Encoding.UTF8.GetBytes("<w:document><w:body><w:p><w:r><w:t>Part one of text before corruption occurs and data gets truncated.");
        byte[] compXml;
        using (MemoryStream ms = new MemoryStream())
        {
            using (DeflateStream def = new DeflateStream(ms, CompressionMode.Compress, true))
            {
                def.Write(unclosedXml, 0, unclosedXml.Length);
            }
            compXml = ms.ToArray();
        }

        byte[] nameBytes = Encoding.UTF8.GetBytes("word/document.xml");
        byte[] rawStream = new byte[30 + nameBytes.Length + compXml.Length + 10];
        rawStream[0] = 0x50; rawStream[1] = 0x4B; rawStream[2] = 0x03; rawStream[3] = 0x04;
        BitConverter.GetBytes((ushort)20).CopyTo(rawStream, 4);
        BitConverter.GetBytes((ushort)0x0800).CopyTo(rawStream, 6);
        BitConverter.GetBytes((ushort)8).CopyTo(rawStream, 8); // Deflate
        BitConverter.GetBytes((uint)0).CopyTo(rawStream, 14);
        BitConverter.GetBytes((uint)compXml.Length).CopyTo(rawStream, 18);
        BitConverter.GetBytes((uint)unclosedXml.Length).CopyTo(rawStream, 22);
        BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(rawStream, 26);
        BitConverter.GetBytes((ushort)0).CopyTo(rawStream, 28);
        nameBytes.CopyTo(rawStream, 30);
        Array.Copy(compXml, 0, rawStream, 30 + nameBytes.Length, compXml.Length);

        OfficeSalvageResult result = OfficeXmlSalvage.SalvageFromBytes(rawStream);
        Check(result.Kind == OfficeDocumentKind.WordDocx, "Recognized Word doc despite severed archive");
        Check(result.PartsRecovered >= 1, "Extracted part");
        Check(result.HasRepairedXml, "XML was balanced and closed cleanly");
        Check(result.ExtractedText.Contains("Part one of text"), "Text recovered: " + result.ExtractedText);
    }
}
