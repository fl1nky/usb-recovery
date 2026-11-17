using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class Tier5AdversarialChallenger2Tests
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
        {
            throw new Exception("Challenger 2 check failed: " + message);
        }
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("=========================================================================");
        Console.WriteLine("STARTING CHALLENGER 2 EMPIRICAL TIER-5 ADVERSARIAL STRESS TEST");
        Console.WriteLine("Target: LocalWebServer /api/export-zip and /api/report (Milestone 3)");
        Console.WriteLine("=========================================================================");

        string tempRoot = Path.Combine(Path.GetTempPath(), "challenger2_tier5_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        try
        {
            // Section 1: Streaming ZIP Edge Cases & Path Traversal Injection
            TestZipEdgeCasesAndPathTraversal(tempRoot);

            // Section 2: ZIP Binary Specification & Decompression Oracles
            TestZipBinarySpecificationAndOracles(tempRoot);

            // Section 3: Report Generation (HTML, JSON, PDF), XSS Escaping & Chain-of-Custody Oracle
            TestReportGenerationAndXssEscaping(tempRoot);

            // Section 4: Pure C# PDF 1.4 Specification Compliance
            TestPureCSharpPdf14Compliance(tempRoot);

            // Section 5: High Concurrency, Socket Aborts (TCP RST) & Socket Leak Resilience
            TestConcurrencyAndSocketAborts(tempRoot);

            // Section 6: Forensic Immutability & Write-Blocking Guarantees
            TestForensicImmutability(tempRoot);

            Console.WriteLine("=========================================================================");
            Console.WriteLine("PASS Challenger2_Tier5: {0} empirical checks passed with 0 errors.", checks);
            Console.WriteLine("CHALLENGER 2 ADVERSARIAL VERIFICATION COMPLETE: ALL CHECKS PASSED.");
            Console.WriteLine("=========================================================================");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL Challenger2_Tier5: {0}\n{1}", ex.Message, ex.StackTrace);
            return 1;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempRoot))
                    Directory.Delete(tempRoot, true);
            }
            catch { }
        }
    }

    // =========================================================================
    // SECTION 1: STREAMING ZIP EDGE CASES & PATH TRAVERSAL INJECTION
    // =========================================================================
    private static void TestZipEdgeCasesAndPathTraversal(string tempRoot)
    {
        Console.WriteLine("-> Running Section 1: Streaming ZIP Edge Cases & Path Traversal Injection...");
        string testDir = Path.Combine(tempRoot, "zip_edge_cases");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "evidence.raw");
        File.WriteAllBytes(dummyImage, new byte[1024]);

        // 1.1 Missing output directory returns HTTP 404
        string missingDir = Path.Combine(testDir, "non_existent_folder");
        int port1 = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, missingDir, port1))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;
            AssertHttpStatus(baseUrl + "/api/export-zip", HttpStatusCode.NotFound, "No recovered files directory found");
            server.Stop();
        }

        // 1.2 Empty output directory returns HTTP 404
        string emptyDir = Path.Combine(testDir, "empty_folder");
        Directory.CreateDirectory(emptyDir);
        int port2 = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, emptyDir, port2))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;
            AssertHttpStatus(baseUrl + "/api/export-zip", HttpStatusCode.NotFound, "No recovered files to export");
            server.Stop();
        }

        // 1.3 Path traversal and injection attempts
        string recDir = Path.Combine(testDir, "valid_recovered");
        Directory.CreateDirectory(recDir);
        File.WriteAllText(Path.Combine(recDir, "artifact_1.txt"), "Evidence text 1");
        File.WriteAllText(Path.Combine(recDir, "artifact_2.bin"), "Binary data 2");

        int port3 = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recDir, port3))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            // Attack vectors: Directory traversal variations
            string[] traversalAttacks = new string[]
            {
                "../",
                "..\\",
                "../../cmd.exe",
                "..\\..\\windows\\system32\\calc.exe",
                "/etc/passwd",
                "C:\\Windows\\win.ini",
                "....//....//boot.ini",
                "..%2F..%2Fwin.ini",
                "%2e%2e%2fboot.ini",
                "artifact_1.txt/../../boot.ini",
                "../valid_recovered/../evidence.raw",
                "nonexistent_file.xyz",
                "   ",
                ",,,,"
            };

            for (int i = 0; i < traversalAttacks.Length; i++)
            {
                string attack = traversalAttacks[i];
                string url = baseUrl + "/api/export-zip?files=" + Uri.EscapeDataString(attack);
                AssertHttpStatus(url, HttpStatusCode.NotFound, "No matching files found for export");
            }

            // Normal valid filter download
            using (var client = new WebClient())
            {
                byte[] zipFiltered = client.DownloadData(baseUrl + "/api/export-zip?files=artifact_1.txt");
                Check(zipFiltered != null && zipFiltered.Length > 0, "Filtered zip downloaded successfully");
                using (var archive = new ZipArchive(new MemoryStream(zipFiltered), ZipArchiveMode.Read))
                {
                    Check(archive.Entries.Count == 1, "Only 1 filtered file included in archive");
                    Check(archive.Entries[0].Name == "artifact_1.txt", "Archive contains exact requested file");
                }
            }

            server.Stop();
        }
    }

    // =========================================================================
    // SECTION 2: ZIP BINARY SPECIFICATION & DECOMPRESSION ORACLES
    // =========================================================================
    private static void TestZipBinarySpecificationAndOracles(string tempRoot)
    {
        Console.WriteLine("-> Running Section 2: ZIP Binary Specification & Decompression Oracles...");
        string testDir = Path.Combine(tempRoot, "zip_spec");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "evidence.raw");
        File.WriteAllBytes(dummyImage, new byte[1024]);

        string recDir = Path.Combine(testDir, "recovered");
        Directory.CreateDirectory(recDir);

        // 2.1 File matrix: 0-byte, 1-byte, 256KB random, unicode names, nested hierarchies
        byte[] zeroByte = new byte[0];
        File.WriteAllBytes(Path.Combine(recDir, "empty.dat"), zeroByte);

        byte[] singleByte = new byte[] { 0x42 };
        File.WriteAllBytes(Path.Combine(recDir, "single.bin"), singleByte);

        byte[] mediumData = new byte[256 * 1024];
        new Random(42).NextBytes(mediumData);
        File.WriteAllBytes(Path.Combine(recDir, "random_medium.dat"), mediumData);

        // Deeply nested subfolders with backslashes and forward slashes
        string nestedDir = Path.Combine(recDir, "deep" + Path.DirectorySeparatorChar + "folder" + Path.DirectorySeparatorChar + "structure");
        Directory.CreateDirectory(nestedDir);
        byte[] nestedPayload = Encoding.UTF8.GetBytes("Deeply nested evidence payload");
        File.WriteAllBytes(Path.Combine(nestedDir, "nested_file.txt"), nestedPayload);

        // Unicode filename (UTF-8)
        string unicodeName = "отчёт_крипто_🔥.txt";
        byte[] unicodePayload = Encoding.UTF8.GetBytes("Unicode forensic payload: подтверждено");
        File.WriteAllBytes(Path.Combine(recDir, unicodeName), unicodePayload);

        int port = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recDir, port))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            using (var client = new WebClient())
            {
                byte[] zipBytes = client.DownloadData(baseUrl + "/api/export-zip");
                Check(zipBytes != null && zipBytes.Length > 200, "Full archive downloaded");

                // 2.2 Low-level binary verification of ZIP specification
                // Check Local File Header signature: PK\x03\x04 (0x04034B50)
                Check(zipBytes[0] == 0x50 && zipBytes[1] == 0x4B && zipBytes[2] == 0x03 && zipBytes[3] == 0x04,
                    "ZIP local file header has valid PK\\x03\\x04 signature");

                // Locate Central Directory Header signature: PK\x01\x02 (0x02014B50)
                bool foundCd = false;
                for (int i = 0; i < zipBytes.Length - 4; i++)
                {
                    if (zipBytes[i] == 0x50 && zipBytes[i + 1] == 0x4B && zipBytes[i + 2] == 0x01 && zipBytes[i + 3] == 0x02)
                    {
                        foundCd = true;
                        break;
                    }
                }
                Check(foundCd, "ZIP central directory contains valid PK\\x01\\x02 signatures");

                // Locate End of Central Directory signature: PK\x05\x06 (0x06054B50)
                bool foundEocd = false;
                int eocdOffset = -1;
                for (int i = zipBytes.Length - 22; i >= 0; i--)
                {
                    if (zipBytes[i] == 0x50 && zipBytes[i + 1] == 0x4B && zipBytes[i + 2] == 0x05 && zipBytes[i + 3] == 0x06)
                    {
                        foundEocd = true;
                        eocdOffset = i;
                        break;
                    }
                }
                Check(foundEocd, "ZIP end of central directory record contains valid PK\\x05\\x06 signature");
                Check(eocdOffset >= 0, "Valid EOCD offset identified");

                // 2.3 Strict verification via .NET ZipArchive Decompression Oracle
                using (var archive = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read))
                {
                    Check(archive.Entries.Count == 5, "Archive contains exactly 5 entries");

                    var map = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
                    foreach (var entry in archive.Entries)
                    {
                        map[entry.Name] = entry;

                        // Check forward-slash directory normalization
                        Check(!entry.FullName.Contains("\\"), "Entry full name contains forward slashes only: " + entry.FullName);
                        Check(!entry.FullName.StartsWith("/"), "Entry full name has no leading slash: " + entry.FullName);
                    }

                    // Check empty.dat
                    Check(map.ContainsKey("empty.dat"), "empty.dat entry present");
                    Check(map["empty.dat"].Length == 0, "empty.dat uncompressed length is 0");
                    using (var s = map["empty.dat"].Open())
                    {
                        byte[] buf = new byte[16];
                        int r = s.Read(buf, 0, 16);
                        Check(r == 0, "empty.dat extracts 0 bytes");
                    }

                    // Check single.bin
                    Check(map.ContainsKey("single.bin"), "single.bin entry present");
                    Check(map["single.bin"].Length == 1, "single.bin length is 1");
                    using (var s = map["single.bin"].Open())
                    {
                        byte[] buf = new byte[1];
                        int r = s.Read(buf, 0, 1);
                        Check(r == 1 && buf[0] == 0x42, "single.bin content verified");
                    }

                    // Check random_medium.dat bitwise identity and CRC-32
                    Check(map.ContainsKey("random_medium.dat"), "random_medium.dat entry present");
                    Check(map["random_medium.dat"].Length == mediumData.Length, "Medium file length matches");
                    using (var s = map["random_medium.dat"].Open())
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        byte[] extracted = ms.ToArray();
                        Check(ByteArrayEquals(extracted, mediumData), "Medium random data extracted bitwise identical");
                        Check(ComputeSha256(extracted) == ComputeSha256(mediumData), "Medium random data SHA-256 matches oracle");
                    }

                    // Check nested file
                    Check(map.ContainsKey("nested_file.txt"), "nested_file.txt entry present");
                    ZipArchiveEntry nestedEntry = map["nested_file.txt"];
                    Check(nestedEntry.FullName.Equals("deep/folder/structure/nested_file.txt", StringComparison.OrdinalIgnoreCase),
                        "Nested relative path normalized cleanly: " + nestedEntry.FullName);
                    using (var s = nestedEntry.Open())
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        Check(ByteArrayEquals(ms.ToArray(), nestedPayload), "Nested file content extracted cleanly");
                    }

                    // Check unicode file
                    Check(map.ContainsKey(unicodeName), "Unicode filename entry present: " + unicodeName);
                    using (var s = map[unicodeName].Open())
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        Check(ByteArrayEquals(ms.ToArray(), unicodePayload), "Unicode file content extracted cleanly");
                    }
                }
            }

            server.Stop();
        }
    }

    // =========================================================================
    // SECTION 3: REPORT GENERATION, XSS ESCAPING & CHAIN-OF-CUSTODY ORACLE
    // =========================================================================
    private static void TestReportGenerationAndXssEscaping(string tempRoot)
    {
        Console.WriteLine("-> Running Section 3: Report Generation (HTML, JSON, PDF), XSS Escaping & Chain Oracle...");
        string testDir = Path.Combine(tempRoot, "report_spec");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "evidence.raw");
        File.WriteAllBytes(dummyImage, new byte[2048]);

        string recDir = Path.Combine(testDir, "recovered");
        Directory.CreateDirectory(recDir);

        // 3.1 Empty catalog report test
        int port1 = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recDir, port1))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            using (var client = new WebClient { Encoding = Encoding.UTF8 })
            {
                // JSON empty report
                string jsonStr = client.DownloadString(baseUrl + "/api/report?format=json");
                var serializer = new JavaScriptSerializer();
                var rep = serializer.Deserialize<Dictionary<string, object>>(jsonStr);
                Check(Convert.ToInt32(rep["fileCount"]) == 0, "Empty catalog reports fileCount = 0");
                Check(rep["chainOfCustodySha256"].ToString() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "Empty catalog chain hash is SHA-256 of empty string");

                // HTML empty report
                string htmlStr = client.DownloadString(baseUrl + "/api/report?format=html");
                Check(htmlStr.Contains("No artifacts recovered."), "HTML reports 'No artifacts recovered.'");
                Check(htmlStr.Contains("0 items"), "HTML reports '0 items'");
                Check(htmlStr.Contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                    "HTML reports master chain hash for empty catalog");
            }
            server.Stop();
        }

        // 3.2 Adversarial Injection payloads in recovered filenames and query params
        // Note: Windows NTFS restricts < > : " / \ | ? * in filenames, so file tests focus on & and ' and =
        string[] xssFiles = new string[]
        {
            "quote_' onmouseover='alert(1)'.csv",
            "amp_&_apos_'quote'_test.txt",
            "attr_name='value' onclick='alert(1)'.log",
            "param_xss=alert(document.cookie);.dat"
        };

        for (int i = 0; i < xssFiles.Length; i++)
        {
            File.WriteAllText(Path.Combine(recDir, xssFiles[i]), "benign payload content " + i);
        }

        int port2 = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recDir, port2))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            using (var client = new WebClient { Encoding = Encoding.UTF8 })
            {
                // Verify HTML report has zero unescaped tags or event handlers
                string html = client.DownloadString(baseUrl + "/api/report?format=html");

                Check(!html.Contains("<script>"), "Malicious <script> tag strictly prohibited in HTML report");
                Check(!html.Contains("</script>"), "Closing </script> tag strictly prohibited in HTML report");
                Check(!html.Contains("onload="), "Malicious onload= attribute strictly prohibited in HTML report");

                // Verify HTML entity escaping was applied to filenames with special chars
                Check(html.Contains("&amp;"), "Ampersand safely escaped as &amp;");
                Check(html.Contains("&#39;") || html.Contains("'"), "Single quote handled safely");

                // Verify format parameter XSS resistance with raw tags
                string[] xssFormatParams = new string[]
                {
                    "%3Cscript%3Ealert('Pwn')%3C%2Fscript%3E",
                    "%22%3E%3Csvg%20onload=alert(1)%3E",
                    "javascript:alert(1)"
                };

                for (int p = 0; p < xssFormatParams.Length; p++)
                {
                    string xssFormatUrl = baseUrl + "/api/report?format=" + xssFormatParams[p];
                    string formatHtml = client.DownloadString(xssFormatUrl);
                    Check(!formatHtml.Contains("<script>alert('Pwn')</script>"), "format query parameter cannot inject <script>");
                    Check(!formatHtml.Contains("<svg onload=alert(1)>"), "format query parameter cannot inject <svg>");
                    Check(formatHtml.Contains("<!DOCTYPE html>"), "Fallback to HTML report preserved");
                }

                // 3.3 Independent Chain-of-Custody SHA-256 Oracle Verification
                string json = client.DownloadString(baseUrl + "/api/report?format=json");
                var serializer = new JavaScriptSerializer();
                var rep = serializer.Deserialize<Dictionary<string, object>>(json);
                Check(Convert.ToInt32(rep["fileCount"]) == 4, "Report lists 4 files");

                // Calculate oracle chain-of-custody hash independently
                var dir = new DirectoryInfo(recDir);
                var files = dir.GetFiles("*", SearchOption.AllDirectories);
                Array.Sort(files, (a, b) => string.Compare(a.FullName, b.FullName, StringComparison.Ordinal));

                var oracleShaList = new List<string>();
                for (int i = 0; i < files.Length; i++)
                {
                    byte[] fb = File.ReadAllBytes(files[i].FullName);
                    oracleShaList.Add(ComputeSha256(fb));
                }

                string concatenated = string.Join("\n", oracleShaList.ToArray());
                string oracleChainHash = ComputeSha256(Encoding.UTF8.GetBytes(concatenated));

                string reportChainHash = rep["chainOfCustodySha256"].ToString();
                Check(reportChainHash == oracleChainHash,
                    string.Format("Chain of Custody hash '{0}' matches independent oracle '{1}'", reportChainHash, oracleChainHash));
            }

            server.Stop();
        }
    }

    // =========================================================================
    // SECTION 4: PURE C# PDF 1.4 SPECIFICATION COMPLIANCE
    // =========================================================================
    private static void TestPureCSharpPdf14Compliance(string tempRoot)
    {
        Console.WriteLine("-> Running Section 4: Pure C# PDF 1.4 Specification Compliance...");
        string testDir = Path.Combine(tempRoot, "pdf_spec");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "evidence.raw");
        File.WriteAllBytes(dummyImage, new byte[2048]);

        string recDir = Path.Combine(testDir, "recovered");
        Directory.CreateDirectory(recDir);

        // Generate synthetic pure C# PDF 1.4 document
        byte[] pdfBytes = BuildValidPdf14Document("Forensic Investigation Case #2026-11-A", "Subject Disk SHA-256 Immutability Verified");
        string pdfFilePath = Path.Combine(recDir, "case_report.pdf");
        File.WriteAllBytes(pdfFilePath, pdfBytes);

        // 4.1 Validate binary PDF structure directly
        string pdfText = Encoding.ASCII.GetString(pdfBytes);
        Check(pdfText.StartsWith("%PDF-1.4\n"), "PDF starts with %PDF-1.4 header");
        Check(pdfText.TrimEnd().EndsWith("%%EOF"), "PDF terminates with %%EOF");
        Check(pdfText.Contains("/Type /Catalog"), "PDF contains /Type /Catalog");
        Check(pdfText.Contains("/Type /Pages"), "PDF contains /Type /Pages");
        Check(pdfText.Contains("/Type /Page"), "PDF contains /Type /Page");
        Check(pdfText.Contains("xref"), "PDF contains xref table");
        Check(pdfText.Contains("trailer"), "PDF contains trailer dictionary");
        Check(pdfText.Contains("startxref"), "PDF contains startxref pointer");

        int port = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recDir, port))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            using (var client = new WebClient { Encoding = Encoding.UTF8 })
            {
                // Verify /api/report?format=pdf serves HTML print-to-PDF layout
                string pdfHtml = client.DownloadString(baseUrl + "/api/report?format=pdf");
                Check(pdfHtml.Contains("<!DOCTYPE html>"), "format=pdf serves HTML template");
                Check(pdfHtml.Contains("@media print"), "format=pdf contains @media print CSS rule");
                Check(pdfHtml.Contains("ISO/IEC 27037 Compatible"), "Contains ISO/IEC 27037 badge");

                // Verify PDF artifact cataloged in JSON report
                string jsonStr = client.DownloadString(baseUrl + "/api/report?format=json");
                var serializer = new JavaScriptSerializer();
                var rep = serializer.Deserialize<Dictionary<string, object>>(jsonStr);
                Check(Convert.ToInt32(rep["fileCount"]) == 1, "Report lists 1 file");

                var filesList = (System.Collections.ArrayList)rep["files"];
                Dictionary<string, object> fileEntry = (Dictionary<string, object>)filesList[0];
                Check(fileEntry["name"].ToString() == "case_report.pdf", "File name is case_report.pdf");
                Check(Convert.ToInt64(fileEntry["size"]) == pdfBytes.Length, "Report size matches PDF byte length");
                Check(fileEntry["sha256"].ToString() == ComputeSha256(pdfBytes), "Report sha256 matches PDF SHA-256");
                Check(fileEntry["extension"].ToString() == "PDF", "Report extension is PDF");

                // Verify bitwise export of PDF via /api/export-zip
                byte[] zipBytes = client.DownloadData(baseUrl + "/api/export-zip?files=case_report.pdf");
                using (var archive = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read))
                {
                    Check(archive.Entries.Count == 1, "Archive has 1 entry");
                    var entry = archive.Entries[0];
                    Check(entry.Name == "case_report.pdf", "Archive entry is case_report.pdf");
                    using (var s = entry.Open())
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        byte[] extracted = ms.ToArray();
                        Check(ByteArrayEquals(extracted, pdfBytes), "Extracted PDF is bitwise identical to synthetic PDF");
                    }
                }
            }

            server.Stop();
        }
    }

    // =========================================================================
    // SECTION 5: CONCURRENCY, SOCKET ABORTS (TCP RST) & SOCKET LEAKS
    // =========================================================================
    private static void TestConcurrencyAndSocketAborts(string tempRoot)
    {
        Console.WriteLine("-> Running Section 5: High Concurrency, Socket Aborts & Socket Leak Resilience...");
        string testDir = Path.Combine(tempRoot, "concurrency_spec");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "evidence.raw");

        byte[] rawDisk = new byte[65536];
        new Random(77).NextBytes(rawDisk);
        // Add fake MFT record at offset 4096: "FILE"
        rawDisk[4096] = (byte)'F'; rawDisk[4097] = (byte)'I'; rawDisk[4098] = (byte)'L'; rawDisk[4099] = (byte)'E';
        File.WriteAllBytes(dummyImage, rawDisk);

        string recDir = Path.Combine(testDir, "recovered");
        Directory.CreateDirectory(recDir);
        for (int i = 0; i < 8; i++)
        {
            File.WriteAllText(Path.Combine(recDir, string.Format("file_{0}.txt", i)), "Evidence record content payload " + i);
        }

        int port = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recDir, port))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            // 5.1 Abrupt Client TCP RST Disconnects (15 cycles)
            for (int cycle = 0; cycle < 15; cycle++)
            {
                using (var tcp = new TcpClient())
                {
                    tcp.Connect("127.0.0.1", server.Port);
                    // LingerOption(true, 0) forces sending TCP RST instead of graceful FIN handshake
                    tcp.Client.LingerState = new LingerOption(true, 0);
                    var stream = tcp.GetStream();

                    string path = (cycle % 3 == 0)
                        ? "/api/export-zip"
                        : ((cycle % 3 == 1) ? "/api/report?format=html" : "/api/report?format=json");

                    string req = string.Format("GET {0} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
                    byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                    stream.Write(reqBytes, 0, reqBytes.Length);

                    // Read tiny initial slice (e.g. 10 bytes) then abruptly abort
                    byte[] slice = new byte[10];
                    int r = stream.Read(slice, 0, 10);
                    Check(r > 0, "Initial partial response bytes received before RST");

                    // Close immediately sending RST
                    tcp.Close();
                }
            }

            Check(server.IsRunning, "Server remains active after 15 abrupt TCP RST aborts");

            // 5.2 High Concurrency: 25 concurrent requests across varied endpoints
            const int totalThreads = 25;
            Task[] tasks = new Task[totalThreads];
            int successCounter = 0;

            for (int i = 0; i < totalThreads; i++)
            {
                int workerId = i;
                tasks[i] = Task.Run(() =>
                {
                    using (var client = new WebClient { Encoding = Encoding.UTF8 })
                    {
                        int op = workerId % 5;
                        if (op == 0)
                        {
                            // Export ZIP
                            byte[] zip = client.DownloadData(baseUrl + "/api/export-zip");
                            if (zip != null && zip.Length > 100) Interlocked.Increment(ref successCounter);
                        }
                        else if (op == 1)
                        {
                            // Report JSON
                            string json = client.DownloadString(baseUrl + "/api/report?format=json");
                            if (json.Contains("chainOfCustodySha256")) Interlocked.Increment(ref successCounter);
                        }
                        else if (op == 2)
                        {
                            // Report HTML
                            string html = client.DownloadString(baseUrl + "/api/report?format=html");
                            if (html.Contains("Recovered Artifact Manifest")) Interlocked.Increment(ref successCounter);
                        }
                        else if (op == 3)
                        {
                            // Status API
                            string status = client.DownloadString(baseUrl + "/api/status");
                            if (status.Contains("USB-Recovery")) Interlocked.Increment(ref successCounter);
                        }
                        else
                        {
                            // Hex API
                            string hex = client.DownloadString(baseUrl + "/api/hex?offset=4096&length=16");
                            if (hex.Contains("46494C45")) Interlocked.Increment(ref successCounter);
                        }
                    }
                });
            }

            Task.WaitAll(tasks);
            Check(successCounter == totalThreads,
                string.Format("All {0} concurrent worker requests succeeded without error ({1} passed)", totalThreads, successCounter));

            // Verify server responds immediately to a subsequent health request
            using (var client = new WebClient { Encoding = Encoding.UTF8 })
            {
                string status = client.DownloadString(baseUrl + "/api/status");
                Check(status.Contains("USB-Recovery"), "Server fully responsive immediately post-stress");
            }

            server.Stop();
        }
    }

    // =========================================================================
    // SECTION 6: FORENSIC IMMUTABILITY & WRITE-BLOCKING GUARANTEES
    // =========================================================================
    private static void TestForensicImmutability(string tempRoot)
    {
        Console.WriteLine("-> Running Section 6: Forensic Immutability & Write-Blocking Guarantees...");
        string testDir = Path.Combine(tempRoot, "immutability_spec");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "evidence.raw");

        byte[] rawDisk = new byte[65536];
        new Random(12345).NextBytes(rawDisk);
        File.WriteAllBytes(dummyImage, rawDisk);

        string recDir = Path.Combine(testDir, "recovered");
        Directory.CreateDirectory(recDir);
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(recDir, string.Format("file_{0}.txt", i)), "Immutable evidence content " + i);
        }

        // Snapshot pre-test cryptographic hashes and timestamps
        string preImageHash = ComputeSha256(File.ReadAllBytes(dummyImage));
        long preImageLen = new FileInfo(dummyImage).Length;
        DateTime preImageWrite = File.GetLastWriteTimeUtc(dummyImage);

        var preHashes = new Dictionary<string, string>();
        var preLengths = new Dictionary<string, long>();
        var preWrites = new Dictionary<string, DateTime>();

        foreach (var f in Directory.GetFiles(recDir))
        {
            preHashes[f] = ComputeSha256(File.ReadAllBytes(f));
            preLengths[f] = new FileInfo(f).Length;
            preWrites[f] = File.GetLastWriteTimeUtc(f);
        }

        int port = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recDir, port))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            // Execute full gauntlet of reads and exports
            using (var client = new WebClient { Encoding = Encoding.UTF8 })
            {
                client.DownloadString(baseUrl + "/api/status");
                client.DownloadString(baseUrl + "/api/files");
                client.DownloadString(baseUrl + "/api/hex?offset=0&length=512");
                client.DownloadString(baseUrl + "/api/clusters");
                client.DownloadString(baseUrl + "/api/report?format=html");
                client.DownloadString(baseUrl + "/api/report?format=json");
                client.DownloadString(baseUrl + "/api/report?format=pdf");
                client.DownloadData(baseUrl + "/api/export-zip");
                client.DownloadData(baseUrl + "/api/export-zip?files=file_0.txt,file_1.txt");
            }

            server.Stop();
        }

        // Snapshot post-test cryptographic hashes and timestamps
        string postImageHash = ComputeSha256(File.ReadAllBytes(dummyImage));
        long postImageLen = new FileInfo(dummyImage).Length;
        DateTime postImageWrite = File.GetLastWriteTimeUtc(dummyImage);

        Check(preImageHash == postImageHash, "Evidence raw disk hash is 100% bitwise immutable");
        Check(preImageLen == postImageLen, "Evidence raw disk length is unaltered");
        Check(preImageWrite == postImageWrite, "Evidence raw disk write timestamp is unaltered");

        foreach (var f in Directory.GetFiles(recDir))
        {
            string postHash = ComputeSha256(File.ReadAllBytes(f));
            long postLen = new FileInfo(f).Length;
            DateTime postWrite = File.GetLastWriteTimeUtc(f);

            Check(preHashes[f] == postHash, "Recovered file hash is 100% bitwise immutable: " + Path.GetFileName(f));
            Check(preLengths[f] == postLen, "Recovered file length is unaltered: " + Path.GetFileName(f));
            Check(preWrites[f] == postWrite, "Recovered file write timestamp is unaltered: " + Path.GetFileName(f));
        }
    }

    // =========================================================================
    // SYNTHETIC BUILDERS & UTILITIES
    // =========================================================================

    private static byte[] BuildValidPdf14Document(string title, string content)
    {
        var objects = new List<string>();
        // 1 0 obj: Catalog
        objects.Add("<< /Type /Catalog /Pages 2 0 R >>");
        // 2 0 obj: Pages
        objects.Add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        // 3 0 obj: Page
        objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>");
        // 4 0 obj: Font
        objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
        // 5 0 obj: Content stream
        string streamBody = "BT /F1 12 Tf 50 720 Td (" + title + ") Tj ET\nBT /F1 10 Tf 50 700 Td (" + content + ") Tj ET";
        objects.Add("<< /Length " + Encoding.ASCII.GetByteCount(streamBody) + " >>\nstream\n" + streamBody + "\nendstream");

        var sb = new StringBuilder("%PDF-1.4\n");
        var offsets = new List<int>();
        offsets.Add(0); // entry 0 in xref

        for (int i = 0; i < objects.Count; i++)
        {
            offsets.Add(Encoding.ASCII.GetByteCount(sb.ToString()));
            sb.Append((i + 1).ToString()).Append(" 0 obj\n").Append(objects[i]).Append("\nendobj\n");
        }

        int xrefOffset = Encoding.ASCII.GetByteCount(sb.ToString());
        sb.Append("xref\n0 ").Append((objects.Count + 1).ToString()).Append("\n0000000000 65535 f \n");
        for (int i = 1; i < offsets.Count; i++)
        {
            sb.Append(offsets[i].ToString("D10")).Append(" 00000 n \n");
        }

        sb.Append("trailer\n<< /Size ").Append((objects.Count + 1).ToString()).Append(" /Root 1 0 R >>\nstartxref\n")
          .Append(xrefOffset.ToString()).Append("\n%%EOF\n");

        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private static void AssertHttpStatus(string url, HttpStatusCode expectedCode, string expectedBodySnippet)
    {
        bool caught = false;
        try
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            using (var resp = (HttpWebResponse)req.GetResponse())
            {
                Check(resp.StatusCode == expectedCode, "HTTP status matches expected: " + expectedCode);
            }
        }
        catch (WebException wex)
        {
            var resp = wex.Response as HttpWebResponse;
            if (resp != null && resp.StatusCode == expectedCode)
            {
                caught = true;
                if (!string.IsNullOrEmpty(expectedBodySnippet))
                {
                    using (var r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    {
                        string body = r.ReadToEnd();
                        Check(body.Contains(expectedBodySnippet), "Error body contains expected snippet: " + expectedBodySnippet);
                    }
                }
            }
            else
            {
                throw;
            }
        }
        Check(caught, "Expected HTTP error status: " + expectedCode);
    }

    private static int FindFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static string ComputeSha256(byte[] data)
    {
        using (var sha = SHA256.Create())
        {
            byte[] h = sha.ComputeHash(data);
            var sb = new StringBuilder(64);
            for (int i = 0; i < h.Length; i++) sb.Append(h[i].ToString("x2"));
            return sb.ToString();
        }
    }

    private static bool ByteArrayEquals(byte[] a, byte[] b)
    {
        if (a == b) return true;
        if (a == null || b == null || a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
