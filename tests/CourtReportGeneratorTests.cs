using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class CourtReportGeneratorTests
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

    public static int Main(string[] args)
    {
        Console.WriteLine("Running CourtReportGeneratorTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "court-report-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            TestHtmlReportGeneration(testDir);
            TestMarkdownReportGeneration(testDir);

            Console.WriteLine("PASS CourtReportGeneratorTests: {0} checks passed; Rule 902(14) Expert Witness report, Chain of Custody hashes, artifact synthesis, and HTML/MD rendering verified.", checks);
            return 0;
        }
        finally
        {
            try
            {
                if (Directory.Exists(testDir))
                {
                    Directory.Delete(testDir, true);
                }
            }
            catch { }
        }
    }

    private static void TestHtmlReportGeneration(string testDir)
    {
        var meta = new ForensicCaseMetadata
        {
            CaseNumber = "CR-2026-9042",
            EvidenceId = "USB-SAMSUNG-512GB-01",
            InvestigatorName = "Jane Doe, EnCE, CCE",
            Organization = "Federal Digital Forensics Laboratory",
            SourcePath = @"E:\images\suspect_drive.e01",
            EvidenceSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            EvidenceMd5 = "d41d8cd98f00b204e9800998ecf8427e",
            TotalBytes = 512110190592L
        };

        var timeline = new ForensicTimeline();
        timeline.AddEvent(new DateTime(2026, 11, 21, 10, 0, 0, DateTimeKind.Utc), "USN_JOURNAL", "FILE_CREATED", "exfil.zip", "USN #1234");
        timeline.AddEvent(new DateTime(2026, 11, 21, 10, 5, 0, DateTimeKind.Utc), "AMCACHE", "SUSPICIOUS_EXECUTION", "miner.exe", "Double extension camouflage");

        var amcache = new List<AmcacheEntry>
        {
            new AmcacheEntry
            {
                Path = @"C:\Users\Public\miner.exe",
                Sha1 = "11223344556677889900aabbccddeeff11223344",
                FileSize = 1048576,
                IsSuspicious = true,
                SuspicionReason = "Executed from Public directory"
            }
        };

        var shellbags = new List<ShellbagRecord>
        {
            new ShellbagRecord
            {
                FullPath = @"F:\Secret_R&D_Designs",
                ItemType = ShellbagItemType.Directory,
                KeyLastWriteTimeUtc = new DateTime(2026, 11, 21, 10, 2, 0, DateTimeKind.Utc),
                RegistrySource = "UsrClass.dat"
            }
        };

        var mftRecords = new List<MftFileRecord>
        {
            new MftFileRecord
            {
                RecordNumber = 42,
                FileName = "backdoor.sys",
                CreationTimeUtc = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                FnCreationTimeUtc = new DateTime(2026, 11, 21, 9, 0, 0, DateTimeKind.Utc),
                IsTimestomped = true
            }
        };

        var entropy = new EntropyReport
        {
            TotalBytesAnalyzed = 1048576,
            TotalBlocks = 16,
            MeanEntropy = 7.96,
            DominantCategory = EntropyCategory.EncryptedOrRansomware,
            IsSuspiciousRansomware = true,
            SuspicionReason = "CRITICAL: 100% of blocks exhibit cryptographic entropy without compression headers"
        };

        string html = CourtReportGenerator.GenerateHtmlReport(meta, timeline, amcache, shellbags, mftRecords, entropy);

        Check(html.Contains("CR-2026-9042"), "HTML must contain Case Number");
        Check(html.Contains("Jane Doe"), "HTML must contain Investigator Name");
        Check(html.Contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "HTML must contain SHA-256 Chain of Custody hash");
        Check(html.Contains("RULE 902(14)"), "HTML must cite Federal Rules of Evidence Rule 902(14)");
        Check(html.Contains("TIMESTOMPED"), "HTML must highlight MFT timestomping anomaly");
        Check(html.Contains("Secret_R&amp;D_Designs") || html.Contains("Secret_R&D_Designs"), "HTML must list Shellbags folder access");
        Check(html.Contains("miner.exe"), "HTML must report Amcache execution");
        Check(html.Contains("7.9600 bits/byte"), "HTML must display Mean Entropy");

        string outHtmlPath = Path.Combine(testDir, "report.html");
        File.WriteAllText(outHtmlPath, html, Encoding.UTF8);
        Check(File.Exists(outHtmlPath) && new FileInfo(outHtmlPath).Length > 1000, "HTML report should be successfully written to disk");
    }

    private static void TestMarkdownReportGeneration(string testDir)
    {
        var meta = new ForensicCaseMetadata
        {
            CaseNumber = "INCIDENT-2026-B",
            InvestigatorName = "Alex Smith",
            SourcePath = @"C:\cases\disk.raw",
            EvidenceSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            TotalBytes = 1073741824L
        };

        string md = CourtReportGenerator.GenerateMarkdownReport(meta);
        Check(md.Contains("INCIDENT-2026-B"), "MD must contain Case Number");
        Check(md.Contains("Alex Smith"), "MD must contain Examiner Name");
        Check(md.Contains("1.00 GiB"), "MD must format size as 1.00 GiB");
        Check(md.Contains("Rule 902(14)"), "MD must cite Rule 902(14)");
    }
}
