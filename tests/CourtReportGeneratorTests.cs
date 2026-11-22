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

        var srum = new SrumReport
        {
            DatabasePath = @"C:\Windows\System32\sru\SRUDB.dat",
            NetworkEntries = new List<SrumNetworkEntry>
            {
                new SrumNetworkEntry { AppName = "exfil.exe", BytesSent = 104857600, BytesReceived = 1024, InterfaceType = "Wireless", IsSuspicious = true, SuspicionReason = "High volume wireless exfiltration" }
            }
        };

        var jumpLists = new JumpListReport
        {
            SourcePath = @"C:\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations",
            Entries = new List<JumpListEntry>
            {
                new JumpListEntry { AppName = "Explorer", TargetPath = @"E:\Confidential\source_code.zip", AccessCount = 5, PinStatus = "Pinned" }
            }
        };

        var recycleBin = new RecycleBinReport
        {
            SourcePath = @"C:\$Recycle.Bin",
            Entries = new List<RecycleBinEntry>
            {
                new RecycleBinEntry { OriginalFilePath = @"C:\Users\suspect\Documents\shredded.docx", OriginalFileSize = 8192, HasDataFile = true, UserSid = "S-1-5-21-1234567890-1001" }
            }
        };

        var extensions = new BrowserExtensionsReport
        {
            SourcePath = @"C:\Users\suspect\AppData\Local\Google\Chrome\User Data\Default\Extensions",
            Extensions = new List<BrowserExtensionArtifact>
            {
                new BrowserExtensionArtifact { Name = "MetaMask", ExtensionId = "nkbihfbeogaeaoehlefnkodbefgpgknn", Category = "Crypto Wallet", ManifestVersion = "3", LevelDbKeyCount = 12 }
            }
        };

        var evtx = new EvtxAuditReport
        {
            SourcePath = @"C:\Windows\System32\winevt\Logs\Security.evtx",
            Records = new List<EvtxRecord>
            {
                new EvtxRecord { EventId = 4625, ProviderName = "Microsoft-Windows-Security-Auditing", ComputerName = "TARGET-PC", TimestampUtc = new DateTime(2026, 11, 21, 10, 0, 0, DateTimeKind.Utc) }
            }
        };

        var vss = new VssReport
        {
            SourcePath = @"C:\images\suspect_drive.e01",
            Snapshots = new List<VssSnapshotRecord>
            {
                new VssSnapshotRecord { SnapshotId = Guid.NewGuid(), VolumeSize = 512110190592L, AllocatedBytes = 104857600L, Attributes = "ClientAccessible" }
            }
        };

        var telegram = new TelegramForensicReport
        {
            TargetPath = @"C:\Users\suspect\AppData\Roaming\Telegram Desktop\tdata",
            TotalTdfContainersFound = 14,
            ActiveMessagesCount = 42,
            CarvedMessagesCount = 8,
            DesktopProfiles = new List<TelegramDesktopProfile>
            {
                new TelegramDesktopProfile { Path = @"C:\Users\suspect\AppData\Roaming\Telegram Desktop\tdata", HasKeyData = true, HasPasscode = false, AccountsCount = 1, MediaFilesCount = 120, TotalTdfFiles = 14 }
            },
            Messages = new List<TelegramMessageRecord>
            {
                new TelegramMessageRecord { MessageId = 1001, PeerId = 987654321, PeerType = "User", TimestampUtc = new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc), IsOut = false, Text = "Confidential transfer confirmed", IsDeletedOrCarved = true, SourceOrigin = "FreelistPage" }
            }
        };

        string html = CourtReportGenerator.GenerateHtmlReport(meta, timeline, amcache, shellbags, mftRecords, entropy, srum, jumpLists, recycleBin, extensions, evtx, vss, telegram);

        Check(html.Contains("CR-2026-9042"), "HTML must contain Case Number");
        Check(html.Contains("Jane Doe"), "HTML must contain Investigator Name");
        Check(html.Contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "HTML must contain SHA-256 Chain of Custody hash");
        Check(html.Contains("RULE 902(14)"), "HTML must cite Federal Rules of Evidence Rule 902(14)");
        Check(html.Contains("TIMESTOMPED"), "HTML must highlight MFT timestomping anomaly");
        Check(html.Contains("Secret_R&amp;D_Designs") || html.Contains("Secret_R&D_Designs"), "HTML must list Shellbags folder access");
        Check(html.Contains("miner.exe"), "HTML must report Amcache execution");
        Check(html.Contains("7.9600 bits/byte"), "HTML must display Mean Entropy");
        Check(html.Contains("SRUM Network Exfiltration"), "HTML must contain SRUM section");
        Check(html.Contains("Jump Lists Application History"), "HTML must contain Jump Lists section");
        Check(html.Contains("Recycle Bin ($I/$R) Deletion"), "HTML must contain Recycle Bin section");
        Check(html.Contains("Browser Extensions &amp; Cryptocurrency") || html.Contains("Browser Extensions & Cryptocurrency"), "HTML must contain Browser Extensions section");
        Check(html.Contains("Windows Event Log (EVTX)"), "HTML must contain EVTX section");
        Check(html.Contains("Volume Shadow Copies (VSS)"), "HTML must contain VSS section");
        Check(html.Contains("Telegram Desktop &amp; Mobile Forensic Artifacts") || html.Contains("Telegram Desktop & Mobile Forensic Artifacts"), "HTML must contain Telegram section");
        Check(html.Contains("Confidential transfer confirmed"), "HTML must contain carved Telegram message");
        Check(html.Contains("FreelistPage"), "HTML must contain carved origin");

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

        var srumMd = new SrumReport
        {
            DatabasePath = @"C:\Windows\System32\sru\SRUDB.dat",
            NetworkEntries = new List<SrumNetworkEntry> { new SrumNetworkEntry { AppName = "test.exe", BytesSent = 100 } }
        };
        var jlMd = new JumpListReport { Entries = new List<JumpListEntry> { new JumpListEntry { AppName = "test", TargetPath = @"C:\test.txt" } } };
        var rbMd = new RecycleBinReport { Entries = new List<RecycleBinEntry> { new RecycleBinEntry { OriginalFilePath = @"C:\del.txt" } } };
        var extMd = new BrowserExtensionsReport { Extensions = new List<BrowserExtensionArtifact> { new BrowserExtensionArtifact { Name = "Wallet", ExtensionId = "123" } } };
        var evtxMd = new EvtxAuditReport { Records = new List<EvtxRecord> { new EvtxRecord { EventId = 4624 } } };
        var vssMd = new VssReport { Snapshots = new List<VssSnapshotRecord> { new VssSnapshotRecord { SnapshotId = Guid.NewGuid() } } };
        var tgMd = new TelegramForensicReport
        {
            Messages = new List<TelegramMessageRecord>
            {
                new TelegramMessageRecord { MessageId = 555, PeerId = 111, TimestampUtc = new DateTime(2026, 11, 21, 14, 0, 0, DateTimeKind.Utc), Text = "Confirmed target coordinates", IsDeletedOrCarved = false }
            }
        };

        string md = CourtReportGenerator.GenerateMarkdownReport(meta, srum: srumMd, jumpLists: jlMd, recycleBin: rbMd, extensions: extMd, evtx: evtxMd, vss: vssMd, telegram: tgMd);
        Check(md.Contains("INCIDENT-2026-B"), "MD must contain Case Number");
        Check(md.Contains("Alex Smith"), "MD must contain Examiner Name");
        Check(md.Contains("1.00 GiB"), "MD must format size as 1.00 GiB");
        Check(md.Contains("Rule 902(14)"), "MD must cite Rule 902(14)");
        Check(md.Contains("Windows SRUM Network Exfiltration"), "MD must contain SRUM section");
        Check(md.Contains("Windows Jump Lists Application History"), "MD must contain Jump Lists section");
        Check(md.Contains("Windows Recycle Bin ($I/$R) Deletion"), "MD must contain Recycle Bin section");
        Check(md.Contains("Browser Extensions & Cryptocurrency Wallet Artifacts"), "MD must contain Browser Extensions section");
        Check(md.Contains("Windows Event Log (EVTX) High Risk"), "MD must contain EVTX section");
        Check(md.Contains("Volume Shadow Copies (VSS) Historical"), "MD must contain VSS section");
        Check(md.Contains("Telegram Desktop & Mobile Forensic Artifacts"), "MD must contain Telegram section");
        Check(md.Contains("Confirmed target coordinates"), "MD must contain Telegram message text");
    }
}
