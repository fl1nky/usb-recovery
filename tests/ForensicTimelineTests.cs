using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class ForensicTimelineTests
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
        TestMultiSourceEventAggregation();
        TestChronologicalSorting();
        TestFilteringAndTimeWindow();
        TestCsvExport();

        Console.WriteLine("PASS ForensicTimelineTests: {0} checks passed; multi-source event aggregation (USN, MFT, EVTX, Prefetch, Browser, Shimcache), sorting, keyword/range filtering, and RFC 4180 CSV export verified.", checks);
    }

    private static void TestMultiSourceEventAggregation()
    {
        var timeline = new ForensicTimeline();

        // 1. USN Record
        var usn = new UsnRecord
        {
            FileName = "invoice.pdf.exe",
            TimeStampUtc = new DateTime(2026, 11, 21, 14, 0, 5, DateTimeKind.Utc),
            Reason = UsnReason.FileCreate | UsnReason.Close,
            Usn = 100,
            FileReferenceNumber = 555UL
        };
        timeline.AddUsnRecords(new[] { usn });

        // 2. MFT Record
        var mft = new MftFileRecord
        {
            FileName = "invoice.pdf.exe",
            CreationTimeUtc = new DateTime(2026, 11, 21, 14, 0, 4, DateTimeKind.Utc),
            ModificationTimeUtc = new DateTime(2026, 11, 21, 14, 0, 5, DateTimeKind.Utc),
            IsAllocated = false,
            FileSize = 204800
        };
        timeline.AddMftRecords(new[] { mft });

        // 3. Prefetch
        var pf = new PrefetchArtifact
        {
            ExecutableName = "INVOICE.PDF.EXE",
            Hash = "0x89ABCDEF",
            RunCount = 1,
            LastRunTimes = new List<DateTime> { new DateTime(2026, 11, 21, 14, 0, 8, DateTimeKind.Utc) }
        };
        timeline.AddPrefetch(pf);

        // 4. Browser History
        var bh = new BrowserHistoryRecord
        {
            Browser = BrowserType.Chromium,
            Url = "http://malicious-delivery.com/invoice.pdf.exe",
            Title = "Invoice Download Portal",
            LastVisitUtc = new DateTime(2026, 11, 21, 14, 0, 0, DateTimeKind.Utc),
            VisitCount = 1
        };
        timeline.AddBrowserHistory(new[] { bh });

        // 5. EVTX
        var ev = new EvtxRecord
        {
            EventId = 4688,
            Channel = "Security",
            ProviderName = "Microsoft-Windows-Security-Auditing",
            TimestampUtc = new DateTime(2026, 11, 21, 14, 0, 9, DateTimeKind.Utc),
            RecordId = 123456
        };
        timeline.AddEvtxRecords(new[] { ev });

        // 6. Shimcache
        var sc = new AppCompatCacheEntry
        {
            Path = "C:\\Users\\Admin\\Downloads\\invoice.pdf.exe",
            LastModifiedTimeUtc = new DateTime(2026, 11, 21, 14, 0, 6, DateTimeKind.Utc),
            Executed = true,
            EntryIndex = 1
        };
        timeline.AddShimcache(new[] { sc });

        // 7. Amcache
        var ac = new AmcacheEntry
        {
            Path = @"C:\Users\Admin\Downloads\invoice.pdf.exe",
            Sha1 = "3b71c26b911e2f790c37554be50e7b752945d8f2",
            KeyLastWriteTimeUtc = new DateTime(2026, 11, 21, 14, 0, 7, DateTimeKind.Utc),
            IsSuspicious = true,
            SuspicionReason = "Double extension"
        };
        timeline.AddAmcache(new[] { ac });

        // 8. Shellbags
        var sb = new ShellbagRecord
        {
            FullPath = @"E:\Exfiltrated_Docs",
            ItemType = ShellbagItemType.Directory,
            KeyLastWriteTimeUtc = new DateTime(2026, 11, 21, 14, 5, 0, DateTimeKind.Utc),
            RegistrySource = "UsrClass.dat"
        };
        timeline.AddShellbags(new[] { sb });

        // 9. LNK Shortcut
        var lnk = new LnkArtifact
        {
            TargetPath = @"E:\Confidential\financial_plans.xlsx",
            TargetFileSize = 654321,
            WriteTimeUtc = new DateTime(2026, 11, 21, 14, 6, 0, DateTimeKind.Utc),
            VolumeLabel = "CORP_USB",
            MacAddress = "00:1A:2B:3C:4D:5E"
        };
        timeline.AddLnk(lnk);

        // 10. exFAT Carved Records
        var exFatRec = new ExFatScout.ExFatFileRecord
        {
            Name = "exfiltrated_plan.docx",
            FullPath = @"$CARVED_DELETED\exfiltrated_plan.docx",
            Size = 40960,
            IsDeleted = true,
            NoFatChain = true,
            ModifiedTimeUtc = new DateTime(2026, 11, 21, 14, 7, 0, DateTimeKind.Utc)
        };
        timeline.AddExFatFiles(new[] { exFatRec });

        // 11. HFS+ Carved Records
        var hfsRec = new HfsPlusScout.HfsPlusFileRecord
        {
            Cnid = 88,
            ParentCnid = 2,
            Name = "financial_records_hfs.numbers",
            FullPath = @"$CARVED_HFS\financial_records_hfs.numbers",
            Size = 51200,
            IsDeleted = true,
            ModifyTimeUtc = new DateTime(2026, 11, 21, 14, 8, 0, DateTimeKind.Utc)
        };
        timeline.AddHfsPlusFiles(new[] { hfsRec });

        // 12. SRUM Network Exfiltration Entry
        var srumNet = new SrumNetworkEntry
        {
            AppId = 5,
            AppName = @"C:\Users\Admin\AppData\Local\Temp\exfil.exe",
            UserSid = "S-1-5-21-1234567890-1001",
            BytesSent = 500000000,
            BytesReceived = 10000,
            InterfaceType = "Wireless (802.11)",
            IsSuspicious = true,
            SuspicionReason = "High-volume data transfer",
            TimestampUtc = new DateTime(2026, 11, 21, 14, 9, 0, DateTimeKind.Utc)
        };
        timeline.AddSrumNetworkEntries(new[] { srumNet });

        // 13. Jump List MRU & Pinned Entries
        var jlEntry = new JumpListEntry
        {
            AppId = "1b4dd67f29cb1962",
            AppName = "Windows Explorer",
            EntryId = 1,
            TargetPath = @"C:\Users\Admin\Documents\Confidential_Contract.docx",
            AccessCount = 12,
            LastAccessUtc = new DateTime(2026, 11, 21, 14, 10, 0, DateTimeKind.Utc),
            PinStatus = "Pinned",
            NetBiosName = "EXECUTIVE-PC",
            TargetFileSize = 75000,
            Category = "AutomaticDestinations"
        };
        timeline.AddJumpListEntries(new[] { jlEntry });

        // 14. Recycle Bin Deleted Entry
        var rbEntry = new RecycleBinEntry
        {
            IndexFileName = "$I999999.pdf",
            DataFileName = "$R999999.pdf",
            OriginalFileName = "Wiped_Evidence.pdf",
            OriginalFilePath = @"C:\Users\Admin\Documents\Wiped_Evidence.pdf",
            OriginalFileSize = 120000,
            DeletionTimeUtc = new DateTime(2026, 11, 21, 14, 11, 0, DateTimeKind.Utc),
            UserSid = "S-1-5-21-1234567890-1001",
            HasDataFile = true
        };
        timeline.AddRecycleBinEntries(new[] { rbEntry });

        // 15. VSS Snapshot Entry
        var vssRecord = new VssSnapshotRecord
        {
            SnapshotId = Guid.NewGuid(),
            SnapshotSetId = Guid.NewGuid(),
            CreationTimeUtc = new DateTime(2026, 11, 21, 14, 12, 0, DateTimeKind.Utc),
            VolumeSize = 100000000000L,
            AllocatedBytes = 500000000L,
            StoreBlockCount = 30517,
            MachineName = "DESKTOP-FORENSIC",
            Attributes = "ClientAccessible",
            IsCarved = true
        };
        timeline.AddVssSnapshots(new[] { vssRecord });

        // 16. ISO / UDF File Record
        var isoFile = new IsoUdfFileRecord
        {
            Name = "ExfilArchive.iso",
            FullPath = "Backups/ExfilArchive.iso",
            Size = 700000000,
            ExtentOffset = 204800,
            RecordingTimeUtc = new DateTime(2026, 11, 21, 14, 13, 0, DateTimeKind.Utc),
            IsDirectory = false,
            IsJoliet = true,
            IsCarved = false
        };
        timeline.AddIsoUdfFiles(new[] { isoFile });

        Check(timeline.Count >= 17, "Timeline collected at least 17 multi-source events");
    }

    private static void TestChronologicalSorting()
    {
        var timeline = new ForensicTimeline();

        // Add 3 events out of order
        timeline.AddEvent(new DateTime(2026, 11, 21, 15, 0, 0, DateTimeKind.Utc), "SOURCE_C", "ACTION_3", "file3.txt", "Third");
        timeline.AddEvent(new DateTime(2026, 11, 21, 13, 0, 0, DateTimeKind.Utc), "SOURCE_A", "ACTION_1", "file1.txt", "First");
        timeline.AddEvent(new DateTime(2026, 11, 21, 14, 0, 0, DateTimeKind.Utc), "SOURCE_B", "ACTION_2", "file2.txt", "Second");

        timeline.SortChronological(true); // ascending

        Check(timeline.Events[0].Action == "ACTION_1", "First event chronologically is ACTION_1 (13:00)");
        Check(timeline.Events[1].Action == "ACTION_2", "Second event chronologically is ACTION_2 (14:00)");
        Check(timeline.Events[2].Action == "ACTION_3", "Third event chronologically is ACTION_3 (15:00)");

        timeline.SortChronological(false); // descending
        Check(timeline.Events[0].Action == "ACTION_3", "Descending sort puts latest event first (15:00)");
    }

    private static void TestFilteringAndTimeWindow()
    {
        var timeline = new ForensicTimeline();
        timeline.AddEvent(new DateTime(2026, 11, 21, 10, 0, 0, DateTimeKind.Utc), "TEST", "CREATE", "safe.txt", "Normal file");
        timeline.AddEvent(new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc), "TEST", "DELETE", "malware_payload.bin", "Dropped Trojan");
        timeline.AddEvent(new DateTime(2026, 11, 21, 14, 0, 0, DateTimeKind.Utc), "TEST", "CREATE", "report.docx", "Work report");

        // Time window filter: 11:00 to 13:00
        var window = timeline.FilterByTimeRange(
            new DateTime(2026, 11, 21, 11, 0, 0, DateTimeKind.Utc),
            new DateTime(2026, 11, 21, 13, 0, 0, DateTimeKind.Utc)
        );
        Check(window.Count == 1, "Time range filter returned exactly 1 event");
        Check(window[0].TargetPath == "malware_payload.bin", "Window event matches target in timeframe");

        // Keyword filter: "trojan"
        var keywordMatches = timeline.FilterByKeyword("trojan");
        Check(keywordMatches.Count == 1, "Keyword filter found matching event");
        Check(keywordMatches[0].Description == "Dropped Trojan", "Keyword matched Trojan description");
    }

    private static void TestCsvExport()
    {
        var timeline = new ForensicTimeline();
        timeline.AddEvent(
            new DateTime(2026, 11, 21, 16, 45, 0, DateTimeKind.Utc),
            "TEST_SOURCE",
            "TEST_ACTION",
            "C:\\Folder with \"Quotes\"\\file,name.dat",
            "Description with, commas and \"quotes\""
        );

        using (var ms = new MemoryStream())
        {
            timeline.ExportToCsv(ms);
            string csv = Encoding.UTF8.GetString(ms.ToArray());

            Check(csv.Contains("Timestamp (UTC),Source,Action,Target Path,Description,Extra Details"), "CSV header present");
            Check(csv.Contains("\"2026-11-21 16:45:00\""), "Timestamp formatted accurately in CSV");
            Check(csv.Contains("\"TEST_SOURCE\""), "Source present in CSV");
            Check(csv.Contains("\"\"Quotes\"\""), "Quotes escaped with double quotes per RFC 4180");
        }
    }
}
