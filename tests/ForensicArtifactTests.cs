using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class ForensicArtifactTests
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
        TestEvtxParser();
        TestEvtxSlackCarving();
        TestPrefetchParserUncompressed();
        TestPrefetchMamDecompression();
        TestPrefetchMultiVersion();
        TestLnkParser();
        TestShellbagsParser();
        TestBrowserTimestampConversions();
        TestChromiumSimpleCache();
        TestFirefoxCache2();
        TestChromiumHistoryCarving();
        TestFirefoxHistoryCarving();
        TestForensicWriteBlockingGuarantees();

        Console.WriteLine("PASS ForensicArtifactTests: {0} checks passed; EVTX, Prefetch (MAM XPRESS Huffman), LNK, Shellbags, Browser History, and Cache verified.", checks);
    }

    private static void TestEvtxParser()
    {
        byte[] chunk = CreateSyntheticEvtxChunk(101, 4624, "Security", "CORP-DC-01", "Microsoft-Windows-Security-Auditing", "AdminUser");
        List<EvtxRecord> records = EvtxParser.Parse(chunk);

        Check(records != null, "EVTX records list is not null");
        Check(records.Count == 1, "Parsed exactly 1 EVTX record");

        EvtxRecord r = records[0];
        Check(r.RecordId == 101, "RecordId matches 101");
        Check(r.EventId == 4624, "EventId matches 4624");
        Check(r.Channel == "Security", "Channel matches Security");
        Check(r.ComputerName == "CORP-DC-01", "ComputerName matches CORP-DC-01");
        Check(r.ProviderName == "Microsoft-Windows-Security-Auditing", "ProviderName matches");
        Check(r.Properties.ContainsKey("TargetUserName"), "Properties contains TargetUserName");
        Check(r.Properties["TargetUserName"] == "AdminUser", "TargetUserName matches AdminUser");
        Check(r.TimestampUtc > DateTime.MinValue, "TimestampUtc is valid");
    }

    private static void TestEvtxSlackCarving()
    {
        byte[] chunk = new byte[65536];
        Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(chunk, 0);
        BitConverter.GetBytes((uint)1024).CopyTo(chunk, 48); // FreeSpaceOffset

        // Active record at 512
        byte[] rec1 = CreateSyntheticRecordBytes(201, 1102, "Security", "SERVER-01", "SecurityAudit", "User1");
        Buffer.BlockCopy(rec1, 0, chunk, 512, rec1.Length);

        // Slack-space carved residual record at 2048
        byte[] rec2 = CreateSyntheticRecordBytes(202, 4625, "Security", "SERVER-01", "SecurityAudit", "Attacker");
        Buffer.BlockCopy(rec2, 0, chunk, 2048, rec2.Length);

        List<EvtxRecord> records = EvtxParser.Parse(chunk);
        Check(records.Count == 2, "Both active and slack-space carved records recovered (expected 2, got " + records.Count + ")");
        Check(records[0].RecordId == 201, "Active record ID is 201");
        Check(records[1].RecordId == 202, "Carved record ID is 202");
        Check(records[1].EventId == 4625, "Carved record EventId is 4625 (Logon Failure)");
        Check(records[1].Properties["TargetUserName"] == "Attacker", "Carved record target user is Attacker");
    }

    private static void TestPrefetchParserUncompressed()
    {
        byte[] pfData = CreateSyntheticPrefetchV30("CMD.EXE", 0x3F2A1B0C, 15, new string[] {
            "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
            "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
            "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\CMD.EXE"
        }, 0x12345678);

        PrefetchArtifact artifact = PrefetchParser.Parse(pfData);

        Check(artifact != null, "Prefetch artifact not null");
        Check(artifact.ExecutableName == "CMD.EXE", "Executable name matches CMD.EXE");
        Check(artifact.Hash == "3F2A1B0C", "Hash matches 3F2A1B0C");
        Check(artifact.Version == 30, "Version matches 30");
        Check(artifact.RunCount == 15, "Run count matches 15");
        Check(artifact.LastRunTimes.Count > 0, "LastRunTimes has entries");
        Check(artifact.LoadedFiles.Count == 3, "LoadedFiles count is 3");
        Check(artifact.LoadedFiles.Contains("\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL"), "LoadedFiles contains ntdll.dll");
        Check(artifact.VolumeSerials.Count > 0, "VolumeSerials has entries");
    }

    private static void TestPrefetchMamDecompression()
    {
        byte[] uncompressed = CreateSyntheticPrefetchV30("POWERSHELL.EXE", 0x9A8B7C6D, 42, new string[] {
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\POWERSHELL.EXE"
        }, 0xAABBCCDD);

        byte[] compressedBody = MsXpressHuffman.CompressLiteralOnly(uncompressed);
        byte[] mamFile = new byte[8 + compressedBody.Length];
        mamFile[0] = 0x4D; mamFile[1] = 0x41; mamFile[2] = 0x4D; mamFile[3] = 0x04; // MAM\x04
        BitConverter.GetBytes((uint)uncompressed.Length).CopyTo(mamFile, 4);
        Buffer.BlockCopy(compressedBody, 0, mamFile, 8, compressedBody.Length);

        PrefetchArtifact artifact = PrefetchParser.Parse(mamFile);

        Check(artifact != null, "MAM prefetch artifact parsed successfully");
        Check(artifact.ExecutableName == "POWERSHELL.EXE", "MAM ExecutableName matches POWERSHELL.EXE");
        Check(artifact.Hash == "9A8B7C6D", "MAM Hash matches 9A8B7C6D");
        Check(artifact.RunCount == 42, "MAM RunCount matches 42");
        Check(artifact.LoadedFiles.Count == 1, "MAM LoadedFiles count is 1");
    }

    private static void TestPrefetchMultiVersion()
    {
        // Version 17 (Windows XP)
        byte[] v17 = new byte[256];
        BitConverter.GetBytes((uint)17).CopyTo(v17, 0);
        Encoding.ASCII.GetBytes("SCCA").CopyTo(v17, 4);
        Encoding.Unicode.GetBytes("NOTEPAD.EXE\0").CopyTo(v17, 16);
        BitConverter.GetBytes((uint)0x11223344).CopyTo(v17, 76);
        BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(v17, 120);
        BitConverter.GetBytes((uint)7).CopyTo(v17, 144);

        PrefetchArtifact a17 = PrefetchParser.Parse(v17);
        Check(a17.Version == 17, "v17 parsed");
        Check(a17.ExecutableName == "NOTEPAD.EXE", "v17 executable name matches");
        Check(a17.RunCount == 7, "v17 run count matches");

        // Version 23 (Windows Vista / 7)
        byte[] v23 = new byte[256];
        BitConverter.GetBytes((uint)23).CopyTo(v23, 0);
        Encoding.ASCII.GetBytes("SCCA").CopyTo(v23, 4);
        Encoding.Unicode.GetBytes("CALC.EXE\0").CopyTo(v23, 16);
        BitConverter.GetBytes((uint)0x55667788).CopyTo(v23, 76);
        BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(v23, 128);
        BitConverter.GetBytes((uint)19).CopyTo(v23, 152);

        PrefetchArtifact a23 = PrefetchParser.Parse(v23);
        Check(a23.Version == 23, "v23 parsed");
        Check(a23.ExecutableName == "CALC.EXE", "v23 executable name matches");
        Check(a23.RunCount == 19, "v23 run count matches");
    }

    private static void TestLnkParser()
    {
        byte[] lnkBytes = CreateSyntheticLnk("C:\\Windows\\System32\\cmd.exe", 284160, "Windows Command Prompt", "CORP-LAPTOP-01", "00:11:22:33:44:55");

        LnkArtifact artifact = LnkParser.Parse(lnkBytes);

        Check(artifact != null, "LNK artifact not null");
        Check(artifact.TargetPath == "C:\\Windows\\System32\\cmd.exe", "TargetPath matches C:\\Windows\\System32\\cmd.exe (got: " + artifact.TargetPath + ")");
        Check(artifact.TargetFileSize == 284160, "TargetFileSize matches 284160");
        Check(artifact.Description == "Windows Command Prompt", "Description matches");
        Check(artifact.MachineId == "CORP-LAPTOP-01", "MachineId matches CORP-LAPTOP-01");
        Check(artifact.MacAddress == "00:11:22:33:44:55", "MacAddress matches 00:11:22:33:44:55");
        Check(artifact.CreationTimeUtc > DateTime.MinValue, "CreationTimeUtc is set");
    }

    private static void TestShellbagsParser()
    {
        byte[] mruListEx = new byte[] {
            0x00, 0x00, 0x00, 0x00, // Slot 0
            0x01, 0x00, 0x00, 0x00, // Slot 1
            0xFF, 0xFF, 0xFF, 0xFF  // Terminator
        };

        Dictionary<int, byte[]> childItems = new Dictionary<int, byte[]>();
        childItems[0] = CreateShellItemPath("E:", "Evidence");
        childItems[1] = CreateShellItemPath("E:", "Evidence", "USB_Export");

        List<ShellbagArtifact> bags = LnkParser.ParseShellbags(mruListEx, childItems);

        Check(bags != null, "Shellbag list not null");
        Check(bags.Count == 2, "Parsed 2 shellbags");
        Check(bags[0].SlotId == 0, "First shellbag SlotId is 0");
        Check(bags[0].AccessOrder == 0, "First shellbag AccessOrder is 0");
        Check(bags[0].FolderPath == "E:\\Evidence", "First shellbag path is E:\\Evidence (got: " + bags[0].FolderPath + ")");
        Check(bags[1].SlotId == 1, "Second shellbag SlotId is 1");
        Check(bags[1].AccessOrder == 1, "Second shellbag AccessOrder is 1");
        Check(bags[1].FolderPath == "E:\\Evidence\\USB_Export", "Second shellbag path is E:\\Evidence\\USB_Export (got: " + bags[1].FolderPath + ")");
    }

    private static void TestBrowserTimestampConversions()
    {
        // 1. WebKit Timestamp Round-Trip
        DateTime expectedUtc = new DateTime(2026, 11, 16, 21, 30, 0, DateTimeKind.Utc);
        long webKitMicro = BrowserTimestampConverter.UtcToWebKitTime(expectedUtc);
        DateTime convertedUtc = BrowserTimestampConverter.WebKitTimeToUtc(webKitMicro);
        Check(convertedUtc == expectedUtc, "WebKit timestamp round-trip matches exactly");

        // 2. PRTime Timestamp Round-Trip
        long prTimeMicro = BrowserTimestampConverter.UtcToPrTime(expectedUtc);
        DateTime convertedPrTime = BrowserTimestampConverter.PrTimeToUtc(prTimeMicro);
        Check(convertedPrTime == expectedUtc, "PRTime timestamp round-trip matches exactly");

        // 3. Clamping boundary checks
        Check(BrowserTimestampConverter.WebKitTimeToUtc(0) == DateTime.MinValue, "Zero WebKit maps to MinValue");
        Check(BrowserTimestampConverter.WebKitTimeToUtc(-100) == DateTime.MinValue, "Negative WebKit maps to MinValue");
        Check(BrowserTimestampConverter.WebKitTimeToUtc(long.MaxValue) == DateTime.MaxValue, "Max WebKit maps to MaxValue");
        Check(BrowserTimestampConverter.PrTimeToUtc(0) == DateTime.MinValue, "Zero PRTime maps to MinValue");
        Check(BrowserTimestampConverter.PrTimeToUtc(-100) == DateTime.MinValue, "Negative PRTime maps to MinValue");
        Check(BrowserTimestampConverter.PrTimeToUtc(long.MaxValue) == DateTime.MaxValue, "Max PRTime maps to MaxValue");
    }

    private static void TestChromiumSimpleCache()
    {
        using (MemoryStream ms = new MemoryStream())
        {
            ulong magic = 0xfcfb6d0543706173UL;
            byte[] keyBytes = Encoding.UTF8.GetBytes("https://usb-recovery.example.org/download.zip");
            ms.Write(BitConverter.GetBytes(magic), 0, 8);
            ms.Write(BitConverter.GetBytes((uint)1), 0, 4); // version
            ms.Write(BitConverter.GetBytes((uint)keyBytes.Length), 0, 4); // key length
            ms.Write(BitConverter.GetBytes((uint)0x12345678), 0, 4); // key hash
            ms.Write(keyBytes, 0, keyBytes.Length);

            byte[] httpHead = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n\r\n");
            ms.Write(httpHead, 0, httpHead.Length);

            ms.Seek(0, SeekOrigin.Begin);
            BrowserCacheRecord cacheRec = BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy_0");
            Check(cacheRec != null, "Simple cache parsed successfully");
            Check(cacheRec.Browser == BrowserType.Chromium, "Browser is Chromium");
            Check(cacheRec.KeyUrl == "https://usb-recovery.example.org/download.zip", "Key URL extracted");
            Check(cacheRec.HttpStatusCode == 200, "HTTP Status 200 parsed");
            Check(cacheRec.ContentType == "application/zip", "Content-Type application/zip parsed");
        }
    }

    private static void TestFirefoxCache2()
    {
        using (MemoryStream ms = new MemoryStream())
        {
            byte[] payload = new byte[100];
            ms.Write(payload, 0, payload.Length);

            byte[] keyBytes = Encoding.UTF8.GetBytes(":https://firefox.example.org/logo.svg");
            uint keyLen = (uint)keyBytes.Length;
            byte[] httpHeaders = Encoding.ASCII.GetBytes("request-method\0GET\0response-head\0HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\n\0\0");
            uint metaSize = 20 + keyLen + (uint)httpHeaders.Length;

            byte[] meta = new byte[metaSize];
            meta[3] = 5; // fetch count = 5
            meta[4] = 0x69; meta[5] = 0x1A; meta[6] = 0x62; meta[7] = 0x00; // lastFetched = 1763328000
            meta[16] = (byte)(keyLen >> 24); meta[17] = (byte)(keyLen >> 16);
            meta[18] = (byte)(keyLen >> 8);  meta[19] = (byte)(keyLen);
            Array.Copy(keyBytes, 0, meta, 20, keyBytes.Length);
            Array.Copy(httpHeaders, 0, meta, 20 + keyBytes.Length, httpHeaders.Length);

            ms.Write(meta, 0, meta.Length);

            byte[] sizeFooter = new byte[] {
                (byte)(metaSize >> 24), (byte)(metaSize >> 16), (byte)(metaSize >> 8), (byte)(metaSize)
            };
            ms.Write(sizeFooter, 0, 4);

            ms.Seek(0, SeekOrigin.Begin);
            BrowserCacheRecord cacheRec = BrowserHistoryParser.ParseFirefoxCache2(ms, "dummy_cache2");
            Check(cacheRec != null, "Firefox Cache2 parsed successfully");
            Check(cacheRec.Browser == BrowserType.Firefox, "Browser is Firefox");
            Check(cacheRec.KeyUrl == "https://firefox.example.org/logo.svg", "Clean URL extracted");
            Check(cacheRec.FetchCount == 5, "Fetch count parsed (5)");
            Check(cacheRec.HttpStatusCode == 200, "HTTP Status 200 parsed");
            Check(cacheRec.ContentType == "image/svg+xml", "Content-Type image/svg+xml parsed");
        }
    }

    private static void TestChromiumHistoryCarving()
    {
        int pageSize = 4096;
        byte[] db = CreateSyntheticDatabase(pageSize, 2);
        int pageOffset = 4096;

        // Chromium urls table record:
        // Col 0: id = 1 (int8: ST=1)
        // Col 1: url = "https://github.com/microsoft/win32" (34 chars: ST=81)
        // Col 2: title = "Win32" (5 chars: ST=23)
        // Col 3: visit_count = 3 (int8: ST=1)
        // Col 4: typed_count = 1 (int8: ST=1)
        // Col 5: last_visit_time = 13376284800000000L (8-byte int: ST=6)
        // Col 6: hidden = 0 (const 0: ST=8)
        long[] urlSerialTypes = new long[] { 1, 81, 23, 1, 1, 6, 8 };
        object[] urlValues = new object[] {
            (long)1,
            "https://github.com/microsoft/win32",
            "Win32",
            (long)3,
            (long)1,
            13376284800000000L,
            0L
        };
        byte[] urlPayload = BuildRecordPayload(urlSerialTypes, urlValues);
        byte[] urlCell = BuildTableCell(1, urlPayload);

        // Chromium visits table record:
        // Col 0: id = 10 (int8: ST=1)
        // Col 1: url = 1 (int8: ST=1)
        // Col 2: visit_time = 13376284800000000L (8-byte int: ST=6)
        // Col 3: from_visit = 0 (const 0: ST=8)
        // Col 4: transition = 1 (Typed: ST=1)
        // Col 5: segment_id = 0 (const 0: ST=8)
        // Col 6: visit_duration = 120 (int8: ST=1)
        long[] visitSerialTypes = new long[] { 1, 1, 6, 8, 1, 8, 1 };
        object[] visitValues = new object[] {
            (long)10,
            (long)1,
            13376284800000000L,
            0L,
            (long)1, // Typed
            0L,
            (long)120
        };
        byte[] visitPayload = BuildRecordPayload(visitSerialTypes, visitValues);
        byte[] visitCell = BuildTableCell(10, visitPayload);

        // Place on Page 2
        int cell2Offset = pageSize - visitCell.Length;
        int cell1Offset = cell2Offset - urlCell.Length;

        Buffer.BlockCopy(visitCell, 0, db, pageOffset + cell2Offset, visitCell.Length);
        Buffer.BlockCopy(urlCell, 0, db, pageOffset + cell1Offset, urlCell.Length);

        // Header for Page 2
        db[pageOffset] = 0x0D; // Leaf Table
        db[pageOffset + 3] = 0; db[pageOffset + 4] = 2; // 2 cells
        db[pageOffset + 5] = (byte)(cell1Offset >> 8);
        db[pageOffset + 6] = (byte)(cell1Offset & 0xFF);
        // Cell pointer array
        db[pageOffset + 8] = (byte)(cell1Offset >> 8);
        db[pageOffset + 9] = (byte)(cell1Offset & 0xFF);
        db[pageOffset + 10] = (byte)(cell2Offset >> 8);
        db[pageOffset + 11] = (byte)(cell2Offset & 0xFF);

        using (MemoryStream ms = new MemoryStream(db))
        {
            List<BrowserHistoryRecord> history = BrowserHistoryParser.ParseChromium(ms);
            Check(history != null && history.Count > 0, "Chromium history records recovered");

            BrowserHistoryRecord target = null;
            for (int i = 0; i < history.Count; i++)
            {
                if (history[i].Url == "https://github.com/microsoft/win32")
                {
                    target = history[i];
                    break;
                }
            }

            Check(target != null, "Found GitHub URL record");
            Check(target.Title == "Win32", "Title is Win32");
            Check(target.LastVisitUtc > DateTime.MinValue, "LastVisitUtc is valid");
            Check(target.Visits.Count == 1, "Visit detail correlated");
            Check(target.Visits[0].VisitType == BrowserVisitType.Typed, "Visit type mapped to Typed");
            Check(target.Visits[0].DurationSeconds == 120, "Duration 120 seconds parsed");
        }
    }

    private static void TestFirefoxHistoryCarving()
    {
        int pageSize = 4096;
        byte[] db = CreateSyntheticDatabase(pageSize, 2);
        int pageOffset = 4096;

        // Firefox moz_places record:
        // Col 0: id = 1 (ST=1)
        // Col 1: url = "https://mozilla.org/firefox" (27 chars: ST=67)
        // Col 2: title = "Firefox" (7 chars: ST=27)
        // Col 3: rev_host = "gro.allizom." (12 chars: ST=37)
        // Col 4: visit_count = 2 (ST=1)
        // Col 5: hidden = 0 (ST=8)
        // Col 6: typed = 1 (ST=1)
        // Col 7: frecency = 100 (ST=1)
        // Col 8: last_visit_date = 1763328000000000L (8-byte int: ST=6)
        // Col 9: guid = "abc" (3 chars: ST=19)
        long[] placeSerialTypes = new long[] { 1, 67, 27, 37, 1, 8, 1, 1, 6, 19 };
        object[] placeValues = new object[] {
            (long)1,
            "https://mozilla.org/firefox",
            "Firefox",
            "gro.allizom.",
            (long)2,
            0L,
            (long)1,
            (long)100,
            1763328000000000L,
            "abc"
        };
        byte[] placePayload = BuildRecordPayload(placeSerialTypes, placeValues);
        byte[] placeCell = BuildTableCell(1, placePayload);

        // Firefox moz_historyvisits record:
        // Col 0: id = 50 (ST=1)
        // Col 1: from_visit = 0 (ST=8)
        // Col 2: place_id = 1 (ST=1)
        // Col 3: visit_date = 1763328000000000L (ST=6)
        // Col 4: visit_type = 1 (Link: ST=1)
        // Col 5: session = 1 (ST=1)
        long[] visitSerialTypes = new long[] { 1, 8, 1, 6, 1, 1 };
        object[] visitValues = new object[] {
            (long)50,
            0L,
            (long)1,
            1763328000000000L,
            (long)1, // Link
            (long)1
        };
        byte[] visitPayload = BuildRecordPayload(visitSerialTypes, visitValues);
        byte[] visitCell = BuildTableCell(50, visitPayload);

        int cell2Offset = pageSize - visitCell.Length;
        int cell1Offset = cell2Offset - placeCell.Length;

        Buffer.BlockCopy(visitCell, 0, db, pageOffset + cell2Offset, visitCell.Length);
        Buffer.BlockCopy(placeCell, 0, db, pageOffset + cell1Offset, placeCell.Length);

        db[pageOffset] = 0x0D;
        db[pageOffset + 3] = 0; db[pageOffset + 4] = 2;
        db[pageOffset + 5] = (byte)(cell1Offset >> 8);
        db[pageOffset + 6] = (byte)(cell1Offset & 0xFF);
        db[pageOffset + 8] = (byte)(cell1Offset >> 8);
        db[pageOffset + 9] = (byte)(cell1Offset & 0xFF);
        db[pageOffset + 10] = (byte)(cell2Offset >> 8);
        db[pageOffset + 11] = (byte)(cell2Offset & 0xFF);

        using (MemoryStream ms = new MemoryStream(db))
        {
            List<BrowserHistoryRecord> history = BrowserHistoryParser.ParseFirefox(ms);
            Check(history != null && history.Count > 0, "Firefox history records recovered");

            BrowserHistoryRecord target = null;
            for (int i = 0; i < history.Count; i++)
            {
                if (history[i].Url == "https://mozilla.org/firefox")
                {
                    target = history[i];
                    break;
                }
            }

            Check(target != null, "Found Firefox place record");
            Check(target.Title == "Firefox", "Title is Firefox");
            Check(target.LastVisitUtc > DateTime.MinValue, "LastVisitUtc is valid");
            Check(target.Visits.Count == 1, "Visit detail correlated");
            Check(target.Visits[0].VisitType == BrowserVisitType.Link, "Visit type mapped to Link");
        }
    }

    private static void TestForensicWriteBlockingGuarantees()
    {
        byte[] testChunk = CreateSyntheticEvtxChunk(999, 100, "App", "PC", "Source", "User");
        byte[] hash1 = ComputeSha256(testChunk);

        using (ReadOnlyTestStream ro = new ReadOnlyTestStream(testChunk))
        {
            List<EvtxRecord> recs = EvtxParser.Parse(ro);
            Check(recs != null, "EvtxParser read-only stream executed");
        }

        byte[] hash2 = ComputeSha256(testChunk);
        Check(ByteArraysEqual(hash1, hash2), "EVTX source stream unmodified");
    }

    // -------------------------------------------------------------------------
    // Synthetic Data Generation Helpers
    // -------------------------------------------------------------------------
    private static byte[] CreateSyntheticEvtxChunk(long recordId, int eventId, string channel, string computer, string provider, string user)
    {
        byte[] chunk = new byte[65536];
        Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(chunk, 0);

        byte[] recBytes = CreateSyntheticRecordBytes(recordId, eventId, channel, computer, provider, user);
        Buffer.BlockCopy(recBytes, 0, chunk, 512, recBytes.Length);

        uint freeSpaceOffset = (uint)(512 + recBytes.Length);
        BitConverter.GetBytes(freeSpaceOffset).CopyTo(chunk, 48);

        return chunk;
    }

    private static byte[] CreateSyntheticRecordBytes(long recordId, int eventId, string channel, string computer, string provider, string user)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            ms.Write(new byte[24], 0, 24); // Placeholder for record header

            ms.WriteByte(0x0C);
            ms.WriteByte(0x01); // inline
            ms.Write(BitConverter.GetBytes((uint)1000), 0, 4); // templateOffset
            ms.Write(BitConverter.GetBytes((uint)1), 0, 4);    // templateId

            using (MemoryStream tmpl = new MemoryStream())
            {
                WriteOpenElement(tmpl, "Event");
                WriteOpenElement(tmpl, "System");

                WriteOpenElement(tmpl, "Provider");
                WriteAttribute(tmpl, "Name");
                tmpl.WriteByte(0x0D); tmpl.Write(BitConverter.GetBytes((ushort)0), 0, 2); tmpl.WriteByte(0x01); // Sub 0
                tmpl.WriteByte(0x03);

                WriteOpenElement(tmpl, "EventID");
                tmpl.WriteByte(0x02);
                tmpl.WriteByte(0x0D); tmpl.Write(BitConverter.GetBytes((ushort)1), 0, 2); tmpl.WriteByte(0x07); // Sub 1
                tmpl.WriteByte(0x04);

                WriteOpenElement(tmpl, "Channel");
                tmpl.WriteByte(0x02);
                tmpl.WriteByte(0x0D); tmpl.Write(BitConverter.GetBytes((ushort)2), 0, 2); tmpl.WriteByte(0x01); // Sub 2
                tmpl.WriteByte(0x04);

                WriteOpenElement(tmpl, "Computer");
                tmpl.WriteByte(0x02);
                tmpl.WriteByte(0x0D); tmpl.Write(BitConverter.GetBytes((ushort)3), 0, 2); tmpl.WriteByte(0x01); // Sub 3
                tmpl.WriteByte(0x04);

                tmpl.WriteByte(0x04); // Close System

                WriteOpenElement(tmpl, "EventData");
                WriteOpenElement(tmpl, "Data");
                WriteAttribute(tmpl, "Name");
                WriteValueText(tmpl, "TargetUserName");
                tmpl.WriteByte(0x02);
                tmpl.WriteByte(0x0D); tmpl.Write(BitConverter.GetBytes((ushort)4), 0, 2); tmpl.WriteByte(0x01); // Sub 4
                tmpl.WriteByte(0x04);

                tmpl.WriteByte(0x04); // Close EventData
                tmpl.WriteByte(0x04); // Close Event
                tmpl.WriteByte(0x00); // EOF

                byte[] tBytes = tmpl.ToArray();
                ms.Write(BitConverter.GetBytes((uint)tBytes.Length), 0, 4);
                ms.Write(tBytes, 0, tBytes.Length);
            }

            // Substitution array: 5 values
            ms.Write(BitConverter.GetBytes((uint)5), 0, 4);
            byte[] val0Bytes = Encoding.Unicode.GetBytes(provider + "\0");
            byte[] val1Bytes = BitConverter.GetBytes((int)eventId);
            byte[] val2Bytes = Encoding.Unicode.GetBytes(channel + "\0");
            byte[] val3Bytes = Encoding.Unicode.GetBytes(computer + "\0");
            byte[] val4Bytes = Encoding.Unicode.GetBytes(user + "\0");

            ms.Write(BitConverter.GetBytes((ushort)0x01), 0, 2); ms.Write(BitConverter.GetBytes((ushort)val0Bytes.Length), 0, 2);
            ms.Write(BitConverter.GetBytes((ushort)0x07), 0, 2); ms.Write(BitConverter.GetBytes((ushort)val1Bytes.Length), 0, 2);
            ms.Write(BitConverter.GetBytes((ushort)0x01), 0, 2); ms.Write(BitConverter.GetBytes((ushort)val2Bytes.Length), 0, 2);
            ms.Write(BitConverter.GetBytes((ushort)0x01), 0, 2); ms.Write(BitConverter.GetBytes((ushort)val3Bytes.Length), 0, 2);
            ms.Write(BitConverter.GetBytes((ushort)0x01), 0, 2); ms.Write(BitConverter.GetBytes((ushort)val4Bytes.Length), 0, 2);

            ms.Write(val0Bytes, 0, val0Bytes.Length);
            ms.Write(val1Bytes, 0, val1Bytes.Length);
            ms.Write(val2Bytes, 0, val2Bytes.Length);
            ms.Write(val3Bytes, 0, val3Bytes.Length);
            ms.Write(val4Bytes, 0, val4Bytes.Length);

            ms.Write(new byte[4], 0, 4); // Trailing record size placeholder

            byte[] full = ms.ToArray();
            uint totalSize = (uint)full.Length;

            BitConverter.GetBytes(0x00002A2A).CopyTo(full, 0); // magic
            BitConverter.GetBytes(totalSize).CopyTo(full, 4);
            BitConverter.GetBytes(recordId).CopyTo(full, 8);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(full, 16);

            BitConverter.GetBytes(totalSize).CopyTo(full, full.Length - 4);
            return full;
        }
    }

    private static void WriteOpenElement(Stream s, string name)
    {
        s.WriteByte(0x01);
        s.Write(new byte[2], 0, 2);
        s.Write(new byte[4], 0, 4);
        WriteStringLiteral(s, name);
    }

    private static void WriteAttribute(Stream s, string name)
    {
        s.WriteByte(0x06);
        WriteStringLiteral(s, name);
    }

    private static void WriteValueText(Stream s, string text)
    {
        s.WriteByte(0x05);
        s.WriteByte(0x01);
        WriteStringLiteral(s, text);
    }

    private static void WriteStringLiteral(Stream s, string text)
    {
        s.Write(new byte[2], 0, 2);
        s.Write(BitConverter.GetBytes((ushort)text.Length), 0, 2);
        byte[] u = Encoding.Unicode.GetBytes(text);
        s.Write(u, 0, u.Length);
        s.Write(new byte[2], 0, 2);
    }

    private static byte[] CreateSyntheticPrefetchV30(string exeName, uint hash, uint runCount, string[] loadedFiles, uint volSerial)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            byte[] header = new byte[84];
            BitConverter.GetBytes((uint)30).CopyTo(header, 0);
            Encoding.ASCII.GetBytes("SCCA").CopyTo(header, 4);
            BitConverter.GetBytes((uint)1).CopyTo(header, 8);
            BitConverter.GetBytes((uint)1024).CopyTo(header, 12);
            Encoding.Unicode.GetBytes(exeName + "\0").CopyTo(header, 16);
            BitConverter.GetBytes(hash).CopyTo(header, 76);
            ms.Write(header, 0, 84);

            byte[] offsets = new byte[36];
            ms.Write(offsets, 0, 36);

            byte[] timestamps = new byte[64];
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(timestamps, 8);
            ms.Write(timestamps, 0, 64);

            byte[] runCountBytes = new byte[28];
            BitConverter.GetBytes(runCount).CopyTo(runCountBytes, 24);
            ms.Write(runCountBytes, 0, 28);

            uint secCOffset = (uint)ms.Position;
            StringBuilder secCStrings = new StringBuilder();
            for (int i = 0; i < loadedFiles.Length; i++)
            {
                secCStrings.Append(loadedFiles[i]).Append('\0');
            }
            byte[] secCBytes = Encoding.Unicode.GetBytes(secCStrings.ToString());
            ms.Write(secCBytes, 0, secCBytes.Length);
            uint secCSize = (uint)secCBytes.Length;

            uint secDOffset = (uint)ms.Position;
            byte[] volEntry = new byte[96];
            BitConverter.GetBytes(volSerial).CopyTo(volEntry, 16);
            ms.Write(volEntry, 0, 96);
            uint secDCount = 1;
            uint secDSize = 96;

            byte[] full = ms.ToArray();

            BitConverter.GetBytes(secCOffset).CopyTo(full, 100);
            BitConverter.GetBytes(secCSize).CopyTo(full, 104);
            BitConverter.GetBytes(secDOffset).CopyTo(full, 108);
            BitConverter.GetBytes(secDCount).CopyTo(full, 112);
            BitConverter.GetBytes(secDSize).CopyTo(full, 116);

            return full;
        }
    }

    private static byte[] CreateSyntheticLnk(string targetPath, uint fileSize, string description, string machineId, string mac)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            byte[] hdr = new byte[76];
            BitConverter.GetBytes((uint)0x0000004C).CopyTo(hdr, 0);
            new Guid("00021401-0000-0000-C000-000000000046").ToByteArray().CopyTo(hdr, 4);

            uint flags = 0x01 | 0x02 | 0x04 | 0x80;
            BitConverter.GetBytes(flags).CopyTo(hdr, 20);
            BitConverter.GetBytes((uint)0x20).CopyTo(hdr, 24);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(hdr, 28);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(hdr, 36);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(hdr, 44);
            BitConverter.GetBytes(fileSize).CopyTo(hdr, 52);

            ms.Write(hdr, 0, 76);

            string[] parts = targetPath.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            byte[] idListData = CreateShellItemPath(parts);

            ms.Write(BitConverter.GetBytes((ushort)idListData.Length), 0, 2);
            ms.Write(idListData, 0, idListData.Length);

            byte[] linkInfo = new byte[28];
            BitConverter.GetBytes((uint)28).CopyTo(linkInfo, 0);
            BitConverter.GetBytes((uint)28).CopyTo(linkInfo, 4);
            ms.Write(linkInfo, 0, 28);

            byte[] descBytes = Encoding.Unicode.GetBytes(description);
            ms.Write(BitConverter.GetBytes((ushort)description.Length), 0, 2);
            ms.Write(descBytes, 0, descBytes.Length);

            byte[] tracker = new byte[96];
            BitConverter.GetBytes((uint)96).CopyTo(tracker, 0);
            BitConverter.GetBytes((uint)0xA0000003).CopyTo(tracker, 4);
            Encoding.ASCII.GetBytes(machineId).CopyTo(tracker, 16);

            string[] macParts = mac.Split(':');
            for (int i = 0; i < 6 && i < macParts.Length; i++)
            {
                tracker[58 + i] = Convert.ToByte(macParts[i], 16);
            }
            ms.Write(tracker, 0, 96);

            ms.Write(new byte[4], 0, 4);
            return ms.ToArray();
        }
    }

    private static byte[] CreateShellItemPath(params string[] parts)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i];
                if (i == 0 && part.EndsWith(":"))
                {
                    byte[] volBytes = Encoding.ASCII.GetBytes(part + "\\\0");
                    ushort itemSize = (ushort)(2 + 1 + volBytes.Length);
                    ms.Write(BitConverter.GetBytes(itemSize), 0, 2);
                    ms.WriteByte(0x2F);
                    ms.Write(volBytes, 0, volBytes.Length);
                }
                else
                {
                    byte type = (i == parts.Length - 1) ? (byte)0x32 : (byte)0x31;
                    byte[] ansiShort = Encoding.ASCII.GetBytes(part.ToUpperInvariant() + "\0");

                    byte[] uBytes = Encoding.Unicode.GetBytes(part + "\0");
                    ushort extSize = (ushort)(8 + 6 + uBytes.Length);
                    ushort itemSize = (ushort)(2 + 12 + ansiShort.Length + extSize);

                    ms.Write(BitConverter.GetBytes(itemSize), 0, 2);
                    ms.WriteByte(type);
                    ms.Write(new byte[11], 0, 11);
                    ms.Write(ansiShort, 0, ansiShort.Length);

                    ms.Write(BitConverter.GetBytes(extSize), 0, 2);
                    ms.Write(BitConverter.GetBytes((ushort)0x0004), 0, 2);
                    ms.Write(BitConverter.GetBytes((uint)0xBEEF0004), 0, 4);
                    ms.Write(new byte[6], 0, 6);
                    ms.Write(uBytes, 0, uBytes.Length);
                }
            }

            ms.Write(new byte[2], 0, 2);
            return ms.ToArray();
        }
    }

    private static byte[] CreateSyntheticDatabase(int pageSize, int pageCount)
    {
        byte[] db = new byte[pageSize * pageCount];
        Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(db, 0);
        db[16] = (byte)(pageSize >> 8);
        db[17] = (byte)(pageSize & 0xFF);
        db[18] = 1; db[19] = 1; db[20] = 0;
        db[21] = 64; db[22] = 32; db[23] = 32;

        db[28] = (byte)(pageCount >> 24);
        db[29] = (byte)(pageCount >> 16);
        db[30] = (byte)(pageCount >> 8);
        db[31] = (byte)(pageCount & 0xFF);
        db[56] = 0; db[57] = 0; db[58] = 0; db[59] = 1; // UTF-8
        return db;
    }

    private static byte[] BuildTableCell(long rowId, byte[] payload)
    {
        byte[] pLenVarint = EncodeVarint(payload.Length);
        byte[] rowIdVarint = EncodeVarint(rowId);

        byte[] cell = new byte[pLenVarint.Length + rowIdVarint.Length + payload.Length];
        Buffer.BlockCopy(pLenVarint, 0, cell, 0, pLenVarint.Length);
        Buffer.BlockCopy(rowIdVarint, 0, cell, pLenVarint.Length, rowIdVarint.Length);
        Buffer.BlockCopy(payload, 0, cell, pLenVarint.Length + rowIdVarint.Length, payload.Length);
        return cell;
    }

    private static byte[] BuildRecordPayload(long[] serialTypes, object[] values)
    {
        MemoryStream hStream = new MemoryStream();
        for (int i = 0; i < serialTypes.Length; i++)
        {
            byte[] stVarint = EncodeVarint(serialTypes[i]);
            hStream.Write(stVarint, 0, stVarint.Length);
        }
        byte[] stBytes = hStream.ToArray();

        int hLen = stBytes.Length + 1;
        byte[] hLenVarint = EncodeVarint(hLen);
        if (hLenVarint.Length + stBytes.Length != hLen)
        {
            hLen = hLenVarint.Length + stBytes.Length;
            hLenVarint = EncodeVarint(hLen);
        }

        MemoryStream payload = new MemoryStream();
        payload.Write(hLenVarint, 0, hLenVarint.Length);
        payload.Write(stBytes, 0, stBytes.Length);

        for (int i = 0; i < values.Length; i++)
        {
            long st = serialTypes[i];
            object val = values[i];
            if (st == 0 || st == 8 || st == 9) continue;
            if (st == 1)
            {
                payload.WriteByte((byte)(sbyte)(long)val);
            }
            else if (st == 2)
            {
                short s = (short)(long)val;
                payload.WriteByte((byte)(s >> 8)); payload.WriteByte((byte)(s & 0xFF));
            }
            else if (st == 3)
            {
                int s = (int)(long)val;
                payload.WriteByte((byte)((s >> 16) & 0xFF));
                payload.WriteByte((byte)((s >> 8) & 0xFF));
                payload.WriteByte((byte)(s & 0xFF));
            }
            else if (st == 4)
            {
                int s = (int)(long)val;
                byte[] b = BitConverter.GetBytes(s);
                Array.Reverse(b);
                payload.Write(b, 0, 4);
            }
            else if (st == 5)
            {
                long s = (long)val;
                payload.WriteByte((byte)((s >> 40) & 0xFF));
                payload.WriteByte((byte)((s >> 32) & 0xFF));
                payload.WriteByte((byte)((s >> 24) & 0xFF));
                payload.WriteByte((byte)((s >> 16) & 0xFF));
                payload.WriteByte((byte)((s >> 8) & 0xFF));
                payload.WriteByte((byte)(s & 0xFF));
            }
            else if (st == 6)
            {
                long s = (long)val;
                byte[] b = BitConverter.GetBytes(s);
                Array.Reverse(b);
                payload.Write(b, 0, 8);
            }
            else if (st == 7)
            {
                double d = (double)val;
                byte[] b = BitConverter.GetBytes(d);
                Array.Reverse(b);
                payload.Write(b, 0, 8);
            }
            else if (st >= 12 && (st % 2 == 0))
            {
                byte[] blob = (byte[])val;
                payload.Write(blob, 0, blob.Length);
            }
            else if (st >= 13 && (st % 2 == 1))
            {
                byte[] txt = Encoding.UTF8.GetBytes((string)val);
                payload.Write(txt, 0, txt.Length);
            }
        }

        return payload.ToArray();
    }

    private static byte[] EncodeVarint(long val)
    {
        if (val < 0)
        {
            byte[] res9 = new byte[9];
            for (int i = 0; i < 8; i++) res9[i] = 0xFF;
            res9[8] = 0xFF;
            return res9;
        }

        if (val <= 0x7F)
        {
            return new byte[] { (byte)val };
        }

        List<byte> bytes = new List<byte>();
        bytes.Add((byte)(val & 0x7F));
        val >>= 7;

        while (val > 0)
        {
            bytes.Add((byte)((val & 0x7F) | 0x80));
            val >>= 7;
        }

        bytes.Reverse();
        return bytes.ToArray();
    }

    private static byte[] ComputeSha256(byte[] data)
    {
        using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
        {
            return sha.ComputeHash(data);
        }
    }

    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (a == b) return true;
        if (a == null || b == null || a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    private sealed class ReadOnlyTestStream : MemoryStream
    {
        public ReadOnlyTestStream(byte[] buffer) : base(buffer, false) { }
        public override bool CanWrite { get { return false; } }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }
}
