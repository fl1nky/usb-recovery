using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class JumpListParserTests
{
    static int checks;

    static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
            throw new Exception("Assertion failed: " + message);
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("Running JumpListParserTests...");
        string tempDir = Path.Combine(Path.GetTempPath(), "jumplist_test_" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempDir);

            // 1. AppID Resolution
            Check(JumpListParser.ResolveAppName("1b4dd67f29cb1962").Contains("Explorer"), "1b4dd67f29cb1962 is Windows Explorer");
            Check(JumpListParser.ResolveAppName("918e0ecb43d17e23").Contains("Notepad"), "918e0ecb43d17e23 is Windows Notepad");
            Check(JumpListParser.ResolveAppName("cdf30b95c55fd78d").Contains("PowerShell"), "cdf30b95c55fd78d is Windows PowerShell");
            Check(JumpListParser.ResolveAppName("5d696d521de238c3").Contains("Command Prompt"), "5d696d521de238c3 is Command Prompt");
            Check(JumpListParser.ResolveAppName("12dc1ea8e34b5a34").Contains("Chrome"), "12dc1ea8e34b5a34 is Google Chrome");
            Check(JumpListParser.ResolveAppName("unknown99999999").Contains("unknown99999999"), "Unknown AppId provides fallback name");

            // 2. Threat Detection Heuristics
            var normalEntry = new JumpListEntry
            {
                TargetPath = @"C:\Program Files\Notepad++\notepad++.exe",
                Arguments = "-multiInst"
            };
            JumpListParser.EvaluateThreat(normalEntry);
            Check(!normalEntry.IsSuspicious, "Normal program files executable is not suspicious");

            var tempExeEntry = new JumpListEntry
            {
                TargetPath = @"C:\Users\Analyst\AppData\Local\Temp\dropper.exe"
            };
            JumpListParser.EvaluateThreat(tempExeEntry);
            Check(tempExeEntry.IsSuspicious, "Executable in AppData Local Temp is flagged suspicious");
            Check(tempExeEntry.ThreatDescription.Contains("Temporary directory"), "Reason includes Temporary directory");

            var downloadScriptEntry = new JumpListEntry
            {
                TargetPath = @"C:\Users\Victim\Downloads\invoice_payload.bat"
            };
            JumpListParser.EvaluateThreat(downloadScriptEntry);
            Check(downloadScriptEntry.IsSuspicious, "Batch script in Downloads is flagged suspicious");
            Check(downloadScriptEntry.ThreatDescription.Contains("Downloads folder"), "Reason includes Downloads folder");

            var doubleExtEntry = new JumpListEntry
            {
                TargetPath = @"D:\Confidential\Contract.pdf.exe"
            };
            JumpListParser.EvaluateThreat(doubleExtEntry);
            Check(doubleExtEntry.IsSuspicious, "Masquerading double extension is flagged suspicious");
            Check(doubleExtEntry.ThreatDescription.Contains("double extension"), "Reason includes double extension");

            var obfuscatedCliEntry = new JumpListEntry
            {
                TargetPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                Arguments = "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
            };
            JumpListParser.EvaluateThreat(obfuscatedCliEntry);
            Check(obfuscatedCliEntry.IsSuspicious, "Encoded command arguments are flagged suspicious");
            Check(obfuscatedCliEntry.ThreatDescription.Contains("obfuscated CLI arguments"), "Reason includes obfuscated CLI");

            // 3. Synthetic CFBF AutomaticDestinations Construction & Parsing
            byte[] cfbfData = CreateSyntheticAutomaticDestinations();
            string autoDestFile = Path.Combine(tempDir, "1b4dd67f29cb1962.automaticDestinations-ms");
            File.WriteAllBytes(autoDestFile, cfbfData);

            var report = JumpListParser.Parse(autoDestFile);
            Check(report != null, "Report is not null");
            Check(report.FileType.Contains("AutomaticDestinations"), "FileType is AutomaticDestinations");
            Check(report.AppId == "1b4dd67f29cb1962", "AppID is extracted from filename");
            Check(report.AppName.Contains("Explorer"), "AppName is Windows Explorer");
            Check(report.Entries.Count == 1, "Parsed exactly 1 DestList entry: got " + report.Entries.Count);

            var entry1 = report.Entries[0];
            Check(entry1.EntryId == 1, "EntryId is 1");
            Check(entry1.TargetPath == @"C:\Evidence\Confidential_Record.docx", "TargetPath matches synthetic path: " + entry1.TargetPath);
            Check(entry1.NetBiosName == "ANALYSIS-WORK", "NetBIOS hostname is ANALYSIS-WORK: " + entry1.NetBiosName);
            Check(entry1.AccessCount == 7, "AccessCount is 7: " + entry1.AccessCount);
            Check(entry1.PinStatus == "Unpinned", "PinStatus is Unpinned");
            Check(entry1.TargetFileSize == 123456, "TargetFileSize extracted from LNK stream: " + entry1.TargetFileSize);
            Check(entry1.LastAccessUtc.Year == 2026, "LastAccessUtc year is 2026: " + entry1.LastAccessUtc);

            // 4. Synthetic CustomDestinations Construction & Parsing
            byte[] customData = CreateSyntheticCustomDestinations();
            string customDestFile = Path.Combine(tempDir, "9839aec31243a928.customDestinations-ms");
            File.WriteAllBytes(customDestFile, customData);

            var customReport = JumpListParser.Parse(customDestFile);
            Check(customReport != null, "Custom report is not null");
            Check(customReport.FileType == "CustomDestinations", "FileType is CustomDestinations");
            Check(customReport.AppId == "9839aec31243a928", "AppId extracted from filename");
            Check(customReport.AppName.Contains("Word"), "AppName is Word");
            Check(customReport.Entries.Count >= 2, "Custom destinations extracted at least 2 entries: got " + customReport.Entries.Count);

            var customEntry1 = customReport.Entries[0];
            Check(customEntry1.Category == "Special Projects", "Category 1 title is Special Projects: " + customEntry1.Category);
            Check(customEntry1.TargetPath == @"C:\Projects\AnnualReport.docx", "Target path 1 matches: " + customEntry1.TargetPath);
            Check(customEntry1.TargetFileSize == 88000, "Target file size 1 matches: " + customEntry1.TargetFileSize);

            var customEntry2 = customReport.Entries[1];
            Check(customEntry2.Category == "Tasks", "Category 2 title is Tasks: " + customEntry2.Category);
            Check(customEntry2.IsSuspicious, "Suspicious script in Temp is flagged in custom destinations");

            // 5. Carving from Corrupted Buffer
            byte[] noiseBuffer = new byte[8192];
            new Random(1234).NextBytes(noiseBuffer);
            byte[] validLnk = CreateSyntheticLnkHeader(@"C:\Carved\Wiped_Document.pdf", 54321);
            Buffer.BlockCopy(validLnk, 0, noiseBuffer, 1024, validLnk.Length);

            var carvedReport = JumpListParser.CarveJumpLists(noiseBuffer);
            Check(carvedReport != null, "Carved report is not null");
            Check(carvedReport.Entries.Count >= 1, "Carved at least 1 LNK stream from noise: got " + carvedReport.Entries.Count);
            Check(carvedReport.Entries[0].TargetPath == @"C:\Carved\Wiped_Document.pdf", "Carved target path matches: " + carvedReport.Entries[0].TargetPath);
            Check(carvedReport.Entries[0].IsCarved, "IsCarved flag is true");

            // 6. Adversarial and Corrupt Inputs
            var emptyRep = JumpListParser.Parse(new byte[0]);
            Check(emptyRep != null && emptyRep.Entries.Count == 0, "Empty buffer produces empty report without crashing");

            byte[] truncatedCfbf = new byte[120];
            Buffer.BlockCopy(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, 0, truncatedCfbf, 0, 8);
            var truncRep = JumpListParser.Parse(truncatedCfbf);
            Check(truncRep != null, "Truncated CFBF does not crash");

            // 7. Directory Batch Parsing
            var dirReport = JumpListParser.ParseDirectory(tempDir);
            Check(dirReport != null, "Directory report is not null");
            Check(dirReport.TotalEntries >= 3, "Directory report aggregates all jump list files: got " + dirReport.TotalEntries);
            Check(dirReport.SuspiciousCount >= 1, "Directory report flags suspicious items: " + dirReport.SuspiciousCount);

            // 8. JSON Serialization
            string json = report.ToJson();
            Check(json.Contains("\"FileType\":\"AutomaticDestinations"), "JSON contains FileType");
            Check(json.Contains("Confidential_Record.docx"), "JSON contains target path");
            Check(json.Contains("ANALYSIS-WORK"), "JSON contains NetBIOS name");

            // 9. Timeline Integration
            var timeline = new ForensicTimeline();
            timeline.AddJumpListEntries(report.Entries);
            Check(timeline.Count >= 1, "ForensicTimeline ingested jump list entries: got " + timeline.Count);
            var evt = timeline.Events[0];
            Check(evt.Source == "JumpList", "Timeline source is JumpList");
            Check(evt.Action.Contains("MRU_ACCESS"), "Timeline action is MRU_ACCESS");
            Check(evt.TargetPath == @"C:\Evidence\Confidential_Record.docx", "Timeline TargetPath matches");

            Console.WriteLine("PASS JumpListParserTests: {0} checks passed.", checks);
            return 0;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
            }
            catch { }
        }
    }

    private static byte[] CreateSyntheticAutomaticDestinations()
    {
        // 512 bytes per sector:
        // Sector -1: Header (offset 0..511)
        // Sector 0: FAT (offset 512..1023)
        // Sector 1: Directory (offset 1024..1535)
        // Sector 2: DestList stream (offset 1536..2047)
        // Sector 3: Stream "1" (LNK file) (offset 2048..2559)
        // Total size: 512 * 5 = 2560 bytes

        int sectorSize = 512;
        byte[] file = new byte[sectorSize * 5];

        // 1. CFBF Header (512 bytes)
        byte[] magic = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
        Buffer.BlockCopy(magic, 0, file, 0, 8);

        // Minor version = 0x003E, Major version = 3 (512-byte sectors)
        file[24] = 0x3E; file[25] = 0x00;
        file[26] = 0x03; file[27] = 0x00;

        // Byte order = 0xFFFE
        file[28] = 0xFE; file[29] = 0xFF;

        // Sector shift = 9 (512 bytes)
        file[30] = 0x09; file[31] = 0x00;

        // Mini sector shift = 6 (64 bytes)
        file[32] = 0x06; file[33] = 0x00;

        // Number of FAT sectors = 1
        Buffer.BlockCopy(BitConverter.GetBytes(1U), 0, file, 44, 4);

        // First Directory sector = 1
        Buffer.BlockCopy(BitConverter.GetBytes(1U), 0, file, 48, 4);

        // Mini stream cutoff = 4096 (force all streams into regular FAT sectors for this synthetic test)
        Buffer.BlockCopy(BitConverter.GetBytes(64U), 0, file, 56, 4);

        // First Mini FAT sector = ENDOFCHAIN
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFEU), 0, file, 60, 4);

        // First DIFAT sector = ENDOFCHAIN
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFEU), 0, file, 68, 4);

        // First DIFAT entry = Sector 0 (FAT is at Sector 0)
        Buffer.BlockCopy(BitConverter.GetBytes(0U), 0, file, 76, 4);
        for (int i = 1; i < 109; i++)
        {
            Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFFU), 0, file, 76 + (i * 4), 4);
        }

        // 2. Sector 0: FAT (offset 512)
        int fatOffset = 512;
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFEU), 0, file, fatOffset + 0, 4); // FAT sector 0 -> ENDOFCHAIN
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFEU), 0, file, fatOffset + 4, 4); // Dir sector 1 -> ENDOFCHAIN
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFEU), 0, file, fatOffset + 8, 4); // DestList sector 2 -> ENDOFCHAIN
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFEU), 0, file, fatOffset + 12, 4); // Stream 1 sector 3 -> ENDOFCHAIN
        for (int i = 4; i < 128; i++)
        {
            Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFFU), 0, file, fatOffset + (i * 4), 4);
        }

        // 3. Sector 1: Directory Entries (offset 1024, 4 entries of 128 bytes each)
        int dirOffset = 1024;

        // Entry 0: Root Entry (ObjectType = 5)
        byte[] rootName = Encoding.Unicode.GetBytes("Root Entry\0");
        Buffer.BlockCopy(rootName, 0, file, dirOffset + 0, rootName.Length);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)rootName.Length), 0, file, dirOffset + 64, 2);
        file[dirOffset + 66] = 5; // Root Storage
        file[dirOffset + 67] = 1; // Black
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFEU), 0, file, dirOffset + 116, 4); // Starting sector

        // Entry 1: DestList Entry (ObjectType = 2)
        int destEntryOffset = dirOffset + 128;
        byte[] destListName = Encoding.Unicode.GetBytes("DestList\0");
        Buffer.BlockCopy(destListName, 0, file, destEntryOffset + 0, destListName.Length);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)destListName.Length), 0, file, destEntryOffset + 64, 2);
        file[destEntryOffset + 66] = 2; // Stream
        file[destEntryOffset + 67] = 1; // Black
        Buffer.BlockCopy(BitConverter.GetBytes(2U), 0, file, destEntryOffset + 116, 4); // Starting sector 2
        Buffer.BlockCopy(BitConverter.GetBytes(512UL), 0, file, destEntryOffset + 120, 8); // Size 512 bytes

        // Entry 2: Numbered Stream "1" (ObjectType = 2)
        int stream1Offset = dirOffset + 256;
        byte[] s1Name = Encoding.Unicode.GetBytes("1\0");
        Buffer.BlockCopy(s1Name, 0, file, stream1Offset + 0, s1Name.Length);
        Buffer.BlockCopy(BitConverter.GetBytes((ushort)s1Name.Length), 0, file, stream1Offset + 64, 2);
        file[stream1Offset + 66] = 2; // Stream
        file[stream1Offset + 67] = 1; // Black
        Buffer.BlockCopy(BitConverter.GetBytes(3U), 0, file, stream1Offset + 116, 4); // Starting sector 3
        Buffer.BlockCopy(BitConverter.GetBytes(512UL), 0, file, stream1Offset + 120, 8); // Size 512 bytes

        // 4. Sector 2: DestList Stream (offset 1536)
        int dlOffset = 1536;
        Buffer.BlockCopy(BitConverter.GetBytes(1U), 0, file, dlOffset + 0, 4); // Version 1
        Buffer.BlockCopy(BitConverter.GetBytes(1U), 0, file, dlOffset + 4, 4); // Total entries 1
        Buffer.BlockCopy(BitConverter.GetBytes(0U), 0, file, dlOffset + 8, 4); // Pinned 0

        // DestList Entry 1 at dlOffset + 32:
        int recOffset = dlOffset + 32;
        Guid volDroid = Guid.NewGuid();
        Guid fileDroid = Guid.NewGuid();
        Buffer.BlockCopy(volDroid.ToByteArray(), 0, file, recOffset + 8, 16);
        Buffer.BlockCopy(fileDroid.ToByteArray(), 0, file, recOffset + 24, 16);

        byte[] nbBytes = Encoding.ASCII.GetBytes("ANALYSIS-WORK\0\0\0");
        Buffer.BlockCopy(nbBytes, 0, file, recOffset + 72, 16);

        Buffer.BlockCopy(BitConverter.GetBytes(1U), 0, file, recOffset + 88, 4); // EntryId = 1
        Buffer.BlockCopy(BitConverter.GetBytes(7.0f), 0, file, recOffset + 92, 4); // Access count = 7

        long accessFt = new DateTime(2026, 11, 20, 14, 30, 0, DateTimeKind.Utc).ToFileTimeUtc();
        Buffer.BlockCopy(BitConverter.GetBytes(accessFt), 0, file, recOffset + 96, 8); // LastAccess FILETIME
        Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFFU), 0, file, recOffset + 104, 4); // Pin status: Unpinned

        string targetPath = @"C:\Evidence\Confidential_Record.docx";
        ushort pathChars = (ushort)targetPath.Length;
        Buffer.BlockCopy(BitConverter.GetBytes(pathChars), 0, file, recOffset + 108, 2);
        byte[] pathBytes = Encoding.Unicode.GetBytes(targetPath);
        Buffer.BlockCopy(pathBytes, 0, file, recOffset + 110, pathBytes.Length);

        // 5. Sector 3: Stream "1" (LNK file) (offset 2048)
        byte[] lnkBytes = CreateSyntheticLnkHeader(targetPath, 123456);
        Buffer.BlockCopy(lnkBytes, 0, file, 2048, lnkBytes.Length);

        return file;
    }

    private static byte[] CreateSyntheticCustomDestinations()
    {
        using (var ms = new MemoryStream())
        using (var bw = new BinaryWriter(ms))
        {
            // Header: Version = 1
            bw.Write(1U);

            // Category 0: Custom ("Special Projects")
            bw.Write(0U); // Category type = 0 (Custom)
            string cat1Name = "Special Projects";
            bw.Write((ushort)cat1Name.Length);
            bw.Write(Encoding.Unicode.GetBytes(cat1Name));

            // LNK 1: Normal document
            byte[] lnk1 = CreateSyntheticLnkHeader(@"C:\Projects\AnnualReport.docx", 88000);
            bw.Write(lnk1);

            // Category separator
            bw.Write(new byte[] { 0xAB, 0xFB, 0xBF, 0xBA });

            // Category 1: Known (3 = Tasks)
            bw.Write(1U); // Category type = 1 (Known)
            bw.Write(3U); // Tasks

            // LNK 2: Suspicious script in temp
            byte[] lnk2 = CreateSyntheticLnkHeader(@"C:\Users\Admin\AppData\Local\Temp\cleanup_dropper.vbs", 4096);
            bw.Write(lnk2);

            // Category separator
            bw.Write(new byte[] { 0xAB, 0xFB, 0xBF, 0xBA });

            return ms.ToArray();
        }
    }

    private static byte[] CreateSyntheticLnkHeader(string targetPath, uint targetSize)
    {
        // Construct standard 76-byte Shell Link Header + String Data (RelativePath / TargetPath)
        using (var ms = new MemoryStream())
        using (var bw = new BinaryWriter(ms))
        {
            // HeaderSize (4 bytes) = 0x4C
            bw.Write(0x0000004CU);

            // LinkCLSID (16 bytes) = {00021401-0000-0000-C000-000000000046}
            bw.Write(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray());

            // LinkFlags (4 bytes): HasRelativePath (0x08) | IsUnicode (0x80)
            bw.Write(0x88U);

            // FileAttributes (4 bytes): Archive (0x20)
            bw.Write(0x20U);

            // CreationTime, AccessTime, WriteTime (8 bytes each)
            long ft = new DateTime(2026, 11, 20, 10, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
            bw.Write(ft);
            bw.Write(ft);
            bw.Write(ft);

            // FileSize (4 bytes)
            bw.Write(targetSize);

            // IconIndex (4 bytes), ShowCommand (4 bytes), HotKey (2 bytes), Reserved (10 bytes)
            bw.Write(0U);
            bw.Write(1U);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write(0U);
            bw.Write(0U);

            // String Data: RelativePath (since flag 0x08 is set)
            // Character count (2 bytes) followed by UTF-16LE characters
            bw.Write((ushort)targetPath.Length);
            bw.Write(Encoding.Unicode.GetBytes(targetPath));

            // Terminal zero extra block size
            bw.Write(0U);

            return ms.ToArray();
        }
    }
}
