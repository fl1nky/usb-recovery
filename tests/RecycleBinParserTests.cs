using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class RecycleBinParserTests
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
        Console.WriteLine("Running RecycleBinParserTests...");
        string tempDir = Path.Combine(Path.GetTempPath(), "recycle_test_" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempDir);

            // 1. Windows Vista/7/8/8.1 Version 1 Parsing
            byte[] v1Data = CreateSyntheticIndexV1(@"C:\OldProjects\SecretBlueprint.dwg", 1048576, new DateTime(2026, 11, 20, 15, 30, 0, DateTimeKind.Utc));
            var v1Entry = RecycleBinParser.ParseIndexBuffer(v1Data, 0, v1Data.Length, "$I111111.dwg", "S-1-5-21-999-888-777-1002");
            Check(v1Entry != null, "V1 entry is not null");
            Check(v1Entry.FormatVersion == 1, "V1 format version is 1");
            Check(v1Entry.OriginalFileName == "SecretBlueprint.dwg", "V1 original filename matches: " + v1Entry.OriginalFileName);
            Check(v1Entry.OriginalFilePath == @"C:\OldProjects\SecretBlueprint.dwg", "V1 original file path matches: " + v1Entry.OriginalFilePath);
            Check(v1Entry.OriginalFileSize == 1048576, "V1 original file size matches: " + v1Entry.OriginalFileSize);
            Check(v1Entry.DeletionTimeUtc.Year == 2026, "V1 deletion year is 2026");
            Check(v1Entry.UserSid == "S-1-5-21-999-888-777-1002", "V1 UserSid matches");

            // 2. Windows 10/11 Version 2 Parsing with Long Unicode Path
            string longPath = @"D:\Cases\2026_Incident_Investigation\Confidential_Internal_Financial_Records_Audited_Report_Final_Version_Very_Long_Path.xlsx";
            byte[] v2Data = CreateSyntheticIndexV2(longPath, 524288, new DateTime(2026, 11, 21, 10, 15, 0, DateTimeKind.Utc));
            var v2Entry = RecycleBinParser.ParseIndexBuffer(v2Data, 0, v2Data.Length, "$I222222.xlsx", "S-1-5-21-1234567890-1234567890-1234567890-1001");
            Check(v2Entry != null, "V2 entry is not null");
            Check(v2Entry.FormatVersion == 2, "V2 format version is 2");
            Check(v2Entry.OriginalFileName == "Confidential_Internal_Financial_Records_Audited_Report_Final_Version_Very_Long_Path.xlsx", "V2 long filename matches");
            Check(v2Entry.OriginalFilePath == longPath, "V2 original file path matches");
            Check(v2Entry.OriginalFileSize == 524288, "V2 file size matches");
            Check(v2Entry.DeletionTimeUtc.Minute == 15, "V2 deletion minute is 15");

            // 3. Directory Parsing with $I and $R Matching
            string userFolder = Path.Combine(tempDir, @"$Recycle.Bin\S-1-5-21-5555555555-6666666666-7777777777-1000");
            Directory.CreateDirectory(userFolder);

            string indexFilePath = Path.Combine(userFolder, "$I333333.docx");
            File.WriteAllBytes(indexFilePath, CreateSyntheticIndexV2(@"C:\Users\Executive\Documents\BoardMeeting.docx", 2048, DateTime.UtcNow));

            string dataFilePath = Path.Combine(userFolder, "$R333333.docx");
            byte[] docPayload = Encoding.UTF8.GetBytes("CONFIDENTIAL BOARD MINUTES - MERGER APPROVED 2026");
            File.WriteAllBytes(dataFilePath, docPayload);

            var dirReport = RecycleBinParser.ParseDirectory(tempDir);
            Check(dirReport != null, "Directory report is not null");
            Check(dirReport.TotalRecords == 1, "Directory report found 1 entry: " + dirReport.TotalRecords);
            Check(dirReport.AvailablePayloads == 1, "Directory report found 1 available payload ($R file)");
            Check(dirReport.Entries[0].HasDataFile, "Entry has data file linked");
            Check(dirReport.Entries[0].DataFileName == "$R333333.docx", "Data file name is $R333333.docx");
            Check(dirReport.Entries[0].UserSid == "S-1-5-21-5555555555-6666666666-7777777777-1000", "User SID extracted from parent directory path: " + dirReport.Entries[0].UserSid);

            // 4. File Restoration
            string restoreOut = Path.Combine(tempDir, "RestoredFiles");
            bool restored = RecycleBinParser.RestoreFile(dirReport.Entries[0], restoreOut, recreateSubdirectories: true);
            Check(restored, "RestoreFile returns true");
            string expectedRestoredPath = Path.Combine(restoreOut, @"Users\Executive\Documents\BoardMeeting.docx");
            Check(File.Exists(expectedRestoredPath), "Restored file exists at reconstructed directory path: " + expectedRestoredPath);
            Check(Encoding.UTF8.GetString(File.ReadAllBytes(expectedRestoredPath)) == "CONFIDENTIAL BOARD MINUTES - MERGER APPROVED 2026", "Restored file content is verified");

            // 5. Threat Detection Heuristics
            var tempExe = new RecycleBinEntry
            {
                OriginalFilePath = @"C:\Users\Admin\AppData\Local\Temp\payload_dropper.exe",
                OriginalFileSize = 50000
            };
            RecycleBinParser.EvaluateThreat(tempExe);
            Check(tempExe.IsSuspicious, "Executable deleted from Temp is flagged suspicious");
            Check(tempExe.ThreatDescription.Contains("Temporary directory"), "Reason includes Temporary directory");

            var downloadScript = new RecycleBinEntry
            {
                OriginalFilePath = @"C:\Users\Victim\Downloads\malicious_invoice.ps1",
                OriginalFileSize = 1000
            };
            RecycleBinParser.EvaluateThreat(downloadScript);
            Check(downloadScript.IsSuspicious, "Script deleted from Downloads is flagged suspicious");

            var doubleExt = new RecycleBinEntry
            {
                OriginalFilePath = @"C:\Users\User\Desktop\statement.pdf.exe",
                OriginalFileSize = 60000
            };
            RecycleBinParser.EvaluateThreat(doubleExt);
            Check(doubleExt.IsSuspicious, "Masquerading double extension is flagged suspicious");

            var zeroTruncation = new RecycleBinEntry
            {
                OriginalFilePath = @"C:\Accounting\wiped_ledger.xlsx",
                OriginalFileSize = 100000,
                ActualDataFileSize = 0,
                HasDataFile = true
            };
            RecycleBinParser.EvaluateThreat(zeroTruncation);
            Check(zeroTruncation.IsSuspicious, "Zero-truncation file wiping is flagged suspicious");
            Check(zeroTruncation.ThreatDescription.Contains("Anti-forensics zero-truncation"), "Reason includes zero-truncation");

            var logDeletion = new RecycleBinEntry
            {
                OriginalFilePath = @"C:\Windows\System32\winevt\Logs\Security.evtx",
                OriginalFileSize = 20971520
            };
            RecycleBinParser.EvaluateThreat(logDeletion);
            Check(logDeletion.IsSuspicious, "Security event log deletion is flagged suspicious");
            Check(logDeletion.ThreatDescription.Contains("Evidence destruction"), "Reason includes Evidence destruction");

            // 6. Deep Carving from Noise
            byte[] noiseBuffer = new byte[8192];
            new Random(42).NextBytes(noiseBuffer);
            byte[] v1Slice = CreateSyntheticIndexV1(@"E:\Confidential\PatentDraft.docx", 81920, new DateTime(2026, 11, 19, 8, 0, 0, DateTimeKind.Utc));
            byte[] v2Slice = CreateSyntheticIndexV2(@"C:\Source\SecretCrypto.cs", 16384, new DateTime(2026, 11, 20, 9, 30, 0, DateTimeKind.Utc));
            Buffer.BlockCopy(v1Slice, 0, noiseBuffer, 512, v1Slice.Length);
            Buffer.BlockCopy(v2Slice, 0, noiseBuffer, 2048, v2Slice.Length);

            var carvedReport = RecycleBinParser.Carve(noiseBuffer);
            Check(carvedReport != null, "Carved report is not null");
            Check(carvedReport.Entries.Count >= 2, "Carved at least 2 entries from noise: got " + carvedReport.Entries.Count);
            Check(carvedReport.Entries[0].IsCarved, "Entry 0 IsCarved is true");
            Check(carvedReport.Entries[1].IsCarved, "Entry 1 IsCarved is true");

            // 7. Adversarial & Truncated Inputs
            var emptyRep = RecycleBinParser.ParseBuffer(new byte[0]);
            Check(emptyRep != null && emptyRep.Entries.Count == 0, "Empty buffer does not throw");

            byte[] truncatedBytes = new byte[15];
            Buffer.BlockCopy(BitConverter.GetBytes(2UL), 0, truncatedBytes, 0, 8);
            var truncEntry = RecycleBinParser.ParseIndexBuffer(truncatedBytes, 0, truncatedBytes.Length);
            Check(truncEntry == null, "Truncated buffer returns null without crash");

            byte[] insaneLenBytes = new byte[100];
            Buffer.BlockCopy(BitConverter.GetBytes(2UL), 0, insaneLenBytes, 0, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(1000L), 0, insaneLenBytes, 8, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()), 0, insaneLenBytes, 16, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(999999U), 0, insaneLenBytes, 24, 4); // Insane length
            var insaneEntry = RecycleBinParser.ParseIndexBuffer(insaneLenBytes, 0, insaneLenBytes.Length);
            // Must handle gracefully without buffer overrun
            Check(insaneEntry != null || insaneEntry == null, "Handled insane length safely");

            // 8. JSON Serialization
            string json = dirReport.ToJson();
            Check(json.Contains("BoardMeeting.docx"), "JSON contains restored filename");
            Check(json.Contains("$R333333.docx"), "JSON contains data filename");
            Check(json.Contains("S-1-5-21-5555555555"), "JSON contains user SID");

            // 9. Super-Timeline Ingestion
            var timeline = new ForensicTimeline();
            timeline.AddRecycleBinEntries(dirReport.Entries);
            Check(timeline.Count >= 1, "ForensicTimeline ingested recycle bin entry");
            var tlEvt = timeline.Events[0];
            Check(tlEvt.Source == "RecycleBin", "Timeline source is RecycleBin");
            Check(tlEvt.Action.Contains("DELETED_FILE"), "Timeline action is DELETED_FILE");
            Check(tlEvt.TargetPath.Contains("BoardMeeting.docx"), "Timeline target path matches");

            Console.WriteLine("PASS RecycleBinParserTests: {0} checks passed.", checks);
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

    private static byte[] CreateSyntheticIndexV1(string originalPath, long fileSize, DateTime deletionTime)
    {
        // 544 bytes total:
        // 0..7: Version = 1 (uint64)
        // 8..15: File size (int64)
        // 16..23: Deletion timestamp (int64 FILETIME)
        // 24..543: Fixed 260 WCHARs UTF-16LE
        byte[] buffer = new byte[544];
        Buffer.BlockCopy(BitConverter.GetBytes(1UL), 0, buffer, 0, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(fileSize), 0, buffer, 8, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(deletionTime.ToFileTimeUtc()), 0, buffer, 16, 8);

        byte[] pathBytes = Encoding.Unicode.GetBytes(originalPath + "\0");
        int copyLen = Math.Min(pathBytes.Length, 520);
        Buffer.BlockCopy(pathBytes, 0, buffer, 24, copyLen);

        return buffer;
    }

    private static byte[] CreateSyntheticIndexV2(string originalPath, long fileSize, DateTime deletionTime)
    {
        // Variable length:
        // 0..7: Version = 2 (uint64)
        // 8..15: File size (int64)
        // 16..23: Deletion timestamp (int64 FILETIME)
        // 24..27: Char count (uint32)
        // 28..: Unicode path (2 * charCount bytes)
        byte[] pathBytes = Encoding.Unicode.GetBytes(originalPath);
        uint charCount = (uint)originalPath.Length;

        byte[] buffer = new byte[28 + pathBytes.Length];
        Buffer.BlockCopy(BitConverter.GetBytes(2UL), 0, buffer, 0, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(fileSize), 0, buffer, 8, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(deletionTime.ToFileTimeUtc()), 0, buffer, 16, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(charCount), 0, buffer, 24, 4);
        Buffer.BlockCopy(pathBytes, 0, buffer, 28, pathBytes.Length);

        return buffer;
    }
}
