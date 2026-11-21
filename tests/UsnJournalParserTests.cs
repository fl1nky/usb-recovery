using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class UsnJournalParserTests
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
        TestUsnRecordV2Parsing();
        TestUsnRecordV3Parsing();
        TestCorruptedAndMalformedRecords();
        TestStreamCarvingAndSlidingWindow();
        TestDeletedFileReconstruction();
        TestCarveFromRawBuffer();

        Console.WriteLine("PASS UsnJournalParserTests: {0} checks passed; USN Record V2/V3 parsing, NTFS 48-bit MFT indexing, sliding-window streaming, heuristic carving, and deleted file lifecycle reconstruction verified.", checks);
    }

    private static void TestUsnRecordV2Parsing()
    {
        DateTime expectedTime = new DateTime(2026, 11, 21, 14, 30, 0, DateTimeKind.Utc);
        ulong fileRef = (2UL << 48) | 12345UL; // Seq 2, MFT 12345
        ulong parentRef = (1UL << 48) | 5UL;   // Seq 1, Root dir MFT 5

        byte[] recordBytes = CreateSyntheticRecordV2(
            "SecretFinancials.xlsx",
            fileRef,
            parentRef,
            500000L,
            expectedTime,
            UsnReason.FileCreate | UsnReason.Close,
            0x20 // Archive
        );

        UsnRecord record;
        bool ok = UsnJournalParser.TryParseRecord(recordBytes, 0, 1024, false, out record);
        Check(ok, "V2 record parsed successfully");
        Check(record != null, "Record object created");
        Check(record.MajorVersion == 2, "MajorVersion is 2");
        Check(record.MinorVersion == 0, "MinorVersion is 0");
        Check(record.FileName == "SecretFinancials.xlsx", "FileName is SecretFinancials.xlsx");
        Check(record.FileReferenceNumber == fileRef, "FileReferenceNumber matches");
        Check(record.MftEntryIndex == 12345UL, "MftEntryIndex matches 12345");
        Check(record.MftSequenceNumber == 2, "MftSequenceNumber matches 2");
        Check(record.ParentMftEntryIndex == 5UL, "ParentMftEntryIndex matches 5");
        Check(record.Usn == 500000L, "USN matches 500000");
        Check(record.TimeStampUtc == expectedTime, "TimeStampUtc matches expectedTime");
        Check((record.Reason & UsnReason.FileCreate) != 0, "Reason contains FileCreate");
        Check((record.Reason & UsnReason.Close) != 0, "Reason contains Close");
        Check(record.ReasonText.Contains("FILE_CREATE"), "ReasonText contains FILE_CREATE");
        Check(record.ReasonText.Contains("CLOSE"), "ReasonText contains CLOSE");
        Check(record.FileAttributes == 0x20, "FileAttributes is 0x20");
        Check(record.AbsoluteOffset == 1024, "AbsoluteOffset matches 1024");
        Check(!record.IsCarved, "IsCarved is false");
    }

    private static void TestUsnRecordV3Parsing()
    {
        DateTime expectedTime = new DateTime(2026, 8, 15, 10, 0, 0, DateTimeKind.Utc);
        ulong fileRef = (1UL << 48) | 99999UL;
        ulong parentRef = (1UL << 48) | 5UL;

        byte[] recordBytes = CreateSyntheticRecordV3(
            "ReFsVolumeFile.dat",
            fileRef,
            parentRef,
            12345678L,
            expectedTime,
            UsnReason.DataExtend | UsnReason.FileCreate,
            0x80 // Normal
        );

        UsnRecord record;
        bool ok = UsnJournalParser.TryParseRecord(recordBytes, 0, 2048, true, out record);
        Check(ok, "V3 record parsed successfully");
        Check(record != null, "V3 record created");
        Check(record.MajorVersion == 3, "MajorVersion is 3");
        Check(record.MinorVersion == 0, "MinorVersion is 0");
        Check(record.FileName == "ReFsVolumeFile.dat", "V3 FileName matches");
        Check(record.MftEntryIndex == 99999UL, "V3 MftEntryIndex matches 99999");
        Check(record.Usn == 12345678L, "V3 USN matches");
        Check(record.IsCarved, "IsCarved is true");
    }

    private static void TestCorruptedAndMalformedRecords()
    {
        DateTime validTime = DateTime.UtcNow;
        byte[] valid = CreateSyntheticRecordV2("test.txt", 100, 5, 1, validTime, UsnReason.FileCreate, 0);

        // 1. Unaligned record length (must be multiple of 8)
        byte[] badAlign = (byte[])valid.Clone();
        BitConverter.GetBytes(badAlign.Length + 1).CopyTo(badAlign, 0);
        UsnRecord rec;
        Check(!UsnJournalParser.TryParseRecord(badAlign, 0, 0, false, out rec), "Unaligned length rejected");

        // 2. Out-of-bounds filename offset
        byte[] badNameOff = (byte[])valid.Clone();
        BitConverter.GetBytes((ushort)(badNameOff.Length + 10)).CopyTo(badNameOff, 58);
        Check(!UsnJournalParser.TryParseRecord(badNameOff, 0, 0, false, out rec), "Out of bounds filename offset rejected");

        // 3. Zero reason rejected
        byte[] badReason = (byte[])valid.Clone();
        BitConverter.GetBytes(0U).CopyTo(badReason, 40);
        Check(!UsnJournalParser.TryParseRecord(badReason, 0, 0, false, out rec), "Zero reason rejected");

        // 4. Invalid FILETIME (before 1995 or zero)
        byte[] badTime = (byte[])valid.Clone();
        BitConverter.GetBytes(0L).CopyTo(badTime, 32);
        Check(!UsnJournalParser.TryParseRecord(badTime, 0, 0, false, out rec), "Zero FILETIME rejected");

        // 5. Control characters in filename rejected
        byte[] badChars = (byte[])valid.Clone();
        badChars[60] = 0x01; // Control char SOH
        badChars[61] = 0x00;
        Check(!UsnJournalParser.TryParseRecord(badChars, 0, 0, false, out rec), "Control chars in filename rejected");
    }

    private static void TestStreamCarvingAndSlidingWindow()
    {
        // Build a synthetic stream with:
        // - Leading sparse zero block (10,000 bytes)
        // - Record 1 (near boundary 65500)
        // - Record 2 (spanning across the 65536 chunk boundary!)
        // - Intermediate zero block (5,000 bytes)
        // - Record 3
        using (var ms = new MemoryStream())
        {
            // Sparse zero prefix
            byte[] zeroes = new byte[65400];
            ms.Write(zeroes, 0, zeroes.Length);

            // Record 1 at ~65400
            byte[] r1 = CreateSyntheticRecordV2("FirstSpannedFile.txt", 1001, 5, 100, DateTime.UtcNow.AddMinutes(-10), UsnReason.FileCreate, 0);
            ms.Write(r1, 0, r1.Length);

            // Record 2 placed right across 65536 boundary
            byte[] r2 = CreateSyntheticRecordV2("CrossChunkBoundaryFile.log", 1002, 5, 200, DateTime.UtcNow.AddMinutes(-5), UsnReason.DataExtend | UsnReason.Close, 0);
            ms.Write(r2, 0, r2.Length);

            // Sparse gap
            ms.Write(new byte[4096], 0, 4096);

            // Record 3
            byte[] r3 = CreateSyntheticRecordV2("TrailingFile.zip", 1003, 5, 300, DateTime.UtcNow, UsnReason.FileDelete, 0);
            ms.Write(r3, 0, r3.Length);

            ms.Position = 0;
            List<UsnRecord> parsed = UsnJournalParser.ParseStream(ms);
            Check(parsed.Count == 3, "Parsed all 3 records across sparse blocks and chunk boundary");
            Check(parsed[0].FileName == "FirstSpannedFile.txt", "Record 1 found");
            Check(parsed[1].FileName == "CrossChunkBoundaryFile.log", "Record 2 found across boundary");
            Check(parsed[2].FileName == "TrailingFile.zip", "Record 3 found");
        }
    }

    private static void TestDeletedFileReconstruction()
    {
        DateTime createTime = new DateTime(2026, 11, 20, 9, 0, 0, DateTimeKind.Utc);
        DateTime modifyTime = new DateTime(2026, 11, 20, 11, 0, 0, DateTimeKind.Utc);
        DateTime renameTime = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);
        DateTime deleteTime = new DateTime(2026, 11, 20, 14, 0, 0, DateTimeKind.Utc);

        ulong targetMft = 88888UL;
        ulong parentMft = 5UL;

        var records = new List<UsnRecord>();

        // Lifecycle of File A (Created -> Modified -> Renamed -> Deleted)
        records.Add(new UsnRecord
        {
            FileReferenceNumber = targetMft,
            ParentFileReferenceNumber = parentMft,
            FileName = "DraftStrategy.docx",
            Usn = 100,
            TimeStampUtc = createTime,
            Reason = UsnReason.FileCreate
        });
        records.Add(new UsnRecord
        {
            FileReferenceNumber = targetMft,
            ParentFileReferenceNumber = parentMft,
            FileName = "DraftStrategy.docx",
            Usn = 101,
            TimeStampUtc = modifyTime,
            Reason = UsnReason.DataExtend | UsnReason.Close
        });
        records.Add(new UsnRecord
        {
            FileReferenceNumber = targetMft,
            ParentFileReferenceNumber = parentMft,
            FileName = "FinalStrategy_Wiped.docx",
            Usn = 102,
            TimeStampUtc = renameTime,
            Reason = UsnReason.RenameNewName
        });
        records.Add(new UsnRecord
        {
            FileReferenceNumber = targetMft,
            ParentFileReferenceNumber = parentMft,
            FileName = "FinalStrategy_Wiped.docx",
            Usn = 103,
            TimeStampUtc = deleteTime,
            Reason = UsnReason.FileDelete | UsnReason.Close
        });

        // Lifecycle of File B (Created and still exists, NOT deleted)
        records.Add(new UsnRecord
        {
            FileReferenceNumber = 99999UL,
            ParentFileReferenceNumber = parentMft,
            FileName = "ActiveDocument.pdf",
            Usn = 200,
            TimeStampUtc = createTime,
            Reason = UsnReason.FileCreate | UsnReason.Close
        });

        List<UsnDeletedFileArtifact> deletedFiles = UsnJournalParser.ExtractDeletedFiles(records);
        Check(deletedFiles.Count == 1, "Only deleted file A returned");

        var deleted = deletedFiles[0];
        Check(deleted.FileName == "FinalStrategy_Wiped.docx", "Deleted file latest name matches FinalStrategy_Wiped.docx");
        Check(deleted.FileReferenceNumber == targetMft, "Deleted file reference matches 88888");
        Check(deleted.DeletionTimeUtc == deleteTime, "DeletionTimeUtc matches deleteTime");
        Check(deleted.CreationTimeUtc == createTime, "CreationTimeUtc matches createTime");
        Check(deleted.HistoryRecords.Count == 4, "Full lifecycle history preserved (4 records)");
        Check(deleted.LastUsn == 103, "LastUsn matches 103");
    }

    private static void TestCarveFromRawBuffer()
    {
        byte[] rawBlock = new byte[8192];
        // Fill with pseudo-random noise to simulate unallocated sectors
        new Random(42).NextBytes(rawBlock);

        // Inject 2 valid USN records at aligned offsets 1024 and 4096
        byte[] r1 = CreateSyntheticRecordV2("carved_evidence_1.pdf", 5555, 5, 777, DateTime.UtcNow.AddHours(-1), UsnReason.FileDelete, 0);
        byte[] r2 = CreateSyntheticRecordV2("carved_evidence_2.txt", 6666, 5, 888, DateTime.UtcNow.AddHours(-2), UsnReason.FileCreate, 0);

        Array.Copy(r1, 0, rawBlock, 1024, r1.Length);
        Array.Copy(r2, 0, rawBlock, 4096, r2.Length);

        List<UsnRecord> carved = UsnJournalParser.Carve(rawBlock, 500000);
        Check(carved.Count == 2, "Carver identified exactly 2 records from noise buffer");
        Check(carved[0].FileName == "carved_evidence_1.pdf", "Carved record 1 matched");
        Check(carved[0].AbsoluteOffset == 500000 + 1024, "Carved record 1 offset verified");
        Check(carved[0].IsCarved, "Carved record 1 tagged IsCarved");

        Check(carved[1].FileName == "carved_evidence_2.txt", "Carved record 2 matched");
        Check(carved[1].AbsoluteOffset == 500000 + 4096, "Carved record 2 offset verified");
    }

    #region Helper Record Builders

    private static byte[] CreateSyntheticRecordV2(string fileName, ulong fileRef, ulong parentRef, long usn, DateTime timeStamp, UsnReason reason, uint fileAttrs)
    {
        byte[] nameBytes = Encoding.Unicode.GetBytes(fileName);
        int recordLen = 60 + nameBytes.Length;
        if (recordLen % 8 != 0) recordLen += (8 - (recordLen % 8));

        byte[] data = new byte[recordLen];
        BitConverter.GetBytes((uint)recordLen).CopyTo(data, 0);
        BitConverter.GetBytes((ushort)2).CopyTo(data, 4); // Major
        BitConverter.GetBytes((ushort)0).CopyTo(data, 6); // Minor
        BitConverter.GetBytes(fileRef).CopyTo(data, 8);
        BitConverter.GetBytes(parentRef).CopyTo(data, 16);
        BitConverter.GetBytes(usn).CopyTo(data, 24);
        BitConverter.GetBytes(timeStamp.ToFileTimeUtc()).CopyTo(data, 32);
        BitConverter.GetBytes((uint)reason).CopyTo(data, 40);
        BitConverter.GetBytes(0U).CopyTo(data, 44); // SourceInfo
        BitConverter.GetBytes(0U).CopyTo(data, 48); // SecurityId
        BitConverter.GetBytes(fileAttrs).CopyTo(data, 52);
        BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, 56);
        BitConverter.GetBytes((ushort)60).CopyTo(data, 58); // NameOffset
        Array.Copy(nameBytes, 0, data, 60, nameBytes.Length);

        return data;
    }

    private static byte[] CreateSyntheticRecordV3(string fileName, ulong fileRef, ulong parentRef, long usn, DateTime timeStamp, UsnReason reason, uint fileAttrs)
    {
        byte[] nameBytes = Encoding.Unicode.GetBytes(fileName);
        int recordLen = 80 + nameBytes.Length;
        if (recordLen % 8 != 0) recordLen += (8 - (recordLen % 8));

        byte[] data = new byte[recordLen];
        BitConverter.GetBytes((uint)recordLen).CopyTo(data, 0);
        BitConverter.GetBytes((ushort)3).CopyTo(data, 4); // Major
        BitConverter.GetBytes((ushort)0).CopyTo(data, 6); // Minor

        // V3 128-bit file refs
        BitConverter.GetBytes(fileRef).CopyTo(data, 8);
        BitConverter.GetBytes(0UL).CopyTo(data, 16);
        BitConverter.GetBytes(parentRef).CopyTo(data, 24);
        BitConverter.GetBytes(0UL).CopyTo(data, 32);

        BitConverter.GetBytes(usn).CopyTo(data, 40);
        BitConverter.GetBytes(timeStamp.ToFileTimeUtc()).CopyTo(data, 48);
        BitConverter.GetBytes((uint)reason).CopyTo(data, 56);
        BitConverter.GetBytes(0U).CopyTo(data, 60);
        BitConverter.GetBytes(0U).CopyTo(data, 64);
        BitConverter.GetBytes(fileAttrs).CopyTo(data, 68);
        BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, 72);
        BitConverter.GetBytes((ushort)80).CopyTo(data, 74);
        Array.Copy(nameBytes, 0, data, 80, nameBytes.Length);

        return data;
    }

    #endregion
}
