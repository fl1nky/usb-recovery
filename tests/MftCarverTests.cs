using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class MftCarverTests
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
        TestResidentFileRecord();
        TestNonResidentFileRecordWithDataRuns();
        TestDeletedFileCarving();
        TestTimestompingDetection();
        TestCarvingFromRawStreamAcrossChunkBoundary();

        Console.WriteLine("PASS MftCarverTests: {0} checks passed; MFT 1024-byte record parsing, Fixup arrays, $STANDARD_INFO, $FILE_NAME, resident payload, non-resident data runs, timestomping detection, and unallocated carving verified.", checks);
    }

    private static void TestResidentFileRecord()
    {
        DateTime createTime = new DateTime(2026, 11, 21, 10, 0, 0, DateTimeKind.Utc);
        byte[] payload = Encoding.UTF8.GetBytes("TopSecretMasterKey=9999");

        byte[] mftBytes = CreateSyntheticMftRecord(
            "Passwords_Backup.txt",
            1234UL,
            5UL,
            createTime,
            createTime,
            true,  // isAllocated
            false, // isDirectory
            payload,
            null   // resident
        );

        MftFileRecord record;
        bool ok = MftCarver.TryParseRecord(mftBytes, 0, 4096, out record);
        Check(ok, "MFT record parsed successfully");
        Check(record != null, "Record object created");
        Check(!record.HasFixupError, "Fixup array applied with zero fixup error");
        Check(record.RecordNumber == 1234UL, "RecordNumber matches 1234");
        Check(record.IsAllocated, "IsAllocated is true");
        Check(!record.IsDirectory, "IsDirectory is false");
        Check(record.FileName == "Passwords_Backup.txt", "FileName matches Passwords_Backup.txt");
        Check(record.ParentRecordNumber == 5UL, "ParentRecordNumber matches 5");
        Check(record.CreationTimeUtc == createTime, "CreationTimeUtc matches createTime");
        Check(record.IsResident, "IsResident is true");
        Check(record.ResidentData != null, "ResidentData is not null");
        Check(Encoding.UTF8.GetString(record.ResidentData) == "TopSecretMasterKey=9999", "ResidentData payload recovered accurately");
        Check(record.FileSize == payload.Length, "FileSize matches resident payload length");
        Check(!record.IsTimestomped, "IsTimestomped is false");
    }

    private static void TestNonResidentFileRecordWithDataRuns()
    {
        DateTime time = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);
        var runs = new List<MftDataRun>();
        runs.Add(new MftDataRun { Lcn = 1000, ClusterCount = 8 });
        runs.Add(new MftDataRun { Lcn = 1020, ClusterCount = 4 }); // Delta +20

        byte[] mftBytes = CreateSyntheticMftRecord(
            "LargeDatabase.mdf",
            9999UL,
            5UL,
            time,
            time,
            true,
            false,
            null,
            runs
        );

        MftFileRecord record;
        bool ok = MftCarver.TryParseRecord(mftBytes, 0, 8192, out record);
        Check(ok, "Non-resident MFT record parsed");
        Check(!record.IsResident, "IsResident is false");
        Check(record.DataRuns.Count == 2, "DataRuns count is 2");
        Check(record.DataRuns[0].Lcn == 1000 && record.DataRuns[0].ClusterCount == 8, "DataRun 0: LCN 1000, 8 clusters");
        Check(record.DataRuns[1].Lcn == 1020 && record.DataRuns[1].ClusterCount == 4, "DataRun 1: LCN 1020, 4 clusters");
        Check(record.FileSize == 49152, "FileSize matches non-resident real size");
    }

    private static void TestDeletedFileCarving()
    {
        DateTime time = new DateTime(2026, 10, 10, 15, 30, 0, DateTimeKind.Utc);
        byte[] payload = Encoding.UTF8.GetBytes("DeletedFinancialPlan");

        byte[] deletedMft = CreateSyntheticMftRecord(
            "WipedStrategy.docx",
            5555UL,
            5UL,
            time,
            time,
            false, // isAllocated = FALSE (Deleted!)
            false,
            payload,
            null
        );

        MftFileRecord record;
        bool ok = MftCarver.TryParseRecord(deletedMft, 0, 0, out record);
        Check(ok, "Deleted MFT record parsed");
        Check(!record.IsAllocated, "IsAllocated is false");
        Check(record.FileName == "WipedStrategy.docx", "Deleted FileName preserved");

        var list = new List<MftFileRecord> { record };
        var deletedOnly = MftCarver.ExtractDeletedFiles(list);
        Check(deletedOnly.Count == 1, "ExtractDeletedFiles returned 1 deleted file");
        Check(deletedOnly[0].FileName == "WipedStrategy.docx", "Extracted deleted file matches name");
    }

    private static void TestTimestompingDetection()
    {
        // $STANDARD_INFO set to year 2010 (attacker timestomp), but $FILE_NAME retains 2026!
        DateTime fakeTime = new DateTime(2010, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        DateTime realTime = new DateTime(2026, 11, 21, 14, 0, 0, DateTimeKind.Utc);

        byte[] timestompedMft = CreateSyntheticMftRecord(
            "MalwareDropped.exe",
            7777UL,
            5UL,
            fakeTime,
            realTime,
            true,
            false,
            new byte[] { 0x4D, 0x5A },
            null
        );

        MftFileRecord record;
        bool ok = MftCarver.TryParseRecord(timestompedMft, 0, 0, out record);
        Check(ok, "Timestomped record parsed");
        Check(record.IsTimestomped, "IsTimestomped detected as true due to timestamp divergence");
    }

    private static void TestCarvingFromRawStreamAcrossChunkBoundary()
    {
        using (var ms = new MemoryStream())
        {
            // Pad 65000 bytes with noise
            byte[] noise = new byte[65000];
            new Random(123).NextBytes(noise);
            ms.Write(noise, 0, noise.Length);

            // Align to 512-byte sector boundary: 65000 -> 65024
            int pad = 512 - (65000 % 512);
            ms.Write(new byte[pad], 0, pad); // now at 65024 (or 65024..65536)

            // Record 1 at 65024 (ends at 66048, which spans across 65536 chunk boundary!)
            byte[] r1 = CreateSyntheticMftRecord("SpannedFile1.txt", 101, 5, DateTime.UtcNow, DateTime.UtcNow, true, false, new byte[] { 1 }, null);
            ms.Write(r1, 0, r1.Length);

            // Record 2 at sector alignment
            byte[] r2 = CreateSyntheticMftRecord("SpannedFile2.txt", 102, 5, DateTime.UtcNow, DateTime.UtcNow, false, false, new byte[] { 2 }, null);
            ms.Write(r2, 0, r2.Length);

            ms.Position = 0;
            List<MftFileRecord> carved = MftCarver.CarveFromStream(ms);
            Check(carved.Count >= 2, "Carved at least 2 records across boundary");
            Check(carved[0].FileName == "SpannedFile1.txt", "Carved record 1 filename matches");
            Check(carved[1].FileName == "SpannedFile2.txt", "Carved record 2 filename matches");
        }
    }

    #region Helper Synthetic MFT Builder

    private static byte[] CreateSyntheticMftRecord(
        string fileName,
        ulong recordNum,
        ulong parentMft,
        DateTime siCreateTime,
        DateTime fnCreateTime,
        bool isAllocated,
        bool isDirectory,
        byte[] residentPayload,
        List<MftDataRun> dataRuns)
    {
        byte[] record = new byte[1024];

        // 1. Header
        // "FILE" = 0x454C4946
        record[0] = 0x46; record[1] = 0x49; record[2] = 0x4C; record[3] = 0x45;
        BitConverter.GetBytes((ushort)48).CopyTo(record, 4);  // USA offset
        BitConverter.GetBytes((ushort)3).CopyTo(record, 6);   // USA count (1 check + 2 sectors)
        BitConverter.GetBytes((ushort)1).CopyTo(record, 16);  // Sequence number
        BitConverter.GetBytes((ushort)1).CopyTo(record, 18);  // Hard links
        BitConverter.GetBytes((ushort)56).CopyTo(record, 20); // First attr offset

        ushort flags = 0;
        if (isAllocated) flags |= 0x0001;
        if (isDirectory) flags |= 0x0002;
        BitConverter.GetBytes(flags).CopyTo(record, 22);

        BitConverter.GetBytes(1024U).CopyTo(record, 28); // Allocated size
        BitConverter.GetBytes((uint)recordNum).CopyTo(record, 44); // Record number

        // Fixup array at 48..53: check value 0x4242
        ushort checkVal = 0x4242;
        BitConverter.GetBytes(checkVal).CopyTo(record, 48);
        BitConverter.GetBytes((ushort)0x1111).CopyTo(record, 50); // Original sector 1 ending
        BitConverter.GetBytes((ushort)0x2222).CopyTo(record, 52); // Original sector 2 ending

        // Put check values at sector ends
        BitConverter.GetBytes(checkVal).CopyTo(record, 510);
        BitConverter.GetBytes(checkVal).CopyTo(record, 1022);

        int cursor = 56;

        // 2. $STANDARD_INFORMATION (0x10)
        int siLen = 24 + 48; // attr header 24 + resident data 48 = 72
        BitConverter.GetBytes(0x10U).CopyTo(record, cursor);
        BitConverter.GetBytes((uint)siLen).CopyTo(record, cursor + 4);
        record[cursor + 8] = 0; // Resident
        BitConverter.GetBytes(48U).CopyTo(record, cursor + 16); // Value length
        BitConverter.GetBytes((ushort)24).CopyTo(record, cursor + 20); // Value offset

        BitConverter.GetBytes(siCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 24);
        BitConverter.GetBytes(siCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 32);
        BitConverter.GetBytes(siCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 40);
        BitConverter.GetBytes(siCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 48);
        BitConverter.GetBytes(0x20U).CopyTo(record, cursor + 56); // Archive
        cursor += siLen;

        // 3. $FILE_NAME (0x30)
        byte[] nameBytes = Encoding.Unicode.GetBytes(fileName);
        int fnValLen = 66 + nameBytes.Length;
        int fnAttrLen = 24 + fnValLen;
        if (fnAttrLen % 8 != 0) fnAttrLen += (8 - (fnAttrLen % 8));

        BitConverter.GetBytes(0x30U).CopyTo(record, cursor);
        BitConverter.GetBytes((uint)fnAttrLen).CopyTo(record, cursor + 4);
        record[cursor + 8] = 0; // Resident
        BitConverter.GetBytes((uint)fnValLen).CopyTo(record, cursor + 16);
        BitConverter.GetBytes((ushort)24).CopyTo(record, cursor + 20);

        ulong parentRef = (1UL << 48) | parentMft;
        BitConverter.GetBytes(parentRef).CopyTo(record, cursor + 24);
        BitConverter.GetBytes(fnCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 32);
        BitConverter.GetBytes(fnCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 40);
        BitConverter.GetBytes(fnCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 48);
        BitConverter.GetBytes(fnCreateTime.ToFileTimeUtc()).CopyTo(record, cursor + 56);

        long fileSize = (residentPayload != null) ? (long)residentPayload.Length : (dataRuns != null ? 49152L : 0L);
        BitConverter.GetBytes(fileSize).CopyTo(record, cursor + 64); // Alloc size
        BitConverter.GetBytes(fileSize).CopyTo(record, cursor + 72); // Real size
        BitConverter.GetBytes(0x20U).CopyTo(record, cursor + 80);

        record[cursor + 88] = (byte)(fileName.Length); // Length in chars
        record[cursor + 89] = 1; // Win32 namespace
        Array.Copy(nameBytes, 0, record, cursor + 90, nameBytes.Length);
        cursor += fnAttrLen;

        // 4. $DATA (0x80)
        if (residentPayload != null)
        {
            int dataValLen = residentPayload.Length;
            int dataAttrLen = 24 + dataValLen;
            if (dataAttrLen % 8 != 0) dataAttrLen += (8 - (dataAttrLen % 8));

            BitConverter.GetBytes(0x80U).CopyTo(record, cursor);
            BitConverter.GetBytes((uint)dataAttrLen).CopyTo(record, cursor + 4);
            record[cursor + 8] = 0; // Resident
            BitConverter.GetBytes((uint)dataValLen).CopyTo(record, cursor + 16);
            BitConverter.GetBytes((ushort)24).CopyTo(record, cursor + 20);
            Array.Copy(residentPayload, 0, record, cursor + 24, dataValLen);
            cursor += dataAttrLen;
        }
        else if (dataRuns != null && dataRuns.Count > 0)
        {
            // Non-resident $DATA
            int dataAttrLen = 64 + 16;
            BitConverter.GetBytes(0x80U).CopyTo(record, cursor);
            BitConverter.GetBytes((uint)dataAttrLen).CopyTo(record, cursor + 4);
            record[cursor + 8] = 1; // Non-Resident
            BitConverter.GetBytes(0UL).CopyTo(record, cursor + 16); // Starting VCN
            BitConverter.GetBytes(11UL).CopyTo(record, cursor + 24); // Last VCN
            BitConverter.GetBytes((ushort)64).CopyTo(record, cursor + 32); // Data runs offset
            BitConverter.GetBytes(65536L).CopyTo(record, cursor + 40); // Allocated size
            BitConverter.GetBytes(49152L).CopyTo(record, cursor + 48); // Real size
            BitConverter.GetBytes(49152L).CopyTo(record, cursor + 56); // Initialized size

            int runCursor = cursor + 64;
            long prevLcn = 0;
            for (int i = 0; i < dataRuns.Count; i++)
            {
                var run = dataRuns[i];
                long lcnDelta = run.Lcn - prevLcn;
                prevLcn = run.Lcn;

                // Encode run: 1 byte len, 2 bytes offset -> header 0x21
                record[runCursor++] = 0x21;
                record[runCursor++] = (byte)(run.ClusterCount & 0xFF);
                record[runCursor++] = (byte)(lcnDelta & 0xFF);
                record[runCursor++] = (byte)((lcnDelta >> 8) & 0xFF);
            }
            record[runCursor++] = 0; // End of data runs
            cursor += dataAttrLen;
        }

        // 5. End marker
        BitConverter.GetBytes(0xFFFFFFFFU).CopyTo(record, cursor);
        cursor += 4;

        BitConverter.GetBytes((uint)cursor).CopyTo(record, 24); // Real size

        return record;
    }

    #endregion
}
