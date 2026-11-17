using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class SqliteCarverTests
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
        TestDatabaseHeaderParsing();
        TestVarintDecoding();
        TestSerialTypesAndValues();
        TestActiveCellCarving();
        TestFreeblockCarving();
        TestUnallocatedGapCarving();
        TestFreelistTrunkAndLeafTraversal();
        TestHeuristicCarvingCorruptedBuffers();
        TestForensicWriteBlockingGuarantees();

        Console.WriteLine("PASS SqliteCarverTests: {0} checks passed; SQLite database header, freelist traversal, freeblock chains, unallocated gap carving, varints, and serial types verified.", checks);
    }

    private static void TestDatabaseHeaderParsing()
    {
        // 1. Valid 4096-byte page size header
        byte[] db4096 = CreateSyntheticDatabase(4096, 5, 0, 0);
        SqliteDatabaseHeader h4096;
        Check(SqliteCarver.TryParseHeader(db4096, out h4096), "Header 4096 parsed successfully");
        Check(h4096 != null && h4096.PageSize == 4096, "Page size is 4096");
        Check(h4096.PageCount == 5, "Page count matches 5");
        Check(h4096.TextEncoding == 1, "Text encoding matches UTF-8 (1)");

        // 2. Valid 512-byte page size header
        byte[] db512 = CreateSyntheticDatabase(512, 10, 0, 0);
        SqliteDatabaseHeader h512;
        Check(SqliteCarver.TryParseHeader(db512, out h512), "Header 512 parsed successfully");
        Check(h512 != null && h512.PageSize == 512, "Page size is 512");

        // 3. Valid 65536-byte page size header (encoded as 0x0001 in uint16)
        byte[] db65536 = CreateSyntheticDatabase(65536, 2, 0, 0);
        SqliteDatabaseHeader h65536;
        Check(SqliteCarver.TryParseHeader(db65536, out h65536), "Header 65536 (0x0001) parsed successfully");
        Check(h65536 != null && h65536.PageSize == 65536, "Page size is 65536");

        // 4. Invalid magic rejected
        byte[] badMagic = (byte[])db4096.Clone();
        badMagic[0] = 0xFF;
        SqliteDatabaseHeader hBadMagic;
        Check(!SqliteCarver.TryParseHeader(badMagic, out hBadMagic), "Corrupted magic rejected");

        // 5. Non-power-of-two page size rejected (e.g. 1000)
        byte[] badPageSize = (byte[])db4096.Clone();
        badPageSize[16] = (byte)(1000 >> 8);
        badPageSize[17] = (byte)(1000 & 0xFF);
        SqliteDatabaseHeader hBadPageSize;
        Check(!SqliteCarver.TryParseHeader(badPageSize, out hBadPageSize), "Non-power-of-2 page size rejected");

        // 6. Buffer too short rejected
        byte[] shortBuf = new byte[99];
        SqliteDatabaseHeader hShort;
        Check(!SqliteCarver.TryParseHeader(shortBuf, out hShort), "Short header buffer (<100) rejected");
    }

    private static void TestVarintDecoding()
    {
        // 1-byte varints (0..127)
        long val;
        int len;

        len = SqliteCarver.ReadVarint(new byte[] { 0x00 }, 0, out val);
        Check(len == 1 && val == 0, "Varint 0 decoded");

        len = SqliteCarver.ReadVarint(new byte[] { 0x01 }, 0, out val);
        Check(len == 1 && val == 1, "Varint 1 decoded");

        len = SqliteCarver.ReadVarint(new byte[] { 0x7F }, 0, out val);
        Check(len == 1 && val == 127, "Varint 127 decoded");

        // 2-byte varint (128 -> 0x81, 0x00)
        len = SqliteCarver.ReadVarint(new byte[] { 0x81, 0x00 }, 0, out val);
        Check(len == 2 && val == 128, "Varint 128 decoded");

        // 2-byte varint (16383 -> 0xFF, 0x7F)
        len = SqliteCarver.ReadVarint(new byte[] { 0xFF, 0x7F }, 0, out val);
        Check(len == 2 && val == 16383, "Varint 16383 decoded");

        // 3-byte varint (16384 -> 0x81, 0x80, 0x00)
        len = SqliteCarver.ReadVarint(new byte[] { 0x81, 0x80, 0x00 }, 0, out val);
        Check(len == 3 && val == 16384, "Varint 16384 decoded");

        // 9-byte varint (all 8 continuation bytes + 9th byte with all 8 bits)
        // Encode -1L (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
        byte[] v9 = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        len = SqliteCarver.ReadVarint(v9, 0, out val);
        Check(len == 9 && val == -1L, "Varint 9-byte -1L decoded");

        // Truncated varint (continuation bit set but buffer ends)
        len = SqliteCarver.ReadVarint(new byte[] { 0x81, 0x82 }, 0, out val);
        Check(len == 0 && val == 0, "Truncated varint returns 0");
    }

    private static void TestSerialTypesAndValues()
    {
        // Construct payload with all serial types:
        // Col 0: Type 0 (NULL)
        // Col 1: Type 1 (int8 = -42)
        // Col 2: Type 2 (int16 = -1234)
        // Col 3: Type 3 (int24 = -70000, tests 24-bit sign extension)
        // Col 4: Type 4 (int32 = 1000000)
        // Col 5: Type 5 (int48 = -50000000000L, tests 48-bit sign extension)
        // Col 6: Type 6 (int64 = 9876543210123L)
        // Col 7: Type 7 (float64 = 3.14159)
        // Col 8: Type 8 (const 0)
        // Col 9: Type 9 (const 1)
        // Col 10: Type 12 (BLOB length 0)
        // Col 11: Type 16 (BLOB length 2: 0xCA, 0xFE)
        // Col 12: Type 13 (TEXT length 0)
        // Col 13: Type 23 (TEXT length 5: "Hello")

        long[] serialTypes = new long[] {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 13, 23
        };

        object[] values = new object[] {
            null,
            (long)-42,
            (long)-1234,
            (long)-70000,
            (long)1000000,
            (long)-50000000000L,
            (long)9876543210123L,
            (double)3.14159,
            0L,
            1L,
            new byte[0],
            new byte[] { 0xCA, 0xFE },
            String.Empty,
            "Hello"
        };

        byte[] payload = BuildRecordPayload(serialTypes, values);

        List<SqliteColumnValue> columns;
        int headerLength;
        int totalConsumed;

        bool parsed = SqliteCarver.TryParseRecord(payload, 0, payload.Length, out columns, out headerLength, out totalConsumed);
        Check(parsed, "TryParseRecord parsed all serial types");
        Check(columns.Count == 14, "Parsed 14 columns");

        // Verify Col 0: NULL
        Check(columns[0].Type == SqliteColumnType.Null && columns[0].Value == null, "Col 0 NULL");

        // Verify Col 1: int8 (-42)
        Check(columns[1].Type == SqliteColumnType.Integer && columns[1].AsLong(0) == -42, "Col 1 int8 -42");

        // Verify Col 2: int16 (-1234)
        Check(columns[2].Type == SqliteColumnType.Integer && columns[2].AsLong(0) == -1234, "Col 2 int16 -1234");

        // Verify Col 3: int24 (-70000 sign extended)
        Check(columns[3].Type == SqliteColumnType.Integer && columns[3].AsLong(0) == -70000, "Col 3 int24 -70000 sign extension");

        // Verify Col 4: int32 (1000000)
        Check(columns[4].Type == SqliteColumnType.Integer && columns[4].AsLong(0) == 1000000, "Col 4 int32 1000000");

        // Verify Col 5: int48 (-50000000000 sign extended)
        Check(columns[5].Type == SqliteColumnType.Integer && columns[5].AsLong(0) == -50000000000L, "Col 5 int48 -50000000000 sign extension");

        // Verify Col 6: int64 (9876543210123)
        Check(columns[6].Type == SqliteColumnType.Integer && columns[6].AsLong(0) == 9876543210123L, "Col 6 int64 9876543210123");

        // Verify Col 7: float64 (3.14159)
        Check(columns[7].Type == SqliteColumnType.Float && Math.Abs(columns[7].AsDouble(0) - 3.14159) < 0.0001, "Col 7 float64");

        // Verify Col 8: const 0
        Check(columns[8].Type == SqliteColumnType.Integer && columns[8].AsLong(-1) == 0L, "Col 8 const 0");

        // Verify Col 9: const 1
        Check(columns[9].Type == SqliteColumnType.Integer && columns[9].AsLong(-1) == 1L, "Col 9 const 1");

        // Verify Col 10: BLOB length 0
        Check(columns[10].Type == SqliteColumnType.Blob && ((byte[])columns[10].Value).Length == 0, "Col 10 BLOB 0");

        // Verify Col 11: BLOB length 2 (0xCA, 0xFE)
        byte[] b11 = (byte[])columns[11].Value;
        Check(columns[11].Type == SqliteColumnType.Blob && b11.Length == 2 && b11[0] == 0xCA && b11[1] == 0xFE, "Col 11 BLOB 2");

        // Verify Col 12: TEXT length 0
        Check(columns[12].Type == SqliteColumnType.Text && (string)columns[12].Value == String.Empty, "Col 12 TEXT 0");

        // Verify Col 13: TEXT "Hello"
        Check(columns[13].Type == SqliteColumnType.Text && (string)columns[13].Value == "Hello", "Col 13 TEXT 'Hello'");

        // Test reserved types 10 and 11 rejection
        byte[] badRecord10 = new byte[] { 0x02, 10 }; // header length 2, serial type 10
        List<SqliteColumnValue> badCols;
        int badH;
        int badC;
        Check(!SqliteCarver.TryParseRecord(badRecord10, 0, 2, out badCols, out badH, out badC), "Reserved serial type 10 rejected");

        byte[] badRecord11 = new byte[] { 0x02, 11 };
        Check(!SqliteCarver.TryParseRecord(badRecord11, 0, 2, out badCols, out badH, out badC), "Reserved serial type 11 rejected");
    }

    private static void TestActiveCellCarving()
    {
        // Create 4096-byte database with 1 table leaf page (Page 2)
        int pageSize = 4096;
        byte[] db = CreateSyntheticDatabase(pageSize, 2, 0, 0);

        // Build 2 active cell records:
        // Record 1: RowID 1, Name = "Alice", Age = 30
        byte[] payload1 = BuildRecordPayload(new long[] { 23, 1 }, new object[] { "Alice", (long)30 });
        byte[] cell1 = BuildTableCell(1, payload1);

        // Record 2: RowID 2, Name = "Bob", Age = 25
        byte[] payload2 = BuildRecordPayload(new long[] { 19, 1 }, new object[] { "Bob", (long)25 });
        byte[] cell2 = BuildTableCell(2, payload2);

        // Put on Page 2 (offset 4096)
        int pageOffset = 4096;
        int cell2Offset = pageSize - cell2.Length;
        int cell1Offset = cell2Offset - cell1.Length;

        Buffer.BlockCopy(cell2, 0, db, pageOffset + cell2Offset, cell2.Length);
        Buffer.BlockCopy(cell1, 0, db, pageOffset + cell1Offset, cell1.Length);

        // Page 2 B-tree Leaf Table Header: 0x0D, cell count = 2, cell content start = cell1Offset
        db[pageOffset] = 0x0D;
        db[pageOffset + 1] = 0; db[pageOffset + 2] = 0; // first freeblock = 0
        db[pageOffset + 3] = 0; db[pageOffset + 4] = 2; // cell count = 2
        db[pageOffset + 5] = (byte)(cell1Offset >> 8);
        db[pageOffset + 6] = (byte)(cell1Offset & 0xFF);
        db[pageOffset + 7] = 0; // fragmented free bytes

        // Cell pointer array at offset 8
        db[pageOffset + 8] = (byte)(cell1Offset >> 8);
        db[pageOffset + 9] = (byte)(cell1Offset & 0xFF);
        db[pageOffset + 10] = (byte)(cell2Offset >> 8);
        db[pageOffset + 11] = (byte)(cell2Offset & 0xFF);

        using (MemoryStream ms = new MemoryStream(db))
        {
            List<CarvedSqliteRecord> carved = SqliteCarver.CarveDatabase(ms);
            Check(carved != null, "Carved active records not null");

            List<CarvedSqliteRecord> active = new List<CarvedSqliteRecord>();
            for (int i = 0; i < carved.Count; i++)
            {
                if (carved[i].Origin == CarvedRecordOrigin.ActiveCell) active.Add(carved[i]);
            }

            Check(active.Count == 2, "Found 2 active records (found " + active.Count + ")");
            Check(active[0].RowId == 1 && active[0].Columns[0].AsString() == "Alice", "Record 1 is Alice, RowId 1");
            Check(active[1].RowId == 2 && active[1].Columns[0].AsString() == "Bob", "Record 2 is Bob, RowId 2");
        }
    }

    private static void TestFreeblockCarving()
    {
        int pageSize = 4096;
        byte[] db = CreateSyntheticDatabase(pageSize, 2, 0, 0);
        int pageOffset = 4096;

        // Build deleted cell record in freeblock:
        // Deleted user: RowId 99, "DeletedUser", Age 45
        byte[] payloadDeleted = BuildRecordPayload(new long[] { 35, 1 }, new object[] { "DeletedUser", (long)45 });
        byte[] cellDeleted = BuildTableCell(99, payloadDeleted);

        int fbOffset = 3000;
        int fbSize = 4 + cellDeleted.Length; // 4 bytes freeblock header + cell data

        // Freeblock header: next offset (0), size (fbSize)
        db[pageOffset + fbOffset] = 0;
        db[pageOffset + fbOffset + 1] = 0;
        db[pageOffset + fbOffset + 2] = (byte)(fbSize >> 8);
        db[pageOffset + fbOffset + 3] = (byte)(fbSize & 0xFF);
        Buffer.BlockCopy(cellDeleted, 0, db, pageOffset + fbOffset + 4, cellDeleted.Length);

        // Page header: first freeblock = fbOffset
        db[pageOffset] = 0x0D;
        db[pageOffset + 1] = (byte)(fbOffset >> 8);
        db[pageOffset + 2] = (byte)(fbOffset & 0xFF);
        db[pageOffset + 3] = 0; db[pageOffset + 4] = 0; // cell count = 0
        db[pageOffset + 5] = (byte)(pageSize >> 8);
        db[pageOffset + 6] = (byte)(pageSize & 0xFF);

        using (MemoryStream ms = new MemoryStream(db))
        {
            List<CarvedSqliteRecord> carved = SqliteCarver.CarveDatabase(ms);
            Check(carved != null, "Carved freeblock not null");

            CarvedSqliteRecord fbRec = null;
            for (int i = 0; i < carved.Count; i++)
            {
                if (carved[i].Origin == CarvedRecordOrigin.Freeblock)
                {
                    fbRec = carved[i];
                    break;
                }
            }

            Check(fbRec != null, "Found carved freeblock record");
            Check(fbRec.RowId == 99, "Freeblock record RowId matches 99");
            Check(fbRec.Columns[0].AsString() == "DeletedUser", "Freeblock record name is DeletedUser");
            Check(fbRec.Columns[1].AsLong(0) == 45, "Freeblock record age is 45");
        }
    }

    private static void TestUnallocatedGapCarving()
    {
        int pageSize = 4096;
        byte[] db = CreateSyntheticDatabase(pageSize, 2, 0, 0);
        int pageOffset = 4096;

        // Build deleted cell placed in unallocated gap (e.g. between cell pointer array end and cellContentAreaStart)
        byte[] payloadGap = BuildRecordPayload(new long[] { 35, 1 }, new object[] { "GhostRecord", (long)77 });
        byte[] cellGap = BuildTableCell(888, payloadGap);

        // Cell pointer array ends at offset 8 (0 cells).
        // Cell content start is at 3500.
        // Gap is from offset 8 to 3500.
        int gapPlacement = 200;
        Buffer.BlockCopy(cellGap, 0, db, pageOffset + gapPlacement, cellGap.Length);

        // Page header
        db[pageOffset] = 0x0D;
        db[pageOffset + 1] = 0; db[pageOffset + 2] = 0;
        db[pageOffset + 3] = 0; db[pageOffset + 4] = 0; // cell count 0
        db[pageOffset + 5] = (byte)(3500 >> 8);
        db[pageOffset + 6] = (byte)(3500 & 0xFF);

        using (MemoryStream ms = new MemoryStream(db))
        {
            List<CarvedSqliteRecord> carved = SqliteCarver.CarveDatabase(ms);
            CarvedSqliteRecord gapRec = null;
            for (int i = 0; i < carved.Count; i++)
            {
                if (carved[i].Origin == CarvedRecordOrigin.UnallocatedGap)
                {
                    gapRec = carved[i];
                    break;
                }
            }

            Check(gapRec != null, "Found unallocated gap record");
            Check(gapRec.RowId == 888, "Gap record RowId is 888");
            Check(gapRec.Columns[0].AsString() == "GhostRecord", "Gap record name is GhostRecord");
            Check(gapRec.Columns[1].AsLong(0) == 77, "Gap record age is 77");
        }
    }

    private static void TestFreelistTrunkAndLeafTraversal()
    {
        int pageSize = 4096;
        // 4 pages total:
        // Page 1: DB Header (First Freelist Trunk = Page 2, Total Freelist Pages = 2)
        // Page 2: Freelist Trunk Page (Next Trunk = 0, Leaf Count = 1, Leaf Page Pointer = Page 3)
        // Page 3: Freelist Leaf Page (Contains residual dropped records)
        // Page 4: Normal B-Tree page
        byte[] db = CreateSyntheticDatabase(pageSize, 4, 2, 2);

        // Configure Page 2 (Trunk) at offset 4096
        int p2Offset = 4096;
        WriteUInt32BE(db, p2Offset, 0); // Next trunk = 0
        WriteUInt32BE(db, p2Offset + 4, 1); // Leaf count = 1
        WriteUInt32BE(db, p2Offset + 8, 3); // Leaf 1 = Page 3

        // Populate Page 3 (Freelist Leaf) at offset 8192 with dropped records
        int p3Offset = 8192;
        byte[] payloadLeaf = BuildRecordPayload(new long[] { 43, 2 }, new object[] { "DroppedFreelist", (long)999 });
        byte[] cellLeaf = BuildTableCell(7777, payloadLeaf);
        Buffer.BlockCopy(cellLeaf, 0, db, p3Offset + 100, cellLeaf.Length);

        using (MemoryStream ms = new MemoryStream(db))
        {
            List<CarvedSqliteRecord> carved = SqliteCarver.CarveDatabase(ms);
            CarvedSqliteRecord flRec = null;
            for (int i = 0; i < carved.Count; i++)
            {
                if (carved[i].Origin == CarvedRecordOrigin.FreelistLeaf)
                {
                    flRec = carved[i];
                    break;
                }
            }

            Check(flRec != null, "Freelist leaf record recovered");
            Check(flRec.PageNumber == 3, "Freelist leaf record page number is 3");
            Check(flRec.RowId == 7777, "Freelist record RowId is 7777");
            Check(flRec.Columns[0].AsString() == "DroppedFreelist", "Freelist record text matches DroppedFreelist");
        }
    }

    private static void TestHeuristicCarvingCorruptedBuffers()
    {
        // Damaged buffer without DB header or B-tree headers (e.g. raw disk cluster slack)
        byte[] rawSlack = new byte[2048];
        for (int i = 0; i < rawSlack.Length; i++) rawSlack[i] = 0xAA; // garbage fill

        // Inject cell at offset 500: RowId 1234, "CarvedFromSlack", 404
        byte[] payload = BuildRecordPayload(new long[] { 43, 2 }, new object[] { "CarvedFromSlack", (long)404 });
        byte[] cell = BuildTableCell(1234, payload);
        Buffer.BlockCopy(cell, 0, rawSlack, 500, cell.Length);

        List<CarvedSqliteRecord> carved = SqliteCarver.CarveBuffer(rawSlack, 100000);
        Check(carved != null && carved.Count > 0, "Heuristic carving recovered record from raw buffer");

        CarvedSqliteRecord rec = carved[0];
        Check(rec.RowId == 1234, "Heuristic carved RowId is 1234");
        Check(rec.Columns[0].AsString() == "CarvedFromSlack", "Heuristic carved string matches CarvedFromSlack");
        Check(rec.Columns[1].AsLong(0) == 404, "Heuristic carved integer matches 404");
        Check(rec.AbsoluteOffset == 100500, "Absolute offset correctly adjusted (100000 + 500)");
    }

    private static void TestForensicWriteBlockingGuarantees()
    {
        byte[] db = CreateSyntheticDatabase(4096, 2, 0, 0);
        byte[] originalHash = ComputeSha256(db);

        // Pass through ReadOnlyMemoryStream
        using (ReadOnlyTestStream roStream = new ReadOnlyTestStream(db))
        {
            List<CarvedSqliteRecord> results = SqliteCarver.CarveDatabase(roStream);
            Check(results != null, "Carving executed through ReadOnlyStream");
        }

        byte[] postHash = ComputeSha256(db);
        Check(ByteArraysEqual(originalHash, postHash), "Source database bytes 100% immutable and unmodified");
    }

    // -------------------------------------------------------------------------
    // Synthetic Data Generation Helpers
    // -------------------------------------------------------------------------
    private static byte[] CreateSyntheticDatabase(int pageSize, int pageCount, int freelistTrunkPage, int freelistCount)
    {
        byte[] db = new byte[pageSize * pageCount];
        Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(db, 0);

        if (pageSize == 65536)
        {
            db[16] = 0x00; db[17] = 0x01;
        }
        else
        {
            db[16] = (byte)(pageSize >> 8);
            db[17] = (byte)(pageSize & 0xFF);
        }
        db[18] = 1; db[19] = 1; db[20] = 0; // write/read version, reserved
        db[21] = 64; db[22] = 32; db[23] = 32;

        WriteUInt32BE(db, 28, (uint)pageCount);
        WriteUInt32BE(db, 32, (uint)freelistTrunkPage);
        WriteUInt32BE(db, 36, (uint)freelistCount);
        WriteUInt32BE(db, 56, 1); // UTF-8
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
            // 9-byte varint
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

    private static void WriteUInt32BE(byte[] buffer, int offset, uint val)
    {
        buffer[offset] = (byte)(val >> 24);
        buffer[offset + 1] = (byte)(val >> 16);
        buffer[offset + 2] = (byte)(val >> 8);
        buffer[offset + 3] = (byte)(val & 0xFF);
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
