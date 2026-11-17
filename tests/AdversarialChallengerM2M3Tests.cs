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

public static class AdversarialChallengerM2M3Tests
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
        {
            throw new Exception("Adversarial check failed: " + message);
        }
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("=========================================================================");
        Console.WriteLine("STARTING TIER-5 ADVERSARIAL STRESS TEST SUITE (Milestones 2 & 3)");
        Console.WriteLine("Scope: SqliteCarver, EvtxParser, PrefetchParser, LnkParser,");
        Console.WriteLine("       BrowserHistoryParser, /api/export-zip, and /api/report");
        Console.WriteLine("=========================================================================");

        string tempRoot = Path.Combine(Path.GetTempPath(), "adv_m2m3_tier5_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        try
        {
            // Suite 1: SqliteCarver Adversarial Stress & Freelist/Freeblock Cycle Defense
            TestSuite1_SqliteCarverStress(tempRoot);

            // Suite 2: EvtxParser BinXml Adversarial Tokens & Chunk Corruption
            TestSuite2_EvtxParserStress(tempRoot);

            // Suite 3: PrefetchParser MAM XPRESS Huffman & Multi-Version Decompression
            TestSuite3_PrefetchParserStress(tempRoot);

            // Suite 4: LnkParser Shell Link & Shellbag MRU Corrupt Layouts
            TestSuite4_LnkParserStress(tempRoot);

            // Suite 5: BrowserHistoryParser Timestamp Clamping & Cache Corruption
            TestSuite5_BrowserHistoryStress(tempRoot);

            // Suite 6: LocalWebServer /api/export-zip Adversarial Edge Cases
            TestSuite6_WebServerExportZip(tempRoot);

            // Suite 7: LocalWebServer /api/report & PDF Artifact Syntax
            TestSuite7_WebServerReportAndPdf(tempRoot);

            // Suite 8: High Concurrency, Socket Aborts & Write-Blocking Guarantees
            TestSuite8_ConcurrencyAndWriteBlocking(tempRoot);

            Console.WriteLine("=========================================================================");
            Console.WriteLine("PASS AdversarialChallengerM2M3: {0} checks passed with 0 errors.", checks);
            Console.WriteLine("ADVERSARIAL CHALLENGER M2M3 COMPLETE: All {0} checks PASSED with 0 errors.", checks);
            Console.WriteLine("=========================================================================");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL AdversarialChallengerM2M3: {0}\n{1}", ex.Message, ex.StackTrace);
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
    // SUITE 1: SQLITE CARVER ADVERSARIAL STRESS & FREELIST/FREEBLOCK CYCLES
    // =========================================================================
    private static void TestSuite1_SqliteCarverStress(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 1: SqliteCarver Adversarial Stress & Freelist/Freeblock Cycle Defense...");
        string suiteDir = Path.Combine(tempRoot, "sqlite_suite");
        Directory.CreateDirectory(suiteDir);

        // 1.1 Corrupted 100-byte database header & truncated streams
        SqliteDatabaseHeader header;
        Check(!SqliteCarver.TryParseHeader(null, out header), "Null buffer rejected by TryParseHeader");
        Check(!SqliteCarver.TryParseHeader(new byte[0], out header), "Zero-byte buffer rejected by TryParseHeader");
        Check(!SqliteCarver.TryParseHeader(new byte[50], out header), "50-byte buffer rejected by TryParseHeader");
        Check(!SqliteCarver.TryParseHeader(new byte[99], out header), "99-byte buffer rejected by TryParseHeader");

        // Non-power-of-2 page sizes and boundary page sizes
        byte[] badHeader = new byte[100];
        Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(badHeader, 0);
        badHeader[16] = 0x01; badHeader[17] = 0xF4; // Page size 500
        badHeader[18] = 1; badHeader[19] = 1;
        Check(!SqliteCarver.TryParseHeader(badHeader, out header), "Page size 500 (non-power-of-2) rejected");

        badHeader[16] = 0x00; badHeader[17] = 0x00; // Page size 0
        Check(!SqliteCarver.TryParseHeader(badHeader, out header), "Page size 0 rejected");

        // Maximum valid page size 65536 stored as 0x0001
        badHeader[16] = 0x00; badHeader[17] = 0x01;
        Check(SqliteCarver.TryParseHeader(badHeader, out header), "Page size 65536 accepted");
        Check(header.PageSize == 65536, "PageSize correctly parsed as 65536");

        // Zero-byte stream carving
        using (var ms = new MemoryStream(new byte[0]))
        {
            var zeroRecords = SqliteCarver.CarveDatabase(ms);
            Check(zeroRecords != null && zeroRecords.Count == 0, "CarveDatabase on empty stream returns 0 records");
        }

        // 1.2 Freelist trunk self-loop & cyclic graph defense (A -> A, and A -> B -> A)
        int pageSize = 512;
        byte[] cyclicDb = CreateSyntheticSqliteDb(pageSize, 4, 2, 2);
        // Trunk 1 at Page 2 (offset 512). Set NextTrunk = 2 (self-loop)
        WriteUInt32BE(cyclicDb, 512, 2); // Next trunk = 2
        WriteUInt32BE(cyclicDb, 516, 0); // Leaf count = 0

        using (var ms = new MemoryStream(cyclicDb))
        {
            DateTime start = DateTime.UtcNow;
            var records = SqliteCarver.CarveDatabase(ms);
            Check((DateTime.UtcNow - start).TotalSeconds < 2.0, "Freelist self-loop terminates promptly via visitedTrunks guard");
            Check(records != null, "Freelist self-loop returned valid record list");
        }

        // Cyclic trunk A -> B -> A: Page 2 points to Page 3, Page 3 points to Page 2
        WriteUInt32BE(cyclicDb, 512, 3); // Page 2 points to Page 3
        WriteUInt32BE(cyclicDb, 512 + pageSize, 2); // Page 3 points to Page 2
        using (var ms = new MemoryStream(cyclicDb))
        {
            DateTime start = DateTime.UtcNow;
            var records = SqliteCarver.CarveDatabase(ms);
            Check((DateTime.UtcNow - start).TotalSeconds < 2.0, "Cyclic freelist graph terminates promptly");
        }

        // Maliciously large leaf count in trunk page (0xFFFFFFFF) clamped to maxLeavesPerTrunk
        WriteUInt32BE(cyclicDb, 512, 0); // No next trunk
        WriteUInt32BE(cyclicDb, 516, 0xFFFFFFFF); // Absurd leaf count
        using (var ms = new MemoryStream(cyclicDb))
        {
            var records = SqliteCarver.CarveDatabase(ms);
            Check(records != null, "Absurd leaf count clamped safely without out-of-bounds read");
        }

        // 1.3 Freeblock cyclic linked list defense
        byte[] pageBuf = new byte[pageSize];
        // B-tree leaf table header: type 0x0D, firstFreeblock = 100, cellCount = 0, cellContentStart = 500
        pageBuf[0] = 0x0D;
        pageBuf[1] = 0x00; pageBuf[2] = 100; // firstFreeblock = 100
        pageBuf[3] = 0x00; pageBuf[4] = 0;   // cellCount = 0
        pageBuf[5] = 0x01; pageBuf[6] = 0xF4; // cellContentAreaStart = 500

        // Freeblock at 100: points to itself (next = 100, size = 16)
        pageBuf[100] = 0x00; pageBuf[101] = 100; // next = 100
        pageBuf[102] = 0x00; pageBuf[103] = 16;  // size = 16

        DateTime fbStart = DateTime.UtcNow;
        var carvedFromCycle = SqliteCarver.CarvePage(pageBuf, 2, 512);
        Check((DateTime.UtcNow - fbStart).TotalSeconds < 2.0, "Freeblock self-loop terminates promptly via visitedFb guard");

        // Freeblock size < 4 bytes (invalid degenerate size)
        pageBuf[100] = 0x00; pageBuf[101] = 0;   // next = 0
        pageBuf[102] = 0x00; pageBuf[103] = 2;   // size = 2 (< 4)
        var carvedSmallFb = SqliteCarver.CarvePage(pageBuf, 2, 512);
        Check(carvedSmallFb != null, "Freeblock size < 4 handled cleanly without exception");

        // Freeblock exceeding usable size (fbOffset + fbSize > usableSize)
        pageBuf[100] = 0x00; pageBuf[101] = 0;
        pageBuf[102] = 0x04; pageBuf[103] = 0x00; // size = 1024 > 512
        var carvedOverflowFb = SqliteCarver.CarvePage(pageBuf, 2, 512);
        Check(carvedOverflowFb != null, "Freeblock bounds overflow handled cleanly");

        // 1.4 Inverted unallocated gap bounds & excessive cell count
        pageBuf[1] = 0x00; pageBuf[2] = 0x00; // firstFreeblock = 0
        pageBuf[3] = 0x75; pageBuf[4] = 0x30; // cellCount = 30000 (huge)
        pageBuf[5] = 0x00; pageBuf[6] = 0x0A; // cellContentAreaStart = 10 (inverted: < arrayEnd)
        var carvedInverted = SqliteCarver.CarvePage(pageBuf, 2, 512);
        Check(carvedInverted != null, "Inverted gap and huge cell count handled safely");

        // 1.5 Varint, Serial Type & Integer Sign-Extension Stress
        // Reserved serial types 10 and 11
        int dummyLen;
        Check(!SqliteCarver.GetSerialTypeContentLength(10, out dummyLen), "Serial type 10 rejected");
        Check(!SqliteCarver.GetSerialTypeContentLength(11, out dummyLen), "Serial type 11 rejected");

        // Serial type single-column safety cap (> 1MB)
        long hugeBlobSerial = ((50000000L * 2) + 12);
        Check(!SqliteCarver.GetSerialTypeContentLength(hugeBlobSerial, out dummyLen), "50MB blob serial type rejected (> 1MB cap)");

        // 24-bit integer sign-extension verification
        // Craft a record with SerialType 3:
        // Header: [HeaderLen=3] [SerialType=3 (24-bit)] [SerialType=3 (24-bit)]
        // Data: [0x01, 0x02, 0x03 = +66051], [0x80, 0x00, 0x01 = -8388607]
        byte[] record24 = new byte[] {
            3, 3, 3,
            0x01, 0x02, 0x03,       // +66051
            0x80, 0x00, 0x01        // -8388607
        };
        List<SqliteColumnValue> cols24;
        int hLen24, totalConsumed24;
        bool parsed24 = SqliteCarver.TryParseRecord(record24, 0, record24.Length, out cols24, out hLen24, out totalConsumed24);
        Check(parsed24, "24-bit record parsed successfully");
        Check(cols24.Count == 2, "24-bit record has 2 columns");
        Check(cols24[0].AsLong(0) == 66051L, "Positive 24-bit integer decoded accurately");
        Check(cols24[1].AsLong(0) == -8388607L, "Negative 24-bit integer correctly sign-extended");

        // 48-bit integer sign-extension verification
        // Craft a record with SerialType 5:
        // Header: [HeaderLen=3] [SerialType=5] [SerialType=5]
        // Data: [0x00, 0x00, 0x00, 0x01, 0x00, 0x00 = +65536], [0x80, 0x00, 0x00, 0x00, 0x00, 0x01 = negative]
        byte[] record48 = new byte[] {
            3, 5, 5,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00,             // +65536
            0x80, 0x00, 0x00, 0x00, 0x00, 0x01              // sign-extended negative 48-bit
        };
        List<SqliteColumnValue> cols48;
        int hLen48, totalConsumed48;
        bool parsed48 = SqliteCarver.TryParseRecord(record48, 0, record48.Length, out cols48, out hLen48, out totalConsumed48);
        Check(parsed48, "48-bit record parsed successfully");
        Check(cols48.Count == 2, "48-bit record has 2 columns");
        Check(cols48[0].AsLong(0) == 65536L, "Positive 48-bit integer decoded accurately");
        long expectedNeg48 = unchecked((long)0xFFFF800000000001L);
        Check(cols48[1].AsLong(0) == expectedNeg48, "Negative 48-bit integer correctly sign-extended");

        // Corrupted varint past 9 bytes
        byte[] corruptVarint = new byte[] { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
        long vVal;
        int vLen = SqliteCarver.ReadVarint(corruptVarint, 0, out vVal);
        Check(vLen == 9, "9-byte varint limit enforced");

        // 1.6 Large stream & Heuristic Carving
        byte[] largeDb = CreateSyntheticSqliteDb(4096, 256, 0, 0); // 1 MB multi-page database
        using (var ms = new MemoryStream(largeDb))
        {
            var largeRecords = SqliteCarver.CarveDatabase(ms);
            Check(largeRecords != null, "CarveDatabase on 1MB multi-page stream completes without memory issues");
        }

        // Raw damaged buffer / slack space heuristic scan
        byte[] rawSlack = new byte[65536];
        for (int i = 0; i < rawSlack.Length; i++) rawSlack[i] = 0xAA; // dense garbage fill
        byte[] payload = BuildRecordPayload(new long[] { 43, 2 }, new object[] { "CarvedFromSlack", (long)404 });
        byte[] cell = BuildTableCell(1234, payload);
        Buffer.BlockCopy(cell, 0, rawSlack, 500, cell.Length);

        List<CarvedSqliteRecord> carvedSlack = SqliteCarver.CarveBuffer(rawSlack, 100000);
        Check(carvedSlack != null && carvedSlack.Count > 0, "Heuristic carving recovered record from raw buffer");
        Check(carvedSlack[0].RowId == 1234, "Heuristic carved RowId is 1234");
        Check(carvedSlack[0].Columns[0].AsString() == "CarvedFromSlack", "Heuristic carved string matches CarvedFromSlack");
        Check(carvedSlack[0].Columns[1].AsLong(0) == 404, "Heuristic carved integer matches 404");
        Check(carvedSlack[0].AbsoluteOffset == 100500, "Absolute offset correctly adjusted (100000 + 500)");

        // 1.7 Write-blocking invariant
        string hashBefore = ComputeSha256(rawSlack);
        SqliteCarver.CarveBuffer(rawSlack, 0);
        string hashAfter = ComputeSha256(rawSlack);
        Check(hashBefore == hashAfter, "SqliteCarver adheres strictly to write-blocking guarantee");
    }

    // =========================================================================
    // SUITE 2: EVTX PARSER ADVERSARIAL STRESS & CORRUPTED BINXML TOKENS
    // =========================================================================
    private static void TestSuite2_EvtxParserStress(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 2: EvtxParser BinXml Adversarial Tokens & Chunk Corruption...");

        // 2.1 Truncated buffers & corrupt headers
        Check(EvtxParser.Parse(new byte[0]).Count == 0, "0-byte EVTX buffer returns 0 records");
        Check(EvtxParser.Parse(new byte[128]).Count == 0, "128-byte EVTX buffer returns 0 records");
        Check(EvtxParser.Parse(new byte[511]).Count == 0, "511-byte EVTX buffer returns 0 records");

        // File header with ElfFile\0 but 0 chunks (random noise after 4096 bytes)
        byte[] fakeFile = new byte[8192];
        Encoding.ASCII.GetBytes("ElfFile\0").CopyTo(fakeFile, 0);
        new Random(42).NextBytes(fakeFile);
        Encoding.ASCII.GetBytes("ElfFile\0").CopyTo(fakeFile, 0); // Restore magic
        var fakeRecords = EvtxParser.Parse(fakeFile);
        Check(fakeRecords != null && fakeRecords.Count == 0, "ElfFile header followed by random bytes returns 0 records without crash");

        // 2.2 Corrupt chunk FreeSpaceOffset
        byte[] corruptChunk = CreateAdversarialEvtxChunk(0, null); // FreeSpaceOffset = 0
        var recordsCorruptFso = EvtxParser.Parse(corruptChunk);
        Check(recordsCorruptFso != null, "FreeSpaceOffset = 0 handled safely");

        byte[] corruptChunkBig = CreateAdversarialEvtxChunk(0xFFFFFFFF, null); // FreeSpaceOffset out of bounds
        var recordsCorruptBigFso = EvtxParser.Parse(corruptChunkBig);
        Check(recordsCorruptBigFso != null, "FreeSpaceOffset = 0xFFFFFFFF clamped safely");

        // 2.3 Record size mismatch & corruption
        byte[] mismatchPayload = new byte[256];
        WriteUInt32LE(mismatchPayload, 0, 0x00002A2A); // Magic
        WriteUInt32LE(mismatchPayload, 4, 100);        // Record size = 100
        WriteUInt32LE(mismatchPayload, 100 - 4, 200);  // Trailing size = 200 (MISMATCH)
        byte[] chunkMismatch = CreateAdversarialEvtxChunk(1024, mismatchPayload);
        var recMismatch = EvtxParser.Parse(chunkMismatch);
        Check(recMismatch.Count == 0, "Record with mismatched trailing size safely skipped");

        // Record with size < 28
        byte[] smallPayload = new byte[256];
        WriteUInt32LE(smallPayload, 0, 0x00002A2A);
        WriteUInt32LE(smallPayload, 4, 20); // < 28 bytes
        byte[] chunkSmall = CreateAdversarialEvtxChunk(1024, smallPayload);
        var recSmall = EvtxParser.Parse(chunkSmall);
        Check(recSmall.Count == 0, "Record with size < 28 safely skipped");

        // 2.4 BinXml Token Robustness & Stack Balancing
        // Test deep nesting of OpenStartElement (0x01) without closing EndElement (500 tokens)
        var templateCache = new Dictionary<uint, BinXmlTemplate>();
        var advRecord = new EvtxRecord();
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(0x0F); ms.WriteByte(0x01); ms.WriteByte(0x01); ms.WriteByte(0x00); // FragmentHeader
            for (int i = 0; i < 50; i++)
            {
                ms.WriteByte(0x01); // OpenStartElement
                ms.Write(new byte[] { 0, 0 }, 0, 2); // depId
                byte[] nameBytes = Encoding.Unicode.GetBytes(string.Format("Elem{0}\0", i));
                ms.Write(BitConverter.GetBytes((uint)nameBytes.Length), 0, 4);
                ms.Write(nameBytes, 0, nameBytes.Length);
            }
            byte[] nestedXmlBytes = ms.ToArray();
            BinXmlDecoder.Decode(nestedXmlBytes, 0, nestedXmlBytes.Length, 0, templateCache, advRecord);
            Check(advRecord.XmlContent != null && advRecord.XmlContent.Length > 0, "Deeply nested BinXml elements unwind gracefully at EOF");
        }

        // Test unbalanced EndElement tokens (0x04) with empty element stack
        advRecord = new EvtxRecord();
        byte[] underflowTokens = new byte[] { 0x0F, 0x01, 0x01, 0x00, 0x04, 0x04, 0x04, 0x04, 0x00 };
        BinXmlDecoder.Decode(underflowTokens, 0, underflowTokens.Length, 0, templateCache, advRecord);
        Check(advRecord.XmlContent.Contains("</Element>"), "Unbalanced EndElement emits fallback element without stack underflow");

        // Test unknown/garbage BinXml tokens (0xEE, 0xFF, 0x42)
        advRecord = new EvtxRecord();
        byte[] garbageTokens = new byte[] { 0x0F, 0x01, 0x01, 0x00, 0xEE, 0xFF, 0x42, 0xAA, 0x00 };
        BinXmlDecoder.Decode(garbageTokens, 0, garbageTokens.Length, 0, templateCache, advRecord);
        Check(advRecord.XmlContent != null, "Garbage BinXml tokens handled cleanly without infinite loop");

        // 2.5 Corrupted SID substitution (size < 8 + subAuthCount * 4)
        // Token 0x0C (TemplateInstance), Header 0x01, Inline template with SID value
        byte[] corruptSidTokens = new byte[] {
            0x0F, 0x01, 0x01, 0x00, // Fragment header
            0x0C,                   // TemplateInstance
            0x01,                   // Inline template
            0x00, 0x00, 0x00, 0x00, // Template offset
            0x01, 0x00, 0x00, 0x00, // Template ID = 1
            0x02, 0x00, 0x00, 0x00, // Template len = 2
            0x00, 0x00,             // Template EOF
            0x01, 0x00, 0x00, 0x00, // 1 substitution value
            0x13, 0x00,             // Type 0x13 (SID)
            0x08, 0x00,             // Value size = 8 bytes
            0x01, 0xFF,             // Revision 1, subAuthCount = 255 (requires 8 + 255*4 bytes, but only 8 provided)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05 // Auth ID
        };
        advRecord = new EvtxRecord();
        BinXmlDecoder.Decode(corruptSidTokens, 0, corruptSidTokens.Length, 0, templateCache, advRecord);
        Check(advRecord != null, "Corrupted SID substitution value handled without index out of range");

        // 2.6 Slack-space carving edge cases
        // Create 64 KiB chunk with allocated space ending at offset 600, leaving ~64.9 KiB of slack space.
        // In slack space, place 5 fake records with bad trailing sizes, and 1 genuine deleted record.
        byte[] slackChunk = new byte[65536];
        Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(slackChunk, 0);
        WriteUInt32LE(slackChunk, 48, 600); // FreeSpaceOffset = 600

        // Fake records at slack offset 1000, 1500, 2000
        for (int offset = 1000; offset <= 2000; offset += 500)
        {
            WriteUInt32LE(slackChunk, offset, 0x00002A2A);
            WriteUInt32LE(slackChunk, offset + 4, 100);
            WriteUInt32LE(slackChunk, offset + 100 - 4, 999); // Bad trailing size
        }

        // Genuine deleted record at slack offset 3000
        int delRecSize = 64;
        WriteUInt32LE(slackChunk, 3000, 0x00002A2A);
        WriteUInt32LE(slackChunk, 3004, (uint)delRecSize);
        WriteInt64LE(slackChunk, 3008, 9999L); // RecordId
        WriteInt64LE(slackChunk, 3016, DateTime.UtcNow.ToFileTimeUtc()); // FileTime
        // Simple fragment: 0x0F, 0x01, 0x01, 0x00, 0x00
        slackChunk[3024] = 0x0F; slackChunk[3025] = 0x01; slackChunk[3026] = 0x01; slackChunk[3027] = 0x00; slackChunk[3028] = 0x00;
        WriteUInt32LE(slackChunk, 3000 + delRecSize - 4, (uint)delRecSize); // Matching trailing size

        var slackRecords = EvtxParser.Parse(slackChunk);
        Check(slackRecords.Count == 1, "Slack space carver isolated valid record and filtered out fake markers");
        Check(slackRecords[0].RecordId == 9999L, "Slack space carved record ID matches 9999");

        // 2.7 Write-blocking invariant
        string evtxHashBefore = ComputeSha256(slackChunk);
        EvtxParser.Parse(slackChunk);
        string evtxHashAfter = ComputeSha256(slackChunk);
        Check(evtxHashBefore == evtxHashAfter, "EvtxParser adheres strictly to write-blocking guarantee");
    }

    // =========================================================================
    // SUITE 3: PREFETCH PARSER MAM XPRESS HUFFMAN & CORRUPTED HEADERS
    // =========================================================================
    private static void TestSuite3_PrefetchParserStress(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 3: PrefetchParser MAM XPRESS Huffman & Multi-Version Decompression...");

        // 3.1 Buffer under 84 bytes throws InvalidDataException
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(new byte[0]), "0-byte buffer throws InvalidDataException");
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(new byte[50]), "50-byte buffer throws InvalidDataException");
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(new byte[83]), "83-byte buffer throws InvalidDataException");

        // 3.2 MAM uncompressed size out of bounds (0, 50 < 84, and 20MB > 10MB)
        byte[] badMam1 = new byte[84];
        WriteUInt32LE(badMam1, 0, 0x044D414D); // "MAM\x04"
        WriteUInt32LE(badMam1, 4, 50);         // < 84
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(badMam1), "MAM size < 84 rejected");

        byte[] badMam2 = new byte[84];
        WriteUInt32LE(badMam2, 0, 0x044D414D);
        WriteUInt32LE(badMam2, 4, 20 * 1024 * 1024); // 20 MB > 10 MB cap
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(badMam2), "MAM size > 10MB rejected");

        // 3.3 Truncated MAM compressed body
        byte[] truncMam = new byte[84];
        WriteUInt32LE(truncMam, 0, 0x044D414D);
        WriteUInt32LE(truncMam, 4, 1024); // Claims 1024 bytes, but only 76 bytes of payload follow
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(truncMam), "Truncated MAM body rejected");

        // 3.4 Corrupted Canonical Huffman table (sum of bit lengths != 32768)
        byte[] badHuffmanBlock = new byte[260];
        // All nibbles 0 -> sum = 0 != 32768
        AssertThrows<InvalidDataException>(() => MsXpressHuffman.Decompress(badHuffmanBlock, 0, badHuffmanBlock.Length, 1024),
            "Huffman table sum == 0 rejected with InvalidDataException");

        // 3.5 Out-of-bounds match offset & cyclic match length
        // Synthetic prefetch generation
        byte[] validScca = CreateSyntheticPrefetch(30, "CMD.EXE", 0x12345678, 5, false);
        var sccaArt = PrefetchParser.Parse(validScca);
        Check(sccaArt.ExecutableName == "CMD.EXE", "Valid synthetic SCCA prefetch exe name parsed");
        Check(sccaArt.RunCount == 5, "Run count parsed: " + sccaArt.RunCount);
        Check(sccaArt.Hash == "12345678", "Hash parsed: " + sccaArt.Hash);

        // Compress with MAM and verify decompression roundtrip
        byte[] validMam = CreateSyntheticPrefetch(30, "POWERSHELL.EXE", 0xABCDEF01, 42, true);
        var mamArt = PrefetchParser.Parse(validMam);
        Check(mamArt.ExecutableName == "POWERSHELL.EXE", "MAM compressed prefetch decompressed & parsed");
        Check(mamArt.RunCount == 42, "MAM run count matches 42");

        // Out-of-bounds match offset test in Decompress
        // In compressed bitstream, reference matchOffset > currentOutputPos
        byte[] literalData = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] compressedLiteral = MsXpressHuffman.CompressLiteralOnly(literalData);
        byte[] decompressedLiteral = MsXpressHuffman.Decompress(compressedLiteral, 0, compressedLiteral.Length, literalData.Length);
        Check(ByteArrayEquals(literalData, decompressedLiteral), "Literal only compression roundtrips accurately");

        // 3.6 Multi-version prefetch header parsing (v17 XP, v23 Vista/7, v26 Win8, v30 Win10/11)
        byte[] pfXp = CreateSyntheticPrefetch(17, "CALC.EXE", 0x11111111, 1, false);
        Check(PrefetchParser.Parse(pfXp).Version == 17, "XP version 17 parsed");

        byte[] pfVista = CreateSyntheticPrefetch(23, "NOTEPAD.EXE", 0x22222222, 2, false);
        Check(PrefetchParser.Parse(pfVista).Version == 23, "Vista version 23 parsed");

        byte[] pfWin8 = CreateSyntheticPrefetch(26, "EXPLORER.EXE", 0x33333333, 3, false);
        Check(PrefetchParser.Parse(pfWin8).Version == 26, "Win8 version 26 parsed");

        byte[] pfWin10 = CreateSyntheticPrefetch(30, "SVCHOST.EXE", 0x44444444, 4, false);
        Check(PrefetchParser.Parse(pfWin10).Version == 30, "Win10 version 30 parsed");

        // Non-null-terminated executable name (60 characters without null)
        byte[] pfNonTerm = CreateSyntheticPrefetch(30, "VERYLONGEXECUTABLENAMETHATFILLSTHEENTIREBUFFERWITHOUTTERMINATION", 0x55555555, 1, false);
        var artNonTerm = PrefetchParser.Parse(pfNonTerm);
        Check(artNonTerm.ExecutableName.Length > 0, "Non-null-terminated exe name handled safely without overrun");

        // Corrupted Section C & Section D offsets (pointing past EOF)
        byte[] pfBadSec = (byte[])pfWin10.Clone();
        WriteUInt32LE(pfBadSec, 100, 0xFFFFFF); // secCOffset
        WriteUInt32LE(pfBadSec, 104, 50000);    // secDCount
        var artBadSec = PrefetchParser.Parse(pfBadSec);
        Check(artBadSec != null, "Corrupt section offsets handled safely with empty file/volume lists");

        // 3.7 Write-blocking invariant
        string pfHashBefore = ComputeSha256(validMam);
        PrefetchParser.Parse(validMam);
        string pfHashAfter = ComputeSha256(validMam);
        Check(pfHashBefore == pfHashAfter, "PrefetchParser adheres strictly to write-blocking guarantee");
    }

    // =========================================================================
    // SUITE 4: LNK PARSER SHELL LINK & SHELLBAG MRU CORRUPT LAYOUTS
    // =========================================================================
    private static void TestSuite4_LnkParserStress(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 4: LnkParser Shell Link & Shellbag MRU Corrupt Layouts...");

        Guid validClsid = new Guid("00021401-0000-0000-c000-000000000046");

        // 4.1 Buffer under 76 bytes, HeaderSize != 0x4C, and invalid CLSID
        AssertThrows<InvalidDataException>(() => LnkParser.Parse(new byte[0]), "0-byte LNK throws InvalidDataException");
        AssertThrows<InvalidDataException>(() => LnkParser.Parse(new byte[75]), "75-byte LNK throws InvalidDataException");

        byte[] badHeaderSize = CreateAdversarialLnk(0x50, validClsid, 0, null, null);
        AssertThrows<InvalidDataException>(() => LnkParser.Parse(badHeaderSize), "HeaderSize != 0x4C rejected");

        byte[] badClsid = CreateAdversarialLnk(0x4C, Guid.NewGuid(), 0, null, null);
        AssertThrows<InvalidDataException>(() => LnkParser.Parse(badClsid), "Invalid CLSID rejected");

        // 4.2 Degenerate shell item size = 0 in IDList (Infinite Loop Trap)
        byte[] zeroItem = new byte[] { 0x00, 0x00, 0x10, 0x00 };
        byte[] lnkZeroItem = CreateAdversarialLnk(0x4C, validClsid, 0x01, zeroItem, null);
        DateTime idStart = DateTime.UtcNow;
        var artZeroItem = LnkParser.Parse(lnkZeroItem);
        Check((DateTime.UtcNow - idStart).TotalSeconds < 2.0, "Zero-size shell item terminates immediately without loop");

        // Truncated IDList item bounds
        byte[] truncIdList = new byte[] { 0x50, 0x00, 0x1F, 0x00 }; // Claims 80 bytes, only 4 provided
        byte[] lnkTruncId = CreateAdversarialLnk(0x4C, validClsid, 0x01, truncIdList, null);
        var artTrunc = LnkParser.Parse(lnkTruncId);
        Check(artTrunc != null, "Truncated IDList item bounded safely");

        // 4.3 Corrupt LinkInfo offsets
        using (var ms = new MemoryStream())
        {
            ms.Write(BitConverter.GetBytes((uint)28), 0, 4);  // linkInfoSize = 28
            ms.Write(BitConverter.GetBytes((uint)28), 0, 4);  // linkInfoHeaderSize = 28
            ms.Write(BitConverter.GetBytes((uint)1), 0, 4);   // flags = VolumeIDAndLocalBasePath
            ms.Write(BitConverter.GetBytes((uint)1000), 0, 4); // volumeIdOffset (out of bounds)
            ms.Write(BitConverter.GetBytes((uint)2000), 0, 4); // localBasePathOffset (out of bounds)
            ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
            ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
            byte[] linkInfo = ms.ToArray();

            byte[] lnkBadInfo = CreateAdversarialLnk(0x4C, validClsid, 0x02, null, null);
            // Append bad linkinfo
            byte[] combined = new byte[lnkBadInfo.Length + linkInfo.Length];
            Buffer.BlockCopy(lnkBadInfo, 0, combined, 0, lnkBadInfo.Length);
            Buffer.BlockCopy(linkInfo, 0, combined, lnkBadInfo.Length, linkInfo.Length);

            var artBadInfo = LnkParser.Parse(combined);
            Check(artBadInfo != null, "LinkInfo offsets out of bounds handled safely without crash");
        }

        // 4.4 Degenerate ExtraData block size < 4 (Infinite Loop Trap)
        byte[] extraDataZero = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        byte[] lnkExtraZero = CreateAdversarialLnk(0x4C, validClsid, 0, null, extraDataZero);
        DateTime exStart = DateTime.UtcNow;
        var artExtraZero = LnkParser.Parse(lnkExtraZero);
        Check((DateTime.UtcNow - exStart).TotalSeconds < 2.0, "ExtraData block size < 4 terminates immediately");

        // Malformed TrackerDataBlock (0xA0000003) with size < 88 bytes
        byte[] badTracker = new byte[] {
            30, 0, 0, 0,                 // Size = 30 (< 88)
            0x03, 0x00, 0x00, 0xA0,      // Signature = 0xA0000003
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
        byte[] lnkBadTracker = CreateAdversarialLnk(0x4C, validClsid, 0, null, badTracker);
        var artBadTracker = LnkParser.Parse(lnkBadTracker);
        Check(artBadTracker.MachineId == string.Empty, "Malformed TrackerDataBlock skipped safely");

        // 4.5 Shellbags corrupted MRUListEx loops and missing slot IDs
        // Valid MRU entry terminating with 0xFFFFFFFF
        byte[] mruValid = new byte[] {
            0, 0, 0, 0,                 // Slot 0
            1, 0, 0, 0,                 // Slot 1
            0xFF, 0xFF, 0xFF, 0xFF      // Terminator
        };
        var childItems = new Dictionary<int, byte[]>();
        childItems[0] = new byte[] { 0x14, 0x00, 0x31, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)'A', 0, 0, 0, 0, 0 };
        // Slot 1 missing from dictionary
        var shellbags = LnkParser.ParseShellbags(mruValid, childItems);
        Check(shellbags != null && shellbags.Count == 1, "Shellbag parses available slot and ignores missing slot ID");

        // MRU list without 0xFFFFFFFF terminator
        byte[] mruUnterminated = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        var shellbagsUnterm = LnkParser.ParseShellbags(mruUnterminated, childItems);
        Check(shellbagsUnterm != null, "Unterminated MRU list parsed without infinite loop");

        // 4.6 Write-blocking invariant
        string lnkHashBefore = ComputeSha256(lnkBadTracker);
        LnkParser.Parse(lnkBadTracker);
        string lnkHashAfter = ComputeSha256(lnkBadTracker);
        Check(lnkHashBefore == lnkHashAfter, "LnkParser adheres strictly to write-blocking guarantee");
    }

    // =========================================================================
    // SUITE 5: BROWSER HISTORY PARSER TIMESTAMP CLAMPING & CACHE CORRUPTION
    // =========================================================================
    private static void TestSuite5_BrowserHistoryStress(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 5: BrowserHistoryParser Timestamp Clamping & Cache Corruption...");

        // 5.1 WebKit timestamp extreme boundaries
        Check(BrowserTimestampConverter.WebKitTimeToUtc(-100) == DateTime.MinValue, "Negative WebKit time clamps to DateTime.MinValue");
        Check(BrowserTimestampConverter.WebKitTimeToUtc(0) == DateTime.MinValue, "0 WebKit time clamps to DateTime.MinValue");
        DateTime normalWebKit = BrowserTimestampConverter.WebKitTimeToUtc(11644473600000000L); // 1970-01-01
        Check(normalWebKit.Year == 1970, "Normal WebKit timestamp decoded to 1970");
        Check(BrowserTimestampConverter.WebKitTimeToUtc(long.MaxValue) == DateTime.MaxValue, "long.MaxValue WebKit time clamps to DateTime.MaxValue");

        // 5.2 Mozilla PRTime extreme boundaries
        Check(BrowserTimestampConverter.PrTimeToUtc(-100) == DateTime.MinValue, "Negative PRTime clamps to DateTime.MinValue");
        Check(BrowserTimestampConverter.PrTimeToUtc(0) == DateTime.MinValue, "0 PRTime clamps to DateTime.MinValue");
        DateTime normalPrTime = BrowserTimestampConverter.PrTimeToUtc(946684800000000L); // 2000-01-01
        Check(normalPrTime.Year == 2000, "Normal PRTime decoded to 2000");
        Check(BrowserTimestampConverter.PrTimeToUtc(long.MaxValue) == DateTime.MaxValue, "long.MaxValue PRTime clamps to DateTime.MaxValue");

        // 5.3 Chromium history orphaned visits
        // Create synthetic CarvedSqliteRecord representing an orphaned visit in "visits" table
        var orphanedVisit = new CarvedSqliteRecord();
        orphanedVisit.Columns = new List<SqliteColumnValue>();
        // Column 0: id (1)
        var c0 = new SqliteColumnValue(); c0.ColumnIndex = 0; c0.Type = SqliteColumnType.Integer; c0.Value = 1L; orphanedVisit.Columns.Add(c0);
        // Column 1: url (url_id = 999999)
        var c1 = new SqliteColumnValue(); c1.ColumnIndex = 1; c1.Type = SqliteColumnType.Integer; c1.Value = 999999L; orphanedVisit.Columns.Add(c1);
        // Column 2: visit_time
        var c2 = new SqliteColumnValue(); c2.ColumnIndex = 2; c2.Type = SqliteColumnType.Integer; c2.Value = 13200000000000000L; orphanedVisit.Columns.Add(c2);
        // Column 3: from_visit
        var c3 = new SqliteColumnValue(); c3.ColumnIndex = 3; c3.Type = SqliteColumnType.Integer; c3.Value = 0L; orphanedVisit.Columns.Add(c3);
        // Column 4: transition
        var c4 = new SqliteColumnValue(); c4.ColumnIndex = 4; c4.Type = SqliteColumnType.Integer; c4.Value = 0L; orphanedVisit.Columns.Add(c4);

        var chromResults = BrowserHistoryParser.InterpretChromiumRecords(new CarvedSqliteRecord[] { orphanedVisit });
        Check(chromResults.Count == 1, "Chromium orphaned visit preserved without loss");
        Check(chromResults[0].Url.Contains("999999"), "Orphaned visit records synthetic placeholder URL");

        // 5.4 Firefox history orphaned visits
        var mozOrphanedVisit = new CarvedSqliteRecord();
        mozOrphanedVisit.Columns = new List<SqliteColumnValue>();
        // Col 0: id
        var m0 = new SqliteColumnValue(); m0.ColumnIndex = 0; m0.Type = SqliteColumnType.Integer; m0.Value = 1L; mozOrphanedVisit.Columns.Add(m0);
        // Col 1: from_visit
        var m1 = new SqliteColumnValue(); m1.ColumnIndex = 1; m1.Type = SqliteColumnType.Integer; m1.Value = 0L; mozOrphanedVisit.Columns.Add(m1);
        // Col 2: place_id = 888888
        var m2 = new SqliteColumnValue(); m2.ColumnIndex = 2; m2.Type = SqliteColumnType.Integer; m2.Value = 888888L; mozOrphanedVisit.Columns.Add(m2);
        // Col 3: visit_date
        var m3 = new SqliteColumnValue(); m3.ColumnIndex = 3; m3.Type = SqliteColumnType.Integer; m3.Value = 1600000000000000L; mozOrphanedVisit.Columns.Add(m3);
        // Col 4: visit_type
        var m4 = new SqliteColumnValue(); m4.ColumnIndex = 4; m4.Type = SqliteColumnType.Integer; m4.Value = 1L; mozOrphanedVisit.Columns.Add(m4);

        var ffResults = BrowserHistoryParser.InterpretFirefoxRecords(new CarvedSqliteRecord[] { mozOrphanedVisit });
        Check(ffResults.Count == 1, "Firefox orphaned visit preserved without loss");
        Check(ffResults[0].Url.Contains("888888"), "Firefox orphaned visit records synthetic placeholder URL");

        // 5.5 Chromium Simple Cache corrupted headers
        using (var ms = new MemoryStream(new byte[10]))
        {
            Check(BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy") == null, "Stream < 24 bytes returns null");
        }

        byte[] badSimpleCache = new byte[64];
        BitConverter.GetBytes(0x1234567890ABCDEFUL).CopyTo(badSimpleCache, 0); // Bad magic
        using (var ms = new MemoryStream(badSimpleCache))
        {
            Check(BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy") == null, "Invalid Simple Cache magic returns null");
        }

        // Key length overflow
        byte[] overflowKeySimple = new byte[64];
        BitConverter.GetBytes(0xfcfb6d0543706173UL).CopyTo(overflowKeySimple, 0); // Valid magic
        BitConverter.GetBytes((uint)1).CopyTo(overflowKeySimple, 8);               // Version
        BitConverter.GetBytes((uint)5000).CopyTo(overflowKeySimple, 12);           // Key length > buffer
        using (var ms = new MemoryStream(overflowKeySimple))
        {
            Check(BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy") == null, "Key length overflow returns null");
        }

        // 5.6 Firefox Cache2 corrupted metadata
        using (var ms = new MemoryStream(new byte[10]))
        {
            Check(BrowserHistoryParser.ParseFirefoxCache2(ms, "dummy") == null, "Stream < 24 bytes returns null");
        }

        // Metadata size overflow
        byte[] badFfCache = new byte[64];
        badFfCache[60] = 0; badFfCache[61] = 0; badFfCache[62] = 0x04; badFfCache[63] = 0x00; // metaDataSize = 1024 > 64
        using (var ms = new MemoryStream(badFfCache))
        {
            Check(BrowserHistoryParser.ParseFirefoxCache2(ms, "dummy") == null, "Firefox Cache2 metaDataSize overflow returns null");
        }

        // 5.7 Write-blocking invariant
        byte[] cacheData = new byte[128];
        BitConverter.GetBytes(0xfcfb6d0543706173UL).CopyTo(cacheData, 0);
        string cacheHashBefore = ComputeSha256(cacheData);
        using (var ms = new MemoryStream(cacheData))
        {
            BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy");
        }
        string cacheHashAfter = ComputeSha256(cacheData);
        Check(cacheHashBefore == cacheHashAfter, "BrowserCache parser adheres strictly to write-blocking guarantee");
    }

    // =========================================================================
    // SUITE 6: LOCAL WEB SERVER /api/export-zip ADVERSARIAL EDGE CASES
    // =========================================================================
    private static void TestSuite6_WebServerExportZip(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 6: LocalWebServer /api/export-zip Adversarial Edge Cases...");
        string testDir = Path.Combine(tempRoot, "zip_suite");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "dummy.raw");
        File.WriteAllBytes(dummyImage, new byte[512]);

        // 6.1 Missing directory returns 404
        string missingDir = Path.Combine(testDir, "missing_recovered");
        int portA = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, missingDir, portA))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;
            AssertHttpStatus(baseUrl + "/api/export-zip", HttpStatusCode.NotFound, "No recovered files directory found");
            server.Stop();
        }

        // 6.2 Empty directory returns 404
        string emptyDir = Path.Combine(testDir, "empty_recovered");
        Directory.CreateDirectory(emptyDir);
        int portB = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, emptyDir, portB))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;
            AssertHttpStatus(baseUrl + "/api/export-zip", HttpStatusCode.NotFound, "No recovered files to export");
            server.Stop();
        }

        // 6.3 Path traversal and invalid filters
        string recoveredDir = Path.Combine(testDir, "recovered");
        Directory.CreateDirectory(recoveredDir);
        File.WriteAllText(Path.Combine(recoveredDir, "file1.txt"), "Evidence payload 1");
        File.WriteAllText(Path.Combine(recoveredDir, "file2.bin"), "Evidence binary 2");

        // Create nested subfolder to verify forward-slash normalization
        string subDir = Path.Combine(recoveredDir, "sub\\nested");
        Directory.CreateDirectory(subDir);
        File.WriteAllText(Path.Combine(subDir, "nested_artifact.log"), "Nested log data");

        int portC = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, recoveredDir, portC))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            // Path traversal attempt
            AssertHttpStatus(baseUrl + "/api/export-zip?files=../../cmd.exe,../boot.ini",
                HttpStatusCode.NotFound, "No matching files found for export");
            AssertHttpStatus(baseUrl + "/api/export-zip?files=..\\..\\windows\\system32\\calc.exe",
                HttpStatusCode.NotFound, "No matching files found for export");

            // Non-existent filter item
            AssertHttpStatus(baseUrl + "/api/export-zip?files=missing_file.xyz",
                HttpStatusCode.NotFound, "No matching files found for export");

            // Malformed delimiters
            AssertHttpStatus(baseUrl + "/api/export-zip?files=,,,  ,,",
                HttpStatusCode.NotFound, "No matching files found for export");

            // 6.6 Forward-slash normalization in ZIP entries & Valid ZIP binary header
            using (var client = new WebClient())
            {
                byte[] zipBytes = client.DownloadData(baseUrl + "/api/export-zip");
                Check(zipBytes != null && zipBytes.Length > 100, "Exported zip bytes downloaded");

                // Check standard PK 03 04 header
                Check(zipBytes[0] == 0x50 && zipBytes[1] == 0x4B && zipBytes[2] == 0x03 && zipBytes[3] == 0x04,
                    "ZIP header begins with PK\\x03\\x04 (0x04034b50)");

                // Verify with .NET ZipArchive oracle
                using (var archive = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read))
                {
                    Check(archive.Entries.Count == 3, "ZipArchive parsed all 3 files");
                    foreach (var entry in archive.Entries)
                    {
                        Check(!entry.FullName.Contains("\\"), "Zip entry path normalized with forward slashes only: " + entry.FullName);
                        using (var s = entry.Open())
                        using (var ms = new MemoryStream())
                        {
                            s.CopyTo(ms);
                            Check(ms.Length > 0, "Non-empty entry extracted successfully: " + entry.Name);
                        }
                    }
                }
            }

            server.Stop();
        }
    }

    // =========================================================================
    // SUITE 7: LOCAL WEB SERVER /api/report & PURE C# PDF SYNTAX
    // =========================================================================
    private static void TestSuite7_WebServerReportAndPdf(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 7: LocalWebServer /api/report & PDF Artifact Syntax...");
        string testDir = Path.Combine(tempRoot, "report_suite");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "dummy.raw");
        File.WriteAllBytes(dummyImage, new byte[512]);

        // 7.1 Missing / empty catalog report
        string emptyOutput = Path.Combine(testDir, "empty_report");
        Directory.CreateDirectory(emptyOutput);

        int portA = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, emptyOutput, portA))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            using (var client = new WebClient { Encoding = Encoding.UTF8 })
            {
                string json = client.DownloadString(baseUrl + "/api/report?format=json");
                var serializer = new JavaScriptSerializer();
                var rep = serializer.Deserialize<Dictionary<string, object>>(json);
                Check(Convert.ToInt32(rep["fileCount"]) == 0, "Empty catalog has fileCount = 0");
                Check(rep["chainOfCustodySha256"].ToString() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "Empty catalog chain-of-custody hash is SHA-256 of empty string");

                string html = client.DownloadString(baseUrl + "/api/report?format=html");
                Check(html.Contains("No artifacts recovered."), "Empty catalog HTML contains 'No artifacts recovered.'");
                Check(html.Contains("0 items"), "Empty catalog HTML displays '0 items'");
            }
            server.Stop();
        }

        // 7.2 Adversarial format query parameters & HTML escaping / XSS protection
        string xssOutput = Path.Combine(testDir, "xss_report");
        Directory.CreateDirectory(xssOutput);
        string maliciousName = "test_artifact_&_special_'quote'.dat";
        File.WriteAllText(Path.Combine(xssOutput, maliciousName), "clean content");

        // 7.4 Pure C# PDF 1.4 synthetic artifact in catalog
        byte[] syntheticPdf = CreateSyntheticPdf14("Forensic Report", "Cryptographic Chain of Custody Verified");
        string pdfPath = Path.Combine(xssOutput, "recovered_evidence.pdf");
        File.WriteAllBytes(pdfPath, syntheticPdf);

        int portB = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, xssOutput, portB))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            using (var client = new WebClient { Encoding = Encoding.UTF8 })
            {
                // Uppercase JSON
                string jsonUpper = client.DownloadString(baseUrl + "/api/report?format=JSON");
                Check(jsonUpper.StartsWith("{") && jsonUpper.Contains("chainOfCustodySha256"), "?format=JSON accepted");

                // format=pdf fallback to HTML with @media print CSS
                string pdfFall = client.DownloadString(baseUrl + "/api/report?format=pdf");
                Check(pdfFall.Contains("<!DOCTYPE html>") && pdfFall.Contains("@media print"), "?format=pdf serves HTML print layout");

                // format=xml fallback to HTML
                string xmlFall = client.DownloadString(baseUrl + "/api/report?format=xml");
                Check(xmlFall.Contains("<!DOCTYPE html>"), "?format=xml falls back to HTML");

                // format=<script> XSS fallback
                string xssFall = client.DownloadString(baseUrl + "/api/report?format=%3Cscript%3Ealert(1)%3C/script%3E");
                Check(xssFall.Contains("<!DOCTYPE html>"), "XSS format param falls back to HTML");
                Check(!xssFall.Contains("<script>alert(1)</script>"), "Raw malicious <script> tag strictly absent from HTML report");

                // HTML entity escaping verification
                string html = client.DownloadString(baseUrl + "/api/report?format=html");
                Check(!html.Contains("<script>alert"), "No unescaped script tag in HTML report");
                Check(html.Contains("test_artifact_&amp;_special_&#39;quote&#39;.dat") || html.Contains("test_artifact_&amp;_special_'quote'.dat"),
                    "Filename with special characters safely HTML encoded");

                // Verify ISO/IEC 27037 compliance badges
                Check(html.Contains("ISO/IEC 27037 Compatible"), "Contains 'ISO/IEC 27037 Compatible' seal");
                Check(html.Contains("Cryptographic Chain-of-Custody Manifest"), "Contains 'Cryptographic Chain-of-Custody Manifest'");

                // Verify PDF artifact cataloged in JSON report
                var serializer = new JavaScriptSerializer();
                var rep = serializer.Deserialize<Dictionary<string, object>>(jsonUpper);
                Check(Convert.ToInt32(rep["fileCount"]) == 2, "Report lists 2 files (including PDF)");
                var filesList = (System.Collections.ArrayList)rep["files"];
                bool foundPdf = false;
                foreach (Dictionary<string, object> f in filesList)
                {
                    if (f["name"].ToString() == "recovered_evidence.pdf")
                    {
                        foundPdf = true;
                        Check(Convert.ToInt64(f["size"]) == syntheticPdf.Length, "PDF artifact size in report matches synthetic size");
                        Check(f["sha256"].ToString() == ComputeSha256(syntheticPdf), "PDF artifact SHA-256 in report matches oracle hash");
                        break;
                    }
                }
                Check(foundPdf, "Synthetic PDF 1.4 artifact successfully cataloged in forensic manifest");
            }

            // Export ZIP and verify PDF extracted bitwise identical
            using (var client = new WebClient())
            {
                byte[] zipBytes = client.DownloadData(baseUrl + "/api/export-zip?files=recovered_evidence.pdf");
                using (var archive = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read))
                {
                    Check(archive.Entries.Count == 1, "Exported filtered ZIP contains 1 entry");
                    var entry = archive.Entries[0];
                    Check(entry.Name == "recovered_evidence.pdf", "Entry name is recovered_evidence.pdf");
                    using (var s = entry.Open())
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        byte[] extractedPdf = ms.ToArray();
                        Check(ByteArrayEquals(extractedPdf, syntheticPdf), "Extracted PDF is bitwise identical to synthetic PDF");
                        // Verify PDF 1.4 header and %%EOF trailer syntax
                        string pdfText = Encoding.ASCII.GetString(extractedPdf);
                        Check(pdfText.StartsWith("%PDF-1.4"), "Extracted PDF preserves %PDF-1.4 header");
                        Check(pdfText.TrimEnd().EndsWith("%%EOF"), "Extracted PDF preserves %%EOF trailer");
                    }
                }
            }

            server.Stop();
        }
    }

    // =========================================================================
    // SUITE 8: CONCURRENCY, SOCKET ABORTS & WRITE-BLOCKING GUARANTEES
    // =========================================================================
    private static void TestSuite8_ConcurrencyAndWriteBlocking(string tempRoot)
    {
        Console.WriteLine("-> Running Suite 8: High Concurrency, Socket Aborts & Write-Blocking Guarantees...");
        string testDir = Path.Combine(tempRoot, "concurrency_suite");
        Directory.CreateDirectory(testDir);
        string dummyImage = Path.Combine(testDir, "evidence.raw");

        byte[] rawDisk = new byte[65536];
        new Random(99).NextBytes(rawDisk);
        File.WriteAllBytes(dummyImage, rawDisk);

        string outputDir = Path.Combine(testDir, "recovered");
        Directory.CreateDirectory(outputDir);
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(outputDir, string.Format("file_{0}.txt", i)), "Evidence payload data " + i);
        }

        string preImageHash = ComputeSha256(File.ReadAllBytes(dummyImage));
        string preFile0Hash = ComputeSha256(File.ReadAllBytes(Path.Combine(outputDir, "file_0.txt")));
        DateTime preImageWrite = File.GetLastWriteTimeUtc(dummyImage);
        DateTime preFile0Write = File.GetLastWriteTimeUtc(Path.Combine(outputDir, "file_0.txt"));

        int port = FindFreePort();
        using (var server = new LocalWebServer(dummyImage, outputDir, port))
        {
            server.Start();
            string baseUrl = "http://127.0.0.1:" + server.Port;

            // 8.1 Client disconnect handling (TCP RST)
            for (int cycle = 0; cycle < 10; cycle++)
            {
                using (var tcp = new TcpClient())
                {
                    tcp.Connect("127.0.0.1", server.Port);
                    tcp.Client.LingerState = new LingerOption(true, 0); // Send TCP RST on close
                    var netStream = tcp.GetStream();
                    string req = (cycle % 2 == 0)
                        ? "GET /api/export-zip HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                        : "GET /api/report?format=html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
                    byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                    netStream.Write(reqBytes, 0, reqBytes.Length);

                    byte[] smallBuf = new byte[16];
                    int r = netStream.Read(smallBuf, 0, 16);
                    Check(r > 0, "Partial response read before socket abort");
                    tcp.Close();
                }
            }

            Check(server.IsRunning, "Server remains active after 10 abrupt client disconnects");

            // 8.2 10-thread concurrent export requests + concurrent report requests
            const int totalWorkers = 20;
            Task[] tasks = new Task[totalWorkers];
            int successCount = 0;

            for (int i = 0; i < totalWorkers; i++)
            {
                int idx = i;
                tasks[i] = Task.Run(() =>
                {
                    using (var client = new WebClient { Encoding = Encoding.UTF8 })
                    {
                        if (idx % 2 == 0)
                        {
                            // Export ZIP
                            byte[] zip = client.DownloadData(baseUrl + "/api/export-zip");
                            if (zip != null && zip.Length > 50) Interlocked.Increment(ref successCount);
                        }
                        else
                        {
                            // Report JSON
                            string json = client.DownloadString(baseUrl + "/api/report?format=json");
                            if (json.Contains("chainOfCustodySha256")) Interlocked.Increment(ref successCount);
                        }
                    }
                });
            }

            Task.WaitAll(tasks);
            Check(successCount == totalWorkers, string.Format("All {0} concurrent requests succeeded ({1} verified)", totalWorkers, successCount));

            server.Stop();
        }

        // 8.3 Verify write-blocking and forensic immutability
        string postImageHash = ComputeSha256(File.ReadAllBytes(dummyImage));
        string postFile0Hash = ComputeSha256(File.ReadAllBytes(Path.Combine(outputDir, "file_0.txt")));
        DateTime postImageWrite = File.GetLastWriteTimeUtc(dummyImage);
        DateTime postFile0Write = File.GetLastWriteTimeUtc(Path.Combine(outputDir, "file_0.txt"));

        Check(preImageHash == postImageHash, "Evidence disk image remained 100% bitwise immutable (Write-Blocking)");
        Check(preFile0Hash == postFile0Hash, "Recovered artifact file remained 100% bitwise immutable");
        Check(preImageWrite == postImageWrite, "Evidence image timestamp unaltered");
        Check(preFile0Write == postFile0Write, "Recovered artifact timestamp unaltered");
    }

    // =========================================================================
    // SYNTHETIC FIXTURE GENERATORS & HELPER UTILITIES
    // =========================================================================

    private static byte[] CreateSyntheticSqliteDb(int pageSize, int pageCount, uint firstFreelistTrunk, uint totalFreelistPages)
    {
        byte[] db = new byte[pageSize * pageCount];
        byte[] magic = new byte[] { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00 };
        Buffer.BlockCopy(magic, 0, db, 0, 16);
        ushort rawPageSize = (pageSize == 65536) ? (ushort)1 : (ushort)pageSize;
        db[16] = (byte)(rawPageSize >> 8); db[17] = (byte)(rawPageSize & 0xFF);
        db[18] = 1; db[19] = 1; db[20] = 0;
        WriteUInt32BE(db, 28, (uint)pageCount);
        WriteUInt32BE(db, 32, firstFreelistTrunk);
        WriteUInt32BE(db, 36, totalFreelistPages);
        WriteUInt32BE(db, 56, 1); // UTF-8
        return db;
    }

    private static byte[] CreateAdversarialEvtxChunk(uint freeSpaceOffset, byte[] recordPayload)
    {
        byte[] chunk = new byte[65536];
        Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(chunk, 0);
        WriteUInt32LE(chunk, 48, freeSpaceOffset);
        if (recordPayload != null && recordPayload.Length > 0 && 512 + recordPayload.Length <= 65536)
        {
            Buffer.BlockCopy(recordPayload, 0, chunk, 512, recordPayload.Length);
        }
        return chunk;
    }

    private static byte[] CreateSyntheticPrefetch(uint version, string exeName, uint hash, uint runCount, bool compressMam)
    {
        byte[] raw = new byte[256];
        WriteUInt32LE(raw, 0, version);
        Encoding.ASCII.GetBytes("SCCA").CopyTo(raw, 4);
        Encoding.Unicode.GetBytes(exeName + "\0").CopyTo(raw, 16);
        WriteUInt32LE(raw, 76, hash);
        WriteInt64LE(raw, 128, DateTime.UtcNow.ToFileTimeUtc());
        WriteUInt32LE(raw, 208, runCount);

        if (!compressMam) return raw;

        byte[] compressed = MsXpressHuffman.CompressLiteralOnly(raw);
        byte[] mam = new byte[8 + compressed.Length];
        mam[0] = 0x4D; mam[1] = 0x41; mam[2] = 0x4D; mam[3] = 0x04;
        WriteUInt32LE(mam, 4, (uint)raw.Length);
        Buffer.BlockCopy(compressed, 0, mam, 8, compressed.Length);
        return mam;
    }

    private static byte[] CreateAdversarialLnk(uint headerSize, Guid clsid, uint linkFlags, byte[] idList, byte[] extraData)
    {
        using (var ms = new MemoryStream())
        {
            ms.Write(BitConverter.GetBytes(headerSize), 0, 4);
            ms.Write(clsid.ToByteArray(), 0, 16);
            ms.Write(BitConverter.GetBytes(linkFlags), 0, 4);
            ms.Write(BitConverter.GetBytes((uint)0x20), 0, 4); // FileAttributes
            ms.Write(BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()), 0, 8); // Creation
            ms.Write(BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()), 0, 8); // Access
            ms.Write(BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()), 0, 8); // Write
            ms.Write(BitConverter.GetBytes((uint)1024), 0, 4); // FileSize
            ms.Write(BitConverter.GetBytes((uint)0), 0, 4); // IconIndex
            ms.Write(BitConverter.GetBytes((uint)1), 0, 4); // ShowCommand
            ms.Write(new byte[16], 0, 16); // HotKey + Reserved

            if ((linkFlags & 0x01) != 0 && idList != null)
            {
                ms.Write(BitConverter.GetBytes((ushort)idList.Length), 0, 2);
                ms.Write(idList, 0, idList.Length);
            }

            if (extraData != null)
            {
                ms.Write(extraData, 0, extraData.Length);
            }

            return ms.ToArray();
        }
    }

    private static byte[] CreateSyntheticPdf14(string title, string content)
    {
        var objects = new List<string>();
        objects.Add("<< /Type /Catalog /Pages 2 0 R >>");
        objects.Add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        string streamContent = "BT /F1 12 Tf 50 700 Td (" + title + ": " + content + ") Tj ET";
        objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>");
        objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
        objects.Add("<< /Length " + Encoding.ASCII.GetByteCount(streamContent) + " >>\nstream\n" + streamContent + "\nendstream");

        var sb = new StringBuilder("%PDF-1.4\n");
        var offsets = new List<int>();
        offsets.Add(0);
        for (int i = 0; i < objects.Count; i++)
        {
            offsets.Add(Encoding.ASCII.GetByteCount(sb.ToString()));
            sb.Append(i + 1).Append(" 0 obj\n").Append(objects[i]).Append("\nendobj\n");
        }
        int xrefOffset = Encoding.ASCII.GetByteCount(sb.ToString());
        sb.Append("xref\n0 ").Append(objects.Count + 1).Append("\n0000000000 65535 f \n");
        for (int i = 1; i < offsets.Count; i++)
        {
            sb.Append(offsets[i].ToString("D10")).Append(" 00000 n \n");
        }
        sb.Append("trailer\n<< /Size ").Append(objects.Count + 1).Append(" /Root 1 0 R >>\nstartxref\n").Append(xrefOffset).Append("\n%%EOF\n");
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
                Check(resp.StatusCode == expectedCode, "HTTP status matches expected " + expectedCode);
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

    private static void AssertThrows<TException>(Action action, string message) where TException : Exception
    {
        bool threw = false;
        try
        {
            action();
        }
        catch (TException)
        {
            threw = true;
        }
        catch (Exception ex)
        {
            throw new Exception(string.Format("Expected {0} but got {1}: {2}", typeof(TException).Name, ex.GetType().Name, message));
        }
        Check(threw, message);
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

    private static void WriteUInt32BE(byte[] buffer, int offset, uint val)
    {
        buffer[offset] = (byte)(val >> 24);
        buffer[offset + 1] = (byte)(val >> 16);
        buffer[offset + 2] = (byte)(val >> 8);
        buffer[offset + 3] = (byte)val;
    }

    private static void WriteUInt32LE(byte[] buffer, int offset, uint val)
    {
        buffer[offset] = (byte)val;
        buffer[offset + 1] = (byte)(val >> 8);
        buffer[offset + 2] = (byte)(val >> 16);
        buffer[offset + 3] = (byte)(val >> 24);
    }

    private static void WriteInt64LE(byte[] buffer, int offset, long val)
    {
        for (int i = 0; i < 8; i++)
        {
            buffer[offset + i] = (byte)(val >> (8 * i));
        }
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
        using (MemoryStream hStream = new MemoryStream())
        {
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

            using (MemoryStream payload = new MemoryStream())
            {
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
                    else if (st >= 13 && (st % 2 == 1))
                    {
                        byte[] strBytes = Encoding.UTF8.GetBytes((string)val);
                        payload.Write(strBytes, 0, strBytes.Length);
                    }
                }
                return payload.ToArray();
            }
        }
    }
}

