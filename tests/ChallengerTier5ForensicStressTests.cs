using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UsbRecovery;

public static class ChallengerTier5ForensicStressTests
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        Interlocked.Increment(ref checks);
        if (!condition)
        {
            throw new Exception("Adversarial challenger check failed: " + message);
        }
    }

    private static void AssertThrows<TException>(Action action, string message) where TException : Exception
    {
        Interlocked.Increment(ref checks);
        try
        {
            action();
            throw new Exception("Expected " + typeof(TException).Name + " was not thrown: " + message);
        }
        catch (TException)
        {
            // Expected
        }
        catch (Exception ex)
        {
            if (ex.Message.StartsWith("Expected ")) throw;
            throw new Exception("Expected " + typeof(TException).Name + " but got " + ex.GetType().Name + ": " + message, ex);
        }
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("=========================================================================");
        Console.WriteLine("STARTING CHALLENGER TIER-5 INDEPENDENT FORENSIC STRESS TEST HARNESS");
        Console.WriteLine("Target Parsers: SqliteCarver, EvtxParser, PrefetchParser, LnkParser, BrowserHistoryParser");
        Console.WriteLine("Scope: Exhaustive boundary conditions, malformed tokens, cycle defense, write-blocking");
        Console.WriteLine("=========================================================================");

        string tempRoot = Path.Combine(Path.GetTempPath(), "challenger_m2_stress_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        try
        {
            Suite1_SqliteCarverAdversarial(tempRoot);
            Suite2_EvtxParserAdversarial(tempRoot);
            Suite3_PrefetchParserAdversarial(tempRoot);
            Suite4_LnkParserAdversarial(tempRoot);
            Suite5_BrowserHistoryAdversarial(tempRoot);
            Suite6_ConcurrentForensicStress(tempRoot);

            Console.WriteLine("=========================================================================");
            Console.WriteLine("PASS ChallengerTier5ForensicStress: {0} checks passed with 0 errors.", checks);
            Console.WriteLine("CHALLENGER TIER-5 FORENSIC STRESS COMPLETE: ALL CHECKS PASSED EMPIRICALLY.");
            Console.WriteLine("=========================================================================");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL ChallengerTier5ForensicStress: {0}\n{1}", ex.Message, ex.StackTrace);
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
    // SUITE 1: SQLITE CARVER DEEP ADVERSARIAL & FREELIST/FREEBLOCK ATTACKS
    // =========================================================================
    private static void Suite1_SqliteCarverAdversarial(string tempRoot)
    {
        Console.WriteLine("-> Executing Suite 1: SqliteCarver Adversarial Stress & Cycle Traps...");

        // 1.1 Null and truncated stream boundary checks
        AssertThrows<ArgumentNullException>(() => SqliteCarver.CarveDatabase((Stream)null), "Null stream throws ArgumentNullException");
        AssertThrows<ArgumentNullException>(() => SqliteCarver.CarveDatabase((string)null), "Null path throws ArgumentNullException");
        AssertThrows<FileNotFoundException>(() => SqliteCarver.CarveDatabase(Path.Combine(tempRoot, "nonexistent.db")), "Missing file throws FileNotFoundException");

        int[] truncatedSizes = new int[] { 0, 1, 15, 16, 50, 99, 100, 255, 511 };
        foreach (int sz in truncatedSizes)
        {
            byte[] buf = new byte[sz];
            using (var ms = new MemoryStream(buf))
            {
                var records = SqliteCarver.CarveDatabase(ms);
                Check(records != null && records.Count == 0, string.Format("Truncated {0}-byte database returns empty list", sz));
            }
        }

        // 1.2 Database header boundary values
        SqliteDatabaseHeader dbHdr;
        // Correct magic but truncated
        byte[] magicOnly = Encoding.ASCII.GetBytes("SQLite format 3\0");
        Check(!SqliteCarver.TryParseHeader(magicOnly, out dbHdr), "16-byte magic-only buffer rejected by TryParseHeader");

        // Non-power-of-2 page size values
        int[] invalidPageSizes = new int[] { 0, 255, 500, 513, 1000, 3000, 70000 };
        foreach (int ps in invalidPageSizes)
        {
            byte[] hBuf = new byte[100];
            Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(hBuf, 0);
            hBuf[16] = (byte)((ps >> 8) & 0xFF);
            hBuf[17] = (byte)(ps & 0xFF);
            Check(!SqliteCarver.TryParseHeader(hBuf, out dbHdr), string.Format("Invalid page size {0} rejected", ps));
        }

        // Valid page sizes: 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 (stored as 1)
        int[] validPageSizes = new int[] { 512, 1024, 2048, 4096, 8192, 16384, 32768 };
        foreach (int ps in validPageSizes)
        {
            byte[] hBuf = new byte[100];
            Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(hBuf, 0);
            hBuf[16] = (byte)((ps >> 8) & 0xFF);
            hBuf[17] = (byte)(ps & 0xFF);
            Check(SqliteCarver.TryParseHeader(hBuf, out dbHdr) && dbHdr.PageSize == ps, string.Format("Valid page size {0} accepted", ps));
        }

        // Page size 65536 stored as 0x0001
        byte[] h64k = new byte[100];
        Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(h64k, 0);
        h64k[16] = 0x00; h64k[17] = 0x01;
        Check(SqliteCarver.TryParseHeader(h64k, out dbHdr) && dbHdr.PageSize == 65536, "Page size 65536 (0x0001) parsed accurately");

        // 1.3 Freelist Trunk Complex Ring Cycle: 10 Trunks (1 -> 2 -> ... -> 10 -> 1)
        int pageSize = 512;
        int numTrunkPages = 10;
        byte[] ringDb = CreateSyntheticDb(pageSize, numTrunkPages + 1, 2, (uint)numTrunkPages);
        for (int t = 1; t <= numTrunkPages; t++)
        {
            int pageIdx = t + 1; // trunk 1 is page 2, trunk 2 is page 3, etc.
            int offset = (pageIdx - 1) * pageSize;
            uint nextTrunk = (t < numTrunkPages) ? (uint)(pageIdx + 1) : 2; // last trunk points back to page 2 (cycle)
            WriteUInt32BE(ringDb, offset, nextTrunk);
            WriteUInt32BE(ringDb, offset + 4, 1); // 1 leaf
            WriteUInt32BE(ringDb, offset + 8, 1); // leaf points to page 1
        }

        using (var ms = new MemoryStream(ringDb))
        {
            DateTime ringStart = DateTime.UtcNow;
            var records = SqliteCarver.CarveDatabase(ms);
            Check((DateTime.UtcNow - ringStart).TotalSeconds < 2.0, "10-trunk circular ring terminates promptly via visitedTrunks guard");
            Check(records != null, "Circular freelist ring returns valid results");
        }

        // 1.4 Freeblock Multi-Node Ring Cycle: 10 freeblocks forming a loop
        byte[] fbPage = new byte[pageSize];
        fbPage[0] = 0x0D; // Leaf Table
        fbPage[1] = 0x00; fbPage[2] = 20; // First freeblock at offset 20
        fbPage[3] = 0x00; fbPage[4] = 0;  // 0 cells
        fbPage[5] = 0x01; fbPage[6] = 0xF4; // cellContentAreaStart = 500

        // Create 10 freeblocks at offsets 20, 40, 60, ... 200
        for (int i = 0; i < 10; i++)
        {
            int curFb = 20 + i * 20;
            int nxtFb = (i < 9) ? (curFb + 20) : 20; // loop back to 20
            fbPage[curFb] = (byte)((nxtFb >> 8) & 0xFF);
            fbPage[curFb + 1] = (byte)(nxtFb & 0xFF);
            fbPage[curFb + 2] = 0x00;
            fbPage[curFb + 3] = 16; // size 16
        }

        DateTime fbRingStart = DateTime.UtcNow;
        var carvedRingFb = SqliteCarver.CarvePage(fbPage, 2, 512);
        Check((DateTime.UtcNow - fbRingStart).TotalSeconds < 2.0, "10-node freeblock ring cycle terminates promptly via visitedFb guard");

        // 1.5 Fuzzing B-tree page parser with 50 randomized corrupted pages
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++)
        {
            byte[] fuzzedPage = new byte[pageSize];
            rng.NextBytes(fuzzedPage);
            // Even with total random garbage, CarvePage must never throw an unhandled exception
            var fuzzedRecords = SqliteCarver.CarvePage(fuzzedPage, (uint)(i + 1), (long)i * pageSize);
            Check(fuzzedRecords != null, "Randomly fuzzed B-tree page handled without exception");
        }

        // 1.6 Forensic Write-Blocking Immutability Check
        byte[] immutableDb = (byte[])ringDb.Clone();
        string shaBefore = ComputeSha256(immutableDb);
        using (var ms = new MemoryStream(immutableDb))
        {
            SqliteCarver.CarveDatabase(ms);
        }
        string shaAfter = ComputeSha256(immutableDb);
        Check(shaBefore == shaAfter, "SqliteCarver guaranteed 100% forensic write-blocking immutability");
    }

    // =========================================================================
    // SUITE 2: EVTX PARSER ADVERSARIAL STRESS & CORRUPTED BINXML CHUNKS
    // =========================================================================
    private static void Suite2_EvtxParserAdversarial(string tempRoot)
    {
        Console.WriteLine("-> Executing Suite 2: EvtxParser BinXml Adversarial Tokens & Chunk Corruption...");

        // 2.1 Truncated EVTX stream checks
        int[] evtxTruncSizes = new int[] { 0, 1, 100, 511, 512, 1024, 4095, 4096, 8192, 65535 };
        foreach (int sz in evtxTruncSizes)
        {
            byte[] buf = new byte[sz];
            var recs = EvtxParser.Parse(buf);
            Check(recs != null && recs.Count == 0, string.Format("Truncated {0}-byte EVTX buffer returns 0 records safely", sz));
        }

        // 2.2 Hostile FreeSpaceOffset values in chunk header
        uint[] hostileFso = new uint[] { 0, 1, 511, 65536, 100000, 0x7FFFFFFF, 0xFFFFFFFF };
        foreach (uint fso in hostileFso)
        {
            byte[] chunk = new byte[65536];
            Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(chunk, 0);
            WriteUInt32LE(chunk, 48, fso);
            var recs = EvtxParser.Parse(chunk);
            Check(recs != null, string.Format("Chunk with FreeSpaceOffset=0x{0:X8} handled safely", fso));
        }

        // 2.3 Record size and trailing size adversarial edge cases
        // Record size = 0, size = 4, size = 27 (< 28)
        uint[] badSizes = new uint[] { 0, 4, 12, 24, 27 };
        foreach (uint bsz in badSizes)
        {
            byte[] chunk = new byte[65536];
            Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(chunk, 0);
            WriteUInt32LE(chunk, 48, 1024);
            WriteUInt32LE(chunk, 512, 0x00002A2A); // Record magic
            WriteUInt32LE(chunk, 516, bsz);
            var recs = EvtxParser.Parse(chunk);
            Check(recs.Count == 0, string.Format("Record size {0} (< 28) safely ignored", bsz));
        }

        // Trailing size mismatch
        byte[] mismatchChunk = new byte[65536];
        Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(mismatchChunk, 0);
        WriteUInt32LE(mismatchChunk, 48, 1024);
        WriteUInt32LE(mismatchChunk, 512, 0x00002A2A);
        WriteUInt32LE(mismatchChunk, 516, 64);
        WriteUInt32LE(mismatchChunk, 512 + 64 - 4, 128); // Trailing size != record size
        var recsMismatch = EvtxParser.Parse(mismatchChunk);
        Check(recsMismatch.Count == 0, "Record with mismatched trailing size ignored");

        // 2.4 BinXml deep recursion and unbalanced tag attacks
        var cache = new Dictionary<uint, BinXmlTemplate>();
        var evtxRec = new EvtxRecord();

        // 200 unbalanced OpenStartElements (0x01)
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(0x0F); ms.WriteByte(0x01); ms.WriteByte(0x01); ms.WriteByte(0x00);
            for (int i = 0; i < 200; i++)
            {
                ms.WriteByte(0x01); // OpenStartElement
                ms.Write(new byte[] { 0, 0 }, 0, 2); // depId
                byte[] name = Encoding.Unicode.GetBytes(string.Format("Node{0}\0", i));
                ms.Write(BitConverter.GetBytes((uint)name.Length), 0, 4);
                ms.Write(name, 0, name.Length);
            }
            byte[] deepXml = ms.ToArray();
            BinXmlDecoder.Decode(deepXml, 0, deepXml.Length, 0, cache, evtxRec);
            Check(evtxRec.XmlContent != null && evtxRec.XmlContent.Length > 0, "200 nested BinXml elements handled safely without stack overflow");
        }

        // 200 EndElements (0x04) with empty element stack
        evtxRec = new EvtxRecord();
        byte[] underflowBuf = new byte[205];
        underflowBuf[0] = 0x0F; underflowBuf[1] = 0x01; underflowBuf[2] = 0x01; underflowBuf[3] = 0x00;
        for (int i = 4; i < 204; i++) underflowBuf[i] = 0x04; // EndElement
        underflowBuf[204] = 0x00; // EOF
        BinXmlDecoder.Decode(underflowBuf, 0, underflowBuf.Length, 0, cache, evtxRec);
        Check(evtxRec.XmlContent != null, "200 EndElement tokens handled without stack underflow");

        // 500 unrecognized garbage tokens
        evtxRec = new EvtxRecord();
        byte[] garbageTokens = new byte[505];
        garbageTokens[0] = 0x0F; garbageTokens[1] = 0x01; garbageTokens[2] = 0x01; garbageTokens[3] = 0x00;
        for (int i = 4; i < 504; i++) garbageTokens[i] = (byte)(0x20 + (i % 200));
        garbageTokens[504] = 0x00;
        BinXmlDecoder.Decode(garbageTokens, 0, garbageTokens.Length, 0, cache, evtxRec);
        Check(evtxRec.XmlContent != null, "500 unknown BinXml tokens handled cleanly");

        // 2.5 Corrupted SID substitutions with truncated sub-authorities
        byte[] sidAttack = new byte[] {
            0x0F, 0x01, 0x01, 0x00,
            0x0C, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, // Template ID
            0x02, 0x00, 0x00, 0x00, // Template len
            0x00, 0x00,             // EOF
            0x01, 0x00, 0x00, 0x00, // Value count = 1
            0x13, 0x00,             // Type = SID (0x13)
            0x04, 0x00,             // Size = 4 bytes (< 8 bytes header)
            0x01, 0x05, 0x00, 0x00  // Truncated SID bytes
        };
        evtxRec = new EvtxRecord();
        BinXmlDecoder.Decode(sidAttack, 0, sidAttack.Length, 0, cache, evtxRec);
        Check(evtxRec != null, "Truncated SID substitution handled without IndexOutOfRangeException");

        // 2.6 Fuzzing EVTX chunks with 30 randomized byte arrays
        Random rng = new Random(42);
        for (int i = 0; i < 30; i++)
        {
            byte[] fuzzedEvtx = new byte[65536];
            rng.NextBytes(fuzzedEvtx);
            Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(fuzzedEvtx, 0);
            var fuzzedRecs = EvtxParser.Parse(fuzzedEvtx);
            Check(fuzzedRecs != null, "Randomly fuzzed EVTX chunk handled safely");
        }

        // 2.7 Forensic Write-Blocking Immutability Check
        byte[] immutableEvtx = new byte[65536];
        Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(immutableEvtx, 0);
        string shaEvtxBefore = ComputeSha256(immutableEvtx);
        EvtxParser.Parse(immutableEvtx);
        string shaEvtxAfter = ComputeSha256(immutableEvtx);
        Check(shaEvtxBefore == shaEvtxAfter, "EvtxParser guaranteed 100% forensic write-blocking immutability");
    }

    // =========================================================================
    // SUITE 3: PREFETCH PARSER & MS-XPRESS HUFFMAN ADVERSARIAL STRESS
    // =========================================================================
    private static void Suite3_PrefetchParserAdversarial(string tempRoot)
    {
        Console.WriteLine("-> Executing Suite 3: PrefetchParser MAM XPRESS Huffman & Header Attacks...");

        // 3.1 Null and truncated buffer bounds (< 84 bytes)
        AssertThrows<ArgumentNullException>(() => PrefetchParser.Parse((byte[])null), "Null buffer throws ArgumentNullException");
        AssertThrows<ArgumentNullException>(() => PrefetchParser.Parse((Stream)null), "Null stream throws ArgumentNullException");

        int[] pfTrunc = new int[] { 0, 1, 10, 50, 83 };
        foreach (int sz in pfTrunc)
        {
            AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(new byte[sz]),
                string.Format("Prefetch buffer {0} bytes (< 84) rejected with InvalidDataException", sz));
        }

        // Invalid signature at offset 4
        byte[] badSig = new byte[84];
        WriteUInt32LE(badSig, 0, 30);
        WriteUInt32LE(badSig, 4, 0x12345678); // Not SCCA (0x41434353)
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(badSig), "Invalid prefetch signature rejected");

        // 3.2 MAM compression header adversarial bounds
        // MAM size < 84
        byte[] mamTooSmall = new byte[84];
        WriteUInt32LE(mamTooSmall, 0, 0x044D414D);
        WriteUInt32LE(mamTooSmall, 4, 83);
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(mamTooSmall), "MAM size < 84 rejected");

        // MAM size > 10 MB (e.g. 50 MB)
        byte[] mamTooBig = new byte[84];
        WriteUInt32LE(mamTooBig, 0, 0x044D414D);
        WriteUInt32LE(mamTooBig, 4, 50 * 1024 * 1024);
        AssertThrows<InvalidDataException>(() => PrefetchParser.Parse(mamTooBig), "MAM size > 10MB rejected");

        // 3.3 MsXpressHuffman table sum corruption
        // Table sum != 32768
        byte[] corruptTable = new byte[300];
        // Nibbles all 0 -> sum = 0 != 32768
        AssertThrows<InvalidDataException>(() => MsXpressHuffman.Decompress(corruptTable, 0, corruptTable.Length, 1024),
            "Huffman table sum == 0 rejected with InvalidDataException");

        // Nibbles all 15 -> sum = 512 * 1 = 512 != 32768
        for (int i = 0; i < 256; i++) corruptTable[i] = 0xFF;
        AssertThrows<InvalidDataException>(() => MsXpressHuffman.Decompress(corruptTable, 0, corruptTable.Length, 1024),
            "Huffman table sum == 512 rejected with InvalidDataException");

        // Truncated Huffman block (< 256 bytes)
        byte[] shortBlock = new byte[100];
        AssertThrows<InvalidDataException>(() => MsXpressHuffman.Decompress(shortBlock, 0, shortBlock.Length, 1024),
            "Truncated Huffman block header rejected with InvalidDataException");

        // 3.4 Valid SCCA prefetch multi-version parsing & roundtrip
        int[] versions = new int[] { 17, 23, 26, 30 };
        foreach (int ver in versions)
        {
            byte[] scca = CreateAdversarialPrefetch((uint)ver, "TESTAPP.EXE", 0x11223344, 7, false);
            var artifact = PrefetchParser.Parse(scca);
            Check(artifact.Version == (uint)ver, string.Format("Prefetch version {0} parsed accurately", ver));
            Check(artifact.ExecutableName == "TESTAPP.EXE", "Executable name parsed accurately");
            Check(artifact.RunCount == 7, "Run count parsed accurately");
            Check(artifact.Hash == "11223344", "Hash parsed accurately");
        }

        // 3.5 MAM compressed prefetch decompression & parsing
        byte[] mamPrefetch = CreateAdversarialPrefetch(30, "MAMTEST.EXE", 0xDEADBEEF, 19, true);
        var mamArtifact = PrefetchParser.Parse(mamPrefetch);
        Check(mamArtifact.ExecutableName == "MAMTEST.EXE", "MAM prefetch decompressed and parsed executable name");
        Check(mamArtifact.RunCount == 19, "MAM prefetch run count parsed accurately");
        Check(mamArtifact.Hash == "DEADBEEF", "MAM prefetch hash parsed accurately");

        // 3.6 Non-null-terminated executable names (adversarial length 60 without null)
        byte[] nonTermPf = CreateAdversarialPrefetch(30, "123456789012345678901234567890", 0x99999999, 1, false);
        var nonTermArt = PrefetchParser.Parse(nonTermPf);
        Check(nonTermArt.ExecutableName.Length > 0, "Non-terminated executable name parsed without buffer overrun");

        // 3.7 Forensic Write-Blocking Immutability Check
        byte[] immutableMam = (byte[])mamPrefetch.Clone();
        string shaPfBefore = ComputeSha256(immutableMam);
        PrefetchParser.Parse(immutableMam);
        string shaPfAfter = ComputeSha256(immutableMam);
        Check(shaPfBefore == shaPfAfter, "PrefetchParser guaranteed 100% forensic write-blocking immutability");
    }

    // =========================================================================
    // SUITE 4: LNK PARSER & SHELLBAG ADVERSARIAL STRESS
    // =========================================================================
    private static void Suite4_LnkParserAdversarial(string tempRoot)
    {
        Console.WriteLine("-> Executing Suite 4: LnkParser Shell Link & Shellbag MRU Corrupt Layouts...");

        Guid validClsid = new Guid("00021401-0000-0000-c000-000000000046");

        // 4.1 Null and truncated buffer bounds (< 76 bytes)
        AssertThrows<ArgumentNullException>(() => LnkParser.Parse((byte[])null), "Null buffer throws ArgumentNullException");
        AssertThrows<ArgumentNullException>(() => LnkParser.Parse((Stream)null), "Null stream throws ArgumentNullException");

        int[] lnkTrunc = new int[] { 0, 1, 10, 50, 75 };
        foreach (int sz in lnkTrunc)
        {
            AssertThrows<InvalidDataException>(() => LnkParser.Parse(new byte[sz]),
                string.Format("LNK buffer {0} bytes (< 76) rejected with InvalidDataException", sz));
        }

        // HeaderSize != 0x4C
        byte[] badHdrSz = CreateAdversarialLnkHeader(0x50, validClsid, 0);
        AssertThrows<InvalidDataException>(() => LnkParser.Parse(badHdrSz), "HeaderSize != 0x4C rejected");

        // Invalid CLSID
        byte[] badClsid = CreateAdversarialLnkHeader(0x4C, Guid.NewGuid(), 0);
        AssertThrows<InvalidDataException>(() => LnkParser.Parse(badClsid), "Invalid CLSID rejected");

        // 4.2 Degenerate shell item size = 0 in IDList (Infinite Loop Trap)
        byte[] zeroItemPayload = new byte[] { 0x00, 0x00, 0x10, 0x00 };
        byte[] lnkLoop = CreateAdversarialLnk(0x4C, validClsid, 0x01, zeroItemPayload, null);
        DateTime loopStart = DateTime.UtcNow;
        var artLoop = LnkParser.Parse(lnkLoop);
        Check((DateTime.UtcNow - loopStart).TotalSeconds < 2.0, "Zero-size IDList item terminates immediately without infinite loop");

        // Truncated IDList item bounds
        byte[] truncItemPayload = new byte[] { 0xFF, 0x00, 0x1F, 0x00 }; // Claims 255 bytes, only 4 provided
        byte[] lnkTruncItem = CreateAdversarialLnk(0x4C, validClsid, 0x01, truncItemPayload, null);
        var artTrunc = LnkParser.Parse(lnkTruncItem);
        Check(artTrunc != null, "Truncated IDList item bounded safely");

        // 4.3 LinkInfo corrupted offsets pointing outside boundaries
        using (var ms = new MemoryStream())
        {
            ms.Write(BitConverter.GetBytes((uint)28), 0, 4);   // size = 28
            ms.Write(BitConverter.GetBytes((uint)28), 0, 4);   // header size = 28
            ms.Write(BitConverter.GetBytes((uint)1), 0, 4);    // flags = 1
            ms.Write(BitConverter.GetBytes((uint)50000), 0, 4); // volumeIdOffset (out of bounds)
            ms.Write(BitConverter.GetBytes((uint)60000), 0, 4); // localBasePathOffset (out of bounds)
            ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
            ms.Write(BitConverter.GetBytes((uint)0), 0, 4);
            byte[] badLinkInfo = ms.ToArray();

            byte[] lnkBase = CreateAdversarialLnk(0x4C, validClsid, 0x02, null, null);
            byte[] combined = new byte[lnkBase.Length + badLinkInfo.Length];
            Buffer.BlockCopy(lnkBase, 0, combined, 0, lnkBase.Length);
            Buffer.BlockCopy(badLinkInfo, 0, combined, lnkBase.Length, badLinkInfo.Length);

            var artBadInfo = LnkParser.Parse(combined);
            Check(artBadInfo != null, "LinkInfo with out-of-bounds offsets parsed safely without crash");
        }

        // 4.4 ExtraData blocks with size < 4 (Infinite Loop Trap)
        byte[] zeroExtraData = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        byte[] lnkExtraLoop = CreateAdversarialLnk(0x4C, validClsid, 0, null, zeroExtraData);
        DateTime exStart = DateTime.UtcNow;
        var artExtra = LnkParser.Parse(lnkExtraLoop);
        Check((DateTime.UtcNow - exStart).TotalSeconds < 2.0, "ExtraData block size < 4 terminates immediately without loop");

        // 4.5 Shellbag MRUListEx edge cases
        // Empty MRUListEx
        Check(LnkParser.ParseShellbags(new byte[0], new Dictionary<int, byte[]>()).Count == 0, "0-byte MRUListEx returns 0 shellbags");

        // Null dictionaries
        Check(LnkParser.ParseShellbags(null, null).Count == 0, "Null MRUListEx arguments return empty list");

        // MRU list referencing missing slot IDs and negative slots
        byte[] mruAdversarial = new byte[] {
            0, 0, 0, 0,                  // Slot 0 (exists)
            99, 0, 0, 0,                 // Slot 99 (missing)
            0xFF, 0xFF, 0xFF, 0x7F,      // Slot 2147483647 (missing)
            0xFF, 0xFF, 0xFF, 0xFF       // Terminator
        };
        var slots = new Dictionary<int, byte[]>();
        slots[0] = new byte[] { 0x14, 0x00, 0x31, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)'X', 0, 0, 0, 0, 0 };
        var bags = LnkParser.ParseShellbags(mruAdversarial, slots);
        Check(bags != null && bags.Count == 1, "Shellbag parser recovers available slot and skips missing/extreme slot IDs");

        // 4.6 Forensic Write-Blocking Immutability Check
        byte[] immutableLnk = (byte[])lnkLoop.Clone();
        string shaLnkBefore = ComputeSha256(immutableLnk);
        LnkParser.Parse(immutableLnk);
        string shaLnkAfter = ComputeSha256(immutableLnk);
        Check(shaLnkBefore == shaLnkAfter, "LnkParser guaranteed 100% forensic write-blocking immutability");
    }

    // =========================================================================
    // SUITE 5: BROWSER HISTORY PARSER TIMESTAMP CLAMPING & CACHE CORRUPTION
    // =========================================================================
    private static void Suite5_BrowserHistoryAdversarial(string tempRoot)
    {
        Console.WriteLine("-> Executing Suite 5: BrowserHistoryParser Timestamp Clamping & Cache Attacks...");

        // 5.1 WebKit timestamp extreme boundaries and clamping
        long[] webKitNegatives = new long[] { -1000000000000L, -1L, 0L };
        foreach (long val in webKitNegatives)
        {
            Check(BrowserTimestampConverter.WebKitTimeToUtc(val) == DateTime.MinValue,
                string.Format("WebKit timestamp {0} clamped to DateTime.MinValue", val));
        }

        // Safe normal WebKit timestamp (1970-01-01)
        DateTime wk1970 = BrowserTimestampConverter.WebKitTimeToUtc(11644473600000000L);
        Check(wk1970.Year == 1970 && wk1970.Month == 1 && wk1970.Day == 1, "WebKit 1970 timestamp decoded accurately");

        // Maximum safe WebKit boundary: 265046774399999999L
        DateTime maxSafeWk = BrowserTimestampConverter.WebKitTimeToUtc(265046774399999999L);
        Check(maxSafeWk.Year == 9999, "Max safe WebKit timestamp decoded to year 9999");

        // Extreme values above safe maximum
        long[] webKitOverflows = new long[] { 265046774400000000L, 500000000000000000L, long.MaxValue };
        foreach (long val in webKitOverflows)
        {
            Check(BrowserTimestampConverter.WebKitTimeToUtc(val) == DateTime.MaxValue,
                string.Format("WebKit extreme timestamp {0} clamped to DateTime.MaxValue", val));
        }

        // 5.2 Mozilla PRTime extreme boundaries and clamping
        long[] prNegatives = new long[] { -1000000000000L, -1L, 0L };
        foreach (long val in prNegatives)
        {
            Check(BrowserTimestampConverter.PrTimeToUtc(val) == DateTime.MinValue,
                string.Format("PRTime timestamp {0} clamped to DateTime.MinValue", val));
        }

        // Safe normal PRTime timestamp (2000-01-01)
        DateTime pr2000 = BrowserTimestampConverter.PrTimeToUtc(946684800000000L);
        Check(pr2000.Year == 2000 && pr2000.Month == 1 && pr2000.Day == 1, "PRTime 2000 timestamp decoded accurately");

        // Extreme values above safe maximum: 253402300799999999L
        long[] prOverflows = new long[] { 253402300800000000L, 500000000000000000L, long.MaxValue };
        foreach (long val in prOverflows)
        {
            Check(BrowserTimestampConverter.PrTimeToUtc(val) == DateTime.MaxValue,
                string.Format("PRTime extreme timestamp {0} clamped to DateTime.MaxValue", val));
        }

        // 5.3 Chromium Simple Cache adversarial corruptions
        // Stream < 24 bytes
        using (var ms = new MemoryStream(new byte[15]))
        {
            Check(BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy") == null, "Simple cache stream < 24B returns null");
        }

        // Invalid magic
        byte[] badSimpleMagic = new byte[64];
        BitConverter.GetBytes(0xDEADBEEFCAFEBABEUL).CopyTo(badSimpleMagic, 0);
        using (var ms = new MemoryStream(badSimpleMagic))
        {
            Check(BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy") == null, "Invalid Simple Cache magic returns null");
        }

        // Key length overflow
        byte[] keyOverflow = new byte[64];
        BitConverter.GetBytes(0xfcfb6d0543706173UL).CopyTo(keyOverflow, 0); // Magic
        BitConverter.GetBytes((uint)1).CopyTo(keyOverflow, 8);               // Version
        BitConverter.GetBytes((uint)65535).CopyTo(keyOverflow, 12);          // KeyLength > buffer
        using (var ms = new MemoryStream(keyOverflow))
        {
            Check(BrowserHistoryParser.ParseChromiumSimpleCache(ms, "dummy") == null, "Simple Cache keyLength overflow returns null");
        }

        // Valid Simple Cache entry with HTTP headers
        byte[] validSimple = CreateSyntheticChromiumCache("https://example.com/test.html", 200, "OK", "text/html");
        using (var ms = new MemoryStream(validSimple))
        {
            var cacheRec = BrowserHistoryParser.ParseChromiumSimpleCache(ms, "synthetic.cache");
            Check(cacheRec != null, "Valid Simple Cache entry parsed");
            Check(cacheRec.KeyUrl == "https://example.com/test.html", "KeyUrl parsed accurately");
            Check(cacheRec.HttpStatusCode == 200, "HTTP Status Code 200 parsed accurately");
            Check(cacheRec.HttpStatusText == "OK", "HTTP Status Text OK parsed accurately");
            Check(cacheRec.ContentType == "text/html", "Content-Type parsed accurately");
        }

        // 5.4 Firefox Cache2 adversarial corruptions
        // Stream < 24 bytes
        using (var ms = new MemoryStream(new byte[15]))
        {
            Check(BrowserHistoryParser.ParseFirefoxCache2(ms, "dummy") == null, "Firefox Cache2 stream < 24B returns null");
        }

        // MetaDataSize overflow
        byte[] badFfMeta = new byte[64];
        badFfMeta[60] = 0x00; badFfMeta[61] = 0x00; badFfMeta[62] = 0x08; badFfMeta[63] = 0x00; // 2048 > 64
        using (var ms = new MemoryStream(badFfMeta))
        {
            Check(BrowserHistoryParser.ParseFirefoxCache2(ms, "dummy") == null, "Firefox Cache2 metaDataSize overflow returns null");
        }

        // Valid Firefox Cache2 entry
        byte[] validFf = CreateSyntheticFirefoxCache2("https://mozilla.org/privacy", 10, 1600000000, 1700000000);
        using (var ms = new MemoryStream(validFf))
        {
            var ffCache = BrowserHistoryParser.ParseFirefoxCache2(ms, "ff.cache");
            Check(ffCache != null, "Valid Firefox Cache2 entry parsed");
            Check(ffCache.KeyUrl == "https://mozilla.org/privacy", "Firefox Cache2 KeyUrl parsed accurately");
            Check(ffCache.FetchCount == 10, "Firefox Cache2 FetchCount parsed accurately");
        }

        // 5.5 Forensic Write-Blocking Immutability Check
        byte[] immutableCache = (byte[])validSimple.Clone();
        string shaCacheBefore = ComputeSha256(immutableCache);
        using (var ms = new MemoryStream(immutableCache))
        {
            BrowserHistoryParser.ParseChromiumSimpleCache(ms, "test");
        }
        string shaCacheAfter = ComputeSha256(immutableCache);
        Check(shaCacheBefore == shaCacheAfter, "BrowserHistoryParser guaranteed 100% forensic write-blocking immutability");
    }

    // =========================================================================
    // SUITE 6: CONCURRENT FORENSIC STRESS & UNIVERSAL WRITE-BLOCKING
    // =========================================================================
    private static void Suite6_ConcurrentForensicStress(string tempRoot)
    {
        Console.WriteLine("-> Executing Suite 6: Multi-Threaded Concurrent Adversarial Stress & Write-Blocking...");

        // Generate synthetic evidence files
        string sqlitePath = Path.Combine(tempRoot, "evidence.db");
        string evtxPath = Path.Combine(tempRoot, "evidence.evtx");
        string pfPath = Path.Combine(tempRoot, "evidence.pf");
        string lnkPath = Path.Combine(tempRoot, "evidence.lnk");

        byte[] dbBytes = CreateSyntheticDb(512, 16, 0, 0);
        File.WriteAllBytes(sqlitePath, dbBytes);

        byte[] evtxBytes = new byte[65536];
        Encoding.ASCII.GetBytes("ElfChnk\0").CopyTo(evtxBytes, 0);
        File.WriteAllBytes(evtxPath, evtxBytes);

        byte[] pfBytes = CreateAdversarialPrefetch(30, "CMD.EXE", 0x12345678, 5, false);
        File.WriteAllBytes(pfPath, pfBytes);

        byte[] lnkBytes = CreateAdversarialLnk(0x4C, new Guid("00021401-0000-0000-c000-000000000046"), 0, null, null);
        File.WriteAllBytes(lnkPath, lnkBytes);

        // Compute pre-concurrency SHA-256 hashes and LastWriteTime
        string dbShaBefore = ComputeFileSha256(sqlitePath);
        string evtxShaBefore = ComputeFileSha256(evtxPath);
        string pfShaBefore = ComputeFileSha256(pfPath);
        string lnkShaBefore = ComputeFileSha256(lnkPath);

        DateTime dbTimeBefore = File.GetLastWriteTimeUtc(sqlitePath);
        DateTime evtxTimeBefore = File.GetLastWriteTimeUtc(evtxPath);
        DateTime pfTimeBefore = File.GetLastWriteTimeUtc(pfPath);
        DateTime lnkTimeBefore = File.GetLastWriteTimeUtc(lnkPath);

        // Launch 20 concurrent threads randomly reading and parsing evidence
        int threadCount = 20;
        int iterationsPerThread = 15;
        int errorCount = 0;
        List<Thread> threads = new List<Thread>();

        for (int t = 0; t < threadCount; t++)
        {
            int threadId = t;
            Thread th = new Thread(() =>
            {
                try
                {
                    for (int iter = 0; iter < iterationsPerThread; iter++)
                    {
                        switch (threadId % 4)
                        {
                            case 0:
                                var r1 = SqliteCarver.CarveDatabase(sqlitePath);
                                if (r1 == null) Interlocked.Increment(ref errorCount);
                                break;
                            case 1:
                                var r2 = EvtxParser.ParseFile(evtxPath);
                                if (r2 == null) Interlocked.Increment(ref errorCount);
                                break;
                            case 2:
                                var r3 = PrefetchParser.ParseFile(pfPath);
                                if (r3 == null) Interlocked.Increment(ref errorCount);
                                break;
                            case 3:
                                var r4 = LnkParser.ParseFile(lnkPath);
                                if (r4 == null) Interlocked.Increment(ref errorCount);
                                break;
                        }
                    }
                }
                catch
                {
                    Interlocked.Increment(ref errorCount);
                }
            });
            threads.Add(th);
            th.Start();
        }

        foreach (var th in threads)
        {
            th.Join();
        }

        Check(errorCount == 0, string.Format("20 concurrent threads completed {0} operations with 0 errors", threadCount * iterationsPerThread));

        // Verify post-concurrency SHA-256 hashes and timestamps (Write-Blocking Verification)
        Check(ComputeFileSha256(sqlitePath) == dbShaBefore, "SQLite evidence file unmodified after 20-thread concurrency");
        Check(ComputeFileSha256(evtxPath) == evtxShaBefore, "EVTX evidence file unmodified after 20-thread concurrency");
        Check(ComputeFileSha256(pfPath) == pfShaBefore, "Prefetch evidence file unmodified after 20-thread concurrency");
        Check(ComputeFileSha256(lnkPath) == lnkShaBefore, "LNK evidence file unmodified after 20-thread concurrency");

        Check(File.GetLastWriteTimeUtc(sqlitePath) == dbTimeBefore, "SQLite LastWriteTime unmodified");
        Check(File.GetLastWriteTimeUtc(evtxPath) == evtxTimeBefore, "EVTX LastWriteTime unmodified");
        Check(File.GetLastWriteTimeUtc(pfPath) == pfTimeBefore, "Prefetch LastWriteTime unmodified");
        Check(File.GetLastWriteTimeUtc(lnkPath) == lnkTimeBefore, "LNK LastWriteTime unmodified");
    }

    // =========================================================================
    // HELPER GENERATORS
    // =========================================================================
    private static byte[] CreateSyntheticDb(int pageSize, int pageCount, uint firstTrunk, uint totalFreelist)
    {
        byte[] db = new byte[pageSize * pageCount];
        Encoding.ASCII.GetBytes("SQLite format 3\0").CopyTo(db, 0);
        db[16] = (byte)((pageSize >> 8) & 0xFF);
        db[17] = (byte)(pageSize & 0xFF);
        db[18] = 1; db[19] = 1; db[20] = 0;
        WriteUInt32BE(db, 28, (uint)pageCount);
        WriteUInt32BE(db, 32, firstTrunk);
        WriteUInt32BE(db, 36, totalFreelist);
        return db;
    }

    private static byte[] CreateAdversarialPrefetch(uint version, string exeName, uint hash, uint runCount, bool compressMam)
    {
        byte[] scca = new byte[256];
        WriteUInt32LE(scca, 0, version);
        WriteUInt32LE(scca, 4, 0x41434353); // "SCCA"
        Encoding.Unicode.GetBytes(exeName).CopyTo(scca, 16);
        WriteUInt32LE(scca, 76, hash);

        // Sections
        WriteUInt32LE(scca, 84 + 16, 0); // secCOffset
        WriteUInt32LE(scca, 84 + 20, 0); // secCSize
        WriteUInt32LE(scca, 84 + 24, 0); // secDOffset
        WriteUInt32LE(scca, 84 + 28, 0); // secDCount
        WriteUInt32LE(scca, 84 + 32, 0); // secDSize

        if (version == 17)
        {
            WriteUInt32LE(scca, 144, runCount);
        }
        else if (version == 23)
        {
            WriteUInt32LE(scca, 152, runCount);
        }
        else
        {
            WriteUInt32LE(scca, 208, runCount);
        }

        if (!compressMam) return scca;

        byte[] compressed = MsXpressHuffman.CompressLiteralOnly(scca);
        byte[] mam = new byte[8 + compressed.Length];
        WriteUInt32LE(mam, 0, 0x044D414D);
        WriteUInt32LE(mam, 4, (uint)scca.Length);
        Buffer.BlockCopy(compressed, 0, mam, 8, compressed.Length);
        return mam;
    }

    private static byte[] CreateAdversarialLnkHeader(uint headerSize, Guid clsid, uint flags)
    {
        byte[] buf = new byte[76];
        WriteUInt32LE(buf, 0, headerSize);
        clsid.ToByteArray().CopyTo(buf, 4);
        WriteUInt32LE(buf, 20, flags);
        return buf;
    }

    private static byte[] CreateAdversarialLnk(uint headerSize, Guid clsid, uint flags, byte[] idList, byte[] extraData)
    {
        using (var ms = new MemoryStream())
        {
            ms.Write(CreateAdversarialLnkHeader(headerSize, clsid, flags), 0, 76);
            if (idList != null && idList.Length > 0)
            {
                ms.Write(BitConverter.GetBytes((ushort)idList.Length), 0, 2);
                ms.Write(idList, 0, idList.Length);
            }
            if (extraData != null && extraData.Length > 0)
            {
                ms.Write(extraData, 0, extraData.Length);
            }
            return ms.ToArray();
        }
    }

    private static byte[] CreateSyntheticChromiumCache(string url, int statusCode, string statusText, string contentType)
    {
        using (var ms = new MemoryStream())
        {
            byte[] magic = BitConverter.GetBytes(0xfcfb6d0543706173UL);
            ms.Write(magic, 0, 8);
            ms.Write(BitConverter.GetBytes((uint)1), 0, 4); // version
            byte[] keyBytes = Encoding.UTF8.GetBytes(url);
            ms.Write(BitConverter.GetBytes((uint)keyBytes.Length), 0, 4);
            ms.Write(BitConverter.GetBytes((uint)0), 0, 4); // hash
            ms.Write(keyBytes, 0, keyBytes.Length);

            // HTTP response headers
            string headerStr = string.Format("HTTP/1.1 {0} {1}\r\nContent-Type: {2}\r\n\r\n", statusCode, statusText, contentType);
            byte[] hBytes = Encoding.ASCII.GetBytes(headerStr);
            ms.Write(hBytes, 0, hBytes.Length);

            return ms.ToArray();
        }
    }

    private static byte[] CreateSyntheticFirefoxCache2(string url, uint fetchCount, uint lastFetchedSec, uint expirationSec)
    {
        using (var ms = new MemoryStream())
        {
            byte[] payload = new byte[128];
            ms.Write(payload, 0, payload.Length);

            byte[] keyBytes = Encoding.UTF8.GetBytes(url);
            uint metaSize = (uint)(20 + keyBytes.Length);

            byte[] meta = new byte[metaSize];
            WriteUInt32BE(meta, 0, fetchCount);
            WriteUInt32BE(meta, 4, lastFetchedSec);
            WriteUInt32BE(meta, 8, expirationSec);
            WriteUInt32BE(meta, 12, 0); // fz
            WriteUInt32BE(meta, 16, (uint)keyBytes.Length);
            Buffer.BlockCopy(keyBytes, 0, meta, 20, keyBytes.Length);
            ms.Write(meta, 0, meta.Length);

            byte[] footer = new byte[4];
            WriteUInt32BE(footer, 0, metaSize);
            ms.Write(footer, 0, 4);

            return ms.ToArray();
        }
    }

    private static void WriteUInt32LE(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static void WriteUInt32BE(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)((value >> 24) & 0xFF);
        buffer[offset + 1] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 3] = (byte)(value & 0xFF);
    }

    private static string ComputeSha256(byte[] data)
    {
        using (var sha = SHA256.Create())
        {
            byte[] hash = sha.ComputeHash(data);
            StringBuilder sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    private static string ComputeFileSha256(string path)
    {
        using (var sha = SHA256.Create())
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            byte[] hash = sha.ComputeHash(fs);
            StringBuilder sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}
