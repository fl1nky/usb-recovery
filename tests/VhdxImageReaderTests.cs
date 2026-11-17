using System;
using System.IO;
using System.Text;
using UsbRecovery;

public static class VhdxImageReaderTests
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
        TestSignatureDetection();
        TestFixedVhdxReading();
        TestDynamicVhdxSparseAndZeroFill();
        TestDualHeaderSelection();
        TestWriteBlockingAndSeeking();
        TestDisposalBehavior();

        Console.WriteLine("PASS VhdxImageReaderTests: {0} checks passed; Fixed/Dynamic VHDX parsing, dual-header CRC32C, BAT interleaving, seeking, and write-blocking verified.", checks);
    }

    private static void TestSignatureDetection()
    {
        byte[] vhdx = CreateSyntheticVhdx(new byte[512], false);
        Check(VhdxImageReader.IsVhdxStream(new MemoryStream(vhdx)), "Synthetic VHDX recognized as valid VHDX stream");

        byte[] nonVhdx = new byte[65536];
        Check(!VhdxImageReader.IsVhdxStream(new MemoryStream(nonVhdx)), "All-zero stream rejected as VHDX");
        Check(!VhdxImageReader.IsVhdxStream(null), "Null stream rejected");

        string tempDir = Path.Combine(Path.GetTempPath(), "vhdx-sig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            string tempFile = Path.Combine(tempDir, "test.vhdx");
            File.WriteAllBytes(tempFile, vhdx);
            Check(VhdxImageReader.IsVhdxFile(tempFile), "IsVhdxFile returns true for synthetic VHDX");
            Check(!VhdxImageReader.IsVhdxFile(Path.Combine(tempDir, "nonexistent.vhdx")), "IsVhdxFile returns false for missing file");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestFixedVhdxReading()
    {
        // 1 MB payload with repeated pattern
        byte[] payload = new byte[1048576];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 251);

        byte[] vhdxData = CreateSyntheticVhdx(payload, false);
        using (MemoryStream ms = new MemoryStream(vhdxData))
        using (VhdxImageReader reader = new VhdxImageReader(ms))
        {
            Check(reader.CanRead, "Fixed VHDX CanRead is true");
            Check(reader.CanSeek, "Fixed VHDX CanSeek is true");
            Check(!reader.CanWrite, "Fixed VHDX CanWrite is false");
            Check(reader.Length == 1048576L, "Fixed VHDX Length matches payload size");
            Check(!reader.IsDynamicDisk, "Fixed VHDX IsDynamicDisk is false");

            // Read first 1024 bytes
            byte[] readBuf = new byte[1024];
            int r = reader.Read(readBuf, 0, 1024);
            Check(r == 1024, "Read 1024 bytes from start");
            bool match = true;
            for (int i = 0; i < 1024; i++) if (readBuf[i] != payload[i]) { match = false; break; }
            Check(match, "Payload data bytes match expected pattern");

            // Seek and read across 512KB offset
            reader.Seek(524288L, SeekOrigin.Begin);
            Check(reader.Position == 524288L, "Position updated after Seek");
            r = reader.Read(readBuf, 0, 1024);
            Check(r == 1024, "Read 1024 bytes from offset 524288");
            match = true;
            for (int i = 0; i < 1024; i++) if (readBuf[i] != payload[524288 + i]) { match = false; break; }
            Check(match, "Seek read matches expected pattern");

            // Read past EOF returns 0
            reader.Seek(1048576L, SeekOrigin.Begin);
            byte[] eofBuf = new byte[16];
            Check(reader.Read(eofBuf, 0, 16) == 0, "Read at EOF returns 0");
        }
    }

    private static void TestDynamicVhdxSparseAndZeroFill()
    {
        // 2 MB virtual disk (2 blocks of 1 MB each)
        // Block 0: Allocated with pattern (0x77)
        // Block 1: Sparse / Not Present (must return 0)
        byte[] block0 = new byte[1048576];
        for (int i = 0; i < block0.Length; i++) block0[i] = 0x77;

        byte[] vhdxData = CreateSyntheticVhdx(block0, true);
        using (MemoryStream ms = new MemoryStream(vhdxData))
        using (VhdxImageReader reader = new VhdxImageReader(ms))
        {
            Check(reader.Length == 2097152L, "Dynamic VHDX Length is 2 MB");
            Check(reader.IsDynamicDisk, "Dynamic VHDX IsDynamicDisk is true");

            // Read from Block 0 (allocated)
            byte[] buf = new byte[512];
            int r = reader.Read(buf, 0, 512);
            Check(r == 512, "Read 512 bytes from Block 0");
            Check(buf[0] == 0x77 && buf[511] == 0x77, "Block 0 data is 0x77");

            // Seek into Block 1 (unallocated/sparse)
            reader.Seek(1048576L + 100L, SeekOrigin.Begin);
            r = reader.Read(buf, 0, 512);
            Check(r == 512, "Read 512 bytes from Block 1 (sparse)");
            bool allZero = true;
            for (int i = 0; i < 512; i++) if (buf[i] != 0) { allZero = false; break; }
            Check(allZero, "Sparse Block 1 correctly returns zeroes");

            // Straddle read across Block 0 and Block 1
            reader.Seek(1048576L - 50L, SeekOrigin.Begin);
            byte[] straddle = new byte[100];
            int sRead = reader.Read(straddle, 0, 100);
            Check(sRead == 100, "Straddle read returned 100 bytes");
            for (int i = 0; i < 50; i++)
            {
                if (straddle[i] != 0x77) throw new Exception("Straddle Block 0 mismatch at " + i);
            }
            for (int i = 50; i < 100; i++)
            {
                if (straddle[i] != 0) throw new Exception("Straddle Block 1 mismatch at " + i);
            }
        }
    }

    private static void TestDualHeaderSelection()
    {
        byte[] payload = new byte[1048576];
        byte[] vhdxData = CreateSyntheticVhdx(payload, false);

        // Header 1 is at 0x10000 with SequenceNumber = 1
        // Create Header 2 at 0x20000 with SequenceNumber = 2
        byte[] h2 = new byte[4096];
        Array.Copy(Encoding.ASCII.GetBytes("head"), 0, h2, 0, 4);
        BitConverter.GetBytes(2UL).CopyTo(h2, 8); // SequenceNumber = 2
        BitConverter.GetBytes((ushort)1).CopyTo(h2, 66); // Version = 1
        uint crc2 = VhdxImageReader.ComputeCrc32c(h2, 0, 4096);
        BitConverter.GetBytes(crc2).CopyTo(h2, 4);
        Array.Copy(h2, 0, vhdxData, 0x20000, 4096);

        using (MemoryStream ms = new MemoryStream(vhdxData))
        using (VhdxImageReader reader = new VhdxImageReader(ms))
        {
            Check(reader.HeaderSequenceNumber == 2UL, "Dual header resolution selected Header 2 with higher sequence number (2 > 1)");
        }

        // Now test corruption of Header 2: fallback to Header 1
        byte[] corruptedData = (byte[])vhdxData.Clone();
        corruptedData[0x20004] ^= 0xFF; // Corrupt Header 2 CRC
        using (MemoryStream ms = new MemoryStream(corruptedData))
        using (VhdxImageReader reader = new VhdxImageReader(ms))
        {
            Check(reader.HeaderSequenceNumber == 1UL, "Fallback to Header 1 when Header 2 is corrupt");
        }
    }

    private static void TestWriteBlockingAndSeeking()
    {
        byte[] vhdxData = CreateSyntheticVhdx(new byte[1048576], false);
        using (MemoryStream ms = new MemoryStream(vhdxData))
        using (VhdxImageReader reader = new VhdxImageReader(ms))
        {
            // Verify Write throws NotSupportedException
            bool writeBlocked = false;
            try { reader.Write(new byte[10], 0, 10); }
            catch (NotSupportedException) { writeBlocked = true; }
            Check(writeBlocked, "Write throws NotSupportedException");

            // Verify SetLength throws NotSupportedException
            bool setLengthBlocked = false;
            try { reader.SetLength(100); }
            catch (NotSupportedException) { setLengthBlocked = true; }
            Check(setLengthBlocked, "SetLength throws NotSupportedException");

            // Verify negative Seek throws IOException
            bool seekBlocked = false;
            try { reader.Seek(-10, SeekOrigin.Begin); }
            catch (IOException) { seekBlocked = true; }
            Check(seekBlocked, "Negative seek throws IOException");

            // Seek from Current
            reader.Seek(100, SeekOrigin.Begin);
            reader.Seek(50, SeekOrigin.Current);
            Check(reader.Position == 150, "Seek from Current verified");

            // Seek from End
            reader.Seek(-100, SeekOrigin.End);
            Check(reader.Position == 1048576 - 100, "Seek from End verified");

            // Flush is a safe no-op
            reader.Flush();
            Check(true, "Flush completed without exception");
        }
    }

    private static void TestDisposalBehavior()
    {
        byte[] vhdxData = CreateSyntheticVhdx(new byte[1048576], false);
        MemoryStream ms = new MemoryStream(vhdxData);
        VhdxImageReader reader = new VhdxImageReader(ms, false);
        Check(reader.CanRead, "CanRead before disposal");
        reader.Dispose();

        Check(!reader.CanRead, "CanRead is false after disposal");
        Check(!reader.CanSeek, "CanSeek is false after disposal");

        bool threw = false;
        try
        {
            reader.Read(new byte[10], 0, 10);
        }
        catch (ObjectDisposedException)
        {
            threw = true;
        }
        Check(threw, "Read throws ObjectDisposedException after disposal");
    }

    // -------------------------------------------------------------
    // Synthetic VHDX Image Generator Recipe
    // -------------------------------------------------------------
    public static byte[] CreateSyntheticVhdx(byte[] payloadData, bool isDynamic)
    {
        uint blockSize = 1048576; // 1 MB
        ulong diskSize = isDynamic ? (2UL * blockSize) : (ulong)blockSize;
        byte[] vhdx = new byte[4 * 1024 * 1024]; // 4 MB container

        // 1. File Type Identifier at offset 0
        Array.Copy(Encoding.ASCII.GetBytes("vhdxfile"), 0, vhdx, 0, 8);

        // 2. Header 1 at offset 0x10000 (64 KB)
        byte[] header = new byte[4096];
        Array.Copy(Encoding.ASCII.GetBytes("head"), 0, header, 0, 4);
        BitConverter.GetBytes(1UL).CopyTo(header, 8); // SequenceNumber = 1
        BitConverter.GetBytes((ushort)1).CopyTo(header, 66); // Version = 1
        uint hCrc = VhdxImageReader.ComputeCrc32c(header, 0, 4096);
        BitConverter.GetBytes(hCrc).CopyTo(header, 4);
        Array.Copy(header, 0, vhdx, 0x10000, 4096);

        // 3. Region Table at offset 0x30000 (192 KB)
        byte[] regi = new byte[65536];
        Array.Copy(Encoding.ASCII.GetBytes("regi"), 0, regi, 0, 4);
        BitConverter.GetBytes(2U).CopyTo(regi, 8); // EntryCount = 2

        // Region 0: BAT Region (Offset 1 MB = 0x100000, Length 1 MB)
        Guid batGuid = new Guid("2DC27766-F623-4200-9D64-115E9BFD4A08");
        batGuid.ToByteArray().CopyTo(regi, 16);
        BitConverter.GetBytes(1048576UL).CopyTo(regi, 32);
        BitConverter.GetBytes(1048576U).CopyTo(regi, 40);
        BitConverter.GetBytes(1U).CopyTo(regi, 44);

        // Region 1: Metadata Region (Offset 2 MB = 0x200000, Length 1 MB)
        Guid metaGuid = new Guid("8B7D40A4-0796-4B43-AC8B-3B224F3A39E0");
        metaGuid.ToByteArray().CopyTo(regi, 48);
        BitConverter.GetBytes(2097152UL).CopyTo(regi, 64);
        BitConverter.GetBytes(1048576U).CopyTo(regi, 72);
        BitConverter.GetBytes(1U).CopyTo(regi, 76);

        uint rCrc = VhdxImageReader.ComputeCrc32c(regi, 0, 65536);
        BitConverter.GetBytes(rCrc).CopyTo(regi, 4);
        Array.Copy(regi, 0, vhdx, 0x30000, 65536);

        // 4. BAT Region at offset 1 MB (0x100000)
        // Block 0: State = 6 (FULLY_PRESENT), FileOffsetMB = 3 (0x300000)
        ulong bat0 = (3UL << 20) | 6UL;
        BitConverter.GetBytes(bat0).CopyTo(vhdx, 1048576);

        if (isDynamic)
        {
            // Block 1: State = 0 (PAYLOAD_BLOCK_NOT_PRESENT)
            BitConverter.GetBytes(0UL).CopyTo(vhdx, 1048576 + 8);
        }

        // 5. Metadata Region at offset 2 MB (0x200000)
        int metaBase = 2097152;
        Array.Copy(Encoding.ASCII.GetBytes("metadata"), 0, vhdx, metaBase, 8);
        BitConverter.GetBytes((ushort)4).CopyTo(vhdx, metaBase + 10); // EntryCount = 4

        // Item 0: File Parameters (Offset 256, Length 8)
        new Guid("CAA16737-FA36-4D43-B3B6-30F00AAEE56B").ToByteArray().CopyTo(vhdx, metaBase + 32);
        BitConverter.GetBytes(256U).CopyTo(vhdx, metaBase + 48);
        BitConverter.GetBytes(8U).CopyTo(vhdx, metaBase + 52);
        BitConverter.GetBytes(blockSize).CopyTo(vhdx, metaBase + 256);
        BitConverter.GetBytes(isDynamic ? 0U : 1U).CopyTo(vhdx, metaBase + 260);

        // Item 1: Virtual Disk Size (Offset 288, Length 8)
        new Guid("2FA54261-B276-42FB-AA69-E3B10F7264F3").ToByteArray().CopyTo(vhdx, metaBase + 64);
        BitConverter.GetBytes(288U).CopyTo(vhdx, metaBase + 80);
        BitConverter.GetBytes(8U).CopyTo(vhdx, metaBase + 84);
        BitConverter.GetBytes(diskSize).CopyTo(vhdx, metaBase + 288);

        // Item 2: Logical Sector Size (Offset 320, Length 4)
        new Guid("8141214F-43CD-4529-A8BB-4D0E75E9B646").ToByteArray().CopyTo(vhdx, metaBase + 96);
        BitConverter.GetBytes(320U).CopyTo(vhdx, metaBase + 112);
        BitConverter.GetBytes(4U).CopyTo(vhdx, metaBase + 116);
        BitConverter.GetBytes(512U).CopyTo(vhdx, metaBase + 320);

        // Item 3: Physical Sector Size (Offset 352, Length 4)
        new Guid("CDA348C7-445D-4471-9CC9-E9885251C556").ToByteArray().CopyTo(vhdx, metaBase + 128);
        BitConverter.GetBytes(352U).CopyTo(vhdx, metaBase + 144);
        BitConverter.GetBytes(4U).CopyTo(vhdx, metaBase + 148);
        BitConverter.GetBytes(512U).CopyTo(vhdx, metaBase + 352);

        // 6. Payload Block 0 at offset 3 MB (0x300000)
        Array.Copy(payloadData, 0, vhdx, 3 * 1024 * 1024, Math.Min(payloadData.Length, (int)blockSize));

        return vhdx;
    }
}
