using System;
using System.IO;
using System.Text;
using UsbRecovery;

public static class VhdImageReaderTests
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
        TestSignatureAndValidation();
        TestSyntheticFixedVhd();
        TestSyntheticDynamicVhd();
        TestDynamicVhdBigEndianBitmap();
        TestWriteBlockingGuarantees();
        TestDisposalBehavior();

        Console.WriteLine("PASS VhdImageReader: {0} checks; Fixed and Dynamic VHD parsing, BAT translation, sector bitmap bitmasks, and write-blocking verified.", checks);
    }

    private static void TestSignatureAndValidation()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-sig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // 1. Non-existent file
            Check(!VhdImageReader.IsVhdFile(Path.Combine(tempDir, "missing.vhd")), "Missing file returns false");

            // 2. Short file
            string shortFile = Path.Combine(tempDir, "short.vhd");
            File.WriteAllBytes(shortFile, new byte[256]);
            Check(!VhdImageReader.IsVhdFile(shortFile), "Short file returns false");

            // 3. Invalid cookie
            string invalidCookie = Path.Combine(tempDir, "badcookie.vhd");
            byte[] badData = new byte[512];
            Encoding.ASCII.GetBytes("notavhd!").CopyTo(badData, 0);
            File.WriteAllBytes(invalidCookie, badData);
            Check(!VhdImageReader.IsVhdFile(invalidCookie), "Invalid cookie returns false");

            // 4. Valid Fixed VHD recognized
            byte[] payload = new byte[1024];
            for (int i = 0; i < payload.Length; i++) payload[i] = 0xAA;
            byte[] fixedVhd = CreateSyntheticFixedVhd(payload);
            string validFixedPath = Path.Combine(tempDir, "valid_fixed.vhd");
            File.WriteAllBytes(validFixedPath, fixedVhd);
            Check(VhdImageReader.IsVhdFile(validFixedPath), "Valid Fixed VHD recognized by IsVhdFile");

            // 5. Corrupted checksum rejected
            byte[] corruptVhd = (byte[])fixedVhd.Clone();
            corruptVhd[corruptVhd.Length - 512 + 64] ^= 0xFF; // Invert checksum byte
            string corruptPath = Path.Combine(tempDir, "corrupt.vhd");
            File.WriteAllBytes(corruptPath, corruptVhd);
            Check(!VhdImageReader.IsVhdFile(corruptPath), "Corrupted footer checksum rejected by IsVhdFile");

            bool threw = false;
            try
            {
                using (VhdImageReader.Open(corruptPath)) { }
            }
            catch (InvalidDataException)
            {
                threw = true;
            }
            Check(threw, "Open throws InvalidDataException on corrupt checksum");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestSyntheticFixedVhd()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-fixed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vhdPath = Path.Combine(tempDir, "test_fixed.vhd");

        try
        {
            int diskBytes = 65536; // 64 KiB
            byte[] payload = new byte[diskBytes];
            for (int i = 0; i < diskBytes; i++) payload[i] = (byte)(i % 251);

            byte[] vhdData = CreateSyntheticFixedVhd(payload);
            File.WriteAllBytes(vhdPath, vhdData);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.CanRead, "Fixed VHD CanRead is true");
                Check(reader.CanSeek, "Fixed VHD CanSeek is true");
                Check(!reader.CanWrite, "Fixed VHD CanWrite is false");
                Check(reader.Length == diskBytes, "Fixed VHD Length equals payload size: " + reader.Length);
                Check(reader.DiskType == VhdType.Fixed, "DiskType is Fixed");
                Check(reader.Footer.CreatorApp == "test", "CreatorApp parsed: " + reader.Footer.CreatorApp);

                // Sequential read
                byte[] readBuf = new byte[diskBytes];
                int totalRead = 0;
                while (totalRead < diskBytes)
                {
                    int r = reader.Read(readBuf, totalRead, diskBytes - totalRead);
                    if (r <= 0) break;
                    totalRead += r;
                }
                Check(totalRead == diskBytes, "Read full fixed payload");
                for (int i = 0; i < diskBytes; i++)
                {
                    if (readBuf[i] != payload[i]) throw new Exception("Fixed data mismatch at byte " + i);
                }
                Check(reader.Position == diskBytes, "Position is at EOF: " + reader.Position);

                // Read past EOF returns 0
                byte[] dummy = new byte[16];
                Check(reader.Read(dummy, 0, dummy.Length) == 0, "Read at EOF returns 0");

                // Random Seek
                reader.Seek(1024, SeekOrigin.Begin);
                Check(reader.Position == 1024, "Position after seek is 1024");
                byte[] sample = new byte[4];
                reader.Read(sample, 0, 4);
                Check(sample[0] == payload[1024] && sample[1] == payload[1025], "Seek sample matches payload");

                // Seek from Current
                reader.Seek(100, SeekOrigin.Current);
                Check(reader.Position == 1128, "Position after SeekOrigin.Current is 1128");

                // Seek from End
                reader.Seek(-10, SeekOrigin.End);
                Check(reader.Position == diskBytes - 10, "Position after SeekOrigin.End is " + reader.Position);

                // Negative Seek throws IOException
                bool seekThrew = false;
                try
                {
                    reader.Seek(-1, SeekOrigin.Begin);
                }
                catch (IOException)
                {
                    seekThrew = true;
                }
                Check(seekThrew, "Seeking before beginning throws IOException");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestSyntheticDynamicVhd()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-dyn-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vhdPath = Path.Combine(tempDir, "test_dynamic.vhd");

        try
        {
            uint blockSize = 2097152; // 2 MB
            // 2 blocks total: Block 0 allocated (with 4096 bytes data), Block 1 unallocated
            byte[] block0Data = new byte[4096];
            for (int i = 0; i < block0Data.Length; i++) block0Data[i] = (byte)((i * 7) % 256);

            byte[] vhdData = CreateSyntheticDynamicVhd(block0Data, blockSize);
            File.WriteAllBytes(vhdPath, vhdData);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.CanRead, "Dynamic VHD CanRead is true");
                Check(reader.CanSeek, "Dynamic VHD CanSeek is true");
                Check(!reader.CanWrite, "Dynamic VHD CanWrite is false");
                Check(reader.Length == 2L * blockSize, "Dynamic VHD Length is 4 MB: " + reader.Length);
                Check(reader.DiskType == VhdType.Dynamic, "DiskType is Dynamic");
                Check(reader.DynamicHeader.BlockSize == blockSize, "Dynamic BlockSize is 2 MB");
                Check(reader.DynamicHeader.MaxTableEntries == 2, "MaxTableEntries is 2");

                // 1. Read Block 0 written data (first 4096 bytes = 8 sectors)
                byte[] buf0 = new byte[4096];
                int r0 = reader.Read(buf0, 0, 4096);
                Check(r0 == 4096, "Read 4096 bytes from Block 0");
                for (int i = 0; i < 4096; i++)
                {
                    if (buf0[i] != block0Data[i]) throw new Exception("Block 0 data mismatch at byte " + i);
                }

                // 2. Read Block 0 unwritten sectors (sector 8 to sector 4095)
                byte[] unwrittenBuf = new byte[1024];
                int rUnwritten = reader.Read(unwrittenBuf, 0, 1024);
                Check(rUnwritten == 1024, "Read unwritten sectors in allocated block");
                for (int i = 0; i < unwrittenBuf.Length; i++)
                {
                    if (unwrittenBuf[i] != 0) throw new Exception("Unwritten sector non-zero at byte " + i);
                }

                // 3. Read Block 1 (completely unallocated in BAT = 0xFFFFFFFF)
                reader.Seek(blockSize, SeekOrigin.Begin);
                Check(reader.Position == blockSize, "Seeked to start of Block 1");
                byte[] unallocBuf = new byte[4096];
                int rUnalloc = reader.Read(unallocBuf, 0, 4096);
                Check(rUnalloc == 4096, "Read unallocated BAT block returned 4096 bytes");
                for (int i = 0; i < unallocBuf.Length; i++)
                {
                    if (unallocBuf[i] != 0) throw new Exception("Unallocated block non-zero at byte " + i);
                }

                // 4. Boundary crossing read (straddling Block 0 and Block 1)
                long straddlePos = blockSize - 100;
                reader.Seek(straddlePos, SeekOrigin.Begin);
                byte[] straddleBuf = new byte[200];
                int rStraddle = reader.Read(straddleBuf, 0, 200);
                Check(rStraddle == 200, "Straddle read returned 200 bytes");
                for (int i = 0; i < 200; i++)
                {
                    // Both Block 0 tail and Block 1 head are zero-fill
                    if (straddleBuf[i] != 0) throw new Exception("Straddle buffer non-zero at index " + i);
                }
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestDynamicVhdBigEndianBitmap()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-bitmap-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vhdPath = Path.Combine(tempDir, "test_bitmap.vhd");

        try
        {
            uint blockSize = 2097152; // 2 MB
            // Create custom dynamic VHD where sectors 0, 2, 7, 8 are written, and 1, 3..6, 9 are unwritten
            byte[] blockData = new byte[blockSize];
            // Sector 0
            for (int i = 0; i < 512; i++) blockData[i] = 0x11;
            // Sector 1: left as 0
            // Sector 2
            for (int i = 0; i < 512; i++) blockData[1024 + i] = 0x22;
            // Sector 7
            for (int i = 0; i < 512; i++) blockData[3584 + i] = 0x77;
            // Sector 8
            for (int i = 0; i < 512; i++) blockData[4096 + i] = 0x88;

            // Build sector bitmap:
            // Byte 0:
            // bit 7 (sector 0) = 1
            // bit 6 (sector 1) = 0
            // bit 5 (sector 2) = 1
            // bit 4..1 (sectors 3..6) = 0
            // bit 0 (sector 7) = 1
            // -> Byte 0 = 0x80 | 0x20 | 0x01 = 0xA1
            // Byte 1:
            // bit 7 (sector 8) = 1
            // -> Byte 1 = 0x80
            byte[] customBitmap = new byte[512];
            customBitmap[0] = 0xA1;
            customBitmap[1] = 0x80;

            byte[] vhdBytes = CreateCustomDynamicVhdWithBitmap(blockData, customBitmap, blockSize);
            File.WriteAllBytes(vhdPath, vhdBytes);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                byte[] sector = new byte[512];

                // Check Sector 0: should be 0x11
                reader.Seek(0, SeekOrigin.Begin);
                reader.Read(sector, 0, 512);
                Check(sector[0] == 0x11 && sector[511] == 0x11, "Sector 0 has marker 0x11");

                // Check Sector 1: unwritten in bitmap -> must be all zeroes!
                reader.Read(sector, 0, 512);
                Check(sector[0] == 0 && sector[511] == 0, "Sector 1 is zero-filled");

                // Check Sector 2: should be 0x22
                reader.Read(sector, 0, 512);
                Check(sector[0] == 0x22 && sector[511] == 0x22, "Sector 2 has marker 0x22");

                // Check Sector 7: should be 0x77
                reader.Seek(7 * 512, SeekOrigin.Begin);
                reader.Read(sector, 0, 512);
                Check(sector[0] == 0x77 && sector[511] == 0x77, "Sector 7 has marker 0x77");

                // Check Sector 8: should be 0x88
                reader.Read(sector, 0, 512);
                Check(sector[0] == 0x88 && sector[511] == 0x88, "Sector 8 has marker 0x88");

                // Check Sector 9: unwritten in bitmap -> must be all zeroes!
                reader.Read(sector, 0, 512);
                Check(sector[0] == 0 && sector[511] == 0, "Sector 9 is zero-filled");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestWriteBlockingGuarantees()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-wb-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vhdPath = Path.Combine(tempDir, "writeblock.vhd");

        try
        {
            byte[] vhdData = CreateSyntheticFixedVhd(new byte[512]);
            File.WriteAllBytes(vhdPath, vhdData);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(!reader.CanWrite, "CanWrite is false");

                bool wrote = false;
                try
                {
                    reader.Write(new byte[10], 0, 10);
                }
                catch (NotSupportedException)
                {
                    wrote = true;
                }
                Check(wrote, "Write throws NotSupportedException");

                bool setLen = false;
                try
                {
                    reader.SetLength(100);
                }
                catch (NotSupportedException)
                {
                    setLen = true;
                }
                Check(setLen, "SetLength throws NotSupportedException");

                // Flush is a safe no-op
                reader.Flush();
                Check(true, "Flush executes without error");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestDisposalBehavior()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-disp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vhdPath = Path.Combine(tempDir, "disposal.vhd");

        try
        {
            byte[] vhdData = CreateSyntheticFixedVhd(new byte[512]);
            File.WriteAllBytes(vhdPath, vhdData);

            VhdImageReader reader = VhdImageReader.Open(vhdPath);
            Check(reader.CanRead, "Before disposal: CanRead is true");
            reader.Dispose();

            Check(!reader.CanRead, "After disposal: CanRead is false");
            Check(!reader.CanSeek, "After disposal: CanSeek is false");

            bool readDisposed = false;
            try
            {
                reader.Read(new byte[10], 0, 10);
            }
            catch (ObjectDisposedException)
            {
                readDisposed = true;
            }
            Check(readDisposed, "Read on disposed stream throws ObjectDisposedException");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // --- Synthetic Fixture Generators ---

    public static byte[] CreateSyntheticFixedVhd(byte[] guestPayload)
    {
        long diskSize = guestPayload.Length;
        byte[] vhd = new byte[diskSize + 512];
        Array.Copy(guestPayload, 0, vhd, 0, guestPayload.Length);

        byte[] footer = new byte[512];
        Encoding.ASCII.GetBytes("conectix").CopyTo(footer, 0);
        footer[11] = 0x02; // Features
        footer[12] = 0; footer[13] = 1; footer[14] = 0; footer[15] = 0; // Version 1.0
        for (int i = 16; i < 24; i++) footer[i] = 0xFF; // DataOffset = 0xFFFFFFFFFFFFFFFF

        uint ts = 100000;
        footer[24] = (byte)(ts >> 24); footer[25] = (byte)(ts >> 16);
        footer[26] = (byte)(ts >> 8);  footer[27] = (byte)ts;

        Encoding.ASCII.GetBytes("test").CopyTo(footer, 28);
        for (int i = 0; i < 8; i++)
        {
            byte b = (byte)((diskSize >> (8 * (7 - i))) & 0xFF);
            footer[40 + i] = b;
            footer[48 + i] = b;
        }

        footer[56] = 0; footer[57] = 1; footer[58] = 1; footer[59] = 1; // Geometry
        footer[63] = 2; // DiskType = 2 (Fixed)
        Guid.NewGuid().ToByteArray().CopyTo(footer, 68);

        uint csum = VhdImageReader.ComputeFooterChecksum(footer);
        footer[64] = (byte)(csum >> 24); footer[65] = (byte)(csum >> 16);
        footer[66] = (byte)(csum >> 8);  footer[67] = (byte)csum;

        Array.Copy(footer, 0, vhd, diskSize, 512);
        return vhd;
    }

    public static byte[] CreateSyntheticDynamicVhd(byte[] block0Data, uint blockSize)
    {
        byte[] customBitmap = new byte[512];
        int sectorsInPayload = (block0Data.Length + 511) / 512;
        for (int s = 0; s < sectorsInPayload; s++)
        {
            int byteIdx = s / 8;
            byte bitMask = (byte)(0x80 >> (s % 8));
            customBitmap[byteIdx] |= bitMask;
        }

        byte[] blockData = new byte[blockSize];
        Array.Copy(block0Data, 0, blockData, 0, Math.Min(block0Data.Length, (int)blockSize));

        return CreateCustomDynamicVhdWithBitmap(blockData, customBitmap, blockSize);
    }

    public static byte[] CreateCustomDynamicVhdWithBitmap(byte[] block0Data, byte[] sectorBitmap, uint blockSize)
    {
        long virtualDiskSize = 2L * blockSize;
        int bitmapBytes = (int)(((blockSize / 512) / 8 + 511) / 512) * 512;

        long block0Offset = 2048;
        long block0DataOffset = block0Offset + bitmapBytes;
        long eofOffset = block0DataOffset + blockSize;
        byte[] vhd = new byte[eofOffset + 512];

        // 1. Build Footer
        byte[] footer = new byte[512];
        Encoding.ASCII.GetBytes("conectix").CopyTo(footer, 0);
        footer[11] = 0x02; // Features
        footer[12] = 0; footer[13] = 1; footer[14] = 0; footer[15] = 0; // Version 1.0
        footer[22] = 0x02; footer[23] = 0x00; // Data Offset = 512

        for (int i = 0; i < 8; i++)
        {
            byte b = (byte)((virtualDiskSize >> (8 * (7 - i))) & 0xFF);
            footer[40 + i] = b; footer[48 + i] = b;
        }
        footer[63] = 3; // Disk Type = 3 (Dynamic)
        Guid.NewGuid().ToByteArray().CopyTo(footer, 68);

        uint fCsum = VhdImageReader.ComputeFooterChecksum(footer);
        footer[64] = (byte)(fCsum >> 24); footer[65] = (byte)(fCsum >> 16);
        footer[66] = (byte)(fCsum >> 8);  footer[67] = (byte)fCsum;

        Array.Copy(footer, 0, vhd, 0, 512);
        Array.Copy(footer, 0, vhd, eofOffset, 512);

        // 2. Build Dynamic Header
        byte[] dynHeader = new byte[1024];
        Encoding.ASCII.GetBytes("cxsparse").CopyTo(dynHeader, 0);
        for (int i = 8; i < 16; i++) dynHeader[i] = 0xFF;
        dynHeader[22] = 0x06; dynHeader[23] = 0x00; // Table Offset = 1536 (0x600)
        dynHeader[25] = 0x01; // Version = 1.0
        dynHeader[31] = 2; // Max Table Entries = 2

        dynHeader[32] = (byte)(blockSize >> 24); dynHeader[33] = (byte)(blockSize >> 16);
        dynHeader[34] = (byte)(blockSize >> 8);  dynHeader[35] = (byte)blockSize;

        uint hCsum = VhdImageReader.ComputeDynamicHeaderChecksum(dynHeader);
        dynHeader[36] = (byte)(hCsum >> 24); dynHeader[37] = (byte)(hCsum >> 16);
        dynHeader[38] = (byte)(hCsum >> 8);  dynHeader[39] = (byte)hCsum;

        Array.Copy(dynHeader, 0, vhd, 512, 1024);

        // 3. Build BAT (at offset 1536)
        // Entry 0: Sector 4 (2048 / 512)
        vhd[1536] = 0; vhd[1537] = 0; vhd[1538] = 0; vhd[1539] = 4;
        // Entry 1: 0xFFFFFFFF (unallocated)
        vhd[1540] = 0xFF; vhd[1541] = 0xFF; vhd[1542] = 0xFF; vhd[1543] = 0xFF;

        // 4. Sector Bitmap (at offset 2048)
        Array.Copy(sectorBitmap, 0, vhd, block0Offset, Math.Min(sectorBitmap.Length, bitmapBytes));

        // 5. Block 0 Payload Data
        Array.Copy(block0Data, 0, vhd, block0DataOffset, block0Data.Length);

        return vhd;
    }
}
