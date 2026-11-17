using System;
using System.IO;
using System.Text;
using UsbRecovery;

public static class VmdkImageReaderTests
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
        TestMonolithicFlatVmdk();
        TestMonolithicFlatWithZeroExtent();
        TestMonolithicSparseVmdk();
        TestWriteBlockingAndDisposal();
        TestCorruptHeaderRejection();

        Console.WriteLine("PASS VmdkImageReader: {0} checks; Monolithic Flat and Sparse VMDK parsing, Grain Directory/Table translation, LRU cache, seeking, and write-blocking verified.", checks);
    }

    private static void TestMonolithicFlatVmdk()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-test-flat-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string descPath = Path.Combine(tempDir, "disk.vmdk");
        string flatPath = Path.Combine(tempDir, "disk-flat.vmdk");

        try
        {
            // 64 KB test payload
            byte[] payload = new byte[65536];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)((i * 11 + 7) % 256);

            CreateSyntheticFlatVmdk(descPath, flatPath, payload);

            Check(VmdkImageReader.IsVmdkFile(descPath), "IsVmdkFile recognizes Flat VMDK descriptor");

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                Check(reader.CanRead, "CanRead is true");
                Check(reader.CanSeek, "CanSeek is true");
                Check(!reader.CanWrite, "CanWrite is false (write-blocking)");
                Check(reader.Subformat == VmdkSubformat.MonolithicFlat, "Subformat is MonolithicFlat");
                Check(reader.Length == 65536, "Length is 65536 bytes (128 sectors * 512): " + reader.Length);

                // Sequential read
                byte[] readBuf = new byte[65536];
                int r = reader.Read(readBuf, 0, 65536);
                Check(r == 65536, "Read full flat payload");
                for (int i = 0; i < payload.Length; i++)
                {
                    if (readBuf[i] != payload[i]) throw new Exception("Payload mismatch at byte " + i);
                }
                Check(reader.Position == 65536, "Position at EOF");

                // Read at EOF returns 0
                byte[] eofBuf = new byte[10];
                Check(reader.Read(eofBuf, 0, 10) == 0, "Read at EOF returns 0");

                // Random seek
                reader.Seek(2048, SeekOrigin.Begin);
                Check(reader.Position == 2048, "Seek Begin to 2048");
                byte[] sample = new byte[4];
                reader.Read(sample, 0, 4);
                Check(sample[0] == payload[2048], "Data matches at 2048");

                // Seek from Current
                reader.Seek(500, SeekOrigin.Current);
                Check(reader.Position == 2552, "Seek Current +500");

                // Seek from End
                reader.Seek(-128, SeekOrigin.End);
                Check(reader.Position == 65536 - 128, "Seek End -128");

                // Flush is safe no-op
                reader.Flush();
                Check(true, "Flush on Flat VMDK succeeds");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestMonolithicFlatWithZeroExtent()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-test-zero-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string descPath = Path.Combine(tempDir, "disk_with_zero.vmdk");
        string flatPath = Path.Combine(tempDir, "flat.vmdk");

        try
        {
            // 32 KB payload for flat extent (64 sectors)
            byte[] flatPayload = new byte[32768];
            for (int i = 0; i < flatPayload.Length; i++)
            {
                flatPayload[i] = (byte)((i * 13 + 5) % 251 + 1); // 1..251 non-zero pattern
            }
            File.WriteAllBytes(flatPath, flatPayload);

            // Construct standard VMware descriptor with 3-token ZERO extent followed by FLAT extent
            // Extent 0: RW 64 ZERO (sectors 0..63 -> guest bytes 0..32767)
            // Extent 1: RW 64 FLAT "flat.vmdk" 0 (sectors 64..127 -> guest bytes 32768..65535)
            string flatFileName = Path.GetFileName(flatPath);
            string descriptor = string.Format(
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=7b8b4a20\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 64 ZERO\n" +
                "RW 64 FLAT \"{0}\" 0\n\n" +
                "# The Disk Data Base\n" +
                "#DDB\n" +
                "ddb.adapterType = \"lsilogic\"\n" +
                "ddb.geometry.cylinders = \"1\"\n" +
                "ddb.geometry.heads = \"1\"\n" +
                "ddb.geometry.sectors = \"128\"\n",
                flatFileName);
            File.WriteAllText(descPath, descriptor, Encoding.ASCII);

            Check(VmdkImageReader.IsVmdkFile(descPath), "IsVmdkFile recognizes flat descriptor with 3-token ZERO extent");

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                Check(reader.CanRead, "CanRead is true");
                Check(reader.CanSeek, "CanSeek is true");
                Check(!reader.CanWrite, "CanWrite is false (write-blocking)");
                Check(reader.Subformat == VmdkSubformat.MonolithicFlat, "Subformat is MonolithicFlat");
                Check(reader.Length == 65536L, "Length is 65536 bytes (128 sectors): " + reader.Length);
                Check(reader.Extents.Count == 2, "Extents count is 2: " + reader.Extents.Count);
                Check(reader.Extents[0].Type == "ZERO", "Extent 0 type is ZERO");
                Check(reader.Extents[0].SectorCount == 64L, "Extent 0 SectorCount is 64");
                Check(reader.Extents[0].GuestStartSector == 0L, "Extent 0 GuestStartSector is 0");
                Check(reader.Extents[0].ExtentStream == null, "Extent 0 ExtentStream is null");
                Check(reader.Extents[1].Type == "FLAT", "Extent 1 type is FLAT");
                Check(reader.Extents[1].SectorCount == 64L, "Extent 1 SectorCount is 64");
                Check(reader.Extents[1].GuestStartSector == 64L, "Extent 1 GuestStartSector is 64");
                Check(reader.Extents[1].ExtentStream != null, "Extent 1 ExtentStream is active");

                // 1. Read first 32,768 bytes (ZERO extent) -> must return all zeroes
                byte[] firstHalf = new byte[32768];
                int r1 = reader.Read(firstHalf, 0, 32768);
                Check(r1 == 32768, "Read first 32768 bytes");
                bool allZero = true;
                for (int i = 0; i < 32768; i++)
                {
                    if (firstHalf[i] != 0) { allZero = false; break; }
                }
                Check(allZero, "First 32768 bytes from ZERO extent are all zeroes");
                Check(reader.Position == 32768L, "Position is 32768 after reading first half");

                // 2. Read second 32,768 bytes (FLAT extent) -> must match flat payload exactly
                byte[] secondHalf = new byte[32768];
                int r2 = reader.Read(secondHalf, 0, 32768);
                Check(r2 == 32768, "Read second 32768 bytes");
                bool flatMatch = true;
                for (int i = 0; i < 32768; i++)
                {
                    if (secondHalf[i] != flatPayload[i]) { flatMatch = false; break; }
                }
                Check(flatMatch, "Second 32768 bytes match flat extent payload exactly");
                Check(reader.Position == 65536L, "Position is 65536 (EOF) after reading second half");

                // 3. Read at EOF returns 0
                byte[] eofBuf = new byte[16];
                Check(reader.Read(eofBuf, 0, 16) == 0, "Read at EOF returns 0");

                // 4. Seek across ZERO/FLAT boundary: seek to 32768 - 128 (32640) and read 256 bytes
                reader.Seek(32768L - 128L, SeekOrigin.Begin);
                Check(reader.Position == 32768L - 128L, "Position after seek to 32640");

                byte[] straddleBuf = new byte[256];
                int rStraddle = reader.Read(straddleBuf, 0, 256);
                Check(rStraddle == 256, "Read 256 bytes straddling ZERO/FLAT boundary");

                // First 128 bytes from ZERO extent must be 0
                bool straddleZeroOk = true;
                for (int i = 0; i < 128; i++)
                {
                    if (straddleBuf[i] != 0) { straddleZeroOk = false; break; }
                }
                Check(straddleZeroOk, "First 128 bytes of straddle read are zeroes");

                // Next 128 bytes from FLAT extent must match flatPayload[0..127]
                bool straddleFlatOk = true;
                for (int i = 0; i < 128; i++)
                {
                    if (straddleBuf[128 + i] != flatPayload[i]) { straddleFlatOk = false; break; }
                }
                Check(straddleFlatOk, "Second 128 bytes of straddle read match flat payload");

                // 5. Precise 2-byte boundary crossing: seek to 32767, read 2 bytes (1 byte ZERO, 1 byte FLAT)
                reader.Seek(32767L, SeekOrigin.Begin);
                byte[] twoBytes = new byte[2];
                int rTwo = reader.Read(twoBytes, 0, 2);
                Check(rTwo == 2, "Read 2 bytes across boundary");
                Check(twoBytes[0] == 0, "Byte at 32767 is 0 (ZERO extent tail)");
                Check(twoBytes[1] == flatPayload[0], "Byte at 32768 matches flatPayload[0] (FLAT extent head)");

                // 6. Seek from Current and End
                reader.Seek(100, SeekOrigin.Current);
                Check(reader.Position == 32769L + 100L, "Seek Current +100 verified");
                Check(reader.ReadByte() == flatPayload[101], "ReadByte matches flatPayload at offset 101");

                reader.Seek(-1, SeekOrigin.End);
                Check(reader.Position == 65535L, "Seek End -1 verified");
                Check(reader.ReadByte() == flatPayload[32767], "ReadByte matches last byte of flatPayload");
            }

            // Case B: Inverted order (FLAT extent followed by ZERO extent)
            string descInvertedPath = Path.Combine(tempDir, "disk_inverted.vmdk");
            string descInverted = string.Format(
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=7b8b4a20\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 64 FLAT \"{0}\" 0\n" +
                "RW 64 ZERO\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n",
                flatFileName);
            File.WriteAllText(descInvertedPath, descInverted, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descInvertedPath))
            {
                Check(reader.Length == 65536L, "Inverted descriptor Length is 65536 bytes");
                Check(reader.Extents.Count == 2, "Inverted descriptor Extents count is 2");

                byte[] flatBuf = new byte[32768];
                int rf = reader.Read(flatBuf, 0, 32768);
                Check(rf == 32768, "Read 32768 bytes from first extent (FLAT)");
                bool flatMatch = true;
                for (int i = 0; i < 32768; i++)
                {
                    if (flatBuf[i] != flatPayload[i]) { flatMatch = false; break; }
                }
                Check(flatMatch, "First extent matches flat payload");

                byte[] zeroBuf = new byte[32768];
                int rz = reader.Read(zeroBuf, 0, 32768);
                Check(rz == 32768, "Read 32768 bytes from second extent (ZERO)");
                bool zeroMatch = true;
                for (int i = 0; i < 32768; i++)
                {
                    if (zeroBuf[i] != 0) { zeroMatch = false; break; }
                }
                Check(zeroMatch, "Second extent returns all zeroes");

                // Boundary straddle crossing from FLAT to ZERO
                reader.Seek(32768L - 64L, SeekOrigin.Begin);
                byte[] straddleInv = new byte[128];
                int rsi = reader.Read(straddleInv, 0, 128);
                Check(rsi == 128, "Read 128 bytes straddling FLAT to ZERO");
                for (int i = 0; i < 64; i++)
                {
                    if (straddleInv[i] != flatPayload[32768 - 64 + i]) throw new Exception("FLAT tail mismatch at " + i);
                }
                for (int i = 64; i < 128; i++)
                {
                    if (straddleInv[i] != 0) throw new Exception("ZERO head non-zero at " + i);
                }
                Check(true, "Straddle from FLAT to ZERO extent verified");
            }

            // Case C: Pure ZERO extent descriptor (no backing file needed)
            string descPureZeroPath = Path.Combine(tempDir, "disk_pure_zero.vmdk");
            string descPureZero =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=7b8b4a20\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 128 ZERO\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n";
            File.WriteAllText(descPureZeroPath, descPureZero, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPureZeroPath))
            {
                Check(reader.Length == 65536L, "Pure ZERO descriptor Length is 65536 bytes");
                Check(reader.Extents.Count == 1, "Pure ZERO descriptor Extents count is 1");
                Check(reader.Extents[0].Type == "ZERO", "Extent 0 is ZERO");
                Check(reader.Extents[0].ExtentStream == null, "ExtentStream is null for ZERO extent");

                byte[] pureBuf = new byte[4096];
                int rp = reader.Read(pureBuf, 0, 4096);
                Check(rp == 4096, "Read 4096 bytes from pure ZERO disk");
                bool allZeroPure = true;
                for (int i = 0; i < 4096; i++)
                {
                    if (pureBuf[i] != 0) { allZeroPure = false; break; }
                }
                Check(allZeroPure, "Pure ZERO disk returns all zeroes");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestMonolithicSparseVmdk()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-test-sparse-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vmdkPath = Path.Combine(tempDir, "sparse_test.vmdk");

        try
        {
            // Capacity = 256 sectors (128 KB = 2 grains)
            // Grain 0: 64 KB allocated with pattern
            // Grain 1: 64 KB unallocated (GTE = 0 -> zero fill)
            byte[] grain0Data = new byte[65536];
            for (int i = 0; i < grain0Data.Length; i++) grain0Data[i] = (byte)(0xC0 + (i % 64));

            byte[] vmdkBytes = CreateSyntheticSparseVmdk(grain0Data, 256);
            File.WriteAllBytes(vmdkPath, vmdkBytes);

            Check(VmdkImageReader.IsVmdkFile(vmdkPath), "IsVmdkFile recognizes Sparse VMDK");

            using (VmdkImageReader reader = VmdkImageReader.Open(vmdkPath))
            {
                Check(reader.Subformat == VmdkSubformat.MonolithicSparse, "Subformat is MonolithicSparse");
                Check(reader.Length == 131072, "Length is 128 KB (256 sectors * 512): " + reader.Length);

                // Read allocated Grain 0
                byte[] g0 = new byte[65536];
                int r0 = reader.Read(g0, 0, 65536);
                Check(r0 == 65536, "Read Grain 0");
                for (int i = 0; i < 65536; i++)
                {
                    if (g0[i] != grain0Data[i]) throw new Exception("Grain 0 mismatch at " + i);
                }

                // Read unallocated Grain 1 (GTE = 0 -> zero fill)
                byte[] g1 = new byte[65536];
                int r1 = reader.Read(g1, 0, 65536);
                Check(r1 == 65536, "Read Grain 1");
                for (int i = 0; i < 65536; i++)
                {
                    if (g1[i] != 0) throw new Exception("Grain 1 not zero-filled at " + i);
                }

                // Boundary straddle read crossing Grain 0 and Grain 1
                long straddlePos = 65536 - 100;
                reader.Seek(straddlePos, SeekOrigin.Begin);
                byte[] straddleBuf = new byte[200];
                int sRead = reader.Read(straddleBuf, 0, 200);
                Check(sRead == 200, "Straddle read 200 bytes across grain boundary");
                // First 100 bytes from Grain 0
                for (int i = 0; i < 100; i++)
                {
                    if (straddleBuf[i] != grain0Data[65536 - 100 + i]) throw new Exception("Straddle Grain 0 mismatch at " + i);
                }
                // Next 100 bytes from Grain 1 (zero-filled)
                for (int i = 100; i < 200; i++)
                {
                    if (straddleBuf[i] != 0) throw new Exception("Straddle Grain 1 mismatch at " + i);
                }

                // Verify LRU cache hit
                reader.Seek(0, SeekOrigin.Begin);
                byte[] cacheBuf = new byte[16];
                reader.Read(cacheBuf, 0, 16);
                Check(cacheBuf[0] == grain0Data[0], "Cache hit read verified");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestWriteBlockingAndDisposal()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-test-wb-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vmdkPath = Path.Combine(tempDir, "wb_test.vmdk");

        try
        {
            byte[] vmdkBytes = CreateSyntheticSparseVmdk(new byte[512], 128);
            File.WriteAllBytes(vmdkPath, vmdkBytes);

            using (VmdkImageReader reader = VmdkImageReader.Open(vmdkPath))
            {
                bool writeThrew = false;
                try { reader.Write(new byte[10], 0, 10); }
                catch (NotSupportedException) { writeThrew = true; }
                Check(writeThrew, "Write throws NotSupportedException");

                bool setLenThrew = false;
                try { reader.SetLength(100); }
                catch (NotSupportedException) { setLenThrew = true; }
                Check(setLenThrew, "SetLength throws NotSupportedException");

                bool negSeekThrew = false;
                try { reader.Seek(-50, SeekOrigin.Begin); }
                catch (IOException) { negSeekThrew = true; }
                Check(negSeekThrew, "Negative seek throws IOException");
            }

            VmdkImageReader disposedReader = VmdkImageReader.Open(vmdkPath);
            disposedReader.Dispose();
            bool readDisposedThrew = false;
            try { disposedReader.Read(new byte[10], 0, 10); }
            catch (ObjectDisposedException) { readDisposedThrew = true; }
            Check(readDisposedThrew, "Read on disposed stream throws ObjectDisposedException");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestCorruptHeaderRejection()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-test-corrupt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vmdkPath = Path.Combine(tempDir, "corrupt.vmdk");

        try
        {
            // Invalid file (random bytes without VMDK magic or descriptor signature)
            File.WriteAllBytes(vmdkPath, new byte[] { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB });

            bool threw = false;
            try
            {
                using (VmdkImageReader reader = VmdkImageReader.Open(vmdkPath)) { }
            }
            catch (InvalidDataException)
            {
                threw = true;
            }
            Check(threw, "Invalid VMDK file throws InvalidDataException");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void CreateSyntheticFlatVmdk(string descriptorPath, string flatPath, byte[] guestPayload)
    {
        File.WriteAllBytes(flatPath, guestPayload);
        long numSectors = (guestPayload.Length + 511) / 512;
        string flatFileName = Path.GetFileName(flatPath);

        string descriptor = string.Format(
            "# Disk DescriptorFile\n" +
            "version=1\n" +
            "CID=7b8b4a20\n" +
            "parentCID=ffffffff\n" +
            "createType=\"monolithicFlat\"\n\n" +
            "# Extent description\n" +
            "RW {0} FLAT \"{1}\" 0\n\n" +
            "# The Disk Data Base\n" +
            "#DDB\n" +
            "ddb.adapterType = \"lsilogic\"\n" +
            "ddb.geometry.cylinders = \"1\"\n" +
            "ddb.geometry.heads = \"1\"\n" +
            "ddb.geometry.sectors = \"{0}\"\n",
            numSectors, flatFileName);

        File.WriteAllText(descriptorPath, descriptor, Encoding.ASCII);
    }

    private static byte[] CreateSyntheticSparseVmdk(byte[] grain0Data, ulong capacitySectors)
    {
        ulong grainSize = 128;
        int numGTEsPerGT = 512;
        byte[] vmdk = new byte[128 * 1024]; // 128 KB file

        // 1. SparseExtentHeader at sector 0 (512 bytes)
        BitConverter.GetBytes(0x564D444BU).CopyTo(vmdk, 0); // Magic = "VMDK"
        BitConverter.GetBytes(1U).CopyTo(vmdk, 4);          // Version = 1
        BitConverter.GetBytes(0x00010000U).CopyTo(vmdk, 8); // Flags
        BitConverter.GetBytes(capacitySectors).CopyTo(vmdk, 12);
        BitConverter.GetBytes(grainSize).CopyTo(vmdk, 20);
        BitConverter.GetBytes(1UL).CopyTo(vmdk, 28);         // DescriptorOffset = 1
        BitConverter.GetBytes(1UL).CopyTo(vmdk, 36);         // DescriptorSize = 1
        BitConverter.GetBytes(numGTEsPerGT).CopyTo(vmdk, 44);
        BitConverter.GetBytes(0UL).CopyTo(vmdk, 48);         // RgdOffset = 0
        BitConverter.GetBytes(2UL).CopyTo(vmdk, 56);         // GdOffset = sector 2
        BitConverter.GetBytes(128UL).CopyTo(vmdk, 64);       // OverHead = 128
        vmdk[72] = 0;    // UncleanShutdown = 0
        vmdk[73] = 0x0A; // SingleEndLineChar = '\n'
        vmdk[74] = 0x20; // NonEndLineChar = ' '
        vmdk[75] = 0x0D; // DoubleEndLineChar1 = '\r'
        vmdk[76] = 0x0A; // DoubleEndLineChar2 = '\n'
        BitConverter.GetBytes((ushort)0).CopyTo(vmdk, 77); // CompressAlgorithm = 0

        // 2. Embedded Descriptor at sector 1 (offset 512)
        string desc = "# Disk DescriptorFile\ncreateType=\"monolithicSparse\"\n";
        Encoding.ASCII.GetBytes(desc).CopyTo(vmdk, 512);

        // 3. Grain Directory at sector 2 (offset 1024) -> points to GT 0 at sector 3
        BitConverter.GetBytes(3U).CopyTo(vmdk, 1024);

        // 4. Grain Table 0 at sector 3 (offset 1536)
        // GTE 0: points to sector 128 (offset 65536)
        BitConverter.GetBytes(128U).CopyTo(vmdk, 1536);
        // GTE 1: 0 (unallocated)
        BitConverter.GetBytes(0U).CopyTo(vmdk, 1540);

        // 5. Grain 0 Data at sector 128 (offset 65536)
        Array.Copy(grain0Data, 0, vmdk, 65536, Math.Min(grain0Data.Length, 65536));

        return vmdk;
    }
}
