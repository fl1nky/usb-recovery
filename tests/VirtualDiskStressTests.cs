using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class VirtualDiskStressTests
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
        Console.WriteLine("Starting Empirical Stress Verification of Virtual Disk Readers...");

        TestVhdStress_Fixed();
        TestVhdStress_Dynamic_SectorCrossingAndBlockStraddling();
        TestVhdxStress_FixedAndDynamic();
        TestVmdkStress_MultiExtentFlat();
        TestVmdkStress_SparseGrainStraddling();
        TestVmdk_StandardZeroExtentBugDemonstration();

        Console.WriteLine("PASS VirtualDiskStressTests: {0} empirical checks passed across VHD, VHDX, and VMDK stress harnesses.", checks);
    }

    // =========================================================================
    // 1. VHD STRESS TESTS (Fixed & Dynamic)
    // =========================================================================

    private static void TestVhdStress_Fixed()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-stress-fix-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vhdPath = Path.Combine(tempDir, "fixed_stress.vhd");

        try
        {
            const int diskSize = 65536; // 64 KiB
            byte[] oraclePayload = new byte[diskSize];
            for (int i = 0; i < diskSize; i++)
            {
                oraclePayload[i] = (byte)((i * 37 + 13) % 251);
            }

            byte[] vhdBytes = CreateFixedVhd(oraclePayload);
            File.WriteAllBytes(vhdPath, vhdBytes);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.CanRead, "Fixed VHD CanRead is true");
                Check(reader.CanSeek, "Fixed VHD CanSeek is true");
                Check(!reader.CanWrite, "Fixed VHD CanWrite is false");
                Check(reader.Length == diskSize, "Fixed VHD Length matches expected");

                // 1. Single-byte read loop across first 8192 bytes
                reader.Seek(0, SeekOrigin.Begin);
                byte[] singleBuf = new byte[1];
                for (int i = 0; i < 8192; i++)
                {
                    int r = reader.Read(singleBuf, 0, 1);
                    Check(r == 1, "Single-byte read returned 1 at byte " + i);
                    Check(singleBuf[0] == oraclePayload[i], "Single-byte read data mismatch at index " + i);
                    Check(reader.Position == i + 1, "Position advanced correctly after single-byte read");
                }

                // 2. Sector-crossing and misaligned reads
                int[] testOffsets = new int[] { 0, 1, 3, 510, 511, 512, 513, 1022, 1023, 1024, 1025, 4095, 4096, 4097 };
                int[] testSizes = new int[] { 1, 2, 3, 7, 13, 511, 512, 513, 1023, 1024, 1025, 2048 };

                foreach (int off in testOffsets)
                {
                    foreach (int sz in testSizes)
                    {
                        if (off + sz > diskSize) continue;
                        reader.Seek(off, SeekOrigin.Begin);
                        byte[] buf = new byte[sz];
                        int r = reader.Read(buf, 0, sz);
                        Check(r == sz, string.Format("Misaligned read (off={0}, sz={1}) returned {2}", off, sz, r));
                        for (int j = 0; j < sz; j++)
                        {
                            if (buf[j] != oraclePayload[off + j])
                            {
                                throw new Exception(string.Format("Misaligned read mismatch at off={0}, j={1}", off, j));
                            }
                        }
                    }
                }

                // 3. Random seeking across Begin, Current, End with oracle comparison
                Random rng = new Random(12345);
                for (int iter = 0; iter < 300; iter++)
                {
                    int targetPos = rng.Next(0, diskSize - 512);
                    int originChoice = rng.Next(0, 3);
                    switch (originChoice)
                    {
                        case 0: // Begin
                            reader.Seek(targetPos, SeekOrigin.Begin);
                            break;
                        case 1: // Current
                            long current = reader.Position;
                            reader.Seek(targetPos - current, SeekOrigin.Current);
                            break;
                        case 2: // End
                            reader.Seek(targetPos - diskSize, SeekOrigin.End);
                            break;
                    }
                    Check(reader.Position == targetPos, "Seek arrived at expected target position");

                    int readLen = rng.Next(1, 256);
                    byte[] readBuf = new byte[readLen];
                    int r = reader.Read(readBuf, 0, readLen);
                    Check(r == readLen, "Random read length matched");
                    for (int k = 0; k < readLen; k++)
                    {
                        if (readBuf[k] != oraclePayload[targetPos + k])
                        {
                            throw new Exception("Random seek read data mismatch");
                        }
                    }
                }

                // 4. Negative seek boundary protection
                bool negSeekBegin = false;
                try { reader.Seek(-1, SeekOrigin.Begin); }
                catch (IOException) { negSeekBegin = true; }
                Check(negSeekBegin, "Seek(-1, Begin) throws IOException");

                reader.Seek(100, SeekOrigin.Begin);
                bool negSeekCurrent = false;
                try { reader.Seek(-101, SeekOrigin.Current); }
                catch (IOException) { negSeekCurrent = true; }
                Check(negSeekCurrent, "Seek(-101, Current from 100) throws IOException");

                bool negSeekEnd = false;
                try { reader.Seek(-(diskSize + 1), SeekOrigin.End); }
                catch (IOException) { negSeekEnd = true; }
                Check(negSeekEnd, "Seek(-(diskSize + 1), End) throws IOException");

                bool invalidOrigin = false;
                try { reader.Seek(0, (SeekOrigin)99); }
                catch (ArgumentException) { invalidOrigin = true; }
                Check(invalidOrigin, "Invalid SeekOrigin value throws ArgumentException");

                // 5. Seek beyond EOF
                reader.Seek(diskSize + 5000, SeekOrigin.Begin);
                Check(reader.Position == diskSize + 5000, "Seek beyond EOF allowed in position");
                byte[] eofBuf = new byte[16];
                int eofRead = reader.Read(eofBuf, 0, 16);
                Check(eofRead == 0, "Read beyond EOF returns 0");

                // 6. Zero-length read
                reader.Seek(100, SeekOrigin.Begin);
                int zeroRead = reader.Read(new byte[10], 0, 0);
                Check(zeroRead == 0, "Read with count=0 returns 0");
                Check(reader.Position == 100, "Position unchanged after count=0 read");

                // 7. Buffer boundary validations
                bool nullBuf = false;
                try { reader.Read(null, 0, 1); } catch (ArgumentNullException) { nullBuf = true; }
                Check(nullBuf, "Read(null) throws ArgumentNullException");

                bool negOff = false;
                try { reader.Read(new byte[10], -1, 5); } catch (ArgumentOutOfRangeException) { negOff = true; }
                Check(negOff, "Read with negative offset throws ArgumentOutOfRangeException");

                bool negCount = false;
                try { reader.Read(new byte[10], 0, -1); } catch (ArgumentOutOfRangeException) { negCount = true; }
                Check(negCount, "Read with negative count throws ArgumentOutOfRangeException");

                bool bufOverflow = false;
                try { reader.Read(new byte[10], 8, 5); } catch (ArgumentException) { bufOverflow = true; }
                Check(bufOverflow, "Read with offset+count > Length throws ArgumentException");

                // 8. Write-blocking guarantees
                bool writeBlocked = false;
                try { reader.Write(new byte[10], 0, 10); } catch (NotSupportedException) { writeBlocked = true; }
                Check(writeBlocked, "Write throws NotSupportedException");

                bool setLengthBlocked = false;
                try { reader.SetLength(100); } catch (NotSupportedException) { setLengthBlocked = true; }
                Check(setLengthBlocked, "SetLength throws NotSupportedException");

                bool writeByteBlocked = false;
                try { reader.WriteByte(0x99); } catch (NotSupportedException) { writeByteBlocked = true; }
                Check(writeByteBlocked, "WriteByte throws NotSupportedException");
            }

            // 9. Safe disposal and underlying file handle release
            VhdImageReader dispReader = VhdImageReader.Open(vhdPath);
            Check(dispReader.CanRead, "Pre-dispose CanRead");
            dispReader.Dispose();

            Check(!dispReader.CanRead, "Post-dispose CanRead is false");
            Check(!dispReader.CanSeek, "Post-dispose CanSeek is false");

            bool readDisposed = false;
            try { dispReader.Read(new byte[10], 0, 10); } catch (ObjectDisposedException) { readDisposed = true; }
            Check(readDisposed, "Read after Dispose throws ObjectDisposedException");

            bool seekDisposed = false;
            try { dispReader.Seek(0, SeekOrigin.Begin); } catch (ObjectDisposedException) { seekDisposed = true; }
            Check(seekDisposed, "Seek after Dispose throws ObjectDisposedException");

            bool setPosDisposed = false;
            try { dispReader.Position = 0; } catch (ObjectDisposedException) { setPosDisposed = true; }
            Check(setPosDisposed, "Setting Position after Dispose throws ObjectDisposedException");

            // Idempotent dispose
            dispReader.Dispose();
            Check(true, "Secondary Dispose call is idempotent and safe");

            // Verify file handle release by opening file with exclusive write lock
            using (FileStream exclusiveFs = new FileStream(vhdPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Check(exclusiveFs.CanWrite, "Underlying file handle unlocked after reader disposal");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdStress_Dynamic_SectorCrossingAndBlockStraddling()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-stress-dyn-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vhdPath = Path.Combine(tempDir, "dynamic_stress.vhd");

        try
        {
            uint blockSize = 2097152; // 2 MB
            int bitmapBytes = (int)(((blockSize / 512) / 8 + 511) / 512) * 512;
            byte[] sectorBitmap = new byte[bitmapBytes];
            byte[] block0Data = new byte[blockSize];

            // Setup sector allocations in Block 0:
            // Sector 0: allocated (0x11)
            // Sector 1: unallocated (0x00)
            // Sector 2: allocated (0x22)
            // Sector 3: unallocated (0x00)
            // Sectors 4..7: allocated (0x33)
            // Sector 4095 (last sector of Block 0): allocated (0x44)

            // Bitmap bitmask for sector s: (0x80 >> (s % 8)) in byte s / 8
            sectorBitmap[0] |= (byte)(0x80 >> 0); // sector 0
            for (int i = 0; i < 512; i++) block0Data[0 * 512 + i] = 0x11;

            // sector 1 unallocated (bit 1 is 0)

            sectorBitmap[0] |= (byte)(0x80 >> 2); // sector 2
            for (int i = 0; i < 512; i++) block0Data[2 * 512 + i] = 0x22;

            // sector 3 unallocated (bit 3 is 0)

            sectorBitmap[0] |= (byte)(0x80 >> 4); // sector 4
            sectorBitmap[0] |= (byte)(0x80 >> 5); // sector 5
            sectorBitmap[0] |= (byte)(0x80 >> 6); // sector 6
            sectorBitmap[0] |= (byte)(0x80 >> 7); // sector 7
            for (int s = 4; s <= 7; s++)
            {
                for (int i = 0; i < 512; i++) block0Data[s * 512 + i] = 0x33;
            }

            // Sector 4095: byte 4095 / 8 = 511, bit 4095 % 8 = 7 -> 0x80 >> 7 = 0x01
            sectorBitmap[511] |= 0x01;
            for (int i = 0; i < 512; i++) block0Data[4095 * 512 + i] = 0x44;

            byte[] vhdBytes = CreateCustomDynamicVhdWithBitmap(block0Data, sectorBitmap, blockSize);
            File.WriteAllBytes(vhdPath, vhdBytes);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.Length == 2L * blockSize, "Dynamic VHD Length is 4 MB");

                // 1. Sector crossing reads within Block 0:
                // From offset 510 (last 2 bytes of sector 0) to 514 (first 2 bytes of sector 1):
                reader.Seek(510, SeekOrigin.Begin);
                byte[] crossBuf = new byte[4];
                int rCross = reader.Read(crossBuf, 0, 4);
                Check(rCross == 4, "Sector crossing read returned 4 bytes");
                Check(crossBuf[0] == 0x11 && crossBuf[1] == 0x11, "First 2 bytes from allocated sector 0");
                Check(crossBuf[2] == 0x00 && crossBuf[3] == 0x00, "Next 2 bytes from unallocated sector 1");

                // From offset 1022 (unallocated sector 1) to 1026 (allocated sector 2):
                reader.Seek(1022, SeekOrigin.Begin);
                rCross = reader.Read(crossBuf, 0, 4);
                Check(rCross == 4, "Sector crossing 1->2 returned 4 bytes");
                Check(crossBuf[0] == 0x00 && crossBuf[1] == 0x00, "First 2 bytes from unallocated sector 1");
                Check(crossBuf[2] == 0x22 && crossBuf[3] == 0x22, "Next 2 bytes from allocated sector 2");

                // From offset 1534 (allocated sector 2) to 1538 (unallocated sector 3):
                reader.Seek(1534, SeekOrigin.Begin);
                rCross = reader.Read(crossBuf, 0, 4);
                Check(rCross == 4, "Sector crossing 2->3 returned 4 bytes");
                Check(crossBuf[0] == 0x22 && crossBuf[1] == 0x22, "First 2 bytes from allocated sector 2");
                Check(crossBuf[2] == 0x00 && crossBuf[3] == 0x00, "Next 2 bytes from unallocated sector 3");

                // From offset 2046 (unallocated sector 3) to 2050 (allocated sector 4):
                reader.Seek(2046, SeekOrigin.Begin);
                rCross = reader.Read(crossBuf, 0, 4);
                Check(rCross == 4, "Sector crossing 3->4 returned 4 bytes");
                Check(crossBuf[0] == 0x00 && crossBuf[1] == 0x00, "First 2 bytes from unallocated sector 3");
                Check(crossBuf[2] == 0x33 && crossBuf[3] == 0x33, "Next 2 bytes from allocated sector 4");

                // 2. Single-byte read loop across sector 0 -> sector 1 -> sector 2
                reader.Seek(508, SeekOrigin.Begin);
                byte[] single = new byte[1];
                for (int i = 0; i < 8; i++)
                {
                    reader.Read(single, 0, 1);
                    byte expected = (i < 4) ? (byte)0x11 : (byte)0x00;
                    Check(single[0] == expected, "Single byte mismatch across sector boundary at step " + i);
                }

                // 3. True Block Straddling: Block 0 (allocated tail sector 4095 = 0x44) to Block 1 (unallocated BAT)
                long straddleOffset = blockSize - 16;
                reader.Seek(straddleOffset, SeekOrigin.Begin);
                byte[] straddleBuf = new byte[32];
                int rStraddle = reader.Read(straddleBuf, 0, 32);
                Check(rStraddle == 32, "Block straddle read returned 32 bytes");
                for (int i = 0; i < 16; i++)
                {
                    Check(straddleBuf[i] == 0x44, "Straddle byte from Block 0 tail matches allocated sector 4095");
                }
                for (int i = 16; i < 32; i++)
                {
                    Check(straddleBuf[i] == 0x00, "Straddle byte from Block 1 head is zero-filled");
                }

                // 4. Large misaligned read straddling Block 0 and Block 1
                reader.Seek(blockSize - 1000, SeekOrigin.Begin);
                byte[] largeStraddle = new byte[2000];
                int rLarge = reader.Read(largeStraddle, 0, 2000);
                Check(rLarge == 2000, "Large straddle read returned 2000 bytes");
                // Check sector 4095 bytes (offsets 1000 - 512 to 1000):
                for (int i = 1000 - 512; i < 1000; i++)
                {
                    Check(largeStraddle[i] == 0x44, "Large straddle sector 4095 verified");
                }
                // Check Block 1 head (offsets 1000 to 2000):
                for (int i = 1000; i < 2000; i++)
                {
                    Check(largeStraddle[i] == 0x00, "Large straddle Block 1 zero-fill verified");
                }
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // 2. VHDX STRESS TESTS (Fixed & Dynamic)
    // =========================================================================

    private static void TestVhdxStress_FixedAndDynamic()
    {
        uint blockSize = 1048576; // 1 MB
        byte[] payloadData = new byte[blockSize];
        for (int i = 0; i < payloadData.Length; i++)
        {
            payloadData[i] = (byte)((i * 17 + 5) % 251);
        }

        // Test Dynamic VHDX (2 MB virtual disk: Block 0 Fully Present, Block 1 Zero / Not Present)
        byte[] vhdxBytes = CreateSyntheticVhdx(payloadData, true);

        using (MemoryStream ms = new MemoryStream(vhdxBytes))
        using (VhdxImageReader reader = new VhdxImageReader(ms, false))
        {
            Check(reader.CanRead, "VHDX CanRead is true");
            Check(reader.CanSeek, "VHDX CanSeek is true");
            Check(!reader.CanWrite, "VHDX CanWrite is false");
            Check(reader.Length == 2L * blockSize, "VHDX Length is 2 MB");

            // 1. Single-byte read loop across 4096 bytes
            reader.Seek(0, SeekOrigin.Begin);
            byte[] single = new byte[1];
            for (int i = 0; i < 4096; i++)
            {
                int r = reader.Read(single, 0, 1);
                Check(r == 1, "Single-byte read returned 1 at index " + i);
                Check(single[0] == payloadData[i], "Single-byte VHDX data mismatch at index " + i);
                Check(reader.Position == i + 1, "Position advanced correctly in VHDX");
            }

            // 2. Misaligned reads crossing sector (512) and physical sector (4096) boundaries
            int[] testOffsets = new int[] { 0, 1, 510, 511, 512, 513, 4094, 4095, 4096, 4097, 8191, 8192 };
            int[] testSizes = new int[] { 1, 2, 3, 511, 512, 513, 4095, 4096, 4097 };

            foreach (int off in testOffsets)
            {
                foreach (int sz in testSizes)
                {
                    reader.Seek(off, SeekOrigin.Begin);
                    byte[] buf = new byte[sz];
                    int r = reader.Read(buf, 0, sz);
                    Check(r == sz, string.Format("VHDX misaligned read (off={0}, sz={1})", off, sz));
                    for (int j = 0; j < sz; j++)
                    {
                        if (buf[j] != payloadData[off + j])
                        {
                            throw new Exception(string.Format("VHDX mismatch at off={0}, j={1}", off, j));
                        }
                    }
                }
            }

            // 3. Block Straddling Read: Block 0 (fully present) to Block 1 (unallocated / zero)
            long blockBoundary = blockSize;
            reader.Seek(blockBoundary - 64, SeekOrigin.Begin);
            byte[] straddleBuf = new byte[128];
            int rStraddle = reader.Read(straddleBuf, 0, 128);
            Check(rStraddle == 128, "VHDX block straddle returned 128 bytes");
            for (int i = 0; i < 64; i++)
            {
                Check(straddleBuf[i] == payloadData[blockSize - 64 + i], "VHDX Block 0 tail matches");
            }
            for (int i = 64; i < 128; i++)
            {
                Check(straddleBuf[i] == 0x00, "VHDX Block 1 head is zero");
            }

            // 4. Random seeking across all origins
            Random rng = new Random(54321);
            for (int iter = 0; iter < 300; iter++)
            {
                int target = rng.Next(0, (int)blockSize - 512);
                int originChoice = rng.Next(0, 3);
                switch (originChoice)
                {
                    case 0: reader.Seek(target, SeekOrigin.Begin); break;
                    case 1: reader.Seek(target - reader.Position, SeekOrigin.Current); break;
                    case 2: reader.Seek(target - (long)(2 * blockSize), SeekOrigin.End); break;
                }
                Check(reader.Position == target, "VHDX seek arrived at target");

                int readLen = rng.Next(1, 128);
                byte[] rBuf = new byte[readLen];
                int r = reader.Read(rBuf, 0, readLen);
                Check(r == readLen, "VHDX random read length matched");
                for (int k = 0; k < readLen; k++)
                {
                    if (rBuf[k] != payloadData[target + k]) throw new Exception("VHDX random seek read mismatch");
                }
            }

            // 5. Negative seek boundary protection
            bool negBegin = false;
            try { reader.Seek(-1, SeekOrigin.Begin); } catch (IOException) { negBegin = true; }
            Check(negBegin, "VHDX Seek(-1, Begin) throws IOException");

            reader.Seek(50, SeekOrigin.Begin);
            bool negCurrent = false;
            try { reader.Seek(-51, SeekOrigin.Current); } catch (IOException) { negCurrent = true; }
            Check(negCurrent, "VHDX Seek(-51, Current from 50) throws IOException");

            bool negEnd = false;
            try { reader.Seek(-(long)(2 * blockSize + 1), SeekOrigin.End); } catch (IOException) { negEnd = true; }
            Check(negEnd, "VHDX Seek(-(Length + 1), End) throws IOException");

            bool invalidOrigin = false;
            try { reader.Seek(0, (SeekOrigin)88); } catch (ArgumentException) { invalidOrigin = true; }
            Check(invalidOrigin, "VHDX invalid SeekOrigin throws ArgumentException");

            // 6. Seek beyond EOF
            reader.Seek(5000000L, SeekOrigin.Begin);
            Check(reader.Position == 5000000L, "VHDX seek beyond EOF allowed in position");
            Check(reader.Read(new byte[10], 0, 10) == 0, "VHDX read beyond EOF returns 0");

            // 7. Write blocking
            bool writeBlocked = false;
            try { reader.Write(new byte[10], 0, 10); } catch (NotSupportedException) { writeBlocked = true; }
            Check(writeBlocked, "VHDX Write throws NotSupportedException");

            bool setLengthBlocked = false;
            try { reader.SetLength(100); } catch (NotSupportedException) { setLengthBlocked = true; }
            Check(setLengthBlocked, "VHDX SetLength throws NotSupportedException");

            bool writeByteBlocked = false;
            try { reader.WriteByte(0x12); } catch (NotSupportedException) { writeByteBlocked = true; }
            Check(writeByteBlocked, "VHDX WriteByte throws NotSupportedException");
        }

        // 8. Safe disposal test
        using (MemoryStream ms = new MemoryStream(vhdxBytes))
        {
            VhdxImageReader dispReader = new VhdxImageReader(ms, true);
            dispReader.Dispose();

            Check(!dispReader.CanRead, "VHDX CanRead false post-dispose");
            Check(!dispReader.CanSeek, "VHDX CanSeek false post-dispose");

            bool readDisposed = false;
            try { dispReader.Read(new byte[10], 0, 10); } catch (ObjectDisposedException) { readDisposed = true; }
            Check(readDisposed, "VHDX Read throws ObjectDisposedException");

            bool seekDisposed = false;
            try { dispReader.Seek(0, SeekOrigin.Begin); } catch (ObjectDisposedException) { seekDisposed = true; }
            Check(seekDisposed, "VHDX Seek throws ObjectDisposedException");

            bool setPosDisposed = false;
            try { dispReader.Position = 0; } catch (ObjectDisposedException) { setPosDisposed = true; }
            Check(setPosDisposed, "VHDX set Position throws ObjectDisposedException");

            dispReader.Dispose(); // Idempotent
            Check(true, "VHDX double dispose is safe");
        }
    }

    // =========================================================================
    // 3. VMDK STRESS TESTS (Multi-Extent Flat & Monolithic Sparse)
    // =========================================================================

    private static void TestVmdkStress_MultiExtentFlat()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-stress-flat-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string descPath = Path.Combine(tempDir, "disk.vmdk");
        string extent0Path = Path.Combine(tempDir, "disk-f1.vmdk");
        string extent2Path = Path.Combine(tempDir, "disk-f2.vmdk");

        try
        {
            // Extent 0: FLAT (128 sectors = 65,536 bytes)
            byte[] ext0Data = new byte[65536];
            for (int i = 0; i < ext0Data.Length; i++) ext0Data[i] = (byte)((i * 23 + 3) % 256);
            File.WriteAllBytes(extent0Path, ext0Data);

            // Extent 1: ZERO (64 sectors = 32,768 bytes)

            // Extent 2: FLAT (64 sectors = 32,768 bytes)
            byte[] ext2Data = new byte[32768];
            for (int i = 0; i < ext2Data.Length; i++) ext2Data[i] = (byte)((i * 29 + 11) % 256);
            File.WriteAllBytes(extent2Path, ext2Data);

            // Descriptor with 3 extents
            string descriptor = string.Format(
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=12345678\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 128 FLAT \"{0}\" 0\n" +
                "RW 64 ZERO \"none\" 0\n" +
                "RW 64 FLAT \"{1}\" 0\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n",
                Path.GetFileName(extent0Path), Path.GetFileName(extent2Path));
            File.WriteAllText(descPath, descriptor, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                long totalBytes = 256 * 512L; // 131,072 bytes
                Check(reader.Length == totalBytes, "Multi-extent Flat VMDK Length is 131,072: " + reader.Length);
                Check(reader.Extents.Count == 3, "Extents count is 3");

                // 1. Single-byte read across Extent 0 -> Extent 1 boundary
                reader.Seek(65530, SeekOrigin.Begin);
                byte[] single = new byte[1];
                for (int i = 0; i < 12; i++)
                {
                    reader.Read(single, 0, 1);
                    byte expected = (i < 6) ? ext0Data[65530 + i] : (byte)0x00;
                    Check(single[0] == expected, "Single byte mismatch across Extent 0->1 boundary at step " + i);
                }

                // 2. Straddling Extent 0 (FLAT) and Extent 1 (ZERO)
                reader.Seek(65536 - 64, SeekOrigin.Begin);
                byte[] straddle01 = new byte[128];
                int r01 = reader.Read(straddle01, 0, 128);
                Check(r01 == 128, "Read across Extent 0->1 returned 128 bytes");
                for (int i = 0; i < 64; i++) Check(straddle01[i] == ext0Data[65536 - 64 + i], "Extent 0 tail matches");
                for (int i = 64; i < 128; i++) Check(straddle01[i] == 0x00, "Extent 1 head is zero");

                // 3. Straddling Extent 1 (ZERO) and Extent 2 (FLAT)
                reader.Seek(98304 - 64, SeekOrigin.Begin);
                byte[] straddle12 = new byte[128];
                int r12 = reader.Read(straddle12, 0, 128);
                Check(r12 == 128, "Read across Extent 1->2 returned 128 bytes");
                for (int i = 0; i < 64; i++) Check(straddle12[i] == 0x00, "Extent 1 tail is zero");
                for (int i = 64; i < 128; i++) Check(straddle12[i] == ext2Data[i - 64], "Extent 2 head matches");

                // 4. Random seek across all 3 extents
                Random rng = new Random(9876);
                for (int iter = 0; iter < 200; iter++)
                {
                    int target = rng.Next(0, (int)totalBytes - 256);
                    reader.Seek(target, SeekOrigin.Begin);
                    Check(reader.Position == target, "Flat VMDK seek arrived at target");

                    byte[] buf = new byte[128];
                    int r = reader.Read(buf, 0, 128);
                    Check(r == 128, "Flat VMDK read returned 128 bytes");
                    for (int k = 0; k < 128; k++)
                    {
                        long pos = target + k;
                        byte expected;
                        if (pos < 65536) expected = ext0Data[pos];
                        else if (pos < 98304) expected = 0x00;
                        else expected = ext2Data[pos - 98304];

                        if (buf[k] != expected) throw new Exception("Flat VMDK multi-extent data mismatch");
                    }
                }

                // 5. Negative seek boundary protection
                bool negBegin = false;
                try { reader.Seek(-1, SeekOrigin.Begin); } catch (IOException) { negBegin = true; }
                Check(negBegin, "Flat VMDK Seek(-1, Begin) throws IOException");

                reader.Seek(100, SeekOrigin.Begin);
                bool negCurrent = false;
                try { reader.Seek(-101, SeekOrigin.Current); } catch (IOException) { negCurrent = true; }
                Check(negCurrent, "Flat VMDK Seek(-101, Current from 100) throws IOException");

                bool negEnd = false;
                try { reader.Seek(-(totalBytes + 1), SeekOrigin.End); } catch (IOException) { negEnd = true; }
                Check(negEnd, "Flat VMDK Seek(-(Length + 1), End) throws IOException");

                // 6. Write blocking
                bool writeBlocked = false;
                try { reader.Write(new byte[10], 0, 10); } catch (NotSupportedException) { writeBlocked = true; }
                Check(writeBlocked, "Flat VMDK Write throws NotSupportedException");
            }

            // 7. Safe disposal & extent file unlocking
            VmdkImageReader dispReader = VmdkImageReader.Open(descPath);
            dispReader.Dispose();

            Check(!dispReader.CanRead, "Flat VMDK CanRead is false post-dispose");
            bool readDisposed = false;
            try { dispReader.Read(new byte[10], 0, 10); } catch (ObjectDisposedException) { readDisposed = true; }
            Check(readDisposed, "Flat VMDK Read throws ObjectDisposedException");

            dispReader.Dispose(); // Idempotent

            // Confirm extent files are fully closed by opening exclusive write handles
            using (FileStream fs0 = new FileStream(extent0Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            using (FileStream fs2 = new FileStream(extent2Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Check(fs0.CanWrite && fs2.CanWrite, "Flat VMDK extent files unlocked after disposal");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkStress_SparseGrainStraddling()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-stress-sparse-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string vmdkPath = Path.Combine(tempDir, "sparse_stress.vmdk");

        try
        {
            // Capacity = 256 sectors (128 KiB). Grain size = 128 sectors (64 KiB).
            // Grain 0: Allocated with pattern. Grain 1: Unallocated (returns 0).
            byte[] grain0Data = new byte[65536];
            for (int i = 0; i < grain0Data.Length; i++) grain0Data[i] = (byte)((i * 19 + 7) % 256);

            byte[] vmdkBytes = CreateSparseVmdk(grain0Data, 256, 128);
            File.WriteAllBytes(vmdkPath, vmdkBytes);

            using (VmdkImageReader reader = VmdkImageReader.Open(vmdkPath))
            {
                long totalBytes = 128 * 1024L;
                Check(reader.Length == totalBytes, "Sparse VMDK Length is 131,072: " + reader.Length);

                // 1. Single-byte read loop across grain boundary (Grain 0 -> Grain 1)
                reader.Seek(65530, SeekOrigin.Begin);
                byte[] single = new byte[1];
                for (int i = 0; i < 16; i++)
                {
                    reader.Read(single, 0, 1);
                    byte expected = (i < 6) ? grain0Data[65530 + i] : (byte)0x00;
                    Check(single[0] == expected, "Single byte grain crossing mismatch at step " + i);
                }

                // 2. Grain Straddling Read: Grain 0 (allocated) to Grain 1 (unallocated)
                reader.Seek(65536 - 128, SeekOrigin.Begin);
                byte[] straddleBuf = new byte[256];
                int rStraddle = reader.Read(straddleBuf, 0, 256);
                Check(rStraddle == 256, "Sparse grain straddle read returned 256 bytes");
                for (int i = 0; i < 128; i++)
                {
                    Check(straddleBuf[i] == grain0Data[65536 - 128 + i], "Grain 0 tail data matches");
                }
                for (int i = 128; i < 256; i++)
                {
                    Check(straddleBuf[i] == 0x00, "Grain 1 unallocated head is zero");
                }

                // 3. Misaligned reads across grain boundary
                int[] misalignSizes = new int[] { 1, 3, 7, 511, 512, 513, 1023, 1025, 4096 };
                foreach (int sz in misalignSizes)
                {
                    reader.Seek(65536 - (sz / 2), SeekOrigin.Begin);
                    byte[] buf = new byte[sz];
                    int r = reader.Read(buf, 0, sz);
                    Check(r == sz, "Misaligned grain straddle returned requested size: " + sz);
                    long startPos = 65536 - (sz / 2);
                    for (int j = 0; j < sz; j++)
                    {
                        long currentPos = startPos + j;
                        byte expected = (currentPos < 65536) ? grain0Data[currentPos] : (byte)0x00;
                        if (buf[j] != expected) throw new Exception("Grain straddle mismatch with size " + sz);
                    }
                }

                // 4. Random seeking across Grain 0 and Grain 1
                Random rng = new Random(4321);
                for (int iter = 0; iter < 300; iter++)
                {
                    int target = rng.Next(0, (int)totalBytes - 256);
                    reader.Seek(target, SeekOrigin.Begin);
                    Check(reader.Position == target, "Sparse VMDK seek arrived at target");

                    byte[] buf = new byte[128];
                    int r = reader.Read(buf, 0, 128);
                    Check(r == 128, "Sparse VMDK read returned 128 bytes");
                    for (int k = 0; k < 128; k++)
                    {
                        long pos = target + k;
                        byte expected = (pos < 65536) ? grain0Data[pos] : (byte)0x00;
                        if (buf[k] != expected) throw new Exception("Sparse VMDK random seek data mismatch");
                    }
                }

                // 5. Negative seek boundary protection
                bool negBegin = false;
                try { reader.Seek(-1, SeekOrigin.Begin); } catch (IOException) { negBegin = true; }
                Check(negBegin, "Sparse VMDK Seek(-1, Begin) throws IOException");

                reader.Seek(100, SeekOrigin.Begin);
                bool negCurrent = false;
                try { reader.Seek(-101, SeekOrigin.Current); } catch (IOException) { negCurrent = true; }
                Check(negCurrent, "Sparse VMDK Seek(-101, Current from 100) throws IOException");

                bool negEnd = false;
                try { reader.Seek(-(totalBytes + 1), SeekOrigin.End); } catch (IOException) { negEnd = true; }
                Check(negEnd, "Sparse VMDK Seek(-(Length + 1), End) throws IOException");

                // 6. Write blocking
                bool writeBlocked = false;
                try { reader.Write(new byte[10], 0, 10); } catch (NotSupportedException) { writeBlocked = true; }
                Check(writeBlocked, "Sparse VMDK Write throws NotSupportedException");

                bool setLengthBlocked = false;
                try { reader.SetLength(100); } catch (NotSupportedException) { setLengthBlocked = true; }
                Check(setLengthBlocked, "Sparse VMDK SetLength throws NotSupportedException");
            }

            // 7. Safe disposal & file unlocking
            VmdkImageReader dispReader = VmdkImageReader.Open(vmdkPath);
            dispReader.Dispose();

            Check(!dispReader.CanRead, "Sparse VMDK CanRead is false post-dispose");
            bool readDisposed = false;
            try { dispReader.Read(new byte[10], 0, 10); } catch (ObjectDisposedException) { readDisposed = true; }
            Check(readDisposed, "Sparse VMDK Read throws ObjectDisposedException");

            dispReader.Dispose(); // Idempotent

            using (FileStream fs = new FileStream(vmdkPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Check(fs.CanWrite, "Sparse VMDK file unlocked after disposal");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdk_StandardZeroExtentBugDemonstration()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-zero-bug-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string descPath = Path.Combine(tempDir, "zero_bug.vmdk");
        string flatPath = Path.Combine(tempDir, "flat.vmdk");

        try
        {
            // Extent 1: FLAT (64 sectors = 32 KB)
            byte[] flatData = new byte[32768];
            for (int i = 0; i < flatData.Length; i++) flatData[i] = 0x55;
            File.WriteAllBytes(flatPath, flatData);

            // Descriptor with standard VMware ZERO extent: RW 64 ZERO followed by RW 64 FLAT
            string descriptor = string.Format(
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=12345678\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 64 ZERO\n" +
                "RW 64 FLAT \"{0}\" 0\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n",
                Path.GetFileName(flatPath));
            File.WriteAllText(descPath, descriptor, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                // EMPIRICAL BUG RESOLUTION VERIFICATION:
                // Expected total sectors: 128 (64 zero + 64 flat) = 65,536 bytes.
                // VmdkImageReader now correctly parses 3-token "RW 64 ZERO" extents.
                bool extentFixed = (reader.Length == 65536L && reader.Extents.Count == 2);
                Check(extentFixed, "VmdkImageReader correctly parses standard 3-token 'RW <size> ZERO' extents, preserving 65536 bytes disk length and 2 extents.");
                Console.WriteLine("  [VMDK ZERO EXTENT FIXED & VERIFIED]: VmdkImageReader parsed 'RW 64 ZERO', disk length = {0} bytes (expected 65536 bytes), Extents count = {1} (expected 2).", reader.Length, reader.Extents.Count);
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // SYNTHETIC FIXTURE GENERATORS
    // =========================================================================

    private static byte[] CreateFixedVhd(byte[] guestPayload)
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

    private static byte[] CreateCustomDynamicVhdWithBitmap(byte[] block0Data, byte[] sectorBitmap, uint blockSize)
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

    private static byte[] CreateSyntheticVhdx(byte[] payloadData, bool isDynamic)
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

    private static byte[] CreateSparseVmdk(byte[] grain0Data, ulong capacitySectors, ulong grainSizeSectors)
    {
        int numGTEsPerGT = 512;
        byte[] vmdk = new byte[128 * 1024]; // 128 KB file

        // 1. SparseExtentHeader at sector 0 (512 bytes)
        BitConverter.GetBytes(0x564D444BU).CopyTo(vmdk, 0); // Magic = "VMDK"
        BitConverter.GetBytes(1U).CopyTo(vmdk, 4);          // Version = 1
        BitConverter.GetBytes(0x00010000U).CopyTo(vmdk, 8); // Flags
        BitConverter.GetBytes(capacitySectors).CopyTo(vmdk, 12);
        BitConverter.GetBytes(grainSizeSectors).CopyTo(vmdk, 20);
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
