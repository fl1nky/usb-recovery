using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class AdversarialChallengerM1It2Tests
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

    public static void Main(string[] args)
    {
        Console.WriteLine("=========================================================================");
        Console.WriteLine("STARTING ADVERSARIAL CHALLENGER SUITE (Milestone 1 Iteration 2)");
        Console.WriteLine("=========================================================================");

        // Suite 1: VMDK Multi-Extent Complex Layouts & Boundary Straddles
        TestVmdkComplexMultiExtentLayout();
        TestVmdkPureZeroDescriptor();
        TestVmdkDescriptorSyntaxVariations();
        TestVmdkMissingBackingFileCleanup();
        TestVmdkBoundaryStraddleExhaustive();

        // Suite 2: VHD Header Corruption, BAT Straddling, and File Locking
        TestVhdFixedFooterCorruptionAndChecksum();
        TestVhdDynamicBatAndBitmapStraddling();
        TestVhdReadOnlyAttributeSupport();

        // Suite 3: VHDX Dual Header CRC32C Arbitration and Mixed BAT States
        TestVhdxDualHeaderArbitration();
        TestVhdxBatStateTransitions();

        // Suite 4: Universal Write-Blocking & Stream Contracts
        TestUniversalWriteBlockingAndDisposal();

        // Suite 5: Multi-Reader Concurrency & Forensic Sharing
        TestConcurrentForensicAccess();

        Console.WriteLine("=========================================================================");
        Console.WriteLine("ADVERSARIAL CHALLENGE COMPLETE: All {0} checks PASSED with 0 errors.", checks);
        Console.WriteLine("=========================================================================");
    }

    // =========================================================================
    // SUITE 1: VMDK MULTI-EXTENT COMPLEX LAYOUTS & BOUNDARY STRADDLES
    // =========================================================================

    private static void TestVmdkComplexMultiExtentLayout()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-adv-multi-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string descPath = Path.Combine(tempDir, "complex.vmdk");
            string flat1Path = Path.Combine(tempDir, "flat1.bin");
            string flat2Path = Path.Combine(tempDir, "flat2.bin");

            // Flat 1: 64 sectors = 32,768 bytes
            byte[] flat1 = new byte[32768];
            for (int i = 0; i < flat1.Length; i++) flat1[i] = (byte)(0xA0 + (i % 31));
            File.WriteAllBytes(flat1Path, flat1);

            // Flat 2: 128 sectors = 65,536 bytes
            byte[] flat2 = new byte[65536];
            for (int i = 0; i < flat2.Length; i++) flat2[i] = (byte)(0xC0 + (i % 47));
            File.WriteAllBytes(flat2Path, flat2);

            // Construct 5-extent layout:
            // Extent 0: RW 32 ZERO (sectors 0..31 -> 16,384 bytes zeros)
            // Extent 1: RW 64 FLAT "flat1.bin" 0 (sectors 32..95 -> 32,768 bytes flat1)
            // Extent 2: RW 48 ZERO (sectors 96..143 -> 24,576 bytes zeros)
            // Extent 3: RW 128 FLAT "flat2.bin" 0 (sectors 144..271 -> 65,536 bytes flat2)
            // Extent 4: RW 16 ZERO (sectors 272..287 -> 8,192 bytes zeros)
            // Total sectors: 32 + 64 + 48 + 128 + 16 = 288 sectors = 147,456 bytes.
            string desc = string.Format(
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=aabbccdd\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 32 ZERO\n" +
                "RW 64 FLAT \"{0}\" 0\n" +
                "RW 48 ZERO\n" +
                "RW 128 FLAT \"{1}\" 0\n" +
                "RW 16 ZERO\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n",
                Path.GetFileName(flat1Path),
                Path.GetFileName(flat2Path));
            File.WriteAllText(descPath, desc, Encoding.ASCII);

            // Ground truth oracle buffer
            byte[] oracle = new byte[147456];
            Array.Copy(flat1, 0, oracle, 16384, 32768);
            Array.Copy(flat2, 0, oracle, 73728, 65536);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                Check(reader.Length == 147456L, "VMDK total length matches 147,456 bytes: " + reader.Length);
                Check(reader.Extents.Count == 5, "VMDK extent count matches 5: " + reader.Extents.Count);

                Check(reader.Extents[0].Type == "ZERO" && reader.Extents[0].SectorCount == 32L && reader.Extents[0].GuestStartSector == 0L, "Extent 0 matches");
                Check(reader.Extents[1].Type == "FLAT" && reader.Extents[1].SectorCount == 64L && reader.Extents[1].GuestStartSector == 32L, "Extent 1 matches");
                Check(reader.Extents[2].Type == "ZERO" && reader.Extents[2].SectorCount == 48L && reader.Extents[2].GuestStartSector == 96L, "Extent 2 matches");
                Check(reader.Extents[3].Type == "FLAT" && reader.Extents[3].SectorCount == 128L && reader.Extents[3].GuestStartSector == 144L, "Extent 3 matches");
                Check(reader.Extents[4].Type == "ZERO" && reader.Extents[4].SectorCount == 16L && reader.Extents[4].GuestStartSector == 272L, "Extent 4 matches");

                // Full sequential read and compare with oracle
                byte[] full = new byte[147456];
                int totalRead = 0;
                while (totalRead < full.Length)
                {
                    int r = reader.Read(full, totalRead, full.Length - totalRead);
                    if (r <= 0) break;
                    totalRead += r;
                }
                Check(totalRead == 147456, "Full sequential read reached 147,456 bytes");
                for (int i = 0; i < oracle.Length; i++)
                {
                    if (full[i] != oracle[i])
                    {
                        Check(false, string.Format("Byte mismatch at offset {0}: expected {1:X2}, got {2:X2}", i, oracle[i], full[i]));
                    }
                }
                Check(true, "All 147,456 bytes match ground truth oracle byte-for-byte across 5 extents");

                // Test reading past EOF returns 0
                byte[] eofBuf = new byte[100];
                Check(reader.Read(eofBuf, 0, 100) == 0, "Read at EOF returns 0");

                // Test Seeking
                reader.Seek(0, SeekOrigin.Begin);
                Check(reader.Position == 0, "Seek to Begin(0)");

                // Seek into middle of Extent 2 (ZERO extent at 16384 + 32768 = 49152)
                reader.Seek(50000, SeekOrigin.Begin);
                Check(reader.Position == 50000, "Seek to 50000 in ZERO extent");
                byte[] midZero = new byte[128];
                int rMid = reader.Read(midZero, 0, 128);
                Check(rMid == 128, "Read 128 bytes from ZERO extent");
                for (int i = 0; i < 128; i++) Check(midZero[i] == 0, "Mid-ZERO extent byte is zero");

                // Seek into Extent 3 (FLAT extent at 73728)
                reader.Seek(73728 + 100, SeekOrigin.Begin);
                byte[] midFlat = new byte[64];
                int rFlat = reader.Read(midFlat, 0, 64);
                Check(rFlat == 64, "Read 64 bytes from second FLAT extent");
                for (int i = 0; i < 64; i++)
                {
                    Check(midFlat[i] == flat2[100 + i], "Byte in second flat matches payload");
                }
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkPureZeroDescriptor()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-adv-purezero-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string descPath = Path.Combine(tempDir, "purezero.vmdk");
            string desc =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=12345678\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 100 ZERO\n" +
                "RW 200 ZERO\n" +
                "RW 300 ZERO\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n";
            File.WriteAllText(descPath, desc, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                Check(reader.Length == 600L * 512L, "Pure ZERO length is 307,200 bytes: " + reader.Length);
                Check(reader.Extents.Count == 3, "Extents count is 3");
                Check(reader.Extents[0].ExtentStream == null, "Extent 0 stream is null");
                Check(reader.Extents[1].ExtentStream == null, "Extent 1 stream is null");
                Check(reader.Extents[2].ExtentStream == null, "Extent 2 stream is null");

                byte[] buf = new byte[4096];
                int r = reader.Read(buf, 0, 4096);
                Check(r == 4096, "Read 4096 zeros");
                for (int i = 0; i < 4096; i++) Check(buf[i] == 0, "Byte is zero");

                // Seek across all three zero extents
                reader.Seek(reader.Length - 10, SeekOrigin.Begin);
                Check(reader.Position == reader.Length - 10, "Seek to end of pure zero disk");
                int rEnd = reader.Read(buf, 0, 20);
                Check(rEnd == 10, "Read exactly 10 bytes at EOF");
                for (int i = 0; i < 10; i++) Check(buf[i] == 0, "End byte is zero");
                Check(reader.Position == reader.Length, "Position at EOF");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkDescriptorSyntaxVariations()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-adv-syntax-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string flatPath = Path.Combine(tempDir, "sample.bin");
            File.WriteAllBytes(flatPath, new byte[16384]);

            // Test 1: Mixed casing and tabs
            string descPath1 = Path.Combine(tempDir, "casing.vmdk");
            string desc1 = string.Format(
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "rw\t32\tzero\n" +
                "RW\t32\tFLAT\t\"{0}\"\t0\n",
                Path.GetFileName(flatPath));
            File.WriteAllText(descPath1, desc1, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath1))
            {
                Check(reader.Length == 64L * 512L, "Tabs and lowercase 'rw', 'zero' parsed: " + reader.Length);
                Check(reader.Extents.Count == 2, "2 extents parsed");
            }

            // Test 2: FLAT extent with missing filename (< 4 tokens) must be rejected/ignored safely
            string descPath2 = Path.Combine(tempDir, "badflat.vmdk");
            string desc2 = string.Format(
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 32 FLAT\n" +
                "RW 32 ZERO\n" +
                "RW 32 FLAT \"{0}\" 0\n",
                Path.GetFileName(flatPath));
            File.WriteAllText(descPath2, desc2, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath2))
            {
                Check(reader.Length == 64L * 512L, "Malformed 3-token FLAT line skipped safely, length is 32768: " + reader.Length);
                Check(reader.Extents.Count == 2, "Only 2 valid extents parsed: " + reader.Extents.Count);
                Check(reader.Extents[0].Type == "ZERO", "Extent 0 is ZERO");
                Check(reader.Extents[1].Type == "FLAT", "Extent 1 is FLAT");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkMissingBackingFileCleanup()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-adv-missing-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string existingFlat = Path.Combine(tempDir, "existing.bin");
            File.WriteAllBytes(existingFlat, new byte[16384]);

            string descPath = Path.Combine(tempDir, "missing.vmdk");
            string desc = string.Format(
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 32 FLAT \"{0}\" 0\n" +
                "RW 32 FLAT \"nonexistent_extent_file.bin\" 0\n",
                Path.GetFileName(existingFlat));
            File.WriteAllText(descPath, desc, Encoding.ASCII);

            bool caught = false;
            try
            {
                using (VmdkImageReader.Open(descPath)) { }
            }
            catch (FileNotFoundException)
            {
                caught = true;
            }
            Check(caught, "FileNotFoundException thrown for missing extent file");

            bool canOpen = true;
            try
            {
                using (FileStream fs = new FileStream(existingFlat, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                }
            }
            catch
            {
                canOpen = false;
            }
            Check(canOpen, "Previously opened extents were cleanly disposed upon error, no file lock leak");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkBoundaryStraddleExhaustive()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-adv-straddle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string flatPath = Path.Combine(tempDir, "flat.bin");
            byte[] flat = new byte[32768];
            for (int i = 0; i < flat.Length; i++) flat[i] = (byte)(0x10 + (i % 200));
            File.WriteAllBytes(flatPath, flat);

            string descPath = Path.Combine(tempDir, "straddle.vmdk");
            string desc = string.Format(
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 16 ZERO\n" +
                "RW 64 FLAT \"{0}\" 0\n" +
                "RW 16 ZERO\n",
                Path.GetFileName(flatPath));
            File.WriteAllText(descPath, desc, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                // Boundary 1 at 8192
                reader.Seek(8191, SeekOrigin.Begin);
                byte[] pair1 = new byte[2];
                int r1 = reader.Read(pair1, 0, 2);
                Check(r1 == 2, "Read 2 bytes across Boundary 1");
                Check(pair1[0] == 0x00, "Byte before boundary 1 is 0x00");
                Check(pair1[1] == flat[0], "Byte after boundary 1 is flat[0]");

                // Boundary 2 at 8192 + 32768 = 40960
                reader.Seek(40959, SeekOrigin.Begin);
                byte[] pair2 = new byte[2];
                int r2 = reader.Read(pair2, 0, 2);
                Check(r2 == 2, "Read 2 bytes across Boundary 2");
                Check(pair2[0] == flat[32767], "Byte before boundary 2 is flat[32767]");
                Check(pair2[1] == 0x00, "Byte after boundary 2 is 0x00");

                // Large straddle spanning all three extents
                reader.Seek(8000, SeekOrigin.Begin);
                int spanLen = 33500;
                byte[] spanBuf = new byte[spanLen];
                int rSpan = reader.Read(spanBuf, 0, spanLen);
                Check(rSpan == spanLen, "Read entire span across 3 extents");

                for (int i = 0; i < 192; i++) Check(spanBuf[i] == 0x00, "Span extent 0 part is zero");
                for (int i = 0; i < 32768; i++)
                {
                    Check(spanBuf[192 + i] == flat[i], "Span extent 1 byte matches flat");
                }
                for (int i = 192 + 32768; i < spanLen; i++)
                {
                    Check(spanBuf[i] == 0x00, "Span extent 2 part is zero");
                }
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // SUITE 2: VHD HEADER CORRUPTION, BAT STRADDLING, AND READ-ONLY SUPPORT
    // =========================================================================

    private static void TestVhdFixedFooterCorruptionAndChecksum()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-adv-corrupt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            byte[] payload = new byte[4096];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 255);

            byte[] vhdBytes = CreateSyntheticFixedVhd(payload);
            string vhdPath = Path.Combine(tempDir, "test.vhd");
            File.WriteAllBytes(vhdPath, vhdBytes);

            Check(VhdImageReader.IsVhdFile(vhdPath), "IsVhdFile returns true for valid Fixed VHD");
            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.Length == 4096, "Fixed VHD length is 4096");
            }

            // Corrupt cookie
            byte[] badCookie = (byte[])vhdBytes.Clone();
            badCookie[4096] = 0x58; // 'X'
            string badCookiePath = Path.Combine(tempDir, "badcookie.vhd");
            File.WriteAllBytes(badCookiePath, badCookie);

            Check(!VhdImageReader.IsVhdFile(badCookiePath), "IsVhdFile returns false for invalid cookie");
            bool openFailed = false;
            try
            {
                using (VhdImageReader.Open(badCookiePath)) { }
            }
            catch (InvalidDataException)
            {
                openFailed = true;
            }
            Check(openFailed, "VhdImageReader.Open throws InvalidDataException for invalid cookie");

            // Corrupt checksum
            byte[] badChecksum = (byte[])vhdBytes.Clone();
            badChecksum[4096 + 64] ^= 0xFF;
            string badChecksumPath = Path.Combine(tempDir, "badsum.vhd");
            File.WriteAllBytes(badChecksumPath, badChecksum);

            bool checksumFailed = false;
            try
            {
                using (VhdImageReader.Open(badChecksumPath)) { }
            }
            catch (InvalidDataException)
            {
                checksumFailed = true;
            }
            Check(checksumFailed, "VhdImageReader.Open throws InvalidDataException for corrupted footer checksum");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdDynamicBatAndBitmapStraddling()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-adv-dynamic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            const int blockSize = 524288; // 512 KiB
            const int totalSize = 1048576; // 1 MiB

            byte[] block1Payload = new byte[blockSize];
            for (int i = 0; i < blockSize; i++) block1Payload[i] = (byte)(0x33 ^ (i & 0xFF));

            string vhdPath = Path.Combine(tempDir, "dynamic.vhd");
            CreateSyntheticDynamicVhd(vhdPath, totalSize, blockSize, null, block1Payload);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.Length == totalSize, "Dynamic VHD length matches 1 MiB");
                Check(reader.DiskType == VhdType.Dynamic, "DiskType is Dynamic");

                reader.Seek(blockSize - 512, SeekOrigin.Begin);
                byte[] straddle = new byte[1024];
                int r = reader.Read(straddle, 0, 1024);
                Check(r == 1024, "Read 1024 bytes straddling VHD dynamic blocks");

                for (int i = 0; i < 512; i++)
                {
                    Check(straddle[i] == 0x00, "Unallocated block yields zero byte at " + i);
                }
                for (int i = 0; i < 512; i++)
                {
                    Check(straddle[512 + i] == block1Payload[i], "Allocated block yields payload byte at " + i);
                }
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdReadOnlyAttributeSupport()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-adv-readonly-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            byte[] payload = new byte[1024];
            byte[] vhdBytes = CreateSyntheticFixedVhd(payload);
            string vhdPath = Path.Combine(tempDir, "readonly.vhd");
            File.WriteAllBytes(vhdPath, vhdBytes);

            File.SetAttributes(vhdPath, FileAttributes.ReadOnly);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.Length == 1024, "Opened read-only fixed VHD successfully");
                byte[] b = new byte[512];
                int r = reader.Read(b, 0, 512);
                Check(r == 512, "Read from read-only fixed VHD");
            }

            File.SetAttributes(vhdPath, FileAttributes.Normal);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // SUITE 3: VHDX DUAL HEADER CRC32C ARBITRATION AND BAT STATES
    // =========================================================================

    private static void TestVhdxDualHeaderArbitration()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhdx-adv-arbitration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            byte[] payload = new byte[1048576];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(0x77 + (i % 17));

            byte[] raw = CreateSyntheticVhdx(payload, false);
            string vhdxPath = Path.Combine(tempDir, "dual.vhdx");
            File.WriteAllBytes(vhdxPath, raw);

            // Case A: Corrupt Header 1 CRC32C -> Header 2 should be selected
            byte[] h1Corrupt = (byte[])raw.Clone();
            h1Corrupt[0x10000 + 4] ^= 0xFF;
            string h1CorruptPath = Path.Combine(tempDir, "h1_corrupt.vhdx");
            File.WriteAllBytes(h1CorruptPath, h1Corrupt);

            using (VhdxImageReader reader = VhdxImageReader.Open(h1CorruptPath))
            {
                Check(reader.Length == 1048576, "Header 2 successfully chosen when Header 1 corrupted");
                byte[] b = new byte[64];
                reader.Read(b, 0, 64);
                Check(b[0] == payload[0], "Payload verified via fallback header");
            }

            // Case B: Corrupt Header 2 CRC32C -> Header 1 should be selected
            byte[] h2Corrupt = (byte[])raw.Clone();
            h2Corrupt[0x20000 + 4] ^= 0xFF;
            string h2CorruptPath = Path.Combine(tempDir, "h2_corrupt.vhdx");
            File.WriteAllBytes(h2CorruptPath, h2Corrupt);

            using (VhdxImageReader reader = VhdxImageReader.Open(h2CorruptPath))
            {
                Check(reader.Length == 1048576, "Header 1 successfully chosen when Header 2 corrupted");
                byte[] b = new byte[64];
                reader.Read(b, 0, 64);
                Check(b[0] == payload[0], "Payload verified via primary header");
            }

            // Case C: Corrupt BOTH headers -> should throw InvalidDataException
            byte[] bothCorrupt = (byte[])raw.Clone();
            bothCorrupt[0x10000 + 4] ^= 0xFF;
            bothCorrupt[0x20000 + 4] ^= 0xFF;
            string bothCorruptPath = Path.Combine(tempDir, "both_corrupt.vhdx");
            File.WriteAllBytes(bothCorruptPath, bothCorrupt);

            bool bothFailed = false;
            try
            {
                using (VhdxImageReader.Open(bothCorruptPath)) { }
            }
            catch (InvalidDataException)
            {
                bothFailed = true;
            }
            Check(bothFailed, "InvalidDataException thrown when both VHDX headers have invalid CRC32C");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdxBatStateTransitions()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhdx-adv-batstates-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            const int blockSize = 1048576; // 1 MB
            byte[] b1Data = new byte[blockSize];
            for (int i = 0; i < blockSize; i++) b1Data[i] = (byte)(0xAA + (i % 37));

            // Dynamic VHDX with Block 0 present, Block 1 not present
            byte[] vhdxBytes = CreateSyntheticVhdx(b1Data, true);
            string vhdxPath = Path.Combine(tempDir, "batstates.vhdx");
            File.WriteAllBytes(vhdxPath, vhdxBytes);

            using (VhdxImageReader reader = VhdxImageReader.Open(vhdxPath))
            {
                Check(reader.Length == 2L * blockSize, "VHDX 2MB length verified");

                // Straddle block 0 (PRESENT) and block 1 (NOT_PRESENT): seek to 1MB - 100, read 200 bytes
                reader.Seek(blockSize - 100, SeekOrigin.Begin);
                byte[] straddle = new byte[200];
                int r = reader.Read(straddle, 0, 200);
                Check(r == 200, "Read 200 bytes across Block 0/1 transition");
                for (int i = 0; i < 100; i++) Check(straddle[i] == b1Data[blockSize - 100 + i], "Block 0 end yields payload");
                for (int i = 0; i < 100; i++) Check(straddle[100 + i] == 0x00, "Block 1 NOT_PRESENT state yields 0x00");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // SUITE 4: UNIVERSAL WRITE-BLOCKING & STREAM CONTRACTS
    // =========================================================================

    private static void TestUniversalWriteBlockingAndDisposal()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "write-block-adv-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string flatPath = Path.Combine(tempDir, "dummy.bin");
            File.WriteAllBytes(flatPath, new byte[1024]);
            string vmdkPath = Path.Combine(tempDir, "dummy.vmdk");
            File.WriteAllText(vmdkPath, string.Format("version=1\ncreateType=\"monolithicFlat\"\nRW 2 FLAT \"{0}\" 0\n", Path.GetFileName(flatPath)));

            string vhdPath = Path.Combine(tempDir, "dummy.vhd");
            File.WriteAllBytes(vhdPath, CreateSyntheticFixedVhd(new byte[1024]));

            string vhdxPath = Path.Combine(tempDir, "dummy.vhdx");
            File.WriteAllBytes(vhdxPath, CreateSyntheticVhdx(new byte[1048576], false));

            // Test VMDK
            VmdkImageReader vmdk = VmdkImageReader.Open(vmdkPath);
            Check(!vmdk.CanWrite, "VMDK CanWrite is false");
            Check(vmdk.CanRead, "VMDK CanRead is true");
            Check(vmdk.CanSeek, "VMDK CanSeek is true");
            AssertWriteThrows(vmdk, "VMDK");
            vmdk.Dispose();
            vmdk.Dispose();
            AssertDisposedThrows(vmdk, "VMDK");

            // Test VHD
            VhdImageReader vhd = VhdImageReader.Open(vhdPath);
            Check(!vhd.CanWrite, "VHD CanWrite is false");
            Check(vhd.CanRead, "VHD CanRead is true");
            Check(vhd.CanSeek, "VHD CanSeek is true");
            AssertWriteThrows(vhd, "VHD");
            vhd.Dispose();
            vhd.Dispose();
            AssertDisposedThrows(vhd, "VHD");

            // Test VHDX
            VhdxImageReader vhdx = VhdxImageReader.Open(vhdxPath);
            Check(!vhdx.CanWrite, "VHDX CanWrite is false");
            Check(vhdx.CanRead, "VHDX CanRead is true");
            Check(vhdx.CanSeek, "VHDX CanSeek is true");
            AssertWriteThrows(vhdx, "VHDX");
            vhdx.Dispose();
            vhdx.Dispose();
            AssertDisposedThrows(vhdx, "VHDX");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void AssertWriteThrows(Stream stream, string name)
    {
        bool writeThrows = false;
        try
        {
            stream.Write(new byte[10], 0, 10);
        }
        catch (NotSupportedException)
        {
            writeThrows = true;
        }
        Check(writeThrows, name + " Write throws NotSupportedException");

        bool setLengthThrows = false;
        try
        {
            stream.SetLength(100);
        }
        catch (NotSupportedException)
        {
            setLengthThrows = true;
        }
        Check(setLengthThrows, name + " SetLength throws NotSupportedException");
    }

    private static void AssertDisposedThrows(Stream stream, string name)
    {
        bool readThrows = false;
        try
        {
            stream.Read(new byte[10], 0, 10);
        }
        catch (ObjectDisposedException)
        {
            readThrows = true;
        }
        Check(readThrows, name + " Read after Dispose throws ObjectDisposedException");

        bool seekThrows = false;
        try
        {
            stream.Seek(0, SeekOrigin.Begin);
        }
        catch (ObjectDisposedException)
        {
            seekThrows = true;
        }
        Check(seekThrows, name + " Seek after Dispose throws ObjectDisposedException");
    }

    // =========================================================================
    // SUITE 5: MULTI-READER CONCURRENCY & FORENSIC SHARING
    // =========================================================================

    private static void TestConcurrentForensicAccess()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "concurrent-adv-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            byte[] payload = new byte[1048576];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 127);

            // VMDK
            string flatPath = Path.Combine(tempDir, "flat.bin");
            File.WriteAllBytes(flatPath, payload);
            string vmdkPath = Path.Combine(tempDir, "disk.vmdk");
            File.WriteAllText(vmdkPath, string.Format("version=1\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"{0}\" 0\n", Path.GetFileName(flatPath)));

            // VHD
            string vhdPath = Path.Combine(tempDir, "disk.vhd");
            File.WriteAllBytes(vhdPath, CreateSyntheticFixedVhd(payload));

            // VHDX
            string vhdxPath = Path.Combine(tempDir, "disk.vhdx");
            File.WriteAllBytes(vhdxPath, CreateSyntheticVhdx(payload, false));

            // Open 5 concurrent VMDK readers
            List<VmdkImageReader> vmdkReaders = new List<VmdkImageReader>();
            for (int i = 0; i < 5; i++)
            {
                vmdkReaders.Add(VmdkImageReader.Open(vmdkPath));
            }
            Check(vmdkReaders.Count == 5, "5 concurrent VMDK readers opened simultaneously");
            for (int i = 0; i < 5; i++)
            {
                byte[] b = new byte[100];
                vmdkReaders[i].Seek(i * 100, SeekOrigin.Begin);
                int r = vmdkReaders[i].Read(b, 0, 100);
                Check(r == 100 && b[0] == payload[i * 100], "Concurrent VMDK reader " + i + " read successfully");
                vmdkReaders[i].Dispose();
            }

            // Open 5 concurrent VHD readers
            List<VhdImageReader> vhdReaders = new List<VhdImageReader>();
            for (int i = 0; i < 5; i++)
            {
                vhdReaders.Add(VhdImageReader.Open(vhdPath));
            }
            Check(vhdReaders.Count == 5, "5 concurrent VHD readers opened simultaneously");
            for (int i = 0; i < 5; i++)
            {
                byte[] b = new byte[100];
                vhdReaders[i].Seek(i * 100, SeekOrigin.Begin);
                int r = vhdReaders[i].Read(b, 0, 100);
                Check(r == 100 && b[0] == payload[i * 100], "Concurrent VHD reader " + i + " read successfully");
                vhdReaders[i].Dispose();
            }

            // Open 5 concurrent VHDX readers
            List<VhdxImageReader> vhdxReaders = new List<VhdxImageReader>();
            for (int i = 0; i < 5; i++)
            {
                vhdxReaders.Add(VhdxImageReader.Open(vhdxPath));
            }
            Check(vhdxReaders.Count == 5, "5 concurrent VHDX readers opened simultaneously");
            for (int i = 0; i < 5; i++)
            {
                byte[] b = new byte[100];
                vhdxReaders[i].Seek(i * 100, SeekOrigin.Begin);
                int r = vhdxReaders[i].Read(b, 0, 100);
                Check(r == 100 && b[0] == payload[i * 100], "Concurrent VHDX reader " + i + " read successfully");
                vhdxReaders[i].Dispose();
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // SYNTHETIC GENERATOR HELPERS
    // =========================================================================

    private static byte[] CreateSyntheticFixedVhd(byte[] payload)
    {
        long diskSize = payload.Length;
        byte[] vhd = new byte[diskSize + 512];
        Array.Copy(payload, 0, vhd, 0, payload.Length);

        byte[] footer = new byte[512];
        Encoding.ASCII.GetBytes("conectix").CopyTo(footer, 0);
        footer[11] = 0x02;
        footer[12] = 0; footer[13] = 1; footer[14] = 0; footer[15] = 0;
        for (int i = 16; i < 24; i++) footer[i] = 0xFF;

        uint ts = 100000;
        footer[24] = (byte)(ts >> 24); footer[25] = (byte)(ts >> 16);
        footer[26] = (byte)(ts >> 8);  footer[27] = (byte)ts;

        Encoding.ASCII.GetBytes("adv ").CopyTo(footer, 28);
        for (int i = 0; i < 8; i++)
        {
            byte b = (byte)((diskSize >> (8 * (7 - i))) & 0xFF);
            footer[40 + i] = b;
            footer[48 + i] = b;
        }

        footer[56] = 0x00; footer[57] = 0x04;
        footer[58] = 0x04; footer[59] = 0x11;
        footer[63] = 0x02; // Fixed

        Guid.NewGuid().ToByteArray().CopyTo(footer, 68);

        uint checksum = VhdImageReader.ComputeFooterChecksum(footer);
        footer[64] = (byte)(checksum >> 24); footer[65] = (byte)(checksum >> 16);
        footer[66] = (byte)(checksum >> 8);  footer[67] = (byte)checksum;

        Array.Copy(footer, 0, vhd, diskSize, 512);
        return vhd;
    }

    private static void CreateSyntheticDynamicVhd(string vhdPath, long diskSize, int blockSize, byte[] block0, byte[] block1)
    {
        int numBlocks = (int)((diskSize + blockSize - 1) / blockSize);
        int batBytes = ((numBlocks * 4 + 511) / 512) * 512;

        int sectorsPerBlock = blockSize / 512;
        int bitmapBytes = ((sectorsPerBlock + 7) / 8);
        int bitmapSectorAligned = ((bitmapBytes + 511) / 512) * 512;

        using (FileStream fs = new FileStream(vhdPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            byte[] footer = new byte[512];
            Encoding.ASCII.GetBytes("conectix").CopyTo(footer, 0);
            footer[11] = 0x02;
            footer[12] = 0; footer[13] = 1; footer[14] = 0; footer[15] = 0;
            footer[22] = 0x02; footer[23] = 0x00;

            for (int i = 0; i < 8; i++)
            {
                byte b = (byte)((diskSize >> (8 * (7 - i))) & 0xFF);
                footer[40 + i] = b;
                footer[48 + i] = b;
            }
            footer[63] = 0x03; // Dynamic
            Guid.NewGuid().ToByteArray().CopyTo(footer, 68);
            uint footerChecksum = VhdImageReader.ComputeFooterChecksum(footer);
            footer[64] = (byte)(footerChecksum >> 24); footer[65] = (byte)(footerChecksum >> 16);
            footer[66] = (byte)(footerChecksum >> 8);  footer[67] = (byte)footerChecksum;
            fs.Write(footer, 0, 512);

            byte[] dyn = new byte[1024];
            Encoding.ASCII.GetBytes("cxsparse").CopyTo(dyn, 0);
            for (int i = 8; i < 16; i++) dyn[i] = 0xFF;
            dyn[22] = 0x06; dyn[23] = 0x00;
            dyn[25] = 0x01;
            dyn[30] = (byte)(numBlocks >> 8); dyn[31] = (byte)numBlocks;
            dyn[32] = (byte)(blockSize >> 24); dyn[33] = (byte)(blockSize >> 16);
            dyn[34] = (byte)(blockSize >> 8);  dyn[35] = (byte)blockSize;
            Guid.NewGuid().ToByteArray().CopyTo(dyn, 40);

            uint dynChecksum = VhdImageReader.ComputeDynamicHeaderChecksum(dyn);
            dyn[36] = (byte)(dynChecksum >> 24); dyn[37] = (byte)(dynChecksum >> 16);
            dyn[38] = (byte)(dynChecksum >> 8);  dyn[39] = (byte)dynChecksum;
            fs.Write(dyn, 0, 1024);

            long currentHostOffset = 1536 + batBytes;
            byte[] bat = new byte[batBytes];
            for (int i = 0; i < bat.Length; i++) bat[i] = 0xFF;

            uint block1Sector = (uint)(currentHostOffset / 512L);
            bat[4] = (byte)(block1Sector >> 24); bat[5] = (byte)(block1Sector >> 16);
            bat[6] = (byte)(block1Sector >> 8);  bat[7] = (byte)block1Sector;
            fs.Write(bat, 0, bat.Length);

            byte[] bitmap = new byte[bitmapSectorAligned];
            for (int i = 0; i < bitmapBytes; i++) bitmap[i] = 0xFF;
            fs.Write(bitmap, 0, bitmap.Length);
            fs.Write(block1, 0, block1.Length);

            fs.Write(footer, 0, 512);
        }
    }

    private static byte[] CreateSyntheticVhdx(byte[] payloadData, bool isDynamic)
    {
        uint blockSize = 1048576; // 1 MB
        ulong diskSize = isDynamic ? (2UL * blockSize) : (ulong)blockSize;
        byte[] vhdx = new byte[4 * 1024 * 1024];

        // 1. File Type Identifier
        Array.Copy(Encoding.ASCII.GetBytes("vhdxfile"), 0, vhdx, 0, 8);

        // 2. Header 1 at 0x10000 (64 KB)
        byte[] header1 = new byte[4096];
        Array.Copy(Encoding.ASCII.GetBytes("head"), 0, header1, 0, 4);
        BitConverter.GetBytes(1UL).CopyTo(header1, 8); // SequenceNumber = 1
        BitConverter.GetBytes((ushort)1).CopyTo(header1, 66); // Version = 1
        uint h1Crc = VhdxImageReader.ComputeCrc32c(header1, 0, 4096);
        BitConverter.GetBytes(h1Crc).CopyTo(header1, 4);
        Array.Copy(header1, 0, vhdx, 0x10000, 4096);

        // 3. Header 2 at 0x20000 (128 KB)
        byte[] header2 = new byte[4096];
        Array.Copy(Encoding.ASCII.GetBytes("head"), 0, header2, 0, 4);
        BitConverter.GetBytes(2UL).CopyTo(header2, 8); // SequenceNumber = 2
        BitConverter.GetBytes((ushort)1).CopyTo(header2, 66); // Version = 1
        uint h2Crc = VhdxImageReader.ComputeCrc32c(header2, 0, 4096);
        BitConverter.GetBytes(h2Crc).CopyTo(header2, 4);
        Array.Copy(header2, 0, vhdx, 0x20000, 4096);

        // 4. Region Table at 0x30000 (192 KB)
        byte[] regi = new byte[65536];
        Array.Copy(Encoding.ASCII.GetBytes("regi"), 0, regi, 0, 4);
        BitConverter.GetBytes(2U).CopyTo(regi, 8);

        Guid batGuid = new Guid("2DC27766-F623-4200-9D64-115E9BFD4A08");
        batGuid.ToByteArray().CopyTo(regi, 16);
        BitConverter.GetBytes(1048576UL).CopyTo(regi, 32);
        BitConverter.GetBytes(1048576U).CopyTo(regi, 40);
        BitConverter.GetBytes(1U).CopyTo(regi, 44);

        Guid metaGuid = new Guid("8B7D40A4-0796-4B43-AC8B-3B224F3A39E0");
        metaGuid.ToByteArray().CopyTo(regi, 48);
        BitConverter.GetBytes(2097152UL).CopyTo(regi, 64);
        BitConverter.GetBytes(1048576U).CopyTo(regi, 72);
        BitConverter.GetBytes(1U).CopyTo(regi, 76);

        uint rCrc = VhdxImageReader.ComputeCrc32c(regi, 0, 65536);
        BitConverter.GetBytes(rCrc).CopyTo(regi, 4);
        Array.Copy(regi, 0, vhdx, 0x30000, 65536);

        // 5. BAT Region at 1 MB (0x100000)
        ulong bat0 = (3UL << 20) | 6UL; // Fully present at 3 MB
        BitConverter.GetBytes(bat0).CopyTo(vhdx, 1048576);

        if (isDynamic)
        {
            BitConverter.GetBytes(0UL).CopyTo(vhdx, 1048576 + 8); // Not present
        }

        // 6. Metadata Region at 2 MB (0x200000)
        int metaBase = 2097152;
        Array.Copy(Encoding.ASCII.GetBytes("metadata"), 0, vhdx, metaBase, 8);
        BitConverter.GetBytes((ushort)4).CopyTo(vhdx, metaBase + 10);

        new Guid("CAA16737-FA36-4D43-B3B6-30F00AAEE56B").ToByteArray().CopyTo(vhdx, metaBase + 32);
        BitConverter.GetBytes(256U).CopyTo(vhdx, metaBase + 48);
        BitConverter.GetBytes(8U).CopyTo(vhdx, metaBase + 52);
        BitConverter.GetBytes(blockSize).CopyTo(vhdx, metaBase + 256);
        BitConverter.GetBytes(isDynamic ? 0U : 1U).CopyTo(vhdx, metaBase + 260);

        new Guid("2FA54261-B276-42FB-AA69-E3B10F7264F3").ToByteArray().CopyTo(vhdx, metaBase + 64);
        BitConverter.GetBytes(288U).CopyTo(vhdx, metaBase + 80);
        BitConverter.GetBytes(8U).CopyTo(vhdx, metaBase + 84);
        BitConverter.GetBytes(diskSize).CopyTo(vhdx, metaBase + 288);

        new Guid("8141214F-43CD-4529-A8BB-4D0E75E9B646").ToByteArray().CopyTo(vhdx, metaBase + 96);
        BitConverter.GetBytes(320U).CopyTo(vhdx, metaBase + 112);
        BitConverter.GetBytes(4U).CopyTo(vhdx, metaBase + 116);
        BitConverter.GetBytes(512U).CopyTo(vhdx, metaBase + 320);

        new Guid("CDA348C7-445D-4471-9CC9-E9885251C556").ToByteArray().CopyTo(vhdx, metaBase + 128);
        BitConverter.GetBytes(352U).CopyTo(vhdx, metaBase + 144);
        BitConverter.GetBytes(4U).CopyTo(vhdx, metaBase + 148);
        BitConverter.GetBytes(512U).CopyTo(vhdx, metaBase + 352);

        // 7. Payload Block 0 at 3 MB (0x300000)
        Array.Copy(payloadData, 0, vhdx, 3 * 1024 * 1024, Math.Min(payloadData.Length, (int)blockSize));

        return vhdx;
    }
}
