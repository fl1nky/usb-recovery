using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class VirtualDiskFormatStressTests
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
        {
            throw new Exception("Empirical stress check failed: " + message);
        }
    }

    public static void Main(string[] args)
    {
        Console.WriteLine("=== Starting Milestone 1 Virtual Disk Format Edge-Case Stress Tests ===");

        // --- VHD Format Stress Tests ---
        TestVhdTruncationAndShortFiles();
        TestVhdInvalidCookiesAndChecksums();
        TestVhdNonStandardBlockSizes();
        TestVhdAlternatingSectorBitmap();
        TestVhdZeroAndAllOneBlocks();

        // --- VHDX Format Stress Tests ---
        TestVhdxTruncationAndShortFiles();
        TestVhdxDualHeaderCorruptionAndFallback();
        TestVhdxBatAllocationStates();

        // --- VMDK Format Stress Tests ---
        TestVmdkMalformedDescriptorSyntax();
        TestVmdkMissingFlatExtent();
        TestVmdkSparseUnallocatedGrainDirectory();
        TestVmdkZeroExtentSyntaxThreeTokens();

        Console.WriteLine("=========================================================================");
        Console.WriteLine("ALL STRESS TESTS PASSED: {0} empirical checks verified across VHD, VHDX, and VMDK.", checks);
    }

    // =========================================================================
    // SECTION 1: VHD FORMAT EDGE CASES
    // =========================================================================

    private static void TestVhdTruncationAndShortFiles()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-stress-trunc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            int[] testSizes = new int[] { 0, 1, 16, 128, 256, 511 };
            for (int i = 0; i < testSizes.Length; i++)
            {
                int sz = testSizes[i];
                string filePath = Path.Combine(tempDir, string.Format("trunc_{0}.vhd", sz));
                File.WriteAllBytes(filePath, new byte[sz]);

                Check(!VhdImageReader.IsVhdFile(filePath),
                    string.Format("IsVhdFile must return false for truncated file of size {0} bytes", sz));

                bool threw = false;
                try
                {
                    using (VhdImageReader.Open(filePath)) { }
                }
                catch (InvalidDataException)
                {
                    threw = true;
                }
                Check(threw, string.Format("VhdImageReader.Open must throw InvalidDataException for truncated file of size {0} bytes", sz));
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdInvalidCookiesAndChecksums()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-stress-cookies-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            byte[] validFixed = CreateSyntheticFixedVhd(new byte[1024]);

            // Case 1: Bad footer cookie
            byte[] badFooterCookie = (byte[])validFixed.Clone();
            Encoding.ASCII.GetBytes("badcooki").CopyTo(badFooterCookie, badFooterCookie.Length - 512);
            string badFooterPath = Path.Combine(tempDir, "bad_footer_cookie.vhd");
            File.WriteAllBytes(badFooterPath, badFooterCookie);

            Check(!VhdImageReader.IsVhdFile(badFooterPath), "IsVhdFile returns false on invalid footer cookie");
            bool threwBadCookie = false;
            try
            {
                using (VhdImageReader.Open(badFooterPath)) { }
            }
            catch (InvalidDataException)
            {
                threwBadCookie = true;
            }
            Check(threwBadCookie, "Open throws InvalidDataException on invalid footer cookie");

            // Case 2: Dynamic VHD with bad dynamic header cookie
            byte[] validDynamic = CreateSyntheticDynamicVhd(new byte[1024], 524288);
            byte[] badDynamicCookie = (byte[])validDynamic.Clone();
            Encoding.ASCII.GetBytes("badparse").CopyTo(badDynamicCookie, 512); // Offset 512 is dynamic header
            // Recompute footer checksum because offset 0 has header copy
            string badDynamicPath = Path.Combine(tempDir, "bad_dyn_cookie.vhd");
            File.WriteAllBytes(badDynamicPath, badDynamicCookie);

            bool threwBadDynCookie = false;
            try
            {
                using (VhdImageReader.Open(badDynamicPath)) { }
            }
            catch (InvalidDataException)
            {
                threwBadDynCookie = true;
            }
            Check(threwBadDynCookie, "Open throws InvalidDataException on invalid dynamic header cookie");

            // Case 3: Dynamic VHD with corrupted dynamic header checksum
            byte[] badDynCsum = (byte[])validDynamic.Clone();
            badDynCsum[512 + 36] ^= 0xFF; // Invert dynamic header checksum byte
            string badDynCsumPath = Path.Combine(tempDir, "bad_dyn_csum.vhd");
            File.WriteAllBytes(badDynCsumPath, badDynCsum);

            bool threwBadDynCsum = false;
            try
            {
                using (VhdImageReader.Open(badDynCsumPath)) { }
            }
            catch (InvalidDataException)
            {
                threwBadDynCsum = true;
            }
            Check(threwBadDynCsum, "Open throws InvalidDataException on invalid dynamic header checksum");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdNonStandardBlockSizes()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-stress-blocks-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            // Standard VHD block size is 2 MB (2,097,152 bytes).
            // Test non-standard power-of-2 block size: 512 KB (524,288 bytes)
            uint nonStdBlockSize = 524288;
            byte[] payload = new byte[nonStdBlockSize];
            for (int i = 0; i < payload.Length; i++) payload[i] = (byte)((i * 13) % 251);

            byte[] vhdData = CreateSyntheticDynamicVhd(payload, nonStdBlockSize);
            string vhdPath = Path.Combine(tempDir, "non_std_512k.vhd");
            File.WriteAllBytes(vhdPath, vhdData);

            Check(VhdImageReader.IsVhdFile(vhdPath), "IsVhdFile recognizes 512KB block size dynamic VHD");

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                Check(reader.DynamicHeader != null, "DynamicHeader is present");
                Check(reader.DynamicHeader.BlockSize == nonStdBlockSize, "BlockSize parsed as 524288");
                Check(reader.Length == 2L * nonStdBlockSize, "Virtual disk length is 1048576 (2 * 512KB)");

                // Read full allocated block 0
                byte[] readBuf = new byte[nonStdBlockSize];
                int r = reader.Read(readBuf, 0, (int)nonStdBlockSize);
                Check(r == nonStdBlockSize, "Read 524288 bytes from block 0");
                bool match = true;
                for (int i = 0; i < nonStdBlockSize; i++)
                {
                    if (readBuf[i] != payload[i]) { match = false; break; }
                }
                Check(match, "Block 0 data matches 512KB payload");

                // Read unallocated block 1 (must be all zeroes)
                byte[] unallocatedBuf = new byte[1024];
                reader.Seek(nonStdBlockSize, SeekOrigin.Begin);
                int rUnalloc = reader.Read(unallocatedBuf, 0, 1024);
                Check(rUnalloc == 1024, "Read 1024 bytes from unallocated block 1");
                bool allZero = true;
                for (int i = 0; i < 1024; i++) if (unallocatedBuf[i] != 0) { allZero = false; break; }
                Check(allZero, "Unallocated block 1 returns zeroes");

                // Straddle read across the 512KB boundary
                reader.Seek(nonStdBlockSize - 512, SeekOrigin.Begin);
                byte[] straddleBuf = new byte[1024];
                int rStraddle = reader.Read(straddleBuf, 0, 1024);
                Check(rStraddle == 1024, "Straddle read returned 1024 bytes");
                for (int i = 0; i < 512; i++)
                {
                    if (straddleBuf[i] != payload[nonStdBlockSize - 512 + i])
                        throw new Exception("Straddle block 0 mismatch");
                }
                for (int i = 512; i < 1024; i++)
                {
                    if (straddleBuf[i] != 0) throw new Exception("Straddle block 1 zero mismatch");
                }
            }

            // Test non-power-of-2 block size rejection
            // Construct dynamic header with blockSize = 300000
            byte[] invalidBlockVhd = (byte[])vhdData.Clone();
            uint badBlockSize = 300000U;
            invalidBlockVhd[512 + 32] = (byte)(badBlockSize >> 24);
            invalidBlockVhd[512 + 33] = (byte)(badBlockSize >> 16);
            invalidBlockVhd[512 + 34] = (byte)(badBlockSize >> 8);
            invalidBlockVhd[512 + 35] = (byte)badBlockSize;
            // Update dynamic header checksum
            byte[] dynHdr = new byte[1024];
            Array.Copy(invalidBlockVhd, 512, dynHdr, 0, 1024);
            dynHdr[36] = 0; dynHdr[37] = 0; dynHdr[38] = 0; dynHdr[39] = 0;
            uint newCsum = VhdImageReader.ComputeDynamicHeaderChecksum(dynHdr);
            invalidBlockVhd[512 + 36] = (byte)(newCsum >> 24);
            invalidBlockVhd[512 + 37] = (byte)(newCsum >> 16);
            invalidBlockVhd[512 + 38] = (byte)(newCsum >> 8);
            invalidBlockVhd[512 + 39] = (byte)newCsum;

            string invalidBlockPath = Path.Combine(tempDir, "bad_block_size.vhd");
            File.WriteAllBytes(invalidBlockPath, invalidBlockVhd);

            bool threwNonPowerOf2 = false;
            try
            {
                using (VhdImageReader.Open(invalidBlockPath)) { }
            }
            catch (InvalidDataException)
            {
                threwNonPowerOf2 = true;
            }
            Check(threwNonPowerOf2, "Open throws InvalidDataException for non-power-of-2 block size");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdAlternatingSectorBitmap()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-stress-bitmap-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            uint blockSize = 524288; // 512 KB = 1024 sectors
            byte[] blockData = new byte[blockSize];

            // Fill each sector with distinct payload byte: sector s -> byte (s % 250 + 1)
            for (int s = 0; s < 1024; s++)
            {
                byte val = (byte)(s % 250 + 1);
                for (int b = 0; b < 512; b++)
                {
                    blockData[s * 512 + b] = val;
                }
            }

            // Create alternating sector bitmap: 0xAA (10101010b in big-endian)
            // Even sectors (0, 2, 4...) have bit 1 (allocated -> read returns blockData)
            // Odd sectors (1, 3, 5...) have bit 0 (unallocated -> read returns 0)
            byte[] alternatingBitmap = new byte[512];
            for (int i = 0; i < alternatingBitmap.Length; i++)
            {
                alternatingBitmap[i] = 0xAA;
            }

            byte[] vhdData = CreateCustomDynamicVhdWithBitmap(blockData, alternatingBitmap, blockSize);
            string vhdPath = Path.Combine(tempDir, "alternating_bitmap.vhd");
            File.WriteAllBytes(vhdPath, vhdData);

            using (VhdImageReader reader = VhdImageReader.Open(vhdPath))
            {
                // Verify each sector individually
                byte[] sectorBuf = new byte[512];
                for (int s = 0; s < 16; s++)
                {
                    reader.Seek((long)s * 512L, SeekOrigin.Begin);
                    int r = reader.Read(sectorBuf, 0, 512);
                    Check(r == 512, string.Format("Read sector {0} returned 512 bytes", s));

                    if ((s % 2) == 0)
                    {
                        // Even sector: allocated
                        byte expected = (byte)(s % 250 + 1);
                        bool secMatch = true;
                        for (int b = 0; b < 512; b++)
                        {
                            if (sectorBuf[b] != expected) { secMatch = false; break; }
                        }
                        Check(secMatch, string.Format("Allocated sector {0} matched expected payload byte 0x{1:X2}", s, expected));
                    }
                    else
                    {
                        // Odd sector: unallocated -> zeroes
                        bool secZero = true;
                        for (int b = 0; b < 512; b++)
                        {
                            if (sectorBuf[b] != 0) { secZero = false; break; }
                        }
                        Check(secZero, string.Format("Unallocated sector {0} returned all zeroes", s));
                    }
                }

                // Verify multi-sector straddle read across alternating sectors (e.g. sectors 0..3 = 2048 bytes)
                reader.Seek(0, SeekOrigin.Begin);
                byte[] multiBuf = new byte[2048];
                int multiRead = reader.Read(multiBuf, 0, 2048);
                Check(multiRead == 2048, "Read 2048 bytes across alternating sectors");

                // Sector 0 (0..511): allocated with expected byte
                byte exp0 = (byte)(0 % 250 + 1);
                for (int i = 0; i < 512; i++) Check(multiBuf[i] == exp0, "Sector 0 byte verified");

                // Sector 1 (512..1023): zeroes
                for (int i = 512; i < 1023; i++) Check(multiBuf[i] == 0, "Sector 1 zero verified");

                // Sector 2 (1024..1535): allocated with expected byte
                byte exp2 = (byte)(2 % 250 + 1);
                for (int i = 1024; i < 1535; i++) Check(multiBuf[i] == exp2, "Sector 2 byte verified");

                // Sector 3 (1536..2047): zeroes
                for (int i = 1536; i < 2047; i++) Check(multiBuf[i] == 0, "Sector 3 zero verified");

                // Verify intra-sector offset reading across boundary
                // Seek to offset 256 (middle of sector 0) and read 768 bytes (256 of sec 0 + 512 of sec 1)
                reader.Seek(256, SeekOrigin.Begin);
                byte[] partialBuf = new byte[768];
                int partialRead = reader.Read(partialBuf, 0, 768);
                Check(partialRead == 768, "Read partial intra-sector buffer");
                for (int i = 0; i < 256; i++) Check(partialBuf[i] == exp0, "Intra-sector 0 data matches");
                for (int i = 256; i < 768; i++) Check(partialBuf[i] == 0, "Intra-sector 1 data is zero");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdZeroAndAllOneBlocks()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhd-stress-zeroone-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            uint blockSize = 524288;

            // Block with all zeroes
            byte[] zeroBlock = new byte[blockSize];
            byte[] vhdZero = CreateSyntheticDynamicVhd(zeroBlock, blockSize);
            string zeroPath = Path.Combine(tempDir, "all_zero.vhd");
            File.WriteAllBytes(zeroPath, vhdZero);

            using (VhdImageReader reader = VhdImageReader.Open(zeroPath))
            {
                byte[] buf = new byte[4096];
                int r = reader.Read(buf, 0, 4096);
                Check(r == 4096, "Read 4096 bytes from all-zero block");
                bool allZero = true;
                for (int i = 0; i < 4096; i++) if (buf[i] != 0) { allZero = false; break; }
                Check(allZero, "All-zero block verified");
            }

            // Block with all ones (0xFF)
            byte[] oneBlock = new byte[blockSize];
            for (int i = 0; i < oneBlock.Length; i++) oneBlock[i] = 0xFF;
            byte[] vhdOne = CreateSyntheticDynamicVhd(oneBlock, blockSize);
            string onePath = Path.Combine(tempDir, "all_one.vhd");
            File.WriteAllBytes(onePath, vhdOne);

            using (VhdImageReader reader = VhdImageReader.Open(onePath))
            {
                byte[] buf = new byte[4096];
                int r = reader.Read(buf, 0, 4096);
                Check(r == 4096, "Read 4096 bytes from all-one block");
                bool allOne = true;
                for (int i = 0; i < 4096; i++) if (buf[i] != 0xFF) { allOne = false; break; }
                Check(allOne, "All-one (0xFF) block verified");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // SECTION 2: VHDX FORMAT EDGE CASES
    // =========================================================================

    private static void TestVhdxTruncationAndShortFiles()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhdx-stress-trunc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            int[] testSizes = new int[] { 0, 8, 512, 1024, 4096, 65535 };
            for (int i = 0; i < testSizes.Length; i++)
            {
                int sz = testSizes[i];
                string filePath = Path.Combine(tempDir, string.Format("trunc_vhdx_{0}.vhdx", sz));
                File.WriteAllBytes(filePath, new byte[sz]);

                Check(!VhdxImageReader.IsVhdxFile(filePath),
                    string.Format("IsVhdxFile returns false for truncated VHDX of size {0}", sz));

                bool threw = false;
                try
                {
                    using (VhdxImageReader.Open(filePath)) { }
                }
                catch (InvalidDataException)
                {
                    threw = true;
                }
                Check(threw, string.Format("VhdxImageReader.Open throws InvalidDataException for truncated file of size {0}", sz));
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdxDualHeaderCorruptionAndFallback()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhdx-stress-dualhdr-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            byte[] payload = new byte[1048576];
            for (int i = 0; i < payload.Length; i++) payload[i] = 0x5A;

            // Generate synthetic VHDX with both Header 1 (seq=1) and Header 2 (seq=2)
            byte[] vhdxData = CreateSyntheticVhdxWithDualHeaders(payload, 1UL, 2UL);

            // Test Case 1: Corrupt Header 1 CRC32C -> must fall back to Header 2
            byte[] h1Corrupt = (byte[])vhdxData.Clone();
            h1Corrupt[0x10004] ^= 0xFF; // Invert Header 1 CRC
            string h1CorruptPath = Path.Combine(tempDir, "h1_corrupt.vhdx");
            File.WriteAllBytes(h1CorruptPath, h1Corrupt);

            using (VhdxImageReader reader = VhdxImageReader.Open(h1CorruptPath))
            {
                Check(reader.ActiveHeaderSequenceNumber == 2UL,
                    "Fallback to Header 2 succeeded with SequenceNumber = 2 when Header 1 CRC corrupted");

                byte[] buf = new byte[512];
                int r = reader.Read(buf, 0, 512);
                Check(r == 512, "Read from VHDX with Header 1 corrupted succeeded");
                Check(buf[0] == 0x5A, "Payload matches 0x5A");
            }

            // Test Case 2: Header 1 has higher sequence (seq=10), Header 2 has seq=2
            byte[] h1Higher = CreateSyntheticVhdxWithDualHeaders(payload, 10UL, 2UL);
            string h1HigherPath = Path.Combine(tempDir, "h1_higher.vhdx");
            File.WriteAllBytes(h1HigherPath, h1Higher);

            using (VhdxImageReader reader = VhdxImageReader.Open(h1HigherPath))
            {
                Check(reader.ActiveHeaderSequenceNumber == 10UL,
                    "Header 1 selected when SequenceNumber 10 > SequenceNumber 2");
            }

            // Test Case 3: Corrupt BOTH Header 1 and Header 2 CRC32C -> must throw InvalidDataException
            byte[] bothCorrupt = (byte[])vhdxData.Clone();
            bothCorrupt[0x10004] ^= 0xFF; // Corrupt H1 CRC
            bothCorrupt[0x20004] ^= 0xFF; // Corrupt H2 CRC
            string bothCorruptPath = Path.Combine(tempDir, "both_corrupt.vhdx");
            File.WriteAllBytes(bothCorruptPath, bothCorrupt);

            bool threwBothCorrupt = false;
            try
            {
                using (VhdxImageReader.Open(bothCorruptPath)) { }
            }
            catch (InvalidDataException)
            {
                threwBothCorrupt = true;
            }
            Check(threwBothCorrupt, "Open throws InvalidDataException when both Header 1 and Header 2 are corrupt");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVhdxBatAllocationStates()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vhdx-stress-bat-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            // Create a 6 MB virtual disk with 6 blocks of 1 MB each.
            // Block 0: State 6 (FULLY_PRESENT) with pattern 0x41 ('A')
            // Block 1: State 0 (PAYLOAD_BLOCK_NOT_PRESENT) -> zeroes
            // Block 2: State 2 (PAYLOAD_BLOCK_ZERO) -> zeroes
            // Block 3: State 3 (PAYLOAD_BLOCK_UNMAPPED) -> zeroes
            // Block 4: State 1 (PAYLOAD_BLOCK_UNDEFINED) -> zeroes
            // Block 5: State 6 (FULLY_PRESENT) with pattern 0x42 ('B')
            uint blockSize = 1048576; // 1 MB
            ulong totalDiskSize = 6UL * blockSize;

            byte[] vhdx = new byte[8 * 1024 * 1024]; // 8 MB file

            // 1. File Identifier
            Array.Copy(Encoding.ASCII.GetBytes("vhdxfile"), 0, vhdx, 0, 8);

            // 2. Header 1 at 0x10000
            byte[] header = new byte[4096];
            Array.Copy(Encoding.ASCII.GetBytes("head"), 0, header, 0, 4);
            BitConverter.GetBytes(1UL).CopyTo(header, 8);
            BitConverter.GetBytes((ushort)1).CopyTo(header, 66);
            uint hCrc = VhdxImageReader.ComputeCrc32c(header, 0, 4096);
            BitConverter.GetBytes(hCrc).CopyTo(header, 4);
            Array.Copy(header, 0, vhdx, 0x10000, 4096);

            // 3. Region Table at 0x30000
            byte[] regi = new byte[65536];
            Array.Copy(Encoding.ASCII.GetBytes("regi"), 0, regi, 0, 4);
            BitConverter.GetBytes(2U).CopyTo(regi, 8);

            // Region 0: BAT at 1 MB (0x100000)
            new Guid("2DC27766-F623-4200-9D64-115E9BFD4A08").ToByteArray().CopyTo(regi, 16);
            BitConverter.GetBytes(1048576UL).CopyTo(regi, 32);
            BitConverter.GetBytes(1048576U).CopyTo(regi, 40);
            BitConverter.GetBytes(1U).CopyTo(regi, 44);

            // Region 1: Metadata at 2 MB (0x200000)
            new Guid("8B7D40A4-0796-4B43-AC8B-3B224F3A39E0").ToByteArray().CopyTo(regi, 48);
            BitConverter.GetBytes(2097152UL).CopyTo(regi, 64);
            BitConverter.GetBytes(1048576U).CopyTo(regi, 72);
            BitConverter.GetBytes(1U).CopyTo(regi, 76);

            uint rCrc = VhdxImageReader.ComputeCrc32c(regi, 0, 65536);
            BitConverter.GetBytes(rCrc).CopyTo(regi, 4);
            Array.Copy(regi, 0, vhdx, 0x30000, 65536);

            // 4. BAT entries at 1 MB
            // Block 0: State 6, host offset 4 MB
            BitConverter.GetBytes((4UL << 20) | 6UL).CopyTo(vhdx, 1048576 + 0 * 8);
            // Block 1: State 0 (NOT_PRESENT)
            BitConverter.GetBytes(0UL).CopyTo(vhdx, 1048576 + 1 * 8);
            // Block 2: State 2 (ZERO)
            BitConverter.GetBytes(2UL).CopyTo(vhdx, 1048576 + 2 * 8);
            // Block 3: State 3 (UNMAPPED)
            BitConverter.GetBytes(3UL).CopyTo(vhdx, 1048576 + 3 * 8);
            // Block 4: State 1 (UNDEFINED)
            BitConverter.GetBytes(1UL).CopyTo(vhdx, 1048576 + 4 * 8);
            // Block 5: State 6, host offset 5 MB
            BitConverter.GetBytes((5UL << 20) | 6UL).CopyTo(vhdx, 1048576 + 5 * 8);

            // 5. Metadata Region at 2 MB
            int metaBase = 2097152;
            Array.Copy(Encoding.ASCII.GetBytes("metadata"), 0, vhdx, metaBase, 8);
            BitConverter.GetBytes((ushort)4).CopyTo(vhdx, metaBase + 10);

            // File Parameters
            new Guid("CAA16737-FA36-4D43-B3B6-30F00AAEE56B").ToByteArray().CopyTo(vhdx, metaBase + 32);
            BitConverter.GetBytes(256U).CopyTo(vhdx, metaBase + 48);
            BitConverter.GetBytes(8U).CopyTo(vhdx, metaBase + 52);
            BitConverter.GetBytes(blockSize).CopyTo(vhdx, metaBase + 256);
            BitConverter.GetBytes(0U).CopyTo(vhdx, metaBase + 260); // Dynamic

            // Virtual Disk Size
            new Guid("2FA54261-B276-42FB-AA69-E3B10F7264F3").ToByteArray().CopyTo(vhdx, metaBase + 64);
            BitConverter.GetBytes(288U).CopyTo(vhdx, metaBase + 80);
            BitConverter.GetBytes(8U).CopyTo(vhdx, metaBase + 84);
            BitConverter.GetBytes(totalDiskSize).CopyTo(vhdx, metaBase + 288);

            // Sector Sizes (512 / 512)
            new Guid("8141214F-43CD-4529-A8BB-4D0E75E9B646").ToByteArray().CopyTo(vhdx, metaBase + 96);
            BitConverter.GetBytes(320U).CopyTo(vhdx, metaBase + 112);
            BitConverter.GetBytes(4U).CopyTo(vhdx, metaBase + 116);
            BitConverter.GetBytes(512U).CopyTo(vhdx, metaBase + 320);

            new Guid("CDA348C7-445D-4471-9CC9-E9885251C556").ToByteArray().CopyTo(vhdx, metaBase + 128);
            BitConverter.GetBytes(352U).CopyTo(vhdx, metaBase + 144);
            BitConverter.GetBytes(4U).CopyTo(vhdx, metaBase + 148);
            BitConverter.GetBytes(512U).CopyTo(vhdx, metaBase + 352);

            // 6. Payload Data
            // Block 0 at 4 MB (0x400000) filled with 0x41
            for (int i = 0; i < (int)blockSize; i++) vhdx[4 * 1024 * 1024 + i] = 0x41;
            // Block 5 at 5 MB (0x500000) filled with 0x42
            for (int i = 0; i < (int)blockSize; i++) vhdx[5 * 1024 * 1024 + i] = 0x42;

            string batVhdxPath = Path.Combine(tempDir, "bat_states.vhdx");
            File.WriteAllBytes(batVhdxPath, vhdx);

            using (VhdxImageReader reader = VhdxImageReader.Open(batVhdxPath))
            {
                Check(reader.Length == (long)totalDiskSize, "VHDX total disk size matches 6 MB");

                // Test Block 0: Fully Present (0x41)
                byte[] b0 = new byte[512];
                int r0 = reader.Read(b0, 0, 512);
                Check(r0 == 512 && b0[0] == 0x41 && b0[511] == 0x41, "Block 0 (FULLY_PRESENT) returned 0x41");

                // Test Block 1: State 0 (NOT_PRESENT) -> zeroes
                reader.Seek(1 * 1024 * 1024, SeekOrigin.Begin);
                byte[] b1 = new byte[512];
                int r1 = reader.Read(b1, 0, 512);
                Check(r1 == 512, "Read 512 bytes from Block 1");
                bool b1Zero = true;
                for (int i = 0; i < 512; i++) if (b1[i] != 0) { b1Zero = false; break; }
                Check(b1Zero, "Block 1 (NOT_PRESENT) returned zeroes");

                // Test Block 2: State 2 (ZERO) -> zeroes
                reader.Seek(2 * 1024 * 1024, SeekOrigin.Begin);
                byte[] b2 = new byte[512];
                int r2 = reader.Read(b2, 0, 512);
                Check(r2 == 512, "Read 512 bytes from Block 2");
                bool b2Zero = true;
                for (int i = 0; i < 512; i++) if (b2[i] != 0) { b2Zero = false; break; }
                Check(b2Zero, "Block 2 (ZERO) returned zeroes");

                // Test Block 3: State 3 (UNMAPPED) -> zeroes
                reader.Seek(3 * 1024 * 1024, SeekOrigin.Begin);
                byte[] b3 = new byte[512];
                int r3 = reader.Read(b3, 0, 512);
                Check(r3 == 512, "Read 512 bytes from Block 3");
                bool b3Zero = true;
                for (int i = 0; i < 512; i++) if (b3[i] != 0) { b3Zero = false; break; }
                Check(b3Zero, "Block 3 (UNMAPPED) returned zeroes");

                // Test Block 4: State 1 (UNDEFINED) -> zeroes
                reader.Seek(4 * 1024 * 1024, SeekOrigin.Begin);
                byte[] b4 = new byte[512];
                int r4 = reader.Read(b4, 0, 512);
                Check(r4 == 512, "Read 512 bytes from Block 4");
                bool b4Zero = true;
                for (int i = 0; i < 512; i++) if (b4[i] != 0) { b4Zero = false; break; }
                Check(b4Zero, "Block 4 (UNDEFINED) returned zeroes");

                // Test Block 5: Fully Present (0x42)
                reader.Seek(5 * 1024 * 1024, SeekOrigin.Begin);
                byte[] b5 = new byte[512];
                int r5 = reader.Read(b5, 0, 512);
                Check(r5 == 512 && b5[0] == 0x42 && b5[511] == 0x42, "Block 5 (FULLY_PRESENT) returned 0x42");

                // Test Straddle read spanning Block 0 (allocated) into Block 1 (unallocated)
                reader.Seek(1048576 - 256, SeekOrigin.Begin);
                byte[] straddle = new byte[512];
                int rStraddle = reader.Read(straddle, 0, 512);
                Check(rStraddle == 512, "Read 512 bytes straddling Block 0 and Block 1");
                for (int i = 0; i < 256; i++) Check(straddle[i] == 0x41, "Straddle Block 0 matches 0x41");
                for (int i = 256; i < 512; i++) Check(straddle[i] == 0, "Straddle Block 1 matches zero");

                // Test Straddle read spanning Block 4 (unallocated) into Block 5 (allocated)
                reader.Seek(5 * 1024 * 1024 - 256, SeekOrigin.Begin);
                byte[] straddle2 = new byte[512];
                int rStraddle2 = reader.Read(straddle2, 0, 512);
                Check(rStraddle2 == 512, "Read 512 bytes straddling Block 4 and Block 5");
                for (int i = 0; i < 256; i++) Check(straddle2[i] == 0, "Straddle Block 4 matches zero");
                for (int i = 256; i < 512; i++) Check(straddle2[i] == 0x42, "Straddle Block 5 matches 0x42");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // SECTION 3: VMDK FORMAT EDGE CASES
    // =========================================================================

    private static void TestVmdkMalformedDescriptorSyntax()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-stress-malformed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            // Case 1: Descriptor with header but zero extent lines
            string noExtentsPath = Path.Combine(tempDir, "no_extents.vmdk");
            File.WriteAllText(noExtentsPath, "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\n");

            bool threwNoExtents = false;
            try
            {
                using (VmdkImageReader.Open(noExtentsPath)) { }
            }
            catch (InvalidDataException)
            {
                threwNoExtents = true;
            }
            Check(threwNoExtents, "Open throws InvalidDataException when VMDK descriptor has no extents");

            // Case 2: Descriptor with corrupt / invalid extent syntax
            string badSyntaxPath = Path.Combine(tempDir, "bad_syntax.vmdk");
            File.WriteAllText(badSyntaxPath, "# Disk DescriptorFile\nversion=1\nRW NOT_A_NUMBER FLAT \"disk-flat.vmdk\" 0\n");

            bool threwBadSyntax = false;
            try
            {
                using (VmdkImageReader.Open(badSyntaxPath)) { }
            }
            catch (InvalidDataException)
            {
                threwBadSyntax = true;
            }
            Check(threwBadSyntax, "Open throws InvalidDataException when extent line has non-numeric sector count");

            // Case 3: Empty VMDK file (0 bytes)
            string emptyVmdk = Path.Combine(tempDir, "empty.vmdk");
            File.WriteAllBytes(emptyVmdk, new byte[0]);

            Check(!VmdkImageReader.IsVmdkFile(emptyVmdk), "IsVmdkFile returns false for empty file");
            bool threwEmpty = false;
            try
            {
                using (VmdkImageReader.Open(emptyVmdk)) { }
            }
            catch (InvalidDataException)
            {
                threwEmpty = true;
            }
            Check(threwEmpty, "Open throws InvalidDataException for 0-byte VMDK file");

            // Case 4: File with random binary garbage (< 512 bytes)
            string garbagePath = Path.Combine(tempDir, "garbage.vmdk");
            File.WriteAllBytes(garbagePath, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

            Check(!VmdkImageReader.IsVmdkFile(garbagePath), "IsVmdkFile returns false for garbage bytes");
            bool threwGarbage = false;
            try
            {
                using (VmdkImageReader.Open(garbagePath)) { }
            }
            catch (InvalidDataException)
            {
                threwGarbage = true;
            }
            Check(threwGarbage, "Open throws InvalidDataException for binary garbage file");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkMissingFlatExtent()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-stress-missing-ext-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            string descPath = Path.Combine(tempDir, "missing_ext.vmdk");
            string missingExtentFile = "definitely_nonexistent_extent_file.vmdk";

            string desc = string.Format(
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=12345678\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 2048 FLAT \"{0}\" 0\n",
                missingExtentFile);

            File.WriteAllText(descPath, desc, Encoding.ASCII);

            Check(VmdkImageReader.IsVmdkFile(descPath), "IsVmdkFile recognizes flat descriptor even if extent is missing");

            bool threwNotFound = false;
            try
            {
                using (VmdkImageReader.Open(descPath)) { }
            }
            catch (FileNotFoundException ex)
            {
                threwNotFound = true;
                Check(ex.Message.IndexOf(missingExtentFile, StringComparison.OrdinalIgnoreCase) >= 0 ||
                      ex.FileName.IndexOf(missingExtentFile, StringComparison.OrdinalIgnoreCase) >= 0,
                      "FileNotFoundException contains missing extent filename");
            }
            Check(threwNotFound, "Open throws FileNotFoundException when flat extent file is missing");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkSparseUnallocatedGrainDirectory()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-stress-sparse-gd-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            // Construct a sparse VMDK with 2 Grain Directory entries.
            // Grain size = 128 sectors (64 KB).
            // NumGTEsPerGT = 512.
            // 1 Grain Table covers 512 * 64 KB = 32 MB (65,536 sectors).
            // Capacity = 131,072 sectors (64 MB = 2 Grain Tables = 2 GD entries).
            // GD[0] -> Sector 4 (GT 0)
            //   GT 0:
            //     GTE[0] -> Sector 128 (allocated grain, payload 0x7E)
            //     GTE[1] -> 0 (unallocated grain in allocated GD)
            //     GTE[2] -> Sector 256 (allocated grain, payload 0x7F)
            // GD[1] -> 0 (UNALLOCATED GRAIN DIRECTORY ENTRY -> covers virtual offsets 32 MB..64 MB)

            ulong capacitySectors = 131072; // 64 MB
            byte[] vmdk = new byte[256 * 1024]; // 256 KB file

            // 1. SparseExtentHeader at sector 0
            BitConverter.GetBytes(0x564D444BU).CopyTo(vmdk, 0); // "VMDK"
            BitConverter.GetBytes(1U).CopyTo(vmdk, 4);
            BitConverter.GetBytes(0x00010000U).CopyTo(vmdk, 8);
            BitConverter.GetBytes(capacitySectors).CopyTo(vmdk, 12);
            BitConverter.GetBytes(128UL).CopyTo(vmdk, 20); // GrainSize = 128 sectors (64 KB)
            BitConverter.GetBytes(1UL).CopyTo(vmdk, 28);   // DescriptorOffset = 1
            BitConverter.GetBytes(1UL).CopyTo(vmdk, 36);   // DescriptorSize = 1
            BitConverter.GetBytes(512U).CopyTo(vmdk, 44);  // NumGTEsPerGT = 512
            BitConverter.GetBytes(0UL).CopyTo(vmdk, 48);   // RgdOffset = 0
            BitConverter.GetBytes(2UL).CopyTo(vmdk, 56);   // GdOffset = 2 (offset 1024)
            BitConverter.GetBytes(128UL).CopyTo(vmdk, 64); // OverHead = 128
            vmdk[72] = 0;
            vmdk[73] = 0x0A; vmdk[74] = 0x20; vmdk[75] = 0x0D; vmdk[76] = 0x0A;
            BitConverter.GetBytes((ushort)0).CopyTo(vmdk, 77); // Uncompressed

            // 2. Embedded Descriptor at sector 1 (offset 512)
            string desc = "# Disk DescriptorFile\ncreateType=\"monolithicSparse\"\n";
            Encoding.ASCII.GetBytes(desc).CopyTo(vmdk, 512);

            // 3. Grain Directory at sector 2 (offset 1024)
            // GD has 2 entries (8 bytes):
            // GD[0] = 4 (Sector 4 = offset 2048)
            BitConverter.GetBytes(4U).CopyTo(vmdk, 1024);
            // GD[1] = 0 (Unallocated Grain Directory entry!)
            BitConverter.GetBytes(0U).CopyTo(vmdk, 1028);

            // 4. Grain Table 0 at sector 4 (offset 2048)
            // GTE[0] = 128 (Sector 128 = offset 65536) -> allocated grain
            BitConverter.GetBytes(128U).CopyTo(vmdk, 2048 + 0 * 4);
            // GTE[1] = 0 (Unallocated grain)
            BitConverter.GetBytes(0U).CopyTo(vmdk, 2048 + 1 * 4);
            // GTE[2] = 256 (Sector 256 = offset 131072) -> allocated grain
            BitConverter.GetBytes(256U).CopyTo(vmdk, 2048 + 2 * 4);

            // 5. Payload Data
            // Grain 0 at sector 128 (offset 65536, length 65536) filled with 0x7E
            for (int i = 0; i < 65536; i++) vmdk[65536 + i] = 0x7E;
            // Grain 2 at sector 256 (offset 131072, length 65536) filled with 0x7F
            for (int i = 0; i < 65536; i++) vmdk[131072 + i] = 0x7F;

            string sparsePath = Path.Combine(tempDir, "unalloc_gd.vmdk");
            File.WriteAllBytes(sparsePath, vmdk);

            using (VmdkImageReader reader = VmdkImageReader.Open(sparsePath))
            {
                Check(reader.Length == 67108864L, "Virtual disk length is 64 MB (131072 * 512)");
                Check(reader.Subformat == VmdkSubformat.MonolithicSparse, "Subformat is MonolithicSparse");

                // Test 1: Read Grain 0 (allocated, GD[0], GTE[0])
                byte[] g0 = new byte[1024];
                int r0 = reader.Read(g0, 0, 1024);
                Check(r0 == 1024 && g0[0] == 0x7E && g0[1023] == 0x7E, "Grain 0 returned 0x7E");

                // Test 2: Read Grain 1 (unallocated GTE in allocated GD[0], offset 64 KB)
                reader.Seek(65536, SeekOrigin.Begin);
                byte[] g1 = new byte[1024];
                int r1 = reader.Read(g1, 0, 1024);
                Check(r1 == 1024, "Read 1024 bytes from unallocated GTE 1");
                bool g1Zero = true;
                for (int i = 0; i < 1024; i++) if (g1[i] != 0) { g1Zero = false; break; }
                Check(g1Zero, "Unallocated GTE 1 returned zeroes");

                // Test 3: Read Grain 2 (allocated, GD[0], GTE[2], offset 128 KB)
                reader.Seek(131072, SeekOrigin.Begin);
                byte[] g2 = new byte[1024];
                int r2 = reader.Read(g2, 0, 1024);
                Check(r2 == 1024 && g2[0] == 0x7F && g2[1023] == 0x7F, "Grain 2 returned 0x7F");

                // Test 4: Read from Unallocated Grain Directory entry GD[1] (offset 32 MB = 33,554,432)
                reader.Seek(33554432L, SeekOrigin.Begin);
                byte[] gd1Buf = new byte[4096];
                int rGd1 = reader.Read(gd1Buf, 0, 4096);
                Check(rGd1 == 4096, "Read 4096 bytes from unallocated GD[1]");
                bool gd1Zero = true;
                for (int i = 0; i < 4096; i++) if (gd1Buf[i] != 0) { gd1Zero = false; break; }
                Check(gd1Zero, "Unallocated Grain Directory entry GD[1] returned clean zeroes");

                // Test 5: Read from near end of virtual disk in unallocated GD[1] (offset 64 MB - 512)
                reader.Seek(67108864L - 512L, SeekOrigin.Begin);
                byte[] endBuf = new byte[512];
                int rEnd = reader.Read(endBuf, 0, 512);
                Check(rEnd == 512, "Read 512 bytes from end of unallocated GD[1]");
                bool endZero = true;
                for (int i = 0; i < 512; i++) if (endBuf[i] != 0) { endZero = false; break; }
                Check(endZero, "End of unallocated GD[1] returned zeroes");

                // Test 6: Straddle read across Grain 0 (allocated) and Grain 1 (unallocated GTE)
                reader.Seek(65536 - 256, SeekOrigin.Begin);
                byte[] straddleG0G1 = new byte[512];
                int rStraddle = reader.Read(straddleG0G1, 0, 512);
                Check(rStraddle == 512, "Read 512 bytes straddling Grain 0 and Grain 1");
                for (int i = 0; i < 256; i++) Check(straddleG0G1[i] == 0x7E, "Grain 0 portion matches 0x7E");
                for (int i = 256; i < 512; i++) Check(straddleG0G1[i] == 0, "Grain 1 portion matches zero");

                // Test 7: Straddle read across boundary of GD[0] and GD[1] (at 32 MB)
                reader.Seek(33554432L - 512L, SeekOrigin.Begin);
                byte[] straddleGd = new byte[1024];
                int rStraddleGd = reader.Read(straddleGd, 0, 1024);
                Check(rStraddleGd == 1024, "Read 1024 bytes straddling GD[0] and GD[1]");
                bool straddleGdZero = true;
                for (int i = 0; i < 1024; i++) if (straddleGd[i] != 0) { straddleGdZero = false; break; }
                Check(straddleGdZero, "Straddle GD[0] unallocated GTE and GD[1] unallocated GD returned all zeroes");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestVmdkZeroExtentSyntaxThreeTokens()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-stress-zero-token-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            string flatPath = Path.Combine(tempDir, "flat.vmdk");
            byte[] flatData = new byte[32768]; // 64 sectors
            for (int i = 0; i < flatData.Length; i++) flatData[i] = 0xAA;
            File.WriteAllBytes(flatPath, flatData);

            // Case A: 5-token workaround syntax: RW 64 ZERO "none" 0
            string descWorkaroundPath = Path.Combine(tempDir, "workaround.vmdk");
            string descWorkaround = string.Format(
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=12345678\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 64 ZERO \"none\" 0\n" +
                "RW 64 FLAT \"{0}\" 0\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n",
                Path.GetFileName(flatPath));
            File.WriteAllText(descWorkaroundPath, descWorkaround, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descWorkaroundPath))
            {
                Check(reader.Length == 65536L, "5-token ZERO extent accepts total length 65536");
                Check(reader.Extents.Count == 2, "5-token ZERO extent includes both extents");
                byte[] zBuf = new byte[512];
                reader.Read(zBuf, 0, 512);
                bool isZero = true;
                for (int i = 0; i < 512; i++) if (zBuf[i] != 0) { isZero = false; break; }
                Check(isZero, "5-token ZERO extent returns zero bytes");
            }

            // Case B: Standard 3-token VMware syntax: RW 64 ZERO
            string descStandardPath = Path.Combine(tempDir, "standard.vmdk");
            string descStandard = string.Format(
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
            File.WriteAllText(descStandardPath, descStandard, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descStandardPath))
            {
                // VERIFICATION OF ZERO EXTENT FIX:
                // Standard VMware specification syntax for ZERO extents is 3 tokens: "RW <sectors> ZERO".
                // VmdkImageReader.cs now accepts 3-token ZERO extents.
                bool parsedThreeTokenZero = (reader.Length == 65536L && reader.Extents.Count == 2);
                Check(parsedThreeTokenZero,
                    "Empirically confirmed fixed: VmdkImageReader.cs parses standard 3-token 'RW <sectors> ZERO' extents (length 65536, extents 2).");
                Console.WriteLine("  [FINDING VERIFIED FIXED]: VmdkImageReader correctly parses 3-token 'RW 64 ZERO' extents (disk length={0}, extents={1}).", reader.Length, reader.Extents.Count);
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    // =========================================================================
    // HELPER FIXTURE GENERATORS
    // =========================================================================

    private static byte[] CreateSyntheticFixedVhd(byte[] guestPayload)
    {
        long diskSize = guestPayload.Length;
        byte[] vhd = new byte[diskSize + 512];
        Array.Copy(guestPayload, 0, vhd, 0, guestPayload.Length);

        byte[] footer = new byte[512];
        Encoding.ASCII.GetBytes("conectix").CopyTo(footer, 0);
        footer[11] = 0x02;
        footer[12] = 0; footer[13] = 1; footer[14] = 0; footer[15] = 0;
        for (int i = 16; i < 24; i++) footer[i] = 0xFF;

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

        footer[56] = 0; footer[57] = 1; footer[58] = 1; footer[59] = 1;
        footer[63] = 2; // Fixed
        Guid.NewGuid().ToByteArray().CopyTo(footer, 68);

        uint csum = VhdImageReader.ComputeFooterChecksum(footer);
        footer[64] = (byte)(csum >> 24); footer[65] = (byte)(csum >> 16);
        footer[66] = (byte)(csum >> 8);  footer[67] = (byte)csum;

        Array.Copy(footer, 0, vhd, diskSize, 512);
        return vhd;
    }

    private static byte[] CreateSyntheticDynamicVhd(byte[] block0Data, uint blockSize)
    {
        int bitmapBytes = (int)(((blockSize / 512) / 8 + 511) / 512) * 512;
        byte[] customBitmap = new byte[bitmapBytes];
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
        footer[11] = 0x02;
        footer[12] = 0; footer[13] = 1; footer[14] = 0; footer[15] = 0;
        footer[22] = 0x02; footer[23] = 0x00; // Data Offset = 512

        for (int i = 0; i < 8; i++)
        {
            byte b = (byte)((virtualDiskSize >> (8 * (7 - i))) & 0xFF);
            footer[40 + i] = b; footer[48 + i] = b;
        }
        footer[63] = 3; // Dynamic
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
        dynHeader[22] = 0x06; dynHeader[23] = 0x00; // Table Offset = 1536
        dynHeader[25] = 0x01; // Version = 1.0
        dynHeader[31] = 2; // Max Table Entries = 2

        dynHeader[32] = (byte)(blockSize >> 24); dynHeader[33] = (byte)(blockSize >> 16);
        dynHeader[34] = (byte)(blockSize >> 8);  dynHeader[35] = (byte)blockSize;

        uint hCsum = VhdImageReader.ComputeDynamicHeaderChecksum(dynHeader);
        dynHeader[36] = (byte)(hCsum >> 24); dynHeader[37] = (byte)(hCsum >> 16);
        dynHeader[38] = (byte)(hCsum >> 8);  dynHeader[39] = (byte)hCsum;

        Array.Copy(dynHeader, 0, vhd, 512, 1024);

        // 3. BAT: Entry 0 = sector 4 (2048 / 512), Entry 1 = 0xFFFFFFFF
        vhd[1536] = 0; vhd[1537] = 0; vhd[1538] = 0; vhd[1539] = 4;
        vhd[1540] = 0xFF; vhd[1541] = 0xFF; vhd[1542] = 0xFF; vhd[1543] = 0xFF;

        // 4. Sector Bitmap
        Array.Copy(sectorBitmap, 0, vhd, block0Offset, Math.Min(sectorBitmap.Length, bitmapBytes));

        // 5. Payload
        Array.Copy(block0Data, 0, vhd, block0DataOffset, block0Data.Length);

        return vhd;
    }

    private static byte[] CreateSyntheticVhdxWithDualHeaders(byte[] payloadData, ulong seqH1, ulong seqH2)
    {
        uint blockSize = 1048576;
        ulong diskSize = (ulong)blockSize;
        byte[] vhdx = new byte[4 * 1024 * 1024];

        // 1. File Identifier
        Array.Copy(Encoding.ASCII.GetBytes("vhdxfile"), 0, vhdx, 0, 8);

        // 2. Header 1 at 0x10000
        byte[] h1 = new byte[4096];
        Array.Copy(Encoding.ASCII.GetBytes("head"), 0, h1, 0, 4);
        BitConverter.GetBytes(seqH1).CopyTo(h1, 8);
        BitConverter.GetBytes((ushort)1).CopyTo(h1, 66);
        uint h1Crc = VhdxImageReader.ComputeCrc32c(h1, 0, 4096);
        BitConverter.GetBytes(h1Crc).CopyTo(h1, 4);
        Array.Copy(h1, 0, vhdx, 0x10000, 4096);

        // 3. Header 2 at 0x20000
        byte[] h2 = new byte[4096];
        Array.Copy(Encoding.ASCII.GetBytes("head"), 0, h2, 0, 4);
        BitConverter.GetBytes(seqH2).CopyTo(h2, 8);
        BitConverter.GetBytes((ushort)1).CopyTo(h2, 66);
        uint h2Crc = VhdxImageReader.ComputeCrc32c(h2, 0, 4096);
        BitConverter.GetBytes(h2Crc).CopyTo(h2, 4);
        Array.Copy(h2, 0, vhdx, 0x20000, 4096);

        // 4. Region Table at 0x30000
        byte[] regi = new byte[65536];
        Array.Copy(Encoding.ASCII.GetBytes("regi"), 0, regi, 0, 4);
        BitConverter.GetBytes(2U).CopyTo(regi, 8);

        // BAT Region at 1 MB
        new Guid("2DC27766-F623-4200-9D64-115E9BFD4A08").ToByteArray().CopyTo(regi, 16);
        BitConverter.GetBytes(1048576UL).CopyTo(regi, 32);
        BitConverter.GetBytes(1048576U).CopyTo(regi, 40);
        BitConverter.GetBytes(1U).CopyTo(regi, 44);

        // Metadata Region at 2 MB
        new Guid("8B7D40A4-0796-4B43-AC8B-3B224F3A39E0").ToByteArray().CopyTo(regi, 48);
        BitConverter.GetBytes(2097152UL).CopyTo(regi, 64);
        BitConverter.GetBytes(1048576U).CopyTo(regi, 72);
        BitConverter.GetBytes(1U).CopyTo(regi, 76);

        uint rCrc = VhdxImageReader.ComputeCrc32c(regi, 0, 65536);
        BitConverter.GetBytes(rCrc).CopyTo(regi, 4);
        Array.Copy(regi, 0, vhdx, 0x30000, 65536);

        // 5. BAT Region at 1 MB: Block 0 -> 3 MB, State 6
        ulong bat0 = (3UL << 20) | 6UL;
        BitConverter.GetBytes(bat0).CopyTo(vhdx, 1048576);

        // 6. Metadata at 2 MB
        int metaBase = 2097152;
        Array.Copy(Encoding.ASCII.GetBytes("metadata"), 0, vhdx, metaBase, 8);
        BitConverter.GetBytes((ushort)4).CopyTo(vhdx, metaBase + 10);

        new Guid("CAA16737-FA36-4D43-B3B6-30F00AAEE56B").ToByteArray().CopyTo(vhdx, metaBase + 32);
        BitConverter.GetBytes(256U).CopyTo(vhdx, metaBase + 48);
        BitConverter.GetBytes(8U).CopyTo(vhdx, metaBase + 52);
        BitConverter.GetBytes(blockSize).CopyTo(vhdx, metaBase + 256);
        BitConverter.GetBytes(1U).CopyTo(vhdx, metaBase + 260); // Fixed

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

        // 7. Payload Block 0 at 3 MB
        Array.Copy(payloadData, 0, vhdx, 3 * 1024 * 1024, Math.Min(payloadData.Length, (int)blockSize));

        return vhdx;
    }
}
