using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class EmpiricalVmdkZeroExtentProbes
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
        {
            throw new Exception("EMPIRICAL CHECK FAILED: " + message);
        }
    }

    public static void Main(string[] args)
    {
        Console.WriteLine("=== Starting Empirical VMDK ZERO Extent Challenge Probes ===");

        TestComplexAlternatingExtents();
        TestAccessModeVariations();
        TestPureZeroVirtualDisks();
        TestRejectionOfMalformedDescriptors();
        TestSeekingAndEofBoundaries();
        TestWriteBlockingAndDisposal();

        Console.WriteLine("============================================================");
        Console.WriteLine("ALL EMPIRICAL PROBES PASSED: {0} checks verified.", checks);
    }

    private static void TestComplexAlternatingExtents()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-probe-alt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // Extent 0: ZERO (16 sectors = 8,192 bytes)
            // Extent 1: FLAT "flat1.bin" 0 (32 sectors = 16,384 bytes)
            // Extent 2: ZERO (48 sectors = 24,576 bytes)
            // Extent 3: FLAT "flat2.bin" 0 (64 sectors = 32,768 bytes)
            // Total sectors: 160 sectors = 81,920 bytes.
            string flat1Path = Path.Combine(tempDir, "flat1.bin");
            string flat2Path = Path.Combine(tempDir, "flat2.bin");

            byte[] flat1Payload = new byte[16384];
            for (int i = 0; i < flat1Payload.Length; i++) flat1Payload[i] = (byte)((i * 17 + 3) & 0xFF);
            File.WriteAllBytes(flat1Path, flat1Payload);

            byte[] flat2Payload = new byte[32768];
            for (int i = 0; i < flat2Payload.Length; i++) flat2Payload[i] = (byte)((i * 31 + 19) & 0xFF);
            File.WriteAllBytes(flat2Path, flat2Payload);

            // Construct expected full virtual disk oracle (81,920 bytes)
            byte[] oracle = new byte[81920];
            // 0..8191 are 0
            // 8192..24575 are flat1Payload
            Array.Copy(flat1Payload, 0, oracle, 8192, 16384);
            // 24576..49151 are 0
            // 49152..81919 are flat2Payload
            Array.Copy(flat2Payload, 0, oracle, 49152, 32768);

            string descPath = Path.Combine(tempDir, "disk_alt.vmdk");
            string descContent =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=1a2b3c4d\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "RW 16 ZERO\n" +
                "RW 32 FLAT \"flat1.bin\" 0\n" +
                "RW 48 ZERO\n" +
                "RW 64 FLAT \"flat2.bin\" 0\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n";
            File.WriteAllText(descPath, descContent, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                Check(reader.Length == 81920L, "Disk Length is exactly 81,920 bytes: " + reader.Length);
                Check(reader.Extents.Count == 4, "Extents count is 4: " + reader.Extents.Count);

                // Verify extent metadata
                Check(reader.Extents[0].Type == "ZERO" && reader.Extents[0].SectorCount == 16 && reader.Extents[0].GuestStartSector == 0, "Extent 0 metadata verified");
                Check(reader.Extents[1].Type == "FLAT" && reader.Extents[1].SectorCount == 32 && reader.Extents[1].GuestStartSector == 16, "Extent 1 metadata verified");
                Check(reader.Extents[2].Type == "ZERO" && reader.Extents[2].SectorCount == 48 && reader.Extents[2].GuestStartSector == 48, "Extent 2 metadata verified");
                Check(reader.Extents[3].Type == "FLAT" && reader.Extents[3].SectorCount == 64 && reader.Extents[3].GuestStartSector == 96, "Extent 3 metadata verified");

                // Sequential byte-by-byte verification
                for (int i = 0; i < 81920; i++)
                {
                    int b = reader.ReadByte();
                    if (b != oracle[i])
                    {
                        throw new Exception(string.Format("Sequential ReadByte mismatch at offset {0}: expected 0x{1:X2}, got 0x{2:X2}", i, oracle[i], b));
                    }
                }
                Check(true, "Sequential byte-by-byte read across all 81,920 bytes (ZERO and FLAT extents) 100% matched oracle");

                // Verify EOF reached
                Check(reader.ReadByte() == -1, "ReadByte at EOF returns -1");
                byte[] eofBuf = new byte[16];
                Check(reader.Read(eofBuf, 0, 16) == 0, "Read at EOF returns 0");

                // Full-span single read (81,920 bytes in one buffer)
                reader.Seek(0, SeekOrigin.Begin);
                byte[] fullBuf = new byte[81920];
                int totalRead = reader.Read(fullBuf, 0, 81920);
                Check(totalRead == 81920, "Single read across all 4 extents returned 81,920 bytes");
                for (int i = 0; i < 81920; i++)
                {
                    if (fullBuf[i] != oracle[i])
                    {
                        throw new Exception(string.Format("Full read mismatch at offset {0}: expected 0x{1:X2}, got 0x{2:X2}", i, oracle[i], fullBuf[i]));
                    }
                }
                Check(true, "Full span read across 4 extents matches oracle byte-for-byte");

                // Precise boundary transition 1: ZERO (offset 8191) to FLAT (offset 8192)
                reader.Seek(8191L, SeekOrigin.Begin);
                byte[] b1 = new byte[2];
                Check(reader.Read(b1, 0, 2) == 2, "Read 2 bytes across Boundary 1");
                Check(b1[0] == 0x00, "Boundary 1 byte 0 is ZERO");
                Check(b1[1] == flat1Payload[0], "Boundary 1 byte 1 is flat1[0]");

                // Precise boundary transition 2: FLAT (offset 24575) to ZERO (offset 24576)
                reader.Seek(24575L, SeekOrigin.Begin);
                byte[] b2 = new byte[2];
                Check(reader.Read(b2, 0, 2) == 2, "Read 2 bytes across Boundary 2");
                Check(b2[0] == flat1Payload[16383], "Boundary 2 byte 0 is flat1[16383]");
                Check(b2[1] == 0x00, "Boundary 2 byte 1 is ZERO");

                // Precise boundary transition 3: ZERO (offset 49151) to FLAT (offset 49152)
                reader.Seek(49151L, SeekOrigin.Begin);
                byte[] b3 = new byte[2];
                Check(reader.Read(b3, 0, 2) == 2, "Read 2 bytes across Boundary 3");
                Check(b3[0] == 0x00, "Boundary 3 byte 0 is ZERO");
                Check(b3[1] == flat2Payload[0], "Boundary 3 byte 1 is flat2[0]");

                // Multi-extent crossing: from inside Extent 0 (offset 8000) to inside Extent 2 (offset 25000)
                // Spans ZERO -> entire FLAT1 (16,384 bytes) -> ZERO
                reader.Seek(8000L, SeekOrigin.Begin);
                int crossCount = 17000;
                byte[] crossBuf = new byte[crossCount];
                int rCross = reader.Read(crossBuf, 0, crossCount);
                Check(rCross == crossCount, "Multi-extent read returned expected byte count");
                for (int i = 0; i < crossCount; i++)
                {
                    if (crossBuf[i] != oracle[8000 + i])
                    {
                        throw new Exception(string.Format("Multi-extent crossing mismatch at offset {0}: expected 0x{1:X2}, got 0x{2:X2}", 8000 + i, oracle[8000 + i], crossBuf[i]));
                    }
                }
                Check(true, "Multi-extent spanning read (ZERO -> entire FLAT -> ZERO) matches oracle byte-for-byte");

                // 1,000 pseudo-random seek and read operations
                Random rng = new Random(0x42);
                for (int trial = 0; trial < 1000; trial++)
                {
                    int seekPos = rng.Next(0, 81920);
                    int readLen = rng.Next(1, 4096);
                    int expectedToRead = Math.Min(readLen, 81920 - seekPos);

                    reader.Seek(seekPos, SeekOrigin.Begin);
                    Check(reader.Position == seekPos, "Reader position verified before read");

                    byte[] buf = new byte[readLen];
                    int actualRead = reader.Read(buf, 0, readLen);
                    Check(actualRead == expectedToRead, string.Format("Trial {0}: Expected read {1}, got {2}", trial, expectedToRead, actualRead));

                    for (int k = 0; k < actualRead; k++)
                    {
                        if (buf[k] != oracle[seekPos + k])
                        {
                            throw new Exception(string.Format("Trial {0} mismatch at pos {1}: expected 0x{2:X2}, got 0x{3:X2}", trial, seekPos + k, oracle[seekPos + k], buf[k]));
                        }
                    }
                }
                Check(true, "1,000 random seeks and reads across alternating ZERO and FLAT extents verified against oracle");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestAccessModeVariations()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-probe-modes-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // Descriptor with various access modes and mixed case:
            // "rw 32 ZERO"
            // "RDONLY 32 zero"
            // "noaccess 16 ZERO"
            // "RW 16 ZeRo"
            // Total sectors: 32 + 32 + 16 + 16 = 96 sectors = 49,152 bytes.
            string descPath = Path.Combine(tempDir, "disk_modes.vmdk");
            string descContent =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "CID=aabbccdd\n" +
                "parentCID=ffffffff\n" +
                "createType=\"monolithicFlat\"\n\n" +
                "# Extent description\n" +
                "rw   32   ZERO\n" +
                "\tRDONLY \t 32 \t zero\n" +
                "# comment line\n" +
                "noaccess 16 ZERO\n" +
                "RW 16 ZeRo\n\n" +
                "# The Disk Data Base\n" +
                "ddb.adapterType = \"lsilogic\"\n";
            File.WriteAllText(descPath, descContent, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                Check(reader.Length == 49152L, "Length for varied access modes is 49,152 bytes: " + reader.Length);
                Check(reader.Extents.Count == 4, "Extents count is 4: " + reader.Extents.Count);

                Check(reader.Extents[0].Access.Equals("rw", StringComparison.OrdinalIgnoreCase), "Extent 0 access is rw");
                Check(reader.Extents[1].Access.Equals("RDONLY", StringComparison.OrdinalIgnoreCase), "Extent 1 access is RDONLY");
                Check(reader.Extents[2].Access.Equals("noaccess", StringComparison.OrdinalIgnoreCase), "Extent 2 access is noaccess");
                Check(reader.Extents[3].Access.Equals("RW", StringComparison.OrdinalIgnoreCase), "Extent 3 access is RW");

                for (int i = 0; i < reader.Extents.Count; i++)
                {
                    Check(reader.Extents[i].Type == "ZERO", "Extent " + i + " Type is ZERO");
                    Check(reader.Extents[i].ExtentStream == null, "Extent " + i + " ExtentStream is null");
                }

                // Verify reading entire virtual disk returns all zeroes
                byte[] buf = new byte[49152];
                int r = reader.Read(buf, 0, 49152);
                Check(r == 49152, "Read 49,152 bytes from mixed-mode ZERO extents");
                for (int i = 0; i < 49152; i++)
                {
                    if (buf[i] != 0) throw new Exception("Non-zero byte at offset " + i);
                }
                Check(true, "All bytes returned from mixed-mode ZERO extents are zeroes");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestPureZeroVirtualDisks()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-probe-pure-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // 1. Single-sector pure zero disk (512 bytes)
            string desc1Path = Path.Combine(tempDir, "pure1.vmdk");
            string desc1 =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 1 ZERO\n";
            File.WriteAllText(desc1Path, desc1, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(desc1Path))
            {
                Check(reader.Length == 512L, "Single-sector pure zero length is 512 bytes");
                Check(reader.Extents.Count == 1, "Single-sector pure zero extent count is 1");
                byte[] buf = new byte[512];
                Check(reader.Read(buf, 0, 512) == 512, "Read 512 bytes");
                for (int i = 0; i < 512; i++) { if (buf[i] != 0) throw new Exception("Expected 0"); }
                Check(reader.Read(buf, 0, 512) == 0, "Read at EOF returns 0");
            }

            // 2. Large pure zero disk (1 GB virtual disk = 2,097,152 sectors)
            string descLargePath = Path.Combine(tempDir, "pure_large.vmdk");
            string descLarge =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 2097152 ZERO\n";
            File.WriteAllText(descLargePath, descLarge, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descLargePath))
            {
                long expectedSize = 2097152L * 512L; // 1,073,741,824 bytes (1 GB)
                Check(reader.Length == expectedSize, "Large pure zero length is 1 GB (1,073,741,824 bytes): " + reader.Length);

                // Read 64 KB from middle of 1 GB disk
                reader.Seek(536870912L, SeekOrigin.Begin); // 512 MB offset
                byte[] chunk = new byte[65536];
                int rc = reader.Read(chunk, 0, chunk.Length);
                Check(rc == chunk.Length, "Read 64 KB from offset 512 MB");
                for (int i = 0; i < chunk.Length; i++) { if (chunk[i] != 0) throw new Exception("Expected 0"); }

                // Seek near EOF
                reader.Seek(-1024L, SeekOrigin.End);
                Check(reader.Position == expectedSize - 1024L, "Position is at Length - 1024");
                byte[] tail = new byte[2048];
                int rt = reader.Read(tail, 0, tail.Length);
                Check(rt == 1024, "Read tail returns remaining 1024 bytes");
                for (int i = 0; i < 1024; i++) { if (tail[i] != 0) throw new Exception("Expected 0"); }
                Check(reader.Position == expectedSize, "Position reached EOF");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestRejectionOfMalformedDescriptors()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-probe-malform-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // 1. Descriptor with invalid FLAT extent lacking filename, followed by valid ZERO extent
            string descMissingFlatFile = Path.Combine(tempDir, "missing_flat_file.vmdk");
            string descContent1 =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 64 FLAT\n" + // Invalid FLAT: only 3 tokens! Must be skipped!
                "RW 32 ZERO\n";
            File.WriteAllText(descMissingFlatFile, descContent1, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descMissingFlatFile))
            {
                // Line "RW 64 FLAT" was skipped because type == "FLAT" && parts.Length < 4
                // Valid extent is only "RW 32 ZERO" (32 sectors = 16,384 bytes)
                Check(reader.Length == 16384L, "Invalid FLAT was safely skipped, disk length is 16,384 bytes: " + reader.Length);
                Check(reader.Extents.Count == 1, "Only 1 extent loaded: " + reader.Extents.Count);
                Check(reader.Extents[0].Type == "ZERO", "Extent is ZERO");
            }

            // 2. Descriptor with ONLY invalid FLAT extent (no filename): must throw InvalidDataException
            string descOnlyInvalidFlat = Path.Combine(tempDir, "only_invalid_flat.vmdk");
            string descContent2 =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 64 FLAT\n";
            File.WriteAllText(descOnlyInvalidFlat, descContent2, Encoding.ASCII);

            bool caughtInvalidFlat = false;
            try
            {
                using (VmdkImageReader r = VmdkImageReader.Open(descOnlyInvalidFlat)) { }
            }
            catch (InvalidDataException)
            {
                caughtInvalidFlat = true;
            }
            Check(caughtInvalidFlat, "Opening descriptor with only invalid FLAT extent throws InvalidDataException");

            // 3. Descriptor with FLAT extent referencing nonexistent backing file: must throw FileNotFoundException
            // and must NOT leak file lock on earlier opened extents!
            string validFlatPath = Path.Combine(tempDir, "valid_flat.bin");
            File.WriteAllBytes(validFlatPath, new byte[512]);

            string descMissingFile = Path.Combine(tempDir, "desc_missing_file.vmdk");
            string descContent3 =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 1 FLAT \"valid_flat.bin\" 0\n" +
                "RW 1 FLAT \"non_existent_file.bin\" 0\n";
            File.WriteAllText(descMissingFile, descContent3, Encoding.ASCII);

            bool caughtMissingBacking = false;
            try
            {
                using (VmdkImageReader r = VmdkImageReader.Open(descMissingFile)) { }
            }
            catch (FileNotFoundException)
            {
                caughtMissingBacking = true;
            }
            Check(caughtMissingBacking, "Missing backing file throws FileNotFoundException");

            // Verify that validFlatPath is NOT locked (proves DisposeFlatExtents was invoked on failure)
            bool canDeleteValidFlat = false;
            try
            {
                File.Delete(validFlatPath);
                canDeleteValidFlat = true;
            }
            catch { }
            Check(canDeleteValidFlat, "Earlier opened extent stream was closed and file lock released upon exception");

            // 4. Descriptor with invalid non-numeric sector count
            string descBadSectors = Path.Combine(tempDir, "bad_sectors.vmdk");
            string descContent4 =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW invalid_count ZERO\n" +
                "RW 16 ZERO\n";
            File.WriteAllText(descBadSectors, descContent4, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descBadSectors))
            {
                Check(reader.Length == 8192L, "Bad sector count skipped, valid extent retained: length 8,192 bytes");
                Check(reader.Extents.Count == 1, "Extents count is 1");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestSeekingAndEofBoundaries()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-probe-seek-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string descPath = Path.Combine(tempDir, "disk_seek.vmdk");
            string descContent =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 10 ZERO\n"; // 10 sectors = 5,120 bytes
            File.WriteAllText(descPath, descContent, Encoding.ASCII);

            using (VmdkImageReader reader = VmdkImageReader.Open(descPath))
            {
                // Negative Seek from Begin
                bool caughtNegBegin = false;
                try { reader.Seek(-1, SeekOrigin.Begin); }
                catch (IOException) { caughtNegBegin = true; }
                Check(caughtNegBegin, "Seek(-1, SeekOrigin.Begin) throws IOException");

                // Seek beyond 0 from Current
                reader.Seek(10, SeekOrigin.Begin);
                bool caughtNegCurrent = false;
                try { reader.Seek(-15, SeekOrigin.Current); }
                catch (IOException) { caughtNegCurrent = true; }
                Check(caughtNegCurrent, "Seek before beginning from Current throws IOException");

                // Seek before 0 from End
                bool caughtNegEnd = false;
                try { reader.Seek(-5121, SeekOrigin.End); }
                catch (IOException) { caughtNegEnd = true; }
                Check(caughtNegEnd, "Seek before beginning from End throws IOException");

                // Seek exactly to End (Length)
                long posEnd = reader.Seek(0, SeekOrigin.End);
                Check(posEnd == 5120L && reader.Position == 5120L, "Seek(0, SeekOrigin.End) is exactly at Length");
                byte[] b = new byte[10];
                Check(reader.Read(b, 0, 10) == 0, "Read at Length returns 0");
                Check(reader.ReadByte() == -1, "ReadByte at Length returns -1");

                // Seek past Length: Read returns 0
                reader.Seek(100, SeekOrigin.End);
                Check(reader.Position == 5220L, "Position is past Length");
                Check(reader.Read(b, 0, 10) == 0, "Read past Length returns 0");
                Check(reader.ReadByte() == -1, "ReadByte past Length returns -1");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestWriteBlockingAndDisposal()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vmdk-probe-wb-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string descPath = Path.Combine(tempDir, "disk_wb.vmdk");
            string descContent =
                "# Disk DescriptorFile\n" +
                "version=1\n" +
                "createType=\"monolithicFlat\"\n" +
                "RW 16 ZERO\n";
            File.WriteAllText(descPath, descContent, Encoding.ASCII);

            VmdkImageReader reader = VmdkImageReader.Open(descPath);
            Check(reader.CanRead == true, "CanRead is true");
            Check(reader.CanSeek == true, "CanSeek is true");
            Check(reader.CanWrite == false, "CanWrite is false (write-blocking)");

            // Write blocking
            bool caughtWrite = false;
            try { reader.Write(new byte[10], 0, 10); } catch (NotSupportedException) { caughtWrite = true; }
            Check(caughtWrite, "Write throws NotSupportedException");

            bool caughtWriteByte = false;
            try { reader.WriteByte(0xFF); } catch (NotSupportedException) { caughtWriteByte = true; }
            Check(caughtWriteByte, "WriteByte throws NotSupportedException");

            bool caughtSetLength = false;
            try { reader.SetLength(100); } catch (NotSupportedException) { caughtSetLength = true; }
            Check(caughtSetLength, "SetLength throws NotSupportedException");

            // Disposal idempotence
            reader.Dispose();
            reader.Dispose(); // second call should not throw
            Check(true, "Dispose is idempotent");

            Check(reader.CanRead == false, "CanRead is false after Dispose");
            Check(reader.CanSeek == false, "CanSeek is false after Dispose");

            bool caughtReadDisposed = false;
            try { reader.Read(new byte[10], 0, 10); } catch (ObjectDisposedException) { caughtReadDisposed = true; }
            Check(caughtReadDisposed, "Read after Dispose throws ObjectDisposedException");

            bool caughtSeekDisposed = false;
            try { reader.Seek(0, SeekOrigin.Begin); } catch (ObjectDisposedException) { caughtSeekDisposed = true; }
            Check(caughtSeekDisposed, "Seek after Dispose throws ObjectDisposedException");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }
}
