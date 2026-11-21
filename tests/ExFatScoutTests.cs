using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class ExFatScoutTests
{
    static int checks;

    static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
            throw new Exception("Assertion failed: " + message);
    }

    public static int Main(string[] args)
    {
        Console.WriteLine("Running ExFatScoutTests...");
        string tempDir = Path.Combine(Path.GetTempPath(), "exfat_test_" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempDir);

            // 1. Test Boot Sector Detection
            byte[] invalidSector = new byte[512];
            Check(!ExFatScout.IsExFatBootSector(invalidSector), "Zeroed sector is not exFAT");

            byte[] bootBytes = CreateSyntheticExFatBootSector(1048576, 24, 8, 32, 100, 2);
            Check(ExFatScout.IsExFatBootSector(bootBytes), "Valid exFAT boot sector recognized");

            var boot = ExFatScout.ParseBootSector(bootBytes, 0, false);
            Check(boot != null, "Boot sector successfully parsed");
            Check(boot.BytesPerSector == 512, "BytesPerSector is 512");
            Check(boot.SectorsPerCluster == 8, "SectorsPerCluster is 8 (4096 bytes per cluster)");
            Check(boot.ClusterSizeBytes == 4096, "ClusterSizeBytes is 4096");
            Check(boot.RootDirectoryCluster == 2, "RootDirectoryCluster is 2");
            Check(boot.ClusterHeapOffsetSector == 32, "ClusterHeapOffsetSector is 32");

            // Verify cluster translation
            long offC2 = boot.ClusterToOffset(2);
            Check(offC2 == 32L * 512L, "Cluster 2 maps to start of cluster heap (32 * 512)");
            long offC3 = boot.ClusterToOffset(3);
            Check(offC3 == (32L * 512L) + 4096L, "Cluster 3 maps to cluster 2 + 4096 bytes");
            Check(boot.ClusterToOffset(1) == -1, "Invalid cluster < 2 returns -1");

            // 2. Test Timestamp Decoding
            // Date: 2026-11-20 14:30:10
            uint dosTime = ((2026 - 1980) << 25) | (11 << 21) | (20 << 16) | (14 << 11) | (30 << 5) | (10 / 2);
            byte[] timeBuf = BitConverter.GetBytes(dosTime);
            DateTime parsedDt = ExFatScout.ParseExFatTimestamp(timeBuf, 0, 50, 0); // 500ms, no timezone
            Check(parsedDt.Year == 2026, "Timestamp year is 2026");
            Check(parsedDt.Month == 11, "Timestamp month is 11");
            Check(parsedDt.Day == 20, "Timestamp day is 20");
            Check(parsedDt.Hour == 14, "Timestamp hour is 14");
            Check(parsedDt.Minute == 30, "Timestamp minute is 30");
            Check(parsedDt.Second == 10, "Timestamp second is 10");
            Check(parsedDt.Millisecond == 500, "Timestamp millisecond is 500");

            // 3. Create Full Synthetic exFAT Image
            string diskPath = Path.Combine(tempDir, "exfat_test_disk.raw");
            long totalDiskSize = 256 * 1024; // 256 KiB synthetic image
            byte[] fullDisk = new byte[totalDiskSize];

            // Copy Primary VBR at sector 0
            Array.Copy(bootBytes, 0, fullDisk, 0, 512);

            // Compute Checksum for sectors 0..10
            uint csum = ExFatScout.ComputeBootChecksum(fullDisk, 11 * 512);
            // Write checksum repeated in sector 11
            for (int ci = 0; ci < 512; ci += 4)
            {
                BitConverter.GetBytes(csum).CopyTo(fullDisk, (11 * 512) + ci);
            }

            // Copy Backup VBR at sector 12
            Array.Copy(bootBytes, 0, fullDisk, 12 * 512, 512);
            // Write backup checksum in sector 23
            for (int ci = 0; ci < 512; ci += 4)
            {
                BitConverter.GetBytes(csum).CopyTo(fullDisk, (23 * 512) + ci);
            }

            // Populate Root Directory at Cluster 2 (offset = 32 * 512 = 16384)
            int rootOffset = 32 * 512;

            // Entry 0: Volume Label "EVIDENCE_USB" (0x83)
            fullDisk[rootOffset] = ExFatScout.EntryTypeVolumeLabel;
            string labelStr = "EVIDENCE_USB";
            fullDisk[rootOffset + 1] = (byte)labelStr.Length;
            Encoding.Unicode.GetBytes(labelStr).CopyTo(fullDisk, rootOffset + 2);

            // Entry Set 1: Active File "Financials.xlsx"
            // File Entry (0x85) at rootOffset + 32
            int f1 = rootOffset + 32;
            fullDisk[f1] = ExFatScout.EntryTypeFileActive;
            fullDisk[f1 + 1] = 2; // secondary count = 2 (stream + 1 name entry)
            BitConverter.GetBytes(ExFatScout.AttrArchive).CopyTo(fullDisk, f1 + 4);
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, f1 + 8);  // Create
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, f1 + 12); // Modified
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, f1 + 16); // Accessed

            // Stream Entry (0xC0) at f1 + 32
            int s1 = f1 + 32;
            fullDisk[s1] = ExFatScout.EntryTypeStreamActive;
            fullDisk[s1 + 1] = 0x03; // AllocationPossible(1) | NoFatChain(2)
            fullDisk[s1 + 3] = (byte)"Financials.xlsx".Length;
            BitConverter.GetBytes(100UL).CopyTo(fullDisk, s1 + 8);  // ValidDataLength
            BitConverter.GetBytes(3U).CopyTo(fullDisk, s1 + 20);    // FirstCluster = 3
            BitConverter.GetBytes(100UL).CopyTo(fullDisk, s1 + 24); // DataLength = 100 bytes

            // Name Entry (0xC1) at s1 + 32
            int n1 = s1 + 32;
            fullDisk[n1] = ExFatScout.EntryTypeNameActive;
            Encoding.Unicode.GetBytes("Financials.xlsx").CopyTo(fullDisk, n1 + 2);

            // Write active file payload into Cluster 3 (offset = 16384 + 4096 = 20480)
            int c3Offset = rootOffset + 4096;
            byte[] activePayload = Encoding.UTF8.GetBytes("COMPANY_FINANCIAL_RECORDS_Q4_CONFIDENTIAL_ACTIVE_RECOVERY_PROOF");
            Array.Copy(activePayload, 0, fullDisk, c3Offset, activePayload.Length);

            // Entry Set 2: Deleted File "Secret.pdf"
            // File Entry (0x05) at n1 + 32
            int f2 = n1 + 32;
            fullDisk[f2] = ExFatScout.EntryTypeFileDeleted;
            fullDisk[f2 + 1] = 2; // secondary count = 2
            BitConverter.GetBytes(ExFatScout.AttrArchive).CopyTo(fullDisk, f2 + 4);
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, f2 + 8);
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, f2 + 12);
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, f2 + 16);

            // Stream Entry (0x40) at f2 + 32
            int s2 = f2 + 32;
            fullDisk[s2] = ExFatScout.EntryTypeStreamDeleted;
            fullDisk[s2 + 1] = 0x03; // NoFatChain
            fullDisk[s2 + 3] = (byte)"Secret.pdf".Length;
            BitConverter.GetBytes(80UL).CopyTo(fullDisk, s2 + 8);
            BitConverter.GetBytes(4U).CopyTo(fullDisk, s2 + 20);   // FirstCluster = 4
            BitConverter.GetBytes(80UL).CopyTo(fullDisk, s2 + 24);  // DataLength = 80 bytes

            // Name Entry (0x41) at s2 + 32
            int n2 = s2 + 32;
            fullDisk[n2] = ExFatScout.EntryTypeNameDeleted;
            Encoding.Unicode.GetBytes("Secret.pdf").CopyTo(fullDisk, n2 + 2);

            // Write deleted file payload into Cluster 4 (offset = 16384 + 8192 = 24576)
            int c4Offset = rootOffset + 8192;
            byte[] deletedPayload = Encoding.UTF8.GetBytes("TOP_SECRET_RECOVERED_DELETED_EVIDENCE_FOR_RULE_902_COURT_PACKAGE");
            Array.Copy(deletedPayload, 0, fullDisk, c4Offset, deletedPayload.Length);

            // Entry Set 3: Carved Orphan Deleted File placed deep in unallocated space (Cluster 6)
            // Multi-entry filename test: 17 chars ("SlackEvidence.doc") spanning 2 name entries
            int orphanOffset = rootOffset + (4 * 4096);
            fullDisk[orphanOffset] = ExFatScout.EntryTypeFileDeleted;
            fullDisk[orphanOffset + 1] = 3; // secondary count = 3 (1 stream + 2 name entries)
            BitConverter.GetBytes(ExFatScout.AttrArchive).CopyTo(fullDisk, orphanOffset + 4);
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, orphanOffset + 8);
            BitConverter.GetBytes(dosTime).CopyTo(fullDisk, orphanOffset + 12);

            int s3 = orphanOffset + 32;
            fullDisk[s3] = ExFatScout.EntryTypeStreamDeleted;
            fullDisk[s3 + 1] = 0x03;
            fullDisk[s3 + 3] = (byte)"SlackEvidence.doc".Length;
            BitConverter.GetBytes(60UL).CopyTo(fullDisk, s3 + 8);
            BitConverter.GetBytes(5U).CopyTo(fullDisk, s3 + 20);   // Cluster 5
            BitConverter.GetBytes(60UL).CopyTo(fullDisk, s3 + 24);

            int n3 = s3 + 32;
            fullDisk[n3] = ExFatScout.EntryTypeNameDeleted;
            Encoding.Unicode.GetBytes("SlackEvidence.d").CopyTo(fullDisk, n3 + 2); // First 15 chars

            int n3_2 = n3 + 32;
            fullDisk[n3_2] = ExFatScout.EntryTypeNameDeleted;
            Encoding.Unicode.GetBytes("oc").CopyTo(fullDisk, n3_2 + 2); // Remaining 2 chars

            // Write cluster 5 payload
            int c5Offset = rootOffset + (3 * 4096);
            byte[] orphanPayload = Encoding.UTF8.GetBytes("DEEP_CARVED_SLACK_RECORD_VERIFICATION_PAYLOAD_SUCCESS");
            Array.Copy(orphanPayload, 0, fullDisk, c5Offset, orphanPayload.Length);

            File.WriteAllBytes(diskPath, fullDisk);

            // 4. Test Scout Execution on Image
            using (var fs = new FileStream(diskPath, FileMode.Open, FileAccess.Read))
            {
                var scoutRes = ExFatScout.Scout(fs, CancellationToken.None);

                Check(scoutRes.Status == "OK", "Scout status is OK: " + scoutRes.Status);
                Check(scoutRes.PrimaryBoot != null, "Primary boot sector found");
                Check(scoutRes.PrimaryBoot.IsChecksumValid, "Boot sector checksum verified");
                Check(scoutRes.PrimaryBoot.VolumeLabel == "EVIDENCE_USB", "Volume label is EVIDENCE_USB: " + scoutRes.PrimaryBoot.VolumeLabel);
                Check(scoutRes.BackupBoot != null, "Backup boot sector found at sector 12");
                Check(scoutRes.BackupBoot.IsBackup, "Backup boot sector marked IsBackup");

                // Check Active Files
                Check(scoutRes.TotalActiveCount == 1, "TotalActiveCount == 1");
                var activeFile = scoutRes.ActiveFiles[0];
                Check(activeFile.Name == "Financials.xlsx", "Active file name is Financials.xlsx");
                Check(activeFile.Size == 100, "Active file size is 100");
                Check(!activeFile.IsDeleted, "Active file is not deleted");
                Check(activeFile.NoFatChain, "Active file NoFatChain flag is true");
                Check(activeFile.PhysicalOffset == c3Offset, "Active file physical offset matches Cluster 3");

                // Check Deleted Files
                Check(scoutRes.TotalDeletedCount >= 2, "TotalDeletedCount >= 2 (found root deleted + carved orphan)");
                ExFatScout.ExFatFileRecord deletedFile = null;
                ExFatScout.ExFatFileRecord carvedFile = null;
                for (int i = 0; i < scoutRes.DeletedFiles.Count; i++)
                {
                    if (scoutRes.DeletedFiles[i].Name == "Secret.pdf") deletedFile = scoutRes.DeletedFiles[i];
                    if (scoutRes.DeletedFiles[i].Name == "SlackEvidence.doc") carvedFile = scoutRes.DeletedFiles[i];
                }

                Check(deletedFile != null, "Found deleted file Secret.pdf");
                Check(deletedFile.Size == 80, "Deleted file size is 80");
                Check(deletedFile.IsDeleted, "Deleted file marked IsDeleted");
                Check(deletedFile.NoFatChain, "Deleted file NoFatChain is true");

                Check(carvedFile != null, "Found carved orphan file SlackEvidence.doc");
                Check(carvedFile.Size == 60, "Carved file size is 60");
                Check(carvedFile.IsDeleted, "Carved file marked IsDeleted");

                // 5. Test File Extraction
                using (var msActive = new MemoryStream())
                {
                    ExFatScout.ExtractFile(fs, scoutRes.PrimaryBoot, activeFile, msActive);
                    byte[] extractedActive = msActive.ToArray();
                    Check(extractedActive.Length == 100, "Extracted active length is 100");
                    string strActive = Encoding.UTF8.GetString(extractedActive);
                    Check(strActive.Contains("COMPANY_FINANCIAL_RECORDS"), "Extracted active payload matches written data");
                }

                using (var msDeleted = new MemoryStream())
                {
                    ExFatScout.ExtractFile(fs, scoutRes.PrimaryBoot, deletedFile, msDeleted);
                    byte[] extractedDeleted = msDeleted.ToArray();
                    Check(extractedDeleted.Length == 80, "Extracted deleted length is 80");
                    string strDeleted = Encoding.UTF8.GetString(extractedDeleted);
                    Check(strDeleted.Contains("TOP_SECRET_RECOVERED_DELETED_EVIDENCE"), "Extracted deleted payload matches written data");
                }

                using (var msCarved = new MemoryStream())
                {
                    ExFatScout.ExtractFile(fs, scoutRes.PrimaryBoot, carvedFile, msCarved);
                    byte[] extractedCarved = msCarved.ToArray();
                    Check(extractedCarved.Length == 60, "Extracted carved length is 60");
                    string strCarved = Encoding.UTF8.GetString(extractedCarved);
                    Check(strCarved.Contains("DEEP_CARVED_SLACK_RECORD"), "Extracted carved payload matches written data");
                }

                // 6. Test JSON serialization
                string json = scoutRes.ToJson();
                Check(json.Contains("Financials.xlsx"), "JSON contains active filename");
                Check(json.Contains("Secret.pdf"), "JSON contains deleted filename");
                Check(json.Contains("EVIDENCE_USB"), "JSON contains volume label");
            }

            Console.WriteLine("PASS ExFatScoutTests: {0} checks passed; primary/backup VBR, checksum, directory traversal, deleted entry carving, and contiguous stream extraction verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL ExFatScoutTests: {0}", ex.Message);
            return 1;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, true);
            }
            catch { }
        }
    }

    private static byte[] CreateSyntheticExFatBootSector(ulong volumeLengthSectors, uint fatOffset, uint fatLength, uint clusterHeapOffset, uint clusterCount, uint rootCluster)
    {
        byte[] sector = new byte[512];
        sector[0] = 0xEB; sector[1] = 0x76; sector[2] = 0x90; // Jump boot
        Encoding.ASCII.GetBytes(ExFatScout.ExFatOemId).CopyTo(sector, 3); // "EXFAT   "
        BitConverter.GetBytes(0UL).CopyTo(sector, 0x40); // VolumeOffset
        BitConverter.GetBytes(volumeLengthSectors).CopyTo(sector, 0x48);
        BitConverter.GetBytes(fatOffset).CopyTo(sector, 0x50);
        BitConverter.GetBytes(fatLength).CopyTo(sector, 0x54);
        BitConverter.GetBytes(clusterHeapOffset).CopyTo(sector, 0x58);
        BitConverter.GetBytes(clusterCount).CopyTo(sector, 0x5C);
        BitConverter.GetBytes(rootCluster).CopyTo(sector, 0x60);
        BitConverter.GetBytes(0x12345678U).CopyTo(sector, 0x64); // Serial
        BitConverter.GetBytes((ushort)0x0100).CopyTo(sector, 0x68); // Rev 1.00
        BitConverter.GetBytes((ushort)0).CopyTo(sector, 0x6A); // Flags
        sector[0x6C] = 9;  // 2^9 = 512 bytes per sector
        sector[0x6D] = 3;  // 2^3 = 8 sectors per cluster (4096 bytes)
        sector[0x6E] = 1;  // 1 FAT
        sector[0x6F] = 0x80; // DriveSelect
        sector[0x70] = 10;   // PercentInUse
        sector[510] = 0x55;
        sector[511] = 0xAA;
        return sector;
    }
}
