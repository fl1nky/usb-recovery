using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class HfsPlusScoutTests
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
        Console.WriteLine("Running HfsPlusScoutTests...");
        string tempDir = Path.Combine(Path.GetTempPath(), "hfs_test_" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempDir);

            // 1. Test Big-Endian Helpers & Signature Detection
            byte[] testBuf = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
            Check(HfsPlusScout.ReadBig16(testBuf, 0) == 0x1234, "ReadBig16 reads 0x1234");
            Check(HfsPlusScout.ReadBig32(testBuf, 0) == 0x12345678U, "ReadBig32 reads 0x12345678");
            Check(HfsPlusScout.ReadBig64(testBuf, 0) == 0x123456789ABCDEF0UL, "ReadBig64 reads 0x123456789ABCDEF0");

            byte[] hfsSig = new byte[512];
            hfsSig[0] = 0x48; hfsSig[1] = 0x2B; // 'H+'
            Check(HfsPlusScout.IsHfsPlusHeader(hfsSig), "HFS+ signature recognized");

            byte[] hfsXSig = new byte[512];
            hfsXSig[0] = 0x48; hfsXSig[1] = 0x58; // 'HX'
            Check(HfsPlusScout.IsHfsPlusHeader(hfsXSig), "HFSX signature recognized");

            byte[] invalidSig = new byte[512];
            Check(!HfsPlusScout.IsHfsPlusHeader(invalidSig), "Zeroed buffer is not HFS+");

            // 2. Test Mac Timestamp Parsing
            // HFS seconds for 2026-11-20 00:00:00 UTC:
            // 2026-11-20 Unix timestamp: 1795132800. Mac epoch difference: 2082844800.
            uint macTime = (uint)(1795132800L + 2082844800L);
            DateTime parsedDt = HfsPlusScout.ParseHfsTimestamp(macTime);
            Check(parsedDt.Year == 2026, "HFS timestamp year is 2026");
            Check(parsedDt.Month == 11, "HFS timestamp month is 11");
            Check(parsedDt.Day == 20, "HFS timestamp day is 20");
            Check(HfsPlusScout.ParseHfsTimestamp(0) == DateTime.MinValue, "Zero timestamp returns MinValue");

            // 3. Create Full Synthetic HFS+ Disk Image
            // 64 blocks of 4096 bytes = 262,144 bytes (256 KiB)
            int blockSize = 4096;
            uint totalBlocks = 64;
            int totalBytes = (int)totalBlocks * blockSize;
            byte[] diskBytes = new byte[totalBytes];

            // Primary Volume Header at offset 1024
            byte[] vhBytes = CreateSyntheticVolumeHeader(totalBlocks, (uint)blockSize, macTime);
            Array.Copy(vhBytes, 0, diskBytes, 1024, 512);

            // Backup Volume Header at totalBytes - 1024
            Array.Copy(vhBytes, 0, diskBytes, totalBytes - 1024, 512);

            // Catalog Fork starts at Block 4 (offset = 4 * 4096 = 16384)
            int catStart = 4 * blockSize;

            // Block 4: B-Tree Node 0 (Header Node)
            int n0 = catStart;
            diskBytes[n0 + 8] = (byte)HfsPlusScout.NodeKindHeader; // NodeKind = 1
            WriteBig16(diskBytes, n0 + 10, 3); // numRecords = 3
            // Header record at byte 14:
            WriteBig16(diskBytes, n0 + 32, (ushort)blockSize); // nodeSize = 4096
            WriteBig32(diskBytes, n0 + 36, 2); // totalNodes = 2

            // Block 5: B-Tree Node 1 (Leaf Node) at offset 16384 + 4096 = 20480
            int n1 = catStart + blockSize;
            diskBytes[n1 + 8] = 0xFF; // NodeKind = -1 (Leaf)
            WriteBig16(diskBytes, n1 + 10, 2); // numRecords = 2

            // Record 1: Folder Record "Documents" (CNID 20)
            int rec1Offset = 14;
            // Record 1 Key: parentCnid = 1 (root), name = "Documents" (9 chars)
            int k1 = n1 + rec1Offset;
            ushort k1Len = (ushort)(2 + 4 + 2 + (9 * 2));
            WriteBig16(diskBytes, k1, k1Len);
            WriteBig32(diskBytes, k1 + 2, 1); // parentCnid = 1
            WriteBig16(diskBytes, k1 + 6, 9); // nameLen = 9
            byte[] docName = Encoding.BigEndianUnicode.GetBytes("Documents");
            Array.Copy(docName, 0, diskBytes, k1 + 8, docName.Length);

            // Record 1 Data: FolderRecord (recordType 0x0001)
            int d1 = k1 + 2 + k1Len;
            WriteBig16(diskBytes, d1, HfsPlusScout.RecordTypeFolder);
            WriteBig32(diskBytes, d1 + 8, 20); // cnid = 20
            WriteBig32(diskBytes, d1 + 12, macTime); // create
            WriteBig32(diskBytes, d1 + 16, macTime); // modify

            // Record 2: Active File Record "Evidence.pdf" (CNID 21)
            int rec2Offset = (d1 - n1) + 88;
            int k2 = n1 + rec2Offset;
            ushort k2Len = (ushort)(2 + 4 + 2 + (12 * 2));
            WriteBig16(diskBytes, k2, k2Len);
            WriteBig32(diskBytes, k2 + 2, 20); // parentCnid = 20 (inside Documents)
            WriteBig16(diskBytes, k2 + 6, 12); // nameLen = 12
            byte[] fileDocName = Encoding.BigEndianUnicode.GetBytes("Evidence.pdf");
            Array.Copy(fileDocName, 0, diskBytes, k2 + 8, fileDocName.Length);

            // Record 2 Data: FileRecord (recordType 0x0002)
            int d2 = k2 + 2 + k2Len;
            WriteBig16(diskBytes, d2, HfsPlusScout.RecordTypeFile);
            WriteBig32(diskBytes, d2 + 8, 21); // cnid = 21
            WriteBig32(diskBytes, d2 + 12, macTime); // create
            WriteBig32(diskBytes, d2 + 16, macTime); // modify

            // DataFork at d2 + 88: logicalSize = 120, totalBlocks = 1
            WriteBig64(diskBytes, d2 + 88, 120UL);
            WriteBig32(diskBytes, d2 + 88 + 12, 1U); // 1 block
            // Extent 0 at d2 + 88 + 16: startBlock = 8, blockCount = 1
            WriteBig32(diskBytes, d2 + 88 + 16, 8U);
            WriteBig32(diskBytes, d2 + 88 + 20, 1U);

            // Write record offsets at end of node 1 (growing backwards)
            WriteBig16(diskBytes, n1 + blockSize - 2, (ushort)rec1Offset);
            WriteBig16(diskBytes, n1 + blockSize - 4, (ushort)rec2Offset);

            // Write active file payload into Block 8 (offset = 8 * 4096 = 32768)
            int blk8Offset = 8 * blockSize;
            byte[] activePayload = Encoding.UTF8.GetBytes("CONFIDENTIAL_HFS_APPLE_CASE_EVIDENCE_FOR_ANALYSIS_100_PERCENT_RECOVERED");
            Array.Copy(activePayload, 0, diskBytes, blk8Offset, activePayload.Length);

            // Block 10: Carved Deleted Orphan File Record in unallocated space
            int blk10Offset = 10 * blockSize;
            WriteBig16(diskBytes, blk10Offset, HfsPlusScout.RecordTypeFile); // 0x0002
            WriteBig32(diskBytes, blk10Offset + 8, 99U); // cnid = 99
            WriteBig32(diskBytes, blk10Offset + 12, macTime); // create
            WriteBig32(diskBytes, blk10Offset + 16, macTime); // modify
            WriteBig64(diskBytes, blk10Offset + 88, 85UL);     // size = 85 bytes
            WriteBig32(diskBytes, blk10Offset + 104, 12U);    // startBlock = 12
            WriteBig32(diskBytes, blk10Offset + 108, 1U);     // blockCount = 1

            // Write orphan file payload into Block 12 (offset = 12 * 4096 = 49152)
            int blk12Offset = 12 * blockSize;
            byte[] orphanPayload = Encoding.UTF8.GetBytes("ORPHAN_HFS_CATALOG_RECORD_EXTRACTED_FROM_SLACK_SUCCESSFULLY_FOR_FORENSIC_WITNESS");
            Array.Copy(orphanPayload, 0, diskBytes, blk12Offset, orphanPayload.Length);

            string imagePath = Path.Combine(tempDir, "hfs_test_disk.raw");
            File.WriteAllBytes(imagePath, diskBytes);

            // 4. Test Scout Execution
            using (var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read))
            {
                var scoutRes = HfsPlusScout.Scout(fs, CancellationToken.None);

                Check(scoutRes.Status == "OK", "Scout status is OK: " + scoutRes.Status);
                Check(scoutRes.VolumeHeader != null, "Primary volume header found");
                Check(scoutRes.VolumeHeader.Signature == HfsPlusScout.HfsPlusMagic, "Signature matches 0x482B");
                Check(scoutRes.VolumeHeader.BlockSize == 4096, "BlockSize is 4096");
                Check(scoutRes.VolumeHeader.TotalBlocks == 64, "TotalBlocks is 64");
                Check(scoutRes.BackupVolumeHeader != null, "Backup volume header found");

                // Check Active Files & Folders
                Check(scoutRes.DirectoriesCount >= 1, "Directories count >= 1");
                Check(scoutRes.FilesCount >= 1, "Files count >= 1");
                Check(scoutRes.DeletedCount >= 1, "Deleted orphan count >= 1");

                HfsPlusScout.HfsPlusFileRecord activeFile = null;
                HfsPlusScout.HfsPlusFileRecord orphanFile = null;
                for (int i = 0; i < scoutRes.Files.Count; i++)
                {
                    if (scoutRes.Files[i].Name == "Evidence.pdf") activeFile = scoutRes.Files[i];
                    if (scoutRes.Files[i].Cnid == 99) orphanFile = scoutRes.Files[i];
                }

                Check(activeFile != null, "Found active file Evidence.pdf");
                Check(activeFile.Size == 120, "Active file size is 120");
                Check(!activeFile.IsDeleted, "Active file IsDeleted is false");
                Check(activeFile.ParentCnid == 20, "Active file ParentCnid is 20");

                Check(orphanFile != null, "Found carved orphan file CNID 99");
                Check(orphanFile.Size == 85, "Orphan file size is 85");
                Check(orphanFile.IsDeleted, "Orphan file IsDeleted is true");

                // 5. Test File Extraction
                using (var msActive = new MemoryStream())
                {
                    HfsPlusScout.ExtractFile(fs, scoutRes.VolumeHeader, activeFile, msActive);
                    byte[] actExt = msActive.ToArray();
                    Check(actExt.Length == 120, "Extracted active length matches 120");
                    string strAct = Encoding.UTF8.GetString(actExt);
                    Check(strAct.Contains("CONFIDENTIAL_HFS_APPLE_CASE"), "Extracted active matches written payload");
                }

                using (var msOrphan = new MemoryStream())
                {
                    HfsPlusScout.ExtractFile(fs, scoutRes.VolumeHeader, orphanFile, msOrphan);
                    byte[] orpExt = msOrphan.ToArray();
                    Check(orpExt.Length == 85, "Extracted orphan length matches 85");
                    string strOrp = Encoding.UTF8.GetString(orpExt);
                    Check(strOrp.Contains("ORPHAN_HFS_CATALOG_RECORD"), "Extracted orphan matches written payload");
                }

                // 6. Test JSON
                string json = scoutRes.ToJson();
                Check(json.Contains("Evidence.pdf"), "JSON contains active filename");
                Check(json.Contains("HFS_CNID_99"), "JSON contains carved filename");
            }

            Console.WriteLine("PASS HfsPlusScoutTests: {0} checks passed; primary/backup volume headers, B-tree catalog leaf parsing, deleted orphan carving, and direct extent extraction verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL HfsPlusScoutTests: {0}", ex.Message);
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

    private static byte[] CreateSyntheticVolumeHeader(uint totalBlocks, uint blockSize, uint macTime)
    {
        byte[] vh = new byte[512];
        WriteBig16(vh, 0, HfsPlusScout.HfsPlusMagic); // 0x482B
        WriteBig16(vh, 2, 4); // version = 4
        WriteBig32(vh, 16, macTime); // create
        WriteBig32(vh, 20, macTime); // modify
        WriteBig32(vh, 40, blockSize);
        WriteBig32(vh, 44, totalBlocks);
        WriteBig32(vh, 48, totalBlocks - 10); // free blocks

        // Catalog Fork at byte 272:
        // logicalSize = 8192 (2 blocks)
        WriteBig64(vh, 272, (ulong)(2 * blockSize));
        WriteBig32(vh, 272 + 12, 2U); // totalBlocks = 2
        // Extent 0 at 272 + 16: startBlock = 4, blockCount = 2
        WriteBig32(vh, 272 + 16, 4U);
        WriteBig32(vh, 272 + 20, 2U);

        return vh;
    }

    private static void WriteBig16(byte[] buf, int offset, ushort val)
    {
        buf[offset] = (byte)(val >> 8);
        buf[offset + 1] = (byte)val;
    }

    private static void WriteBig32(byte[] buf, int offset, uint val)
    {
        buf[offset] = (byte)(val >> 24);
        buf[offset + 1] = (byte)(val >> 16);
        buf[offset + 2] = (byte)(val >> 8);
        buf[offset + 3] = (byte)val;
    }

    private static void WriteBig64(byte[] buf, int offset, ulong val)
    {
        WriteBig32(buf, offset, (uint)(val >> 32));
        WriteBig32(buf, offset + 4, (uint)val);
    }
}
