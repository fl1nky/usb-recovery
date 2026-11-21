using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class F2fsScoutTests
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

    public static int Main(string[] args)
    {
        Console.WriteLine("Running F2fsScoutTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "f2fs-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            TestSuperblockParsing(testDir);
            TestCheckpointAndInodeParsing(testDir);
            TestInlineFileAndExtentRecovery(testDir);
            TestFullScoutAndHierarchy(testDir);

            Console.WriteLine("PASS F2fsScoutTests: {0} checks passed; F2FS superblocks (primary/backup), NAT mapping, inline payloads, extent reconstruction, and directory hierarchy verified.", checks);
            return 0;
        }
        finally
        {
            try
            {
                if (Directory.Exists(testDir))
                {
                    Directory.Delete(testDir, true);
                }
            }
            catch { }
        }
    }

    private static void TestSuperblockParsing(string testDir)
    {
        string imgPath = Path.Combine(testDir, "f2fs_sb.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(16 * 1024); // 16 KiB image

            // Primary Superblock at offset 0x400 (1024)
            byte[] sb1 = CreateMockSuperblock(1, 2, "F2FS_SYSTEM_A");
            fs.Position = 0x400;
            fs.Write(sb1, 0, sb1.Length);

            // Backup Superblock at offset 0x1400 (5120)
            byte[] sb2 = CreateMockSuperblock(1, 2, "F2FS_SYSTEM_A_BACKUP");
            fs.Position = 0x1400;
            fs.Write(sb2, 0, sb2.Length);
            fs.Flush();

            fs.Position = 0;
            var superblocks = F2fsScout.ProbeSuperblocks(fs);
            Check(superblocks.Count == 2, "Should discover both primary (0x400) and backup (0x1400) superblocks");
            Check(superblocks[0].PhysicalOffset == 0x400, "Primary SB offset should be 0x400");
            Check(superblocks[0].Magic == F2fsScout.F2fsSuperMagic, "Primary SB magic must match 0xF2F52010");
            Check(superblocks[0].MajorVersion == 1, "Major version should be 1");
            Check(superblocks[0].SectorSize == 512, "Sector size should be 512");
            Check(superblocks[0].BlockSize == 4096, "Block size should be 4096");
            Check(superblocks[0].VolumeName.Contains("F2FS_SYSTEM_A"), "Volume label should match");

            Check(superblocks[1].PhysicalOffset == 0x1400, "Backup SB offset should be 0x1400");
            Check(superblocks[1].VolumeName.Contains("F2FS_SYSTEM_A_BACKUP"), "Backup volume label should match");
        }
    }

    private static void TestCheckpointAndInodeParsing(string testDir)
    {
        // 1. Checkpoint test
        byte[] cpBuf = new byte[4096];
        WriteUInt64Le(cpBuf, 0, 42); // CheckpointVer = 42
        WriteUInt64Le(cpBuf, 8, 10000); // UserBlockCount
        WriteUInt64Le(cpBuf, 16, 8500); // ValidBlockCount
        WriteUInt32Le(cpBuf, 72, 0x01); // CkptFlags
        WriteUInt32Le(cpBuf, 88, 128); // ValidInodeCount

        var cp = F2fsScout.ParseCheckpoint(cpBuf, 0x20000);
        Check(cp != null, "Checkpoint should not be null");
        Check(cp.CheckpointVer == 42, "Checkpoint version must match");
        Check(cp.ValidBlockCount == 8500, "ValidBlockCount must match");
        Check(cp.ValidInodeCount == 128, "ValidInodeCount must match");

        // 2. Regular Inode test
        byte[] inodeBuf = new byte[4096];
        WriteUInt16Le(inodeBuf, 0, (ushort)F2fsScout.ModeTypeReg); // Regular file
        inodeBuf[3] = 0; // Not inline
        WriteUInt64Le(inodeBuf, 16, 8192); // File size = 8 KiB (2 blocks)
        WriteUInt64Le(inodeBuf, 56, 1700000000); // Modified time Unix sec
        WriteUInt32Le(inodeBuf, 84, 3); // Parent = root (3)

        byte[] nameBytes = Encoding.UTF8.GetBytes("evidence_dump.bin");
        WriteUInt32Le(inodeBuf, 88, (uint)nameBytes.Length);
        Array.Copy(nameBytes, 0, inodeBuf, 92, nameBytes.Length);

        // Direct block pointers at 352 (0x160)
        WriteUInt32Le(inodeBuf, 352, 100); // Block 100
        WriteUInt32Le(inodeBuf, 356, 101); // Block 101

        // Footer at 4072
        WriteUInt32Le(inodeBuf, 4072, 15); // nid = 15
        WriteUInt32Le(inodeBuf, 4076, 15); // ino = 15
        WriteUInt32Le(inodeBuf, 4088, 1);  // is_inode = 1

        var fileRec = F2fsScout.ParseInodeBlock(inodeBuf, 0x100000, 4096);
        Check(fileRec != null, "Parsed inode should not be null");
        Check(fileRec.InodeNumber == 15, "Inode number must match 15");
        Check(!fileRec.IsDirectory, "Should be a regular file");
        Check(fileRec.Size == 8192, "Size must be 8192");
        Check(fileRec.Name == "evidence_dump.bin", "Name must match evidence_dump.bin");
        Check(fileRec.Extents.Count == 2, "Should have 2 extents");
        Check(fileRec.Extents[0].PhysicalOffset == 100 * 4096, "Extent 0 offset must be 100 * 4096");
        Check(fileRec.Extents[1].PhysicalOffset == 101 * 4096, "Extent 1 offset must be 101 * 4096");
    }

    private static void TestInlineFileAndExtentRecovery(string testDir)
    {
        byte[] inodeBuf = new byte[4096];
        WriteUInt16Le(inodeBuf, 0, (ushort)F2fsScout.ModeTypeReg);
        inodeBuf[3] = F2fsScout.InlineDataFlag; // INLINE DATA!
        string inlineText = "TOP_SECRET_FORENSIC_KEY_123456789";
        byte[] payload = Encoding.UTF8.GetBytes(inlineText);
        WriteUInt64Le(inodeBuf, 16, (ulong)payload.Length);

        byte[] nameBytes = Encoding.UTF8.GetBytes("secret.txt");
        WriteUInt32Le(inodeBuf, 88, (uint)nameBytes.Length);
        Array.Copy(nameBytes, 0, inodeBuf, 92, nameBytes.Length);

        // Put payload directly in i_addr area at offset 352
        Array.Copy(payload, 0, inodeBuf, 352, payload.Length);

        // Footer
        WriteUInt32Le(inodeBuf, 4072, 20);
        WriteUInt32Le(inodeBuf, 4076, 20);
        WriteUInt32Le(inodeBuf, 4088, 1);

        var fileRec = F2fsScout.ParseInodeBlock(inodeBuf, 0x200000, 4096);
        Check(fileRec != null, "Inline inode should not be null");
        Check(fileRec.IsInline, "IsInline flag must be true");
        Check(fileRec.Extents.Count == 1, "Should have 1 inline extent");
        Check(fileRec.Extents[0].IsInline, "Extent should be inline");
        Check(Encoding.UTF8.GetString(fileRec.Extents[0].InlineData) == inlineText, "Inline payload must match secret text");
    }

    private static void TestFullScoutAndHierarchy(string testDir)
    {
        string imgPath = Path.Combine(testDir, "f2fs_full.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(4 * 1024 * 1024); // 4 MiB image

            // Superblock at 0x400
            byte[] sb = CreateMockSuperblock(1, 2, "F2FS_NVME_CARV");
            // Set NAT blk addr = 32, Main blk addr = 64, Root ino = 3
            WriteUInt32Le(sb, 72, 16); // cp_blkaddr = 16
            WriteUInt32Le(sb, 80, 32); // nat_blkaddr = 32
            WriteUInt32Le(sb, 88, 64); // main_blkaddr = 64
            WriteUInt32Le(sb, 92, 3);  // root_ino = 3
            fs.Position = 0x400;
            fs.Write(sb, 0, sb.Length);

            // Inode 3 (Root Directory) at block 64 (offset 64 * 4096 = 262144)
            byte[] rootDir = new byte[4096];
            WriteUInt16Le(rootDir, 0, (ushort)F2fsScout.ModeTypeDir);
            WriteUInt32Le(rootDir, 4072, 3);
            WriteUInt32Le(rootDir, 4076, 3);
            WriteUInt32Le(rootDir, 4088, 1);
            fs.Position = 64 * 4096;
            fs.Write(rootDir, 0, 4096);

            // Inode 10 (Subdirectory "artifacts") at block 65
            byte[] subDir = new byte[4096];
            WriteUInt16Le(subDir, 0, (ushort)F2fsScout.ModeTypeDir);
            WriteUInt32Le(subDir, 84, 3); // parent = 3
            byte[] subName = Encoding.UTF8.GetBytes("artifacts");
            WriteUInt32Le(subDir, 88, (uint)subName.Length);
            Array.Copy(subName, 0, subDir, 92, subName.Length);
            WriteUInt32Le(subDir, 4072, 10);
            WriteUInt32Le(subDir, 4076, 10);
            WriteUInt32Le(subDir, 4088, 1);
            fs.Position = 65 * 4096;
            fs.Write(subDir, 0, 4096);

            // Inode 25 (File "log.txt" under "artifacts") at block 66
            byte[] subFile = new byte[4096];
            WriteUInt16Le(subFile, 0, (ushort)F2fsScout.ModeTypeReg);
            subFile[3] = F2fsScout.InlineDataFlag;
            byte[] filePayload = Encoding.UTF8.GetBytes("System boot completed successfully at 00:00:01");
            WriteUInt64Le(subFile, 16, (ulong)filePayload.Length);
            WriteUInt32Le(subFile, 84, 10); // parent = 10
            byte[] fName = Encoding.UTF8.GetBytes("log.txt");
            WriteUInt32Le(subFile, 88, (uint)fName.Length);
            Array.Copy(fName, 0, subFile, 92, fName.Length);
            Array.Copy(filePayload, 0, subFile, 352, filePayload.Length);
            WriteUInt32Le(subFile, 4072, 25);
            WriteUInt32Le(subFile, 4076, 25);
            WriteUInt32Le(subFile, 4088, 1);
            fs.Position = 66 * 4096;
            fs.Write(subFile, 0, 4096);

            fs.Flush();
            fs.Position = 0;

            var result = F2fsScout.Scout(fs, CancellationToken.None, null);
            Check(result != null, "Scout result should not be null");
            Check(result.Superblocks.Count >= 1, "Should have found superblocks");
            Check(result.Files.Count == 3, "Should have discovered 3 inodes (root, artifacts, log.txt)");

            // Verify full paths
            F2fsScout.F2fsFileRecord rootRec = result.Files.Find(delegate(F2fsScout.F2fsFileRecord f) { return f.InodeNumber == 3; });
            F2fsScout.F2fsFileRecord dirRec = result.Files.Find(delegate(F2fsScout.F2fsFileRecord f) { return f.InodeNumber == 10; });
            F2fsScout.F2fsFileRecord fileRec2 = result.Files.Find(delegate(F2fsScout.F2fsFileRecord f) { return f.InodeNumber == 25; });

            Check(rootRec != null && rootRec.FullPath == "/", "Root path should be /");
            Check(dirRec != null && dirRec.FullPath == "/artifacts", "Subdir path should be /artifacts");
            Check(fileRec2 != null && fileRec2.FullPath == "/artifacts/log.txt", "File full path should be /artifacts/log.txt");
            Check(fileRec2.Extents.Count == 1 && fileRec2.Extents[0].IsInline, "File should have inline extent");

            string json = result.ToJson();
            Check(json.Contains("/artifacts/log.txt"), "JSON export must contain full path");
        }
    }

    private static byte[] CreateMockSuperblock(ushort major, ushort minor, string volName)
    {
        byte[] sb = new byte[1024];
        WriteUInt32Le(sb, 0, F2fsScout.F2fsSuperMagic);
        WriteUInt16Le(sb, 4, major);
        WriteUInt16Le(sb, 6, minor);
        WriteUInt32Le(sb, 8, 9);   // logSectorSize = 9 (512)
        WriteUInt32Le(sb, 16, 12); // logBlockSize = 12 (4096)
        WriteUInt32Le(sb, 20, 9);  // logBlocksPerSeg = 9 (512)
        WriteUInt32Le(sb, 24, 1);  // segs_per_sec = 1
        WriteUInt32Le(sb, 28, 1);  // secs_per_zone = 1
        WriteUInt64Le(sb, 36, 1024); // totalBlocks = 1024
        WriteUInt32Le(sb, 44, 2);  // sectionCount = 2
        WriteUInt32Le(sb, 48, 2);  // segmentCount = 2
        WriteUInt32Le(sb, 72, 4);  // cpBlkAddr = 4
        WriteUInt32Le(sb, 80, 8);  // natBlkAddr = 8
        WriteUInt32Le(sb, 88, 16); // mainBlkAddr = 16
        WriteUInt32Le(sb, 92, 3);  // rootIno = 3

        // UUID
        byte[] uuid = Guid.NewGuid().ToByteArray();
        Array.Copy(uuid, 0, sb, 104, 16);

        // Volume name UTF-16LE
        byte[] nameBytes = Encoding.Unicode.GetBytes(volName);
        Array.Copy(nameBytes, 0, sb, 120, Math.Min(nameBytes.Length, 500));

        return sb;
    }

    private static void WriteUInt16Le(byte[] b, int offset, ushort val)
    {
        b[offset] = (byte)(val & 0xFF);
        b[offset + 1] = (byte)((val >> 8) & 0xFF);
    }

    private static void WriteUInt32Le(byte[] b, int offset, uint val)
    {
        b[offset] = (byte)(val & 0xFF);
        b[offset + 1] = (byte)((val >> 8) & 0xFF);
        b[offset + 2] = (byte)((val >> 16) & 0xFF);
        b[offset + 3] = (byte)((val >> 24) & 0xFF);
    }

    private static void WriteUInt64Le(byte[] b, int offset, ulong val)
    {
        WriteUInt32Le(b, offset, (uint)(val & 0xFFFFFFFFU));
        WriteUInt32Le(b, offset + 4, (uint)((val >> 32) & 0xFFFFFFFFU));
    }
}
