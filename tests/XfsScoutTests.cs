using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class XfsScoutTests
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
        Console.WriteLine("Running XfsScoutTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "xfs-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            // 1. Test Superblock Parsing
            TestSuperblockParsing(testDir);

            // 2. Test Inodes, Directory Hierarchy & Extent Mapping
            TestInodeAndExtentRecovery(testDir);

            // 3. Test Inline File Payload
            TestInlineFile(testDir);

            // 4. Test CLI Dispatch
            TestCliDispatch(testDir);

            Console.WriteLine("PASS XfsScout: {0} checks; XFS Allocation Group superblocks, inodes, extents and directory graph verified.", checks);
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
        string imgPath = Path.Combine(testDir, "xfs_sb.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(0x20000); // 128 KiB
            // Primary SB at offset 0
            byte[] sb0 = CreateSyntheticSuperblock(4096, 16, 2, 256, "xfs_primary");
            fs.Write(sb0, 0, sb0.Length);

            // Secondary SB at AG 1: offset = 16 * 4096 = 65536 (0x10000)
            fs.Seek(65536, SeekOrigin.Begin);
            byte[] sb1 = CreateSyntheticSuperblock(4096, 16, 2, 256, "xfs_ag1");
            fs.Write(sb1, 0, sb1.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var sbs = XfsScout.ProbeSuperblocks(fs);
            Check(sbs != null && sbs.Count == 2, "Found 2 XFS superblocks (primary + AG1)");
            Check(sbs[0].PhysicalOffset == 0, "Primary SB offset 0");
            Check(sbs[0].BlockSize == 4096, "Block size 4096");
            Check(sbs[0].AgBlocks == 16, "AG blocks 16");
            Check(sbs[0].AgCount == 2, "AG count 2");
            Check(sbs[0].InodeSize == 256, "Inode size 256");
            Check(sbs[0].Label == "xfs_primary", "Label matches xfs_primary");

            Check(sbs[1].PhysicalOffset == 65536, "AG1 SB offset 65536");
            Check(sbs[1].AllocationGroup == 1, "AG1 index 1");
        }
    }

    private static void TestInodeAndExtentRecovery(string testDir)
    {
        string imgPath = Path.Combine(testDir, "xfs_data.img");
        uint blockSize = 4096;
        ushort inodeSize = 256;

        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(0x40000); // 256 KiB
            // Superblock at offset 0
            byte[] sb = CreateSyntheticSuperblock(blockSize, 64, 1, inodeSize, "xfs_data");
            fs.Write(sb, 0, sb.Length);

            // Inode block at offset 4096 (block 1):
            // Inode 16 (offset 4096): Root Directory inode (format 1 - shortform)
            // Inode 17 (offset 4352): File inode "database.db" (format 2 - extents)
            fs.Seek(4096, SeekOrigin.Begin);
            byte[] inodeBlock = new byte[blockSize];

            // Inode 16: Directory linking to child inode 17 ("database.db")
            WriteDirectoryInode(inodeBlock, 0, 16, 17, "database.db");

            // Inode 17: Regular file with extents
            // startblock = 10 (physical offset 40960), blockcount = 5 (20480 bytes)
            WriteExtentFileInode(inodeBlock, 256, 17, 20480, 10, 5);

            fs.Write(inodeBlock, 0, inodeBlock.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var result = XfsScout.Scout(fs, CancellationToken.None, null);
            Check(result != null, "Scout result not null");
            Check(result.Status == "complete", "Scout status complete");
            Check(result.Superblocks.Count == 1, "One superblock found");
            Check(result.DirectoriesCount >= 1, "At least one directory found");
            Check(result.FilesCount >= 1, "At least one file found");

            XfsScout.XfsFileRecord dbFile = null;
            foreach (var f in result.Files)
            {
                if (f.Name == "database.db") dbFile = f;
            }

            Check(dbFile != null, "database.db found in XFS");
            Check(dbFile.FullPath == "/database.db", "database.db full path");
            Check(dbFile.Size == 20480, "database.db size match");
            Check(dbFile.Extents.Count == 1, "One extent found");
            Check(dbFile.Extents[0].PhysicalBlockNumber == 10, "Physical block number 10");
            Check(dbFile.Extents[0].PhysicalByteOffset == 40960, "Physical byte offset 40960");
            Check(dbFile.Extents[0].BlockCount == 5, "Block count 5");
        }
    }

    private static void TestInlineFile(string testDir)
    {
        string imgPath = Path.Combine(testDir, "xfs_inline.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(0x20000);
            byte[] sb = CreateSyntheticSuperblock(4096, 32, 1, 256, "xfs_inline");
            fs.Write(sb, 0, sb.Length);

            fs.Seek(4096, SeekOrigin.Begin);
            byte[] inodeBlock = new byte[4096];

            // Inode 16: Directory -> "notes.txt" (inode 17)
            WriteDirectoryInode(inodeBlock, 0, 16, 17, "notes.txt");

            // Inode 17: Inline file
            byte[] payload = Encoding.UTF8.GetBytes("Recovered XFS inline payload!");
            WriteInlineFileInode(inodeBlock, 256, 17, payload);

            fs.Write(inodeBlock, 0, inodeBlock.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var result = XfsScout.Scout(fs, CancellationToken.None, null);
            Check(result.FilesCount >= 1, "Inline file recovered");

            XfsScout.XfsFileRecord notesFile = null;
            foreach (var f in result.Files)
            {
                if (f.Name == "notes.txt") notesFile = f;
            }

            Check(notesFile != null, "notes.txt found");
            Check(notesFile.Extents.Count == 1, "One extent");
            Check(notesFile.Extents[0].IsInline, "Extent is inline");
            Check(notesFile.Extents[0].InlineData != null, "Inline data present");
            string text = Encoding.UTF8.GetString(notesFile.Extents[0].InlineData);
            Check(text == "Recovered XFS inline payload!", "Inline text matches payload");
        }
    }

    private static void TestCliDispatch(string testDir)
    {
        string imgPath = Path.Combine(testDir, "xfs_data.img");
        int rc = CommandLineHandler.Run(new string[] { "xfs-scout", imgPath, "--json" });
        Check(rc == 0, "CLI xfs-scout exit code 0");
    }

    private static byte[] CreateSyntheticSuperblock(uint blockSize, uint agBlocks, uint agCount, ushort inodeSize, string label)
    {
        byte[] sb = new byte[512];
        // 0..3: "XFSB"
        XfsScout.XfsMagic.CopyTo(sb, 0);

        // 4..7: BlockSize (BE)
        WriteUInt32Be(sb, 4, blockSize);

        // 8..15: DataBlocks (BE)
        WriteUInt64Be(sb, 8, (ulong)agBlocks * agCount);

        // 32..47: UUID
        for (int i = 0; i < 16; i++) sb[32 + i] = (byte)(0x20 + i);

        // 56..63: RootInode = 16
        WriteUInt64Be(sb, 56, 16);

        // 84..87: AgBlocks
        WriteUInt32Be(sb, 84, agBlocks);

        // 88..91: AgCount
        WriteUInt32Be(sb, 88, agCount);

        // 104..105: InodeSize
        WriteUInt16Be(sb, 104, inodeSize);

        // 106..107: InodesPerBlock
        WriteUInt16Be(sb, 106, (ushort)(blockSize / inodeSize));

        // 108..119: Label
        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        Buffer.BlockCopy(labelBytes, 0, sb, 108, Math.Min(12, labelBytes.Length));

        return sb;
    }

    private static void WriteDirectoryInode(byte[] block, int slot, ulong selfInode, ulong childInode, string childName)
    {
        // Magic 'IN'
        block[slot] = 0x49; block[slot + 1] = 0x4E;
        // di_mode: S_IFDIR (0x41ED)
        WriteUInt16Be(block, slot + 2, 0x41ED);
        // di_version = 2
        block[slot + 4] = 2;
        // di_format = 1 (local / shortform)
        block[slot + 5] = 1;
        // di_nlink = 2
        WriteUInt32Be(block, slot + 16, 2);

        // Data starts at slot + 100
        int data = slot + 100;
        // Shortform header:
        // count = 1
        block[data] = 1;
        // i8count = 0 (4-byte inodes)
        block[data + 1] = 0;
        // parent inode (4 bytes) = selfInode
        WriteUInt32Be(block, data + 2, (uint)selfInode);

        // Entry:
        // namelen (1 byte)
        byte[] nameBytes = Encoding.UTF8.GetBytes(childName);
        block[data + 6] = (byte)nameBytes.Length;
        // offset (2 bytes) = 0
        WriteUInt16Be(block, data + 7, 0);
        // name
        Buffer.BlockCopy(nameBytes, 0, block, data + 9, nameBytes.Length);
        // child inode (4 bytes)
        WriteUInt32Be(block, data + 9 + nameBytes.Length, (uint)childInode);
    }

    private static void WriteExtentFileInode(byte[] block, int slot, ulong selfInode, long fileSize, ulong startBlock, ulong blockCount)
    {
        block[slot] = 0x49; block[slot + 1] = 0x4E;
        // di_mode: S_IFREG (0x81A4)
        WriteUInt16Be(block, slot + 2, 0x81A4);
        block[slot + 4] = 2;
        // di_format = 2 (extents)
        block[slot + 5] = 2;
        // di_size
        WriteUInt64Be(block, slot + 8, (ulong)fileSize);
        // di_nlink = 1
        WriteUInt32Be(block, slot + 16, 1);
        // di_nextents = 1
        WriteUInt32Be(block, slot + 28, 1);

        // Data starts at slot + 100
        int data = slot + 100;

        // 128-bit packed extent descriptor:
        // startoff: 0
        // startblock: startBlock (52 bits)
        // blockcount: blockCount (21 bits)
        // hi = (startoff << 9) | (startblock >> 43)
        // lo = (startblock << 21) | blockCount
        ulong hi = ((ulong)0 << 9) | ((startBlock >> 43) & 0x1FFL);
        ulong lo = ((startBlock & 0x7FFFFFFFFFFFL) << 21) | (blockCount & 0x1FFFFFL);

        WriteUInt64Be(block, data, hi);
        WriteUInt64Be(block, data + 8, lo);
    }

    private static void WriteInlineFileInode(byte[] block, int slot, ulong selfInode, byte[] payload)
    {
        block[slot] = 0x49; block[slot + 1] = 0x4E;
        WriteUInt16Be(block, slot + 2, 0x81A4);
        block[slot + 4] = 2;
        // di_format = 1 (local / inline)
        block[slot + 5] = 1;
        WriteUInt64Be(block, slot + 8, (ulong)payload.Length);
        WriteUInt32Be(block, slot + 16, 1);

        int data = slot + 100;
        Buffer.BlockCopy(payload, 0, block, data, payload.Length);
    }

    private static void WriteUInt16Be(byte[] b, int offset, ushort val)
    {
        b[offset] = (byte)((val >> 8) & 0xFF);
        b[offset + 1] = (byte)(val & 0xFF);
    }

    private static void WriteUInt32Be(byte[] b, int offset, uint val)
    {
        b[offset] = (byte)((val >> 24) & 0xFF);
        b[offset + 1] = (byte)((val >> 16) & 0xFF);
        b[offset + 2] = (byte)((val >> 8) & 0xFF);
        b[offset + 3] = (byte)(val & 0xFF);
    }

    private static void WriteUInt64Be(byte[] b, int offset, ulong val)
    {
        WriteUInt32Be(b, offset, (uint)(val >> 32));
        WriteUInt32Be(b, offset + 4, (uint)(val & 0xFFFFFFFF));
    }
}
