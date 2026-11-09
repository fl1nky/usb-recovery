using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class BtrfsScoutTests
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
        Console.WriteLine("Running BtrfsScoutTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "btrfs-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            // 1. Test Superblock creation and parsing
            TestSuperblockParsing(testDir);

            // 2. Test Logical to Physical address translation
            TestChunkTranslation();

            // 3. Test Full Leaf Parsing and File Reconstruction
            TestLeafAndFileReconstruction(testDir);

            // 4. Test Inline Extent Data
            TestInlineExtents(testDir);

            // 5. Test CLI btrfs-scout and probe
            TestCliBtrfsScout(testDir);

            Console.WriteLine("PASS BtrfsScout: {0} checks; Btrfs superblocks, chunk mappings, leaf nodes and file extents verified.", checks);
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
        string imgPath = Path.Combine(testDir, "btrfs_sb.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(0x20000); // 128 KiB
            // Primary SB is at offset 0x10000 (64 KiB)
            fs.Seek(0x10000, SeekOrigin.Begin);
            byte[] sb = CreateSyntheticSuperblock(1542, "usb_backup", 0x100000, 0x200000, 0x1000000);
            fs.Write(sb, 0, sb.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var sbs = BtrfsScout.ProbeSuperblocks(fs);
            Check(sbs != null && sbs.Count == 1, "Exactly one superblock found");
            var sb = sbs[0];
            Check(sb.PhysicalOffset == 0x10000, "Superblock physical offset 64 KiB");
            Check(sb.Generation == 1542, "Superblock generation matches");
            Check(sb.Label == "usb_backup", "Superblock label matches");
            Check(sb.SectorSize == 4096, "Sector size matches 4096");
            Check(sb.NodeSize == 16384, "Node size matches 16384");
            Check(sb.SystemChunks != null && sb.SystemChunks.Count >= 1, "System chunk mappings parsed");
            Check(sb.SystemChunks[0].LogicalAddress == 0x100000, "Chunk logical address");
            Check(sb.SystemChunks[0].PhysicalOffset == 0x200000, "Chunk physical offset");
        }
    }

    private static void TestChunkTranslation()
    {
        var chunks = new List<BtrfsScout.ChunkMapping>
        {
            new BtrfsScout.ChunkMapping
            {
                LogicalAddress = 0x100000,
                Length = 0x1000000, // 16 MiB
                PhysicalOffset = 0x200000
            },
            new BtrfsScout.ChunkMapping
            {
                LogicalAddress = 0x2000000,
                Length = 0x1000000,
                PhysicalOffset = 0x5000000
            }
        };

        long phys1 = BtrfsScout.LogicalToPhysical(0x100000, chunks);
        Check(phys1 == 0x200000, "Start of chunk 1 mapped");

        long phys2 = BtrfsScout.LogicalToPhysical(0x104000, chunks);
        Check(phys2 == 0x204000, "Offset in chunk 1 mapped");

        long phys3 = BtrfsScout.LogicalToPhysical(0x2001000, chunks);
        Check(phys3 == 0x5001000, "Offset in chunk 2 mapped");

        long physNotFound = BtrfsScout.LogicalToPhysical(0x50000, chunks);
        Check(physNotFound == -1, "Unmapped logical address returns -1");
    }

    private static void TestLeafAndFileReconstruction(string testDir)
    {
        string imgPath = Path.Combine(testDir, "btrfs_leaf.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(0x40000); // 256 KiB
            // 1. Write Superblock at 0x10000
            fs.Seek(0x10000, SeekOrigin.Begin);
            byte[] sb = CreateSyntheticSuperblock(100, "test_fs", 0x100000, 0x200000, 0x1000000);
            fs.Write(sb, 0, sb.Length);

            // 2. Write Leaf at 0x20000 (128 KiB)
            fs.Seek(0x20000, SeekOrigin.Begin);
            byte[] leaf = CreateSyntheticLeafWithFiles();
            fs.Write(leaf, 0, leaf.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var result = BtrfsScout.Scout(fs, CancellationToken.None, null);
            Check(result != null, "Scout result not null");
            Check(result.Status == "complete", "Scout status complete");
            Check(result.Superblocks.Count == 1, "One superblock found");
            Check(result.DirectoriesCount >= 1, "At least one directory found");
            Check(result.FilesCount >= 1, "At least one file found");

            // Look for secret.txt
            BtrfsScout.BtrfsFileRecord secretFile = null;
            foreach (var f in result.Files)
            {
                if (f.Name == "secret.txt") secretFile = f;
            }

            Check(secretFile != null, "secret.txt discovered in Btrfs tree");
            Check(secretFile.InodeId == 257, "Inode ID matches 257");
            Check(secretFile.Size == 42, "File size matches 42 bytes");
            Check(secretFile.FullPath == "/secret.txt", "Full path matches /secret.txt");
            Check(secretFile.Extents != null && secretFile.Extents.Count == 1, "One extent found");
            Check(secretFile.Extents[0].DiskByteNr == 0x104000, "Extent disk bytenr");
            Check(secretFile.Extents[0].PhysicalOffset == 0x204000, "Physical offset mapped correctly");
            Check(secretFile.Extents[0].Length == 42, "Extent length 42");
        }
    }

    private static void TestInlineExtents(string testDir)
    {
        string imgPath = Path.Combine(testDir, "btrfs_inline.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(0x40000);
            fs.Seek(0x10000, SeekOrigin.Begin);
            byte[] sb = CreateSyntheticSuperblock(50, "inline_test", 0x100000, 0x200000, 0x1000000);
            fs.Write(sb, 0, sb.Length);

            fs.Seek(0x20000, SeekOrigin.Begin);
            byte[] leaf = CreateSyntheticLeafWithInlineFile();
            fs.Write(leaf, 0, leaf.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var result = BtrfsScout.Scout(fs, CancellationToken.None, null);
            Check(result.FilesCount >= 1, "Inline file found");
            BtrfsScout.BtrfsFileRecord inlineFile = null;
            foreach (var f in result.Files)
            {
                if (f.Name == "notes.txt") inlineFile = f;
            }

            Check(inlineFile != null, "notes.txt found");
            Check(inlineFile.Extents.Count == 1, "notes.txt has 1 extent");
            Check(inlineFile.Extents[0].IsInline, "Extent is inline");
            Check(inlineFile.Extents[0].InlineData != null, "Inline data present");
            string text = Encoding.UTF8.GetString(inlineFile.Extents[0].InlineData);
            Check(text == "Btrfs inline content recovered!", "Inline text matches payload");
        }
    }

    private static void TestCliBtrfsScout(string testDir)
    {
        string imgPath = Path.Combine(testDir, "btrfs_leaf.img");
        int rc1 = CommandLineHandler.Run(new string[] { "btrfs-scout", imgPath, "--json" });
        Check(rc1 == 0, "CLI btrfs-scout exit code 0");

        int rc2 = CommandLineHandler.Run(new string[] { "probe", imgPath, "--json" });
        Check(rc2 == 0, "CLI probe exit code 0");
    }

    private static byte[] CreateSyntheticSuperblock(ulong generation, string label, ulong chunkLog, ulong chunkPhys, ulong chunkLen)
    {
        byte[] sb = new byte[4096];
        // Offset 0x20: UUID (16 bytes)
        for (int i = 0; i < 16; i++) sb[0x20 + i] = (byte)(0x10 + i);

        // Offset 0x40: Magic "_BHRfS_M"
        BtrfsScout.BtrfsMagic.CopyTo(sb, 0x40);

        // Offset 0x48: Generation
        BitConverter.GetBytes(generation).CopyTo(sb, 0x48);

        // Offset 0x68: TotalBytes = 1 GiB
        BitConverter.GetBytes((ulong)1024 * 1024 * 1024).CopyTo(sb, 0x68);

        // Offset 0x78: RootDirObjectId = 256
        BitConverter.GetBytes((ulong)256).CopyTo(sb, 0x78);

        // Offset 0x88: SectorSize = 4096
        BitConverter.GetBytes((uint)4096).CopyTo(sb, 0x88);

        // Offset 0x8C: NodeSize = 16384
        BitConverter.GetBytes((uint)16384).CopyTo(sb, 0x8C);

        // Offset 0x90: LeafSize = 16384
        BitConverter.GetBytes((uint)16384).CopyTo(sb, 0x90);

        // Label at offset 0x12A (298)
        byte[] labelBytes = Encoding.UTF8.GetBytes(label);
        labelBytes.CopyTo(sb, 0x12A);

        // System chunk array at 0x1A4 (420)
        // Entry: btrfs_key (17) + btrfs_chunk (48) + btrfs_stripe (32) = 97 bytes
        int chunkPos = 0x1A4;
        // Key: objId=256, type=228 (CHUNK_ITEM), offset=chunkLog
        BitConverter.GetBytes((ulong)256).CopyTo(sb, chunkPos);
        sb[chunkPos + 8] = 228;
        BitConverter.GetBytes(chunkLog).CopyTo(sb, chunkPos + 9);
        chunkPos += 17;

        // Chunk: length, owner=2, stripe_len=65536, type=1, io_align=4096, io_width=4096, sector_size=4096, num_stripes=1
        BitConverter.GetBytes(chunkLen).CopyTo(sb, chunkPos);
        BitConverter.GetBytes((ulong)2).CopyTo(sb, chunkPos + 8);
        BitConverter.GetBytes((ulong)65536).CopyTo(sb, chunkPos + 16);
        BitConverter.GetBytes((ulong)1).CopyTo(sb, chunkPos + 24);
        BitConverter.GetBytes((ushort)1).CopyTo(sb, chunkPos + 44); // num_stripes
        chunkPos += 48;

        // Stripe: devid=1, offset=chunkPhys
        BitConverter.GetBytes((ulong)1).CopyTo(sb, chunkPos);
        BitConverter.GetBytes(chunkPhys).CopyTo(sb, chunkPos + 8);
        chunkPos += 32;

        // Set sys_chunk_array_size at 0x98
        BitConverter.GetBytes((uint)(chunkPos - 0x1A4)).CopyTo(sb, 0x98);

        return sb;
    }

    private static byte[] CreateSyntheticLeafWithFiles()
    {
        byte[] leaf = new byte[16384];

        // Leaf header: 101 bytes
        // Offset 96: nritems = 4
        BitConverter.GetBytes((uint)4).CopyTo(leaf, 96);
        // Offset 100: level = 0 (leaf)
        leaf[100] = 0;

        int headerSize = 101;
        int itemHdrSize = 25;

        // Item 0: Root directory INODE_ITEM (objId=256, type=1, offset=0)
        // Data placed at leaf offset 15000 (relative to header = 15000 - 101 = 14899)
        int dataPos0 = 15000;
        WriteItemHeader(leaf, headerSize + 0 * itemHdrSize, 256, 1, 0, (uint)(dataPos0 - 101), 160);
        WriteInodeData(leaf, dataPos0, 0, 0x41ED, 1729000000); // dir

        // Item 1: DIR_ITEM linking 256 -> "secret.txt" (child objId=257)
        int dataPos1 = 15200;
        string fileName = "secret.txt";
        byte[] nameBytes = Encoding.UTF8.GetBytes(fileName);
        uint dirItemSize = (uint)(30 + nameBytes.Length);
        WriteItemHeader(leaf, headerSize + 1 * itemHdrSize, 256, 84, 0, (uint)(dataPos1 - 101), dirItemSize);
        WriteDirItemData(leaf, dataPos1, 257, 1, nameBytes);

        // Item 2: File INODE_ITEM (objId=257, type=1, offset=0, size=42)
        int dataPos2 = 15300;
        WriteItemHeader(leaf, headerSize + 2 * itemHdrSize, 257, 1, 0, (uint)(dataPos2 - 101), 160);
        WriteInodeData(leaf, dataPos2, 42, 0x81A4, 1729000100); // regular file

        // Item 3: EXTENT_DATA (objId=257, type=108, offset=0, diskByteNr=0x104000, length=42)
        int dataPos3 = 15500;
        WriteItemHeader(leaf, headerSize + 3 * itemHdrSize, 257, 108, 0, (uint)(dataPos3 - 101), 53);
        WriteRegularExtentData(leaf, dataPos3, 0x104000, 42);

        return leaf;
    }

    private static byte[] CreateSyntheticLeafWithInlineFile()
    {
        byte[] leaf = new byte[16384];
        BitConverter.GetBytes((uint)3).CopyTo(leaf, 96);
        leaf[100] = 0;

        int headerSize = 101;
        int itemHdrSize = 25;

        // Dir item: notes.txt (inode 300)
        string name = "notes.txt";
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        WriteItemHeader(leaf, headerSize + 0 * itemHdrSize, 256, 84, 0, (uint)(15000 - 101), (uint)(30 + nameBytes.Length));
        WriteDirItemData(leaf, 15000, 300, 1, nameBytes);

        // Inode item: notes.txt
        byte[] textBytes = Encoding.UTF8.GetBytes("Btrfs inline content recovered!");
        WriteItemHeader(leaf, headerSize + 1 * itemHdrSize, 300, 1, 0, (uint)(15100 - 101), 160);
        WriteInodeData(leaf, 15100, (ulong)textBytes.Length, 0x81A4, 1729000200);

        // Extent data: inline
        uint extSize = (uint)(21 + textBytes.Length);
        WriteItemHeader(leaf, headerSize + 2 * itemHdrSize, 300, 108, 0, (uint)(15300 - 101), extSize);
        // byte 20 = 0 (inline)
        leaf[15300 + 20] = 0;
        textBytes.CopyTo(leaf, 15300 + 21);

        return leaf;
    }

    private static void WriteItemHeader(byte[] leaf, int pos, ulong objId, byte type, ulong offset, uint dataOffsetRel, uint dataSize)
    {
        BitConverter.GetBytes(objId).CopyTo(leaf, pos);
        leaf[pos + 8] = type;
        BitConverter.GetBytes(offset).CopyTo(leaf, pos + 9);
        BitConverter.GetBytes(dataOffsetRel).CopyTo(leaf, pos + 17);
        BitConverter.GetBytes(dataSize).CopyTo(leaf, pos + 21);
    }

    private static void WriteInodeData(byte[] leaf, int pos, ulong size, uint mode, ulong mtime)
    {
        BitConverter.GetBytes(size).CopyTo(leaf, pos + 16);
        BitConverter.GetBytes(mode).CopyTo(leaf, pos + 40);
        BitConverter.GetBytes(mtime).CopyTo(leaf, pos + 112);
    }

    private static void WriteDirItemData(byte[] leaf, int pos, ulong childObjId, byte childType, byte[] nameBytes)
    {
        BitConverter.GetBytes(childObjId).CopyTo(leaf, pos);
        leaf[pos + 8] = childType;
        // name_len at pos + 27
        BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(leaf, pos + 27);
        leaf[pos + 29] = 1; // regular file
        nameBytes.CopyTo(leaf, pos + 30);
    }

    private static void WriteRegularExtentData(byte[] leaf, int pos, ulong diskByteNr, ulong length)
    {
        leaf[pos + 20] = 1; // regular extent
        BitConverter.GetBytes(diskByteNr).CopyTo(leaf, pos + 21);
        BitConverter.GetBytes(length).CopyTo(leaf, pos + 29); // disk_num_bytes
        BitConverter.GetBytes((ulong)0).CopyTo(leaf, pos + 37); // offset
        BitConverter.GetBytes(length).CopyTo(leaf, pos + 45); // num_bytes
    }
}
