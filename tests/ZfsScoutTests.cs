using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class ZfsScoutTests
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
        Console.WriteLine("Running ZfsScoutTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "zfs-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            // 1. Test Uberblock Discovery & Highest TXG Resolution
            TestUberblockDiscovery(testDir);

            // 2. Test Block Pointer Parsing
            TestBlockPointerParsing();

            // 3. Test Dnode & Object Traversal
            TestDnodeObjectTraversal(testDir);

            // 4. Test CLI Dispatch
            TestCliDispatch(testDir);

            Console.WriteLine("PASS ZfsScout: {0} checks; ZFS VDEV labels, uberblock arrays, transaction groups and dnodes verified.", checks);
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

    private static void TestUberblockDiscovery(string testDir)
    {
        string imgPath = Path.Combine(testDir, "zfs_pool.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            // Pool image: 1 MiB (contains Label 0 at 0, Label 1 at 256K, Label 2 at 512K, Label 3 at 768K)
            fs.SetLength(1024 * 1024);

            // Label 0: slot 0 (offset 32768) -> TXG 100
            fs.Seek(32768, SeekOrigin.Begin);
            byte[] ub0 = CreateSyntheticUberblock(100, 1729000000, 0x100);
            fs.Write(ub0, 0, ub0.Length);

            // Label 0: slot 1 (offset 33792) -> TXG 150 (ACTIVE!)
            fs.Seek(33792, SeekOrigin.Begin);
            byte[] ub1 = CreateSyntheticUberblock(150, 1729000500, 0x200);
            fs.Write(ub1, 0, ub1.Length);

            // Label 1: slot 0 (offset 256K + 32K = 294912) -> TXG 120
            fs.Seek(294912, SeekOrigin.Begin);
            byte[] ub2 = CreateSyntheticUberblock(120, 1729000200, 0x150);
            fs.Write(ub2, 0, ub2.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var ubs = ZfsScout.ProbeUberblocks(fs);
            Check(ubs != null && ubs.Count == 3, "Found 3 uberblocks across VDEV labels");

            var result = ZfsScout.Scout(fs, CancellationToken.None, null);
            Check(result != null, "Scout result not null");
            Check(result.Status == "complete", "Scout status complete");
            Check(result.UberblocksFound == 3, "Uberblocks count matches 3");

            // Verify active uberblock has highest TXG (150)
            Check(result.ActiveUberblock != null, "Active uberblock identified");
            Check(result.ActiveUberblock.Txg == 150, "Active uberblock has highest TXG 150");
            Check(result.ActiveUberblock.SlotIndex == 1, "Active uberblock slot index 1");
            Check(result.ActiveUberblock.VdevLabel == 0, "Active uberblock label 0");
            Check(result.ActiveUberblock.RootBlockPointer != null, "Root block pointer present");
            Check(result.ActiveUberblock.RootBlockPointer.DvaSectorOffset == 0x200, "Root BP DVA sector offset matches");
            Check(result.ActiveUberblock.RootBlockPointer.PhysicalByteOffset == 0x200 * 512, "Root BP physical byte offset matches");
        }
    }

    private static void TestBlockPointerParsing()
    {
        byte[] bpBuf = new byte[128];
        // DVA 0: asize = 128 KiB (256 sectors), vdev = 1
        // dva0_hi = (asize / 512 << 40) | vdev
        ulong asizeSec = 256;
        ulong vdev = 1;
        ulong hi = (asizeSec << 40) | vdev;
        ulong sectorOff = 0x8000;
        ulong lo = sectorOff;

        BitConverter.GetBytes(hi).CopyTo(bpBuf, 0);
        BitConverter.GetBytes(lo).CopyTo(bpBuf, 8);

        // Props at offset 48: comp=1 (lzjb), chksum=2 (fletcher4), objType=19 (plain file)
        ulong props = ((ulong)1 << 56) | ((ulong)2 << 48) | ((ulong)19 << 40);
        BitConverter.GetBytes(props).CopyTo(bpBuf, 48);

        // Birth TXG = 42
        BitConverter.GetBytes((ulong)42).CopyTo(bpBuf, 80);

        var ptr = ZfsScout.ParseBlockPointer(bpBuf, 0, false);
        Check(ptr != null, "Block pointer parsed");
        Check(ptr.DvaVdev == 1, "DVA vdev matches 1");
        Check(ptr.DvaSectorOffset == 0x8000, "DVA sector offset 0x8000");
        Check(ptr.PhysicalByteOffset == (long)0x8000 * 512, "Physical offset 16 MiB");
        Check(ptr.AllocatedBytes == 128 * 1024, "Allocated bytes 128 KiB");
        Check(ptr.CompressionType == 1, "Compression type 1");
        Check(ptr.ChecksumType == 2, "Checksum type 2");
        Check(ptr.ObjectType == 19, "Object type 19");
        Check(ptr.BirthTxg == 42, "Birth TXG 42");
    }

    private static void TestDnodeObjectTraversal(string testDir)
    {
        string imgPath = Path.Combine(testDir, "zfs_dnodes.img");
        using (var fs = new FileStream(imgPath, FileMode.Create, FileAccess.ReadWrite))
        {
            fs.SetLength(1024 * 1024);
            // Label 0 uberblock at 32768
            fs.Seek(32768, SeekOrigin.Begin);
            byte[] ub = CreateSyntheticUberblock(200, 1729000800, 0x1000);
            fs.Write(ub, 0, ub.Length);

            // Write Dnodes at offset 512 KiB (524288)
            fs.Seek(524288, SeekOrigin.Begin);
            byte[] dnodesBlock = new byte[1024];

            // Dnode 0 (512 bytes): Directory object (type 20)
            WriteSyntheticDnode(dnodesBlock, 0, 20, 1, 256, "documents");

            // Dnode 1 (512 bytes): Plain file object (type 19)
            WriteSyntheticDnode(dnodesBlock, 512, 19, 1, 256, "financial_data.csv");

            fs.Write(dnodesBlock, 0, dnodesBlock.Length);
        }

        using (var fs = File.OpenRead(imgPath))
        {
            var result = ZfsScout.Scout(fs, CancellationToken.None, null);
            Check(result != null, "Scout result not null");
            Check(result.FilesCount >= 1, "At least one file object carved");
            Check(result.DirectoriesCount >= 1, "At least one directory object carved");

            ZfsScout.ZfsFileRecord csvFile = null;
            foreach (var f in result.Files)
            {
                if (f.Name != null && f.Name.Contains("financial_data.csv")) csvFile = f;
            }

            Check(csvFile != null, "financial_data.csv discovered");
            Check(!csvFile.IsDirectory, "financial_data.csv is not directory");
            Check(csvFile.FileSizeBytes == 128 * 1024, "File size 128 KiB");
            Check(csvFile.BlockExtents.Count == 1, "Block extent found");
            Check(csvFile.BlockExtents[0].PhysicalByteOffset > 0, "Physical offset mapped");
        }
    }

    private static void TestCliDispatch(string testDir)
    {
        string imgPath = Path.Combine(testDir, "zfs_dnodes.img");
        int rc = CommandLineHandler.Run(new string[] { "zfs-scout", imgPath, "--json" });
        Check(rc == 0, "CLI zfs-scout exit code 0");
    }

    private static byte[] CreateSyntheticUberblock(ulong txg, ulong timestamp, ulong rootBpSector)
    {
        byte[] ub = new byte[1024];
        // 0..7: Magic 0x00bab10c
        BitConverter.GetBytes(ZfsScout.UberblockMagicLe).CopyTo(ub, 0);

        // 8..15: TXG
        BitConverter.GetBytes(txg).CopyTo(ub, 8);

        // 16..23: GuidSum
        BitConverter.GetBytes((ulong)0x1234567890ABCDEFUL).CopyTo(ub, 16);

        // 24..31: Timestamp
        BitConverter.GetBytes(timestamp).CopyTo(ub, 24);

        // 32..159: Root Block Pointer
        // DVA 0: asize=256 (128KB), vdev=0
        ulong hi = ((ulong)256 << 40) | 0;
        ulong lo = rootBpSector;
        BitConverter.GetBytes(hi).CopyTo(ub, 32);
        BitConverter.GetBytes(lo).CopyTo(ub, 40);

        // Props: plain file type=19
        ulong props = ((ulong)19 << 40);
        BitConverter.GetBytes(props).CopyTo(ub, 32 + 48);

        // Birth TXG = txg
        BitConverter.GetBytes(txg).CopyTo(ub, 32 + 80);

        return ub;
    }

    private static void WriteSyntheticDnode(byte[] block, int slot, byte dnType, byte nblkptr, ushort datablkszsec, string name)
    {
        // 0: dn_type
        block[slot] = dnType;
        // 3: dn_nlevels = 1
        block[slot + 3] = 1;
        // 4: dn_nblkptr
        block[slot + 4] = nblkptr;
        // 6..7: dn_datablkszsec (256 = 128 KiB)
        BitConverter.GetBytes(datablkszsec).CopyTo(block, slot + 6);

        // Block pointer at slot + 64:
        ulong hi = ((ulong)datablkszsec << 40);
        ulong lo = (ulong)(0x1000 + slot);
        BitConverter.GetBytes(hi).CopyTo(block, slot + 64);
        BitConverter.GetBytes(lo).CopyTo(block, slot + 72);

        // Bonus buffer at slot + 192: write name
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        Buffer.BlockCopy(nameBytes, 0, block, slot + 192, Math.Min(64, nameBytes.Length));
    }
}
