using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class AmcacheParserTests
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
        Console.WriteLine("Running AmcacheParserTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "amcache-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            TestWindows10InventoryFiles(testDir);
            TestWindows7FileFormat(testDir);
            TestSuspiciousThreatDetection(testDir);
            TestRawStreamCarving(testDir);

            Console.WriteLine("PASS AmcacheParserTests: {0} checks passed; Windows 10/11 InventoryApplicationFile, Windows 7/8 File hive, SHA-1 parsing, threat heuristics, and stream carving verified.", checks);
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

    private static void TestWindows10InventoryFiles(string testDir)
    {
        byte[] hiveBytes = CreateMockHiveWithWin10Amcache();
        using (var hive = RegistryHive.Open(hiveBytes))
        {
            var entries = AmcacheParser.Parse(hive);
            Check(entries.Count == 2, "Should parse 2 entries from Windows 10 InventoryApplicationFile");

            var normal = entries.Find(delegate(AmcacheEntry e) { return e.Name == "svchost.exe"; });
            Check(normal != null, "Should find svchost.exe entry");
            Check(normal.Sha1 == "3b71c26b911e2f790c37554be50e7b752945d8f2", "Sha1 should have leading 0000 stripped");
            Check(normal.Path == @"C:\Windows\System32\svchost.exe", "Path should match");
            Check(normal.Publisher == "Microsoft Corporation", "Publisher should match");
            Check(normal.FileSize == 55320, "FileSize should match");
            Check(!normal.IsSuspicious, "Standard svchost in system32 should NOT be flagged as suspicious");

            var malware = entries.Find(delegate(AmcacheEntry e) { return e.Name == "payload.exe"; });
            Check(malware != null, "Should find payload.exe entry");
            Check(malware.Sha1 == "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "Sha1 should match");
            Check(malware.IsSuspicious, "Payload in Temp should be flagged as suspicious");
            Check(malware.SuspicionReason.Contains("Temp"), "Suspicion reason should mention Temp directory");
        }
    }

    private static void TestWindows7FileFormat(string testDir)
    {
        byte[] hiveBytes = CreateMockHiveWithWin7Amcache();
        using (var hive = RegistryHive.Open(hiveBytes))
        {
            var entries = AmcacheParser.Parse(hive);
            Check(entries.Count == 1, "Should parse 1 entry from Windows 7 format");
            var e = entries[0];
            Check(e.Path == @"C:\Program Files\Vendor\tool.exe", "Win7 path should match");
            Check(e.Sha1 == "f1e2d3c4b5a60718293a4b5c6d7e8f9012345678", "Win7 SHA1 should match");
            Check(e.Publisher == "Vendor Security Inc", "Company should match");
            Check(e.FileSize == 1048576, "Size should be 1 MiB");
        }
    }

    private static void TestSuspiciousThreatDetection(string testDir)
    {
        byte[] raw = Encoding.ASCII.GetBytes(@"C:\Users\John\AppData\Local\Temp\invoice.pdf.exe ... 1111222233334444555566667777888899990000");
        using (var ms = new MemoryStream(raw))
        {
            var carved = AmcacheParser.CarveFromStream(ms, System.Threading.CancellationToken.None);
            Check(carved.Count >= 1, "Should carve match");
            var item = carved.Find(delegate(AmcacheEntry e) { return e.Sha1 == "1111222233334444555566667777888899990000"; });
            Check(item != null, "Should find carved item");
            Check(item.IsSuspicious, "Double extension in Temp MUST be flagged suspicious");
            Check(item.SuspicionReason.Contains("Double extension") || item.SuspicionReason.Contains("Temp"),
                "Reason must indicate double extension or temp");
        }
    }

    private static void TestRawStreamCarving(string testDir)
    {
        string rawCarveFile = Path.Combine(testDir, "raw_disk_carve.bin");
        using (var fs = new FileStream(rawCarveFile, FileMode.Create, FileAccess.ReadWrite))
        {
            byte[] garbage = new byte[70000];
            fs.Write(garbage, 0, garbage.Length);

            byte[] record1 = Encoding.ASCII.GetBytes("Found file at C:\\Users\\Public\\miner.exe with checksum 99887766554433221100aabbccddeeff00112233 in deleted block");
            fs.Write(record1, 0, record1.Length);

            fs.Flush();
            fs.Position = 0;

            var results = AmcacheParser.CarveFromStream(fs, System.Threading.CancellationToken.None);
            Check(results.Count >= 1, "Should carve at least 1 entry across chunk boundary");
            var miner = results.Find(delegate(AmcacheEntry e) { return e.Sha1 == "99887766554433221100aabbccddeeff00112233"; });
            Check(miner != null, "Miner entry must be found");
            Check(miner.Path.Contains(@"C:\Users\Public\miner.exe"), "Path must be carved");
            Check(miner.IsSuspicious, "Miner in Public must be suspicious");
        }
    }

    // =========================================================================
    // Synthetic Hive Builders
    // =========================================================================

    private sealed class HiveBuilder
    {
        private readonly byte[] data;
        private int cursor;

        public HiveBuilder(int totalSize, string hiveName)
        {
            data = new byte[totalSize];
            cursor = 4096 + 32; // Skip 4096 header + 32 hbin header

            // Header (0..4095)
            data[0] = 0x72; data[1] = 0x65; data[2] = 0x67; data[3] = 0x66; // "regf"
            BitConverter.GetBytes(1U).CopyTo(data, 4);
            BitConverter.GetBytes(1U).CopyTo(data, 8);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 12);
            BitConverter.GetBytes(1U).CopyTo(data, 20); // major
            BitConverter.GetBytes(3U).CopyTo(data, 24); // minor
            BitConverter.GetBytes(32U).CopyTo(data, 36); // root cell offset relative to hbin (32)
            BitConverter.GetBytes((uint)(totalSize - 4096)).CopyTo(data, 40);

            byte[] nameBytes = Encoding.Unicode.GetBytes(hiveName);
            Array.Copy(nameBytes, 0, data, 48, Math.Min(nameBytes.Length, 64));

            // Hbin 1 header at 4096
            data[4096] = 0x68; data[4097] = 0x62; data[4098] = 0x69; data[4099] = 0x6E; // "hbin"
            BitConverter.GetBytes(0U).CopyTo(data, 4100);
            BitConverter.GetBytes((uint)(totalSize - 4096)).CopyTo(data, 4104);
        }

        public byte[] Finish()
        {
            if (cursor < data.Length)
            {
                int slack = data.Length - cursor;
                WriteCellHeader(cursor, slack, true);
            }

            uint checksum = 0;
            for (int i = 0; i < 508; i += 4)
            {
                checksum ^= BitConverter.ToUInt32(data, i);
            }
            BitConverter.GetBytes(checksum).CopyTo(data, 508);
            return data;
        }

        public int Alloc(int size)
        {
            if (size % 8 != 0) size += (8 - (size % 8));
            int pos = cursor;
            cursor += size;
            if (cursor > data.Length) throw new InvalidOperationException("HiveBuilder buffer overflow: " + cursor + " > " + data.Length);
            return pos;
        }

        public uint ToRelative(int absOffset)
        {
            return (uint)(absOffset - 4096);
        }

        private void WriteCellHeader(int offset, int size, bool isFree)
        {
            int encodedSize = isFree ? Math.Abs(size) : -Math.Abs(size);
            BitConverter.GetBytes(encodedSize).CopyTo(data, offset);
        }

        public int WriteNkAt(int offset, string name, bool isRoot, uint sublistRel, int subCount, uint valListRel, int valCount)
        {
            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int cellSize = 80 + nameBytes.Length;
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));

            WriteCellHeader(offset, cellSize, false);
            data[offset + 4] = 0x6E; data[offset + 5] = 0x6B; // "nk"
            ushort flags = 0x0020;
            if (isRoot) flags |= 0x0004;
            BitConverter.GetBytes(flags).CopyTo(data, offset + 6);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, offset + 8);
            BitConverter.GetBytes((uint)subCount).CopyTo(data, offset + 24);
            BitConverter.GetBytes(sublistRel).CopyTo(data, offset + 28);
            BitConverter.GetBytes((uint)valCount).CopyTo(data, offset + 36);
            BitConverter.GetBytes(valListRel).CopyTo(data, offset + 40);
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, offset + 72);
            Array.Copy(nameBytes, 0, data, offset + 76, nameBytes.Length);
            return offset;
        }

        public int WriteNk(string name, bool isRoot, uint sublistRel, int subCount, uint valListRel, int valCount)
        {
            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int cellSize = 80 + nameBytes.Length;
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));
            int offset = Alloc(cellSize);
            return WriteNkAt(offset, name, isRoot, sublistRel, subCount, valListRel, valCount);
        }

        public int WriteSublist(List<uint> subkeyRelOffsets)
        {
            if (subkeyRelOffsets == null || subkeyRelOffsets.Count == 0) return 0;
            int cellSize = 8 + (subkeyRelOffsets.Count * 8);
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));
            int offset = Alloc(cellSize);
            WriteCellHeader(offset, cellSize, false);
            data[offset + 4] = 0x6C; data[offset + 5] = 0x66; // "lf"
            BitConverter.GetBytes((ushort)subkeyRelOffsets.Count).CopyTo(data, offset + 6);
            int cur = offset + 8;
            for (int i = 0; i < subkeyRelOffsets.Count; i++)
            {
                BitConverter.GetBytes(subkeyRelOffsets[i]).CopyTo(data, cur);
                BitConverter.GetBytes(0x41424344U).CopyTo(data, cur + 4);
                cur += 8;
            }
            return offset;
        }

        public int WriteValueList(List<uint> valRelOffsets)
        {
            if (valRelOffsets == null || valRelOffsets.Count == 0) return 0;
            int cellSize = 4 + (valRelOffsets.Count * 4);
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));
            int offset = Alloc(cellSize);
            WriteCellHeader(offset, cellSize, false);
            int cur = offset + 4;
            for (int i = 0; i < valRelOffsets.Count; i++)
            {
                BitConverter.GetBytes(valRelOffsets[i]).CopyTo(data, cur);
                cur += 4;
            }
            return offset;
        }

        public int WriteVkDword(string name, uint val)
        {
            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int cellSize = 32 + nameBytes.Length;
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));
            int offset = Alloc(cellSize);
            WriteCellHeader(offset, cellSize, false);
            data[offset + 4] = 0x76; data[offset + 5] = 0x6B; // "vk"
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, offset + 6);
            BitConverter.GetBytes(0x80000004U).CopyTo(data, offset + 8);
            BitConverter.GetBytes(val).CopyTo(data, offset + 12);
            BitConverter.GetBytes(4U).CopyTo(data, offset + 16);
            BitConverter.GetBytes((ushort)1).CopyTo(data, offset + 20);
            Array.Copy(nameBytes, 0, data, offset + 24, nameBytes.Length);
            return offset;
        }

        public int WriteVkString(string name, string val)
        {
            byte[] strBytes = Encoding.Unicode.GetBytes(val + "\0");
            int dataCellSize = 8 + strBytes.Length;
            if (dataCellSize % 8 != 0) dataCellSize += (8 - (dataCellSize % 8));
            int dataOff = Alloc(dataCellSize);
            WriteCellHeader(dataOff, dataCellSize, false);
            Array.Copy(strBytes, 0, data, dataOff + 4, strBytes.Length);

            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int cellSize = 32 + nameBytes.Length;
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));
            int offset = Alloc(cellSize);
            WriteCellHeader(offset, cellSize, false);
            data[offset + 4] = 0x76; data[offset + 5] = 0x6B;
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, offset + 6);
            BitConverter.GetBytes((uint)strBytes.Length).CopyTo(data, offset + 8);
            BitConverter.GetBytes(ToRelative(dataOff)).CopyTo(data, offset + 12);
            BitConverter.GetBytes(1U).CopyTo(data, offset + 16);
            BitConverter.GetBytes((ushort)1).CopyTo(data, offset + 20);
            Array.Copy(nameBytes, 0, data, offset + 24, nameBytes.Length);
            return offset;
        }
    }

    private static byte[] CreateMockHiveWithWin10Amcache()
    {
        var b = new HiveBuilder(16384, "Amcache.hve");

        // 1. Reserve root NK at 4096 + 32 = 4128
        int rootOff = b.Alloc(80 + 4);

        // 2. Values for Entry 1 (svchost)
        int vPath1 = b.WriteVkString("LowerCaseLongPath", @"C:\Windows\System32\svchost.exe");
        int vName1 = b.WriteVkString("Name", "svchost.exe");
        int vPub1  = b.WriteVkString("Publisher", "Microsoft Corporation");
        int vSize1 = b.WriteVkDword("Size", 55320);
        int vList1 = b.WriteValueList(new List<uint> { b.ToRelative(vPath1), b.ToRelative(vName1), b.ToRelative(vPub1), b.ToRelative(vSize1) });

        int nkEntry1 = b.WriteNk("00003b71c26b911e2f790c37554be50e7b752945d8f2", false, 0, 0, b.ToRelative(vList1), 4);

        // 3. Values for Entry 2 (payload)
        int vPath2 = b.WriteVkString("LowerCaseLongPath", @"C:\Users\Admin\AppData\Local\Temp\payload.exe");
        int vName2 = b.WriteVkString("Name", "payload.exe");
        int vSize2 = b.WriteVkDword("Size", 12345);
        int vList2 = b.WriteValueList(new List<uint> { b.ToRelative(vPath2), b.ToRelative(vName2), b.ToRelative(vSize2) });

        int nkEntry2 = b.WriteNk("0000a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", false, 0, 0, b.ToRelative(vList2), 3);

        // 4. Sublist for InventoryApplicationFile
        int lfEntries = b.WriteSublist(new List<uint> { b.ToRelative(nkEntry1), b.ToRelative(nkEntry2) });

        // 5. NK InventoryApplicationFile
        int nkInv = b.WriteNk("InventoryApplicationFile", false, b.ToRelative(lfEntries), 2, 0, 0);

        // 6. Sublist for Root
        int lfRoot = b.WriteSublist(new List<uint> { b.ToRelative(nkInv) });

        // 7. Write Root NK at reserved pos
        b.WriteNkAt(rootOff, "Root", true, b.ToRelative(lfRoot), 1, 0, 0);

        return b.Finish();
    }

    private static byte[] CreateMockHiveWithWin7Amcache()
    {
        var b = new HiveBuilder(16384, "Amcache.hve");

        int rootOff = b.Alloc(80 + 4);

        // Values for Win7 entry (tool.exe)
        int vPath = b.WriteVkString("15", @"C:\Program Files\Vendor\tool.exe");
        int vSha1 = b.WriteVkString("101", "0000f1e2d3c4b5a60718293a4b5c6d7e8f9012345678");
        int vComp = b.WriteVkString("1", "Vendor Security Inc");
        int vSize = b.WriteVkDword("d", 1048576);
        int vList = b.WriteValueList(new List<uint> { b.ToRelative(vPath), b.ToRelative(vSha1), b.ToRelative(vComp), b.ToRelative(vSize) });

        int nkEntry = b.WriteNk("entry1", false, 0, 0, b.ToRelative(vList), 4);

        int lfFile = b.WriteSublist(new List<uint> { b.ToRelative(nkEntry) });
        int nkFile = b.WriteNk("File", false, b.ToRelative(lfFile), 1, 0, 0);

        int lfRoot = b.WriteSublist(new List<uint> { b.ToRelative(nkFile) });
        b.WriteNkAt(rootOff, "Root", true, b.ToRelative(lfRoot), 1, 0, 0);

        return b.Finish();
    }
}
