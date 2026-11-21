using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class ShellbagsParserTests
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
        Console.WriteLine("Running ShellbagsParserTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "shellbags-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            TestRootClsidDecoding(testDir);
            TestDriveLetterDecoding(testDir);
            TestDirectoryAndExtensionBlockDecoding(testDir);
            TestFullBagMruHierarchy(testDir);

            Console.WriteLine("PASS ShellbagsParserTests: {0} checks passed; Root CLSIDs, USB Drive letters, directory extension blocks, and hierarchical BagMRU paths verified.", checks);
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

    private static void TestRootClsidDecoding(string testDir)
    {
        // 0x1F Root CLSID item (e.g. "This PC" {20D04FE0-3AEA-1069-A2D8-08002B30309D})
        byte[] item = new byte[22];
        WriteUInt16Le(item, 0, (ushort)item.Length);
        item[2] = 0x1F;
        item[3] = 0x50; // Sort order

        Guid guid = new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D");
        Array.Copy(guid.ToByteArray(), 0, item, 4, 16);

        var rec = ShellbagsParser.DecodeShItemId(item);
        Check(rec != null, "Decoded record should not be null");
        Check(rec.ItemType == ShellbagItemType.Root, "ItemType must be Root");
        Check(rec.FolderName == "This PC", "CLSID should map to friendly name 'This PC'");
    }

    private static void TestDriveLetterDecoding(string testDir)
    {
        // Drive letter (e.g. "E:\\")
        byte[] item = new byte[25];
        WriteUInt16Le(item, 0, (ushort)item.Length);
        item[2] = 0x23; // Drive type

        byte[] driveStr = Encoding.ASCII.GetBytes("E:\\\0");
        Array.Copy(driveStr, 0, item, 3, driveStr.Length);

        var rec = ShellbagsParser.DecodeShItemId(item);
        Check(rec != null, "Decoded drive record should not be null");
        Check(rec.ItemType == ShellbagItemType.Drive, "ItemType must be Drive");
        Check(rec.FolderName == "E:\\", "FolderName must be E:\\");
        Check(rec.FullPath == "E:\\", "FullPath must match E:\\");
    }

    private static void TestDirectoryAndExtensionBlockDecoding(string testDir)
    {
        // Directory entry with short name + BEEF extension block
        byte[] item = new byte[120];
        WriteUInt16Le(item, 0, (ushort)item.Length);
        item[2] = 0x31; // Directory type

        // DOS modified date (2025-05-10, 14:30:00)
        // Year = 2025 - 1980 = 45 -> 45 << 9 = 23040; Month = 5 -> 5 << 5 = 160; Day = 10 -> 23210
        ushort dosDate = (ushort)((45 << 9) | (5 << 5) | 10);
        // Hour = 14 -> 14 << 11 = 28672; Min = 30 -> 30 << 5 = 960; Sec = 0 -> 29632
        ushort dosTime = (ushort)((14 << 11) | (30 << 5) | 0);
        WriteUInt16Le(item, 8, dosDate);
        WriteUInt16Le(item, 10, dosTime);

        // Short ASCII name at offset 14
        byte[] shortName = Encoding.ASCII.GetBytes("FINANC~1\0");
        Array.Copy(shortName, 0, item, 14, shortName.Length);

        // Extension block at offset 26
        int extPos = 26;
        ushort extSize = (ushort)(item.Length - extPos);
        WriteUInt16Le(item, extPos, extSize);
        WriteUInt16Le(item, extPos + 2, 0x0004); // ext version
        WriteUInt16Le(item, extPos + 4, 0xBEEF); // signature

        // Creation date
        WriteUInt16Le(item, extPos + 8, dosDate);
        WriteUInt16Le(item, extPos + 10, dosTime);

        // Long Unicode name at offset extPos + 16
        byte[] longName = Encoding.Unicode.GetBytes("Financial Audit Records 2025\0");
        Array.Copy(longName, 0, item, extPos + 16, longName.Length);

        var rec = ShellbagsParser.DecodeShItemId(item);
        Check(rec != null, "Directory record should not be null");
        Check(rec.ItemType == ShellbagItemType.Directory, "ItemType must be Directory");
        Check(rec.FolderName == "Financial Audit Records 2025", "Extension block long Unicode name must be preferred over 8.3 short name");
        Check(rec.ModifiedTimeUtc.Year == 2025, "Modified year must be 2025");
        Check(rec.ModifiedTimeUtc.Month == 5, "Modified month must be 5");
        Check(rec.ModifiedTimeUtc.Day == 10, "Modified day must be 10");
    }

    private static void TestFullBagMruHierarchy(string testDir)
    {
        // Construct mock UsrClass.dat with BagMRU tree:
        // BagMRU (Root)
        //   -> Value "0": Drive "E:\"
        //   -> Subkey "0"
        //        -> Value "0": Folder "Exfiltrated"
        //        -> Subkey "0"
        //             -> Value "0": Folder "Passwords"
        byte[] hive = BuildShellbagsHive();
        using (var reg = RegistryHive.Open(hive))
        {
            var records = ShellbagsParser.Parse(reg, "UsrClass.dat");
            Check(records.Count == 3, "Should decode 3 hierarchical shellbag records");

            var drive = records.Find(delegate(ShellbagRecord r) { return r.ItemType == ShellbagItemType.Drive; });
            Check(drive != null && drive.FullPath == "E:\\", "Drive record should be E:\\");

            var folder1 = records.Find(delegate(ShellbagRecord r) { return r.FolderName == "Exfiltrated"; });
            Check(folder1 != null && folder1.FullPath == "E:\\Exfiltrated", "Folder 1 path should be E:\\Exfiltrated");

            var folder2 = records.Find(delegate(ShellbagRecord r) { return r.FolderName == "Passwords"; });
            Check(folder2 != null && folder2.FullPath == "E:\\Exfiltrated\\Passwords", "Folder 2 path should be E:\\Exfiltrated\\Passwords");
        }
    }

    // =========================================================================
    // Mock Hive Builder for BagMRU
    // =========================================================================

    private static byte[] BuildShellbagsHive()
    {
        // We use our proven HiveBuilder pattern
        var b = new MockHiveBuilder(16384, "UsrClass.dat");
        int rootOff = b.Alloc(84);

        // Drive item data
        byte[] driveData = new byte[20];
        WriteUInt16Le(driveData, 0, (ushort)driveData.Length);
        driveData[2] = 0x23;
        Encoding.ASCII.GetBytes("E:\\\0").CopyTo(driveData, 3);

        // Folder 1 item data
        byte[] f1Data = new byte[32];
        WriteUInt16Le(f1Data, 0, (ushort)f1Data.Length);
        f1Data[2] = 0x31;
        Encoding.ASCII.GetBytes("Exfiltrated\0").CopyTo(f1Data, 14);

        // Folder 2 item data
        byte[] f2Data = new byte[32];
        WriteUInt16Le(f2Data, 0, (ushort)f2Data.Length);
        f2Data[2] = 0x31;
        Encoding.ASCII.GetBytes("Passwords\0").CopyTo(f2Data, 14);

        // Level 2: Subkey "0" inside Folder 1's subkey -> contains Folder 2
        int v2 = b.WriteVkBinary("0", f2Data);
        int vList2 = b.WriteValueList(new List<uint> { b.ToRelative(v2) });
        int nkSubLevel2 = b.WriteNk("0", false, 0, 0, b.ToRelative(vList2), 1);

        // Level 1: Subkey "0" inside BagMRU -> contains Folder 1 + subkey "0"
        int v1 = b.WriteVkBinary("0", f1Data);
        int vList1 = b.WriteValueList(new List<uint> { b.ToRelative(v1) });
        int lfSubLevel1 = b.WriteSublist(new List<uint> { b.ToRelative(nkSubLevel2) });
        int nkSubLevel1 = b.WriteNk("0", false, b.ToRelative(lfSubLevel1), 1, b.ToRelative(vList1), 1);

        // BagMRU Root Key -> contains Drive + subkey "0"
        int vDrive = b.WriteVkBinary("0", driveData);
        int vListDrive = b.WriteValueList(new List<uint> { b.ToRelative(vDrive) });
        int lfDrive = b.WriteSublist(new List<uint> { b.ToRelative(nkSubLevel1) });
        int nkBagMru = b.WriteNk("BagMRU", false, b.ToRelative(lfDrive), 1, b.ToRelative(vListDrive), 1);

        // Root
        int lfRoot = b.WriteSublist(new List<uint> { b.ToRelative(nkBagMru) });
        b.WriteNkAt(rootOff, "Root", true, b.ToRelative(lfRoot), 1, 0, 0);

        return b.Finish();
    }

    private sealed class MockHiveBuilder
    {
        private readonly byte[] data;
        private int cursor;

        public MockHiveBuilder(int totalSize, string hiveName)
        {
            data = new byte[totalSize];
            cursor = 4096 + 32;

            data[0] = 0x72; data[1] = 0x65; data[2] = 0x67; data[3] = 0x66;
            BitConverter.GetBytes(1U).CopyTo(data, 4);
            BitConverter.GetBytes(1U).CopyTo(data, 8);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 12);
            BitConverter.GetBytes(1U).CopyTo(data, 20);
            BitConverter.GetBytes(3U).CopyTo(data, 24);
            BitConverter.GetBytes(32U).CopyTo(data, 36);
            BitConverter.GetBytes((uint)(totalSize - 4096)).CopyTo(data, 40);

            byte[] nameBytes = Encoding.Unicode.GetBytes(hiveName);
            Array.Copy(nameBytes, 0, data, 48, Math.Min(nameBytes.Length, 64));

            data[4096] = 0x68; data[4097] = 0x62; data[4098] = 0x69; data[4099] = 0x6E;
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
            if (cursor > data.Length) throw new InvalidOperationException("Buffer overflow");
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
            data[offset + 4] = 0x6E; data[offset + 5] = 0x6B;
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
            data[offset + 4] = 0x6C; data[offset + 5] = 0x66;
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

        public int WriteVkBinary(string name, byte[] binaryData)
        {
            int dataCellSize = 8 + binaryData.Length;
            if (dataCellSize % 8 != 0) dataCellSize += (8 - (dataCellSize % 8));
            int dataOff = Alloc(dataCellSize);
            WriteCellHeader(dataOff, dataCellSize, false);
            Array.Copy(binaryData, 0, data, dataOff + 4, binaryData.Length);

            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int cellSize = 32 + nameBytes.Length;
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));
            int offset = Alloc(cellSize);
            WriteCellHeader(offset, cellSize, false);
            data[offset + 4] = 0x76; data[offset + 5] = 0x6B;
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, offset + 6);
            BitConverter.GetBytes((uint)binaryData.Length).CopyTo(data, offset + 8);
            BitConverter.GetBytes(ToRelative(dataOff)).CopyTo(data, offset + 12);
            BitConverter.GetBytes(3U).CopyTo(data, offset + 16); // REG_BINARY = 3
            BitConverter.GetBytes((ushort)1).CopyTo(data, offset + 20);
            Array.Copy(nameBytes, 0, data, offset + 24, nameBytes.Length);
            return offset;
        }
    }

    private static void WriteUInt16Le(byte[] b, int offset, ushort val)
    {
        b[offset] = (byte)(val & 0xFF);
        b[offset + 1] = (byte)((val >> 8) & 0xFF);
    }
}
