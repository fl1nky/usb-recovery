using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class RegistryHiveParserTests
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

    public static void Main(string[] args)
    {
        TestHeaderParsingAndChecksum();
        TestKeyAndValueHierarchy();
        TestSearchFunctionality();
        TestDeletedCellCarving();
        TestExtractSystemSummary();
        TestStreamAndFileSafety();

        Console.WriteLine("PASS RegistryHiveParserTests: {0} checks passed; REGF header checksum, hbin cells, nk/vk parsing, value decoding, subkey indexing, deleted cell carving, search, and system summary verified.", checks);
    }

    private static void TestHeaderParsingAndChecksum()
    {
        // 1. Build minimal valid REGF hive
        byte[] hive = BuildMinimalHive("SYSTEM");
        Check(RegistryHive.IsRegistryHive(new MemoryStream(hive)), "IsRegistryHive detects regf magic");

        using (var reg = RegistryHive.Open(hive))
        {
            Check(reg.IsChecksumValid, "Header checksum verified");
            Check(reg.RootKey != null, "Root key is not null");
            Check(reg.RootKey.Name == "ROOT", "Root key name is ROOT");
            Check(reg.EmbeddedFileName == "SYSTEM", "Embedded file name matches SYSTEM");
        }

        // 2. Corrupt checksum and verify IsChecksumValid is false
        byte[] corruptedChecksum = (byte[])hive.Clone();
        corruptedChecksum[508] ^= 0xFF;
        using (var reg = RegistryHive.Open(corruptedChecksum))
        {
            Check(!reg.IsChecksumValid, "Corrupted header checksum detected as invalid");
        }

        // 3. Corrupt magic and verify rejection
        byte[] corruptedMagic = (byte[])hive.Clone();
        corruptedMagic[0] = 0x00;
        Check(!RegistryHive.IsRegistryHive(new MemoryStream(corruptedMagic)), "Corrupted magic rejected by IsRegistryHive");
        bool threw = false;
        try
        {
            RegistryHive.Open(corruptedMagic);
        }
        catch (InvalidDataException)
        {
            threw = true;
        }
        Check(threw, "Corrupted magic throws InvalidDataException");

        // 4. Too small buffer rejected
        threw = false;
        try
        {
            RegistryHive.Open(new byte[1024]);
        }
        catch (InvalidDataException)
        {
            threw = true;
        }
        Check(threw, "Small buffer (< 4096) throws InvalidDataException");
    }

    private static void TestKeyAndValueHierarchy()
    {
        byte[] hive = BuildRichHive();
        using (var reg = RegistryHive.Open(hive))
        {
            var root = reg.RootKey;
            Check(root != null, "Rich hive root exists");
            Check(root.Subkeys.Count >= 2, "Root has at least 2 subkeys");

            // Find CurrentControlSet
            var ccs = reg.GetKey("CurrentControlSet");
            Check(ccs != null, "Found CurrentControlSet by path");
            Check(ccs.Name == "CurrentControlSet", "ccs.Name is CurrentControlSet");

            // Navigate to Control\\ComputerName\\ComputerName
            var compKey = reg.GetKey("CurrentControlSet\\Control\\ComputerName\\ComputerName");
            Check(compKey != null, "Found nested ComputerName key");

            var compVal = compKey.GetValue("ComputerName");
            Check(compVal != null, "ComputerName value exists");
            Check(compVal.ValueType == RegistryValueType.String, "ComputerName is REG_SZ");
            Check(compVal.Value is string, "ComputerName value is string");
            Check((string)compVal.Value == "ANALYSIS-PC", "ComputerName string is ANALYSIS-PC");
            Check(compVal.ValueAsString() == "ANALYSIS-PC", "ValueAsString returns ANALYSIS-PC");

            // Check DWORD value
            var dwordVal = compKey.GetValue("ActiveDword");
            Check(dwordVal != null, "ActiveDword exists");
            Check(dwordVal.ValueType == RegistryValueType.DWord, "ActiveDword is REG_DWORD");
            Check(dwordVal.Value is uint && (uint)dwordVal.Value == 42U, "ActiveDword value is 42");

            // Check Multi-String value
            var multiVal = compKey.GetValue("MultiList");
            Check(multiVal != null, "MultiList exists");
            Check(multiVal.ValueType == RegistryValueType.MultiString, "MultiList is REG_MULTI_SZ");
            string[] parts = multiVal.Value as string[];
            Check(parts != null && parts.Length == 2, "MultiList has 2 parts");
            Check(parts[0] == "Alpha" && parts[1] == "Beta", "MultiList parts are Alpha and Beta");

            // Check Binary value
            var binVal = compKey.GetValue("DataBytes");
            Check(binVal != null, "DataBytes exists");
            Check(binVal.ValueType == RegistryValueType.Binary, "DataBytes is REG_BINARY");
            byte[] bytes = binVal.Value as byte[];
            Check(bytes != null && bytes.Length == 4 && bytes[0] == 0xDE && bytes[1] == 0xAD, "Binary value matches DEAD");
        }
    }

    private static void TestSearchFunctionality()
    {
        byte[] hive = BuildRichHive();
        using (var reg = RegistryHive.Open(hive))
        {
            // Search by key name
            var keys = reg.SearchKeys("ComputerName");
            Check(keys.Count >= 1, "SearchKeys finds ComputerName");
            Check(keys[0].Name == "ComputerName", "Matched key name is ComputerName");

            // Search by value name with searchValues: true
            var valMatches = reg.SearchKeys("ActiveDword", true);
            Check(valMatches.Count >= 1, "SearchKeys with searchValues: true finds key holding ActiveDword");

            // Search values directly
            var vals = reg.SearchValues("ANALYSIS-PC");
            Check(vals.Count >= 1, "SearchValues finds value containing ANALYSIS-PC");
            Check(vals[0].Name == "ComputerName", "SearchValues found ComputerName value");
        }
    }

    private static void TestDeletedCellCarving()
    {
        byte[] hive = BuildHiveWithDeletedCells();
        using (var reg = RegistryHive.Open(hive))
        {
            // Carve deleted keys
            List<RegistryKey> carvedKeys = reg.CarveDeletedKeys();
            Check(carvedKeys.Count >= 1, "CarveDeletedKeys carved at least 1 deleted key");

            bool foundDeletedKey = false;
            for (int i = 0; i < carvedKeys.Count; i++)
            {
                if (carvedKeys[i].Name == "DeletedMalwareKey")
                {
                    foundDeletedKey = true;
                    Check(carvedKeys[i].IsDeleted, "Carved key marked IsDeleted == true");
                    Check(carvedKeys[i].Path.StartsWith("[CARVED_DELETED]"), "Carved key path tagged [CARVED_DELETED]");
                    break;
                }
            }
            Check(foundDeletedKey, "Found DeletedMalwareKey in carved keys");

            // Carve deleted values
            List<RegistryValue> carvedValues = reg.CarveDeletedValues();
            Check(carvedValues.Count >= 1, "CarveDeletedValues carved at least 1 deleted value");

            bool foundDeletedVal = false;
            for (int i = 0; i < carvedValues.Count; i++)
            {
                if (carvedValues[i].Name == "InjectedPayload")
                {
                    foundDeletedVal = true;
                    Check(carvedValues[i].IsDeleted, "Carved value marked IsDeleted == true");
                    Check(carvedValues[i].ValueAsString().Contains("powershell"), "Carved value contains payload text");
                    break;
                }
            }
            Check(foundDeletedVal, "Found InjectedPayload in carved values");
        }
    }

    private static void TestExtractSystemSummary()
    {
        byte[] hive = BuildRichHive();
        using (var reg = RegistryHive.Open(hive))
        {
            RegistrySystemSummary summary = reg.ExtractSystemSummary();
            Check(summary != null, "Summary extracted");
            Check(summary.ComputerName == "ANALYSIS-PC", "Summary extracted ComputerName");
            Check(summary.ProductName == "Windows 11 Pro Enterprise", "Summary extracted ProductName");
            Check(summary.CurrentBuild == "26100", "Summary extracted CurrentBuild");
            Check(summary.CurrentControlSet == "ControlSet001", "Summary extracted CurrentControlSet");
            Check(summary.UsbDevices.Count >= 1, "Summary extracted USB devices");
            Check(summary.UsbDevices[0].Contains("Ultra USB"), "USB device friendly name identified");
            Check(summary.RunKeys.Count >= 1, "Summary extracted Run persistence keys");
            Check(summary.RunKeys[0].Contains("SecurityAgent"), "Persistence agent identified in Run keys");
        }
    }

    private static void TestStreamAndFileSafety()
    {
        byte[] hive = BuildMinimalHive("TESTHIVE");

        // Open via Stream
        using (var ms = new MemoryStream(hive))
        using (var reg = RegistryHive.Open(ms))
        {
            Check(reg.RootKey != null, "Stream open succeeded");
        }

        // Test temp file open and write-blocking
        string tempPath = Path.Combine(Path.GetTempPath(), "test_regf_" + Guid.NewGuid().ToString("N") + ".dat");
        try
        {
            File.WriteAllBytes(tempPath, hive);
            Check(RegistryHive.IsRegistryHive(tempPath), "IsRegistryHive file check works");

            using (var reg = RegistryHive.Open(tempPath))
            {
                Check(reg.RootKey != null, "File open succeeded");
            }
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    #region Synthetic Hive Builders

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
            BitConverter.GetBytes(32U).CopyTo(data, 36); // root cell offset relative to hbin
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

        public int WriteVkMultiString(string name, string[] strings)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < strings.Length; i++) { sb.Append(strings[i]); sb.Append('\0'); }
            sb.Append('\0');
            byte[] strBytes = Encoding.Unicode.GetBytes(sb.ToString());
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
            BitConverter.GetBytes(7U).CopyTo(data, offset + 16);
            BitConverter.GetBytes((ushort)1).CopyTo(data, offset + 20);
            Array.Copy(nameBytes, 0, data, offset + 24, nameBytes.Length);
            return offset;
        }

        public int WriteVkBinary(string name, byte[] rawBytes)
        {
            int dataCellSize = 8 + rawBytes.Length;
            if (dataCellSize % 8 != 0) dataCellSize += (8 - (dataCellSize % 8));
            int dataOff = Alloc(dataCellSize);
            WriteCellHeader(dataOff, dataCellSize, false);
            Array.Copy(rawBytes, 0, data, dataOff + 4, rawBytes.Length);

            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int cellSize = 32 + nameBytes.Length;
            if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));
            int offset = Alloc(cellSize);
            WriteCellHeader(offset, cellSize, false);
            data[offset + 4] = 0x76; data[offset + 5] = 0x6B;
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, offset + 6);
            BitConverter.GetBytes((uint)rawBytes.Length).CopyTo(data, offset + 8);
            BitConverter.GetBytes(ToRelative(dataOff)).CopyTo(data, offset + 12);
            BitConverter.GetBytes(3U).CopyTo(data, offset + 16);
            BitConverter.GetBytes((ushort)1).CopyTo(data, offset + 20);
            Array.Copy(nameBytes, 0, data, offset + 24, nameBytes.Length);
            return offset;
        }

        public void WriteDeletedNk(string name)
        {
            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int size = 96 + nameBytes.Length;
            if (size % 8 != 0) size += (8 - (size % 8));
            int offset = Alloc(size);
            WriteCellHeader(offset, size, true);
            data[offset + 4] = 0x6E; data[offset + 5] = 0x6B;
            BitConverter.GetBytes((ushort)0x0020).CopyTo(data, offset + 6);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, offset + 8);
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, offset + 72);
            Array.Copy(nameBytes, 0, data, offset + 76, nameBytes.Length);
        }

        public void WriteDeletedVk(string name, string payload)
        {
            byte[] strBytes = Encoding.Unicode.GetBytes(payload + "\0");
            int dataCellSize = 8 + strBytes.Length;
            if (dataCellSize % 8 != 0) dataCellSize += (8 - (dataCellSize % 8));
            int dataOff = Alloc(dataCellSize);
            WriteCellHeader(dataOff, dataCellSize, true);
            Array.Copy(strBytes, 0, data, dataOff + 4, strBytes.Length);

            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            int size = 32 + nameBytes.Length;
            if (size % 8 != 0) size += (8 - (size % 8));
            int offset = Alloc(size);
            WriteCellHeader(offset, size, true);
            data[offset + 4] = 0x76; data[offset + 5] = 0x6B;
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(data, offset + 6);
            BitConverter.GetBytes((uint)strBytes.Length).CopyTo(data, offset + 8);
            BitConverter.GetBytes(ToRelative(dataOff)).CopyTo(data, offset + 12);
            BitConverter.GetBytes(1U).CopyTo(data, offset + 16);
            BitConverter.GetBytes((ushort)1).CopyTo(data, offset + 20);
            Array.Copy(nameBytes, 0, data, offset + 24, nameBytes.Length);
        }
    }

    private static byte[] BuildMinimalHive(string hiveName)
    {
        var b = new HiveBuilder(8192, hiveName);
        int rootOff = b.Alloc(96); // 4128
        b.WriteNkAt(rootOff, "ROOT", true, 0, 0, 0, 0);
        return b.Finish();
    }

    private static byte[] BuildRichHive()
    {
        var b = new HiveBuilder(32768, "SYSTEM");

        // Reserve root key at 4128
        int rootOff = b.Alloc(96);

        // 1. CurrentControlSet\Control\ComputerName\ComputerName
        // Values for inner ComputerName:
        List<uint> compVals = new List<uint>();
        compVals.Add(b.ToRelative(b.WriteVkString("ComputerName", "ANALYSIS-PC")));
        compVals.Add(b.ToRelative(b.WriteVkDword("ActiveDword", 42U)));
        compVals.Add(b.ToRelative(b.WriteVkMultiString("MultiList", new string[] { "Alpha", "Beta" })));
        compVals.Add(b.ToRelative(b.WriteVkBinary("DataBytes", new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })));
        uint compValListRel = b.ToRelative(b.WriteValueList(compVals));
        int compInnerOff = b.WriteNk("ComputerName", false, 0, 0, compValListRel, compVals.Count);

        // Subkey ComputerName (outer):
        List<uint> compOuterSubkeys = new List<uint>();
        compOuterSubkeys.Add(b.ToRelative(compInnerOff));
        uint compOuterSublistRel = b.ToRelative(b.WriteSublist(compOuterSubkeys));
        int compOuterOff = b.WriteNk("ComputerName", false, compOuterSublistRel, compOuterSubkeys.Count, 0, 0);

        // Subkey Control:
        List<uint> ctrlSubkeys = new List<uint>();
        ctrlSubkeys.Add(b.ToRelative(compOuterOff));
        uint ctrlSublistRel = b.ToRelative(b.WriteSublist(ctrlSubkeys));
        int ctrlOff = b.WriteNk("Control", false, ctrlSublistRel, ctrlSubkeys.Count, 0, 0);

        // 2. USBSTOR: Enum -> USBSTOR -> Disk -> Inst
        List<uint> instVals = new List<uint>();
        instVals.Add(b.ToRelative(b.WriteVkString("FriendlyName", "SanDisk Ultra USB 3.0")));
        uint instValListRel = b.ToRelative(b.WriteValueList(instVals));
        int instOff = b.WriteNk("001A92B3C", false, 0, 0, instValListRel, instVals.Count);

        List<uint> diskSubkeys = new List<uint>();
        diskSubkeys.Add(b.ToRelative(instOff));
        uint diskSublistRel = b.ToRelative(b.WriteSublist(diskSubkeys));
        int diskOff = b.WriteNk("Disk&Ven_SanDisk&Prod_Ultra", false, diskSublistRel, diskSubkeys.Count, 0, 0);

        List<uint> usbSubkeys = new List<uint>();
        usbSubkeys.Add(b.ToRelative(diskOff));
        uint usbSublistRel = b.ToRelative(b.WriteSublist(usbSubkeys));
        int usbOff = b.WriteNk("USBSTOR", false, usbSublistRel, usbSubkeys.Count, 0, 0);

        List<uint> enumSubkeys = new List<uint>();
        enumSubkeys.Add(b.ToRelative(usbOff));
        uint enumSublistRel = b.ToRelative(b.WriteSublist(enumSubkeys));
        int enumOff = b.WriteNk("Enum", false, enumSublistRel, enumSubkeys.Count, 0, 0);

        // CurrentControlSet parent:
        List<uint> ccsSubkeys = new List<uint>();
        ccsSubkeys.Add(b.ToRelative(ctrlOff));
        ccsSubkeys.Add(b.ToRelative(enumOff));
        uint ccsSublistRel = b.ToRelative(b.WriteSublist(ccsSubkeys));
        int ccsOff = b.WriteNk("CurrentControlSet", false, ccsSublistRel, ccsSubkeys.Count, 0, 0);

        // 3. Select key: Current = 1
        List<uint> selVals = new List<uint>();
        selVals.Add(b.ToRelative(b.WriteVkDword("Current", 1U)));
        uint selValListRel = b.ToRelative(b.WriteValueList(selVals));
        int selOff = b.WriteNk("Select", false, 0, 0, selValListRel, selVals.Count);

        // 4. Microsoft -> Windows NT -> CurrentVersion
        List<uint> cvVals = new List<uint>();
        cvVals.Add(b.ToRelative(b.WriteVkString("ProductName", "Windows 11 Pro Enterprise")));
        cvVals.Add(b.ToRelative(b.WriteVkString("CurrentBuild", "26100")));
        cvVals.Add(b.ToRelative(b.WriteVkDword("InstallDate", 1700000000U)));
        uint cvValListRel = b.ToRelative(b.WriteValueList(cvVals));
        int cvOff = b.WriteNk("CurrentVersion", false, 0, 0, cvValListRel, cvVals.Count);

        List<uint> ntSubkeys = new List<uint>();
        ntSubkeys.Add(b.ToRelative(cvOff));
        uint ntSublistRel = b.ToRelative(b.WriteSublist(ntSubkeys));
        int ntOff = b.WriteNk("Windows NT", false, ntSublistRel, ntSubkeys.Count, 0, 0);

        // Microsoft -> Windows -> CurrentVersion -> Run
        List<uint> runVals = new List<uint>();
        runVals.Add(b.ToRelative(b.WriteVkString("SecurityAgent", "C:\\Program Files\\Agent\\agent.exe")));
        uint runValListRel = b.ToRelative(b.WriteValueList(runVals));
        int runOff = b.WriteNk("Run", false, 0, 0, runValListRel, runVals.Count);

        List<uint> winCvSubkeys = new List<uint>();
        winCvSubkeys.Add(b.ToRelative(runOff));
        uint winCvSublistRel = b.ToRelative(b.WriteSublist(winCvSubkeys));
        int winCvOff = b.WriteNk("CurrentVersion", false, winCvSublistRel, winCvSubkeys.Count, 0, 0);

        List<uint> winSubkeys = new List<uint>();
        winSubkeys.Add(b.ToRelative(winCvOff));
        uint winSublistRel = b.ToRelative(b.WriteSublist(winSubkeys));
        int winOff = b.WriteNk("Windows", false, winSublistRel, winSubkeys.Count, 0, 0);

        List<uint> msSubkeys = new List<uint>();
        msSubkeys.Add(b.ToRelative(ntOff));
        msSubkeys.Add(b.ToRelative(winOff));
        uint msSublistRel = b.ToRelative(b.WriteSublist(msSubkeys));
        int msOff = b.WriteNk("Microsoft", false, msSublistRel, msSubkeys.Count, 0, 0);

        // Root key links ccs, Select, Microsoft
        List<uint> rootSubkeys = new List<uint>();
        rootSubkeys.Add(b.ToRelative(ccsOff));
        rootSubkeys.Add(b.ToRelative(selOff));
        rootSubkeys.Add(b.ToRelative(msOff));
        uint rootSublistRel = b.ToRelative(b.WriteSublist(rootSubkeys));

        b.WriteNkAt(rootOff, "ROOT", true, rootSublistRel, rootSubkeys.Count, 0, 0);

        return b.Finish();
    }

    private static byte[] BuildHiveWithDeletedCells()
    {
        var b = new HiveBuilder(8192, "SOFTWARE");
        int rootOff = b.Alloc(96);
        b.WriteNkAt(rootOff, "ROOT", true, 0, 0, 0, 0);

        // Unallocated deleted cells
        b.WriteDeletedNk("DeletedMalwareKey");
        b.WriteDeletedVk("InjectedPayload", "powershell -enc AAAA");

        return b.Finish();
    }

    #endregion
}
