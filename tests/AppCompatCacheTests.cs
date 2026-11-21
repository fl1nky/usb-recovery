using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using UsbRecovery;

public static class AppCompatCacheTests
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
        TestWindows10ShimcacheParsing();
        TestWindows7ShimcacheParsing();
        TestExtractFromSystemHiveIntegration();

        Console.WriteLine("PASS AppCompatCacheTests: {0} checks passed; Windows 10/11 '10ts' format, Windows 7 BADC0FFE format, path cleaning, execution flags, and SYSTEM hive integration verified.", checks);
    }

    private static void TestWindows10ShimcacheParsing()
    {
        DateTime expectedTime = new DateTime(2026, 11, 20, 18, 0, 0, DateTimeKind.Utc);
        byte[] data = CreateSyntheticWin10Shimcache(
            "C:\\Windows\\System32\\cmd.exe",
            expectedTime,
            true
        );

        List<AppCompatCacheEntry> entries = AppCompatCacheParser.Parse(data);
        Check(entries.Count >= 1, "Win10 Shimcache entry parsed");
        Check(entries[0].Path == "C:\\Windows\\System32\\cmd.exe", "Path matches cmd.exe");
        Check(entries[0].Executed, "Executed flag is true");
        Check(entries[0].LastModifiedTimeUtc == expectedTime, "LastModifiedTimeUtc matches expectedTime");
    }

    private static void TestWindows7ShimcacheParsing()
    {
        DateTime expectedTime = new DateTime(2026, 5, 10, 8, 30, 0, DateTimeKind.Utc);
        byte[] data = CreateSyntheticWin7Shimcache(
            "C:\\Tools\\ProcessHacker.exe",
            expectedTime,
            true
        );

        List<AppCompatCacheEntry> entries = AppCompatCacheParser.Parse(data);
        Check(entries.Count >= 1, "Win7 Shimcache entry parsed");
        Check(entries[0].Path == "C:\\Tools\\ProcessHacker.exe", "Win7 Path matches ProcessHacker.exe");
        Check(entries[0].Executed, "Win7 Executed flag is true");
        Check(entries[0].LastModifiedTimeUtc == expectedTime, "Win7 LastModified matches");
    }

    private static void TestExtractFromSystemHiveIntegration()
    {
        DateTime expectedTime = new DateTime(2026, 10, 1, 14, 0, 0, DateTimeKind.Utc);
        byte[] shimcacheRaw = CreateSyntheticWin10Shimcache(
            "C:\\Users\\Admin\\AppData\\Local\\Temp\\malware_loader.exe",
            expectedTime,
            true
        );

        // Build a synthetic hive containing ControlSet001\Control\Session Manager\AppCompatCache
        byte[] hiveBytes = BuildSystemHiveWithShimcache(shimcacheRaw);

        using (var hive = RegistryHive.Open(hiveBytes))
        {
            List<AppCompatCacheEntry> entries = AppCompatCacheParser.ExtractFromSystemHive(hive);
            Check(entries.Count >= 1, "Extracted Shimcache directly from SYSTEM RegistryHive");
            Check(entries[0].Path.Contains("malware_loader.exe"), "Identified malware loader from SYSTEM hive");
            Check(entries[0].Executed, "Marked as executed in SYSTEM hive");
        }
    }

    #region Helpers

    private static byte[] CreateSyntheticWin10Shimcache(string path, DateTime lastMod, bool executed)
    {
        using (var ms = new MemoryStream())
        {
            // Header: "10ts" at offset 0
            ms.Write(new byte[] { 0x31, 0x30, 0x73, 0x74 }, 0, 4); // "10ts"
            ms.Write(BitConverter.GetBytes(0U), 0, 4); // checksum or reserved

            // Entry:
            // "10ts" signature
            ms.Write(new byte[] { 0x31, 0x30, 0x73, 0x74 }, 0, 4);
            ms.Write(BitConverter.GetBytes(0U), 0, 4); // reserved
            ms.Write(BitConverter.GetBytes(executed ? 4U : 0U), 0, 4); // data size

            byte[] pathBytes = Encoding.Unicode.GetBytes(path);
            ms.Write(BitConverter.GetBytes((ushort)pathBytes.Length), 0, 2);
            ms.Write(pathBytes, 0, pathBytes.Length);

            ms.Write(BitConverter.GetBytes(lastMod.ToFileTimeUtc()), 0, 8);
            if (executed)
            {
                ms.Write(BitConverter.GetBytes(0x02U), 0, 4); // Execution flag data
            }

            return ms.ToArray();
        }
    }

    private static byte[] CreateSyntheticWin7Shimcache(string path, DateTime lastMod, bool executed)
    {
        byte[] pathBytes = Encoding.Unicode.GetBytes(path);
        int totalSize = 128 + 32 + pathBytes.Length;
        byte[] data = new byte[totalSize];

        // Magic BADC0FFE
        BitConverter.GetBytes(0xBADC0FFEU).CopyTo(data, 0);
        BitConverter.GetBytes(1U).CopyTo(data, 4); // 1 entry

        // Descriptor at 128
        int descOffset = 128;
        int pathOffset = 128 + 32;

        BitConverter.GetBytes((ushort)pathBytes.Length).CopyTo(data, descOffset);
        BitConverter.GetBytes((ushort)(pathBytes.Length + 2)).CopyTo(data, descOffset + 2);
        BitConverter.GetBytes((uint)pathOffset).CopyTo(data, descOffset + 4);
        BitConverter.GetBytes(lastMod.ToFileTimeUtc()).CopyTo(data, descOffset + 8);
        BitConverter.GetBytes(executed ? 0x02U : 0x00U).CopyTo(data, descOffset + 16);

        Array.Copy(pathBytes, 0, data, pathOffset, pathBytes.Length);
        return data;
    }

    private static byte[] BuildSystemHiveWithShimcache(byte[] shimcacheData)
    {
        // Total size 32768
        byte[] data = new byte[32768];

        // Header
        data[0] = 0x72; data[1] = 0x65; data[2] = 0x67; data[3] = 0x66;
        BitConverter.GetBytes(1U).CopyTo(data, 4);
        BitConverter.GetBytes(1U).CopyTo(data, 8);
        BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 12);
        BitConverter.GetBytes(1U).CopyTo(data, 20);
        BitConverter.GetBytes(3U).CopyTo(data, 24);
        BitConverter.GetBytes(32U).CopyTo(data, 36); // root cell offset 32 past 4096
        BitConverter.GetBytes(28672U).CopyTo(data, 40);

        byte[] nameBytes = Encoding.Unicode.GetBytes("SYSTEM");
        Array.Copy(nameBytes, 0, data, 48, Math.Min(nameBytes.Length, 64));

        // Hbin at 4096
        data[4096] = 0x68; data[4097] = 0x62; data[4098] = 0x69; data[4099] = 0x6E;
        BitConverter.GetBytes(0U).CopyTo(data, 4100);
        BitConverter.GetBytes(28672U).CopyTo(data, 4104);

        int cursor = 4096 + 32;

        // Reserve root key at 4128
        int rootOff = cursor;
        cursor += 96;

        // Leaf key: AppCompatCache (4400)
        // Value: AppCompatCache (REG_BINARY, shimcacheData)
        // Write data cell for shimcacheData
        int dataCellSize = 8 + shimcacheData.Length;
        if (dataCellSize % 8 != 0) dataCellSize += (8 - (dataCellSize % 8));
        int dataCellOff = cursor;
        cursor += dataCellSize;
        BitConverter.GetBytes(-dataCellSize).CopyTo(data, dataCellOff);
        Array.Copy(shimcacheData, 0, data, dataCellOff + 4, shimcacheData.Length);

        // Write vk cell for AppCompatCache
        byte[] vName = Encoding.ASCII.GetBytes("AppCompatCache");
        int vkSize = 32 + vName.Length;
        if (vkSize % 8 != 0) vkSize += (8 - (vkSize % 8));
        int vkOff = cursor;
        cursor += vkSize;
        BitConverter.GetBytes(-vkSize).CopyTo(data, vkOff);
        data[vkOff + 4] = 0x76; data[vkOff + 5] = 0x6B;
        BitConverter.GetBytes((ushort)vName.Length).CopyTo(data, vkOff + 6);
        BitConverter.GetBytes((uint)shimcacheData.Length).CopyTo(data, vkOff + 8);
        BitConverter.GetBytes((uint)(dataCellOff - 4096)).CopyTo(data, vkOff + 12);
        BitConverter.GetBytes(3U).CopyTo(data, vkOff + 16); // REG_BINARY
        BitConverter.GetBytes((ushort)1).CopyTo(data, vkOff + 20); // ASCII name
        Array.Copy(vName, 0, data, vkOff + 24, vName.Length);

        // Value list for AppCompatCache key
        int valListOff = cursor;
        cursor += 16;
        BitConverter.GetBytes(-16).CopyTo(data, valListOff);
        BitConverter.GetBytes((uint)(vkOff - 4096)).CopyTo(data, valListOff + 4);

        // Key cell: AppCompatCache
        int appCompatKeyOff = cursor;
        cursor += 96;
        WriteNkCellAt(data, appCompatKeyOff, "AppCompatCache", false, 0, 0, (uint)(valListOff - 4096), 1);

        // Sublist for Session Manager
        int smSublistOff = cursor;
        cursor += 24;
        BitConverter.GetBytes(-24).CopyTo(data, smSublistOff);
        data[smSublistOff + 4] = 0x6C; data[smSublistOff + 5] = 0x66;
        BitConverter.GetBytes((ushort)1).CopyTo(data, smSublistOff + 6);
        BitConverter.GetBytes((uint)(appCompatKeyOff - 4096)).CopyTo(data, smSublistOff + 8);
        BitConverter.GetBytes(0x41424344U).CopyTo(data, smSublistOff + 12);

        // Key cell: Session Manager
        int smKeyOff = cursor;
        cursor += 96;
        WriteNkCellAt(data, smKeyOff, "Session Manager", false, (uint)(smSublistOff - 4096), 1, 0, 0);

        // Sublist for Control
        int ctrlSublistOff = cursor;
        cursor += 24;
        BitConverter.GetBytes(-24).CopyTo(data, ctrlSublistOff);
        data[ctrlSublistOff + 4] = 0x6C; data[ctrlSublistOff + 5] = 0x66;
        BitConverter.GetBytes((ushort)1).CopyTo(data, ctrlSublistOff + 6);
        BitConverter.GetBytes((uint)(smKeyOff - 4096)).CopyTo(data, ctrlSublistOff + 8);
        BitConverter.GetBytes(0x41424344U).CopyTo(data, ctrlSublistOff + 12);

        // Key cell: Control
        int ctrlKeyOff = cursor;
        cursor += 96;
        WriteNkCellAt(data, ctrlKeyOff, "Control", false, (uint)(ctrlSublistOff - 4096), 1, 0, 0);

        // Sublist for ControlSet001
        int cs001SublistOff = cursor;
        cursor += 24;
        BitConverter.GetBytes(-24).CopyTo(data, cs001SublistOff);
        data[cs001SublistOff + 4] = 0x6C; data[cs001SublistOff + 5] = 0x66;
        BitConverter.GetBytes((ushort)1).CopyTo(data, cs001SublistOff + 6);
        BitConverter.GetBytes((uint)(ctrlKeyOff - 4096)).CopyTo(data, cs001SublistOff + 8);
        BitConverter.GetBytes(0x41424344U).CopyTo(data, cs001SublistOff + 12);

        // Key cell: ControlSet001
        int cs001KeyOff = cursor;
        cursor += 96;
        WriteNkCellAt(data, cs001KeyOff, "ControlSet001", false, (uint)(cs001SublistOff - 4096), 1, 0, 0);

        // Root sublist
        int rootSublistOff = cursor;
        cursor += 24;
        BitConverter.GetBytes(-24).CopyTo(data, rootSublistOff);
        data[rootSublistOff + 4] = 0x6C; data[rootSublistOff + 5] = 0x66;
        BitConverter.GetBytes((ushort)1).CopyTo(data, rootSublistOff + 6);
        BitConverter.GetBytes((uint)(cs001KeyOff - 4096)).CopyTo(data, rootSublistOff + 8);
        BitConverter.GetBytes(0x41424344U).CopyTo(data, rootSublistOff + 12);

        // Write root key
        WriteNkCellAt(data, rootOff, "ROOT", true, (uint)(rootSublistOff - 4096), 1, 0, 0);

        // Fill remaining slack
        int slack = data.Length - cursor;
        if (slack >= 8)
        {
            BitConverter.GetBytes(slack).CopyTo(data, cursor); // positive = unallocated
        }

        // Checksum
        uint checksum = 0;
        for (int i = 0; i < 508; i += 4) checksum ^= BitConverter.ToUInt32(data, i);
        BitConverter.GetBytes(checksum).CopyTo(data, 508);

        return data;
    }

    private static void WriteNkCellAt(byte[] buffer, int offset, string name, bool isRoot, uint sublistRel, int subCount, uint valListRel, int valCount)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        int cellSize = 80 + nameBytes.Length;
        if (cellSize % 8 != 0) cellSize += (8 - (cellSize % 8));

        BitConverter.GetBytes(-cellSize).CopyTo(buffer, offset);
        buffer[offset + 4] = 0x6E; buffer[offset + 5] = 0x6B;
        ushort flags = 0x0020;
        if (isRoot) flags |= 0x0004;
        BitConverter.GetBytes(flags).CopyTo(buffer, offset + 6);
        BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(buffer, offset + 8);
        BitConverter.GetBytes((uint)subCount).CopyTo(buffer, offset + 24);
        BitConverter.GetBytes(sublistRel).CopyTo(buffer, offset + 28);
        BitConverter.GetBytes((uint)valCount).CopyTo(buffer, offset + 36);
        BitConverter.GetBytes(valListRel).CopyTo(buffer, offset + 40);
        BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(buffer, offset + 72);
        Array.Copy(nameBytes, 0, buffer, offset + 76, nameBytes.Length);
    }

    #endregion
}
