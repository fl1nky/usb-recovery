using System;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class VssScoutTests
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
        try
        {
            TestSyntheticVssCatalogBlock();
            TestSyntheticVssStoreBlockTable();
            TestCarvedSnapshotAntiForensics();
            TestDirectoryScouting();
            TestCorruptAndTruncatedBuffers();
            TestJsonSerialization();
            TestCancellationToken();

            Console.WriteLine("PASS VssScoutTests: {0} checks passed; Volume Shadow Copies (VSS) catalog parsing, CoW block descriptors, anti-forensics deletion detection, and carving verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL VssScoutTests: {0}", ex.Message);
            return 1;
        }
    }

    private static void TestSyntheticVssCatalogBlock()
    {
        byte[] buffer = new byte[1024];

        // 1. VSS Header identifier GUID
        Buffer.BlockCopy(VssScout.VssIdentifierGuid, 0, buffer, 0, 16);

        // Version = 1
        BitConverter.GetBytes(1U).CopyTo(buffer, 16);

        // RecordType = 2 (Catalog 1)
        BitConverter.GetBytes(2U).CopyTo(buffer, 20);

        // RelOffset = 0, NextRelOffset = 0
        BitConverter.GetBytes(0UL).CopyTo(buffer, 24);
        BitConverter.GetBytes(0UL).CopyTo(buffer, 32);

        // Catalog entry at offset 40:
        // EntryType = 2 (Snapshot Entry)
        BitConverter.GetBytes(2U).CopyTo(buffer, 40);

        // EntrySize = 128
        BitConverter.GetBytes(128U).CopyTo(buffer, 44);

        // SnapshotId at 40 + 8 = 48
        Guid expectedSnapId = Guid.NewGuid();
        Buffer.BlockCopy(expectedSnapId.ToByteArray(), 0, buffer, 48, 16);

        // SnapshotSetId at 40 + 24 = 64
        Guid expectedSetId = Guid.NewGuid();
        Buffer.BlockCopy(expectedSetId.ToByteArray(), 0, buffer, 64, 16);

        // Creation FILETIME at 40 + 40 = 80
        DateTime expectedDt = new DateTime(2026, 11, 20, 12, 30, 0, DateTimeKind.Utc);
        BitConverter.GetBytes(expectedDt.ToFileTimeUtc()).CopyTo(buffer, 80);

        // Volume size (uint64) at 40 + 48 = 88
        long volSize = 250000000000L; // 250 GB
        BitConverter.GetBytes(volSize).CopyTo(buffer, 88);

        // Allocated store bytes at 40 + 56 = 96
        long allocBytes = 16384000L; // ~16 MB
        BitConverter.GetBytes(allocBytes).CopyTo(buffer, 96);

        // Machine name at 40 + 64 = 104
        byte[] nameBytes = Encoding.ASCII.GetBytes("FORENSIC-WORK01");
        Buffer.BlockCopy(nameBytes, 0, buffer, 104, Math.Min(nameBytes.Length, 16));

        var report = VssScout.ParseBuffer(buffer, "test_catalog.raw");

        Check(report != null, "Report is not null");
        Check(report.TotalSnapshots == 1, "Catalog parsed exactly 1 snapshot");
        Check(report.Snapshots.Count == 1, "Snapshots list count is 1");

        var snap = report.Snapshots[0];
        Check(snap.SnapshotId == expectedSnapId, "SnapshotId matches");
        Check(snap.SnapshotSetId == expectedSetId, "SnapshotSetId matches");
        Check(snap.CreationTimeUtc == expectedDt, "CreationTimeUtc matches");
        Check(snap.VolumeSize == volSize, "VolumeSize matches 250 GB");
        Check(snap.AllocatedBytes == allocBytes, "AllocatedBytes matches 16 MB");
        Check(snap.StoreBlockCount == (int)(allocBytes / 16384L), "StoreBlockCount matches allocated blocks");
        Check(snap.MachineName.StartsWith("FORENSIC-WORK01"), "MachineName matches FORENSIC-WORK01");
        Check(snap.Attributes.Contains("ClientAccessible"), "Attributes contain ClientAccessible");
    }

    private static void TestSyntheticVssStoreBlockTable()
    {
        byte[] buffer = new byte[1024];

        // VSS Header identifier GUID
        Buffer.BlockCopy(VssScout.VssIdentifierGuid, 0, buffer, 0, 16);

        // Version = 1
        BitConverter.GetBytes(1U).CopyTo(buffer, 16);

        // RecordType = 4 (Store Block Table)
        BitConverter.GetBytes(4U).CopyTo(buffer, 20);

        // Block mappings start at offset 40:
        // Entry 1: VolumeOffset 0x100000 -> StoreOffset 0x4000
        BitConverter.GetBytes(0x100000UL).CopyTo(buffer, 40);
        BitConverter.GetBytes(0x4000UL).CopyTo(buffer, 48);

        // Entry 2: VolumeOffset 0x200000 -> StoreOffset 0x8000
        BitConverter.GetBytes(0x200000UL).CopyTo(buffer, 56);
        BitConverter.GetBytes(0x8000UL).CopyTo(buffer, 64);

        // Entry 3: VolumeOffset 0x300000 -> StoreOffset 0xC000
        BitConverter.GetBytes(0x300000UL).CopyTo(buffer, 72);
        BitConverter.GetBytes(0xC000UL).CopyTo(buffer, 80);

        var report = VssScout.ParseBuffer(buffer, "test_store_table.raw");

        Check(report != null, "Report is not null");
        Check(report.Snapshots.Count == 1, "Store block table represented as snapshot record");

        var snap = report.Snapshots[0];
        Check(snap.BlockMappings.Count == 3, "Parsed 3 CoW block mappings");
        Check(snap.BlockMappings[0].OriginalVolumeOffset == 0x100000, "Mapping 0 VolumeOffset is 0x100000");
        Check(snap.BlockMappings[0].StoreOffset == 0x4000, "Mapping 0 StoreOffset is 0x4000");
        Check(snap.BlockMappings[1].OriginalVolumeOffset == 0x200000, "Mapping 1 VolumeOffset is 0x200000");
        Check(snap.BlockMappings[2].StoreOffset == 0xC000, "Mapping 2 StoreOffset is 0xC000");
        Check(snap.StoreBlockCount == 3, "StoreBlockCount is 3");
        Check(snap.AllocatedBytes == 3 * 16384L, "AllocatedBytes is 49152");
    }

    private static void TestCarvedSnapshotAntiForensics()
    {
        // Simulate orphaned / carved sector where volume header was deleted or wiped
        byte[] buffer = new byte[2048];

        int carveOffset = 512;
        Buffer.BlockCopy(VssScout.VssIdentifierGuid, 0, buffer, carveOffset, 16);

        // Write GUIDs and timestamp
        Guid snapId = Guid.NewGuid();
        Guid setId = Guid.NewGuid();
        DateTime dt = new DateTime(2026, 11, 15, 8, 0, 0, DateTimeKind.Utc);

        Buffer.BlockCopy(snapId.ToByteArray(), 0, buffer, carveOffset + 16, 16);
        Buffer.BlockCopy(setId.ToByteArray(), 0, buffer, carveOffset + 32, 16);
        BitConverter.GetBytes(dt.ToFileTimeUtc()).CopyTo(buffer, carveOffset + 48);

        var report = VssScout.ParseBuffer(buffer, "carved_wiped_volume.raw");

        Check(report != null, "Report is not null");
        Check(report.TotalSnapshots >= 1, "Discovered carved snapshot");
        Check(report.IsWipedOrOrphaned, "IsWipedOrOrphaned flagged true");
        Check(report.SuspicionReason.Contains("T1490"), "SuspicionReason flags MITRE ATT&CK T1490 Inhibit System Recovery");

        var snap = report.Snapshots[0];
        Check(snap.IsCarved, "Snapshot IsCarved is true");
        Check(snap.SnapshotId == snapId, "Carved SnapshotId matches");
        Check(snap.CreationTimeUtc == dt, "Carved CreationTimeUtc matches");
    }

    private static void TestDirectoryScouting()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "vss_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tempDir);
            string vssFile = Path.Combine(tempDir, "{6b870838-c176-484e-b7ae-04046e6cc752}{3808876b-c176-4e48-b7ae-04046e6cc752}");

            byte[] buffer = new byte[512];
            Buffer.BlockCopy(VssScout.VssIdentifierGuid, 0, buffer, 0, 16);
            BitConverter.GetBytes(1U).CopyTo(buffer, 16);
            BitConverter.GetBytes(2U).CopyTo(buffer, 20); // Catalog 1
            BitConverter.GetBytes(2U).CopyTo(buffer, 40); // Snapshot entry
            BitConverter.GetBytes(128U).CopyTo(buffer, 44);
            Guid id = Guid.NewGuid();
            Buffer.BlockCopy(id.ToByteArray(), 0, buffer, 48, 16);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(buffer, 80);
            File.WriteAllBytes(vssFile, buffer);

            var report = VssScout.ScoutDirectory(tempDir);

            Check(report != null, "Directory report is not null");
            Check(report.TotalSnapshots == 1, "Directory found 1 snapshot in catalog file");
            Check(report.Snapshots[0].SnapshotId == id, "Snapshot ID matched directory parsed file");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestCorruptAndTruncatedBuffers()
    {
        var emptyRep = VssScout.ParseBuffer(new byte[0]);
        Check(emptyRep.TotalSnapshots == 0, "Empty buffer yields 0 snapshots");

        var smallRep = VssScout.ParseBuffer(new byte[32]);
        Check(smallRep.TotalSnapshots == 0, "Small buffer yields 0 snapshots");

        byte[] noise = new byte[2048];
        new Random(42).NextBytes(noise);
        var noiseRep = VssScout.ParseBuffer(noise);
        Check(noiseRep.TotalSnapshots == 0, "Random noise yields 0 snapshots");
    }

    private static void TestJsonSerialization()
    {
        var rep = new VssReport
        {
            SourcePath = "test.raw",
            TotalSnapshots = 1,
            TotalStoreBlocks = 10,
            TotalSnapshotBytes = 163840,
            IsWipedOrOrphaned = true,
            SuspicionReason = "Orphaned snapshot"
        };
        rep.Snapshots.Add(new VssSnapshotRecord
        {
            SnapshotId = Guid.NewGuid(),
            SnapshotSetId = Guid.NewGuid(),
            CreationTimeUtc = new DateTime(2026, 11, 20, 10, 0, 0, DateTimeKind.Utc),
            VolumeSize = 1000000,
            AllocatedBytes = 163840,
            MachineName = "DESKTOP-ABC",
            IsCarved = true
        });

        string json = rep.ToJson();
        Check(!string.IsNullOrEmpty(json), "JSON output is not empty");
        Check(json.Contains("\"SourcePath\":\"test.raw\""), "JSON contains SourcePath");
        Check(json.Contains("\"TotalSnapshots\":1"), "JSON contains TotalSnapshots");
        Check(json.Contains("\"IsWipedOrOrphaned\":true"), "JSON contains IsWipedOrOrphaned");
        Check(json.Contains("\"MachineName\":\"DESKTOP-ABC\""), "JSON contains MachineName");
    }

    private static void TestCancellationToken()
    {
        using (var cts = new CancellationTokenSource())
        {
            cts.Cancel();
            byte[] buf = new byte[65536];
            using (var ms = new MemoryStream(buf))
            {
                var rep = VssScout.ScoutStream(ms, "canceled.raw", cts.Token);
                Check(rep != null, "Canceled report is not null");
                Check(rep.TotalSnapshots == 0, "Canceled report has 0 snapshots");
            }
        }
    }
}
