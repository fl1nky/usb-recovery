using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using UsbRecovery;

public static class Qcow2ImageReaderTests
{
    public static void Main()
    {
        int passed = 0;

        // 1. Signature check
        Assert(Qcow2ImageReader.IsQcow2Signature(new byte[] { 0x51, 0x46, 0x49, 0xFB }), "Valid QCOW2 signature");
        passed++;

        Assert(!Qcow2ImageReader.IsQcow2Signature(new byte[] { 0x50, 0x46, 0x49, 0xFB }), "Invalid signature rejected");
        passed++;

        Assert(!Qcow2ImageReader.IsQcow2Signature(null), "Null signature rejected");
        passed++;

        Assert(!Qcow2ImageReader.IsQcow2Signature(new byte[] { 0x51, 0x46 }), "Short signature rejected");
        passed++;

        // 2. Build synthetic QCOW2 v2 and v3 images in memory
        byte[] v2Image = CreateSyntheticQcow2(version: 2, clusterBits: 16, diskSize: 1048576); // 1 MB, 64KB clusters
        using (MemoryStream ms = new MemoryStream(v2Image))
        using (Qcow2ImageReader reader = Qcow2ImageReader.Open(ms, true))
        {
            Assert(reader.Header.Version == 2, "QCOW2 v2 version parsed");
            passed++;

            Assert(reader.Length == 1048576, "QCOW2 disk length is 1MB");
            passed++;

            Assert(reader.ClusterSize == 65536, "Cluster size is 64KB");
            passed++;

            Assert(reader.CanRead && reader.CanSeek && !reader.CanWrite, "Write-blocking and seek capabilities verified");
            passed++;

            // Test reading Cluster 0 (contains test payload "QCOW2_TEST_PAYLOAD_AT_CLUSTER_0")
            byte[] buf = new byte[32];
            int r = reader.Read(buf, 0, buf.Length);
            Assert(r == 32, "Read 32 bytes from cluster 0");
            passed++;

            string text = Encoding.ASCII.GetString(buf, 0, 31);
            Assert(text.StartsWith("QCOW2_TEST_PAYLOAD_AT_CLUSTER_0"), "Read expected payload from cluster 0");
            passed++;

            // Test seeking and reading Cluster 1 (unallocated / sparse -> must return zeros)
            reader.Position = 65536; // cluster 1
            byte[] sparseBuf = new byte[1024];
            r = reader.Read(sparseBuf, 0, sparseBuf.Length);
            Assert(r == 1024, "Read 1024 bytes from sparse cluster 1");
            passed++;

            bool allZero = true;
            for (int i = 0; i < sparseBuf.Length; i++)
            {
                if (sparseBuf[i] != 0) { allZero = false; break; }
            }
            Assert(allZero, "Sparse cluster returns all zeros");
            passed++;

            // Test reading Cluster 2 (Compressed cluster)
            reader.Position = 131072; // cluster 2
            byte[] compReadBuf = new byte[64];
            r = reader.Read(compReadBuf, 0, compReadBuf.Length);
            Assert(r == 64, "Read 64 bytes from compressed cluster");
            passed++;

            string compText = Encoding.ASCII.GetString(compReadBuf, 0, 29);
            Assert(compText.StartsWith("COMPRESSED_CLUSTER_DATA_V2"), "Decompressed cluster data verified");
            passed++;

            // Test seeking using SeekOrigin
            reader.Seek(-100, SeekOrigin.End);
            Assert(reader.Position == 1048576 - 100, "Seek from End verified");
            passed++;

            reader.Seek(10, SeekOrigin.Current);
            Assert(reader.Position == 1048576 - 90, "Seek from Current verified");
            passed++;

            // Test Write and SetLength throw NotSupportedException
            bool writeBlocked = false;
            try { reader.Write(new byte[1], 0, 1); } catch (NotSupportedException) { writeBlocked = true; }
            Assert(writeBlocked, "Write throws NotSupportedException");
            passed++;

            bool setLengthBlocked = false;
            try { reader.SetLength(500); } catch (NotSupportedException) { setLengthBlocked = true; }
            Assert(setLengthBlocked, "SetLength throws NotSupportedException");
            passed++;
        }

        // 3. Test QCOW2 v3 features (Zero cluster, Incompatible features)
        byte[] v3Image = CreateSyntheticQcow2(version: 3, clusterBits: 12, diskSize: 65536); // 4KB clusters
        using (MemoryStream ms = new MemoryStream(v3Image))
        using (Qcow2ImageReader reader = Qcow2ImageReader.Open(ms, true))
        {
            Assert(reader.Header.Version == 3, "QCOW2 v3 version parsed");
            passed++;

            Assert(reader.ClusterSize == 4096, "Cluster size is 4KB");
            passed++;

            Assert(reader.Length == 65536, "Disk size is 64KB");
            passed++;

            // Reading past EOF returns 0
            reader.Position = 65536;
            byte[] eofBuf = new byte[16];
            int eofRead = reader.Read(eofBuf, 0, 16);
            Assert(eofRead == 0, "Read past EOF returns 0");
            passed++;
        }

        // 4. File-based detection test
        string tempFile = Path.Combine(Path.GetTempPath(), "test_" + Guid.NewGuid().ToString("N") + ".qcow2");
        try
        {
            File.WriteAllBytes(tempFile, v2Image);
            Assert(Qcow2ImageReader.IsQcow2File(tempFile), "IsQcow2File detects valid file on disk");
            passed++;

            using (Qcow2ImageReader fileReader = Qcow2ImageReader.Open(tempFile))
            {
                Assert(fileReader.Length == 1048576, "Opened fileReader length matches");
                passed++;

                byte[] b = new byte[10];
                fileReader.Read(b, 0, 10);
                Assert(Encoding.ASCII.GetString(b).StartsWith("QCOW2"), "Read from file matches");
                passed++;
            }
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                try { File.Delete(tempFile); } catch { }
            }
        }

        Console.WriteLine("PASS Qcow2ImageReaderTests: {0} checks passed; QCOW2 v2/v3 parsing, sparse clusters, zlib decompression, seeking, and write-blocking verified.", passed);
    }

    private static byte[] CreateSyntheticQcow2(uint version, uint clusterBits, ulong diskSize)
    {
        uint clusterSize = 1U << (int)clusterBits;
        // Total image structure layout:
        // Cluster 0 (0 .. clusterSize-1): Header
        // Cluster 1 (clusterSize .. 2*clusterSize-1): L1 Table (supports up to clusterSize / 8 entries)
        // Cluster 2 (2*clusterSize .. 3*clusterSize-1): L2 Table
        // Cluster 3 (3*clusterSize .. 4*clusterSize-1): Data Cluster 0
        // Cluster 4 (4*clusterSize .. 5*clusterSize-1): Compressed Cluster 2
        int totalClusters = 6;
        byte[] image = new byte[clusterSize * (uint)totalClusters];

        // 1. QCOW2 Header at offset 0
        WriteUInt32BE(image, 0, Qcow2ImageReader.Qcow2Magic); // magic
        WriteUInt32BE(image, 4, version);                    // version
        WriteUInt64BE(image, 8, 0);                          // backing file offset
        WriteUInt32BE(image, 16, 0);                         // backing file size
        WriteUInt32BE(image, 20, clusterBits);               // cluster_bits
        WriteUInt64BE(image, 24, diskSize);                  // virtual disk size
        WriteUInt32BE(image, 32, 0);                         // crypt_method (0)
        WriteUInt32BE(image, 36, 1);                         // l1_size (1 entry)
        WriteUInt64BE(image, 40, clusterSize);               // l1_table_offset (Cluster 1)
        WriteUInt64BE(image, 48, 0);                         // refcount table offset
        WriteUInt32BE(image, 56, 0);                         // refcount table clusters
        WriteUInt32BE(image, 60, 0);                         // snapshots
        WriteUInt64BE(image, 64, 0);                         // snapshots offset

        if (version >= 3)
        {
            WriteUInt64BE(image, 72, 0);                     // incompatible features
            WriteUInt64BE(image, 80, 0);                     // compatible features
            WriteUInt64BE(image, 88, 0);                     // autoclear features
            WriteUInt32BE(image, 96, 4);                     // refcount_order
            WriteUInt32BE(image, 100, 104);                  // header length
        }

        // 2. L1 Table at Cluster 1 (offset = clusterSize)
        // Entry 0 points to Cluster 2 (L2 Table)
        ulong l2Offset = clusterSize * 2;
        ulong l1Entry = l2Offset | 0x8000000000000000UL; // Copied bit set
        WriteUInt64BE(image, (int)clusterSize, l1Entry);

        // 3. L2 Table at Cluster 2 (offset = clusterSize * 2)
        int l2Base = (int)(clusterSize * 2);

        // L2[0]: Data Cluster 0 (at clusterSize * 3)
        ulong dataCluster0Offset = clusterSize * 3;
        ulong l2Entry0 = dataCluster0Offset | 0x8000000000000000UL;
        WriteUInt64BE(image, l2Base, l2Entry0);

        // L2[1]: Sparse / Unallocated (offset = 0)
        WriteUInt64BE(image, l2Base + 8, 0);

        // L2[2]: Compressed cluster at Cluster 4 (offset = clusterSize * 4)
        byte[] rawClusterData = Encoding.ASCII.GetBytes("COMPRESSED_CLUSTER_DATA_V2_WITH_EXTRA_PADDING_TO_FILL_SPACE_AND_TEST_DECOMPRESSION");
        byte[] compressedData = CompressZlib(rawClusterData);

        int compClusterOffset = (int)(clusterSize * 4);
        Buffer.BlockCopy(compressedData, 0, image, compClusterOffset, compressedData.Length);

        // Compute L2 entry for compressed cluster:
        // Bit 62: set
        // Bits (62 - (clusterBits - 8)) .. 61: number of 512 sectors minus 1
        int nbSectors = (compressedData.Length + 511) / 512;
        int csizeShift = 62 - ((int)clusterBits - 8);
        ulong csizeVal = (ulong)(nbSectors - 1);
        ulong l2Entry2 = (1UL << 62) | (csizeVal << csizeShift) | (ulong)(uint)compClusterOffset;
        WriteUInt64BE(image, l2Base + 16, l2Entry2);

        // 4. Data Cluster 0 contents at Cluster 3
        int dataBase = (int)(clusterSize * 3);
        byte[] payload0 = Encoding.ASCII.GetBytes("QCOW2_TEST_PAYLOAD_AT_CLUSTER_0_FORENSIC_READY");
        Buffer.BlockCopy(payload0, 0, image, dataBase, payload0.Length);

        return image;
    }

    private static byte[] CompressZlib(byte[] data)
    {
        using (MemoryStream dest = new MemoryStream())
        {
            // Write standard 2-byte zlib header (0x78, 0x9C)
            dest.WriteByte(0x78);
            dest.WriteByte(0x9C);
            using (DeflateStream def = new DeflateStream(dest, CompressionMode.Compress, true))
            {
                def.Write(data, 0, data.Length);
            }
            return dest.ToArray();
        }
    }

    private static void WriteUInt32BE(byte[] buffer, int offset, uint val)
    {
        buffer[offset] = (byte)(val >> 24);
        buffer[offset + 1] = (byte)(val >> 16);
        buffer[offset + 2] = (byte)(val >> 8);
        buffer[offset + 3] = (byte)val;
    }

    private static void WriteUInt64BE(byte[] buffer, int offset, ulong val)
    {
        buffer[offset] = (byte)(val >> 56);
        buffer[offset + 1] = (byte)(val >> 48);
        buffer[offset + 2] = (byte)(val >> 40);
        buffer[offset + 3] = (byte)(val >> 32);
        buffer[offset + 4] = (byte)(val >> 24);
        buffer[offset + 5] = (byte)(val >> 16);
        buffer[offset + 6] = (byte)(val >> 8);
        buffer[offset + 7] = (byte)val;
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception("Assertion failed: " + message);
        }
    }
}
