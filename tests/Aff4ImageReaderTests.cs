using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using UsbRecovery;

public static class Aff4ImageReaderTests
{
    public static void Main()
    {
        int passed = 0;

        // 1. Test Snappy decompression in isolation
        byte[] rawSnappyData = CreateSnappyBlock("HELLO_WORLD_SNAPPY_FORENSIC_AFF4_STREAM_TEST_STRING_REPEAT_REPEAT_REPEAT");
        byte[] decompressedSnappy = Aff4ImageReader.DecompressSnappy(rawSnappyData, rawSnappyData.Length);
        Assert(decompressedSnappy != null, "Snappy decompression returned non-null");
        passed++;

        string snappyText = Encoding.ASCII.GetString(decompressedSnappy);
        Assert(snappyText.StartsWith("HELLO_WORLD_SNAPPY"), "Snappy payload matches expected text");
        passed++;

        // 2. Build synthetic AFF4 container with Turtle manifest and single data stream
        byte[] aff4Bytes = CreateSyntheticAff4(
            size: 65536,
            chunkSize: 4096,
            compression: "Deflate",
            payload: "AFF4_STANDARD_IMAGE_RAW_DATA_PAYLOAD_TEST_1234567890"
        );

        using (MemoryStream ms = new MemoryStream(aff4Bytes))
        using (Aff4ImageReader reader = Aff4ImageReader.Open(ms, true))
        {
            Assert(reader.Length == 65536, "AFF4 virtual disk size parsed from Turtle");
            passed++;

            Assert(reader.Metadata.ChunkSize == 4096, "AFF4 chunk size parsed");
            passed++;

            Assert(reader.Metadata.CaseNumber == "CASE-2026-USB", "CaseNumber parsed");
            passed++;

            Assert(reader.Metadata.EvidenceNumber == "EVD-999", "EvidenceNumber parsed");
            passed++;

            Assert(reader.Metadata.Examiner == "Chief Forensics Examiner", "Examiner parsed");
            passed++;

            Assert(reader.CanRead && reader.CanSeek && !reader.CanWrite, "Write-blocking and seeking verified");
            passed++;

            byte[] buf = new byte[32];
            int r = reader.Read(buf, 0, buf.Length);
            Assert(r == 32, "Read 32 bytes from AFF4 stream");
            passed++;

            string readText = Encoding.ASCII.GetString(buf, 0, 31);
            Assert(readText.StartsWith("AFF4_STANDARD_IMAGE_RAW_DATA"), "AFF4 payload read accurately");
            passed++;

            // Test seeking
            reader.Seek(10, SeekOrigin.Begin);
            Assert(reader.Position == 10, "Seek from Begin verified");
            passed++;

            reader.Seek(100, SeekOrigin.Current);
            Assert(reader.Position == 110, "Seek from Current verified");
            passed++;

            reader.Seek(-50, SeekOrigin.End);
            Assert(reader.Position == 65536 - 50, "Seek from End verified");
            passed++;

            // Test write blocking
            bool writeBlocked = false;
            try { reader.Write(new byte[1], 0, 1); } catch (NotSupportedException) { writeBlocked = true; }
            Assert(writeBlocked, "Write throws NotSupportedException");
            passed++;

            bool setLengthBlocked = false;
            try { reader.SetLength(100); } catch (NotSupportedException) { setLengthBlocked = true; }
            Assert(setLengthBlocked, "SetLength throws NotSupportedException");
            passed++;
        }

        // 3. Build synthetic segmented AFF4 container (00000000, 00000001)
        byte[] segmentedAff4 = CreateSyntheticSegmentedAff4(
            size: 8192,
            chunkSize: 4096,
            chunksPerSegment: 1
        );

        using (MemoryStream ms = new MemoryStream(segmentedAff4))
        using (Aff4ImageReader reader = Aff4ImageReader.Open(ms, true))
        {
            Assert(reader.Length == 8192, "Segmented AFF4 length matches");
            passed++;

            byte[] b0 = new byte[16];
            reader.Position = 0;
            reader.Read(b0, 0, 16);
            Assert(Encoding.ASCII.GetString(b0).StartsWith("SEGMENT_0"), "Read segment 0 verified");
            passed++;

            byte[] b1 = new byte[16];
            reader.Position = 4096;
            reader.Read(b1, 0, 16);
            Assert(Encoding.ASCII.GetString(b1).StartsWith("SEGMENT_1"), "Read segment 1 verified");
            passed++;
        }

        // 4. File-based detection test
        string tempFile = Path.Combine(Path.GetTempPath(), "test_" + Guid.NewGuid().ToString("N") + ".aff4");
        try
        {
            File.WriteAllBytes(tempFile, aff4Bytes);
            Assert(Aff4ImageReader.IsAff4File(tempFile), "IsAff4File detects valid file on disk");
            passed++;

            using (Aff4ImageReader fileReader = Aff4ImageReader.Open(tempFile))
            {
                Assert(fileReader.Length == 65536, "Opened fileReader length matches");
                passed++;

                byte[] b = new byte[10];
                fileReader.Read(b, 0, 10);
                Assert(Encoding.ASCII.GetString(b).StartsWith("AFF4"), "Read from file matches");
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

        Console.WriteLine("PASS Aff4ImageReaderTests: {0} checks passed; AFF4 RDF Turtle manifest parsing, segmented and linear streams, Snappy decompression, seeking, and write-blocking verified.", passed);
    }

    private static byte[] CreateSyntheticAff4(long size, int chunkSize, string compression, string payload)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            using (ZipArchive zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                // 1. information.turtle
                ZipArchiveEntry turtleEntry = zip.CreateEntry("information.turtle");
                using (StreamWriter w = new StreamWriter(turtleEntry.Open(), Encoding.UTF8))
                {
                    w.WriteLine("@prefix aff4: <http://aff4.org/Schema#> .");
                    w.WriteLine("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .");
                    w.WriteLine("<aff4://c2517f6e-40fa-4496-8216-914460f13e49>");
                    w.WriteLine("    a aff4:Image, aff4:DiskImage ;");
                    w.WriteLine(string.Format("    aff4:size {0} ;", size));
                    w.WriteLine(string.Format("    aff4:chunk_size {0} ;", chunkSize));
                    w.WriteLine(string.Format("    aff4:compression aff4:{0} ;", compression));
                    w.WriteLine("    aff4:caseNumber \"CASE-2026-USB\" ;");
                    w.WriteLine("    aff4:evidenceNumber \"EVD-999\" ;");
                    w.WriteLine("    aff4:examiner \"Chief Forensics Examiner\" ;");
                    w.WriteLine("    aff4:dataStream <aff4://c2517f6e-40fa-4496-8216-914460f13e49/data> .");
                }

                // 2. data entry
                ZipArchiveEntry dataEntry = zip.CreateEntry("data");
                using (Stream s = dataEntry.Open())
                {
                    byte[] data = new byte[size];
                    byte[] pay = Encoding.ASCII.GetBytes(payload);
                    Buffer.BlockCopy(pay, 0, data, 0, pay.Length);
                    s.Write(data, 0, data.Length);
                }
            }
            return ms.ToArray();
        }
    }

    private static byte[] CreateSyntheticSegmentedAff4(long size, int chunkSize, int chunksPerSegment)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            using (ZipArchive zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                ZipArchiveEntry turtleEntry = zip.CreateEntry("information.turtle");
                using (StreamWriter w = new StreamWriter(turtleEntry.Open(), Encoding.UTF8))
                {
                    w.WriteLine("@prefix aff4: <http://aff4.org/Schema#> .");
                    w.WriteLine("<aff4://segmented-guid-1234>");
                    w.WriteLine("    a aff4:Image ;");
                    w.WriteLine(string.Format("    aff4:size {0} ;", size));
                    w.WriteLine(string.Format("    aff4:chunk_size {0} ;", chunkSize));
                    w.WriteLine(string.Format("    aff4:chunks_per_segment {0} .", chunksPerSegment));
                }

                // Segment 00000000
                ZipArchiveEntry seg0 = zip.CreateEntry("00000000");
                using (Stream s0 = seg0.Open())
                {
                    byte[] d0 = new byte[chunkSize];
                    byte[] pay0 = Encoding.ASCII.GetBytes("SEGMENT_0_DATA_CONTENT");
                    Buffer.BlockCopy(pay0, 0, d0, 0, pay0.Length);
                    s0.Write(d0, 0, d0.Length);
                }

                // Segment 00000001
                ZipArchiveEntry seg1 = zip.CreateEntry("00000001");
                using (Stream s1 = seg1.Open())
                {
                    byte[] d1 = new byte[chunkSize];
                    byte[] pay1 = Encoding.ASCII.GetBytes("SEGMENT_1_DATA_CONTENT");
                    Buffer.BlockCopy(pay1, 0, d1, 0, pay1.Length);
                    s1.Write(d1, 0, d1.Length);
                }
            }
            return ms.ToArray();
        }
    }

    private static byte[] CreateSnappyBlock(string text)
    {
        byte[] raw = Encoding.ASCII.GetBytes(text);
        // Build raw Snappy block:
        // 1. Varint uncompressed length
        using (MemoryStream ms = new MemoryStream())
        {
            int len = raw.Length;
            while (len >= 0x80)
            {
                ms.WriteByte((byte)((len & 0x7F) | 0x80));
                len >>= 7;
            }
            ms.WriteByte((byte)len);

            // Literal element: tag = (raw.Length - 1) << 2
            if (raw.Length <= 60)
            {
                byte tag = (byte)((raw.Length - 1) << 2);
                ms.WriteByte(tag);
            }
            else
            {
                byte tag = (byte)(60 << 2); // 60 means 1 byte extra length
                ms.WriteByte(tag);
                ms.WriteByte((byte)(raw.Length - 1));
            }

            ms.Write(raw, 0, raw.Length);
            return ms.ToArray();
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception("Assertion failed: " + message);
        }
    }
}
