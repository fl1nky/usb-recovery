using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using UsbRecovery;

public static class E01ImageReaderTests
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
        TestSignatureCheck();
        TestDiscoverSegments();
        TestSyntheticE01ReadAndSeek();

        Console.WriteLine("PASS E01ImageReader: {0} checks; Expert Witness Format (E01) parser, chunk decompression, and random-access seeking verified.", checks);
    }

    private static void TestSignatureCheck()
    {
        byte[] valid = new byte[] { 0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00 };
        Check(E01ImageReader.IsE01Signature(valid), "Valid E01 signature recognized");

        byte[] invalid = new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00 };
        Check(!E01ImageReader.IsE01Signature(invalid), "Zip signature rejected as E01");

        Check(!E01ImageReader.IsE01Signature(null), "Null signature rejected");
        Check(!E01ImageReader.IsE01Signature(new byte[5]), "Short signature rejected");

        Check(!E01ImageReader.IsE01File("nonexistent_path_xyz.e01"), "Nonexistent file is not E01");
    }

    private static void TestDiscoverSegments()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "e01-seg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string seg1 = Path.Combine(tempDir, "evidence.E01");
            string seg2 = Path.Combine(tempDir, "evidence.E02");
            string seg3 = Path.Combine(tempDir, "evidence.E03");

            File.WriteAllBytes(seg1, new byte[100]);
            File.WriteAllBytes(seg2, new byte[100]);
            File.WriteAllBytes(seg3, new byte[100]);

            List<string> found = E01ImageReader.DiscoverSegments(seg1);
            Check(found.Count == 3, "Discovered all 3 segments: count=" + found.Count);
            Check(found[0].EndsWith("evidence.E01"), "First segment is E01");
            Check(found[1].EndsWith("evidence.E02"), "Second segment is E02");
            Check(found[2].EndsWith("evidence.E03"), "Third segment is E03");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestSyntheticE01ReadAndSeek()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "e01-synth-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string e01Path = Path.Combine(tempDir, "synthetic_case.E01");

        try
        {
            // Create synthetic E01 file:
            // 2 chunks of 32 KiB each = 64 KiB total disk space.
            // Chunk 0: uncompressed pattern bytes (0xAA)
            // Chunk 1: zlib/deflate compressed pattern bytes (0xBB)
            int chunkSize = 32768;
            byte[] chunk0Data = new byte[chunkSize];
            for (int i = 0; i < chunkSize; i++) chunk0Data[i] = (byte)(i % 256);

            byte[] chunk1Data = new byte[chunkSize];
            for (int i = 0; i < chunkSize; i++) chunk1Data[i] = (byte)((i * 3) % 256);

            // Compress chunk 1 with raw deflate
            byte[] chunk1Deflated;
            using (MemoryStream ms = new MemoryStream())
            {
                using (DeflateStream def = new DeflateStream(ms, CompressionMode.Compress, true))
                {
                    def.Write(chunk1Data, 0, chunk1Data.Length);
                }
                chunk1Deflated = ms.ToArray();
            }

            using (FileStream fs = new FileStream(e01Path, FileMode.Create, FileAccess.Write))
            {
                // 1. File Header (13 bytes)
                // EVF\t\r\n\xff\x00 (8 bytes) + 0x01 (1 byte) + 0x0001 (segment 1) + 0x0000
                fs.Write(new byte[] { 0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00 }, 0, 13);

                // 2. Section "header"
                long headerSectStart = fs.Position;
                string headerKv = "c\tCASE-2026-DFIR\r\ne\tEVID-007\r\na\tForensic Examiner Danil\r\nd\tUSB Device Clone\r\n";
                byte[] headerKvBytes = Encoding.UTF8.GetBytes(headerKv);
                byte[] headerSectHdr = CreateSectionHeader("header", headerSectStart + 76 + headerKvBytes.Length, 76 + headerKvBytes.Length);
                fs.Write(headerSectHdr, 0, 76);
                fs.Write(headerKvBytes, 0, headerKvBytes.Length);

                // 3. Section "volume"
                long volumeSectStart = fs.Position;
                byte[] volData = new byte[64];
                BitConverter.GetBytes((uint)1).CopyTo(volData, 0); // media type
                BitConverter.GetBytes((uint)2).CopyTo(volData, 4); // chunk count = 2
                BitConverter.GetBytes((uint)64).CopyTo(volData, 8); // sectors per chunk = 64
                BitConverter.GetBytes((uint)512).CopyTo(volData, 12); // bytes per sector = 512
                BitConverter.GetBytes((ulong)128).CopyTo(volData, 16); // total sectors = 128 (64KB)
                byte[] volumeSectHdr = CreateSectionHeader("volume", volumeSectStart + 76 + 64, 76 + 64);
                fs.Write(volumeSectHdr, 0, 76);
                fs.Write(volData, 0, 64);

                // 4. Section "sectors" (raw chunk data)
                long sectorsSectStart = fs.Position;
                long rawDataLen = chunk0Data.Length + chunk1Deflated.Length;
                long sectorsSectEnd = sectorsSectStart + 76 + rawDataLen;
                byte[] sectorsSectHdr = CreateSectionHeader("sectors", sectorsSectEnd, 76 + rawDataLen);
                fs.Write(sectorsSectHdr, 0, 76);
                long chunk0Offset = fs.Position;
                fs.Write(chunk0Data, 0, chunk0Data.Length);
                long chunk1Offset = fs.Position;
                fs.Write(chunk1Deflated, 0, chunk1Deflated.Length);

                // 5. Section "table" (chunk index table)
                long tableSectStart = fs.Position;
                uint entryCount = 2;
                byte[] tblData = new byte[24 + (entryCount * 4)];
                BitConverter.GetBytes(entryCount).CopyTo(tblData, 0);
                BitConverter.GetBytes((ulong)sectorsSectStart + 76).CopyTo(tblData, 8); // base offset

                // Chunk 0: uncompressed, offset = 0
                uint chunk0Val = (uint)(chunk0Offset - (sectorsSectStart + 76)); // uncompressed (bit 31 = 0)
                BitConverter.GetBytes(chunk0Val).CopyTo(tblData, 24);

                // Chunk 1: compressed (bit 31 = 1)
                uint chunk1Val = 0x80000000u | (uint)(chunk1Offset - (sectorsSectStart + 76));
                BitConverter.GetBytes(chunk1Val).CopyTo(tblData, 28);

                byte[] tableSectHdr = CreateSectionHeader("table", tableSectStart + 76 + tblData.Length, 76 + tblData.Length);
                fs.Write(tableSectHdr, 0, 76);
                fs.Write(tblData, 0, tblData.Length);

                // 6. Section "hash" (MD5)
                long hashSectStart = fs.Position;
                byte[] hashData = new byte[36];
                for (int i = 0; i < 16; i++) hashData[i] = (byte)(0x10 + i);
                byte[] hashSectHdr = CreateSectionHeader("hash", hashSectStart + 76 + 36, 76 + 36);
                fs.Write(hashSectHdr, 0, 76);
                fs.Write(hashData, 0, 36);

                // 7. Section "done"
                long doneSectStart = fs.Position;
                byte[] doneSectHdr = CreateSectionHeader("done", doneSectStart + 76, 76);
                fs.Write(doneSectHdr, 0, 76);
            }

            // Verify with E01ImageReader
            Check(E01ImageReader.IsE01File(e01Path), "E01ImageReader identifies synthetic E01");

            using (E01ImageReader reader = E01ImageReader.Open(e01Path))
            {
                Check(reader.CanRead, "CanRead is true");
                Check(reader.CanSeek, "CanSeek is true");
                Check(!reader.CanWrite, "CanWrite is false");
                Check(reader.Length == 65536, "Length is 65536 bytes (128 sectors * 512): " + reader.Length);
                Check(reader.ChunkCount == 2, "Chunk count is 2: " + reader.ChunkCount);

                // Verify Metadata
                E01Metadata meta = reader.Metadata;
                Check(meta.CaseNumber == "CASE-2026-DFIR", "CaseNumber parsed: " + meta.CaseNumber);
                Check(meta.EvidenceNumber == "EVID-007", "EvidenceNumber parsed: " + meta.EvidenceNumber);
                Check(meta.Examiner == "Forensic Examiner Danil", "Examiner parsed: " + meta.Examiner);
                Check(meta.Description == "USB Device Clone", "Description parsed: " + meta.Description);
                Check(meta.TotalSectors == 128, "TotalSectors is 128");
                Check(meta.BytesPerSector == 512, "BytesPerSector is 512");
                Check(meta.SectorsPerChunk == 64, "SectorsPerChunk is 64");
                Check(meta.StoredMd5 == "101112131415161718191a1b1c1d1e1f", "StoredMd5 matched: " + meta.StoredMd5);

                // Verify sequential read of chunk 0
                byte[] readBuf = new byte[chunkSize];
                int r0 = reader.Read(readBuf, 0, chunkSize);
                Check(r0 == chunkSize, "Read full chunk 0");
                for (int i = 0; i < chunkSize; i++)
                {
                    if (readBuf[i] != chunk0Data[i]) throw new Exception("Chunk 0 data mismatch at byte " + i);
                }
                Check(reader.Position == chunkSize, "Position advanced to 32768");

                // Verify sequential read of chunk 1 (compressed)
                byte[] readBuf1 = new byte[chunkSize];
                int r1 = reader.Read(readBuf1, 0, chunkSize);
                Check(r1 == chunkSize, "Read full chunk 1");
                for (int i = 0; i < chunkSize; i++)
                {
                    if (readBuf1[i] != chunk1Data[i]) throw new Exception("Chunk 1 data mismatch at byte " + i);
                }
                Check(reader.Position == 65536, "Position advanced to end: " + reader.Position);

                // Verify reading past EOF returns 0
                byte[] eofBuf = new byte[10];
                Check(reader.Read(eofBuf, 0, 10) == 0, "Read at EOF returns 0");

                // Verify Seek and Random Access
                reader.Seek(100, SeekOrigin.Begin);
                Check(reader.Position == 100, "Seek to position 100");
                byte[] sample = new byte[4];
                reader.Read(sample, 0, 4);
                Check(sample[0] == chunk0Data[100] && sample[1] == chunk0Data[101], "Data at offset 100 matches");

                // Verify Boundary crossing read (straddling chunk 0 and chunk 1)
                long straddleOffset = 32760; // 8 bytes before end of chunk 0
                reader.Seek(straddleOffset, SeekOrigin.Begin);
                byte[] straddleBuf = new byte[20];
                int straddleRead = reader.Read(straddleBuf, 0, 20);
                Check(straddleRead == 20, "Straddle read returned 20 bytes");
                // First 8 bytes come from chunk 0
                for (int i = 0; i < 8; i++)
                {
                    Check(straddleBuf[i] == chunk0Data[32760 + i], "Straddle chunk 0 part matches at " + i);
                }
                // Next 12 bytes come from chunk 1
                for (int i = 0; i < 12; i++)
                {
                    Check(straddleBuf[8 + i] == chunk1Data[i], "Straddle chunk 1 part matches at " + i);
                }

                // Verify Seek from current and end
                reader.Seek(-10, SeekOrigin.End);
                Check(reader.Position == 65536 - 10, "Seek from End matches: " + reader.Position);

                // Verify LRU cache hit
                reader.Seek(0, SeekOrigin.Begin);
                byte[] cacheBuf = new byte[16];
                reader.Read(cacheBuf, 0, 16);
                Check(cacheBuf[0] == chunk0Data[0], "Cache hit chunk 0 read successful");
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static byte[] CreateSectionHeader(string type, long nextOffset, long size)
    {
        byte[] hdr = new byte[76];
        byte[] typeBytes = Encoding.ASCII.GetBytes(type);
        Array.Copy(typeBytes, hdr, Math.Min(16, typeBytes.Length));
        BitConverter.GetBytes((ulong)nextOffset).CopyTo(hdr, 16);
        BitConverter.GetBytes((ulong)size).CopyTo(hdr, 24);
        return hdr;
    }
}
