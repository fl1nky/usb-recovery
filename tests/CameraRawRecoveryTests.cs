using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class CameraRawRecoveryTests
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
        Console.WriteLine("Running CameraRawRecoveryTests...");
        string testDir = Path.Combine(Path.GetTempPath(), "usb-raw-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            // 1. Test Fujifilm RAF
            TestFujifilmRaf(testDir);

            // 2. Test Canon CR2
            TestCanonCr2(testDir);

            // 3. Test Nikon NEF
            TestNikonNef(testDir);

            // 4. Test Sony ARW
            TestSonyArw(testDir);

            // 5. Test Adobe DNG
            TestAdobeDng(testDir);

            // 6. Test Canon CR3 (ISOBMFF)
            TestCanonCr3(testDir);

            // 7. Test Carving Stream
            TestCarvingStream();

            // 8. Test Directory Salvage
            TestDirectorySalvage(testDir);

            // 9. Test CLI salvage-raw
            TestCliSalvageRaw(testDir);

            Console.WriteLine("PASS CameraRawRecovery: {0} checks; Fuji RAF, Canon CR2/CR3, Nikon NEF, Sony ARW, Adobe DNG carving and EXIF extraction verified.", checks);
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

    private static byte[] CreateSampleJpeg(int width, int height)
    {
        var ms = new MemoryStream();
        // SOI
        ms.WriteByte(0xFF); ms.WriteByte(0xD8);
        // APP0
        ms.WriteByte(0xFF); ms.WriteByte(0xE0);
        ms.WriteByte(0x00); ms.WriteByte(0x10); // length 16
        byte[] jfif = Encoding.ASCII.GetBytes("JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        ms.Write(jfif, 0, jfif.Length);

        // SOF0 (Baseline DCT)
        ms.WriteByte(0xFF); ms.WriteByte(0xC0);
        ms.WriteByte(0x00); ms.WriteByte(0x0B); // length 11
        ms.WriteByte(0x08); // precision 8 bits
        ms.WriteByte((byte)((height >> 8) & 0xFF));
        ms.WriteByte((byte)(height & 0xFF));
        ms.WriteByte((byte)((width >> 8) & 0xFF));
        ms.WriteByte((byte)(width & 0xFF));
        ms.WriteByte(0x01); // 1 component
        ms.WriteByte(0x01); // component ID 1
        ms.WriteByte(0x11); // sampling factors
        ms.WriteByte(0x00); // quant table 0

        // SOS (Start of Scan)
        ms.WriteByte(0xFF); ms.WriteByte(0xDA);
        ms.WriteByte(0x00); ms.WriteByte(0x08);
        ms.WriteByte(0x01); // 1 component
        ms.WriteByte(0x01); ms.WriteByte(0x00);
        ms.WriteByte(0x00); ms.WriteByte(0x3F); ms.WriteByte(0x00);

        // Scan payload bytes
        byte[] payload = new byte[] { 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE };
        ms.Write(payload, 0, payload.Length);

        // EOI
        ms.WriteByte(0xFF); ms.WriteByte(0xD9);
        return ms.ToArray();
    }

    private static void TestFujifilmRaf(string testDir)
    {
        byte[] jpeg = CreateSampleJpeg(640, 480);
        var ms = new MemoryStream();
        byte[] header = new byte[128];
        Encoding.ASCII.GetBytes("FUJIFILMCCD-RAW ").CopyTo(header, 0);
        Encoding.ASCII.GetBytes("0201").CopyTo(header, 16);
        Encoding.ASCII.GetBytes("X-T4    ").CopyTo(header, 20);

        // Preview JPEG at offset 128
        uint jpgOffset = 128;
        uint jpgLength = (uint)jpeg.Length;
        header[84] = (byte)((jpgOffset >> 24) & 0xFF);
        header[85] = (byte)((jpgOffset >> 16) & 0xFF);
        header[86] = (byte)((jpgOffset >> 8) & 0xFF);
        header[87] = (byte)(jpgOffset & 0xFF);

        header[88] = (byte)((jpgLength >> 24) & 0xFF);
        header[89] = (byte)((jpgLength >> 16) & 0xFF);
        header[90] = (byte)((jpgLength >> 8) & 0xFF);
        header[91] = (byte)(jpgLength & 0xFF);

        ms.Write(header, 0, header.Length);
        ms.Write(jpeg, 0, jpeg.Length);

        byte[] rafBytes = ms.ToArray();
        string rafPath = Path.Combine(testDir, "sample.raf");
        File.WriteAllBytes(rafPath, rafBytes);

        using (var fs = File.OpenRead(rafPath))
        {
            var meta = CameraRawRecovery.Inspect(fs);
            Check(meta != null, "Fuji RAF inspect not null");
            Check(meta.Format == "Fujifilm RAF", "Fuji RAF format detected");
            Check(meta.Make == "FUJIFILM", "Fuji make detected");
            Check(meta.Model == "X-T4", "Fuji model detected");
            Check(meta.PreviewOffset == 128, "Fuji preview offset");
            Check(meta.PreviewLength == jpeg.Length, "Fuji preview length");

            byte[] extracted = CameraRawRecovery.ExtractPreview(fs, meta);
            Check(extracted != null, "Fuji preview extracted");
            Check(extracted.Length == jpeg.Length, "Fuji preview length match");
            Check(extracted[0] == 0xFF && extracted[1] == 0xD8, "Fuji preview JPEG header");
        }
    }

    private static void TestCanonCr2(string testDir)
    {
        byte[] jpeg = CreateSampleJpeg(1024, 768);
        var ms = new MemoryStream();

        // Little-endian TIFF header + CR2 magic at offset 8
        // 0..3: II*\0
        ms.Write(new byte[] { 0x49, 0x49, 0x2A, 0x00 }, 0, 4);
        // 4..7: Offset of IFD0 = 16
        uint ifdOffset = 16;
        ms.Write(BitConverter.GetBytes(ifdOffset), 0, 4);
        // 8..11: "CR\x02\x00"
        ms.Write(new byte[] { 0x43, 0x52, 0x02, 0x00 }, 0, 4);
        // 12..15: Padding
        ms.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 0, 4);

        // IFD0 at offset 16
        // Count: 7 tags
        ushort tagCount = 7;
        ms.Write(BitConverter.GetBytes(tagCount), 0, 2);

        // Tag 1: 0x010F Make (Canon) -> string offset 120
        WriteTiffEntry(ms, 0x010F, 2, 6, 120);
        // Tag 2: 0x0110 Model (EOS R5) -> string offset 130
        WriteTiffEntry(ms, 0x0110, 2, 7, 130);
        // Tag 3: 0x0100 Width (8192)
        WriteTiffEntry(ms, 0x0100, 4, 1, 8192);
        // Tag 4: 0x0101 Height (5464)
        WriteTiffEntry(ms, 0x0101, 4, 1, 5464);
        // Tag 5: 0x8827 ISO (400)
        WriteTiffEntry(ms, 0x8827, 3, 1, 400);
        // Tag 6: 0x0201 JPEGInterchangeFormat (preview offset = 200)
        WriteTiffEntry(ms, 0x0201, 4, 1, 200);
        // Tag 7: 0x0202 JPEGInterchangeFormatLength
        WriteTiffEntry(ms, 0x0202, 4, 1, (uint)jpeg.Length);

        // Next IFD offset: 0
        ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4);

        // Pad to offset 120
        while (ms.Length < 120) ms.WriteByte(0);
        byte[] makeBytes = Encoding.ASCII.GetBytes("Canon\0");
        ms.Write(makeBytes, 0, makeBytes.Length);

        // Pad to offset 130
        while (ms.Length < 130) ms.WriteByte(0);
        byte[] modelBytes = Encoding.ASCII.GetBytes("EOS R5\0");
        ms.Write(modelBytes, 0, modelBytes.Length);

        // Pad to offset 200
        while (ms.Length < 200) ms.WriteByte(0);
        ms.Write(jpeg, 0, jpeg.Length);

        byte[] cr2Bytes = ms.ToArray();
        string cr2Path = Path.Combine(testDir, "sample.cr2");
        File.WriteAllBytes(cr2Path, cr2Bytes);

        using (var fs = File.OpenRead(cr2Path))
        {
            var meta = CameraRawRecovery.Inspect(fs);
            Check(meta != null, "CR2 inspect not null");
            Check(meta.Format == "Canon CR2", "CR2 format detected");
            Check(meta.Make == "Canon", "CR2 make detected");
            Check(meta.Model == "EOS R5", "CR2 model detected");
            Check(meta.Width == 8192, "CR2 width");
            Check(meta.Height == 5464, "CR2 height");
            Check(meta.Iso == 400, "CR2 ISO");
            Check(meta.PreviewOffset == 200, "CR2 preview offset");
            Check(meta.PreviewLength == jpeg.Length, "CR2 preview length");

            byte[] extracted = CameraRawRecovery.ExtractPreview(fs, meta);
            Check(extracted != null && extracted.Length == jpeg.Length, "CR2 preview extracted");
        }
    }

    private static void TestNikonNef(string testDir)
    {
        byte[] jpeg = CreateSampleJpeg(800, 600);
        var ms = new MemoryStream();

        ms.Write(new byte[] { 0x49, 0x49, 0x2A, 0x00 }, 0, 4);
        ms.Write(BitConverter.GetBytes((uint)8), 0, 4); // IFD0 at offset 8

        ushort tagCount = 4;
        ms.Write(BitConverter.GetBytes(tagCount), 0, 2);

        WriteTiffEntry(ms, 0x010F, 2, 6, 80); // Make: NIKON\0
        WriteTiffEntry(ms, 0x0110, 2, 9, 90); // Model: NIKON Z8\0
        WriteTiffEntry(ms, 0x0201, 4, 1, 150);
        WriteTiffEntry(ms, 0x0202, 4, 1, (uint)jpeg.Length);
        ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4); // Next IFD

        while (ms.Length < 80) ms.WriteByte(0);
        ms.Write(Encoding.ASCII.GetBytes("NIKON\0"), 0, 6);

        while (ms.Length < 90) ms.WriteByte(0);
        ms.Write(Encoding.ASCII.GetBytes("NIKON Z8\0"), 0, 9);

        while (ms.Length < 150) ms.WriteByte(0);
        ms.Write(jpeg, 0, jpeg.Length);

        string nefPath = Path.Combine(testDir, "sample.nef");
        File.WriteAllBytes(nefPath, ms.ToArray());

        using (var fs = File.OpenRead(nefPath))
        {
            var meta = CameraRawRecovery.Inspect(fs);
            Check(meta != null, "NEF inspect not null");
            Check(meta.Format == "Nikon NEF", "NEF format detected");
            Check(meta.Make == "NIKON", "NEF make detected");
            Check(meta.Model == "NIKON Z8", "NEF model detected");
            Check(meta.PreviewOffset == 150, "NEF preview offset");
        }
    }

    private static void TestSonyArw(string testDir)
    {
        byte[] jpeg = CreateSampleJpeg(640, 480);
        var ms = new MemoryStream();

        ms.Write(new byte[] { 0x49, 0x49, 0x2A, 0x00 }, 0, 4);
        ms.Write(BitConverter.GetBytes((uint)8), 0, 4);

        ushort tagCount = 4;
        ms.Write(BitConverter.GetBytes(tagCount), 0, 2);

        WriteTiffEntry(ms, 0x010F, 2, 5, 80); // SONY\0
        WriteTiffEntry(ms, 0x0110, 2, 10, 90); // ILCE-7RM5\0
        WriteTiffEntry(ms, 0x0201, 4, 1, 120);
        WriteTiffEntry(ms, 0x0202, 4, 1, (uint)jpeg.Length);
        ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4);

        while (ms.Length < 80) ms.WriteByte(0);
        ms.Write(Encoding.ASCII.GetBytes("SONY\0"), 0, 5);

        while (ms.Length < 90) ms.WriteByte(0);
        ms.Write(Encoding.ASCII.GetBytes("ILCE-7RM5\0"), 0, 10);

        while (ms.Length < 120) ms.WriteByte(0);
        ms.Write(jpeg, 0, jpeg.Length);

        string arwPath = Path.Combine(testDir, "sample.arw");
        File.WriteAllBytes(arwPath, ms.ToArray());

        using (var fs = File.OpenRead(arwPath))
        {
            var meta = CameraRawRecovery.Inspect(fs);
            Check(meta != null, "ARW inspect not null");
            Check(meta.Format == "Sony ARW", "ARW format detected");
            Check(meta.Make == "SONY", "ARW make");
            Check(meta.Model == "ILCE-7RM5", "ARW model");
        }
    }

    private static void TestAdobeDng(string testDir)
    {
        var ms = new MemoryStream();
        ms.Write(new byte[] { 0x49, 0x49, 0x2A, 0x00 }, 0, 4);
        ms.Write(BitConverter.GetBytes((uint)8), 0, 4);

        ushort tagCount = 3;
        ms.Write(BitConverter.GetBytes(tagCount), 0, 2);

        WriteTiffEntry(ms, 0x010F, 2, 6, 80); // Adobe\0
        WriteTiffEntry(ms, 0x0110, 2, 4, 90); // DNG\0
        // DNGVersion tag 0xC612 = [1, 4, 0, 0] stored inline in 4 bytes
        uint dngVer = (1 << 24) | (4 << 16) | (0 << 8) | 0;
        WriteTiffEntry(ms, 0xC612, 1, 4, dngVer);
        ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4);

        while (ms.Length < 80) ms.WriteByte(0);
        ms.Write(Encoding.ASCII.GetBytes("Adobe\0"), 0, 6);

        while (ms.Length < 90) ms.WriteByte(0);
        ms.Write(Encoding.ASCII.GetBytes("DNG\0"), 0, 4);

        string dngPath = Path.Combine(testDir, "sample.dng");
        File.WriteAllBytes(dngPath, ms.ToArray());

        using (var fs = File.OpenRead(dngPath))
        {
            var meta = CameraRawRecovery.Inspect(fs);
            Check(meta != null, "DNG inspect not null");
            Check(meta.Format == "Adobe DNG", "Adobe DNG format detected");
            Check(meta.ExtraTags.ContainsKey("DNGVersion"), "DNG version tag present");
            Check(meta.ExtraTags["DNGVersion"] == "1.4.0.0", "DNG version match");
        }
    }

    private static void TestCanonCr3(string testDir)
    {
        byte[] jpeg = CreateSampleJpeg(400, 300);
        var ms = new MemoryStream();

        // ftyp box (16 bytes)
        byte[] ftypBox = new byte[]
        {
            0x00, 0x00, 0x00, 0x18, // size 24
            0x66, 0x74, 0x79, 0x70, // "ftyp"
            0x63, 0x72, 0x78, 0x20, // "crx "
            0x00, 0x00, 0x00, 0x01, // minor version
            0x63, 0x72, 0x78, 0x20, // compatible brands
            0x69, 0x73, 0x6F, 0x6D
        };
        ms.Write(ftypBox, 0, ftypBox.Length);

        // PRVW box containing preview JPEG
        uint prvwSize = (uint)(8 + jpeg.Length);
        byte[] prvwHeader = new byte[]
        {
            (byte)((prvwSize >> 24) & 0xFF), (byte)((prvwSize >> 16) & 0xFF),
            (byte)((prvwSize >> 8) & 0xFF), (byte)(prvwSize & 0xFF),
            0x50, 0x52, 0x56, 0x57 // "PRVW"
        };
        ms.Write(prvwHeader, 0, prvwHeader.Length);
        ms.Write(jpeg, 0, jpeg.Length);

        string cr3Path = Path.Combine(testDir, "sample.cr3");
        File.WriteAllBytes(cr3Path, ms.ToArray());

        using (var fs = File.OpenRead(cr3Path))
        {
            var meta = CameraRawRecovery.Inspect(fs);
            Check(meta != null, "CR3 inspect not null");
            Check(meta.Format == "Canon CR3", "CR3 format detected");
            Check(meta.Make == "Canon", "CR3 make");
            Check(meta.PreviewOffset > 0, "CR3 preview offset found");
            Check(meta.PreviewLength == jpeg.Length, "CR3 preview length match");

            byte[] extracted = CameraRawRecovery.ExtractPreview(fs, meta);
            Check(extracted != null && extracted.Length == jpeg.Length, "CR3 preview extracted");
        }
    }

    private static void TestCarvingStream()
    {
        byte[] jpeg = CreateSampleJpeg(320, 240);
        var ms = new MemoryStream();

        // 1. Random noise padding (1024 bytes)
        byte[] noise1 = new byte[1024];
        for (int i = 0; i < noise1.Length; i++) noise1[i] = (byte)(i % 251);
        ms.Write(noise1, 0, noise1.Length);

        // 2. Fuji RAF binary
        long fujiStart = ms.Position;
        byte[] fujiHdr = new byte[128];
        Encoding.ASCII.GetBytes("FUJIFILMCCD-RAW ").CopyTo(fujiHdr, 0);
        Encoding.ASCII.GetBytes("X-T30   ").CopyTo(fujiHdr, 20);
        uint jpgOffset = 128;
        fujiHdr[84] = (byte)((jpgOffset >> 24) & 0xFF);
        fujiHdr[85] = (byte)((jpgOffset >> 16) & 0xFF);
        fujiHdr[86] = (byte)((jpgOffset >> 8) & 0xFF);
        fujiHdr[87] = (byte)(jpgOffset & 0xFF);
        fujiHdr[88] = (byte)(((uint)jpeg.Length >> 24) & 0xFF);
        fujiHdr[89] = (byte)(((uint)jpeg.Length >> 16) & 0xFF);
        fujiHdr[90] = (byte)(((uint)jpeg.Length >> 8) & 0xFF);
        fujiHdr[91] = (byte)((uint)jpeg.Length & 0xFF);
        ms.Write(fujiHdr, 0, fujiHdr.Length);
        ms.Write(jpeg, 0, jpeg.Length);

        // 3. Noise padding (2048 bytes)
        byte[] noise2 = new byte[2048];
        ms.Write(noise2, 0, noise2.Length);

        // 4. Canon CR2 binary
        long cr2Start = ms.Position;
        ms.Write(new byte[] { 0x49, 0x49, 0x2A, 0x00 }, 0, 4);
        ms.Write(BitConverter.GetBytes((uint)16), 0, 4);
        ms.Write(new byte[] { 0x43, 0x52, 0x02, 0x00 }, 0, 4);
        ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4);
        // IFD0
        ms.Write(BitConverter.GetBytes((ushort)3), 0, 2);
        WriteTiffEntry(ms, 0x010F, 2, 6, 80);
        WriteTiffEntry(ms, 0x0201, 4, 1, 100);
        WriteTiffEntry(ms, 0x0202, 4, 1, (uint)jpeg.Length);
        ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4);
        while (ms.Position < cr2Start + 80) ms.WriteByte(0);
        ms.Write(Encoding.ASCII.GetBytes("Canon\0"), 0, 6);
        while (ms.Position < cr2Start + 100) ms.WriteByte(0);
        ms.Write(jpeg, 0, jpeg.Length);

        // Reset and carve
        ms.Position = 0;
        var carved = CameraRawRecovery.Carve(ms, CancellationToken.None, null);
        Check(carved != null && carved.Count >= 2, "At least 2 RAW photos carved");

        bool foundFuji = false, foundCr2 = false;
        foreach (var c in carved)
        {
            if (c.Format == "Fujifilm RAF" && c.Offset == fujiStart)
            {
                foundFuji = true;
                Check(c.PreviewBytes != null && c.PreviewBytes.Length == jpeg.Length, "Carved Fuji preview bytes match");
            }
            if (c.Format == "Canon CR2" && c.Offset == cr2Start)
            {
                foundCr2 = true;
                Check(c.PreviewBytes != null && c.PreviewBytes.Length == jpeg.Length, "Carved CR2 preview bytes match");
            }
        }
        Check(foundFuji, "Carved Fuji RAF found at exact offset");
        Check(foundCr2, "Carved Canon CR2 found at exact offset");
    }

    private static void TestDirectorySalvage(string testDir)
    {
        string outDir = Path.Combine(testDir, "salvaged_out");
        var report = CameraRawRecovery.SalvageDirectory(testDir, outDir, true, CancellationToken.None, null);

        Check(report != null, "Salvage report generated");
        Check(report.Status == "complete", "Salvage report status complete");
        Check(report.RawFilesFound >= 4, "Found multiple RAW photos in directory");
        Check(report.PreviewsExtracted >= 3, "Extracted previews in directory salvage");
        Check(File.Exists(Path.Combine(outDir, "raw-salvage-report.json")), "Report JSON written");
    }

    private static void TestCliSalvageRaw(string testDir)
    {
        string cliOut = Path.Combine(testDir, "cli_salvaged");
        int rc = CommandLineHandler.Run(new string[] { "salvage-raw", testDir, "-o", cliOut, "--json" });
        Check(rc == 0, "CLI salvage-raw exit code 0");
        Check(File.Exists(Path.Combine(cliOut, "raw-salvage-report.json")), "CLI raw-salvage-report.json exists");
    }

    private static void WriteTiffEntry(Stream stream, ushort tag, ushort type, uint count, uint valOrOffset)
    {
        stream.Write(BitConverter.GetBytes(tag), 0, 2);
        stream.Write(BitConverter.GetBytes(type), 0, 2);
        stream.Write(BitConverter.GetBytes(count), 0, 4);
        stream.Write(BitConverter.GetBytes(valOrOffset), 0, 4);
    }
}
