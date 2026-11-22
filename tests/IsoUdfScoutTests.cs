using System;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class IsoUdfScoutTests
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
            TestSyntheticStandardIso9660();
            TestSyntheticJolietUnicode();
            TestSyntheticUdfVrsSequence();
            TestCarvedIsoFromUnallocatedSectors();
            TestFileExtraction();
            TestCorruptAndTruncatedBuffers();
            TestJsonSerialization();
            TestCancellationToken();

            Console.WriteLine("PASS IsoUdfScoutTests: {0} checks passed; ISO 9660, Joliet Unicode, UDF recognition, directory traversal, and file carving verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL IsoUdfScoutTests: {0}", ex.Message);
            return 1;
        }
    }

    private static void TestSyntheticStandardIso9660()
    {
        int sectorSize = 2048;
        // Total 20 sectors: 16 system area, 1 PVD (sector 16), 1 root dir (sector 17), 1 payload (sector 18), 1 terminator (sector 19)
        byte[] image = new byte[20 * sectorSize];

        // 1. Sector 16: PVD
        int pvdOffset = 16 * sectorSize;
        image[pvdOffset] = 0x01; // Primary Volume Descriptor
        Buffer.BlockCopy(IsoUdfScout.IsoMagic, 0, image, pvdOffset + 1, 5); // "CD001"
        image[pvdOffset + 6] = 0x01; // Version

        // System Identifier at 8 (32 bytes)
        byte[] sysId = Encoding.ASCII.GetBytes("LINUX_OR_WIN32");
        Buffer.BlockCopy(sysId, 0, image, pvdOffset + 8, sysId.Length);

        // Volume Identifier at 40 (32 bytes)
        byte[] volId = Encoding.ASCII.GetBytes("FORENSIC_EVIDENCE_CD");
        Buffer.BlockCopy(volId, 0, image, pvdOffset + 40, volId.Length);

        // Volume Space Size at 80 (both-endian uint32)
        WriteBothEndianUInt32(image, pvdOffset + 80, 20);

        // Logical Block Size at 128 (both-endian uint16)
        WriteBothEndianUInt16(image, pvdOffset + 128, (ushort)sectorSize);

        // Root Directory Record at offset 156 (34 bytes):
        int rootRecOff = pvdOffset + 156;
        image[rootRecOff] = 34; // Record Length
        WriteBothEndianUInt32(image, rootRecOff + 2, 17); // Extent LBA = Sector 17
        WriteBothEndianUInt32(image, rootRecOff + 10, (uint)sectorSize); // Data Length = 2048
        WriteIsoDateTime(image, rootRecOff + 18, new DateTime(2026, 11, 20, 10, 0, 0, DateTimeKind.Utc));
        image[rootRecOff + 25] = 0x02; // Directory flag
        image[rootRecOff + 32] = 1; // Name Length
        image[rootRecOff + 33] = 0x00; // Root name

        // 2. Sector 17: Root Directory contents
        int dirOffset = 17 * sectorSize;
        int cur = dirOffset;

        // Entry 1: Current dir "."
        image[cur] = 34;
        WriteBothEndianUInt32(image, cur + 2, 17);
        WriteBothEndianUInt32(image, cur + 10, (uint)sectorSize);
        image[cur + 25] = 0x02;
        image[cur + 32] = 1;
        image[cur + 33] = 0x00;
        cur += 34;

        // Entry 2: Parent dir ".."
        image[cur] = 34;
        WriteBothEndianUInt32(image, cur + 2, 17);
        WriteBothEndianUInt32(image, cur + 10, (uint)sectorSize);
        image[cur + 25] = 0x02;
        image[cur + 32] = 1;
        image[cur + 33] = 0x01;
        cur += 34;

        // Entry 3: File "EVIDENCE.TXT;1"
        byte[] fileName = Encoding.ASCII.GetBytes("EVIDENCE.TXT;1");
        int fileRecLen = 33 + fileName.Length;
        if (fileRecLen % 2 != 0) fileRecLen++; // padding
        image[cur] = (byte)fileRecLen;
        WriteBothEndianUInt32(image, cur + 2, 18); // Extent LBA = Sector 18
        WriteBothEndianUInt32(image, cur + 10, 17); // Length = 17 bytes
        WriteIsoDateTime(image, cur + 18, new DateTime(2026, 11, 20, 11, 30, 0, DateTimeKind.Utc));
        image[cur + 25] = 0x00; // Regular file
        image[cur + 32] = (byte)fileName.Length;
        Buffer.BlockCopy(fileName, 0, image, cur + 33, fileName.Length);

        // 3. Sector 18: File Payload
        int payloadOffset = 18 * sectorSize;
        byte[] payload = Encoding.UTF8.GetBytes("TOP_SECRET_EXFIL");
        Buffer.BlockCopy(payload, 0, image, payloadOffset, payload.Length);

        // 4. Sector 19: Terminator
        int termOffset = 19 * sectorSize;
        image[termOffset] = 0xFF; // Terminator
        Buffer.BlockCopy(IsoUdfScout.IsoMagic, 0, image, termOffset + 1, 5);

        var report = IsoUdfScout.ParseBuffer(image, "test_iso9660.iso");

        Check(report != null, "Report is not null");
        Check(report.FilesystemType == "ISO 9660", "FilesystemType is ISO 9660");
        Check(report.VolumeIdentifier == "FORENSIC_EVIDENCE_CD", "VolumeIdentifier matches FORENSIC_EVIDENCE_CD");
        Check(report.SystemIdentifier == "LINUX_OR_WIN32", "SystemIdentifier matches");
        Check(report.VolumeSpaceSize == 20 * 2048, "VolumeSpaceSize matches 20 sectors");
        Check(report.LogicalBlockSize == 2048, "LogicalBlockSize matches 2048");
        Check(report.TotalFiles == 1, "TotalFiles count is 1");
        Check(report.Files.Count == 1, "Files list count is 1");

        var file = report.Files[0];
        Check(file.Name == "EVIDENCE.TXT", "File name version suffix stripped: " + file.Name);
        Check(file.Size == 17, "File size matches 17 bytes");
        Check(file.ExtentOffset == 18 * 2048, "File extent offset matches sector 18");
        Check(file.RecordingTimeUtc.Year == 2026, "RecordingTimeUtc year is 2026");
        Check(!file.IsDirectory, "IsDirectory is false");
        Check(!file.IsJoliet, "IsJoliet is false");
    }

    private static void TestSyntheticJolietUnicode()
    {
        int sectorSize = 2048;
        byte[] image = new byte[20 * sectorSize];

        // Sector 16: PVD
        int pvdOffset = 16 * sectorSize;
        image[pvdOffset] = 0x01;
        Buffer.BlockCopy(IsoUdfScout.IsoMagic, 0, image, pvdOffset + 1, 5);
        byte[] asciiVol = Encoding.ASCII.GetBytes("ASCII_NAME");
        Buffer.BlockCopy(asciiVol, 0, image, pvdOffset + 40, asciiVol.Length);
        WriteBothEndianUInt32(image, pvdOffset + 80, 20);
        WriteBothEndianUInt16(image, pvdOffset + 128, (ushort)sectorSize);

        // Sector 17: Joliet SVD (Type 0x02)
        int svdOffset = 17 * sectorSize;
        image[svdOffset] = 0x02; // SVD
        Buffer.BlockCopy(IsoUdfScout.IsoMagic, 0, image, svdOffset + 1, 5);
        byte[] ucs2Vol = Encoding.BigEndianUnicode.GetBytes("JOLIET_UNICODE");
        Buffer.BlockCopy(ucs2Vol, 0, image, svdOffset + 40, ucs2Vol.Length);
        WriteBothEndianUInt32(image, svdOffset + 80, 20);
        WriteBothEndianUInt16(image, svdOffset + 128, (ushort)sectorSize);

        // Root directory record in SVD at offset 156:
        int rootRecOff = svdOffset + 156;
        image[rootRecOff] = 34;
        WriteBothEndianUInt32(image, rootRecOff + 2, 18); // Extent at sector 18
        WriteBothEndianUInt32(image, rootRecOff + 10, (uint)sectorSize);
        image[rootRecOff + 25] = 0x02; // Directory
        image[rootRecOff + 32] = 1;

        // Sector 18: Joliet Directory entries
        int dirOffset = 18 * sectorSize;
        int cur = dirOffset;

        // Entry 1: "."
        image[cur] = 34;
        WriteBothEndianUInt32(image, cur + 2, 18);
        WriteBothEndianUInt32(image, cur + 10, (uint)sectorSize);
        image[cur + 25] = 0x02;
        image[cur + 32] = 1;
        image[cur + 33] = 0x00;
        cur += 34;

        // Entry 2: Unicode filename "Document_2026.docx"
        byte[] uniName = Encoding.BigEndianUnicode.GetBytes("Document_2026.docx");
        int recLen = 33 + uniName.Length;
        if (recLen % 2 != 0) recLen++;
        image[cur] = (byte)recLen;
        WriteBothEndianUInt32(image, cur + 2, 19); // Extent at sector 19
        WriteBothEndianUInt32(image, cur + 10, 5000);
        WriteIsoDateTime(image, cur + 18, new DateTime(2026, 11, 21, 14, 0, 0, DateTimeKind.Utc));
        image[cur + 25] = 0x00;
        image[cur + 32] = (byte)uniName.Length;
        Buffer.BlockCopy(uniName, 0, image, cur + 33, uniName.Length);

        var report = IsoUdfScout.ParseBuffer(image, "test_joliet.iso");

        Check(report != null, "Report is not null");
        Check(report.FilesystemType.Contains("Joliet"), "FilesystemType contains Joliet: " + report.FilesystemType);
        Check(report.VolumeIdentifier == "JOLIET_UNICODE", "VolumeIdentifier matches Joliet Unicode: " + report.VolumeIdentifier);
        Check(report.TotalFiles == 1, "TotalFiles count is 1");

        var file = report.Files[0];
        Check(file.Name == "Document_2026.docx", "Unicode file name matches: " + file.Name);
        Check(file.Size == 5000, "File size matches 5000");
        Check(file.IsJoliet, "IsJoliet is true");
    }

    private static void TestSyntheticUdfVrsSequence()
    {
        int sectorSize = 2048;
        byte[] image = new byte[25 * sectorSize];

        // Sector 16: BEA01 (Beginning Extended Area)
        Buffer.BlockCopy(IsoUdfScout.UdfBeaMagic, 0, image, 16 * sectorSize + 1, 5);

        // Sector 17: NSR02 (Non-Sequential Recording)
        Buffer.BlockCopy(IsoUdfScout.UdfNsr02Magic, 0, image, 17 * sectorSize + 1, 5);

        // Sector 18: TEA01 (Terminating Extended Area)
        Buffer.BlockCopy(IsoUdfScout.UdfTeaMagic, 0, image, 18 * sectorSize + 1, 5);

        var report = IsoUdfScout.ParseBuffer(image, "test_udf.iso");

        Check(report != null, "Report is not null");
        Check(report.FilesystemType.Contains("UDF"), "FilesystemType contains UDF: " + report.FilesystemType);
    }

    private static void TestCarvedIsoFromUnallocatedSectors()
    {
        // Place PVD at sector 100 instead of standard sector 16 (simulating orphaned unallocated partition)
        int sectorSize = 2048;
        byte[] image = new byte[110 * sectorSize];

        int carvePvdOffset = 100 * sectorSize;
        image[carvePvdOffset] = 0x01; // PVD
        Buffer.BlockCopy(IsoUdfScout.IsoMagic, 0, image, carvePvdOffset + 1, 5);
        byte[] volId = Encoding.ASCII.GetBytes("CARVED_USB_BACKUP");
        Buffer.BlockCopy(volId, 0, image, carvePvdOffset + 40, volId.Length);
        WriteBothEndianUInt32(image, carvePvdOffset + 80, 110);
        WriteBothEndianUInt16(image, carvePvdOffset + 128, (ushort)sectorSize);

        // Root directory record
        int rootRecOff = carvePvdOffset + 156;
        image[rootRecOff] = 34;
        WriteBothEndianUInt32(image, rootRecOff + 2, 102); // Sector 102
        WriteBothEndianUInt32(image, rootRecOff + 10, (uint)sectorSize);
        image[rootRecOff + 25] = 0x02;

        // Sector 102: Directory entry
        int dirOff = 102 * sectorSize;
        byte[] carvedFile = Encoding.ASCII.GetBytes("SALVAGED.DAT;1");
        int recLen = 33 + carvedFile.Length;
        if (recLen % 2 != 0) recLen++;
        image[dirOff] = (byte)recLen;
        WriteBothEndianUInt32(image, dirOff + 2, 103);
        WriteBothEndianUInt32(image, dirOff + 10, 1024);
        image[dirOff + 25] = 0x00;
        image[dirOff + 32] = (byte)carvedFile.Length;
        Buffer.BlockCopy(carvedFile, 0, image, dirOff + 33, carvedFile.Length);

        var report = IsoUdfScout.ParseBuffer(image, "damaged_unallocated.raw");

        Check(report != null, "Report is not null");
        Check(report.IsCarved, "IsCarved is true");
        Check(report.VolumeIdentifier == "CARVED_USB_BACKUP", "VolumeIdentifier matches CARVED_USB_BACKUP");
        Check(report.TotalFiles >= 1, "Carved at least 1 file");
        Check(report.Files[0].Name == "SALVAGED.DAT", "Carved file name is SALVAGED.DAT: " + report.Files[0].Name);
    }

    private static void TestFileExtraction()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "iso_extract_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tempDir);
            byte[] rawImage = new byte[8192];
            byte[] secretBytes = Encoding.UTF8.GetBytes("FORENSIC_INTEGRITY_CHECK_OK");
            Buffer.BlockCopy(secretBytes, 0, rawImage, 4096, secretBytes.Length);

            var fileRec = new IsoUdfFileRecord
            {
                Name = "secret.txt",
                FullPath = "classified/secret.txt",
                Size = secretBytes.Length,
                ExtentOffset = 4096,
                IsDirectory = false
            };

            string extractedPath = Path.Combine(tempDir, "extracted_secret.txt");
            using (var ms = new MemoryStream(rawImage))
            {
                bool ok = IsoUdfScout.ExtractFile(ms, fileRec, extractedPath);
                Check(ok, "ExtractFile returned true");
            }

            Check(File.Exists(extractedPath), "Extracted file exists on disk");
            string text = File.ReadAllText(extractedPath);
            Check(text == "FORENSIC_INTEGRITY_CHECK_OK", "Extracted payload content matches");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static void TestCorruptAndTruncatedBuffers()
    {
        var emptyRep = IsoUdfScout.ParseBuffer(new byte[0]);
        Check(emptyRep.TotalFiles == 0, "Empty buffer yields 0 files");

        var smallRep = IsoUdfScout.ParseBuffer(new byte[100]);
        Check(smallRep.TotalFiles == 0, "Small buffer yields 0 files");

        byte[] noise = new byte[4096];
        new Random(42).NextBytes(noise);
        var noiseRep = IsoUdfScout.ParseBuffer(noise);
        Check(noiseRep.TotalFiles == 0, "Random noise yields 0 files");
    }

    private static void TestJsonSerialization()
    {
        var rep = new IsoUdfReport
        {
            SourcePath = "image.iso",
            VolumeIdentifier = "TEST_VOL",
            SystemIdentifier = "TEST_SYS",
            FilesystemType = "ISO 9660",
            VolumeSpaceSize = 1000000,
            LogicalBlockSize = 2048,
            TotalFiles = 1,
            TotalDirectories = 0,
            TotalFileBytes = 500,
            IsCarved = false
        };
        rep.Files.Add(new IsoUdfFileRecord
        {
            Name = "TEST.BIN",
            FullPath = "TEST.BIN",
            Size = 500,
            ExtentOffset = 20480,
            RecordingTimeUtc = new DateTime(2026, 11, 20, 10, 0, 0, DateTimeKind.Utc),
            IsDirectory = false
        });

        string json = rep.ToJson();
        Check(!string.IsNullOrEmpty(json), "JSON is not empty");
        Check(json.Contains("\"VolumeIdentifier\":\"TEST_VOL\""), "JSON contains VolumeIdentifier");
        Check(json.Contains("\"FilesystemType\":\"ISO 9660\""), "JSON contains FilesystemType");
        Check(json.Contains("\"Name\":\"TEST.BIN\""), "JSON contains file Name");
    }

    private static void TestCancellationToken()
    {
        using (var cts = new CancellationTokenSource())
        {
            cts.Cancel();
            byte[] buf = new byte[65536];
            using (var ms = new MemoryStream(buf))
            {
                var rep = IsoUdfScout.ScoutStream(ms, "canceled.iso", cts.Token);
                Check(rep != null, "Canceled report is not null");
                Check(rep.TotalFiles == 0, "Canceled report has 0 files");
            }
        }
    }

    private static void WriteBothEndianUInt32(byte[] buffer, int offset, uint val)
    {
        // Little Endian at offset
        BitConverter.GetBytes(val).CopyTo(buffer, offset);
        // Big Endian at offset + 4
        byte[] be = BitConverter.GetBytes(val);
        Array.Reverse(be);
        Buffer.BlockCopy(be, 0, buffer, offset + 4, 4);
    }

    private static void WriteBothEndianUInt16(byte[] buffer, int offset, ushort val)
    {
        // Little Endian at offset
        BitConverter.GetBytes(val).CopyTo(buffer, offset);
        // Big Endian at offset + 2
        byte[] be = BitConverter.GetBytes(val);
        Array.Reverse(be);
        Buffer.BlockCopy(be, 0, buffer, offset + 2, 2);
    }

    private static void WriteIsoDateTime(byte[] buffer, int offset, DateTime dt)
    {
        buffer[offset] = (byte)(dt.Year - 1900);
        buffer[offset + 1] = (byte)dt.Month;
        buffer[offset + 2] = (byte)dt.Day;
        buffer[offset + 3] = (byte)dt.Hour;
        buffer[offset + 4] = (byte)dt.Minute;
        buffer[offset + 5] = (byte)dt.Second;
        buffer[offset + 6] = 0; // GMT
    }
}
