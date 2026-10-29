using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class FilesystemRecoveryTests
{
    static string fixtureRoot;
    static int assertions;
    static void Assert(bool condition, string message) { assertions++; if (!condition) throw new Exception(message); }
    static void W16(byte[] b, int p, int v) { b[p] = (byte)v; b[p + 1] = (byte)(v >> 8); }
    static void W32(byte[] b, int p, uint v) { for (int i = 0; i < 4; i++) b[p + i] = (byte)(v >> (8 * i)); }
    static void W64(byte[] b, int p, ulong v) { for (int i = 0; i < 8; i++) b[p + i] = (byte)(v >> (8 * i)); }
    static void Text(byte[] b, int p, string text) { Encoding.ASCII.GetBytes(text).CopyTo(b, p); }
    static byte[] Pattern(int size, int seed) { var b = new byte[size]; new Random(seed).NextBytes(b); return b; }
    static string Hash(byte[] data) { using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(data)).Replace("-", ""); }
    static string HashFile(string path) { using (var h = SHA256.Create()) using (var f = File.OpenRead(path)) return BitConverter.ToString(h.ComputeHash(f)).Replace("-", ""); }
    static uint Crc(byte[] data) { uint result = 0xFFFFFFFF; foreach (byte b in data) { result ^= b; for (int i = 0; i < 8; i++) result = (result & 1) == 0 ? result >> 1 : (result >> 1) ^ 0xEDB88320; } return ~result; }
    static byte[] Jpeg()
    {
        using (var bitmap = new Bitmap(96, 80))
        using (var memory = new MemoryStream())
        {
            var random = new Random(991);
            for (int y = 0; y < bitmap.Height; y++) for (int x = 0; x < bitmap.Width; x++)
                bitmap.SetPixel(x, y, Color.FromArgb(random.Next(256), random.Next(256), random.Next(256)));
            bitmap.Save(memory, ImageFormat.Jpeg); return memory.ToArray();
        }
    }
    public sealed class FatFixture
    {
        public byte[] Bytes;
        public int Bits, FatStart, RootStart, DataStart, FatSectors, Clusters;
        public FatFixture(int bits)
        {
            Bits = bits; Clusters = bits == 12 ? 2000 : bits == 16 ? 5000 : 70000;
            FatSectors = ((Clusters + 2) * (bits == 12 ? 3 : bits / 4) / 2 + 511) / 512;
            if (bits != 12) FatSectors = ((Clusters + 2) * (bits / 8) + 511) / 512;
            int reserved = bits == 32 ? 32 : 1, rootSectors = bits == 32 ? 0 : 4;
            FatStart = reserved * 512; RootStart = (reserved + FatSectors) * 512; DataStart = RootStart + rootSectors * 512;
            Bytes = new byte[DataStart + Clusters * 512];
            Text(Bytes, 3, "MSDOS5.0"); Bytes[0] = 0xEB; Bytes[1] = 0x3C; Bytes[2] = 0x90;
            W16(Bytes, 11, 512); Bytes[13] = 1; W16(Bytes, 14, reserved); Bytes[16] = 1; W16(Bytes, 17, bits == 32 ? 0 : 64);
            uint sectors = (uint)(Bytes.Length / 512);
            if (sectors <= 65535) W16(Bytes, 19, (int)sectors); else W32(Bytes, 32, sectors);
            Bytes[21] = 0xF8; Bytes[510] = 0x55; Bytes[511] = 0xAA;
            if (bits == 32) { W32(Bytes, 36, (uint)FatSectors); W32(Bytes, 44, 2); RootStart = Cluster(2); SetFat(2, End); }
            else W16(Bytes, 22, FatSectors);
            SetFat(0, End); SetFat(1, End);
        }
        public uint End { get { return Bits == 12 ? 0xFFFU : Bits == 16 ? 0xFFFFU : 0x0FFFFFFFU; } }
        public int Cluster(uint cluster) { return DataStart + ((int)cluster - 2) * 512; }
        public void SetFat(uint cluster, uint value)
        {
            if (Bits == 12)
            {
                int p = FatStart + (int)(cluster + cluster / 2);
                int old = Bytes[p] | Bytes[p + 1] << 8;
                old = (cluster & 1) == 0 ? (old & 0xF000) | (int)value : (old & 0xF) | ((int)value << 4);
                W16(Bytes, p, old);
            }
            else if (Bits == 16) W16(Bytes, FatStart + (int)cluster * 2, (int)value);
            else W32(Bytes, FatStart + (int)cluster * 4, value);
        }
        public int Entry(int slot, string sfn, uint cluster, int length, bool deleted, bool directory)
        {
            int p = RootStart + slot * 32; Text(Bytes, p, sfn); if (deleted) Bytes[p] = 0xE5;
            Bytes[p + 11] = (byte)(directory ? 0x10 : 0x20); W16(Bytes, p + 26, (int)cluster); if (Bits == 32) W16(Bytes, p + 20, (int)(cluster >> 16));
            W32(Bytes, p + 28, (uint)length); return p;
        }
        public void Put(byte[] payload, uint first, bool fragmented)
        {
            int parts = (payload.Length + 511) / 512;
            for (int i = 0; i < parts; i++)
            {
                uint cluster = first + (uint)(i * (fragmented ? 4 : 1));
                Buffer.BlockCopy(payload, i * 512, Bytes, Cluster(cluster), Math.Min(512, payload.Length - i * 512));
                if (fragmented) SetFat(cluster, i + 1 == parts ? End : cluster + 4);
            }
        }
    }
    static byte SfnChecksum(string shortName)
    {
        int sum = 0; foreach (byte c in Encoding.ASCII.GetBytes(shortName)) sum = (((sum & 1) != 0 ? 128 : 0) + (sum >> 1) + c) & 255;
        return (byte)sum;
    }
    static int AddLfn(FatFixture fat, int firstSlot, string longName, string sfn)
    {
        int chunks = (longName.Length + 12) / 13; int[] positions = new int[] { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
        for (int part = 0; part < chunks; part++)
        {
            int index = chunks - part - 1, at = fat.RootStart + (firstSlot + part) * 32;
            fat.Bytes[at] = 0xE5; fat.Bytes[at + 11] = 15; fat.Bytes[at + 13] = SfnChecksum(sfn);
            for (int n = 0; n < 13; n++) { int c = index * 13 + n; W16(fat.Bytes, at + positions[n], c < longName.Length ? longName[c] : c == longName.Length ? 0 : 65535); }
        }
        return firstSlot + chunks;
    }
    static string Save(string name, byte[] bytes) { string path = Path.Combine(fixtureRoot, name); File.WriteAllBytes(path, bytes); return path; }
    static string Run(string image, string label, int expectedCount, bool expectedLimited = false)
    {
        string before = HashFile(image), run = Path.Combine(fixtureRoot, "results-" + label);
        int count = 0; bool limited = false;
        try { count = FilesystemRecovery.Recover(image, run, CancellationToken.None, null); }
        catch (IOException) { limited = true; count = Outputs(run).Length; }
        Assert(limited == expectedLimited, label + " incomplete-stage state unexpected");
        Assert(count == expectedCount, label + " count expected " + expectedCount + ", got " + count);
        Assert(HashFile(image) == before, label + " changed image");
        Assert(File.Exists(Path.Combine(run, "filesystem", "metadata.csv")), label + " metadata report missing");
        string report = File.ReadAllText(Path.Combine(run, "filesystem", "report.json"));
        Assert(report.Contains("\"limited\":" + (expectedLimited ? "true" : "false")), label + " report limit state wrong");
        return run;
    }
    static string[] Outputs(string run) { string root = Path.Combine(run, "filesystem", "files"); return Directory.Exists(root) ? Directory.GetFiles(root, "*", SearchOption.AllDirectories) : new string[0]; }
    static string Csv(string run) { return File.ReadAllText(Path.Combine(run, "filesystem", "metadata.csv"), Encoding.UTF8); }
    static void TestFat(int bits)
    {
        var fat = new FatFixture(bits);
        byte[] jpeg = bits == 12 ? Jpeg() : Pattern(1100, bits), contiguous = Pattern(700, 20), partial = Pattern(900, 31);
        fat.Put(jpeg, 3, true);
        fat.Entry(0, "PHOTO   JPG", 3, jpeg.Length, true, false);
        fat.Put(contiguous, 200, false); int sfn = AddLfn(fat, 1, "Фото прабабушки.jpg", "BABUSH~1JPG"); fat.Entry(sfn, "BABUSH~1JPG", 200, contiguous.Length, true, false);
        fat.Put(partial, 600, false); fat.Entry(sfn + 1, "PARTIAL BIN", 600, partial.Length, true, false);
        fat.SetFat(601, fat.End); fat.Entry(sfn + 2, "LIVE    BIN", 601, 20, false, false);
        fat.Entry(sfn + 3, "REUSED  BIN", 601, 20, true, false);
        // A live directory contains one genuinely deleted child and an intact current file.
        fat.Entry(sfn + 4, "SUBDIR     ", 700, 0, false, true); fat.SetFat(700, fat.End);
        int child = fat.Cluster(700); Text(fat.Bytes, child, "CHILD   TXT"); fat.Bytes[child] = 0xE5; fat.Bytes[child + 11] = 0x20; W16(fat.Bytes, child + 26, 750); W32(fat.Bytes, child + 28, 80);
        byte[] childContent = Pattern(80, 80); fat.Put(childContent, 750, false);
        string image = Save("fat" + bits + "-fragmented.dd", fat.Bytes);
        string run = Run(image, "fat" + bits, 4);
        string[] files = Outputs(run);
        Assert(files.Any(p => HashFile(p) == Hash(jpeg)), "FAT" + bits + " fragmented file digest mismatch");
        Assert(files.Any(p => Path.GetFileName(p).Contains("Фото прабабушки.jpg") && HashFile(p) == Hash(contiguous)), "FAT" + bits + " deleted long name/contiguous content missing");
        Assert(files.Any(p => Path.GetFileName(p).Contains("PARTIAL") && new FileInfo(p).Length == 512 && HashFile(p) == Hash(partial.Take(512).ToArray())), "FAT" + bits + " reallocation partial stop failed");
        Assert(files.Any(p => HashFile(p) == Hash(childContent)), "FAT" + bits + " child directory recovery missing");
        Assert(!files.Any(p => Path.GetFileName(p).Contains("REUSED") || Path.GetFileName(p).Contains("LIVE")), "Live/reallocated file exported as deleted");
        Assert(Csv(run).Contains("retained-fat-uncertain") && Csv(run).Contains("contiguous-guess") && Csv(run).Contains("cluster currently owned"), "FAT" + bits + " uncertainty report missing");
        if (bits == 12)
        {
            string expected = Save("fragmented-expected.jpg", jpeg);
            File.WriteAllText(Path.Combine(fixtureRoot, "Filesystem-fragmented-fixture.txt"), "image=" + image + "\r\nexpected=" + expected + "\r\nsha256=" + Hash(jpeg) + "\r\nrecovered=" + files.First(p => HashFile(p) == Hash(jpeg)), Encoding.UTF8);
            Console.WriteLine("FRAGMENTED_JPEG image=" + image + "; expected=" + expected + "; SHA256=" + Hash(jpeg));
            TestPartitions(fat.Bytes);
        }
    }
    static void TestPartitions(byte[] volume)
    {
        byte[] mbr = new byte[volume.Length + 1024 * 1024]; mbr[510] = 0x55; mbr[511] = 0xAA; mbr[450] = 1; W32(mbr, 454, 2048); W32(mbr, 458, (uint)(volume.Length / 512)); Buffer.BlockCopy(volume, 0, mbr, 1024 * 1024, volume.Length);
        Run(Save("fat12-mbr.dd", mbr), "mbr", 4);
        byte[] gpt = new byte[mbr.Length]; Buffer.BlockCopy(volume, 0, gpt, 1024 * 1024, volume.Length);
        Text(gpt, 512, "EFI PART"); W32(gpt, 520, 0x10000); W32(gpt, 524, 92); W64(gpt, 536, 1); W64(gpt, 584, 2); W32(gpt, 592, 1); W32(gpt, 596, 128);
        gpt[1024] = 1; W64(gpt, 1056, 2048); W64(gpt, 1064, (ulong)(2048 + volume.Length / 512 - 1));
        W32(gpt, 600, Crc(gpt.Skip(1024).Take(128).ToArray())); W32(gpt, 528, Crc(gpt.Skip(512).Take(92).ToArray()));
        Run(Save("fat12-gpt.dd", gpt), "gpt", 4);
        byte[] lost = new byte[volume.Length + 4096]; Buffer.BlockCopy(volume, 0, lost, 4096, volume.Length);
        Run(Save("fat12-missing-table.dd", lost), "scan-boot", 4);
    }
    public sealed class ExFixture
    {
        public byte[] Bytes = new byte[1024 * 512];
        public int Cluster(uint c) { return (32 + (int)c - 2) * 512; }
        public ExFixture()
        {
            Text(Bytes, 3, "EXFAT   "); Bytes[0] = 0xEB; Bytes[1] = 0x76; Bytes[2] = 0x90;
            W64(Bytes, 72, 1024); W32(Bytes, 80, 24); W32(Bytes, 84, 8); W32(Bytes, 88, 32); W32(Bytes, 92, 992); W32(Bytes, 96, 2);
            W16(Bytes, 104, 0x100); Bytes[108] = 9; Bytes[110] = 1; Bytes[510] = 0x55; Bytes[511] = 0xAA;
            Fat(2, 3); Fat(3, 0xFFFFFFFF); Fat(4, 0xFFFFFFFF);
            int root = Cluster(2); Bytes[root] = 0x81; W32(Bytes, root + 20, 4); W64(Bytes, root + 24, 124);
            Allocated(2, true); Allocated(3, true); Allocated(4, true);
            UpdateBootChecksum();
        }
        public void UpdateBootChecksum()
        {
            uint checksum = 0;
            for (int i = 0; i < 11 * 512; i++) if (i != 106 && i != 107 && i != 112)
                checksum = unchecked(((checksum & 1) == 0 ? 0 : 0x80000000U) + (checksum >> 1) + Bytes[i]);
            for (int i = 11 * 512; i < 12 * 512; i += 4) W32(Bytes, i, checksum);
        }
        public void Fat(uint c, uint v) { W32(Bytes, 24 * 512 + (int)c * 4, v); }
        public void Allocated(uint c, bool yes) { int p = Cluster(4) + ((int)c - 2) / 8; byte mask = (byte)(1 << (((int)c - 2) % 8)); if (yes) Bytes[p] |= mask; else Bytes[p] &= (byte)~mask; }
        public int Entry(int slot, string name, uint first, byte[] content, bool deleted, bool contiguous, long validLength)
        {
            int at = Cluster(2) + slot * 32, names = (name.Length + 14) / 15, secondary = names + 1;
            Bytes[at] = 0x85; Bytes[at + 1] = (byte)secondary; W16(Bytes, at + 4, 0x20);
            Bytes[at + 32] = 0xC0; Bytes[at + 33] = (byte)(contiguous ? 3 : 1); Bytes[at + 35] = (byte)name.Length;
            W64(Bytes, at + 40, (ulong)validLength); W32(Bytes, at + 52, first); W64(Bytes, at + 56, (ulong)content.Length);
            for (int n = 0; n < names; n++)
            {
                int p = at + (n + 2) * 32; Bytes[p] = 0xC1;
                for (int c = 0; c < 15 && n * 15 + c < name.Length; c++) W16(Bytes, p + 2 + c * 2, name[n * 15 + c]);
            }
            int checksum = 0;
            for (int i = 0; i < (secondary + 1) * 32; i++) if (i != 2 && i != 3) checksum = (((checksum & 1) != 0 ? 0x8000 : 0) + (checksum >> 1) + Bytes[at + i]) & 65535;
            W16(Bytes, at + 2, checksum);
            if (deleted) for (int n = 0; n <= secondary; n++) Bytes[at + n * 32] &= 0x7F;
            int parts = (content.Length + 511) / 512;
            for (int p = 0; p < parts; p++)
            {
                uint c = first + (uint)(p * (contiguous ? 1 : 3)); Buffer.BlockCopy(content, p * 512, Bytes, Cluster(c), Math.Min(512, content.Length - p * 512));
                if (!contiguous) Fat(c, p + 1 == parts ? 0xFFFFFFFFU : c + 3);
                if (!deleted) Allocated(c, true);
            }
            return slot + secondary + 1;
        }
    }
    static void TestExfat()
    {
        var ex = new ExFixture(); byte[] content = Pattern(900, 333), fragments = Pattern(1100, 444), partial = Pattern(900, 555);
        int slot = ex.Entry(1, "Прабабушка 🥧.jpg", 10, content, true, true, content.Length);
        slot = ex.Entry(slot, "fragmented.png", 30, fragments, true, false, fragments.Length);
        slot = ex.Entry(slot, "reallocated.bin", 50, partial, true, true, partial.Length); ex.Allocated(51, true);
        slot = ex.Entry(slot, "live.bin", 70, Pattern(20, 777), false, true, 20);
        slot = ex.Entry(slot, "zero-tail.bin", 80, Pattern(700, 888), true, true, 100);
        int corruptAt = ex.Cluster(2) + slot * 32;
        slot = ex.Entry(slot, "corrupt.bin", 90, Pattern(20, 888), true, true, 20); ex.Bytes[corruptAt + 4] ^= 1;
        string run = Run(Save("exfat-unicode.dd", ex.Bytes), "exfat", 4);
        string[] files = Outputs(run);
        Assert(files.Any(p => Path.GetFileName(p).Contains("Прабабушка 🥧.jpg") && HashFile(p) == Hash(content)), "exFAT Unicode/contiguous file missing");
        Assert(files.Any(p => Path.GetFileName(p).Contains("fragmented.png") && HashFile(p) == Hash(fragments)), "exFAT fragmented chain missing");
        Assert(files.Any(p => Path.GetFileName(p).Contains("PARTIAL") && new FileInfo(p).Length == 512), "exFAT bitmap reallocation stop missing");
        Assert(!files.Any(p => Path.GetFileName(p).Contains("live.bin") || Path.GetFileName(p).Contains("corrupt.bin")), "exFAT current/corrupt records exported");
        string zero = files.First(p => p.EndsWith("zero-tail.bin")); byte[] zeros = File.ReadAllBytes(zero);
        Assert(zeros.Skip(100).All(b => b == 0), "exFAT uninitialized tail not zeroed");
        Assert(Csv(run).Contains("active exFAT bitmap"), "exFAT bitmap evidence missing");
        var absent = new ExFixture(); int root = absent.Cluster(2); absent.Bytes[root] = 0x82; absent.Entry(1, "no-bitmap.bin", 10, Pattern(200, 10), true, true, 200);
        Run(Save("exfat-missing-bitmap.dd", absent.Bytes), "exfat-no-bitmap", 0, true);
        var bootCorrupt = new ExFixture(); bootCorrupt.Bytes[100] ^= 1;
        Run(Save("exfat-boot-checksum-corrupt.dd", bootCorrupt.Bytes), "exfat-boot-checksum", 0);
    }
    static void TestMalformedAndCancellation()
    {
        var malformed = new FatFixture(12); W32(malformed.Bytes, 32, UInt32.MaxValue); W16(malformed.Bytes, 19, 0);
        Run(Save("malformed-length.dd", malformed.Bytes), "badlength", 0);
        var cycle = new FatFixture(12); cycle.Entry(0, "CYCLE   BIN", 4, 2000, true, false); cycle.SetFat(4, 6); cycle.SetFat(6, 4); cycle.Put(Pattern(512, 22), 4, false); cycle.Put(Pattern(512, 33), 6, false);
        string cycleRun = Run(Save("fat12-cyclic.dd", cycle.Bytes), "cyclic", 1);
        Assert(Outputs(cycleRun).All(p => new FileInfo(p).Length == 1024 && p.Contains("PARTIAL")), "Cycle was not bounded and partial");
        string image = Save("cancel.dd", new FatFixture(12).Bytes), before = HashFile(image); bool cancelled = false;
        using (var source = new CancellationTokenSource())
        {
            source.Cancel(); try { FilesystemRecovery.Recover(image, Path.Combine(fixtureRoot, "cancel-results"), source.Token, null); } catch (OperationCanceledException) { cancelled = true; }
        }
        Assert(cancelled, "Pre-cancel not respected"); Assert(before == HashFile(image), "Cancelled scan changed image");
        bool repeated = false; string existing = Path.Combine(fixtureRoot, "existing-run"); Directory.CreateDirectory(Path.Combine(existing, "filesystem"));
        try { FilesystemRecovery.Recover(image, existing, CancellationToken.None, null); } catch (IOException) { repeated = true; }
        Assert(repeated, "Existing recovery output accepted");
        bool sourceCollision = false; string inside = Path.Combine(existing, "filesystem", "image.dd"); File.Copy(image, inside);
        try { FilesystemRecovery.Recover(inside, existing, CancellationToken.None, null); } catch (IOException) { sourceCollision = true; }
        Assert(sourceCollision, "Image/output collision accepted");
        var unsafeName = new ExFixture(); unsafeName.Entry(1, "..\\escape.jpg", 10, Pattern(100, 1), true, true, 100);
        string safeRun = Run(Save("unsafe-name.dd", unsafeName.Bytes), "safe-name", 1);
        Assert(Outputs(safeRun).All(p => p.StartsWith(Path.Combine(safeRun, "filesystem", "files"), StringComparison.OrdinalIgnoreCase)), "Metadata filename escaped output");
        using (var source = new CancellationTokenSource())
        {
            cancelled = false;
            try { FilesystemRecovery.Recover(image, Path.Combine(fixtureRoot, "cancel-during"), source.Token, delegate(string p) { source.Cancel(); }); } catch (OperationCanceledException) { cancelled = true; }
            Assert(cancelled, "Cancellation during traversal not respected");
        }
    }
    public static int Main()
    {
        fixtureRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Filesystem-fixtures-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(fixtureRoot);
        try
        {
            TestFat(12); TestFat(16); TestFat(32); TestExfat(); TestMalformedAndCancellation();
            string summary = "PASS FilesystemRecovery: " + assertions + " assertions; FAT12/FAT16/FAT32 fragmented+contiguous, surviving LFN, current ownership/partial stops, exFAT Unicode+bitmap+fragmentation+checksum+ValidDataLength, MBR/GPT/bounded boot search, corruption/cycles/cancellation/path isolation; images SHA256 unchanged. Fixtures: " + fixtureRoot;
            Console.WriteLine(summary); File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FilesystemRecoveryTests.result.txt"), summary, Encoding.UTF8); return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
