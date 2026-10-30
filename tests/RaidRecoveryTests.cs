using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using UsbRecovery;

// Literal disk-position tables and polynomial multiplication are independent
// of the production mapper and its logarithm tables. All members are own files.
public static class RaidRecoveryTests
{
    static int checks, sequence; static string root, project;
    sealed class Fixture { public RaidConfiguration Configuration; public byte[] Payload; public List<string> Paths = new List<string>(), Hashes = new List<string>(); }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateHardLink(string newPath, string existingPath, IntPtr reserved);
    static void Check(bool condition, string description) { checks++; if (!condition) throw new Exception(description); }
    static string Digest(byte[] bytes) { using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
    static string Digest(string path) { using (var input = File.OpenRead(path)) using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant(); }
    static string NewDirectory(string label) { string path = Path.Combine(root, (++sequence).ToString("D4") + "-" + label); Directory.CreateDirectory(path); return path; }
    static string NewOutput() { return Path.Combine(root, "output-" + (++sequence).ToString("D4")); }
    static byte Product(byte x, byte y)
    {
        int result = 0, a = x, b = y;
        while (b != 0) { if ((b & 1) != 0) result ^= a; a <<= 1; if ((a & 256) != 0) a ^= 0x11D; b >>= 1; }
        return (byte)result;
    }
    static int[][] Positions(string level, string layout)
    {
        if (level == "0") return new[] { new[] { 0, 1, 2 } };
        if (level == "10") return new[] { new[] { 0, 2, 4 } };
        if (level == "5") switch (layout) {
            case "left-symmetric": return new[] { new[] { 0, 1, 2, 3 }, new[] { 3, 0, 1, 2 }, new[] { 2, 3, 0, 1 }, new[] { 1, 2, 3, 0 } };
            case "right-symmetric": return new[] { new[] { 1, 2, 3, 0 }, new[] { 2, 3, 0, 1 }, new[] { 3, 0, 1, 2 }, new[] { 0, 1, 2, 3 } };
            case "left-asymmetric": return new[] { new[] { 0, 1, 2, 3 }, new[] { 0, 1, 3, 2 }, new[] { 0, 2, 3, 1 }, new[] { 1, 2, 3, 0 } };
            case "right-asymmetric": return new[] { new[] { 1, 2, 3, 0 }, new[] { 0, 2, 3, 1 }, new[] { 0, 1, 3, 2 }, new[] { 0, 1, 2, 3 } };
            case "parity-first": return new[] { new[] { 1, 2, 3, 0 } };
            case "parity-last": return new[] { new[] { 0, 1, 2, 3 } };
        }
        if (level == "6") switch (layout) {
            case "left-symmetric": return new[] { new[] { 1, 2, 3, 4, 0 }, new[] { 0, 1, 2, 3, 4 }, new[] { 4, 0, 1, 2, 3 }, new[] { 3, 4, 0, 1, 2 }, new[] { 2, 3, 4, 0, 1 } };
            case "right-symmetric": return new[] { new[] { 2, 3, 4, 0, 1 }, new[] { 3, 4, 0, 1, 2 }, new[] { 4, 0, 1, 2, 3 }, new[] { 0, 1, 2, 3, 4 }, new[] { 1, 2, 3, 4, 0 } };
            case "parity-last": return new[] { new[] { 0, 1, 2, 3, 4 } };
        }
        throw new Exception("Unknown independent fixture layout");
    }
    static Fixture Make(string level, string layout, byte[] payload = null)
    {
        int count = level == "0" || level == "1" ? 3 : level == "5" ? 4 : level == "6" ? 5 : 6;
        int chunk = 512, dataCount = level == "1" ? 1 : level == "10" ? count / 2 : level == "5" ? count - 1 : level == "6" ? count - 2 : count;
        if (payload == null) { payload = new byte[7 * dataCount * chunk - 37]; new Random(7921 + Int32.Parse(level)).NextBytes(payload); }
        int rows = (payload.Length + dataCount * chunk - 1) / (dataCount * chunk);
        int memberLength = level == "1" ? payload.Length : rows * chunk;
        var fixture = new Fixture { Payload = payload, Configuration = new RaidConfiguration { Level = level, Layout = layout, ChunkSize = chunk, LogicalSize = payload.Length, ExpectedSha256 = Digest(payload) } };
        byte[][] disks = Enumerable.Range(0, count).Select(i => new byte[memberLength]).ToArray();
        if (level == "1") foreach (var disk in disks) Buffer.BlockCopy(payload, 0, disk, 0, payload.Length);
        else {
            var table = Positions(level, layout);
            for (int row = 0; row < rows; row++) {
                int[] mapping = table[row % table.Length];
                for (int d = 0; d < dataCount; d++) {
                    int start = (row * dataCount + d) * chunk, length = Math.Min(chunk, payload.Length - start);
                    if (length > 0) Buffer.BlockCopy(payload, start, disks[mapping[d]], row * chunk, length);
                    if (level == "10" && length > 0) Buffer.BlockCopy(payload, start, disks[mapping[d] + 1], row * chunk, length);
                }
                if (level == "5" || level == "6") for (int b = 0; b < chunk; b++) {
                    byte parity = 0, q = 0, coefficient = 1;
                    for (int d = 0; d < dataCount; d++) { byte value = disks[mapping[d]][row * chunk + b]; parity ^= value; q ^= Product(coefficient, value); coefficient = Product(coefficient, 2); }
                    disks[mapping[dataCount]][row * chunk + b] = parity;
                    if (level == "6") disks[mapping[dataCount + 1]][row * chunk + b] = q;
                }
            }
        }
        string directory = NewDirectory("members-" + level + "-" + layout);
        for (int i = 0; i < count; i++) {
            int prefix = 19 + i * 7; byte[] file = new byte[prefix + disks[i].Length]; for (int j = 0; j < prefix; j++) file[j] = (byte)(147 + j); Buffer.BlockCopy(disks[i], 0, file, prefix, disks[i].Length);
            string path = Path.Combine(directory, "участник-" + i + ".dd"); File.WriteAllBytes(path, file); fixture.Paths.Add(path); fixture.Hashes.Add(Digest(file)); fixture.Configuration.Members.Add(new RaidMember { Path = path, Offset = prefix });
        }
        return fixture;
    }
    static RaidConfiguration Copy(RaidConfiguration config)
    {
        return new RaidConfiguration { Level = config.Level, Layout = config.Layout, ChunkSize = config.ChunkSize, LogicalSize = config.LogicalSize, ExpectedSha256 = config.ExpectedSha256, Members = config.Members.Select(m => new RaidMember { Path = m.Path, Offset = m.Offset, Missing = m.Missing }).ToList() };
    }
    static RaidBuildResult Valid(Fixture fixture, params int[] missing)
    {
        var config = Copy(fixture.Configuration); foreach (int disk in missing) config.Members[disk].Missing = true;
        long observed = -1; bool validProgress = true; string output = NewOutput(); var phases = new List<string>();
        var result = RaidImageBuilder.Build(config, output, CancellationToken.None, (done, total) => { validProgress &= done >= 0 && done >= observed && done <= total && total == fixture.Payload.Length; observed = done; }, phases.Add);
        string label = config.Level + "/" + config.Layout + "/" + String.Join(",", missing);
        Check(result.Bytes == fixture.Payload.Length && result.Sha256 == Digest(fixture.Payload) && Digest(result.ImagePath) == result.Sha256, "exact output hash and length " + label);
        Check(result.Degraded == (missing.Length > 0) && File.Exists(result.ReportPath) && !File.Exists(result.ImagePath + ".partial"), "publication and degraded state " + label);
        Check(validProgress && observed == fixture.Payload.Length && phases.Count >= 4, "measured progress and phases " + label);
        Check(File.ReadAllText(result.ImagePath + ".sha256").StartsWith(result.Sha256, StringComparison.Ordinal), "checksum sidecar " + label);
        Check(fixture.Paths.Select((path, i) => Digest(path) == fixture.Hashes[i]).All(x => x), "all source files unchanged " + label);
        return result;
    }
    static string Fails(RaidConfiguration config, string code, Action<long, long> progress = null, CancellationToken token = default(CancellationToken), string output = null)
    {
        output = output ?? NewOutput(); bool rejected = false; string observed = null;string prior=File.Exists(Path.Combine(output,"raid.dd"))?Digest(Path.Combine(output,"raid.dd")):null;
        try { RaidImageBuilder.Build(config, output, token, progress); }
        catch (RaidRecoveryException error) { rejected = true; observed = error.Code; }
        catch (OperationCanceledException) { rejected = true; observed = "CANCELLED"; }
        Check(rejected && (code == null || code == observed), "controlled rejection " + code + " got " + observed);
        Check(prior==null?!File.Exists(Path.Combine(output,"raid.dd")):Digest(Path.Combine(output,"raid.dd"))==prior,"failure never publishes or changes final image "+observed);
        return output;
    }
    static void Matrices()
    {
        Valid(Make("0", "striped"));
        var mirror = Make("1", "mirror"); Valid(mirror); for (int i = 0; i < 3; i++) Valid(mirror, i); for (int i = 0; i < 3; i++) Valid(mirror, i, (i + 1) % 3);
        foreach (string layout in RaidImageBuilder.SupportedLayouts("RAID 5")) { var fixture = Make("5", layout); Valid(fixture); for (int disk = 0; disk < 4; disk++) Valid(fixture, disk); }
        foreach (string layout in RaidImageBuilder.SupportedLayouts("6")) { var fixture = Make("6", layout); Valid(fixture); for (int disk = 0; disk < 5; disk++) { Valid(fixture, disk); for (int other = disk + 1; other < 5; other++) Valid(fixture, disk, other); } }
        var raid10 = Make("10", "adjacent-pairs"); Valid(raid10); for (int disk = 0; disk < 6; disk++) Valid(raid10, disk); for (int bits = 0; bits < 8; bits++) Valid(raid10, (bits & 1), 2 + ((bits >> 1) & 1), 4 + ((bits >> 2) & 1));
        for(int firstPair=0;firstPair<3;firstPair++)for(int secondPair=firstPair+1;secondPair<3;secondPair++)for(int first=0;first<2;first++)for(int second=0;second<2;second++)Valid(raid10,firstPair*2+first,secondPair*2+second);
        Check(Product(4, 128) == 0x3A && (byte)(1 ^ 4 ^ Product(4, 128)) == 0x3F, "independent fixed RAID6 GF vector 01,02,80 gives Q3F");
        var vector = new byte[3 * 512]; vector[0] = 1; vector[512] = 2; vector[1024] = 128; var known = Make("6", "left-symmetric", vector);
        Check(File.ReadAllBytes(known.Paths[0])[known.Configuration.Members[0].Offset] == 0x3F && File.ReadAllBytes(known.Paths[4])[known.Configuration.Members[4].Offset] == 0x83, "literal first-stripe Q/P disk placement");
        Valid(known, 1, 3);
    }
    static void Flip(Fixture fixture, int disk, int relative)
    {
        byte[] bytes = File.ReadAllBytes(fixture.Paths[disk]); bytes[fixture.Configuration.Members[disk].Offset + relative] ^= 0xA7; File.WriteAllBytes(fixture.Paths[disk], bytes);
    }
    static void CorruptionAndBounds()
    {
        var mirror = Make("1", "mirror"); Flip(mirror, 2, 101); string failed = Fails(mirror.Configuration, "RAID_MIRROR_MISMATCH"); Check(File.Exists(Path.Combine(failed, "raid.dd.partial")) && File.Exists(Path.Combine(failed, "raid-failure.json")), "mirror mismatch retains only partial and failure record");
        var raid10 = Make("10", "adjacent-pairs"); Flip(raid10, 3, 719); Fails(raid10.Configuration, "RAID_MIRROR_MISMATCH");
        var five = Make("5", "left-symmetric"); Flip(five, 3, 80); Fails(five.Configuration, "RAID_PARITY_MISMATCH");
        var six = Make("6", "left-symmetric"); Flip(six, 0, 80); var degraded = Copy(six.Configuration); degraded.Members[1].Missing = true; Fails(degraded, "RAID_PARITY_MISMATCH");
        var noIndependentParity = Make("5", "left-symmetric"); Flip(noIndependentParity, 3, 80); degraded = Copy(noIndependentParity.Configuration); degraded.Members[0].Missing = true; Fails(degraded, "RAID_EXPECTED_HASH_MISMATCH");
        var truncated = Make("0", "striped"); using (var stream = File.OpenWrite(truncated.Paths[1])) stream.SetLength(stream.Length - 1); Fails(truncated.Configuration, null);
        var wrongLayout = Make("5", "left-symmetric"); var wrong = Copy(wrongLayout.Configuration); wrong.Layout = "right-symmetric"; Fails(wrong, "RAID_EXPECTED_HASH_MISMATCH");
        var wrongOrder = Copy(wrongLayout.Configuration); var swap = wrongOrder.Members[0]; wrongOrder.Members[0] = wrongOrder.Members[1]; wrongOrder.Members[1] = swap; Fails(wrongOrder, "RAID_EXPECTED_HASH_MISMATCH");
        wrong.ExpectedSha256 = null; var assumptions = RaidImageBuilder.Build(wrong, NewOutput(), CancellationToken.None, null); Check(assumptions.Sha256 != Digest(wrongLayout.Payload) && File.ReadAllText(assumptions.ReportPath).Contains("\"layout_confirmed\":false"), "parity alone cannot validate an assumed wrong RAID5 layout");
        var config = Make("0", "striped").Configuration; config.Members[0].Missing = true; Fails(config, "RAID_TOO_MANY_MISSING");
        config = Make("5", "left-symmetric").Configuration; config.Members[0].Missing = config.Members[1].Missing = true; Fails(config, "RAID_TOO_MANY_MISSING");
        config = Make("6", "left-symmetric").Configuration; config.Members[0].Missing = config.Members[1].Missing = config.Members[2].Missing = true; Fails(config, "RAID_TOO_MANY_MISSING");
        config = Make("10", "adjacent-pairs").Configuration; config.Members[0].Missing = config.Members[1].Missing = true; Fails(config, "RAID_MIRROR_PAIR_MISSING");
        config = Make("1", "mirror").Configuration; foreach (var member in config.Members) member.Missing = true; Fails(config, "RAID_TOO_MANY_MISSING");
        foreach (string level in new[] { "2", "4", "50", "60", "Storage Spaces" }) { config = Make("0", "striped").Configuration; config.Level = level; Fails(config, "RAID_LEVEL_UNSUPPORTED"); }
        foreach (long size in new long[] { 0, 511, 513, 8L * 1024 * 1024, Int64.MaxValue }) { config = Make("0", "striped").Configuration; config.ChunkSize = size; Fails(config, "RAID_CHUNK_INVALID"); }
        config = Make("6", "left-symmetric").Configuration; config.Layout = "left-asymmetric"; Fails(config, "RAID_LAYOUT_UNSUPPORTED");
        config = Make("5", "left-symmetric").Configuration; config.Layout = ""; Fails(config, "RAID_LAYOUT_UNSUPPORTED");
        config = Make("0", "striped").Configuration; config.Members[0].Offset = Int64.MaxValue; Fails(config, "RAID_OFFSET_INVALID");
        config = Make("0", "striped").Configuration; config.LogicalSize = Int64.MaxValue; Fails(config, "RAID_SIZE_EXCEEDS_MEMBERS");
        config = Make("0", "striped").Configuration; config.ExpectedSha256 = "not-a-hash"; Fails(config, "RAID_SHA256_INVALID");
    }
    static void Safety()
    {
        var fixture = Make("0", "striped"); var duplicate = Copy(fixture.Configuration); duplicate.Members[1] = duplicate.Members[0]; Fails(duplicate, "RAID_DUPLICATE_MEMBER");
        string link = Path.Combine(Path.GetDirectoryName(fixture.Paths[0]), "hardlink.dd"); Check(CreateHardLink(link, fixture.Paths[0], IntPtr.Zero), "synthetic hardlink fixture created"); Fails(fixture.Configuration, "RAID_FILE_IDENTITY_INVALID"); File.Delete(link);
        var partial = Copy(fixture.Configuration); string partialFile = fixture.Paths[0] + ".partial"; File.Copy(fixture.Paths[0], partialFile); partial.Members[0].Path = partialFile; Fails(partial, "RAID_REGULAR_IMAGE_REQUIRED");
        string existing = NewDirectory("not-empty"); File.WriteAllText(Path.Combine(existing, "keep.txt"), "Do not touch"); Fails(fixture.Configuration, "RAID_DESTINATION_NOT_EMPTY", null, CancellationToken.None, existing); Check(File.ReadAllText(Path.Combine(existing, "keep.txt")) == "Do not touch", "existing output preserved");
        var autoFixture = Make("0", "striped", new byte[6 * 512]); autoFixture.Configuration.LogicalSize = 0; autoFixture.Configuration.ExpectedSha256 = null;
        var automatic = RaidImageBuilder.Build(autoFixture.Configuration, NewOutput(), CancellationToken.None, null); Check(automatic.Bytes == 6 * 512 && File.ReadAllText(automatic.ReportPath).Contains("derived_conservative_whole_stripes"), "automatic length is explicitly conservative");
        var unequal = Copy(fixture.Configuration); unequal.LogicalSize = 0; using (var stream = File.OpenWrite(unequal.Members[0].Path)) stream.SetLength(stream.Length + 512); Fails(unequal, "RAID_LENGTHS_DIFFER");
        fixture = Make("0", "striped"); bool locked = false; string output = NewOutput();
        var lockedResult = RaidImageBuilder.Build(fixture.Configuration, output, CancellationToken.None, null, phase => { if (phase == "Проверка образов участников") try { using (File.OpenWrite(fixture.Paths[0])) { } } catch (IOException) { locked = true; } });
        Check(locked && Digest(lockedResult.ImagePath) == Digest(fixture.Payload), "source write denied throughout hashing and assembly");
        bool canWriteAfter = false; using (File.Open(fixture.Paths[0], FileMode.Open, FileAccess.ReadWrite, FileShare.None)) canWriteAfter = true; Check(canWriteAfter, "source handles released after completion");
        var repeated = Copy(fixture.Configuration); Fails(repeated, "RAID_DESTINATION_NOT_EMPTY", null, CancellationToken.None, output); Check(Digest(lockedResult.ImagePath) == Digest(fixture.Payload), "completed output is never overwritten");
        fixture = Make("0", "striped"); using (var stop = new CancellationTokenSource()) {
            string cancelledOutput = NewOutput(); Fails(fixture.Configuration, "CANCELLED", (done, total) => { if (done > 0) stop.Cancel(); }, stop.Token, cancelledOutput);
            Check(File.Exists(Path.Combine(cancelledOutput, "raid.dd.partial")) && new FileInfo(Path.Combine(cancelledOutput, "raid.dd.partial")).Length < fixture.Payload.Length, "cancellation leaves an incomplete .partial");
            Check(File.ReadAllText(Path.Combine(cancelledOutput, "raid-failure.json")).Contains("\"published\":false"), "cancelled result explicitly unpublished");
        }
        using (var stop = new CancellationTokenSource()) { stop.Cancel(); Fails(fixture.Configuration, "CANCELLED", null, stop.Token); }
        using (var stop = new CancellationTokenSource()) {
            string finalCancel=NewOutput();Fails(fixture.Configuration,"CANCELLED",(done,total)=>{if(done==total)stop.Cancel();},stop.Token,finalCancel);
            Check(File.Exists(Path.Combine(finalCancel,"raid.dd.partial"))&&new FileInfo(Path.Combine(finalCancel,"raid.dd.partial")).Length==fixture.Payload.Length,"cancel after copied bytes does not publish before verification");
        }
        string collision=NewOutput();bool collisionRejected=false;
        try{RaidImageBuilder.Build(fixture.Configuration,collision,CancellationToken.None,null,phase=>{if(phase=="Повторная проверка исходных образов"){File.WriteAllText(Path.Combine(collision,"raid-report.json"),"foreign report");File.WriteAllText(Path.Combine(collision,"raid.dd.sha256"),"foreign checksum");}});}catch(RaidRecoveryException error){collisionRejected=error.Code=="RAID_IO_ERROR";}
        Check(collisionRejected&&!File.Exists(Path.Combine(collision,"raid.dd")),"late publication collision cannot publish an image");
        Check(File.ReadAllText(Path.Combine(collision,"raid-report.json"))=="foreign report"&&File.ReadAllText(Path.Combine(collision,"raid.dd.sha256"))=="foreign checksum","late foreign reports and checksums never overwritten or deleted");
        var mutable=Copy(fixture.Configuration);var stable=RaidImageBuilder.Build(mutable,NewOutput(),CancellationToken.None,null,phase=>{if(phase=="Проверка образов участников"){mutable.Level="6";mutable.Members[0].Offset=Int64.MaxValue;mutable.Members.Clear();}});
        Check(stable.Sha256==Digest(fixture.Payload),"configuration is snapshotted before callbacks or worker changes");
    }
    static void W16(byte[] bytes, int at, int value) { bytes[at] = (byte)value; bytes[at + 1] = (byte)(value >> 8); }
    static void W32(byte[] bytes, int at, int value) { for (int i = 0; i < 4; i++) bytes[at + i] = (byte)(value >> (i * 8)); }
    static void FatPipeline()
    {
        // An independent FAT12 disk with a deleted entry spans member stripes.
        int clusters = 2000, fatSectors = 6, dataStart = (1 + fatSectors + 4) * 512; byte[] disk = new byte[dataStart + clusters * 512];
        disk[0] = 0xEB; disk[1] = 0x3C; disk[2] = 0x90; Encoding.ASCII.GetBytes("MSDOS5.0").CopyTo(disk, 3); W16(disk, 11, 512); disk[13] = 1; W16(disk, 14, 1); disk[16] = 1; W16(disk, 17, 64); W16(disk, 19, disk.Length / 512); disk[21] = 0xF8; W16(disk, 22, fatSectors); disk[510] = 0x55; disk[511] = 0xAA; disk[512] = 0xF8; disk[513] = disk[514] = 0xFF;
        byte[] payload = new byte[1471]; for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i * 29 + 83);
        int entry = (1 + fatSectors) * 512; Encoding.ASCII.GetBytes("RECIPE  TXT").CopyTo(disk, entry); disk[entry] = 0xE5; disk[entry + 11] = 0x20; W16(disk, entry + 26, 2); W32(disk, entry + 28, payload.Length); Buffer.BlockCopy(payload, 0, disk, dataStart, payload.Length);
        var fixture = Make("5", "left-symmetric", disk); var built = Valid(fixture, 2); string results = NewDirectory("fat-results");
        var assembly = typeof(RecoveryCore).Assembly; var recover = assembly.GetType("UsbRecovery.FilesystemRecovery").GetMethod("Recover", new[] { typeof(string), typeof(string), typeof(CancellationToken), typeof(Action<string>) });
        int found = (int)recover.Invoke(null, new object[] { built.ImagePath, results, CancellationToken.None, new Action<string>(s => { }) });
        Check(found > 0 && Directory.EnumerateFiles(results, "*", SearchOption.AllDirectories).Any(file => new FileInfo(file).Length == payload.Length && Digest(file) == Digest(payload)), "actual FAT12 deleted payload recovers exactly from a degraded assembled RAID5");
        Check(Digest(built.ImagePath) == Digest(disk), "filesystem parser leaves assembled image unchanged");
    }
    public static int Main(string[] args)
    {
        try {
            project = Path.GetFullPath(args[0]); root = Path.Combine(project, ".build", "raid-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            Matrices(); CorruptionAndBounds(); Safety(); FatPipeline();
            Console.WriteLine("PASS RaidRecovery: " + checks + " checks; literal-layout independent fixtures, RAID0/1/5/6/10, all supported missing-member combinations, GF/P/Q, hashverified publication, parity/mirror rejection, cancellation, source locks/identity, bounds and actual deleted FAT12 pipeline. Synthetic ordinary files only; no devices or automatic layout inference."); return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally { if (root != null && Path.GetFullPath(root).StartsWith(Path.Combine(project, ".build", "raid-tests-"), StringComparison.OrdinalIgnoreCase) && Directory.Exists(root)) try { Directory.Delete(root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
    }
}
