using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class RaidControllerRecoveryTests
{
    public sealed class Fixture { public string name, format, sha256; public int level, disks, role; public long bytes; }
    public sealed class Manifest { public int schema; public string format; public List<Fixture> cases; }
    static string project, fixtures, work; static int checks, number;

    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { using (var input = File.OpenRead(path)) using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant(); }
    static string Copy(string source, string name = null) { string path = Path.Combine(work, (++number).ToString("D3") + "-" + (name ?? Path.GetFileName(source))); File.Copy(source, path); return path; }

    static RaidMetadataProbe.Report Probe(params string[] paths)
    {
        var before = paths.Where(File.Exists).Distinct().ToDictionary(p => p, Hash);
        var result = RaidMetadataProbe.Probe(paths, CancellationToken.None);
        foreach (var pair in before) Check(Hash(pair.Key) == pair.Value, "probe leaves supplied image bytes unchanged");
        Check(result.MetadataBytesRead <= 65536L * paths.Length, "only documented bounded metadata ranges read");
        return result;
    }

    static void TestImsm()
    {
        // 1. IMSM RAID 0
        string d0 = Path.Combine(fixtures, "imsm-raid0-1.dd");
        string d1 = Path.Combine(fixtures, "imsm-raid0-2.dd");
        var rep0 = Probe(d1, d0); // Reversed input order must not break role order
        Check(rep0.Groups.Count == 1, "IMSM RAID 0 group discovered");
        var g0 = rep0.Groups[0];
        Check(g0.Format == "imsm" && g0.Level == "0" && g0.RaidDisks == 2 && g0.Status == "candidate", "IMSM RAID 0 parameters decoded");
        Check(g0.Configuration != null && g0.Configuration.Members[0].Path == d0 && g0.Configuration.Members[1].Path == d1, "IMSM disk roles preserve metadata order");
        string out0 = Path.Combine(work, "assembled-imsm-r0");
        var built0 = RaidImageBuilder.Build(g0.Configuration, out0, CancellationToken.None, (d, t) => { });
        Check(built0.Bytes == g0.Configuration.LogicalSize && File.Exists(built0.ImagePath), "IMSM RAID 0 image built successfully");

        // 2. IMSM RAID 1
        string m0 = Path.Combine(fixtures, "imsm-raid1-1.dd");
        string m1 = Path.Combine(fixtures, "imsm-raid1-2.dd");
        var rep1 = Probe(m0, m1);
        Check(rep1.Groups.Count == 1, "IMSM RAID 1 group discovered");
        var g1 = rep1.Groups[0];
        Check(g1.Format == "imsm" && g1.Level == "1" && g1.RaidDisks == 2 && g1.Status == "candidate", "IMSM RAID 1 parameters decoded");
        string out1 = Path.Combine(work, "assembled-imsm-r1");
        var built1 = RaidImageBuilder.Build(g1.Configuration, out1, CancellationToken.None, (d, t) => { });
        Check(built1.Bytes == g1.Configuration.LogicalSize && File.Exists(built1.ImagePath), "IMSM RAID 1 image built successfully");

        // 3. IMSM RAID 5
        string p0 = Path.Combine(fixtures, "imsm-raid5-1.dd");
        string p1 = Path.Combine(fixtures, "imsm-raid5-2.dd");
        string p2 = Path.Combine(fixtures, "imsm-raid5-3.dd");
        var rep5 = Probe(p2, p0, p1);
        Check(rep5.Groups.Count == 1, "IMSM RAID 5 group discovered");
        var g5 = rep5.Groups[0];
        Check(g5.Format == "imsm" && g5.Level == "5" && g5.RaidDisks == 3 && g5.Status == "candidate", "IMSM RAID 5 parameters decoded");
        Check(g5.Configuration.Members[0].Path == p0 && g5.Configuration.Members[1].Path == p1 && g5.Configuration.Members[2].Path == p2, "IMSM RAID 5 role mapping");
        string out5 = Path.Combine(work, "assembled-imsm-r5");
        var built5 = RaidImageBuilder.Build(g5.Configuration, out5, CancellationToken.None, (d, t) => { });
        Check(built5.Bytes == g5.Configuration.LogicalSize && File.Exists(built5.ImagePath), "IMSM RAID 5 image built successfully");
    }

    static void TestDdf()
    {
        // 1. DDF RAID 0
        string d0 = Path.Combine(fixtures, "ddf-raid0-1.dd");
        string d1 = Path.Combine(fixtures, "ddf-raid0-2.dd");
        var rep0 = Probe(d1, d0);
        Check(rep0.Groups.Count == 1, "DDF RAID 0 group discovered");
        var g0 = rep0.Groups[0];
        Check(g0.Format == "ddf" && g0.Level == "0" && g0.RaidDisks == 2 && g0.Status == "candidate", "DDF RAID 0 parameters decoded");
        Check(g0.Configuration.Members[0].Path == d0 && g0.Configuration.Members[1].Path == d1, "DDF disk roles preserve metadata order");
        string out0 = Path.Combine(work, "assembled-ddf-r0");
        var built0 = RaidImageBuilder.Build(g0.Configuration, out0, CancellationToken.None, (d, t) => { });
        Check(built0.Bytes == g0.Configuration.LogicalSize && File.Exists(built0.ImagePath), "DDF RAID 0 image built successfully");

        // 2. DDF RAID 1
        string m0 = Path.Combine(fixtures, "ddf-raid1-1.dd");
        string m1 = Path.Combine(fixtures, "ddf-raid1-2.dd");
        var rep1 = Probe(m0, m1);
        Check(rep1.Groups.Count == 1, "DDF RAID 1 group discovered");
        var g1 = rep1.Groups[0];
        Check(g1.Format == "ddf" && g1.Level == "1" && g1.RaidDisks == 2 && g1.Status == "candidate", "DDF RAID 1 parameters decoded");
        string out1 = Path.Combine(work, "assembled-ddf-r1");
        var built1 = RaidImageBuilder.Build(g1.Configuration, out1, CancellationToken.None, (d, t) => { });
        Check(built1.Bytes == g1.Configuration.LogicalSize && File.Exists(built1.ImagePath), "DDF RAID 1 image built successfully");
    }

    static void TestStorageSpaces()
    {
        // 1. Storage Spaces Simple
        string s0 = Path.Combine(fixtures, "spaces-simple-1.dd");
        string s1 = Path.Combine(fixtures, "spaces-simple-2.dd");
        var rep0 = Probe(s1, s0);
        Check(rep0.Groups.Count == 1, "Storage Spaces Simple group discovered");
        var g0 = rep0.Groups[0];
        Check(g0.Format == "storage-spaces" && g0.Level == "0" && g0.RaidDisks == 2 && g0.Status == "candidate", "Storage Spaces Simple parameters decoded");
        Check(g0.Configuration.Members[0].Path == s0 && g0.Configuration.Members[1].Path == s1, "Storage Spaces column roles preserve metadata order");
        string out0 = Path.Combine(work, "assembled-spaces-simple");
        var built0 = RaidImageBuilder.Build(g0.Configuration, out0, CancellationToken.None, (d, t) => { });
        Check(built0.Bytes == g0.Configuration.LogicalSize && File.Exists(built0.ImagePath), "Storage Spaces Simple image built successfully");

        // 2. Storage Spaces Mirror
        string m0 = Path.Combine(fixtures, "spaces-mirror-1.dd");
        string m1 = Path.Combine(fixtures, "spaces-mirror-2.dd");
        var rep1 = Probe(m0, m1);
        Check(rep1.Groups.Count == 1, "Storage Spaces Mirror group discovered");
        var g1 = rep1.Groups[0];
        Check(g1.Format == "storage-spaces" && g1.Level == "1" && g1.RaidDisks == 2 && g1.Status == "candidate", "Storage Spaces Mirror parameters decoded");
        string out1 = Path.Combine(work, "assembled-spaces-mirror");
        var built1 = RaidImageBuilder.Build(g1.Configuration, out1, CancellationToken.None, (d, t) => { });
        Check(built1.Bytes == g1.Configuration.LogicalSize && File.Exists(built1.ImagePath), "Storage Spaces Mirror image built successfully");
    }

    static void TestNegatives()
    {
        // 1. Corrupted IMSM Checksum
        string origImsm = Path.Combine(fixtures, "imsm-raid0-1.dd");
        byte[] bytes = File.ReadAllBytes(origImsm);
        bytes[bytes.Length - 100] ^= 0xFF; // corrupt metadata
        string badImsm = Path.Combine(work, "corrupted-imsm.dd");
        File.WriteAllBytes(badImsm, bytes);
        var repBad = Probe(badImsm);
        Check(repBad.Members.Any(m => m.Status == "invalid" && m.Code == "MD_CHECKSUM_INVALID"), "Corrupted IMSM checksum rejected");

        // 2. Corrupted DDF CRC32
        string origDdf = Path.Combine(fixtures, "ddf-raid0-1.dd");
        bytes = File.ReadAllBytes(origDdf);
        bytes[bytes.Length - 50] ^= 0xFF;
        string badDdf = Path.Combine(work, "corrupted-ddf.dd");
        File.WriteAllBytes(badDdf, bytes);
        var repDdf = Probe(badDdf);
        Check(repDdf.Members.Any(m => m.Status == "invalid" && m.Code == "MD_CHECKSUM_INVALID"), "Corrupted DDF CRC32 rejected");

        // 3. Corrupted Storage Spaces CRC
        string origSpaces = Path.Combine(fixtures, "spaces-simple-1.dd");
        bytes = File.ReadAllBytes(origSpaces);
        bytes[4096 + 100] ^= 0xFF;
        string badSpaces = Path.Combine(work, "corrupted-spaces.dd");
        File.WriteAllBytes(badSpaces, bytes);
        var repSpaces = Probe(badSpaces);
        Check(repSpaces.Members.Any(m => m.Status == "invalid" && m.Code == "MD_CHECKSUM_INVALID"), "Corrupted Storage Spaces CRC rejected");

        // 4. Inconsistent Events (Generation Mismatch)
        string d0 = Path.Combine(fixtures, "imsm-raid0-1.dd");
        bytes = File.ReadAllBytes(Path.Combine(fixtures, "imsm-raid0-2.dd"));
        // alter generation_num at offset 40 of MPB (length - 1024 + 40)
        int genAt = bytes.Length - 1024 + 40;
        uint gen = (uint)bytes[genAt] | ((uint)bytes[genAt+1] << 8) | ((uint)bytes[genAt+2] << 16) | ((uint)bytes[genAt+3] << 24);
        gen += 5;
        bytes[genAt] = (byte)gen; bytes[genAt+1] = (byte)(gen >> 8); bytes[genAt+2] = (byte)(gen >> 16); bytes[genAt+3] = (byte)(gen >> 24);
        // recompute additive checksum at length - 1024 + 32
        int mpbAt = bytes.Length - 1024;
        bytes[mpbAt + 32] = 0; bytes[mpbAt + 33] = 0; bytes[mpbAt + 34] = 0; bytes[mpbAt + 35] = 0;
        ulong sum = 0;
        for (int i = 0; i < 1024; i += 4) {
            uint w = (uint)bytes[mpbAt + i] | ((uint)bytes[mpbAt + i + 1] << 8) | ((uint)bytes[mpbAt + i + 2] << 16) | ((uint)bytes[mpbAt + i + 3] << 24);
            sum += w;
        }
        uint csum = (uint)sum;
        bytes[mpbAt + 32] = (byte)csum; bytes[mpbAt + 33] = (byte)(csum >> 8); bytes[mpbAt + 34] = (byte)(csum >> 16); bytes[mpbAt + 35] = (byte)(csum >> 24);
        string alteredImsm = Path.Combine(work, "altered-gen-imsm.dd");
        File.WriteAllBytes(alteredImsm, bytes);
        var repGen = Probe(d0, alteredImsm);
        Check(repGen.Groups.Count == 1 && repGen.Groups[0].Status == "inconsistent" && repGen.Groups[0].Reasons.Contains("MD_EVENT_COUNTER_MISMATCH"), "IMSM generation mismatch detected as inconsistent");
    }

    public static int Main(string[] args)
    {
        try
        {
            project = Path.GetFullPath(args.Length > 0 ? args[0] : ".");
            fixtures = args.Length > 1 ? Path.GetFullPath(args[1]) : Path.Combine(project, ".build", "raid-controller-fixtures-current");
            work = args.Length > 2 ? Path.GetFullPath(args[2]) : Path.Combine(project, ".build", "raid-ctrl-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(work);

            TestImsm();
            TestDdf();
            TestStorageSpaces();
            TestNegatives();

            Console.WriteLine("PASS RaidControllerRecovery: " + checks + " checks; Intel Matrix / RST (IMSM), SNIA DDF, Windows Storage Spaces, parity/mirror/stripe assembly, checksums, generation mismatch and corruption negatives.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }
}
