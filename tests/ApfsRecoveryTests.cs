// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ApfsRecoveryTests
{
    static int assertions;
    static string fixtures, results;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };

    static void Assert(bool value, string message)
    {
        assertions++;
        if (!value) throw new Exception(message);
    }

    static string Hash(string file)
    {
        using (var f = File.OpenRead(file))
        using (var h = SHA256.Create())
            return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
    }

    static void Throws<T>(Action action, string message) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            assertions++;
            return;
        }
        throw new Exception(message);
    }

    static ApfsRecovery.Report Report(string folder)
    {
        return Json.Deserialize<ApfsRecovery.Report>(File.ReadAllText(Path.Combine(folder, "apfs", "report.json")));
    }

    static string Output(string folder, ApfsRecovery.Entry entry)
    {
        return Path.Combine(folder, "apfs", entry.Output.Replace('/', Path.DirectorySeparatorChar));
    }

    static string Run(string image, string name, out ApfsRecovery.Report report, IEnumerable<long> offsets = null, ApfsRecovery.Limits limits = null)
    {
        string destination = Path.Combine(results, name);
        ApfsRecovery.Recover(image, destination, CancellationToken.None, null, offsets, limits);
        report = Report(destination);
        return destination;
    }

    static void Cases()
    {
        string manifestPath = Path.Combine(fixtures, "manifest.json");
        Assert(File.Exists(manifestPath), "APFS salvage manifest.json exists");
        var manifest = (Dictionary<string, object>)Json.DeserializeObject(File.ReadAllText(manifestPath));
        var cases = (IEnumerable)manifest["cases"];

        foreach (Dictionary<string, object> c in cases)
        {
            string name = (string)c["name"];
            string imageFile = Path.Combine(fixtures, (string)c["image"]);
            Assert(File.Exists(imageFile), "Fixture image file exists: " + imageFile);
            string imageHash = Hash(imageFile);
            Assert(imageHash == (string)c["sha256"], "Fixture image sha256 matches manifest pin: " + name);

            File.SetAttributes(imageFile, File.GetAttributes(imageFile) | FileAttributes.ReadOnly);

            ApfsRecovery.Report report;
            string dest = Run(imageFile, name, out report);

            Assert(report.Status == "complete", "Report status is complete: " + name);
            Assert(report.SourceUnchanged, "Source image unmutated: " + name);
            Assert(Hash(imageFile) == imageHash, "Source image byte hash confirmed unchanged after recovery: " + name);
            Assert(report.Capabilities.Fletcher64Verified, "Fletcher64 verified in capability matrix");
            Assert(report.Capabilities.UnreferencedSalvageSupported, "Unreferenced salvage supported in capability matrix");
            Assert(report.Volumes.Count >= 1, "At least one volume discovered: " + name);

            // Check Live Files
            var liveExpected = (IEnumerable)c["live_files"];
            foreach (Dictionary<string, object> expected in liveExpected)
            {
                string rel = (string)expected["path"];
                string expSha = (string)expected["sha256"];
                long expSize = Convert.ToInt64(expected["size"]);

                var entry = report.Entries.FirstOrDefault(e => e.Name == Path.GetFileName(rel) && e.Status == "recovered_live");
                Assert(entry != null, "Live file entry found in report: " + rel);
                Assert(entry.Status == "recovered_live", "Status is recovered_live");
                Assert(entry.DeletionEvidence == "none", "Live file deletion evidence is none");
                Assert(entry.ContentAuthenticityVerified, "Live file content authenticity verified");
                Assert(entry.DeclaredSize == expSize, "Live file size matches declared: " + rel);
                Assert(entry.Sha256 == expSha, "Live file sha256 matches expectation: " + rel);

                string outPath = Output(dest, entry);
                Assert(File.Exists(outPath), "Extracted live file exists on disk: " + outPath);
                Assert(new FileInfo(outPath).Length == expSize, "Extracted live file size on disk matches: " + rel);
                Assert(Hash(outPath) == expSha, "Extracted live file hash on disk matches: " + rel);
            }

            // Check Salvaged Files
            var salvExpected = (IEnumerable)c["salvaged_files"];
            foreach (Dictionary<string, object> expected in salvExpected)
            {
                string rel = (string)expected["path"];
                string expSha = (string)expected["sha256"];
                long expSize = Convert.ToInt64(expected["size"]);
                ulong expInode = Convert.ToUInt64(expected["inode"]);

                var entry = report.Entries.FirstOrDefault(e => e.ObjectId == expInode && e.Status == "deleted_apfs_unreferenced_candidate");
                Assert(entry != null, "Salvaged file entry found in report: " + rel + " (inode " + expInode + ")");
                Assert(entry.Status == "deleted_apfs_unreferenced_candidate", "Status is deleted_apfs_unreferenced_candidate");
                Assert(entry.DeletionEvidence == "unreferenced_in_live_btree", "Deletion evidence is unreferenced_in_live_btree");
                Assert(!entry.ContentAuthenticityVerified, "Deleted candidate content authenticity correctly unverified");
                Assert(entry.MetadataChecksumVerified, "Deleted candidate metadata checksum verified via Fletcher-64");
                Assert(entry.DeclaredSize == expSize, "Salvaged file size matches declared: " + rel);
                Assert(entry.Sha256 == expSha, "Salvaged file sha256 matches expectation: " + rel);
                Assert(entry.Extents.Count >= 1, "Extents recorded for salvaged file");

                string outPath = Output(dest, entry);
                Assert(File.Exists(outPath), "Extracted salvaged file exists on disk: " + outPath);
                Assert(new FileInfo(outPath).Length == expSize, "Extracted salvaged file size on disk matches: " + rel);
                Assert(Hash(outPath) == expSha, "Extracted salvaged file hash on disk matches: " + rel);
            }

            // Corrupt case check
            if (c.ContainsKey("corrupted_block"))
            {
                Assert(report.Volumes[0].CorruptedNodesSkipped >= 1, "Corrupted block safely detected and skipped");
                Assert(report.Entries.All(e => e.Name != "corrupted.txt"), "Corrupted metadata entry rejected");
            }
        }
    }

    static void Safety()
    {
        string singleImage = Path.Combine(fixtures, "apfs-deleted-single.dd");
        string before = Hash(singleImage);

        // Pre-cancellation
        var cancelled = new CancellationToken(true);
        string preCancelDest = Path.Combine(results, "pre-cancel");
        Throws<OperationCanceledException>(() =>
            ApfsRecovery.Recover(singleImage, preCancelDest, cancelled, null),
            "Pre-cancellation honored");
        Assert(!Directory.Exists(preCancelDest), "Cancelled operation leaves no directory");

        // Existing destination directory blocked
        string existingDir = Path.Combine(results, "existing-dir");
        Directory.CreateDirectory(Path.Combine(existingDir, "apfs"));
        Throws<IOException>(() =>
            ApfsRecovery.Recover(singleImage, existingDir, CancellationToken.None, null),
            "Existing destination directory blocked");

        // Invalid resource limits blocked
        Throws<ArgumentException>(() =>
            ApfsRecovery.Recover(singleImage, Path.Combine(results, "neg-limits"), CancellationToken.None, null, null, new ApfsRecovery.Limits { MaximumFileBytes = -1 }),
            "Negative MaximumFileBytes rejected");

        // Bounded output bytes
        ApfsRecovery.Report boundRep;
        Run(singleImage, "bounded-output", out boundRep, null, new ApfsRecovery.Limits { MaximumOutputBytes = 20 });
        Assert(boundRep.Limited, "MaximumOutputBytes bound sets Limited = true");
        Assert(boundRep.Status == "limited", "Report status is limited when bound reached");

        // Bounded file bytes
        ApfsRecovery.Report boundFileRep;
        Run(singleImage, "bounded-file", out boundFileRep, null, new ApfsRecovery.Limits { MaximumFileBytes = 20 });
        Assert(boundFileRep.Limited, "MaximumFileBytes bound sets Limited = true");

        Assert(Hash(singleImage) == before, "Cancellation and safety preserve source");
    }

    public static int Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && Directory.Exists(args[0]))
                fixtures = Path.GetFullPath(args[0]);
            else
            {
                fixtures = Path.GetFullPath(".build/apfs-fixtures-current");
                if (!Directory.Exists(fixtures))
                    fixtures = Path.GetFullPath("tests/fixtures/apfs-salvage");
            }

            if (args.Length > 1)
                results = Path.GetFullPath(args[1]);
            else
                results = Path.GetFullPath(".build/apfs-tests-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));

            if (Directory.Exists(results))
            {
                try { Directory.Delete(results, true); } catch { }
            }
            Directory.CreateDirectory(results);

            // 1. Fletcher-64 Unit Tests
            byte[] testBuf = Encoding.ASCII.GetBytes("Apple File System Fletcher-64 test vector with multiple 32-bit words!!");
            ulong ck = ApfsRecovery.ComputeFletcher64(testBuf, 0, testBuf.Length);
            Assert(ck != 0, "Fletcher64 computes non-zero checksum");
            ulong ckSame = ApfsRecovery.ComputeFletcher64(testBuf, 0, testBuf.Length);
            Assert(ck == ckSame, "Fletcher64 deterministic");
            testBuf[10] ^= 0x01;
            ulong ckDiff = ApfsRecovery.ComputeFletcher64(testBuf, 0, testBuf.Length);
            Assert(ck != ckDiff, "Fletcher64 sensitive to bit flips");

            // 2. Cases
            Cases();

            // 3. Safety & Bounds
            Safety();

            Console.WriteLine("PASS ApfsRecovery: " + assertions + " assertions; live + RoW unreferenced salvage, Fletcher-64, non-contiguous extents, orphan reconstruction, corrupt rejection, bounds and cancellation. " + results);
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }
}
