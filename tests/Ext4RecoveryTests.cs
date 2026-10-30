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

public static class Ext4RecoveryTests
{
    static int assertions;
    static string fixtures, results;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };
    static void Assert(bool value, string message) { assertions++; if (!value) throw new Exception(message); }
    static string Hash(string file) { using (var f = File.OpenRead(file)) using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant(); }
    static void Throws<T>(Action action, string message) where T : Exception { try { action(); } catch (T) { assertions++; return; } throw new Exception(message); }
    static Ext4Recovery.Report Report(string folder) { return Json.Deserialize<Ext4Recovery.Report>(File.ReadAllText(Path.Combine(folder, "ext4", "report.json"))); }
    static string Output(string folder, Ext4Recovery.Entry entry) { return Path.Combine(folder, "ext4", entry.Output.Replace('/', Path.DirectorySeparatorChar)); }
    static string Run(string image, string name, out Ext4Recovery.Report report, IEnumerable<long> offsets = null, Ext4Recovery.Limits limits = null)
    {
        string destination = Path.Combine(results, name);
        Ext4Recovery.Recover(image, destination, CancellationToken.None, null, offsets, limits); report = Report(destination); return destination;
    }
    static void Cases()
    {
        var manifest = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(fixtures, "manifest.json")));
        foreach (Dictionary<string, object> sample in (IEnumerable)manifest["cases"]) {
            string name = (string)sample["name"], image = Path.Combine(fixtures, (string)sample["image"]), before = Hash(image);
            Assert(before == (string)sample["sha256"], name + ": fixture input matches independent manifest");
            File.SetAttributes(image, File.GetAttributes(image) | FileAttributes.ReadOnly);
            Ext4Recovery.Report report; string folder = Run(image, name, out report);
            uint inode = Convert.ToUInt32(sample["target_inode"]);
            var entries = report.Entries.Where(x => x.Inode == inode).ToList();
            Assert(report.SourceUnchanged && report.SourceSha256 == before && Hash(image) == before, name + ": input bytes unchanged");
            Assert(!report.Failed && !report.Cancelled, name + ": scan completed without an exception");
            Assert(!Directory.GetFiles(folder, "*.partial", SearchOption.AllDirectories).Any(), name + ": no partial output published");
            Assert(report.Entries.All(x => !x.ContentAuthenticityVerified), name + ": metadata checksum is never called a content checksum");
            string outcome = (string)sample["outcome"];
            if (outcome == "recover" || outcome == "candidate_current_bytes") {
                Assert(entries.Count == 1 && entries[0].Output != null, name + ": retained deleted inode extracted");
                Ext4Recovery.Entry entry = entries[0]; string output = Output(folder, entry);
                Assert(File.Exists(output) && Hash(output) == entry.Sha256 && entry.RecoveredBytes == new FileInfo(output).Length, name + ": published content hash and length");
                Assert(entry.Status == "deleted_inode_candidate" && entry.AllocationStatus.StartsWith("currently_free"), name + ": correct candidate/allocation classification");
                if (sample.ContainsKey("extension")) Assert(entry.Output.EndsWith((string)sample["extension"], StringComparison.Ordinal) && entry.ContentTypeHint == ((string)sample["extension"]).Substring(1) + "_signature_only", name + ": extension is only a current-byte signature hint, never original filename/integrity");
                Assert(entry.Note.Contains("перезаписаны"), name + ": overwrite uncertainty explicit");
                Assert(entry.Extents.Sum(x => x.Length) == entry.DeclaredSize, name + ": complete nonfabricated source extent map");
                using (var actual = File.OpenRead(output)) using (var source = File.OpenRead(image)) {
                    foreach (var extent in entry.Extents) {
                        byte[] a = new byte[extent.Length], b = new byte[extent.Length]; actual.Position = extent.LogicalOffset; source.Position = extent.ImageOffset;
                        Assert(actual.Read(a, 0, a.Length) == a.Length && source.Read(b, 0, b.Length) == b.Length && a.SequenceEqual(b), name + ": exact source range provenance");
                    }
                }
                Assert((entry.Sha256 == (string)sample["payload_sha256"]) == (outcome == "recover"), name + ": authentic known fixture compared independently, overwritten bytes never repaired by guessing");
                if (sample.ContainsKey("minimum_extents")) Assert(entry.Extents.Count >= Convert.ToInt32(sample["minimum_extents"]), name + ": physical fragmentation retained");
                if (sample.ContainsKey("mapping")) Assert(entry.Mapping == (string)sample["mapping"], name + ": legacy mapping exercised");
                if (sample.ContainsKey("expected_name")) Assert(entry.Names.Any(x => x.Name == (string)sample["expected_name"] && x.DirectoryPath == "/архив/" && x.DirectoryChecksumVerified), name + ": Unicode name is an actual checksummed directory reference");
                if (sample.ContainsKey("names_must_be_absent")) Assert(entry.Names.Count == 0, "Damaged directory checksum cannot attach a filename");
                if (name == "partition-offset") {
                    Assert(entry.VolumeOffset == 1048576, "MBR partition offset is included in source extents");
                    Ext4Recovery.Report explicitReport; Run(image, name + "-explicit", out explicitReport, new long[] { 1048576 });
                    Assert(explicitReport.Entries.Single(x => x.Inode == inode).Sha256 == entry.Sha256, "Explicit partition offset agrees with MBR discovery");
                }
            } else {
                Assert(entries.All(x => x.Output == null), name + ": unsupported/corrupted/allocated metadata not exported");
                if (sample.ContainsKey("reason")) Assert(entries.Any(x => x.Reason == (string)sample["reason"]), name + ": exact mapping rejection");
                if (sample.ContainsKey("skipped")) Assert(report.Skipped.ContainsKey((string)sample["skipped"]), name + ": exact metadata rejection");
                if (sample.ContainsKey("volume_reason")) Assert(report.Volumes.Any(x => x.Reason == (string)sample["volume_reason"]), name + ": unsupported volume rejected before extraction");
                if (outcome == "live") Assert(entries.Count == 0 && report.Volumes.Sum(x => x.LiveInodes) > 0, "Live inode is not a deleted message/file candidate");
                if (name == "bad-super-checksum") Assert(report.Volumes.Any(x => x.Reason == "superblock_checksum_invalid"), "Superblock CRC checked before metadata pointers");
                if (name == "bad-extent-node-checksum") Assert(entries.Any(x => x.Reason == "extent_node_checksum_invalid"), "External extent node CRC checked");
                if (name == "cyclic-extent-tree-valid-crc") Assert(entries.Any(x => x.Reason == "mapping_cycle_or_duplicate_node"), "Valid CRC cannot authorize a cyclic tree");
                if (name == "allocated-data-conflict") Assert(entries.Any(x => x.Reason == "currently_allocated_block_conflict"), "Reallocated source block rejected");
                if (name == "unwritten-deleted") Assert(entries.Any(x => x.Reason == "unwritten_extent_not_original_data"), "Unwritten extents never fabricated as original zeros");
                if (name == "sparse-deleted") Assert(entries.Any(x => x.Reason.Contains("sparse")), "Sparse hole never fabricated as original bytes");
            }
        }
    }
    static void Safety()
    {
        string image = Path.Combine(fixtures, "extent-deleted.dd"), before = Hash(image);
        var cancelled = new CancellationToken(true); string pre = Path.Combine(results, "pre-cancelled");
        Throws<OperationCanceledException>(() => Ext4Recovery.Recover(image, pre, cancelled, null), "Pre-cancellation honored");
        Assert(!Directory.Exists(Path.Combine(pre, "ext4")), "Pre-cancellation does not create a successful archive");
        string during = Path.Combine(results, "during-cancelled");
        using (var cancel = new CancellationTokenSource()) {
            Throws<OperationCanceledException>(() => Ext4Recovery.Recover(image, during, cancel.Token, message => cancel.Cancel()), "Cancellation during traversal honored");
        }
        Assert(Report(during).Cancelled && Report(during).Status == "cancelled" && !Directory.GetFiles(during, "*.partial", SearchOption.AllDirectories).Any(), "Cancelled report is explicit and partial outputs removed");
        string existing = Path.Combine(results, "extent-deleted");
        Throws<IOException>(() => Ext4Recovery.Recover(image, existing, CancellationToken.None, null), "Existing result folder not overwritten");
        Ext4Recovery.Report report; Run(image, "bounded-inodes", out report, null, new Ext4Recovery.Limits { MaximumInodes = 1 });
        Assert(report.Limited && report.RecoveredFiles == 0 && report.Skipped.ContainsKey("inode_limit"), "Global inode work limit recorded");
        Run(image, "bounded-output", out report, null, new Ext4Recovery.Limits { MaximumOutputBytes = 10 });
        Assert(report.Limited && report.RecoveredFiles == 0 && report.Entries.Any(x => x.Reason == "output_limit"), "Output budget never publishes an incomplete file");
        Run(image, "bounded-file", out report, null, new Ext4Recovery.Limits { MaximumFileBytes = 10 });
        Assert(report.Limited && report.RecoveredFiles == 0 && report.Skipped.ContainsKey("file_size_limit"), "Per-file budget marks incomplete coverage");
        Run(image, "bounded-directories", out report, null, new Ext4Recovery.Limits { MaximumDirectories = 1 });
        Assert(report.Limited && report.Skipped.ContainsKey("directory_count_limit"), "Directory count truncation cannot look complete");
        Throws<ArgumentException>(() => Ext4Recovery.Recover(image, Path.Combine(results, "invalid-directory-limit"), CancellationToken.None, null, null, new Ext4Recovery.Limits { MaximumDirectoryBytes = -1 }), "Negative directory work budget rejected");
        Run(image, "invalid-offset", out report, new long[] { -512, 1, long.MaxValue });
        Assert(report.RecoveredFiles == 0 && report.Skipped["invalid_partition_offset"] == 3, "Invalid offsets do not wrap arithmetic or touch a device");
        Assert(Hash(image) == before, "Cancellation and failures preserve source");
    }
    public static int Main(string[] args)
    {
        try {
            fixtures = Path.GetFullPath(args.Length > 0 ? args[0] : ".build/ext4-fixtures-01");
            results = Path.GetFullPath(args.Length > 1 ? args[1] : ".build/ext4-tests-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
            if (Directory.Exists(results)) throw new IOException("New result directory required"); Directory.CreateDirectory(results);
            Cases(); Safety();
            Console.WriteLine("PASS Ext4Recovery: " + assertions + " assertions; real e2fsprogs fixtures, checksums, extents/indirect, Unicode, allocation conflicts, no guessed sparse/unwritten bytes, bounds and cancellation. " + results);
            return 0;
        } catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
