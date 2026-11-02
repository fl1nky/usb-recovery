// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class RefsRecoveryTests
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

    static RefsRecovery.Report Report(string folder)
    {
        return Json.Deserialize<RefsRecovery.Report>(File.ReadAllText(Path.Combine(folder, "refs", "report.json")));
    }

    static string Output(string folder, RefsRecovery.Entry entry)
    {
        return Path.Combine(folder, "refs", entry.Output.Replace('/', Path.DirectorySeparatorChar));
    }

    static string Run(string image, string name, out RefsRecovery.Report report, IEnumerable<long> offsets = null, RefsRecovery.Limits limits = null)
    {
        string destination = Path.Combine(results, name);
        RefsRecovery.Recover(image, destination, CancellationToken.None, null, offsets, limits);
        report = Report(destination);
        return destination;
    }

    static void Cases()
    {
        var manifest = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(fixtures, "manifest.json")));
        foreach (Dictionary<string, object> sample in (IEnumerable)manifest["cases"])
        {
            string name = (string)sample["name"];
            string image = Path.Combine(fixtures, (string)sample["image"]);
            string before = Hash(image);
            Assert(before == (string)sample["sha256"], name + ": synthetic input matches recorded manifest");
            File.SetAttributes(image, File.GetAttributes(image) | FileAttributes.ReadOnly);

            RefsRecovery.Report report;
            string folder = Run(image, name, out report);

            Assert(report.SourceUnchanged && report.SourceSha256 == before && Hash(image) == before, name + ": input bytes unchanged");
            Assert(!report.Failed && !report.Cancelled, name + ": scan completed without failure");
            Assert(!Directory.GetFiles(folder, "*.partial", SearchOption.AllDirectories).Any(), name + ": no .partial output remains");
            Assert(report.Entries.All(x => !x.ContentAuthenticityVerified), name + ": metadata checksum is never claimed to authenticate historical data");

            string outcome = (string)sample["outcome"];
            if (outcome == "recover")
            {
                Assert(report.RecoveredFiles >= 1, name + ": files successfully recovered");
                Assert(report.Entries.Where(e => e.Output != null && e.Status == "recovered_live").All(e => e.MetadataChecksumVerified), name + ": live metadata chain verified");
                if (sample.ContainsKey("expected_version"))
                {
                    Assert(report.Capabilities.ReFSVersion == (string)sample["expected_version"], name + ": ReFS version matches expected");
                }

                if (sample.ContainsKey("target_name"))
                {
                    string targetName = (string)sample["target_name"];
                    var entry = report.Entries.FirstOrDefault(x => x.Name == targetName);
                    Assert(entry != null, name + ": target entry found: " + targetName);
                    string outPath = Output(folder, entry);
                    Assert(File.Exists(outPath), name + ": extracted file exists");
                    Assert(Hash(outPath) == (string)sample["payload_sha256"], name + ": exact payload SHA256 match");

                    if (sample.ContainsKey("expected_path"))
                    {
                        Assert(entry.RelativePath == (string)sample["expected_path"], name + ": hierarchical path reconstructed");
                    }

                    // Check extent byte provenance
                    if (!entry.IsResident && entry.Extents.Count > 0)
                    {
                        using (var actual = File.OpenRead(outPath))
                        using (var source = File.OpenRead(image))
                        {
                            foreach (var ext in entry.Extents)
                            {
                                byte[] a = new byte[ext.Length];
                                byte[] b = new byte[ext.Length];
                                actual.Position = ext.LogicalOffset;
                                source.Position = ext.ImageOffset;
                                Assert(actual.Read(a, 0, a.Length) == a.Length && source.Read(b, 0, b.Length) == b.Length && a.SequenceEqual(b), name + ": exact source range provenance");
                            }
                        }
                    }
                }

                if (name == "refs-backup-vbr")
                {
                    Assert(report.Capabilities.BackupVbrUsed, name + ": backup VBR fallback reported");
                }
                if (name == "refs-checkpoint-pingpong")
                {
                    Assert(report.Capabilities.CheckpointIndexUsed == 1, name + ": highest sequence clock checkpoint arbitrated");
                }
            }
            else if (outcome == "reject")
            {
                Assert(report.RecoveredFiles == 0, name + ": rejected metadata cannot reappear as unchecked salvage");
                if (name == "refs-corrupted-crc")
                {
                    Assert(report.Warnings.Any(w => w.Contains("metadata_checksum_mismatch")), name + ": corrupted CRC rejected");
                }
                if (name == "refs-unsupported-compression")
                {
                    Assert(report.Capabilities.CompressionDetected, name + ": compression detected");
                    Assert(report.Capabilities.UnsupportedFeatures.Contains("cluster_compression"), name + ": cluster_compression recorded in unsupported features");
                    Assert(report.Entries.Any(e => e.Status == "unsupported_feature" && e.Reason == "unsupported_compression"), name + ": compression entry marked unsupported");
                }
            }
            else if (outcome == "salvage")
            {
                Assert(report.Entries.Any(e => e.Status == "unreferenced_refs_candidate"), name + ": unreferenced candidate found");
                var salvaged = report.Entries.First(e => e.Status == "unreferenced_refs_candidate");
                Assert(salvaged.DeletionEvidence == null && !salvaged.MetadataChecksumVerified, name + ": no invented deletion or checksum proof");
                string outPath = Output(folder, salvaged);
                Assert(File.Exists(outPath) && Hash(outPath) == (string)sample["payload_sha256"], name + ": salvaged payload hash matches");
            }
        }
    }

    static void Safety()
    {
        string image = Path.Combine(fixtures, "refs-v314-minimal.dd");
        string before = Hash(image);

        // Pre-cancellation
        var cancelled = new CancellationToken(true);
        string pre = Path.Combine(results, "pre-cancelled");
        Throws<OperationCanceledException>(() => RefsRecovery.Recover(image, pre, cancelled, null), "Pre-cancellation honored");
        Assert(!Directory.Exists(Path.Combine(pre, "refs")), "Pre-cancelled does not create report");

        // Existing directory
        string existing = Path.Combine(results, "refs-v314-minimal");
        Throws<IOException>(() => RefsRecovery.Recover(image, existing, CancellationToken.None, null), "Existing result directory blocked");

        // Output budget limit
        RefsRecovery.Report report;
        Run(image, "bounded-output", out report, null, new RefsRecovery.Limits { MaximumOutputBytes = 5 });
        Assert(report.Limited && report.Skipped.ContainsKey("output_limit"), "Output budget enforced");

        // Invalid partition offset
        Run(image, "invalid-offset", out report, new long[] { -512, 1, long.MaxValue });
        Assert(report.RecoveredFiles == 0 && report.Skipped["invalid_partition_offset"] == 3, "Invalid offsets rejected safely");

        Assert(Hash(image) == before, "Cancellation and safety preserve source");
    }

    static void NativeMetadata()
    {
        var manifest=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(fixtures,"native_metadata.json")));
        Type geometry=typeof(RefsRecovery).GetNestedType("VolumeGeometry",BindingFlags.NonPublic);
        MethodInfo self=typeof(RefsRecovery).GetMethod("VerifySelfChecksum",BindingFlags.NonPublic|BindingFlags.Static);
        MethodInfo parse=typeof(RefsRecovery).GetMethod("ParseBlockReference",BindingFlags.NonPublic|BindingFlags.Static);
        foreach(Dictionary<string,object> item in (IEnumerable)manifest["fixtures"])
        {
            string file=Path.Combine(fixtures,(string)item["file"]), kind=(string)item["kind"];
            byte version=Convert.ToByte(item["version"]);
            Assert(Hash(file)==(string)item["sha256"],"Independent primary metadata bytes pinned: "+kind+version);
            byte[] data=File.ReadAllBytes(file);
            if(kind=="block_reference")
            {
                object reference=parse.Invoke(null,new object[]{data,0,version});
                Type t=reference.GetType();
                Assert((bool)t.GetField("DescriptorValid").GetValue(reference),"Native descriptor accepted");
                Assert((ulong)t.GetField("BlockNumber").GetValue(reference)==30,"Native reference block 30");
                Assert((ulong)t.GetField("ExpectedChecksum").GetValue(reference)==(version==1?0xc4e1de0a46e65f5dUL:0x68befbe2UL),"Native checksum at descriptor-relative offset eight");
            }
            else
            {
                object g=Activator.CreateInstance(geometry,true);
                geometry.GetField("MajorVersion").SetValue(g,version);
                int h=version==1?48:80;
                uint offset=BitConverter.ToUInt32(data,h+(kind=="superblock"?40:8));
                uint size=BitConverter.ToUInt32(data,h+(kind=="superblock"?44:12));
                ulong number=BitConverter.ToUInt64(data,version==1?0:32);
                Assert((bool)self.Invoke(null,new object[]{data,g,offset,size,number}),"Unmodified native self-checksum matches: "+kind+version);
                data[data.Length-1]^=1;
                Assert(!(bool)self.Invoke(null,new object[]{data,g,offset,size,number}),"Native metadata bit corruption rejected: "+kind+version);
            }
        }
    }

    public static int Main(string[] args)
    {
        try
        {
            fixtures = Path.GetFullPath(args.Length > 0 ? args[0] : ".build/refs-fixtures-current");
            results = Path.GetFullPath(args.Length > 1 ? args[1] : ".build/refs-tests-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
            if (Directory.Exists(results)) throw new IOException("New result directory required");
            Directory.CreateDirectory(results);

            Cases();
            Safety();
            NativeMetadata();
            byte[] crcCheck = Encoding.ASCII.GetBytes("123456789");
            Assert(RefsRecovery.ComputeCrc32c(crcCheck, 0, crcCheck.Length) == 0xe3069283U, "CRC32C catalogue check vector");
            Assert(RefsRecovery.ComputeCrc64Nvme(crcCheck, 0, crcCheck.Length) == 0xae8b14860a799888UL, "CRC64/NVME catalogue check vector");

            Console.WriteLine("PASS RefsRecovery: " + assertions + " assertions on synthetic structures and pinned independent native metadata; full-volume evidence is separate. " + results);
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }
}
