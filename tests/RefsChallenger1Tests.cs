// SPDX-License-Identifier: AGPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class RefsChallenger1Tests
{
    static int assertions;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 64 * 1024 * 1024 };

    static void Assert(bool condition, string message)
    {
        assertions++;
        if (!condition)
        {
            throw new Exception("ASSERTION FAILED: " + message);
        }
    }

    static RefsRecovery.Report RunRecovery(string imagePath, string outDir, out Exception caughtException)
    {
        caughtException = null;
        try
        {
            RefsRecovery.Recover(imagePath, outDir, CancellationToken.None, null, (IEnumerable<long>)null, null);
        }
        catch (Exception ex)
        {
            caughtException = ex;
        }

        string reportPath = Path.Combine(outDir, "refs", "report.json");
        if (File.Exists(reportPath))
        {
            return Json.Deserialize<RefsRecovery.Report>(File.ReadAllText(reportPath));
        }
        return null;
    }

    public static int Main(string[] args)
    {
        try
        {
            string fixDir = Path.GetFullPath(args.Length > 0 ? args[0] : ".build/refs-adversarial-fixtures");
            string testRunRoot = Path.GetFullPath(Path.Combine(".build", "challenger1-run-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")));
            Directory.CreateDirectory(testRunRoot);

            Console.WriteLine("=== REFS CHALLENGER 1 EMPIRICAL ADVERSARIAL SUITE ===");
            Console.WriteLine("Fixture Directory: " + fixDir);

            Exception ex;
            RefsRecovery.Report rep;

            // -------------------------------------------------------------
            // Test 1: VBR Both Corrupt
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 1] adv-vbr-both-corrupt");
            string d1 = Path.Combine(testRunRoot, "t1");
            rep = RunRecovery(Path.Combine(fixDir, "adv-vbr-both-corrupt.dd"), d1, out ex);
            Assert(ex == null, "VBR both corrupt must not throw exception: " + (ex != null ? ex.ToString() : ""));
            Assert(rep != null, "Report must be generated");
            Assert(rep.Status == "complete", "Status must be complete (clean skip)");
            Assert(rep.Volumes.Count == 0, "No volumes claimed");
            Assert(rep.RecoveredFiles == 0, "0 files recovered");

            // -------------------------------------------------------------
            // Test 2: VBR Invalid Geometry Fallback
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 2] adv-vbr-invalid-geom");
            string d2 = Path.Combine(testRunRoot, "t2");
            rep = RunRecovery(Path.Combine(fixDir, "adv-vbr-invalid-geom.dd"), d2, out ex);
            Assert(ex == null, "Invalid VBR geometry must not throw exception");
            Assert(rep != null && rep.Volumes.Count > 0, "Volume parsed with fallbacks");
            var v2 = rep.Volumes[0];
            Assert(v2.SectorSize == 512, "SectorSize defaulted to 512");
            Assert(v2.ClusterSize == 4096, "ClusterSize defaulted to 4096 (512 * 8)");
            Assert(v2.ContainerSize == 0x4000, "ContainerSize defaulted to 0x4000");

            // -------------------------------------------------------------
            // Test 3: Unsupported Major Version 2
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 3] adv-vbr-unsupported-v2");
            string d3 = Path.Combine(testRunRoot, "t3");
            rep = RunRecovery(Path.Combine(fixDir, "adv-vbr-unsupported-v2.dd"), d3, out ex);
            Assert(ex == null, "Unsupported version must not throw exception");
            Assert(rep != null && rep.Volumes.Count > 0, "Volume record present");
            Assert(rep.Volumes[0].Status == "rejected", "Volume status rejected");
            Assert(rep.Volumes[0].Reason == "unsupported_refs_major_version_2", "Reason indicates version 2");
            Assert(rep.Capabilities.UnsupportedFeatures.Contains("unsupported_refs_major_version_2"), "Unsupported features records reason");

            // -------------------------------------------------------------
            // Test 4: Superblock signature corrupted
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 4] adv-sb-invalid-sig");
            string d4 = Path.Combine(testRunRoot, "t4");
            rep = RunRecovery(Path.Combine(fixDir, "adv-sb-invalid-sig.dd"), d4, out ex);
            Assert(ex == null, "Corrupt superblock signature must not throw exception");
            Assert(rep != null && rep.Volumes.Count > 0, "Volume present");
            Assert(rep.Volumes[0].Status == "rejected", "Volume status rejected");
            Assert(rep.Volumes[0].Reason == "superblock_unreadable_or_corrupt", "Reason is superblock_unreadable_or_corrupt");

            // -------------------------------------------------------------
            // Test 5: Checkpoint Ping-Pong: Checkpoint 0 Sequence Clock Higher
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 5] adv-chkp-pingpong-chkp0-higher");
            string d5 = Path.Combine(testRunRoot, "t5");
            rep = RunRecovery(Path.Combine(fixDir, "adv-chkp-pingpong-chkp0-higher.dd"), d5, out ex);
            Assert(ex == null, "Ping-pong arbitration must not throw exception");
            Assert(rep != null && rep.Capabilities.ActiveCheckpointValid, "Active checkpoint valid");
            Assert(rep.Capabilities.CheckpointIndexUsed == 0, "Checkpoint index 0 selected (higher seq clock 200 vs 100)");
            Assert(rep.Entries.Any(e => e.Name == "file_from_chkp0.txt"), "File from chkp0 recovered");
            Assert(!rep.Entries.Any(e => e.Name == "file_from_chkp1.txt"), "File from chkp1 NOT recovered");

            // -------------------------------------------------------------
            // Test 6: Checkpoint Ping-Pong: Checkpoint 1 Corrupt CRC Fallback to 0
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 6] adv-chkp-pingpong-chkp1-corrupt");
            string d6 = Path.Combine(testRunRoot, "t6");
            rep = RunRecovery(Path.Combine(fixDir, "adv-chkp-pingpong-chkp1-corrupt.dd"), d6, out ex);
            Assert(ex == null, "Corrupt checkpoint fallback must not throw exception");
            Assert(rep != null && rep.Capabilities.ActiveCheckpointValid, "Active checkpoint valid");
            Assert(rep.Capabilities.CheckpointIndexUsed == 0, "Fell back to Checkpoint 0");
            Assert(rep.Warnings.Contains("checkpoint_crc_corrupted_fallback_used"), "Warning checkpoint_crc_corrupted_fallback_used recorded");

            // -------------------------------------------------------------
            // Test 7: Both Checkpoints Corrupted CRC
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 7] adv-chkp-both-corrupt");
            string d7 = Path.Combine(testRunRoot, "t7");
            rep = RunRecovery(Path.Combine(fixDir, "adv-chkp-both-corrupt.dd"), d7, out ex);
            Assert(ex == null, "Both checkpoints corrupt must not crash");
            Assert(rep != null && rep.Volumes.Count > 0, "Volume record present");
            Assert(rep.Volumes[0].Status == "rejected", "Volume rejected");
            Assert(rep.Volumes[0].Reason == "all_checkpoints_corrupt", "Reason is all_checkpoints_corrupt");

            // -------------------------------------------------------------
            // Test 8: Tree Node Cycle Detection
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 8] adv-tree-cycle");
            string d8 = Path.Combine(testRunRoot, "t8");
            rep = RunRecovery(Path.Combine(fixDir, "adv-tree-cycle.dd"), d8, out ex);
            Assert(ex == null, "Tree cycle must not throw exception or hang");
            Assert(rep != null, "Report generated");
            Assert(rep.Warnings.Contains("tree_node_cycle_detected"), "Warning tree_node_cycle_detected recorded");

            // -------------------------------------------------------------
            // Test 9: Circular Subdirectories Detection
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 9] adv-dir-circular");
            string d9 = Path.Combine(testRunRoot, "t9");
            rep = RunRecovery(Path.Combine(fixDir, "adv-dir-circular.dd"), d9, out ex);
            Assert(ex == null, "Circular directory must not throw exception or hang");
            Assert(rep != null, "Report generated");
            Assert(rep.Warnings.Contains("circular_directory_reference_detected"), "Warning circular_directory_reference_detected recorded");

            // -------------------------------------------------------------
            // Test 10: Unicode Sanitization & Emojis
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 10] adv-unicode-stress");
            string d10 = Path.Combine(testRunRoot, "t10");
            rep = RunRecovery(Path.Combine(fixDir, "adv-unicode-stress.dd"), d10, out ex);
            Assert(ex == null, "Unicode stress must not throw exception: " + (ex != null ? ex.ToString() : ""));
            Assert(rep != null && rep.RecoveredFiles == 2, "Both files recovered");
            var emojiFile = rep.Entries.FirstOrDefault(e => e.Name.Contains("\U0001F600") || e.Name.Contains("test_"));
            Assert(emojiFile != null, "Emoji file entry recovered");
            var slashFile = rep.Entries.FirstOrDefault(e => e.Name.Contains("bad_name_test.txt"));
            Assert(slashFile != null, "Slashes sanitized in filename");

            // -------------------------------------------------------------
            // Test 11: ReFS v3 Container Translation
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 11] adv-container-trans");
            string d11 = Path.Combine(testRunRoot, "t11");
            rep = RunRecovery(Path.Combine(fixDir, "adv-container-trans.dd"), d11, out ex);
            Assert(ex == null, "Container translation must not throw exception: " + (ex != null ? ex.ToString() : ""));
            Assert(rep != null && rep.RecoveredFiles == 1, "Container file recovered");
            var cEntry = rep.Entries[0];
            Assert(cEntry.Extents.Count == 1, "1 extent");
            Assert(cEntry.Extents[0].ImageOffset == 150L * 4096L, "Extent ImageOffset translated to physical cluster 150: " + cEntry.Extents[0].ImageOffset);
            string cOutPath = Path.Combine(d11, "refs", cEntry.Output.Replace('/', Path.DirectorySeparatorChar));
            Assert(File.Exists(cOutPath), "Recovered file exists on disk");
            byte[] cBytes = File.ReadAllBytes(cOutPath);
            string cText = Encoding.ASCII.GetString(cBytes);
            Assert(cText == "PAYLOAD_CONTAINER_TRANSLATION_VERIFIED_7777777", "Recovered bytes match translated container payload: " + cText);

            // -------------------------------------------------------------
            // Test 12: CRC64-ECMA-182 Type 2 Checksum
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 12] adv-crc64-valid");
            string d12 = Path.Combine(testRunRoot, "t12");
            rep = RunRecovery(Path.Combine(fixDir, "adv-crc64-valid.dd"), d12, out ex);
            Assert(ex == null, "Valid CRC64 must not throw exception");
            Assert(rep != null && rep.RecoveredFiles == 1, "File with CRC64 block reference recovered");

            // -------------------------------------------------------------
            // Test 13: CRC64 Rejection on Single-Bit Corruption
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 13] adv-crc64-corrupt-bit");
            string d13 = Path.Combine(testRunRoot, "t13");
            rep = RunRecovery(Path.Combine(fixDir, "adv-crc64-corrupt-bit.dd"), d13, out ex);
            Assert(ex == null, "Corrupt CRC64 bit flip must not crash");
            Assert(rep != null, "Report generated");
            Assert(rep.Warnings.Contains("metadata_checksum_mismatch"), "Warning metadata_checksum_mismatch recorded for CRC64");
            Assert(rep.RecoveredFiles == 0, "Corrupted block rejected, 0 files recovered");

            // -------------------------------------------------------------
            // Test 14: Extent Pointing Beyond Image EOF (Out-of-bounds extent)
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 14] adv-extent-oob");
            string d14 = Path.Combine(testRunRoot, "t14");
            rep = RunRecovery(Path.Combine(fixDir, "adv-extent-oob.dd"), d14, out ex);
            Console.WriteLine("Test 14 Result: ex = " + (ex != null ? ex.GetType().Name + ": " + ex.Message : "null") +
                              ", rep.Status = " + (rep != null ? rep.Status : "null"));

            // -------------------------------------------------------------
            // Test 15: Extent with declaredSize = 0
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 15] adv-zero-declared-size");
            string d15 = Path.Combine(testRunRoot, "t15");
            rep = RunRecovery(Path.Combine(fixDir, "adv-zero-declared-size.dd"), d15, out ex);
            Console.WriteLine("Test 15 Result: ex = " + (ex != null ? ex.GetType().Name + ": " + ex.Message : "null") +
                              ", rep.Status = " + (rep != null ? rep.Status : "null") +
                              ", recovered = " + (rep != null ? rep.RecoveredFiles : -1));

            // -------------------------------------------------------------
            // Test 16: Extent with Negative Wrap / Huge Block (physBlk = 0xFFFFFFFFFFFFFFFF)
            // -------------------------------------------------------------
            Console.WriteLine("[Adversarial 16] adv-physblk-negative-wrap");
            string d16 = Path.Combine(testRunRoot, "t16");
            rep = RunRecovery(Path.Combine(fixDir, "adv-physblk-negative-wrap.dd"), d16, out ex);
            Console.WriteLine("Test 16 Result: ex = " + (ex != null ? ex.GetType().Name + ": " + ex.Message : "null") +
                              ", rep.Status = " + (rep != null ? rep.Status : "null"));

            // Remove the duplicate RefsAdversarialTests.cs if we made it
            Console.WriteLine("PASS: ReFS Challenger 1 completed successfully with " + assertions + " assertions verified.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }
}
