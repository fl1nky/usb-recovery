using System;
using System.IO;
using System.Text;
using UsbRecovery;

public static class CommandLineTests
{
    static int checks;

    static void Check(bool condition, string description)
    {
        checks++;
        if (!condition) throw new Exception(description);
    }

    public static int Main(string[] args)
    {
        string work = Path.Combine(Path.GetTempPath(), "cli-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);

        try
        {
            // 1. Detection tests
            Check(!CommandLineHandler.IsCliCommand(null), "null args is not CLI command");
            Check(!CommandLineHandler.IsCliCommand(new string[0]), "empty args is not CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "--help" }), "--help is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "-h" }), "-h is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "/?" }), "/? is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "help" }), "help is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "--version" }), "--version is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "-v" }), "-v is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "probe" }), "probe is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "scan" }), "scan is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "gallery" }), "gallery is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "serve" }), "serve is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "salvage-office" }), "salvage-office is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "salvage-raw" }), "salvage-raw is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "btrfs-scout" }), "btrfs-scout is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "xfs-scout" }), "xfs-scout is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "zfs-scout" }), "zfs-scout is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "registry" }), "registry is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "usn" }), "usn is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "carve-mft" }), "carve-mft is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "timeline" }), "timeline is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "f2fs-scout" }), "f2fs-scout is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "exfat-scout" }), "exfat-scout is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "hfs-scout" }), "hfs-scout is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "srum" }), "srum is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "jumplist" }), "jumplist is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "recycle-bin" }), "recycle-bin is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "amcache" }), "amcache is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "shellbags" }), "shellbags is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "entropy" }), "entropy is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "court-report" }), "court-report is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "benchmark" }), "benchmark is CLI command");
            Check(CommandLineHandler.IsCliCommand(new[] { "lnk" }), "lnk is CLI command");

            // Worker commands must not be treated as regular CLI commands
            Check(!CommandLineHandler.IsCliCommand(new[] { "--document-preview-worker" }), "document preview worker bypass");
            Check(!CommandLineHandler.IsCliCommand(new[] { "--local-media-preview-worker" }), "local media preview worker bypass");
            Check(!CommandLineHandler.IsCliCommand(new[] { "--media-decode-worker" }), "media decode worker bypass");

            // 2. Help and Version execution
            Check(CommandLineHandler.Run(new[] { "--help" }) == 0, "run --help returns 0");
            Check(CommandLineHandler.Run(new[] { "-h" }) == 0, "run -h returns 0");
            Check(CommandLineHandler.Run(new[] { "--version" }) == 0, "run --version returns 0");
            Check(CommandLineHandler.Run(new[] { "-v" }) == 0, "run -v returns 0");

            // 3. Error handling
            Check(CommandLineHandler.Run(new[] { "nonexistent_command" }) == 2, "unknown command returns 2");
            Check(CommandLineHandler.Run(new[] { "probe" }) == 2, "probe without target returns 2");
            Check(CommandLineHandler.Run(new[] { "probe", Path.Combine(work, "missing.raw") }) == 1, "probe missing file returns 1");
            Check(CommandLineHandler.Run(new[] { "scan" }) == 2, "scan without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "scan", Path.Combine(work, "missing.raw"), "-o", work }) == 1, "scan missing file returns 1");
            Check(CommandLineHandler.Run(new[] { "gallery" }) == 2, "gallery without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "gallery", Path.Combine(work, "missing_dir") }) == 1, "gallery missing dir returns 1");
            Check(CommandLineHandler.Run(new[] { "serve" }) == 1, "serve without arguments returns 1");
            Check(CommandLineHandler.Run(new[] { "serve", Path.Combine(work, "missing.raw") }) == 1, "serve missing file returns 1");
            Check(CommandLineHandler.Run(new[] { "salvage-office" }) == 1, "salvage-office without arguments returns 1");
            Check(CommandLineHandler.Run(new[] { "salvage-office", Path.Combine(work, "missing.raw") }) == 1, "salvage-office missing file returns 1");
            Check(CommandLineHandler.Run(new[] { "salvage-raw" }) == 2, "salvage-raw without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "salvage-raw", Path.Combine(work, "missing.raw") }) == 2, "salvage-raw missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "btrfs-scout" }) == 2, "btrfs-scout without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "btrfs-scout", Path.Combine(work, "missing.raw") }) == 2, "btrfs-scout missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "xfs-scout" }) == 2, "xfs-scout without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "xfs-scout", Path.Combine(work, "missing.raw") }) == 2, "xfs-scout missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "zfs-scout" }) == 2, "zfs-scout without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "zfs-scout", Path.Combine(work, "missing.raw") }) == 2, "zfs-scout missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "registry" }) == 2, "registry without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "registry", Path.Combine(work, "missing.raw") }) == 2, "registry missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "usn" }) == 2, "usn without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "usn", Path.Combine(work, "missing.raw") }) == 2, "usn missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "carve-mft" }) == 2, "carve-mft without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "carve-mft", Path.Combine(work, "missing.raw") }) == 2, "carve-mft missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "timeline" }) == 2, "timeline without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "timeline", Path.Combine(work, "missing.raw") }) == 2, "timeline missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "f2fs-scout" }) == 2, "f2fs-scout without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "f2fs-scout", Path.Combine(work, "missing.raw") }) == 2, "f2fs-scout missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "exfat-scout" }) == 2, "exfat-scout without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "exfat-scout", Path.Combine(work, "missing.raw") }) == 2, "exfat-scout missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "hfs-scout" }) == 2, "hfs-scout without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "hfs-scout", Path.Combine(work, "missing.raw") }) == 2, "hfs-scout missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "srum" }) == 2, "srum without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "srum", Path.Combine(work, "missing.raw") }) == 2, "srum missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "jumplist" }) == 2, "jumplist without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "jumplist", Path.Combine(work, "missing.raw") }) == 2, "jumplist missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "recycle-bin" }) == 2, "recycle-bin without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "recycle-bin", Path.Combine(work, "missing.raw") }) == 2, "recycle-bin missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "amcache" }) == 2, "amcache without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "amcache", Path.Combine(work, "missing.raw") }) == 2, "amcache missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "shellbags" }) == 2, "shellbags without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "shellbags", Path.Combine(work, "missing.raw") }) == 2, "shellbags missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "entropy" }) == 2, "entropy without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "entropy", Path.Combine(work, "missing.raw") }) == 2, "entropy missing file returns 2");
            Check(CommandLineHandler.Run(new[] { "court-report" }) == 2, "court-report without arguments returns 2");
            Check(CommandLineHandler.Run(new[] { "court-report", Path.Combine(work, "missing.raw") }) == 2, "court-report missing file returns 2");

            // 4. Synthetic probe test
            string syntheticImage = Path.Combine(work, "synthetic_probe.raw");
            byte[] imageBytes = new byte[1024 * 1024]; // 1MB
            // Write MBR signature at offset 510
            imageBytes[510] = 0x55;
            imageBytes[511] = 0xAA;
            // Write a simple FAT32 boot sector at sector 0
            imageBytes[0] = 0xEB; imageBytes[1] = 0x58; imageBytes[2] = 0x90;
            Encoding.ASCII.GetBytes("MSDOS5.0").CopyTo(imageBytes, 3);
            BitConverter.GetBytes((ushort)512).CopyTo(imageBytes, 11); // Bytes per sector
            imageBytes[13] = 8; // Sectors per cluster
            BitConverter.GetBytes((ushort)32).CopyTo(imageBytes, 14); // Reserved sectors
            imageBytes[16] = 2; // FAT copies
            BitConverter.GetBytes((uint)2048).CopyTo(imageBytes, 32); // Total sectors 32
            BitConverter.GetBytes((uint)64).CopyTo(imageBytes, 36); // Sectors per FAT 32
            Encoding.ASCII.GetBytes("FAT32   ").CopyTo(imageBytes, 82);

            File.WriteAllBytes(syntheticImage, imageBytes);

            int probeResult = CommandLineHandler.Run(new[] { "probe", syntheticImage });
            Check(probeResult == 0, "probe on synthetic image returns 0");

            int probeJsonResult = CommandLineHandler.Run(new[] { "probe", syntheticImage, "--json" });
            Check(probeJsonResult == 0, "probe with --json returns 0");

            // Entropy execution test
            Check(CommandLineHandler.Run(new[] { "entropy", syntheticImage, "--json" }) == 0, "entropy execution on synthetic image returns 0");

            // Court report execution test
            string courtReportOut = Path.Combine(work, "court_report_test.html");
            Check(CommandLineHandler.Run(new[] { "court-report", syntheticImage, "-o", courtReportOut }) == 0, "court-report execution returns 0");
            Check(File.Exists(courtReportOut), "court report HTML file exists");

            // Benchmark execution test
            Check(CommandLineHandler.Run(new[] { "benchmark", "--mb", "4", "--json" }) == 0, "benchmark execution returns 0");
            Check(CommandLineHandler.Run(new[] { "lnk" }) == 2, "lnk without args returns 2");
            Check(CommandLineHandler.Run(new[] { "lnk", Path.Combine(work, "missing.lnk") }) == 2, "lnk missing file returns 2");

            string dummyJumpList = Path.Combine(work, "test.automaticDestinations-ms");
            File.WriteAllBytes(dummyJumpList, new byte[512]);
            Check(CommandLineHandler.Run(new[] { "jumplist", dummyJumpList }) == 0, "jumplist execution returns 0");
            Check(CommandLineHandler.Run(new[] { "jumplist", dummyJumpList, "--json" }) == 0, "jumplist --json returns 0");

            string dummyRecycle = Path.Combine(work, "$I123456.txt");
            File.WriteAllBytes(dummyRecycle, new byte[544]);
            Check(CommandLineHandler.Run(new[] { "recycle-bin", dummyRecycle }) == 0, "recycle-bin execution returns 0");
            Check(CommandLineHandler.Run(new[] { "recycle-bin", dummyRecycle, "--json" }) == 0, "recycle-bin --json returns 0");

            // 5. salvage-office execution test
            string syntheticDoc = Path.Combine(work, "damaged_office.raw");
            byte[] docXml = Encoding.UTF8.GetBytes("<w:document><w:body><w:p><w:t>CLI Salvage Verified</w:t></w:p></w:body></w:document>");
            byte[] samplePkg = OfficeXmlSalvage.BuildRepairedZipPackage(OfficeDocumentKind.WordDocx, new[] { new OfficeSalvagePart("word/document.xml", docXml, false, "application/xml") });
            File.WriteAllBytes(syntheticDoc, samplePkg);
            string officeOut = Path.Combine(work, "office_out");
            Check(CommandLineHandler.Run(new[] { "salvage-office", syntheticDoc, "-o", officeOut, "--json" }) == 0, "salvage-office execution returns 0");
            Check(File.Exists(Path.Combine(officeOut, "salvaged_document.docx")), "salvaged docx exists");
            Check(File.Exists(Path.Combine(officeOut, "extracted_text.txt")), "extracted text exists");
            Check(File.ReadAllText(Path.Combine(officeOut, "extracted_text.txt")).Contains("CLI Salvage Verified"), "extracted text matches");

            Console.WriteLine("PASS CommandLine: {0} checks; CLI options, probe, scan and version dispatch verified.", checks);
            return 0;
        }
        finally
        {
            try { Directory.Delete(work, true); } catch { }
        }
    }
}
