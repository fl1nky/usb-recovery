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
