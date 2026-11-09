using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public static class CommandLineHandler
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AttachConsole(int dwProcessId);

        const int ATTACH_PARENT_PROCESS = -1;

        public static bool IsCliCommand(string[] args)
        {
            if (args == null || args.Length == 0) return false;
            string first = args[0].ToLowerInvariant();
            if (first == "--document-preview-worker" || first == "--local-media-preview-worker" || first == "--media-decode-worker")
                return false;

            return first == "--help" || first == "-h" || first == "/?" || first == "help"
                || first == "--version" || first == "-v" || first == "version"
                || first == "probe" || first == "scan" || first == "gallery" || first == "serve";
        }

        public static int Run(string[] args)
        {
            try
            {
                AttachConsole(ATTACH_PARENT_PROCESS);
            }
            catch { }

            if (args == null || args.Length == 0)
            {
                PrintHelp();
                return 0;
            }

            string command = args[0].ToLowerInvariant();
            switch (command)
            {
                case "--help":
                case "-h":
                case "/?":
                case "help":
                    PrintHelp();
                    return 0;

                case "--version":
                case "-v":
                case "version":
                    PrintVersion();
                    return 0;

                case "probe":
                    return ExecuteProbe(args);

                case "scan":
                    return ExecuteScan(args);

                case "gallery":
                    return ExecuteGallery(args);

                case "serve":
                    return ExecuteServe(args);

                default:
                    Console.Error.WriteLine("Error: Unknown command '{0}'. Run 'USB-Recovery.exe --help' for usage.", args[0]);
                    return 2;
            }
        }

        public static void PrintVersion()
        {
            Console.WriteLine("USB-Recovery v2026.11 (x64)");
            Console.WriteLine("Copyright (C) 2026 USB-Recovery Contributors");
            Console.WriteLine("License: GNU Affero General Public License v3.0 (AGPL-3.0)");
            Console.WriteLine("https://github.com/fl1nky/usb-recovery");
            Console.WriteLine("100% Free & Open Source · Zero Telemetry · Offline Forensic Architecture");
        }

        public static void PrintHelp()
        {
            Console.WriteLine("USB-Recovery — High-Performance Forensic Data Recovery Suite");
            Console.WriteLine();
            Console.WriteLine("Usage: USB-Recovery.exe [command] [options]");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  probe <image_path>             Inspect disk image, partition table and filesystem types");
            Console.WriteLine("  scan  <image_path> -o <dir>    Execute non-interactive recovery scan on disk image");
            Console.WriteLine("  serve <image_path>             Launch interactive local Web-UI with Cluster Map & Hex Inspector");
            Console.WriteLine("  gallery <directory>            Generate HTML photo gallery catalog from recovered files");
            Console.WriteLine("  --version, -v                  Display version, license, and build information");
            Console.WriteLine("  --help, -h                     Display this help message");
            Console.WriteLine();
            Console.WriteLine("Scan Options:");
            Console.WriteLine("  -o, --output <directory>       Required. Destination folder for recovered files and report");
            Console.WriteLine("  --mode <full|fast|photos|media|archives>");
            Console.WriteLine("                                 Recovery mode profile (default: full)");
            Console.WriteLine("                                   full:     All filesystems, signatures, fragmented media, archives");
            Console.WriteLine("                                   fast:     Metadata-only scan (NTFS, FAT, ext4, ReFS, APFS)");
            Console.WriteLine("                                   photos:   Deep fragmented photo reconstruction (JPEG, PNG)");
            Console.WriteLine("                                   media:    Photo and video stream carving (MP4, MOV, HEVC, AAC)");
            Console.WriteLine("                                   archives: Central-directory and fragmented archive salvage (ZIP)");
            Console.WriteLine("  --fs <auto|all|ntfs|fat|ext4|refs|apfs>");
            Console.WriteLine("                                 Specific filesystem metadata parser (default: all)");
            Console.WriteLine("  --ddrescue-map <mapfile>       Import GNU ddrescue mapfile to focus carving on rescued sectors");
            Console.WriteLine("  -p, --port <port>              Port for local Web-UI server (default: 8080)");
            Console.WriteLine("  --open-browser                 Automatically open web browser on startup");
            Console.WriteLine("  --checksum <sha256_file>       Path to .sha256 verification file (auto-generated if missing)");
            Console.WriteLine("  --json                         Output scan events and final summary in JSON format");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  USB-Recovery.exe probe C:\\images\\usb_stick.raw");
            Console.WriteLine("  USB-Recovery.exe scan C:\\images\\disk.raw -o C:\\recovered --mode full");
            Console.WriteLine("  USB-Recovery.exe scan C:\\images\\hfs_volume.img -o C:\\recovered --fs apfs");
        }

        static int ExecuteProbe(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Missing target image path. Usage: USB-Recovery.exe probe <image_path>");
                return 2;
            }

            string image = Path.GetFullPath(args[1]);
            if (!File.Exists(image))
            {
                Console.Error.WriteLine("Error: Source image file not found: {0}", image);
                return 1;
            }

            bool json = args.Any(a => string.Equals(a, "--json", StringComparison.OrdinalIgnoreCase));

            try
            {
                var fileInfo = new FileInfo(image);
                long length = fileInfo.Length;
                Console.WriteLine("Probing storage image: {0} ({1:N0} bytes, {2:F2} MB)", image, length, (double)length / (1024 * 1024));

                var candidates = BootScout.Find(image, CancellationToken.None, (done, total) => { });
                Console.WriteLine("Found {0} partition candidate(s):", candidates.Count);
                for (int i = 0; i < candidates.Count; i++)
                {
                    var c = candidates[i];
                    Console.WriteLine("  [{0}] Offset: {1:N0} (0x{1:X}), Length: {2:N0} bytes ({3:F2} MB), Type: {4}, Origin: {5}",
                        i + 1, c.Offset, c.Length, (double)c.Length / (1024 * 1024), c.Kind, c.Origin);
                }

                // Check for RAID superblocks
                var raidReport = RaidMetadataProbe.Probe(new[] { image }, CancellationToken.None);
                if (raidReport != null && raidReport.Members != null && raidReport.Members.Count > 0)
                {
                    var raidMember = raidReport.Members[0];
                    if (raidMember.Status != "not_found")
                    {
                        Console.WriteLine("RAID Metadata Detected: Format={0}, Level={1}, Status={2}, UUID={3}",
                            raidMember.Format, raidMember.Level, raidMember.Status, raidMember.Uuid);
                    }
                }

                if (json)
                {
                    var serializer = new JavaScriptSerializer();
                    var probeObj = new
                    {
                        image = image,
                        size = length,
                        partitions = candidates,
                        raid = raidReport != null && raidReport.Members != null && raidReport.Members.Count > 0 && raidReport.Members[0].Status != "not_found" ? raidReport.Members[0] : null
                    };
                    Console.WriteLine(serializer.Serialize(probeObj));
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during probe: {0}", ex.Message);
                return 1;
            }
        }

        static int ExecuteScan(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Missing parameters. Usage: USB-Recovery.exe scan <image_path> -o <output_dir> [options]");
                return 2;
            }

            string image = Path.GetFullPath(args[1]);
            if (!File.Exists(image))
            {
                Console.Error.WriteLine("Error: Source image file not found: {0}", image);
                return 1;
            }

            string outputDir = null;
            string mode = "full";
            string fs = "all";
            string checksumFile = null;
            string ddrescueMapFile = null;
            bool json = false;

            for (int i = 2; i < args.Length; i++)
            {
                string a = args[i];
                if ((a == "-o" || a == "--output") && i + 1 < args.Length)
                {
                    outputDir = Path.GetFullPath(args[++i]);
                }
                else if (a == "--mode" && i + 1 < args.Length)
                {
                    mode = args[++i].ToLowerInvariant();
                }
                else if (a == "--fs" && i + 1 < args.Length)
                {
                    fs = args[++i].ToLowerInvariant();
                }
                else if (a == "--checksum" && i + 1 < args.Length)
                {
                    checksumFile = Path.GetFullPath(args[++i]);
                }
                else if (a == "--ddrescue-map" && i + 1 < args.Length)
                {
                    ddrescueMapFile = Path.GetFullPath(args[++i]);
                }
                else if (a == "--json")
                {
                    json = true;
                }
            }

            if (string.IsNullOrEmpty(outputDir))
            {
                Console.Error.WriteLine("Error: Output directory is required. Specify with -o <dir> or --output <dir>.");
                return 2;
            }

            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            if (!string.IsNullOrEmpty(ddrescueMapFile))
            {
                if (!File.Exists(ddrescueMapFile))
                {
                    Console.Error.WriteLine("Error: ddrescue mapfile not found: {0}", ddrescueMapFile);
                    return 1;
                }
                var map = DdrescueMap.Load(ddrescueMapFile);
                if (!json)
                {
                    Console.WriteLine("Loaded ddrescue mapfile: {0} blocks, rescued={1:N0} bytes, bad={2:N0} bytes",
                        map.Blocks.Count, map.TotalRescuedBytes, map.TotalBadBytes);
                }
            }

            // Auto-generate or verify sha256 checksum
            if (string.IsNullOrEmpty(checksumFile))
            {
                string defaultSha = image + ".sha256";
                if (File.Exists(defaultSha))
                {
                    checksumFile = defaultSha;
                }
                else
                {
                    checksumFile = Path.Combine(outputDir, Path.GetFileName(image) + ".sha256");
                    if (!File.Exists(checksumFile))
                    {
                        Console.WriteLine("Computing initial SHA-256 integrity hash for {0}...", Path.GetFileName(image));
                        string hash = ComputeFileSha256(image);
                        File.WriteAllText(checksumFile, hash + " *" + Path.GetFileName(image) + "\r\n", Encoding.UTF8);
                        Console.WriteLine("Integrity hash recorded: {0}", hash);
                    }
                }
            }

            var options = BuildOptions(mode, fs);
            options.Validate();

            Console.WriteLine("Starting USB-Recovery scan:");
            Console.WriteLine("  Image:  {0}", image);
            Console.WriteLine("  Output: {0}", outputDir);
            Console.WriteLine("  Mode:   {0}", mode);
            Console.WriteLine("  FS:     {0}", fs);

            try
            {
                var cancelSource = new CancellationTokenSource();
                Console.CancelKeyPress += (sender, e) =>
                {
                    e.Cancel = true;
                    Console.WriteLine("\nCancellation requested by user. Finalizing checkpoints...");
                    cancelSource.Cancel();
                };

                var scanResult = RecoveryPipeline.Run(
                    image,
                    outputDir,
                    options,
                    cancelSource.Token,
                    progressMsg =>
                    {
                        if (!json)
                        {
                            Console.WriteLine("[PROGRESS] {0}", progressMsg);
                        }
                    },
                    checksumFile,
                    activity =>
                    {
                        if (json)
                        {
                            var s = new JavaScriptSerializer();
                            Console.WriteLine(s.Serialize(new
                            {
                                type = "activity",
                                key = activity.Key,
                                title = activity.Title,
                                state = activity.State,
                                completed = activity.Completed,
                                total = activity.Total,
                                candidates = activity.Candidates
                            }));
                        }
                    });

                Console.WriteLine();
                Console.WriteLine("Scan completed successfully!");
                Console.WriteLine("  Candidates Found:   {0}", scanResult.Candidates);
                Console.WriteLine("  Unique Files Saved: {0}", scanResult.UniqueFiles);
                Console.WriteLine("  Resumed Stages:     {0}", scanResult.ResumedStages);
                if (scanResult.HasWarnings)
                {
                    Console.WriteLine("  Warnings: Some stages encountered non-fatal issues (see logs in output dir).");
                }

                if (json)
                {
                    var s = new JavaScriptSerializer();
                    Console.WriteLine(s.Serialize(new
                    {
                        status = "success",
                        candidates = scanResult.Candidates,
                        uniqueFiles = scanResult.UniqueFiles,
                        resumedStages = scanResult.ResumedStages,
                        hasWarnings = scanResult.HasWarnings,
                        output = outputDir
                    }));
                }

                return 0;
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("\nScan cancelled. Intermediate session state preserved.");
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("\nError during recovery scan: {0}", ex.Message);
                return 1;
            }
        }

        static int ExecuteGallery(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Missing target directory. Usage: USB-Recovery.exe gallery <directory>");
                return 2;
            }

            string dir = Path.GetFullPath(args[1]);
            if (!Directory.Exists(dir))
            {
                Console.Error.WriteLine("Error: Directory not found: {0}", dir);
                return 1;
            }

            try
            {
                string galleryPath = Program.WriteGallery(dir);
                Console.WriteLine("Gallery catalog generated: {0}", galleryPath);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error generating gallery: {0}", ex.Message);
                return 1;
            }
        }

        static RecoveryOptions BuildOptions(string mode, string fs)
        {
            var options = new RecoveryOptions();

            switch (mode)
            {
                case "fast":
                    options.Signatures = false;
                    options.Photos = false;
                    options.Video = false;
                    options.Audio = false;
                    options.Documents = false;
                    options.Archives = false;
                    options.Other = false;
                    options.EmbeddedPhotos = false;
                    options.Containers = false;
                    options.SmallBlocks = false;
                    options.FatMetadata = true;
                    options.NtfsMetadata = true;
                    options.Ext4Metadata = true;
                    options.RefsMetadata = true;
                    options.ApfsMetadata = true;
                    break;

                case "photos":
                    options.Photos = true;
                    options.FragmentedPhotos = true;
                    options.EmbeddedPhotos = true;
                    options.JpegFragments = true;
                    options.Video = false;
                    options.Audio = false;
                    options.Documents = false;
                    options.Archives = false;
                    options.Other = false;
                    break;

                case "media":
                    options.Photos = true;
                    options.Video = true;
                    options.Audio = true;
                    options.FragmentedPhotos = true;
                    options.FragmentedVideo = true;
                    options.EmbeddedPhotos = true;
                    options.JpegFragments = true;
                    options.Documents = false;
                    options.Archives = false;
                    options.Other = false;
                    break;

                case "archives":
                    options.Archives = true;
                    options.ArchiveMembers = true;
                    options.FragmentedArchives = true;
                    options.Photos = false;
                    options.Video = false;
                    options.Audio = false;
                    options.Documents = false;
                    options.Other = false;
                    break;

                case "full":
                default:
                    options.FatMetadata = true;
                    options.NtfsMetadata = true;
                    options.Ext4Metadata = true;
                    options.RefsMetadata = true;
                    options.ApfsMetadata = true;
                    options.LostPartitions = true;
                    options.Signatures = true;
                    options.SmallBlocks = true;
                    options.EmbeddedPhotos = true;
                    options.Containers = true;
                    options.MetadataRescue = true;
                    options.ArchiveMembers = true;
                    options.FragmentedArchives = true;
                    options.FragmentedPhotos = true;
                    options.FragmentedVideo = true;
                    options.JpegFragments = true;
                    break;
            }

            if (fs == "apfs")
            {
                options.FatMetadata = false;
                options.NtfsMetadata = false;
                options.Ext4Metadata = false;
                options.RefsMetadata = false;
                options.ApfsMetadata = true;
            }
            else if (fs == "refs")
            {
                options.FatMetadata = false;
                options.NtfsMetadata = false;
                options.Ext4Metadata = false;
                options.RefsMetadata = true;
                options.ApfsMetadata = false;
            }
            else if (fs == "ext4")
            {
                options.FatMetadata = false;
                options.NtfsMetadata = false;
                options.Ext4Metadata = true;
                options.RefsMetadata = false;
                options.ApfsMetadata = false;
            }
            else if (fs == "ntfs")
            {
                options.FatMetadata = false;
                options.NtfsMetadata = true;
                options.Ext4Metadata = false;
                options.RefsMetadata = false;
                options.ApfsMetadata = false;
            }
            else if (fs == "fat")
            {
                options.FatMetadata = true;
                options.NtfsMetadata = false;
                options.Ext4Metadata = false;
                options.RefsMetadata = false;
                options.ApfsMetadata = false;
            }

            return options;
        }

        static string ComputeFileSha256(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4 * 1024 * 1024))
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(stream);
                var sb = new StringBuilder(64);
                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }
        static int ExecuteServe(string[] args)
        {
            if (args.Length < 2 || args[1].StartsWith("-"))
            {
                Console.Error.WriteLine("Error: Missing image file path for serve command.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe serve <image_path> [-p|--port <port>] [-o|--output <dir>] [--open-browser]");
                return 1;
            }

            string image = Path.GetFullPath(args[1]);
            if (!File.Exists(image))
            {
                Console.Error.WriteLine("Error: Disk image file does not exist: {0}", image);
                return 1;
            }

            int port = 8080;
            string output = Path.Combine(Directory.GetCurrentDirectory(), "recovered");
            bool openBrowser = false;

            for (int i = 2; i < args.Length; i++)
            {
                string opt = args[i].ToLowerInvariant();
                if ((opt == "-p" || opt == "--port") && i + 1 < args.Length)
                {
                    int p; if (int.TryParse(args[++i], out p) && p > 0 && p < 65536) port = p;
                }
                else if ((opt == "-o" || opt == "--output") && i + 1 < args.Length)
                {
                    output = Path.GetFullPath(args[++i]);
                }
                else if (opt == "--open-browser")
                {
                    openBrowser = true;
                }
            }

            try
            {
                using (var server = new LocalWebServer(image, output, port))
                {
                    server.Start();
                    string url = string.Format(System.Globalization.CultureInfo.InvariantCulture, "http://127.0.0.1:{0}/", server.Port);

                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Forensic Web Dashboard & Interactive Cluster Map");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Local Web-UI:    {0}", url);
                    Console.WriteLine("  Security:        100% Offline · Strictly bound to 127.0.0.1 (Loopback)");
                    Console.WriteLine("  Target Image:    {0} ({1:N0} bytes)", Path.GetFileName(image), new FileInfo(image).Length);
                    Console.WriteLine("  Output Folder:   {0}", output);
                    Console.WriteLine("--------------------------------------------------------------------------------");
                    Console.WriteLine("  Dashboard Features:");
                    Console.WriteLine("   * Sector / Cluster Allocation Map (visual density canvas)");
                    Console.WriteLine("   * Live Data & Hex Inspector (Data types, Windows FILETIME, Unix time, GUID)");
                    Console.WriteLine("   * Partition Hierarchy & Storage Layout Viewer");
                    Console.WriteLine("   * Real-time Scan Progress & Recovered File Browser");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("Press Ctrl+C or Enter in this terminal to stop the server...");

                    if (openBrowser)
                    {
                        try { System.Diagnostics.Process.Start(url); } catch { }
                    }

                    var wait = new ManualResetEvent(false);
                    Console.CancelKeyPress += (s, e) => { e.Cancel = true; wait.Set(); };
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        try { Console.ReadLine(); } catch { }
                        wait.Set();
                    });

                    wait.WaitOne();
                    Console.WriteLine("Stopping USB-Recovery local web server...");
                    server.Stop();
                    Console.WriteLine("Server stopped.");
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error launching Web-UI server: {0}", ex.Message);
                return 1;
            }
        }
    }
}
