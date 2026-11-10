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
                || first == "probe" || first == "scan" || first == "gallery" || first == "serve" || first == "salvage-office" || first == "salvage-raw" || first == "btrfs-scout" || first == "xfs-scout" || first == "zfs-scout";
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

                case "salvage-office":
                    return ExecuteSalvageOffice(args);

                case "salvage-raw":
                    return ExecuteSalvageRaw(args);

                case "btrfs-scout":
                    return ExecuteBtrfsScout(args);

                case "xfs-scout":
                    return ExecuteXfsScout(args);

                case "zfs-scout":
                    return ExecuteZfsScout(args);

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
            Console.WriteLine("  probe <image_path>             Inspect disk image (.raw, .dd, .img, .E01), partition table and filesystems");
            Console.WriteLine("  scan  <image_path> -o <dir>    Execute non-interactive recovery scan on disk image");
            Console.WriteLine("  serve <image_path>             Launch interactive local Web-UI with Cluster Map & Hex Inspector (.raw, .E01)");
            Console.WriteLine("  salvage-office <file_or_image> Salvage damaged DOCX, XLSX, PPTX, ODT documents & extract text");
            Console.WriteLine("  salvage-raw <path>             Carve & inspect camera RAW photos (CR2/CR3, NEF, ARW, DNG, RAF)");
            Console.WriteLine("  btrfs-scout <image_path>       Forensic Btrfs metadata scout, chunk mapping & file extent recovery");
            Console.WriteLine("  xfs-scout <image_path>         Forensic XFS metadata scout, AG superblocks & BMBT extent recovery");
            Console.WriteLine("  zfs-scout <image_path>         Forensic ZFS pool scout, uberblocks & dnode object traversal");
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
                E01Metadata e01Meta = null;
                if (E01ImageReader.IsE01File(image))
                {
                    try
                    {
                        using (var e01 = E01ImageReader.Open(image))
                        {
                            e01Meta = e01.Metadata;
                            length = e01.Length;
                        }
                    }
                    catch { }
                }

                Console.WriteLine("Probing storage image: {0} ({1:N0} bytes, {2:F2} MB)", image, length, (double)length / (1024 * 1024));
                if (e01Meta != null)
                {
                    Console.WriteLine("Expert Witness Format (.E01) Detected: Segments={0}, Sectors={1:N0}, ChunkSize={2} KiB",
                        e01Meta.TotalSegments, e01Meta.TotalSectors, e01Meta.ChunkSize / 1024);
                    if (!String.IsNullOrEmpty(e01Meta.CaseNumber) || !String.IsNullOrEmpty(e01Meta.Examiner))
                    {
                        Console.WriteLine("  Case: {0}, Evidence: {1}, Examiner: {2}", e01Meta.CaseNumber, e01Meta.EvidenceNumber, e01Meta.Examiner);
                    }
                    if (!String.IsNullOrEmpty(e01Meta.StoredMd5))
                    {
                        Console.WriteLine("  Acquisition Hash (MD5): {0}", e01Meta.StoredMd5);
                    }
                }

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

                // Check for Btrfs superblocks
                List<BtrfsScout.BtrfsSuperblock> btrfsSbs = null;
                try
                {
                    using (var fs = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        btrfsSbs = BtrfsScout.ProbeSuperblocks(fs);
                    }
                }
                catch { }

                if (btrfsSbs != null && btrfsSbs.Count > 0)
                {
                    Console.WriteLine("Btrfs Superblock Detected: UUID={0}, Label={1}, Generation={2}, Superblocks={3}",
                        btrfsSbs[0].FsUuid, btrfsSbs[0].Label ?? "N/A", btrfsSbs[0].Generation, btrfsSbs.Count);
                }

                // Check for XFS superblocks
                List<XfsScout.XfsSuperblock> xfsSbs = null;
                try
                {
                    using (var fs = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        xfsSbs = XfsScout.ProbeSuperblocks(fs);
                    }
                }
                catch { }

                if (xfsSbs != null && xfsSbs.Count > 0)
                {
                    Console.WriteLine("XFS Superblock Detected: UUID={0}, Label={1}, AGCount={2}, BlockSize={3}",
                        xfsSbs[0].FsUuid, xfsSbs[0].Label ?? "N/A", xfsSbs[0].AgCount, xfsSbs[0].BlockSize);
                }

                // Check for ZFS uberblocks
                List<ZfsScout.ZfsUberblock> zfsUbs = null;
                try
                {
                    using (var fs = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        zfsUbs = ZfsScout.ProbeUberblocks(fs);
                    }
                }
                catch { }

                if (zfsUbs != null && zfsUbs.Count > 0)
                {
                    Console.WriteLine("ZFS Uberblocks Detected: Count={0}, MaxTXG={1}, Timestamp={2}",
                        zfsUbs.Count, zfsUbs[0].Txg, zfsUbs[0].TimestampUtc);
                }

                if (json)
                {
                    var serializer = new JavaScriptSerializer();
                    var probeObj = new
                    {
                        image = image,
                        size = length,
                        e01 = e01Meta != null ? new { total_sectors = e01Meta.TotalSectors, chunk_size = e01Meta.ChunkSize, case_number = e01Meta.CaseNumber, examiner = e01Meta.Examiner, md5 = e01Meta.StoredMd5 } : null,
                        partitions = candidates,
                        raid = raidReport != null && raidReport.Members != null && raidReport.Members.Count > 0 && raidReport.Members[0].Status != "not_found" ? raidReport.Members[0] : null,
                        btrfs = btrfsSbs != null && btrfsSbs.Count > 0 ? new { uuid = btrfsSbs[0].FsUuid, label = btrfsSbs[0].Label, generation = btrfsSbs[0].Generation, count = btrfsSbs.Count } : null,
                        xfs = xfsSbs != null && xfsSbs.Count > 0 ? new { uuid = xfsSbs[0].FsUuid, label = xfsSbs[0].Label, ag_count = xfsSbs[0].AgCount, block_size = xfsSbs[0].BlockSize } : null,
                        zfs = zfsUbs != null && zfsUbs.Count > 0 ? new { count = zfsUbs.Count, max_txg = zfsUbs[0].Txg, timestamp = zfsUbs[0].TimestampUtc.ToString("o") } : null
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

        private static int ExecuteSalvageOffice(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: Missing target file or disk image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe salvage-office <file_or_image> [-o <output_dir>] [--json]");
                return 1;
            }

            string target = Path.GetFullPath(args[1]);
            if (!File.Exists(target))
            {
                Console.Error.WriteLine("Error: File or disk image does not exist: {0}", target);
                return 1;
            }

            string output = Path.Combine(Directory.GetCurrentDirectory(), "salvaged_office");
            bool json = false;

            for (int i = 2; i < args.Length; i++)
            {
                string opt = args[i].ToLowerInvariant();
                if ((opt == "-o" || opt == "--output") && i + 1 < args.Length)
                {
                    output = Path.GetFullPath(args[++i]);
                }
                else if (opt == "--json")
                {
                    json = true;
                }
            }

            try
            {
                Directory.CreateDirectory(output);
                OfficeSalvageResult result;

                using (FileStream fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    result = OfficeXmlSalvage.SalvageFromStream(fs, 0, fs.Length);
                }

                if (result.Kind == OfficeDocumentKind.Unknown || result.PartsRecovered == 0)
                {
                    if (json)
                    {
                        Console.WriteLine("{\"status\":\"not_found\",\"parts\":0,\"message\":\"No Office or OpenDocument XML structures discovered.\"}");
                    }
                    else
                    {
                        Console.WriteLine("No Office or OpenDocument XML structures discovered in {0}.", Path.GetFileName(target));
                    }
                    return 0;
                }

                string ext = ".docx";
                if (result.Kind == OfficeDocumentKind.ExcelXlsx) ext = ".xlsx";
                else if (result.Kind == OfficeDocumentKind.PowerPointPptx) ext = ".pptx";
                else if (result.Kind == OfficeDocumentKind.OpenDocumentText) ext = ".odt";
                else if (result.Kind == OfficeDocumentKind.OpenDocumentSpreadsheet) ext = ".ods";

                string recoveredDocPath = Path.Combine(output, "salvaged_document" + ext);
                if (result.ReconstructedPackage != null && result.ReconstructedPackage.Length > 0)
                {
                    File.WriteAllBytes(recoveredDocPath, result.ReconstructedPackage);
                }

                string textFilePath = Path.Combine(output, "extracted_text.txt");
                if (!String.IsNullOrEmpty(result.ExtractedText))
                {
                    File.WriteAllText(textFilePath, result.ExtractedText, Encoding.UTF8);
                }

                if (json)
                {
                    var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
                    var dto = new Dictionary<string, object>
                    {
                        { "status", "salvaged" },
                        { "kind", result.Kind.ToString() },
                        { "type_name", result.DetectedTypeName },
                        { "parts_recovered", result.PartsRecovered },
                        { "xml_repaired", result.HasRepairedXml },
                        { "package_path", recoveredDocPath },
                        { "package_bytes", result.ReconstructedPackage != null ? result.ReconstructedPackage.Length : 0 },
                        { "text_path", textFilePath },
                        { "text_length", result.ExtractedText != null ? result.ExtractedText.Length : 0 },
                        { "summary", result.PrimaryTextSummary }
                    };
                    Console.WriteLine(serializer.Serialize(dto));
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Office Open XML & Document Salvage Engine");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Detected Document: {0}", result.DetectedTypeName);
                    Console.WriteLine("  Surviving Parts:   {0} records recovered", result.PartsRecovered);
                    Console.WriteLine("  XML Balancing:     {0}", result.HasRepairedXml ? "Severed tags automatically closed & repaired" : "Intact");
                    Console.WriteLine("  Reconstructed Doc: {0} ({1:N0} bytes)", recoveredDocPath, result.ReconstructedPackage != null ? result.ReconstructedPackage.Length : 0);
                    Console.WriteLine("  Extracted Text:    {0} ({1:N0} characters)", textFilePath, result.ExtractedText != null ? result.ExtractedText.Length : 0);
                    if (!String.IsNullOrEmpty(result.PrimaryTextSummary))
                    {
                        Console.WriteLine("--------------------------------------------------------------------------------");
                        Console.WriteLine("  Document Preview:");
                        Console.WriteLine("  {0}", result.PrimaryTextSummary);
                    }
                    Console.WriteLine("================================================================================");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error salvaging Office document: {0}", ex.Message);
                return 1;
            }
        }

        private static int ExecuteSalvageRaw(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'salvage-raw' requires an input path (file, directory, or image).");
                Console.Error.WriteLine("Usage: USB-Recovery.exe salvage-raw <path> [-o <output_dir>] [--extract-previews] [--json]");
                return 2;
            }

            string target = args[1];
            string output = "salvaged_raw_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            bool json = false;
            bool extractPreviews = true;

            for (int i = 2; i < args.Length; i++)
            {
                string arg = args[i];
                if ((arg == "-o" || arg == "--output") && i + 1 < args.Length)
                {
                    output = args[++i];
                }
                else if (arg == "--json")
                {
                    json = true;
                }
                else if (arg == "--no-previews")
                {
                    extractPreviews = false;
                }
                else if (arg == "--extract-previews")
                {
                    extractPreviews = true;
                }
            }

            if (!File.Exists(target) && !Directory.Exists(target))
            {
                Console.Error.WriteLine("Error: Target path does not exist: {0}", target);
                return 2;
            }

            try
            {
                Directory.CreateDirectory(output);
                CameraRawRecovery.SalvageReport report = null;

                if (Directory.Exists(target))
                {
                    report = CameraRawRecovery.SalvageDirectory(target, output, extractPreviews, CancellationToken.None, null);
                }
                else
                {
                    using (var fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var meta = CameraRawRecovery.Inspect(fs);
                        if (meta != null && meta.Format != "Unknown")
                        {
                            report = CameraRawRecovery.SalvageDirectory(target, output, extractPreviews, CancellationToken.None, null);
                        }
                        else
                        {
                            var carved = CameraRawRecovery.Carve(fs, CancellationToken.None, null);
                            report = new CameraRawRecovery.SalvageReport
                            {
                                Status = "complete",
                                FilesInspected = 1,
                                RawFilesFound = carved.Count
                            };

                            string previewsDir = Path.Combine(output, "previews");
                            if (extractPreviews && carved.Count > 0) Directory.CreateDirectory(previewsDir);

                            for (int c = 0; c < carved.Count; c++)
                            {
                                var item = carved[c];
                                string baseName = string.Format("carved_raw_{0:D5}_{1}", c + 1, item.Format.Replace(" ", "_"));
                                string rawName = CameraRawRecovery.PublishOutput(output, baseName, ".raw", file =>
                                {
                                    fs.Seek(item.Offset, SeekOrigin.Begin);
                                    byte[] buffer = new byte[1024 * 1024];
                                    long remaining = item.Length;
                                    while (remaining > 0)
                                    {
                                        int read = fs.Read(buffer, 0, (int)Math.Min(remaining, buffer.Length));
                                        if (read == 0) throw new EndOfStreamException();
                                        file.Write(buffer, 0, read);
                                        remaining -= read;
                                    }
                                });

                                string prevPath = null;
                                if (extractPreviews && item.PreviewBytes != null && item.PreviewBytes.Length > 0)
                                {
                                    string previewName = CameraRawRecovery.PublishOutput(previewsDir, baseName, "-preview.jpg",
                                        file => file.Write(item.PreviewBytes, 0, item.PreviewBytes.Length));
                                    prevPath = Path.Combine("previews", previewName);
                                    report.PreviewsExtracted++;
                                }

                                report.Files.Add(new CameraRawRecovery.CarvedFileEntry
                                {
                                    SourceFile = Path.GetFileName(target),
                                    SourceOffset = item.Offset,
                                    FileBytes = item.Length,
                                    Format = item.Format,
                                    Make = item.Metadata != null ? item.Metadata.Make : null,
                                    Model = item.Metadata != null ? item.Metadata.Model : null,
                                    DateTimeOriginal = item.Metadata != null ? item.Metadata.DateTimeOriginal : null,
                                    OutputPath = rawName,
                                    PreviewPath = prevPath,
                                    PreviewBytes = item.PreviewBytes != null ? item.PreviewBytes.Length : 0
                                });
                            }

                            CameraRawRecovery.PublishReport(output, report);
                        }
                    }
                }

                if (json)
                {
                    var js = new System.Web.Script.Serialization.JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                    Console.WriteLine(js.Serialize(report));
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Professional Camera RAW Photo Recovery Engine");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Target:            {0}", target);
                    Console.WriteLine("  Output Directory:  {0}", output);
                    Console.WriteLine("  RAW Photos Found:  {0}", report.RawFilesFound);
                    Console.WriteLine("  Previews Carved:   {0}", report.PreviewsExtracted);
                    Console.WriteLine("--------------------------------------------------------------------------------");
                    foreach (var f in report.Files)
                    {
                        Console.WriteLine("  • [{0}] {1} (Make: {2}, Model: {3}, Date: {4})",
                            f.Format, f.SourceFile, f.Make ?? "Unknown", f.Model ?? "Unknown", f.DateTimeOriginal ?? "N/A");
                        if (!string.IsNullOrEmpty(f.PreviewPath))
                        {
                            Console.WriteLine("    ↳ Preview JPEG: {0} ({1:N0} bytes)", f.PreviewPath, f.PreviewBytes);
                        }
                    }
                    Console.WriteLine("================================================================================");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during Camera RAW salvage: {0}", ex.Message);
                return 1;
            }
        }

        private static int ExecuteBtrfsScout(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'btrfs-scout' requires an image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe btrfs-scout <image_path> [--json]");
                return 2;
            }

            string target = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(target))
            {
                Console.Error.WriteLine("Error: Target file not found: {0}", target);
                return 2;
            }

            try
            {
                using (var fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var result = BtrfsScout.Scout(fs, CancellationToken.None, null);

                    if (json)
                    {
                        var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                        Console.WriteLine(js.Serialize(result));
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — Btrfs Forensic Metadata Scout & Tree Traversal");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Status:            {0}", result.Status);
                        Console.WriteLine("  Superblocks:       {0} found", result.Superblocks.Count);
                        foreach (var sb in result.Superblocks)
                        {
                            Console.WriteLine("    ↳ Superblock at 0x{0:X}: UUID={1}, Gen={2}, Label='{3}', Chunks={4}",
                                sb.PhysicalOffset, sb.FsUuid, sb.Generation, sb.Label ?? "None", sb.SystemChunks.Count);
                        }
                        Console.WriteLine("  System Chunks:     {0} mappings", result.ChunkTable.Count);
                        Console.WriteLine("  Directories:       {0}", result.DirectoriesCount);
                        Console.WriteLine("  Files:             {0} ({1:N0} bytes recoverable)", result.FilesCount, result.TotalRecoverableBytes);
                        Console.WriteLine("--------------------------------------------------------------------------------");
                        Console.WriteLine("  Recovered File Hierarchy:");
                        int displayed = 0;
                        foreach (var f in result.Files)
                        {
                            if (displayed++ >= 50)
                            {
                                Console.WriteLine("  ... and {0} more files", result.Files.Count - 50);
                                break;
                            }
                            string typeStr = f.IsDirectory ? "<DIR>" : string.Format("{0,10:N0} B", f.Size);
                            Console.WriteLine("  {0,-14} {1} [Extents: {2}]", typeStr, f.FullPath, f.Extents.Count);
                        }
                        Console.WriteLine("================================================================================");
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during Btrfs scout: {0}", ex.Message);
                return 1;
            }
        }

        private static int ExecuteXfsScout(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'xfs-scout' requires an image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe xfs-scout <image_path> [--json]");
                return 2;
            }

            string target = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(target))
            {
                Console.Error.WriteLine("Error: Target file not found: {0}", target);
                return 2;
            }

            try
            {
                using (var fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var result = XfsScout.Scout(fs, CancellationToken.None, null);

                    if (json)
                    {
                        var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                        Console.WriteLine(js.Serialize(result));
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — XFS Allocation Group Metadata Scout & BMBT Traversal");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Status:            {0}", result.Status);
                        Console.WriteLine("  Superblocks:       {0} found", result.Superblocks.Count);
                        foreach (var sb in result.Superblocks)
                        {
                            Console.WriteLine("    ↳ AG {0} Superblock at 0x{1:X}: UUID={2}, Label='{3}', BlockSize={4}, AGBlocks={5}",
                                sb.AllocationGroup, sb.PhysicalOffset, sb.FsUuid, sb.Label ?? "None", sb.BlockSize, sb.AgBlocks);
                        }
                        Console.WriteLine("  Directories:       {0}", result.DirectoriesCount);
                        Console.WriteLine("  Files:             {0} ({1:N0} bytes recoverable)", result.FilesCount, result.TotalRecoverableBytes);
                        Console.WriteLine("--------------------------------------------------------------------------------");
                        Console.WriteLine("  Recovered File Hierarchy:");
                        int displayed = 0;
                        foreach (var f in result.Files)
                        {
                            if (displayed++ >= 50)
                            {
                                Console.WriteLine("  ... and {0} more files", result.Files.Count - 50);
                                break;
                            }
                            string typeStr = f.IsDirectory ? "<DIR>" : string.Format("{0,10:N0} B", f.Size);
                            Console.WriteLine("  {0,-14} {1} [Extents: {2}]", typeStr, f.FullPath, f.Extents.Count);
                        }
                        Console.WriteLine("================================================================================");
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during XFS scout: {0}", ex.Message);
                return 1;
            }
        }

        private static int ExecuteZfsScout(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'zfs-scout' requires an image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe zfs-scout <image_path> [--json]");
                return 2;
            }

            string target = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(target))
            {
                Console.Error.WriteLine("Error: Target file not found: {0}", target);
                return 2;
            }

            try
            {
                using (var fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var result = ZfsScout.Scout(fs, CancellationToken.None, null);

                    if (json)
                    {
                        var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                        Console.WriteLine(js.Serialize(result));
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — ZFS Pool Uberblock Scout & Block Pointer Traversal");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Status:            {0}", result.Status);
                        Console.WriteLine("  Uberblocks Found:  {0}", result.UberblocksFound);
                        if (result.ActiveUberblock != null)
                        {
                            var ub = result.ActiveUberblock;
                            Console.WriteLine("  Active Uberblock:  TXG={0}, Label={1}, Slot={2}, Offset=0x{3:X}, Time={4}",
                                ub.Txg, ub.VdevLabel, ub.SlotIndex, ub.PhysicalOffset, ub.TimestampUtc);
                            if (ub.RootBlockPointer != null)
                            {
                                Console.WriteLine("  Root BlockPointer: DVA Sector=0x{0:X}, ByteOffset=0x{1:X}, Alloc={2} B",
                                    ub.RootBlockPointer.DvaSectorOffset, ub.RootBlockPointer.PhysicalByteOffset, ub.RootBlockPointer.AllocatedBytes);
                            }
                        }
                        Console.WriteLine("  Directories:       {0}", result.DirectoriesCount);
                        Console.WriteLine("  Files:             {0} ({1:N0} bytes recoverable)", result.FilesCount, result.TotalRecoverableBytes);
                        Console.WriteLine("--------------------------------------------------------------------------------");
                        Console.WriteLine("  Recovered Object Set:");
                        int displayed = 0;
                        foreach (var f in result.Files)
                        {
                            if (displayed++ >= 50)
                            {
                                Console.WriteLine("  ... and {0} more files", result.Files.Count - 50);
                                break;
                            }
                            string typeStr = f.IsDirectory ? "<DIR>" : string.Format("{0,10:N0} B", f.FileSizeBytes);
                            Console.WriteLine("  {0,-14} {1} [Extents: {2}]", typeStr, f.FullPath, f.BlockExtents.Count);
                        }
                        Console.WriteLine("================================================================================");
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during ZFS scout: {0}", ex.Message);
                return 1;
            }
        }
    }
}
