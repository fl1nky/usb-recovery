using System.Globalization;
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
                || first == "probe" || first == "scan" || first == "gallery" || first == "serve" || first == "salvage-office" || first == "salvage-raw" || first == "btrfs-scout" || first == "xfs-scout" || first == "zfs-scout"
                || first == "registry" || first == "usn" || first == "carve-mft" || first == "timeline" || first == "f2fs-scout" || first == "exfat-scout" || first == "hfs-scout" || first == "srum" || first == "jumplist" || first == "amcache" || first == "shellbags" || first == "entropy" || first == "court-report" || first == "benchmark" || first == "lnk";
        }

        public static int Run(string[] args)
        {
            try
            {
                AttachConsole(ATTACH_PARENT_PROCESS);
                Console.OutputEncoding = System.Text.Encoding.UTF8;
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

                case "registry":
                    return ExecuteRegistry(args);

                case "usn":
                    return ExecuteUsn(args);

                case "carve-mft":
                    return ExecuteCarveMft(args);

                case "timeline":
                    return ExecuteTimeline(args);

                case "f2fs-scout":
                    return ExecuteF2fsScout(args);

                case "exfat-scout":
                    return ExecuteExFatScout(args);

                case "hfs-scout":
                    return ExecuteHfsPlusScout(args);

                case "srum":
                    return ExecuteSrum(args);

                case "jumplist":
                    return ExecuteJumpList(args);

                case "amcache":
                    return ExecuteAmcache(args);

                case "shellbags":
                    return ExecuteShellbags(args);

                case "entropy":
                    return ExecuteEntropy(args);

                case "court-report":
                    return ExecuteCourtReport(args);

                case "benchmark":
                    return ExecuteBenchmark(args);

                case "lnk":
                    return ExecuteLnk(args);

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
            Console.WriteLine("  f2fs-scout <image_path>        Flash-Friendly File System (F2FS) scout for mobile/NVMe flash storage");
            Console.WriteLine("  exfat-scout <image_path>       Forensic exFAT scout, deleted entry sets carving & recovery");
            Console.WriteLine("  hfs-scout <image_path>         Apple HFS+ / HFSX scout, catalog B-Tree traversal & carving");
            Console.WriteLine("  srum <path_or_image>           Windows SRUM database, network exfiltration & resource usage");
            Console.WriteLine("  jumplist <file_or_dir>         Windows Jump Lists parser (.automaticDestinations, .customDestinations)");
            Console.WriteLine("  amcache <hive_or_image>        Amcache.hve parser, PE execution forensics, SHA-1 & threat detection");
            Console.WriteLine("  shellbags <hive_or_file>       Windows Explorer Shellbags folder access & USB removable drive history");
            Console.WriteLine("  entropy <image_path>           Shannon entropy classifier, block profiling & ransomware detection");
            Console.WriteLine("  court-report <image_path>      Rule 902(14) Expert Witness court package with Chain of Custody hashes");
            Console.WriteLine("  benchmark [--mb <size>] [--json] Run high-speed forensic benchmark & zero-leak audit (SWAR, Entropy, MFT)");
            Console.WriteLine("  lnk <file_or_dir> [--json]     Parse Windows Shell Link (.lnk) shortcuts, target paths, MAC & serials");
            Console.WriteLine("  registry <hive_path>           Inspect Windows REGF registry hive, dump system summary, search, or carve");
            Console.WriteLine("  usn <image_or_drive>           Parse NTFS USN Change Journal ($UsnJrnl:$J) and reconstruct deleted files");
            Console.WriteLine("  carve-mft <image_path> -o <dir> Carve 1024-byte NTFS $MFT FILE records & extract resident payloads");
            Console.WriteLine("  timeline <source_or_dir>       Aggregate multi-source forensic super-timeline (USN, MFT, EVTX, Browser)");
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
            options.ReadMapPath = ddrescueMapFile;
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
                    options.UnknownNtfsAllocation = true;
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

        private static int ExecuteRegistry(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'registry' requires a hive file path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe registry <hive_path> [--summary] [--search <term>] [--carve] [--json]");
                return 2;
            }

            string target = args[1];
            bool summary = false;
            string searchTerm = null;
            bool carve = false;
            bool json = false;

            for (int i = 2; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--summary") summary = true;
                else if (arg == "--carve") carve = true;
                else if (arg == "--json") json = true;
                else if (arg == "--search" && i + 1 < args.Length) searchTerm = args[++i];
            }

            if (!File.Exists(target))
            {
                Console.Error.WriteLine("Error: Target hive file not found: {0}", target);
                return 2;
            }

            try
            {
                using (RegistryHive hive = RegistryHive.Open(target))
                {
                    if (carve)
                    {
                        List<RegistryKey> carvedKeys = hive.CarveDeletedKeys();
                        List<RegistryValue> carvedVals = hive.CarveDeletedValues();
                        if (json)
                        {
                            var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                            var dto = new Dictionary<string, object>
                            {
                                { "carved_keys_count", carvedKeys.Count },
                                { "carved_values_count", carvedVals.Count },
                                { "carved_keys", carvedKeys.Select(k => k.Path).ToList() }
                            };
                            Console.WriteLine(js.Serialize(dto));
                        }
                        else
                        {
                            Console.WriteLine("================================================================================");
                            Console.WriteLine("  USB-Recovery — REGF Registry Hive Deleted Cell Carver");
                            Console.WriteLine("================================================================================");
                            Console.WriteLine("  Source Hive:    {0}", target);
                            Console.WriteLine("  Carved Keys:    {0}", carvedKeys.Count);
                            Console.WriteLine("  Carved Values:  {0}", carvedVals.Count);
                            Console.WriteLine("--------------------------------------------------------------------------------");
                            int limit = Math.Min(carvedKeys.Count, 50);
                            for (int ci = 0; ci < limit; ci++)
                            {
                                Console.WriteLine("  Key: {0}", carvedKeys[ci].Path);
                            }
                            if (carvedKeys.Count > 50)
                            {
                                Console.WriteLine("  ... and {0} more carved keys", carvedKeys.Count - 50);
                            }
                            Console.WriteLine("================================================================================");
                        }
                        return 0;
                    }

                    if (summary)
                    {
                        RegistrySystemSummary sysSummary = hive.ExtractSystemSummary();
                        if (json)
                        {
                            var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                            Console.WriteLine(js.Serialize(sysSummary));
                        }
                        else
                        {
                            Console.WriteLine("================================================================================");
                            Console.WriteLine("  USB-Recovery — Windows Registry System Summary");
                            Console.WriteLine("================================================================================");
                            Console.WriteLine("  Computer Name:   {0}", sysSummary.ComputerName ?? "Unknown");
                            Console.WriteLine("  Product Name:    {0}", sysSummary.ProductName ?? "Unknown");
                            Console.WriteLine("  Current Version: {0}", sysSummary.CurrentVersion ?? "Unknown");
                            Console.WriteLine("  Current Build:   {0}", sysSummary.CurrentBuild ?? "Unknown");
                            Console.WriteLine("  Current Control: {0}", sysSummary.CurrentControlSet ?? "Unknown");
                            Console.WriteLine("  Timezone:        {0}", sysSummary.TimeZoneStandardName ?? "Unknown");
                            Console.WriteLine("  USB Devices:     {0} connected storage devices", sysSummary.UsbDevices.Count);
                            Console.WriteLine("  User Accounts:   {0} accounts", sysSummary.UserAccounts.Count);
                            Console.WriteLine("  Run Keys:        {0} auto-start items", sysSummary.RunKeys.Count);
                            Console.WriteLine("================================================================================");
                        }
                        return 0;
                    }

                    if (!string.IsNullOrEmpty(searchTerm))
                    {
                        List<RegistryKey> matchingKeys = hive.SearchKeys(searchTerm, true);
                        List<RegistryValue> matchingVals = hive.SearchValues(searchTerm);
                        if (json)
                        {
                            var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                            var dto = new Dictionary<string, object>
                            {
                                { "query", searchTerm },
                                { "matching_keys", matchingKeys.Select(k => k.Path).ToList() },
                                { "matching_values_count", matchingVals.Count }
                            };
                            Console.WriteLine(js.Serialize(dto));
                        }
                        else
                        {
                            Console.WriteLine("================================================================================");
                            Console.WriteLine("  USB-Recovery — Registry Search for '{0}'", searchTerm);
                            Console.WriteLine("================================================================================");
                            Console.WriteLine("  Matching Keys:   {0}", matchingKeys.Count);
                            Console.WriteLine("  Matching Values: {0}", matchingVals.Count);
                            Console.WriteLine("--------------------------------------------------------------------------------");
                            int limit = Math.Min(matchingKeys.Count, 50);
                            for (int ri = 0; ri < limit; ri++)
                            {
                                Console.WriteLine("  Key: {0}", matchingKeys[ri].Path);
                            }
                            if (matchingKeys.Count > 50)
                            {
                                Console.WriteLine("  ... and {0} more matches", matchingKeys.Count - 50);
                            }
                            Console.WriteLine("================================================================================");
                        }
                        return 0;
                    }

                    // Default info
                    if (json)
                    {
                        var js = new JavaScriptSerializer();
                        var dto = new Dictionary<string, object>
                        {
                            { "file", target },
                            { "root_key", hive.RootKey != null ? hive.RootKey.Name : "null" },
                            { "subkeys_count", hive.RootKey != null ? hive.RootKey.Subkeys.Count : 0 },
                            { "values_count", hive.RootKey != null ? hive.RootKey.Values.Count : 0 }
                        };
                        Console.WriteLine(js.Serialize(dto));
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — REGF Registry Hive Inspector");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Hive Path:     {0}", target);
                        Console.WriteLine("  Root Key:      {0}", hive.RootKey != null ? hive.RootKey.Name : "None");
                        Console.WriteLine("  Subkeys:       {0}", hive.RootKey != null ? hive.RootKey.Subkeys.Count : 0);
                        Console.WriteLine("  Values:        {0}", hive.RootKey != null ? hive.RootKey.Values.Count : 0);
                        Console.WriteLine("================================================================================");
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error inspecting registry hive: {0}", ex.Message);
                return 1;
            }
        }

        private static int ExecuteUsn(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'usn' requires a path to $UsnJrnl:$J or disk image.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe usn <target> [--deleted] [--timeline] [--json]");
                return 2;
            }

            string target = args[1];
            bool deletedOnly = false;
            bool timeline = false;
            bool json = false;

            for (int i = 2; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "--deleted") deletedOnly = true;
                else if (arg == "--timeline") timeline = true;
                else if (arg == "--json") json = true;
            }

            if (!File.Exists(target))
            {
                Console.Error.WriteLine("Error: Target USN journal file not found: {0}", target);
                return 2;
            }

            try
            {
                List<UsnRecord> records;
                using (FileStream fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    records = UsnJournalParser.ParseStream(fs, CancellationToken.None);
                }

                if (deletedOnly)
                {
                    List<UsnDeletedFileArtifact> deleted = UsnJournalParser.ExtractDeletedFiles(records);
                    if (json)
                    {
                        var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                        Console.WriteLine(js.Serialize(deleted));
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — NTFS USN Change Journal Deleted File Reconstructor");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Source:         {0}", target);
                        Console.WriteLine("  Deleted Files:  {0}", deleted.Count);
                        Console.WriteLine("--------------------------------------------------------------------------------");
                        int limit = Math.Min(deleted.Count, 50);
                        for (int di = 0; di < limit; di++)
                        {
                            UsnDeletedFileArtifact df = deleted[di];
                            Console.WriteLine("  {0:yyyy-MM-dd HH:mm:ss} | MFT #{1,-8} | {2}",
                                df.DeletionTimeUtc, df.FileReferenceNumber, df.FileName);
                        }
                        if (deleted.Count > 50)
                        {
                            Console.WriteLine("  ... and {0} more deleted files", deleted.Count - 50);
                        }
                        Console.WriteLine("================================================================================");
                    }
                    return 0;
                }

                if (json)
                {
                    var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                    Console.WriteLine(js.Serialize(records));
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — NTFS USN Change Journal Parser");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Source:         {0}", target);
                    Console.WriteLine("  Total Records:  {0:N0}", records.Count);
                    if (records.Count > 0)
                    {
                        Console.WriteLine("  Time Span:      {0:yyyy-MM-dd HH:mm:ss} .. {1:yyyy-MM-dd HH:mm:ss}",
                            records[0].TimeStampUtc, records[records.Count - 1].TimeStampUtc);
                    }
                    if (timeline)
                    {
                        Console.WriteLine("--------------------------------------------------------------------------------");
                        int limit = Math.Min(records.Count, 50);
                        for (int ri = 0; ri < limit; ri++)
                        {
                            UsnRecord rec = records[ri];
                            Console.WriteLine("  {0:yyyy-MM-dd HH:mm:ss} | MFT #{1,-8} | {2,-20} | {3}",
                                rec.TimeStampUtc, rec.FileReferenceNumber, rec.Reason, rec.FileName);
                        }
                        if (records.Count > 50)
                        {
                            Console.WriteLine("  ... and {0} more journal entries", records.Count - 50);
                        }
                    }
                    Console.WriteLine("================================================================================");
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error parsing USN change journal: {0}", ex.Message);
                return 1;
            }
        }

        private static int ExecuteCarveMft(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'carve-mft' requires an image or device path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe carve-mft <image_path> [-o <out_dir>] [--json]");
                return 2;
            }

            string target = args[1];
            string outDir = "carved_mft_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            bool json = false;

            for (int i = 2; i < args.Length; i++)
            {
                string arg = args[i];
                if ((arg == "-o" || arg == "--output") && i + 1 < args.Length) outDir = args[++i];
                else if (arg == "--json") json = true;
            }

            if (!File.Exists(target))
            {
                Console.Error.WriteLine("Error: Target image file not found: {0}", target);
                return 2;
            }

            try
            {
                Directory.CreateDirectory(outDir);
                List<MftFileRecord> records;
                using (FileStream fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    records = MftCarver.CarveFromStream(fs, CancellationToken.None);
                }

                int residentRecovered = 0;
                int timestompCount = 0;

                for (int ri = 0; ri < records.Count; ri++)
                {
                    MftFileRecord rec = records[ri];
                    if (rec.IsTimestomped) timestompCount++;

                    if (rec.ResidentData != null && rec.ResidentData.Length > 0)
                    {
                        string safeName = string.IsNullOrEmpty(rec.FileName) ? ("record_" + rec.RecordNumber + ".bin") : rec.FileName;
                        foreach (char inv in Path.GetInvalidFileNameChars())
                        {
                            safeName = safeName.Replace(inv, '_');
                        }
                        string destFile = Path.Combine(outDir, string.Format("MFT_{0}_{1}", rec.RecordNumber, safeName));
                        try
                        {
                            File.WriteAllBytes(destFile, rec.ResidentData);
                            residentRecovered++;
                        }
                        catch { }
                    }
                }

                if (json)
                {
                    var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                    var dto = new Dictionary<string, object>
                    {
                        { "status", "carved" },
                        { "records_carved", records.Count },
                        { "resident_files_extracted", residentRecovered },
                        { "timestomping_detected", timestompCount },
                        { "output_directory", outDir }
                    };
                    Console.WriteLine(js.Serialize(dto));
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — NTFS $MFT Record Carver & Resident Payload Extractor");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Source Image:           {0}", target);
                    Console.WriteLine("  FILE Records Carved:    {0:N0}", records.Count);
                    Console.WriteLine("  Resident Files Dumped:  {0:N0} (saved to '{1}')", residentRecovered, outDir);
                    Console.WriteLine("  Timestomping Anomalies: {0:N0}", timestompCount);
                    Console.WriteLine("================================================================================");
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error carving MFT records: {0}", ex.Message);
                return 1;
            }
        }

        private static int ExecuteTimeline(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'timeline' requires a source directory or file path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe timeline <source> [-o <timeline.csv>] [--from <yyyy-MM-dd>] [--to <yyyy-MM-dd>] [--filter <term>] [--json]");
                return 2;
            }

            string target = args[1];
            string outCsv = "forensic_timeline.csv";
            string filterTerm = null;
            DateTime? fromUtc = null;
            DateTime? toUtc = null;
            bool json = false;

            for (int i = 2; i < args.Length; i++)
            {
                string arg = args[i];
                if ((arg == "-o" || arg == "--output") && i + 1 < args.Length) outCsv = args[++i];
                else if (arg == "--filter" && i + 1 < args.Length) filterTerm = args[++i];
                else if (arg == "--json") json = true;
                else if (arg == "--from" && i + 1 < args.Length)
                {
                    DateTime dt;
                    if (DateTime.TryParse(args[++i], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out dt))
                        fromUtc = dt;
                }
                else if (arg == "--to" && i + 1 < args.Length)
                {
                    DateTime dt;
                    if (DateTime.TryParse(args[++i], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out dt))
                        toUtc = dt;
                }
            }

            if (!File.Exists(target) && !Directory.Exists(target))
            {
                Console.Error.WriteLine("Error: Target path not found: {0}", target);
                return 2;
            }

            try
            {
                ForensicTimeline timeline = new ForensicTimeline();

                if (File.Exists(target))
                {
                    if (target.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase))
                    {
                        timeline.AddEvtxRecords(EvtxParser.ParseFile(target));
                    }
                    else if (target.EndsWith(".pf", StringComparison.OrdinalIgnoreCase))
                    {
                        PrefetchArtifact pf = PrefetchParser.ParseFile(target);
                        if (pf != null) timeline.AddPrefetch(pf);
                    }
                    else
                    {
                        using (FileStream fs = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            timeline.AddUsnRecords(UsnJournalParser.ParseStream(fs, CancellationToken.None));
                        }
                    }
                }

                timeline.SortChronological(true);
                List<ForensicTimelineEvent> events = timeline.Events.ToList();
                if (fromUtc.HasValue && toUtc.HasValue)
                {
                    events = timeline.FilterByTimeRange(fromUtc.Value, toUtc.Value);
                }
                if (!string.IsNullOrEmpty(filterTerm))
                {
                    timeline = new ForensicTimeline();
                    foreach (ForensicTimelineEvent ev in events)
                    {
                        timeline.AddEvent(ev.TimeStampUtc, ev.Source, ev.Action, ev.TargetPath, ev.Description, ev.ExtraDetails);
                    }
                    events = timeline.FilterByKeyword(filterTerm);
                }

                using (FileStream outFs = new FileStream(outCsv, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    timeline.ExportToCsv(outFs);
                }

                if (json)
                {
                    var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                    Console.WriteLine(js.Serialize(events));
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Unified Forensic Super-Timeline Engine");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Source:        {0}", target);
                    Console.WriteLine("  Total Events:  {0:N0}", events.Count);
                    Console.WriteLine("  Exported File: {0}", outCsv);
                    Console.WriteLine("================================================================================");
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error generating forensic timeline: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // F2FS Scout Command
        // =========================================================================
        private static int ExecuteF2fsScout(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'f2fs-scout' requires an image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe f2fs-scout <image_path> [--json]");
                return 2;
            }

            string image = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(image))
            {
                Console.Error.WriteLine("Error: Image not found: {0}", image);
                return 2;
            }

            try
            {
                using (var fs = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var result = F2fsScout.Scout(fs, CancellationToken.None, null);
                    if (json)
                    {
                        Console.WriteLine(result.ToJson());
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — Flash-Friendly File System (F2FS) Metadata Scout");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Status:        {0}", result.Status);
                        Console.WriteLine("  Superblocks:   {0}", result.Superblocks.Count);
                        Console.WriteLine("  Directories:   {0:N0}", result.DirectoriesCount);
                        Console.WriteLine("  Files:         {0:N0}", result.FilesCount);
                        Console.WriteLine("  Recoverable:   {0:N0} bytes", result.TotalRecoverableBytes);
                        Console.WriteLine("================================================================================");
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during F2FS scout: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // =========================================================================
        // exFAT Command
        // =========================================================================
        private static int ExecuteExFatScout(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'exfat-scout' requires an image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe exfat-scout <image_path> [--json]");
                return 2;
            }

            string image = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(image))
            {
                Console.Error.WriteLine("Error: Image not found: {0}", image);
                return 2;
            }

            try
            {
                using (var fs = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var result = ExFatScout.Scout(fs, CancellationToken.None);
                    if (json)
                    {
                        Console.WriteLine(result.ToJson());
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — Forensic exFAT Filesystem Scout & Carver");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Status:          {0}", result.Status);
                        if (result.PrimaryBoot != null)
                        {
                            Console.WriteLine("  Volume Label:    {0}", string.IsNullOrEmpty(result.PrimaryBoot.VolumeLabel) ? "(none)" : result.PrimaryBoot.VolumeLabel);
                            Console.WriteLine("  Sector Size:     {0} bytes", result.PrimaryBoot.BytesPerSector);
                            Console.WriteLine("  Cluster Size:    {0} bytes", result.PrimaryBoot.ClusterSizeBytes);
                            Console.WriteLine("  VBR Checksum:    {0}", result.PrimaryBoot.IsChecksumValid ? "VALID" : "INVALID / UNVERIFIED");
                            Console.WriteLine("  Backup VBR:      {0}", result.BackupBoot != null ? "PRESENT" : "MISSING");
                        }
                        Console.WriteLine("  Active Files:    {0:N0}", result.TotalActiveCount);
                        Console.WriteLine("  Deleted Files:   {0:N0}", result.TotalDeletedCount);
                        Console.WriteLine("  Recoverable:     {0:N0} bytes", result.TotalRecoverableBytes);
                        Console.WriteLine("================================================================================");

                        if (result.DeletedFiles.Count > 0)
                        {
                            Console.WriteLine("Carved Deleted Files:");
                            int show = Math.Min(25, result.DeletedFiles.Count);
                            for (int i = 0; i < show; i++)
                            {
                                var df = result.DeletedFiles[i];
                                Console.WriteLine("  [{0}] {1,-32} {2,10:N0} bytes  Cluster: {3}  Contiguous: {4}",
                                    i + 1, df.Name, df.Size, df.FirstCluster, df.NoFatChain ? "YES" : "NO");
                            }
                            if (result.DeletedFiles.Count > show)
                            {
                                Console.WriteLine("  ... and {0} more deleted files.", result.DeletedFiles.Count - show);
                            }
                        }
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during exFAT scout: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // HFS+ Command
        // =========================================================================
        private static int ExecuteHfsPlusScout(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'hfs-scout' requires an image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe hfs-scout <image_path> [--json]");
                return 2;
            }

            string image = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(image))
            {
                Console.Error.WriteLine("Error: Image not found: {0}", image);
                return 2;
            }

            try
            {
                using (var fs = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var result = HfsPlusScout.Scout(fs, CancellationToken.None);
                    if (json)
                    {
                        Console.WriteLine(result.ToJson());
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — Forensic Apple HFS+ / HFSX Metadata Scout");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Status:          {0}", result.Status);
                        if (result.VolumeHeader != null)
                        {
                            Console.WriteLine("  Signature:       0x{0:X4} ({1})", result.VolumeHeader.Signature, result.VolumeHeader.Signature == 0x482B ? "HFS+" : "HFSX");
                            Console.WriteLine("  Block Size:      {0} bytes", result.VolumeHeader.BlockSize);
                            Console.WriteLine("  Total Blocks:    {0:N0} ({1:N0} bytes)", result.VolumeHeader.TotalBlocks, result.VolumeHeader.TotalVolumeBytes);
                            Console.WriteLine("  Free Blocks:     {0:N0}", result.VolumeHeader.FreeBlocks);
                            Console.WriteLine("  Created (UTC):   {0}", result.VolumeHeader.CreateTimeUtc != DateTime.MinValue ? result.VolumeHeader.CreateTimeUtc.ToString("yyyy-MM-dd HH:mm:ss") : "—");
                            Console.WriteLine("  Modified (UTC):  {0}", result.VolumeHeader.ModifyTimeUtc != DateTime.MinValue ? result.VolumeHeader.ModifyTimeUtc.ToString("yyyy-MM-dd HH:mm:ss") : "—");
                            Console.WriteLine("  Backup VBR:      {0}", result.BackupVolumeHeader != null ? "PRESENT" : "MISSING");
                        }
                        Console.WriteLine("  Directories:     {0:N0}", result.DirectoriesCount);
                        Console.WriteLine("  Files:           {0:N0}", result.FilesCount);
                        Console.WriteLine("  Deleted Orphans: {0:N0}", result.DeletedCount);
                        Console.WriteLine("  Recoverable:     {0:N0} bytes", result.TotalRecoverableBytes);
                        Console.WriteLine("================================================================================");

                        if (result.Files.Count > 0)
                        {
                            Console.WriteLine("Recovered & Carved Records:");
                            int show = Math.Min(25, result.Files.Count);
                            for (int i = 0; i < show; i++)
                            {
                                var f = result.Files[i];
                                Console.WriteLine("  [{0}] {1} {2,-30} {3,10:N0} bytes  CNID: {4}  Parent: {5}",
                                    i + 1, f.IsDeleted ? "[DEL]" : (f.IsDirectory ? "[DIR]" : "[ACT]"), f.Name, f.Size, f.Cnid, f.ParentCnid);
                            }
                            if (result.Files.Count > show)
                            {
                                Console.WriteLine("  ... and {0} more records.", result.Files.Count - show);
                            }
                        }
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during HFS+ scout: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // SRUM Command
        // =========================================================================
        private static int ExecuteSrum(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'srum' requires a database (SRUDB.dat) or disk image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe srum <path> [--json]");
                return 2;
            }

            string path = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(path))
            {
                Console.Error.WriteLine("Error: Target not found: {0}", path);
                return 2;
            }

            try
            {
                var report = SrumParser.Parse(path);
                if (json)
                {
                    Console.WriteLine(report.ToJson());
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Windows System Resource Usage Monitor (SRUM)");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Target:            {0}", path);
                    Console.WriteLine("  Page Size:         {0} bytes", report.PageSize);
                    Console.WriteLine("  Total Pages:       {0:N0}", report.TotalPages);
                    Console.WriteLine("  IdMap Entries:     {0:N0}", report.IdMapCount);
                    Console.WriteLine("  Network Records:   {0:N0}", report.NetworkEntries.Count);
                    Console.WriteLine("  App Usage Records: {0:N0}", report.AppUsageEntries.Count);
                    Console.WriteLine("  Total Sent:        {0:N0} bytes ({1:F2} MB)", report.TotalBytesExfiltrated, report.TotalBytesExfiltrated / 1048576.0);
                    Console.WriteLine("  Total Received:    {0:N0} bytes ({1:F2} MB)", report.TotalBytesReceived, report.TotalBytesReceived / 1048576.0);
                    Console.WriteLine("  Threat Alerts:     {0}", report.SuspiciousAlertCount > 0 ? "🚨 ALERT (" + report.SuspiciousAlertCount + " suspicious events)" : "✓ Normal");
                    Console.WriteLine("================================================================================");

                    if (report.NetworkEntries.Count > 0)
                    {
                        Console.WriteLine("Top Network Communications & Exfiltration:");
                        int show = Math.Min(20, report.NetworkEntries.Count);
                        for (int i = 0; i < show; i++)
                        {
                            var n = report.NetworkEntries[i];
                            Console.WriteLine("  [{0}] {1,-35} Sent: {2,12:N0} B  Recv: {3,12:N0} B  {4}",
                                i + 1, n.AppName, n.BytesSent, n.BytesReceived, n.InterfaceType);
                            if (n.IsSuspicious)
                            {
                                Console.WriteLine("      └── [ALERT]: {0}", n.SuspicionReason);
                            }
                        }
                        if (report.NetworkEntries.Count > show)
                        {
                            Console.WriteLine("  ... and {0} more network records.", report.NetworkEntries.Count - show);
                        }
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during SRUM parsing: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // JumpList Command
        // =========================================================================
        private static int ExecuteJumpList(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'jumplist' requires a file (.automaticDestinations-ms / .customDestinations-ms) or directory path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe jumplist <path> [--json]");
                return 2;
            }

            string path = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(path) && !Directory.Exists(path))
            {
                Console.Error.WriteLine("Error: Target path not found: {0}", path);
                return 2;
            }

            try
            {
                var report = JumpListParser.Parse(path);
                if (json)
                {
                    Console.WriteLine(report.ToJson());
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Windows Jump Lists Forensic Parser");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Target:            {0}", path);
                    Console.WriteLine("  Format:            {0}", report.FileType);
                    Console.WriteLine("  Application:       {0} ({1})", report.AppName, string.IsNullOrEmpty(report.AppId) ? "N/A" : report.AppId);
                    Console.WriteLine("  Total Items:       {0:N0}", report.TotalEntries);
                    Console.WriteLine("  Pinned Items:      {0:N0}", report.PinnedCount);
                    Console.WriteLine("  Threat Alerts:     {0}", report.SuspiciousCount > 0 ? "🚨 ALERT (" + report.SuspiciousCount + " suspicious items)" : "✓ Normal");
                    Console.WriteLine("================================================================================");

                    if (report.Entries != null && report.Entries.Count > 0)
                    {
                        Console.WriteLine("Jump List MRU & Pinned Entries:");
                        int show = Math.Min(30, report.Entries.Count);
                        for (int i = 0; i < show; i++)
                        {
                            var e = report.Entries[i];
                            string ts = e.LastAccessUtc != DateTime.MinValue ? e.LastAccessUtc.ToString("yyyy-MM-dd HH:mm:ss") : "N/A";
                            Console.WriteLine("  [{0,2}] {1,-19} [{2,-8}] {3}",
                                i + 1, ts, e.PinStatus, e.TargetPath);
                            if (!string.IsNullOrEmpty(e.NetBiosName) || !string.IsNullOrEmpty(e.VolumeSerialNumber))
                            {
                                Console.WriteLine("       Hostname: {0} | VolSerial: {1} | Size: {2:N0} bytes",
                                    string.IsNullOrEmpty(e.NetBiosName) ? "Local" : e.NetBiosName,
                                    string.IsNullOrEmpty(e.VolumeSerialNumber) ? "N/A" : e.VolumeSerialNumber,
                                    e.TargetFileSize);
                            }
                            if (e.IsSuspicious)
                            {
                                Console.WriteLine("       └── [ALERT]: {0}", e.ThreatDescription);
                            }
                        }
                        if (report.Entries.Count > show)
                        {
                            Console.WriteLine("  ... and {0} more items.", report.Entries.Count - show);
                        }
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error during Jump List parsing: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // Amcache Command
        // =========================================================================
        private static int ExecuteAmcache(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'amcache' requires a hive or image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe amcache <path> [--json]");
                return 2;
            }

            string path = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(path))
            {
                Console.Error.WriteLine("Error: Target not found: {0}", path);
                return 2;
            }

            try
            {
                List<AmcacheEntry> entries = AmcacheParser.Parse(path);
                if (json)
                {
                    var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                    Console.WriteLine(js.Serialize(entries));
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Windows Amcache.hve Execution & Threat Parser");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Total Entries: {0:N0}", entries.Count);
                    int alertCount = 0;
                    for (int i = 0; i < entries.Count; i++) if (entries[i].IsSuspicious) alertCount++;
                    Console.WriteLine("  Suspicious:    {0:N0}", alertCount);
                    Console.WriteLine("================================================================================");
                    int limit = Math.Min(entries.Count, 20);
                    for (int i = 0; i < limit; i++)
                    {
                        var e = entries[i];
                        string alert = e.IsSuspicious ? " [ALERT]" : "";
                        Console.WriteLine("  [{0:N0}] {1} (SHA1: {2}){3}", i + 1, e.Path, e.Sha1, alert);
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error parsing Amcache: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // Shellbags Command
        // =========================================================================
        private static int ExecuteShellbags(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'shellbags' requires a hive or image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe shellbags <path> [--json]");
                return 2;
            }

            string path = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(path))
            {
                Console.Error.WriteLine("Error: Target not found: {0}", path);
                return 2;
            }

            try
            {
                List<ShellbagRecord> records = ShellbagsParser.Parse(path);
                if (json)
                {
                    var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                    Console.WriteLine(js.Serialize(records));
                }
                else
                {
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  USB-Recovery — Windows Explorer Shellbags Folder Access Parser");
                    Console.WriteLine("================================================================================");
                    Console.WriteLine("  Total Records: {0:N0}", records.Count);
                    Console.WriteLine("================================================================================");
                    int limit = Math.Min(records.Count, 20);
                    for (int i = 0; i < limit; i++)
                    {
                        var r = records[i];
                        Console.WriteLine("  [{0:N0}] {1} (Type: {2}, Modified: {3})", i + 1, r.FullPath, r.ItemType, r.ModifiedTimeUtc != DateTime.MinValue ? r.ModifiedTimeUtc.ToString("s") : "N/A");
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error parsing Shellbags: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // Entropy Command
        // =========================================================================
        private static int ExecuteEntropy(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'entropy' requires an image or file path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe entropy <image_path> [--json]");
                return 2;
            }

            string path = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(path))
            {
                Console.Error.WriteLine("Error: Target not found: {0}", path);
                return 2;
            }

            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var report = EntropyClassifier.AnalyzeStream(fs);
                    if (json)
                    {
                        Console.WriteLine(report.ToJson());
                    }
                    else
                    {
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  USB-Recovery — Shannon Entropy & Ransomware Threat Classifier");
                        Console.WriteLine("================================================================================");
                        Console.WriteLine("  Mean Entropy:      {0:F4} bits/byte", report.MeanEntropy);
                        Console.WriteLine("  Standard Dev:      {0:F4}", report.StandardDeviation);
                        Console.WriteLine("  Classification:    {0}", report.DominantCategory);
                        Console.WriteLine("  Total Blocks:      {0:N0} (64 KiB each)", report.TotalBlocks);
                        Console.WriteLine("  Encrypted Blocks:  {0:N0}", report.EncryptedOrRansomwareBlocks);
                        Console.WriteLine("  Ransomware Threat: {0}", report.IsSuspiciousRansomware ? "🚨 ALERT: SUSPICIOUS ENCRYPTION" : "✓ Normal");
                        Console.WriteLine("  Summary:           {0}", report.SuspicionReason);
                        Console.WriteLine("================================================================================");
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error computing entropy: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // Court Report Command
        // =========================================================================
        private static int ExecuteCourtReport(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'court-report' requires an image path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe court-report <image_path> [-o <out.html>] [--case <id>] [--examiner <name>]");
                return 2;
            }

            string path = args[1];
            string outHtml = "court_report.html";
            string caseNo = "CR-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm");
            string examiner = "Digital Forensics Lead";

            for (int i = 2; i < args.Length; i++)
            {
                if ((args[i] == "-o" || args[i] == "--output") && i + 1 < args.Length)
                {
                    outHtml = args[++i];
                }
                else if (args[i] == "--case" && i + 1 < args.Length)
                {
                    caseNo = args[++i];
                }
                else if (args[i] == "--examiner" && i + 1 < args.Length)
                {
                    examiner = args[++i];
                }
            }

            if (!File.Exists(path))
            {
                Console.Error.WriteLine("Error: Target not found: {0}", path);
                return 2;
            }

            try
            {
                var meta = new ForensicCaseMetadata
                {
                    CaseNumber = caseNo,
                    InvestigatorName = examiner,
                    SourcePath = path,
                    TotalBytes = new FileInfo(path).Length
                };

                // Compute SHA-256 Chain of Custody hash with bounded buffer
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sha = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(fs);
                    var sbHash = new StringBuilder(64);
                    for (int b = 0; b < hash.Length; b++) sbHash.Append(hash[b].ToString("x2"));
                    meta.EvidenceSha256 = sbHash.ToString();
                }

                EntropyReport entropy = null;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    entropy = EntropyClassifier.AnalyzeStream(fs, 10 * 1024 * 1024); // Analyze first 10 MiB
                }

                string html = CourtReportGenerator.GenerateHtmlReport(meta, null, null, null, null, entropy);
                File.WriteAllText(outHtml, html, Encoding.UTF8);

                Console.WriteLine("================================================================================");
                Console.WriteLine("  USB-Recovery — Rule 902(14) Certified Expert Witness Court Report");
                Console.WriteLine("================================================================================");
                Console.WriteLine("  Case Number:       {0}", caseNo);
                Console.WriteLine("  Examiner:          {0}", examiner);
                Console.WriteLine("  Evidence SHA-256:  {0}", meta.EvidenceSha256);
                Console.WriteLine("  Report Generated:  {0}", outHtml);
                Console.WriteLine("================================================================================");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error generating court report: {0}", ex.Message);
                return 1;
            }
        }

        // =========================================================================
        // Benchmark Command
        // =========================================================================
        private static int ExecuteBenchmark(string[] args)
        {
            int mb = 32;
            bool json = false;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
                else if ((args[i] == "--mb" || args[i] == "-s") && i + 1 < args.Length)
                {
                    int val;
                    if (int.TryParse(args[++i], out val) && val > 0) mb = val;
                }
            }

            var report = ForensicBenchmarkSuite.RunAll(mb);
            if (json)
            {
                Console.WriteLine(report.ToJson());
            }
            else
            {
                ForensicBenchmarkSuite.PrintReport(report);
            }
            return 0;
        }

        // =========================================================================
        // LNK Command
        // =========================================================================
        private static int ExecuteLnk(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Error: 'lnk' requires a .lnk file or directory path.");
                Console.Error.WriteLine("Usage: USB-Recovery.exe lnk <path> [--json]");
                return 2;
            }

            string path = args[1];
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--json") json = true;
            }

            if (!File.Exists(path) && !Directory.Exists(path))
            {
                Console.Error.WriteLine("Error: Target path not found: {0}", path);
                return 2;
            }

            var artifacts = new List<LnkArtifact>();
            if (File.Exists(path))
            {
                try
                {
                    artifacts.Add(LnkParser.ParseFile(path));
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Error parsing LNK file: {0}", ex.Message);
                    return 1;
                }
            }
            else
            {
                string[] files = Directory.GetFiles(path, "*.lnk", SearchOption.AllDirectories);
                for (int f = 0; f < files.Length; f++)
                {
                    try { artifacts.Add(LnkParser.ParseFile(files[f])); } catch { }
                }
            }

            if (json)
            {
                var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                Console.WriteLine(js.Serialize(artifacts));
            }
            else
            {
                Console.WriteLine("================================================================================");
                Console.WriteLine("  USB-Recovery — Windows Shell Link (.lnk) Forensic Parser");
                Console.WriteLine("================================================================================");
                Console.WriteLine("  Total Artifacts: {0:N0}", artifacts.Count);
                Console.WriteLine("================================================================================");
                int limit = Math.Min(artifacts.Count, 25);
                for (int i = 0; i < limit; i++)
                {
                    var a = artifacts[i];
                    Console.WriteLine("  [{0:N0}] Target: {1}", i + 1, a.TargetPath);
                    Console.WriteLine("       Size:   {0:N0} bytes | Modified: {1:yyyy-MM-dd HH:mm:ss} UTC", a.TargetFileSize, a.WriteTimeUtc);
                    Console.WriteLine("       Volume: {0} (Serial: {1}) | MAC: {2} | Host: {3}", a.VolumeLabel, a.DriveSerialNumber, a.MacAddress, a.MachineId);
                }
            }
            return 0;
        }
    }
}
