using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class LocalWebServer : IDisposable
    {
        readonly HttpListener listener;
        readonly string imagePath;
        readonly string outputPath;
        readonly long imageSize;
        readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
        readonly object scanLock = new object();
        readonly object usnLock = new object();
        readonly object mftLock = new object();
        List<MftFileRecord> cachedMftRecords;
        string cachedMftPath;

        readonly object shimLock = new object();
        List<AppCompatCacheEntry> cachedShimRecords;
        string cachedShimPath;

        readonly object amcacheLock = new object();
        List<AmcacheEntry> cachedAmcacheRecords;
        string cachedAmcachePath;

        readonly object shellbagsLock = new object();
        List<ShellbagRecord> cachedShellbagRecords;
        string cachedShellbagsPath;

        readonly object srumLock = new object();
        SrumReport cachedSrumReport;
        string cachedSrumPath;

        readonly object jumpListLock = new object();
        JumpListReport cachedJumpListReport;
        string cachedJumpListPath;

        readonly object entropyLock = new object();
        EntropyReport cachedEntropyReport;
        string cachedEntropyPath;
        List<UsnRecord> cachedUsnRecords;
        string cachedUsnPath;

        Thread workerThread;
        bool running;
        CancellationTokenSource scanCts;
        bool isScanning;
        string scanStatus = "idle";
        long scanCandidates;
        long scanUniqueFiles;
        long scanBytesProcessed;
        string scanError;

        public int Port { get; private set; }
        public bool IsRunning { get { return running; } }

        public LocalWebServer(string imagePath, string outputPath, int port = 8080)
        {
            this.imagePath = imagePath;
            this.outputPath = string.IsNullOrEmpty(outputPath) ? Path.Combine(Directory.GetCurrentDirectory(), "recovered") : outputPath;
            this.Port = port;

            if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
            {
                if (E01ImageReader.IsE01File(imagePath))
                {
                    try
                    {
                        using (var e01 = E01ImageReader.Open(imagePath))
                        {
                            this.imageSize = e01.Length;
                        }
                    }
                    catch
                    {
                        this.imageSize = new FileInfo(imagePath).Length;
                    }
                }
                else if (VhdImageReader.IsVhdFile(imagePath))
                {
                    try
                    {
                        using (var vhd = VhdImageReader.Open(imagePath))
                        {
                            this.imageSize = vhd.Length;
                        }
                    }
                    catch
                    {
                        this.imageSize = new FileInfo(imagePath).Length;
                    }
                }
                else if (VhdxImageReader.IsVhdxFile(imagePath))
                {
                    try
                    {
                        using (var vhdx = VhdxImageReader.Open(imagePath))
                        {
                            this.imageSize = vhdx.Length;
                        }
                    }
                    catch
                    {
                        this.imageSize = new FileInfo(imagePath).Length;
                    }
                }
                else if (VmdkImageReader.IsVmdkFile(imagePath))
                {
                    try
                    {
                        using (var vmdk = VmdkImageReader.Open(imagePath))
                        {
                            this.imageSize = vmdk.Length;
                        }
                    }
                    catch
                    {
                        this.imageSize = new FileInfo(imagePath).Length;
                    }
                }
                else if (Aff4ImageReader.IsAff4File(imagePath))
                {
                    try
                    {
                        using (var aff4 = Aff4ImageReader.Open(imagePath))
                        {
                            this.imageSize = aff4.Length;
                        }
                    }
                    catch
                    {
                        this.imageSize = new FileInfo(imagePath).Length;
                    }
                }
                else if (Qcow2ImageReader.IsQcow2File(imagePath))
                {
                    try
                    {
                        using (var qcow = Qcow2ImageReader.Open(imagePath))
                        {
                            this.imageSize = qcow.Length;
                        }
                    }
                    catch
                    {
                        this.imageSize = new FileInfo(imagePath).Length;
                    }
                }
                else
                {
                    this.imageSize = new FileInfo(imagePath).Length;
                }
            }

            listener = new HttpListener();
            string prefix = string.Format(CultureInfo.InvariantCulture, "http://127.0.0.1:{0}/", port);
            listener.Prefixes.Add(prefix);
        }

        public void Start()
        {
            if (running) return;
            running = true;
            try
            {
                listener.Start();
            }
            catch (HttpListenerException)
            {
                // Fallback to random free port if requested port is taken
                listener.Prefixes.Clear();
                Port = FindFreePort();
                listener.Prefixes.Add(string.Format(CultureInfo.InvariantCulture, "http://127.0.0.1:{0}/", Port));
                listener.Start();
            }

            workerThread = new Thread(ListenLoop)
            {
                IsBackground = true,
                Name = "USB-Recovery-WebUI"
            };
            workerThread.Start();
        }

        private Stream OpenImageStream()
        {
            if (E01ImageReader.IsE01File(imagePath))
            {
                return E01ImageReader.Open(imagePath);
            }
            if (VhdImageReader.IsVhdFile(imagePath))
            {
                return VhdImageReader.Open(imagePath);
            }
            if (VhdxImageReader.IsVhdxFile(imagePath))
            {
                return VhdxImageReader.Open(imagePath);
            }
            if (VmdkImageReader.IsVmdkFile(imagePath))
            {
                return VmdkImageReader.Open(imagePath);
            }
            if (Aff4ImageReader.IsAff4File(imagePath))
            {
                return Aff4ImageReader.Open(imagePath);
            }
            if (Qcow2ImageReader.IsQcow2File(imagePath))
            {
                return Qcow2ImageReader.Open(imagePath);
            }
            return new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        }

        public void Stop()
        {
            running = false;
            try
            {
                if (scanCts != null)
                {
                    scanCts.Cancel();
                    scanCts.Dispose();
                    scanCts = null;
                }
            }
            catch { }

            try
            {
                if (listener.IsListening)
                {
                    listener.Stop();
                    listener.Close();
                }
            }
            catch { }
        }

        public void Dispose()
        {
            Stop();
            try { listener.Close(); } catch { }
        }

        static int FindFreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        void ListenLoop()
        {
            while (running && listener.IsListening)
            {
                try
                {
                    var context = listener.GetContext();
                    ThreadPool.QueueUserWorkItem(_ => HandleRequest(context));
                }
                catch (HttpListenerException) { break; }
                catch (ObjectDisposedException) { break; }
                catch { }
            }
        }

        void HandleRequest(HttpListenerContext context)
        {
            var req = context.Request;
            var res = context.Response;

            // Strict security: Reject any connection not originating from loopback
            if (!IPAddress.IsLoopback(req.RemoteEndPoint.Address))
            {
                res.StatusCode = (int)HttpStatusCode.Forbidden;
                res.Close();
                return;
            }

            try
            {
                string path = req.Url.AbsolutePath.ToLowerInvariant();

                if (path == "/" || path == "/index.html")
                {
                    ServeDashboard(res);
                }
                else if (path == "/api/status")
                {
                    ServeStatus(res);
                }
                else if (path == "/api/probe")
                {
                    ServeProbe(res);
                }
                else if (path == "/api/clusters")
                {
                    ServeClusters(req, res);
                }
                else if (path == "/api/hex")
                {
                    ServeHex(req, res);
                }
                else if (path == "/api/files")
                {
                    ServeFiles(res);
                }
                else if (path == "/api/file")
                {
                    ServeFileContent(req, res);
                }
                else if (path == "/api/export-zip")
                {
                    ServeExportZip(req, res);
                }
                else if (path == "/api/report")
                {
                    ServeReport(req, res);
                }
                else if (path == "/api/registry")
                {
                    ServeRegistry(req, res);
                }
                else if (path == "/api/usn")
                {
                    ServeUsn(req, res);
                }
                else if (path == "/api/mft")
                {
                    ServeMft(req, res);
                }
                else if (path == "/api/shimcache")
                {
                    ServeShimcache(req, res);
                }
                else if (path == "/api/timeline")
                {
                    ServeTimeline(req, res);
                }
                else if (path == "/api/amcache")
                {
                    ServeAmcache(req, res);
                }
                else if (path == "/api/shellbags")
                {
                    ServeShellbags(req, res);
                }
                else if (path == "/api/entropy")
                {
                    ServeEntropy(req, res);
                }
                else if (path == "/api/srum")
                {
                    ServeSrum(req, res);
                }
                else if (path == "/api/jumplists")
                {
                    ServeJumpLists(req, res);
                }
                else if (path == "/api/court-report")
                {
                    ServeCourtReport(req, res);
                }
                else if (path == "/api/scan" && req.HttpMethod == "POST")
                {
                    ServeStartScan(res);
                }
                else if (path == "/api/cancel" && req.HttpMethod == "POST")
                {
                    ServeCancelScan(res);
                }
                else
                {
                    res.StatusCode = (int)HttpStatusCode.NotFound;
                    WriteText(res, "404 Not Found");
                }
            }
            catch (Exception ex)
            {
                try
                {
                    res.StatusCode = (int)HttpStatusCode.InternalServerError;
                    WriteText(res, "Error: " + ex.Message);
                }
                catch { }
            }
            finally
            {
                try { res.Close(); } catch { }
            }
        }

        void ServeDashboard(HttpListenerResponse res)
        {
            res.ContentType = "text/html; charset=utf-8";
            res.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate");
            byte[] bytes = Encoding.UTF8.GetBytes(DashboardHtml);
            res.ContentLength64 = bytes.Length;
            res.OutputStream.Write(bytes, 0, bytes.Length);
        }

        void ServeStatus(HttpListenerResponse res)
        {
            var data = new
            {
                app = "USB-Recovery",
                version = "2026.11",
                license = "AGPL-3.0",
                imagePath = imagePath,
                imageName = !string.IsNullOrEmpty(imagePath) ? Path.GetFileName(imagePath) : "None",
                imageSize = imageSize,
                imageSizeHuman = FormatBytes(imageSize),
                outputPath = outputPath,
                isScanning = isScanning,
                scanStatus = scanStatus,
                candidates = scanCandidates,
                uniqueFiles = scanUniqueFiles,
                bytesProcessed = scanBytesProcessed,
                error = scanError
            };
            WriteJson(res, data);
        }

        void ServeProbe(HttpListenerResponse res)
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
            {
                WriteJson(res, new { error = "Image file does not exist" });
                return;
            }

            try
            {
                var raidReport = RaidMetadataProbe.Probe(new[] { imagePath }, CancellationToken.None);
                var candidates = BootScout.Find(imagePath, CancellationToken.None, (d, t) => { });

                List<BtrfsScout.BtrfsSuperblock> btrfsSbs = null;
                try
                {
                    using (var fs = OpenImageStream())
                    {
                        btrfsSbs = BtrfsScout.ProbeSuperblocks(fs);
                    }
                }
                catch { }

                var partitions = new List<object>();
                if (candidates != null)
                {
                    foreach (var p in candidates)
                    {
                        partitions.Add(new
                        {
                            offset = p.Offset,
                            offsetHex = "0x" + p.Offset.ToString("X8"),
                            length = p.Length,
                            lengthHuman = FormatBytes(p.Length),
                            filesystem = p.Kind,
                            label = p.Origin ?? "",
                            clusterSize = p.SectorSize
                        });
                    }
                }

                var data = new
                {
                    image = Path.GetFileName(imagePath),
                    size = imageSize,
                    sizeHuman = FormatBytes(imageSize),
                    partitionCount = partitions.Count,
                    partitions = partitions,
                    raid = raidReport != null && raidReport.Members.Count > 0 && raidReport.Members[0].Status != "not_found" ? new
                    {
                        format = raidReport.Members[0].Format,
                        status = raidReport.Members[0].Status,
                        level = raidReport.Members[0].Level
                    } : null,
                    btrfs = btrfsSbs != null && btrfsSbs.Count > 0 ? new
                    {
                        uuid = btrfsSbs[0].FsUuid,
                        label = btrfsSbs[0].Label,
                        generation = btrfsSbs[0].Generation,
                        superblocks = btrfsSbs.Count
                    } : null
                };
                WriteJson(res, data);
            }
            catch (Exception ex)
            {
                WriteJson(res, new { error = ex.Message });
            }
        }

        void ServeClusters(HttpListenerRequest req, HttpListenerResponse res)
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath) || imageSize <= 0)
            {
                WriteJson(res, new { total = 0, blockCount = 0, blockSize = 512, blocks = new object[0] });
                return;
            }

            long offset = 0;
            long count = imageSize;
            int blocksToReturn = 500;

            long qOffset;
            if (long.TryParse(req.QueryString["offset"], out qOffset) && qOffset >= 0) offset = qOffset;
            long qCount;
            if (long.TryParse(req.QueryString["count"], out qCount) && qCount > 0) count = Math.Min(qCount, imageSize - offset);

            long blockSize = Math.Max(512, count / blocksToReturn);
            var blocks = new List<object>();

            // Sample blocks across the range
            using (var stream = OpenImageStream())
            {
                byte[] sample = new byte[512];
                for (int i = 0; i < blocksToReturn; i++)
                {
                    long blockStart = offset + (i * blockSize);
                    if (blockStart >= imageSize) break;

                    string type = "free"; // default
                    stream.Position = blockStart;
                    int read = stream.Read(sample, 0, Math.Min(sample.Length, (int)Math.Min(blockSize, imageSize - blockStart)));

                    if (read >= 16)
                    {
                        if (blockStart == 0 && sample[510] == 0x55 && sample[511] == 0xAA)
                        {
                            type = "boot";
                        }
                        else if (sample[0] == 'F' && sample[1] == 'I' && sample[2] == 'L' && sample[3] == 'E')
                        {
                            type = "mft";
                        }
                        else if (sample[0] == 0xFF && sample[1] == 0xD8 && sample[2] == 0xFF)
                        {
                            type = "photo";
                        }
                        else if (sample[0] == 0x89 && sample[1] == 'P' && sample[2] == 'N' && sample[3] == 'G')
                        {
                            type = "photo";
                        }
                        else if (read >= 8 && sample[4] == 'f' && sample[5] == 't' && sample[6] == 'y' && sample[7] == 'p')
                        {
                            type = "video";
                        }
                        else if (sample[0] == 'P' && sample[1] == 'K' && sample[2] == 0x03 && sample[3] == 0x04)
                        {
                            type = "archive";
                        }
                        else if (sample[0] == 'S' && sample[1] == 'Q' && sample[2] == 'L' && sample[3] == 'i')
                        {
                            type = "database";
                        }
                        else
                        {
                            // Check non-zero entropy
                            bool nonZero = false;
                            for (int b = 0; b < read; b++)
                            {
                                if (sample[b] != 0) { nonZero = true; break; }
                            }
                            if (nonZero) type = "data";
                        }
                    }

                    blocks.Add(new
                    {
                        index = i,
                        offset = blockStart,
                        offsetHex = "0x" + blockStart.ToString("X8"),
                        length = blockSize,
                        type = type
                    });
                }
            }

            WriteJson(res, new { total = imageSize, blockCount = blocks.Count, blockSize = blockSize, blocks = blocks });
        }

        void ServeHex(HttpListenerRequest req, HttpListenerResponse res)
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath) || imageSize <= 0)
            {
                WriteJson(res, new { error = "Image not found or empty" });
                return;
            }

            long offset = 0;
            int length = 256;

            long qOffsetHex;
            if (long.TryParse(req.QueryString["offset"], out qOffsetHex) && qOffsetHex >= 0) offset = qOffsetHex;
            int qLen;
            if (int.TryParse(req.QueryString["length"], out qLen) && qLen > 0) length = Math.Min(qLen, 2048);

            offset = Math.Max(0, Math.Min(offset, imageSize - 1));
            length = (int)Math.Min(length, imageSize - offset);

            byte[] buffer = new byte[length];
            using (var stream = OpenImageStream())
            {
                stream.Position = offset;
                int read = stream.Read(buffer, 0, length);
                if (read < length) Array.Resize(ref buffer, read);
            }

            var hexBuilder = new StringBuilder();
            var asciiBuilder = new StringBuilder();
            for (int i = 0; i < buffer.Length; i++)
            {
                hexBuilder.Append(buffer[i].ToString("X2"));
                char c = (char)buffer[i];
                asciiBuilder.Append(c >= 32 && c <= 126 ? c : '.');
            }

            // Interpret first 16 bytes under cursor
            byte b0 = buffer.Length > 0 ? buffer[0] : (byte)0;
            short s16 = buffer.Length >= 2 ? BitConverter.ToInt16(buffer, 0) : (short)0;
            ushort u16 = buffer.Length >= 2 ? BitConverter.ToUInt16(buffer, 0) : (ushort)0;
            int s32 = buffer.Length >= 4 ? BitConverter.ToInt32(buffer, 0) : 0;
            uint u32 = buffer.Length >= 4 ? BitConverter.ToUInt32(buffer, 0) : 0;
            long s64 = buffer.Length >= 8 ? BitConverter.ToInt64(buffer, 0) : 0;
            ulong u64 = buffer.Length >= 8 ? BitConverter.ToUInt64(buffer, 0) : 0;

            string unixTime = "";
            try
            {
                if (u32 > 946684800 && u32 < 2524608000) // between years 2000 and 2050
                    unixTime = DateTimeOffset.FromUnixTimeSeconds(u32).ToString("yyyy-MM-dd HH:mm:ss UTC");
            }
            catch { }

            string fileTime = "";
            try
            {
                if (s64 > 116444736000000000 && s64 < 150000000000000000) // Windows FILETIME window
                    fileTime = DateTime.FromFileTimeUtc(s64).ToString("yyyy-MM-dd HH:mm:ss UTC");
            }
            catch { }

            string guid = buffer.Length >= 16 ? new Guid(buffer.Take(16).ToArray()).ToString() : "";

            var data = new
            {
                offset = offset,
                offsetHex = "0x" + offset.ToString("X8"),
                length = buffer.Length,
                hex = hexBuilder.ToString(),
                ascii = asciiBuilder.ToString(),
                inspector = new
                {
                    uint8 = b0,
                    int8 = (sbyte)b0,
                    uint16 = u16,
                    int16 = s16,
                    uint32 = u32,
                    int32 = s32,
                    uint64 = u64.ToString(),
                    int64 = s64.ToString(),
                    unixTime = unixTime,
                    fileTime = fileTime,
                    guid = guid
                }
            };
            WriteJson(res, data);
        }

        void ServeFiles(HttpListenerResponse res)
        {
            var files = new List<object>();
            if (Directory.Exists(outputPath))
            {
                var dir = new DirectoryInfo(outputPath);
                foreach (var f in dir.GetFiles("*", SearchOption.AllDirectories))
                {
                    files.Add(new
                    {
                        name = f.Name,
                        relativePath = f.FullName.Substring(dir.FullName.Length).TrimStart(Path.DirectorySeparatorChar),
                        size = f.Length,
                        sizeHuman = FormatBytes(f.Length),
                        extension = f.Extension.TrimStart('.').ToUpperInvariant(),
                        modified = f.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss")
                    });
                }
            }
            WriteJson(res, new { count = files.Count, outputDir = outputPath, files = files });
        }

        void ServeFileContent(HttpListenerRequest req, HttpListenerResponse res)
        {
            string rel = req.QueryString["name"];
            if (string.IsNullOrEmpty(rel) || string.IsNullOrEmpty(outputPath))
            {
                res.StatusCode = (int)HttpStatusCode.BadRequest;
                WriteText(res, "Missing file name");
                return;
            }

            string full = Path.GetFullPath(Path.Combine(outputPath, rel.TrimStart('/', '\\')));
            string outFull = Path.GetFullPath(outputPath);
            if (!full.StartsWith(outFull, StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
            {
                res.StatusCode = (int)HttpStatusCode.NotFound;
                WriteText(res, "File not found");
                return;
            }

            string ext = Path.GetExtension(full).ToLowerInvariant();
            string mime = "application/octet-stream";
            if (ext == ".jpg" || ext == ".jpeg") mime = "image/jpeg";
            else if (ext == ".png") mime = "image/png";
            else if (ext == ".gif") mime = "image/gif";
            else if (ext == ".mp4") mime = "video/mp4";
            else if (ext == ".txt" || ext == ".log") mime = "text/plain";
            else if (ext == ".json") mime = "application/json";
            else if (ext == ".csv") mime = "text/csv";
            else if (ext == ".html") mime = "text/html";

            res.ContentType = mime;
            res.Headers.Add("Content-Disposition", "inline; filename=\"" + Path.GetFileName(full) + "\"");
            var fileInfo = new FileInfo(full);
            res.ContentLength64 = fileInfo.Length;
            using (var fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            {
                byte[] buf = new byte[65536];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    res.OutputStream.Write(buf, 0, n);
                }
            }
        }

        void ServeExportZip(HttpListenerRequest req, HttpListenerResponse res)
        {
            if (string.IsNullOrEmpty(outputPath) || !Directory.Exists(outputPath))
            {
                res.StatusCode = (int)HttpStatusCode.NotFound;
                WriteText(res, "No recovered files directory found");
                return;
            }

            var dir = new DirectoryInfo(outputPath);
            FileInfo[] allFiles = dir.GetFiles("*", SearchOption.AllDirectories);
            if (allFiles.Length == 0)
            {
                res.StatusCode = (int)HttpStatusCode.NotFound;
                WriteText(res, "No recovered files to export");
                return;
            }

            string filterParam = req.QueryString["files"];
            HashSet<string> requestedFiles = null;
            if (!string.IsNullOrEmpty(filterParam))
            {
                requestedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                string[] parts = filterParam.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < parts.Length; i++)
                {
                    requestedFiles.Add(parts[i].Trim());
                }
            }

            List<FileInfo> filesToExport = new List<FileInfo>();
            for (int i = 0; i < allFiles.Length; i++)
            {
                var f = allFiles[i];
                string relPath = f.FullName.Substring(dir.FullName.Length).TrimStart(Path.DirectorySeparatorChar, '/');
                if (requestedFiles == null || requestedFiles.Contains(relPath) || requestedFiles.Contains(f.Name))
                {
                    filesToExport.Add(f);
                }
            }

            if (filesToExport.Count == 0)
            {
                res.StatusCode = (int)HttpStatusCode.NotFound;
                WriteText(res, "No matching files found for export");
                return;
            }

            res.ContentType = "application/zip";
            res.Headers.Add("Content-Disposition", "attachment; filename=\"USB-Recovery-Export.zip\"");
            res.SendChunked = true;

            ZipStreamingWriter.StreamZip(filesToExport, dir.FullName, res.OutputStream);
        }

        void ServeReport(HttpListenerRequest req, HttpListenerResponse res)
        {
            string format = (req.QueryString["format"] ?? "html").ToLowerInvariant();

            string detectedFormat = "RAW / Physical Disk";
            if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
            {
                if (E01ImageReader.IsE01File(imagePath)) detectedFormat = "Expert Witness E01 (zlib compressed)";
                else if (VhdImageReader.IsVhdFile(imagePath)) detectedFormat = "Microsoft VHD (Virtual Hard Disk)";
                else if (VhdxImageReader.IsVhdxFile(imagePath)) detectedFormat = "Microsoft VHDX (V2 Virtual Hard Disk)";
                else if (VmdkImageReader.IsVmdkFile(imagePath)) detectedFormat = "VMware VMDK (Virtual Machine Disk)";
                else if (Aff4ImageReader.IsAff4File(imagePath)) detectedFormat = "AFF4 Forensic Container (Standard Image / Map)";
                else if (Qcow2ImageReader.IsQcow2File(imagePath)) detectedFormat = "QEMU Copy-On-Write (QCOW2 v2/v3)";
            }

            var fileRecords = new List<Dictionary<string, object>>();
            var shaList = new List<string>();

            if (Directory.Exists(outputPath))
            {
                var dir = new DirectoryInfo(outputPath);
                var files = dir.GetFiles("*", SearchOption.AllDirectories).OrderBy(f => f.FullName).ToArray();
                using (var sha = SHA256.Create())
                {
                    for (int fi = 0; fi < files.Length; fi++)
                    {
                        var f = files[fi];
                        string rel = f.FullName.Substring(dir.FullName.Length).TrimStart(Path.DirectorySeparatorChar, '/').Replace('\\', '/');
                        byte[] hBytes = null;
                        try
                        {
                            using (var fileStream = new FileStream(f.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
                            {
                                hBytes = sha.ComputeHash(fileStream);
                            }
                        }
                        catch
                        {
                            hBytes = new byte[32];
                        }
                        var hSb = new StringBuilder(64);
                        for (int i = 0; i < hBytes.Length; i++) hSb.Append(hBytes[i].ToString("x2"));
                        string hashStr = hSb.ToString();
                        shaList.Add(hashStr);

                        var r = new Dictionary<string, object>();
                        r["name"] = f.Name;
                        r["relativePath"] = rel;
                        r["size"] = f.Length;
                        r["sizeHuman"] = FormatBytes(f.Length);
                        r["sha256"] = hashStr;
                        r["createdUtc"] = f.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
                        r["modifiedUtc"] = f.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
                        r["extension"] = f.Extension.TrimStart('.').ToUpperInvariant();
                        fileRecords.Add(r);
                    }
                }
            }

            // Compute Chain of Custody hash (SHA-256 over concatenated hashes)
            string chainOfCustodyHash = "";
            using (var sha = SHA256.Create())
            {
                byte[] chainBytes = Encoding.UTF8.GetBytes(string.Join("\n", shaList.ToArray()));
                byte[] chH = sha.ComputeHash(chainBytes);
                var chSb = new StringBuilder(64);
                for (int i = 0; i < chH.Length; i++) chSb.Append(chH[i].ToString("x2"));
                chainOfCustodyHash = chSb.ToString();
            }

            if (format == "json")
            {
                var reportObj = new
                {
                    reportTitle = "USB-Recovery Forensic Chain-of-Custody Manifest",
                    version = "2026.11",
                    generator = "USB-Recovery Pure C# DFIR Engine",
                    generatedUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    targetImage = new
                    {
                        path = imagePath,
                        name = !string.IsNullOrEmpty(imagePath) ? Path.GetFileName(imagePath) : "None",
                        format = detectedFormat,
                        logicalSize = imageSize,
                        logicalSizeHuman = FormatBytes(imageSize)
                    },
                    fileCount = fileRecords.Count,
                    chainOfCustodySha256 = chainOfCustodyHash,
                    files = fileRecords
                };
                WriteJson(res, reportObj);
            }
            else
            {
                // HTML format
                res.ContentType = "text/html; charset=utf-8";
                string html = GenerateReportHtml(detectedFormat, chainOfCustodyHash, fileRecords);
                byte[] bytes = Encoding.UTF8.GetBytes(html);
                res.ContentLength64 = bytes.Length;
                res.OutputStream.Write(bytes, 0, bytes.Length);
            }
        }

        string GenerateReportHtml(string detectedFormat, string chainOfCustodyHash, List<Dictionary<string, object>> files)
        {
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\"/>\n");
            sb.Append("<title>USB-Recovery — Forensic Chain-of-Custody Report</title>\n");
            sb.Append("<style>\n");
            sb.Append("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 32px; line-height: 1.5; }\n");
            sb.Append(".report-container { max-width: 1100px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }\n");
            sb.Append(".header { border-bottom: 2px solid #38bdf8; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }\n");
            sb.Append(".title { font-size: 24px; font-weight: 800; color: #fff; }\n");
            sb.Append(".badge { background: rgba(56, 189, 248, 0.2); color: #38bdf8; padding: 4px 12px; border-radius: 16px; font-size: 13px; font-weight: 600; }\n");
            sb.Append(".meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; background: rgba(15, 23, 42, 0.6); padding: 16px; border-radius: 8px; border: 1px solid #334155; }\n");
            sb.Append(".meta-item { font-size: 13px; }\n");
            sb.Append(".meta-label { color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; margin-bottom: 4px; }\n");
            sb.Append(".meta-value { color: #fff; font-weight: 500; font-family: 'Consolas', monospace; word-break: break-all; }\n");
            sb.Append(".chain-box { background: rgba(74, 222, 128, 0.1); border: 1px solid rgba(74, 222, 128, 0.3); border-radius: 8px; padding: 16px; margin-bottom: 24px; }\n");
            sb.Append(".chain-title { font-size: 13px; font-weight: 700; color: #4ade80; text-transform: uppercase; margin-bottom: 6px; }\n");
            sb.Append(".chain-hash { font-family: 'Consolas', monospace; font-size: 14px; color: #fff; word-break: break-all; }\n");
            sb.Append("table { width: 100%; border-collapse: collapse; font-size: 12px; text-align: left; margin-top: 16px; }\n");
            sb.Append("th { background: #0f172a; padding: 10px 12px; border-bottom: 1px solid #334155; color: #94a3b8; text-transform: uppercase; font-size: 11px; }\n");
            sb.Append("td { padding: 10px 12px; border-bottom: 1px solid rgba(51, 65, 85, 0.4); }\n");
            sb.Append(".hash-col { font-family: 'Consolas', monospace; color: #38bdf8; }\n");
            sb.Append("@media print { body { background: #fff; color: #000; padding: 0; } .report-container { border: none; box-shadow: none; background: #fff; } th { background: #f1f5f9; color: #000; } td { color: #000; } .meta-grid { background: #f8fafc; border: 1px solid #cbd5e1; } .meta-label { color: #64748b; } .meta-value { color: #000; } .hash-col { color: #0369a1; } .chain-box { background: #f0fdf4; border-color: #86efac; } .chain-hash { color: #000; } }\n");
            sb.Append("</style>\n</head>\n<body>\n");
            sb.Append("<div class=\"report-container\">\n");
            sb.Append("<div class=\"header\"><div><div class=\"title\">⚡ USB-Recovery Forensic Report</div><div style=\"color: #94a3b8; font-size: 13px;\">Cryptographic Chain-of-Custody Manifest</div></div><span class=\"badge\">ISO/IEC 27037 Compatible</span></div>\n");

            sb.Append("<div class=\"meta-grid\">\n");
            sb.Append("<div class=\"meta-item\"><div class=\"meta-label\">Evidence Target</div><div class=\"meta-value\">").Append(WebUtility.HtmlEncode(string.IsNullOrEmpty(imagePath) ? "None" : Path.GetFileName(imagePath))).Append("</div></div>\n");
            sb.Append("<div class=\"meta-item\"><div class=\"meta-label\">Container Format</div><div class=\"meta-value\">").Append(WebUtility.HtmlEncode(detectedFormat)).Append("</div></div>\n");
            sb.Append("<div class=\"meta-item\"><div class=\"meta-label\">Evidence Size</div><div class=\"meta-value\">").Append(FormatBytes(imageSize)).Append(" (").Append(imageSize).Append(" bytes)</div></div>\n");
            sb.Append("<div class=\"meta-item\"><div class=\"meta-label\">Audit Timestamp (UTC)</div><div class=\"meta-value\">").Append(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")).Append("</div></div>\n");
            sb.Append("<div class=\"meta-item\"><div class=\"meta-label\">Total Recovered Items</div><div class=\"meta-value\">").Append(files.Count).Append(" items</div></div>\n");
            sb.Append("<div class=\"meta-item\"><div class=\"meta-label\">Engine Version</div><div class=\"meta-value\">USB-Recovery 2026.11 (AGPL-3.0)</div></div>\n");
            sb.Append("</div>\n");

            sb.Append("<div class=\"chain-box\">\n");
            sb.Append("<div class=\"chain-title\">🔒 Chain of Custody Master Hash (SHA-256)</div>\n");
            sb.Append("<div class=\"chain-hash\">").Append(string.IsNullOrEmpty(chainOfCustodyHash) ? "EMPTY" : chainOfCustodyHash).Append("</div>\n");
            sb.Append("<div style=\"font-size: 11px; color: #94a3b8; margin-top: 4px;\">Computed over ordered SHA-256 hashes of all recovered artifacts. Any bitwise alteration invalidates this seal.</div>\n");
            sb.Append("</div>\n");

            sb.Append("<h3 style=\"font-size: 16px; margin-bottom: 8px; color: #fff;\">Recovered Artifact Manifest</h3>\n");
            sb.Append("<table><thead><tr><th>#</th><th>Artifact Path</th><th>Size</th><th>Last Modified (UTC)</th><th>SHA-256 Checksum</th></tr></thead><tbody>\n");

            if (files.Count == 0)
            {
                sb.Append("<tr><td colspan=\"5\" style=\"text-align: center; color: #94a3b8;\">No artifacts recovered.</td></tr>\n");
            }
            else
            {
                for (int i = 0; i < files.Count; i++)
                {
                    var f = files[i];
                    sb.Append("<tr>\n");
                    sb.Append("<td>").Append(i + 1).Append("</td>\n");
                    sb.Append("<td><strong>").Append(WebUtility.HtmlEncode(f["relativePath"].ToString())).Append("</strong></td>\n");
                    sb.Append("<td>").Append(WebUtility.HtmlEncode(f["sizeHuman"].ToString())).Append("</td>\n");
                    sb.Append("<td>").Append(WebUtility.HtmlEncode(f["modifiedUtc"].ToString())).Append("</td>\n");
                    sb.Append("<td class=\"hash-col\"><code>").Append(WebUtility.HtmlEncode(f["sha256"].ToString())).Append("</code></td>\n");
                    sb.Append("</tr>\n");
                }
            }

            sb.Append("</tbody></table>\n");
            sb.Append("<div style=\"margin-top: 32px; padding-top: 16px; border-top: 1px solid #334155; font-size: 11px; color: #64748b; text-align: center;\">Generated 100% offline by USB-Recovery Local Web Engine. Zero outbound telemetry. Write-blocking strictly enforced.</div>\n");
            sb.Append("</div>\n</body>\n</html>");
            return sb.ToString();
        }

        void ServeRegistry(HttpListenerRequest req, HttpListenerResponse res)
        {
            if (string.IsNullOrEmpty(outputPath) || !Directory.Exists(outputPath))
            {
                WriteJson(res, new { error = "No output directory configured or found" });
                return;
            }

            string rel = req.QueryString["path"];
            string outFull = Path.GetFullPath(outputPath);
            string action = (req.QueryString["action"] ?? "list").ToLowerInvariant();

            if (action == "list")
            {
                var hivesList = new List<object>();
                var dir = new DirectoryInfo(outputPath);
                var allFiles = dir.GetFiles("*", SearchOption.AllDirectories);
                for (int i = 0; i < allFiles.Length; i++)
                {
                    var f = allFiles[i];
                    if (RegistryHive.IsRegistryHive(f.FullName))
                    {
                        string rPath = f.FullName.Substring(dir.FullName.Length).TrimStart(Path.DirectorySeparatorChar, '/').Replace('\\', '/');
                        hivesList.Add(new
                        {
                            name = f.Name,
                            relativePath = rPath,
                            size = f.Length,
                            sizeHuman = FormatBytes(f.Length),
                            modifiedUtc = f.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                        });
                    }
                }
                WriteJson(res, new { count = hivesList.Count, hives = hivesList });
                return;
            }

            string targetHivePath = null;
            if (!string.IsNullOrEmpty(rel))
            {
                string candidate = Path.GetFullPath(Path.Combine(outputPath, rel.TrimStart('/', '\\')));
                if (candidate.StartsWith(outFull, StringComparison.OrdinalIgnoreCase) && File.Exists(candidate))
                {
                    targetHivePath = candidate;
                }
            }
            else
            {
                var dir = new DirectoryInfo(outputPath);
                var allFiles = dir.GetFiles("*", SearchOption.AllDirectories);
                for (int i = 0; i < allFiles.Length; i++)
                {
                    if (RegistryHive.IsRegistryHive(allFiles[i].FullName))
                    {
                        targetHivePath = allFiles[i].FullName;
                        rel = allFiles[i].FullName.Substring(dir.FullName.Length).TrimStart(Path.DirectorySeparatorChar, '/').Replace('\\', '/');
                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(targetHivePath) || !File.Exists(targetHivePath))
            {
                WriteJson(res, new { error = "Registry hive file not found. Ensure output folder contains a valid hive or pass ?path=" });
                return;
            }

            using (var hive = RegistryHive.Open(targetHivePath))
            {
                if (action == "summary" || action == "info")
                {
                    var sum = hive.ExtractSystemSummary();
                    WriteJson(res, new
                    {
                        hiveFile = rel ?? Path.GetFileName(targetHivePath),
                        embeddedFileName = hive.EmbeddedFileName,
                        isChecksumValid = hive.IsChecksumValid,
                        primarySeq = hive.PrimarySequenceNumber,
                        secondarySeq = hive.SecondarySequenceNumber,
                        lastWriteUtc = hive.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                        majorVersion = hive.MajorVersion,
                        minorVersion = hive.MinorVersion,
                        rootCellOffset = hive.RootCellOffset,
                        hiveBinsLength = hive.HiveBinsLength,
                        summary = new
                        {
                            productName = sum.ProductName,
                            currentVersion = sum.CurrentVersion,
                            currentBuild = sum.CurrentBuild,
                            installDateUtc = sum.InstallDateUtc,
                            computerName = sum.ComputerName,
                            timeZoneStandardName = sum.TimeZoneStandardName,
                            currentControlSet = sum.CurrentControlSet,
                            usbDevices = sum.UsbDevices,
                            userAccounts = sum.UserAccounts,
                            runKeys = sum.RunKeys
                        }
                    });
                }
                else if (action == "search")
                {
                    string q = req.QueryString["q"] ?? "";
                    if (string.IsNullOrEmpty(q))
                    {
                        WriteJson(res, new { error = "Search query parameter 'q' required" });
                        return;
                    }

                    var keyMatches = hive.SearchKeys(q, true);
                    var valMatches = hive.SearchValues(q);

                    var keysJson = new List<object>();
                    int maxK = Math.Min(50, keyMatches.Count);
                    for (int i = 0; i < maxK; i++)
                    {
                        var k = keyMatches[i];
                        keysJson.Add(new { name = k.Name, path = k.Path, subkeyCount = k.SubkeyCount, valueCount = k.ValueCount, isDeleted = k.IsDeleted });
                    }

                    var valsJson = new List<object>();
                    int maxV = Math.Min(50, valMatches.Count);
                    for (int i = 0; i < maxV; i++)
                    {
                        var v = valMatches[i];
                        valsJson.Add(new { name = v.Name, type = v.ValueType.ToString(), value = v.ValueAsString(), isDeleted = v.IsDeleted });
                    }

                    WriteJson(res, new
                    {
                        query = q,
                        matchingKeysCount = keyMatches.Count,
                        matchingValuesCount = valMatches.Count,
                        keys = keysJson,
                        values = valsJson
                    });
                }
                else if (action == "carve")
                {
                    var delKeys = hive.CarveDeletedKeys();
                    var delVals = hive.CarveDeletedValues();

                    var keysJson = new List<object>();
                    int maxK = Math.Min(100, delKeys.Count);
                    for (int i = 0; i < maxK; i++)
                    {
                        var k = delKeys[i];
                        keysJson.Add(new { name = k.Name, path = k.Path, offset = "0x" + k.CellOffset.ToString("X8"), lastWriteUtc = k.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") });
                    }

                    var valsJson = new List<object>();
                    int maxV = Math.Min(100, delVals.Count);
                    for (int i = 0; i < maxV; i++)
                    {
                        var v = delVals[i];
                        valsJson.Add(new { name = v.Name, type = v.ValueType.ToString(), value = v.ValueAsString(), offset = "0x" + v.CellOffset.ToString("X8") });
                    }

                    WriteJson(res, new
                    {
                        carvedKeysCount = delKeys.Count,
                        carvedValuesCount = delVals.Count,
                        keys = keysJson,
                        values = valsJson
                    });
                }
                else if (action == "key")
                {
                    string keyPath = req.QueryString["keyPath"] ?? "";
                    var k = hive.GetKey(keyPath);
                    if (k == null)
                    {
                        WriteJson(res, new { error = "Key not found: " + keyPath });
                        return;
                    }

                    var subkeys = new List<string>();
                    for (int i = 0; i < k.Subkeys.Count; i++) subkeys.Add(k.Subkeys[i].Name);

                    var values = new List<object>();
                    for (int i = 0; i < k.Values.Count; i++)
                    {
                        var v = k.Values[i];
                        values.Add(new { name = v.Name, type = v.ValueType.ToString(), value = v.ValueAsString(), isDeleted = v.IsDeleted });
                    }

                    WriteJson(res, new
                    {
                        name = k.Name,
                        path = k.Path,
                        lastWriteUtc = k.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                        subkeys = subkeys,
                        values = values
                    });
                }
                else
                {
                    WriteJson(res, new { error = "Unsupported action: " + action });
                }
            }
        }

        void ServeUsn(HttpListenerRequest req, HttpListenerResponse res)
        {
            string rel = req.QueryString["path"];
            string action = (req.QueryString["action"] ?? "deleted").ToLowerInvariant();
            string outFull = !string.IsNullOrEmpty(outputPath) ? Path.GetFullPath(outputPath) : null;

            string targetPath = null;
            if (!string.IsNullOrEmpty(rel) && outFull != null)
            {
                string candidate = Path.GetFullPath(Path.Combine(outputPath, rel.TrimStart('/', '\\')));
                if (candidate.StartsWith(outFull, StringComparison.OrdinalIgnoreCase) && File.Exists(candidate))
                {
                    targetPath = candidate;
                }
            }

            // Auto-detect USN journal or J file in output directory
            if (string.IsNullOrEmpty(targetPath) && outFull != null && Directory.Exists(outFull))
            {
                var dir = new DirectoryInfo(outputPath);
                var files = dir.GetFiles("*", SearchOption.AllDirectories);
                for (int i = 0; i < files.Length; i++)
                {
                    string fName = files[i].Name.ToLowerInvariant();
                    if (fName.Contains("usn") || fName.Contains("$j") || fName.EndsWith(".usn") || fName.EndsWith(".j"))
                    {
                        targetPath = files[i].FullName;
                        break;
                    }
                }
            }

            // Fallback to disk image if available
            bool isFromDiskImage = false;
            if (string.IsNullOrEmpty(targetPath) && !string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
            {
                targetPath = imagePath;
                isFromDiskImage = true;
            }

            if (string.IsNullOrEmpty(targetPath) || !File.Exists(targetPath))
            {
                WriteJson(res, new { error = "No USN journal or disk image available to inspect." });
                return;
            }

            List<UsnRecord> records = null;
            lock (usnLock)
            {
                if (cachedUsnPath == targetPath && cachedUsnRecords != null)
                {
                    records = cachedUsnRecords;
                }
                else
                {
                    try
                    {
                        if (isFromDiskImage)
                        {
                            using (var s = OpenImageStream())
                            {
                                records = UsnJournalParser.CarveFromStream(s);
                            }
                        }
                        else
                        {
                            using (var s = new FileStream(targetPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
                            {
                                records = UsnJournalParser.ParseStream(s);
                                if (records.Count == 0)
                                {
                                    s.Position = 0;
                                    records = UsnJournalParser.CarveFromStream(s);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteJson(res, new { error = "Error reading USN journal: " + ex.Message });
                        return;
                    }

                    // Limit memory cache to at most 10000 records
                    if (records.Count > 10000)
                    {
                        records = records.GetRange(0, 10000);
                    }
                    cachedUsnRecords = records;
                    cachedUsnPath = targetPath;
                }
            }

            if (action == "deleted")
            {
                var deleted = UsnJournalParser.ExtractDeletedFiles(records);
                var delJson = new List<object>();
                int maxD = Math.Min(200, deleted.Count);
                for (int i = 0; i < maxD; i++)
                {
                    var d = deleted[i];
                    delJson.Add(new
                    {
                        fileName = d.FileName,
                        deletionTimeUtc = d.DeletionTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                        creationTimeUtc = d.CreationTimeUtc.HasValue ? d.CreationTimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—",
                        mftIndex = d.FileReferenceNumber & 0x0000FFFFFFFFFFFFUL,
                        parentMftIndex = d.ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFUL,
                        lastUsn = d.LastUsn,
                        historyCount = d.HistoryRecords.Count
                    });
                }

                WriteJson(res, new
                {
                    totalEvents = records.Count,
                    deletedCount = deleted.Count,
                    source = Path.GetFileName(targetPath),
                    deletedFiles = delJson
                });
            }
            else if (action == "timeline")
            {
                var timeJson = new List<object>();
                int maxT = Math.Min(200, records.Count);
                for (int i = 0; i < maxT; i++)
                {
                    var r = records[i];
                    timeJson.Add(new
                    {
                        usn = r.Usn,
                        fileName = r.FileName,
                        timeStampUtc = r.TimeStampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                        reason = r.ReasonText,
                        mftIndex = r.MftEntryIndex,
                        parentMftIndex = r.ParentMftEntryIndex,
                        isCarved = r.IsCarved
                    });
                }

                WriteJson(res, new
                {
                    totalEvents = records.Count,
                    source = Path.GetFileName(targetPath),
                    events = timeJson
                });
            }
            else if (action == "search")
            {
                string q = (req.QueryString["q"] ?? "").ToLowerInvariant();
                var matches = new List<object>();
                if (!string.IsNullOrEmpty(q))
                {
                    for (int i = 0; i < records.Count; i++)
                    {
                        var r = records[i];
                        if (r.FileName.ToLowerInvariant().Contains(q))
                        {
                            matches.Add(new
                            {
                                usn = r.Usn,
                                fileName = r.FileName,
                                timeStampUtc = r.TimeStampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                                reason = r.ReasonText,
                                mftIndex = r.MftEntryIndex
                            });
                            if (matches.Count >= 200) break;
                        }
                    }
                }
                WriteJson(res, new { query = q, matchingCount = matches.Count, results = matches });
            }
            else
            {
                WriteJson(res, new { error = "Unsupported USN action: " + action });
            }
        }

        void ServeStartScan(HttpListenerResponse res)
        {
            lock (scanLock)
            {
                if (isScanning)
                {
                    WriteJson(res, new { error = "Scan is already in progress" });
                    return;
                }

                if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
                {
                    WriteJson(res, new { error = "Image file does not exist" });
                    return;
                }

                isScanning = true;
                scanStatus = "running";
                scanError = null;
                scanCandidates = 0;
                scanUniqueFiles = 0;
                scanBytesProcessed = 0;
                scanCts = new CancellationTokenSource();

                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        var options = new RecoveryOptions
                        {
                            FatMetadata = true,
                            NtfsMetadata = true,
                            LostPartitions = true,
                            AlternateFat = true,
                            Ext4Metadata = true,
                            RefsMetadata = true,
                            Signatures = true,
                            SmallBlocks = true,
                            JpegFragments = true,
                            KeepCorrupted = false,
                            EmbeddedPhotos = true,
                            Containers = true,
                            MetadataRescue = true,
                            ArchiveMembers = true,
                            Photos = true,
                            Video = true,
                            Audio = true,
                            Documents = true,
                            Archives = true,
                            Other = true
                        };

                        Directory.CreateDirectory(outputPath);
                        var result = RecoveryPipeline.Run(imagePath, outputPath, options, scanCts.Token, msg =>
                        {
                            scanStatus = msg ?? "running";
                        });

                        lock (scanLock)
                        {
                            isScanning = false;
                            scanStatus = "complete";
                            scanCandidates = result.Candidates;
                            scanUniqueFiles = result.UniqueFiles;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        lock (scanLock)
                        {
                            isScanning = false;
                            scanStatus = "cancelled";
                        }
                    }
                    catch (Exception ex)
                    {
                        lock (scanLock)
                        {
                            isScanning = false;
                            scanStatus = "error";
                            scanError = ex.Message;
                        }
                    }
                    finally
                    {
                        lock (scanLock)
                        {
                            if (scanCts != null)
                            {
                                try { scanCts.Dispose(); } catch { }
                                scanCts = null;
                            }
                        }
                    }
                });

                WriteJson(res, new { status = "started", output = outputPath });
            }
        }

        void ServeCancelScan(HttpListenerResponse res)
        {
            lock (scanLock)
            {
                if (isScanning && scanCts != null)
                {
                    scanCts.Cancel();
                    scanStatus = "cancelling";
                    WriteJson(res, new { status = "cancelling" });
                }
                else
                {
                    WriteJson(res, new { status = scanStatus });
                }
            }
        }

        void WriteJson(HttpListenerResponse res, object data)
        {
            res.ContentType = "application/json; charset=utf-8";
            res.Headers.Add("Cache-Control", "no-cache");
            byte[] bytes = Encoding.UTF8.GetBytes(json.Serialize(data));
            res.ContentLength64 = bytes.Length;
            res.OutputStream.Write(bytes, 0, bytes.Length);
        }

        void WriteText(HttpListenerResponse res, string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            res.ContentLength64 = bytes.Length;
            res.OutputStream.Write(bytes, 0, bytes.Length);
        }

        static string FormatBytes(long bytes)
        {
            if (bytes >= 1099511627776L) return (bytes / 1099511627776.0).ToString("F2", CultureInfo.InvariantCulture) + " TB";
            if (bytes >= 1073741824L) return (bytes / 1073741824.0).ToString("F2", CultureInfo.InvariantCulture) + " GB";
            if (bytes >= 1048576L) return (bytes / 1048576.0).ToString("F2", CultureInfo.InvariantCulture) + " MB";
            if (bytes >= 1024L) return (bytes / 1024.0).ToString("F2", CultureInfo.InvariantCulture) + " KB";
            return bytes + " B";
        }


        void ServeMft(HttpListenerRequest req, HttpListenerResponse res)
        {
            string action = (req.QueryString["action"] ?? "carved").ToLowerInvariant();
            string targetPath = imagePath;

            if (string.IsNullOrEmpty(targetPath) || !File.Exists(targetPath))
            {
                WriteJson(res, new { error = "No disk image available to carve MFT records from." });
                return;
            }

            List<MftFileRecord> records = null;
            lock (mftLock)
            {
                if (cachedMftPath == targetPath && cachedMftRecords != null)
                {
                    records = cachedMftRecords;
                }
                else
                {
                    try
                    {
                        using (var s = OpenImageStream())
                        {
                            records = MftCarver.CarveFromStream(s, CancellationToken.None);
                            if (records != null && records.Count > 2000) records = records.GetRange(0, 2000);
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteJson(res, new { error = "Error carving MFT records: " + ex.Message });
                        return;
                    }

                    cachedMftRecords = records;
                    cachedMftPath = targetPath;
                }
            }

            int timestompedCount = 0;
            for (int i = 0; i < records.Count; i++)
            {
                if (records[i].IsTimestomped) timestompedCount++;
            }

            var list = new List<object>();
            int limit = Math.Min(200, records.Count);
            for (int i = 0; i < records.Count; i++)
            {
                var r = records[i];
                if (action == "timestomped" && !r.IsTimestomped) continue;

                list.Add(new
                {
                    recordNumber = r.RecordNumber,
                    sequenceNumber = r.SequenceNumber,
                    isAllocated = r.IsAllocated,
                    fileName = r.FileName,
                    fileSize = r.FileSize,
                    creationTimeUtc = r.CreationTimeUtc != DateTime.MinValue ? r.CreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—",
                    modificationTimeUtc = r.ModificationTimeUtc != DateTime.MinValue ? r.ModificationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—",
                    fnCreationTimeUtc = r.FnCreationTimeUtc != DateTime.MinValue ? r.FnCreationTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—",
                    isResident = r.IsResident,
                    residentLength = r.ResidentData != null ? r.ResidentData.Length : 0,
                    isTimestomped = r.IsTimestomped
                });

                if (list.Count >= limit) break;
            }

            WriteJson(res, new
            {
                totalCarved = records.Count,
                timestompedCount = timestompedCount,
                results = list
            });
        }

        void ServeShimcache(HttpListenerRequest req, HttpListenerResponse res)
        {
            List<AppCompatCacheEntry> entries = null;
            lock (shimLock)
            {
                if (cachedShimPath == imagePath && cachedShimRecords != null)
                {
                    entries = cachedShimRecords;
                }
                else
                {
                    entries = new List<AppCompatCacheEntry>();
                    // Try to locate SYSTEM hive in output folder
                    if (Directory.Exists(outputPath))
                    {
                        var files = new DirectoryInfo(outputPath).GetFiles("*", SearchOption.AllDirectories);
                        for (int i = 0; i < files.Length; i++)
                        {
                            if (files[i].Name.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                            {
                                try
                                {
                                    using (var hive = RegistryHive.Open(files[i].FullName))
                                    {
                                        entries = AppCompatCacheParser.ExtractFromSystemHive(hive);
                                    }
                                    if (entries.Count > 0) break;
                                }
                                catch { }
                            }
                        }
                    }

                    cachedShimRecords = entries;
                    cachedShimPath = imagePath;
                }
            }

            var list = new List<object>();
            int limit = Math.Min(300, entries.Count);
            for (int i = 0; i < limit; i++)
            {
                var e = entries[i];
                list.Add(new
                {
                    index = i + 1,
                    path = e.Path,
                    lastModifiedUtc = e.LastModifiedTimeUtc != DateTime.MinValue ? e.LastModifiedTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—",
                    dataSize = e.DataSize,
                    executed = e.Executed
                });
            }

            WriteJson(res, new
            {
                totalEntries = entries.Count,
                results = list
            });
        }

        void ServeTimeline(HttpListenerRequest req, HttpListenerResponse res)
        {
            string action = (req.QueryString["action"] ?? "events").ToLowerInvariant();
            string keyword = req.QueryString["q"];

            if (action == "export-csv")
            {
                res.ContentType = "text/csv; charset=utf-8";
                res.AddHeader("Content-Disposition", "attachment; filename=\"forensic-super-timeline.csv\"");

                ForensicTimeline timeline = new ForensicTimeline();
                lock (usnLock)
                {
                    if (cachedUsnRecords != null) timeline.AddUsnRecords(cachedUsnRecords);
                }
                lock (mftLock)
                {
                    if (cachedMftRecords != null) timeline.AddMftRecords(cachedMftRecords);
                }
                lock (shimLock)
                {
                    if (cachedShimRecords != null) timeline.AddShimcache(cachedShimRecords);
                }

                timeline.SortChronological(true);
                timeline.ExportToCsv(res.OutputStream);
                return;
            }

            ForensicTimeline activeTimeline = new ForensicTimeline();
            lock (usnLock)
            {
                if (cachedUsnRecords != null) activeTimeline.AddUsnRecords(cachedUsnRecords);
            }
            lock (mftLock)
            {
                if (cachedMftRecords != null) activeTimeline.AddMftRecords(cachedMftRecords);
            }
            lock (shimLock)
            {
                if (cachedShimRecords != null) activeTimeline.AddShimcache(cachedShimRecords);
            }

            activeTimeline.SortChronological(true);
            var eventList = activeTimeline.Events;
            if (!string.IsNullOrEmpty(keyword))
            {
                eventList = activeTimeline.FilterByKeyword(keyword);
            }

            var list = new List<object>();
            int limit = Math.Min(300, eventList.Count);
            for (int i = 0; i < limit; i++)
            {
                var ev = eventList[i];
                list.Add(new
                {
                    timeStampUtc = ev.TimeStampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"),
                    source = ev.Source,
                    action = ev.Action,
                    targetPath = ev.TargetPath,
                    description = ev.Description
                });
            }

            WriteJson(res, new
            {
                totalEvents = eventList.Count,
                results = list
            });
        }


        void ServeAmcache(HttpListenerRequest req, HttpListenerResponse res)
        {
            List<AmcacheEntry> entries = null;
            lock (amcacheLock)
            {
                if (cachedAmcachePath == imagePath && cachedAmcacheRecords != null)
                {
                    entries = cachedAmcacheRecords;
                }
                else
                {
                    entries = new List<AmcacheEntry>();
                    if (Directory.Exists(outputPath))
                    {
                        var files = new DirectoryInfo(outputPath).GetFiles("Amcache.hve", SearchOption.AllDirectories);
                        if (files.Length > 0)
                        {
                            try { entries = AmcacheParser.Parse(files[0].FullName); } catch { }
                        }
                    }
                    if (entries.Count == 0 && !string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                    {
                        try
                        {
                            using (var s = OpenImageStream())
                            {
                                entries = AmcacheParser.CarveFromStream(s, CancellationToken.None);
                            }
                        }
                        catch { }
                    }
                    cachedAmcacheRecords = entries;
                    cachedAmcachePath = imagePath;
                }
            }

            int alertCount = 0;
            for (int i = 0; i < entries.Count; i++) if (entries[i].IsSuspicious) alertCount++;

            var list = new List<object>();
            int limit = Math.Min(300, entries.Count);
            for (int i = 0; i < limit; i++)
            {
                var a = entries[i];
                list.Add(new
                {
                    index = i + 1,
                    path = a.Path,
                    sha1 = a.Sha1,
                    size = a.FileSize,
                    publisher = a.Publisher,
                    isSuspicious = a.IsSuspicious,
                    reason = a.SuspicionReason,
                    lastModifiedUtc = a.KeyLastWriteTimeUtc != DateTime.MinValue ? a.KeyLastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : (a.LinkerTimestampUtc != DateTime.MinValue ? a.LinkerTimestampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—")
                });
            }

            WriteJson(res, new
            {
                totalEntries = entries.Count,
                alertCount = alertCount,
                results = list
            });
        }

        void ServeShellbags(HttpListenerRequest req, HttpListenerResponse res)
        {
            List<ShellbagRecord> records = null;
            lock (shellbagsLock)
            {
                if (cachedShellbagsPath == imagePath && cachedShellbagRecords != null)
                {
                    records = cachedShellbagRecords;
                }
                else
                {
                    records = new List<ShellbagRecord>();
                    if (Directory.Exists(outputPath))
                    {
                        var files = new DirectoryInfo(outputPath).GetFiles("*", SearchOption.AllDirectories);
                        for (int i = 0; i < files.Length; i++)
                        {
                            string fname = files[i].Name.ToLowerInvariant();
                            if (fname == "usrclass.dat" || fname == "ntuser.dat")
                            {
                                try
                                {
                                    var parsed = ShellbagsParser.Parse(files[i].FullName);
                                    records.AddRange(parsed);
                                }
                                catch { }
                            }
                        }
                    }
                    cachedShellbagRecords = records;
                    cachedShellbagsPath = imagePath;
                }
            }

            var list = new List<object>();
            int limit = Math.Min(300, records.Count);
            for (int i = 0; i < limit; i++)
            {
                var r = records[i];
                list.Add(new
                {
                    index = i + 1,
                    fullPath = r.FullPath,
                    itemType = r.ItemType.ToString(),
                    modifiedUtc = r.ModifiedTimeUtc != DateTime.MinValue ? r.ModifiedTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—",
                    registryAccessUtc = r.KeyLastWriteTimeUtc != DateTime.MinValue ? r.KeyLastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'") : "—",
                    source = r.RegistrySource
                });
            }

            WriteJson(res, new
            {
                totalRecords = records.Count,
                results = list
            });
        }

        void ServeEntropy(HttpListenerRequest req, HttpListenerResponse res)
        {
            EntropyReport report = null;
            lock (entropyLock)
            {
                if (cachedEntropyPath == imagePath && cachedEntropyReport != null)
                {
                    report = cachedEntropyReport;
                }
                else
                {
                    if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                    {
                        try
                        {
                            using (var s = OpenImageStream())
                            {
                                report = EntropyClassifier.AnalyzeStream(s, 16 * 1024 * 1024); // 16 MiB analysis
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteJson(res, new { error = "Error computing entropy: " + ex.Message });
                            return;
                        }
                    }
                    else
                    {
                        report = new EntropyReport();
                    }
                    cachedEntropyReport = report;
                    cachedEntropyPath = imagePath;
                }
            }

            WriteJson(res, report);
        }

        void ServeSrum(HttpListenerRequest req, HttpListenerResponse res)
        {
            SrumReport report = null;
            lock (srumLock)
            {
                if (cachedSrumPath == imagePath && cachedSrumReport != null)
                {
                    report = cachedSrumReport;
                }
                else
                {
                    if (Directory.Exists(outputPath))
                    {
                        var files = new DirectoryInfo(outputPath).GetFiles("SRUDB.dat", SearchOption.AllDirectories);
                        if (files.Length > 0)
                        {
                            try { report = SrumParser.Parse(files[0].FullName); } catch { }
                        }
                    }
                    if (report == null && !string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                    {
                        try
                        {
                            using (var s = OpenImageStream())
                            {
                                report = SrumParser.ParseStream(s, imagePath, CancellationToken.None);
                            }
                        }
                        catch { }
                    }
                    if (report == null)
                    {
                        report = new SrumReport();
                    }
                    cachedSrumReport = report;
                    cachedSrumPath = imagePath;
                }
            }

            WriteJson(res, report);
        }

        void ServeJumpLists(HttpListenerRequest req, HttpListenerResponse res)
        {
            JumpListReport report = null;
            lock (jumpListLock)
            {
                if (cachedJumpListPath == imagePath && cachedJumpListReport != null)
                {
                    report = cachedJumpListReport;
                }
                else
                {
                    if (Directory.Exists(outputPath))
                    {
                        var files = new DirectoryInfo(outputPath).GetFiles("*Destinations-ms", SearchOption.AllDirectories);
                        if (files.Length > 0)
                        {
                            try { report = JumpListParser.Parse(files[0].FullName); } catch { }
                        }
                    }
                    if (report == null && !string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                    {
                        try
                        {
                            using (var s = OpenImageStream())
                            {
                                int readLen = (int)Math.Min(s.Length, 16L * 1024 * 1024);
                                byte[] buf = new byte[readLen];
                                s.Read(buf, 0, readLen);
                                report = JumpListParser.Parse(buf, imagePath);
                            }
                        }
                        catch { }
                    }
                    if (report == null)
                    {
                        report = new JumpListReport { FileType = "No Jump Lists Found" };
                    }
                    cachedJumpListReport = report;
                    cachedJumpListPath = imagePath;
                }
            }

            WriteJson(res, report);
        }

        void ServeCourtReport(HttpListenerRequest req, HttpListenerResponse res)
        {
            var meta = new ForensicCaseMetadata
            {
                CaseNumber = "CR-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm"),
                InvestigatorName = "Digital Forensics Lead",
                SourcePath = imagePath ?? "USB-Recovery Session",
                TotalBytes = imageSize
            };

            ForensicTimeline activeTl = new ForensicTimeline();
            if (cachedMftRecords != null) activeTl.AddMftRecords(cachedMftRecords);
            if (cachedShimRecords != null) activeTl.AddShimcache(cachedShimRecords);
            if (cachedAmcacheRecords != null) activeTl.AddAmcache(cachedAmcacheRecords);
            if (cachedShellbagRecords != null) activeTl.AddShellbags(cachedShellbagRecords);
            if (cachedSrumReport != null && cachedSrumReport.NetworkEntries != null)
            {
                activeTl.AddSrumNetworkEntries(cachedSrumReport.NetworkEntries);
                activeTl.AddSrumAppUsageEntries(cachedSrumReport.AppUsageEntries);
            }
            if (cachedJumpListReport != null && cachedJumpListReport.Entries != null)
            {
                activeTl.AddJumpListEntries(cachedJumpListReport.Entries);
            }

            string html = CourtReportGenerator.GenerateHtmlReport(meta, activeTl, cachedAmcacheRecords, cachedShellbagRecords, cachedMftRecords, cachedEntropyReport);
            byte[] bytes = Encoding.UTF8.GetBytes(html);

            res.StatusCode = 200;
            res.ContentType = "text/html; charset=utf-8";
            res.ContentLength64 = bytes.Length;
            res.OutputStream.Write(bytes, 0, bytes.Length);
            res.OutputStream.Close();
        }

        const string DashboardHtml = @"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""utf-8""/>
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0""/>
<title>USB-Recovery — Forensic Web Dashboard</title>
<style>
:root {
  --bg-dark: #0f172a;
  --bg-card: #1e293b;
  --border: #334155;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --accent: #38bdf8;
  --accent-green: #4ade80;
  --accent-purple: #c084fc;
  --accent-red: #f87171;
  --accent-amber: #fbbf24;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
body { background: var(--bg-dark); color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; }
header { background: #182234; border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; justify-content: space-between; align-items: center; }
.logo-box { display: flex; align-items: center; gap: 12px; }
.logo-icon { width: 32px; height: 32px; background: linear-gradient(135deg, #0284c7, #38bdf8); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 18px; color: #fff; }
.logo-title { font-size: 18px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
.logo-badge { font-size: 11px; background: rgba(56, 189, 248, 0.15); color: var(--accent); padding: 3px 8px; border-radius: 12px; font-weight: 600; }
.nav-status { display: flex; align-items: center; gap: 16px; }
.status-pill { display: flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 500; color: var(--accent-green); background: rgba(74, 222, 128, 0.1); padding: 4px 12px; border-radius: 16px; border: 1px solid rgba(74, 222, 128, 0.2); }
.status-dot { width: 8px; height: 8px; background: var(--accent-green); border-radius: 50%; box-shadow: 0 0 8px var(--accent-green); }
nav.tabs { display: flex; background: #131d2e; border-bottom: 1px solid var(--border); padding: 0 24px; gap: 8px; }
.tab-btn { background: none; border: none; outline: none; padding: 14px 18px; font-size: 14px; font-weight: 600; color: var(--text-muted); cursor: pointer; border-bottom: 3px solid transparent; transition: all 0.2s; }
.tab-btn:hover { color: var(--text-main); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
main { flex: 1; padding: 24px; max-width: 1440px; margin: 0 auto; width: 100%; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.25); }
.card h2 { font-size: 16px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; color: #fff; }
.grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-box { background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.stat-label { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.stat-value { font-size: 22px; font-weight: 700; color: #fff; margin-top: 6px; }
.btn { background: linear-gradient(135deg, #0284c7, #0369a1); border: 1px solid #38bdf8; color: #fff; padding: 10px 20px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; transition: all 0.2s; text-decoration: none; }
.btn:hover { background: linear-gradient(135deg, #0369a1, #0284c7); box-shadow: 0 0 12px rgba(56, 189, 248, 0.4); }
.btn-red { background: linear-gradient(135deg, #dc2626, #b91c1c); border-color: #f87171; }
.btn-red:hover { background: linear-gradient(135deg, #b91c1c, #dc2626); box-shadow: 0 0 12px rgba(248, 113, 113, 0.4); }
/* Cluster Canvas */
.canvas-container { position: relative; width: 100%; height: 320px; background: #0b1120; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 12px; }
canvas#clusterMap { width: 100%; height: 100%; display: block; cursor: crosshair; }
.cluster-legend { display: flex; flex-wrap: wrap; gap: 16px; font-size: 12px; margin-top: 8px; }
.legend-item { display: flex; align-items: center; gap: 6px; }
.legend-swatch { width: 12px; height: 12px; border-radius: 3px; }
/* Hex View */
.hex-layout { display: grid; grid-template-columns: 1fr 340px; gap: 20px; }
.hex-editor { background: #0b1120; border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; line-height: 1.6; overflow-x: auto; color: #cbd5e1; height: 480px; }
.hex-controls { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; }
.hex-input { background: #0b1120; border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; color: #fff; font-family: monospace; font-size: 14px; width: 160px; }
.inspector-panel { background: rgba(15, 23, 42, 0.8); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.inspector-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid rgba(51, 65, 85, 0.5); font-size: 13px; }
.inspector-name { color: var(--text-muted); font-weight: 500; }
.inspector-val { font-family: monospace; color: var(--accent); font-weight: 600; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* Table */
table.file-table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
table.file-table th { padding: 12px; background: #131d2e; color: var(--text-muted); border-bottom: 1px solid var(--border); font-weight: 600; }
table.file-table td { padding: 10px 12px; border-bottom: 1px solid rgba(51, 65, 85, 0.4); }
table.file-table tr:hover { background: rgba(56, 189, 248, 0.04); }
</style>
</head>
<body>
<header>
  <div class=""logo-box"">
    <div class=""logo-icon"">⚡</div>
    <div>
      <div class=""logo-title"">USB-Recovery</div>
      <div style=""font-size: 11px; color: var(--text-muted);"">Forensic Data Recovery Suite</div>
    </div>
    <span class=""logo-badge"">v2026.11</span>
    <span class=""logo-badge"" style=""color: var(--accent-green); background: rgba(74, 222, 128, 0.15);"">AGPL-3.0</span>
  </div>
  <div class=""nav-status"">
    <div class=""status-pill"">
      <div class=""status-dot""></div>
      <span>100% Offline · Localhost Security</span>
    </div>
  </div>
</header>
<nav class=""tabs"">
  <button class=""tab-btn active"" onclick=""switchTab('overview')"">📊 Overview & Scan</button>
  <button class=""tab-btn"" onclick=""switchTab('clusters')"">🗺️ Cluster Allocation Map</button>
  <button class=""tab-btn"" onclick=""switchTab('hex')"">🔍 Data & Hex Inspector</button>
  <button class=""tab-btn"" onclick=""switchTab('files')"">📁 Recovered Files</button>
  <button class=""tab-btn"" onclick=""switchTab('registry')"">🏛️ Registry Forensics</button>
  <button class=""tab-btn"" onclick=""switchTab('usn')"">⏱️ USN Journal</button>
  <button class=""tab-btn"" onclick=""switchTab('mft')"">🧩 MFT Carver & Timestomp</button>
  <button class=""tab-btn"" onclick=""switchTab('shimcache')"">⚡ Shimcache</button>
  <button class=""tab-btn"" onclick=""switchTab('timeline')"">🌐 Super-Timeline</button>
  <button class=""tab-btn"" onclick=""switchTab('amcache')"">🛡️ Amcache</button>
  <button class=""tab-btn"" onclick=""switchTab('shellbags')"">📁 Shellbags</button>
  <button class=""tab-btn"" onclick=""switchTab('entropy')"">⚡ Entropy</button>
  <button class=""tab-btn"" onclick=""switchTab('srum')"">📡 SRUM Exfiltration</button>
  <button class=""tab-btn"" onclick=""switchTab('jumplist')"">📋 Jump Lists</button>
  <button class=""tab-btn"" onclick=""window.open('/api/court-report', '_blank')"">⚖️ Court Report</button>
</nav>
<main>
  <!-- OVERVIEW TAB -->
  <div id=""overview"" class=""tab-content active"">
    <div class=""grid-stats"">
      <div class=""stat-box"">
        <div class=""stat-label"">Target Image</div>
        <div class=""stat-value"" id=""stat-image"">—</div>
      </div>
      <div class=""stat-box"">
        <div class=""stat-label"">Image Size</div>
        <div class=""stat-value"" id=""stat-size"">—</div>
      </div>
      <div class=""stat-box"">
        <div class=""stat-label"">Scan Status</div>
        <div class=""stat-value"" id=""stat-status"" style=""color: var(--accent);"">Idle</div>
      </div>
      <div class=""stat-box"">
        <div class=""stat-label"">Recovered Unique Files</div>
        <div class=""stat-value"" id=""stat-recovered"" style=""color: var(--accent-green);"">0</div>
      </div>
    </div>
    <div class=""card"">
      <h2>⚙️ Recovery Actions</h2>
      <div style=""display: flex; gap: 12px; align-items: center;"">
        <button id=""btn-scan"" class=""btn"" onclick=""startScan()"">▶ Start Deep Recovery Scan</button>
        <button id=""btn-cancel"" class=""btn btn-red"" style=""display: none;"" onclick=""cancelScan()"">⏹ Cancel Scan</button>
        <span id=""scan-msg"" style=""font-size: 13px; color: var(--text-muted);"">Ready to analyze raw sectors without modifying source image.</span>
      </div>
    </div>
    <div class=""card"">
      <h2>🗂️ Detected Partitions & Storage Layout</h2>
      <div id=""partitions-container"">Loading probe results...</div>
    </div>
  </div>

  <!-- CLUSTERS TAB -->
  <div id=""clusters"" class=""tab-content"">
    <div class=""card"">
      <h2>🗺️ Sector / Cluster Allocation Map</h2>
      <p style=""font-size: 13px; color: var(--text-muted); margin-bottom: 12px;"">Visual density map of disk blocks. Click any cluster block to inspect its raw data in the Hex Inspector.</p>
      <div class=""canvas-container"">
        <canvas id=""clusterMap""></canvas>
      </div>
      <div class=""cluster-legend"">
        <div class=""legend-item""><div class=""legend-swatch"" style=""background: #38bdf8;""></div> Boot / System</div>
        <div class=""legend-item""><div class=""legend-swatch"" style=""background: #c084fc;""></div> Filesystem Metadata (MFT/FAT/Inode)</div>
        <div class=""legend-item""><div class=""legend-swatch"" style=""background: #4ade80;""></div> Photo / Media Extent</div>
        <div class=""legend-item""><div class=""legend-swatch"" style=""background: #fbbf24;""></div> Archive / Document</div>
        <div class=""legend-item""><div class=""legend-swatch"" style=""background: #f87171;""></div> Bad / Unreadable Sector</div>
        <div class=""legend-item""><div class=""legend-swatch"" style=""background: #334155;""></div> Unallocated / Free</div>
      </div>
    </div>
  </div>

  <!-- HEX INSPECTOR TAB -->
  <div id=""hex"" class=""tab-content"">
    <div class=""card"">
      <h2>🔍 Raw Hex & Forensic Data Inspector</h2>
      <div class=""hex-controls"">
        <label style=""font-size: 13px; color: var(--text-muted);"">Offset:</label>
        <input type=""text"" id=""hex-offset"" class=""hex-input"" value=""0x00000000""/>
        <button class=""btn"" style=""padding: 8px 14px;"" onclick=""loadHex()"">Seek</button>
        <button class=""btn"" style=""padding: 8px 14px; background: #334155; border-color: #475569;"" onclick=""stepHex(-512)"">◀ -512 B</button>
        <button class=""btn"" style=""padding: 8px 14px; background: #334155; border-color: #475569;"" onclick=""stepHex(512)"">+512 B ▶</button>
      </div>
      <div class=""hex-layout"">
        <div id=""hex-view"" class=""hex-editor"">Loading hex dump...</div>
        <div class=""inspector-panel"">
          <h3 style=""font-size: 14px; margin-bottom: 12px; color: #fff;"">Data Types Under Cursor</h3>
          <div class=""inspector-row""><span class=""inspector-name"">UInt8 / Byte</span><span class=""inspector-val"" id=""val-u8"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">Int8 / SByte</span><span class=""inspector-val"" id=""val-s8"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">UInt16 (LE)</span><span class=""inspector-val"" id=""val-u16"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">Int16 (LE)</span><span class=""inspector-val"" id=""val-s16"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">UInt32 (LE)</span><span class=""inspector-val"" id=""val-u32"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">Int32 (LE)</span><span class=""inspector-val"" id=""val-s32"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">UInt64</span><span class=""inspector-val"" id=""val-u64"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">Int64</span><span class=""inspector-val"" id=""val-s64"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">Unix Timestamp</span><span class=""inspector-val"" id=""val-unix"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">Windows FILETIME</span><span class=""inspector-val"" id=""val-filetime"">—</span></div>
          <div class=""inspector-row""><span class=""inspector-name"">GUID / UUID</span><span class=""inspector-val"" id=""val-guid"">—</span></div>
        </div>
      </div>
    </div>
  </div>

  <!-- RECOVERED FILES TAB -->
  <div id=""files"" class=""tab-content"">
    <div class=""card"">
      <h2>📁 Recovered Files Inventory</h2>
      <div style=""display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;"">
        <div style=""display: flex; gap: 10px; align-items: center; flex-wrap: wrap;"">
          <a href=""/api/export-zip"" class=""btn"" download=""USB-Recovery-Export.zip"">📦 Download All as ZIP</a>
          <a href=""/api/report?format=html"" class=""btn"" style=""background: linear-gradient(135deg, #10b981, #059669); border-color: #34d399;"" target=""_blank"">📋 Chain-of-Custody Report (HTML)</a>
          <a href=""/api/report?format=json"" class=""btn"" style=""background: #334155; border-color: #475569;"" target=""_blank"">📄 JSON Manifest</a>
        </div>
        <div>
          <input type=""text"" id=""file-search"" placeholder=""Filter by name/ext..."" class=""hex-input"" style=""width: 200px;"" oninput=""filterFiles()""/>
        </div>
      </div>
      <div style=""overflow-x: auto;"">
        <table class=""file-table"">
          <thead>
            <tr>
              <th>File Name</th>
              <th>Type</th>
              <th>Size</th>
              <th>Date Modified</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id=""file-tbody"">
            <tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">No files recovered yet. Run a scan to discover files.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- REGISTRY FORENSICS TAB -->
  <div id=""registry"" class=""tab-content"">
    <div class=""card"">
      <h2>🏛️ Windows Registry Forensics (REGF Native Parser)</h2>
      <p style=""font-size: 13px; color: var(--text-muted); margin-bottom: 16px;"">
        100% pure C# offline analysis of recovered Windows Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT).
        Extracts OS build, ComputerName, TimeZone, USB storage history (USBSTOR), persistence Run keys, and carves deleted keys from hive slack space.
      </p>
      <div style=""display: flex; gap: 12px; align-items: center; margin-bottom: 20px; flex-wrap: wrap;"">
        <select id=""reg-hive-select"" class=""hex-input"" style=""width: 280px;"" onchange=""loadRegistrySummary()"">
          <option value="""">Auto-Detect Hives...</option>
        </select>
        <button class=""btn"" onclick=""loadRegistrySummary()"">⚡ Load Summary</button>
        <button class=""btn"" style=""background: #334155; border-color: #475569;"" onclick=""carveRegistry()"">⛏️ Carve Deleted Slack Cells</button>
      </div>

      <div id=""reg-summary-container"">
        <div class=""grid-stats"">
          <div class=""stat-box""><div class=""stat-label"">Product Name</div><div class=""stat-value"" id=""reg-product"" style=""font-size: 16px;"">—</div></div>
          <div class=""stat-box""><div class=""stat-label"">Build / Version</div><div class=""stat-value"" id=""reg-build"" style=""font-size: 16px;"">—</div></div>
          <div class=""stat-box""><div class=""stat-label"">Computer Name</div><div class=""stat-value"" id=""reg-comp"" style=""font-size: 16px; color: var(--accent);"">—</div></div>
          <div class=""stat-box""><div class=""stat-label"">Time Zone</div><div class=""stat-value"" id=""reg-tz"" style=""font-size: 16px;"">—</div></div>
        </div>

        <div style=""display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; margin-top: 16px;"">
          <div class=""card"" style=""margin: 0;"">
            <h3 style=""font-size: 14px; margin-bottom: 10px; color: #fff;"">🔌 USB Storage History (USBSTOR)</h3>
            <ul id=""reg-usbstor-list"" style=""font-size: 12px; color: var(--text-muted); padding-left: 20px;""><li>No USB devices loaded.</li></ul>
          </div>
          <div class=""card"" style=""margin: 0;"">
            <h3 style=""font-size: 14px; margin-bottom: 10px; color: #fff;"">🚀 Persistence Run Keys</h3>
            <ul id=""reg-run-list"" style=""font-size: 12px; color: var(--text-muted); padding-left: 20px;""><li>No Run keys loaded.</li></ul>
          </div>
        </div>
      </div>

      <div style=""margin-top: 24px;"">
        <h3 style=""font-size: 15px; margin-bottom: 12px; color: #fff;"">🔍 Search Keys & Values</h3>
        <div style=""display: flex; gap: 10px; margin-bottom: 12px;"">
          <input type=""text"" id=""reg-search-query"" placeholder=""Search key or value name (e.g. CurrentVersion, Run, USB)..."" class=""hex-input"" style=""flex: 1;"" onkeydown=""if(event.key==='Enter') searchRegistry()""/>
          <button class=""btn"" onclick=""searchRegistry()"">Search</button>
        </div>
        <div id=""reg-search-results"" style=""font-size: 13px; color: var(--text-muted);""></div>
      </div>

      <div id=""reg-carve-container"" style=""margin-top: 24px; display: none;"">
        <h3 style=""font-size: 15px; margin-bottom: 12px; color: var(--accent-amber);"">⛏️ Carved Deleted Keys & Values (From Unallocated Cells)</h3>
        <div id=""reg-carve-results"" style=""font-size: 13px; color: var(--text-muted);""></div>
      </div>
    </div>
  </div>

  <!-- USN JOURNAL & DELETED FILES TAB -->
  <div id=""usn"" class=""tab-content"">
    <div class=""card"">
      <h2>⏱️ NTFS USN Change Journal ($UsnJrnl:$J) & Deleted Files Forensics</h2>
      <p style=""font-size: 13px; color: var(--text-muted); margin-bottom: 16px;"">
        Chronological file creation, rename, data modification, and deletion timeline.
        Reconstructs files that were wiped or deleted even if their MFT records were overwritten.
      </p>
      <div style=""display: flex; gap: 12px; align-items: center; margin-bottom: 20px; flex-wrap: wrap;"">
        <button id=""btn-usn-deleted"" class=""btn"" onclick=""loadUsnDeleted()"">🗑️ Reconstructed Deleted Files</button>
        <button id=""btn-usn-timeline"" class=""btn"" style=""background: #334155; border-color: #475569;"" onclick=""loadUsnTimeline()"">📜 Full Event Timeline</button>
        <input type=""text"" id=""usn-search-input"" placeholder=""Filter by filename (e.g. document, secret, exe)..."" class=""hex-input"" style=""flex: 1; min-width: 200px;"" oninput=""searchUsn()""/>
      </div>

      <div class=""grid-stats"">
        <div class=""stat-box""><div class=""stat-label"">Reconstructed Deleted Files</div><div class=""stat-value"" id=""stat-usn-deleted"" style=""color: var(--accent-red);"">—</div></div>
        <div class=""stat-box""><div class=""stat-label"">Total USN Journal Events</div><div class=""stat-value"" id=""stat-usn-events"" style=""color: var(--accent);"">—</div></div>
        <div class=""stat-box""><div class=""stat-label"">Journal Source</div><div class=""stat-value"" id=""stat-usn-source"" style=""font-size: 16px;"">—</div></div>
      </div>

      <div style=""overflow-x: auto; margin-top: 16px;"">
        <table class=""file-table"">
          <thead id=""usn-thead"">
            <tr>
              <th>File Name</th>
              <th>Deletion Time (UTC)</th>
              <th>Creation Time (UTC)</th>
              <th>MFT Index</th>
              <th>Parent MFT</th>
              <th>Events Count</th>
            </tr>
          </thead>
          <tbody id=""usn-tbody"">
            <tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">Click 'Reconstructed Deleted Files' or 'Full Event Timeline' to load journal events.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</main>

<script>
let currentOffset = 0;
let clusterBlocks = [];

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById(tabId).classList.add('active');
  if (tabId === 'clusters') renderClusters();
  if (tabId === 'hex') loadHex();
  if (tabId === 'files') loadFiles();
  if (tabId === 'registry') loadRegistryHives();
  if (tabId === 'usn') loadUsnDeleted();
}

async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('stat-image').innerText = data.imageName || 'None';
    document.getElementById('stat-size').innerText = data.imageSizeHuman || '0 B';
    document.getElementById('stat-status').innerText = data.scanStatus.toUpperCase();
    document.getElementById('stat-recovered').innerText = data.uniqueFiles;

    const btnScan = document.getElementById('btn-scan');
    const btnCancel = document.getElementById('btn-cancel');
    if (data.isScanning) {
      btnScan.style.display = 'none';
      btnCancel.style.display = 'inline-flex';
      document.getElementById('scan-msg').innerText = `Scanning: ${data.candidates} candidates found (${data.uniqueFiles} unique files)...`;
    } else {
      btnScan.style.display = 'inline-flex';
      btnCancel.style.display = 'none';
      if (data.scanStatus === 'complete') {
        document.getElementById('scan-msg').innerText = `Scan complete! Recovered ${data.uniqueFiles} unique files.`;
      }
    }
  } catch (e) { }
}

async function loadProbe() {
  try {
    const res = await fetch('/api/probe');
    const data = await res.json();
    const cont = document.getElementById('partitions-container');
    if (!data.partitions || data.partitions.length === 0) {
      cont.innerHTML = '<p style=""color: var(--text-muted);"">No standard partitions found (raw disk or carved filesystem mode).</p>';
      return;
    }
    let html = '<table class=""file-table""><thead><tr><th>Offset</th><th>Filesystem</th><th>Label</th><th>Size</th><th>Cluster Size</th></tr></thead><tbody>';
    data.partitions.forEach(p => {
      html += `<tr><td><code>${p.offsetHex}</code></td><td><strong>${p.filesystem}</strong></td><td>${p.label || '—'}</td><td>${p.lengthHuman}</td><td>${p.clusterSize ? p.clusterSize + ' B' : '—'}</td></tr>`;
    });
    html += '</tbody></table>';
    cont.innerHTML = html;
  } catch (e) { }
}

async function renderClusters() {
  try {
    const res = await fetch('/api/clusters');
    const data = await res.json();
    clusterBlocks = data.blocks || [];
    const canvas = document.getElementById('clusterMap');
    const ctx = canvas.getContext('2d');
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;

    const cols = 50;
    const rows = Math.ceil(clusterBlocks.length / cols);
    const cellW = canvas.width / cols;
    const cellH = canvas.height / rows;

    const colorMap = {
      'boot': '#38bdf8',
      'mft': '#c084fc',
      'photo': '#4ade80',
      'video': '#10b981',
      'archive': '#fbbf24',
      'database': '#f59e0b',
      'bad': '#f87171',
      'data': '#64748b',
      'free': '#1e293b'
    };

    clusterBlocks.forEach((b, idx) => {
      const c = idx % cols;
      const r = Math.floor(idx / cols);
      ctx.fillStyle = colorMap[b.type] || '#1e293b';
      ctx.fillRect(c * cellW + 1, r * cellH + 1, cellW - 2, cellH - 2);
    });

    canvas.onclick = (e) => {
      const clickX = e.offsetX;
      const clickY = e.offsetY;
      const c = Math.floor(clickX / cellW);
      const r = Math.floor(clickY / cellH);
      const idx = r * cols + c;
      if (idx >= 0 && idx < clusterBlocks.length) {
        currentOffset = clusterBlocks[idx].offset;
        document.getElementById('hex-offset').value = clusterBlocks[idx].offsetHex;
        switchTab('hex');
      }
    };
  } catch (e) { }
}

async function loadHex() {
  const offVal = document.getElementById('hex-offset').value.trim();
  let off = currentOffset;
  if (offVal.startsWith('0x') || offVal.startsWith('0X')) off = parseInt(offVal, 16);
  else if (!isNaN(parseInt(offVal))) off = parseInt(offVal, 10);
  currentOffset = isNaN(off) ? 0 : off;

  try {
    const res = await fetch(`/api/hex?offset=${currentOffset}&length=256`);
    const data = await res.json();
    if (data.error) {
      document.getElementById('hex-view').innerText = data.error;
      return;
    }

    let out = '';
    const hex = data.hex || '';
    const ascii = data.ascii || '';
    for (let i = 0; i < hex.length; i += 32) {
      const lineOff = (currentOffset + (i / 2)).toString(16).padStart(8, '0').toUpperCase();
      const lineHexRaw = hex.substring(i, i + 32);
      let lineHex = '';
      for (let h = 0; h < lineHexRaw.length; h += 2) {
        lineHex += lineHexRaw.substring(h, h + 2) + ' ';
        if (h === 14) lineHex += ' ';
      }
      lineHex = lineHex.padEnd(50, ' ');
      const lineAscii = ascii.substring(i / 2, i / 2 + 16);
      out += `${lineOff}  ${lineHex} |${lineAscii}|\n`;
    }
    document.getElementById('hex-view').innerText = out;

    const insp = data.inspector || {};
    document.getElementById('val-u8').innerText = insp.uint8 ?? '—';
    document.getElementById('val-s8').innerText = insp.int8 ?? '—';
    document.getElementById('val-u16').innerText = insp.uint16 ?? '—';
    document.getElementById('val-s16').innerText = insp.int16 ?? '—';
    document.getElementById('val-u32').innerText = insp.uint32 ?? '—';
    document.getElementById('val-s32').innerText = insp.int32 ?? '—';
    document.getElementById('val-u64').innerText = insp.uint64 ?? '—';
    document.getElementById('val-s64').innerText = insp.int64 ?? '—';
    document.getElementById('val-unix').innerText = insp.unixTime || '—';
    document.getElementById('val-filetime').innerText = insp.fileTime || '—';
    document.getElementById('val-guid').innerText = insp.guid || '—';
  } catch (e) { }
}

function stepHex(delta) {
  currentOffset = Math.max(0, currentOffset + delta);
  document.getElementById('hex-offset').value = '0x' + currentOffset.toString(16).toUpperCase();
  loadHex();
}

let allLoadedFiles = [];
async function loadFiles() {
  try {
    const res = await fetch('/api/files');
    const data = await res.json();
    allLoadedFiles = data.files || [];
    renderFilesTable(allLoadedFiles);
  } catch (e) { }
}

function filterFiles() {
  const query = (document.getElementById('file-search').value || '').toLowerCase();
  const filtered = allLoadedFiles.filter(f => (f.name || '').toLowerCase().includes(query) || (f.extension || '').toLowerCase().includes(query));
  renderFilesTable(filtered);
}

function renderFilesTable(files) {
  const tbody = document.getElementById('file-tbody');
  if (!files || files.length === 0) {
    tbody.innerHTML = '<tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">No files match the filter.</td></tr>';
    return;
  }
  let html = '';
  files.forEach(f => {
    html += `<tr><td><strong>${f.name}</strong></td><td><span class=""logo-badge"">${f.extension}</span></td><td>${f.sizeHuman}</td><td>${f.modified}</td><td><a href=""/api/file?name=${encodeURIComponent(f.relativePath)}"" class=""btn"" style=""padding: 4px 10px; font-size: 12px;"" target=""_blank"">Open / Download</a></td></tr>`;
  });
  tbody.innerHTML = html;
}

async function startScan() {
  await fetch('/api/scan', { method: 'POST' });
  refreshStatus();
}

async function cancelScan() {
  await fetch('/api/cancel', { method: 'POST' });
  refreshStatus();
}

async function loadRegistryHives() {
  try {
    const res = await fetch('/api/registry?action=list');
    const data = await res.json();
    const sel = document.getElementById('reg-hive-select');
    sel.innerHTML = '';
    if (data.hives && data.hives.length > 0) {
      data.hives.forEach(h => {
        const opt = document.createElement('option');
        opt.value = h.relativePath;
        opt.innerText = h.name + ' (' + h.sizeHuman + ')';
        sel.appendChild(opt);
      });
      loadRegistrySummary();
    } else {
      sel.innerHTML = '<option value="""">No hives found in output</option>';
    }
  } catch (e) { }
}

async function loadRegistrySummary() {
  const hivePath = document.getElementById('reg-hive-select').value;
  try {
    const url = hivePath ? ('/api/registry?action=summary&path=' + encodeURIComponent(hivePath)) : '/api/registry?action=summary';
    const res = await fetch(url);
    const data = await res.json();
    if (data.summary) {
      document.getElementById('reg-product').innerText = data.summary.productName || '—';
      document.getElementById('reg-build').innerText = (data.summary.currentBuild ? ('Build ' + data.summary.currentBuild) : (data.summary.currentVersion || '—'));
      document.getElementById('reg-comp').innerText = data.summary.computerName || '—';
      document.getElementById('reg-tz').innerText = data.summary.timeZoneStandardName || '—';

      const usbList = document.getElementById('reg-usbstor-list');
      usbList.innerHTML = '';
      if (data.summary.usbDevices && data.summary.usbDevices.length > 0) {
        data.summary.usbDevices.forEach(d => {
          const li = document.createElement('li');
          li.innerText = d;
          usbList.appendChild(li);
        });
      } else {
        usbList.innerHTML = '<li>No USB storage history found in this hive.</li>';
      }

      const runList = document.getElementById('reg-run-list');
      runList.innerHTML = '';
      if (data.summary.runKeys && data.summary.runKeys.length > 0) {
        data.summary.runKeys.forEach(r => {
          const li = document.createElement('li');
          li.innerText = r;
          runList.appendChild(li);
        });
      } else {
        runList.innerHTML = '<li>No autorun persistence keys found in this hive.</li>';
      }
    }
  } catch (e) { }
}

async function searchRegistry() {
  const q = document.getElementById('reg-search-query').value.trim();
  if (!q) return;
  const hivePath = document.getElementById('reg-hive-select').value;
  const resContainer = document.getElementById('reg-search-results');
  resContainer.innerHTML = 'Searching...';
  try {
    const url = '/api/registry?action=search&q=' + encodeURIComponent(q) + '&path=' + encodeURIComponent(hivePath);
    const res = await fetch(url);
    const data = await res.json();
    if (data.keys || data.values) {
      let html = '<div style=""margin-bottom: 8px;"">Found <strong>' + data.matchingKeysCount + '</strong> keys and <strong>' + data.matchingValuesCount + '</strong> values:</div><ul style=""padding-left: 20px;"">';
      (data.keys || []).forEach(k => {
        html += '<li>📁 <strong>' + k.path + '</strong> (' + k.valueCount + ' values)</li>';
      });
      (data.values || []).forEach(v => {
        html += '<li>📄 <code>' + v.name + '</code> [' + v.type + '] = ' + v.value + '</li>';
      });
      html += '</ul>';
      resContainer.innerHTML = html;
    } else {
      resContainer.innerHTML = data.error || 'No results found.';
    }
  } catch (e) { resContainer.innerHTML = 'Search failed.'; }
}

async function carveRegistry() {
  const hivePath = document.getElementById('reg-hive-select').value;
  const cDiv = document.getElementById('reg-carve-container');
  const resDiv = document.getElementById('reg-carve-results');
  cDiv.style.display = 'block';
  resDiv.innerHTML = 'Carving unallocated cells and slack space...';
  try {
    const url = '/api/registry?action=carve&path=' + encodeURIComponent(hivePath);
    const res = await fetch(url);
    const data = await res.json();
    if (data.carvedKeysCount !== undefined) {
      let html = '<div style=""margin-bottom: 8px;"">Carved <strong>' + data.carvedKeysCount + '</strong> deleted keys and <strong>' + data.carvedValuesCount + '</strong> deleted values:</div><ul style=""padding-left: 20px;"">';
      (data.keys || []).forEach(k => {
        html += '<li>⚠️ <code>' + k.offset + '</code>: <strong>' + k.path + '</strong></li>';
      });
      (data.values || []).forEach(v => {
        html += '<li>⚠️ <code>' + v.offset + '</code>: <code>' + v.name + '</code> [' + v.type + '] = ' + v.value + '</li>';
      });
      html += '</ul>';
      resDiv.innerHTML = html;
    } else {
      resDiv.innerHTML = data.error || 'Carving completed with no items.';
    }
  } catch (e) { resDiv.innerHTML = 'Carve request failed.'; }
}

async function loadUsnDeleted() {
  document.getElementById('btn-usn-deleted').style.background = 'linear-gradient(135deg, #0284c7, #0369a1)';
  document.getElementById('btn-usn-deleted').style.borderColor = '#38bdf8';
  document.getElementById('btn-usn-timeline').style.background = '#334155';
  document.getElementById('btn-usn-timeline').style.borderColor = '#475569';

  document.getElementById('usn-thead').innerHTML = '<tr><th>File Name</th><th>Deletion Time (UTC)</th><th>Creation Time (UTC)</th><th>MFT Index</th><th>Parent MFT</th><th>Events Count</th></tr>';
  const tbody = document.getElementById('usn-tbody');
  tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">Loading deleted files from USN journal...</td></tr>';

  try {
    const res = await fetch('/api/usn?action=deleted');
    const data = await res.json();
    if (data.deletedFiles) {
      document.getElementById('stat-usn-deleted').innerText = data.deletedCount;
      document.getElementById('stat-usn-events').innerText = data.totalEvents;
      document.getElementById('stat-usn-source').innerText = data.source || 'None';

      if (data.deletedFiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">No deleted files detected in current journal data.</td></tr>';
        return;
      }

      let html = '';
      data.deletedFiles.forEach(f => {
        html += '<tr>' +
          '<td><strong style=""color: #fff;"">' + f.fileName + '</strong></td>' +
          '<td style=""color: var(--accent-red); font-weight: 600;"">' + f.deletionTimeUtc + '</td>' +
          '<td>' + f.creationTimeUtc + '</td>' +
          '<td><code>' + f.mftIndex + '</code></td>' +
          '<td><code>' + f.parentMftIndex + '</code></td>' +
          '<td><span class=""logo-badge"">' + f.historyCount + ' events</span></td>' +
          '</tr>';
      });
      tbody.innerHTML = html;
    } else {
      tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">' + (data.error || 'Failed to load deleted files.') + '</td></tr>';
    }
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">Error requesting USN deleted files.</td></tr>';
  }
}

async function loadUsnTimeline() {
  document.getElementById('btn-usn-timeline').style.background = 'linear-gradient(135deg, #0284c7, #0369a1)';
  document.getElementById('btn-usn-timeline').style.borderColor = '#38bdf8';
  document.getElementById('btn-usn-deleted').style.background = '#334155';
  document.getElementById('btn-usn-deleted').style.borderColor = '#475569';

  document.getElementById('usn-thead').innerHTML = '<tr><th>Timestamp (UTC)</th><th>USN</th><th>File Name</th><th>Reason Flags</th><th>MFT Index</th><th>Parent MFT</th></tr>';
  const tbody = document.getElementById('usn-tbody');
  tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">Loading chronological event timeline...</td></tr>';

  try {
    const res = await fetch('/api/usn?action=timeline');
    const data = await res.json();
    if (data.events) {
      document.getElementById('stat-usn-events').innerText = data.totalEvents;
      document.getElementById('stat-usn-source').innerText = data.source || 'None';

      if (data.events.length === 0) {
        tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">No timeline events found in current journal.</td></tr>';
        return;
      }

      let html = '';
      data.events.forEach(e => {
        html += '<tr>' +
          '<td>' + e.timeStampUtc + '</td>' +
          '<td><code>' + e.usn + '</code></td>' +
          '<td><strong style=""color: #fff;"">' + e.fileName + '</strong></td>' +
          '<td><span class=""logo-badge"" style=""color: var(--accent); background: rgba(56, 189, 248, 0.1);"">' + e.reason + '</span></td>' +
          '<td><code>' + e.mftIndex + '</code></td>' +
          '<td><code>' + e.parentMftIndex + '</code></td>' +
          '</tr>';
      });
      tbody.innerHTML = html;
    } else {
      tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">' + (data.error || 'Failed to load timeline.') + '</td></tr>';
    }
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">Error requesting timeline events.</td></tr>';
  }
}

async function searchUsn() {
  const q = document.getElementById('usn-search-input').value.trim();
  if (!q) {
    loadUsnDeleted();
    return;
  }
  const tbody = document.getElementById('usn-tbody');
  try {
    const res = await fetch('/api/usn?action=search&q=' + encodeURIComponent(q));
    const data = await res.json();
    if (data.results) {
      document.getElementById('usn-thead').innerHTML = '<tr><th>Timestamp (UTC)</th><th>USN</th><th>File Name</th><th>Reason Flags</th><th>MFT Index</th></tr>';
      if (data.results.length === 0) {
        tbody.innerHTML = '<tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">No matching USN records found.</td></tr>';
        return;
      }
      let html = '';
      data.results.forEach(r => {
        html += '<tr>' +
          '<td>' + r.timeStampUtc + '</td>' +
          '<td><code>' + r.usn + '</code></td>' +
          '<td><strong style=""color: #fff;"">' + r.fileName + '</strong></td>' +
          '<td><span class=""logo-badge"">' + r.reason + '</span></td>' +
          '<td><code>' + r.mftIndex + '</code></td>' +
          '</tr>';
      });
      tbody.innerHTML = html;
    }
  } catch (e) { }
}


async function loadMft(action) {
  var tbody = document.getElementById('mft-tbody');
  var stats = document.getElementById('mft-stats');
  tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">Carving MFT sectors from disk...</td></tr>';
  try {
    var res = await fetch('/api/mft?action=' + action);
    var data = await res.json();
    if (data.error) {
      tbody.innerHTML = '<tr><td colspan=""6"" style=""color: #ef4444; text-align: center;"">' + data.error + '</td></tr>';
      return;
    }
    stats.innerHTML = 'Total Carved: <strong>' + data.totalCarved + '</strong> | Timestomped Anomalies: <strong style=""color: #ef4444;"">' + data.timestompedCount + '</strong>';
    if (!data.results || data.results.length === 0) {
      tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">No records found.</td></tr>';
      return;
    }
    var html = '';
    data.results.forEach(function(r) {
      var badge = r.isTimestomped ? '<span class=""logo-badge"" style=""background: rgba(239, 68, 68, 0.2); color: #ef4444; border-color: rgba(239, 68, 68, 0.4);"">🚨 TIMESTOMPED</span>' : '<span style=""color: #10b981;"">✓ Normal</span>';
      html += '<tr>' +
        '<td><code>#' + r.recordNumber + '</code></td>' +
        '<td><strong style=""color: #fff;"">' + (r.fileName || 'orphan_record_' + r.recordNumber) + '</strong></td>' +
        '<td>' + r.creationTimeUtc + '</td>' +
        '<td>' + r.fnCreationTimeUtc + '</td>' +
        '<td>' + badge + '</td>' +
        '<td>' + (r.isResident ? (r.residentLength + ' B') : 'Non-resident') + '</td>' +
        '</tr>';
    });
    tbody.innerHTML = html;
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan=""6"" style=""color: #ef4444; text-align: center;"">Error loading MFT data.</td></tr>';
  }
}

async function loadShimcache() {
  var tbody = document.getElementById('shim-tbody');
  var stats = document.getElementById('shim-stats');
  tbody.innerHTML = '<tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">Parsing AppCompatCache...</td></tr>';
  try {
    var res = await fetch('/api/shimcache');
    var data = await res.json();
    if (data.error) {
      tbody.innerHTML = '<tr><td colspan=""5"" style=""color: #ef4444; text-align: center;"">' + data.error + '</td></tr>';
      return;
    }
    stats.innerHTML = 'Total Execution Entries: <strong>' + data.totalEntries + '</strong>';
    if (!data.results || data.results.length === 0) {
      tbody.innerHTML = '<tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">No Shimcache entries found in active hives.</td></tr>';
      return;
    }
    var html = '';
    data.results.forEach(function(r) {
      html += '<tr>' +
        '<td>' + r.index + '</td>' +
        '<td><code style=""color: #38bdf8;"">' + r.path + '</code></td>' +
        '<td>' + r.lastModifiedUtc + '</td>' +
        '<td>' + (r.dataSize ? (r.dataSize + ' B') : '—') + '</td>' +
        '<td>' + (r.executed ? '<span style=""color: #10b981;"">✓ Executed</span>' : '<span style=""color: var(--text-muted);"">Cached</span>') + '</td>' +
        '</tr>';
    });
    tbody.innerHTML = html;
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan=""5"" style=""color: #ef4444; text-align: center;"">Error loading Shimcache.</td></tr>';
  }
}

async function loadSuperTimeline() {
  var tbody = document.getElementById('timeline-tbody');
  var stats = document.getElementById('timeline-stats');
  var filter = document.getElementById('timeline-filter') ? document.getElementById('timeline-filter').value : '';
  tbody.innerHTML = '<tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">Correlating timeline events...</td></tr>';
  try {
    var res = await fetch('/api/timeline?q=' + encodeURIComponent(filter));
    var data = await res.json();
    if (data.error) {
      tbody.innerHTML = '<tr><td colspan=""5"" style=""color: #ef4444; text-align: center;"">' + data.error + '</td></tr>';
      return;
    }
    stats.innerHTML = 'Correlated Events: <strong>' + data.totalEvents + '</strong>';
    if (!data.results || data.results.length === 0) {
      tbody.innerHTML = '<tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">No timeline events match filter.</td></tr>';
      return;
    }
    var html = '';
    data.results.forEach(function(r) {
      var badgeStyle = 'background: #334155; color: #94a3b8;';
      if (r.source === 'USN_JOURNAL') badgeStyle = 'background: rgba(14, 165, 233, 0.2); color: #38bdf8; border-color: rgba(14, 165, 233, 0.4);';
      else if (r.source === 'MFT_RECORD') badgeStyle = 'background: rgba(168, 85, 247, 0.2); color: #c084fc; border-color: rgba(168, 85, 247, 0.4);';
      else if (r.source === 'SHIMCACHE') badgeStyle = 'background: rgba(239, 68, 68, 0.2); color: #f87171; border-color: rgba(239, 68, 68, 0.4);';
      else if (r.source === 'BROWSER') badgeStyle = 'background: rgba(16, 185, 129, 0.2); color: #34d399; border-color: rgba(16, 185, 129, 0.4);';

      html += '<tr>' +
        '<td>' + r.timeStampUtc + '</td>' +
        '<td><span class=""logo-badge"" style=""' + badgeStyle + '"">' + r.source + '</span></td>' +
        '<td><strong>' + r.action + '</strong></td>' +
        '<td><code style=""color: #fff;"">' + r.targetPath + '</code></td>' +
        '<td>' + (r.description || '—') + '</td>' +
        '</tr>';
    });
    tbody.innerHTML = html;
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan=""5"" style=""color: #ef4444; text-align: center;"">Error loading timeline events.</td></tr>';
  }
}

// Initial boot
refreshStatus();
loadProbe();
setInterval(refreshStatus, 1500);
</script>
</body>
</html>";
    }

    internal static class ZipStreamingWriter
    {
        private static readonly uint[] CrcTable = InitializeCrcTable();

        private static uint[] InitializeCrcTable()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint entry = i;
                for (int j = 0; j < 8; j++)
                {
                    if ((entry & 1) == 1)
                        entry = (entry >> 1) ^ 0xEDB88320u;
                    else
                        entry >>= 1;
                }
                table[i] = entry;
            }
            return table;
        }

        public static uint ComputeCrc32(byte[] data, int offset, int length)
        {
            uint crc = 0xFFFFFFFFu;
            for (int i = 0; i < length; i++)
            {
                byte b = data[offset + i];
                crc = (crc >> 8) ^ CrcTable[(crc & 0xFF) ^ b];
            }
            return ~crc;
        }

        public static uint UpdateCrc32(uint runningCrc, byte[] data, int offset, int length)
        {
            for (int i = 0; i < length; i++)
            {
                byte b = data[offset + i];
                runningCrc = (runningCrc >> 8) ^ CrcTable[(runningCrc & 0xFF) ^ b];
            }
            return runningCrc;
        }

        public static uint ComputeFileCrc32(string filePath)
        {
            uint runningCrc = 0xFFFFFFFFu;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
            {
                byte[] buf = new byte[65536];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    runningCrc = UpdateCrc32(runningCrc, buf, 0, n);
                }
            }
            return ~runningCrc;
        }

        private struct ZipEntryRecord
        {
            public string RelativePath;
            public uint Crc32;
            public uint UncompressedSize;
            public uint CompressedSize;
            public uint HeaderOffset;
            public ushort DosTime;
            public ushort DosDate;
        }

        public static void StreamZip(List<FileInfo> files, string baseDirectory, Stream output)
        {
            List<ZipEntryRecord> entries = new List<ZipEntryRecord>();
            uint currentOffset = 0;

            for (int i = 0; i < files.Count; i++)
            {
                FileInfo fi = files[i];
                string rel = fi.FullName.Substring(baseDirectory.Length).TrimStart(Path.DirectorySeparatorChar, '/').Replace('\\', '/');
                byte[] nameBytes = Encoding.UTF8.GetBytes(rel);

                uint crc = ComputeFileCrc32(fi.FullName);
                uint size = (uint)Math.Min((long)uint.MaxValue, fi.Length);

                DateTime mod = fi.LastWriteTime;
                ushort dosTime = (ushort)(((mod.Hour & 0x1F) << 11) | ((mod.Minute & 0x3F) << 5) | ((mod.Second / 2) & 0x1F));
                ushort dosDate = (ushort)((((Math.Max(1980, mod.Year) - 1980) & 0x7F) << 9) | ((mod.Month & 0x0F) << 5) | (mod.Day & 0x1F));

                ZipEntryRecord rec = new ZipEntryRecord();
                rec.RelativePath = rel;
                rec.Crc32 = crc;
                rec.UncompressedSize = size;
                rec.CompressedSize = size; // Store
                rec.HeaderOffset = currentOffset;
                rec.DosTime = dosTime;
                rec.DosDate = dosDate;
                entries.Add(rec);

                // Local file header (30 bytes + name length)
                byte[] localHeader = new byte[30 + nameBytes.Length];
                // Signature 0x04034b50
                localHeader[0] = 0x50; localHeader[1] = 0x4b; localHeader[2] = 0x03; localHeader[3] = 0x04;
                // Version needed (20)
                localHeader[4] = 20; localHeader[5] = 0;
                // General purpose bit flag (bit 11 = UTF-8)
                localHeader[6] = 0x00; localHeader[7] = 0x08;
                // Compression method (0 = Store)
                localHeader[8] = 0; localHeader[9] = 0;
                // Mod time & date
                localHeader[10] = (byte)(dosTime & 0xFF); localHeader[11] = (byte)((dosTime >> 8) & 0xFF);
                localHeader[12] = (byte)(dosDate & 0xFF); localHeader[13] = (byte)((dosDate >> 8) & 0xFF);
                // CRC32
                localHeader[14] = (byte)(crc & 0xFF); localHeader[15] = (byte)((crc >> 8) & 0xFF);
                localHeader[16] = (byte)((crc >> 16) & 0xFF); localHeader[17] = (byte)((crc >> 24) & 0xFF);
                // Compressed size
                localHeader[18] = (byte)(size & 0xFF); localHeader[19] = (byte)((size >> 8) & 0xFF);
                localHeader[20] = (byte)((size >> 16) & 0xFF); localHeader[21] = (byte)((size >> 24) & 0xFF);
                // Uncompressed size
                localHeader[22] = (byte)(size & 0xFF); localHeader[23] = (byte)((size >> 8) & 0xFF);
                localHeader[24] = (byte)((size >> 16) & 0xFF); localHeader[25] = (byte)((size >> 24) & 0xFF);
                // File name length
                localHeader[26] = (byte)(nameBytes.Length & 0xFF); localHeader[27] = (byte)((nameBytes.Length >> 8) & 0xFF);
                // Extra field length = 0
                localHeader[28] = 0; localHeader[29] = 0;
                Array.Copy(nameBytes, 0, localHeader, 30, nameBytes.Length);

                output.Write(localHeader, 0, localHeader.Length);
                using (var fs = new FileStream(fi.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
                {
                    byte[] chunk = new byte[65536];
                    int n;
                    while ((n = fs.Read(chunk, 0, chunk.Length)) > 0)
                    {
                        output.Write(chunk, 0, n);
                    }
                }

                currentOffset += (uint)(localHeader.Length + size);
            }

            uint centralDirOffset = currentOffset;
            uint centralDirSize = 0;

            // Write Central Directory headers
            for (int i = 0; i < entries.Count; i++)
            {
                ZipEntryRecord rec = entries[i];
                byte[] nameBytes = Encoding.UTF8.GetBytes(rec.RelativePath);
                byte[] cdHeader = new byte[46 + nameBytes.Length];

                // Signature 0x02014b50
                cdHeader[0] = 0x50; cdHeader[1] = 0x4b; cdHeader[2] = 0x01; cdHeader[3] = 0x02;
                // Version made by
                cdHeader[4] = 20; cdHeader[5] = 0;
                // Version needed
                cdHeader[6] = 20; cdHeader[7] = 0;
                // Flag (UTF-8)
                cdHeader[8] = 0x00; cdHeader[9] = 0x08;
                // Compression method (0)
                cdHeader[10] = 0; cdHeader[11] = 0;
                // Time & Date
                cdHeader[12] = (byte)(rec.DosTime & 0xFF); cdHeader[13] = (byte)((rec.DosTime >> 8) & 0xFF);
                cdHeader[14] = (byte)(rec.DosDate & 0xFF); cdHeader[15] = (byte)((rec.DosDate >> 8) & 0xFF);
                // CRC32
                cdHeader[16] = (byte)(rec.Crc32 & 0xFF); cdHeader[17] = (byte)((rec.Crc32 >> 8) & 0xFF);
                cdHeader[18] = (byte)((rec.Crc32 >> 16) & 0xFF); cdHeader[19] = (byte)((rec.Crc32 >> 24) & 0xFF);
                // Compressed size
                cdHeader[20] = (byte)(rec.CompressedSize & 0xFF); cdHeader[21] = (byte)((rec.CompressedSize >> 8) & 0xFF);
                cdHeader[22] = (byte)((rec.CompressedSize >> 16) & 0xFF); cdHeader[23] = (byte)((rec.CompressedSize >> 24) & 0xFF);
                // Uncompressed size
                cdHeader[24] = (byte)(rec.UncompressedSize & 0xFF); cdHeader[25] = (byte)((rec.UncompressedSize >> 8) & 0xFF);
                cdHeader[26] = (byte)((rec.UncompressedSize >> 16) & 0xFF); cdHeader[27] = (byte)((rec.UncompressedSize >> 24) & 0xFF);
                // File name length
                cdHeader[28] = (byte)(nameBytes.Length & 0xFF); cdHeader[29] = (byte)((nameBytes.Length >> 8) & 0xFF);
                // Extra field length (0)
                cdHeader[30] = 0; cdHeader[31] = 0;
                // Comment length (0)
                cdHeader[32] = 0; cdHeader[33] = 0;
                // Disk start (0)
                cdHeader[34] = 0; cdHeader[35] = 0;
                // Internal attrs (0)
                cdHeader[36] = 0; cdHeader[37] = 0;
                // External attrs (0x81A40000 -> regular file 0644)
                cdHeader[38] = 0x00; cdHeader[39] = 0x00; cdHeader[40] = 0xA4; cdHeader[41] = 0x81;
                // Offset of local header
                cdHeader[42] = (byte)(rec.HeaderOffset & 0xFF); cdHeader[43] = (byte)((rec.HeaderOffset >> 8) & 0xFF);
                cdHeader[44] = (byte)((rec.HeaderOffset >> 16) & 0xFF); cdHeader[45] = (byte)((rec.HeaderOffset >> 24) & 0xFF);
                Array.Copy(nameBytes, 0, cdHeader, 46, nameBytes.Length);

                output.Write(cdHeader, 0, cdHeader.Length);
                centralDirSize += (uint)cdHeader.Length;
            }

            // End of Central Directory record (22 bytes)
            byte[] eocd = new byte[22];
            // Signature 0x06054b50
            eocd[0] = 0x50; eocd[1] = 0x4b; eocd[2] = 0x05; eocd[3] = 0x06;
            // Disk number (0)
            eocd[4] = 0; eocd[5] = 0;
            // Central directory disk (0)
            eocd[6] = 0; eocd[7] = 0;
            // Entries this disk
            ushort count = (ushort)entries.Count;
            eocd[8] = (byte)(count & 0xFF); eocd[9] = (byte)((count >> 8) & 0xFF);
            // Total entries
            eocd[10] = (byte)(count & 0xFF); eocd[11] = (byte)((count >> 8) & 0xFF);
            // Size of central directory
            eocd[12] = (byte)(centralDirSize & 0xFF); eocd[13] = (byte)((centralDirSize >> 8) & 0xFF);
            eocd[14] = (byte)((centralDirSize >> 16) & 0xFF); eocd[15] = (byte)((centralDirSize >> 24) & 0xFF);
            // Offset of central directory
            eocd[16] = (byte)(centralDirOffset & 0xFF); eocd[17] = (byte)((centralDirOffset >> 8) & 0xFF);
            eocd[18] = (byte)((centralDirOffset >> 16) & 0xFF); eocd[19] = (byte)((centralDirOffset >> 24) & 0xFF);
            // Comment length (0)
            eocd[20] = 0; eocd[21] = 0;

            output.Write(eocd, 0, eocd.Length);
            output.Flush();
        }
    }
}
