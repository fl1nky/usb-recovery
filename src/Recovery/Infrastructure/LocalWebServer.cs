using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
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
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
            {
                WriteJson(res, new { blocks = new object[0] });
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
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
            {
                WriteJson(res, new { error = "Image not found" });
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
            byte[] fileBytes = File.ReadAllBytes(full);
            res.ContentLength64 = fileBytes.Length;
            res.OutputStream.Write(fileBytes, 0, fileBytes.Length);
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

async function loadFiles() {
  try {
    const res = await fetch('/api/files');
    const data = await res.json();
    const tbody = document.getElementById('file-tbody');
    if (!data.files || data.files.length === 0) {
      tbody.innerHTML = '<tr><td colspan=""5"" style=""text-align: center; color: var(--text-muted);"">No files recovered yet. Run a scan to discover files.</td></tr>';
      return;
    }
    let html = '';
    data.files.forEach(f => {
      html += `<tr><td><strong>${f.name}</strong></td><td><span class=""logo-badge"">${f.extension}</span></td><td>${f.sizeHuman}</td><td>${f.modified}</td><td><a href=""/api/file?name=${encodeURIComponent(f.relativePath)}"" class=""btn"" style=""padding: 4px 10px; font-size: 12px;"" target=""_blank"">Open / Download</a></td></tr>`;
    });
    tbody.innerHTML = html;
  } catch (e) { }
}

async function startScan() {
  await fetch('/api/scan', { method: 'POST' });
  refreshStatus();
}

async function cancelScan() {
  await fetch('/api/cancel', { method: 'POST' });
  refreshStatus();
}

// Initial boot
refreshStatus();
loadProbe();
setInterval(refreshStatus, 1500);
</script>
</body>
</html>";
    }
}
