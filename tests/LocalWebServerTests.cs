using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class LocalWebServerTests
{
    static int checks;

    static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
            throw new Exception("Assertion failed: " + message);
    }

    public static int Main(string[] args)
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "webserver_test_" + Guid.NewGuid().ToString("N"));
        string testImage = Path.Combine(tempDir, "test_disk.raw");

        try
        {
            Directory.CreateDirectory(tempDir);

            // Create a small synthetic test image (64 KiB)
            byte[] imageBytes = new byte[65536];
            // Write boot signature at 510-511
            imageBytes[510] = 0x55;
            imageBytes[511] = 0xAA;
            // Write a fake MFT record at offset 4096: "FILE"
            imageBytes[4096] = (byte)'F';
            imageBytes[4097] = (byte)'I';
            imageBytes[4098] = (byte)'L';
            imageBytes[4099] = (byte)'E';
            File.WriteAllBytes(testImage, imageBytes);

            string outputDir = Path.Combine(tempDir, "recovered");
            Directory.CreateDirectory(outputDir);
            File.WriteAllText(Path.Combine(outputDir, "recovered_file.txt"), "USB-Recovery offline test payload");

            // Test server lifecycle
            int testPort = 18080 + (new Random().Next(100, 900));
            using (var server = new LocalWebServer(testImage, outputDir, testPort))
            {
                Check(!server.IsRunning, "Server should not be running before Start()");
                server.Start();
                Check(server.IsRunning, "Server should be running after Start()");

                string baseUrl = "http://127.0.0.1:" + server.Port;

                // Test 1: GET / (Dashboard HTML)
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string html = client.DownloadString(baseUrl + "/");
                    Check(html.Contains("USB-Recovery"), "Dashboard HTML contains application title");
                    Check(html.Contains("Cluster Allocation Map"), "Dashboard HTML contains Cluster Allocation Map");
                    Check(html.Contains("Raw Hex & Forensic Data Inspector"), "Dashboard HTML contains Hex Inspector");
                }

                // Test 2: GET /api/status
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string statusJson = client.DownloadString(baseUrl + "/api/status");
                    var serializer = new JavaScriptSerializer();
                    var status = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(statusJson);

                    Check(status != null, "Status JSON parsed");
                    Check(status["app"].ToString() == "USB-Recovery", "Status app name is USB-Recovery");
                    Check(status["version"].ToString() == "2026.11", "Status version matches 2026.11");
                    Check(status["license"].ToString() == "AGPL-3.0", "Status license is AGPL-3.0");
                    Check(status["imageName"].ToString() == "test_disk.raw", "Status image name matches");
                }

                // Test 3: GET /api/clusters
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string clustersJson = client.DownloadString(baseUrl + "/api/clusters");
                    var serializer = new JavaScriptSerializer();
                    var clusters = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(clustersJson);

                    Check(clusters != null, "Clusters JSON parsed");
                    Check(clusters.ContainsKey("blocks"), "Clusters contains blocks array");
                    var blocks = (System.Collections.ArrayList)clusters["blocks"];
                    Check(blocks.Count > 0, "Clusters blocks array is populated");
                }

                // Test 4: GET /api/hex
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string hexJson = client.DownloadString(baseUrl + "/api/hex?offset=0&length=16");
                    var serializer = new JavaScriptSerializer();
                    var hex = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(hexJson);

                    Check(hex != null, "Hex JSON parsed");
                    Check(hex.ContainsKey("hex"), "Hex response contains hex string");
                    Check(hex.ContainsKey("inspector"), "Hex response contains inspector object");

                    var inspector = (System.Collections.Generic.Dictionary<string, object>)hex["inspector"];
                    Check(inspector.ContainsKey("uint8"), "Inspector contains uint8");
                    Check(inspector.ContainsKey("uint32"), "Inspector contains uint32");
                    Check(inspector.ContainsKey("guid"), "Inspector contains guid");
                }

                // Test 5: GET /api/files
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string filesJson = client.DownloadString(baseUrl + "/api/files");
                    var serializer = new JavaScriptSerializer();
                    var filesObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(filesJson);

                    Check(filesObj != null, "Files JSON parsed");
                    Check(Convert.ToInt32(filesObj["count"]) >= 1, "Files count is at least 1");
                }

                // Test 6: GET /api/file content streaming
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string content = client.DownloadString(baseUrl + "/api/file?name=recovered_file.txt");
                    Check(content == "USB-Recovery offline test payload", "File content streamed accurately");
                }

                // Test 7: GET /api/export-zip streaming
                using (var client = new WebClient())
                {
                    byte[] zipBytes = client.DownloadData(baseUrl + "/api/export-zip");
                    Check(zipBytes != null && zipBytes.Length > 30, "Zip bytes downloaded");
                    Check(zipBytes[0] == 0x50 && zipBytes[1] == 0x4B && zipBytes[2] == 0x03 && zipBytes[3] == 0x04, "Zip file starts with PK 03 04 signature");
                    string zipAscii = Encoding.ASCII.GetString(zipBytes);
                    Check(zipAscii.Contains("recovered_file.txt"), "Zip archive contains recovered_file.txt entry name");
                    Check(zipAscii.Contains("USB-Recovery offline test payload"), "Zip archive contains file payload");
                }

                // Test 8: GET /api/report?format=json
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string reportJson = client.DownloadString(baseUrl + "/api/report?format=json");
                    var serializer = new JavaScriptSerializer();
                    var report = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(reportJson);
                    Check(report != null, "Report JSON parsed");
                    Check(report.ContainsKey("chainOfCustodySha256"), "Report contains chainOfCustodySha256");
                    string chainHash = report["chainOfCustodySha256"].ToString();
                    Check(chainHash.Length == 64, "Chain of custody hash is 64 hex characters: " + chainHash);
                    Check(report.ContainsKey("files"), "Report contains files list");
                    var repFiles = (System.Collections.ArrayList)report["files"];
                    Check(repFiles.Count >= 1, "Report contains at least 1 file record");
                    var firstFile = (System.Collections.Generic.Dictionary<string, object>)repFiles[0];
                    Check(firstFile.ContainsKey("sha256"), "File record contains sha256");
                    Check(firstFile["sha256"].ToString().Length == 64, "File sha256 is 64 hex characters");
                }

                // Test 9: GET /api/report?format=html
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string reportHtml = client.DownloadString(baseUrl + "/api/report?format=html");
                    Check(reportHtml.Contains("USB-Recovery Forensic Report"), "Report HTML contains title");
                    Check(reportHtml.Contains("Chain of Custody Master Hash"), "Report HTML contains master hash");
                    Check(reportHtml.Contains("recovered_file.txt"), "Report HTML contains artifact row");
                }

                // Test 10: 404 on unknown endpoint
                bool got404 = false;
                try
                {
                    using (var client = new WebClient())
                    {
                        client.DownloadString(baseUrl + "/api/nonexistent_endpoint");
                    }
                }
                catch (WebException wex)
                {
                    var resp = wex.Response as HttpWebResponse;
                    if (resp != null && resp.StatusCode == HttpStatusCode.NotFound)
                        got404 = true;
                }
                Check(got404, "Unknown endpoint returns 404 Not Found");

                server.Stop();
                Check(!server.IsRunning, "Server stops cleanly");
            }

            // Test 11: Virtual Disk VHD Reader Integration
            byte[] vhdBytes = CreateSyntheticFixedVhd(imageBytes);
            string testVhd = Path.Combine(tempDir, "test_disk.vhd");
            File.WriteAllBytes(testVhd, vhdBytes);

            int vhdPort = 19080 + (new Random().Next(100, 900));
            using (var vhdServer = new LocalWebServer(testVhd, outputDir, vhdPort))
            {
                vhdServer.Start();
                string vhdUrl = "http://127.0.0.1:" + vhdServer.Port;

                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string statusJson = client.DownloadString(vhdUrl + "/api/status");
                    var serializer = new JavaScriptSerializer();
                    var status = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(statusJson);
                    Check(Convert.ToInt64(status["imageSize"]) == 65536, "VHD logical image size is 65536");

                    string reportJson = client.DownloadString(vhdUrl + "/api/report?format=json");
                    var report = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(reportJson);
                    var target = (System.Collections.Generic.Dictionary<string, object>)report["targetImage"];
                    Check(target["format"].ToString().Contains("VHD"), "Report detects VHD container format: " + target["format"]);

                    string hexJson = client.DownloadString(vhdUrl + "/api/hex?offset=510&length=2");
                    var hex = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(hexJson);
                    Check(hex["hex"].ToString() == "55AA", "VHD boot signature hex read accurately: " + hex["hex"]);
                }

                vhdServer.Stop();
            }

            Console.WriteLine("PASS LocalWebServer: {0} checks; localhost loopback Web-UI, cluster map, hex inspector, and REST endpoints verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL LocalWebServer: {0}", ex.Message);
            return 1;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, true);
            }
            catch { }
        }
    }

    private static byte[] CreateSyntheticFixedVhd(byte[] guestPayload)
    {
        long diskSize = guestPayload.Length;
        byte[] vhd = new byte[diskSize + 512];
        Array.Copy(guestPayload, 0, vhd, 0, guestPayload.Length);

        byte[] footer = new byte[512];
        Encoding.ASCII.GetBytes("conectix").CopyTo(footer, 0);
        footer[11] = 0x02; // Features
        footer[12] = 0; footer[13] = 1; footer[14] = 0; footer[15] = 0; // Version 1.0
        for (int i = 16; i < 24; i++) footer[i] = 0xFF; // DataOffset = 0xFFFFFFFFFFFFFFFF

        uint ts = 100000;
        footer[24] = (byte)(ts >> 24); footer[25] = (byte)(ts >> 16);
        footer[26] = (byte)(ts >> 8);  footer[27] = (byte)ts;

        Encoding.ASCII.GetBytes("test").CopyTo(footer, 28);
        for (int i = 0; i < 8; i++)
        {
            byte b = (byte)((diskSize >> (8 * (7 - i))) & 0xFF);
            footer[40 + i] = b;
            footer[48 + i] = b;
        }

        footer[56] = 0; footer[57] = 1; footer[58] = 1; footer[59] = 1; // Geometry
        footer[63] = 2; // DiskType = 2 (Fixed)
        Guid.NewGuid().ToByteArray().CopyTo(footer, 68);

        uint csum = VhdImageReader.ComputeFooterChecksum(footer);
        footer[64] = (byte)(csum >> 24); footer[65] = (byte)(csum >> 16);
        footer[66] = (byte)(csum >> 8);  footer[67] = (byte)csum;

        Array.Copy(footer, 0, vhd, diskSize, 512);
        return vhd;
    }
}

