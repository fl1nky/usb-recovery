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

            // Create a synthetic registry hive in output directory for forensic registry testing
            byte[] hiveBytes = new byte[8192];
            hiveBytes[0] = 0x72; hiveBytes[1] = 0x65; hiveBytes[2] = 0x67; hiveBytes[3] = 0x66;
            BitConverter.GetBytes(1U).CopyTo(hiveBytes, 4);
            BitConverter.GetBytes(1U).CopyTo(hiveBytes, 8);
            BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(hiveBytes, 12);
            BitConverter.GetBytes(1U).CopyTo(hiveBytes, 20);
            BitConverter.GetBytes(3U).CopyTo(hiveBytes, 24);
            BitConverter.GetBytes(32U).CopyTo(hiveBytes, 36);
            BitConverter.GetBytes(4096U).CopyTo(hiveBytes, 40);
            Encoding.Unicode.GetBytes("SYSTEM").CopyTo(hiveBytes, 48);
            hiveBytes[4096] = 0x68; hiveBytes[4097] = 0x62; hiveBytes[4098] = 0x69; hiveBytes[4099] = 0x6E;
            BitConverter.GetBytes(0U).CopyTo(hiveBytes, 4100);
            BitConverter.GetBytes(4096U).CopyTo(hiveBytes, 4104);
            int nkSize = 96;
            BitConverter.GetBytes(-nkSize).CopyTo(hiveBytes, 4128);
            hiveBytes[4132] = 0x6E; hiveBytes[4133] = 0x6B;
            BitConverter.GetBytes((ushort)0x0024).CopyTo(hiveBytes, 4134);
            BitConverter.GetBytes((ushort)4).CopyTo(hiveBytes, 4200);
            Encoding.ASCII.GetBytes("ROOT").CopyTo(hiveBytes, 4204);
            BitConverter.GetBytes(4096 - 32 - 96).CopyTo(hiveBytes, 4128 + 96);
            uint chk = 0;
            for (int ci = 0; ci < 508; ci += 4) chk ^= BitConverter.ToUInt32(hiveBytes, ci);
            BitConverter.GetBytes(chk).CopyTo(hiveBytes, 508);
            File.WriteAllBytes(Path.Combine(outputDir, "SYSTEM.hive"), hiveBytes);

            // Create a synthetic USN journal in output directory
            byte[] usnBytes = new byte[512];
            byte[] nameBytes1 = Encoding.Unicode.GetBytes("WipedEvidence.docx");
            int r1Len = 60 + nameBytes1.Length;
            if (r1Len % 8 != 0) r1Len += (8 - (r1Len % 8));
            BitConverter.GetBytes((uint)r1Len).CopyTo(usnBytes, 0);
            BitConverter.GetBytes((ushort)2).CopyTo(usnBytes, 4);
            BitConverter.GetBytes(77777UL).CopyTo(usnBytes, 8);
            BitConverter.GetBytes(5UL).CopyTo(usnBytes, 16);
            BitConverter.GetBytes(1001L).CopyTo(usnBytes, 24);
            BitConverter.GetBytes(DateTime.UtcNow.AddHours(-2).ToFileTimeUtc()).CopyTo(usnBytes, 32);
            BitConverter.GetBytes(0x00000100U).CopyTo(usnBytes, 40); // FileCreate
            BitConverter.GetBytes((ushort)nameBytes1.Length).CopyTo(usnBytes, 56);
            BitConverter.GetBytes((ushort)60).CopyTo(usnBytes, 58);
            Array.Copy(nameBytes1, 0, usnBytes, 60, nameBytes1.Length);

            int r2Off = r1Len;
            byte[] nameBytes2 = Encoding.Unicode.GetBytes("WipedEvidence.docx");
            int r2Len = 60 + nameBytes2.Length;
            if (r2Len % 8 != 0) r2Len += (8 - (r2Len % 8));
            BitConverter.GetBytes((uint)r2Len).CopyTo(usnBytes, r2Off);
            BitConverter.GetBytes((ushort)2).CopyTo(usnBytes, r2Off + 4);
            BitConverter.GetBytes(77777UL).CopyTo(usnBytes, r2Off + 8);
            BitConverter.GetBytes(5UL).CopyTo(usnBytes, r2Off + 16);
            BitConverter.GetBytes(1002L).CopyTo(usnBytes, r2Off + 24);
            BitConverter.GetBytes(DateTime.UtcNow.AddHours(-1).ToFileTimeUtc()).CopyTo(usnBytes, r2Off + 32);
            BitConverter.GetBytes(0x80000200U).CopyTo(usnBytes, r2Off + 40); // FileDelete | Close
            BitConverter.GetBytes((ushort)nameBytes2.Length).CopyTo(usnBytes, r2Off + 56);
            BitConverter.GetBytes((ushort)60).CopyTo(usnBytes, r2Off + 58);
            Array.Copy(nameBytes2, 0, usnBytes, r2Off + 60, nameBytes2.Length);
            File.WriteAllBytes(Path.Combine(outputDir, "usn_journal.bin"), usnBytes);

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
                    Check(html.Contains("Registry Forensics"), "Dashboard HTML contains Registry Forensics tab");
                    Check(html.Contains("USN Journal"), "Dashboard HTML contains USN Journal tab");
                    Check(html.Contains("Super-Timeline"), "Dashboard HTML contains Super-Timeline tab");
                    Check(html.Contains("Amcache"), "Dashboard HTML contains Amcache tab");
                    Check(html.Contains("Shellbags"), "Dashboard HTML contains Shellbags tab");
                    Check(html.Contains("Entropy"), "Dashboard HTML contains Entropy tab");
                    Check(html.Contains("SRUM Exfiltration"), "Dashboard HTML contains SRUM tab");
                    Check(html.Contains("Jump Lists"), "Dashboard HTML contains Jump Lists tab");
                    Check(html.Contains("Recycle Bin"), "Dashboard HTML contains Recycle Bin tab");
                    Check(html.Contains("Volume Shadows (VSS)"), "Dashboard HTML contains Volume Shadows (VSS) tab");
                    Check(html.Contains("ISO / UDF Optical"), "Dashboard HTML contains ISO / UDF Optical tab");
                    Check(html.Contains("Court Report"), "Dashboard HTML contains Court Report button");
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

                // Test 10: GET /api/registry endpoints
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;

                    // 10a. List hives
                    string listJson = client.DownloadString(baseUrl + "/api/registry?action=list");
                    var serializer = new JavaScriptSerializer();
                    var listObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(listJson);
                    Check(listObj != null && listObj.ContainsKey("hives"), "Registry list JSON parsed");
                    var hives = (System.Collections.ArrayList)listObj["hives"];
                    Check(hives.Count >= 1, "Registry hives list contains at least 1 hive");

                    // 10b. Summary
                    string summaryJson = client.DownloadString(baseUrl + "/api/registry?action=summary&path=SYSTEM.hive");
                    var sumObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(summaryJson);
                    Check(sumObj != null && sumObj.ContainsKey("isChecksumValid"), "Registry summary JSON parsed");
                    Check(Convert.ToBoolean(sumObj["isChecksumValid"]), "Registry header checksum verified via web API");
                    Check(sumObj["embeddedFileName"].ToString() == "SYSTEM", "Registry embedded file name matches SYSTEM");

                    // 10c. Key details
                    string keyJson = client.DownloadString(baseUrl + "/api/registry?action=key&path=SYSTEM.hive&keyPath=ROOT");
                    var keyObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(keyJson);
                    Check(keyObj != null && keyObj.ContainsKey("name"), "Registry key JSON parsed");
                    Check(keyObj["name"].ToString() == "ROOT", "Registry ROOT key verified via web API");

                    // 10d. Carve deleted
                    string carveJson = client.DownloadString(baseUrl + "/api/registry?action=carve&path=SYSTEM.hive");
                    var carveObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(carveJson);
                    Check(carveObj != null && carveObj.ContainsKey("carvedKeysCount"), "Registry carve JSON parsed");
                }

                // Test 11: GET /api/usn endpoints
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    var serializer = new JavaScriptSerializer();

                    // 11a. Deleted files
                    string delJson = client.DownloadString(baseUrl + "/api/usn?action=deleted");
                    var delObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(delJson);
                    Check(delObj != null && delObj.ContainsKey("deletedFiles"), "USN deleted files JSON parsed");
                    var delFiles = (System.Collections.ArrayList)delObj["deletedFiles"];
                    Check(delFiles.Count == 1, "USN journal identified 1 deleted file");
                    var firstDel = (System.Collections.Generic.Dictionary<string, object>)delFiles[0];
                    Check(firstDel["fileName"].ToString() == "WipedEvidence.docx", "Deleted filename matches WipedEvidence.docx");

                    // 11b. Timeline
                    string timeJson = client.DownloadString(baseUrl + "/api/usn?action=timeline");
                    var timeObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(timeJson);
                    Check(timeObj != null && timeObj.ContainsKey("events"), "USN timeline JSON parsed");
                    var evs = (System.Collections.ArrayList)timeObj["events"];
                    Check(evs.Count == 2, "USN timeline contains 2 events");

                    // 11c. Search
                    string searchJson = client.DownloadString(baseUrl + "/api/usn?action=search&q=Wiped");
                    var searchObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(searchJson);
                    Check(searchObj != null && searchObj.ContainsKey("results"), "USN search JSON parsed");
                    var resList = (System.Collections.ArrayList)searchObj["results"];
                    Check(resList.Count == 2, "USN search returned 2 matching records");
                }

                // Test 12: 404 on unknown endpoint
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

                // Test 13: GET /api/amcache
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string amcacheJson = client.DownloadString(baseUrl + "/api/amcache");
                    var serializer = new JavaScriptSerializer();
                    var amcacheObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(amcacheJson);
                    Check(amcacheObj != null, "Amcache JSON parsed");
                    Check(amcacheObj.ContainsKey("totalEntries"), "Amcache contains totalEntries");
                    Check(amcacheObj.ContainsKey("alertCount"), "Amcache contains alertCount");
                    Check(amcacheObj.ContainsKey("results"), "Amcache contains results");
                }

                // Test 14: GET /api/shellbags
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string sbJson = client.DownloadString(baseUrl + "/api/shellbags");
                    var serializer = new JavaScriptSerializer();
                    var sbObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(sbJson);
                    Check(sbObj != null, "Shellbags JSON parsed");
                    Check(sbObj.ContainsKey("totalRecords"), "Shellbags contains totalRecords");
                    Check(sbObj.ContainsKey("results"), "Shellbags contains results");
                }

                // Test 15: GET /api/entropy
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string entJson = client.DownloadString(baseUrl + "/api/entropy");
                    var serializer = new JavaScriptSerializer();
                    var entObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(entJson);
                    Check(entObj != null, "Entropy JSON parsed");
                    Check(entObj.ContainsKey("MeanEntropy"), "Entropy contains MeanEntropy");
                    Check(entObj.ContainsKey("IsSuspiciousRansomware"), "Entropy contains IsSuspiciousRansomware");
                }

                // Test 16: GET /api/court-report
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string reportHtml = client.DownloadString(baseUrl + "/api/court-report");
                    Check(reportHtml.Contains("RULE 902(14)"), "Court report HTML contains Rule 902(14)");
                    Check(reportHtml.Contains("Chain of Custody"), "Court report HTML contains Chain of Custody");
                }

                // Test 17: GET /api/srum
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string srumJson = client.DownloadString(baseUrl + "/api/srum");
                    var serializer = new JavaScriptSerializer();
                    var srumObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(srumJson);
                    Check(srumObj != null, "SRUM JSON parsed");
                    Check(srumObj.ContainsKey("PageSize"), "SRUM contains PageSize");
                    Check(srumObj.ContainsKey("NetworkEntries"), "SRUM contains NetworkEntries");
                    Check(srumObj.ContainsKey("AppUsageEntries"), "SRUM contains AppUsageEntries");
                    Check(srumObj.ContainsKey("TotalBytesExfiltrated"), "SRUM contains TotalBytesExfiltrated");
                }

                // Test 18: GET /api/jumplists
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string jlJson = client.DownloadString(baseUrl + "/api/jumplists");
                    var serializer = new JavaScriptSerializer();
                    var jlObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(jlJson);
                    Check(jlObj != null, "JumpLists JSON parsed");
                    Check(jlObj.ContainsKey("FileType"), "JumpLists contains FileType");
                    Check(jlObj.ContainsKey("TotalEntries"), "JumpLists contains TotalEntries");
                    Check(jlObj.ContainsKey("Entries"), "JumpLists contains Entries");
                }

                // Test 19: GET /api/recyclebin
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string rbJson = client.DownloadString(baseUrl + "/api/recyclebin");
                    var serializer = new JavaScriptSerializer();
                    var rbObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(rbJson);
                    Check(rbObj != null, "RecycleBin JSON parsed");
                    Check(rbObj.ContainsKey("TotalRecords"), "RecycleBin contains TotalRecords");
                    Check(rbObj.ContainsKey("TotalBytesDeleted"), "RecycleBin contains TotalBytesDeleted");
                    Check(rbObj.ContainsKey("Entries"), "RecycleBin contains Entries");
                }

                // Test 20: GET /api/vss
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string vssJson = client.DownloadString(baseUrl + "/api/vss");
                    var serializer = new JavaScriptSerializer();
                    var vssObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(vssJson);
                    Check(vssObj != null, "VSS JSON parsed");
                    Check(vssObj.ContainsKey("TotalSnapshots"), "VSS contains TotalSnapshots");
                    Check(vssObj.ContainsKey("TotalStoreBlocks"), "VSS contains TotalStoreBlocks");
                    Check(vssObj.ContainsKey("Snapshots"), "VSS contains Snapshots");
                }

                // Test 21: GET /api/iso
                using (var client = new WebClient())
                {
                    client.Encoding = Encoding.UTF8;
                    string isoJson = client.DownloadString(baseUrl + "/api/iso");
                    var serializer = new JavaScriptSerializer();
                    var isoObj = serializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(isoJson);
                    Check(isoObj != null, "ISO JSON parsed");
                    Check(isoObj.ContainsKey("TotalFiles"), "ISO contains TotalFiles");
                    Check(isoObj.ContainsKey("TotalDirectories"), "ISO contains TotalDirectories");
                    Check(isoObj.ContainsKey("Files"), "ISO contains Files");
                }

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

