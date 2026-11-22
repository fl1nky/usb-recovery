using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class SrumParserTests
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
        Console.WriteLine("Running SrumParserTests...");
        string tempDir = Path.Combine(Path.GetTempPath(), "srum_test_" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempDir);

            // 1. Test Interface Type Resolution
            Check(SrumParser.ResolveInterfaceType(0) == "Loopback/Local", "Interface 0 is Loopback/Local");
            ulong ethLuid = (6UL << 48) | 0x1234UL;
            Check(SrumParser.ResolveInterfaceType(ethLuid) == "Ethernet", "Interface type 6 is Ethernet");
            ulong wifiLuid = (71UL << 48) | 0x5678UL;
            Check(SrumParser.ResolveInterfaceType(wifiLuid) == "Wireless (802.11)", "Interface type 71 is Wireless");
            ulong wwanLuid = (243UL << 48) | 0x9ABCUL;
            Check(SrumParser.ResolveInterfaceType(wwanLuid) == "Mobile Broadband (WWAN)", "Interface type 243 is Mobile Broadband");

            // 2. Test Threat Heuristics on Network Entries
            var testNormal = new SrumNetworkEntry
            {
                AppId = 10,
                AppName = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                BytesSent = 1000000,
                BytesReceived = 5000000
            };
            // Evaluate via reflection or direct testing
            Check(!testNormal.IsSuspicious, "Normal chrome executable is not suspicious");

            // 3. Create Synthetic SRUDB.dat ESE Database
            int pageSize = 4096;
            byte[] dbBytes = new byte[pageSize * 8]; // 8 pages (32 KiB)

            // Page 0: Database Header
            BitConverter.GetBytes(0x12345678U).CopyTo(dbBytes, 0); // Checksum
            BitConverter.GetBytes(SrumParser.EseMagic).CopyTo(dbBytes, 4); // 0x89ABCDEF
            BitConverter.GetBytes(0x00000620U).CopyTo(dbBytes, 8); // Format version
            BitConverter.GetBytes(0U).CopyTo(dbBytes, 12); // File type: database
            BitConverter.GetBytes((uint)pageSize).CopyTo(dbBytes, 236); // Page size: 4096

            // Page 1: SruDbIdMapTable
            int p1 = pageSize;
            // Write Id 1: User SID
            WriteIdMapEntry(dbBytes, p1 + 32, 1, 1, "S-1-5-21-1234567890-1234567890-1234567890-1001");
            // Write Id 2: Suspicious exfiltration tool in Temp
            WriteIdMapEntry(dbBytes, p1 + 160, 2, 2, @"C:\Users\Admin\AppData\Local\Temp\exfiltrator.exe");
            // Write Id 3: Normal Chrome browser
            WriteIdMapEntry(dbBytes, p1 + 320, 2, 3, @"C:\Program Files\Google\Chrome\Application\chrome.exe");
            // Write Id 4: Offensive mimikatz tool
            WriteIdMapEntry(dbBytes, p1 + 500, 2, 4, @"C:\Windows\System32\mimikatz.exe");

            // Page 2: Network Data Usage Table ({973F5D5C-1D90-4944-BE81-70B51431B5E0})
            int p2 = pageSize * 2;
            DateTime dt1 = new DateTime(2026, 11, 20, 18, 30, 0, DateTimeKind.Utc);
            long ft1 = dt1.ToFileTimeUtc();

            // Record 1: Exfiltrator sending 1.2 GB over Wi-Fi
            BitConverter.GetBytes(2U).CopyTo(dbBytes, p2 + 64);      // AppId = 2 (exfiltrator.exe)
            BitConverter.GetBytes(1U).CopyTo(dbBytes, p2 + 68);      // UserId = 1 (SID 1001)
            BitConverter.GetBytes(wifiLuid).CopyTo(dbBytes, p2 + 72); // InterfaceLuid (Wi-Fi)
            BitConverter.GetBytes(1200000000UL).CopyTo(dbBytes, p2 + 80); // BytesSent = 1.2 GB
            BitConverter.GetBytes(50000UL).CopyTo(dbBytes, p2 + 88);      // BytesRecv = 50 KB
            BitConverter.GetBytes(ft1).CopyTo(dbBytes, p2 + 96);          // FileTime

            // Record 2: Chrome receiving 15 MB over Ethernet
            DateTime dt2 = new DateTime(2026, 11, 20, 18, 35, 0, DateTimeKind.Utc);
            long ft2 = dt2.ToFileTimeUtc();
            BitConverter.GetBytes(3U).CopyTo(dbBytes, p2 + 160);     // AppId = 3 (chrome.exe)
            BitConverter.GetBytes(1U).CopyTo(dbBytes, p2 + 164);     // UserId = 1
            BitConverter.GetBytes(ethLuid).CopyTo(dbBytes, p2 + 168);// InterfaceLuid (Ethernet)
            BitConverter.GetBytes(250000UL).CopyTo(dbBytes, p2 + 176);   // BytesSent = 250 KB
            BitConverter.GetBytes(15000000UL).CopyTo(dbBytes, p2 + 184); // BytesRecv = 15 MB
            BitConverter.GetBytes(ft2).CopyTo(dbBytes, p2 + 192);        // FileTime

            // Page 3: Application Usage Table ({D10CA2FE-6FCF-4F6D-848E-B2E9939E74C6})
            int p3 = pageSize * 3;
            DateTime dt3 = new DateTime(2026, 11, 20, 18, 40, 0, DateTimeKind.Utc);
            long ft3 = dt3.ToFileTimeUtc();

            // Record 1: mimikatz execution
            BitConverter.GetBytes(4U).CopyTo(dbBytes, p3 + 64);      // AppId = 4 (mimikatz.exe)
            BitConverter.GetBytes(1U).CopyTo(dbBytes, p3 + 68);      // UserId = 1
            BitConverter.GetBytes(50000000UL).CopyTo(dbBytes, p3 + 72); // ForegroundDuration
            BitConverter.GetBytes(1000000UL).CopyTo(dbBytes, p3 + 80);  // BackgroundDuration
            BitConverter.GetBytes(987654321UL).CopyTo(dbBytes, p3 + 88);// CpuCycles
            BitConverter.GetBytes(1048576UL).CopyTo(dbBytes, p3 + 96);  // BytesRead (1 MB)
            BitConverter.GetBytes(4096UL).CopyTo(dbBytes, p3 + 104);    // BytesWritten
            BitConverter.GetBytes(ft3).CopyTo(dbBytes, p3 + 112);       // FileTime

            string srumFile = Path.Combine(tempDir, "SRUDB.dat");
            File.WriteAllBytes(srumFile, dbBytes);

            // 4. Test SrumParser Execution
            var report = SrumParser.Parse(srumFile);

            Check(report != null, "SRUM report generated");
            Check(report.PageSize == 4096, "Detected page size is 4096");
            Check(report.TotalPages == 8, "Total pages count is 8");
            Check(report.IdMapCount >= 4, "IdMap resolved at least 4 entries");

            // Verify Network Entries
            Check(report.NetworkEntries.Count >= 2, "Network entries count >= 2: " + report.NetworkEntries.Count);
            SrumNetworkEntry exfilEntry = null;
            SrumNetworkEntry chromeEntry = null;
            for (int i = 0; i < report.NetworkEntries.Count; i++)
            {
                if (report.NetworkEntries[i].AppId == 2) exfilEntry = report.NetworkEntries[i];
                if (report.NetworkEntries[i].AppId == 3) chromeEntry = report.NetworkEntries[i];
            }

            Check(exfilEntry != null, "Found exfiltration network entry");
            Check(exfilEntry.AppName.Contains("exfiltrator.exe"), "Exfil entry resolved to exfiltrator.exe: " + exfilEntry.AppName);
            Check(exfilEntry.UserSid.Contains("1001"), "Exfil entry resolved user SID 1001: " + exfilEntry.UserSid);
            Check(exfilEntry.InterfaceType == "Wireless (802.11)", "Exfil interface is Wireless (802.11)");
            Check(exfilEntry.BytesSent == 1200000000UL, "Exfil bytes sent is 1.2 GB");
            Check(exfilEntry.IsSuspicious, "Exfil entry correctly flagged as suspicious (Temp + high outbound)");
            Check(exfilEntry.TimestampUtc.Year == 2026, "Exfil timestamp year is 2026");

            Check(chromeEntry != null, "Found Chrome network entry");
            Check(chromeEntry.AppName.Contains("chrome.exe"), "Chrome entry resolved to chrome.exe");
            Check(chromeEntry.InterfaceType == "Ethernet", "Chrome interface is Ethernet");
            Check(!chromeEntry.IsSuspicious, "Chrome normal traffic is NOT flagged suspicious");

            // Verify App Usage Entries
            Check(report.AppUsageEntries.Count >= 1, "App usage entries count >= 1");
            SrumAppUsageEntry mimiEntry = null;
            for (int i = 0; i < report.AppUsageEntries.Count; i++)
            {
                if (report.AppUsageEntries[i].AppId == 4) mimiEntry = report.AppUsageEntries[i];
            }

            Check(mimiEntry != null, "Found mimikatz app usage entry");
            Check(mimiEntry.AppName.Contains("mimikatz.exe"), "Mimikatz entry resolved to mimikatz.exe");
            Check(mimiEntry.CpuCycles == 987654321UL, "Mimikatz CPU cycles match 987654321");
            Check(mimiEntry.IsSuspicious, "Mimikatz flagged as suspicious binary");

            // Verify Summary Statistics
            Check(report.TotalBytesExfiltrated >= 1200000000UL, "TotalBytesExfiltrated tracks 1.2 GB");
            Check(report.SuspiciousAlertCount >= 2, "SuspiciousAlertCount tracks both alerts");

            // 5. Verify JSON Serialization
            string json = report.ToJson();
            Check(json.Contains("exfiltrator.exe"), "JSON contains exfiltrator.exe");
            Check(json.Contains("mimikatz.exe"), "JSON contains mimikatz.exe");
            Check(json.Contains("Wireless"), "JSON contains Wireless interface");

            Console.WriteLine("PASS SrumParserTests: {0} checks passed; ESE database header, IdMap correlation, network exfiltration, app resource usage, threat heuristics, and JSON verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL SrumParserTests: {0}", ex.Message);
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

    private static void WriteIdMapEntry(byte[] buf, int offset, ushort idType, uint idIndex, string val)
    {
        BitConverter.GetBytes(idType).CopyTo(buf, offset);
        BitConverter.GetBytes(idIndex).CopyTo(buf, offset + 2);
        byte[] strBytes = Encoding.Unicode.GetBytes(val);
        BitConverter.GetBytes((ushort)strBytes.Length).CopyTo(buf, offset + 6);
        Array.Copy(strBytes, 0, buf, offset + 8, strBytes.Length);
    }
}
