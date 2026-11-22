using System;
using System.IO;
using System.Text;
using UsbRecovery;

public static class BrowserExtensionsParserTests
{
    private static int checks = 0;

    private static void Check(bool condition, string message)
    {
        checks++;
        if (!condition)
        {
            throw new Exception("Check failed: " + message);
        }
    }

    public static int Main(string[] args)
    {
        try
        {
            TestManifestV3Parsing();
            TestKnownCryptoWalletIdentification();
            TestKnownPasswordManagerIdentification();
            TestThreatHeuristicsManInTheBrowser();
            TestThreatHeuristicsNativeMessaging();
            TestDirectoryStructureAndLevelDbStorage();
            TestCarvingFromRawBuffer();
            TestCorruptAndTruncatedBuffers();
            TestJsonSerialization();

            Console.WriteLine("PASS BrowserExtensionsParserTests: {0} checks passed; Manifest V2/V3 parsing, crypto wallets, password managers, LevelDB credential stores, and threat heuristics verified.", checks);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL BrowserExtensionsParserTests: {0}", ex.Message);
            return 1;
        }
    }

    private static void TestManifestV3Parsing()
    {
        string manifestJson = @"
        {
            ""name"": ""Safe Developer Tools"",
            ""version"": ""2.1.0"",
            ""description"": ""Inspection and developer utilities"",
            ""manifest_version"": 3,
            ""background"": {
                ""service_worker"": ""background.js""
            },
            ""permissions"": [
                ""storage"",
                ""alarms""
            ]
        }";

        var artifact = BrowserExtensionsParser.ParseManifestJson(manifestJson, "safe_ext_001", "manifest.json");

        Check(artifact != null, "Parsed artifact is not null");
        Check(artifact.Name == "Safe Developer Tools", "Name matches");
        Check(artifact.Version == "2.1.0", "Version matches");
        Check(artifact.ManifestVersion == "3", "Manifest version is 3");
        Check(artifact.BackgroundScript == "background.js", "Background script is background.js");
        Check(artifact.Permissions.Count == 2, "Parsed 2 permissions");
        Check(artifact.Permissions.Contains("storage"), "Permissions contain storage");
        Check(artifact.Permissions.Contains("alarms"), "Permissions contain alarms");
        Check(!artifact.IsSuspicious, "Normal extension is not suspicious");
    }

    private static void TestKnownCryptoWalletIdentification()
    {
        // MetaMask extension ID: nkbihfbeogaeaoehlefnkodbefgpgknn
        string mmManifest = @"
        {
            ""name"": ""MetaMask"",
            ""version"": ""10.34.0"",
            ""description"": ""Ethereum Crypto Wallet"",
            ""manifest_version"": 3,
            ""permissions"": [""storage""]
        }";

        var artifact = BrowserExtensionsParser.ParseManifestJson(mmManifest, "nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask_manifest.json");

        Check(artifact != null, "MetaMask artifact parsed");
        Check(artifact.Category == "Crypto Wallet", "Categorized as Crypto Wallet");
        Check(artifact.Name == "MetaMask", "Name is MetaMask");
        Check(artifact.ExtensionId == "nkbihfbeogaeaoehlefnkodbefgpgknn", "ExtensionId matches");

        // Phantom wallet: bfnaelmomeimhlpmgjnjophhpkkoljpa
        string phantomManifest = @"
        {
            ""name"": ""Phantom"",
            ""version"": ""24.5.0"",
            ""manifest_version"": 3
        }";
        var phantom = BrowserExtensionsParser.ParseManifestJson(phantomManifest, "bfnaelmomeimhlpmgjnjophhpkkoljpa", "phantom.json");
        Check(phantom.Category == "Crypto Wallet", "Phantom categorized as Crypto Wallet");
    }

    private static void TestKnownPasswordManagerIdentification()
    {
        // Bitwarden extension ID: nngceckbapebfimnlniiiahkandclblb
        string bwManifest = @"
        {
            ""name"": ""Bitwarden - Free Password Manager"",
            ""version"": ""2026.5.0"",
            ""manifest_version"": 3,
            ""permissions"": [""storage""]
        }";

        var artifact = BrowserExtensionsParser.ParseManifestJson(bwManifest, "nngceckbapebfimnlniiiahkandclblb", "bitwarden.json");

        Check(artifact != null, "Bitwarden artifact parsed");
        Check(artifact.Category == "Password Manager", "Categorized as Password Manager");
    }

    private static void TestThreatHeuristicsManInTheBrowser()
    {
        // Suspicious extension with broad interception rights
        string maliciousManifest = @"
        {
            ""name"": ""Suspicious Ad Tracker"",
            ""version"": ""1.0.0"",
            ""manifest_version"": 2,
            ""permissions"": [
                ""<all_urls>"",
                ""webRequest"",
                ""webRequestBlocking"",
                ""cookies""
            ]
        }";

        var artifact = BrowserExtensionsParser.ParseManifestJson(maliciousManifest, "bad_ext_1234", "malicious.json");

        Check(artifact != null, "Parsed malicious manifest");
        Check(artifact.IsSuspicious, "Flagged suspicious");
        Check(artifact.SuspicionReason.Contains("Man-in-the-Browser"), "Suspicion reason mentions Man-in-the-Browser");
    }

    private static void TestThreatHeuristicsNativeMessaging()
    {
        string nativeManifest = @"
        {
            ""name"": ""Host Connector"",
            ""version"": ""1.0.0"",
            ""manifest_version"": 3,
            ""permissions"": [
                ""nativeMessaging""
            ]
        }";

        var artifact = BrowserExtensionsParser.ParseManifestJson(nativeManifest, "host_ext_1234", "native.json");

        Check(artifact != null, "Parsed native messaging manifest");
        Check(artifact.IsSuspicious, "Native messaging flagged suspicious");
        Check(artifact.SuspicionReason.Contains("Native Messaging"), "Suspicion reason mentions Native Messaging");
    }

    private static void TestDirectoryStructureAndLevelDbStorage()
    {
        string tempProfile = Path.Combine(Path.GetTempPath(), "ext_test_profile_" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tempProfile);

            // Create Chrome Extensions directory structure:
            // Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/10.34.0_0/manifest.json
            string mmExtDir = Path.Combine(tempProfile, @"Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn\10.34.0_0");
            Directory.CreateDirectory(mmExtDir);

            string mmManifest = @"
            {
                ""name"": ""MetaMask"",
                ""version"": ""10.34.0"",
                ""manifest_version"": 3,
                ""permissions"": [""storage""]
            }";
            File.WriteAllText(Path.Combine(mmExtDir, "manifest.json"), mmManifest);

            // Create Local Extension Settings with simulated LevelDB log
            string ldbDir = Path.Combine(tempProfile, @"Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn");
            Directory.CreateDirectory(ldbDir);
            File.WriteAllText(Path.Combine(ldbDir, "000003.log"), "Simulated LevelDB log containing vault_keyring_seed_encrypted credentials payload.");
            File.WriteAllBytes(Path.Combine(ldbDir, "000005.ldb"), new byte[512]);

            var report = BrowserExtensionsParser.ParseDirectory(tempProfile);

            Check(report != null, "Directory report is not null");
            Check(report.TotalExtensions == 1, "Discovered exactly 1 extension in profile");
            Check(report.CryptoWalletsCount == 1, "CryptoWalletsCount is 1");

            var ext = report.Extensions[0];
            Check(ext.Name == "MetaMask", "Extension name is MetaMask");
            Check(ext.HasLevelDbStorage, "HasLevelDbStorage is true");
            Check(ext.LevelDbKeyCount > 0, "LevelDbKeyCount is positive");
            Check(ext.DiscoveredTokens.Count > 0, "DiscoveredTokens found vault indicator");
        }
        finally
        {
            try { Directory.Delete(tempProfile, true); } catch { }
        }
    }

    private static void TestCarvingFromRawBuffer()
    {
        // Simulate carved memory or unallocated sector containing MetaMask ID and Bitwarden ID
        byte[] buffer = new byte[8192];
        string content = "RANDOM_SLACK_nkbihfbeogaeaoehlefnkodbefgpgknn_USER_DATA_nngceckbapebfimnlniiiahkandclblb_END";
        byte[] contentBytes = Encoding.ASCII.GetBytes(content);
        Buffer.BlockCopy(contentBytes, 0, buffer, 512, contentBytes.Length);

        var report = BrowserExtensionsParser.Carve(buffer, "unallocated_ram.raw");

        Check(report != null, "Carved report is not null");
        Check(report.TotalExtensions == 2, "Carved exactly 2 known extensions: " + report.TotalExtensions);
        Check(report.CryptoWalletsCount == 1, "Found 1 crypto wallet (MetaMask)");
        Check(report.PasswordManagersCount == 1, "Found 1 password manager (Bitwarden)");
        Check(report.Extensions[0].IsCarved, "Extension 0 IsCarved is true");
        Check(report.Extensions[1].IsCarved, "Extension 1 IsCarved is true");
    }

    private static void TestCorruptAndTruncatedBuffers()
    {
        var emptyRep = BrowserExtensionsParser.Carve(new byte[0]);
        Check(emptyRep.TotalExtensions == 0, "Empty buffer yields 0 extensions");

        var smallRep = BrowserExtensionsParser.Carve(new byte[32]);
        Check(smallRep.TotalExtensions == 0, "Small buffer yields 0 extensions");

        var nullArt = BrowserExtensionsParser.ParseManifestJson("", "test", "test.json");
        Check(nullArt == null, "Empty manifest JSON yields null artifact");
    }

    private static void TestJsonSerialization()
    {
        var rep = new BrowserExtensionsReport
        {
            SourcePath = "test_profile",
            TotalExtensions = 1,
            CryptoWalletsCount = 1,
            PasswordManagersCount = 0,
            SuspiciousCount = 1
        };
        var ext = new BrowserExtensionArtifact
        {
            ExtensionId = "nkbihfbeogaeaoehlefnkodbefgpgknn",
            Name = "MetaMask",
            Version = "10.34.0",
            Category = "Crypto Wallet",
            IsSuspicious = true,
            SuspicionReason = "Man-in-the-Browser test"
        };
        ext.Permissions.Add("<all_urls>");
        ext.DiscoveredTokens.Add("Vault");
        rep.Extensions.Add(ext);

        string json = rep.ToJson();
        Check(!string.IsNullOrEmpty(json), "JSON is not empty");
        Check(json.Contains("\"TotalExtensions\":1"), "JSON contains TotalExtensions");
        Check(json.Contains("\"CryptoWalletsCount\":1"), "JSON contains CryptoWalletsCount");
        Check(json.Contains("\"Name\":\"MetaMask\""), "JSON contains MetaMask");
        Check(json.Contains("\"Category\":\"Crypto Wallet\""), "JSON contains Crypto Wallet");
        Check(json.Contains("\"IsSuspicious\":true"), "JSON contains IsSuspicious");
    }
}
