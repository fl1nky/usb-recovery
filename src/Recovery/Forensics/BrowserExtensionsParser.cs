using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace UsbRecovery
{
    /// <summary>
    /// Represents a parsed browser extension artifact (Chromium / Firefox).
    /// </summary>
    public sealed class BrowserExtensionArtifact
    {
        public string ExtensionId { get; set; }
        public string Name { get; set; }
        public string Version { get; set; }
        public string Description { get; set; }
        public string Browser { get; set; }
        public string Category { get; set; }
        public string ManifestVersion { get; set; }
        public List<string> Permissions { get; set; }
        public string BackgroundScript { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }
        public bool HasLevelDbStorage { get; set; }
        public int LevelDbKeyCount { get; set; }
        public List<string> DiscoveredTokens { get; set; }
        public string SourcePath { get; set; }
        public bool IsCarved { get; set; }

        public BrowserExtensionArtifact()
        {
            ExtensionId = String.Empty;
            Name = String.Empty;
            Version = String.Empty;
            Description = String.Empty;
            Browser = "Chromium";
            Category = "General Extension";
            ManifestVersion = "3";
            Permissions = new List<string>();
            BackgroundScript = String.Empty;
            SuspicionReason = String.Empty;
            DiscoveredTokens = new List<string>();
            SourcePath = String.Empty;
        }
    }

    /// <summary>
    /// Forensic summary report for browser extensions.
    /// </summary>
    public sealed class BrowserExtensionsReport
    {
        public string SourcePath { get; set; }
        public int TotalExtensions { get; set; }
        public int CryptoWalletsCount { get; set; }
        public int PasswordManagersCount { get; set; }
        public int SuspiciousCount { get; set; }
        public List<BrowserExtensionArtifact> Extensions { get; set; }
        public List<string> Warnings { get; set; }

        public BrowserExtensionsReport()
        {
            SourcePath = String.Empty;
            Extensions = new List<BrowserExtensionArtifact>();
            Warnings = new List<string>();
        }

        public string ToJson()
        {
            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"SourcePath\":\"{0}\",", EscapeJson(SourcePath));
            sb.AppendFormat("\"TotalExtensions\":{0},", TotalExtensions);
            sb.AppendFormat("\"CryptoWalletsCount\":{0},", CryptoWalletsCount);
            sb.AppendFormat("\"PasswordManagersCount\":{0},", PasswordManagersCount);
            sb.AppendFormat("\"SuspiciousCount\":{0},", SuspiciousCount);
            sb.Append("\"Extensions\":[");
            for (int i = 0; i < Extensions.Count; i++)
            {
                if (i > 0) sb.Append(",");
                var ext = Extensions[i];
                sb.Append("{");
                sb.AppendFormat("\"ExtensionId\":\"{0}\",", EscapeJson(ext.ExtensionId));
                sb.AppendFormat("\"Name\":\"{0}\",", EscapeJson(ext.Name));
                sb.AppendFormat("\"Version\":\"{0}\",", EscapeJson(ext.Version));
                sb.AppendFormat("\"Description\":\"{0}\",", EscapeJson(ext.Description));
                sb.AppendFormat("\"Browser\":\"{0}\",", EscapeJson(ext.Browser));
                sb.AppendFormat("\"Category\":\"{0}\",", EscapeJson(ext.Category));
                sb.AppendFormat("\"ManifestVersion\":\"{0}\",", EscapeJson(ext.ManifestVersion));
                sb.AppendFormat("\"BackgroundScript\":\"{0}\",", EscapeJson(ext.BackgroundScript));
                sb.AppendFormat("\"IsSuspicious\":{0},", ext.IsSuspicious ? "true" : "false");
                sb.AppendFormat("\"SuspicionReason\":\"{0}\",", EscapeJson(ext.SuspicionReason));
                sb.AppendFormat("\"HasLevelDbStorage\":{0},", ext.HasLevelDbStorage ? "true" : "false");
                sb.AppendFormat("\"LevelDbKeyCount\":{0},", ext.LevelDbKeyCount);
                sb.AppendFormat("\"IsCarved\":{0},", ext.IsCarved ? "true" : "false");
                sb.Append("\"Permissions\":[");
                for (int p = 0; p < ext.Permissions.Count; p++)
                {
                    if (p > 0) sb.Append(",");
                    sb.AppendFormat("\"{0}\"", EscapeJson(ext.Permissions[p]));
                }
                sb.Append("],");
                sb.Append("\"DiscoveredTokens\":[");
                for (int t = 0; t < ext.DiscoveredTokens.Count; t++)
                {
                    if (t > 0) sb.Append(",");
                    sb.AppendFormat("\"{0}\"", EscapeJson(ext.DiscoveredTokens[t]));
                }
                sb.Append("]");
                sb.Append("}");
            }
            sb.Append("]");
            sb.Append("}");
            return sb.ToString();
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return String.Empty;
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }
    }

    /// <summary>
    /// Forensic parser and carver for Web Browser Extensions (Chromium and Firefox).
    /// Discovers installed extensions, Manifest V2/V3 structure, permissions,
    /// LevelDB / IndexedDB credential stores (MetaMask, Phantom, Bitwarden, etc.),
    /// and flags suspicious high-privilege interception extensions (MITRE T1176 Browser Extensions).
    /// </summary>
    public static class BrowserExtensionsParser
    {
        // Known High-Value Crypto Wallet Extension IDs (32 lower-case chars a-p)
        private static readonly Dictionary<string, string> KnownCryptoWallets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask" },
            { "bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom" },
            { "hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet" },
            { "fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin Wallet" },
            { "ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink" },
            { "aeachknmefphepccionboohckonoeemg", "Coin98 Wallet" },
            { "egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet" },
            { "mcohilncbfahbmgdjkbpemancnofnebd", "Exodus Web3" },
            { "dmkamcknogkgcdfhhbddcghachkejeap", "Keplr" },
            { "ffnbelfdoeiohenkjibnbebbgdfidhbm", "Martian Aptos Wallet" }
        };

        // Known High-Value Password Managers
        private static readonly Dictionary<string, string> KnownPasswordManagers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "nngceckbapebfimnlniiiahkandclblb", "Bitwarden" },
            { "aeblfdkhhhdcdjpifhhbdiojplfjncoa", "1Password" },
            { "hdokiejnpimakedhajhdlcegeplioahd", "LastPass" },
            { "fdjamakpfbbflfjalbgdfbmfaiefbnlo", "Dashlane" },
            { "oboonakemofpalcgghocfoadofidjkkk", "KeePassXC-Browser" },
            { "imloifkgjagghnncjkhggdhalmcnfklk", "NordPass" }
        };

        // Known 2FA Authenticators
        private static readonly Dictionary<string, string> KnownAuthenticators = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "bhghoamapcdpbohkgigflimgghegnloj", "Authenticator (2FA)" },
            { "gaedmjdfmmahhbjefcbgaolhhanlaolb", "Authy" }
        };

        /// <summary>
        /// Parses browser extension artifacts from a directory, manifest file, or raw image.
        /// </summary>
        public static BrowserExtensionsReport Parse(string path)
        {
            if (path == null) throw new ArgumentNullException("path");

            var report = new BrowserExtensionsReport { SourcePath = path };

            if (Directory.Exists(path))
            {
                return ParseDirectory(path);
            }

            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Target path not found", path);
            }

            // If file is named manifest.json, parse single manifest
            if (Path.GetFileName(path).Equals("manifest.json", StringComparison.OrdinalIgnoreCase))
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                string extId = Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(path)));
                var artifact = ParseManifestJson(json, extId, path);
                if (artifact != null)
                {
                    report.Extensions.Add(artifact);
                }
            }
            else
            {
                // Raw disk or buffer carve
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    int readLen = (int)Math.Min(fs.Length, 32L * 1024 * 1024); // Up to 32 MB sample
                    byte[] buffer = new byte[readLen];
                    fs.Read(buffer, 0, readLen);
                    return Carve(buffer, path);
                }
            }

            FinalizeReport(report);
            return report;
        }

        /// <summary>
        /// Parses an entire browser profile directory (e.g. Chrome 'Default' or profile root).
        /// </summary>
        public static BrowserExtensionsReport ParseDirectory(string profileDir)
        {
            var report = new BrowserExtensionsReport { SourcePath = profileDir };

            try
            {
                // Search for manifest.json files in Extensions subdirectory
                string extDir = Path.Combine(profileDir, "Extensions");
                if (Directory.Exists(extDir))
                {
                    var manifests = Directory.GetFiles(extDir, "manifest.json", SearchOption.AllDirectories);
                    foreach (var manifestPath in manifests)
                    {
                        try
                        {
                            string json = File.ReadAllText(manifestPath, Encoding.UTF8);
                            // Directory structure: Extensions\<ExtensionID>\<Version>\manifest.json
                            string versionDir = Path.GetDirectoryName(manifestPath);
                            string extIdDir = Path.GetDirectoryName(versionDir);
                            string extId = Path.GetFileName(extIdDir);

                            var artifact = ParseManifestJson(json, extId, manifestPath);
                            if (artifact != null)
                            {
                                // Check for LevelDB settings
                                InspectExtensionStorage(profileDir, artifact);
                                report.Extensions.Add(artifact);
                            }
                        }
                        catch (Exception ex)
                        {
                            report.Warnings.Add("Failed parsing manifest " + Path.GetFileName(manifestPath) + ": " + ex.Message);
                        }
                    }
                }

                // Also check for orphan Local Extension Settings / IndexedDB directories
                string localSettingsDir = Path.Combine(profileDir, "Local Extension Settings");
                if (Directory.Exists(localSettingsDir))
                {
                    var settingDirs = Directory.GetDirectories(localSettingsDir);
                    foreach (var sdir in settingDirs)
                    {
                        string extId = Path.GetFileName(sdir);
                        if (extId.Length == 32 && !report.Extensions.Exists(e => e.ExtensionId.Equals(extId, StringComparison.OrdinalIgnoreCase)))
                        {
                            // Orphan settings without manifest
                            var orphan = new BrowserExtensionArtifact
                            {
                                ExtensionId = extId,
                                SourcePath = sdir,
                                IsCarved = true
                            };
                            CategorizeExtension(orphan);
                            orphan.Name = string.IsNullOrEmpty(orphan.Name) ? ("Orphan Extension (" + extId.Substring(0, 8) + "...)") : orphan.Name;
                            InspectExtensionStorage(profileDir, orphan);
                            report.Extensions.Add(orphan);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                report.Warnings.Add("Directory scan error: " + ex.Message);
            }

            FinalizeReport(report);
            return report;
        }

        /// <summary>
        /// Carves browser extension manifests, IDs, and LevelDB artifacts from raw memory/disk sectors.
        /// </summary>
        public static BrowserExtensionsReport Carve(byte[] buffer, string sourceName = null)
        {
            var report = new BrowserExtensionsReport { SourcePath = sourceName ?? "Buffer" };
            if (buffer == null || buffer.Length < 64) return report;

            string text = Encoding.ASCII.GetString(buffer);

            // 1. Scan for known extension IDs (MetaMask, Phantom, Bitwarden, etc.)
            foreach (var kvp in KnownCryptoWallets)
            {
                if (text.IndexOf(kvp.Key, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!report.Extensions.Exists(e => e.ExtensionId.Equals(kvp.Key, StringComparison.OrdinalIgnoreCase)))
                    {
                        var ext = new BrowserExtensionArtifact
                        {
                            ExtensionId = kvp.Key,
                            Name = kvp.Value,
                            Category = "Crypto Wallet",
                            IsCarved = true,
                            SourcePath = sourceName ?? "Carved Memory/Disk"
                        };
                        report.Extensions.Add(ext);
                    }
                }
            }

            foreach (var kvp in KnownPasswordManagers)
            {
                if (text.IndexOf(kvp.Key, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!report.Extensions.Exists(e => e.ExtensionId.Equals(kvp.Key, StringComparison.OrdinalIgnoreCase)))
                    {
                        var ext = new BrowserExtensionArtifact
                        {
                            ExtensionId = kvp.Key,
                            Name = kvp.Value,
                            Category = "Password Manager",
                            IsCarved = true,
                            SourcePath = sourceName ?? "Carved Memory/Disk"
                        };
                        report.Extensions.Add(ext);
                    }
                }
            }

            // 2. Scan for manifest.json fragments: `"manifest_version"`
            int idx = 0;
            while ((idx = text.IndexOf("\"manifest_version\"", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                int start = Math.Max(0, idx - 100);
                int openBrace = text.LastIndexOf('{', idx);
                if (openBrace >= 0 && openBrace >= start)
                {
                    int closeBrace = text.IndexOf('}', idx);
                    if (closeBrace > openBrace && closeBrace - openBrace < 8192)
                    {
                        string jsonSnippet = text.Substring(openBrace, closeBrace - openBrace + 1);
                        var parsed = ParseManifestJson(jsonSnippet, "carved_" + Guid.NewGuid().ToString("N").Substring(0, 8), sourceName);
                        if (parsed != null && !report.Extensions.Exists(e => e.Name.Equals(parsed.Name, StringComparison.OrdinalIgnoreCase)))
                        {
                            parsed.IsCarved = true;
                            report.Extensions.Add(parsed);
                        }
                    }
                }
                idx += 18;
            }

            FinalizeReport(report);
            return report;
        }

        public static BrowserExtensionArtifact ParseManifestJson(string json, string extensionId, string sourcePath)
        {
            if (string.IsNullOrEmpty(json)) return null;

            var artifact = new BrowserExtensionArtifact
            {
                ExtensionId = extensionId ?? String.Empty,
                SourcePath = sourcePath ?? String.Empty
            };

            // Extract Name
            var nameMatch = Regex.Match(json, "\"name\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
            if (nameMatch.Success) artifact.Name = nameMatch.Groups[1].Value;

            // Extract Version
            var verMatch = Regex.Match(json, "\"version\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
            if (verMatch.Success) artifact.Version = verMatch.Groups[1].Value;

            // Extract Description
            var descMatch = Regex.Match(json, "\"description\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
            if (descMatch.Success) artifact.Description = descMatch.Groups[1].Value;

            // Extract Manifest Version
            var mvMatch = Regex.Match(json, "\"manifest_version\"\\s*:\\s*([23])", RegexOptions.IgnoreCase);
            if (mvMatch.Success) artifact.ManifestVersion = mvMatch.Groups[1].Value;

            // Extract Background script / service worker
            var bgMatch = Regex.Match(json, "\"service_worker\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
            if (bgMatch.Success) artifact.BackgroundScript = bgMatch.Groups[1].Value;
            else
            {
                var bgScripts = Regex.Match(json, "\"scripts\"\\s*:\\s*\\[([^\\]]+)\\]", RegexOptions.IgnoreCase);
                if (bgScripts.Success) artifact.BackgroundScript = bgScripts.Groups[1].Value.Trim('"', ' ', '\r', '\n');
            }

            // Extract Permissions array
            var permMatch = Regex.Match(json, "\"permissions\"\\s*:\\s*\\[([^\\]]*)\\]", RegexOptions.IgnoreCase);
            if (permMatch.Success)
            {
                string permsBlock = permMatch.Groups[1].Value;
                var singlePerms = Regex.Matches(permsBlock, "\"([^\"]+)\"");
                foreach (Match m in singlePerms)
                {
                    artifact.Permissions.Add(m.Groups[1].Value);
                }
            }

            CategorizeExtension(artifact);
            EvaluateThreats(artifact);

            return artifact;
        }

        private static void CategorizeExtension(BrowserExtensionArtifact artifact)
        {
            if (string.IsNullOrEmpty(artifact.ExtensionId)) return;

            if (KnownCryptoWallets.ContainsKey(artifact.ExtensionId))
            {
                artifact.Category = "Crypto Wallet";
                if (string.IsNullOrEmpty(artifact.Name)) artifact.Name = KnownCryptoWallets[artifact.ExtensionId];
            }
            else if (KnownPasswordManagers.ContainsKey(artifact.ExtensionId))
            {
                artifact.Category = "Password Manager";
                if (string.IsNullOrEmpty(artifact.Name)) artifact.Name = KnownPasswordManagers[artifact.ExtensionId];
            }
            else if (KnownAuthenticators.ContainsKey(artifact.ExtensionId))
            {
                artifact.Category = "2FA Authenticator";
                if (string.IsNullOrEmpty(artifact.Name)) artifact.Name = KnownAuthenticators[artifact.ExtensionId];
            }
        }

        private static void EvaluateThreats(BrowserExtensionArtifact artifact)
        {
            var reasons = new List<string>();

            bool hasAllUrls = artifact.Permissions.Exists(p => p.Equals("<all_urls>", StringComparison.OrdinalIgnoreCase) || p.Contains("*://*/*"));
            bool hasWebRequest = artifact.Permissions.Exists(p => p.Contains("webRequest"));
            bool hasCookies = artifact.Permissions.Exists(p => p.Equals("cookies", StringComparison.OrdinalIgnoreCase));
            bool hasNativeMessaging = artifact.Permissions.Exists(p => p.Equals("nativeMessaging", StringComparison.OrdinalIgnoreCase));

            if (hasAllUrls && (hasWebRequest || hasCookies))
            {
                reasons.Add("Man-in-the-Browser Interception (<all_urls> with webRequest/cookies)");
            }

            if (hasNativeMessaging)
            {
                reasons.Add("Native Messaging execution capability (Host process breakout)");
            }

            if (artifact.Permissions.Contains("debugger"))
            {
                reasons.Add("Chrome DevTools Debugger protocol control");
            }

            if (reasons.Count > 0)
            {
                artifact.IsSuspicious = true;
                artifact.SuspicionReason = string.Join("; ", reasons.ToArray());
            }
        }

        private static void InspectExtensionStorage(string profileDir, BrowserExtensionArtifact artifact)
        {
            if (string.IsNullOrEmpty(artifact.ExtensionId) || artifact.ExtensionId.Length != 32) return;

            try
            {
                string ldbDir = Path.Combine(profileDir, Path.Combine("Local Extension Settings", artifact.ExtensionId));
                if (Directory.Exists(ldbDir))
                {
                    artifact.HasLevelDbStorage = true;
                    var ldbFiles = Directory.GetFiles(ldbDir, "*.ldb");
                    var logFiles = Directory.GetFiles(ldbDir, "*.log");

                    int keyCount = 0;
                    foreach (var f in ldbFiles)
                    {
                        keyCount += (int)(new FileInfo(f).Length / 64);
                    }
                    foreach (var f in logFiles)
                    {
                        keyCount += (int)(new FileInfo(f).Length / 64);
                    }
                    artifact.LevelDbKeyCount = Math.Max(1, keyCount);

                    // Quick scan for vault/credential indicators
                    foreach (var f in logFiles)
                    {
                        try
                        {
                            string logText = File.ReadAllText(f, Encoding.ASCII);
                            if (logText.Contains("vault") || logText.Contains("keyring") || logText.Contains("seed") || logText.Contains("encrypted"))
                            {
                                if (!artifact.DiscoveredTokens.Contains("Encrypted Keyring / Vault Detected"))
                                {
                                    artifact.DiscoveredTokens.Add("Encrypted Keyring / Vault Detected");
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private static void FinalizeReport(BrowserExtensionsReport report)
        {
            report.TotalExtensions = report.Extensions.Count;
            int wallets = 0;
            int passManagers = 0;
            int suspicious = 0;

            foreach (var ext in report.Extensions)
            {
                if (ext.Category == "Crypto Wallet") wallets++;
                else if (ext.Category == "Password Manager") passManagers++;

                if (ext.IsSuspicious) suspicious++;
            }

            report.CryptoWalletsCount = wallets;
            report.PasswordManagersCount = passManagers;
            report.SuspiciousCount = suspicious;
        }
    }
}
