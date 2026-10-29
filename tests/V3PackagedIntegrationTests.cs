using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class V3PackagedIntegrationTests
{
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
    static int assertions;
    static void Check(bool value, string text) { if (!value) throw new Exception(text); assertions++; Console.WriteLine("PASS " + text); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    public static int Main(string[] args)
    {
        string project = Path.GetFullPath(args[0]);
        string evidence = Path.Combine(project, "tests", "V3-packaged-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(evidence); string input = Path.Combine(evidence, "Синтетический источник"); Directory.CreateDirectory(input);
        try {
            Check(File.Exists(HelperClient.Executable), "portable helper present");
            string png = Path.Combine(project, "tests", "photorec-20261011T231546120952Z", "fixtures", "expected.png");
            File.Copy(png, Path.Combine(input, "family-photo.png")); File.Copy(png, Path.Combine(input, "cache-no-extension"));
            var messages = new[] { new { id = 1, from_id = "user900", from = "Прабабушка", date = "2026-10-11T12:30:00", text = "Секрет пирожков 🥧\n</script><img src=https://example.test/tracker>", photo = "family-photo.png" }, new { id = 2, from_id = "user900", from = "Прабабушка", date = "2026-10-11T12:31:00", text = "Секрет пирожков 🥧", photo = "family-photo.png" } };
            string export = Json.Serialize(new { id = 42, name = "Семья", messages = messages });
            File.WriteAllText(Path.Combine(input, "result.json"), export, new UTF8Encoding(false)); File.WriteAllText(Path.Combine(input, "result-copy.json"), export, new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(input, "чат.txt"), "01/02/2026, 12:30 - Alice: первая строка\nвторая 🥧", new UTF8Encoding(false));
            var originalHashes = Directory.GetFiles(input).ToDictionary(p => p, p => Hash(p));
            string run = Path.Combine(evidence, "Запуск"); var source = new LocalFolderSource(input);
            string snapshot = SourceAcquisition.Copy(source, "", run, CancellationToken.None, text => { });
            var manifest = Json.Deserialize<AcquisitionManifest>(File.ReadAllText(Path.Combine(run, "acquisition.json")));
            Check(manifest.Status == "finished" && manifest.Files.Count == 5 && manifest.Files.All(f => f.Status == "complete" && Hash(Path.Combine(run, f.LocalPath)) == f.Sha256), "acquisition keeps exact bytes and SHA256 provenance");
            string secret = "INTEGRATION_SECRET_CANARY_пирожки_28";
            var secrets = new Dictionary<string, string> { { "ios_password", secret }, { "whatsapp_key", secret }, { "signal_key", secret } };
            string archive = Path.Combine(run, "archive");
            var result = HelperClient.Scan(snapshot, archive, secrets, true, CancellationToken.None, text => { Check(!text.Contains(secret), "progress contains no secret"); });
            Check((result.Status == "complete" || result.Status == "partial") && result.Messages == 3 && result.Media > 0, "C# acquisition to packaged Python parser creates messages and media");
            var records = File.ReadAllLines(Path.Combine(archive, "messages.jsonl"), Encoding.UTF8).Select(line => Json.Deserialize<Dictionary<string, object>>(line)).ToArray();
            Check(records.Count(m => (string)m["app"] == "Telegram") == 2, "confirmed Telegram IDs deduplicate exports without merging distinct text matches");
            var wa = records.Single(m => (string)m["app"] == "WhatsApp");
            Check(wa["timestamp"] == null && Convert.ToBoolean(wa["timestamp_ambiguous"]) && ((string)wa["text"]).Contains("вторая 🥧"), "multiline Unicode and ambiguous dates survive import");
            Check(records.All(m => Convert.ToString(m["source_file"]).StartsWith(input, StringComparison.OrdinalIgnoreCase)), "records refer to original source paths");
            foreach (string file in new[] { "Фотографии.html", "Переписки.html", "chat-index.sqlite", "photo-metadata.json", "sources.json" }) Check(File.Exists(Path.Combine(archive, file)), "archive contains " + file);
            string chatHtml = File.ReadAllText(Path.Combine(archive, "Переписки.html"));
            Check(!chatHtml.Contains("</script><img src=https:") && chatHtml.Contains("connect-src 'none'"), "source HTML is escaped and archive disables remote requests");
            foreach (string path in Directory.GetFiles(archive, "*", SearchOption.AllDirectories)) {
                if (new FileInfo(path).Length < 16 * 1024 * 1024) Check(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains(secret), "secret absent in " + Path.GetFileName(path));
            }
            Check(originalHashes.All(pair => Hash(pair.Key) == pair.Value), "source export and photos stay unchanged");
            var copiedTimes = manifest.Files.ToDictionary(f => f.LocalPath, f => File.GetLastWriteTimeUtc(Path.Combine(run, f.LocalPath)));
            SourceAcquisition.Copy(source, "", run, CancellationToken.None, text => { });
            Check(copiedTimes.All(pair => File.GetLastWriteTimeUtc(Path.Combine(run, pair.Key)) == pair.Value), "resume verifies complete files without recopying");
            Console.WriteLine("PASS packaged v3: " + assertions + " assertions; evidence=" + evidence); return 0;
        } catch (Exception ex) { Console.WriteLine("FAIL " + ex.Message + "; evidence=" + evidence); return 1; }
    }
}
