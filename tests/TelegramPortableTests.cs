using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class TelegramPortableTests
{
    static int assertions;
    static void Check(bool value, string name) { assertions++; if (!value) throw new Exception(name); }
    static string Hash(string path) { using (var file = File.OpenRead(path)) using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant(); }
    public static int Main()
    {
        string testRoot = Path.Combine(Path.GetTempPath(), "TelegramPortable-synthetic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testRoot);
        try {
            string source = Path.Combine(testRoot, "input"), output = Path.Combine(testRoot, "archive");
            string hidden = Path.Combine(source, ".hidden", "nested"); Directory.CreateDirectory(hidden);
            File.SetAttributes(Path.Combine(source, ".hidden"), FileAttributes.Directory | FileAttributes.Hidden);
            var json = new JavaScriptSerializer();
            string export = Path.Combine(hidden, "result.json");
            File.WriteAllText(export, json.Serialize(new { name = "Семья", type = "personal_chat", id = 123, messages = new[] {
                new { id = 1, date = "2020-01-01T00:00:00+03:00", from = "Тест", from_id = "user5", text = "Старый рецепт" },
                new { id = 2, date = "2026-10-27T10:00:00+03:00", from = "Тест", from_id = "user5", text = "Рецепт пирожков с яблоками" } } }), new UTF8Encoding(false));
            string dump = Path.Combine(hidden, "phone.hprof");
            using (var stream = File.Create(dump)) {
                foreach (var enc in new[] { Encoding.UTF8, Encoding.Unicode, Encoding.BigEndianUnicode }) {
                    stream.Write(new byte[] { 0, 0, 255, 0 }, 0, 4); byte[] bytes = enc.GetBytes("Важный рецепт из дампа памяти"); stream.Write(bytes, 0, bytes.Length);
                }
                stream.Write(new byte[] { 0, 0 }, 0, 2);
            }
            File.WriteAllText(Path.Combine(hidden, "key_datas.dmp"), "PRIVATE_SESSION_SYNTHETIC_CANARY");
            File.WriteAllText(Path.Combine(hidden, "cache.dat"), "TDF$SYNTHETIC_ENCRYPTED_CACHE");
            string exportHash = Hash(export), dumpHash = Hash(dump);
            var result = TelegramAnalysisService.AnalyzeSelected(output, source, "рецепт|пирожк.*", true, CancellationToken.None, null);
            Check(result.Status != "error", "portable analysis completes");
            Check(result.HistoryMessages == 2, "recognized history count excludes fragments");
            Check(result.FragmentRecords == 3, "all three dump encodings found");
            Check(result.EncryptedSources > 0, "encrypted cache reported");
            Check(Hash(export) == exportHash && Hash(dump) == dumpHash, "input hashes unchanged");
            Check(!Directory.Exists(output + ".work"), "private scratch removed");
            Check(!File.Exists(Path.Combine(output, "job.incomplete")), "only complete archive published");
            string records = File.ReadAllText(Path.Combine(output, "messages.jsonl"), Encoding.UTF8);
            Check(!records.Contains("PRIVATE_SESSION_SYNTHETIC_CANARY"), "account file not archived");
            var search = ArchiveSearchService.Search(output, "Telegram", "", "", 0, CancellationToken.None);
            Check(search.total == 5 && Convert.ToInt32(search.records[0].message_id) == 2, "latest known message first");
            Check(search.records[2].timestamp == null && search.records[2].sender_id == null, "fragments have no invented dates/authors");
            search = ArchiveSearchService.Search(output, "Telegram", "памяти", "fragment", 0, CancellationToken.None);
            Check(search.total == 3 && search.records[0].application_confirmed == false, "keyword finds separately labeled fragments");
            Check(search.records[0].source_sha256 == dumpHash && search.records[0].byte_offset != null, "source hash and byte position retained");
            search = ArchiveSearchService.Search(output, "Telegram", "пирожк\\w+", "export", 0, CancellationToken.None, true);
            Check(search.total == 1, "bundled native regex reader works");
            search = ArchiveSearchService.Search(output, "Telegram", "[", "", 0, CancellationToken.None, true);
            Check(search.status == "error" && search.code == "REGEX_INVALID", "invalid regex has controlled error");
            string badOutput = Path.Combine(testRoot, "bad-regex");
            result = TelegramAnalysisService.AnalyzeSelected(badOutput, dump, "[", true, CancellationToken.None, null);
            Check(result.Status == "error" && result.Code == "REGEX_INVALID", "analysis rejects invalid regex");
            Check(!Directory.Exists(badOutput) && !Directory.Exists(badOutput + ".work"), "bad regex cannot publish success");
            using (var cancellation = new CancellationTokenSource()) {
                cancellation.Cancel(); bool stopped = false;
                try { TelegramAnalysisService.AnalyzeSelected(Path.Combine(testRoot,"cancelled"), dump, "", false, cancellation.Token, null); } catch (OperationCanceledException) { stopped = true; }
                Check(stopped, "pre-start cancellation respected");
            }
            Console.WriteLine("PASS " + assertions + " portable integration assertions; synthetic local files only."); return 0;
        } catch (Exception error) { Console.WriteLine("FAIL " + error.Message); return 1; }
        finally {
            // A freshly generated synthetic directory; no user data locations.
            if (Path.GetFullPath(testRoot).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)) try { Directory.Delete(testRoot, true); } catch { }
        }
    }
}
