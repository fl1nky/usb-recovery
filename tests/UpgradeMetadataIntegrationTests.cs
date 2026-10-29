using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class UpgradeMetadataIntegrationTests
{
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static void IgnoreProgress(long done, long total) { }
    public static int Main(string[] args)
    {
        string project = Path.GetFullPath(args[0]), fixture = Path.GetFullPath(args[1]), expectedPath = Path.GetFullPath(args[2]), mode = args[3];
        string evidence = Path.Combine(project, "tests", "UpgradeMetadataIntegration-" + mode + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(evidence);
        string resultPath = Path.Combine(project, "tests", "UpgradeMetadataIntegration-" + mode + ".result.txt");
        string prior = Environment.GetEnvironmentVariable("__COMPAT_LAYER");
        var stopwatch = Stopwatch.StartNew();
        using (var cancel = new CancellationTokenSource(60000))
        {
            try
            {
                Assert(File.Exists(fixture) && !fixture.StartsWith(@"\\.\"), "Only regular synthetic image files are supported by this integration test");
                string originalHash = RecoveryCore.HashFile(fixture, cancel.Token, IgnoreProgress);
                string image = Path.Combine(evidence, "Синтетическая копия флешки.dd"); File.Copy(fixture, image);
                File.WriteAllText(image + ".sha256", originalHash + "  " + Path.GetFileName(image), new UTF8Encoding(false));
                string output = Path.Combine(evidence, "Результаты"); Directory.CreateDirectory(output);
                Environment.SetEnvironmentVariable("__COMPAT_LAYER", "RunAsInvoker");
                ScanResult result = RecoveryPipeline.Run(image, output, true, cancel.Token, delegate(string message) { Console.WriteLine(message); });
                var serializer = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
                var stages = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(output, "scan-stages.json")));
                var stageRecords = ((IEnumerable)stages["stages"]).Cast<Dictionary<string, object>>().ToArray();
                Assert((string)stages["status"] == "finished" && !result.HasWarnings && stageRecords.Length == 4 && stageRecords.All(s => (string)s["status"] == "complete"), "One or more packaged recovery stages did not complete");
                var catalog = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(output, "photo-catalog.json")));
                var photos = ((IEnumerable)catalog["items"]).Cast<Dictionary<string, object>>().ToArray();
                string[] files = RecoveryCore.RecoveredFiles(output).ToArray();
                Assert(result.Candidates == files.Length && Convert.ToInt32(stages["candidates"]) == files.Length, "Actual candidate counts disagree");
                string[] expected = Directory.Exists(expectedPath) ? Directory.GetFiles(expectedPath).Where(p => Path.GetExtension(p).Equals(".jpg", StringComparison.OrdinalIgnoreCase) || Path.GetExtension(p).Equals(".png", StringComparison.OrdinalIgnoreCase)).ToArray() : new[] { expectedPath };
                Assert(expected.Length == (mode == "unaligned" ? 2 : 1), "Wrong expected fixture count");
                foreach (string photo in expected)
                {
                    string hash = RecoveryCore.HashFile(photo, cancel.Token, IgnoreProgress);
                    Dictionary<string, object> item = photos.Single(p => (string)p["Sha256"] == hash);
                    Assert((string)item["Status"] == "decoded", "Expected exact image is not decoded");
                    Assert(File.Exists(Path.Combine(output, ((string)item["Thumbnail"]).Replace('/', Path.DirectorySeparatorChar))), "Expected image thumbnail missing");
                    Assert(files.Any(p => RecoveryCore.HashFile(p, cancel.Token, IgnoreProgress) == hash), "Expected output bytes missing");
                    if (mode == "ntfs")
                    {
                        Assert(hash == "08d0c3aa75b9b357ad9ce43b39cf8a8e039f462863fe983f66c4726e36d7c282", "NTFS expected fixture hash mismatch");
                        Assert((string)item["Name"] == "grandma-photo.jpg" && ((string)item["Path"]).StartsWith("ntfs/"), "Original NTFS filename not preserved/preferred");
                        Console.WriteLine("NTFS known photo: name=" + item["Name"] + "; copies=" + item["Copies"] + "; SHA256=" + hash);
                    }
                    if (mode == "fat")
                    {
                        Assert(hash == "b7fb9b832727b3401f71110641f48b7ebf5195bf83ca10dc753fb41e5ed83e77", "FAT expected fixture hash mismatch");
                        Assert(((string)item["Name"]).EndsWith("_HOTO.JPG") && ((string)item["Path"]).Contains("/retained-fat-uncertain/"), "FAT lost first character falsely reconstructed or wrong method used");
                        Assert(((string)item["Detail"]).Contains("предположительно") && ((string)item["Detail"]).Contains("перезаписанные"), "FAT reconstruction uncertainty hidden from photo catalog");
                        string csv = File.ReadAllText(Path.Combine(output, "filesystem", "metadata.csv"));
                        Assert(csv.Contains("retained-fat-uncertain") && csv.Contains("short name: first character lost") && csv.Contains("partial"), "FAT uncertainty/name-loss/partial report missing");
                        Console.WriteLine("FAT fragmented photo: name=" + item["Name"] + "; bytes=" + item["Bytes"] + "; status=" + item["Status"] + "; uncertainty visible; SHA256=" + hash);
                    }
                }
                Assert(RecoveryCore.HashFile(fixture, cancel.Token, IgnoreProgress) == originalHash, "Original fixture changed");
                Assert(RecoveryCore.HashFile(image, cancel.Token, IgnoreProgress) == originalHash, "Scanned copy changed");
                Assert(File.Exists(result.Gallery), "Photo gallery missing");
                int partialPhotos = photos.Count(p => (string)p["Status"] == "partial");
                int unreadablePhotos = photos.Count(p => (string)p["Status"] == "unreadable");
                string stageCounts = String.Join("; ", stageRecords.Select(s => (string)s["method"] + "=" + s["candidates"]));
                string summary = "PASS packaged " + mode + " pipeline; stages=" + stageCounts + "; actualCandidates=" + files.Length + "; photoCandidates=" + catalog["candidates"] + "; uniquePhotos=" + catalog["unique"] + "; decoded=" + catalog["decoded"] + "; partialPhotos=" + partialPhotos + "; unreadablePhotos=" + unreadablePhotos + "; warnings=" + result.HasWarnings + "; expectedExact=" + expected.Length + "; original/copy SHA256 unchanged; elapsed=" + stopwatch.Elapsed.TotalSeconds.ToString("0.00") + "s; tool=" + RecoveryCore.ToolPath + "; evidence=" + evidence;
                File.WriteAllText(resultPath, summary, new UTF8Encoding(false)); Console.WriteLine(summary); return 0;
            }
            catch (Exception ex) { string summary = "FAIL packaged " + mode + ": " + ex + "\r\nEvidence=" + evidence; File.WriteAllText(resultPath, summary, new UTF8Encoding(false)); Console.WriteLine(summary); return 1; }
            finally { Environment.SetEnvironmentVariable("__COMPAT_LAYER", prior); }
        }
    }
}
