using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class ArchiveSalvageTests
{
    static int checks;
    static void Check(bool value, string message) { checks++; if (!value) throw new Exception(message); }
    static string Hash(string path) { using (var input = File.OpenRead(path)) using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(input)).Replace("-", "").ToLowerInvariant(); }
    public static int Main(string[] args)
    {
        var json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
        string root = Path.GetFullPath(args[0]);
        var fixtures = json.Deserialize<List<Dictionary<string, object>>>(File.ReadAllText(Path.Combine(root, "fixtures.json")));
        foreach (var fixture in fixtures) {
            string image = Path.Combine(root, (string)fixture["file"]), output = Path.Combine(root, (string)fixture["case"] + "-" + Guid.NewGuid().ToString("N"));
            var expected = (System.Collections.ArrayList)fixture["expected"];
            int count = ArchiveSalvage.Recover(image, output, CancellationToken.None, null);
            Check(count == expected.Count, fixture["case"] + " member count");
            var report = json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(output, "archive-salvage.json")));
            Check((string)report["status"] == "complete", fixture["case"] + " complete scan");
            var members = (System.Collections.ArrayList)report["files"];
            for (int n = 0; n < expected.Count; n++) {
                var wanted = (Dictionary<string, object>)expected[n]; var actual = (Dictionary<string, object>)members[n];
                string relative = (string)actual["Path"], path = Path.Combine(output, relative.Replace('/', Path.DirectorySeparatorChar));
                Check((string)actual["OriginalMemberName"] == (string)wanted["name"], "original name provenance");
                Check(Convert.ToInt64(actual["HeaderOffset"]) == Convert.ToInt64(wanted["offset"]), "image offset provenance");
                Check(Hash(path) == (string)wanted["sha256"] && (string)actual["Sha256"] == (string)wanted["sha256"], "exact independent SHA256 match");
                Check(new FileInfo(path).Length == Convert.ToInt64(wanted["size"]), "exact uncompressed size");
                Check((string)actual["Status"] == "member_crc_verified", "only member verified");
                Check(relative.StartsWith("salvage-content/", StringComparison.Ordinal) && Path.GetFileName(relative).IndexOf("..", StringComparison.Ordinal) < 0, "safe flat output");
                if (((string)wanted["name"]).EndsWith(".html") || ((string)wanted["name"]).EndsWith(".exe")) Check(path.EndsWith(".untrusted.bin", StringComparison.Ordinal), "active extension neutralized");
            }
            Check(Hash(image) == (string)fixture["image_sha256"], fixture["case"] + " source unchanged");
            Check(!Directory.GetFiles(output, "*.partial", SearchOption.AllDirectories).Any(), "no unverified partial published");
        }
        string cancelOutput = Path.Combine(root, "cancel-" + Guid.NewGuid().ToString("N")), cancelImage = Path.Combine(root, "block-boundary.dd");
        var cancellation = new CancellationTokenSource();
        bool cancelled = false;
        try { ArchiveSalvage.Recover(cancelImage, cancelOutput, cancellation.Token, (a,b) => cancellation.Cancel()); }
        catch (OperationCanceledException) { cancelled = true; }
        Check(cancelled, "cancellation observed");
        Check(File.ReadAllText(Path.Combine(cancelOutput, "archive-salvage.json")).Contains("cancelled"), "cancellation checkpoint");
        bool rejected = false;
        try { ArchiveSalvage.Recover(@"\\.\PhysicalDrive0", Path.Combine(root, "never-created"), CancellationToken.None, null); }
        catch (IOException) { rejected = true; }
        Check(rejected, "device path rejected before open");
        string existing = Path.Combine(root, "existing-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(Path.Combine(existing, "salvage-content")); File.WriteAllText(Path.Combine(existing, "salvage-content", "keep.txt"), "keep"); rejected = false;
        try { ArchiveSalvage.Recover(cancelImage, existing, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && File.ReadAllText(Path.Combine(existing, "salvage-content", "keep.txt")) == "keep", "existing output never overwritten");
        string collision = Path.Combine(root, "source-collision-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(collision);
        string collisionImage = Path.Combine(collision, "archive-salvage.json"); File.Copy(cancelImage, collisionImage); string collisionHash = Hash(collisionImage); rejected = false;
        try { ArchiveSalvage.Recover(collisionImage, collision, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && Hash(collisionImage) == collisionHash, "report/source path collision cannot overwrite the source");
        string limitOutput = Path.Combine(root, "candidate-limit-" + Guid.NewGuid().ToString("N")); rejected = false;
        try { ArchiveSalvage.Recover(Path.Combine(root, "candidate-limit.dd"), limitOutput, CancellationToken.None, null); } catch (IOException) { rejected = true; }
        Check(rejected && File.ReadAllText(Path.Combine(limitOutput, "archive-salvage.json")).Contains("limited"), "candidate scan work capped with explicit limited status");
        Check(!Directory.GetFiles(Path.Combine(limitOutput, "salvage-content")).Any(), "unsupported candidate limit publishes no data");
        Console.WriteLine("PASS ArchiveSalvage: " + checks + " checks; " + fixtures.Count + " independent Python ZIP fixtures"); return 0;
    }
}
