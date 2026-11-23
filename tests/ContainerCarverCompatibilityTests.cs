using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Existing independent ZIP/Pillow/wave producer. The MP4 is deliberately only a
// structural container; this test does not count it as decodable recovered video.
public static class ContainerCarverCompatibilityTests
{
    static int checks;
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    public static int Main(string[] args)
    {
        try
        {
            string project = Path.GetFullPath(args[0]);
            string fixtures = Path.Combine(project, "tests", "DeepRecoveryWork");
            string source = Path.Combine(fixtures, "containers.dd"), before = Hash(source);
            var json = new JavaScriptSerializer();
            var expected = json.Deserialize<List<Dictionary<string, object>>>(File.ReadAllText(
                Path.Combine(fixtures, "containers-expected.json")));
            string root = Path.Combine(project, ".build", "container-compatibility-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            foreach (bool documentsOnly in new[] { false, true })
            {
                var options = new RecoveryOptions { Other = !documentsOnly, Photos = !documentsOnly,
                    Video = !documentsOnly, Audio = !documentsOnly, Archives = !documentsOnly, Documents = true };
                string output = Path.Combine(root, documentsOnly ? "documents" : "all");
                int count = ContainerCarver.Recover(source, output, options, CancellationToken.None, null);
                var wanted = expected.Where(x => !documentsOnly || new[] { ".pdf", ".docx" }.Contains((string)x["extension"])).ToArray();
                Check(count == wanted.Length, "format selection returns exactly the producer targets");
                foreach (var target in wanted)
                {
                    string path = Path.Combine(output, "containers", "offset-" + Convert.ToInt64(target["offset"]).ToString("D16") + (string)target["extension"]);
                    Check(new FileInfo(path).Length == Convert.ToInt64(target["bytes"]), "exact independent container size");
                    Check(Hash(path) == (string)target["sha256"], "exact independent container bytes");
                }
                var report = json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(output, "container-search.json")));
                var records = json.ConvertToType<List<Dictionary<string, object>>>(report["files"]);
                Check(records.All(x => (string)x["status"] == "structure_only"), "structural validation retains its evidence limit");
                Check(!Directory.GetFiles(output, "*.partial", SearchOption.AllDirectories).Any(), "no incomplete named output");
            }
            var movie = expected.Single(x => (string)x["extension"] == ".mp4");
            string eof = Path.Combine(root, "terminal-atom.dd");
            File.WriteAllBytes(eof, File.ReadAllBytes(source).Skip(Convert.ToInt32(movie["offset"])).Take(Convert.ToInt32(movie["bytes"])).ToArray());
            Check(ContainerCarver.Recover(eof, Path.Combine(root, "terminal-atom"), new RecoveryOptions(), CancellationToken.None, null) == 1,
                "eight-byte BMFF terminal atom at EOF is retained");
            using (var token = new CancellationTokenSource())
            {
                token.Cancel(); bool cancelled = false;
                try { ContainerCarver.Recover(source, Path.Combine(root, "cancelled"), new RecoveryOptions(), token.Token, null); }
                catch (OperationCanceledException) { cancelled = true; }
                Check(cancelled && !Directory.Exists(Path.Combine(root, "cancelled")), "pre-cancel creates no output");
            }
            Check(Hash(source) == before, "all source bytes unchanged");
            Console.WriteLine("PASS ContainerCarverCompatibility: " + checks + " checks; DOCX/PDF/WebP/WAV/structural MP4, filters, terminal atom and source SHA; no video decoding/GUI/devices claim");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
