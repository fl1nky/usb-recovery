using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using UsbRecovery;

// Owned PNG/JPEG and PCM WAV originals, regular disk images, no UI/audio playback.
public static class RangeCarverCheckpointTests
{
    static string work, method;
    static bool footerMode;
    static int checks;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
    static string OutputFolder { get { return method == "photos" ? "extra-photos" : method; } }
    static string Prefix { get { return method == "photos" ? "Фотографии: " : method == "containers" ? "Контейнеры: " : "Свои типы: "; } }
    static string OffsetPrefix { get { return method == "user-signatures" ? "owned-" : "offset-"; } }
    static string ModeName { get { return footerMode ? "user-signatures-footer" : method; } }
    static void Select(string name)
    {
        footerMode = name == "user-signatures-footer";
        method = footerMode ? "user-signatures" : name;
    }
    static void Check(bool value, string why) { checks++; if (!value) throw new Exception(method + ": " + why); }
    static string Hash(string path) { return RecoveryCore.HashFile(path, CancellationToken.None, (a, b) => { }); }
    static RecoveryOptions Options()
    {
        return new RecoveryOptions { FatMetadata = false, NtfsMetadata = false, LostPartitions = false,
            Signatures = false, EmbeddedPhotos = method == "photos", Containers = method == "containers",
            CustomSignatures = method == "user-signatures", CustomRules = new List<UserSignatureRule> {
                new UserSignatureRule { Id = "owned", Name = "Owned fixed candidate", Extension = "bin",
                    HeaderHex = "52 49 46 46", FixedBytes = footerMode ? 0 : 108,
                    FooterHex = footerMode ? "4F574E4544454E4421" : null,
                    MinBytes = footerMode ? 108 : 0, MaxBytes = footerMode ? 256 : 0 } } };
    }
    static byte[] Original(int variant)
    {
        using (var memory = new MemoryStream())
        {
            if (method == "photos")
            {
                using (var bitmap = new Bitmap(20, 12))
                {
                    for (int y = 0; y < bitmap.Height; y++) for (int x = 0; x < bitmap.Width; x++)
                        bitmap.SetPixel(x, y, Color.FromArgb((x * 11 + variant * 17) % 256, y * 19, (x * y + variant * 31) % 256));
                    bitmap.Save(memory, variant == 2 ? ImageFormat.Jpeg : ImageFormat.Png);
                }
            }
            else
            {
                using (var writer = new BinaryWriter(memory, Encoding.ASCII, true))
                {
                    writer.Write(Encoding.ASCII.GetBytes("RIFF")); writer.Write(100);
                    writer.Write(Encoding.ASCII.GetBytes("WAVEfmt ")); writer.Write(16);
                    writer.Write((short)1); writer.Write((short)1); writer.Write(8000); writer.Write(16000);
                    writer.Write((short)2); writer.Write((short)16);
                    writer.Write(Encoding.ASCII.GetBytes("data")); writer.Write(64);
                    for (int i = 0; i < 32; i++) writer.Write((short)((i * 311 + variant * 197) % 12000));
                }
                if (footerMode)
                {
                    byte[] footer = Encoding.ASCII.GetBytes("OWNEDEND!");
                    memory.Write(footer, 0, footer.Length);
                }
            }
            return memory.ToArray();
        }
    }
    static string Image(string name, bool many)
    {
        string path = Path.Combine(work, ModeName + "-" + name + ".dd");
        byte[] data = new byte[40 * 1024 * 1024];
        var offsets = many ? Enumerable.Range(0, 129).Select(i => 1024 * 1024 + i * 4096 + 9)
            .Concat(new[] { 30 * 1024 * 1024 + 17 }).ToArray() :
            new[] { 1024 * 1024 + 9, 4 * 1024 * 1024 - 3, 30 * 1024 * 1024 + 17 };
        for (int i = 0; i < offsets.Length; i++)
        {
            byte[] original = Original(i);
            Buffer.BlockCopy(original, 0, data, offsets[i], original.Length);
            File.WriteAllBytes(path + ".original-" + offsets[i], original);
        }
        File.WriteAllBytes(path, data);
        File.WriteAllText(path + ".sha256", Hash(path).ToUpperInvariant());
        return path;
    }
    static int Percent(string message)
    {
        return message.StartsWith(Prefix, StringComparison.Ordinal) ? Int32.Parse(message.Substring(Prefix.Length).TrimEnd('%')) : -1;
    }
    static Dictionary<string, object> Object(string path)
    {
        return Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
    }
    static long Cursor(string root)
    {
        var stage = RecoverySession.Read(root).Stages.Single(x => x.Key == method);
        Check(stage.CheckpointPath != null && stage.CheckpointSequence > 0, "parent stores an internal checkpoint");
        string path = RecoveryCatalog.SafeFile(root, stage.CheckpointPath);
        Check(Hash(path) == stage.CheckpointSha256, "parent pins exact checkpoint bytes");
        return Convert.ToInt64(((Dictionary<string, object>)Object(path)["Payload"])["Position"]);
    }
    static long Cancel(string source, string root)
    {
        bool stopped = false;
        using (var cancel = new CancellationTokenSource())
        {
            try { RecoveryPipeline.Run(source, root, Options(), cancel.Token, message =>
                { if (Percent(message) >= 20) cancel.Cancel(); }, source + ".sha256"); }
            catch (OperationCanceledException) { stopped = true; }
        }
        Check(stopped && !File.Exists(Path.Combine(root, "files-index.json")), "cancelled pass publishes no successful catalog");
        long position = Cursor(root);
        Check(position == 8 * 1024 * 1024, "two consumed scan blocks are committed");
        return position;
    }
    static void Resume(string source, string root, long position, int expected)
    {
        string before = Hash(source);
        int first = -1;
        RecoveryPipeline.Resume(root, CancellationToken.None, message =>
            { int percent = Percent(message); if (percent >= 0 && first < 0) first = percent; });
        Check(first == position * 100 / new FileInfo(source).Length, "scan resumes the committed cursor");
        Check(!Directory.Exists(Path.Combine(root, "attempt-history")), "inner continuation retains the same attempt");
        string[] files = Directory.GetFiles(Path.Combine(root, OutputFolder)).Where(x => !x.EndsWith(".partial")).ToArray();
        Check(files.Length == expected, "all expected named candidates appear exactly once");
        foreach (string file in files)
        {
            string stem = Path.GetFileNameWithoutExtension(file);
            long offset = Int64.Parse(stem.Substring(OffsetPrefix.Length));
            Check(File.ReadAllBytes(file).SequenceEqual(File.ReadAllBytes(source + ".original-" + offset)), "exact original bytes and source offset");
        }
        string report = Path.Combine(root, method == "photos" ? "extra-photo-search.json" :
            method == "containers" ? "container-search.json" : "user-signatures.json");
        Check(Object(report)[method == "user-signatures" ? "Status" : "status"].Equals("complete"), "resumed report is complete");
        if (method == "user-signatures")
        {
            var signatureReport = Json.Deserialize<UserSignatureRecovery.Report>(File.ReadAllText(report));
            Check(signatureReport.Files.All(r => r.Status == "signature_candidate" &&
                r.Boundary == (footerMode ? "first_matching_footer" : "user_fixed_size")),
                "signature boundary and unknown file validity survive continuation");
            Check(footerMode ? signatureReport.FooterWorkBytes > 0 : signatureReport.FooterWorkBytes == 0,
                "footer search work is preserved in the saved state");
        }
        Check(RecoverySession.Read(root).Stages.Single().Status == "complete", "parent commits method completion");
        string reportHash = Hash(report);
        Check(RecoveryPipeline.Resume(root, CancellationToken.None, message => { }).ResumedStages == 1 && Hash(report) == reportHash,
            "completed pass is reused unchanged");
        Check(Hash(source) == before, "source unchanged");
    }
    static void Cancellation(bool missing)
    {
        string source = Image(missing ? "missing" : "cancel", false), root = source + ".job";
        long position = Cancel(source, root);
        string[] files = Directory.GetFiles(Path.Combine(root, OutputFolder));
        Check(files.Length == 2, "both early candidates, including the split signature, survive cancellation");
        string oldHash = Hash(files[0]);
        if (missing) File.Delete(files[0]);
        Resume(source, root, position, 3);
        Check(Hash(files[0]) == oldHash, "committed missing output is reconstructed exactly");
    }
    static void Rejected(string kind)
    {
        bool many = kind == "ledger";
        string source = Image(kind, many), root = source + ".job";
        Cancel(source, root);
        string changed;
        if (kind == "source") changed = source;
        else if (kind == "checkpoint")
            changed = RecoveryCatalog.SafeFile(root, RecoverySession.Read(root).Stages.Single().CheckpointPath);
        else if (kind == "ledger")
        {
            var stage = RecoverySession.Read(root).Stages.Single();
            var payload = (Dictionary<string, object>)Object(RecoveryCatalog.SafeFile(root, stage.CheckpointPath))["Payload"];
            var head = (Dictionary<string, object>)payload["Output"];
            string newest = RecoveryCatalog.SafeFile(root, (string)head["Path"]);
            var previous = (Dictionary<string, object>)Object(newest)["Previous"];
            Check(Convert.ToInt32(previous["Count"]) == 128, "output inventory really spans multiple pinned pages");
            changed = RecoveryCatalog.SafeFile(root, (string)previous["Path"]);
        }
        else if (kind == "unknown")
        {
            changed = Path.Combine(root, OutputFolder, "unexpected.txt");
            File.WriteAllText(changed, "owned unexpected file");
        }
        else changed = Directory.GetFiles(Path.Combine(root, OutputFolder)).First();
        if (kind != "unknown") using (var stream = new FileStream(changed, FileMode.Open, FileAccess.ReadWrite))
        { int value = stream.ReadByte(); stream.Position = 0; stream.WriteByte((byte)(value ^ 1)); }
        string before = Hash(changed); bool rejected = false;
        try { RecoveryPipeline.Resume(root, CancellationToken.None, message => { }); }
        catch (IOException) { rejected = true; }
        Check(rejected && Hash(changed) == before, kind + " tamper is rejected without overwriting evidence");
    }
    static void PublicationFailure()
    {
        string source = Image("publication-failure", false), root = source + ".job";
        string extension = method == "photos" ? ".png" : method == "containers" ? ".wav" : ".bin";
        string partial = Path.Combine(root, OutputFolder, OffsetPrefix + (1024 * 1024 + 9).ToString("D16") + extension + ".partial");
        bool failed = false, injected = false;
        try
        {
            RecoveryPipeline.Run(source, root, Options(), CancellationToken.None, message =>
            {
                if (injected || !message.StartsWith(method == "photos" ? "JPEG/PNG внутри данных" :
                    method == "containers" ? "Контейнеры и медиа по смещениям" : "Свои типы файлов", StringComparison.Ordinal)) return;
                Directory.CreateDirectory(Path.GetDirectoryName(partial));
                File.WriteAllText(partial, "owned stale partial");
                File.SetAttributes(partial, FileAttributes.ReadOnly); injected = true;
            }, source + ".sha256");
        }
        catch (UnauthorizedAccessException) { failed = true; }
        finally { if (File.Exists(partial)) File.SetAttributes(partial, FileAttributes.Normal); }
        Check(injected && failed && File.Exists(partial), "real denied output publication occurs after write-ahead commit");
        long position = Cursor(root);
        Check(position == (method == "user-signatures" ? 2 : 4) * 1024 * 1024 && Directory.GetFiles(Path.Combine(root, OutputFolder)).Length == 1,
            "parent pins planned ranges while named candidate files are still absent");
        Resume(source, root, position, 3);
        Check(!File.Exists(partial), "repaired output replaces only the stale partial name");
    }
    static void KilledProcess()
    {
        string source = Image("killed", false), root = source + ".job", ready = source + ".ready";
        var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
            "child " + ModeName + " \"" + source + "\" \"" + root + "\" \"" + ready + "\"")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            try
            {
                var watch = Stopwatch.StartNew();
                while (!File.Exists(ready) && !child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(25)) Thread.Sleep(10);
                Check(File.Exists(ready), "owned child reaches durable scan boundary");
                child.Kill(); Check(child.WaitForExit(10000), "owned child terminated");
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(10000); } }
        }
        Resume(source, root, Cursor(root), 3);
    }
    static void FailedParentSave()
    {
        string source = Image("parent-failure", false), root = source + ".job";
        string parent = Path.Combine(root, RecoverySession.FileName);
        bool failed = false;
        try
        {
            RecoveryPipeline.Run(source, root, Options(), CancellationToken.None, message =>
                { if (Percent(message) >= 20) File.SetAttributes(parent, FileAttributes.ReadOnly); }, source + ".sha256");
        }
        catch (UnauthorizedAccessException) { failed = true; }
        catch (IOException) { failed = true; }
        finally { if (File.Exists(parent)) File.SetAttributes(parent, FileAttributes.Normal); }
        Check(failed, "denied parent state write interrupts the real scan");
        long position = Cursor(root);
        Check(position == 8 * 1024 * 1024, "unacknowledged generation cannot advance the saved cursor");
        Resume(source, root, position, 3);
    }
    public static int Main(string[] args)
    {
        if (args.Length == 5 && args[0] == "child")
        {
            Select(args[1]);
            RecoveryPipeline.Run(args[2], args[3], Options(), CancellationToken.None, message =>
                { if (Percent(message) >= 20) { File.WriteAllText(args[4], "ready"); Thread.Sleep(Timeout.Infinite); } }, args[2] + ".sha256");
            return 3;
        }
        try
        {
            work = Path.Combine(Path.GetFullPath(args[0]), ".build", "range-checkpoints-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(work);
            foreach (string key in args.Length > 1 ? new[] { args[1] } : new[] { "photos", "containers", "user-signatures", "user-signatures-footer" })
            {
                Select(key); Cancellation(false);
                if (args.Length > 2) continue;
                Cancellation(true); PublicationFailure(); FailedParentSave();
                foreach (string kind in new[] { "source", "output", "unknown", method == "user-signatures" ? "checkpoint" : "ledger" }) Rejected(kind);
                KilledProcess();
            }
            Console.WriteLine("PASS RangeCarverCheckpoint: " + checks + " checks; exact originals, split signatures, cancel/kill/cursor, write-ahead repair, multi-page ledgers and tamper; no GUI/devices");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
