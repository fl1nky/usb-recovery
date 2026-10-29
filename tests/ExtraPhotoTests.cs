using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using UsbRecovery;

public static class ExtraPhotoTests
{
    static string Hash(string file) { using (var s = File.OpenRead(file)) using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(s)); }
    static void Assert(bool value, string why) { if (!value) throw new Exception(why); }
    static byte[] MakeImage(ImageFormat format)
    {
        using (var bitmap = new Bitmap(140, 90)) using (var stream = new MemoryStream())
        {
            for (int y = 0; y < bitmap.Height; y++) for (int x = 0; x < bitmap.Width; x++) bitmap.SetPixel(x, y, Color.FromArgb((x * 3 + y) % 256, (y * 5 + x) % 256, (x * 7 + y * 13) % 256));
            bitmap.Save(stream, format); return stream.ToArray();
        }
    }
    public static int Main()
    {
        try
        {
            string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "extra-photo-tests-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff")); Directory.CreateDirectory(root);
            byte[] jpg = MakeImage(ImageFormat.Jpeg), png = MakeImage(ImageFormat.Png), raw = new byte[8 * 1024 * 1024];
            int jpegOffset = 131089, pngOffset = 4 * 1024 * 1024 + 4;
            Buffer.BlockCopy(jpg, 0, raw, jpegOffset, jpg.Length); Buffer.BlockCopy(png, 0, raw, pngOffset, png.Length);
            Buffer.BlockCopy(jpg, 0, raw, 7 * 1024 * 1024 + 7, jpg.Length - 2); // missing EOI
            byte[] corrupt = (byte[])png.Clone(); corrupt[35] ^= 1; Buffer.BlockCopy(corrupt, 0, raw, 6 * 1024 * 1024 + 9, corrupt.Length);
            string image = Path.Combine(root, "Фото внутри данных.dd"); File.WriteAllBytes(image, raw);
            string before = Hash(image), output = Path.Combine(root, "Усиленный поиск"); Directory.CreateDirectory(output);
            int count;
            using (var guard = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read)) count = ExtraPhotoSearch.Recover(image, output, CancellationToken.None, (done, total) => { });
            Assert(count == 2, "Expected exactly two structurally complete photo streams, got " + count);
            byte[] savedJpeg = File.ReadAllBytes(Path.Combine(output, "extra-photos", "offset-" + jpegOffset.ToString("D16") + ".jpg"));
            byte[] savedPng = File.ReadAllBytes(Path.Combine(output, "extra-photos", "offset-" + pngOffset.ToString("D16") + ".png"));
            Assert(jpg.SequenceEqual(savedJpeg), "Unaligned JPEG not byte-identical"); Assert(png.SequenceEqual(savedPng), "Boundary-crossing PNG not byte-identical");
            Assert(before == Hash(image), "Source changed");
            var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            try { ExtraPhotoSearch.Recover(image, output, cancelled.Token, (a, b) => { }); throw new Exception("Pre-cancel ignored"); } catch (OperationCanceledException) { }
            var midway = new CancellationTokenSource(); string partial = Path.Combine(root, "Остановка"); Directory.CreateDirectory(partial);
            try { ExtraPhotoSearch.Recover(image, partial, midway.Token, (a, b) => midway.Cancel()); throw new Exception("Midway cancel ignored"); } catch (OperationCanceledException) { }

            string tool = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "tools", "testdisk-7.2", "photorec_win.exe"));
            string baseline = Path.Combine(root, "До улучшения"); Directory.CreateDirectory(baseline);
            string arguments = "/log /logname \"" + Path.Combine(baseline, "photorec.log") + "\" /d \"" + Path.Combine(baseline, "files") + "\" /cmd \"" + image + "\" partition_none,fileopt,everything,enable,wholespace,search";
            var info = new ProcessStartInfo(tool, arguments) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = baseline, RedirectStandardOutput = true, RedirectStandardError = true };
            info.EnvironmentVariables["__COMPAT_LAYER"] = "RunAsInvoker"; info.EnvironmentVariables["CYGWIN"] = "noglob"; info.EnvironmentVariables["LANG"] = "C.UTF-8"; info.EnvironmentVariables["LC_ALL"] = "C.UTF-8";
            using (var process = Process.Start(info))
            {
                var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(30000)) { process.Kill(); throw new Exception("Baseline timeout"); }
                Assert(process.ExitCode == 0, "Baseline failed: " + stderr.Result); File.WriteAllText(Path.Combine(baseline, "stdout.log"), stdout.Result, Encoding.UTF8);
            }
            int baselineExact = Directory.GetFiles(baseline, "*", SearchOption.AllDirectories).Where(p => Path.GetExtension(p) == ".jpg" || Path.GetExtension(p) == ".png").Count(p => { byte[] bytes = File.ReadAllBytes(p); return bytes.SequenceEqual(jpg) || bytes.SequenceEqual(png); });
            Assert(baselineExact == 0, "Fixture is not an improvement over baseline");
            Assert(before == Hash(image), "Source changed after baseline");
            string summary = "PASS: unaligned JPEG and boundary-crossing PNG exact; corrupted PNG and truncated JPEG rejected; pre/mid cancellation; image unchanged. Baseline exact photos=0, extra search=2. Fixture=" + image;
            File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ExtraPhotoTests.result.txt"), summary, Encoding.UTF8); Console.WriteLine(summary); return 0;
        }
        catch (Exception e) { Console.WriteLine(e); return 1; }
    }
}
