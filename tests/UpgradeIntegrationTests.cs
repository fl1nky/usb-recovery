using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using UsbRecovery;

public static class UpgradeIntegrationTests
{
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static void IgnoreProgress(long done, long total) { }
    static IEnumerable<Control> Controls(Control parent)
    {
        foreach (Control control in parent.Controls) { yield return control; foreach (Control child in Controls(control)) yield return child; }
    }
    static void Render(string evidence)
    {
        using (var form = new RecoveryForm())
        {
            // These operations lay out and print an unshown form. No Shown event or drive enumeration.
            form.ShowInTaskbar = false;
            form.CreateControl(); form.PerformLayout();
            foreach (Control child in Controls(form)) { child.CreateControl(); child.PerformLayout(); }
            form.PerformLayout();
            using (var bitmap = new Bitmap(form.Width, form.Height))
            {
                form.DrawToBitmap(bitmap, new Rectangle(0, 0, bitmap.Width, bitmap.Height));
                // WinForms skips hidden descendants when printing their parent. Print each leaf
                // independently at its actual layout coordinates; this is a composed preview,
                // not evidence that a visible native window was opened or operated.
                int border = (form.Width - form.ClientSize.Width) / 2;
                int caption = form.Height - form.ClientSize.Height - border;
                using (Graphics graphics = Graphics.FromImage(bitmap))
                foreach (Control leaf in Controls(form).Where(c => c.Controls.Count == 0 && c.Width > 0 && c.Height > 0))
                {
                    int x = border, y = caption;
                    for (Control node = leaf; node != form; node = node.Parent) { x += node.Left; y += node.Top; }
                    using (var tile = new Bitmap(leaf.Width, leaf.Height)) { leaf.DrawToBitmap(tile, new Rectangle(0, 0, tile.Width, tile.Height)); graphics.DrawImageUnscaled(tile, x, y); }
                }
                bitmap.Save(Path.Combine(evidence, "UpgradeIntegration-ui.png"), ImageFormat.Png);
            }
            var report = new StringBuilder();
            var buttons = Controls(form).OfType<Button>().ToArray();
            Assert(buttons.Length == 7, "Unexpected buttons count");
            foreach (var button in buttons)
            {
                Size text = TextRenderer.MeasureText(button.Text, button.Font);
                report.AppendLine(button.Text + ": bounds=" + button.Bounds + "; text=" + text + "; fits=" + (text.Width + 8 <= button.Width && text.Height + 6 <= button.Height));
                Assert(button.Width >= text.Width + 8 && button.Height >= text.Height + 6, "Button text may clip: " + button.Text);
            }
            CheckBox search = Controls(form).OfType<CheckBox>().Single();
            Assert(search.Checked && search.Bounds.Width <= search.Parent.ClientSize.Width, "Deep-search checkbox unavailable or clips parent");
            report.AppendLine("Checkbox: " + search.Bounds + "; text=" + search.Text + "; enabled-by-default=" + search.Checked);
            Assert(Controls(form).OfType<ComboBox>().Single().Items.Count == 0, "Unexpected drive enumeration occurred");
            Assert(!form.Visible, "Form was shown during render test");
            File.WriteAllText(Path.Combine(evidence, "UpgradeIntegration-ui-layout.txt"), report.ToString(), new UTF8Encoding(false));
            Console.WriteLine("PASS composed unshown-control render; seven button texts fit; deep-search checkbox checked; disk list remains empty. No visible native window interaction tested.");
        }
    }
    [STAThread]
    public static int Main(string[] args)
    {
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        string app = AppDomain.CurrentDomain.BaseDirectory;
        string project = args.Length > 0 ? Path.GetFullPath(args[0]) : app;
        string testBase = Path.Combine(project, "tests");
        string evidence = Path.Combine(testBase, "UpgradeIntegration-data-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff"));
        Directory.CreateDirectory(evidence);
        string priorLayer = Environment.GetEnvironmentVariable("__COMPAT_LAYER");
        var clock = Stopwatch.StartNew();
        using (var cancel = new CancellationTokenSource(60000))
        {
            try
            {
                string fixtureRoot = Path.Combine(testBase, "extra-photo-tests-20261012-095218-483");
                string fixture = Path.Combine(fixtureRoot, "Фото внутри данных.dd");
                string before = RecoveryCore.HashFile(fixture, cancel.Token, IgnoreProgress);
                string image = Path.Combine(evidence, "Полная синтетическая копия.dd");
                File.Copy(fixture, image);
                File.WriteAllText(image + ".sha256", before + "  " + Path.GetFileName(image) + "\r\n", new UTF8Encoding(false));
                string output = Path.Combine(evidence, "Результаты"); Directory.CreateDirectory(output);
                Environment.SetEnvironmentVariable("__COMPAT_LAYER", "RunAsInvoker");
                var messages = new List<string>();
                ScanResult result = RecoveryPipeline.Run(image, output, true, cancel.Token, delegate(string message) { messages.Add(message); Console.WriteLine(message); });
                string[] files = RecoveryCore.RecoveredFiles(output).ToArray();
                Assert(result.Candidates == files.Length, "Pipeline candidate count differs from actual output files");
                Assert(!result.HasWarnings, "Unexpected warnings in complete synthetic pipeline");
                var serializer = new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue };
                var stages = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(output, "scan-stages.json")));
                Assert((string)stages["status"] == "finished" && Convert.ToBoolean(stages["deep"]), "Pipeline completion not recorded");
                Assert(((IEnumerable)stages["stages"]).Cast<object>().Count() == 4, "Not all recovery stages ran");
                var catalog = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(output, "photo-catalog.json")));
                var photos = ((IEnumerable)catalog["items"]).Cast<Dictionary<string, object>>().ToList();
                string expectedRoot = Path.Combine(fixtureRoot, "Усиленный поиск", "extra-photos");
                foreach (string expected in Directory.EnumerateFiles(expectedRoot))
                {
                    string hash = RecoveryCore.HashFile(expected, cancel.Token, IgnoreProgress);
                    var found = photos.Single(i => (string)i["Sha256"] == hash);
                    Assert((string)found["Status"] == "decoded" && Convert.ToInt32(found["Width"]) == 140 && Convert.ToInt32(found["Height"]) == 90, "Known image missing or not decoded correctly: " + expected);
                    string thumbnail = Path.Combine(output, ((string)found["Thumbnail"]).Replace('/', Path.DirectorySeparatorChar));
                    Assert(File.Exists(thumbnail), "Known image thumbnail missing");
                    Assert(files.Any(p => RecoveryCore.HashFile(p, cancel.Token, IgnoreProgress) == hash), "Known image not byte-identical in output");
                }
                Assert(File.Exists(result.Gallery), "Gallery missing");
                Assert(before == RecoveryCore.HashFile(fixture, cancel.Token, IgnoreProgress), "Original source image modified");
                Assert(before == RecoveryCore.HashFile(image, cancel.Token, IgnoreProgress), "Scanned copy modified");
                Assert(files.All(p => p.StartsWith(output + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && Path.GetFullPath(p) != image), "Recovered output overlaps image");
                Assert(messages.Any(m => m.Contains("Дополнительный поиск")) && messages.Any(m => m.Contains("Галерея готова")), "Missing pipeline progress");
                Console.WriteLine("PASS whole upgraded deep pipeline; candidates=" + result.Candidates + "; decoded=" + catalog["decoded"] + "; unique=" + catalog["unique"] + "; JPEG+PNG exact; source and copy SHA256 unchanged.");
                Render(evidence);
                string summary = "PASS whole upgraded deep pipeline and unshown form render. candidates=" + result.Candidates + "; decoded=" + catalog["decoded"] + "; unique=" + catalog["unique"] + "; elapsed=" + clock.Elapsed.TotalSeconds.ToString("0.00") + "s; evidence=" + evidence + "; app=" + app;
                File.WriteAllText(Path.Combine(testBase, "UpgradeIntegrationTests.result.txt"), summary, new UTF8Encoding(false));
                Console.WriteLine(summary); return 0;
            }
            catch (Exception ex)
            {
                string summary = "FAIL " + ex + "\r\nEvidence=" + evidence;
                File.WriteAllText(Path.Combine(testBase, "UpgradeIntegrationTests.result.txt"), summary, new UTF8Encoding(false)); Console.WriteLine(summary); return 1;
            }
            finally { Environment.SetEnvironmentVariable("__COMPAT_LAYER", priorLayer); }
        }
    }
}
