using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using UsbRecovery;

class ArchiveSearchNativeTests
{
    static int count;
    static void Assert(bool value, string label) { if (!value) throw new Exception(label); count++; }
    static void Rejected(string archive, string relative, string label) { try { ArchiveSearchService.VerifiedAttachment(archive, relative); throw new Exception(label); } catch (IOException) { count++; } }
    [STAThread] static void Main()
    {
        string root = Path.Combine(Path.GetTempPath(), "archive-search-native-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "media"));
        try {
            byte[] data = Encoding.UTF8.GetBytes("Synthetic verified attachment"); string hash;
            using (var sha = SHA256.Create()) hash = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
            string relative = "media/" + hash + ".jpg", path = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)); File.WriteAllBytes(path, data);
            Assert(ArchiveSearchService.VerifiedAttachment(root, relative) == path, "verified attachment path");
            Rejected(root, "https://example.test/photo.jpg", "remote source"); Rejected(root, "../media/" + hash + ".jpg", "traversal");
            Rejected(root, "media/" + hash + ".exe", "executable attachment"); Rejected(root, "media/" + hash + ".html", "HTML source execution");
            Rejected(root, "media/" + new String('0', 64) + ".jpg", "missing attachment");
            File.AppendAllText(path, "changed"); Rejected(root, relative, "changed attachment hash");
            var parsed = new JavaScriptSerializer().Deserialize<ArchiveSearchResult>("{\"status\":\"complete\",\"code\":\"OK\",\"total\":1,\"records\":[{\"app\":\"Telegram\",\"text\":\"Unicode рецепт\",\"timestamp\":null,\"sender_id\":42,\"date_ambiguous\":null,\"timezone_unknown\":null,\"attachments\":[]}]}");
            Assert(parsed.records[0].text == "Unicode рецепт" && parsed.records[0].timestamp == null, "protocol Unicode and unknown values");
            Assert(Convert.ToString(parsed.records[0].sender_id) == "42", "numeric IDs remain available");
            using (var panel = new ArchiveSearchPanel()) {
                panel.SetApplication("Telegram"); Assert(!panel.IsBusy, "panel initially idle"); panel.SetApplication("Signal"); panel.SelectArchive(null); Assert(!panel.IsBusy, "empty archive does not trigger helper");
                int imports = 0; panel.ImportRequested += delegate { imports++; }; FindButton(panel, "Импортировать экспорт / копию").PerformClick(); Assert(imports == 1, "import navigation event");
            }
            Console.WriteLine("PASS " + count + " native archive-search assertions");
        }
        finally { foreach (string file in Directory.GetFiles(Path.Combine(root, "media"))) File.Delete(file); Directory.Delete(Path.Combine(root, "media")); Directory.Delete(root); }
    }
    static Button FindButton(Control parent, string label) { foreach (Control child in parent.Controls) { var b = child as Button; if (b != null && b.Text == label) return b; var nested = FindButton(child, label); if (nested != null) return nested; } return null; }
}
