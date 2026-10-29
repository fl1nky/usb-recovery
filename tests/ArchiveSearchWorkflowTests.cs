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
using System.Windows.Forms;
using UsbRecovery;

public static class ArchiveSearchWorkflowTests
{
    static int assertions;
    static void Check(bool value, string description) { if (!value) throw new Exception(description); assertions++; Console.WriteLine("PASS " + description); }
    static T Field<T>(object item, string name) { return (T)item.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(item); }
    static void WaitIdle(ArchiveSearchPanel panel) { var clock = Stopwatch.StartNew(); while (panel.IsBusy && clock.ElapsedMilliseconds < 15000) { Application.DoEvents(); Thread.Sleep(20); } Application.DoEvents(); Check(!panel.IsBusy, "native search finishes without blocking UI"); }
    [STAThread] public static int Main(string[] args)
    {
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException); Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        string root = Path.GetFullPath(args[0]), data = Path.Combine(root, "tests", "ArchiveSearch-workflow-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff")); Directory.CreateDirectory(data);
        string archive = Path.Combine(data, "Семейный архив"); Directory.CreateDirectory(archive);
        var json = new JavaScriptSerializer(); var lines = new List<string>();
        for (int i = 0; i < 240; i++) lines.Add(json.Serialize(new { app = new[] { "Telegram", "WhatsApp", "Signal" }[i % 3], snapshot_id = "synthetic", chat_id = 42, chat_name = "Семья", sender_id = "user900", sender_name = "Прабабушка", message_id = i, timestamp = "2026-10-11T12:30:00Z", timestamp_raw = (string)null, evidence_kind = "export", source_file = "fixture:/family-export.json", source_record = "message:" + i, text = "Тестовая переписка " + i + ". Секрет: ПИРОЖКИ, семейный рецепт.\nВторая строка 🥧", attachments = new string[0] }));
        string records = Path.Combine(archive, "messages.jsonl"); File.WriteAllLines(records, lines, new UTF8Encoding(false)); string before = RecoveryCore.HashFile(records, CancellationToken.None, (a,b) => { });
        try {
            var found = ArchiveSearchService.Search(archive, "Telegram", "пирожки РЕЦЕПТ", "", 0, CancellationToken.None);
            Check(found.status == "complete" && found.total == 80 && found.records.Count == 80 && found.records.All(m => m.app == "Telegram"), "packaged Unicode keyword search filters Telegram");
            var page = ArchiveSearchService.Search(archive, "", "пирожки", "", 100, CancellationToken.None);
            Check(page.total == 240 && page.records.Count == 100 && Convert.ToString(page.records[0].message_id) == "100", "pagination preserves record IDs");
            using (var window = new RecoveryHub(false)) {
                window.ShowInTaskbar = false; window.StartPosition = FormStartPosition.Manual; window.Location = new Point(-20000, -20000); window.Show(); Application.DoEvents();
                window.Navigate("Telegram"); var panel = Field<ArchiveSearchPanel>(window, "archive"); var query = Field<TextBox>(panel, "query"); query.Text = "пирожки рецепт"; panel.SelectArchive(archive); WaitIdle(panel);
                var grid = Field<DataGridView>(panel, "grid"); Check(grid.Rows.Count == 80 && Field<TextBox>(panel, "body").Text.Contains("Вторая строка 🥧"), "native grid and full multiline message shown");
                using (var bitmap = new Bitmap(window.Width, window.Height)) { window.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size)); bitmap.Save(Path.Combine(root, "tests", "minimal-ui-search.png"), ImageFormat.Png); }
                Console.WriteLine("Navigating WhatsApp…"); window.Navigate("WhatsApp"); Console.WriteLine("Waiting WhatsApp…"); WaitIdle(panel); Check(grid.Rows.Count == 80 && grid.Rows.Cast<DataGridViewRow>().All(r => Convert.ToString(r.Cells[0].Value) == "WhatsApp"), "WhatsApp sidebar button updates results");
                window.Navigate("Signal"); WaitIdle(panel); Check(grid.Rows.Count == 80 && grid.Rows.Cast<DataGridViewRow>().All(r => Convert.ToString(r.Cells[0].Value) == "Signal"), "Signal sidebar button updates results");
                query.Text = "неттакогословавархиве"; Field<Button>(panel, "search").PerformClick(); WaitIdle(panel); Check(grid.Rows.Count == 0 && Field<TextBox>(panel, "body").Text.Length == 0, "empty search clears old messages");
                window.Navigate("files"); var logical = Field<LogicalRecoveryPanel>(window, "logical"); Field<TabControl>(logical, "results").SelectedIndex = 1;
                var analysis = logical.GetType().GetField("analysisDirectory", BindingFlags.Instance | BindingFlags.NonPublic); analysis.SetValue(logical, archive);
                var chats = Field<Button>(logical, "chats"); chats.Enabled = true; chats.PerformClick(); WaitIdle(panel); Check(panel.Visible, "import result button opens native archive search");
                window.Close();
            }
            Check(RecoveryCore.HashFile(records, CancellationToken.None, (a,b) => { }) == before && !File.Exists(Path.Combine(archive, "chat-index.sqlite")), "search leaves source archive unchanged");
            Console.WriteLine("PASS archive search workflow: " + assertions + " assertions; " + data); return 0;
        } catch (Exception ex) { Console.WriteLine("FAIL " + ex.ToString()); return 1; }
    }
}
