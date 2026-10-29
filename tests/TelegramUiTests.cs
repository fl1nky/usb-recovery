using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using UsbRecovery;

public static class TelegramUiTests
{
    static int assertions;
    static void Assert(bool value, string name) { assertions++; if (!value) throw new Exception(name); }
    static T Field<T>(object item, string name) where T : class { return (T)item.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance).GetValue(item); }
    static IEnumerable<Control> Descendants(Control root) { foreach (Control child in root.Controls) { yield return child; foreach (var item in Descendants(child)) yield return item; } }
    static void Wait(ArchiveSearchPanel panel) { var deadline = DateTime.UtcNow.AddSeconds(15); while (panel.IsBusy && DateTime.UtcNow < deadline) { Application.DoEvents(); Thread.Sleep(20); } Application.DoEvents(); Assert(!panel.IsBusy, "search completed"); }

    [STAThread] public static int Main()
    {
        try {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            using (var form = new Form { ClientSize = new Size(852, 721), ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000) })
            using (var panel = new ArchiveSearchPanel()) {
                form.Controls.Add(panel); form.Show(); Application.DoEvents();
                var analyze = Field<Button>(panel, "analyze"); var stop = Field<Button>(panel, "cancelButton"); var search = Field<Button>(panel, "search"); var query = Field<TextBox>(panel, "query"); var status = Field<TextBox>(panel, "analysisStatus"); var grid = Field<DataGridView>(panel, "grid");
                Assert(analyze.Text == "Анализировать" && analyze.Enabled, "one-click automatic entry");
                int primaries = 0; foreach (var child in Descendants(panel)) {
                    if (child is Button && Convert.ToString(child.Tag) == "primary") primaries++;
                    Assert(child.Text.IndexOf("WhatsApp", StringComparison.OrdinalIgnoreCase) < 0 && child.Text.IndexOf("Signal", StringComparison.OrdinalIgnoreCase) < 0, "Telegram-only labels");
                    var combo = child as ComboBox;
                    if (combo != null) foreach (object item in combo.Items) Assert(Convert.ToString(item).IndexOf("WhatsApp", StringComparison.OrdinalIgnoreCase) < 0 && Convert.ToString(item).IndexOf("Signal", StringComparison.OrdinalIgnoreCase) < 0, "Telegram-only choices");
                    if (child.Visible && child.Parent != null) Assert(child.Width > 0 && child.Height > 0 && child.Right <= child.Parent.ClientSize.Width + 1 && child.Bottom <= child.Parent.ClientSize.Height + 1, "minimum layout bounds: " + child.GetType().Name + " " + child.Bounds + " parent=" + child.Parent.ClientSize);
                }
                Assert(primaries == 1, "only analysis is primary");
                int analyzed = 0, cancelled = 0;
                panel.AnalyzeRequested += delegate { analyzed++; panel.SetAnalysisBusy(true, "Поиск локальных тестовых источников…"); };
                panel.AnalysisCancelRequested += delegate { cancelled++; };
                analyze.PerformClick(); Assert(analyzed == 1 && panel.IsBusy, "analyze starts without archive selection");
                analyze.PerformClick(); Assert(analyzed == 1 && !search.Enabled && !query.Enabled, "no concurrent analysis or search");
                stop.PerformClick(); Assert(cancelled == 1, "stop cancels analysis");
                panel.CompleteAnalysis("", "Найден служебный каталог tdata. Доступных сообщений нет.");
                Assert(!panel.IsBusy && grid.Rows.Count == 0 && status.Text.Contains("tdata"), "empty result retains diagnosis");
                analyze.PerformClick(); panel.ShowAnalysisError("Анализ остановлен. Исходные файлы не изменены.");
                Assert(!panel.IsBusy && analyze.Enabled && status.Text.Contains("остановлен"), "cancellation returns to ready state");
                string archive = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "synthetic-archive"); Directory.CreateDirectory(archive);
                query.Text = "рецепт"; panel.SetApplication("WhatsApp");
                panel.CompleteAnalysis(archive, "Доступный экспорт: 1. Защищённый tdata: 1. История из tdata не извлекается."); Wait(panel);
                Assert(grid.Rows.Count == 1 && Field<TextBox>(panel, "body").Text.Contains("пирожков"), "actual native helper response displayed");
                Assert(Convert.ToString(grid.Rows[0].Cells["date"].Value) == "13.10.2026 10:00", "canonical date readable without changing offset");
                Assert(status.Text.Contains("tdata") && status.Text.Contains("не извлекается"), "warnings survive keyword results");
                Assert(Field<TextBox>(panel, "provenance").Text.Contains("synthetic-export.json"), "message provenance visible");
                using (var image = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(image, new Rectangle(Point.Empty, image.Size)); image.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "TelegramUi-preview.png"), ImageFormat.Png); }
                query.Text = "ничего"; search.PerformClick(); Wait(panel);
                Assert(grid.Rows.Count == 0 && status.Text.Contains("tdata"), "empty keyword results keep analysis warnings");
                query.Text = "уведомление"; search.PerformClick(); Wait(panel);
                Assert(grid.Rows.Count == 1 && Convert.ToString(grid.Rows[0].Cells["category"].Value) == "Уведомление", "notification is separately labeled");
                Assert(Convert.ToString(grid.Rows[0].Cells["author"].Value) == "Автор неизвестен" && Convert.ToString(grid.Rows[0].Cells["date"].Value) == "Дата неизвестна", "notification does not invent author or date");
                Assert(Field<TextBox>(panel, "provenance").Text.Contains("только часть сообщения"), "notification incompleteness visible");
                panel.SetAnalysisSource(Path.Combine(archive, "synthetic-phone.hprof")); Assert(panel.AnalysisSource.EndsWith(".hprof"), "explicit dump selection retained");
                var regex = Field<CheckBox>(panel, "regexMode"); regex.Checked = true; query.Text = "regex-protocol"; search.PerformClick(); Wait(panel); Assert(grid.Rows.Count == 1, "regex mode reaches worker stdin"); regex.Checked = false;
                query.Text = "bad-app"; search.PerformClick(); Wait(panel);
                Assert(grid.Rows.Count == 0 && String.IsNullOrEmpty(Field<TextBox>(panel, "body").Text), "wrong-application worker result rejected");
                form.Hide();
            }
            Console.WriteLine("PASS " + assertions + " UI assertions. Synthetic stdin worker fixture only; no computer-data discovery or device access."); return 0;
        } catch (Exception ex) { Console.WriteLine("FAIL " + ex.Message); return 1; }
    }
}
