using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class RecoveryHub : Form
    {
        RecoveryForm disks;
        readonly LogicalRecoveryPanel logical = new LogicalRecoveryPanel();
        readonly ArchiveSearchPanel archive = new ArchiveSearchPanel();
        readonly StorageRecoveryPanel storage=new StorageRecoveryPanel();
        readonly Panel workspace = new Panel();
        readonly Dictionary<string, Button> navigation = new Dictionary<string, Button>();
        readonly bool automaticDiscovery;
        CancellationTokenSource telegramAnalysis;
        readonly CheckBox motionToggle=new CheckBox();
        readonly Button langToggle=new Button();
        Label subtitleLabel;
        Label footerLabel;
        Label sectionRecoveryLabel;
        Label sectionChatsLabel;
        Label sectionSourcesLabel;

        public RecoveryHub() : this(true) { }
        public RecoveryHub(bool automaticDiscovery)
        {
            this.automaticDiscovery = automaticDiscovery; logical.AutoDiscovery = automaticDiscovery;
            Text = Localization.T("AppTitle");
            Font = new Font("Segoe UI", 10F); ClientSize = new Size(1280, 920);
            MinimumSize = new Size(1060, 760); StartPosition = FormStartPosition.CenterScreen;
            var frame = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty, Padding = Padding.Empty };
            frame.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 228)); frame.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); frame.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var sidebar = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Sidebar, Tag="sidebar", Padding = new Padding(18, 28, 18, 20), Margin = Padding.Empty };
            var links = new FlowLayoutPanel { Dock = DockStyle.Fill,Tag="sidebar", FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };
            links.Controls.Add(new Label { Text = "Recovery",Tag="on-dark", Font = new Font("Segoe UI", 21F, FontStyle.Bold), AutoSize = true, Margin = new Padding(8, 0, 0, 5) });
            subtitleLabel = new Label { Text = Localization.T("RecoverySubtitle"), Tag = "muted-dark", Font=new Font("Segoe UI",8F), AutoSize = true, Margin = new Padding(9, 0, 0, 32) };
            links.Controls.Add(subtitleLabel);

            sectionRecoveryLabel = Section(links, Localization.T("SectionRecovery"));
            Link(links, "usb", Localization.T("NavUsb"));
            Link(links,"storage", Localization.T("NavStorage"));

            sectionChatsLabel = Section(links, Localization.T("SectionChats"));
            Link(links, "Telegram", Localization.T("NavTelegram"));

            sectionSourcesLabel = Section(links, Localization.T("SectionSources"));
            Link(links, "Android", Localization.T("NavAndroid"));
            Link(links, "iPhone", Localization.T("NavIphone"));
            Link(links, "files", Localization.T("NavFiles"));

            sidebar.Controls.Add(links);
            footerLabel = new Label { Text = Localization.T("FooterPrivacy"), Dock = DockStyle.Bottom, Height = 48, Tag = "muted-dark", Font = new Font("Segoe UI", 9F) };
            sidebar.Controls.Add(footerLabel);

            langToggle.Text = Localization.T("LanguageToggle");
            langToggle.Name = "lang-toggle";
            langToggle.FlatStyle = FlatStyle.Flat;
            langToggle.FlatAppearance.BorderSize = 0;
            langToggle.Font = new Font("Segoe UI", 8.5F);
            langToggle.Dock = DockStyle.Bottom;
            langToggle.Height = 32;
            langToggle.Tag = "muted-dark";
            langToggle.Click += delegate { Localization.ToggleLanguage(); };
            sidebar.Controls.Add(langToggle);
            sidebar.Controls.SetChildIndex(langToggle, 1);

            motionToggle.Text=Localization.T("MotionToggle");
            motionToggle.Name="motion-toggle";
            motionToggle.Checked=MotionSettings.Enabled;
            motionToggle.Dock=DockStyle.Bottom;
            motionToggle.Height=34;
            motionToggle.Tag="muted-dark";
            motionToggle.CheckedChanged+=delegate{MotionSettings.Enabled=motionToggle.Checked;};
            sidebar.Controls.Add(motionToggle);
            sidebar.Controls.SetChildIndex(motionToggle,2);

            workspace.Dock = DockStyle.Fill; workspace.Margin = Padding.Empty;
            frame.Controls.Add(sidebar, 0, 0); frame.Controls.Add(workspace, 1, 0); Controls.Add(frame);
            archive.Dock = logical.Dock = DockStyle.Fill; workspace.Controls.Add(logical); workspace.Controls.Add(archive);workspace.Controls.Add(storage);storage.Visible=false; logical.Visible = false;
            archive.AnalyzeRequested += delegate { AnalyzeTelegram(); };
            archive.AnalysisCancelRequested += delegate { if (telegramAnalysis != null) telegramAnalysis.Cancel(); };
            logical.ArchiveCreated += path => {
                if (archive.IsBusy) { MessageBox.Show(this, "Дождись завершения текущего поиска."); return; }
                archive.SelectArchive(path);storage.Visible=false; logical.Visible = false; if (disks != null) disks.Visible = false; archive.Visible = true; archive.BringToFront(); Highlight("Telegram"); archive.FocusQuery();
            };

            Action refresh = RefreshLocalization;
            Localization.LanguageChanged += refresh;
            Disposed += delegate { Localization.LanguageChanged -= refresh; };

            UiTheme.ApplyTree(this); Highlight("Telegram");
            Shown+=delegate{Navigate("usb");};
            FormClosing += delegate(object sender, FormClosingEventArgs e) {
                if (storage.IsBusy || logical.IsBusy || archive.IsBusy || (disks != null && disks.IsBusy)) { e.Cancel = true; MessageBox.Show(this, "Заверши или останови текущую операцию.", "Идёт обработка"); }
            };
        }

        void RefreshLocalization()
        {
            Text = Localization.T("AppTitle");
            if (subtitleLabel != null) subtitleLabel.Text = Localization.T("RecoverySubtitle");
            if (footerLabel != null) footerLabel.Text = Localization.T("FooterPrivacy");
            if (langToggle != null) langToggle.Text = Localization.T("LanguageToggle");
            if (motionToggle != null) motionToggle.Text = Localization.T("MotionToggle");
            if (sectionRecoveryLabel != null) sectionRecoveryLabel.Text = Localization.T("SectionRecovery");
            if (sectionChatsLabel != null) sectionChatsLabel.Text = Localization.T("SectionChats");
            if (sectionSourcesLabel != null) sectionSourcesLabel.Text = Localization.T("SectionSources");

            Button btn;
            if (navigation.TryGetValue("usb", out btn)) btn.Text = Localization.T("NavUsb");
            if (navigation.TryGetValue("storage", out btn)) btn.Text = Localization.T("NavStorage");
            if (navigation.TryGetValue("Telegram", out btn)) btn.Text = Localization.T("NavTelegram");
            if (navigation.TryGetValue("Android", out btn)) btn.Text = Localization.T("NavAndroid");
            if (navigation.TryGetValue("iPhone", out btn)) btn.Text = Localization.T("NavIphone");
            if (navigation.TryGetValue("files", out btn)) btn.Text = Localization.T("NavFiles");
        }

        Label Section(FlowLayoutPanel parent, string text) {
            var lbl = new Label { Text = text, AutoSize = true, Font = new Font("Segoe UI", 8F), Tag = "muted-dark", Margin = new Padding(9, 22, 0, 9) };
            parent.Controls.Add(lbl);
            return lbl;
        }
        void Link(FlowLayoutPanel parent, string key, string text) {
            var button = new NavigationButton { Text = text,Glyph=key=="usb"||key=="storage"?"USB":key=="Telegram"?"TG":key=="Android"?"A":key=="iPhone"?"iOS":"DIR", Width = 190, Height = 46, TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(0, 2, 0, 2), Tag = "nav", Name = "nav-" + key };
            if(key=="storage")button.Font=new Font("Segoe UI",9F);button.Click += delegate { Navigate(key); }; parent.Controls.Add(button); navigation.Add(key, button);
        }
        void Highlight(string key) {
            foreach (var item in navigation) {var button=item.Value as NavigationButton;if(button!=null){button.Selected=item.Key==key;button.Invalidate();}}
        }
        public void Navigate(string key)
        {
            if (!navigation.ContainsKey(key)) throw new ArgumentException("Unknown section");
            bool source = key == "Android" || key == "iPhone" || key == "files";
            if ((source && logical.IsBusy) || (!source && key != "usb" && archive.IsBusy)) return;
            if (source) logical.SetMode(key);
            if (key == "usb" && disks == null) { disks = new RecoveryForm(false) { TopLevel = false, FormBorderStyle = FormBorderStyle.None, MinimumSize = Size.Empty, Dock = DockStyle.Fill }; workspace.Controls.Add(disks); UiTheme.ApplyTree(disks); }
            storage.Visible=key=="storage";logical.Visible = source; archive.Visible = !source && key != "usb"&&key!="storage"; if (disks != null) disks.Visible = key == "usb";
            if(key=="storage")storage.BringToFront();else if (source) { logical.BringToFront(); if (automaticDiscovery && IsHandleCreated && Visible) logical.Discover(); }
            else if (key == "usb") { disks.Show(); disks.BringToFront(); if (automaticDiscovery && IsHandleCreated && Visible) disks.RefreshSources(); }
            else { archive.SetApplication("Telegram"); archive.BringToFront(); archive.FocusQuery(); }
            Highlight(key);
        }
        async void AnalyzeTelegram()
        {
            if (archive.IsBusy || telegramAnalysis != null) return;
            telegramAnalysis = new CancellationTokenSource(); var token = telegramAnalysis.Token;
            string selectedSource = archive.AnalysisSource, fragmentQuery = archive.FragmentQuery; bool useRegex = archive.UseRegex;
            var secrets=archive.TakeDesktopSecrets();
            archive.SetAnalysisBusy(true, "Проверка локальных папок Telegram…");
            try {
                string output = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Recovery-Results", "Telegram-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                var result = await Task.Run(() => TelegramAnalysisService.AnalyzeSelected(output, selectedSource, fragmentQuery, useRegex, secrets, token, message => PostAnalysis(message)));
                if (result.Status == "error") archive.ShowAnalysisError(result.Code == "REGEX_INVALID" ? "Ошибка в регулярном выражении. Исправь запрос или выключи Regex." : result.Code == "REGEX_TIMEOUT" ? "Регулярное выражение слишком сложное. Сократи его или выключи Regex." : "Анализ не завершён. " + TelegramAnalysisService.Summary(result));
                else archive.CompleteAnalysis(result.Archive, TelegramAnalysisService.Summary(result));
            } catch (OperationCanceledException) { archive.ShowAnalysisError("Анализ остановлен. Исходные файлы не изменены."); }
            catch { archive.ShowAnalysisError("Не удалось завершить анализ. Проверь место на диске и доступ к локальным папкам."); }
            finally { foreach(var key in secrets.Keys.ToArray())secrets[key]="";secrets.Clear();telegramAnalysis.Dispose(); telegramAnalysis = null; }
        }
        void PostAnalysis(string message) { if (!IsDisposed && IsHandleCreated) BeginInvoke(new Action(() => { if (telegramAnalysis != null) archive.SetAnalysisBusy(true, message); })); }
    }
}
