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
        readonly Panel workspace = new Panel();
        readonly Dictionary<string, Button> navigation = new Dictionary<string, Button>();
        readonly bool automaticDiscovery;
        CancellationTokenSource telegramAnalysis;
        
        public RecoveryHub() : this(true) { }
        public RecoveryHub(bool automaticDiscovery)
        {
            this.automaticDiscovery = automaticDiscovery; logical.AutoDiscovery = automaticDiscovery;
            Text = "Recovery — восстановление данных";
            Font = new Font("Segoe UI", 10F); ClientSize = new Size(1280, 920);
            MinimumSize = new Size(1060, 760); StartPosition = FormStartPosition.CenterScreen;
            var frame = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty, Padding = Padding.Empty };
            frame.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 228)); frame.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); frame.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var sidebar = new Panel { Dock = DockStyle.Fill, BackColor = UiTheme.Sidebar, Tag="sidebar", Padding = new Padding(18, 28, 18, 20), Margin = Padding.Empty };
            var links = new FlowLayoutPanel { Dock = DockStyle.Fill,Tag="sidebar", FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };
            links.Controls.Add(new Label { Text = "Recovery",Tag="on-dark", Font = new Font("Segoe UI", 21F, FontStyle.Bold), AutoSize = true, Margin = new Padding(8, 0, 0, 5) });
            links.Controls.Add(new Label { Text = "ВОССТАНОВЛЕНИЕ ДАННЫХ", Tag = "muted-dark", Font=new Font("Segoe UI",8F),AutoSize = true, Margin = new Padding(9, 0, 0, 32) });
            Section(links, "ВОССТАНОВЛЕНИЕ");Link(links, "usb", "Флешки и образы");
            Section(links, "ПЕРЕПИСКИ");
            Link(links, "Telegram", "Telegram");
            Section(links, "ИСТОЧНИКИ");
            Link(links, "Android", "Android"); Link(links, "iPhone", "iPhone"); Link(links, "files", "Импорт и кэш");
            sidebar.Controls.Add(links); var footer = new Label { Text = "Локальная обработка\r\nБез подписки и облака", Dock = DockStyle.Bottom, Height = 48, Tag = "muted-dark", Font = new Font("Segoe UI", 9F) }; sidebar.Controls.Add(footer);
            workspace.Dock = DockStyle.Fill; workspace.Margin = Padding.Empty;
            frame.Controls.Add(sidebar, 0, 0); frame.Controls.Add(workspace, 1, 0); Controls.Add(frame);
            archive.Dock = logical.Dock = DockStyle.Fill; workspace.Controls.Add(logical); workspace.Controls.Add(archive); logical.Visible = false;
            archive.AnalyzeRequested += delegate { AnalyzeTelegram(); };
            archive.AnalysisCancelRequested += delegate { if (telegramAnalysis != null) telegramAnalysis.Cancel(); };
            logical.ArchiveCreated += path => {
                if (archive.IsBusy) { MessageBox.Show(this, "Дождись завершения текущего поиска."); return; }
                archive.SelectArchive(path); logical.Visible = false; if (disks != null) disks.Visible = false; archive.Visible = true; archive.BringToFront(); Highlight("Telegram"); archive.FocusQuery();
            };
            UiTheme.ApplyTree(this); Highlight("Telegram");
            Shown+=delegate{Navigate("usb");};
            FormClosing += delegate(object sender, FormClosingEventArgs e) {
                if (logical.IsBusy || archive.IsBusy || (disks != null && disks.IsBusy)) { e.Cancel = true; MessageBox.Show(this, "Заверши или останови текущую операцию.", "Идёт обработка"); }
            };
        }
        void Section(FlowLayoutPanel parent, string text) { parent.Controls.Add(new Label { Text = text, AutoSize = true, Font = new Font("Segoe UI", 8F), Tag = "muted-dark", Margin = new Padding(9, 22, 0, 9) }); }
        void Link(FlowLayoutPanel parent, string key, string text) {
            var button = new NavigationButton { Text = text,Glyph=key=="usb"?"USB":key=="Telegram"?"TG":key=="Android"?"A":key=="iPhone"?"iOS":"DIR", Width = 190, Height = 46, TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(0, 2, 0, 2), Tag = "nav", Name = "nav-" + key };
            button.Click += delegate { Navigate(key); }; parent.Controls.Add(button); navigation.Add(key, button);
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
            logical.Visible = source; archive.Visible = !source && key != "usb"; if (disks != null) disks.Visible = key == "usb";
            if (source) { logical.BringToFront(); if (automaticDiscovery && IsHandleCreated && Visible) logical.Discover(); }
            else if (key == "usb") { disks.Show(); disks.BringToFront(); if (automaticDiscovery && IsHandleCreated && Visible) disks.RefreshSources(); }
            else { archive.SetApplication("Telegram"); archive.BringToFront(); archive.FocusQuery(); }
            Highlight(key);
        }
        async void AnalyzeTelegram()
        {
            if (archive.IsBusy || telegramAnalysis != null) return;
            telegramAnalysis = new CancellationTokenSource(); var token = telegramAnalysis.Token;
            string selectedSource = archive.AnalysisSource, fragmentQuery = archive.FragmentQuery; bool useRegex = archive.UseRegex;
            archive.SetAnalysisBusy(true, "Проверка локальных папок Telegram…");
            try {
                string output = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Recovery-Results", "Telegram-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                var result = await Task.Run(() => TelegramAnalysisService.AnalyzeSelected(output, selectedSource, fragmentQuery, useRegex, token, message => PostAnalysis(message)));
                if (result.Status == "error") archive.ShowAnalysisError(result.Code == "REGEX_INVALID" ? "Ошибка в регулярном выражении. Исправь запрос или выключи Regex." : result.Code == "REGEX_TIMEOUT" ? "Регулярное выражение слишком сложное. Сократи его или выключи Regex." : "Анализ не завершён. " + TelegramAnalysisService.Summary(result));
                else archive.CompleteAnalysis(result.Archive, TelegramAnalysisService.Summary(result));
            } catch (OperationCanceledException) { archive.ShowAnalysisError("Анализ остановлен. Исходные файлы не изменены."); }
            catch { archive.ShowAnalysisError("Не удалось завершить анализ. Проверь место на диске и доступ к локальным папкам."); }
            finally { telegramAnalysis.Dispose(); telegramAnalysis = null; }
        }
        void PostAnalysis(string message) { if (!IsDisposed && IsHandleCreated) BeginInvoke(new Action(() => { if (telegramAnalysis != null) archive.SetAnalysisBusy(true, message); })); }
    }

    public sealed class LogicalRecoveryPanel : UserControl
    {
        readonly ComboBox kind = new ComboBox(), devices = new ComboBox();
        readonly TextBox sourcePath = new TextBox(), destination = new TextBox(), iosPassword = new TextBox(), journal = new TextBox(), remarks = new TextBox();
        readonly Button browse = new Button(), refresh = new Button(), folders = new Button(), chooseOutput = new Button(), start = new Button(), resume = new Button(), stop = new Button();
        readonly Button photos = new Button(), chats = new Button(), sources = new Button(), open = new Button();
        readonly TreeView tree = new TreeView();
        readonly Label help = new Label(), state = new Label();
        readonly CheckBox deep = new CheckBox();
        readonly ProgressBar progress = new ProgressBar();
        readonly TabControl results = new TabControl();
        CancellationTokenSource cancellation;
        bool busy, loading; string runDirectory, analysisDirectory, sourceReport;
        public bool IsBusy { get { return busy || loading; } }
        public bool AutoDiscovery = true;

        readonly Label heading = new Label(), introduction = new Label();
        readonly TableLayoutPanel layout = new TableLayoutPanel();
        readonly Panel keyControls = new Panel();
        readonly Button credentials = new Button();
        string mode = "files";
        sealed class ModeChoice { public int Code; public string Name; public override string ToString() { return Name; } }
        int Kind { get { var item = kind.SelectedItem as ModeChoice; return item == null ? 0 : item.Code; } }
        public event Action<string> ArchiveCreated;

        public LogicalRecoveryPanel()
        {
            Dock = DockStyle.Fill; BackColor = UiTheme.Background; AutoScroll = true;
            layout.Dock = DockStyle.Top; layout.Padding = new Padding(28, 24, 28, 24); layout.ColumnCount = 3; layout.RowCount = 13;
            Resize += delegate { FitLayout(); }; VisibleChanged += delegate { if (Visible) FitLayout(); };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 146)); layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 146));
            for (int i = 0; i < 12; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles[6] = new RowStyle(SizeType.Absolute, 0);
            Controls.Add(layout);
            heading.Font = new Font("Segoe UI", 20F, FontStyle.Bold); heading.AutoSize = true; heading.Margin = new Padding(0, 0, 0, 7); Span(layout, heading, 0);
            introduction.AutoSize = true; introduction.MaximumSize = new Size(880, 0); introduction.Tag = "muted"; introduction.Margin = new Padding(0, 0, 0, 20); Span(layout, introduction, 1);
            kind.Name = "source-kind"; kind.DropDownStyle = ComboBoxStyle.DropDownList; kind.Dock = DockStyle.Fill; kind.Margin = new Padding(0, 0, 8, 8); kind.SelectedIndexChanged += delegate { ChangeKind(); };
            layout.Controls.Add(kind, 0, 2); Button(refresh, "Обновить", delegate { Discover(); }); layout.Controls.Add(refresh, 1, 2);
            Button(credentials, "Пароль копии", delegate { ShowCredentials(!keyControls.Visible); }); layout.Controls.Add(credentials, 2, 2);
            var sourcePanel = new Panel { Dock = DockStyle.Fill, Height = 34, Margin = new Padding(0, 0, 8, 5) };
            sourcePath.Name = "source-path"; sourcePath.ReadOnly = true; sourcePath.Dock = DockStyle.Fill; sourcePath.Font = new Font("Consolas", 9.5F); sourcePanel.Controls.Add(sourcePath);
            devices.Name = "source-device"; devices.DropDownStyle = ComboBoxStyle.DropDownList; devices.Dock = DockStyle.Fill; devices.SelectedIndexChanged += delegate { ChangeDevice(); }; sourcePanel.Controls.Add(devices);
            layout.Controls.Add(sourcePanel, 0, 3); layout.SetColumnSpan(sourcePanel, 2);
            var actions = new Panel { Dock = DockStyle.Fill, Height = 36, Margin = new Padding(3, 0, 0, 5) }; Button(browse, "Выбрать", delegate { BrowseSource(); }); Button(folders, "Выбрать папки", delegate { ListFolders(); }); actions.Controls.Add(browse); actions.Controls.Add(folders); layout.Controls.Add(actions, 2, 3);
            help.AutoSize = true; help.MaximumSize = new Size(870, 0); help.Tag = "muted"; help.Margin = new Padding(0, 5, 0, 14); Span(layout, help, 4);
            tree.Dock = DockStyle.Fill; tree.Height = 110; tree.Visible = false; tree.VisibleChanged += delegate { FitLayout(); }; tree.AfterSelect += delegate { if (tree.SelectedNode != null) state.Text = "Папка: " + tree.SelectedNode.FullPath; }; Span(layout, tree, 5);
            keyControls.Dock = DockStyle.Fill; keyControls.Visible = false;
            var keys = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 3 };
            keys.RowStyles.Add(new RowStyle(SizeType.Absolute, 23)); keys.RowStyles.Add(new RowStyle(SizeType.Absolute, 31)); keys.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            keys.ColumnCount = 1; keys.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            keys.Controls.Add(new Label { Text = "Пароль локальной копии iPhone", AutoSize = true }, 0, 0);
            iosPassword.UseSystemPasswordChar = true; iosPassword.Dock = DockStyle.Fill; keys.Controls.Add(iosPassword, 0, 1);
            var keyNote = new Label { Text = "Для защищённой копии. Пароль не сохраняется.", AutoSize = true, Tag = "muted", Margin = new Padding(3, 7, 0, 0) }; keys.Controls.Add(keyNote, 0, 2); keys.SetColumnSpan(keyNote, 1); keyControls.Controls.Add(keys); Span(layout, keyControls, 6);
            Span(layout, new Label { Text = "Сохранить рабочую копию и архив", AutoSize = true, Margin = new Padding(0, 4, 0, 8) }, 7);
            destination.Text = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Recovery-Results"); destination.ReadOnly = true; destination.Dock = DockStyle.Fill; destination.Font = new Font("Consolas", 9.5F); destination.Margin = new Padding(0, 0, 8, 0); layout.Controls.Add(destination, 0, 8); layout.SetColumnSpan(destination, 2);
            Button(chooseOutput, "Выбрать папку", delegate { using (var dialog = new FolderBrowserDialog { Description = "Папка на компьютере вне источника" }) if (dialog.ShowDialog(this) == DialogResult.OK) destination.Text = dialog.SelectedPath; }); layout.Controls.Add(chooseOutput, 2, 8);
            deep.Text = "Встроенные изображения и текстовые фрагменты"; deep.Checked = true; deep.AutoSize = true; deep.Margin = new Padding(0, 13, 0, 14); Span(layout, deep, 9);
            Button(start, "Найти и создать архив", delegate { Begin(null); }); start.Tag = "primary"; start.Name = "import-start"; layout.Controls.Add(start, 0, 10);
            Button(resume, "Продолжить", delegate { using (var dialog = new FolderBrowserDialog { Description = "Папка предыдущего запуска. Вверху выбери тот же источник." }) if (dialog.ShowDialog(this) == DialogResult.OK) Begin(dialog.SelectedPath); }); layout.Controls.Add(resume, 1, 10);
            Button(stop, "Остановить", delegate { if (cancellation != null) { cancellation.Cancel(); stop.Enabled = false; state.Text = "Остановка…"; } }); stop.Enabled = false; layout.Controls.Add(stop, 2, 10);
            var statusPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0, 12, 0, 12) }; statusPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); statusPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            progress.Dock = DockStyle.Fill; progress.Height = 5; state.Text = "Выбери источник."; state.AutoSize = true; state.MaximumSize = new Size(870, 0); state.Tag = "muted"; statusPanel.Controls.Add(progress); statusPanel.Controls.Add(state); Span(layout, statusPanel, 11);
            results.Dock = DockStyle.Fill;
            AddResultPage("Фотографии", "Галерея изображений с размерами и источниками.", photos, "Открыть фотографии", delegate { OpenArtifact("Фотографии.html"); });
            AddResultPage("Переписки", "Поиск по тексту, автору и чату в готовом архиве.", chats, "Искать в переписках", delegate { if (ArchiveCreated != null && !String.IsNullOrEmpty(analysisDirectory)) ArchiveCreated(analysisDirectory); });
            var infoPage = new TabPage("Источники"); remarks.Multiline = true; remarks.ReadOnly = true; remarks.ScrollBars = ScrollBars.Vertical; remarks.Dock = DockStyle.Fill; remarks.Font = new Font("Consolas", 9F); infoPage.Controls.Add(remarks); Button(sources, "Открыть отчёт", delegate { OpenPath(sourceReport); }); sources.Dock = DockStyle.Bottom; infoPage.Controls.Add(sources); results.TabPages.Add(infoPage);
            var logPage = new TabPage("Журнал"); journal.Multiline = true; journal.ReadOnly = true; journal.ScrollBars = ScrollBars.Vertical; journal.Dock = DockStyle.Fill; journal.Font = new Font("Consolas", 9F); logPage.Controls.Add(journal); Button(open, "Открыть папку", delegate { OpenPath(runDirectory); }); open.Dock = DockStyle.Bottom; logPage.Controls.Add(open); results.TabPages.Add(logPage); Span(layout, results, 12);
            photos.Enabled = chats.Enabled = sources.Enabled = open.Enabled = false; SetMode("files"); UiTheme.ApplyTree(this); FitLayout();
        }
        void FitLayout() { if (layout.RowStyles.Count < 13) return; layout.Height = Math.Max(ClientSize.Height, 650 + (int)layout.RowStyles[6].Height + (tree.Nodes.Count > 0 ? 116 : 0)); }
        void ShowCredentials(bool value) { keyControls.Visible = value; layout.RowStyles[6].Height = value ? 100 : 0; credentials.Text = value ? "Скрыть пароль" : "Пароль копии"; FitLayout(); }
        public void SetMode(string value)
        {
            if (busy || loading) return;
            mode = value; kind.Items.Clear(); sourcePath.Clear(); devices.Items.Clear(); tree.Visible = false;
            if (mode == "Android") {
                heading.Text = "Android"; introduction.Text = "Фотографии, доступные файлы и резервные копии телефона.";
                kind.Items.Add(new ModeChoice { Code = 2, Name = "Передача файлов по USB" }); kind.Items.Add(new ModeChoice { Code = 3, Name = "USB-отладка (ADB)" });
            } else if (mode == "iPhone") {
                heading.Text = "iPhone"; introduction.Text = "Доступные фото по USB или существующая локальная копия.";
                kind.Items.Add(new ModeChoice { Code = 2, Name = "Фотографии по USB" }); kind.Items.Add(new ModeChoice { Code = 4, Name = "Локальная резервная копия" });
            } else {
                mode = "files"; heading.Text = "Импорт и кэш"; introduction.Text = "Экспорты переписок, резервные копии и фотографии из папок компьютера.";
                kind.Items.Add(new ModeChoice { Code = 0, Name = "Папка" }); kind.Items.Add(new ModeChoice { Code = 1, Name = "Файл экспорта или резервной копии" });
            }
            ShowCredentials(false); kind.SelectedIndex = 0;
        }

        static void Span(TableLayoutPanel layout, Control control, int row) { layout.Controls.Add(control, 0, row); layout.SetColumnSpan(control, 3); }
        static void Button(Button button, string label, EventHandler click) { button.Text = label; button.Dock = DockStyle.Fill; button.MinimumSize = new Size(0, 34); button.Click += click; }
        void AddResultPage(string title, string text, Button button, string label, EventHandler click) {
            var page = new TabPage(title); var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), RowCount = 2, ColumnCount = 1 }; panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            panel.Controls.Add(new Label { Text = text, AutoSize = true, MaximumSize = new Size(780, 0) }, 0, 0); Button(button, label, click); panel.Controls.Add(button, 0, 1); page.Controls.Add(panel); results.TabPages.Add(page);
        }
        void Post(Action action) { if (!IsDisposed && IsHandleCreated) BeginInvoke(action); }
        void Append(string message) { if (journal.TextLength > 128000) journal.Text = journal.Text.Substring(journal.TextLength - 64000); journal.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + message + Environment.NewLine); }
        void ChangeKind() {
            bool phone = Kind == 2 || Kind == 3; sourcePath.Visible = !phone; devices.Visible = phone; folders.Visible = folders.Enabled = phone; browse.Visible = browse.Enabled = !phone; refresh.Enabled = phone; tree.Visible = false; tree.Nodes.Clear();
            help.Text = Kind == 3 ? "Включи USB-отладку вручную и подтверди подключение на Android. Закрытые области приложений могут быть недоступны." : phone ? "Если телефон не найден, проверь разблокировку, USB-режим и доверие компьютеру. Доступность папок зависит от телефона." : "Выбери доступную папку, существующий экспорт или резервную копию. Программа сначала скопирует источник.";
            if (phone && AutoDiscovery && IsHandleCreated && Visible) Discover();
        }
        void ChangeDevice() { tree.Visible = false; tree.Nodes.Clear(); var device = devices.SelectedItem as SourceInfo; if (device != null) help.Text = device.Name + " · " + device.Status + ". Открой список доступных папок или скопируй все доступные файлы."; }
        public async void Discover() {
            if (busy || loading || (Kind != 2 && Kind != 3)) return; loading = true; refresh.Enabled = start.Enabled = false;
            int selectedKind = Kind;
            try { var list = await Task.Run(() => selectedKind == 2 ? SourceDiscovery.ListWpdDevices() : SourceDiscovery.ListAdbDevices()); if (IsDisposed || selectedKind != Kind) return; devices.Items.Clear(); foreach (var item in list) devices.Items.Add(item); if (devices.Items.Count == 1) devices.SelectedIndex = 0; if (devices.Items.Count == 0) help.Text = "Подключённые доступные устройства не найдены. Проверь кабель, режим USB и разрешение подключения."; }
            catch { help.Text = "Не удалось получить список устройств. Проверь подключение и нажми «Обновить»."; }
            finally { loading = false; if (!IsDisposed) { refresh.Enabled = Kind == 2 || Kind == 3; start.Enabled = true; } }
        }
        void BrowseSource() {
            if (Kind == 1) { using (var dialog = new OpenFileDialog { Title = "Существующий экспорт или резервная копия", Filter = "Экспорты и базы|*.json;*.html;*.txt;*.zip;*.db;*.sqlite|Все файлы|*.*" }) if (dialog.ShowDialog(this) == DialogResult.OK) sourcePath.Text = dialog.FileName;  }
            else {
                string root = sourcePath.Text;
                if (Kind == 4) { string modern = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Apple", "MobileSync", "Backup"); string old = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Apple Computer", "MobileSync", "Backup"); root = Directory.Exists(modern) ? modern : Directory.Exists(old) ? old : ""; }
                using (var dialog = new FolderBrowserDialog { Description = Kind == 4 ? "Выбери одну существующую копию iPhone с Manifest.db или Manifest.plist" : "Папка фотографий, кэша, экспорта или резервной копии", SelectedPath = Directory.Exists(root) ? root : "", ShowNewFolderButton = false }) if (dialog.ShowDialog(this) == DialogResult.OK) sourcePath.Text = dialog.SelectedPath;
            }
        }
        IRecoverySource SelectedSource(out string selectedRoot) {
            if (Kind == 2 || Kind == 3) {
                var device = devices.SelectedItem as SourceInfo; if (device == null) throw new IOException("Выбери подключённый телефон.");
                selectedRoot = tree.Visible && tree.SelectedNode != null ? Convert.ToString(tree.SelectedNode.Tag) : Kind == 2 ? "DEVICE" : "/storage/emulated/0";
                return Kind == 2 ? (IRecoverySource)new WpdRecoverySource(device.Id) : new AdbRecoverySource(device.Id);
            }
            if (Kind == 1) { if (!File.Exists(sourcePath.Text)) throw new IOException("Выбери существующий файл."); selectedRoot = Path.GetFileName(sourcePath.Text); return new LocalFolderSource(Path.GetDirectoryName(sourcePath.Text)); }
            if (!Directory.Exists(sourcePath.Text)) throw new IOException("Выбери существующую папку."); selectedRoot = ""; return Kind == 4 ? (IRecoverySource)new BackupRecoverySource(sourcePath.Text) : new LocalFolderSource(sourcePath.Text);
        }
        async void ListFolders() {
            if (busy || loading) return; IRecoverySource source; string root;
            try { source = SelectedSource(out root); } catch (IOException ex) { MessageBox.Show(this, ex.Message); return; }
            busy = true; cancellation = new CancellationTokenSource(); SetBusy(true); results.SelectedIndex = 3;
            try {
                var entries = await Task.Run(() => source.Enumerate(root, cancellation.Token).Where(e => e.IsDirectory).Take(100000).ToArray());
                tree.Nodes.Clear(); var top = tree.Nodes.Add("Все доступные файлы"); top.Tag = root;
                var nodes = new Dictionary<string, TreeNode>(StringComparer.Ordinal); nodes[""] = top;
                foreach (var entry in entries.OrderBy(e => e.RelativePath.Length)) {
                    string path = entry.RelativePath.Replace('\\', '/').Trim('/'); string parent = path.Contains('/') ? path.Substring(0, path.LastIndexOf('/')) : ""; TreeNode parentNode;
                    if (!nodes.TryGetValue(parent, out parentNode)) parentNode = top;
                    var node = parentNode.Nodes.Add(Path.GetFileName(path)); node.Tag = Kind == 2 ? entry.Id : entry.OriginalPath; nodes[path] = node;
                }
                tree.Visible = true; tree.SelectedNode = top; top.Expand(); FitLayout(); Append("Доступных папок: " + entries.Length + ". Закрытые области не извлекаются.");
            } catch (OperationCanceledException) { Append("Просмотр папок остановлен."); } catch { Append("Не удалось прочитать папки. Проверь доступ и USB-подключение."); }
            finally { busy = false; cancellation.Dispose(); cancellation = null; SetBusy(false); }
        }
        void SetBusy(bool value) { kind.Enabled = devices.Enabled = browse.Enabled = chooseOutput.Enabled = start.Enabled = resume.Enabled = deep.Enabled = credentials.Enabled = iosPassword.Enabled = !value; refresh.Enabled = !value && (Kind == 2 || Kind == 3); folders.Enabled = !value && (Kind == 2 || Kind == 3); tree.Enabled = !value; stop.Enabled = value; progress.Style = value ? ProgressBarStyle.Marquee : ProgressBarStyle.Blocks; }
        async void Begin(string previous) {
            if (busy || loading) return;
            IRecoverySource source; string root;
            try {
                source = SelectedSource(out root);
                if (!File.Exists(HelperClient.Executable)) throw new IOException("В комплекте отсутствует обработчик версии 3. Запусти программу из полной готовой папки.");
                if (previous != null && !File.Exists(Path.Combine(previous, "acquisition.json"))) throw new IOException("Выбери папку запуска с acquisition.json.");
                runDirectory = previous ?? Path.Combine(destination.Text, "Recovery-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                SourceAcquisition.ValidateOutput(source, root, runDirectory);
            } catch (IOException ex) { MessageBox.Show(this, ex.Message, "Проверь источник"); return; } catch { MessageBox.Show(this, "Не удалось подготовить источник или папку результатов."); return; }
            var secrets = new Dictionary<string, string> { { "ios_password", iosPassword.Text } };
            bool deepSearch = deep.Checked;
            iosPassword.Clear(); analysisDirectory = sourceReport = null; busy = true; cancellation = new CancellationTokenSource(); SetBusy(true); results.SelectedIndex = 3; photos.Enabled = chats.Enabled = sources.Enabled = false;
            try {
                var token = cancellation.Token;
                HelperResult result = await Task.Run(() => {
                    string snapshot = SourceAcquisition.Copy(source, root, runDirectory, token, text => Post(() => { Append(text); state.Text = "Копирование доступных файлов…"; }));
                    analysisDirectory = Path.Combine(runDirectory, "archive-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                    Post(() => Append("Рабочая копия готова. Начинается анализ сохранённых данных."));
                    return HelperClient.Scan(snapshot, analysisDirectory, secrets, deepSearch, token, text => Post(() => { state.Text = text; }));
                });
                if (result.Status == "error") { state.Text = ErrorText(result.Code); Append(state.Text); }
                else {
                    AcquisitionManifest copyInfo = ReadAcquisition();
                    state.Text = result.Status == "partial" || (copyInfo != null && copyInfo.Status != "finished") ? "Обработка завершена с замечаниями. Проверь раздел источников." : result.Messages == 0 && result.Media == 0 ? "В доступных источниках ничего не найдено." : "Архив готов: сообщений " + result.Messages + ", медиа " + result.Media + ".";
                    Append(state.Text);
                    photos.Enabled = File.Exists(Path.Combine(analysisDirectory, "Фотографии.html")); chats.Enabled = File.Exists(Path.Combine(analysisDirectory, "Переписки.html"));
                }
                WriteSourcesReport(); open.Enabled = true; results.SelectedIndex = 2;
            } catch (OperationCanceledException) { state.Text = "Остановлено. Рабочая копия и .partial сохранены для продолжения."; Append(state.Text); open.Enabled = Directory.Exists(runDirectory); WriteSourcesReport(); }
            catch { state.Text = "Обработка не завершена. Проверь доступ к источнику, место на диске и подключение. Неполная копия сохранена."; Append(state.Text); open.Enabled = Directory.Exists(runDirectory); WriteSourcesReport(); }
            finally { foreach (string key in secrets.Keys.ToArray()) secrets[key] = ""; busy = false; cancellation.Dispose(); cancellation = null; SetBusy(false); }
        }
        static string ErrorText(string code) {
            if (code == "AUTH_FAILED" || code == "AUTHENTICATION_FAILED" || code == "DECRYPTION_FAILED" || code == "WRONG_KEY") return "Не удалось проверить защищённую копию: неверный секрет или повреждение. Подтверждённый архив не создан.";
            if (code == "UNSUPPORTED_VERSION" || code == "UNSUPPORTED_FORMAT") return "Версия или формат источника не поддерживается. Проверь замечания.";
            if (code == "SECRET_REQUIRED" || code == "KEY_REQUIRED" || code == "PASSWORD_REQUIRED") return "Для защищённого источника нужен соответствующий пароль или ключ. Введи его и продолжи копию.";
            return "Обработчик не завершил анализ. Проверь формат источника и раздел замечаний.";
        }
        void WriteSourcesReport() {
            var text = new StringBuilder("Исходные файлы обрабатываются через рабочую копию.\r\nКопирование и анализ не восстанавливают данные обратно в приложения.\r\n\r\n");
            string acquisition = Path.Combine(runDirectory, "acquisition.json"), sourceFile = String.IsNullOrEmpty(analysisDirectory) ? "" : Path.Combine(analysisDirectory, "sources.json");
            if (File.Exists(acquisition)) text.Append("Рабочая копия: ").Append(acquisition).Append("\r\n");
            AcquisitionManifest copied = ReadAcquisition();
            if (copied != null) {
                text.Append("Состояние копирования: ").Append(copied.Status).Append("\r\n");
                text.Append("Полностью скопировано: ").Append(copied.Files.Count(f => f.Status == "complete")).Append("; неполных файлов: ").Append(copied.Files.Count(f => f.Status != "complete")).Append("\r\n");
                foreach (string warning in copied.Warnings.Take(100)) text.Append("Замечание: ").Append(warning).Append("\r\n");
                foreach (var file in copied.Files.Where(f => f.Status != "complete").Take(100)) text.Append("Неполный файл: ").Append(file.OriginalPath ?? file.RelativePath).Append(" · ").Append(file.Message).Append("\r\n");
            }
            if (File.Exists(sourceFile)) { text.Append("\r\nИсточники анализа:\r\n"); var info = new FileInfo(sourceFile); if (info.Length <= 8 * 1024 * 1024) text.Append(File.ReadAllText(sourceFile, Encoding.UTF8)); else text.Append("Большой отчёт: открой sources.json из папки архива."); }
            remarks.Text = text.ToString();
            string reportDirectory = Directory.Exists(analysisDirectory) ? analysisDirectory : runDirectory;
            if (!Directory.Exists(reportDirectory)) return;
            sourceReport = Path.Combine(reportDirectory, "Источники.html");
            try { File.WriteAllText(sourceReport, "<!doctype html><html lang='ru'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; object-src 'none'\"><title>Источники и замечания</title><style>body{font:16px system-ui;margin:32px;color:#182744}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Источники и замечания</h1><pre>" + WebUtility.HtmlEncode(text.ToString()) + "</pre></html>", new UTF8Encoding(false)); sources.Enabled = true; } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        AcquisitionManifest ReadAcquisition() { try { string path = Path.Combine(runDirectory, "acquisition.json"); if (!File.Exists(path) || new FileInfo(path).Length > 256L * 1024 * 1024) return null; return new JavaScriptSerializer { MaxJsonLength = Int32.MaxValue }.Deserialize<AcquisitionManifest>(File.ReadAllText(path, Encoding.UTF8)); } catch { return null; } }
        void OpenArtifact(string file) { if (!String.IsNullOrEmpty(analysisDirectory)) OpenPath(Path.Combine(analysisDirectory, file)); }
        void OpenPath(string path) { if (String.IsNullOrEmpty(path)) return; try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch { MessageBox.Show(this, "Не удалось открыть результат. Открой папку запуска в проводнике."); } }
    }
}
