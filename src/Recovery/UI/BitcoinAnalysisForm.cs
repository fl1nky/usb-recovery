using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UsbRecovery
{
    internal sealed class BitcoinAnalysisForm : Form
    {
        readonly ProgressBar progress = new ProgressBar { Dock = DockStyle.Fill };
        readonly Label status = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
        readonly TextBox results = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Multiline = true,
            WordWrap = false, ScrollBars = ScrollBars.Both, Font = new Font("Consolas", 10F) };
        readonly Button action = new Button { Text = "Остановить", AutoSize = true, Anchor = AnchorStyles.Right };
        readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        bool running;

        public BitcoinAnalysisForm(string file)
        {
            Text = "Анализ данных Bitcoin";
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(760, 470);
            MinimumSize = new Size(560, 360);
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(18) };
            foreach (int height in new[] { 36, 48, 12, 40 })
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
            layout.Controls.Add(new Label { Text = Path.GetFileName(file), Dock = DockStyle.Fill, AutoEllipsis = true,
                Font = new Font("Segoe UI", 13F, FontStyle.Bold) }, 0, 0);
            layout.Controls.Add(new Label { Dock = DockStyle.Fill,
                Text = "Поиск публичных адресов основной сети Bitcoin и упоминаний wallet.dat в ASCII и UTF-16LE. Смещения указаны в байтах от начала файла." }, 0, 1);
            layout.Controls.Add(progress, 0, 2);
            layout.Controls.Add(status, 0, 3);
            layout.Controls.Add(results, 0, 4);
            layout.Controls.Add(action, 0, 5);
            Controls.Add(layout);
            UiTheme.ApplyTree(this);
            action.Click += delegate { if (running) RequestStop(); else Close(); };
            FormClosing += delegate(object sender, FormClosingEventArgs e) {
                if (running) { e.Cancel = true; RequestStop(); }
            };
            Shown += async delegate { await Scan(file); };
            Disposed += delegate { cancellation.Dispose(); };
        }

        void RequestStop()
        {
            cancellation.Cancel();
            action.Enabled = false;
            status.Text = "Остановка…";
        }

        async Task Scan(string file)
        {
            running = true;
            status.Text = "Чтение выбранного файла…";
            var updates = new Progress<int>(value => { if (running && !IsDisposed) progress.Value = value; });
            try
            {
                var scan = await Task.Run(() => BitcoinTraceScan.ReadFile(file, cancellation.Token, updates));
                var lines = new StringBuilder();
                foreach (var hit in scan.Matches)
                    lines.AppendFormat("0x{0:X}   {1}   {2}", hit.Offset,
                        hit.IsWalletName ? "Упоминание файла" : "Публичный адрес", hit.Text).AppendLine();
                results.Text = lines.ToString();
                if (!scan.Limited) progress.Value = 100;
                status.Text = scan.Limited ? "Показана первая 1000 совпадений. Поиск остановлен на лимите."
                    : scan.Matches.Count == 0 ? "В прочитанных данных совпадений нет."
                    : "Поиск завершён. Совпадений: " + scan.Matches.Count + ". Выделенный текст можно скопировать.";
            }
            catch (OperationCanceledException) { status.Text = "Анализ остановлен. Файл можно выбрать повторно."; }
            catch (IOException e) { status.Text = "Не удалось прочитать файл. " + e.Message; }
            catch (UnauthorizedAccessException) { status.Text = "Windows отказала в доступе к файлу."; }
            finally { running = false; action.Enabled = true; action.Text = "Закрыть"; }
        }

        public static void ChooseAndAnalyze(IWin32Window owner)
        {
            using (var picker = new OpenFileDialog {
                Title = "Выбери RAW-образ диска или восстановленный файл для поиска Bitcoin-адресов",
                Filter = "Образы RAW (*.img;*.dd;*.raw;*.bin)|*.img;*.dd;*.raw;*.bin|Все файлы (*.*)|*.*",
                FilterIndex = 2, CheckFileExists = true, RestoreDirectory = true })
            {
                if (picker.ShowDialog(owner) != DialogResult.OK) return;
                using (var form = new BitcoinAnalysisForm(picker.FileName)) form.ShowDialog(owner);
            }
        }
    }
}
