using System.Drawing;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed partial class RecoveryForm
    {
        private SurfaceCard BuildSourceCard()
        {
            var card = new SurfaceCard { Dock = DockStyle.Fill, Padding = new Padding(16, 12, 16, 12), Margin = new Padding(0, 4, 0, 8) };
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, Margin = Padding.Empty };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 25));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            card.Controls.Add(grid);
            grid.Controls.Add(FieldLabel("Источник данных", disks), 0, 0);
            grid.Controls.Add(FieldLabel("Куда сохранить результат", destination), 1, 0);

            disks.DropDownStyle = ComboBoxStyle.DropDownList;
            Configure(refresh, "Обновить", delegate { RefreshDisks(); });
            grid.Controls.Add(InputWithAction(disks, refresh), 0, 1);
            destination.Text = ApplicationPaths.DefaultResultsDirectory;
            destination.ReadOnly = true;
            Configure(choose, "Выбрать…", delegate { ChooseDirectory(); });
            grid.Controls.Add(InputWithAction(destination, choose), 1, 1);

            var alternatives = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Margin = new Padding(0, 0, 12, 0) };
            alternatives.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 145));
            alternatives.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Configure(resume, "Открыть образ…", delegate { ResumeImage(); });
            resume.Tag = "primary";
            resume.AccessibleDescription = "Открыть существующий образ диска для анализа";
            alternatives.Controls.Add(resume, 0, 0);
            sourceHelp.Text = "Подключи флешку или выбери образ.";
            sourceHelp.AutoEllipsis = true;
            sourceHelp.Dock = DockStyle.Fill;
            sourceHelp.TextAlign = ContentAlignment.MiddleLeft;
            sourceHelp.ForeColor = UiTheme.Muted;
            sourceHelp.Margin = new Padding(8, 0, 0, 0);
            alternatives.Controls.Add(sourceHelp, 1, 0);
            grid.Controls.Add(alternatives, 0, 2);
            grid.Controls.Add(new Label { Text = "Выбери другой физический диск. Для полного поиска нужно около четырёх объёмов источника + 1 ГБ.",
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = UiTheme.Muted, Font = new Font("Segoe UI", 8.5F) }, 1, 2);
            return card;
        }

        private static bool HasDeviceAccess()
        {
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                return new System.Security.Principal.WindowsPrincipal(identity)
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        private void OfferElevatedWindow()
        {
            const string prompt = "Для чтения физической флешки Windows нужны права администратора. Открыть отдельное окно с этими правами? Затем выбери флешку ещё раз.";
            if (MessageBox.Show(this, prompt, "Доступ к флешке", MessageBoxButtons.YesNo,
                MessageBoxIcon.Information, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            try
            {
                var launch = new System.Diagnostics.ProcessStartInfo(typeof(RecoveryForm).Assembly.Location)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WorkingDirectory = System.AppDomain.CurrentDomain.BaseDirectory
                };
                using (var window = System.Diagnostics.Process.Start(launch)) { }
            }
            catch (System.ComponentModel.Win32Exception error)
            {
                if (error.NativeErrorCode != 1223)
                    MessageBox.Show(this, error.Message, "Не удалось открыть окно");
            }
        }

        private static Label FieldLabel(string text, Control input)
        {
            input.AccessibleName = text;
            return new Label { Text = text, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft,
                Font = new Font("Segoe UI", 10F, FontStyle.Bold), Margin = Padding.Empty };
        }

        private static TableLayoutPanel InputWithAction(Control input, Button action)
        {
            var row = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Margin = new Padding(0, 0, 12, 0) };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 96));
            input.Dock = DockStyle.Fill;
            input.Margin = new Padding(0, 4, 8, 0);
            row.Controls.Add(input, 0, 0);
            row.Controls.Add(action, 1, 0);
            return row;
        }
    }
}
