using System.Drawing;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class RecoveryRunStatusCard : UserControl
    {
        readonly Label heading = new Label();
        readonly Label measurement = new Label();
        readonly Label saved = new Label();
        readonly Label nextAction = new Label();

        public RecoveryRunStatusCard()
        {
            Name = "recovery-run-status";
            BackColor = UiTheme.Surface;
            Padding = new Padding(14, 10, 14, 10);
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, Margin = Padding.Empty };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 27));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 23));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Configure(heading, "run-heading", true);
            Configure(measurement, "run-measurement", false);
            Configure(saved, "run-saved-checkpoint", false);
            Configure(nextAction, "run-next-action", false);
            measurement.TextAlign = ContentAlignment.MiddleRight;
            grid.Controls.Add(heading, 0, 0);
            grid.Controls.Add(measurement, 1, 0);
            grid.Controls.Add(saved, 0, 1); grid.SetColumnSpan(saved, 2);
            grid.Controls.Add(nextAction, 0, 2); grid.SetColumnSpan(nextAction, 2);
            Controls.Add(grid);
        }

        static void Configure(Label label, string name, bool bold)
        {
            label.Name = name;
            label.Dock = DockStyle.Fill;
            label.Margin = Padding.Empty;
            label.AutoEllipsis = true;
            label.Font = new Font("Segoe UI", bold ? 11F : 9F, bold ? FontStyle.Bold : FontStyle.Regular);
            label.ForeColor = bold ? UiTheme.Text : UiTheme.Muted;
        }

        public void Present(RecoveryRunPresentation state)
        {
            heading.Text = state.Heading;
            measurement.Text = state.ProgressText;
            saved.Text = state.SaveText;
            nextAction.Text = state.ActionText;
            AccessibleName = state.Heading;
            AccessibleDescription = state.ProgressText + ". " + state.SaveText + ". " + state.ActionText;
        }
    }
}
