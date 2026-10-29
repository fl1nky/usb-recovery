using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using UsbRecovery;

public static class MinimalUiPreview
{
    static readonly List<string> failures = new List<string>();
    static string scope;
    static int layouts;

    [STAThread] public static int Main()
    {
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        using (var hub = new RecoveryHub(false))
        {
            hub.ShowInTaskbar = false; hub.StartPosition = FormStartPosition.Manual; hub.Location = new Point(-20000, -20000); hub.Show();
            Inspect(hub, new Size(1180, 820), false);
            Inspect(hub, new Size(1060, 760), false);
            Inspect(hub, hub.MinimumSize, true);
            hub.Hide();
        }
        foreach (string failure in failures) Console.WriteLine("FAIL " + failure);
        Console.WriteLine((failures.Count == 0 ? "PASS " : "FAIL ") + layouts + " visible layouts; no device discovery, file acquisition, helper search or disk reading invoked.");
        return failures.Count == 0 ? 0 : 1;
    }

    static void Inspect(RecoveryHub hub, Size size, bool outerSize)
    {
        if (outerSize) hub.Size = size; else hub.ClientSize = size;
        string dimensions = (outerSize ? "outer-" : "client-") + size.Width + "x" + size.Height;
        foreach (string section in new[] { "archives", "Telegram", "WhatsApp", "Signal", "Android", "iPhone", "files", "usb" })
        {
            hub.Navigate(section); Flush(hub); scope = dimensions + "/" + section; Verify(hub); layouts++;
            if (!outerSize && size.Width == 1180)
            {
                if (section == "archives") Save(hub, "minimal-ui.png");
                if (section == "usb") Save(hub, "minimal-ui-usb.png");
                if (section == "Android") Save(hub, "minimal-ui-source.png");
            }
            if (section != "Android" && section != "iPhone" && section != "files") continue;
            var logical = Find<LogicalRecoveryPanel>(hub); var kinds = (ComboBox)logical.Controls[0].Controls.Find("source-kind", true)[0];
            for (int kind = 0; kind < kinds.Items.Count; kind++)
            {
                kinds.SelectedIndex = kind; var credentials = Field<Button>(logical, "credentials"); credentials.PerformClick(); Flush(hub);
                scope = dimensions + "/" + section + "/mode-" + kind + "/credentials"; Verify(hub); layouts++;
                foreach (string name in new[] { "iosPassword", "whatsappKey", "signalKey" }) if (!Field<TextBox>(logical, name).UseSystemPasswordChar) Failure("Unmasked secret entry " + name);
                if (section != "files" && kind == 0)
                {
                    var tree = Field<TreeView>(logical, "tree"); tree.Nodes.Clear(); tree.Nodes.Add("DCIM"); tree.Visible = true; Flush(hub);
                    scope = dimensions + "/" + section + "/folders-and-credentials"; Verify(hub); layouts++;
                    tree.Visible = false;
                }
                credentials.PerformClick(); Flush(hub);
                var results = Field<TabControl>(logical, "results");
                for (int tab = 0; tab < results.TabPages.Count; tab++) { results.SelectedIndex = tab; Flush(hub); scope = dimensions + "/" + section + "/mode-" + kind + "/tab-" + tab; Verify(hub); layouts++; }
                results.SelectedIndex = 0;
            }
        }
    }

    static void Flush(Control control) { Application.DoEvents(); control.PerformLayout(); Application.DoEvents(); }
    static void Save(Form hub, string name) { using (var bitmap = new Bitmap(hub.Width, hub.Height)) { hub.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size)); bitmap.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name), ImageFormat.Png); } }
    static T Field<T>(object item, string name) where T : class { return (T)item.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(item); }
    static T Find<T>(Control root) where T : Control { foreach (Control child in root.Controls) { var match = child as T; if (match != null) return match; match = Find<T>(child); if (match != null) return match; } return null; }
    static void Failure(string detail) { string value = scope + " " + detail; if (!failures.Contains(value)) failures.Add(value); }

    static void Verify(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            if (!child.Visible) continue;
            var scrollable = parent as ScrollableControl;
            Rectangle available = scrollable != null && scrollable.AutoScroll ? scrollable.DisplayRectangle : new Rectangle(Point.Empty, parent.ClientSize);
            if (child.Width <= 0 || child.Height <= 0 || child.Right > available.Right + 1 || child.Bottom > available.Bottom + 1)
                Failure("Outside " + parent.GetType().Name + " " + parent.ClientSize + ": " + child.GetType().Name + " " + child.Bounds + " " + child.Text);
            var button = child as Button;
            if (button != null)
            {
                var text = TextRenderer.MeasureText(button.Text, button.Font);
                if (text.Width > button.ClientSize.Width - button.Padding.Horizontal - 8 || text.Height > button.ClientSize.Height - 4) Failure("Button text clipped: " + button.Text + " " + button.ClientSize);
                if (button.ForeColor == Color.White && button.FlatAppearance.MouseOverBackColor.GetBrightness() > .65F) Failure("White label on light hover background: " + button.Text);
            }
            Verify(child);
        }
    }
}
