using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using UsbRecovery;

public static class V3UiRenderTests
{
    [STAThread] public static int Main()
    {
        string basePath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".."));
        AppDomain.CurrentDomain.AssemblyResolve += delegate(object sender, ResolveEventArgs args) { return args.Name.StartsWith("USB-Recovery,") ? Assembly.LoadFrom(Path.Combine(basePath, ".build", "app", "USB-Recovery.exe")) : null; };
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); try { return Render(); } catch (Exception ex) { Console.WriteLine("FAIL " + ex.Message); return 1; }
    }
    [MethodImpl(MethodImplOptions.NoInlining)] static int Render()
    {
        using (var form = new Form { ClientSize = new Size(970, 875), Font = new Font("Segoe UI", 10F), ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000) })
        {
            var panel = new LogicalRecoveryPanel(); form.Controls.Add(panel); form.Show(); Application.DoEvents(); form.PerformLayout();
            using (var bitmap = new Bitmap(form.Width, form.Height)) { form.DrawToBitmap(bitmap, new Rectangle(0, 0, bitmap.Width, bitmap.Height)); bitmap.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "v3-ui.png"), ImageFormat.Png); }
            var layout = (TableLayoutPanel)panel.Controls[0]; Console.WriteLine("Rows: " + String.Join(",", layout.GetRowHeights())); foreach (Control child in layout.Controls) Console.WriteLine("Row " + layout.GetRow(child) + " " + child.GetType().Name + " " + child.Bounds);
            Report(panel); Console.WriteLine("PASS v3 initial interface rendered; no device acquisition or worker invoked."); form.Hide(); return 0;
        }
    }
    static void Report(Control parent)
    {
        foreach (Control control in parent.Controls) {
            if (!control.Visible) continue;
            if (control.Width <= 0 || control.Height <= 0 || control.Bottom > parent.ClientSize.Height + 1 || control.Right > parent.ClientSize.Width + 1) throw new Exception("Control outside container: " + control.GetType().Name + " " + control.Bounds + " parent " + parent.ClientSize + " " + control.Text);
            if (control is TextBox && ((TextBox)control).UseSystemPasswordChar) Console.WriteLine("PASS secret entry masked");
            Report(control);
        }
    }
}
