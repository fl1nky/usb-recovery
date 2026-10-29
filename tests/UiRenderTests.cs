using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using UsbRecovery;

public static class UiRenderTests
{
    [STAThread]
    public static int Main()
    {
        string basePath=Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,".."));
        AppDomain.CurrentDomain.AssemblyResolve += delegate(object sender, ResolveEventArgs args) {
            return args.Name.StartsWith("USB-Recovery,") ? Assembly.LoadFrom(Path.Combine(basePath,"USB-Recovery.exe")) : null;
        };
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        return Render();
    }
    [MethodImpl(MethodImplOptions.NoInlining)]
    static int Render()
    {
        using(var form=new RecoveryForm())
        {
            // Suppress automatic disk enumeration; only render the empty initial interface.
            var shownKey=typeof(Form).GetField("EVENT_SHOWN",BindingFlags.Static|BindingFlags.NonPublic);
            var eventsProperty=typeof(Control).GetProperty("Events",BindingFlags.Instance|BindingFlags.NonPublic);
            if(shownKey==null || eventsProperty==null) throw new Exception("Could not isolate render test from Shown handler.");
            var handlers=(EventHandlerList)eventsProperty.GetValue(form,null);
            object key=shownKey.GetValue(null);
            handlers.RemoveHandler(key,handlers[key]);
            form.ShowInTaskbar=false;
            form.StartPosition=FormStartPosition.Manual;
            form.Location=new Point(-20000,-20000);
            form.Show();
            Application.DoEvents();
            IntPtr unused=form.Handle;
            form.PerformLayout();
            using(var bitmap=new Bitmap(form.Width,form.Height))
            {
                form.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));
                bitmap.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"ui.png"),ImageFormat.Png);
            }
            form.Hide();
            Console.WriteLine("Rendered initial form offscreen without invoking disk enumeration or recovery.");
            Report(form);
            return 0;
        }
    }
    static void Report(Control parent)
    {
        foreach(Control control in parent.Controls)
        {
            if(control is Label || control is Button)
            {
                Console.WriteLine(control.GetType().Name+" bounds="+control.Bounds+" text="+control.Text);
                if(control.Width<=0 || control.Height<=0) throw new Exception("Invisible sized control: "+control.Text);
                if(control.Bottom>parent.ClientSize.Height || control.Right>parent.ClientSize.Width)
                    throw new Exception("Control extends beyond its container: "+control.Text);
            }
            Report(control);
        }
    }
}
