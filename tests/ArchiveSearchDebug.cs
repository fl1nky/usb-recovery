using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using UsbRecovery;
public static class ArchiveSearchDebug
{
    static T Field<T>(object o,string name) { return (T)o.GetType().GetField(name, BindingFlags.NonPublic | BindingFlags.Instance).GetValue(o); }
    [STAThread] public static void Main(string[] args)
    {
        Trace.Listeners.Add(new ConsoleTraceListener()); Trace.AutoFlush=true;
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException); Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        using(var window=new RecoveryHub(false)) {
            window.ShowInTaskbar=false; window.StartPosition=FormStartPosition.Manual; window.Location=new Point(-20000,-20000); window.Show(); Application.DoEvents();
            var panel=Field<ArchiveSearchPanel>(window,"archive"); Field<TextBox>(panel,"query").Text="пирожки рецепт";
            window.Navigate("Telegram"); panel.SelectArchive(args[0]); Wait(panel);
            window.Navigate("WhatsApp"); Wait(panel);
            window.Navigate("Signal"); Wait(panel);
        }
    }
    static void Wait(ArchiveSearchPanel panel) {
        var watch=Stopwatch.StartNew(); var last=0L;
        while(panel.IsBusy && watch.ElapsedMilliseconds<25000) {
            Application.DoEvents(); Thread.Sleep(20);
            if(watch.ElapsedMilliseconds-last>2000) { int workers,ports; ThreadPool.GetAvailableThreads(out workers,out ports); Console.WriteLine("Busy: " + Field<Label>(panel,"count").Text + " threadpool available " + workers); last=watch.ElapsedMilliseconds; }
        }
        Console.WriteLine("Search idle: " + !panel.IsBusy + " rows: " + Field<DataGridView>(panel,"grid").Rows.Count + " " + Field<Label>(panel,"count").Text);
    }
}
