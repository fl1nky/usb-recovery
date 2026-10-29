using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using UsbRecovery;

public static class RecoveryMotionUiTests
{
    static int checks;
    static string project,work;
    static void Check(bool value,string name){checks++;if(!value)throw new Exception(name);}
    static T Field<T>(object target,string name){return (T)target.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(target);}
    static void Pump(){for(int i=0;i<5;i++){Application.DoEvents();Thread.Sleep(12);}Application.DoEvents();}
    static void Visible(Control control,Form host,string name)
    {
        Rectangle bounds=host.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
        Check(control.Visible&&control.Width>0&&control.Height>0&&host.ClientRectangle.Contains(bounds),name+" fits visible window: "+bounds+" in "+host.ClientSize);
        Check(control.Parent.ClientRectangle.Contains(control.Bounds),name+" fits its parent: "+control.Bounds+" in "+control.Parent.ClientSize);
        Check(control.Parent.GetChildAtPoint(new Point(control.Left+control.Width/2,control.Top+control.Height/2))==control,name+" is not covered by another control");
    }
    static void Hub()
    {
        bool preference=MotionSettings.Enabled;
        try{
            using(var hub=new RecoveryHub(false)){
                hub.ShowInTaskbar=false;hub.StartPosition=FormStartPosition.Manual;hub.Location=new Point(-20000,-20000);hub.Show();Pump();
                var toggle=Field<CheckBox>(hub,"motionToggle");var panel=Field<ArchiveSearchPanel>(hub,"archive");
                var activity=Field<RecoveryActivityView>(panel,"analysisActivity");var layout=Field<TableLayoutPanel>(panel,"contentLayout");
                var stop=Field<Button>(panel,"cancelButton");var state=Field<Panel>(panel,"analysisState");
                for(int size=0;size<2;size++){
                    if(size==0)hub.ClientSize=new Size(1280,920);else hub.Size=hub.MinimumSize;Pump();
                    Visible(toggle,hub,"motion toggle");hub.Navigate("Telegram");Pump();
                    float idleHeight=layout.RowStyles[2].Height;int idleStateHeight=state.Height;
                    int cancellations=0;EventHandler cancelled=delegate{cancellations++;};panel.AnalysisCancelRequested+=cancelled;
                    panel.SetAnalysisBusy(true,"Чтение искусственного локального образца");Pump();
                    Check(panel.IsBusy&&activity.Visible&&activity.IsActive&&!activity.IsComplete&&!activity.ProgressKnown,"Telegram analysis shows active unknown progress without claiming success");
                    Check(layout.RowStyles[2].Height>idleHeight&&state.Height>idleStateHeight,"Telegram activity grows only for active analysis");
                    Visible(activity,hub,"Telegram activity");Visible(stop,hub,"Telegram stop");Check(stop.Enabled,"Telegram stop enabled during analysis");
                    toggle.Checked=false;Pump();Check(!MotionSettings.Enabled&&!Field<System.Windows.Forms.Timer>(activity,"timer").Enabled&&activity.IsActive,"sidebar off stops animation without stopping analysis");
                    toggle.Checked=true;Pump();Check(MotionSettings.Enabled&&Field<System.Windows.Forms.Timer>(activity,"timer").Enabled==MotionSettings.Allowed,"sidebar on respects actual system animation preference");
                    stop.PerformClick();Check(cancellations==1,"visible Telegram stop dispatches analysis cancellation");
                    panel.ShowAnalysisError("Искусственный анализ остановлен");Pump();
                    Check(!panel.IsBusy&&!activity.Visible&&!activity.IsActive&&!activity.IsComplete&&!stop.Enabled,"stopped analysis returns idle without success state");
                    Check(layout.RowStyles[2].Height==idleHeight&&state.Height==idleStateHeight,"Telegram activity shrinks back to exact idle row");
                    panel.AnalysisCancelRequested-=cancelled;hub.Navigate("usb");Pump();
                    var disks=Field<RecoveryForm>(hub,"disks");var journal=Field<CheckBox>(disks,"journalToggle");var log=Field<TextBox>(disks,"log");
                    var results=Field<Button>(disks,"fileList");var diskStop=Field<Button>(disks,"stop");string before=log.Text;
                    Check(!journal.Checked&&!log.Visible,"USB journal starts collapsed");
                    foreach(bool expanded in new[]{true,false}){journal.Checked=expanded;Pump();Check(log.Visible==expanded&&log.Text==before,"journal toggle changes visibility without losing evidence");Visible(results,hub,"USB results/export entry");Visible(diskStop,hub,"USB stop");}
                }
                hub.Close();
            }
        }finally{MotionSettings.Enabled=preference;}
    }
    static void WorkingJournalAndExport()
    {
        Directory.CreateDirectory(Path.Combine(work,"results","files.1"));string output=Path.Combine(work,"results");
        File.WriteAllText(Path.Combine(output,"files.1","example.txt"),"Synthetic local fixture\r\n"+new string('x',2*1024*1024));
        File.WriteAllText(Path.Combine(output,"result.json"),"{\"status\":\"cancelled\"}");
        using(var form=new RecoveryForm(false)){
            form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.Size=form.MinimumSize;form.Show();Pump();
            var journal=Field<CheckBox>(form,"journalToggle");var log=Field<TextBox>(form,"log");var stop=Field<Button>(form,"stop");
            Task<bool> pending=form.PrepareFoundFilesAsync(output);Check(form.IsBusy&&stop.Enabled,"actual catalog preparation exposes enabled stop");
            journal.Checked=true;Check(log.Visible&&log.Text.IndexOf("каталог",StringComparison.OrdinalIgnoreCase)>=0,"busy journal opens on real catalog preparation text");Visible(stop,form,"busy USB stop");
            journal.Checked=false;Check(!log.Visible&&form.IsBusy&&stop.Enabled,"hiding journal preserves actual operation and cancellation");
            DateTime deadline=DateTime.UtcNow.AddSeconds(20);while(!pending.IsCompleted&&DateTime.UtcNow<deadline)Pump();Check(pending.IsCompleted&&pending.Result&&!form.IsBusy,"real synthetic catalog preparation completes");form.Close();
        }
        using(var form=new RecoveryFilesForm(output)){
            form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.ClientSize=new Size(900,650);form.Show();Pump();
            Field<CheckBox>(form,"all").Checked=true;Pump();var export=Field<Button>(form,"export");
            Check(export.Enabled,"actual selected synthetic result can be exported");Visible(export,form,"minimum-window export");
            form.ShowOverview(true);Pump();Visible(export,form,"expanded-overview export");Check(export.Enabled,"expanded summary keeps real export available");form.Close();
        }
    }
    [STAThread]public static int Main(string[] args)
    {
        try{
            project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","recovery-motion-ui-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            Hub();WorkingJournalAndExport();Console.WriteLine("PASS RecoveryMotionUi: "+checks+" checks; real minimum/normal hub hit testing, sidebar motion preference, Telegram activity expansion/cancellation, journal toggle and synthetic catalog/export; no devices or profile discovery.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
        finally{if(project!=null&&work!=null&&Path.GetFullPath(work).StartsWith(Path.Combine(project,".build","recovery-motion-ui-"),StringComparison.OrdinalIgnoreCase)&&Directory.Exists(work))try{Directory.Delete(work,true);}catch(IOException){}catch(UnauthorizedAccessException){}}
    }
}
