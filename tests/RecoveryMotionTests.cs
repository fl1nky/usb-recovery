using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using UsbRecovery;

public static class RecoveryMotionTests
{
    static int checks,code;static string project;static bool realAnimation;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static T Field<T>(object target,string name){return (T)target.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(target);}
    static bool TimerRunning(RecoveryActivityView view){return Field<System.Windows.Forms.Timer>(view,"timer").Enabled;}
    static double Shown(RecoveryActivityView view){return Field<double>(view,"shownProgress");}
    static void Shot(Control control,string name){using(var image=new Bitmap(control.Width,control.Height)){control.DrawToBitmap(image,new Rectangle(Point.Empty,image.Size));image.Save(Path.Combine(project,"tests",name),ImageFormat.Png);}}
    static async Task Work()
    {
        bool prior=MotionSettings.Enabled;MotionSettings.Enabled=true;realAnimation=MotionSettings.Allowed;
        try{
            using(var form=new Form{ClientSize=new Size(920,500),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000),BackColor=UiTheme.Background})
            using(var view=new RecoveryActivityView{Location=new Point(20,20),Size=new Size(880,154)})
            using(var nav=new NavigationButton{Text="Флешки и образы",Glyph="USB",Location=new Point(20,205),Width=230})
            using(var steps=new WorkflowSteps{Location=new Point(20,280),Width=850})
            using(var native=new MotionProgressBar{Location=new Point(20,380),Width=850,Maximum=1000,Style=ProgressBarStyle.Marquee}){
                form.Controls.AddRange(new Control[]{view,nav,steps,native});form.Show();await Task.Delay(70);
                Check(native.Style==ProgressBarStyle.Marquee&&native.EffectiveStyle==(realAnimation?ProgressBarStyle.Marquee:ProgressBarStyle.Continuous),"native marquee respects system preference");
                Check(!TimerRunning(view)&&!view.ProgressKnown&&!view.IsComplete,"idle view has no timer or invented progress");
                view.SetPhase("Создаём рабочую копию","Исходный накопитель используется только для чтения");view.FoundCandidates=0;view.SetProgress(25,100);Check(view.ProgressKnown&&view.CompletedBytes==25&&view.TotalBytes==100&&view.ObservedProgress==0.25D,"real observed byte progress retained");
                Check(Shown(view)==0.25D&&!TimerRunning(view),"idle progress shown without animation loop");
                view.IsActive=true;view.SetProgress(80,100);Check(TimerRunning(view)==realAnimation,"animation respects effective system setting");
                double before=Shown(view);await Task.Delay(140);Check(Shown(view)>=before&&Shown(view)<=view.ObservedProgress,"real clock advances visuals without outrunning observed bytes");
                view.SetProgress(10,100);Check(Shown(view)<=0.1D,"new lower stage progress cannot retain old larger visual");
                view.SetProgress(999,1000);Check(view.AccessibleDescription.Contains("99 процентов")&&!view.AccessibleDescription.Contains("100 процентов"),"near-complete progress never rounds up to success");
                view.SetProgress(Int64.MaxValue-1,Int64.MaxValue);Check(view.AccessibleDescription.Contains("99 процентов"),"long precision cannot turn an unfinished source into 100 percent");
                view.SetProgress(1000,1000);Check(view.AccessibleDescription.Contains("100 процентов")&&!view.IsComplete,"complete byte count is distinct from successful job");
                view.ClearProgress();Check(!view.ProgressKnown&&view.CompletedBytes==-1&&view.TotalBytes==0&&!view.AccessibleDescription.Contains("100 процентов"),"unknown total remains explicitly indeterminate");
                Check(view.IsActive&&!view.IsComplete,"unknown progress does not finish the active job");
                view.Hide();await Task.Delay(50);Check(!TimerRunning(view),"hidden activity leaves no animation timer");view.Show();await Task.Delay(45);Check(TimerRunning(view)==realAnimation,"visible active activity resumes only if allowed");
                view.ReduceMotion=true;Check(!TimerRunning(view),"per-view reduced motion stops immediately");view.ReduceMotion=false;
                view.Enabled=false;Check(!TimerRunning(view),"disabled activity has no timer");view.Enabled=true;
                nav.Selected=true;steps.Current=1;MotionSettings.Enabled=false;
                Check(!TimerRunning(view)&&!Field<MotionAnimator>(nav,"motion").Running&&!Field<MotionAnimator>(steps,"motion").Running,"global off stops all active animations immediately");
                Check(native.Style==ProgressBarStyle.Marquee&&native.EffectiveStyle==ProgressBarStyle.Continuous&&native.Value==0,"disabled native marquee keeps its requested mode and shows no fake progress");
                native.Value=120;Check(native.Value==0,"indeterminate native bar cannot become a false percentage while motion disabled");
                Check(view.IsActive&&view.FoundCandidates==0&&!view.ProgressKnown,"global preference does not change recovery facts");
                nav.Selected=false;steps.Current=2;Check(Field<double>(nav,"selectedAmount")==0D&&Field<double>(steps,"position")==2D,"reduced motion uses final navigation and step states immediately");
                MotionSettings.Enabled=true;nav.Selected=true;steps.Current=0;await Task.Delay(270);
                Check(native.EffectiveStyle==(realAnimation?ProgressBarStyle.Marquee:ProgressBarStyle.Continuous),"native marquee restored only when allowed");
                native.Style=ProgressBarStyle.Continuous;Check(native.EffectiveStyle==ProgressBarStyle.Continuous&&native.Value==120,"known native progress preserves observed value after mode change");
                native.Style=ProgressBarStyle.Marquee;native.Hide();await Task.Delay(35);Check(native.EffectiveStyle==ProgressBarStyle.Continuous&&native.Value==0,"hidden native marquee does not animate");native.Show();await Task.Delay(35);
                native.Enabled=false;Check(native.EffectiveStyle==ProgressBarStyle.Continuous&&native.Value==0,"disabled native marquee does not animate");native.Enabled=true;
                await Task.Run(()=>{native.Style=ProgressBarStyle.Continuous;native.Value=275;});await Task.Delay(50);Check(native.Style==ProgressBarStyle.Continuous&&native.Value==275,"native progress updates safely queued from worker");
                Check(!Field<MotionAnimator>(nav,"motion").Running&&!Field<MotionAnimator>(steps,"motion").Running,"short transitions finish without idle polling");
                Check(Field<double>(nav,"selectedAmount")==1D&&Field<double>(steps,"position")==0D,"final transition values match actual state");
                steps.Current=50;Check(steps.Current==2,"workflow step bounded to supported stages");steps.Current=-50;Check(steps.Current==0,"negative workflow stage bounded safely");
                await Task.Run(()=>{view.SetPhase("Проверяем найденное","Источники и контрольные суммы");view.SetProgress(456,1000);view.FoundCandidates=17;});await Task.Delay(70);
                Check(view.PhaseTitle=="Проверяем найденное"&&view.CompletedBytes==456&&view.FoundCandidates==17,"worker reports queued to UI without touching controls from worker thread");
                view.IsComplete=true;Check(view.IsComplete&&!view.IsActive&&!TimerRunning(view),"explicit completion stops motion without inventing byte total");
                view.IsActive=true;Check(!view.IsComplete,"new operation clears previous successful state");
                view.IsActive=false;Check(!view.IsComplete&&!TimerRunning(view),"cancel or stop does not become success");
                view.SetPhase("Проверяем найденное","Результаты сохраняются отдельно от исходника");view.SetProgress(456,1000);view.FoundCandidates=17;view.IsActive=true;await Task.Delay(100);
                Shot(form,"RecoveryMotion-preview.png");
                foreach(var size in new[]{new Size(250,108),new Size(450,108),new Size(880,154)}){view.Size=size;using(var bitmap=new Bitmap(size.Width,size.Height)){view.DrawToBitmap(bitmap,new Rectangle(Point.Empty,size));Check(bitmap.Width==size.Width&&bitmap.Height==size.Height,"activity paints at "+size);}}
                view.SetProgress(-1,100);Check(!view.ProgressKnown,"negative progress is indeterminate");view.SetProgress(123,0);Check(!view.ProgressKnown,"zero total is indeterminate");
                view.SetProgress(500,100);Check(view.CompletedBytes==100&&view.ObservedProgress==1D,"reported progress bounded to total");
                view.FoundCandidates=-500;Check(view.FoundCandidates==-1,"negative candidate values remain unknown");
                Check(RecoveryActivityView.FormatBytes(-1)=="—"&&RecoveryActivityView.FormatBytes(0)=="0 Б"&&RecoveryActivityView.FormatBytes(1024)=="1 КиБ","byte labels precise and unknown explicit");
                using(var plain=new Panel())using(var animation=new MotionAnimator(plain)){double end=0;animation.Start(100,p=>end=p);Check(end==1D&&!animation.Running,"unshown transition finishes with no hidden timer");bool rejected=false;try{animation.Start(10,null);}catch(ArgumentNullException){rejected=true;}Check(rejected,"invalid transition callback rejected");}
                view.Dispose();nav.Dispose();steps.Dispose();native.Dispose();MotionSettings.Enabled=false;MotionSettings.Enabled=true;Check(view.IsDisposed&&nav.IsDisposed&&steps.IsDisposed&&native.IsDisposed,"disposed controls unsubscribe from preference events");form.Close();
            }
        }finally{MotionSettings.Enabled=prior;}
    }
    [STAThread]public static int Main(string[] args)
    {
        project=Path.GetFullPath(args[0]);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
        using(var runner=new Form{ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000),Size=new Size(2,2)}){
            runner.Shown+=async delegate{try{await Work();Console.WriteLine("PASS RecoveryMotion: "+checks+" checks; real message loop, observed progress, no premature success, unknown totals, worker dispatch, navigation transitions, timer lifecycle, reduced motion; system animation allowed="+realAnimation+". Synthetic UI only.");}catch(Exception error){Console.Error.WriteLine(error);code=1;}finally{runner.Close();}};Application.Run(runner);
        }return code;
    }
}
