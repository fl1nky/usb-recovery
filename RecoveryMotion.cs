using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace UsbRecovery
{
    // A single preference for code-painted controls. Motion never changes the
    // recovery job, source data, observed percentage or result counts.
    public static class MotionSettings
    {
        const uint GetClientAreaAnimation=0x1042;
        [DllImport("user32.dll",SetLastError=true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        static extern bool SystemParametersInfo(uint action,uint parameter,ref int value,uint flags);
        static bool systemAllows=ReadSystemPreference();
        static bool highContrast=SystemInformation.HighContrast;
        static bool enabled=systemAllows;
        public static event EventHandler Changed;
        static MotionSettings()
        {
            try { SystemEvents.UserPreferenceChanged+=delegate { RefreshSystemPreference(); }; }
            catch(InvalidOperationException) { }
        }
        public static bool Enabled
        {
            get { return enabled; }
            set { if(enabled==value)return;enabled=value;RaiseChanged(); }
        }
        public static bool SystemAllowsAnimation { get { return systemAllows; } }
        public static bool Allowed { get { return enabled&&systemAllows&&!highContrast; } }
        public static void RefreshSystemPreference()
        {
            bool current=ReadSystemPreference(),contrast=SystemInformation.HighContrast;if(current==systemAllows&&contrast==highContrast)return;systemAllows=current;highContrast=contrast;RaiseChanged();
        }
        static bool ReadSystemPreference()
        {
            try { int value=0;return SystemParametersInfo(GetClientAreaAnimation,0,ref value,0)&&value!=0; }
            catch(DllNotFoundException) { return false; }
            catch(EntryPointNotFoundException) { return false; }
        }
        static void RaiseChanged()
        {
            var changed=Changed;if(changed!=null)changed(null,EventArgs.Empty);
        }
    }

    // Native marquee controls also obey the same preference. The requested
    // mode is kept separately so a paused indeterminate bar can be restored.
    public sealed class MotionProgressBar : ProgressBar
    {
        readonly int ownerThread=Thread.CurrentThread.ManagedThreadId;
        ProgressBarStyle requestedStyle=ProgressBarStyle.Blocks;
        int requestedValue;
        bool applyPending;
        public MotionProgressBar(){MotionSettings.Changed+=MotionChanged;}
        public new ProgressBarStyle Style
        {
            get { return requestedStyle; }
            set {
                if(!Enum.IsDefined(typeof(ProgressBarStyle),value))throw new System.ComponentModel.InvalidEnumArgumentException("value",(int)value,typeof(ProgressBarStyle));
                OnUi(()=>{requestedStyle=value;ApplyMotion();});
            }
        }
        public new int Value
        {
            get { return base.Value; }
            set { OnUi(()=>{if(value<Minimum||value>Maximum)throw new ArgumentException("Value must be between Minimum and Maximum.");requestedValue=value;ApplyMotion();}); }
        }
        public ProgressBarStyle EffectiveStyle { get { return base.Style; } }
        void OnUi(Action update)
        {
            if(IsDisposed||Disposing)return;
            if(Thread.CurrentThread.ManagedThreadId==ownerThread){update();return;}
            if(!IsHandleCreated)throw new InvalidOperationException("Create the progress bar on the UI thread before reporting progress.");
            try { BeginInvoke(new Action(()=>{if(!IsDisposed&&!Disposing)update();})); }
            catch(ObjectDisposedException) { }
            catch(InvalidOperationException) { }
        }
        void ApplyMotion()
        {
            if(IsDisposed||Disposing)return;
            bool paused=requestedStyle==ProgressBarStyle.Marquee&&(!MotionSettings.Allowed||!Visible||!Enabled);
            var effective=paused?ProgressBarStyle.Continuous:requestedStyle;if(base.Style!=effective)base.Style=effective;
            int value=paused?Math.Max(Minimum,Math.Min(Maximum,0)):Math.Max(Minimum,Math.Min(Maximum,requestedValue));
            if(base.Value!=value)base.Value=value;
        }
        void MotionChanged(object sender,EventArgs e){if(IsDisposed||Disposing||!IsHandleCreated)return;OnUi(ApplyMotion);}
        void QueueMotion()
        {
            if(IsDisposed||Disposing)return;
            if(!IsHandleCreated){ApplyMotion();return;}if(applyPending)return;applyPending=true;
            try { BeginInvoke(new Action(()=>{applyPending=false;if(!IsDisposed&&!Disposing)ApplyMotion();})); }
            catch(ObjectDisposedException) { applyPending=false; }
            catch(InvalidOperationException) { applyPending=false; }
        }
        protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);QueueMotion();}
        protected override void OnHandleDestroyed(EventArgs e){applyPending=false;base.OnHandleDestroyed(e);}
        protected override void OnVisibleChanged(EventArgs e){base.OnVisibleChanged(e);QueueMotion();}
        protected override void OnEnabledChanged(EventArgs e){base.OnEnabledChanged(e);ApplyMotion();}
        protected override void Dispose(bool disposing){if(disposing)MotionSettings.Changed-=MotionChanged;base.Dispose(disposing);}
    }

    // Short owner-bound UI transitions only. Hidden, disabled, disposed and
    // reduced-motion controls finish immediately and leave no idle timer.
    public sealed class MotionAnimator : IDisposable
    {
        readonly Control owner;
        readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
        readonly Stopwatch clock=new Stopwatch();
        Action<double> update;
        int duration;
        bool disposed,running;
        public bool Running { get { return running; } }
        public MotionAnimator(Control control)
        {
            if(control==null)throw new ArgumentNullException("control");owner=control;
            timer.Interval=16;timer.Tick+=Tick;owner.VisibleChanged+=OwnerChanged;owner.EnabledChanged+=OwnerChanged;
            owner.HandleDestroyed+=OwnerChanged;owner.Disposed+=OwnerDisposed;MotionSettings.Changed+=MotionChanged;
        }
        public void Start(int milliseconds,Action<double> frame)
        {
            if(disposed||owner.IsDisposed)return;if(frame==null)throw new ArgumentNullException("frame");
            timer.Stop();clock.Reset();update=frame;duration=Math.Max(1,Math.Min(milliseconds,2000));
            if(!CanAnimate){running=false;update(1D);update=null;return;}
            running=true;clock.Start();update(0D);timer.Start();
        }
        public void Stop(bool finish)
        {
            if(disposed)return;timer.Stop();clock.Stop();running=false;var last=update;update=null;
            if(finish&&last!=null&&!owner.IsDisposed&&!owner.Disposing)last(1D);
        }
        bool CanAnimate { get { return !disposed&&!owner.IsDisposed&&!owner.Disposing&&owner.IsHandleCreated&&owner.Visible&&owner.Enabled&&MotionSettings.Allowed; } }
        void Tick(object sender,EventArgs e)
        {
            if(!CanAnimate){Stop(true);return;}
            double fraction=Math.Min(1D,(double)clock.ElapsedMilliseconds/duration),eased=1D-Math.Pow(1D-fraction,3D);var frame=update;
            if(fraction>=1D){timer.Stop();clock.Stop();running=false;update=null;}
            if(frame!=null)frame(eased);
        }
        void OwnerChanged(object sender,EventArgs e) { if(!CanAnimate)Stop(true); }
        void OwnerDisposed(object sender,EventArgs e) { Dispose(); }
        void MotionChanged(object sender,EventArgs e)
        {
            if(disposed||owner.IsDisposed||!owner.IsHandleCreated)return;
            try { if(owner.InvokeRequired)owner.BeginInvoke(new Action(()=>{if(!disposed&&!CanAnimate)Stop(true);}));else if(!CanAnimate)Stop(true); }
            catch(ObjectDisposedException) { }
            catch(InvalidOperationException) { }
        }
        public void Dispose()
        {
            if(disposed)return;Stop(false);disposed=true;MotionSettings.Changed-=MotionChanged;
            owner.VisibleChanged-=OwnerChanged;owner.EnabledChanged-=OwnerChanged;owner.HandleDestroyed-=OwnerChanged;owner.Disposed-=OwnerDisposed;
            timer.Tick-=Tick;timer.Dispose();update=null;
        }
    }

    // Progress is observed data. Animation can lag behind it briefly but can
    // never run ahead. Without a denominator, an indeterminate marker is drawn
    // and no percentage or artificial estimate is presented.
    public sealed class RecoveryActivityView : Control
    {
        readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
        readonly int ownerThread=Thread.CurrentThread.ManagedThreadId;
        string phaseTitle="Готово к поиску",phaseDetail="Выбери носитель или готовый образ";
        string candidateCaption="НАЙДЕНО НА ЭТАПЕ";
        long completedBytes=-1,totalBytes,foundCandidates=-1;
        bool active,reduceMotion,complete;
        double shownProgress,cycle;
        public RecoveryActivityView()
        {
            SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);
            Height=154;MinimumSize=new Size(250,108);BackColor=UiTheme.Background;TabStop=false;
            AccessibleRole=AccessibleRole.Indicator;AccessibleName="Состояние восстановления";
            timer.Interval=30;timer.Tick+=Tick;MotionSettings.Changed+=MotionChanged;
        }
        public string PhaseTitle { get { return phaseTitle; } set { SetPhase(value,phaseDetail); } }
        public string PhaseDetail { get { return phaseDetail; } set { SetPhase(phaseTitle,value); } }
        public string CandidateCaption { get { return candidateCaption; } set { OnUi(()=>{candidateCaption=String.IsNullOrWhiteSpace(value)?"КАНДИДАТЫ":value;UpdateAccessibleDescription();Invalidate();}); } }
        public long CompletedBytes { get { return completedBytes; } }
        public long TotalBytes { get { return totalBytes; } }
        public bool ProgressKnown { get { return totalBytes>0&&completedBytes>=0; } }
        public double ObservedProgress { get { return ProgressKnown?Math.Min(1D,(double)completedBytes/totalBytes):0D; } }
        public long FoundCandidates
        {
            get { return foundCandidates; }
            set { OnUi(()=>{foundCandidates=Math.Max(-1,value);UpdateAccessibleDescription();Invalidate();}); }
        }
        public bool IsActive
        {
            get { return active; }
            set { OnUi(()=>{active=value;if(value)complete=false;UpdateTimer();UpdateAccessibleDescription();Invalidate();}); }
        }
        public bool IsComplete
        {
            get { return complete; }
            set { OnUi(()=>{complete=value;if(value)active=false;UpdateTimer();UpdateAccessibleDescription();Invalidate();}); }
        }
        public bool ReduceMotion
        {
            get { return reduceMotion; }
            set { OnUi(()=>{reduceMotion=value;UpdateTimer();Invalidate();}); }
        }
        public void SetPhase(string title,string detail)
        {
            OnUi(()=>{phaseTitle=String.IsNullOrWhiteSpace(title)?"Восстановление":title;phaseDetail=detail??"";UpdateAccessibleDescription();Invalidate();});
        }
        public void SetProgress(long completed,long total)
        {
            OnUi(()=>{
                if(total<=0||completed<0){completedBytes=-1;totalBytes=0;shownProgress=0;}
                else { completedBytes=Math.Min(completed,total);totalBytes=total;shownProgress=Math.Min(shownProgress,ObservedProgress); }
                if(!CanAnimate)shownProgress=ObservedProgress;
                UpdateTimer();UpdateAccessibleDescription();Invalidate();
            });
        }
        public void ClearProgress() { SetProgress(-1,0); }
        void OnUi(Action update)
        {
            if(IsDisposed||Disposing)return;
            if(Thread.CurrentThread.ManagedThreadId==ownerThread){update();return;}
            // Never create a UI handle on a worker thread. Job updates normally
            // arrive after the containing form is shown and can be queued.
            if(!IsHandleCreated)throw new InvalidOperationException("Create the activity view on the UI thread before reporting progress.");
            try { BeginInvoke(new Action(()=>{if(!IsDisposed&&!Disposing)update();})); }
            catch(ObjectDisposedException) { }
            catch(InvalidOperationException) { }
        }
        bool CanAnimate { get { return active&&!reduceMotion&&MotionSettings.Allowed&&Visible&&Enabled&&IsHandleCreated&&!IsDisposed&&!Disposing; } }
        void MotionChanged(object sender,EventArgs e)
        {
            if(IsDisposed||Disposing||!IsHandleCreated)return;
            OnUi(()=>{UpdateTimer();Invalidate();});
        }
        void UpdateTimer()
        {
            if(IsDisposed||Disposing)return;
            if(CanAnimate)timer.Start();else {timer.Stop();shownProgress=ObservedProgress;cycle=0;}
        }
        void Tick(object sender,EventArgs e)
        {
            if(!CanAnimate){UpdateTimer();return;}
            cycle=(cycle+0.008D)%1D;
            double observed=ObservedProgress;
            if(ProgressKnown){double gap=observed-shownProgress;shownProgress=gap<0.001D?observed:shownProgress+gap*0.2D;shownProgress=Math.Max(0,Math.Min(observed,shownProgress));}
            Invalidate();
        }
        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e);UpdateTimer(); }
        protected override void OnHandleDestroyed(EventArgs e) { timer.Stop();base.OnHandleDestroyed(e); }
        protected override void OnVisibleChanged(EventArgs e) { base.OnVisibleChanged(e);UpdateTimer(); }
        protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e);UpdateTimer(); }
        protected override void Dispose(bool disposing)
        {
            if(disposing){MotionSettings.Changed-=MotionChanged;timer.Stop();timer.Tick-=Tick;timer.Dispose();}
            base.Dispose(disposing);
        }
        void UpdateAccessibleDescription()
        {
            AccessibleDescription=phaseTitle+". "+phaseDetail+(complete?". Завершено":"")+(ProgressKnown?". "+PercentText()+" процентов. "+FormatBytes(completedBytes)+" из "+FormatBytes(totalBytes):". Процент выполнения неизвестен")+(foundCandidates>=0?". "+candidateCaption+": "+foundCandidates:"");
        }
        string PercentText() { return (completedBytes==totalBytes&&ProgressKnown?100D:Math.Min(99D,Math.Floor(ObservedProgress*100D))).ToString("0",CultureInfo.InvariantCulture); }
        public static string FormatBytes(long bytes)
        {
            if(bytes<0)return "—";string[] units={"Б","КиБ","МиБ","ГиБ","ТиБ","ПиБ","ЭиБ"};int unit=0;double value=bytes;
            while(value>=1024D&&unit<units.Length-1){value/=1024D;unit++;}
            return value.ToString(unit==0?"0":"0.#",CultureInfo.GetCultureInfo("ru-RU"))+" "+units[unit];
        }
        static GraphicsPath Rounded(RectangleF bounds,float radius)
        {
            var path=new GraphicsPath();float diameter=Math.Min(radius*2,Math.Min(bounds.Width,bounds.Height));
            if(diameter<=0){path.AddRectangle(bounds);return path;}
            path.AddArc(bounds.Left,bounds.Top,diameter,diameter,180,90);path.AddArc(bounds.Right-diameter,bounds.Top,diameter,diameter,270,90);path.AddArc(bounds.Right-diameter,bounds.Bottom-diameter,diameter,diameter,0,90);path.AddArc(bounds.Left,bounds.Bottom-diameter,diameter,diameter,90,90);path.CloseFigure();return path;
        }
        static void TextAt(Graphics graphics,string text,Font font,Rectangle bounds,Color color,TextFormatFlags align)
        {
            if(bounds.Width<=0||bounds.Height<=0)return;TextRenderer.DrawText(graphics,text??"",font,bounds,color,TextFormatFlags.NoPadding|TextFormatFlags.EndEllipsis|align);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);if(Width<2||Height<2)return;
            var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;g.Clear(BackColor);
            using(var card=Rounded(new RectangleF(0.5F,0.5F,Width-1F,Height-1F),14))using(var fill=new SolidBrush(UiTheme.Surface))using(var border=new Pen(UiTheme.Border)){g.FillPath(fill,card);g.DrawPath(border,card);}
            bool compact=Height<136,ring=Width>=430,stats=Width>=670;
            int margin=compact?16:22,ringSize=compact?56:76,ringTop=(Height-ringSize)/2;
            int textLeft=ring?margin+ringSize+22:margin,statsWidth=stats?184:0;
            int textWidth=Math.Max(1,Width-textLeft-margin-statsWidth),titleY=compact?18:24;
            Color accent=SystemInformation.HighContrast?SystemColors.Highlight:UiTheme.Accent;
            if(ring){
                var bounds=new RectangleF(margin+3,ringTop+3,ringSize-6,ringSize-6);
                using(var track=new Pen(Color.FromArgb(233,238,247),6F)){track.StartCap=track.EndCap=LineCap.Round;g.DrawEllipse(track,bounds);}
                if(ProgressKnown){using(var progress=new Pen(accent,6F)){progress.StartCap=progress.EndCap=LineCap.Round;if(shownProgress>0D)g.DrawArc(progress,bounds,-90,(float)(shownProgress*359.9D));}}
                else if(active){using(var sweep=new Pen(accent,6F)){sweep.StartCap=sweep.EndCap=LineCap.Round;g.DrawArc(sweep,bounds,(float)(cycle*360D)-90,MotionSettings.Allowed&&!reduceMotion?88:100);}}
                if(complete){float x=margin+ringSize/2F,y=ringTop+ringSize/2F;using(var check=new Pen(accent,2.4F)){check.StartCap=check.EndCap=LineCap.Round;check.LineJoin=LineJoin.Round;g.DrawLines(check,new[]{new PointF(x-10,y),new PointF(x-3,y+7),new PointF(x+11,y-8)});}}
                else if(!ProgressKnown&&!active){float x=margin+ringSize/2F,y=ringTop+ringSize/2F;using(var search=new Pen(accent,1.9F)){search.StartCap=search.EndCap=LineCap.Round;g.DrawEllipse(search,x-9,y-10,15,15);g.DrawLine(search,x+4,y+3,x+11,y+10);}}
                else {string centre=ProgressKnown?PercentText()+"%":"···";using(var number=new Font("Segoe UI",compact?12F:16F,FontStyle.Bold))TextAt(g,centre,number,new Rectangle(margin,ringTop,ringSize,ringSize),accent,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);}
            }
            using(var title=new Font("Segoe UI",compact?12F:15F,FontStyle.Bold))TextAt(g,phaseTitle,title,new Rectangle(textLeft,titleY,textWidth,compact?25:32),UiTheme.Text,TextFormatFlags.VerticalCenter);
            using(var detail=new Font("Segoe UI",9F))TextAt(g,phaseDetail,detail,new Rectangle(textLeft,titleY+(compact?28:35),textWidth,23),UiTheme.Muted,TextFormatFlags.VerticalCenter);
            int barY=Height-margin-10,barWidth=textWidth;
            using(var track=Rounded(new RectangleF(textLeft,barY,barWidth,5),2.5F))using(var brush=new SolidBrush(Color.FromArgb(233,238,247)))g.FillPath(brush,track);
            if(ProgressKnown&&shownProgress>0D){using(var bar=Rounded(new RectangleF(textLeft,barY,Math.Max(1,(float)(barWidth*shownProgress)),5),2.5F))using(var brush=new SolidBrush(accent))g.FillPath(brush,bar);}
            else if(active){float markerWidth=Math.Max(18,barWidth*0.17F),x=textLeft+(float)cycle*(barWidth-markerWidth);using(var marker=Rounded(new RectangleF(x,barY,markerWidth,5),2.5F))using(var brush=new SolidBrush(accent))g.FillPath(brush,marker);}
            if(!compact){using(var text=new Font("Segoe UI",8.5F))TextAt(g,ProgressKnown?FormatBytes(completedBytes)+" / "+FormatBytes(totalBytes):active?"Идёт анализ · общий объём пока неизвестен":"Чтение начнётся после запуска",text,new Rectangle(textLeft,barY-23,textWidth,20),UiTheme.Muted,TextFormatFlags.VerticalCenter);}
            if(stats){
                int x=Width-margin-statsWidth+24;using(var line=new Pen(UiTheme.Border))g.DrawLine(line,x-20,margin,x-20,Height-margin);
                using(var label=new Font("Segoe UI",8F,FontStyle.Bold))TextAt(g,candidateCaption,label,new Rectangle(x,margin,statsWidth-26,20),UiTheme.Muted,TextFormatFlags.VerticalCenter);
                using(var value=new Font("Segoe UI",compact?22F:27F,FontStyle.Bold))TextAt(g,foundCandidates<0?"—":foundCandidates.ToString("N0",CultureInfo.GetCultureInfo("ru-RU")),value,new Rectangle(x,margin+24,statsWidth-26,compact?38:44),UiTheme.Text,TextFormatFlags.VerticalCenter);
                if(!compact)using(var label=new Font("Segoe UI",8F))TextAt(g,complete?"Проверка — в каталоге":"Проверим после поиска",label,new Rectangle(x,Height-margin-25,statsWidth-26,25),UiTheme.Muted,TextFormatFlags.VerticalCenter);
            }
        }
    }
}
