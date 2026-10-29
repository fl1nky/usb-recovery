using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Drawing;
using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.Linq;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class RecoveryResultsCategory
    {
        public readonly string Name;
        public readonly int Count;
        public readonly Color Color;
        internal RecoveryResultsCategory(string name,int count,Color color){Name=name;Count=count;Color=color;}
    }
    public sealed class RecoveryResultsSnapshot
    {
        public readonly int UniqueFiles,Candidates,CheckedFiles,AttentionFiles,UnknownFiles,UnknownSizeFiles;
        public readonly long TotalBytes;
        public readonly bool SizeClipped;
        public readonly ReadOnlyCollection<RecoveryResultsCategory> Categories;
        static readonly string[] CategoryNames={"Фотографии","Видео","Аудио","Документы","Архивы","Прочее"};
        static readonly Color[] CategoryColors={Color.FromArgb(48,99,221),Color.FromArgb(117,94,203),Color.FromArgb(68,145,170),Color.FromArgb(54,139,109),Color.FromArgb(203,146,53),Color.FromArgb(147,159,177)};
        RecoveryResultsSnapshot(RecoveryFileIndex index)
        {
            var counts=new int[CategoryNames.Length];long size=0;bool clipped=false;int total=0,checkedCount=0,attention=0,unknownSize=0;
            foreach(var item in index==null||index.Items==null?Enumerable.Empty<RecoveredItem>():index.Items){
                if(item==null)continue;total++;int category=Array.IndexOf(CategoryNames,item.Category);counts[category<0?CategoryNames.Length-1:category]++;
                if(item.Bytes<0)unknownSize++;else if(item.Bytes>Int64.MaxValue-size){size=Int64.MaxValue;clipped=true;}else size+=item.Bytes;
                switch(item.Quality){case "decoded":case "container_crc":case "member_crc":checkedCount++;break;case "damaged":case "partial":case "read_errors":case "changed":attention++;break;}
            }
            UniqueFiles=total;Candidates=index==null?0:Math.Max(0,index.Candidates);TotalBytes=size;SizeClipped=clipped;UnknownSizeFiles=unknownSize;
            CheckedFiles=checkedCount;AttentionFiles=attention;UnknownFiles=total-checkedCount-attention;
            Categories=new ReadOnlyCollection<RecoveryResultsCategory>(CategoryNames.Select((name,i)=>new RecoveryResultsCategory(name,counts[i],CategoryColors[i])).ToList());
        }
        public static string DisplayCategory(string category){return Array.IndexOf(CategoryNames,category)<0?"Прочее":category;}
        public static RecoveryResultsSnapshot From(RecoveryFileIndex index){return new RecoveryResultsSnapshot(index);}
        public static string FormatBytes(long bytes)
        {
            if(bytes<0)return "Неизвестно";string[] units={"Б","КиБ","МиБ","ГиБ","ТиБ","ПиБ","ЭиБ"};double value=bytes;int at=0;while(value>=1024&&at<units.Length-1){value/=1024;at++;}return value.ToString(at==0?"0":"0.#",CultureInfo.CurrentCulture)+" "+units[at];
        }
    }
    public sealed class RecoveryCategoryEventArgs : EventArgs
    {
        public readonly string Category;
        public RecoveryCategoryEventArgs(string category){Category=category;}
    }
    public sealed class RecoveryResultsOverview : Control
    {
        readonly Timer timer=new Timer{Interval=16};
        readonly List<KeyValuePair<Rectangle,string>> targets=new List<KeyValuePair<Rectangle,string>>();
        readonly ToolTip tip=new ToolTip();
        RecoveryResultsSnapshot snapshot=RecoveryResultsSnapshot.From(null);
        readonly Stopwatch stopwatch=new Stopwatch();
        bool compact,reduceMotion;double reveal=1;
        public event EventHandler<RecoveryCategoryEventArgs> CategoryPicked;
        public RecoveryResultsSnapshot Snapshot{get{return snapshot;}}
        public bool IsAnimating{get{return timer.Enabled;}}
        public bool Compact{get{return compact;}set{if(compact==value)return;compact=value;Restart();}}
        public bool ReduceMotion{get{return reduceMotion;}set{if(reduceMotion==value)return;reduceMotion=value;Restart();}}
        public RecoveryResultsOverview()
        {
            SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);BackColor=Color.White;TabStop=false;Name="recovery-results-overview";Height=128;Margin=new Padding(0,0,0,10);AccessibleName="Сводка найденных файлов";
            tip.SetToolTip(this,"Сводка всех уникальных находок. Нажми на тип, чтобы отфильтровать список. Проверка формата не доказывает исходную полноту файла.");
            timer.Tick+=delegate{if(!CanAnimate()){Finish();return;}double elapsed=stopwatch.Elapsed.TotalMilliseconds/320;reveal=1-Math.Pow(1-Math.Min(1,Math.Max(0,elapsed)),3);if(elapsed>=1){timer.Stop();stopwatch.Stop();}Invalidate();};
            MotionSettings.Changed+=MotionChanged;
        }
        public void SetIndex(RecoveryFileIndex index){snapshot=RecoveryResultsSnapshot.From(index);AccessibleDescription=snapshot.UniqueFiles+" уникальных файлов, "+RecoveryResultsSnapshot.FormatBytes(snapshot.TotalBytes)+". Открываются или проверены CRC: "+snapshot.CheckedFiles+". С повреждениями: "+snapshot.AttentionFiles+". Нужна проверка: "+snapshot.UnknownFiles+". "+String.Join(", ",snapshot.Categories.Where(c=>c.Count>0).Select(c=>c.Name+": "+c.Count));Restart();}
        bool CanAnimate(){return !compact&&!reduceMotion&&MotionSettings.Allowed&&Visible&&IsHandleCreated&&!IsDisposed&&!Disposing&&snapshot.UniqueFiles>0;}
        void Finish(){timer.Stop();stopwatch.Reset();reveal=1;Invalidate();}
        void Restart(){if(CanAnimate()){reveal=0;stopwatch.Restart();timer.Start();}else Finish();Invalidate();}
        void MotionChanged(object sender,EventArgs e){if(IsDisposed||Disposing)return;if(InvokeRequired){if(IsHandleCreated)try{BeginInvoke(new Action(()=>{if(!IsDisposed&&!Disposing)Restart();}));}catch(InvalidOperationException){}return;}Restart();}
        protected override void OnHandleCreated(EventArgs e){base.OnHandleCreated(e);Restart();}
        protected override void OnVisibleChanged(EventArgs e){base.OnVisibleChanged(e);Restart();}
        protected override void OnHandleDestroyed(EventArgs e){timer.Stop();stopwatch.Reset();base.OnHandleDestroyed(e);}
        protected override void Dispose(bool disposing){if(disposing){MotionSettings.Changed-=MotionChanged;timer.Stop();stopwatch.Stop();timer.Dispose();tip.Dispose();}base.Dispose(disposing);}
        void TextAt(Graphics g,string text,Rectangle rectangle,float size,Color color,bool bold=false,TextFormatFlags flags=TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis)
        {using(var font=new Font("Segoe UI",size,bold?FontStyle.Bold:FontStyle.Regular))TextRenderer.DrawText(g,text,font,rectangle,color,flags|TextFormatFlags.SingleLine|TextFormatFlags.NoPrefix);}
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);targets.Clear();var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
            using(var line=new Pen(UiTheme.Border))g.DrawRectangle(line,0,0,Math.Max(0,Width-1),Math.Max(0,Height-1));
            if(Width<200||Height<25)return;
            if(compact||Height<90){DrawCompact(g);return;}
            int divider1=Width>=1040?184:152,divider2=Width>=1040?342:286;int qualityWidth=Width>=1040?274:236,qualityX=Width-qualityWidth-18;
            using(var line=new Pen(UiTheme.Border)){g.DrawLine(line,divider1,18,divider1,Height-18);g.DrawLine(line,divider2,18,divider2,Height-18);}
            TextAt(g,"УНИКАЛЬНЫХ ФАЙЛОВ",new Rectangle(16,12,divider1-30,22),8,UiTheme.Muted,true);
            TextAt(g,snapshot.UniqueFiles.ToString("N0"),new Rectangle(16,34,divider1-30,45),28,UiTheme.Text,true);
            string variants=snapshot.Candidates>=snapshot.UniqueFiles?snapshot.Candidates.ToString("N0")+" кандидатов":"Все находки";
            TextAt(g,variants,new Rectangle(16,84,divider1-30,23),8.5F,UiTheme.Muted);
            TextAt(g,"ОБЪЁМ НАХОДОК",new Rectangle(divider1+16,12,divider2-divider1-30,22),8,UiTheme.Muted,true);
            TextAt(g,(snapshot.SizeClipped?"≥ ":"")+RecoveryResultsSnapshot.FormatBytes(snapshot.TotalBytes),new Rectangle(divider1+16,38,divider2-divider1-30,36),19,UiTheme.Text,true);
            TextAt(g,snapshot.UnknownSizeFiles>0?"Есть неизвестный размер":"Без повторных копий",new Rectangle(divider1+16,84,divider2-divider1-30,23),8.5F,UiTheme.Muted);
            int chartX=divider2+20,chartWidth=Math.Max(40,qualityX-chartX-24);
            TextAt(g,"ТИПЫ ФАЙЛОВ",new Rectangle(chartX,12,chartWidth,22),8,UiTheme.Muted,true);
            Rectangle bar=new Rectangle(chartX,43,chartWidth,10);using(var brush=new SolidBrush(Color.FromArgb(237,241,247)))g.FillRectangle(brush,bar);
            float x=bar.X;int assigned=0;var nonempty=snapshot.Categories.Where(c=>c.Count>0).ToArray();
            for(int i=0;i<nonempty.Length;i++){var category=nonempty[i];int raw=i==nonempty.Length-1?chartWidth-assigned:(int)Math.Round((double)chartWidth*category.Count/Math.Max(1,snapshot.UniqueFiles));raw=Math.Max(0,Math.Min(raw,chartWidth-assigned));assigned+=raw;float w=(float)(raw*reveal);if(w>0)using(var brush=new SolidBrush(category.Color))g.FillRectangle(brush,x,bar.Y,w,bar.Height);x+=raw;}
            if(snapshot.UniqueFiles==0){TextAt(g,"Пока ничего не найдено",new Rectangle(chartX,60,chartWidth,28),9,UiTheme.Muted);}
            else {int cols=chartWidth>=350?3:2;var categories=snapshot.Categories.Where(c=>c.Count>0).ToArray();for(int i=0;i<categories.Length;i++){var category=categories[i];int column=i%cols,row=i/cols;int cellWidth=Math.Max(1,chartWidth/cols);var cell=new Rectangle(chartX+column*cellWidth,61+row*18,cellWidth,18);using(var brush=new SolidBrush(category.Color))g.FillEllipse(brush,cell.X,cell.Y+6,6,6);TextAt(g,category.Name+" "+category.Count,new Rectangle(cell.X+10,cell.Y,Math.Max(1,cell.Width-12),cell.Height),8.1F,UiTheme.Muted);targets.Add(new KeyValuePair<Rectangle,string>(cell,category.Name));}}
            TextAt(g,"ПРОВЕРКА ФАЙЛОВ",new Rectangle(qualityX,12,qualityWidth,22),8,UiTheme.Muted,true);
            QualityRow(g,qualityX,39,qualityWidth,"Открываются / CRC",snapshot.CheckedFiles,Color.FromArgb(54,139,109));
            QualityRow(g,qualityX,63,qualityWidth,"С повреждениями",snapshot.AttentionFiles,Color.FromArgb(190,116,48));
            QualityRow(g,qualityX,87,qualityWidth,"Нужна проверка",snapshot.UnknownFiles,Color.FromArgb(147,159,177));
        }
        void QualityRow(Graphics g,int x,int y,int width,string label,int count,Color color)
        {using(var brush=new SolidBrush(color))g.FillEllipse(brush,x,y+7,7,7);TextAt(g,label,new Rectangle(x+14,y,width-60,22),8.7F,UiTheme.Muted);TextAt(g,count.ToString("N0"),new Rectangle(x+width-48,y,48,22),10,UiTheme.Text,true,TextFormatFlags.Right|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);}
        void DrawCompact(Graphics g)
        {
            int width=Math.Max(1,Width-32);string text=snapshot.UniqueFiles.ToString("N0")+" уникальных · "+(snapshot.SizeClipped?"≥ ":"")+RecoveryResultsSnapshot.FormatBytes(snapshot.TotalBytes);
            TextAt(g,text,new Rectangle(14,2,Math.Min(300,width/2),Height-4),10,UiTheme.Text,true);
            string detail=snapshot.UniqueFiles==0?"Нет находок в доступных источниках":"Открываются / CRC: "+snapshot.CheckedFiles+"   ·   С повреждениями: "+snapshot.AttentionFiles+"   ·   Проверить: "+snapshot.UnknownFiles;
            TextAt(g,detail,new Rectangle(Math.Min(320,width/2+18),2,Math.Max(1,width-Math.Min(304,width/2)),Height-4),8.5F,UiTheme.Muted);
        }
        protected override void OnMouseMove(MouseEventArgs e){base.OnMouseMove(e);Cursor=targets.Any(t=>t.Key.Contains(e.Location))?Cursors.Hand:Cursors.Default;}
        protected override void OnMouseLeave(EventArgs e){Cursor=Cursors.Default;base.OnMouseLeave(e);}
        protected override void OnMouseClick(MouseEventArgs e){base.OnMouseClick(e);if(e.Button!=MouseButtons.Left)return;foreach(var target in targets)if(target.Key.Contains(e.Location)){var handler=CategoryPicked;if(handler!=null)handler(this,new RecoveryCategoryEventArgs(target.Value));break;}}
    }
}
