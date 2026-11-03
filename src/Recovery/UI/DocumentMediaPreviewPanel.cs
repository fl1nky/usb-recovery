using System;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class DocumentMediaPreviewPanel : UserControl
    {
        readonly FlowLayoutPanel tools=new FlowLayoutPanel();readonly Panel viewport=new Panel();readonly PictureBox image=new PictureBox();readonly Label pageLabel=new Label(),status=new Label();readonly Button previous=new Button(),next=new Button(),fit=new Button(),rotate=new Button(),expand=new Button();readonly NumericUpDown pageInput=new NumericUpDown();readonly ComboBox zoom=new ComboBox();
        string source,sha;long bytes;bool pdf,fitPage=true,changing,fullscreen,arranging;int page,pages,generation,rotation;double zoomFactor=1;Image raster;CancellationTokenSource cancellation;LocalMediaPreviewSession video;
        public event Action<string> MessageChanged;
        public DocumentMediaPreviewPanel()
        {
            Dock=DockStyle.Fill;BackColor=Color.White;tools.Dock=DockStyle.Top;tools.AutoSize=true;tools.WrapContents=true;tools.Padding=new Padding(0,2,0,2);tools.Margin=Padding.Empty;
            previous.Text="‹";previous.AccessibleName="Предыдущая страница";next.Text="›";next.AccessibleName="Следующая страница";previous.Width=next.Width=30;pageInput.Minimum=1;pageInput.Maximum=5000;pageInput.Width=55;pageInput.AccessibleName="Страница PDF";pageLabel.AutoSize=true;pageLabel.Margin=new Padding(0,7,2,0);
            zoom.DropDownStyle=ComboBoxStyle.DropDownList;zoom.Width=68;zoom.Items.AddRange(new object[]{"25%","50%","75%","100%","125%","150%","200%","300%"});zoom.SelectedIndex=3;fit.Text="Вписать";rotate.Text="↻";rotate.AccessibleName="Повернуть страницу";rotate.Width=32;fit.AutoSize=true;expand.Text="Окно";expand.AutoSize=true;expand.AccessibleName="Открыть просмотр в отдельном окне";
            tools.Controls.AddRange(new Control[]{previous,pageInput,pageLabel,next,zoom,fit,rotate,expand});
            viewport.Dock=DockStyle.Fill;viewport.AutoScroll=true;viewport.BackColor=Color.FromArgb(242,242,242);image.SizeMode=PictureBoxSizeMode.StretchImage;viewport.Controls.Add(image);status.Dock=DockStyle.Bottom;status.AutoEllipsis=true;status.Height=42;status.Font=new Font("Segoe UI",8);status.ForeColor=UiTheme.Muted;status.Padding=new Padding(2,3,2,0);Controls.Add(viewport);Controls.Add(status);Controls.Add(tools);
            previous.Click+=delegate{Navigate(page-1);};next.Click+=delegate{Navigate(page+1);};pageInput.ValueChanged+=delegate{if(!changing)Navigate((int)pageInput.Value-1);};rotate.Click+=delegate{rotation=(rotation+90)%360;ShowRaster();};fit.Click+=delegate{fitPage=true;ShowRaster();};zoom.SelectedIndexChanged+=delegate{if(changing)return;zoomFactor=Double.Parse(zoom.Text.TrimEnd('%'),System.Globalization.CultureInfo.InvariantCulture)/100;fitPage=false;ShowRaster();};expand.Click+=delegate{OpenWindow();};viewport.Resize+=delegate{if(fitPage)ShowRaster();if(video!=null)video.Resize(viewport.Handle,viewport.ClientSize.Width,viewport.ClientSize.Height);};
        }
        void Message(string value){status.Text=value;var handler=MessageChanged;if(handler!=null)handler(value);}
        public static bool Supports(string path){string ext=Path.GetExtension(path).ToLowerInvariant();return ext==".pdf"||LocalMediaPreviewWorker.Supports(ext);}
        public void ShowFile(string path,long length,string hash)
        {
            Stop();source=path;bytes=length;sha=hash;pdf=Path.GetExtension(path).Equals(".pdf",StringComparison.OrdinalIgnoreCase);page=0;pages=0;rotation=0;fitPage=true;zoomFactor=1;
            foreach(Control control in new Control[]{previous,next,pageInput,pageLabel,zoom,fit,rotate})control.Visible=pdf;expand.Visible=!fullscreen;Visible=true;image.Visible=pdf;
            if(pdf)RenderPage();else{
                Message("Проверка SHA256 и открытие локального видео…");try{
                    video=new LocalMediaPreviewSession(viewport.Handle,path,length,hash);int current=generation;video.Changed+=delegate(LocalMediaPreviewState state){try{if(!IsDisposed&&IsHandleCreated)BeginInvoke(new Action(()=>{if(!IsDisposed&&current==generation)Message(LocalMediaPreviewWorker.Message(state.Code));}));}catch(InvalidOperationException){} };if(video.LastState!=null)Message(LocalMediaPreviewWorker.Message(video.LastState.Code));
                }catch(IOException){Message("Не удалось запустить изолированный просмотр видео.");}
            }
        }
        public void Stop()
        {
            generation++;if(cancellation!=null){cancellation.Cancel();cancellation.Dispose();cancellation=null;}if(video!=null){video.Dispose();video=null;}if(image.Image!=null){image.Image.Dispose();image.Image=null;}if(raster!=null){raster.Dispose();raster=null;}source=null;
        }
        void Navigate(int value){if(!pdf||value<0||pages>0&&value>=pages)return;page=value;RenderPage();}
        async void RenderPage()
        {
            int current=++generation;if(cancellation!=null){cancellation.Cancel();cancellation.Dispose();}cancellation=new CancellationTokenSource();CancellationToken token=cancellation.Token;previous.Enabled=next.Enabled=pageInput.Enabled=false;
            if(image.Image!=null){image.Image.Dispose();image.Image=null;}if(raster!=null){raster.Dispose();raster=null;}Message("Проверка SHA256 и отрисовка страницы PDF…");
            DocumentPreviewWorker.Result result;
            try{string path=source,digest=sha;long length=bytes;int requested=page;result=await Task.Run(()=>DocumentPreviewWorker.Read(path,length,digest,requested,900,token)).ConfigureAwait(false);}catch(OperationCanceledException){return;}catch{result=new DocumentPreviewWorker.Result{Code="PREVIEW_WORKER_FAILED"};}
            if(IsDisposed||!IsHandleCreated||current!=generation)return;
            var ready=result;try{BeginInvoke(new Action(()=>{if(!IsDisposed&&current==generation)ApplyPage(ready);}));}catch(InvalidOperationException){}
        }
        void ApplyPage(DocumentPreviewWorker.Result result)
        {
            if(result.Code!="PDF_RENDERED"){Message(DocumentPreviewWorker.Message(result.Code));return;}
            try{
                byte[] png=Convert.FromBase64String(result.Png);
                if(png.Length<24||png[0]!=137||png[1]!=80||png[2]!=78||png[3]!=71||Read32(png,16)!=result.Width||Read32(png,20)!=result.Height)throw new IOException();
                using(var memory=new MemoryStream(png,false))using(var original=Image.FromStream(memory,true,true))raster=new Bitmap(original);
                pages=result.Pages;changing=true;pageInput.Maximum=pages;pageInput.Value=page+1;changing=false;pageLabel.Text="/ "+pages;previous.Enabled=page>0;next.Enabled=page+1<pages;pageInput.Enabled=true;ShowRaster();Message("Страница "+(page+1)+" из "+pages+" · SHA256 совпал. Отрисовка не доказывает исходную полноту.");
            }catch{Message("Не удалось прочитать отрисованную страницу. Кандидат сохранён.");}
        }
        static int Read32(byte[] data,int at){return (data[at]<<24)|(data[at+1]<<16)|(data[at+2]<<8)|data[at+3];}
        void ShowRaster()
        {
            if(raster==null||!pdf||arranging)return;arranging=true;try{var display=new Bitmap(raster);if(rotation==90)display.RotateFlip(RotateFlipType.Rotate90FlipNone);else if(rotation==180)display.RotateFlip(RotateFlipType.Rotate180FlipNone);else if(rotation==270)display.RotateFlip(RotateFlipType.Rotate270FlipNone);
            double factor=fitPage?Math.Min(Math.Max(1,viewport.ClientSize.Width-20)/(double)display.Width,Math.Max(1,viewport.ClientSize.Height-20)/(double)display.Height):zoomFactor*1200.0/raster.Width;
            int width=Math.Max(1,(int)Math.Round(display.Width*factor)),height=Math.Max(1,(int)Math.Round(display.Height*factor));var old=image.Image;image.Image=display;image.Size=new Size(width,height);image.Location=new Point(Math.Max(0,(viewport.ClientSize.Width-width)/2),Math.Max(0,(viewport.ClientSize.Height-height)/2));viewport.AutoScrollMinSize=new Size(width,height);if(old!=null)old.Dispose();
            }finally{arranging=false;}
        }
        void OpenWindow()
        {
            if(source==null)return;string path=source,digest=sha;long length=bytes;
            // Stop the embedded decoder before creating a second window, so the
            // same selection never plays two audio streams at once.
            if(video!=null){video.Dispose();video=null;}
            using(var window=new Form{Text=Path.GetFileName(path)+" — просмотр",ClientSize=new Size(1060,800),MinimumSize=new Size(640,480),StartPosition=FormStartPosition.CenterParent,KeyPreview=true})using(var panel=new DocumentMediaPreviewPanel{fullscreen=true}){
                window.Controls.Add(panel);window.Shown+=delegate{panel.ShowFile(path,length,digest);};window.FormClosing+=delegate{panel.Stop();};window.KeyDown+=delegate(object sender,KeyEventArgs e){if(e.KeyCode==Keys.Escape){window.Close();e.Handled=true;}};window.ShowDialog(FindForm());
            }
            if(!IsDisposed&&source==path&&!pdf)ShowFile(path,length,digest);
        }
        protected override bool ProcessCmdKey(ref System.Windows.Forms.Message message,Keys keyData)
        {
            if(pdf){if(keyData==Keys.PageDown){Navigate(page+1);return true;}if(keyData==Keys.PageUp){Navigate(page-1);return true;}if(keyData==(Keys.Control|Keys.Home)){Navigate(0);return true;}if(keyData==(Keys.Control|Keys.End)&&pages>0){Navigate(pages-1);return true;}if(keyData==(Keys.Control|Keys.D0)){fitPage=true;ShowRaster();return true;}if(keyData==(Keys.Control|Keys.R)){rotation=(rotation+90)%360;ShowRaster();return true;}if(keyData==(Keys.Control|Keys.Add)||keyData==(Keys.Control|Keys.Oemplus)){zoom.SelectedIndex=Math.Min(zoom.Items.Count-1,zoom.SelectedIndex+1);return true;}if(keyData==(Keys.Control|Keys.Subtract)||keyData==(Keys.Control|Keys.OemMinus)){zoom.SelectedIndex=Math.Max(0,zoom.SelectedIndex-1);return true;}}
            if(keyData==(Keys.Control|Keys.Enter)&&!fullscreen){OpenWindow();return true;}return base.ProcessCmdKey(ref message,keyData);
        }
        protected override void Dispose(bool disposing){if(disposing)Stop();base.Dispose(disposing);}
    }
}
