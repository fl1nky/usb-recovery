using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.Integration;
using System.Windows.Media;

namespace UsbRecovery
{
    public sealed class LocalMediaPreviewState
    {
        public int Protocol=1, Width, Height, Rotation;
        public string Code, State;
        public double Position, Duration, Volume;
    }
    public sealed class LocalMediaPreviewSession : IDisposable
    {
        readonly Process process=new Process();readonly ProcessJob job=new ProcessJob(768L*1024*1024);readonly object gate=new object();Task outgoing=Task.FromResult(0);
        readonly System.Threading.Timer watchdog;readonly Stopwatch wall=Stopwatch.StartNew();long last;bool opened;int disposed,terminal;
        public event Action<LocalMediaPreviewState> Changed;
        public LocalMediaPreviewState LastState {get;private set;}
        public int ProcessId {get;private set;}
        public LocalMediaPreviewSession(IntPtr parent,string source,long bytes,string sha)
        {
            process.StartInfo=new ProcessStartInfo(typeof(Program).Assembly.Location,"--local-media-preview-worker"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=new UTF8Encoding(false,true)};
            try{
                process.Start();ProcessId=process.Id;job.Attach(process);last=Stopwatch.GetTimestamp();
                byte[] input=new UTF8Encoding(false).GetBytes(DocumentPreviewWorker.Json().Serialize(new LocalMediaPreviewWorker.Request{Parent=parent.ToInt64(),Source=source,Bytes=bytes,Sha256=sha})+"\n");
                process.StandardInput.BaseStream.Write(input,0,input.Length);process.StandardInput.BaseStream.Flush();
                Task.Run(()=>{try{byte[] buffer=new byte[4096];while(process.StandardError.BaseStream.Read(buffer,0,buffer.Length)>0){} }catch{} });
                Task.Run(()=>{
                    try{
                        string line;int events=0;
                        while((line=DocumentPreviewWorker.Line(process.StandardOutput,16384))!=null){
                            if(++events>200000)throw new IOException();var state=DocumentPreviewWorker.Json().Deserialize<LocalMediaPreviewState>(line);
                            if(state==null||state.Protocol!=1||!new[]{"verifying","opening","paused","playing","ended","error"}.Contains(state.State)||String.IsNullOrEmpty(state.Code)||state.Code.Length>70||Double.IsNaN(state.Position)||Double.IsNaN(state.Duration)||Double.IsInfinity(state.Position)||Double.IsInfinity(state.Duration)||state.Position<0||state.Duration<0||state.Duration>604800||state.Position>state.Duration+5||state.Volume<0||state.Volume>1||state.Width<0||state.Height<0||state.Width>32768||state.Height>32768)throw new IOException();
                            Interlocked.Exchange(ref last,Stopwatch.GetTimestamp());if(state.State=="paused"||state.State=="playing"||state.State=="ended")opened=true;Notify(state);
                        }
                        if(Volatile.Read(ref disposed)==0)Notify(new LocalMediaPreviewState{State="error",Code="VIDEO_WORKER_CLOSED"});
                    }catch{if(Volatile.Read(ref disposed)==0){job.Stop();Notify(new LocalMediaPreviewState{State="error",Code="VIDEO_WORKER_FAILED"});}}
                });
                watchdog=new System.Threading.Timer(delegate{
                    if(Volatile.Read(ref disposed)!=0)return;
                    double silent=(Stopwatch.GetTimestamp()-Interlocked.Read(ref last))/(double)Stopwatch.Frequency;
                    if(silent>(opened?15:120)||wall.Elapsed.TotalHours>12){job.Stop();Notify(new LocalMediaPreviewState{State="error",Code="VIDEO_PREVIEW_TIMEOUT"});}
                },null,1000,1000);
            }catch{job.Stop();job.Dispose();process.Dispose();throw new IOException("VIDEO_WORKER_FAILED");}
        }
        void Notify(LocalMediaPreviewState state){if(Volatile.Read(ref disposed)!=0||Volatile.Read(ref terminal)!=0)return;if(state.State=="error")Interlocked.Exchange(ref terminal,1);LastState=state;var handler=Changed;if(handler!=null)try{handler(state);}catch{} }
        public void Command(string name,double value=0)
        {
            if(Volatile.Read(ref disposed)!=0)return;
            lock(gate){outgoing=outgoing.ContinueWith(ignored=>{if(Volatile.Read(ref disposed)!=0)return;try{process.StandardInput.WriteLine(DocumentPreviewWorker.Json().Serialize(new LocalMediaPreviewWorker.Command{Action=name,Value=value}));process.StandardInput.Flush();}catch{job.Stop();}},TaskScheduler.Default);}
        }
        public void Resize(IntPtr parent,int width,int height){if(Volatile.Read(ref disposed)==0)LocalMediaPreviewWorker.ResizeChildren(parent,width,height);}
        public void Dispose()
        {
            if(Interlocked.Exchange(ref disposed,1)!=0)return;if(watchdog!=null)watchdog.Dispose();job.Stop();job.Dispose();process.Dispose();
        }
    }
    public static class LocalMediaPreviewWorker
    {
        public sealed class Request {public int Protocol=1;public long Parent;public string Source,Sha256;public long Bytes;}
        public sealed class Command {public string Action;public double Value;}
        [DllImport("user32.dll")] static extern IntPtr SetParent(IntPtr child,IntPtr parent);
        [DllImport("user32.dll",EntryPoint="GetWindowLong")] static extern int GetStyle(IntPtr window,int index);
        [DllImport("user32.dll",EntryPoint="SetWindowLong")] static extern int SetStyle(IntPtr window,int index,int value);
        [DllImport("user32.dll")] static extern bool MoveWindow(IntPtr window,int x,int y,int width,int height,bool repaint);
        [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr window,out RECT rectangle);
        [DllImport("user32.dll")] static extern bool IsWindow(IntPtr window);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent,EnumWindow callback,IntPtr data);
        delegate bool EnumWindow(IntPtr window,IntPtr data);
        [StructLayout(LayoutKind.Sequential)] struct RECT {public int Left,Top,Right,Bottom;}
        internal static void ResizeChildren(IntPtr parent,int width,int height){EnumChildWindows(parent,delegate(IntPtr window,IntPtr data){if(GetParent(window)==parent)MoveWindow(window,0,0,Math.Max(1,width),Math.Max(1,height),true);return true;},IntPtr.Zero);}
        [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr window);
        static readonly object outputGate=new object();
        static void Emit(LocalMediaPreviewState state){lock(outputGate){var bytes=new UTF8Encoding(false).GetBytes(DocumentPreviewWorker.Json().Serialize(state)+"\n");var stream=Console.OpenStandardOutput();stream.Write(bytes,0,bytes.Length);stream.Flush();}}
        static uint Be(byte[] bytes,int offset){return ((uint)bytes[offset]<<24)|((uint)bytes[offset+1]<<16)|((uint)bytes[offset+2]<<8)|bytes[offset+3];}
        sealed class Orientation {public int Degrees,Width,Height;}
        struct Box {public long Start,Data,End;public string Type;}
        static List<Box> Boxes(FileStream file,long start,long end,ref int count)
        {
            var boxes=new List<Box>();var header=new byte[16];
            while(start<end){if(++count>100000||end-start<8)throw new IOException("VIDEO_CONTAINER_UNREADABLE");file.Position=start;if(file.Read(header,0,8)!=8)throw new IOException("VIDEO_CONTAINER_UNREADABLE");ulong size=Be(header,0);int offset=8;
                if(size==1){if(end-start<16||file.Read(header,8,8)!=8)throw new IOException("VIDEO_CONTAINER_UNREADABLE");size=((ulong)Be(header,8)<<32)|Be(header,12);offset=16;}if(size==0)size=(ulong)(end-start);if(size<(ulong)offset||size>(ulong)(end-start))throw new IOException("VIDEO_CONTAINER_UNREADABLE");
                boxes.Add(new Box{Start=start,Data=start+offset,End=start+(long)size,Type=Encoding.ASCII.GetString(header,4,4)});start+=(long)size;
            }return boxes;
        }
        static Orientation Inspect(FileStream file,string extension)
        {
            var orientation=new Orientation();byte[] signature=new byte[16];if(file.Read(signature,0,16)<12)throw new IOException("VIDEO_CONTAINER_UNREADABLE");file.Position=0;
            if(new[]{".mp4",".mov",".m4v",".m4a"}.Contains(extension)){
                int count=0;var roots=Boxes(file,0,file.Length,ref count);if(!roots.Any(x=>x.Type=="moov")||!roots.Any(x=>x.Type=="mdat"))throw new IOException("VIDEO_CONTAINER_UNREADABLE");
                foreach(var moov in roots.Where(x=>x.Type=="moov")){
                    var movie=Boxes(file,moov.Data,moov.End,ref count);if(movie.Any(x=>x.Type=="rmra"||x.Type=="rmda"||x.Type=="rdrf"))throw new IOException("VIDEO_EXTERNAL_REFERENCE");
                    foreach(var track in movie.Where(x=>x.Type=="trak")){
                    var children=Boxes(file,track.Data,track.End,ref count);bool video=false;
                    if(children.Any(x=>x.Type=="rmra"||x.Type=="rmda"||x.Type=="rdrf"))throw new IOException("VIDEO_EXTERNAL_REFERENCE");
                    foreach(var media in children.Where(x=>x.Type=="mdia"))foreach(var entry in Boxes(file,media.Data,media.End,ref count)){
                        if(entry.Type=="hdlr"&&entry.End-entry.Data>=12){byte[] handler=new byte[12];file.Position=entry.Data;file.Read(handler,0,12);video=Encoding.ASCII.GetString(handler,8,4)=="vide";}
                        if(entry.Type=="minf")foreach(var dinf in Boxes(file,entry.Data,entry.End,ref count).Where(x=>x.Type=="dinf"))foreach(var dref in Boxes(file,dinf.Data,dinf.End,ref count).Where(x=>x.Type=="dref")){
                            if(dref.End-dref.Data<8)throw new IOException("VIDEO_CONTAINER_UNREADABLE");foreach(var reference in Boxes(file,dref.Data+8,dref.End,ref count)){
                                byte[] flags=new byte[4];file.Position=reference.Data;if(reference.End-reference.Data<4||file.Read(flags,0,4)!=4||(Be(flags,0)&1)==0)throw new IOException("VIDEO_EXTERNAL_REFERENCE");
                            }
                        }
                    }
                    if(video)foreach(var header in children.Where(x=>x.Type=="tkhd")){
                        if(header.End-header.Data>1024||header.End-header.Data<84)throw new IOException("VIDEO_CONTAINER_UNREADABLE");var bytes=new byte[(int)(header.End-header.Data)];file.Position=header.Data;file.Read(bytes,0,bytes.Length);int matrix=bytes[0]==0?40:bytes[0]==1?52:-1;if(matrix<0||bytes.Length<matrix+44)throw new IOException("VIDEO_CONTAINER_UNREADABLE");
                        int a=(int)Be(bytes,matrix),b=(int)Be(bytes,matrix+4),c=(int)Be(bytes,matrix+12),d=(int)Be(bytes,matrix+16);
                        if(a==0&&b==65536&&c==-65536&&d==0)orientation.Degrees=90;else if(a==-65536&&b==0&&c==0&&d==-65536)orientation.Degrees=180;else if(a==0&&b==-65536&&c==65536&&d==0)orientation.Degrees=270;else if(a!=65536||b!=0||c!=0||d!=65536)throw new IOException("VIDEO_TRANSFORM_UNSUPPORTED");
                        orientation.Width=(int)(Be(bytes,matrix+36)>>16);orientation.Height=(int)(Be(bytes,matrix+40)>>16);
                    }
                }}
            }else{
                bool riff=Encoding.ASCII.GetString(signature,0,4)=="RIFF"&&(Encoding.ASCII.GetString(signature,8,4)=="AVI "||Encoding.ASCII.GetString(signature,8,4)=="WAVE");
                bool mp3=Encoding.ASCII.GetString(signature,0,3)=="ID3"||signature[0]==255&&(signature[1]&224)==224;
                bool binary=riff||mp3||Encoding.ASCII.GetString(signature,0,4)=="fLaC"||Encoding.ASCII.GetString(signature,0,4)=="OggS"||signature[0]==0x1a&&signature[1]==0x45&&signature[2]==0xdf&&signature[3]==0xa3;
                if(!binary)throw new IOException("VIDEO_CONTAINER_UNSUPPORTED");
            }file.Position=0;return orientation;
        }
        public static bool Supports(string extension){return new[]{".mp4",".mov",".m4v",".avi",".mkv",".webm",".m4a",".mp3",".aac",".wav",".flac",".ogg"}.Contains((extension??"").ToLowerInvariant());}
        sealed class Player : Form
        {
            readonly System.Windows.Controls.MediaElement media=new System.Windows.Controls.MediaElement();readonly ElementHost host=new ElementHost();readonly Button play=new Button();readonly TrackBar seek=new TrackBar(),volume=new TrackBar();readonly Label clock=new Label();readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
            readonly Request request;readonly Orientation orientation;bool opened,playing,ended,dragging,update;double duration;int rotation;string code="VIDEO_OPENING";readonly Stopwatch started=Stopwatch.StartNew();
            public Player(Request source,Orientation transform)
            {
                request=source;orientation=transform;Text="Локальный просмотр";FormBorderStyle=FormBorderStyle.None;ShowInTaskbar=false;BackColor=System.Drawing.Color.White;Font=new Font("Segoe UI",9);KeyPreview=true;
                host.Dock=DockStyle.Fill;host.BackColor=System.Drawing.Color.Black;host.Child=media;Controls.Add(host);
                var controls=new TableLayoutPanel{Dock=DockStyle.Bottom,Height=92,ColumnCount=3,RowCount=3,Padding=new Padding(4)};controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,65));controls.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,60));for(int i=0;i<3;i++)controls.RowStyles.Add(new RowStyle(SizeType.Percent,33.33F));
                play.Text="▶";play.Dock=DockStyle.Fill;play.Enabled=false;play.Click+=delegate{Toggle();};controls.Controls.Add(play,0,0);clock.Dock=DockStyle.Fill;clock.TextAlign=ContentAlignment.MiddleLeft;controls.Controls.Add(clock,1,0);controls.SetColumnSpan(clock,2);
                seek.Dock=DockStyle.Fill;seek.AutoSize=false;seek.TickStyle=TickStyle.None;seek.Maximum=10000;seek.Enabled=false;seek.MouseDown+=delegate{dragging=true;};seek.MouseUp+=delegate{dragging=false;Seek(seek.Value/10000.0*duration);};seek.KeyUp+=delegate{Seek(seek.Value/10000.0*duration);};controls.Controls.Add(seek,0,1);controls.SetColumnSpan(seek,3);
                controls.Controls.Add(new Label{Text="Звук",Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft},0,2);volume.Dock=DockStyle.Fill;volume.AutoSize=false;volume.TickStyle=TickStyle.None;volume.Maximum=100;volume.Value=60;volume.ValueChanged+=delegate{if(!update)media.Volume=volume.Value/100.0;};controls.Controls.Add(volume,1,2);var stop=new Button{Text="■",Dock=DockStyle.Fill};stop.Click+=delegate{media.Pause();media.Position=TimeSpan.Zero;playing=false;ended=false;Publish();};controls.Controls.Add(stop,2,2);Controls.Add(controls);
                media.LoadedBehavior=System.Windows.Controls.MediaState.Manual;media.UnloadedBehavior=System.Windows.Controls.MediaState.Manual;media.Stretch=Stretch.Uniform;media.ScrubbingEnabled=true;media.Volume=.6;
                media.MediaOpened+=delegate{
                    if(!media.NaturalDuration.HasTimeSpan||media.NaturalDuration.TimeSpan.TotalSeconds<=0||media.NaturalDuration.TimeSpan.TotalDays>7){Fail("VIDEO_DURATION_UNAVAILABLE");return;}
                    duration=media.NaturalDuration.TimeSpan.TotalSeconds;if(media.NaturalVideoWidth>32768||media.NaturalVideoHeight>32768||(long)media.NaturalVideoWidth*media.NaturalVideoHeight>64000000){Fail("VIDEO_PIXEL_LIMIT");return;}
                    rotation=orientation.Degrees;
                    if((rotation==90||rotation==270)&&orientation.Width!=orientation.Height&&media.NaturalVideoWidth==orientation.Height&&media.NaturalVideoHeight==orientation.Width)rotation=0;
                    if(rotation!=0)media.LayoutTransform=new RotateTransform(rotation);opened=true;playing=false;ended=false;code="VIDEO_READY";play.Enabled=seek.Enabled=true;media.Pause();media.Position=TimeSpan.Zero;Publish();
                };
                media.MediaEnded+=delegate{media.Pause();playing=false;ended=true;code="VIDEO_ENDED";Publish();};
                media.MediaFailed+=delegate{Fail("VIDEO_UNREADABLE_OR_CODEC_UNAVAILABLE");};
                timer.Interval=250;timer.Tick+=delegate{if(!IsWindow(new IntPtr(request.Parent))){Close();return;}if(!opened&&started.Elapsed.TotalSeconds>30){Fail("VIDEO_OPEN_TIMEOUT");return;}Publish();};
                Shown+=delegate{IntPtr parent=new IntPtr(request.Parent);if(!IsWindow(parent)){Close();return;}LocalMediaPreviewWorker.SetStyle(Handle,-16,(LocalMediaPreviewWorker.GetStyle(Handle,-16)&~unchecked((int)0x80000000))|0x40000000);SetParent(Handle,parent);RECT r;GetClientRect(parent,out r);MoveWindow(Handle,0,0,Math.Max(1,r.Right),Math.Max(1,r.Bottom),true);timer.Start();media.Source=new Uri(request.Source,UriKind.Absolute);media.Play();media.Pause();};
                FormClosed+=delegate{timer.Stop();timer.Dispose();media.Stop();media.Close();host.Dispose();};
                KeyDown+=delegate(object sender,KeyEventArgs e){if(e.KeyCode==Keys.Space){Toggle();e.Handled=true;}else if(e.KeyCode==Keys.Left||e.KeyCode==Keys.Right){Seek(media.Position.TotalSeconds+(e.KeyCode==Keys.Left?-5:5));e.Handled=true;}else if(e.KeyCode==Keys.Home){Seek(0);e.Handled=true;}else if(e.KeyCode==Keys.End){Seek(duration);e.Handled=true;}else if(e.KeyCode==Keys.Escape){Command(new Command{Action="pause"});}};
            }
            void Fail(string value){code=value;playing=false;media.Close();play.Enabled=seek.Enabled=false;clock.Text=Message(value);timer.Stop();Emit(new LocalMediaPreviewState{State="error",Code=value});}
            void Toggle(){if(!opened)return;if(playing){media.Pause();playing=false;}else{if(ended||media.Position.TotalSeconds>=duration-.05)media.Position=TimeSpan.Zero;ended=false;media.Play();playing=true;}Publish();}
            void Seek(double seconds){if(!opened||Double.IsInfinity(seconds)||Double.IsNaN(seconds))return;media.Position=TimeSpan.FromSeconds(Math.Max(0,Math.Min(duration,seconds)));ended=false;Publish();}
            public void Command(Command command)
            {
                if(command==null||Double.IsNaN(command.Value)||Double.IsInfinity(command.Value))return;
                switch(command.Action){case "play":if(!playing)Toggle();break;case "pause":if(playing)Toggle();break;case "seek":Seek(command.Value);break;case "volume":media.Volume=Math.Max(0,Math.Min(1,command.Value));update=true;volume.Value=(int)(media.Volume*100);update=false;break;case "state":break;case "close":Close();return;default:Fail("VIDEO_COMMAND_INVALID");return;}Publish();
            }
            static string Time(double seconds){return TimeSpan.FromSeconds(Math.Max(0,seconds)).ToString(seconds>=3600?@"h\:mm\:ss":@"m\:ss");}
            void Publish()
            {
                double position=opened?Math.Max(0,Math.Min(duration,media.Position.TotalSeconds)):0;play.Text=playing?"Ⅱ":"▶";clock.Text=Time(position)+" / "+Time(duration);if(!dragging)seek.Value=duration>0?(int)Math.Max(0,Math.Min(10000,position/duration*10000)):0;
                Emit(new LocalMediaPreviewState{State=!opened?"opening":ended?"ended":playing?"playing":"paused",Code=code,Position=position,Duration=duration,Volume=media.Volume,Width=media.NaturalVideoWidth,Height=media.NaturalVideoHeight,Rotation=orientation.Degrees});
            }
        }
        public static int RunConsole(string[] args)
        {
            try{
                if(args==null||args.Length!=1||args[0]!="--local-media-preview-worker")throw new IOException("VIDEO_REQUEST_INVALID");
                var input=new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false,true));var request=DocumentPreviewWorker.Json().Deserialize<Request>(DocumentPreviewWorker.Line(input,16384));
                if(request==null||request.Protocol!=1||request.Parent==0||!IsWindow(new IntPtr(request.Parent))||!Supports(Path.GetExtension(request.Source)))throw new IOException("VIDEO_REQUEST_INVALID");
                Emit(new LocalMediaPreviewState{State="verifying",Code="VIDEO_VERIFYING"});
                using(var source=DocumentPreviewWorker.VerifiedSource(request.Source,request.Bytes,request.Sha256,64L*1024*1024*1024,CancellationToken.None)){
                    var orientation=Inspect(source,Path.GetExtension(request.Source).ToLowerInvariant());
                    Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);using(var form=new Player(request,orientation)){
                        form.Handle.ToInt64();
                        Task.Run(()=>{try{string line;while((line=DocumentPreviewWorker.Line(input,4096))!=null){var command=DocumentPreviewWorker.Json().Deserialize<Command>(line);if(form.IsDisposed)break;form.BeginInvoke(new Action(()=>form.Command(command)));}}catch{}finally{try{if(!form.IsDisposed)form.BeginInvoke(new Action(()=>form.Close()));}catch{}} });
                        Application.Run(form);
                    }
                }return 0;
            }catch(Exception error){string code=error is FileNotFoundException||error is DirectoryNotFoundException?"PREVIEW_SOURCE_MISSING":error is UnauthorizedAccessException?"PREVIEW_SOURCE_UNAVAILABLE":error is IOException&&System.Text.RegularExpressions.Regex.IsMatch(error.Message,@"\A(?:VIDEO|PREVIEW)_[A-Z_]{1,55}\z")?error.Message:"VIDEO_WORKER_FAILED";try{Emit(new LocalMediaPreviewState{State="error",Code=code});}catch{}return 2;}
        }
        public static string Message(string code)
        {
            switch(code){case "VIDEO_EXTERNAL_REFERENCE":return "Видео содержит ссылку на внешние данные. Просмотр отключён.";case "VIDEO_TRANSFORM_UNSUPPORTED":return "Неподдерживаемое преобразование видео. Кандидат сохранён.";case "VIDEO_PREVIEW_TIMEOUT":case "VIDEO_OPEN_TIMEOUT":return "Достигнут лимит времени просмотра. Открой файл заново.";case "VIDEO_VERIFYING":return "Проверка SHA256 видео…";case "VIDEO_OPENING":return "Открытие локального видео…";case "VIDEO_READY":case "VIDEO_ENDED":return "Локальное воспроизведение · кодеки Windows · Space: пауза · ←/→: 5 с";case "PREVIEW_SOURCE_CHANGED":case "PREVIEW_INPUT_LIMIT":case "PREVIEW_LOCAL_SOURCE_REQUIRED":case "PREVIEW_SOURCE_MISSING":case "PREVIEW_SOURCE_UNAVAILABLE":return DocumentPreviewWorker.Message(code);default:return "Видео повреждено, усечено или кодек недоступен в Windows. Кандидат сохранён.";}
        }
    }
}
