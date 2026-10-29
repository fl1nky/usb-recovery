using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using UsbRecovery;

// Reproducible product preview. Uses an ordinary generated image, not devices,
// accounts, user profiles, reconstructed screenshots, or invented scan progress.
public static class RecoveryVisualDemo
{
    static string project,work,output;static int code,sequence;static Form active;
    static readonly List<object> frames=new List<object>();
    static readonly List<RecoveryStageProgress> observations=new List<RecoveryStageProgress>();
    static T Field<T>(object target,string name){return (T)target.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(target);}
    static void Set(object target,string name,object value){target.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).SetValue(target,value);}
    static void Call(object target,string name,params object[] values){target.GetType().GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic).Invoke(target,values);}
    static async Task Show(Form form){form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.Size=new Size(1180,900);form.Show();active=form;await Task.Delay(120);}
    static void Frame(string phase,int duration=140)
    {
        if(active==null||active.IsDisposed||!active.Visible)return;string path=Path.Combine(work,"frame-"+(sequence++).ToString("D4")+".png");
        using(var bitmap=new Bitmap(1180,928))using(var graphics=Graphics.FromImage(bitmap)){
            graphics.Clear(UiTheme.Background);using(var window=new Bitmap(active.Width,active.Height)){active.DrawToBitmap(window,new Rectangle(Point.Empty,window.Size));graphics.DrawImageUnscaled(window,0,0);}
            using(var brush=new SolidBrush(UiTheme.Sidebar))graphics.FillRectangle(brush,0,900,1180,28);
            using(var font=new Font("Segoe UI",9F))TextRenderer.DrawText(graphics,"Пример на тестовых данных · "+phase,font,new Rectangle(16,900,1148,28),Color.White,TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine);
            bitmap.Save(path,ImageFormat.Png);
        }
        frames.Add(new{path=path,duration=duration,phase=phase});
    }
    static byte[] Picture(int variant,bool jpeg)
    {
        using(var bitmap=new Bitmap(720,480))using(var graphics=Graphics.FromImage(bitmap))using(var memory=new MemoryStream()){
            var skies=new[]{Color.FromArgb(221,234,248),Color.FromArgb(234,227,212),Color.FromArgb(223,236,227)};graphics.Clear(skies[variant]);
            using(var sun=new SolidBrush(Color.FromArgb(244,205,121)))graphics.FillEllipse(sun,510-variant*35,64,88,88);
            using(var far=new SolidBrush(Color.FromArgb(128,157,175)))graphics.FillPolygon(far,new[]{new Point(0,330),new Point(220,130+variant*12),new Point(445,330)});
            using(var near=new SolidBrush(Color.FromArgb(65,111,129)))graphics.FillPolygon(near,new[]{new Point(225,365),new Point(490,180),new Point(720,365)});
            using(var ground=new SolidBrush(Color.FromArgb(64,121,105)))graphics.FillRectangle(ground,0,340,720,140);
            using(var font=new Font("Segoe UI",15F))graphics.DrawString("Тестовое изображение "+(variant+1),font,Brushes.White,26,424);
            bitmap.Save(memory,jpeg?ImageFormat.Jpeg:ImageFormat.Png);return memory.ToArray();
        }
    }
    static uint Crc(byte[] bytes){uint crc=0xffffffff;foreach(byte value in bytes){crc^=value;for(int bit=0;bit<8;bit++)crc=(crc&1)!=0?0xedb88320^(crc>>1):crc>>1;}return ~crc;}
    static byte[] Archive()
    {
        byte[] name=Encoding.ASCII.GetBytes("recipe.txt"),text=Encoding.UTF8.GetBytes("Family recipe\r\nThis is a generated recovery example.\r\nNo personal data.\r\n");uint crc=Crc(text);
        using(var memory=new MemoryStream())using(var writer=new BinaryWriter(memory)){
            writer.Write(0x04034b50u);writer.Write((ushort)20);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0x5821);writer.Write(crc);writer.Write((uint)text.Length);writer.Write((uint)text.Length);writer.Write((ushort)name.Length);writer.Write((ushort)0);writer.Write(name);writer.Write(text);long central=memory.Position;
            writer.Write(0x02014b50u);writer.Write((ushort)20);writer.Write((ushort)20);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0x5821);writer.Write(crc);writer.Write((uint)text.Length);writer.Write((uint)text.Length);writer.Write((ushort)name.Length);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write(0u);writer.Write(0u);writer.Write(name);long end=memory.Position;
            writer.Write(0x06054b50u);writer.Write((ushort)0);writer.Write((ushort)0);writer.Write((ushort)1);writer.Write((ushort)1);writer.Write((uint)(end-central));writer.Write((uint)central);writer.Write((ushort)0);writer.Flush();return memory.ToArray();
        }
    }
    static string Fixture()
    {
        string source=Path.Combine(work,"example-usb.dd");byte[] first=Picture(0,false);
        using(var file=new FileStream(source,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
            file.SetLength(256L*1024*1024);Action<long,byte[]> put=(offset,bytes)=>{file.Position=offset;file.Write(bytes,0,bytes.Length);};
            put(3L*1024*1024+137,first);put(23L*1024*1024+17,Picture(1,false));put(124L*1024*1024+37,Picture(2,true));put(216L*1024*1024+513,first);
            put(140L*1024*1024+19,Archive());put(252L*1024*1024+113,Encoding.UTF8.GetBytes("Семейные пирожки: это тестовый текст для поиска по ключевому слову.\nДанные созданы только для демонстрации программы.\n"));
        }
        string hash=RecoveryCore.HashFile(source,CancellationToken.None,(a,b)=>{});File.WriteAllText(source+".sha256",hash,new UTF8Encoding(false));return source;
    }
    static async Task Work()
    {
        Directory.CreateDirectory(work);string source=await Task.Run(()=>Fixture());string before=File.ReadAllText(source+".sha256");output=Path.Combine(work,"results");Directory.CreateDirectory(output);
        using(var hub=new RecoveryHub(false)){
            await Show(hub);await Task.Delay(200);Frame("Главный экран",2200);File.Copy(Path.Combine(work,"frame-0000.png"),Path.Combine(project,"docs","images","main.png"),true);
            var form=Field<RecoveryForm>(hub,"disks");var settings=Field<RecoverySettingsPanel>(form,"searchSettings");var choices=Field<Dictionary<string,CheckBox>>(settings,"choices");
            foreach(var entry in choices)entry.Value.Checked=new[]{"embedded","containers","members","text","photos","video","audio","documents","archives","other"}.Contains(entry.Key);
            Field<TextBox>(settings,"textQuery").Text="пирожки";var options=settings.Selection();options.Validate();
            var sourceBox=Field<ComboBox>(form,"disks");sourceBox.Items.Add("Тестовый образ · 256 МиБ");sourceBox.SelectedIndex=0;Field<Label>(form,"sourceHelp").Text="example-usb.dd · обычный тестовый файл · только чтение";Field<TextBox>(form,"destination").Text=Path.Combine(".build","visual-demo",Path.GetFileName(work),"results");
            await Task.Delay(180);Frame("Выбраны источник и методы",1500);Set(form,"busy",true);Field<WorkflowSteps>(form,"workflow").Current=1;
            foreach(string name in new[]{"start","resume","refresh","choose","expertButton","continueJob"})Field<Button>(form,name).Enabled=false;sourceBox.Enabled=Field<ComboBox>(form,"profile").Enabled=false;settings.Enabled=false;Field<Button>(form,"stop").Enabled=true;
            Call(form,"BeginActivity","Проверка образа","Обычный тестовый файл 256 МиБ");
            using(var timer=new System.Windows.Forms.Timer{Interval=140}){
                timer.Tick+=delegate{if(sequence<140)Frame("Настоящий поиск по тестовому образу");};timer.Start();
                ScanResult result;
                try{result=await Task.Run(()=>RecoveryPipeline.Run(source,output,options,CancellationToken.None,text=>form.BeginInvoke(new Action(()=>Field<Label>(form,"status").Text=text)),null,state=>{lock(observations)observations.Add(state);form.BeginInvoke(new Action(()=>Call(form,"PresentActivity",state)));}));}
                finally{timer.Stop();Set(form,"busy",false);}
                await Task.Delay(220);Field<WorkflowSteps>(form,"workflow").Current=2;Field<Button>(form,"stop").Enabled=false;Field<Label>(form,"status").Text="Готово · "+result.UniqueFiles+" уникальных файлов · "+result.Candidates+" кандидатов";Frame("Поиск завершён",1800);
            }
            hub.Close();active=null;
        }
        var index=RecoveryCatalog.Load(output);if(index.Items.Count<5||!index.Items.Any(x=>x.Category=="Фотографии")||!index.Items.Any(x=>x.Category=="Архивы"))throw new Exception("Demo requires actual photo and archive results.");
        using(var form=new RecoveryFilesForm(output)){
            await Show(form);var grid=Field<DataGridView>(form,"grid");var photo=grid.Rows.Cast<DataGridViewRow>().First(row=>((RecoveredItem)row.Tag).Category=="Фотографии");grid.ClearSelection();photo.Selected=true;grid.CurrentCell=photo.Cells[1];
            for(int i=0;i<4;i++){await Task.Delay(90);Frame("Найденные файлы и предпросмотр",i==3?2200:100);}
            Field<ComboBox>(form,"category").SelectedItem="Документы";await Task.Delay(250);Frame("Фильтр по типу файлов",1600);Field<CheckBox>(form,"all").Checked=true;await Task.Delay(80);Frame("Выбор файлов для сохранения",1500);
            Field<ComboBox>(form,"category").SelectedIndex=0;await Task.Delay(100);photo=grid.Rows.Cast<DataGridViewRow>().First(row=>((RecoveredItem)row.Tag).Category=="Фотографии");grid.ClearSelection();photo.Selected=true;grid.CurrentCell=photo.Cells[1];await Task.Delay(240);Frame("Все находки с происхождением и проверкой",2200);
            File.Copy(Path.Combine(work,"frame-"+(sequence-1).ToString("D4")+".png"),Path.Combine(project,"docs","images","results.png"),true);form.Close();active=null;
        }
        string after=await Task.Run(()=>RecoveryCore.HashFile(source,CancellationToken.None,(a,b)=>{}));if(before!=after)throw new Exception("Source image changed.");
        if(observations.Any(x=>x.Total>0&&(x.Total!=256L*1024*1024||x.Completed<0||x.Completed>x.Total)))throw new Exception("Unexpected progress dimensions.");
        RecoveryCore.SaveJson(Path.Combine(work,"frames.json"),new{caption="Пример на тестовых данных",width=1180,height=928,frames=frames});
        RecoveryCore.SaveJson(Path.Combine(work,"evidence.json"),new{productAssembly=Path.GetFileName(typeof(RecoveryHub).Assembly.Location),productSha256=RecoveryCore.HashFile(typeof(RecoveryHub).Assembly.Location,CancellationToken.None,(a,b)=>{}),productAssemblyLoadedDirectly=true,source="example-usb.dd",sourceBytes=new FileInfo(source).Length,sourceSha256=before,sourceUnchanged=before==after,sourceKind="generated_regular_file",realDevices=false,userProfiles=false,syntheticProgress=false,uniqueFiles=index.Items.Count,candidates=index.Candidates,categories=index.Items.GroupBy(x=>x.Category).Select(group=>new{name=group.Key,count=group.Count()}),observations=observations,frames=frames.Count});
        Console.WriteLine("PASS RecoveryVisualDemo: "+index.Items.Count+" real unique results from generated 256 MiB image, source SHA256 unchanged, "+observations.Count+" observed stage events, "+frames.Count+" real-window frames; no devices or profiles. "+work);
    }
    [STAThread]public static int Main(string[] args)
    {
        project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","visual-demo",DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
        using(var runner=new Form{ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000),Size=new Size(2,2)}){
            runner.Shown+=async delegate{try{await Work();}catch(Exception error){Console.Error.WriteLine(error);code=1;}finally{if(active!=null&&!active.IsDisposed)active.Dispose();runner.Close();}};Application.Run(runner);
        }return code;
    }
}
