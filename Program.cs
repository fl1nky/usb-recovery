using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UsbRecovery
{
    public static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new RecoveryHub());
        }

        public static string WriteGallery(string directory)
        {
            return PhotoCatalog.Build(directory, CancellationToken.None, text => { });
        }
    }

    public sealed class RecoveryForm : Form
    {
        public bool IsBusy { get { return busy || loading; } }
        public void RefreshSources() { RefreshDisks(); }
        ComboBox disks = new ComboBox();
        Button refresh = new Button(), choose = new Button(), start = new Button(), resume = new Button(), stop = new Button(), open = new Button(), gallery = new Button();
        TextBox destination = new TextBox(), log = new TextBox();
        ProgressBar progress = new ProgressBar();
        Label status = new Label(), sourceHelp = new Label();
        RecoverySettingsPanel searchSettings = new RecoverySettingsPanel();
        Button fileList = new Button();
        readonly Button continueJob=new Button();
        CancellationTokenSource cancellation;
        bool busy, loading;
        string lastDirectory, lastGallery;

        public RecoveryForm() : this(true) { }

        readonly ComboBox profile = new ComboBox();
        readonly Label profileHint = new Label();
        readonly WorkflowSteps workflow = new WorkflowSteps();
        bool applyingProfile;
        const string IdleLogText="Журнал пуст. Здесь появятся этапы чтения, поиска и проверки файлов.";
        readonly Panel settingsHost = new Panel();
        readonly SurfaceCard basicSummary = new SurfaceCard();
        readonly Label summaryTitle = new Label(), summaryBody = new Label();
        readonly Button expertButton = new Button();
        public bool ExpertMode { get; private set; }
        public void SetExpertMode(bool value)
        {
            ExpertMode=value;
            var layout=Controls.Count==0?null:Controls[0] as TableLayoutPanel;
            if(layout!=null&&layout.RowStyles.Count>6){layout.SuspendLayout();layout.RowStyles[3].SizeType=value?SizeType.Percent:SizeType.Absolute;layout.RowStyles[3].Height=value?100:112;layout.RowStyles[6].SizeType=value?SizeType.Absolute:SizeType.Percent;layout.RowStyles[6].Height=value?140:100;layout.ResumeLayout(true);}
            searchSettings.Visible=value;basicSummary.Visible=!value;
            expertButton.Text=value?"Свернуть методы":"Все методы…";
            if(value)searchSettings.BringToFront();else basicSummary.BringToFront();
        }
        void UpdateSearchSummary()
        {
            var options=searchSettings.Selection();int methods=(options.FatMetadata?1:0)+(options.NtfsMetadata?1:0)+(options.Signatures?1:0)+(options.EmbeddedPhotos?1:0)+(options.Containers?1:0)+(options.TextFragments?1:0)+(options.MetadataRescue?1:0)+(options.ArchiveMembers?1:0)+(options.FragmentedArchives?1:0)+(options.CustomSignatures?1:0);
            summaryTitle.Text="Выбран профиль: "+Convert.ToString(profile.SelectedItem);
            summaryBody.Text="Способов извлечения: "+methods+". Поиск по рабочему образу; результаты сохраняются отдельно.\r\nПараметры и типы файлов — в «Все методы».";
        }
        public RecoveryForm(bool autoDiscover)
        {
            Text = "Флешки и образы"; Font = new Font("Segoe UI", 10F);
            ClientSize = new Size(1040, 910); MinimumSize = new Size(850, 740); StartPosition = FormStartPosition.CenterScreen;
            BackColor = UiTheme.Background; AutoScroll = true;
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = false, Padding = new Padding(24,18,24,18), ColumnCount = 1, RowCount = 7, BackColor = UiTheme.Background };
            Controls.Add(layout);layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            foreach(int height in new[]{88,132,64,0,48,54,140})layout.RowStyles.Add(height==0?new RowStyle(SizeType.Percent,100):new RowStyle(SizeType.Absolute,height));
            var header=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=3,Margin=Padding.Empty};header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,156));header.RowStyles.Add(new RowStyle(SizeType.Absolute,32));header.RowStyles.Add(new RowStyle(SizeType.Absolute,20));header.RowStyles.Add(new RowStyle(SizeType.Absolute,36));
            header.Controls.Add(new Label{Text="Восстановление с флешки",Font=new Font("Segoe UI",20F,FontStyle.Bold),AutoSize=true,Margin=Padding.Empty},0,0);
            header.Controls.Add(new Label{Text="Выбери источник. Остальное — по шагам.",AutoSize=true,Tag="muted",Margin=new Padding(0,3,0,0)},0,1);
            var badge=new Label{Text="ТОЛЬКО ЧТЕНИЕ",TextAlign=ContentAlignment.MiddleCenter,Dock=DockStyle.Fill,BackColor=Color.FromArgb(231,243,237),ForeColor=Color.FromArgb(41,117,85),Font=new Font("Segoe UI",8F,FontStyle.Bold),Margin=new Padding(8,5,0,5),Tag="safe-badge"};header.Controls.Add(badge,1,0);
            workflow.Dock=DockStyle.Fill;header.Controls.Add(workflow,0,2);header.SetColumnSpan(workflow,2);layout.Controls.Add(header,0,0);
            var sourceCard=new SurfaceCard{Dock=DockStyle.Fill,Padding=new Padding(16),Margin=new Padding(0,4,0,10)};
            var sourceLayout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=3,Margin=Padding.Empty};sourceLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));sourceLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));sourceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,24));sourceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,36));sourceLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));sourceCard.Controls.Add(sourceLayout);
            sourceLayout.Controls.Add(new Label{Text="01  ИСТОЧНИК",Font=new Font("Segoe UI",8F,FontStyle.Bold),ForeColor=UiTheme.Muted,AutoSize=true},0,0);sourceLayout.Controls.Add(new Label{Text="02  ПАПКА РЕЗУЛЬТАТОВ",Font=new Font("Segoe UI",8F,FontStyle.Bold),ForeColor=UiTheme.Muted,AutoSize=true},1,0);
            var left=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,Margin=new Padding(0,0,18,0)};left.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));left.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,100));disks.DropDownStyle=ComboBoxStyle.DropDownList;disks.Dock=DockStyle.Fill;disks.Margin=new Padding(0,3,8,0);left.Controls.Add(disks,0,0);Configure(refresh,"Обновить",delegate{RefreshDisks();});left.Controls.Add(refresh,1,0);sourceLayout.Controls.Add(left,0,1);
            var right=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,Margin=Padding.Empty};right.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));right.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,88));destination.Text=Path.GetPathRoot(Environment.SystemDirectory).TrimEnd('\\')+@"\USB-Recovery-Results";destination.ReadOnly=true;destination.Dock=DockStyle.Fill;destination.Font=new Font("Consolas",9F);destination.Margin=new Padding(0,4,8,0);right.Controls.Add(destination,0,0);Configure(choose,"Папка…",delegate{ChooseDirectory();});right.Controls.Add(choose,1,0);sourceLayout.Controls.Add(right,1,1);
            sourceHelp.Text="Подключи флешку и обнови список.";sourceHelp.AutoSize=false;sourceHelp.AutoEllipsis=true;sourceHelp.Dock=DockStyle.Fill;sourceHelp.Font=new Font("Segoe UI",8.5F);sourceHelp.ForeColor=UiTheme.Muted;sourceHelp.Margin=new Padding(0,5,18,0);sourceLayout.Controls.Add(sourceHelp,0,2);
            sourceLayout.Controls.Add(new Label{Text="Другой физический диск · около 4 объёмов + 1 ГБ",Font=new Font("Segoe UI",8.5F),ForeColor=UiTheme.Muted,Dock=DockStyle.Fill,Margin=new Padding(0,5,0,0)},1,2);layout.Controls.Add(sourceCard,0,1);
            var profileRow=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4,Margin=new Padding(0,6,0,6)};profileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,150));profileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,225));profileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));profileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,142));profileRow.Controls.Add(new Label{Text="Профиль поиска",AutoSize=true,Anchor=AnchorStyles.Left,Font=new Font("Segoe UI",10F,FontStyle.Bold)},0,0);
            profile.DropDownStyle=ComboBoxStyle.DropDownList;profile.Dock=DockStyle.Fill;profile.Margin=new Padding(0,12,12,0);profile.Items.AddRange(new object[]{"Стандартный","Быстрый · по записям","Фотографии","После форматирования","Максимальный","Свои настройки"});profile.SelectedIndex=0;profileRow.Controls.Add(profile,1,0);profileHint.Text="Сбалансированный поиск. Дополнительные методы можно включить ниже.";profileHint.AutoEllipsis=true;profileHint.Dock=DockStyle.Fill;profileHint.ForeColor=UiTheme.Muted;profileHint.Font=new Font("Segoe UI",9F);profileHint.Padding=new Padding(8,8,0,0);profileRow.Controls.Add(profileHint,2,0);Configure(expertButton,"Все методы…",delegate{SetExpertMode(!ExpertMode);});expertButton.Name="usb-expert-toggle";expertButton.Margin=new Padding(8,8,0,4);profileRow.Controls.Add(expertButton,3,0);layout.Controls.Add(profileRow,0,2);
            profile.SelectedIndexChanged+=delegate{if(applyingProfile||profile.SelectedIndex==5)return;applyingProfile=true;try{string[] codes={"standard","quick","photos","format","maximum"};searchSettings.ApplyProfile(codes[Math.Max(0,profile.SelectedIndex)]);profileHint.Text=profile.SelectedIndex==4?"Долгий поиск, включая фрагменты JPEG. Ошибки чтения включаются отдельно.":profile.SelectedIndex==1?"Только метаданные FAT/NTFS. При отсутствии результата выбери другой профиль.":profile.SelectedIndex==3?"Разделы, резервные записи, вторая FAT и потерянные каталоги.":profile.SelectedIndex==2?"По содержимому ищутся фотографии. Метаданные сохраняют все типы.":"Сбалансированный поиск. Дополнительные методы можно включить ниже.";UpdateSearchSummary();}finally{applyingProfile=false;}};
            searchSettings.SelectionChanged+=delegate{if(!applyingProfile){applyingProfile=true;profile.SelectedIndex=5;applyingProfile=false;profileHint.Text="Индивидуальный набор методов. Наведи на настройку для подробностей.";}UpdateSearchSummary();};
            settingsHost.Dock=DockStyle.Fill;settingsHost.Margin=new Padding(0,0,0,10);searchSettings.Dock=DockStyle.Fill;searchSettings.Margin=Padding.Empty;settingsHost.Controls.Add(searchSettings);
            basicSummary.Dock=DockStyle.Fill;basicSummary.Margin=Padding.Empty;basicSummary.Padding=new Padding(20,14,20,14);summaryTitle.Dock=DockStyle.Top;summaryTitle.Height=26;summaryTitle.AutoEllipsis=true;summaryTitle.Font=new Font("Segoe UI",11F,FontStyle.Bold);summaryBody.Dock=DockStyle.Fill;summaryBody.Font=new Font("Segoe UI",9.5F);summaryBody.ForeColor=UiTheme.Muted;summaryBody.Padding=new Padding(0,8,0,0);basicSummary.Controls.Add(summaryBody);basicSummary.Controls.Add(summaryTitle);settingsHost.Controls.Add(basicSummary);layout.Controls.Add(settingsHost,0,3);UpdateSearchSummary();SetExpertMode(false);
            var actions=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4,Margin=new Padding(0,0,0,8)};actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,174));actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,136));actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,110));
            Configure(start,"Начать восстановление",delegate{StartCapture();});start.Tag="primary";actions.Controls.Add(start,0,0);Configure(resume,"Открыть образ…",delegate{ResumeImage();});actions.Controls.Add(resume,1,0);Configure(stop,"Остановить",delegate{if(cancellation!=null){cancellation.Cancel();stop.Enabled=false;status.Text="Остановка после завершения текущего чтения…";}});stop.Enabled=false;actions.Controls.Add(stop,2,0);var guide=new Button();Configure(guide,"Справка",delegate{OpenPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"USB-DEEP-GUIDE.md"));});actions.Controls.Add(guide,3,0);layout.Controls.Add(actions,0,4);
            var state=new Panel{Dock=DockStyle.Fill,Margin=new Padding(0,0,0,10)};progress.Dock=DockStyle.Top;progress.Height=5;status.Text="Готово. Для первого запуска подходит стандартный профиль.";status.Dock=DockStyle.Bottom;status.Height=36;status.Font=new Font("Segoe UI",9F);status.ForeColor=UiTheme.Muted;state.Controls.Add(status);state.Controls.Add(progress);layout.Controls.Add(state,0,5);
            var footer=new SurfaceCard{Dock=DockStyle.Fill,Padding=new Padding(14),Margin=Padding.Empty};var footerLayout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4,RowCount=3};for(int i=0;i<4;i++)footerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,25));footerLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,23));footerLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));footerLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,38));footer.Controls.Add(footerLayout);footerLayout.Controls.Add(new Label{Text="ХОД ОПЕРАЦИИ",AutoSize=true,Font=new Font("Segoe UI",8F,FontStyle.Bold),ForeColor=UiTheme.Muted},0,0);footerLayout.SetColumnSpan(footerLayout.GetControlFromPosition(0,0),4);
            log.Multiline=true;log.ReadOnly=true;log.Text=IdleLogText;log.ScrollBars=ScrollBars.Vertical;log.Dock=DockStyle.Fill;log.Font=new Font("Consolas",8.5F);log.Margin=new Padding(0,0,0,8);footerLayout.Controls.Add(log,0,1);footerLayout.SetColumnSpan(log,4);
            Configure(open,"Папка результатов",delegate{OpenPath(lastDirectory);});open.Enabled=false;footerLayout.Controls.Add(open,0,2);Configure(gallery,"Фотографии",delegate{OpenPath(lastGallery);});gallery.Enabled=false;footerLayout.Controls.Add(gallery,1,2);Configure(fileList,"Все файлы и экспорт",delegate{ShowRecoveredFiles();});fileList.Enabled=true;footerLayout.Controls.Add(fileList,2,2);Configure(continueJob,"Продолжить…",delegate{ChooseSavedJob();});continueJob.Name="continue-recovery-job";footerLayout.Controls.Add(continueJob,3,2);layout.Controls.Add(footer,0,6);
            UiTheme.ApplyTree(this);badge.BackColor=Color.FromArgb(231,243,237);badge.ForeColor=Color.FromArgb(41,117,85);
            sourceHelp.AutoEllipsis=true;disks.SelectedIndexChanged+=delegate{var selected=disks.SelectedItem as DiskInfo;if(selected!=null)sourceHelp.Text=String.Format("{0:0.0} ГБ · {1} · только чтение",selected.Size/1000000000.0,String.IsNullOrEmpty(selected.Letters)?"без буквы диска":selected.Letters);};
            if(autoDiscover)Shown+=delegate{RefreshDisks();};
            FormClosing+=delegate(object sender,FormClosingEventArgs e){if(busy){e.Cancel=true;MessageBox.Show(this,"Сначала нажми «Остановить» и дождись завершения чтения.","Идёт восстановление");}};
        }

        void Configure(Button button, string text, EventHandler action)
        {
            button.Text = text; button.Dock = DockStyle.Fill; button.MinimumSize = new Size(0, 36); button.Margin = new Padding(3, 0, 0, 0); button.FlatStyle = FlatStyle.Flat; button.FlatAppearance.BorderColor = Color.FromArgb(214, 217, 222); button.FlatAppearance.MouseOverBackColor = Color.FromArgb(241, 243, 245); button.FlatAppearance.MouseDownBackColor = Color.FromArgb(230, 233, 237); button.BackColor = Color.White; button.ForeColor = Color.FromArgb(35, 38, 42); button.UseVisualStyleBackColor = false; button.Click += action;
        }
        void Post(Action action) { if (!IsDisposed && IsHandleCreated) BeginInvoke(action); }
        void Append(string text) { if(log.Text==IdleLogText)log.Clear();log.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + text + Environment.NewLine); }
        void OpenPath(string path) { try { if (!String.IsNullOrEmpty(path)) Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch (Exception e) { MessageBox.Show(this, e.Message); } }
        void UpdateResultAction()
        {
            fileList.Text=!String.IsNullOrEmpty(lastDirectory)&&Directory.Exists(lastDirectory)&&!File.Exists(Path.Combine(lastDirectory,"files-index.json"))?"Подготовить найденное":"Все файлы и экспорт";
        }
        async void ShowRecoveredFiles()
        {
            if(busy)return;string folder=lastDirectory;
            if(String.IsNullOrEmpty(folder)||!Directory.Exists(folder))using(var dialog=new FolderBrowserDialog{Description="Папка готового или остановленного восстановления. Каталог незавершённых результатов будет подготовлен отдельно.",ShowNewFolderButton=false}){if(dialog.ShowDialog(this)!=DialogResult.OK)return;folder=dialog.SelectedPath;}
            if(!File.Exists(Path.Combine(folder,"files-index.json"))&&!await PrepareFoundFilesAsync(folder))return;
            try{using(var viewer=new RecoveryFilesForm(folder))viewer.ShowDialog(this);}catch(IOException e){MessageBox.Show(this,e.Message,"Каталог файлов");}catch(UnauthorizedAccessException){MessageBox.Show(this,"Нет доступа к папке результатов.","Каталог файлов");}
        }
        public async Task<bool> PrepareFoundFilesAsync(string folder)
        {
            if(IsBusy)return false;
            if(!Directory.Exists(folder)||(!File.Exists(Path.Combine(folder,"result.json"))&&!File.Exists(Path.Combine(folder,"capture.json"))&&!File.Exists(Path.Combine(folder,"source-image.json")))){status.Text="Выбери папку результатов программы с result.json, capture.json или source-image.json.";return false;}
            busy=true;lastDirectory=Path.GetFullPath(folder);cancellation=new CancellationTokenSource();CancellationToken token=cancellation.Token;start.Enabled=resume.Enabled=refresh.Enabled=choose.Enabled=disks.Enabled=searchSettings.Enabled=profile.Enabled=expertButton.Enabled=open.Enabled=gallery.Enabled=fileList.Enabled=false;stop.Enabled=true;progress.Style=ProgressBarStyle.Marquee;status.Text="Подготовка уже найденных файлов. Поиск по носителю не продолжается.";Append("Отдельная подготовка каталога: "+lastDirectory);bool complete=false;
            try{
                string galleryFile=await Task.Run(()=>{string value=PhotoCatalog.Build(lastDirectory,token,text=>Post(()=>{status.Text=text;Append(text);}));RecoveryCatalog.Build(lastDirectory,token,text=>Post(()=>{status.Text=text;Append(text);}));return value;});
                lastGallery=galleryFile;complete=true;status.Text="Каталог найденного готов. Состояние исходного поиска сохранено в отчёте.";Append("Каталог подготовлен. result.json и состояние исходного поиска не изменены.");
            }catch(OperationCanceledException){status.Text="Подготовка остановлена. Найденные файлы сохранены; каталог можно подготовить позже.";Append(status.Text);}
            catch(Exception e){status.Text="Не удалось подготовить каталог: "+e.Message;Append(status.Text);}
            finally{busy=false;cancellation.Dispose();cancellation=null;start.Enabled=resume.Enabled=refresh.Enabled=choose.Enabled=disks.Enabled=searchSettings.Enabled=profile.Enabled=expertButton.Enabled=continueJob.Enabled=fileList.Enabled=true;stop.Enabled=false;progress.Style=ProgressBarStyle.Continuous;open.Enabled=Directory.Exists(lastDirectory);gallery.Enabled=lastGallery!=null&&File.Exists(lastGallery);UpdateResultAction();}
            return complete;
        }
        void ChooseDirectory()
        {
            using (var dialog = new FolderBrowserDialog { Description = "Выбери папку на компьютере или другом диске. Исходная флешка не подходит.", ShowNewFolderButton = false })
                if (dialog.ShowDialog(this) == DialogResult.OK) destination.Text = dialog.SelectedPath;
        }

        async void RefreshDisks()
        {
            if (busy || loading) return;
            loading = true; refresh.Enabled = false; start.Enabled = false;
            try
            {
                var list = await Task.Run(() => RecoveryCore.ListDisks().Where(d => d.Eligible).ToArray());
                if (IsDisposed) return;
                disks.Items.Clear(); disks.Items.AddRange(list);
                if (list.Length == 1) disks.SelectedIndex = 0;
                disks.Enabled=list.Length>0;sourceHelp.Text = list.Length == 0 ? "Флешка не найдена. Подключи её или открой уже сохранённый образ." : "Проверь название и объём. В списке только USB-диски, с которых не запущена Windows.";
            }
            catch (Exception e) { if (!IsDisposed) { Append(e.Message); sourceHelp.Text = "Не удалось проверить диски. Нажми «Обновить»."; } }
            finally { loading = false; if (!IsDisposed) { refresh.Enabled = true; start.Enabled = true; } }
        }

        string PrepareDestination()
        {
            string requested = destination.Text;
            if (!Directory.Exists(requested))
            {
                // Only the built-in folder on the system disk may be created before source validation.
                string defaultPath = Path.GetPathRoot(Environment.SystemDirectory).TrimEnd('\\') + @"\USB-Recovery-Results";
                if (!String.Equals(requested, defaultPath, StringComparison.OrdinalIgnoreCase)) throw new IOException("Выбери существующую папку.");
                string parent = Path.GetPathRoot(Environment.SystemDirectory);
                var selected = disks.SelectedItem as DiskInfo;
                if (selected != null) RecoveryCore.ValidateDestination(selected, RecoveryCore.DiskForDirectory(parent));
                Directory.CreateDirectory(requested);
            }
            return RecoveryCore.CanonicalDirectory(requested);
        }

        void StartCapture()
        {
            if (busy || loading) return;
            var selected = disks.SelectedItem as DiskInfo;
            if (selected == null) { MessageBox.Show(this, "Подключи флешку, обнови список и выбери её.", "Выбери флешку"); return; }
            BeginRecovery(selected, null);
        }
        void ResumeImage()
        {
            if (busy || loading) return;
            using (var dialog = new OpenFileDialog { Title = "Полный обычный образ флешки — DD/IMG/RAW", Filter = "Образы флешки|*.dd;*.img;*.raw;*.bin|Все файлы|*.*", CheckFileExists = true })
                if (dialog.ShowDialog(this) == DialogResult.OK) {if(dialog.FileName.EndsWith(".partial",StringComparison.OrdinalIgnoreCase)){MessageBox.Show(this,"Неполная копия .partial не подходит для поиска. Сначала заверши съём.");return;}BeginRecovery(null, dialog.FileName);}
        }

        async void ChooseSavedJob()
        {
            if(IsBusy)return;using(var dialog=new FolderBrowserDialog{Description="Папка остановленного съёма или поиска с recovery-session.json / capture-resume.json",ShowNewFolderButton=false})if(dialog.ShowDialog(this)==DialogResult.OK)await ContinueSavedJobAsync(dialog.SelectedPath);
        }
        public async Task<bool> ContinueSavedJobAsync(string directory)
        {
            if(IsBusy)return false;string folder=Path.GetFullPath(directory);
            if(!File.Exists(RecoveryCatalog.SafeFile(folder,RecoverySession.FileName))&&!File.Exists(RecoveryCatalog.SafeFile(folder,"capture-request.json"))){status.Text="В этой папке нет сохранённой сессии или сведений о съёме.";return false;}
            busy=true;cancellation=new CancellationTokenSource();var token=cancellation.Token;bool complete=false;lastDirectory=folder;lastGallery=null;
            start.Enabled=resume.Enabled=refresh.Enabled=choose.Enabled=disks.Enabled=searchSettings.Enabled=profile.Enabled=expertButton.Enabled=continueJob.Enabled=open.Enabled=gallery.Enabled=fileList.Enabled=false;stop.Enabled=true;
            workflow.Current=1;workflow.Invalidate();status.Text="Проверка сохранённой сессии и результатов…";progress.Style=ProgressBarStyle.Marquee;Append("Продолжение: "+folder+". Используются сохранённые параметры поиска.");
            try{
                var result=await Task.Run(()=>{
                    Action<string> update=text=>Post(()=>{status.Text=text;Append(text);});
                    if(File.Exists(RecoveryCatalog.SafeFile(folder,"capture-request.json")))RecoveryCore.ValidateSavedCaptureDestination(folder);
                    ScanResult found;
                    if(File.Exists(RecoveryCatalog.SafeFile(folder,RecoverySession.FileName)))found=RecoveryPipeline.Resume(folder,token,update);
                    else {
                        string optionsFile=RecoveryCatalog.SafeFile(folder,"search-options.json");if(!File.Exists(optionsFile)||new FileInfo(optionsFile).Length>64*1024)throw new IOException("Не найдены сохранённые параметры. Заверши съём и открой полный образ отдельным поиском.");
                        var options=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<RecoveryOptions>(File.ReadAllText(optionsFile));if(options==null)throw new IOException("Параметры поиска повреждены.");options.Validate();
                        string image=RecoveryCatalog.SafeFile(folder,"usb.dd");
                        if(File.Exists(image))image=RecoveryCore.CompleteSavedCapture(folder,token);else if(File.Exists(RecoveryCatalog.SafeFile(folder,"capture-resume.json"))&&new[]{"complete","complete_with_read_errors"}.Contains(ResumableCapture.Inspect(RecoveryCatalog.SafeFile(folder,"capture-resume.json")).Status))image=RecoveryCore.CompleteSavedCapture(folder,token);else image=RecoveryCore.ResumeCapture(folder,token,(done,total)=>Post(()=>{progress.Style=ProgressBarStyle.Continuous;progress.Value=(int)Math.Min(100,done*100/Math.Max(1,total));status.Text="Продолжение образа: "+progress.Value+"%";}));
                        string baseline=null;
                        found=RecoveryPipeline.Run(image,folder,options,token,update,baseline);
                    }
                    RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(folder,"result.json"),new{status=found.HasWarnings?"finished_with_warnings":"finished",resumed=true,utc=DateTime.UtcNow.ToString("o"),candidates=found.Candidates,uniqueFiles=found.UniqueFiles,resumedStages=found.ResumedStages});return found;
                });
                lastGallery=result.Gallery;workflow.Current=2;workflow.Invalidate();progress.Style=ProgressBarStyle.Continuous;progress.Value=100;status.Text="Продолжение завершено. Файлов: "+result.UniqueFiles+". Проверенных этапов использовано повторно: "+result.ResumedStages+(result.HasWarnings?". Есть замечания.":".");Append(status.Text);complete=true;
            }catch(OperationCanceledException){status.Text="Остановлено. Сессия и уже найденные файлы сохранены; можно продолжить позже.";Append(status.Text);RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(folder,"result.json"),new{status="cancelled",resumed=true,utc=DateTime.UtcNow.ToString("o")});}
            catch(Exception error){status.Text="Продолжение остановлено: "+error.Message;Append(status.Text);}
            finally{busy=false;cancellation.Dispose();cancellation=null;start.Enabled=resume.Enabled=refresh.Enabled=choose.Enabled=disks.Enabled=searchSettings.Enabled=profile.Enabled=expertButton.Enabled=continueJob.Enabled=fileList.Enabled=true;stop.Enabled=false;open.Enabled=Directory.Exists(folder);gallery.Enabled=lastGallery!=null&&File.Exists(lastGallery);progress.Style=ProgressBarStyle.Continuous;UpdateResultAction();}
            return complete;
        }

        async void BeginRecovery(DiskInfo selected, string existingImage)
        {
            string runDirectory = null;
            RecoveryOptions options=searchSettings.Selection();try{options.Validate();}catch(ArgumentException e){MessageBox.Show(this,e.Message,"Способы поиска");return;}
            busy = true; start.Enabled = resume.Enabled = refresh.Enabled = choose.Enabled = disks.Enabled = searchSettings.Enabled = profile.Enabled = expertButton.Enabled = continueJob.Enabled = false; stop.Enabled = true; open.Enabled = gallery.Enabled = fileList.Enabled = false;
            workflow.Current=1;workflow.Invalidate();
            cancellation = new CancellationTokenSource(); var token = cancellation.Token;
            try
            {
                string output = PrepareDestination();
                await Task.Run(() => {
                    int targetDisk = RecoveryCore.DiskForDirectory(output);
                    if (selected != null) { RecoveryCore.ValidateDestination(selected, targetDisk); RecoveryCore.CheckSpace(output, selected.Size); }
                    else { RecoveryCore.CheckSpace(output, new FileInfo(existingImage).Length); }
                });
                token.ThrowIfCancellationRequested();
                runDirectory = Path.Combine(output, "Recovery-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 6));
                Directory.CreateDirectory(runDirectory); lastDirectory = runDirectory; lastGallery = null;
                RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(runDirectory,"search-options.json"),options);
                Append("Результаты: " + runDirectory);
                if (selected != null) Append("Выбрана флешка: " + selected);
                await Task.Run(() => {
                    string image = existingImage;
                    string imageChecksum = null;
                    if (image == null)
                    {
                        Post(() => { status.Text = "Создаётся копия флешки. Не отключай её и не записывай на неё файлы."; progress.Style = ProgressBarStyle.Continuous; });
                        long lastUpdate = 0;
                        image = RecoveryCore.Capture(selected, runDirectory, token, (done, total) => {
                            long now = Environment.TickCount & Int32.MaxValue;
                            if (done == total || now - lastUpdate >= 250) { lastUpdate = now; Post(() => { progress.Value = (int)(done * 100 / total); status.Text = String.Format("Копирование: {0:0.0} из {1:0.0} ГБ ({2}%)", done / 1000000000.0, total / 1000000000.0, done * 100 / total); }); }
                        }, options.TolerateReadErrors);
                        Post(() => Append("Полная копия сохранена. Проверяется её контрольная сумма."));
                    }
                    else if(!File.Exists(image+".sha256")) {
                        Post(()=>{status.Text="Импорт внешнего образа: вычисляется SHA256 без изменения исходника…";progress.Style=ProgressBarStyle.Marquee;});
                        imageChecksum=Path.Combine(runDirectory,"source-image.sha256");string hash=RecoveryCore.HashFile(image,token,(done,total)=>{});File.WriteAllText(imageChecksum,hash+"\n",new UTF8Encoding(false));
                    }
                    Post(() => { status.Text = "Проверяется копия флешки…"; progress.Style = ProgressBarStyle.Marquee; });
                    string lastMessage = null;
                    ScanResult result = RecoveryPipeline.Run(image, runDirectory, options, token, text => Post(() => { status.Text = text; if (text != lastMessage && !text.Contains("%") && !text.StartsWith("PhotoRec:") && !text.StartsWith("Каталог:")) { Append(text); lastMessage = text; } }),imageChecksum);
                    lastGallery = result.Gallery;Post(()=>{workflow.Current=2;workflow.Invalidate();});
                    if (File.Exists(HelperClient.Executable))
                    {
                        string photoOutput = Path.Combine(runDirectory, "photo-archive");
                        try
                        {
                            Post(() => { status.Text = "Дополнительные предпросмотры WebP и HEIC…"; });
                            HelperResult previews = HelperClient.Photos(runDirectory, photoOutput, token);
                            string extendedGallery = Path.Combine(photoOutput, "Фотографии.html");
                            if (previews.Status != "error" && File.Exists(extendedGallery)) lastGallery = extendedGallery;
                            else { result.HasWarnings = true; Post(() => Append("Дополнительные предпросмотры не завершены. Сохранена основная галерея.")); }
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (IOException) { result.HasWarnings = true; Post(() => Append("Дополнительные предпросмотры не завершены. Сохранена основная галерея.")); }
                    }
                    RecoveryCore.SaveJson(Path.Combine(runDirectory, "result.json"), new { status = result.HasWarnings ? "finished_with_warnings" : "finished", utc = DateTime.UtcNow.ToString("o"), candidates = result.Candidates,uniqueFiles=result.UniqueFiles,options=options, image = image, gallery = lastGallery.Substring(runDirectory.Length + 1).Replace('\\', '/') });
                    Post(() => { progress.Style = ProgressBarStyle.Continuous; progress.Value = 100; status.Text = result.HasWarnings ? "Поиск закончен с замечаниями. Смотри журнал; уже найденные файлы сохранены." : "Поиск завершён. Кандидатов: " + result.Candidates + ". Открой галерею с проверкой фотографий."; Append("Галерея показывает размеры и состояние изображений и группирует одинаковые файлы. Файлы на диске не удаляются."); });
                });
            }
            catch (OperationCanceledException)
            {
                status.Text = "Остановлено. Уже найденное сохранено. Для проверки и экспорта нажми «Подготовить найденное».";
                Append("Остановлено пользователем. usb.dd.partial — неполная копия; поиск по ней не запускается. Полную usb.dd можно выбрать кнопкой «Открыть образ».");
                if (runDirectory != null) { try { RecoveryCore.SaveJson(Path.Combine(runDirectory, "result.json"), new { status = "cancelled", utc = DateTime.UtcNow.ToString("o") }); } catch { } }
            }
            catch (Exception e)
            {
                status.Text = "Операция остановлена: " + e.Message; Append(e.Message);
                if (runDirectory != null) { try { RecoveryCore.SaveJson(Path.Combine(runDirectory, "result.json"), new { status = "error", utc = DateTime.UtcNow.ToString("o"), message = e.Message }); } catch { } }
                MessageBox.Show(this, e.Message, "Не удалось завершить восстановление", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            finally
            {
                busy = false; cancellation.Dispose(); cancellation = null;
                start.Enabled = resume.Enabled = refresh.Enabled = choose.Enabled = disks.Enabled = searchSettings.Enabled = profile.Enabled = expertButton.Enabled = continueJob.Enabled = true; stop.Enabled = false;
                progress.Style = ProgressBarStyle.Continuous; open.Enabled = lastDirectory != null && Directory.Exists(lastDirectory); gallery.Enabled = lastGallery != null && File.Exists(lastGallery);
                fileList.Enabled=true;UpdateResultAction();
            }
        }
    }
}
