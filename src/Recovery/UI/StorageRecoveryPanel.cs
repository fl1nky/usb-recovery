using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class StorageRecoveryPanel : UserControl
    {
        readonly TextBox image=new TextBox(),output=new TextBox(),password=new TextBox(),apfsPassword=new TextBox(),raidSize=new TextBox(),expectedSha=new TextBox();
        readonly ComboBox volumes=new ComboBox(),keyKind=new ComboBox(),level=new ComboBox(),layoutKind=new ComboBox();
        readonly TabControl modes=new TabControl();
        readonly DataGridView members=new DataGridView();
        readonly CheckBox snapshots=new CheckBox(),searchAfter=new CheckBox(),maximum=new CheckBox();
        readonly ComboBox chunk=new ComboBox();
        readonly NumericUpDown limit=new NumericUpDown(),snapshotLimit=new NumericUpDown();
        readonly Button browse=new Button(),probe=new Button(),start=new Button(),stop=new Button(),found=new Button(),open=new Button(),searchImage=new Button(),outputBrowse=new Button();
        readonly Label status=new Label(),secretLabel=new Label();
        readonly RecoveryActivityView activity=new RecoveryActivityView();
        readonly Panel sourcePanel=new Panel();
        readonly TableLayoutPanel root=new TableLayoutPanel();
        CancellationTokenSource cancellation;
        StoragePreparedResult prepared;
        string bekPath,lastRoot,lastCatalog;
        public bool IsBusy{get;private set;}
        string Kind{get{return modes.SelectedIndex==0?"APFS":modes.SelectedIndex==1?"RAID":"BitLocker";}}
        static Label Caption(string text){return new Label{Text=text,AutoSize=true,ForeColor=UiTheme.Muted,Margin=new Padding(0,5,8,0)};}
        static void Button(Button button,string text,EventHandler action){button.Text=text;button.Dock=DockStyle.Fill;button.Margin=new Padding(3);button.Click+=action;}
        public StorageRecoveryPanel()
        {
            Dock=DockStyle.Fill;Font=new Font("Segoe UI",10F);BackColor=UiTheme.Background;
            root.Dock=DockStyle.Fill;root.Padding=new Padding(20,16,20,16);root.RowCount=8;root.ColumnCount=1;
            foreach(float height in new[]{64F,80F,44F,250F,34F,120F,44F})root.RowStyles.Add(new RowStyle(SizeType.Absolute,height));root.RowStyles.Add(new RowStyle(SizeType.Percent,100));Controls.Add(root);
            var heading=new Panel{Dock=DockStyle.Fill};heading.Controls.Add(new Label{Text="APFS, RAID и BitLocker",Font=new Font("Segoe UI",19F,FontStyle.Bold),Dock=DockStyle.Top,Height=36});heading.Controls.Add(new Label{Text="Работа с обычными образами · исходники только читаются",Tag="muted",Dock=DockStyle.Bottom,Height=24});root.Controls.Add(heading,0,0);
            sourcePanel.Dock=DockStyle.Fill;var source=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=3,RowCount=2};source.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));source.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,112));source.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,142));source.RowStyles.Add(new RowStyle(SizeType.Absolute,38));source.RowStyles.Add(new RowStyle(SizeType.Percent,100));sourcePanel.Controls.Add(source);
            image.Dock=DockStyle.Fill;image.Name="storage-image";image.Margin=new Padding(0,7,4,3);source.Controls.Add(image,0,0);Button(browse,"Образ…",delegate{ChooseImage();});source.Controls.Add(browse,1,0);Button(probe,"Проверить образ",async delegate{await ProbeAsync();});source.Controls.Add(probe,2,0);volumes.Dock=DockStyle.Fill;volumes.DropDownStyle=ComboBoxStyle.DropDownList;volumes.Name="storage-volumes";source.Controls.Add(volumes,0,1);source.SetColumnSpan(volumes,3);root.Controls.Add(sourcePanel,0,1);
            var destination=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=3};destination.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,118));destination.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));destination.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,112));destination.Controls.Add(Caption("Результаты"),0,0);output.Text=@"C:\USB-Recovery-Results";output.Name="storage-output";output.Dock=DockStyle.Fill;output.Margin=new Padding(0,6,4,0);destination.Controls.Add(output,1,0);Button(outputBrowse,"Папка…",delegate{using(var dialog=new FolderBrowserDialog{Description="Папка результатов на отдельном диске"})if(dialog.ShowDialog(this)==DialogResult.OK)output.Text=dialog.SelectedPath;});destination.Controls.Add(outputBrowse,2,0);root.Controls.Add(destination,0,2);
            modes.Dock=DockStyle.Fill;modes.Name="storage-modes";TabPage apfsPage=new TabPage("APFS"),raidPage=new TabPage("RAID"),bdePage=new TabPage("BitLocker");modes.TabPages.AddRange(new[]{apfsPage,raidPage,bdePage});modes.SelectedIndex=0;root.Controls.Add(modes,0,3);
            var apfs=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,Padding=new Padding(10),AutoScroll=true};apfsPage.Controls.Add(apfs);apfs.Controls.Add(new Label{Text="Файлы и доступные снимки APFS. Файл из снимка отмечается как предыдущая версия.\r\nОтсутствующие записи не выдаются за восстановленные.",AutoSize=true,Font=new Font("Segoe UI",9F)});
            snapshots.Text="Включать доступные снимки";snapshots.Checked=true;snapshots.AutoSize=true;var snapshotRow=new FlowLayoutPanel{Width=650,Height=34,WrapContents=false,Margin=Padding.Empty};snapshotLimit.Minimum=1;snapshotLimit.Maximum=16384;snapshotLimit.Value=32;snapshotLimit.Width=72;snapshotLimit.Name="apfs-snapshot-limit";snapshots.CheckedChanged+=delegate{snapshotLimit.Enabled=snapshots.Checked;};snapshotRow.Controls.AddRange(new Control[]{snapshots,Caption("Последних"),snapshotLimit});apfs.Controls.Add(snapshotRow);apfs.Controls.Add(Caption("Пароль APFS, если том зашифрован"));apfsPassword.UseSystemPasswordChar=true;apfsPassword.Width=380;apfsPassword.Name="apfs-password";apfs.Controls.Add(apfsPassword);apfs.Controls.Add(Caption("Fusion Drive и аппаратные ключи T2 / Secure Enclave не поддерживаются"));
            BuildRaid(raidPage);
            var bde=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,Padding=new Padding(10),AutoScroll=true};bdePage.Controls.Add(bde);bde.Controls.Add(new Label{Text="Расшифровка с твоим ключом в отдельный образ, затем поиск удалённых файлов.\r\nTPM без предоставленного ключа и обход защиты не используются.",AutoSize=true,Font=new Font("Segoe UI",9F)});
            keyKind.Items.AddRange(new object[]{"48-значный ключ восстановления","Пароль тома","Файл ключа .BEK"});keyKind.DropDownStyle=ComboBoxStyle.DropDownList;keyKind.Width=380;keyKind.SelectedIndex=0;keyKind.SelectedIndexChanged+=delegate{password.Enabled=keyKind.SelectedIndex!=2;secretLabel.Text=keyKind.SelectedIndex==2?"Выбери файл .BEK кнопкой ниже":"Пароль и ключ не сохраняются в журнале";};bde.Controls.Add(keyKind);password.UseSystemPasswordChar=true;password.Width=380;password.MaxLength=4096;password.Name="bitlocker-secret";bde.Controls.Add(password);secretLabel.Text="Пароль и ключ не сохраняются в журнале";secretLabel.AutoSize=true;bde.Controls.Add(secretLabel);var bekButton=new Button{Text="Выбрать .BEK…",AutoSize=true};bekButton.Click+=delegate{using(var dialog=new OpenFileDialog{Filter="Ключ BitLocker|*.bek|Все файлы|*.*"})if(dialog.ShowDialog(this)==DialogResult.OK){bekPath=dialog.FileName;keyKind.SelectedIndex=2;secretLabel.Text="Файл ключа выбран · содержимое не сохраняется";}};bde.Controls.Add(bekButton);
            var options=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};searchAfter.Text="Сразу искать удалённые файлы";searchAfter.Checked=true;searchAfter.AutoSize=true;maximum.Text="Максимальный поиск";maximum.AutoSize=true;limit.Minimum=1;limit.Maximum=1048576;limit.Value=256;limit.Width=74;options.Controls.AddRange(new Control[]{searchAfter,maximum,Caption("Лимит, ГиБ"),limit});root.Controls.Add(options,0,4);
            activity.Dock=DockStyle.Fill;activity.Name="storage-activity";activity.SetPhase("Готово","Выбери режим и исходный образ");root.Controls.Add(activity,0,5);
            var actions=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=5};actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));foreach(int width in new[]{108,155,130,90})actions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,width));Button(start,"Анализировать",async delegate{await StartAsync();});start.Tag="primary";start.Name="storage-start";Button(stop,"Остановить",delegate{if(cancellation!=null){cancellation.Cancel();stop.Enabled=false;status.Text="Остановка; незавершённые данные останутся .partial";}});stop.Name="storage-stop";Button(found,"Найденные файлы",delegate{if(lastCatalog!=null)using(var viewer=new RecoveryFilesForm(lastCatalog))viewer.ShowDialog(this);});Button(searchImage,"Искать в образе",async delegate{await SearchPreparedAsync();});Button(open,"Папка",delegate{if(lastRoot!=null&&Directory.Exists(lastRoot))Process.Start(new ProcessStartInfo(lastRoot){UseShellExecute=true});});actions.Controls.Add(start,0,0);actions.Controls.Add(stop,1,0);actions.Controls.Add(found,2,0);actions.Controls.Add(searchImage,3,0);actions.Controls.Add(open,4,0);root.Controls.Add(actions,0,6);
            status.Dock=DockStyle.Fill;status.Font=new Font("Segoe UI",9F);status.Name="storage-status";status.Text="APFS: сохранившиеся записи и снимки. RAID: явные параметры. BitLocker: предоставленный ключ.";root.Controls.Add(status,0,7);
            modes.SelectedIndexChanged+=delegate{RefreshMode();};image.TextChanged+=delegate{volumes.Items.Clear();};Resize+=delegate{bool compact=Height<820;root.Padding=compact?new Padding(14):new Padding(20,16,20,16);root.RowStyles[0].Height=compact?58:64;root.RowStyles[3].Height=(compact?204:250)+(Kind=="RAID"?80:0);root.RowStyles[5].Height=compact?108:120;};RefreshMode();SetBusy(false);UiTheme.ApplyTree(this);
        }
        void BuildRaid(TabPage page)
        {
            var area=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=4,ColumnCount=1,Padding=new Padding(6)};area.RowStyles.Add(new RowStyle(SizeType.Absolute,36));area.RowStyles.Add(new RowStyle(SizeType.Absolute,36));area.RowStyles.Add(new RowStyle(SizeType.Percent,100));area.RowStyles.Add(new RowStyle(SizeType.Absolute,34));page.Controls.Add(area);
            var settings=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};level.DropDownStyle=layoutKind.DropDownStyle=ComboBoxStyle.DropDownList;level.Items.AddRange(new object[]{"0","1","5","6","10"});level.Width=54;layoutKind.Width=180;chunk.DropDownStyle=ComboBoxStyle.DropDownList;for(long n=512;n<=RaidImageBuilder.MaximumChunkSize;n*=2)chunk.Items.Add(n);chunk.SelectedIndex=7;chunk.Width=95;level.SelectedIndexChanged+=delegate{chunk.Enabled=Convert.ToString(level.SelectedItem)!="1";layoutKind.Items.Clear();layoutKind.Items.AddRange(RaidImageBuilder.SupportedLayouts(Convert.ToString(level.SelectedItem)).Cast<object>().ToArray());if(layoutKind.Items.Count>0)layoutKind.SelectedIndex=0;};settings.Controls.AddRange(new Control[]{Caption("Уровень"),level,Caption("Схема"),layoutKind,Caption("Блок, байт"),chunk});area.Controls.Add(settings,0,0);level.SelectedIndex=0;
            var proof=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4};proof.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,150));proof.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,130));proof.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,70));proof.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));proof.Controls.Add(Caption("Байт · 0 = авто"),0,0);raidSize.Text="0";raidSize.Name="raid-logical-size";raidSize.Dock=DockStyle.Fill;proof.Controls.Add(raidSize,1,0);proof.Controls.Add(Caption("SHA256"),2,0);expectedSha.Name="raid-expected-sha256";expectedSha.MaxLength=64;expectedSha.Font=new Font("Consolas",8.5F);expectedSha.Dock=DockStyle.Fill;proof.Controls.Add(expectedSha,3,0);area.Controls.Add(proof,0,1);
            members.BackgroundColor=UiTheme.Surface;members.Dock=DockStyle.Fill;members.Name="raid-members";members.AllowUserToAddRows=false;members.AllowUserToDeleteRows=false;members.MultiSelect=false;members.SelectionMode=DataGridViewSelectionMode.FullRowSelect;members.RowHeadersVisible=false;members.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill;members.Columns.Add(new DataGridViewTextBoxColumn{Name="path",HeaderText="Образ диска · порядок сверху вниз",FillWeight=70});members.Columns.Add(new DataGridViewTextBoxColumn{Name="offset",HeaderText="Смещение, байт",FillWeight=22});members.Columns.Add(new DataGridViewCheckBoxColumn{Name="missing",HeaderText="Нет",FillWeight=8});area.Controls.Add(members,0,2);
            var tools=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false,Margin=Padding.Empty};Action<string,Action> add=(text,click)=>{var button=new Button{Text=text,AutoSize=true,Height=29,Margin=new Padding(1)};button.Click+=delegate{click();};tools.Controls.Add(button);};
            add("Добавить образы",()=>{using(var dialog=new OpenFileDialog{Multiselect=true,Filter="Образы|*.dd;*.img;*.raw;*.bin|Все файлы|*.*"})if(dialog.ShowDialog(this)==DialogResult.OK)foreach(string path in dialog.FileNames)members.Rows.Add(path,"0",false);});add("Найти параметры",()=>{DetectRaidMetadata();});add("Нет диска",()=>members.Rows.Add("","0",true));add("↑",()=>MoveMember(-1));add("↓",()=>MoveMember(1));add("Убрать",()=>{if(members.SelectedRows.Count>0)members.Rows.Remove(members.SelectedRows[0]);});area.Controls.Add(tools,0,3);
        }
        async void DetectRaidMetadata()
        {
            if(IsBusy)return;members.EndEdit();
            var paths=members.Rows.Cast<DataGridViewRow>().Where(row=>!Convert.ToBoolean(row.Cells[2].Value??false)).Select(row=>Convert.ToString(row.Cells[0].Value)).Where(path=>!String.IsNullOrWhiteSpace(path)).ToArray();
            if(paths.Length==0){status.Text="Сначала добавь образы участников RAID.";return;}
            cancellation=new CancellationTokenSource();CancellationToken token=cancellation.Token;SetBusy(true);activity.IsActive=true;
            activity.SetPhase("Поиск параметров RAID","Чтение разметки предоставленных образов");
            try{
                var report=await Task.Run(()=>RaidMetadataProbe.Probe(paths,token,(done,total)=>Post(()=>activity.SetProgress(done,total))));
                if(IsDisposed)return;
                using(var selection=new RaidMetadataSelection(report))if(selection.ShowDialog(this)==DialogResult.OK&&selection.SelectedGroup!=null){
                    var config=selection.SelectedGroup.Configuration;level.SelectedItem=config.Level;layoutKind.SelectedItem=config.Layout;
                    if(chunk.Items.Contains(config.ChunkSize))chunk.SelectedItem=config.ChunkSize;
                    raidSize.Text=config.LogicalSize.ToString(System.Globalization.CultureInfo.InvariantCulture);members.Rows.Clear();
                    foreach(var member in config.Members)members.Rows.Add(member.Path??"",member.Offset.ToString(System.Globalization.CultureInfo.InvariantCulture),member.Missing);
                    status.Text="Параметры из разметки применены. Проверь состав массива и папку результатов, затем нажми «Собрать и найти».";
                }else status.Text="Поиск параметров RAID завершён.";
            }catch(OperationCanceledException){status.Text="Поиск параметров RAID остановлен.";}
            catch(Exception error){status.Text=error is IOException?error.Message:"Не удалось прочитать параметры RAID.";}
            finally{activity.IsActive=false;cancellation.Dispose();cancellation=null;SetBusy(false);}
        }
        void MoveMember(int delta){if(members.SelectedRows.Count==0)return;int at=members.SelectedRows[0].Index,next=at+delta;if(next<0||next>=members.Rows.Count)return;object[] values=members.Rows[at].Cells.Cast<DataGridViewCell>().Select(x=>x.Value).ToArray();members.Rows.RemoveAt(at);members.Rows.Insert(next,values);members.ClearSelection();members.Rows[next].Selected=true;}
        void ChooseImage(){using(var dialog=new OpenFileDialog{Filter="Обычный образ|*.dd;*.img;*.raw;*.bin|Все файлы|*.*"})if(dialog.ShowDialog(this)==DialogResult.OK)image.Text=dialog.FileName;}
        void RefreshMode(){bool raid=Kind=="RAID";sourcePanel.Visible=!raid;root.RowStyles[1].Height=raid?0:80;root.RowStyles[3].Height=(Height<820?204:250)+(raid?80:0);searchAfter.Enabled=Kind!="APFS";maximum.Enabled=Kind!="APFS";searchAfter.Visible=maximum.Visible=Kind!="APFS";start.Text=raid?"Собрать и найти":"Анализировать";volumes.Items.Clear();}
        void Post(Action update){if(!IsDisposed&&IsHandleCreated)try{BeginInvoke(new Action(()=>{if(!IsDisposed)update();}));}catch(InvalidOperationException){}}
        void Observe(RecoveryStageProgress stage){Post(()=>{activity.SetPhase(stage.Title,"Анализ рабочей копии");activity.SetProgress(stage.Completed,stage.Total);activity.FoundCandidates=stage.Candidates;});}
        void SetBusy(bool value){IsBusy=value;image.Enabled=browse.Enabled=probe.Enabled=output.Enabled=outputBrowse.Enabled=modes.Enabled=start.Enabled=volumes.Enabled=!value;searchAfter.Enabled=!value&&Kind!="APFS";maximum.Enabled=!value&&Kind!="APFS";limit.Enabled=!value;stop.Enabled=value;found.Enabled=!value&&lastCatalog!=null&&File.Exists(Path.Combine(lastCatalog,"files-index.json"));open.Enabled=!value&&lastRoot!=null&&Directory.Exists(lastRoot);searchImage.Enabled=!value&&prepared!=null&&prepared.Image!=null;searchImage.Text=prepared!=null&&prepared.Partial?"Искать в части":"Искать в образе";}
        async Task ProbeAsync()
        {
            if(IsBusy)return;cancellation=new CancellationTokenSource();SetBusy(true);activity.IsActive=true;activity.ClearProgress();activity.SetPhase("Проверка образа","Таблица разделов и признаки формата");
            try{string source=image.Text;var result=await Task.Run(()=>StorageRecovery.Probe(source,cancellation.Token));if(result.Status=="error")throw new IOException(StorageRecovery.ErrorText(result.Code));volumes.Items.Clear();foreach(var volume in result.Volumes.Where(x=>x.Kind==Kind))volumes.Items.Add(volume);if(volumes.Items.Count>0)volumes.SelectedIndex=0;status.Text=volumes.Items.Count>0?"Выбери том и нажми «Анализировать». Проверка формата будет выполнена при чтении.":"Подходящий том не найден. Нужен обычный образ тома или диск с проверенной GPT/MBR; DMG/VHD сначала преобразуй в RAW.";}
            catch(OperationCanceledException){status.Text="Проверка остановлена.";}catch(Exception error){status.Text=error is IOException?error.Message:"Не удалось проверить образ.";}
            finally{activity.IsActive=false;cancellation.Dispose();cancellation=null;SetBusy(false);}
        }
        RaidConfiguration ReadRaid()
        {
            members.EndEdit();long logicalSize;if(!Int64.TryParse(raidSize.Text,out logicalSize)||logicalSize<0)throw new IOException("Размер RAID должен быть целым неотрицательным числом байт.");var config=new RaidConfiguration{Level=Convert.ToString(level.SelectedItem),Layout=Convert.ToString(layoutKind.SelectedItem),ChunkSize=Convert.ToInt64(chunk.SelectedItem),LogicalSize=logicalSize,ExpectedSha256=expectedSha.Text.Trim(),Members=new List<RaidMember>()};
            foreach(DataGridViewRow row in members.Rows){long offset;if(!Int64.TryParse(Convert.ToString(row.Cells[1].Value),out offset)||offset<0)throw new IOException("Смещение диска должно быть целым неотрицательным числом байт.");config.Members.Add(new RaidMember{Path=Convert.ToString(row.Cells[0].Value),Offset=offset,Missing=Convert.ToBoolean(row.Cells[2].Value??false)});}RaidImageBuilder.Validate(config);return config;
        }
        async Task StartAsync()
        {
            if (IsBusy) return;
            var secrets = new Dictionary<string, string>();
            StorageRecoveryExecution execution = null;
            bool success = false;
            try {
                var request = new StorageRecoveryRequest {
                    Kind = Kind,
                    Source = image.Text,
                    OutputDirectory = output.Text,
                    Volume = volumes.SelectedItem as StorageVolumeInfo,
                    Raid = Kind == "RAID" ? ReadRaid() : null,
                    IncludeSnapshots = snapshots.Checked,
                    SearchAfterPreparation = searchAfter.Checked,
                    MaximumSearch = maximum.Checked,
                    MaximumSnapshots = (int)snapshotLimit.Value,
                    MaximumOutputBytes = (long)limit.Value * 1024 * 1024 * 1024,
                    Secrets = secrets
                };
                StorageRecoveryWorkflow.Validate(request);
                CollectSecrets(request.Kind, secrets);
                password.Clear();
                apfsPassword.Clear();
                bekPath = null;

                execution = StorageRecoveryWorkflow.Create(request);
                lastRoot = execution.Directory;
                prepared = null;
                lastCatalog = null;
                cancellation = new CancellationTokenSource();
                var token = cancellation.Token;
                SetBusy(true);
                activity.ClearProgress();
                activity.IsActive = true;
                activity.FoundCandidates = -1;
                activity.SetPhase("Подготовка " + request.Kind, "Исходные образы только читаются");
                status.Text = "Работа с образами; пароль не сохраняется.";
                await Task.Run(() => StorageRecoveryWorkflow.Execute(request, execution, token, Observe));

                prepared = execution.Prepared;
                lastCatalog = execution.Catalog;
                var index = execution.Index;
                status.Text = CompletionText(request.Kind, prepared, index);
                activity.FoundCandidates = index == null ? -1 : index.Candidates;
                success = true;
            } catch (OperationCanceledException) {
                status.Text = "Операция остановлена. Незавершённые результаты не считаются готовыми.";
            } catch (Exception error) {
                status.Text = error is IOException || error is ArgumentException
                    ? error.Message : "Операция не завершена; исходники не изменялись.";
            } finally {
                if (execution != null) {
                    prepared = execution.Prepared;
                    lastCatalog = execution.Catalog;
                }
                secrets.Clear();
                password.Clear();
                apfsPassword.Clear();
                activity.IsActive = false;
                activity.IsComplete = success;
                activity.SetPhase(success ? "Обработка завершена" : "Операция не завершена",
                    success ? "Подробности и ограничения — в отчёте источника"
                            : "Проверь сообщение ниже; исходники не изменялись");
                if (cancellation != null) {
                    cancellation.Dispose();
                    cancellation = null;
                }
                SetBusy(false);
            }
        }

        void CollectSecrets(string kind, Dictionary<string, string> secrets)
        {
            if (kind == "APFS" && !String.IsNullOrEmpty(apfsPassword.Text))
                secrets["password"] = apfsPassword.Text;
            if (kind != "BitLocker") return;
            if (keyKind.SelectedIndex != 2) {
                secrets[keyKind.SelectedIndex == 0 ? "recovery_password" : "password"] = password.Text;
                return;
            }
            if (bekPath == null || new FileInfo(bekPath).Length > 65536)
                throw new IOException("Выбери корректный файл .BEK.");
            SourcePaths.NoLinks(bekPath);
            byte[] bytes = File.ReadAllBytes(bekPath);
            try { secrets["bek_base64"] = Convert.ToBase64String(bytes); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }

        static string CompletionText(string kind, StoragePreparedResult result, RecoveryFileIndex index)
        {
            if (index != null && index.Items.Count == 0)
                return result.Partial
                    ? "В доступной части файлы не найдены. Источник проверен не полностью."
                    : "В доступном источнике файлы не найдены.";
            if (result.Partial)
                return kind == "APFS"
                    ? "APFS прочитан не полностью; причины и пропуски указаны в отчёте."
                    : "Сохранён только доступный префикс BitLocker; это не полный том. Подробности в отчёте.";
            return index != null ? "Готово. Проверь найденные файлы и сохрани нужное."
                                 : "Образ подготовлен. Теперь можно искать удалённые файлы.";
        }

        async Task SearchPreparedAsync()
        {
            if (IsBusy || prepared == null || prepared.Image == null) return;
            var execution = new StorageRecoveryExecution {
                Directory = lastRoot, Prepared = prepared, Catalog = lastCatalog
            };
            cancellation = new CancellationTokenSource();
            var token = cancellation.Token;
            bool success = false, deep = maximum.Checked;
            SetBusy(true);
            activity.ClearProgress();
            activity.IsActive = true;
            activity.SetPhase(prepared.Partial ? "Поиск в доступной части" : "Поиск по подготовленному образу",
                "Исходные образы не изменяются");
            try {
                lastCatalog = await Task.Run(() => StorageRecoveryWorkflow.SearchPrepared(execution, deep, token, Observe));
                var index = execution.Index;
                status.Text = CompletionText("BitLocker", prepared, index);
                activity.FoundCandidates = index.Candidates;
                success = true;
            } catch (OperationCanceledException) {
                status.Text = "Поиск остановлен.";
            } catch (Exception error) {
                status.Text = error is IOException ? error.Message : "Поиск не завершён.";
            } finally {
                activity.IsActive = false;
                activity.IsComplete = success;
                if (!success) activity.SetPhase("Поиск не завершён", "Проверь сообщение ниже");
                cancellation.Dispose();
                cancellation = null;
                SetBusy(false);
            }
        }
        protected override void Dispose(bool disposing){if(disposing&&cancellation!=null)cancellation.Cancel();base.Dispose(disposing);}
    }
}
