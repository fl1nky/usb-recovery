using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class RecoveryPreview
    {
        public Image Image;
        public string Text, Message;
    }
    public static class SafeRecoveryPreview
    {
        public static RecoveryPreview ReadHex(string root,RecoveredItem item,CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();string path=RecoveryCatalog.SafeFile(root,item.Path);byte[] first=new byte[4096],block=new byte[1024*1024];int kept=0;
            using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))using(var hash=SHA256.Create()){
                if(stream.Length!=item.Bytes)throw new IOException("Размер файла изменился после поиска.");if(stream.Length>512L*1024*1024)return new RecoveryPreview{Message="Для HEX с полной проверкой SHA256 поддерживаются файлы до 512 МиБ. Используй экспорт."};
                int n;while((n=stream.Read(block,0,block.Length))>0){cancel.ThrowIfCancellationRequested();int take=Math.Min(n,first.Length-kept);if(take>0){Array.Copy(block,0,first,kept,take);kept+=take;}hash.TransformBlock(block,0,n,null,0);}hash.TransformFinalBlock(new byte[0],0,0);if(!String.Equals(BitConverter.ToString(hash.Hash).Replace("-",""),item.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("SHA256 отличается от сохранённого. Файл изменился.");
            }
            cancel.ThrowIfCancellationRequested();var text=new StringBuilder();for(int at=0;at<kept;at+=16){text.Append(at.ToString("X8")).Append("  ");for(int i=0;i<16;i++)text.Append(at+i<kept?first[at+i].ToString("X2"):"  ").Append(' ');text.Append(" ");for(int i=0;i<16&&at+i<kept;i++){byte b=first[at+i];text.Append(b>=32&&b<127?(char)b:'.');}text.AppendLine();}
            return new RecoveryPreview{Text=text.ToString(),Message="SHA256 совпал · HEX, первые "+kept+" из "+item.Bytes+" байт · содержимое не исполняется"};
        }
        const int MaximumImageBytes=64*1024*1024,MaximumTextBytes=16*1024*1024,MaximumTextDisplay=128*1024;
        static bool TextType(string extension){return new[]{".txt",".csv",".json",".xml",".log",".md",".html",".htm"}.Contains(extension);}
        static int Be32(byte[] b,int p){return (b[p]<<24)|(b[p+1]<<16)|(b[p+2]<<8)|b[p+3];}
        static Size Dimensions(byte[] b)
        {
            if(b.Length>=24&&b[0]==137&&b[1]==80&&b[2]==78&&b[3]==71)return new Size(Be32(b,16),Be32(b,20));
            if(b.Length>=10&&b[0]=='G'&&b[1]=='I'&&b[2]=='F')return new Size(BitConverter.ToUInt16(b,6),BitConverter.ToUInt16(b,8));
            if(b.Length>=26&&b[0]=='B'&&b[1]=='M')return new Size(BitConverter.ToInt32(b,18),Math.Abs(BitConverter.ToInt32(b,22)));
            if(b.Length>4&&b[0]==255&&b[1]==216){int at=2;while(at+9<b.Length){if(b[at++]!=255)return Size.Empty;while(at<b.Length&&b[at]==255)at++;if(at>=b.Length)return Size.Empty;int marker=b[at++];if(marker==217||marker==218)return Size.Empty;if(marker==1||marker>=208&&marker<=215)continue;if(at+2>b.Length)return Size.Empty;int size=(b[at]<<8)|b[at+1];if(size<2||at>b.Length-size)return Size.Empty;if(new[]{192,193,194,195,197,198,199,201,202,203,205,206,207}.Contains(marker))return new Size((b[at+5]<<8)|b[at+6],(b[at+3]<<8)|b[at+4]);at+=size;}}
            return Size.Empty;
        }
        public static RecoveryPreview Read(string root,RecoveredItem item,CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();string path=RecoveryCatalog.SafeFile(root,item.Path),ext=Path.GetExtension(path).ToLowerInvariant();
            bool text=TextType(ext),image=new[]{".jpg",".jpeg",".png",".gif",".bmp"}.Contains(ext);
            if(!text&&!image)return new RecoveryPreview{Message="Встроенный просмотр этого формата недоступен. Скопируй файл и проверь его подходящим приложением. Сам файл здесь не запускается."};
            int maximum=image?MaximumImageBytes:MaximumTextBytes;
            using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){
                if(stream.Length>maximum)return new RecoveryPreview{Message="Файл слишком большой для безопасного встроенного просмотра. Используй экспорт."};
                if(stream.Length!=item.Bytes)throw new IOException("Размер файла изменился после поиска. Просмотр остановлен.");
                byte[] bytes=new byte[(int)stream.Length];int done=0,n;
                using(var hash=SHA256.Create()){
                    while(done<bytes.Length){cancel.ThrowIfCancellationRequested();n=stream.Read(bytes,done,Math.Min(1024*1024,bytes.Length-done));if(n==0)throw new IOException("Неполное чтение файла.");hash.TransformBlock(bytes,done,n,null,0);done+=n;}
                    hash.TransformFinalBlock(new byte[0],0,0);string digest=BitConverter.ToString(hash.Hash).Replace("-","");if(!String.Equals(digest,item.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("SHA256 отличается от сохранённого. Просмотр остановлен: файл изменился.");
                }
                cancel.ThrowIfCancellationRequested();
                if(image){
                    Size size;try{size=Dimensions(bytes);}catch(OverflowException){size=Size.Empty;}
                    if(size.Width<1||size.Height<1||size.Width>12000||size.Height>12000||(long)size.Width*size.Height>16000000)return new RecoveryPreview{Message="Размер изображения не подтверждён или превышает лимит предпросмотра. Используй экспорт / галерею."};
                    try{using(var memory=new MemoryStream(bytes,false))using(var original=Image.FromStream(memory,true,true)){
                        cancel.ThrowIfCancellationRequested();int width=Math.Min(1000,original.Width),height=Math.Max(1,(int)((long)original.Height*width/original.Width));if(height>800){height=800;width=Math.Max(1,(int)((long)original.Width*height/original.Height));}
                        var bitmap=new Bitmap(width,height);using(var graphics=Graphics.FromImage(bitmap)){graphics.Clear(Color.White);graphics.DrawImage(original,0,0,width,height);}return new RecoveryPreview{Image=bitmap,Message=size.Width+" × "+size.Height+" · SHA256 совпал. Декодирование не доказывает исходную полноту."};
                    }}catch(ArgumentException){return new RecoveryPreview{Message="Изображение не декодируется. Оригинальный кандидат сохранён."};}catch(OutOfMemoryException){return new RecoveryPreview{Message="Не удалось декодировать изображение в пределах памяти. Оригинальный кандидат сохранён."};}
                }
                Encoding encoding=new UTF8Encoding(false,true);int start=0;if(bytes.Length>=2&&bytes[0]==255&&bytes[1]==254){encoding=Encoding.Unicode;start=2;}else if(bytes.Length>=2&&bytes[0]==254&&bytes[1]==255){encoding=Encoding.BigEndianUnicode;start=2;}else if(bytes.Length>=3&&bytes[0]==239&&bytes[1]==187&&bytes[2]==191)start=3;
                int count=Math.Min(bytes.Length-start,MaximumTextDisplay);string value;try{value=encoding.GetString(bytes,start,count);}catch(DecoderFallbackException){value=Encoding.UTF8.GetString(bytes,start,count);}
                if(value.Count(c=>Char.IsControl(c)&&c!='\r'&&c!='\n'&&c!='\t')>Math.Max(2,value.Length/100))return new RecoveryPreview{Message="Файл содержит двоичные данные или неподдерживаемую кодировку. Просмотр как текста отключён."};
                return new RecoveryPreview{Text=value.Replace("\r\n","\n").Replace("\n","\r\n"),Message="SHA256 совпал · только текст, без исполнения HTML/скриптов"+(bytes.Length-start>count?" · показаны первые 128 КиБ":"")};
            }
        }
    }

    public sealed class RecoveryFilesForm : Form
    {
        readonly TreeView folders=new TreeView();readonly SplitContainer browser=new SplitContainer();readonly Button folderToggle=new Button(),overviewToggle=new Button();readonly RecoveryResultsOverview overview=new RecoveryResultsOverview();readonly RowStyle overviewRow=new RowStyle(SizeType.Absolute,128);bool? overviewExpanded;string folderFilter="";
        static IEnumerable<OriginalLocation> Locations(RecoveredItem item)
        {
            if(item.OriginalLocations!=null&&item.OriginalLocations.Any(x=>x!=null&&!String.IsNullOrEmpty(x.Path)))return item.OriginalLocations.Where(x=>x!=null&&!String.IsNullOrEmpty(x.Path));
            return String.IsNullOrEmpty(item.OriginalPath)?Enumerable.Empty<OriginalLocation>():new[]{new OriginalLocation{Path=item.OriginalPath,Status=item.OriginalPathStatus,VolumeOffset=item.SourceVolumeOffset}};
        }
        static string FolderKey(OriginalLocation location)
        {
            string path=location.Path.Replace('\\','/');int end=path.LastIndexOf('/');string directory=end<=0?"":path.Substring(0,end).TrimEnd('/');
            return (location.Status=="verified_parent_chain"?"NTFS":"FAT-exFAT")+":"+(location.VolumeOffset.HasValue?location.VolumeOffset.Value.ToString():"unknown")+directory;
        }
        bool FolderMatches(RecoveredItem item)
        {
            if(folderFilter=="")return true;var keys=Locations(item).Select(FolderKey).ToArray();if(folderFilter=="unknown")return keys.Length==0;return keys.Any(x=>x==folderFilter||x.StartsWith(folderFilter+"/",StringComparison.OrdinalIgnoreCase));
        }
        public void ShowFolderBrowser(bool value)
        {
            browser.Panel1Collapsed=!value;folderToggle.Text=value?"Скрыть папки":"Папки";if(!value){folderFilter="";page=0;RefreshRows();}
            if(value&&browser.Width>364)browser.SplitterDistance=Math.Min(200,Math.Max(120,browser.Width-244));
        }
        void BuildFolders()
        {
            folders.BeginUpdate();folders.Nodes.Clear();var allNode=folders.Nodes.Add("Все найденные файлы");allNode.Tag="";var nodes=new Dictionary<string,TreeNode>(StringComparer.OrdinalIgnoreCase);int countNodes=1;bool limited=false;
            foreach(var item in index.Items){foreach(var location in Locations(item)){
                string key=FolderKey(location);string[] parts=key.Split('/');string at=parts[0];TreeNode node;
                if(!nodes.TryGetValue(at,out node)){if(countNodes++>=20000){limited=true;break;}node=folders.Nodes.Add((location.Status=="verified_parent_chain"?"NTFS":"FAT/exFAT")+" · "+(location.VolumeOffset.HasValue?"смещение "+location.VolumeOffset.Value:"том неизвестен"));node.Tag=at;nodes.Add(at,node);}
                foreach(string component in parts.Skip(1).Where(x=>x.Length>0).Take(64)){at+="/"+component;TreeNode child;if(!nodes.TryGetValue(at,out child)){if(countNodes++>=20000){limited=true;break;}child=node.Nodes.Add(component);child.Tag=at;nodes.Add(at,child);}node=child;}
                if(limited)break;
            }if(limited)break;}
            if(index.Items.Any(x=>!Locations(x).Any())){var unknown=folders.Nodes.Add("Исходная папка неизвестна");unknown.Tag="unknown";}
            if(limited){var limit=folders.Nodes.Add("Часть дерева скрыта — используй поиск");limit.Tag="";}
            folders.SelectedNode=allNode;folders.EndUpdate();
        }
        readonly string root;readonly RecoveryFileIndex index;readonly HashSet<string> selected=new HashSet<string>(StringComparer.Ordinal);
        readonly TextBox query=new TextBox(),details=new TextBox(),previewText=new TextBox();readonly ComboBox category=new ComboBox(),method=new ComboBox(),quality=new ComboBox();readonly DataGridView grid=new DataGridView();readonly Label count=new Label(),feedback=new Label(),previewMessage=new Label(),pageStatus=new Label();readonly Button previous=new Button(),next=new Button(),export=new Button(),stop=new Button(),clear=new Button();readonly CheckBox all=new CheckBox(),onlySelected=new CheckBox(),preserveFolders=new CheckBox(),hexMode=new CheckBox();readonly PictureBox previewImage=new PictureBox();readonly SplitContainer content=new SplitContainer();
        List<RecoveredItem> filtered;int page,sortColumn=1,previewGeneration;bool binding,busy,ascending=true;CancellationTokenSource cancellation,previewCancellation;
        static string Quality(RecoveredItem item){string label=item.QualityLabel;return String.IsNullOrEmpty(label)?item.Status:label;}
        public RecoveryFilesForm(string directory)
        {
            root=Path.GetFullPath(directory);index=RecoveryCatalog.Load(root);Text="Найденные файлы";ClientSize=new Size(1200,820);MinimumSize=new Size(900,650);Font=new Font("Segoe UI",10);StartPosition=FormStartPosition.CenterParent;
            var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(22),ColumnCount=1,RowCount=8};layout.RowStyles.Add(new RowStyle(SizeType.Absolute,64));layout.RowStyles.Add(overviewRow);layout.RowStyles.Add(new RowStyle(SizeType.Absolute,64));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,36));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,76));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,70));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,26));Controls.Add(layout);layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            var heading=new Panel{Dock=DockStyle.Fill};var headingTitle=new Panel{Dock=DockStyle.Fill};var headingActions=new FlowLayoutPanel{Dock=DockStyle.Right,Width=284,WrapContents=false,Margin=Padding.Empty};heading.Controls.Add(headingTitle);heading.Controls.Add(headingActions);headingTitle.Controls.Add(new Label{Text="Найденные файлы",Font=new Font("Segoe UI",22,FontStyle.Bold),Dock=DockStyle.Top,Height=34});headingTitle.Controls.Add(new Label{Text=index.Items.Count+" уникальных · "+index.Candidates+" кандидатов всех методов · повторы сохранены",Tag="muted",AutoEllipsis=true,Dock=DockStyle.Bottom,Height=24});layout.Controls.Add(heading,0,0);overview.Dock=DockStyle.Fill;overview.SetIndex(index);overview.CategoryPicked+=delegate(object sender,RecoveryCategoryEventArgs e){if(!busy&&category.Items.Contains(e.Category))category.SelectedItem=e.Category;};layout.Controls.Add(overview,0,1);
            var filters=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=4,RowCount=2,Margin=Padding.Empty};filters.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));for(int i=0;i<3;i++)filters.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,190));filters.RowStyles.Add(new RowStyle(SizeType.Absolute,23));filters.RowStyles.Add(new RowStyle(SizeType.Absolute,34));
            string[] titles={"Имя, путь или SHA256","Тип","Способ поиска","Проверка / состояние"};for(int i=0;i<4;i++)filters.Controls.Add(new Label{Text=titles[i],Tag="muted",AutoSize=true,Font=new Font("Segoe UI",8.5F)},i,0);
            query.Dock=DockStyle.Fill;query.Name="files-query";query.Margin=new Padding(0,0,8,0);category.Dock=method.Dock=quality.Dock=DockStyle.Fill;category.DropDownStyle=method.DropDownStyle=quality.DropDownStyle=ComboBoxStyle.DropDownList;
            category.Items.AddRange(new object[]{"Все типы","Фотографии","Видео","Аудио","Документы","Архивы","Прочее"});method.Items.Add("Все способы");quality.Items.Add("Все состояния");foreach(string name in index.Items.Select(x=>x.Method).Where(x=>!String.IsNullOrEmpty(x)).Distinct().OrderBy(x=>x))method.Items.Add(name);foreach(string name in index.Items.Select(Quality).Where(x=>!String.IsNullOrEmpty(x)).Distinct().OrderBy(x=>x))quality.Items.Add(name);category.SelectedIndex=method.SelectedIndex=quality.SelectedIndex=0;foreach(var chooser in new[]{method,quality})chooser.DropDownWidth=Math.Min(560,Math.Max(190,chooser.Items.Cast<object>().Select(x=>TextRenderer.MeasureText(Convert.ToString(x),chooser.Font).Width+32).DefaultIfEmpty(190).Max()));filters.Controls.Add(query,0,1);filters.Controls.Add(category,1,1);filters.Controls.Add(method,2,1);filters.Controls.Add(quality,3,1);layout.Controls.Add(filters,0,2);
            var selection=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false,Margin=Padding.Empty};all.Text="Отметить весь фильтр";onlySelected.Text="Только отмеченные";all.AutoSize=onlySelected.AutoSize=true;clear.Text="Снять отметки";clear.AutoSize=true;clear.Height=30;count.AutoSize=true;count.Margin=new Padding(14,6,0,0);selection.Controls.AddRange(new Control[]{all,onlySelected,clear,count});layout.Controls.Add(selection,0,3);
            content.Size=new Size(1100,400);content.Dock=DockStyle.Fill;content.FixedPanel=FixedPanel.Panel2;content.Panel1MinSize=400;content.Panel2MinSize=260;content.SplitterWidth=8;content.SplitterDistance=760;content.BackColor=UiTheme.Border;
            grid.Dock=DockStyle.Fill;grid.AllowUserToAddRows=grid.AllowUserToDeleteRows=grid.AllowUserToResizeRows=false;grid.RowHeadersVisible=false;grid.AutoGenerateColumns=false;grid.BackgroundColor=Color.White;grid.SelectionMode=DataGridViewSelectionMode.FullRowSelect;grid.MultiSelect=false;grid.Name="recovery-file-grid";
            grid.Columns.Add(new DataGridViewCheckBoxColumn{Name="pick",HeaderText="✓",Width=34});Column("Файл",210);Column("Тип",100);Column("Байт",90);Column("Способ",125);Column("Состояние",160);grid.Columns[1].AutoSizeMode=DataGridViewAutoSizeColumnMode.Fill;browser.Size=new Size(760,400);browser.Dock=DockStyle.Fill;browser.FixedPanel=FixedPanel.Panel1;browser.Panel1MinSize=120;browser.Panel2MinSize=240;browser.SplitterDistance=200;browser.SplitterWidth=6;browser.Panel1Collapsed=true;folders.Dock=DockStyle.Fill;folders.HideSelection=false;folders.Name="original-folder-tree";browser.Panel1.Controls.Add(folders);browser.Panel2.Controls.Add(grid);content.Panel1.Controls.Add(browser);folderToggle.Text="Папки";folderToggle.Size=new Size(124,34);folderToggle.Anchor=AnchorStyles.Top|AnchorStyles.Left;folderToggle.Margin=new Padding(4,4,0,0);headingActions.Controls.Add(folderToggle);overviewToggle.Text="Свернуть сводку";overviewToggle.Name="toggle-results-overview";overviewToggle.Size=new Size(145,34);overviewToggle.Anchor=AnchorStyles.Top|AnchorStyles.Left;overviewToggle.Margin=new Padding(0,4,4,0);headingActions.Controls.Add(overviewToggle);headingActions.Controls.SetChildIndex(overviewToggle,0);overviewToggle.Click+=delegate{ShowOverview(overview.Compact);};folderToggle.Click+=delegate{if(!busy)ShowFolderBrowser(browser.Panel1Collapsed);};folders.AfterSelect+=delegate{if(busy)return;folderFilter=Convert.ToString(folders.SelectedNode==null?"":folders.SelectedNode.Tag);page=0;RefreshRows();};
            var preview=new TableLayoutPanel{Dock=DockStyle.Fill,BackColor=Color.White,Padding=new Padding(10),ColumnCount=1,RowCount=3};preview.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));preview.RowStyles.Add(new RowStyle(SizeType.Absolute,24));preview.RowStyles.Add(new RowStyle(SizeType.Percent,100));preview.RowStyles.Add(new RowStyle(SizeType.Absolute,68));var previewHeader=new Panel{Dock=DockStyle.Fill};hexMode.Text="HEX";hexMode.Name="hex-preview";hexMode.AutoSize=true;hexMode.Dock=DockStyle.Right;previewHeader.Controls.Add(new Label{Text="ПРЕДПРОСМОТР",Tag="muted",Dock=DockStyle.Fill,Font=new Font("Segoe UI",8F,FontStyle.Bold)});previewHeader.Controls.Add(hexMode);hexMode.CheckedChanged+=delegate{ShowSelection();};preview.Controls.Add(previewHeader,0,0);var previewBody=new Panel{Dock=DockStyle.Fill,Margin=Padding.Empty};previewImage.Dock=DockStyle.Fill;previewImage.SizeMode=PictureBoxSizeMode.Zoom;previewText.Dock=DockStyle.Fill;previewText.Multiline=true;previewText.ReadOnly=true;previewText.ScrollBars=ScrollBars.Both;previewText.Font=new Font("Consolas",9F);previewText.WordWrap=true;previewBody.Controls.Add(previewImage);previewBody.Controls.Add(previewText);preview.Controls.Add(previewBody,0,1);previewMessage.Dock=DockStyle.Fill;previewMessage.Font=new Font("Segoe UI",8.5F);previewMessage.ForeColor=UiTheme.Muted;previewMessage.Padding=new Padding(0,6,0,0);preview.Controls.Add(previewMessage,0,2);content.Panel2.Controls.Add(preview);layout.Controls.Add(content,0,4);
            details.Dock=DockStyle.Fill;details.ReadOnly=true;details.Multiline=true;details.ScrollBars=ScrollBars.Vertical;details.Font=new Font("Consolas",8.5F);details.Name="file-provenance";layout.Controls.Add(details,0,5);
            var footer=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=5,RowCount=2,Margin=Padding.Empty};footer.RowStyles.Add(new RowStyle(SizeType.Absolute,38));footer.RowStyles.Add(new RowStyle(SizeType.Absolute,30));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,70));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,125));previous.Text="← Назад";next.Text="Далее →";export.Text="Копировать отмеченные";export.Tag="primary";stop.Text="Остановить";stop.Enabled=false;int col=0;foreach(var button in new[]{previous,next,export,stop}){button.Dock=DockStyle.Fill;button.MinimumSize=new Size(0,32);if(col==2){pageStatus.Dock=DockStyle.Fill;pageStatus.TextAlign=ContentAlignment.MiddleCenter;pageStatus.Tag="muted";footer.Controls.Add(pageStatus,col++,0);}footer.Controls.Add(button,col++,0);}preserveFolders.Text="Сохранить папки";preserveFolders.Name="preserve-original-folders";preserveFolders.AutoSize=true;preserveFolders.Margin=new Padding(0,4,0,0);footer.Controls.Add(preserveFolders,0,1);footer.SetColumnSpan(preserveFolders,5);var folderTip=new ToolTip();folderTip.SetToolTip(preserveFolders,"Подтверждённые пути — по исходным томам. Все подтверждённые имена одинакового файла сохраняются. Остальные файлы — в папке «Без подтверждённой папки».");Disposed+=delegate{folderTip.Dispose();};layout.Controls.Add(footer,0,6);feedback.Dock=DockStyle.Fill;feedback.Tag="muted";feedback.AutoEllipsis=true;feedback.Font=new Font("Segoe UI",8.5F);feedback.Text=index.Items.Count==0?"В доступных источниках ничего не найдено. Это не доказывает окончательное уничтожение данных.":"Выбери строку для просмотра. Оригинальные файлы не запускаются.";layout.Controls.Add(feedback,0,7);
            query.TextChanged+=delegate{page=0;RefreshRows();};foreach(var filter in new[]{category,method,quality})filter.SelectedIndexChanged+=delegate{page=0;RefreshRows();};onlySelected.CheckedChanged+=delegate{page=0;RefreshRows();};previous.Click+=delegate{page--;RefreshRows();};next.Click+=delegate{page++;RefreshRows();};export.Click+=delegate{ExportSelected();};stop.Click+=delegate{if(cancellation!=null)cancellation.Cancel();};clear.Click+=delegate{if(busy)return;selected.Clear();RefreshRows();};
            all.CheckedChanged+=delegate{if(binding||busy)return;foreach(var item in filtered){if(all.Checked)selected.Add(item.Path);else selected.Remove(item.Path);}RefreshRows();};
            grid.CurrentCellDirtyStateChanged+=delegate{if(grid.IsCurrentCellDirty)grid.CommitEdit(DataGridViewDataErrorContexts.Commit);};grid.CellValueChanged+=delegate(object sender,DataGridViewCellEventArgs e){if(binding||e.RowIndex<0||e.ColumnIndex!=0)return;var row=grid.Rows[e.RowIndex];var item=row.Tag as RecoveredItem;if(item==null)return;if(Convert.ToBoolean(row.Cells[0].Value))selected.Add(item.Path);else selected.Remove(item.Path);if(onlySelected.Checked)RefreshRows();else UpdateCount();};
            grid.ColumnHeaderMouseClick+=delegate(object sender,DataGridViewCellMouseEventArgs e){if(e.ColumnIndex<1||busy)return;ascending=sortColumn==e.ColumnIndex?!ascending:true;sortColumn=e.ColumnIndex;page=0;RefreshRows();};grid.SelectionChanged+=delegate{if(!binding)ShowSelection();};
            Resize+=delegate{FitOverview();FitPreview();};Shown+=delegate{FitOverview();FitPreview();};FormClosing+=delegate(object sender,FormClosingEventArgs e){if(busy){e.Cancel=true;if(cancellation!=null)cancellation.Cancel();}};Disposed+=delegate{if(previewCancellation!=null){previewCancellation.Cancel();previewCancellation.Dispose();previewCancellation=null;}if(previewImage.Image!=null){previewImage.Image.Dispose();previewImage.Image=null;}};BuildFolders();UiTheme.ApplyTree(this);FitOverview();RefreshRows();
        }
        public void ShowOverview(bool expanded){overviewExpanded=expanded;FitOverview();}
        void FitOverview(){bool expanded=overviewExpanded??(ClientSize.Height>=760&&ClientSize.Width>=1050);overview.Compact=!expanded;overviewRow.Height=expanded?128:40;overviewToggle.Text=expanded?"Свернуть сводку":"Сводка";}
        void FitPreview(){if(content.Width<10)return;if(content.Width<680){content.Panel2Collapsed=true;}else{content.Panel2Collapsed=false;int distance=content.Width-310;if(distance>content.Panel1MinSize&&distance<content.Width-content.Panel2MinSize)content.SplitterDistance=distance;}if(grid.Columns.Count>4){grid.Columns[2].Visible=content.Panel1.Width>780;grid.Columns[4].Visible=content.Panel1.Width>950;}}
        void Column(string title,int width){grid.Columns.Add(new DataGridViewTextBoxColumn{HeaderText=title,ReadOnly=true,Width=width,SortMode=DataGridViewColumnSortMode.Programmatic});}
        void UpdateCount(){var visible=new HashSet<string>(filtered.Select(x=>x.Path),StringComparer.Ordinal);int hidden=selected.Count(x=>!visible.Contains(x));count.Text="Найдено "+filtered.Count+" · выбрано "+selected.Count+(hidden>0?" · вне фильтра "+hidden:"");binding=true;try{all.Checked=filtered.Count>0&&filtered.All(x=>selected.Contains(x.Path));}finally{binding=false;}export.Enabled=!busy&&selected.Count>0;clear.Enabled=!busy&&selected.Count>0;}
        void RefreshRows()
        {
            if(busy)return;string term=query.Text.Trim();var result=index.Items.Where(x=>FolderMatches(x)&&(category.SelectedIndex==0||RecoveryResultsSnapshot.DisplayCategory(x.Category)==Convert.ToString(category.SelectedItem))&&(method.SelectedIndex==0||x.Method==Convert.ToString(method.SelectedItem))&&(quality.SelectedIndex==0||Quality(x)==Convert.ToString(quality.SelectedItem))&&(!onlySelected.Checked||selected.Contains(x.Path))&&(x.Name.IndexOf(term,StringComparison.OrdinalIgnoreCase)>=0||x.Path.IndexOf(term,StringComparison.OrdinalIgnoreCase)>=0||x.Sha256.IndexOf(term,StringComparison.OrdinalIgnoreCase)>=0||x.Copies.Any(y=>y.IndexOf(term,StringComparison.OrdinalIgnoreCase)>=0)||Locations(x).Any(y=>y.Path.IndexOf(term,StringComparison.OrdinalIgnoreCase)>=0)));
            Func<RecoveredItem,object> key=x=>sortColumn==3?(object)x.Bytes:sortColumn==2?RecoveryResultsSnapshot.DisplayCategory(x.Category):sortColumn==4?x.Method:sortColumn==5?Quality(x):x.Name;
            filtered=(ascending?result.OrderBy(key):result.OrderByDescending(key)).ThenBy(x=>x.Path,StringComparer.OrdinalIgnoreCase).ToList();page=Math.Max(0,Math.Min(page,(filtered.Count-1)/100));binding=true;
            try{grid.Rows.Clear();foreach(var item in filtered.Skip(page*100).Take(100)){int row=grid.Rows.Add(selected.Contains(item.Path),item.Name,RecoveryResultsSnapshot.DisplayCategory(item.Category),item.Bytes,item.Method,Quality(item));grid.Rows[row].Tag=item;grid.Rows[row].Cells[1].ToolTipText=item.Path;}all.Checked=filtered.Count>0&&filtered.All(x=>selected.Contains(x.Path));foreach(DataGridViewColumn column in grid.Columns)column.HeaderCell.SortGlyphDirection=column.Index==sortColumn?(ascending?SortOrder.Ascending:SortOrder.Descending):SortOrder.None;grid.ClearSelection();if(grid.Rows.Count>0){grid.Rows[0].Selected=true;grid.CurrentCell=grid.Rows[0].Cells[1];}}finally{binding=false;}previous.Enabled=page>0;next.Enabled=(page+1)*100<filtered.Count;pageStatus.Text=(filtered.Count==0?0:page+1)+" / "+Math.Max(1,(filtered.Count+99)/100);UpdateCount();ShowSelection();
            if(filtered.Count>0&&feedback.Text.StartsWith("По фильтру",StringComparison.Ordinal))feedback.Text="Выбери строку для просмотра. Оригинальные файлы не запускаются.";
            if(filtered.Count==0){previewMessage.Text="Нет файлов по текущему фильтру.";feedback.Text=index.Items.Count==0?"В доступных источниках ничего не найдено.":"По фильтру ничего не найдено. Измени запрос, тип, способ или состояние.";}
        }
        void ShowSelection()
        {
            var item=grid.SelectedRows.Count==0?null:grid.SelectedRows[0].Tag as RecoveredItem;details.Text=item==null?"":item.Path+" · "+item.Category+" · "+item.Method+"\r\nSHA256: "+item.Sha256+" · Копий: "+(item.Copies.Count+1)+"\r\n"+item.Note+(Locations(item).Any()?"\r\nПути по сохранившимся записям: "+String.Join("; ",Locations(item).Select(x=>x.Path).Distinct().Take(12)):"")+(String.IsNullOrEmpty(item.IntegrityDetail)?"":"\r\n"+item.IntegrityDetail)+(!String.IsNullOrEmpty(item.SourceCandidatePath)?"\r\nИсточник карты диапазонов: "+item.SourceCandidatePath:"")+(item.SourceOffset.HasValue?"\r\nСмещение в образе: "+item.SourceOffset.Value:"")+(item.UnreadBytes.HasValue?" · Непрочитанных байт: "+item.UnreadBytes.Value:"")+(item.Copies.Count>0?"\r\nТакже: "+String.Join("; ",item.Copies.Take(8)):"");StartPreview(item);
        }
        async void StartPreview(RecoveredItem item)
        {
            int generation=++previewGeneration;if(previewCancellation!=null){previewCancellation.Cancel();previewCancellation.Dispose();}previewCancellation=new CancellationTokenSource();CancellationToken token=previewCancellation.Token;
            if(previewImage.Image!=null){previewImage.Image.Dispose();previewImage.Image=null;}previewText.Clear();previewText.Visible=false;previewImage.Visible=false;if(item==null){previewMessage.Text="Выбери файл.";return;}
            previewMessage.Text="Проверка SHA256 и подготовка просмотра…";RecoveryPreview result=null;bool showHex=hexMode.Checked;
            try{result=await Task.Run(()=>showHex?SafeRecoveryPreview.ReadHex(root,item,token):SafeRecoveryPreview.Read(root,item,token)).ConfigureAwait(false);}catch(OperationCanceledException){return;}catch(IOException e){result=new RecoveryPreview{Message=e.Message};}catch(UnauthorizedAccessException){result=new RecoveryPreview{Message="Нет доступа к файлу."};}catch(Exception){result=new RecoveryPreview{Message="Предпросмотр недоступен. Файл не запускался."};}
            if(IsDisposed||!IsHandleCreated||generation!=previewGeneration){if(result!=null&&result.Image!=null)result.Image.Dispose();return;}var ready=result;try{BeginInvoke(new Action(()=>{if(IsDisposed||generation!=previewGeneration){if(ready.Image!=null)ready.Image.Dispose();return;}previewImage.Image=ready.Image;previewImage.Visible=ready.Image!=null;previewText.WordWrap=!showHex;previewText.Text=ready.Text??"";previewText.Visible=ready.Text!=null;previewMessage.Text=ready.Message??"";if(content.Panel2Collapsed&&ready.Text!=null)details.Text+="\r\n\r\nПредпросмотр: "+ready.Text.Substring(0,Math.Min(ready.Text.Length,2000));}));}catch(InvalidOperationException){if(ready.Image!=null)ready.Image.Dispose();}
        }
        async void ExportSelected()
        {
            if(busy||selected.Count==0)return;using(var dialog=new FolderBrowserDialog{Description="Отдельная папка на другом диске. Исходная флешка не подходит.",ShowNewFolderButton=false}){
                if(dialog.ShowDialog(this)!=DialogResult.OK)return;var files=index.Items.Where(x=>selected.Contains(x.Path)).ToArray();string destination=dialog.SelectedPath;bool keepFolders=preserveFolders.Checked;cancellation=new CancellationTokenSource();busy=true;folderToggle.Enabled=folders.Enabled=false;grid.Enabled=query.Enabled=category.Enabled=method.Enabled=quality.Enabled=all.Enabled=onlySelected.Enabled=preserveFolders.Enabled=clear.Enabled=export.Enabled=previous.Enabled=next.Enabled=false;stop.Enabled=true;feedback.Text="Копирование "+files.Length+" файлов с проверкой SHA256…";
                try{string saved=await Task.Run(()=>keepFolders?RecoveryCatalog.ExportPreservingFolders(root,destination,files,cancellation.Token):RecoveryCatalog.Export(root,destination,files,cancellation.Token));feedback.Text="Готово · выбрано файлов: "+files.Length+" · "+saved;}catch(OperationCanceledException){feedback.Text="Копирование остановлено. Готовые файлы и манифест остаются в новой папке.";}catch(IOException e){feedback.Text=e.Message;}catch(UnauthorizedAccessException){feedback.Text="Нет доступа к выбранной папке.";}finally{busy=false;folderToggle.Enabled=folders.Enabled=true;cancellation.Dispose();cancellation=null;grid.Enabled=query.Enabled=category.Enabled=method.Enabled=quality.Enabled=all.Enabled=onlySelected.Enabled=preserveFolders.Enabled=true;stop.Enabled=false;RefreshRows();}
            }
        }
    }
}
