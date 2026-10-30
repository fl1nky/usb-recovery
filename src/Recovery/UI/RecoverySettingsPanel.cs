using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class RecoverySettingsPanel : TabControl
    {
        readonly Dictionary<string,CheckBox> choices=new Dictionary<string,CheckBox>();
        readonly ToolTip tips=new ToolTip{AutoPopDelay=15000};
        readonly TextBox textQuery=new TextBox();
        List<UserSignatureRule> customRules=new List<UserSignatureRule>();
        readonly Label customSummary=new Label();
        public event EventHandler SelectionChanged;
        public RecoverySettingsPanel()
        {
            Height=320;Dock=DockStyle.Fill;Name="usb-method-options";DrawMode=TabDrawMode.OwnerDrawFixed;SizeMode=TabSizeMode.Fixed;ItemSize=new Size(135,36);Padding=new Point(10,6);
            DrawItem+=delegate(object sender,DrawItemEventArgs e){bool active=e.Index==SelectedIndex;using(var b=new SolidBrush(Color.White))e.Graphics.FillRectangle(b,e.Bounds);using(var font=new Font("Segoe UI",9F,active?FontStyle.Bold:FontStyle.Regular))TextRenderer.DrawText(e.Graphics,TabPages[e.Index].Text,font,e.Bounds,active?UiTheme.Accent:UiTheme.Muted,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);if(active)using(var pen=new Pen(UiTheme.Accent,3))e.Graphics.DrawLine(pen,e.Bounds.Left+12,e.Bounds.Bottom-2,e.Bounds.Right-12,e.Bounds.Bottom-2);};
            var methods=Page("Методы");
            Add(methods,"fat","FAT / exFAT: имена и цепочки",true,"Сохранившиеся каталоги и кластеры удалённых файлов. Может вернуть исходное имя.");
            Add(methods,"ntfs","NTFS: записи MFT",true,"TestDisk собирает файлы по сохранившимся записям, включая поддерживаемую фрагментацию.");
            Add(methods,"lost","Потерянные разделы",true,"Полный проход по образу и резервным загрузочным записям. Источник не ремонтируется.");
            Add(methods,"fat2","Вторая копия FAT",false,"Независимая попытка при повреждении первой FAT12/16/32. Возможны повторные варианты.");
            Add(methods,"signatures","По содержимому · PhotoRec",true,"Весь образ, включая свободные области. Имена и папки могут быть утрачены.");
            Add(methods,"small","Мелкий шаг · 512 байт",true,"Полезен после форматирования и смены размера кластера. Более долгий проход.");
            Add(methods,"jpeg","Фрагментированные JPEG",false,"Brute-force PhotoRec. Может работать очень долго; поддерживаются отдельные случаи JPEG.");
            Add(methods,"damaged","Повреждённые кандидаты",false,"Сохранить также частично повреждённые варианты PhotoRec. Нужно проверять содержимое.");
            Add(methods,"embedded","Изображения внутри данных",true,"JPEG/PNG по любому байту, включая миниатюры. Проверка маркеров и CRC PNG.");
            Add(methods,"containers","Контейнеры между блоками",true,"ZIP/Office, PDF, WebP, MP4/MOV/HEIC, AVI/WAV. Структура ещё не доказывает целостность.");
            Add(methods,"reassemble-photos","Сборка фрагментов фото",false,"Собирает JPEG и PNG из уцелевших частей. Неоднозначные варианты пропускает. Найденное фото нужно проверить.");
            Add(methods,"reassemble-video","Сборка фрагментов MP4 / MOV",false,"Ищет разрозненные части по уцелевшей карте кадров. Поддержка зависит от кодека; проверь весь ролик и звук.");
            var formats=Page("Типы файлов");
            Add(formats,"other","Все поддерживаемые форматы",true,"Приоритет над группами ниже. Выключи для узкого поиска. Метаданные FAT/NTFS ищут все типы.");
            Add(formats,"photos","Фотографии и RAW",true,"JPEG, PNG, WebP, TIFF и поддерживаемые форматы камер.");
            Add(formats,"video","Видео",true,"MP4/MOV, AVI, MPEG, Matroska. Контейнеры групп могут пересекаться.");
            Add(formats,"audio","Аудио",true,"MP3, WAV, FLAC, OGG и другие поддерживаемые типы.");
            Add(formats,"documents","Документы и таблицы",true,"PDF, Office, текст. Одна сигнатура не подтверждает все страницы документа.");
            Add(formats,"archives","Архивы",true,"ZIP, RAR, 7z, gzip и другие. Проверяй распаковку на копии результата.");
            var advanced=Page("Доп. поиск");
            Add(advanced,"metadata","Независимые записи NTFS",false,"Отдельный поиск удалённых записей MFT. Резидентные данные читаются прямо из записи; цепочки кластеров — только при подтверждённых параметрах тома и состоянии размещения.");
            Add(advanced,"members","Уцелевшие части ZIP / Office",false,"Извлекает отдельные элементы по контрольным суммам CRC. Уцелевший элемент ещё не означает восстановление целого архива, документа или таблицы.");
            Add(advanced,"fragmented","Собрать раздельные ZIP / Office",false,"Собирает целый ZIP из раздельно сохранившихся записей и оглавления. Все элементы проверяются по CRC. Разрыв внутри сжатого элемента, шифрование и ZIP64 не поддерживаются.");
            Add(advanced,"orphans","Потерянные каталоги FAT",false,"Ищет не связанные с корнем каталоги по структуре . и .., затем читает файлы внутри. FAT12/16/32; exFAT не поддерживается.");
            Add(advanced,"text","Текстовые остатки по словам",false,"Поиск читаемых строк в UTF-8 и Latin/Cyrillic UTF-16. До 5000 находок; это фрагменты, не целые документы.");
            Add(advanced,"custom","Свои типы файлов",false,"Для редкого формата: начало из образца, известный конец или фиксированный размер. Находки — кандидаты; целостность и исходное имя неизвестны.");
            var customCard=new SurfaceCard{Width=500,Height=112,Margin=new Padding(5),Padding=new Padding(12)};var configure=new Button{Text="Настроить свои типы…",Dock=DockStyle.Top,Height=36,Name="configure-signatures"};customSummary.Dock=DockStyle.Bottom;customSummary.Height=36;customSummary.ForeColor=UiTheme.Muted;customSummary.Text="Правила не добавлены";configure.Click+=delegate{using(var dialog=new UserSignatureDialog(customRules))if(dialog.ShowDialog(FindForm())==DialogResult.OK){SetCustomRules(dialog.Rules);choices["custom"].Checked=customRules.Count>0;}};customCard.Controls.Add(configure);customCard.Controls.Add(customSummary);advanced.Controls.Add(customCard);
            var queryCard=new SurfaceCard{Width=500,Height=112,Margin=new Padding(5),Padding=new Padding(12)};
            var title=new Label{Text="Ключевые слова для текстовых остатков",Dock=DockStyle.Top,Height=24,ForeColor=UiTheme.Muted};textQuery.Dock=DockStyle.Top;textQuery.MaxLength=256;textQuery.Name="usb-text-query";textQuery.Enabled=false;
            var queryHelp=new Label{Text="Все слова — в одном фрагменте · до 8 слов · регистр не важен",Dock=DockStyle.Bottom,Height=26,Font=new Font("Segoe UI",8.5F),ForeColor=UiTheme.Muted};queryCard.Controls.Add(textQuery);queryCard.Controls.Add(title);queryCard.Controls.Add(queryHelp);advanced.Controls.Add(queryCard);
            var capture=Page("Чтение");
            Add(capture,"rescue","Читать с пропуском отдельных ошибок",false,"Непрочитанные секторы заменяются нулями и попадают в карту. Отключение останавливает съём. Не GNU ddrescue; до 4096 дополнительных секторных проб.");
            var note=new Label{AutoSize=false,Width=560,Height=126,Text="Образ сохраняется на другой физический диск. Поиск работает по копии.\r\n\r\nКарта ошибок и SHA256 описывают полученный образ, включая нулевые заполнители. Успешное открытие файла ещё не подтверждает его исходную полноту.",ForeColor=UiTheme.Muted,Padding=new Padding(12)};capture.Controls.Add(note);
            var help=Page("Как работать");help.Controls.Add(new Label{Width=650,Height=220,Padding=new Padding(12),Text="01   Выбери флешку или готовый образ.\r\n02   Начни со «Стандартного» профиля. После форматирования выбери соответствующий профиль.\r\n03   Для дополнительных попыток используй тот же образ.\r\n04   «Все файлы» — фильтры, проверка и экспорт отмеченного.\r\n\r\nНовые методы находятся в «Доп. поиск». Их находки не гарантируют факт удаления или целостность файла. Подробная инструкция — USB-DEEP-GUIDE.md рядом с программой.",ForeColor=UiTheme.Muted});
            Action state=()=>{foreach(string key in new[]{"photos","video","audio","documents","archives"})choices[key].Enabled=!choices["other"].Checked;textQuery.Enabled=choices["text"].Checked;choices["orphans"].Enabled=choices["fat"].Checked;choices["fat2"].Enabled=choices["fat"].Checked;};
            foreach(var check in choices.Values)check.CheckedChanged+=delegate{state();var changed=SelectionChanged;if(changed!=null)changed(this,EventArgs.Empty);};textQuery.TextChanged+=delegate{var changed=SelectionChanged;if(changed!=null)changed(this,EventArgs.Empty);};state();Disposed+=delegate{tips.Dispose();};
        }
        FlowLayoutPanel Page(string name)
        {
            var page=new TabPage(name);TabPages.Add(page);var panel=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoScroll=true,FlowDirection=FlowDirection.LeftToRight,WrapContents=true,Padding=new Padding(8),BackColor=Color.White};page.Controls.Add(panel);
            panel.SizeChanged+=delegate{int available=Math.Max(260,panel.ClientSize.Width-panel.Padding.Horizontal-SystemInformation.VerticalScrollBarWidth);int width=available>780?(available/2-10):available-10;foreach(Control card in panel.Controls)card.Width=width;};return panel;
        }
        void Add(FlowLayoutPanel panel,string code,string label,bool value,string help)
        {
            var card=new SurfaceCard{Width=510,Height=96,Margin=new Padding(5),Padding=new Padding(12)};
            var check=new CheckBox{Text=label,Checked=value,AutoSize=false,Dock=DockStyle.Top,Height=28,Font=new Font("Segoe UI",9.5F,FontStyle.Bold),Name="usb-option-"+code,Margin=System.Windows.Forms.Padding.Empty};
            var description=new Label{Text=help,Dock=DockStyle.Fill,Font=new Font("Segoe UI",8.5F),ForeColor=UiTheme.Muted,Padding=new Padding(22,3,0,0)};card.Controls.Add(description);card.Controls.Add(check);choices.Add(code,check);panel.Controls.Add(card);tips.SetToolTip(check,help);tips.SetToolTip(description,help);card.Cursor=description.Cursor=Cursors.Hand;card.Click+=delegate{if(check.Enabled)check.Checked=!check.Checked;};description.Click+=delegate{if(check.Enabled)check.Checked=!check.Checked;};
        }
        public void ApplyProfile(string profile)
        {
            var value=new RecoveryOptions();
            if(profile=="quick"){value.LostPartitions=false;value.Signatures=false;value.EmbeddedPhotos=false;value.Containers=false;}
            if(profile=="photos"){value.FragmentedPhotos=true;value.Other=false;value.Photos=true;value.Video=value.Audio=value.Documents=value.Archives=false;}
            if(profile=="format"){value.AlternateFat=true;value.OrphanDirectories=true;value.MetadataRescue=true;value.ArchiveMembers=true;value.FragmentedArchives=true;}
            if(profile=="maximum"){value.FragmentedPhotos=true;value.FragmentedVideo=true;value.AlternateFat=true;value.OrphanDirectories=true;value.JpegFragments=true;value.KeepCorrupted=true;value.MetadataRescue=true;value.ArchiveMembers=true;value.FragmentedArchives=true;}
            var map=new Dictionary<string,bool>{{"reassemble-photos",value.FragmentedPhotos},{"reassemble-video",value.FragmentedVideo},{"fat",value.FatMetadata},{"ntfs",value.NtfsMetadata},{"lost",value.LostPartitions},{"fat2",value.AlternateFat},{"signatures",value.Signatures},{"small",value.SmallBlocks},{"jpeg",value.JpegFragments},{"damaged",value.KeepCorrupted},{"embedded",value.EmbeddedPhotos},{"containers",value.Containers},{"orphans",value.OrphanDirectories},{"metadata",value.MetadataRescue},{"members",value.ArchiveMembers},{"fragmented",value.FragmentedArchives},{"text",false},{"rescue",false},{"other",value.Other},{"photos",value.Photos},{"video",value.Video},{"audio",value.Audio},{"documents",value.Documents},{"archives",value.Archives}};
            foreach(var entry in map)choices[entry.Key].Checked=entry.Value;
            choices["custom"].Checked=false;
        }
        public void SetCustomRules(IEnumerable<UserSignatureRule> rules){var values=rules==null?new List<UserSignatureRule>():new List<UserSignatureRule>(rules);customRules=values.Count==0?values:UserSignatureRecovery.Validate(values);customSummary.Text=customRules.Count==0?"Правила не добавлены":"Правил: "+customRules.Count+" · настройки сохраняются в сессии";var changed=SelectionChanged;if(changed!=null)changed(this,EventArgs.Empty);}
        public RecoveryOptions Selection(){return new RecoveryOptions{FragmentedPhotos=choices["reassemble-photos"].Checked,FragmentedVideo=choices["reassemble-video"].Checked,CustomSignatures=choices["custom"].Checked,CustomRules=customRules.Count==0?new List<UserSignatureRule>():UserSignatureRecovery.Validate(customRules),MetadataRescue=choices["metadata"].Checked,ArchiveMembers=choices["members"].Checked,FragmentedArchives=choices["fragmented"].Checked,FatMetadata=choices["fat"].Checked,NtfsMetadata=choices["ntfs"].Checked,LostPartitions=choices["lost"].Checked,AlternateFat=choices["fat2"].Checked,Signatures=choices["signatures"].Checked,SmallBlocks=choices["small"].Checked,JpegFragments=choices["jpeg"].Checked,KeepCorrupted=choices["damaged"].Checked,EmbeddedPhotos=choices["embedded"].Checked,Containers=choices["containers"].Checked,OrphanDirectories=choices["fat"].Checked&&choices["orphans"].Checked,TextFragments=choices["text"].Checked,TextQuery=textQuery.Text,TolerateReadErrors=choices["rescue"].Checked,Photos=choices["photos"].Checked,Video=choices["video"].Checked,Audio=choices["audio"].Checked,Documents=choices["documents"].Checked,Archives=choices["archives"].Checked,Other=choices["other"].Checked};}
    }
}
