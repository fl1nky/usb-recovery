using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace UsbRecovery
{
    // A reviewable choice of decoded metadata, never automatic array assembly.
    public sealed class RaidMetadataSelection : Form
    {
        readonly ComboBox arrays=new ComboBox();
        readonly DataGridView disks=new DataGridView();
        readonly Label detail=new Label();
        readonly RaidMetadataProbe.Group[] groups;
        public RaidMetadataProbe.Group SelectedGroup {get{return arrays.SelectedIndex>=0?groups[arrays.SelectedIndex]:null;}}
        public RaidMetadataSelection(RaidMetadataProbe.Report report)
        {
            if(report==null)throw new ArgumentNullException("report");
            groups=report.Groups.Where(group=>group.Status=="candidate"&&group.Configuration!=null).ToArray();
            Text="Параметры RAID из разметки";StartPosition=FormStartPosition.CenterParent;ShowInTaskbar=false;
            ClientSize=new Size(790,430);MinimumSize=new Size(680,390);Font=new Font("Segoe UI",10F);BackColor=UiTheme.Background;
            var root=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=5,Padding=new Padding(18)};
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,44));root.RowStyles.Add(new RowStyle(SizeType.Absolute,38));
            root.RowStyles.Add(new RowStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.Absolute,56));root.RowStyles.Add(new RowStyle(SizeType.Absolute,42));Controls.Add(root);
            root.Controls.Add(new Label{Text="Найдена разметка Linux MD. Выбери массив и проверь его состав перед сборкой.",Dock=DockStyle.Fill},0,0);
            arrays.DropDownStyle=ComboBoxStyle.DropDownList;arrays.Dock=DockStyle.Fill;arrays.Name="raid-detected-groups";
            foreach(var group in groups)arrays.Items.Add("RAID "+group.Level+" · "+group.RaidDisks+" дисков · "+(group.Name??group.Uuid)+" · "+group.Format);
            root.Controls.Add(arrays,0,1);
            disks.Dock=DockStyle.Fill;disks.ReadOnly=true;disks.AllowUserToAddRows=disks.AllowUserToDeleteRows=false;disks.RowHeadersVisible=false;
            disks.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill;disks.BackgroundColor=UiTheme.Surface;
            disks.Columns.Add("role","Место");disks.Columns[0].FillWeight=15;disks.Columns.Add("image","Образ диска");disks.Columns[1].FillWeight=60;
            disks.Columns.Add("offset","Смещение данных, байт");disks.Columns[2].FillWeight=25;root.Controls.Add(disks,0,2);
            detail.Dock=DockStyle.Fill;detail.ForeColor=UiTheme.Muted;root.Controls.Add(detail,0,3);
            var actions=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,WrapContents=false};
            var apply=new Button{Text="Применить параметры",AutoSize=true,Height=34,DialogResult=DialogResult.OK,Enabled=groups.Length>0,Name="raid-apply-metadata"};
            var cancel=new Button{Text="Отмена",AutoSize=true,Height=34,DialogResult=DialogResult.Cancel};actions.Controls.Add(apply);actions.Controls.Add(cancel);
            string notes=Notes(report);if(notes.Length>0){var remarks=new Button{Text="Замечания…",AutoSize=true,Height=34,Name="raid-metadata-notes"};remarks.Click+=delegate{ShowNotes(notes);};actions.Controls.Add(remarks);}
            root.Controls.Add(actions,0,4);AcceptButton=apply;CancelButton=cancel;
            arrays.SelectedIndexChanged+=delegate{ShowGroup();};if(groups.Length>0)arrays.SelectedIndex=0;
            else detail.Text="Однозначные поддерживаемые параметры не найдены. "+(notes.Length>0?"Причины доступны в «Замечаниях».":"Можно задать известные параметры вручную.");
            UiTheme.ApplyTree(this);
        }
        static string Explain(string code)
        {
            switch(code){
                case "MD_CHECKSUM_INVALID":return "Повреждена контрольная сумма разметки";
                case "MD_EVENT_COUNTER_MISMATCH":return "У участников разные версии метаданных";
                case "MD_ARRAY_GEOMETRY_MISMATCH":return "Параметры участников не совпадают";
                case "MD_DUPLICATE_DEVICE_OR_ROLE":case "MD_DUPLICATE_IMAGE":return "Повторяется образ, устройство или место в массиве";
                case "MD_MULTIPLE_SUPERBLOCKS":return "В одном образе несколько вариантов разметки";
                case "MD_ARRAY_NOT_FULLY_SYNCED":return "Синхронизация массива не завершена";
                case "MD_DATA_OR_SUPER_OFFSET_INVALID":case "MD_METADATA_DATA_OVERLAP":case "MD_LEGACY_GEOMETRY_INVALID":case "MD_SECTOR_OVERFLOW":return "Границы данных в разметке не согласованы с образом";
                case "MD_ROLE_TABLE_INCONSISTENT":case "MD_DEVICE_NUMBER_INVALID":case "MD_ROLE_TABLE_BOUNDS":return "Не согласованы номера или роли участников";
                case "MD_NOT_ACTIVE_MEMBER":return "Образ не отмечен как действующий участник";
                case "RAID_TOO_MANY_MISSING":case "RAID_MIRROR_PAIR_MISSING":return "Недостаточно участников для сборки";
                case "MD_NOT_FOUND":return "Разметка Linux MD не найдена";
                case "MD_SOURCE_ACCESS_DENIED":return "Нет доступа к образу";
                case "MD_SOURCE_IO_FAILED":case "MD_SOURCE_TRUNCATED":return "Не удалось полностью прочитать разметку";
                case "MD_SOURCE_CHANGED":return "Образ изменился во время чтения";
                case "MD_FILE_IDENTITY_INVALID":case "MD_LINKED_SOURCE":case "MD_REGULAR_IMAGE_REQUIRED":return "Нужен отдельный обычный файл образа без ссылок";
                case "MD_COMPLETE_RAW_REQUIRED":case "MD_LOCAL_RAW_REQUIRED":case "MD_RAW_LENGTH_INVALID":return "Нужен завершённый локальный RAW-образ компонента";
                default:return "Эта разметка или схема пока не поддерживается";
            }
        }
        static string Line(string value){return new string((value??"").Where(c=>!Char.IsControl(c)).ToArray());}
        static string Notes(RaidMetadataProbe.Report report)
        {
            var notes=new StringBuilder();
            foreach(var group in report.Groups.Where(g=>g.Configuration==null)){
                notes.AppendLine("Массив "+Line(String.IsNullOrWhiteSpace(group.Name)?group.Uuid:group.Name));
                foreach(string reason in group.Reasons.Distinct())notes.AppendLine("  "+Explain(reason)+" ("+Line(reason)+")");
                notes.AppendLine();
            }
            foreach(var member in report.Members.Where(m=>m.Status!="candidate")){
                notes.AppendLine(Line(Path.GetFileName(member.Path))+" — "+Explain(member.Code)+" ("+Line(member.Code)+")");
            }
            return notes.ToString().Trim();
        }
        void ShowNotes(string notes)
        {
            using(var form=new Form{Text="Замечания к разметке RAID",StartPosition=FormStartPosition.CenterParent,ShowInTaskbar=false,ClientSize=new Size(740,390),MinimumSize=new Size(600,330),Font=Font}){
                var layout=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=2,ColumnCount=1,Padding=new Padding(14)};
                layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));form.Controls.Add(layout);
                layout.Controls.Add(new TextBox{Text=notes,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill},0,0);
                var close=new Button{Text="Закрыть",AutoSize=true,Anchor=AnchorStyles.Right,DialogResult=DialogResult.OK};layout.Controls.Add(close,0,1);form.AcceptButton=form.CancelButton=close;UiTheme.ApplyTree(form);form.ShowDialog(this);
            }
        }
        void ShowGroup()
        {
            disks.Rows.Clear();var group=SelectedGroup;if(group==null)return;
            for(int at=0;at<group.Configuration.Members.Count;at++){
                var member=group.Configuration.Members[at];int row=disks.Rows.Add(at,member.Missing?"Диск отсутствует":Path.GetFileName(member.Path),member.Offset);
                if(!member.Missing)disks.Rows[row].Cells[1].ToolTipText=member.Path;
            }
            detail.Text="Схема: "+group.Layout+" · блок: "+group.ChunkBytes.ToString("N0")+" байт. Метаданные согласованы; сохранность содержимого ещё не проверена.";
        }
    }
}
