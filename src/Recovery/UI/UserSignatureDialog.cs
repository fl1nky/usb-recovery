using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class UserSignatureDialog : Form
    {
        readonly ListView list=new ListView();
        List<UserSignatureRule> rules;
        public List<UserSignatureRule> Rules { get { return rules.Count==0?new List<UserSignatureRule>():UserSignatureRecovery.Validate(rules); } }
        public UserSignatureDialog(IEnumerable<UserSignatureRule> existing)
        {
            rules=(existing??new UserSignatureRule[0]).ToList();if(rules.Count>0)rules=UserSignatureRecovery.Validate(rules);
            Text="Свои типы файлов";ClientSize=new Size(820,530);MinimumSize=new Size(680,470);StartPosition=FormStartPosition.CenterParent;Font=new Font("Segoe UI",10);
            var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(20),ColumnCount=1,RowCount=4};layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,90));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,44));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));Controls.Add(layout);
            layout.Controls.Add(new Label{Dock=DockStyle.Fill,Text="Свои типы файлов\r\nДля редкого формата укажи начало и границу файла. Можно взять первые байты из исправного образца. Совпадение даст кандидата; целостность формата отдельно не проверяется.",ForeColor=UiTheme.Muted},0,0);
            list.Dock=DockStyle.Fill;list.View=View.Details;list.FullRowSelect=true;list.MultiSelect=false;list.HideSelection=false;list.Name="signature-rules";list.Columns.Add("Название",230);list.Columns.Add("Тип",80);list.Columns.Add("Граница",230);list.Columns.Add("Смещение",100);layout.Controls.Add(list,0,1);
            var actions=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};Add(actions,"Добавить",()=>Edit(false));Add(actions,"Изменить",()=>Edit(true));Add(actions,"Удалить",()=>{if(list.SelectedIndices.Count>0){rules.RemoveAt(list.SelectedIndices[0]);RefreshList();}});Add(actions,"Импорт…",Import);Add(actions,"Сохранить…",Save);layout.Controls.Add(actions,0,2);
            var footer=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,WrapContents=false};var done=Add(footer,"Готово",()=>{DialogResult=DialogResult.OK;Close();});done.Tag="primary";var cancel=Add(footer,"Отмена",()=>{DialogResult=DialogResult.Cancel;Close();});CancelButton=cancel;AcceptButton=done;layout.Controls.Add(footer,0,3);list.DoubleClick+=delegate{Edit(true);};RefreshList();UiTheme.ApplyTree(this);
        }
        static Button Add(FlowLayoutPanel parent,string text,Action action){var b=new Button{Text=text,AutoSize=true,Height=34,Margin=new Padding(0,4,8,0)};b.Click+=delegate{action();};parent.Controls.Add(b);return b;}
        void RefreshList(){list.Items.Clear();foreach(var rule in rules){var item=new ListViewItem(rule.Name);item.SubItems.Add(rule.Extension);item.SubItems.Add(rule.FixedBytes>0?rule.FixedBytes+" байт":"До конечного маркера");item.SubItems.Add(rule.HeaderOffset.ToString());list.Items.Add(item);}}
        void Edit(bool selected)
        {
            int index=list.SelectedIndices.Count==0?-1:list.SelectedIndices[0];if(selected&&index<0)return;if(!selected&&rules.Count>=32){MessageBox.Show(this,"До 32 правил за один проход.");return;}
            using(var editor=new RuleEditor(selected?rules[index]:null))if(editor.ShowDialog(this)==DialogResult.OK){if(selected)rules[index]=editor.Rule;else rules.Add(editor.Rule);RefreshList();}
        }
        void Import(){using(var d=new OpenFileDialog{Title="Правила поиска",Filter="Правила JSON|*.json"})if(d.ShowDialog(this)==DialogResult.OK)try{if(new FileInfo(d.FileName).Length>1024*1024)throw new ArgumentException("Файл правил слишком большой.");rules=UserSignatureRecovery.ParseRules(File.ReadAllText(d.FileName));RefreshList();}catch(Exception e){if(!(e is ArgumentException||e is IOException||e is UnauthorizedAccessException))throw;MessageBox.Show(this,"Не удалось прочитать правила. "+e.Message,"Правила поиска");}}
        void Save(){using(var d=new SaveFileDialog{Title="Сохранить правила",Filter="Правила JSON|*.json",FileName="file-signatures.json"})if(d.ShowDialog(this)==DialogResult.OK)try{File.WriteAllText(d.FileName,new JavaScriptSerializer().Serialize(Rules),new System.Text.UTF8Encoding(false));}catch(IOException){MessageBox.Show(this,"Не удалось сохранить правила.");}catch(UnauthorizedAccessException){MessageBox.Show(this,"Нет доступа к папке правил.");}}

        sealed class RuleEditor : Form
        {
            readonly TextBox title=new TextBox(),extension=new TextBox(),header=new TextBox(),footer=new TextBox();
            readonly NumericUpDown offset=Number(0,4096,0),minimum=Number(1,134217728,16),maximum=Number(1,134217728,16777216),fixedSize=Number(1,134217728,1024);
            readonly ComboBox boundary=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList};readonly Label status=new Label();readonly string identity;
            public UserSignatureRule Rule;
            static NumericUpDown Number(decimal min,decimal max,decimal value){return new NumericUpDown{Minimum=min,Maximum=max,Value=value,ThousandsSeparator=true,Dock=DockStyle.Fill};}
            public RuleEditor(UserSignatureRule existing)
            {
                identity=existing==null?"rule-"+Guid.NewGuid().ToString("N").Substring(0,12):existing.Id;
                Text=existing==null?"Новый тип файла":"Изменить тип файла";ClientSize=new Size(680,600);MinimumSize=new Size(640,610);StartPosition=FormStartPosition.CenterParent;Font=new Font("Segoe UI",10);
                var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(20),ColumnCount=2,RowCount=12};layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,190));layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));for(int i=0;i<10;i++)layout.RowStyles.Add(new RowStyle(SizeType.Absolute,40));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));Controls.Add(layout);
                Row(layout,0,"Название",title);Row(layout,1,"Расширение",extension);Row(layout,2,"Начало · HEX",header);Row(layout,3,"Смещение начала",offset);boundary.Items.AddRange(new object[]{"До конечного маркера","Фиксированный размер"});boundary.SelectedIndex=0;Row(layout,4,"Как найти конец",boundary);Row(layout,5,"Конец · HEX",footer);Row(layout,6,"Размер · байт",fixedSize);Row(layout,7,"Минимум · байт",minimum);Row(layout,8,"Максимум · байт",maximum);
                var sample=new Button{Text="Взять начало из образца…",Dock=DockStyle.Fill,Name="signature-sample"};sample.Click+=delegate{Sample();};layout.Controls.Add(sample,0,9);layout.SetColumnSpan(sample,2);status.Dock=DockStyle.Fill;status.ForeColor=UiTheme.Muted;status.Text="HEX: пары байтов, например 52 45 43 49 50 45. Образец даёт только начало. Для переменного формата нужен известный конечный маркер; размер другого файла не угадывается.";layout.Controls.Add(status,0,10);layout.SetColumnSpan(status,2);
                var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft};var done=Add(buttons,"Сохранить правило",Commit);done.Tag="primary";var cancel=Add(buttons,"Отмена",()=>{DialogResult=DialogResult.Cancel;Close();});layout.Controls.Add(buttons,0,11);layout.SetColumnSpan(buttons,2);AcceptButton=done;CancelButton=cancel;
                boundary.SelectedIndexChanged+=delegate{State();};State();
                if(existing!=null){title.Text=existing.Name;extension.Text=existing.Extension;header.Text=existing.HeaderHex;footer.Text=existing.FooterHex;offset.Value=existing.HeaderOffset;minimum.Value=existing.MinBytes;maximum.Value=existing.MaxBytes;fixedSize.Value=Math.Max(1,existing.FixedBytes);boundary.SelectedIndex=existing.FixedBytes>0?1:0;}
                UiTheme.ApplyTree(this);
            }
            static void Row(TableLayoutPanel p,int row,string text,Control control){p.Controls.Add(new Label{Text=text,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft,ForeColor=UiTheme.Muted},0,row);control.Dock=DockStyle.Fill;control.Name="signature-"+row;control.Margin=new Padding(3,5,3,5);p.Controls.Add(control,1,row);}
            void State(){footer.Enabled=boundary.SelectedIndex==0;fixedSize.Enabled=boundary.SelectedIndex==1;}
            void Commit(){try{Rule=UserSignatureRecovery.Validate(new[]{new UserSignatureRule{Id=identity,Name=title.Text,Extension=extension.Text,HeaderHex=header.Text,HeaderOffset=(long)offset.Value,FooterHex=boundary.SelectedIndex==0?footer.Text:"",FixedBytes=boundary.SelectedIndex==1?(long)fixedSize.Value:0,MinBytes=(long)minimum.Value,MaxBytes=(long)maximum.Value}}).Single();DialogResult=DialogResult.OK;Close();}catch(IOException e){status.Text=e.Message.Replace("USER_SIGNATURE_INVALID: ","");status.ForeColor=Color.Firebrick;}}
            void Sample()
            {
                using(var dialog=new OpenFileDialog{Title="Исправный образец нужного типа",Filter="Все файлы|*.*"})if(dialog.ShowDialog(this)==DialogResult.OK)try{
                    var info=new FileInfo(dialog.FileName);for(var at=info.Directory;at!=null;at=at.Parent)if((at.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Путь образца содержит перенаправление.");if((info.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Файл-ссылка не подходит.");
                    using(var input=new FileStream(info.FullName,FileMode.Open,FileAccess.Read,FileShare.Read)){input.Position=(long)offset.Value;byte[] bytes=new byte[16];int n=input.Read(bytes,0,bytes.Length);if(n<4)throw new IOException("Не хватает байтов после выбранного смещения.");header.Text=BitConverter.ToString(bytes,0,n).Replace('-', ' ');status.Text="Начало образца прочитано. Его размер: "+input.Length+" байт. Укажи границу искомых файлов; размер образца автоматически не применяется.";if(String.IsNullOrWhiteSpace(extension.Text))extension.Text=info.Extension;}
                }catch(Exception e){if(!(e is IOException||e is UnauthorizedAccessException||e is ArgumentException))throw;status.Text=e.Message;}
            }
        }
    }
}
