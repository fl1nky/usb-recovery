using System;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class ArchiveMessageTextForm:Form
    {
        readonly TextBox body=new TextBox();
        readonly Label status=new Label();
        readonly Button first=new Button(),previous=new Button(),next=new Button(),found=new Button(),copy=new Button();
        readonly string archive,key;
        readonly long matchOffset;
        CancellationTokenSource pending;
        ArchiveTextPage current;
        bool busy;

        public ArchiveMessageTextForm(string archive,ArchiveMessage message)
        {
            this.archive=archive;key=message.archive_record_key;matchOffset=Math.Max(0,message.match_offset);
            Text="Полный текст сообщения";Size=new Size(960,720);MinimumSize=new Size(740,480);StartPosition=FormStartPosition.CenterParent;KeyPreview=true;
            var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(16),ColumnCount=1,RowCount=3};
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute,54));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,38));Controls.Add(layout);
            var actions=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=5,RowCount=1,Margin=Padding.Empty};for(int column=0;column<5;column++)actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,20));
            Add(actions,first,"В начало",delegate{LoadPage(0);});Add(actions,previous,"← Назад",delegate{LoadPage(Math.Max(0,current.text_offset-65536));});Add(actions,next,"Далее →",delegate{LoadPage(current.next_offset);});
            Add(actions,found,"К совпадению",delegate{LoadPage(matchOffset);});Add(actions,copy,"Копировать фрагмент",delegate{if(current!=null)try{Clipboard.SetText(current.text);}catch{}});layout.Controls.Add(actions,0,0);
            body.Name="message-full-text";body.Dock=DockStyle.Fill;body.Multiline=true;body.ReadOnly=true;body.ScrollBars=ScrollBars.Both;body.WordWrap=true;body.BackColor=Color.White;layout.Controls.Add(body,0,1);
            status.Name="message-page-status";status.Dock=DockStyle.Fill;status.AutoEllipsis=true;status.TextAlign=ContentAlignment.MiddleLeft;layout.Controls.Add(status,0,2);
            Shown+=delegate{LoadPage(matchOffset);};FormClosing+=delegate{if(pending!=null)pending.Cancel();};KeyDown+=delegate(object sender,KeyEventArgs args){if(args.KeyCode==Keys.Escape){args.Handled=true;Close();}};
            UiTheme.ApplyTree(this);SetButtons();
        }
        static void Add(Control parent,Button button,string text,EventHandler click)
        {button.Text=text;button.Dock=DockStyle.Fill;button.FlatStyle=FlatStyle.Flat;button.Click+=click;parent.Controls.Add(button);}
        void SetButtons()
        {first.Enabled=!busy&&current!=null&&current.text_offset>0;previous.Enabled=first.Enabled;next.Enabled=!busy&&current!=null&&!current.eof;found.Enabled=!busy&&current!=null&&current.text_offset!=matchOffset;copy.Enabled=!busy&&current!=null&&!String.IsNullOrEmpty(current.text);}
        async void LoadPage(long offset)
        {
            if(busy||IsDisposed)return;busy=true;status.Text="Чтение сохранённого текста…";SetButtons();
            var cancellation=new CancellationTokenSource();pending=cancellation;ArchiveTextPage page=null;bool cancelled=false;
            try{page=await Task.Run(()=>ArchiveSearchService.ReadPage(archive,key,offset,cancellation.Token)).ConfigureAwait(false);}
            catch(OperationCanceledException){cancelled=true;}catch{}
            if(IsDisposed||!IsHandleCreated){cancellation.Dispose();return;}
            try{BeginInvoke(new Action(()=>{
                if(IsDisposed){cancellation.Dispose();return;}pending=null;cancellation.Dispose();busy=false;
                if(cancelled){status.Text="Чтение остановлено";SetButtons();return;}
                if(page==null||page.status=="error"){status.Text=page!=null&&page.code=="RECORD_CHANGED"?"Архив изменился. Выполни поиск снова, чтобы выбрать актуальную запись.":"Не удалось прочитать этот фрагмент. Исходный архив сохранён.";SetButtons();return;}
                current=page;body.Text=page.text;status.Text="Символы "+page.text_offset+"–"+page.next_offset+" из "+page.text_length+(page.eof?" · конец сообщения":"");SetButtons();
            }));}catch(InvalidOperationException){cancellation.Dispose();}
        }
    }
}
