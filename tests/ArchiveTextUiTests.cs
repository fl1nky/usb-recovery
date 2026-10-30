using System;
using System.Drawing;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using UsbRecovery;

public static class ArchiveTextUiTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static T Field<T>(object owner,string name) where T:class{return (T)owner.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(owner);}
    static void Pump(int milliseconds){var until=DateTime.UtcNow.AddMilliseconds(milliseconds);while(DateTime.UtcNow<until){Application.DoEvents();Thread.Sleep(10);}}
    static void Loaded(ArchiveMessageTextForm form){var until=DateTime.UtcNow.AddSeconds(8);while((bool)form.GetType().GetField("busy",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(form)&&DateTime.UtcNow<until)Pump(20);Check(!(bool)form.GetType().GetField("busy",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(form),"page request completes");}
    [STAThread] public static int Main()
    {
        try{
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);string key="sqlite:1:"+new string('a',64);
            var first=ArchiveSearchService.ReadPage("valid",key,0,CancellationToken.None);
            Check(first.text_offset==0&&first.next_offset==65536&&!first.eof,"first bounded page has code-point extent");
            var middle=ArchiveSearchService.ReadPage("valid",key,65536,CancellationToken.None);
            Check(middle.text.Contains(Char.ConvertFromUtf32(0x1f967))&&middle.next_offset==131072,"astral character does not shift page boundaries");
            var last=ArchiveSearchService.ReadPage("valid",key,middle.next_offset,CancellationToken.None);
            Check(last.eof&&(first.text+middle.text+last.text).EndsWith(" end"),"pages cover complete text through EOF");
            foreach(string bad in new[]{"wrong-key","wrong-offset","wrong-length","surrogate","over-limit","partial-page"}){
                bool rejected=false;try{ArchiveSearchService.ReadPage(bad,key,0,CancellationToken.None);}catch(System.IO.IOException){rejected=true;}Check(rejected,"malformed page protocol rejected: "+bad);
            }
            using(var cancel=new CancellationTokenSource(100)){
                bool cancelled=false;try{ArchiveSearchService.ReadPage("hang",key,0,cancel.Token);}catch(OperationCanceledException){cancelled=true;}Check(cancelled,"cancellation terminates child and returns promptly");
            }
            using(var form=new ArchiveMessageTextForm("valid",new ArchiveMessage{archive_record_key=key,match_offset=70008})){
                form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.Show();Pump(20);Loaded(form);
                Check(Field<TextBox>(form,"body").Text.StartsWith("needle"),"viewer opens at actual code-point match");
                form.Size=form.MinimumSize;Pump(20);var actions=Field<Button>(form,"copy").Parent;
                bool contained=true;foreach(Control control in actions.Controls)contained&=control.Right<=actions.ClientSize.Width&&control.Bottom<=actions.ClientSize.Height;
                Check(contained,"all paging actions remain visible at minimum window size");
                Check(Field<Button>(form,"previous").Enabled&&Field<Button>(form,"next").Enabled,"navigation reflects middle page");
                Field<Button>(form,"first").PerformClick();Loaded(form);Check(Field<TextBox>(form,"body").Text.StartsWith("start ")&&!Field<Button>(form,"previous").Enabled,"beginning navigation loads actual first page");
                Field<Button>(form,"next").PerformClick();Loaded(form);Check(Field<TextBox>(form,"body").Text==middle.text,"next navigation uses returned code-point offset");
                Field<Button>(form,"next").PerformClick();Loaded(form);Check(!Field<Button>(form,"next").Enabled&&Field<Label>(form,"status").Text.Contains("конец сообщения"),"EOF disables next and reports full extent");form.Close();
            }
            using(var host=new Form{ClientSize=new Size(900,740),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000)})
            using(var panel=new ArchiveSearchPanel()){
                host.Controls.Add(panel);host.Show();Pump(20);var grid=Field<DataGridView>(panel,"grid");int row=grid.Rows.Add();
                var record=new ArchiveMessage{text=Char.ConvertFromUtf32(0x1f967)+"\r\nneedle",text_truncated=true,text_offset=100,text_end=109,text_length=200000,match_offset=103,match_end=109,archive_record_key=key};
                grid.Rows[row].Tag=record;grid.Rows[row].Selected=true;grid.CurrentCell=grid.Rows[row].Cells[0];
                typeof(ArchiveSearchPanel).GetMethod("ShowMessage",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(panel,null);
                Check(Field<TextBox>(panel,"body").SelectedText=="needle","context selection converts astral and newline coordinates correctly");
                Check(Field<Button>(panel,"fullText").Enabled&&Field<Button>(panel,"copy").Text=="Копировать фрагмент","long snippet offers full-text reader and accurate copy label");
                Check(Field<TextBox>(panel,"provenance").Text.Contains("100–109 из 200000"),"snippet extent is explicit");
                var previewRecord=new ArchiveMessage{text=new string('x',16000)+"needle"+new string('y',49000),text_truncated=true,text_offset=100,text_end=65106,match_offset=16100,match_end=16106};
                string preview=(string)typeof(ArchiveSearchPanel).GetMethod("OneLine",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(panel,new object[]{previewRecord.text,previewRecord});
                Check(preview.Contains("needle")&&preview.StartsWith("…"),"grid preview uses actual long regex match coordinates");
                record.match_offset=102;record.match_end=103;typeof(ArchiveSearchPanel).GetMethod("ShowMessage",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(panel,null);
                Check(Field<TextBox>(panel,"body").SelectionStart==3&&Field<TextBox>(panel,"body").SelectionLength==1,"CRLF interior boundary does not highlight the following text");host.Close();
            }
            Console.WriteLine("PASS ArchiveTextUi: "+checks+" checks; actual bounded child protocol, Unicode pages, navigation, context highlighting and cancellation. Owned fixture worker only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
