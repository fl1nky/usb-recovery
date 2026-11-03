using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
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
    static void Loaded(ArchiveSearchPanel panel){var until=DateTime.UtcNow.AddSeconds(8);while(panel.IsBusy&&DateTime.UtcNow<until)Pump(20);Check(!panel.IsBusy,"owned search request completes");}
    static void StartSearch(ArchiveSearchPanel panel,long offset){typeof(ArchiveSearchPanel).GetMethod("StartSearch",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(panel,new object[]{offset});Loaded(panel);}
    static long PageOffset(ArchiveSearchPanel panel){return (long)typeof(ArchiveSearchPanel).GetField("pageOffset",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(panel);}
    static List<Dictionary<string,object>> Requests()
    {
        var rows=new List<Dictionary<string,object>>();string path=Path.Combine(Path.GetDirectoryName(HelperClient.Executable),"search-requests.jsonl");
        if(File.Exists(path)){var json=new System.Web.Script.Serialization.JavaScriptSerializer();foreach(string line in File.ReadAllLines(path))rows.Add(json.Deserialize<Dictionary<string,object>>(line));}return rows;
    }
    static Dictionary<string,object> LastRequest(){var rows=Requests();return rows[rows.Count-1];}
    static void Query(ArchiveSearchPanel panel,string words){Field<TextBox>(panel,"query").Text=words;Field<Button>(panel,"search").PerformClick();Loaded(panel);}
    static void Pagination()
    {
        using(var host=new Form{ClientSize=new Size(1000,740),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000)})
        using(var panel=new ArchiveSearchPanel()){
            host.Controls.Add(panel);host.Show();Pump(20);panel.SelectArchive("owned-pagination");Loaded(panel);
            var next=Field<Button>(panel,"next");var previous=Field<Button>(panel,"previous");var grid=Field<DataGridView>(panel,"grid");var count=Field<Label>(panel,"count");
            Check(PageOffset(panel)==0&&next.Enabled&&!previous.Enabled&&grid.Rows.Count==100,"first search page supports forward navigation only");
            next.PerformClick();Loaded(panel);Check(PageOffset(panel)==100&&previous.Enabled&&Convert.ToInt64(LastRequest()["offset"])==100,"Next sends the next actual search page");
            previous.PerformClick();Loaded(panel);Check(PageOffset(panel)==0&&!previous.Enabled&&Convert.ToInt64(LastRequest()["offset"])==0,"Back returns to the actual first search page");
            string[] queries={"total99999","total100000","total100001","many"};long[] totals={99999,100000,100001,250000};
            for(int index=0;index<queries.Length;index++){
                Query(panel,queries[index]);StartSearch(panel,99800);
                Check(PageOffset(panel)==99800&&next.Enabled&&previous.Enabled,"penultimate supported page retains Next: "+totals[index]);
                next.PerformClick();Loaded(panel);
                Check(PageOffset(panel)==99900&&!next.Enabled&&previous.Enabled&&Convert.ToInt64(LastRequest()["offset"])==99900,"last supported page keeps Back and prevents invalid Next: "+totals[index]);
                Check(grid.Rows.Count==Math.Min(100,totals[index]-99900),"last page retains actual matching rows: "+totals[index]);
                Check(count.Text.Contains("уточни запрос")== (totals[index]>100000),"refinement hint appears only when matches exceed the search window");
                int requests=Requests().Count;string body=Field<TextBox>(panel,"body").Text,origin=Field<TextBox>(panel,"provenance").Text;var selected=grid.SelectedRows[0].Tag;
                next.PerformClick();Pump(30);Check(Requests().Count==requests,"disabled Next never dispatches an unsupported worker request");
                StartSearch(panel,100000);
                Check(Requests().Count==requests&&count.Text.Contains("100 000 совпадений"),"direct invalid-page request is explained without starting a worker");
                Check(PageOffset(panel)==99900&&Object.ReferenceEquals(selected,grid.SelectedRows[0].Tag)&&Field<TextBox>(panel,"body").Text==body&&Field<TextBox>(panel,"provenance").Text==origin&&Field<Button>(panel,"fullText").Enabled,"local window guard preserves selected message, provenance and full-text action");
                previous.PerformClick();Loaded(panel);Check(PageOffset(panel)==99800&&next.Enabled,"Back remains usable after reaching the limit");
            }
            Query(panel,"small");Check(PageOffset(panel)==0&&grid.Rows.Count==3&&!previous.Enabled&&!next.Enabled,"new search resets the offset and keeps small result navigation accurate");
            Query(panel,"many");StartSearch(panel,99800);Field<TextBox>(panel,"query").Text="small";next.PerformClick();Loaded(panel);
            Check(PageOffset(panel)==0&&grid.Rows.Count==3&&Convert.ToString(LastRequest()["query"])=="small"&&Convert.ToInt64(LastRequest()["offset"])==0,"changed query plus Next starts at its first page rather than reusing the old offset");
            Query(panel,"many");StartSearch(panel,99800);Field<TextBox>(panel,"query").Text="small";previous.PerformClick();Loaded(panel);
            Check(PageOffset(panel)==0&&grid.Rows.Count==3&&Convert.ToInt64(LastRequest()["offset"])==0,"changed query plus Back also starts at its first page");
            Query(panel,"many");StartSearch(panel,99800);Field<CheckBox>(panel,"regexMode").Checked=true;previous.PerformClick();Loaded(panel);
            Check(PageOffset(panel)==0&&Convert.ToString(LastRequest()["query_mode"])=="regex","changed Regex mode resets paging and reaches the worker unchanged");
            StartSearch(panel,99800);Field<ComboBox>(panel,"evidence").SelectedIndex=1;previous.PerformClick();Loaded(panel);
            Check(PageOffset(panel)==0&&Convert.ToString(LastRequest()["evidence"])=="export","changed evidence category resets paging and reaches the worker unchanged");
            Query(panel,"partial-many");StartSearch(panel,99900);
            Check(count.Text.Contains("есть замечания к архиву")&&count.Text.Contains("уточни запрос"),"last-page refinement advice retains existing archive warnings");
            var preserved=grid.SelectedRows[0].Tag;string preservedBody=Field<TextBox>(panel,"body").Text,preservedOrigin=Field<TextBox>(panel,"provenance").Text;
            Query(panel,"window-error");
            Check(count.Text.Contains("100 000 совпадений")&&!count.Text.Contains("Не удалось прочитать архив"),"worker window error has a specific useful explanation");
            Check(PageOffset(panel)==99900&&Object.ReferenceEquals(preserved,grid.SelectedRows[0].Tag)&&Field<TextBox>(panel,"body").Text==preservedBody&&Field<TextBox>(panel,"provenance").Text==preservedOrigin&&Field<Button>(panel,"fullText").Enabled&&previous.Enabled&&!next.Enabled,"worker window error preserves the useful last page and selection");
            Query(panel,"generic-error");Check(grid.Rows.Count==0&&Field<TextBox>(panel,"body").Text==""&&!previous.Enabled&&!next.Enabled,"other archive errors still clear stale results");
            Query(panel,"small");Check(PageOffset(panel)==0&&grid.Rows.Count==3&&!previous.Enabled&&!next.Enabled,"a new query works normally after either error");host.Close();
        }
    }
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
            Pagination();
            Console.WriteLine("PASS ArchiveTextUi: "+checks+" checks; actual bounded child protocol, Unicode pages, navigation, query-context resets, search-window limits, context highlighting and cancellation. Owned fixture worker only.");return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
