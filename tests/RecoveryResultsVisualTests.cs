using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using UsbRecovery;

public static class RecoveryResultsVisualTests
{
    static int checks;static string project,root;
    static void Check(bool value,string message){checks++;if(!value)throw new Exception(message);}
    static T Field<T>(object p,string name){return (T)p.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(p);}
    static void Pump(int milliseconds=80){var end=DateTime.UtcNow.AddMilliseconds(milliseconds);while(DateTime.UtcNow<end){Application.DoEvents();Thread.Sleep(10);}Application.DoEvents();}
    static void Show(Form form){form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.Show();Pump();}
    static void Shot(Form form,string name){using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(root,name+".png"),ImageFormat.Png);}}
    static void Model()
    {
        var empty=RecoveryResultsSnapshot.From(null);Check(empty.UniqueFiles==0&&empty.TotalBytes==0&&empty.Categories.Sum(c=>c.Count)==0,"empty state contains no invented data");
        var items=new List<RecoveredItem>{new RecoveredItem{Category="Фотографии",Quality="decoded",Bytes=100},new RecoveredItem{Category="Документы",Quality="container_crc",Bytes=200},new RecoveredItem{Category="Архивы",Quality="member_crc",Bytes=300},new RecoveredItem{Category="Видео",Quality="damaged",Bytes=400},new RecoveredItem{Category="Аудио",Quality="partial",Bytes=500},new RecoveredItem{Category="Unrecognized category",Quality="signature_candidate",Bytes=-1},new RecoveredItem{Category=null,Quality="future_unknown_quality",Bytes=0},null};items[0].Copies.AddRange(new[]{"copy1","copy2"});
        var index=new RecoveryFileIndex{Candidates=12,Items=items};var data=RecoveryResultsSnapshot.From(index);Check(data.UniqueFiles==7&&data.Candidates==12,"counts unique index rows and raw candidates separately");Check(data.TotalBytes==1500&&data.UnknownSizeFiles==1,"known bytes summed only once; negative size remains unknown");Check(data.CheckedFiles==3&&data.AttentionFiles==2&&data.UnknownFiles==2,"quality groups separate decoder/CRC, damage, unknown");Check(data.Categories.Sum(c=>c.Count)==data.UniqueFiles&&data.Categories.Single(c=>c.Name=="Прочее").Count==2,"unknown and absent category mapped to other without loss");items.Clear();Check(data.UniqueFiles==7&&data.TotalBytes==1500,"snapshot independent of mutable index");
        data=RecoveryResultsSnapshot.From(new RecoveryFileIndex{Items=new List<RecoveredItem>{new RecoveredItem{Bytes=Int64.MaxValue},new RecoveredItem{Bytes=7}}});Check(data.SizeClipped&&data.TotalBytes==Int64.MaxValue,"huge byte sum saturates explicitly rather than overflowing");Check(RecoveryResultsSnapshot.FormatBytes(0)=="0 Б"&&RecoveryResultsSnapshot.FormatBytes(1024).Contains("КиБ"),"readable binary size units");
        data=RecoveryResultsSnapshot.From(new RecoveryFileIndex{Items=new List<RecoveredItem>{new RecoveredItem{Quality="structure"},new RecoveredItem{Quality="fragment"},new RecoveredItem{Quality="encrypted"},new RecoveredItem{Quality="mapping_unknown"}}});Check(data.CheckedFiles==0&&data.AttentionFiles==0&&data.UnknownFiles==4,"structure fragments encryption and missing maps never called recovered or verified complete");
    }
    static void Motion()
    {
        bool original=MotionSettings.Enabled;try{
            MotionSettings.Enabled=false;using(var host=new Form{ClientSize=new Size(1000,160)})using(var view=new RecoveryResultsOverview{Dock=DockStyle.Fill}){
                host.Controls.Add(view);view.SetIndex(new RecoveryFileIndex{Items=new List<RecoveredItem>{new RecoveredItem{Category="Фотографии",Bytes=100}}});Show(host);Check(!view.IsAnimating,"global reduced motion keeps overview static");MotionSettings.Enabled=true;view.SetIndex(new RecoveryFileIndex{Items=new List<RecoveredItem>{new RecoveredItem{Category="Документы",Bytes=200}}});Check(view.IsAnimating==MotionSettings.Allowed,"animation starts only when effective system setting permits");host.Hide();Pump();Check(!view.IsAnimating,"hidden overview stops timer");host.Show();Pump(420);Check(!view.IsAnimating,"finite reveal stops after settling");view.ReduceMotion=true;view.SetIndex(new RecoveryFileIndex{Items=new List<RecoveredItem>{new RecoveredItem{Bytes=10}}});Check(!view.IsAnimating,"per-control reduced motion renders final state");view.ReduceMotion=false;view.Compact=true;Check(!view.IsAnimating,"compact overview has no idle timer");view.Dispose();MotionSettings.Enabled=false;MotionSettings.Enabled=true;Check(view.IsDisposed,"disposed overview unsubscribed from global setting");host.Close();
            }
        }finally{MotionSettings.Enabled=original;}
    }
    static string Fixture()
    {
        string directory=Path.Combine(root,"archive");Directory.CreateDirectory(directory);var index=new RecoveryFileIndex{Candidates=19};
        var specifications=new[]{new[]{"photo.png","Фотографии","decoded"},new[]{"recipe.txt","Документы","unverified"},new[]{"table.xlsx","Документы","container_crc"},new[]{"voice.ogg","Аудио","partial"},new[]{"film.mkv","Видео","damaged"},new[]{"archive.zip","Архивы","container_crc"},new[]{"unknown.bin","Unknown category","future_unknown_quality"}};
        foreach(var spec in specifications){string path=Path.Combine(directory,spec[0]);if(spec[0].EndsWith(".png")){using(var bitmap=new Bitmap(80,50)){using(var g=Graphics.FromImage(bitmap)){g.Clear(Color.FromArgb(62,117,184));g.DrawString("TEST",SystemFonts.DefaultFont,Brushes.White,10,18);}bitmap.Save(path,ImageFormat.Png);}}else File.WriteAllText(path,"Synthetic local result: "+spec[0],new UTF8Encoding(false));index.Items.Add(new RecoveredItem{Path=spec[0],Name=spec[0],Category=spec[1],Quality=spec[2],QualityLabel=spec[2],Method="Synthetic fixture",Sha256=RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{}),Bytes=new FileInfo(path).Length,Note="Synthetic local result, not user data"});}
        RecoveryCore.SaveJson(Path.Combine(directory,"files-index.json"),index);return directory;
    }
    static void HeaderButtons(RecoveryFilesForm form)
    {foreach(string name in new[]{"folderToggle","overviewToggle"}){var button=Field<Button>(form,name);Check(button.Visible&&button.Parent.ClientRectangle.Contains(button.Bounds)&&!button.Parent.Controls.OfType<Label>().Any(label=>label.Bounds.IntersectsWith(button.Bounds)),name+" visible without overlapping title at "+form.ClientSize);}}
    static void FormLayout()
    {
        using(var form=new RecoveryFilesForm(Fixture())){
            Show(form);var view=Field<RecoveryResultsOverview>(form,"overview");Check(!view.Compact&&view.Snapshot.UniqueFiles==7,"normal window displays real overview");Check(view.Snapshot.CheckedFiles==3&&view.Snapshot.AttentionFiles==2&&view.Snapshot.UnknownFiles==2,"form summary keeps truthful known and unknown statuses");form.ShowFolderBrowser(true);Pump(400);HeaderButtons(form);Shot(form,"Visual-results-overview");
            var targets=Field<List<KeyValuePair<Rectangle,string>>>(view,"targets");var target=targets.First(t=>t.Value=="Документы");typeof(Control).GetMethod("OnMouseClick",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(view,new object[]{new MouseEventArgs(MouseButtons.Left,1,target.Key.X+2,target.Key.Y+2,0)});Pump();var grid=Field<DataGridView>(form,"grid");Check(grid.Rows.Count==2&&grid.Rows.Cast<DataGridViewRow>().All(row=>((RecoveredItem)row.Tag).Category=="Документы"),"clicking actual chart legend filters results");Check(view.Snapshot.UniqueFiles==7,"overview remains scope of all unique findings under filter");var category=Field<ComboBox>(form,"category");category.SelectedItem="Прочее";Check(grid.Rows.Count==1&&Convert.ToString(grid.Rows[0].Cells[2].Value)=="Прочее","unknown categories are visible under the overview other filter");category.SelectedItem="Документы";
            Field<CheckBox>(form,"all").Checked=true;Check(Field<HashSet<string>>(form,"selected").Count==2,"filtered selection remains functional");form.ClientSize=new Size(900,650);Pump();HeaderButtons(form);Check(view.Compact&&!view.IsAnimating,"small window automatically uses static compact summary");var export=Field<Button>(form,"export");Check(form.RectangleToClient(export.RectangleToScreen(export.ClientRectangle)).Bottom<form.ClientSize.Height&&export.Enabled,"export stays visible and enabled at minimum");Check(!form.HorizontalScroll.Visible,"minimum layout has no whole-window horizontal scroll");Shot(form,"Visual-results-compact");form.ShowOverview(true);Pump();Check(!view.Compact,"user can expand summary at minimum");Check(form.RectangleToClient(export.RectangleToScreen(export.ClientRectangle)).Bottom<form.ClientSize.Height,"manual expansion does not hide export action");form.ShowOverview(false);Check(view.Compact&&Field<HashSet<string>>(form,"selected").Count==2,"collapsing summary preserves selection");form.Close();
        }
        string empty=Path.Combine(root,"empty");Directory.CreateDirectory(empty);RecoveryCore.SaveJson(Path.Combine(empty,"files-index.json"),new RecoveryFileIndex());using(var form=new RecoveryFilesForm(empty)){Show(form);Check(Field<RecoveryResultsOverview>(form,"overview").Snapshot.UniqueFiles==0&&!Field<RecoveryResultsOverview>(form,"overview").IsAnimating,"empty results static and truthful");Check(!Field<Button>(form,"export").Enabled,"empty result has no export action");form.Close();}
    }
    [STAThread]public static int Main(string[] args)
    {
        project=Path.GetFullPath(args[0]);root=Path.Combine(project,"tests","ResultsVisual-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff"));Directory.CreateDirectory(root);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
        try{Model();Motion();FormLayout();Console.WriteLine("PASS RecoveryResultsVisual: "+checks+" checks; actual unique counts, type filtering, unknown quality, overflow, reduced motion and timer lifecycle, adaptive layout, selection/export; synthetic local files only. "+root);return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
