using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using UsbRecovery;

public static class CompetitionUiTests
{
    static string root;static int checks,code;
    static void Check(bool value,string text){checks++;if(!value)throw new Exception(text);}
    static T Field<T>(object target,string name){return (T)target.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(target);}
    static void Shot(Form form,string name){using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(root,name+".png"),ImageFormat.Png);}}
    static async Task Show(Form form){form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.Show();await Task.Delay(100);}
    static RecoveredItem Item(string directory,string name,string text,params string[] originals)
    {
        Directory.CreateDirectory(Path.Combine(directory,"files.1"));string path=Path.Combine(directory,"files.1",name);File.WriteAllText(path,text,new UTF8Encoding(false));var item=new RecoveredItem{Name=name,Path="files.1/"+name,Extension=".txt",Category="Документы",Method="Synthetic UI",Status="Тестовый файл",Quality="unverified",QualityLabel="Не проверено",IntegrityDetail="Синтетические данные для проверки интерфейса",Sha256=RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{}),Bytes=new FileInfo(path).Length};
        foreach(string original in originals)item.OriginalLocations.Add(new OriginalLocation{Path=original,Status="verified_parent_chain",VolumeOffset=0,CandidatePath=item.Path,Evidence="Synthetic UI fixture"});return item;
    }
    static async Task Work()
    {
        using(var main=new RecoveryForm(false)){
            await Show(main);var button=Field<Button>(main,"continueJob");Check(button.Text=="Продолжить…"&&button.Enabled,"explicit continue action available without device");main.ClientSize=new Size(850,740);await Task.Delay(50);Check(main.RectangleToClient(button.RectangleToScreen(button.ClientRectangle)).Right<main.ClientSize.Width,"continue action fits minimum");Check(!main.HorizontalScroll.Visible,"minimum source form not cropped");Shot(main,"Competition-main-compact");main.Close();
        }
        using(var hub=new RecoveryHub(false)){await Show(hub);Shot(hub,"Competition-main");hub.Close();}
        string archive=Path.Combine(root,"results");var first=Item(archive,"recipe.txt","Рецепт пирожков\nСемейный текст","/Family/Pies/recipe.txt","/Notes/copy.txt");var second=Item(archive,"homework.txt","Другой файл","/School/homework.txt");var third=Item(archive,"unknown.txt","Путь неизвестен");RecoveryCore.SaveJson(Path.Combine(archive,"files-index.json"),new RecoveryFileIndex{Candidates=4,Items=new List<RecoveredItem>{first,second,third}});
        using(var form=new RecoveryFilesForm(archive)){
            await Show(form);var grid=Field<DataGridView>(form,"grid");var tree=Field<TreeView>(form,"folders");form.ShowFolderBrowser(true);await Task.Delay(50);Check(grid.Rows.Count==3,"all originals visible initially");Check(tree.Nodes.Count==3,"all files, known volume, unknown bucket");
            var volume=tree.Nodes.Cast<TreeNode>().Single(x=>Convert.ToString(x.Tag)=="NTFS:0");var family=volume.Nodes.Cast<TreeNode>().Single(x=>x.Text=="Family");tree.SelectedNode=family;await Task.Delay(50);Check(grid.Rows.Count==1&&((RecoveredItem)grid.Rows[0].Tag).Path==first.Path,"folder filter uses recovered original path");Field<CheckBox>(form,"all").Checked=true;await Task.Delay(50);Check(Field<HashSet<string>>(form,"selected").Count==1,"folder selection preserved by content");
            var notes=volume.Nodes.Cast<TreeNode>().Single(x=>x.Text=="Notes");tree.SelectedNode=notes;await Task.Delay(50);Check(grid.Rows.Count==1&&((RecoveredItem)grid.Rows[0].Tag).Path==first.Path,"same hash appears under all original aliases");
            tree.SelectedNode=tree.Nodes.Cast<TreeNode>().Single(x=>Convert.ToString(x.Tag)=="unknown");await Task.Delay(50);Check(grid.Rows.Count==1&&((RecoveredItem)grid.Rows[0].Tag).Path==third.Path,"unknown folder not invented");Check(Field<HashSet<string>>(form,"selected").Count==1&&Field<Label>(form,"count").Text.Contains("вне фильтра 1"),"hidden folder selection reported");
            tree.SelectedNode=tree.Nodes[0];Field<TextBox>(form,"query").Text="/Notes/";await Task.Delay(100);Check(grid.Rows.Count==1,"keyword finds alias-only directory");Check(Field<TextBox>(form,"details").Text.Contains("/Family/Pies/recipe.txt")&&Field<TextBox>(form,"details").Text.Contains("/Notes/copy.txt"),"all path evidence visible in details");Field<TextBox>(form,"query").Clear();tree.SelectedNode=family;await Task.Delay(50);Shot(form,"Competition-folders");
            form.ClientSize=new Size(900,650);await Task.Delay(70);Check(!form.HorizontalScroll.Visible&&Field<Button>(form,"export").Visible,"folder browser remains usable at minimum");Shot(form,"Competition-folders-compact");form.ShowFolderBrowser(false);Check(grid.Rows.Count==3,"hiding tree clears folder filter");form.Close();
        }
    }
    [STAThread]public static int Main(string[] args)
    {
        root=Path.Combine(Path.GetFullPath(args[0]),"tests","CompetitionUI-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));Directory.CreateDirectory(root);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
        using(var runner=new Form{ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000),Size=new Size(2,2)}){
            runner.Shown+=async delegate{try{await Work();Console.WriteLine("PASS CompetitionUI: "+checks+" checks; real message loop, continue action, original-folder and alias filtering, Unicode, selection, unknown provenance, min layout; synthetic files only. "+root);}catch(Exception error){Console.Error.WriteLine(error);code=1;}finally{runner.Close();}};
            Application.Run(runner);
        }return code;
    }
}
