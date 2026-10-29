using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using UsbRecovery;

public static class DeepRecoveryUiTests
{
    static int checks;
    static void Check(bool v,string name){checks++;if(!v)throw new Exception(name);}
    static IEnumerable<Control> Children(Control p){foreach(Control c in p.Controls){yield return c;foreach(var child in Children(c))yield return child;}}
    static T Field<T>(object p,string name) where T:class{return p.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(p) as T;}
    [STAThread]public static int Main(string[] args)
    {
        string project=Path.GetFullPath(args[0]),work=Path.Combine(project,"tests","DeepRecoveryWork");Directory.CreateDirectory(work);
        try{
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            using(var form=new RecoveryForm(false)){form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.ShowInTaskbar=false;form.ClientSize=new Size(1000,980);form.Show();Application.DoEvents();
                var settings=Field<RecoverySettingsPanel>(form,"searchSettings");Check(settings!=null&&settings.TabPages.Count==5,"methods/formats/imaging/help tabs");var checksByName=Children(settings).OfType<CheckBox>().ToDictionary(x=>x.Name);Check(checksByName.Count==23,"all recovery options exposed as checkboxes");Check(!settings.Selection().JpegFragments&&!settings.Selection().KeepCorrupted&&!settings.Selection().TolerateReadErrors,"expensive/uncertain imaging modes opt-in");
                Check(Field<Button>(form,"fileList").Enabled,"previous results accessible without rescanning source");
                settings.SelectedIndex=1;Application.DoEvents();Check(!checksByName["usb-option-photos"].Enabled,"all-formats precedence clear");checksByName["usb-option-other"].Checked=false;Check(checksByName["usb-option-photos"].Enabled,"specific formats selectable");checksByName["usb-option-photos"].Checked=false;Check(!settings.Selection().Photos&&!settings.Selection().Other,"UI choices enter actual options");
                settings.SelectedIndex=0;Application.DoEvents();using(var image=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,new Rectangle(Point.Empty,image.Size));image.Save(Path.Combine(work,"USB-methods.png"),ImageFormat.Png);}
                form.ClientSize=new Size(850,740);Application.DoEvents();Check(form.AutoScroll&&!form.VerticalScroll.Visible&&Field<Button>(form,"start").Visible,"small window keeps primary controls visible without whole-window scrolling");form.Hide();
            }
            string root=Path.Combine(work,"ui-results");Directory.CreateDirectory(Path.Combine(root,"files.1"));File.WriteAllText(Path.Combine(root,"files.1","Рецепт.txt"),"Искусственный семейный рецепт");File.WriteAllBytes(Path.Combine(root,"files.1","photo.webp"),new byte[]{1,2,3,4});PhotoCatalog.Build(root,CancellationToken.None,null);RecoveryCatalog.Build(root,CancellationToken.None,null);
            using(var form=new RecoveryFilesForm(root)){form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.ShowInTaskbar=false;form.Show();Application.DoEvents();var grid=Field<DataGridView>(form,"grid");var query=Field<TextBox>(form,"query");var all=Field<CheckBox>(form,"all");Check(grid.Rows.Count==2,"native file list opens");query.Text="рецепт";Application.DoEvents();Check(grid.Rows.Count==1,"Unicode result filtering");all.Checked=true;Check(Field<HashSet<string>>(form,"selected").Count==1,"select filtered results");query.Clear();Check(grid.Rows.Count==2&&Field<HashSet<string>>(form,"selected").Count==1,"selection retained across filters");using(var image=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,new Rectangle(Point.Empty,image.Size));image.Save(Path.Combine(work,"USB-results.png"),ImageFormat.Png);}form.Hide();}
            Console.WriteLine("PASS "+checks+" USB UI assertions; synthetic files only, device discovery disabled.");return 0;
        }catch(Exception e){Console.WriteLine("FAIL "+e);return 1;}
    }
}
