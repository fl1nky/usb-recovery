using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using UsbRecovery;

// UI state, navigation and synthetic result presentation only. No devices,
// profiles, helper process, cryptographic substitute or user image is opened.
public static class StorageUiTests
{
    static int checks,code;static string project,work;static bool passed;
    [DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern IntPtr SendMessage(IntPtr window,int message,IntPtr first,IntPtr second);
    static void Check(bool condition,string message){checks++;if(!condition)throw new Exception(message);}
    static T Field<T>(object instance,string name){return (T)instance.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(instance);}
    static void Set(object instance,string name,object value){instance.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).SetValue(instance,value);}
    static object Call(object instance,string name,params object[] arguments){return instance.GetType().GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic).Invoke(instance,arguments);}
    static IEnumerable<Control> Children(Control parent){foreach(Control child in parent.Controls){yield return child;foreach(var nested in Children(child))yield return nested;}}
    static void Fits(Control control,Form host,string name)
    {
        Rectangle bounds=host.RectangleToClient(control.RectangleToScreen(control.ClientRectangle));
        Check(control.Visible&&control.Width>0&&control.Height>0&&host.ClientRectangle.Contains(bounds),name+" fits window: "+bounds+" in "+host.ClientSize);
        Check(control.Parent.ClientRectangle.Contains(control.Bounds),name+" fits parent: "+control.Bounds+" in "+control.Parent.ClientSize);
        Check(control.Parent.GetChildAtPoint(new Point(control.Left+control.Width/2,control.Top+control.Height/2))==control,name+" has an uncovered centre");
    }
    static Control Focused(ContainerControl parent){Control active=parent.ActiveControl;while(active is ContainerControl&&((ContainerControl)active).ActiveControl!=null)active=((ContainerControl)active).ActiveControl;return active;}
    static HashSet<Control> Walk(Form form)
    {
        var seen=new HashSet<Control>();for(int i=0;i<200;i++){Control active=Focused(form);if(active!=null)seen.Add(active);if(!form.SelectNextControl(active,true,true,true,true))break;}return seen;
    }
    static void Shot(Form form,string name){using(var bitmap=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(work,name+".png"),ImageFormat.Png);}}
    static async Task Pause(){await Task.Delay(70);}
    static string Catalog()
    {
        string folder=Path.Combine(work,"synthetic-catalog");Directory.CreateDirectory(Path.Combine(folder,"files.1"));string file=Path.Combine(folder,"files.1","recipe.txt");File.WriteAllText(file,"Only a generated UI fixture",new UTF8Encoding(false));
        var item=new RecoveredItem{Name="recipe.txt",Path="files.1/recipe.txt",Extension=".txt",Category="Документы",Method="Synthetic UI",Status="Не проверялось",Quality="unverified",QualityLabel="Нужна проверка",Sha256=RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{}),Bytes=new FileInfo(file).Length};
        var index=new RecoveryFileIndex{Candidates=1};index.Items.Add(item);RecoveryCore.SaveJson(Path.Combine(folder,"files-index.json"),index);return folder;
    }
    static void Keys(StorageRecoveryPanel panel,Form host,int mode)
    {
        var modes=Field<TabControl>(panel,"modes");modes.SelectedIndex=mode;
        TextBox secret=Field<TextBox>(panel,mode==0?"apfsPassword":"password");
        secret.Text="Synthetic-secret-DO-NOT-LOG-702913";
        Check(secret.UseSystemPasswordChar&&SendMessage(secret.Handle,0xD2,IntPtr.Zero,IntPtr.Zero)!=IntPtr.Zero,"secret is actually masked by native edit control "+mode);
        Check(!Children(panel).Where(c=>!(c is TextBox)).Any(c=>c.Text.Contains(secret.Text)),"secret is absent from labels and status "+mode);
        secret.Focus();var visited=Walk(host);Check(secret.CanSelect&&secret.TabStop&&visited.Contains(secret),"secret reachable by keyboard traversal "+mode);secret.Clear();
    }
    static async Task Raid(StorageRecoveryPanel panel,Form host)
    {
        Field<TabControl>(panel,"modes").SelectedIndex=1;await Pause();var grid=Field<DataGridView>(panel,"members");var level=Field<ComboBox>(panel,"level");var layout=Field<ComboBox>(panel,"layoutKind");
        Fits(grid,host,"RAID member grid");Check(grid.Columns.Count==3&&!grid.AllowUserToAddRows&&grid.Columns[2] is DataGridViewCheckBoxColumn,"ordered explicit RAID member model");
        foreach(string value in new[]{"0","1","5","6","10"}){level.SelectedItem=value;Check(layout.Items.Cast<string>().SequenceEqual(RaidImageBuilder.SupportedLayouts(value)),"layout selection follows actual supported engine for RAID "+value);Check(layout.SelectedIndex>=0,"layout has explicit visible choice "+value);}
        var chunk=Field<Control>(panel,"chunk")as ComboBox;Check(chunk!=null,"chunk is a fixed choice instead of accepting unsupported intermediate values");
        if(chunk!=null){Check(chunk.Items.Cast<object>().All(v=>{long chunkBytes=Convert.ToInt64(v);return chunkBytes>=512&&chunkBytes<=RaidImageBuilder.MaximumChunkSize&&(chunkBytes&(chunkBytes-1))==0;}),"all offered chunks are supported powers of two");level.SelectedItem="1";Check(!chunk.Enabled,"chunk disabled for a mirror where it is irrelevant");level.SelectedItem="5";Check(chunk.Enabled,"stripe chunk available for RAID5");foreach(object choice in chunk.Items)if(Convert.ToInt64(choice)==65536){chunk.SelectedItem=choice;break;}}
        grid.Rows.Clear();grid.Rows.Add(Path.Combine(work,"first.dd"),"0",false);grid.Rows.Add(Path.Combine(work,"second.dd"),"512",false);grid.Rows.Add(Path.Combine(work,"third.dd"),"1024",false);
        Action<int> select=row=>{grid.ClearSelection();grid.Rows[row].Selected=true;grid.CurrentCell=grid.Rows[row].Cells[0];};
        Button up=Children(panel).OfType<Button>().First(b=>b.Text=="↑"),down=Children(panel).OfType<Button>().First(b=>b.Text=="↓");Fits(up,host,"RAID move up");Fits(down,host,"RAID move down");
        select(1);up.PerformClick();Check(Convert.ToString(grid.Rows[0].Cells[0].Value).EndsWith("second.dd"),"move up preserves exact member order");down.PerformClick();Check(Convert.ToString(grid.Rows[0].Cells[0].Value).EndsWith("first.dd")&&Convert.ToString(grid.Rows[1].Cells[1].Value)=="512","move down preserves path and offset");
        select(0);up.PerformClick();Check(Convert.ToString(grid.Rows[0].Cells[0].Value).EndsWith("first.dd"),"top boundary cannot wrap member order");select(2);down.PerformClick();Check(Convert.ToString(grid.Rows[2].Cells[0].Value).EndsWith("third.dd"),"bottom boundary cannot wrap member order");
        Children(panel).OfType<Button>().First(b=>b.Text=="Нет диска").PerformClick();Check(grid.Rows.Count==4&&Convert.ToBoolean(grid.Rows[3].Cells[2].Value),"missing member is an explicit ordered row");
        TextBox size=Field<TextBox>(panel,"raidSize"),sha=Field<TextBox>(panel,"expectedSha");size.Text="2048";sha.Text=new string('a',64);var config=(RaidConfiguration)Call(panel,"ReadRaid");
        Check(config.LogicalSize==2048&&config.ExpectedSha256==new string('a',64),"known logical length and optional reference hash reach engine configuration");Check(config.Members.Count==4&&config.Members[1].Offset==512&&config.Members[3].Missing,"grid values and missing row reach engine without inference");
        Fits(size,host,"logical RAID size");Fits(sha,host,"reference RAID hash");Check(sha.MaxLength==64,"reference hash entry bounded");size.Text="0";sha.Clear();
        select(3);Children(panel).OfType<Button>().First(b=>b.Text=="Убрать").PerformClick();Check(grid.Rows.Count==3,"remove acts on selected ordered member");grid.Focus();var keyboard=Walk(host);Check(keyboard.Contains(grid)&&keyboard.Contains(up)&&keyboard.Contains(down),"RAID grid and ordering tools reachable by keyboard");
    }
    static async Task Busy(StorageRecoveryPanel panel,Form host)
    {
        var activity=Field<RecoveryActivityView>(panel,"activity");var start=Field<Button>(panel,"start");var stop=Field<Button>(panel,"stop");
        using(var cancellation=new CancellationTokenSource()){
            Set(panel,"cancellation",cancellation);Call(panel,"SetBusy",true);activity.IsActive=true;activity.ClearProgress();
            try{Check(panel.IsBusy&&!start.Enabled&&stop.Enabled&&!Field<TabControl>(panel,"modes").Enabled,"busy state locks source mode and enables cancellation");Fits(stop,host,"busy storage stop");stop.Focus();Check(Walk(host).Contains(stop),"stop reachable by keyboard while busy");stop.PerformClick();Check(cancellation.IsCancellationRequested&&!stop.Enabled,"stop requests cancellation once");Check(!activity.IsComplete,"requesting stop never claims successful preparation");}
            finally{activity.IsActive=false;Set(panel,"cancellation",null);Call(panel,"SetBusy",false);}
        }
        await Pause();Check(!panel.IsBusy&&start.Enabled&&!stop.Enabled,"busy state can return to idle without a worker or success archive");
    }
    static async Task Results(StorageRecoveryPanel panel,Form host)
    {
        string folder=Catalog();Set(panel,"lastCatalog",folder);Set(panel,"lastRoot",work);Set(panel,"prepared",new StoragePreparedResult{Directory=folder,Image=Path.Combine(work,"synthetic-prepared.dd")});Call(panel,"SetBusy",false);
        var found=Field<Button>(panel,"found");var search=Field<Button>(panel,"searchImage");var open=Field<Button>(panel,"open");Check(found.Enabled&&search.Enabled&&open.Enabled,"prepared result actions enable only with actual local catalog");Fits(found,host,"found action");Fits(search,host,"search prepared action");Fits(open,host,"open output folder action");
        using(var viewer=new RecoveryFilesForm(folder)){
            viewer.ShowInTaskbar=false;viewer.StartPosition=FormStartPosition.Manual;viewer.Location=new Point(-20000,-20000);viewer.Show(host);await Pause();
            foreach(bool compact in new[]{true,false}){viewer.ClientSize=compact?new Size(900,650):new Size(1200,820);await Pause();var export=Field<Button>(viewer,"export");Fits(export,viewer,"result export "+compact);Field<CheckBox>(viewer,"all").Checked=true;Check(export.Enabled&&export.CanSelect,"marked synthetic result can be exported "+compact);}
            viewer.Close();
        }
        Set(panel,"lastCatalog",null);Set(panel,"lastRoot",null);Set(panel,"prepared",null);Call(panel,"SetBusy",false);Check(!found.Enabled&&!search.Enabled&&!open.Enabled,"absent prepared data never enables result actions");
    }
    static async Task Work()
    {
        using(var host=new RecoveryHub(false)){
            host.ShowInTaskbar=false;host.StartPosition=FormStartPosition.Manual;host.Location=new Point(-20000,-20000);host.Show();await Pause();
            var panel=Field<StorageRecoveryPanel>(host,"storage");var nav=Field<Dictionary<string,Button>>(host,"navigation")["storage"];nav.PerformClick();await Pause();
            Check(panel.Visible&&nav is NavigationButton&&((NavigationButton)nav).Selected,"storage navigation shows actual panel");var modes=Field<TabControl>(panel,"modes");var source=Field<Panel>(panel,"sourcePanel");var layout=Field<TableLayoutPanel>(panel,"root");
            Check(modes.TabPages.Cast<TabPage>().Select(p=>p.Text).SequenceEqual(new[]{"APFS","RAID","BitLocker"}),"all three distinct storage workflows exist");
            foreach(bool compact in new[]{false,true}){
                if(compact)host.Size=host.MinimumSize;else host.ClientSize=new Size(1280,920);await Pause();Fits(nav,host,"storage navigation "+compact);Fits(panel,host,"storage workspace "+compact);
                for(int mode=0;mode<3;mode++){
                    modes.SelectedIndex=mode;await Pause();Fits(modes,host,"mode tabs "+mode+"/"+compact);Fits(Field<RecoveryActivityView>(panel,"activity"),host,"storage activity "+mode+"/"+compact);
                    foreach(string field in new[]{"start","stop","found","searchImage","open"})Fits(Field<Button>(panel,field),host,field+" "+mode+"/"+compact);
                    Check(source.Visible==(mode!=1)&&(layout.GetRowHeights()[1]==0)==(mode==1),"source row collapses exactly for RAID "+compact);Check(Field<CheckBox>(panel,"searchAfter").Enabled==(mode!=0),"APFS own extraction workflow mode="+mode+" selected="+modes.SelectedIndex+" enabled="+Field<CheckBox>(panel,"searchAfter").Enabled+" compact="+compact);
                    if(mode!=1){Fits(source,host,"source row "+compact);Fits(Field<TextBox>(panel,"image"),host,"source image field "+compact);Fits(Field<Button>(panel,"probe"),host,"probe action "+compact);Keys(panel,host,mode);}
                    else await Raid(panel,host);
                }
                Shot(host,compact?"storage-compact":"storage-normal");await Busy(panel,host);
            }
            var keyKind=Field<ComboBox>(panel,"keyKind");keyKind.SelectedIndex=2;Check(!Field<TextBox>(panel,"password").Enabled,"BEK selection disables irrelevant password input");keyKind.SelectedIndex=1;Check(Field<TextBox>(panel,"password").Enabled,"password entry restored for passphrase mode");await Results(panel,host);
            host.Navigate("usb");await Pause();Check(!panel.Visible&&!Field<System.Windows.Forms.Timer>(Field<RecoveryActivityView>(panel,"activity"),"timer").Enabled,"hidden idle storage view leaves no timer");host.Close();
        }
    }
    [STAThread]public static int Main(string[] args)
    {
        project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","storage-ui-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
        using(var runner=new Form{ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-20000,-20000),Size=new Size(2,2)}){runner.Shown+=async delegate{try{await Work();passed=true;Console.WriteLine("PASS StorageUi: "+checks+" checks; real Application.Run, minimum/normal layout, APFS/RAID/BitLocker navigation, native masked secrets, explicit RAID parameters/order, keyboard cancellation and synthetic result/export UI; no helper, devices, profiles or cryptographic substitute.");}catch(Exception error){Console.Error.WriteLine(error);code=1;}finally{foreach(var form in Application.OpenForms.Cast<Form>().Where(f=>f!=runner).ToArray())form.Dispose();runner.Close();}};Application.Run(runner);}
        if(passed&&Path.GetFullPath(work).StartsWith(Path.Combine(project,".build","storage-ui-"),StringComparison.OrdinalIgnoreCase))try{Directory.Delete(work,true);}catch(IOException){}catch(UnauthorizedAccessException){}return code;
    }
}
