using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using UsbRecovery;

public static class ModernRecoveryTests
{
    static string root;static int checks;
    static void Check(bool value,string name){checks++;if(!value)throw new Exception(name);}
    static string Hash(string file){return RecoveryCore.HashFile(file,CancellationToken.None,(a,b)=>{});}
    static void W16(byte[] b,int at,int v){BitConverter.GetBytes((ushort)v).CopyTo(b,at);}
    static void W32(byte[] b,int at,int v){BitConverter.GetBytes(v).CopyTo(b,at);}
    static void Text(byte[] b,int at,string text){Encoding.ASCII.GetBytes(text).CopyTo(b,at);}
    static T Field<T>(object item,string name) where T:class{return item.GetType().GetField(name,BindingFlags.NonPublic|BindingFlags.Instance).GetValue(item) as T;}
    static IEnumerable<Control> Children(Control rootControl){foreach(Control child in rootControl.Controls){yield return child;foreach(var c in Children(child))yield return c;}}
    static void Orphans()
    {
        var fat=new FilesystemRecoveryTests.FatFixture(12);byte[] payload=Encoding.UTF8.GetBytes("Семейный рецепт из потерянного каталога");fat.Put(payload,70,false);fat.SetFat(50,fat.End);int at=fat.Cluster(50);Text(fat.Bytes,at,".          ");fat.Bytes[at+11]=16;W16(fat.Bytes,at+26,50);Text(fat.Bytes,at+32,"..         ");fat.Bytes[at+43]=16;W16(fat.Bytes,at+58,0);
        Text(fat.Bytes,at+64,"RECIPE  TXT");fat.Bytes[at+75]=32;W16(fat.Bytes,at+90,70);W32(fat.Bytes,at+92,payload.Length);
        string image=Path.Combine(root,"unlinked-fat.dd");File.WriteAllBytes(image,fat.Bytes);string before=Hash(image),normal=Path.Combine(root,"no-orphans"),deep=Path.Combine(root,"with-orphans");Directory.CreateDirectory(normal);Directory.CreateDirectory(deep);
        Check(FilesystemRecovery.Recover(image,normal,CancellationToken.None,null)==0,"unlinked directory absent from ordinary root walk");
        Check(FilesystemRecovery.Recover(image,deep,CancellationToken.None,null,null,false,true)==1,"orphan sweep recovers disconnected directory child");string recovered=RecoveryCore.RecoveredFiles(deep).Single();Check(File.ReadAllBytes(recovered).SequenceEqual(payload),"orphan file bytes exact");Check(recovered.Contains("orphan-"),"orphan uncertainty visible in path");
        PhotoCatalog.Build(deep,CancellationToken.None,null);var index=RecoveryCatalog.Build(deep,CancellationToken.None,null);Check(index.Items[0].Status=="Потерянный каталог"&&index.Items[0].Note.Contains("факт удаления"),"catalog does not invent deletion state");Check(Hash(image)==before,"orphan sweep source unchanged");
        fat.Bytes[at+26]=51;string falseImage=Path.Combine(root,"false-orphan.dd");File.WriteAllBytes(falseImage,fat.Bytes);string falseOutput=Path.Combine(root,"false-output");Directory.CreateDirectory(falseOutput);Check(FilesystemRecovery.Recover(falseImage,falseOutput,CancellationToken.None,null,null,false,true)==0,"mismatched dot self-cluster is rejected");
        // A current file owns the same content cluster. Orphan recovery must
        // never reinterpret those allocated bytes as an unrelated deleted file.
        fat.Bytes[at+26]=50;fat.Entry(0,"CURRENT TXT",70,payload.Length,false,false);File.WriteAllBytes(falseImage,fat.Bytes);string liveOutput=Path.Combine(root,"live-output");Directory.CreateDirectory(liveOutput);Check(FilesystemRecovery.Recover(falseImage,liveOutput,CancellationToken.None,null,null,false,true)==0,"current ownership excludes orphan payload overlap");
    }
    static void Strings()
    {
        string text="Пирожки: секретный рецепт бабушки";string image=Path.Combine(root,"strings.dd");var stream=new MemoryStream();stream.Write(new byte[1024*1024-7],0,1024*1024-7);
        foreach(var encoding in new Encoding[]{new UTF8Encoding(false),Encoding.Unicode,Encoding.BigEndianUnicode}){byte[] payload=encoding.GetBytes(text);stream.Write(payload,0,payload.Length);stream.Write(new byte[]{0,0,255,255,0,0},0,6);}File.WriteAllBytes(image,stream.ToArray());string before=Hash(image),output=Path.Combine(root,"string-output");Directory.CreateDirectory(output);
        Check(RawTextSearch.Recover(image,output,"РЕЦЕПТ бабушки",CancellationToken.None,null)==3,"UTF8/UTF16 LE/BE literal Unicode words found across block boundary");var report=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(output,"text-search.json")));var records=(System.Collections.IEnumerable)report["files"];var encodings=new HashSet<string>();
        foreach(Dictionary<string,object> record in records){long offset=Convert.ToInt64(record["offset"]);int bytes=Convert.ToInt32(record["sourceBytes"]);string name=Convert.ToString(record["encoding"]);Encoding encoding=name=="utf-8"?Encoding.UTF8:name=="utf-16-le"?Encoding.Unicode:Encoding.BigEndianUnicode;string fragment=encoding.GetString(stream.ToArray(),(int)offset,bytes);Check(fragment.Contains("рецепт"),"exact source byte offset "+name);Check(Convert.ToString(record["deletedState"])=="unknown","deletion state unknown");encodings.Add(name);}
        Check(encodings.Count==3&&Hash(image)==before,"all encodings, input immutable");PhotoCatalog.Build(output,CancellationToken.None,null);var index=RecoveryCatalog.Build(output,CancellationToken.None,null);Check(index.Candidates==3&&index.Items.Count==1&&index.Items[0].Method=="Текстовый остаток","identical converted text grouped with all sources, not full document");
        var options=new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,Signatures=false,Containers=false,EmbeddedPhotos=false,LostPartitions=false,TextFragments=true,TextQuery="рецепт"};options.Validate();string pipe=Path.Combine(root,"text-pipeline");Directory.CreateDirectory(pipe);File.WriteAllText(image+".sha256",Hash(image));var result=RecoveryPipeline.Run(image,pipe,options,CancellationToken.None,s=>{});Check(result.Candidates==3&&File.Exists(result.FileCatalog),"standalone text method integrated into full pipeline");
        bool invalid=false;options.TextQuery="";try{options.Validate();}catch(ArgumentException){invalid=true;}Check(invalid,"empty text request rejected before scan");
        bool cancel=false;using(var token=new CancellationTokenSource()){token.Cancel();try{RawTextSearch.Recover(image,Path.Combine(root,"cancel"),"рецепт",token.Token,null);}catch(OperationCanceledException){cancel=true;}}Check(cancel&&!Directory.Exists(Path.Combine(root,"cancel")),"cancel before text scan publishes nothing");
    }
    static void Snapshot(Form form,string name){using(var image=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,new Rectangle(Point.Empty,image.Size));image.Save(Path.Combine(root,name),ImageFormat.Png);}}
    static void Ui()
    {
        using(var hub=new RecoveryHub(false)){hub.StartPosition=FormStartPosition.Manual;hub.Location=new Point(-20000,-20000);hub.ShowInTaskbar=false;hub.Show();Application.DoEvents();var usb=Field<RecoveryForm>(hub,"disks");Check(usb!=null&&usb.Visible,"USB workspace is modern default, discovery disabled in test");var settings=Field<RecoverySettingsPanel>(usb,"searchSettings");var checksByName=Children(settings).OfType<CheckBox>().ToDictionary(c=>c.Name);Check(checksByName.Count==23,"twenty-three working options");var profile=Field<ComboBox>(usb,"profile");profile.SelectedIndex=4;Check(settings.Selection().OrphanDirectories&&settings.Selection().JpegFragments&&!settings.Selection().TolerateReadErrors&&!settings.Selection().TextFragments,"maximum profile keeps hazardous/empty-query modes opt-in");profile.SelectedIndex=1;Check(!settings.Selection().Signatures&&settings.Selection().FatMetadata,"quick profile changes actual methods");profile.SelectedIndex=2;Check(!settings.Selection().Other&&settings.Selection().Photos&&!settings.Selection().Documents,"photo profile narrow format group");profile.SelectedIndex=0;checksByName["usb-option-orphans"].Checked=true;Check(profile.SelectedIndex==5,"manual change switches to custom profile");
            profile.SelectedIndex=0;Snapshot(hub,"Modern-main.png");settings.SelectedIndex=2;checksByName["usb-option-text"].Checked=true;var query=Children(settings).OfType<TextBox>().Single(t=>t.Name=="usb-text-query");Check(query.Enabled,"text query available only with text mode");query.Text="рецепт пирожки";Check(settings.Selection().TextQuery=="рецепт пирожки","text query reaches options");Snapshot(hub,"Modern-extra.png");
            foreach(var size in new[]{new Size(1280,920),new Size(1060,760),new Size(1440,980)}){hub.ClientSize=size;Application.DoEvents();Check(usb.AutoScroll&&usb.ClientSize.Width>780,"adaptive USB layout "+size.Width);Check(usb.Controls[0].Width<=usb.ClientSize.Width+1,"no horizontal cropping "+size.Width+": "+usb.Controls[0].Width+"/"+usb.ClientSize.Width);}
            hub.ClientSize=new Size(1060,760);Application.DoEvents();Snapshot(hub,"Modern-compact.png");
            hub.Navigate("Telegram");Check(Children(hub).Any(c=>c.Name=="telegram-analyze"&&c.Visible),"Telegram navigation preserved");hub.Hide();
        }
        using(var form=new RecoveryFilesForm(Path.Combine(root,"with-orphans"))){form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.ShowInTaskbar=false;form.Show();Application.DoEvents();Check(Children(form).OfType<DataGridView>().Single().Rows.Count==1,"redesigned file catalog opens actual orphan result");Snapshot(form,"Modern-results.png");form.Hide();}
    }
    [STAThread]public static int Main(string[] args)
    {
        root=Path.Combine(Path.GetFullPath(args[0]),"tests","Modern-results-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));Directory.CreateDirectory(root);
        try{Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Orphans();Strings();Ui();Console.WriteLine("PASS "+checks+" modern recovery assertions. Synthetic images only; physical discovery disabled. Results: "+root);return 0;}catch(Exception error){Console.WriteLine("FAIL "+error);return 1;}
    }
}
