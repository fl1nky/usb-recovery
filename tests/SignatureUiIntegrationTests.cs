using System;using System.Collections.Generic;using System.Drawing;using System.IO;using System.Linq;using System.Reflection;using System.Text;using System.Threading;using System.Web.Script.Serialization;using System.Windows.Forms;using UsbRecovery;
public static class SignatureUiIntegrationTests
{
    static int checks;static string project,work;
    static string Hash(string path){return RecoveryCore.HashFile(path,CancellationToken.None,(a,b)=>{});}
    static void Check(bool value,string text){checks++;if(!value)throw new Exception(text);}
    static T Field<T>(object p,string name){return (T)p.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(p);}
    static IEnumerable<Control> Children(Control p){foreach(Control c in p.Controls){yield return c;foreach(var q in Children(c))yield return q;}}
    static UserSignatureRule Rule(){return new UserSignatureRule{Id="recipe",Name="Редкий рецепт",Extension="recipe",HeaderHex="52 45 43 49 50 45 01",FooterHex="45 4E 44 21",MinBytes=16,MaxBytes=4096};}
    static RecoveryOptions Only(){return new RecoveryOptions{FatMetadata=false,NtfsMetadata=false,LostPartitions=false,Signatures=false,EmbeddedPhotos=false,Containers=false,CustomSignatures=true,CustomRules=new List<UserSignatureRule>{Rule()}};}
    static void Pipeline()
    {
        var bytes=new byte[2*1024*1024+250];byte[] expected=Encoding.ASCII.GetBytes("RECIPE\x01 grandma apples secret END!");int start=1024*1024-3;expected.CopyTo(bytes,start);string image=Path.Combine(work,"source.dd");File.WriteAllBytes(image,bytes);string before=Hash(image);File.WriteAllText(image+".sha256",before);string output=Path.Combine(work,"result");Directory.CreateDirectory(output);
        var result=RecoveryPipeline.Run(image,output,Only(),CancellationToken.None,null);Check(result.Candidates==1&&result.UniqueFiles==1,"custom only stage reaches catalog");var item=RecoveryCatalog.Load(output).Items.Single();Check(File.ReadAllBytes(RecoveryCatalog.SafeFile(output,item.Path)).SequenceEqual(expected),"arbitrary byte signature exact original payload");Check(item.Method=="Своя сигнатура"&&item.Quality=="signature_candidate","custom result labeled candidate not format verified");Check(item.SourceOffset==start&&item.SourceRanges.Count==1&&item.SourceRanges[0].Length==expected.Length,"exact contiguous source map bound to result");Check(Hash(image)==before,"custom integrated recovery source immutable");
        var state=RecoverySession.Read(output);Check(state.Stages.Single().Key=="user-signatures"&&state.Options.CustomRules.Single().Id=="recipe","rule stored inline in session for portable continuation");
        var resumed=RecoveryPipeline.Resume(output,CancellationToken.None,null);Check(resumed.ResumedStages==1&&resumed.UniqueFiles==1,"finished signature stage reused after verifying source and outputs");
        var altered=Only();altered.CustomRules[0].HeaderHex="41 42 43 44";bool rejected=false;try{RecoverySession.Open(output,image,altered,CancellationToken.None,null);}catch(IOException){rejected=true;}Check(rejected,"changed rule cannot silently reuse saved stage");
        File.AppendAllText(RecoveryCatalog.SafeFile(output,item.Path),"changed");item=RecoveryCatalog.Build(output,CancellationToken.None,null).Items.Single();Check(item.Quality=="changed"&&item.SourceRanges.Count==0,"changed candidate loses stale range proof");
        rejected=false;try{RecoveryPipeline.Resume(output,CancellationToken.None,null);}catch(IOException){rejected=true;}Check(rejected,"modified result prevents trusted resume");Check(Hash(image)==before,"source stays immutable after changed output");
        var invalid=Only();invalid.CustomRules.Clear();rejected=false;try{invalid.Validate();}catch(ArgumentException){rejected=true;}Check(rejected,"no empty signature search accepted");
    }
    static void Ui()
    {
        using(var form=new RecoveryForm(false)){
            form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.Show();Application.DoEvents();var settings=Field<RecoverySettingsPanel>(form,"searchSettings");settings.SetCustomRules(new[]{Rule()});form.SetExpertMode(true);settings.SelectedIndex=2;var custom=Children(settings).OfType<CheckBox>().Single(c=>c.Name=="usb-option-custom");Check(!custom.Checked,"custom method opt in after rules supplied");custom.Checked=true;Application.DoEvents();Check(settings.Selection().CustomSignatures&&settings.Selection().CustomRules.Single().Name=="Редкий рецепт","actual UI selection includes immutable rule values");
            var copy=settings.Selection().CustomRules;copy[0].Name="mutated";Check(settings.Selection().CustomRules[0].Name=="Редкий рецепт","external option copy cannot change editor rules");settings.ApplyProfile("maximum");Check(!settings.Selection().CustomSignatures,"maximum never invents custom type");custom.Checked=true;form.ClientSize=new Size(850,740);Application.DoEvents();Check(!form.HorizontalScroll.Visible&&Children(settings).Any(c=>c.Name=="configure-signatures"),"custom configuration accessible at minimum source size");using(var bmp=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bmp,new Rectangle(Point.Empty,bmp.Size));bmp.Save(Path.Combine(project,"tests","CustomTypes-ui.png"));}form.Close();
        }
        using(var dialog=new UserSignatureDialog(new UserSignatureRule[0])){
            Check(dialog.Rules.Count==0,"empty rules editor opens without failed validation");dialog.ShowInTaskbar=false;dialog.StartPosition=FormStartPosition.Manual;dialog.Location=new Point(-20000,-20000);dialog.Show();dialog.ClientSize=new Size(680,470);Application.DoEvents();Check(Children(dialog).OfType<ListView>().Single().Width>400,"rules list fits minimum editor");dialog.Close();
        }
        var type=typeof(UserSignatureDialog).GetNestedType("RuleEditor",BindingFlags.NonPublic);using(var editor=(Form)Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,new object[]{null},null)){
            editor.ShowInTaskbar=false;editor.StartPosition=FormStartPosition.Manual;editor.Location=new Point(-20000,-20000);editor.Show();Application.DoEvents();var commit=type.GetMethod("Commit",BindingFlags.Instance|BindingFlags.NonPublic);commit.Invoke(editor,null);Check(editor.DialogResult!=DialogResult.OK,"invalid rule remains editable with inline message");
            foreach(var pair in new[]{new[]{"signature-0","Family"},new[]{"signature-1","recipe"},new[]{"signature-2","52 45 43 49 50 45 01"},new[]{"signature-5","45 4E 44 21"}})Children(editor).OfType<TextBox>().Single(c=>c.Name==pair[0]).Text=pair[1];commit.Invoke(editor,null);Check(editor.DialogResult==DialogResult.OK,"valid rule saved by real dialog action");
        }
    }
    static void Hex()
    {
        string folder=Path.Combine(work,"hex");Directory.CreateDirectory(folder);byte[] bytes=Enumerable.Range(0,20000).Select(i=>(byte)i).ToArray();string file=Path.Combine(folder,"unknown.bin");File.WriteAllBytes(file,bytes);var item=new RecoveredItem{Path="unknown.bin",Name="unknown.bin",Bytes=bytes.Length,Sha256=Hash(file)};var preview=SafeRecoveryPreview.ReadHex(folder,item,CancellationToken.None);Check(preview.Text.Contains("00000000  00 01 02 03")&&preview.Text.Contains("00000FF0"),"bounded hex displays exact offsets and bytes");Check(!preview.Text.Contains("00001000")&&preview.Text.Length<22000&&preview.Message.Contains("SHA256"),"hex display bounded to4KiB after fullfilehash");
        using(var token=new CancellationTokenSource()){token.Cancel();bool cancelled=false;try{SafeRecoveryPreview.ReadHex(folder,item,token.Token);}catch(OperationCanceledException){cancelled=true;}Check(cancelled,"hex canceled before opening source");}
        bytes[10000]^=37;File.WriteAllBytes(file,bytes);bool rejected=false;try{SafeRecoveryPreview.ReadHex(folder,item,CancellationToken.None);}catch(IOException){rejected=true;}Check(rejected,"hex rejects mutation beyond displayed prefix");
        using(var form=new RecoveryFilesForm(Path.Combine(work,"result"))){form.ShowInTaskbar=false;form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-20000,-20000);form.Show();Application.DoEvents();Check(Children(form).OfType<CheckBox>().Any(c=>c.Name=="hex-preview"),"hex optin available on results");form.Close();}
    }
    [STAThread]public static int Main(string[] args)
    {
        try{project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","signature-integration-"+Guid.NewGuid().ToString("N").Substring(0,8));Directory.CreateDirectory(work);Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Pipeline();Ui();Hex();RecoveryCore.SaveJson(Path.Combine(project,"tests","SignatureUiIntegration-validation.json"),new{status="passed",application_sha256=Hash(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"USB-Recovery.exe")),test_source_sha256=Hash(Path.Combine(project,"tests","SignatureUiIntegrationTests.cs")),checks=checks,real_devices=false});Console.WriteLine("PASS SignatureUiIntegration: "+checks+" checks; exact payload, source map, candidate labels, saved rules, trusted resume, minimum editor, bounded hashverified HEX and inline validation; synthetic only.");return 0;}catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
