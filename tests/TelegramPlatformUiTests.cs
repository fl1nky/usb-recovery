using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using UsbRecovery;

public static class TelegramPlatformUiTests
{
    static int checks;
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static T Field<T>(object owner,string name) where T:class{return(T)owner.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(owner);}
    static IEnumerable<Control> Descendants(Control root){foreach(Control c in root.Controls){yield return c;foreach(var child in Descendants(c))yield return child;}}
    static string Show(ArchiveSearchPanel panel,ArchiveMessage message)
    {
        var grid=Field<DataGridView>(panel,"grid");grid.Rows.Clear();int at=grid.Rows.Add();grid.Rows[at].Tag=message;grid.Rows[at].Selected=true;grid.CurrentCell=grid.Rows[at].Cells[0];
        typeof(ArchiveSearchPanel).GetMethod("ShowMessage",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(panel,null);
        return Field<TextBox>(panel,"provenance").Text;
    }
    [STAThread] public static int Main()
    {
        try{
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            const string canary="SYNTHETIC_DESKTOP_PASSCODE_CANARY";
            using(var dialog=new TelegramDesktopAccessForm(null)){
                var code=Field<TextBox>(dialog,"passcode");var empty=Field<CheckBox>(dialog,"unprotected");
                Check(code.UseSystemPasswordChar&&code.MaxLength==4096,"local Desktop code is masked and bounded");
                Check(!empty.Checked&&dialog.KnownPasscode==null,"missing secret does not imply known empty passcode");
                code.Text=canary;Check(dialog.KnownPasscode==canary&&!empty.Checked,"known passcode retained only in dialog memory");
                empty.Checked=true;Check(dialog.KnownPasscode==""&&code.TextLength==0&&!code.Enabled,"explicit known unprotected state clears code");
                empty.Checked=false;Check(dialog.KnownPasscode==null&&code.Enabled,"clearing selection restores missing secret state");
            }
            using(var form=new Form{ClientSize=new Size(852,721),Location=new Point(-20000,-20000),StartPosition=FormStartPosition.Manual,ShowInTaskbar=false})
            using(var panel=new ArchiveSearchPanel()){
                form.Controls.Add(panel);form.Show();Application.DoEvents();
                var access=Field<Button>(panel,"desktopAccess");Check(access.Visible&&access.Enabled,"Desktop secret entry reachable in Telegram panel");
                foreach(var control in Descendants(panel))if(control.Visible&&control.Parent!=null)
                    Check(control.Right<=control.Parent.ClientSize.Width+1&&control.Bottom<=control.Parent.ClientSize.Height+1,"minimum layout bounds: "+control.GetType().Name);
                typeof(ArchiveSearchPanel).GetField("desktopKnownPasscode",BindingFlags.NonPublic|BindingFlags.Instance).SetValue(panel,canary);
                var secret=panel.TakeDesktopSecrets();Check(secret["telegram_desktop_passcode"]==canary,"pending secret captured for stdin transport");
                Check(panel.TakeDesktopSecrets().Count==0&&access.Text=="Код Desktop…","code consumed once and removed from panel");
                panel.SetAnalysisBusy(true,"Controlled local fixture");Check(!access.Enabled,"secret controls disabled during analysis");panel.SetAnalysisBusy(false,"Native profiles available");
                string progress="";string output=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"owned-archive-protected");
                var result=TelegramAnalysisService.AnalyzeSelected(output,"owned-fixture-source","",false,secret,CancellationToken.None,text=>progress+=text);
                secret.Clear();
                Check(result.Code=="LOCAL_DRAFTS_OR_SCHEDULED_AVAILABLE"&&result.Status=="complete","native nonhistory success code crosses real stdin protocol");
                Check(result.HistoryMessages==0&&result.DraftRecords==2&&result.ScheduledRecords==3&&result.NativeRecords==5,"typed counts keep drafts and scheduled separate from history");
                string summary=TelegramAnalysisService.Summary(result);
                Check(summary.Contains("Черновиков Desktop: 2")&&summary.Contains("Запланированных записей Android: 3"),"summary names distinct native roles");
                Check(!summary.Contains(canary)&&!progress.Contains(canary)&&!Directory.Exists(output+".work"),"helper stdout stderr and scratch do not expose/persist known passcode");
                var knownEmpty=TelegramAnalysisService.AnalyzeSelected(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"owned-archive-unprotected"),"owned-fixture-source","known-empty",false,
                    new Dictionary<string,string>{{"telegram_desktop_passcode",""}},CancellationToken.None,null);
                Check(knownEmpty.DraftRecords==2,"explicit known empty passcode survives stdin JSON");
                var category=typeof(ArchiveSearchPanel).GetMethod("MessageCategory",BindingFlags.Static|BindingFlags.NonPublic);
                var draft=new ArchiveMessage{app="Telegram",text="Controlled native draft",record_kind="telegram_desktop_draft",evidence_kind="backup",chat_id="user:909",completeness="unsent_local_draft_not_message_history_or_deleted_message"};
                string details=Show(panel,draft);
                Check((string)category.Invoke(null,new object[]{draft})=="Черновик Desktop"&&details.Contains("неотправленный текст")&&details.Contains("не удалённое сообщение"),"draft role and limitations are visible");
                Check(draft.sender_id==null&&draft.message_id==null&&draft.timestamp==null,"draft does not manufacture sender date or message ID");
                var scheduled=new ArchiveMessage{app="Telegram",text="Controlled scheduled text",record_kind="telegram_android_scheduled",evidence_kind="backup",timestamp="2026-11-04T10:00:00+00:00"};
                Check((string)category.Invoke(null,new object[]{scheduled})=="Запланировано Android"&&Show(panel,scheduled).Contains("время планируемой отправки"),"scheduled timestamp has its actual meaning");
                var ios=new ArchiveMessage{app="Telegram",text="Controlled historical iOS text",record_kind="telegram_ios29_message",evidence_kind="backup"};
                Check(Show(panel,ios).Contains("схема 29")&&Show(panel,ios).Contains("не поддержка современных баз Postbox"),"historical iOS scope remains explicit");
                Show(panel,draft);
                using(var image=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,new Rectangle(Point.Empty,image.Size));image.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"TelegramPlatformsUi.png"),ImageFormat.Png);}
                form.Hide();
            }
            Console.WriteLine("PASS "+checks+" Telegram native UI/protocol checks. Controlled stdin fixture; native parsing is checked separately.");return 0;
        }catch(Exception ex){Console.WriteLine("FAIL "+ex.Message);return 1;}
    }
}
