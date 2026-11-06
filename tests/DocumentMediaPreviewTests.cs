using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using UsbRecovery;

public static class DocumentMediaPreviewTests
{
    static int checks;static string work;static readonly List<object> evidence=new List<object>();
    static void Check(bool value,string why){checks++;if(!value)throw new Exception(why);}
    static string Hash(string path){using(var file=File.OpenRead(path))using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    static void Pump(int milliseconds){var watch=Stopwatch.StartNew();while(watch.ElapsedMilliseconds<milliseconds){Application.DoEvents();Thread.Sleep(10);}}
    static void Until(Func<bool> condition,int milliseconds,string why){var watch=Stopwatch.StartNew();while(!condition()&&watch.ElapsedMilliseconds<milliseconds)Pump(20);Check(condition(),why);}
    static T Field<T>(object value,string name){return (T)value.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(value);}
    static string Pdf(string path)
    {
        var objects=new List<string>{"<< /Type /Catalog /Pages 2 0 R /OpenAction 10 0 R >>","<< /Type /Pages /Kids [3 0 R 5 0 R 7 0 R] /Count 3 >>"};
        string[] colors={"1 0 0","0 1 0","0 0 1"};
        for(int page=0;page<3;page++){
            int content=4+page*2;objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 400] /Resources << /Font << /F1 9 0 R >> >> /Contents "+content+" 0 R >>");
            string commands="q "+colors[page]+" rg 0 0 300 400 re f Q 0 0 0 rg BT /F1 22 Tf 30 350 Td (PAGE "+(page+1)+") Tj ET";
            objects.Add("<< /Length "+commands.Length+" >>\nstream\n"+commands+"\nendstream");
        }
        objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");objects.Add("<< /S /JavaScript /JS (app.alert\\(\"DO NOT EXECUTE\"\\)) >>");
        var data=new StringBuilder("%PDF-1.4\n");var offsets=new List<int>{0};for(int i=0;i<objects.Count;i++){offsets.Add(Encoding.ASCII.GetByteCount(data.ToString()));data.Append(i+1).Append(" 0 obj\n").Append(objects[i]).Append("\nendobj\n");}
        int xref=Encoding.ASCII.GetByteCount(data.ToString());data.Append("xref\n0 ").Append(objects.Count+1).Append("\n0000000000 65535 f \n");foreach(int offset in offsets.Skip(1))data.Append(offset.ToString("D10")).Append(" 00000 n \n");data.Append("trailer\n<< /Size ").Append(objects.Count+1).Append(" /Root 1 0 R >>\nstartxref\n").Append(xref).Append("\n%%EOF\n");File.WriteAllText(path,data.ToString(),Encoding.ASCII);return path;
    }
    static DocumentPreviewWorker.Result Render(string file,int page,string hash=null,CancellationToken token=default(CancellationToken))
    {
        var result=DocumentPreviewWorker.Read(file,new FileInfo(file).Length,hash??Hash(file),page,600,token);evidence.Add(new{test=Path.GetFileName(file),page=page,code=result.Code,pages=result.Pages,width=result.Width,height=result.Height});return result;
    }
    static void PdfCases(string pdf)
    {
        string original=Hash(pdf);for(int page=0;page<3;page++){
            var result=Render(pdf,page);Check(result.Code=="PDF_RENDERED","native Windows PDF page renders: "+result.Code);Check(result.Pages==3&&result.Page==page&&result.Width>=600&&result.Width<=2400&&Math.Abs(result.Width/(double)result.Height-.75)<.005,"multipage metadata and raster aspect ratio: "+result.Width+"x"+result.Height+" / "+result.Pages);
            byte[] bytes=Convert.FromBase64String(result.Png);File.WriteAllBytes(Path.Combine(work,"page-"+(page+1)+".png"),bytes);using(var memory=new MemoryStream(bytes))using(var bitmap=new Bitmap(memory)){Check(bitmap.Width==result.Width&&bitmap.Height==result.Height,"reported dimensions match actual raster pixels");Color pixel=bitmap.GetPixel(bitmap.Width/2,bitmap.Height/2);Check(page==0?pixel.R>250&&pixel.G<5&&pixel.B<5:page==1?pixel.G>250&&pixel.R<5&&pixel.B<5:pixel.B>250&&pixel.R<5&&pixel.G<5,"independent solid-color page oracle matches actual OS rendered pixels");}
        }
        Check(Hash(pdf)==original,"PDF source bytes unchanged");Check(Render(pdf,3).Code!="PDF_RENDERED","out-of-range page rejected");Check(Render(pdf,0,new string('0',64)).Code=="PREVIEW_SOURCE_CHANGED","wrong SHA rejected before native renderer");
        foreach(string path in new[]{@"\\invalid.invalid\share\a.pdf","//invalid.invalid/share/a.pdf",@"\\?\GLOBALROOT\Device\Harddisk0\a.pdf","https://invalid.invalid/a.pdf"}){
            var clock=Stopwatch.StartNew();var blocked=DocumentPreviewWorker.Read(path,123,new string('0',64),0,600,CancellationToken.None);Check(blocked.Code=="PREVIEW_LOCAL_SOURCE_REQUIRED"&&clock.ElapsedMilliseconds<3000,"network/device path rejected before file probes");
        }
        string invalid=Path.Combine(work,"invalid.pdf");File.WriteAllText(invalid,"This is not a PDF.");Check(Render(invalid,0).Code=="PDF_INVALID","invalid PDF has clear failure");
        string truncated=Path.Combine(work,"truncated.pdf");File.WriteAllBytes(truncated,File.ReadAllBytes(pdf).Take(230).ToArray());Check(Render(truncated,0).Code!="PDF_RENDERED","unusable truncated PDF cannot report render success");
        using(var cancel=new CancellationTokenSource()){cancel.Cancel();bool caught=false;try{Render(pdf,0,null,cancel.Token);}catch(OperationCanceledException){caught=true;}Check(caught,"pre-cancelled render does not launch decoder");}
        using(var cancel=new CancellationTokenSource()){cancel.CancelAfter(20);bool caught=false;var clock=Stopwatch.StartNew();try{Render(pdf,0,null,cancel.Token);}catch(OperationCanceledException){caught=true;}Check(caught&&clock.ElapsedMilliseconds<3000,"in-flight renderer cancellation terminates job promptly");}
    }
    static void PreviewKey(DocumentMediaPreviewPanel panel,Keys key)
    {
        var method=typeof(DocumentMediaPreviewPanel).GetMethod("ProcessCmdKey",BindingFlags.Instance|BindingFlags.NonPublic);
        var message=Message.Create(panel.Handle,0x0100,(IntPtr)(int)key,IntPtr.Zero);
        method.Invoke(panel,new object[]{message,key});
    }
    static bool ShowsPdfPage(DocumentMediaPreviewPanel panel,int page)
    {
        var displayed=Field<PictureBox>(panel,"image").Image as Bitmap;
        if(displayed==null||Field<int>(panel,"page")!=page)return false;
        Color pixel=displayed.GetPixel(displayed.Width/2,displayed.Height/2);
        Color expected=new[]{Color.Red,Color.Lime,Color.Blue}[page];
        return Math.Abs(pixel.R-expected.R)<5&&Math.Abs(pixel.G-expected.G)<5&&Math.Abs(pixel.B-expected.B)<5;
    }
    static void PdfViewer(Form owner,DocumentMediaPreviewPanel embedded,Func<DocumentMediaPreviewPanel,bool> interact)
    {
        Exception failure=null;
        bool escapeHandled=false;
        var clock=Stopwatch.StartNew();
        using(var timer=new System.Windows.Forms.Timer{Interval=40}){
            timer.Tick+=delegate{
                var window=Application.OpenForms.Cast<Form>().FirstOrDefault(x=>x!=owner);
                if(window==null)return;
                try{
                    window.Location=owner.Location;
                    if(clock.ElapsedMilliseconds>12000)throw new TimeoutException("PDF viewer did not finish or close");
                    if(escapeHandled||!interact(window.Controls.OfType<DocumentMediaPreviewPanel>().Single()))return;
                    var key=new KeyEventArgs(Keys.Escape);
                    typeof(Form).GetMethod("OnKeyDown",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(window,new object[]{key});
                    escapeHandled=key.Handled;
                    if(!escapeHandled)throw new InvalidOperationException("PDF viewer did not handle Escape");
                }catch(Exception error){failure=error;window.Close();}
            };
            timer.Start();
            Field<Button>(embedded,"expand").PerformClick();
            timer.Stop();
        }
        if(failure!=null)throw new InvalidOperationException("PDF modal viewer check failed",failure);
        Check(escapeHandled,"Escape closes the separate PDF viewer");
    }
    static void UiCases(string pdf)
    {
        using(var form=new Form{ClientSize=new Size(700,600),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-12000,-12000)})
        using(var panel=new DocumentMediaPreviewPanel()){
            int messages=0;
            panel.MessageChanged+=message=>{messages++;Console.WriteLine("UI "+message);};
            form.Controls.Add(panel);
            form.Show();

            long bytes=new FileInfo(pdf).Length;
            string digest=Hash(pdf);
            var image=Field<PictureBox>(panel,"image");
            var zoom=Field<ComboBox>(panel,"zoom");
            panel.ShowFile(pdf,bytes,digest);
            PreviewKey(panel,Keys.PageDown);
            Check(Field<int>(panel,"page")==0,"PageDown during initial PDF loading leaves the first page selected");
            Until(()=>ShowsPdfPage(panel,0),10000,"first PDF page still renders after early PageDown");
            object defaultZoom=zoom.SelectedItem;
            Size initial=image.Size;

            Field<Button>(panel,"next").PerformClick();
            Until(()=>ShowsPdfPage(panel,1),10000,"next-page UI renders actual green second page");
            Field<Button>(panel,"rotate").PerformClick();
            Check(image.Width>image.Height,"PDF rotation swaps display aspect");
            zoom.SelectedItem="200%";
            Check(image.Width>initial.Width,"PDF zoom changes actual display dimensions");
            Size openedSize=image.Size;

            bool edited=false;
            Size returnedSize=Size.Empty;
            PdfViewer(form,panel,popup=>{
                if(!edited){
                    if(Field<PictureBox>(popup,"image").Image==null)return false;
                    Check(ShowsPdfPage(popup,1)&&Field<int>(popup,"rotation")==90&&
                        Equals(Field<ComboBox>(popup,"zoom").SelectedItem,"200%")&&Field<PictureBox>(popup,"image").Size==openedSize,
                        "separate PDF shows the embedded page, rotation and explicit zoom");
                    Field<Button>(popup,"rotate").PerformClick();
                    Field<ComboBox>(popup,"zoom").SelectedItem="150%";
                    PreviewKey(popup,Keys.PageDown);
                    edited=true;
                    return false;
                }
                if(!ShowsPdfPage(popup,2))return false;
                returnedSize=Field<PictureBox>(popup,"image").Size;
                return true;
            });
            Until(()=>ShowsPdfPage(panel,2),10000,"closing the PDF viewer returns its rendered blue third page");
            Check(Field<int>(panel,"rotation")==180&&Equals(zoom.SelectedItem,"150%")&&image.Size==returnedSize,
                "closing the PDF viewer returns its changed rotation and zoom");

            PdfViewer(form,panel,popup=>{
                if(!ShowsPdfPage(popup,2))return false;
                Field<Button>(popup,"rotate").PerformClick();
                Field<ComboBox>(popup,"zoom").SelectedItem="75%";
                PreviewKey(popup,Keys.PageUp);
                return true;
            });
            Pump(400);
            Check(ShowsPdfPage(panel,2)&&Field<int>(panel,"rotation")==180&&Equals(zoom.SelectedItem,"150%")&&image.Size==returnedSize,
                "Escape during a new PDF page render retains the embedded page and settings");

            string alternate=Path.Combine(work,"another.pdf");
            File.Copy(pdf,alternate);
            panel.ShowFile(alternate,bytes,digest);
            Check(Equals(zoom.SelectedItem,defaultZoom),"changing PDF resets the zoom selector to its default");
            Until(()=>ShowsPdfPage(panel,0),10000,"new PDF selection renders its first page");
            Size fitted=image.Size;
            zoom.SelectedItem="150%";
            Check(image.Width>fitted.Width,"the previous PDF's zoom can be selected again in a new file");
            Field<Button>(panel,"fit").PerformClick();
            Check(image.Width<700&&image.Height<600,"fit-page view stays in viewport");

            for(int i=0;i<8;i++)panel.ShowFile(pdf,bytes,digest);
            panel.Stop();
            int stoppedMessages=messages;
            PreviewKey(panel,Keys.PageDown);
            Pump(800);
            Check(Field<Image>(panel,"raster")==null,"rapid reselection then Stop cannot show stale worker results");
            Check(messages==stoppedMessages,"PageDown after Stop does not start a PDF worker");
            form.Close();
        }
        Pump(400);
    }
    static void VideoCases(string input)
    {
        string file=Path.Combine(work,"контрольное видео.mp4");File.Copy(input,file);string original=Hash(file);long bytes=new FileInfo(file).Length;
        using(var form=new Form{ClientSize=new Size(640,450),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-12000,-12000)}){
            form.Show();LocalMediaPreviewState state=null;int pid;
            using(var session=new LocalMediaPreviewSession(form.Handle,file,bytes,original)){
                pid=session.ProcessId;session.Changed+=s=>{state=s;evidence.Add(new{video=s});};Until(()=>state!=null&&(state.State=="paused"||state.State=="error"),15000,"native video preview opens or reports a bounded error");Check(state.State=="paused","actual AVC/AAC local MediaElement opens: "+state.Code);Check(state.Duration>1&&state.Width>0&&state.Height>0,"native video duration and dimensions available");
                session.Command("volume",.25);Until(()=>state!=null&&Math.Abs(state.Volume-.25)<.01,2000,"volume command changes native player");session.Command("play");Until(()=>state.State=="playing"&&state.Position>.15,4000,"native playback advances timeline");session.Command("pause");Until(()=>state.State=="paused",2000,"native pause applied");double position=state.Position;Pump(350);Check(Math.Abs(state.Position-position)<.1,"paused video position stable");
                session.Command("seek",state.Duration*.65);double target=state.Duration*.65;Until(()=>Math.Abs(state.Position-target)<.2,3000,"paused seek reaches later frame");session.Command("seek",Math.Max(0,state.Duration-.25));session.Command("play");Until(()=>state.State=="ended",4000,"native playback reaches end of full file");session.Resize(form.Handle,480,360);
                bool locked=false;try{using(var write=new FileStream(file,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)){} }catch(IOException){locked=true;}Check(locked,"source remains read-locked throughout playback");
            }
            Until(()=>{try{using(var process=Process.GetProcessById(pid))return process.HasExited;}catch(ArgumentException){return true;}},3000,"disposing preview terminates owned decoder");form.Close();
        }
        Check(Hash(file)==original,"video bytes unchanged after playback/seek");
        var decode=MediaDecodeWorker.Validate(file,new MediaFoundationValidator.DecodeLimits(),CancellationToken.None);Check(decode.Status=="decoded_soft"&&decode.Streams.Any(x=>x.Kind=="audio"&&x.PcmFrames>0),"independent native audio decode confirms actual PCM samples, not only a silent video timeline");evidence.Add(new{audio_decode=decode});
        using(var form=new Form{ClientSize=new Size(480,360),ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-12000,-12000)}){
            form.Show();foreach(string variant in new[]{"corrupt","truncated","changed","missing","external","rotated"}){
                string candidate=Path.Combine(work,variant+".mp4");byte[] data=File.ReadAllBytes(file);if(variant=="corrupt")data=Encoding.ASCII.GetBytes("THIS IS NOT VIDEO DATA.");if(variant=="truncated")data=data.Take(100).ToArray();
                if(variant=="external"){int reference=-1;for(int i=4;i<data.Length-8;i++)if(Encoding.ASCII.GetString(data,i,4)=="url "){reference=i+4;break;}Check(reference>=0,"controlled MP4 has a data-reference entry");for(int i=0;i<4;i++)data[reference+i]=0;}
                if(variant=="rotated"){
                    int at=-1;for(int i=4;i<data.Length-100;i++)if(Encoding.ASCII.GetString(data,i,4)=="tkhd"){at=i+4;break;}Check(at>=0,"controlled MP4 contains independently located track header");int matrix=at+(data[at]==0?40:52);byte[] values={0,0,0,0,0,1,0,0};Array.Copy(values,0,data,matrix,8);data[matrix+12]=255;data[matrix+13]=255;data[matrix+14]=0;data[matrix+15]=0;for(int j=0;j<4;j++)data[matrix+16+j]=0;
                }
                File.WriteAllBytes(candidate,data);long length=data.Length;string digest=variant=="changed"?new string('0',64):Hash(candidate);if(variant=="missing")File.Move(candidate,candidate+".retained");
                using(var session=new LocalMediaPreviewSession(form.Handle,candidate,length,digest)){
                    LocalMediaPreviewState observed=session.LastState;session.Changed+=s=>{observed=s;};Until(()=>observed!=null&&(observed.State=="paused"||observed.State=="error"),12000,"controlled video case completes: "+variant);
                    if(variant=="rotated")Check(observed.State=="paused"&&observed.Rotation==90,"real player opens rotated MP4 and applies 90-degree orientation metadata");else Check(observed.State=="error"&&(variant!="external"||observed.Code=="VIDEO_EXTERNAL_REFERENCE"),"invalid media never silently claims playback: "+variant);
                    evidence.Add(new{variant=variant,state=observed});
                }
            }form.Close();
        }
    }
    static string Catalog(string pdf,string video)
    {
        string root=Path.Combine(work,"catalog");Directory.CreateDirectory(root);File.Copy(pdf,Path.Combine(root,"multipage.pdf"));File.Copy(video,Path.Combine(root,"local-video.mp4"));File.WriteAllText(Path.Combine(root,"note.txt"),"Synthetic plain text retained.");using(var image=new Bitmap(40,30)){using(var g=Graphics.FromImage(image))g.Clear(Color.Gold);image.Save(Path.Combine(root,"photo.png"),System.Drawing.Imaging.ImageFormat.Png);}
        var index=new RecoveryFileIndex{Candidates=4};foreach(string path in Directory.GetFiles(root)){string relative=Path.GetFileName(path);index.Items.Add(new RecoveredItem{Name=relative,Path=relative,Extension=Path.GetExtension(path),Category=RecoveryCatalog.Category(Path.GetExtension(path)),Bytes=new FileInfo(path).Length,Sha256=Hash(path),Method="Controlled local fixture",Note="Synthetic fixture. Rendering does not establish original integrity."});}RecoveryCore.SaveJson(Path.Combine(root,"files-index.json"),index);return root;
    }
    static bool VideoPausedAt(LocalMediaPreviewState state,double position,double volume)
    {
        return state!=null&&state.State=="paused"&&Math.Abs(state.Position-position)<.18&&Math.Abs(state.Volume-volume)<.02;
    }
    static void Integration(string root)
    {
        using(var form=new RecoveryFilesForm(root)){
            form.StartPosition=FormStartPosition.Manual;form.Location=new Point(-12000,-12000);form.Show();var grid=Field<DataGridView>(form,"grid");var preview=Field<DocumentMediaPreviewPanel>(form,"documentMediaPreview");
            foreach(string name in new[]{"multipage.pdf","note.txt","photo.png","local-video.mp4"}){
                var row=grid.Rows.Cast<DataGridViewRow>().Single(x=>((RecoveredItem)x.Tag).Name==name);grid.CurrentCell=row.Cells[1];row.Selected=true;Pump(400);
                if(name.EndsWith(".pdf"))Until(()=>Field<int>(preview,"pages")==3,10000,"catalog selects actual multipage PDF preview");else if(name.EndsWith(".txt"))Until(()=>Field<TextBox>(form,"previewText").Text.Contains("Synthetic plain text"),3000,"existing plain-text preview preserved");else if(name.EndsWith(".png"))Until(()=>Field<PictureBox>(form,"previewImage").Image!=null,3000,"existing photo preview preserved");else Until(()=>Field<LocalMediaPreviewSession>(preview,"video")!=null&&Field<LocalMediaPreviewSession>(preview,"video").LastState!=null&&Field<LocalMediaPreviewSession>(preview,"video").LastState.State=="paused",12000,"catalog selects embedded local video preview");
            }
            Check(Field<RowStyle>(form,"previewFooterRow").Height==0,"media preview uses one status area and keeps viewport space");
            var embedded=Field<LocalMediaPreviewSession>(preview,"video");
            double duration=embedded.LastState.Duration;
            embedded.Command("seek",duration*.28);
            embedded.Command("volume",.23);
            Until(()=>VideoPausedAt(embedded.LastState,duration*.28,.23),4000,"embedded video is paused at a nonzero position and custom volume");
            var beforePopup=embedded.LastState;

            Exception popupFailure=null;
            LocalMediaPreviewState beforeReturn=null;
            int popupPid=0;
            var popupClock=Stopwatch.StartNew();
            using(var closePopup=new System.Windows.Forms.Timer{Interval=100}){
                closePopup.Tick+=delegate{
                    var popup=Application.OpenForms.Cast<Form>().FirstOrDefault(x=>x!=form);
                    if(popup==null)return;
                    try{
                        popup.Location=form.Location;
                        if(popupClock.ElapsedMilliseconds>15000)throw new TimeoutException(popupPid==0
                            ? "separate video viewer did not open paused at the embedded position and volume"
                            : "separate video viewer did not apply its new paused position and volume");
                        var panel=popup.Controls.OfType<DocumentMediaPreviewPanel>().Single();
                        var session=Field<LocalMediaPreviewSession>(panel,"video");
                        var state=session==null?null:session.LastState;
                        if(popupPid==0){
                            if(!VideoPausedAt(state,beforePopup.Position,beforePopup.Volume))return;
                            popupPid=session.ProcessId;
                            session.Command("seek",duration*.72);
                            session.Command("volume",.79);
                        }else if(VideoPausedAt(state,duration*.72,.79)){
                            beforeReturn=state;
                            popup.Close();
                        }
                    }catch(Exception error){popupFailure=error;popup.Close();}
                };
                closePopup.Start();
                Field<Button>(preview,"expand").PerformClick();
                closePopup.Stop();
            }
            if(popupFailure!=null)throw new InvalidOperationException("Separate native video viewer check failed",popupFailure);
            Check(beforeReturn!=null,"separate viewer opens actual native media, preserves and updates paused playback, and closes cleanly");
            Until(()=>{try{using(var process=Process.GetProcessById(popupPid))return process.HasExited;}catch(ArgumentException){return true;}},3000,"separate viewer closes its own decoder");
            Until(()=>{
                var resumed=Field<LocalMediaPreviewSession>(preview,"video");
                return resumed!=null&&resumed!=embedded&&VideoPausedAt(resumed.LastState,beforeReturn.Position,beforeReturn.Volume);
            },10000,"embedded preview returns paused at the separate viewer's changed position and volume");
            Field<CheckBox>(form,"hexMode").Checked=true;Until(()=>Field<TextBox>(form,"previewText").Text.StartsWith("00000000"),3000,"HEX override works for video");Check(Field<LocalMediaPreviewSession>(preview,"video")==null,"HEX switch closes native video decoder");Field<CheckBox>(form,"hexMode").Checked=false;Pump(100);form.Close();Pump(400);Check(Field<LocalMediaPreviewSession>(preview,"video")==null,"catalog close disposes embedded media worker");
        }
    }
    [STAThread]public static int Main(string[] args)
    {
        try{
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);string project=Path.GetFullPath(args[0]);work=Path.Combine(project,".build","document-media-preview-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(work);string pdf=Pdf(Path.Combine(work,"multipage.pdf")),catalog=Catalog(pdf,Path.GetFullPath(args[1]));if(args.Length>2&&args[2]=="--show"){using(var form=new RecoveryFilesForm(catalog)){form.Text="Preview verification — controlled local fixtures";Application.Run(form);}return 0;}PdfCases(pdf);UiCases(pdf);VideoCases(Path.GetFullPath(args[1]));Integration(catalog);File.WriteAllText(Path.Combine(work,"evidence.json"),new JavaScriptSerializer{MaxJsonLength=4*1024*1024}.Serialize(new{checks=checks,evidence=evidence}),new UTF8Encoding(false));Console.WriteLine(work);Console.WriteLine("PASS DocumentMediaPreview: "+checks+" checks; actual OS PDF pixels, multipage UI/rotation/zoom, isolated native playback/pause/seek/end/volume/audio/cleanup and catalog integration. Windows OS-codec evidence.");return 0;
        }catch(Exception error){Console.WriteLine("FAIL "+error);if(work!=null)File.WriteAllText(Path.Combine(work,"failure.txt"),error.ToString());return 1;}
    }
}
