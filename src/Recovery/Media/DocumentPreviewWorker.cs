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
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // Only raster pages cross this boundary. No document navigation, launch
    // action, script, attachment or remote-resource UI is hosted in the app.
    public static class DocumentPreviewWorker
    {
        public sealed class Request
        {
            public int Protocol=1;
            public string Source, Sha256;
            public long Bytes;
            public int Page, Width=1200;
        }
        public sealed class Result
        {
            public int Protocol=1, Pages, Page, Width, Height;
            public string Code, Png;
        }
        const int MaxOutput=48*1024*1024;
        internal static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=MaxOutput,RecursionLimit=8};}
        internal static string Line(TextReader input,int limit)
        {
            var value=new StringBuilder();int c;
            while((c=input.Read())>=0){if(c==10)return value.ToString().TrimEnd('\r');if(value.Length>=limit)throw new IOException("PREVIEW_PROTOCOL_LIMIT");value.Append((char)c);}
            return value.Length==0?null:value.ToString();
        }
        internal static FileStream VerifiedSource(string path,long bytes,string sha,long maximum,CancellationToken token)
        {
            if(String.IsNullOrEmpty(path)||path.Length>4096||path.Any(Char.IsControl)||!Path.IsPathRooted(path)||path.StartsWith(@"\\",StringComparison.Ordinal)||path.IndexOf(':',2)>=0||!System.Text.RegularExpressions.Regex.IsMatch(sha??"",@"\A[a-fA-F0-9]{64}\z"))throw new IOException("PREVIEW_LOCAL_SOURCE_REQUIRED");
            path=Path.GetFullPath(path);if(path.StartsWith(@"\\",StringComparison.Ordinal)||path.StartsWith("//",StringComparison.Ordinal))throw new IOException("PREVIEW_LOCAL_SOURCE_REQUIRED");
            DriveType drive=new DriveInfo(Path.GetPathRoot(path)).DriveType;if(drive!=DriveType.Fixed&&drive!=DriveType.Removable&&drive!=DriveType.Ram)throw new IOException("PREVIEW_LOCAL_SOURCE_REQUIRED");
            if(bytes<1||bytes>maximum)throw new IOException("PREVIEW_INPUT_LIMIT");
            // Check ancestors from the local root down before traversing a
            // junction, which could otherwise redirect a file probe to a share.
            var parents=new List<DirectoryInfo>();for(var directory=new DirectoryInfo(Path.GetDirectoryName(path));directory!=null;directory=directory.Parent)parents.Add(directory);parents.Reverse();
            foreach(var directory in parents)if((File.GetAttributes(directory.FullName)&FileAttributes.ReparsePoint)!=0)throw new IOException("PREVIEW_LOCAL_SOURCE_REQUIRED");
            if((File.GetAttributes(path)&(FileAttributes.ReparsePoint|FileAttributes.Directory))!=0)throw new IOException("PREVIEW_LOCAL_SOURCE_REQUIRED");
            var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            try{
                if(file.Length!=bytes)throw new IOException("PREVIEW_SOURCE_CHANGED");
                using(var hash=SHA256.Create()){
                    var buffer=new byte[1024*1024];int n;
                    while((n=file.Read(buffer,0,buffer.Length))>0){token.ThrowIfCancellationRequested();hash.TransformBlock(buffer,0,n,null,0);}
                    hash.TransformFinalBlock(new byte[0],0,0);
                    if(!String.Equals(BitConverter.ToString(hash.Hash).Replace("-",""),sha,StringComparison.OrdinalIgnoreCase))throw new IOException("PREVIEW_SOURCE_CHANGED");
                }
                file.Position=0;return file;
            }catch{file.Dispose();throw;}
        }
        static Type Win(string name){return Type.GetType(name+", Windows, ContentType=WindowsRuntime",true);}
        static object Await(object operation,Type result)
        {
            MethodInfo method;
            if(result==null)method=typeof(System.WindowsRuntimeSystemExtensions).GetMethods().Single(x=>x.Name=="AsTask"&&!x.IsGenericMethod&&x.GetParameters().Length==1&&x.GetParameters()[0].ParameterType.Name=="IAsyncAction");
            else method=typeof(System.WindowsRuntimeSystemExtensions).GetMethods().Single(x=>x.Name=="AsTask"&&x.IsGenericMethod&&x.GetParameters().Length==1&&x.GetParameters()[0].ParameterType.Name=="IAsyncOperation`1").MakeGenericMethod(result);
            var task=(Task)method.Invoke(null,new[]{operation});task.GetAwaiter().GetResult();return result==null?null:task.GetType().GetProperty("Result").GetValue(task,null);
        }
        static void Close(object value){var disposable=value as IDisposable;if(disposable!=null)disposable.Dispose();}
        static Result Render(Request request)
        {
            if(request==null||request.Protocol!=1||request.Page<0||request.Page>4999||request.Width<100||request.Width>1200)throw new IOException("PREVIEW_REQUEST_INVALID");
            using(var locked=VerifiedSource(request.Source,request.Bytes,request.Sha256,512L*1024*1024,CancellationToken.None)){
                byte[] header=new byte[5];if(locked.Read(header,0,5)!=5||Encoding.ASCII.GetString(header)!="%PDF-")throw new IOException("PDF_INVALID");
                var fileType=Win("Windows.Storage.StorageFile");var pdfType=Win("Windows.Data.Pdf.PdfDocument");
                object file=Await(fileType.GetMethod("GetFileFromPathAsync").Invoke(null,new object[]{request.Source}),fileType);
                object document=Await(pdfType.GetMethod("LoadFromFileAsync",new[]{fileType}).Invoke(null,new[]{file}),pdfType);
                int count=Convert.ToInt32(pdfType.GetProperty("PageCount").GetValue(document,null));
                if(count<1||count>5000)throw new IOException("PDF_PAGE_LIMIT");if(request.Page>=count)throw new IOException("PDF_PAGE_INVALID");
                object page=pdfType.GetMethod("GetPage").Invoke(document,new object[]{(uint)request.Page});object output=null;
                try{
                    object size=page.GetType().GetProperty("Size").GetValue(page,null);double width=(double)size.GetType().GetProperty("Width").GetValue(size,null),height=(double)size.GetType().GetProperty("Height").GetValue(size,null);
                    if(width<=0||height<=0||Double.IsInfinity(width)||Double.IsInfinity(height)||Double.IsNaN(width)||Double.IsNaN(height))throw new IOException("PDF_SIZE_INVALID");
                    double scale=Math.Min(request.Width/width,Math.Min(2048/height,Math.Sqrt(3000000/(width*height))));
                    int targetWidth=Math.Max(1,(int)Math.Round(width*scale)),targetHeight=Math.Max(1,(int)Math.Round(height*scale));
                    var optionsType=Win("Windows.Data.Pdf.PdfPageRenderOptions");object options=Activator.CreateInstance(optionsType);
                    // WinRT takes DIPs and may supersample. Keep the request
                    // conservative, then validate the physical PNG dimensions.
                    optionsType.GetProperty("DestinationWidth").SetValue(options,(uint)targetWidth,null);optionsType.GetProperty("DestinationHeight").SetValue(options,(uint)targetHeight,null);
                    output=Activator.CreateInstance(Win("Windows.Storage.Streams.InMemoryRandomAccessStream"));
                    Await(page.GetType().GetMethods().Single(x=>x.Name=="RenderToStreamAsync"&&x.GetParameters().Length==2).Invoke(page,new[]{output,options}),null);
                    ulong length=(ulong)output.GetType().GetProperty("Size").GetValue(output,null);if(length==0||length>32*1024*1024)throw new IOException("PDF_RASTER_LIMIT");
                    output.GetType().GetMethod("Seek").Invoke(output,new object[]{0UL});
                    var adapter=typeof(System.IO.WindowsRuntimeStreamExtensions).GetMethods().Single(x=>x.Name=="AsStream"&&x.GetParameters().Length==1&&x.GetParameters()[0].ParameterType.Name=="IRandomAccessStream");
                    byte[] bytes=new byte[(int)length];using(var stream=(Stream)adapter.Invoke(null,new[]{output})){int done=0,n;while(done<bytes.Length&&(n=stream.Read(bytes,done,bytes.Length-done))>0)done+=n;if(done!=bytes.Length)throw new IOException("PDF_RASTER_INVALID");}
                    if(bytes.Length<24||bytes[0]!=137||bytes[1]!=80||bytes[2]!=78||bytes[3]!=71)throw new IOException("PDF_RASTER_INVALID");
                    int physicalWidth=(bytes[16]<<24)|(bytes[17]<<16)|(bytes[18]<<8)|bytes[19],physicalHeight=(bytes[20]<<24)|(bytes[21]<<16)|(bytes[22]<<8)|bytes[23];
                    if(physicalWidth<1||physicalHeight<1||physicalWidth>4096||physicalHeight>4096||(long)physicalWidth*physicalHeight>12000000)throw new IOException("PDF_RASTER_LIMIT");
                    return new Result{Code="PDF_RENDERED",Pages=count,Page=request.Page,Width=physicalWidth,Height=physicalHeight,Png=Convert.ToBase64String(bytes)};
                }finally{Close(output);Close(page);Close(document);}
            }
        }
        public static int RunConsole(string[] args)
        {
            try{
                Result result;
                try{
                    if(args==null||args.Length!=1||args[0]!="--document-preview-worker")throw new IOException("PREVIEW_REQUEST_INVALID");
                    using(var input=new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false,true))){var line=Line(input,16384);if(input.Read()!=-1)throw new IOException("PREVIEW_REQUEST_INVALID");result=Render(Json().Deserialize<Request>(line));}
                }catch(Exception error){
                    while(error is TargetInvocationException&&error.InnerException!=null)error=error.InnerException;
                    string code=error is FileNotFoundException||error is DirectoryNotFoundException?"PREVIEW_SOURCE_MISSING":error is UnauthorizedAccessException?"PREVIEW_SOURCE_UNAVAILABLE":error is IOException&&System.Text.RegularExpressions.Regex.IsMatch(error.Message,@"\A(?:PDF|PREVIEW)_[A-Z_]{1,55}\z")?error.Message:error.HResult==unchecked((int)0x8007052b)?"PDF_PASSWORD_REQUIRED":error is TypeLoadException?"PDF_RENDERER_UNAVAILABLE":"PDF_UNREADABLE";
                    result=new Result{Code=code};
                }
                using(var output=new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false))){output.WriteLine(Json().Serialize(result));output.Flush();}return 0;
            }catch{return 2;}
        }
        public static Result Read(string source,long bytes,string sha,int page,int width,CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();var request=new Request{Source=source,Bytes=bytes,Sha256=sha,Page=page,Width=width};
            using(var process=new Process())using(var job=new ProcessJob(768L*1024*1024)){
                process.StartInfo=new ProcessStartInfo(typeof(Program).Assembly.Location,"--document-preview-worker"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=new UTF8Encoding(false,true)};
                try{
                    process.Start();job.Attach(process);var clock=Stopwatch.StartNew();
                    Task<string> output=Task.Run(()=>Line(process.StandardOutput,MaxOutput));var errors=Task.Run(()=>{byte[] buffer=new byte[4096];while(process.StandardError.BaseStream.Read(buffer,0,buffer.Length)>0){} });
                    var write=Task.Run(()=>{byte[] data=new UTF8Encoding(false).GetBytes(Json().Serialize(request)+"\n");process.StandardInput.BaseStream.Write(data,0,data.Length);process.StandardInput.Close();});
                    using(cancel.Register(()=>job.Stop())){
                        while(!process.WaitForExit(30)){
                            cancel.ThrowIfCancellationRequested();if(clock.ElapsedMilliseconds>25000){job.Stop();return new Result{Code="PDF_RENDER_TIMEOUT"};}
                            if(output.IsFaulted||errors.IsFaulted||write.IsFaulted){job.Stop();return new Result{Code="PREVIEW_WORKER_FAILED"};}
                        }
                        cancel.ThrowIfCancellationRequested();if(!Task.WaitAll(new Task[]{output,errors,write},1000)||process.ExitCode!=0)return new Result{Code="PREVIEW_WORKER_FAILED"};
                        var result=Json().Deserialize<Result>(output.Result);
                        if(result==null||result.Protocol!=1||String.IsNullOrEmpty(result.Code)||result.Code.Length>70)throw new IOException("PREVIEW_WORKER_FAILED");
                        if(result.Code=="PDF_RENDERED"&&(result.Pages<1||result.Pages>5000||result.Page!=page||result.Width<1||result.Height<1||result.Width>4096||result.Height>4096||(long)result.Width*result.Height>12010000||String.IsNullOrEmpty(result.Png)))throw new IOException("PREVIEW_WORKER_FAILED");
                        return result;
                    }
                }catch(OperationCanceledException){throw;}catch{return new Result{Code="PREVIEW_WORKER_FAILED"};}finally{job.Stop();}
            }
        }
        public static string Message(string code)
        {
            switch(code){
                case "PDF_PASSWORD_REQUIRED":return "PDF защищён паролем. Встроенный просмотр такого PDF недоступен.";
                case "PDF_RENDERER_UNAVAILABLE":return "Системный просмотр PDF недоступен в этой версии Windows.";
                case "PREVIEW_SOURCE_CHANGED":return "Размер или SHA256 файла изменился. Просмотр остановлен.";
                case "PREVIEW_LOCAL_SOURCE_REQUIRED":return "Для просмотра нужна локальная копия файла.";
                case "PREVIEW_SOURCE_MISSING":return "Файл недоступен: он перемещён или удалён после поиска.";
                case "PREVIEW_SOURCE_UNAVAILABLE":return "Нет доступа к файлу. Проверь локальную копию результата.";
                case "PREVIEW_INPUT_LIMIT":return "Файл превышает лимит встроенного просмотра (PDF: 512 МиБ; видео: 64 ГиБ).";
                case "PDF_RENDER_TIMEOUT":return "PDF не удалось отрисовать за 25 секунд. Просмотр остановлен.";
                case "PDF_PAGE_LIMIT":return "PDF превышает лимит просмотра: 5000 страниц.";
                case "PDF_INVALID":case "PDF_UNREADABLE":return "PDF повреждён, усечён или не поддерживается системным просмотром. Кандидат сохранён.";
                default:return "Просмотр недоступен: файл повреждён, не поддерживается или достигнут лимит ресурсов. Кандидат сохранён.";
            }
        }
    }
}
