using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // Materialization keeps all existing engines on one immutable logical RAW
    // stream. Their offsets never refer to compressed container bytes.
    public static class ForensicImageSource
    {
        public const string RequestFile="prepared-source-request.json";
        public sealed class Request
        {
            public int Schema=1;
            public string SourcePath,ChecksumPath;
            public RecoveryOptions Options;
        }
        public sealed class Prepared {public string Image,Checksum;}
        static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=1024*1024};}
        public static bool HasRequest(string directory){return File.Exists(RecoveryCatalog.SafeFile(directory,RequestFile));}
        public static string WorkingPath(string directory){return RecoveryCatalog.SafeFile(directory,"source-preparation/working.dd");}
        static bool EwfName(string path){string extension=Path.GetExtension(path);return String.Equals(extension,".E01",StringComparison.OrdinalIgnoreCase)||String.Equals(extension,".Ex01",StringComparison.OrdinalIgnoreCase);}
        public static bool Requires(string path,RecoveryOptions options)
        {
            if(!String.IsNullOrEmpty(options.ReadMapPath)||EwfName(path))return true;
            SourcePaths.NoLinks(path);
            using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){
                var b=new byte[8];if(input.Read(b,0,b.Length)!=8)return false;
                return b.SequenceEqual(new byte[]{69,86,70,9,13,10,255,0})||b.SequenceEqual(new byte[]{69,86,70,50,13,10,129,0});
            }
        }
        public static Request Read(string directory)
        {
            string path=RecoveryCatalog.SafeFile(directory,RequestFile);SourcePaths.NoLinks(path);
            if(!File.Exists(path)||new FileInfo(path).Length>1024*1024)throw new IOException("Не найдены параметры подготовки образа.");
            Request request;
            try{request=Json().Deserialize<Request>(File.ReadAllText(path));}catch(ArgumentException){throw new IOException("Параметры подготовки образа повреждены.");}
            if(request==null||request.Schema!=1||String.IsNullOrEmpty(request.SourcePath)||request.Options==null)throw new IOException("Параметры подготовки образа повреждены.");
            request.Options.Validate();return request;
        }
        public static Prepared Prepare(string source,string directory,RecoveryOptions options,string checksum,CancellationToken cancel,Action<string> progress,Action<RecoveryStageProgress> activity)
        {
            source=Path.GetFullPath(source);directory=Path.GetFullPath(directory);SourcePaths.NoLinks(source);SourcePaths.NoLinks(directory);
            if(checksum!=null)checksum=Path.GetFullPath(checksum);
            if(!String.IsNullOrEmpty(options.ReadMapPath))options.ReadMapPath=Path.GetFullPath(options.ReadMapPath);
            options.Validate();cancel.ThrowIfCancellationRequested();Directory.CreateDirectory(directory);
            string child=RecoveryCatalog.SafeFile(directory,"source-preparation"),requestPath=RecoveryCatalog.SafeFile(directory,RequestFile);
            using(var sourceGuard=StorageRecovery.LockImage(source,cancel))
            using(var runGuard=RecoverySession.AcquireRunLock(directory)){
                if(checksum!=null){SourcePaths.NoLinks(checksum);RecoveryCore.VerifyImage(source,checksum,cancel,(a,b)=>{});}
                var request=new Request{SourcePath=source,ChecksumPath=checksum,Options=options};
                if(HasRequest(directory)){
                    var previous=Read(directory);
                    if(Json().Serialize(previous)!=Json().Serialize(request))throw new IOException("Источник или параметры изменены. Выбери новую папку поиска.");
                }else {
                    if(File.Exists(RecoveryCatalog.SafeFile(directory,RecoverySession.FileName)))throw new IOException("В этой папке уже есть другой поиск. Выбери новую папку.");
                    RecoveryCore.SaveJson(requestPath,request);
                }
                if(!Directory.Exists(child))StorageRecovery.CreatePrivateDirectory(child);
                if(progress!=null)progress("Подготовка логического образа; исходные файлы остаются неизменными.");
                var result=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="prepare_image",source=source,destination=child,options=new{read_map=options.ReadMapPath,resume=true,require_ewf=EwfName(source)}},cancel,null,
                    p=>{if(activity!=null)activity(new RecoveryStageProgress{Key="source-preparation:"+p.Phase,Title=p.Phase=="materialize"?"Создание рабочей копии":p.Phase=="verify_prefix"?"Проверка сохранённой части":"Проверка исходного образа",State="running",Completed=p.Completed,Total=p.Total});});
                if(result.Status=="error"||result.Image!="working.dd")throw new IOException("Подготовка образа остановлена: "+(result.Code??"INVALID_SOURCE"));
                string image=WorkingPath(directory),sha=image+".sha256";
                SourcePaths.NoLinks(image);SourcePaths.NoLinks(sha);
                if(!File.Exists(image)||!File.Exists(sha))throw new IOException("Рабочая копия образа не опубликована.");
                string origin=RecoveryCatalog.SafeFile(directory,"source-image.json"),previousOrigin=RecoveryCatalog.SafeFile(directory,"source-before-preparation.json");
                if(File.Exists(origin)&&!File.Exists(previousOrigin))File.Copy(origin,previousOrigin,false);
                RecoveryCore.SaveJson(origin,new{origin="derived_logical_image",sourcePath=image,originalSourcePath=source,logicalChecksum="source-preparation/working.dd.sha256",preparationReport="source-preparation/source-preparation.json",completeness="logical_copy_not_hardware_acquisition"});
                return new Prepared{Image=image,Checksum=sha};
            }
        }
    }
}
