using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace UsbRecovery
{
    public sealed class StoragePreparedResult
    {
        public string Directory,Image,Checksum,Catalog;
        public bool Partial;
        public long Files;
    }
    public static class StorageRecovery
    {
        public static void CreatePrivateDirectory(string path)
        {
            path=Path.GetFullPath(path);SourcePaths.NoLinks(path);
            if(File.Exists(path)||Directory.Exists(path))throw new IOException("Выбери новую папку результатов.");
            var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
            acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            new DirectoryInfo(path).Create(acl);
        }
        public static Stream LockImage(string image,CancellationToken token)
        {
            if(image.EndsWith(".partial",StringComparison.OrdinalIgnoreCase))throw new IOException("Незавершённый .partial нельзя выдавать за готовый образ.");
            var source=new ImageRecoverySource(image);return source.OpenRead(source.Enumerate("",token).First(),token);
        }
        public static HelperResult Probe(string image,CancellationToken token)
        {
            using(var guard=LockImage(image,token))return HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="storage_probe",source=Path.GetFullPath(image)},token,null);
        }
        public static StoragePreparedResult Prepare(string kind,string image,string destination,StorageVolumeInfo volume,Dictionary<string,string> secrets,bool snapshots,long maximumBytes,CancellationToken token,Action<RecoveryStageProgress> activity,int maximumSnapshots=1024)
        {
            if(maximumSnapshots<0||maximumSnapshots>16384)throw new ArgumentException("Недопустимый лимит снимков.");
            if(kind!="APFS"&&kind!="BitLocker")throw new ArgumentException("Неизвестный источник.");
            if(volume==null||volume.Kind!=kind||maximumBytes<=0)throw new IOException("Сначала проверь образ и выбери подходящий том.");
            using(var guard=LockImage(image,token)){
                if(volume.OffsetBytes<0||volume.LengthBytes<=0||volume.OffsetBytes>guard.Length-volume.LengthBytes)throw new IOException("Том выходит за границы образа.");
                CreatePrivateDirectory(destination);
                var result=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation=kind=="APFS"?"apfs":"bitlocker",source=Path.GetFullPath(image),destination=Path.GetFullPath(destination),secrets=secrets,options=new{offset_bytes=volume.OffsetBytes,length_bytes=volume.LengthBytes,include_snapshots=snapshots,max_output_bytes=maximumBytes,max_file_bytes=Math.Min(maximumBytes,1024L*1024*1024*1024),max_files=100000,max_snapshots=maximumSnapshots,prefer_recent_snapshots=true}},token,null,
                    p=>{if(activity!=null)activity(new RecoveryStageProgress{Key="storage",Title=kind=="APFS"?"Чтение APFS и снимков":"Расшифровка BitLocker",State="running",Completed=p.Completed,Total=p.Total});});
                if(result.Status=="error")throw new IOException(ErrorText(result.Code));
                var prepared=new StoragePreparedResult{Directory=destination,Partial=result.Status=="partial",Files=result.Files};
                if(kind=="APFS"){
                    RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"source-image.json"),new{origin="apfs",sourcePath=Path.GetFullPath(image),offset=volume.OffsetBytes,completeness="referenced_files_and_accessible_snapshots",deleted_recovery_guaranteed=false});
                    PhotoCatalog.Build(destination,token,s=>{});var catalog=RecoveryCatalog.Build(destination,token,s=>{});prepared.Catalog=destination;prepared.Files=catalog.Items.Count;
                    RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"result.json"),new{status=prepared.Partial?"finished_with_warnings":"finished",origin="APFS",uniqueFiles=catalog.Items.Count,deleted_recovery_guaranteed=false});
                }else{
                    string relative=result.Image;
                    if(relative!="decrypted.dd"&&relative!="decrypted-prefix.dd")throw new IOException("Неподдерживаемый ответ движка BitLocker.");
                    if((relative=="decrypted-prefix.dd")!=prepared.Partial)throw new IOException("Состояние расшифрованного образа не подтверждено.");
                    prepared.Image=RecoveryCatalog.SafeFile(destination,relative);prepared.Checksum=prepared.Image+".sha256";
                    if(!File.Exists(prepared.Image)||!File.Exists(prepared.Checksum))throw new IOException("Расшифрованный образ не опубликован.");
                    RecoveryCore.VerifyImage(prepared.Image,prepared.Checksum,token,(a,b)=>{});
                }
                return prepared;
            }
        }
        public static string Search(StoragePreparedResult prepared,string destination,bool maximum,CancellationToken token,Action<RecoveryStageProgress> activity)
        {
            if(prepared==null||String.IsNullOrEmpty(prepared.Image))throw new IOException("Сначала подготовь образ.");
            CreatePrivateDirectory(destination);
            var options=new RecoveryOptions{AlternateFat=maximum,OrphanDirectories=maximum,MetadataRescue=maximum,ArchiveMembers=maximum,FragmentedArchives=maximum,JpegFragments=maximum};
            if(prepared.Partial){options.FatMetadata=options.NtfsMetadata=options.LostPartitions=options.OrphanDirectories=options.MetadataRescue=false;}
            RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"source-image.json"),new{origin=prepared.Partial?"decrypted_prefix":"prepared_storage_image",sourcePath=prepared.Image,completeness=prepared.Partial?"partial_prefix":"prepared_under_reported_parameters",preparationReportDirectory=prepared.Directory});
            var result=RecoveryPipeline.Run(prepared.Image,destination,options,token,s=>{},prepared.Checksum,activity);
            RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"result.json"),new{status=result.HasWarnings||prepared.Partial?"finished_with_warnings":"finished",uniqueFiles=result.UniqueFiles,candidates=result.Candidates,partialSource=prepared.Partial});
            return destination;
        }
        public static string ErrorText(string code)
        {
            switch(code){
                case "AUTH_FAILED":case "AUTHENTICATION_FAILED":case "WRONG_KEY":return "Ключ или пароль не подошёл либо проверка подлинности не пройдена.";
                case "SECRET_REQUIRED":case "KEY_REQUIRED":case "PASSWORD_REQUIRED":return "Нужен пароль или ключ этого тома.";
                case "NO_DATA":return "В доступном источнике подходящие данные не найдены.";
                case "DEPENDENCY_MISSING":return "В комплекте отсутствует необходимый компонент. Распакуй программу целиком.";
                case "UNSUPPORTED_FORMAT":case "UNSUPPORTED_VERSION":return "Этот вариант формата или состояние тома пока не поддерживается.";
                case "INVALID_SOURCE":case "SOURCE_ERROR":return "Образ повреждён, изменён или недоступен.";
                default:return "Операция не завершена. Исходный образ не изменялся; смотри отчёт источника.";
            }
        }
    }
}
