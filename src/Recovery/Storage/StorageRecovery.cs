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
        public static HelperResult ProbeLvm(string[] sources,CancellationToken token)
        {
            if(sources==null||sources.Length==0||sources.Length>32)throw new IOException("Выбери от одного до 32 RAW-образов физических томов LVM.");
            return HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="lvm_probe",sources=sources.Select(Path.GetFullPath).ToArray()},token,null);
        }
        public static StoragePreparedResult Prepare(string kind,string image,string destination,StorageVolumeInfo volume,Dictionary<string,string> secrets,bool snapshots,long maximumBytes,CancellationToken token,Action<RecoveryStageProgress> activity,int maximumSnapshots=1024,bool resume=false,string[] lvmSources=null)
        {
            if(maximumSnapshots<0||maximumSnapshots>16384)throw new ArgumentException("Недопустимый лимит снимков.");
            if(kind!="APFS"&&kind!="BitLocker"&&kind!="LVM")throw new ArgumentException("Неизвестный источник.");
            if(volume==null||volume.Kind!=kind||maximumBytes<=0)throw new IOException("Сначала проверь образ и выбери подходящий том.");
            using(var guard=LockImage(image,token)){
                if(volume.OffsetBytes<0||volume.LengthBytes<=0||kind!="LVM"&&volume.OffsetBytes>guard.Length-volume.LengthBytes)throw new IOException("Том выходит за границы образа.");
                SourcePaths.NoLinks(destination);
                if(!resume||!Directory.Exists(destination))CreatePrivateDirectory(destination);
                bool hasCheckpoint=File.Exists(Path.Combine(destination,kind=="APFS"?"apfs-resume.json":kind=="LVM"?"lvm-resume.json":"bitlocker-resume.json"));
                var result=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation=kind=="APFS"?"apfs":kind=="LVM"?"lvm":"bitlocker",source=Path.GetFullPath(image),sources=lvmSources,destination=Path.GetFullPath(destination),secrets=secrets,options=new{volume_id=volume.Identifier,resume=resume&&hasCheckpoint,offset_bytes=volume.OffsetBytes,length_bytes=volume.LengthBytes,include_snapshots=snapshots,max_output_bytes=maximumBytes,max_file_bytes=Math.Min(maximumBytes,1024L*1024*1024*1024),max_files=100000,max_snapshots=maximumSnapshots,prefer_recent_snapshots=true}},token,null,
                    p=>{if(activity!=null)activity(new RecoveryStageProgress{Key="storage",Title=kind=="APFS"?"Чтение APFS и снимков":kind=="LVM"?"Сборка логического тома LVM":"Расшифровка BitLocker",State="running",Completed=p.Completed,Total=p.Total});});
                if(result.Status=="error")throw new IOException(ErrorText(result.Code));
                var prepared=new StoragePreparedResult{Directory=destination,Partial=result.Status=="partial",Files=result.Files};
                if(kind=="APFS"){
                    RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"source-image.json"),new{origin="apfs",sourcePath=Path.GetFullPath(image),offset=volume.OffsetBytes,completeness="referenced_files_and_accessible_snapshots",deleted_recovery_guaranteed=false});
                    PhotoCatalog.Build(destination,token,s=>{});var catalog=RecoveryCatalog.Build(destination,token,s=>{});prepared.Catalog=destination;prepared.Files=catalog.Items.Count;
                    RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"result.json"),new{status=prepared.Partial?"finished_with_warnings":"finished",origin="APFS",uniqueFiles=catalog.Items.Count,deleted_recovery_guaranteed=false});
                }else{
                    string relative=result.Image;
                    if(kind=="LVM"?relative!="lvm.dd"||prepared.Partial:relative!="decrypted.dd"&&relative!="decrypted-prefix.dd")throw new IOException("Неподдерживаемый ответ движка подготовки тома.");
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
            var options=SearchOptions(maximum,prepared.Partial);
            RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"source-image.json"),new{origin=prepared.Partial?"decrypted_prefix":"prepared_storage_image",sourcePath=prepared.Image,completeness=prepared.Partial?"partial_prefix":"prepared_under_reported_parameters",preparationReportDirectory=prepared.Directory});
            var result=RecoveryPipeline.Run(prepared.Image,destination,options,token,s=>{},prepared.Checksum,activity);
            RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(destination,"result.json"),new{status=result.HasWarnings||prepared.Partial?"finished_with_warnings":"finished",uniqueFiles=result.UniqueFiles,candidates=result.Candidates,partialSource=prepared.Partial});
            return destination;
        }
        public static RecoveryOptions SearchOptions(bool maximum,bool partial)
        {
            var options=new RecoveryOptions{AlternateFat=maximum,OrphanDirectories=maximum,MetadataRescue=maximum,ArchiveMembers=maximum,FragmentedArchives=maximum,JpegFragments=maximum,KeepCorrupted=maximum,FragmentedPhotos=maximum,FragmentedVideo=maximum,Ext4Metadata=maximum,RefsMetadata=maximum,UnknownNtfsAllocation=maximum&&!partial};
            if(partial)options.FatMetadata=options.NtfsMetadata=options.Ext4Metadata=options.RefsMetadata=options.LostPartitions=options.OrphanDirectories=options.MetadataRescue=false;
            return options;
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
                case "RESUME_SOURCE_CHANGED":return "Исходный образ или параметры изменились. Продолжение остановлено.";
                case "RESUME_OUTPUT_CHANGED":case "RESUME_CHECKPOINT_INVALID":case "RESUME_RECORD_NOT_FOUND":return "Сохранённая часть или контрольная точка изменена. Продолжение остановлено.";
                case "SOURCE_PREPARATION_BUSY":return "Эта рабочая папка уже используется другой операцией.";
                case "LVM_MEMBERS_MISSING":return "Не все физические тома LVM предоставлены. Добавь недостающие образы.";
                case "LVM_MIRRORS_DISAGREE":case "LVM_METADATA_COPIES_DISAGREE":return "Копии LVM расходятся. Сборка остановлена; требуется разбор состояния массива.";
                case "LVM_RAW_PHYSICAL_VOLUME_REQUIRED":return "Нужны RAW-образы самих физических томов LVM. Образ всего диска сначала раздели по его разметке.";
                case "LVM_LAYOUT_UNSUPPORTED":case "LVM_SEGMENT_UNSUPPORTED":case "LVM_THIN_STATE_UNSUPPORTED":case "LVM_THIN_VERSION_UNSUPPORTED":return "Этот тип или состояние LVM пока не поддерживается.";
                case "LVM_LABEL_CHECKSUM_FAILED":case "LVM_METADATA_CHECKSUM_FAILED":case "LVM_THIN_CHECKSUM_FAILED":case "LVM_THIN_METADATA_INVALID":return "Проверка метаданных LVM не пройдена. Готовый образ не опубликован.";
                default:return "Операция не завершена. Исходный образ не изменялся; смотри отчёт источника.";
            }
        }
    }
}
