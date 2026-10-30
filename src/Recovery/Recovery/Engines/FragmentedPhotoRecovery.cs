using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class PhotoRecoveryCheckpoint
    {
        public string Path,Sha256;
        public long Sequence;
    }
    public static class FragmentedPhotoRecovery
    {
        public sealed class Extent { public long ImageOffset,LogicalOffset,Length; }
        public sealed class Candidate { public string Path,Sha256,Status,Note;public long Bytes;public List<Extent> Extents=new List<Extent>(); }
        public sealed class Report { public int Schema,Candidates,ReusedCandidates;public string Status,SourceSha256;public bool SourceUnchanged,ResumedFromCheckpoint;public long OutputBytes,VerifiedBytes,ResumedIndexBytes;public Dictionary<string,int> Skipped=new Dictionary<string,int>();public List<Candidate> Files=new List<Candidate>(); }
        public static int Recover(string image,string directory,CancellationToken cancel,Action<long,long> progress)
        {return Recover(image,directory,cancel,progress,null,null);}
        public static int Recover(string image,string directory,CancellationToken cancel,Action<long,long> progress,PhotoRecoveryCheckpoint resume,Action<PhotoRecoveryCheckpoint> checkpoint)
        {return Recover(image,directory,cancel,progress,resume,checkpoint,null);}
        internal static int Recover(string image,string directory,CancellationToken cancel,Action<long,long> progress,PhotoRecoveryCheckpoint resume,Action<PhotoRecoveryCheckpoint> checkpoint,string expectedSourceSha256)
        {
            cancel.ThrowIfCancellationRequested();SourcePaths.NoLinks(image);
            string output=RecoveryCatalog.SafeFile(directory,"fragmented-photos");
            using(var sourceGuard=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read)){
            string sourceSha=expectedSourceSha256??RecoveryCore.HashFile(image,cancel,(a,b)=>{});
            if(sourceSha.Length!=64||!sourceSha.All(Uri.IsHexDigit))throw new IOException("Неверная контрольная сумма исходного образа.");
            var result=HelperClient.Run(HelperClient.Executable,new{protocol=1,operation="fragmented_photos",source=image,destination=output,options=new{resume_checkpoint=resume}},cancel,delegate(string message){},delegate(HelperProgress update){
                if(update.Phase=="photo_checkpoint"){
                    if(checkpoint==null)return;
                    checkpoint(new PhotoRecoveryCheckpoint{Path=update.CheckpointPath,Sha256=update.CheckpointSha256,Sequence=update.CheckpointSequence});
                }else if(progress!=null)progress(update.Completed,update.Total);
            });
            cancel.ThrowIfCancellationRequested();
            if(result.Status=="error")throw new IOException(ErrorText(result.Code));
            string reportPath=RecoveryCatalog.SafeFile(directory,"fragmented-photos/report.json");
            if(!File.Exists(reportPath)||new FileInfo(reportPath).Length>16L*1024*1024)throw new IOException("Отчёт сборки фотографий отсутствует или превышает лимит.");
            var report=new JavaScriptSerializer{MaxJsonLength=16*1024*1024}.Deserialize<Report>(File.ReadAllText(reportPath));
            if(report==null||report.Schema!=1||report.Files==null||report.Files.Count>1000||report.Candidates!=report.Files.Count)throw new IOException("Неверный отчёт сборки фотографий.");
            if(!report.SourceUnchanged||report.SourceSha256==null||report.SourceSha256.Length!=64||!report.SourceSha256.All(Uri.IsHexDigit)||!String.Equals(report.SourceSha256,sourceSha,StringComparison.OrdinalIgnoreCase))throw new IOException("Отчёт фотографий не подтверждает неизменность этого исходного образа. Существующие результаты сохранены.");
            if(!(report.Status=="complete"||report.Status=="limited")||(result.Status=="complete")!=(report.Status=="complete")||report.Status=="complete"&&File.Exists(RecoveryCatalog.SafeFile(directory,"fragmented-photos/job.incomplete")))throw new IOException("Состояние отчёта фотографий противоречит завершению обработки.");
            long outputBytes=0;var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var candidate in report.Files){
                if(candidate==null||candidate.Sha256==null||candidate.Sha256.Length!=64||!candidate.Sha256.All(Uri.IsHexDigit)||candidate.Bytes<=0||candidate.Bytes>64L*1024*1024||candidate.Extents==null||candidate.Extents.Count<2||candidate.Extents.Count>100000)throw new IOException("Неверные размеры или контрольная сумма кандидата фотографии.");
                if(!new[]{"png_crc_zlib_reassembled_candidate","jpeg_gap_structural_candidate","jpeg_restart_structural_candidate","jpeg_progressive_structural_candidate","progressive_partial_precision_candidate"}.Contains(candidate.Status))throw new IOException("Неизвестное состояние кандидата фотографии.");
                bool png=candidate.Status.StartsWith("png_",StringComparison.Ordinal);string name=(png?"png-":"jpeg-")+candidate.Sha256+(png?".png":".jpg");
                if(!String.Equals(candidate.Path,name,StringComparison.OrdinalIgnoreCase)||!names.Add(candidate.Path))throw new IOException("Неверное или повторное имя кандидата фотографии.");
                if(candidate.Path==null||candidate.Path.IndexOfAny(new[]{'/','\\',':'})>=0)throw new IOException("Неверный путь кандидата фотографии.");
                candidate.Path="fragmented-photos/"+candidate.Path;
                string file=RecoveryCatalog.SafeFile(directory,candidate.Path);
                if(!File.Exists(file)||new FileInfo(file).Length!=candidate.Bytes)throw new IOException("Кандидат фотографии отсутствует или изменён после извлечения.");
                VerifyMapping(sourceGuard,file,candidate,cancel);
                outputBytes+=candidate.Bytes;if(outputBytes>512L*1024*1024)throw new IOException("Превышен лимит кандидатов фотографий.");
            }
            if(report.OutputBytes!=outputBytes||report.VerifiedBytes<0)throw new IOException("Размеры отчёта фотографий не совпадают с сохранёнными файлами.");
            RecoveryCore.SaveJson(RecoveryCatalog.SafeFile(directory,"fragmented-photo-search.json"),report);
            if(progress!=null)progress(new FileInfo(image).Length,new FileInfo(image).Length);
            if(result.Status=="partial"||report.Status!="complete")throw new IOException("Сборка фотографий достигла ограничения; подтверждённые кандидаты сохранены, проход неполный.");
            return report.Candidates;
            }
        }
        static void VerifyMapping(FileStream source,string file,Candidate candidate,CancellationToken cancel)
        {
            long logical=0,priorEnd=-1;
            foreach(var extent in candidate.Extents){if(extent==null||extent.LogicalOffset!=logical||extent.ImageOffset<0||extent.Length<=0||extent.Length>candidate.Bytes-logical||extent.ImageOffset>source.Length-extent.Length)throw new IOException("Неверная карта исходных участков фотографии.");logical+=extent.Length;}
            foreach(var extent in candidate.Extents.OrderBy(x=>x.ImageOffset)){if(extent.ImageOffset<priorEnd)throw new IOException("Участки исходной фотографии пересекаются.");priorEnd=extent.ImageOffset+extent.Length;}
            if(logical!=candidate.Bytes)throw new IOException("Карта исходных участков фотографии неполна.");
            using(var output=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read)){
                cancel.ThrowIfCancellationRequested();if(output.Length!=candidate.Bytes)throw new IOException("Размер кандидата фотографии изменён после извлечения.");
                using(var hash=SHA256.Create()){string actual=BitConverter.ToString(hash.ComputeHash(output)).Replace("-","").ToLowerInvariant();if(!String.Equals(actual,candidate.Sha256,StringComparison.OrdinalIgnoreCase))throw new IOException("Контрольная сумма кандидата фотографии не совпадает с отчётом.");}output.Position=0;
                byte[] left=new byte[65536],right=new byte[65536];
                foreach(var extent in candidate.Extents){source.Position=extent.ImageOffset;long remaining=extent.Length;
                    while(remaining>0){cancel.ThrowIfCancellationRequested();int count=(int)Math.Min(left.Length,remaining);ReadExact(source,left,count);ReadExact(output,right,count);for(int i=0;i<count;i++)if(left[i]!=right[i])throw new IOException("Сохранённая фотография не совпадает с указанными исходными участками.");remaining-=count;}
                }
            }
        }
        static void ReadExact(Stream stream,byte[] bytes,int count)
        {int done=0;while(done<count){int read=stream.Read(bytes,done,count-done);if(read==0)throw new IOException("Данные фотографии или образа обрезаны.");done+=read;}}
        public static string ErrorText(string code)
        {
            if(code=="PHOTO_CHECKPOINT_BINDING_MISMATCH")return "Источник, параметры или версия обработки отличаются от сохранённой точки. Начни новый поиск в отдельной папке.";
            if(code=="PHOTO_CHECKPOINT_STORAGE_LIMIT")return "Достигнут лимит сохранённых точек продолжения. Найденные кандидаты сохранены, проход неполный.";
            if(code=="PHOTO_CHECKPOINT_JOB_BUSY")return "Этот поиск фотографий уже выполняется. Дождись остановки текущей операции.";
            if(code!=null&&code.StartsWith("PHOTO_CHECKPOINT_OUTPUT_",StringComparison.Ordinal))return "Сохранённый кандидат изменён или недоступен. Продолжение остановлено; существующие файлы сохранены.";
            if(code!=null&&code.StartsWith("PHOTO_CHECKPOINT_",StringComparison.Ordinal))return "Не удалось проверить сохранённую точку поиска фотографий. Исходный образ и результаты сохранены; для независимой попытки выбери новую папку.";
            return "Не удалось завершить поиск фрагментов фотографий. Исходный образ сохранён.";
        }
    }
}
