using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    public sealed class ResumableRange { public long Offset,Length; }
    public sealed class ResumableCaptureResult
    {
        public string Sha256;
        public long UnreadBytes,ResumedBytes,CopiedBytes;
        public List<ResumableRange> Ranges=new List<ResumableRange>();
    }
    public sealed class CaptureCheckpointInfo
    {
        public string Identity,Status,PartialName;
        public long Size,CompletedBytes;
        public int SectorSize;
    }
    // Source identity is supplied by the caller after opening/verifying the
    // physical device. Samples detect some changes, not arbitrary unsampled
    // writes. The source is never opened for writing or modified here.
    public static class ResumableCapture
    {
        public const int ChunkBytes=4*1024*1024,SampleBytes=4096,MaximumSamples=16,MaximumRetrySectors=4096;
        public const int MaximumChunks=262144,MaximumRanges=32768;
        const long MaximumJournalBytes=128L*1024*1024;
        const int MaximumLineBytes=256*1024;
        static readonly Encoding Utf8=new UTF8Encoding(false,true);
        [StructLayout(LayoutKind.Sequential)]struct FileIdentity
        {
            public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
            public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
        }
        [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle,out FileIdentity info);
        static void RejectAlias(FileStream source,FileStream output)
        {
            if(source==null)return;FileIdentity a,b;
            if(GetFileInformationByHandle(source.SafeFileHandle,out a)&&GetFileInformationByHandle(output.SafeFileHandle,out b)&&a.Volume==b.Volume&&a.IndexHigh==b.IndexHigh&&a.IndexLow==b.IndexLow)throw Error("Рабочий файл совпадает с источником (включая жёсткую ссылку).");
        }
        sealed class Sample { public long Offset;public int Length;public string Sha256; }
        sealed class Chunk
        {
            public string Kind,Sha256;
            public long Offset;
            public int Length;
            public List<ResumableRange> Missing=new List<ResumableRange>();
        }
        sealed class Envelope { public string Payload,Previous,Hash; }
        sealed class Pending { public string OldSha256;public Chunk Next; }
        sealed class Head
        {
            public int Version=1,SectorSize,ChunkSize=ChunkBytes,Records;
            public long Size,CompletedBytes,JournalBytes;
            public string Identity,PartialName,Status,LastHash,Checksum;
            public List<Sample> Samples=new List<Sample>();
            public Pending Pending;
        }
        static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=8*1024*1024,RecursionLimit=32};}
        static string Hash(byte[] bytes){using(var sha=SHA256.Create())return Hex(sha.ComputeHash(bytes));}
        static string Hex(byte[] bytes){return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
        static bool Digest(string value){return value!=null&&value.Length==64&&value.All(c=>c>='0'&&c<='9'||c>='a'&&c<='f');}
        static IOException Error(string text){return new IOException(text);}
        static string Canonical(object value)
        {
            var row=value as Dictionary<string,object>;if(row!=null)return "{"+String.Join(",",row.OrderBy(x=>x.Key,StringComparer.Ordinal).Select(x=>Json().Serialize(x.Key)+":"+Canonical(x.Value)))+"}";
            var values=value as object[];if(values!=null)return "["+String.Join(",",values.Select(Canonical))+"]";
            return Json().Serialize(value);
        }
        static string HeaderDigest(Head head){return Hash(Utf8.GetBytes(Canonical(Json().DeserializeObject(Json().Serialize(head)))));}
        static void SafePath(string path)
        {
            string full=Path.GetFullPath(path);
            if(full.StartsWith("\\\\",StringComparison.Ordinal)||full.IndexOf(':',2)>=0)throw Error("Для рабочей копии нужен обычный локальный путь.");
            if(File.Exists(full)&&(File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw Error("Файл-ссылка недопустим для съёма образа.");
            for(var parent=new DirectoryInfo(Path.GetDirectoryName(full));parent!=null;parent=parent.Parent)
                if(parent.Exists&&(parent.Attributes&FileAttributes.ReparsePoint)!=0)throw Error("Перенаправление рабочей папки недопустимо.");
        }
        static string Normalize(string path){SafePath(path);return Path.GetFullPath(path);}
        static void Atomic(string path,string text)
        {
            string temp=path+"."+Guid.NewGuid().ToString("N")+".partial";
            try{byte[] data=Utf8.GetBytes(text);using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)){file.Write(data,0,data.Length);file.Flush(true);}if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);}
            finally{if(File.Exists(temp))File.Delete(temp);}
        }
        static void SaveHead(string file,Head head)
        {
            head.Checksum=null;head.Checksum=HeaderDigest(head);Atomic(file,Json().Serialize(head));
        }
        static Head Load(string file)
        {
            SafePath(file);if(!File.Exists(file)||new FileInfo(file).Length>2L*1024*1024)throw Error("Контрольная точка отсутствует или слишком велика.");
            try{
                var head=Json().Deserialize<Head>(File.ReadAllText(file,Utf8));
                if(head==null||!Digest(head.Checksum))throw Error("Контрольная точка повреждена.");string expected=head.Checksum;head.Checksum=null;string actual=HeaderDigest(head);head.Checksum=expected;
                if(actual!=expected||head.Version!=1||head.ChunkSize!=ChunkBytes||String.IsNullOrWhiteSpace(head.Identity)||head.Identity.Length>4096||String.IsNullOrEmpty(head.PartialName)||Path.GetFileName(head.PartialName)!=head.PartialName||head.Size<=0||head.SectorSize<512||head.SectorSize>4096||(head.SectorSize&(head.SectorSize-1))!=0||head.Size%head.SectorSize!=0||head.Size>(long)MaximumChunks*ChunkBytes||head.CompletedBytes<0||head.CompletedBytes>head.Size||head.CompletedBytes!=head.Size&&head.CompletedBytes%ChunkBytes!=0||head.JournalBytes<0||head.JournalBytes>MaximumJournalBytes||head.Records<0||head.Records>MaximumChunks*2||!Digest(head.LastHash)||head.Samples==null||head.Samples.Count>MaximumSamples)throw Error("Контрольная точка не прошла проверку структуры.");
                if(!new[]{"copying","retrying","cancelled","incomplete","complete","complete_with_read_errors"}.Contains(head.Status))throw Error("Неизвестное состояние съёма.");
                foreach(var sample in head.Samples)if(sample==null||sample.Offset<0||sample.Offset>head.Size-sample.Length||sample.Offset%head.SectorSize!=0||sample.Length<=0||sample.Length>SampleBytes||sample.Length%head.SectorSize!=0||sample.Sha256!=null&&!Digest(sample.Sha256))throw Error("Некорректные отпечатки источника.");
                return head;
            }catch(ArgumentException){throw Error("Не удалось прочитать контрольную точку.");}catch(InvalidOperationException){throw Error("Не удалось прочитать контрольную точку.");}
        }
        public static CaptureCheckpointInfo Inspect(string checkpoint)
        {
            var head=Load(checkpoint);return new CaptureCheckpointInfo{Identity=head.Identity,Status=head.Status,PartialName=head.PartialName,Size=head.Size,SectorSize=head.SectorSize,CompletedBytes=head.CompletedBytes};
        }
        public static ResumableCaptureResult VerifyCompletedImage(string checkpoint,string image,CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();checkpoint=Normalize(checkpoint);image=Normalize(image);var head=Load(checkpoint);
            if(head.CompletedBytes!=head.Size||head.Pending!=null||head.Status!="complete"&&head.Status!="complete_with_read_errors")throw Error("Контрольная точка не подтверждает завершённый съём.");
            var chunks=Replay(Normalize(checkpoint+".chunks.jsonl"),head,cancel);var gaps=Merge(chunks.Values.SelectMany(x=>x.Missing));
            if((gaps.Count>0)!=(head.Status=="complete_with_read_errors"))throw Error("Состояние съёма не соответствует карте ошибок.");
            string digest;using(var file=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))using(var sha=SHA256.Create()){
                if(file.Length!=head.Size)throw Error("Завершённый образ имеет другой размер.");
                foreach(var chunk in chunks.Values){cancel.ThrowIfCancellationRequested();byte[] bytes=Bytes(file,chunk,cancel);if(Hash(bytes)!=chunk.Sha256)throw Error("Блок завершённого образа изменён. Продолжение не подтверждено.");sha.TransformBlock(bytes,0,bytes.Length,null,0);}
                cancel.ThrowIfCancellationRequested();sha.TransformFinalBlock(new byte[0],0,0);digest=Hex(sha.Hash);
            }
            return new ResumableCaptureResult{Sha256=digest,UnreadBytes=gaps.Sum(x=>x.Length),ResumedBytes=head.CompletedBytes,CopiedBytes=head.CompletedBytes,Ranges=gaps};
        }
        static bool Read(Stream source,long offset,byte[] bytes,int start,int count,int sector,CancellationToken cancel)
        {
            try{
                source.Position=offset;int done=0;while(done<count){cancel.ThrowIfCancellationRequested();int n=source.Read(bytes,start+done,count-done);if(n==0)throw new EndOfStreamException("Источник перестал отдавать данные; неполная копия сохранена.");if(n%sector!=0)throw new EndOfStreamException("Источник вернул неполный сектор.");done+=n;}return true;
            }catch(EndOfStreamException){throw;}catch(IOException){return false;}
        }
        static void Available(Func<bool> available)
        {
            if(available!=null&&!available())throw Error("Источник отключился или изменился. Неполная копия и контрольная точка сохранены.");
        }
        static List<Sample> Samples(Stream source,long size,int sector,bool tolerate,CancellationToken cancel,Func<bool> available)
        {
            var result=new List<Sample>();int length=(int)Math.Min(SampleBytes,size);
            for(int i=0;i<MaximumSamples;i++){
                cancel.ThrowIfCancellationRequested();long offset=((size-length)*i/(MaximumSamples-1))/SampleBytes*SampleBytes;if(result.Any(x=>x.Offset==offset))continue;
                byte[] bytes=new byte[length];bool ok=Read(source,offset,bytes,0,length,sector,cancel);if(!ok){Available(available);if(!tolerate)throw Error("Не удалось прочитать контрольный участок источника.");}
                result.Add(new Sample{Offset=offset,Length=length,Sha256=ok?Hash(bytes):null});
            }
            return result;
        }
        static void CheckCapturedSamples(Head head,Chunk chunk,byte[] bytes)
        {
            foreach(var sample in head.Samples){
                if(sample.Offset<chunk.Offset||sample.Offset+sample.Length>chunk.Offset+chunk.Length||chunk.Missing.Any(x=>sample.Offset<x.Offset+x.Length&&x.Offset<sample.Offset+sample.Length))continue;
                var captured=new byte[sample.Length];Buffer.BlockCopy(bytes,(int)(sample.Offset-chunk.Offset),captured,0,captured.Length);string digest=Hash(captured);
                if(sample.Sha256!=null&&sample.Sha256!=digest)throw Error("Контрольный участок источника изменился во время съёма. Смешанная копия не публикуется.");
                sample.Sha256=digest;
            }
        }
        static void VerifySamples(Stream source,Head head,CancellationToken cancel,Func<bool> available)
        {
            int verified=0;
            foreach(var sample in head.Samples){
                cancel.ThrowIfCancellationRequested();if(sample.Sha256==null)continue;
                byte[] bytes=new byte[sample.Length];if(!Read(source,sample.Offset,bytes,0,bytes.Length,head.SectorSize,cancel)){Available(available);throw Error("Ранее прочитанный контрольный участок больше не доступен. Возобновление не подтверждено.");}
                if(Hash(bytes)!=sample.Sha256)throw Error("Содержимое контрольного участка источника изменилось. Старую и новую копии нельзя объединять.");verified++;
            }
            if(verified==0)throw Error("Нет сохранённых читаемых отпечатков источника. Безопасное возобновление не подтверждено; начни отдельную копию.");
            Available(available);
        }
        static List<ResumableRange> Merge(IEnumerable<ResumableRange> ranges)
        {
            var result=new List<ResumableRange>();foreach(var row in ranges.OrderBy(x=>x.Offset)){
                if(result.Count==0||result[result.Count-1].Offset+result[result.Count-1].Length<row.Offset)result.Add(new ResumableRange{Offset=row.Offset,Length=row.Length});
                else{var last=result[result.Count-1];last.Length=Math.Max(last.Offset+last.Length,row.Offset+row.Length)-last.Offset;}
            }
            if(result.Count>MaximumRanges)throw Error("Достигнут предел карты ошибок. Частичная копия сохранена.");return result;
        }
        static void ValidateChunk(Chunk chunk,Head head)
        {
            if(chunk==null||chunk.Offset<0||chunk.Offset>=head.Size||chunk.Offset%ChunkBytes!=0||chunk.Length!=Math.Min(ChunkBytes,head.Size-chunk.Offset)||!Digest(chunk.Sha256)||chunk.Missing==null||chunk.Missing.Count>MaximumRetrySectors+64)throw Error("Запись журнала повреждена.");
            long previous=chunk.Offset;foreach(var gap in chunk.Missing){if(gap==null||gap.Offset<previous||gap.Offset<chunk.Offset||gap.Length<=0||gap.Offset>chunk.Offset+chunk.Length-gap.Length||gap.Offset%head.SectorSize!=0||gap.Length%head.SectorSize!=0)throw Error("Некорректная карта пропусков журнала.");previous=gap.Offset+gap.Length;}
        }
        static string Line(FileStream stream,long limit)
        {
            using(var bytes=new MemoryStream()){
                while(stream.Position<limit){int b=stream.ReadByte();if(b<0)throw Error("Журнал съёма обрезан.");if(b==10)return Utf8.GetString(bytes.ToArray());if(bytes.Length>=MaximumLineBytes)throw Error("Слишком большая запись журнала.");bytes.WriteByte((byte)b);}
                throw Error("Незавершённая запись в подтверждённой части журнала.");
            }
        }
        static SortedDictionary<long,Chunk> Replay(string journal,Head head,CancellationToken cancel)
        {
            var chunks=new SortedDictionary<long,Chunk>();long copied=0;int records=0;string previous=new string('0',64);
            using(var input=new FileStream(journal,FileMode.Open,FileAccess.Read,FileShare.Read)){
                if(input.Length<head.JournalBytes)throw Error("Подтверждённая часть журнала отсутствует.");
                while(input.Position<head.JournalBytes){cancel.ThrowIfCancellationRequested();Envelope envelope;Chunk chunk;
                    try{envelope=Json().Deserialize<Envelope>(Line(input,head.JournalBytes));if(envelope==null||envelope.Previous!=previous||envelope.Payload==null||envelope.Hash!=Hash(Utf8.GetBytes(previous+"\n"+envelope.Payload)))throw Error("Цепочка контрольных сумм журнала не совпала.");chunk=Json().Deserialize<Chunk>(envelope.Payload);}
                    catch(ArgumentException){throw Error("Журнал съёма повреждён.");}catch(InvalidOperationException){throw Error("Журнал съёма повреждён.");}
                    ValidateChunk(chunk,head);
                    if(chunk.Kind=="copy"){
                        if(chunk.Offset!=copied||chunks.ContainsKey(chunk.Offset))throw Error("Порядок скопированных блоков не подтверждён.");copied+=chunk.Length;
                    }else if(chunk.Kind=="repair"){
                        Chunk old;if(!chunks.TryGetValue(chunk.Offset,out old)||!Subset(chunk.Missing,old.Missing))throw Error("Повторное чтение изменило неподтверждённые диапазоны.");
                    }else throw Error("Неизвестный тип записи журнала.");
                    chunks[chunk.Offset]=chunk;previous=envelope.Hash;if(++records>MaximumChunks*2)throw Error("Слишком большой журнал.");
                }
            }
            if(copied!=head.CompletedBytes||records!=head.Records||previous!=head.LastHash)throw Error("Журнал не соответствует контрольной точке.");return chunks;
        }
        static bool Subset(IEnumerable<ResumableRange> small,IList<ResumableRange> big)
        {
            foreach(var range in small)if(!big.Any(x=>range.Offset>=x.Offset&&range.Offset+range.Length<=x.Offset+x.Length))return false;return true;
        }
        static byte[] Bytes(FileStream output,Chunk chunk,CancellationToken cancel)
        {
            var bytes=new byte[chunk.Length];output.Position=chunk.Offset;int at=0;while(at<bytes.Length){cancel.ThrowIfCancellationRequested();int n=output.Read(bytes,at,bytes.Length-at);if(n==0)throw Error("Рабочая копия обрезана.");at+=n;}return bytes;
        }
        static void Commit(FileStream journal,Head head,Chunk chunk)
        {
            if(head.Records>=MaximumChunks*2)throw Error("Достигнут предел журнала.");
            string payload=Json().Serialize(chunk),digest=Hash(Utf8.GetBytes(head.LastHash+"\n"+payload));byte[] bytes=Utf8.GetBytes(Json().Serialize(new Envelope{Payload=payload,Previous=head.LastHash,Hash=digest})+"\n");
            if(bytes.Length>MaximumLineBytes||head.JournalBytes>MaximumJournalBytes-bytes.Length)throw Error("Достигнут предел размера журнала.");
            journal.Position=head.JournalBytes;journal.Write(bytes,0,bytes.Length);journal.Flush(true);head.JournalBytes+=bytes.Length;head.LastHash=digest;head.Records++;
            if(chunk.Kind=="copy")head.CompletedBytes+=chunk.Length;
        }
        static void Map(string path,Head head,List<ResumableRange> gaps)
        {
            Atomic(path,Json().Serialize(new{status=head.Status,size=head.Size,copied=head.CompletedBytes,unreadBytes=gaps.Sum(x=>x.Length),ranges=gaps,sourceIdentitySha256=Hash(Utf8.GetBytes(head.Identity)),note="Unread ranges are zero-filled placeholders. Source is never written. Resume verifies completed output hashes and sampled source fingerprints; arbitrary unsampled source changes cannot be detected."}));
        }
        static void Persist(string checkpoint,string map,Head head,List<ResumableRange> gaps){SaveHead(checkpoint,head);Map(map,head,gaps);}
        static void Write(FileStream output,long offset,byte[] bytes){output.Position=offset;output.Write(bytes,0,bytes.Length);output.Flush(true);}
        static void RestorePending(Stream source,FileStream output,FileStream journal,Head head,SortedDictionary<long,Chunk> chunks,string patch,string checkpoint,string map,CancellationToken cancel,Func<bool> available)
        {
            var pending=head.Pending;if(pending==null)return;Chunk old;ValidateChunk(pending.Next,head);
            if(pending.Next.Kind!="repair"||!chunks.TryGetValue(pending.Next.Offset,out old)||pending.OldSha256!=old.Sha256||!Subset(pending.Next.Missing,old.Missing)||!File.Exists(patch)||new FileInfo(patch).Length!=old.Length)throw Error("Незавершённое повторное чтение не прошло проверку.");
            byte[] bytes=File.ReadAllBytes(patch);if(Hash(bytes)!=pending.Next.Sha256)throw Error("Временный блок повторного чтения изменён.");
            byte[] original=(byte[])bytes.Clone();foreach(var gap in old.Missing)Array.Clear(original,(int)(gap.Offset-old.Offset),(int)gap.Length);
            if(Hash(original)!=old.Sha256)throw Error("Временный блок изменяет уже подтверждённые данные.");
            // Verify newly repaired source bytes before committing a pending
            // transaction left by an interrupted process.
            foreach(var gap in old.Missing)for(long at=gap.Offset;at<gap.Offset+gap.Length;at+=head.SectorSize){
                cancel.ThrowIfCancellationRequested();if(pending.Next.Missing.Any(x=>at>=x.Offset&&at<x.Offset+x.Length))continue;var sector=new byte[head.SectorSize];
                if(!Read(source,at,sector,0,sector.Length,head.SectorSize,cancel)){Available(available);throw Error("Новый фрагмент повторного чтения больше не доступен.");}
                for(int i=0;i<sector.Length;i++)if(sector[i]!=bytes[(int)(at-old.Offset)+i])throw Error("Источник изменился при повторном чтении.");
            }
            CheckCapturedSamples(head,pending.Next,bytes);Write(output,old.Offset,bytes);Commit(journal,head,pending.Next);chunks[old.Offset]=pending.Next;head.Pending=null;Persist(checkpoint,map,head,Merge(chunks.Values.SelectMany(x=>x.Missing)));File.Delete(patch);
        }
        public static ResumableCaptureResult Copy(Stream source,string partial,long size,int sector,string identity,string checkpoint,string map,CancellationToken cancel,Action<long,long> progress,Func<bool> available,bool resume=false,bool tolerateErrors=false,bool retryUnread=true)
        {
            cancel.ThrowIfCancellationRequested();if(source==null||!source.CanRead||!source.CanSeek||size<=0||sector<512||sector>4096||(sector&(sector-1))!=0||size%sector!=0||size>(long)MaximumChunks*ChunkBytes||String.IsNullOrWhiteSpace(identity)||identity.Length>4096)throw Error("Некорректные параметры возобновляемого съёма.");
            partial=Normalize(partial);checkpoint=Normalize(checkpoint);map=Normalize(map);string journalPath=Normalize(checkpoint+".chunks.jsonl"),patch=Normalize(checkpoint+".repair.partial");
            var paths=new[]{partial,checkpoint,map,journalPath,patch};if(paths.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=paths.Length||paths.Any(x=>!String.Equals(Path.GetDirectoryName(x),Path.GetDirectoryName(partial),StringComparison.OrdinalIgnoreCase)))throw Error("Копия и контрольные файлы должны иметь разные имена в одной локальной папке.");
            var fileSource=source as FileStream;if(fileSource!=null){string sourcePath=Path.GetFullPath(fileSource.Name);if(paths.Any(x=>String.Equals(x,sourcePath,StringComparison.OrdinalIgnoreCase)))throw Error("Рабочий файл не может совпадать с источником.");}
            if(fileSource!=null)foreach(string path in paths.Where(File.Exists))using(var existing=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))RejectAlias(fileSource,existing);
            // Device enumeration is expensive. Failed sector probes reuse a
            // one-second availability check; block failures and finalization
            // still perform an immediate identity/disconnect check.
            Func<bool> immediateAvailable=available;
            if(available!=null){var clock=System.Diagnostics.Stopwatch.StartNew();long last=-1000;bool cached=true;available=()=>{if(clock.ElapsedMilliseconds-last>=1000){cached=immediateAvailable();last=clock.ElapsedMilliseconds;}return cached;};}
            Head head;SortedDictionary<long,Chunk> chunks;
            if(resume){
                head=Load(checkpoint);if(head.Identity!=identity||head.Size!=size||head.SectorSize!=sector||!String.Equals(head.PartialName,Path.GetFileName(partial),StringComparison.OrdinalIgnoreCase))throw Error("Контрольная точка принадлежит другому носителю или размеру.");
                chunks=Replay(journalPath,head,cancel);VerifySamples(source,head,cancel,available);
            }else{
                if(paths.Any(x=>File.Exists(x)||Directory.Exists(x)))throw Error("Рабочие файлы уже существуют. Выбери возобновление или новую папку.");
                head=new Head{Identity=identity,Size=size,SectorSize=sector,PartialName=Path.GetFileName(partial),Status="copying",LastHash=new string('0',64),Samples=Samples(source,size,sector,tolerateErrors,cancel,available)};
                chunks=new SortedDictionary<long,Chunk>();
            }
            long resumed=head.CompletedBytes;var gaps=Merge(chunks.Values.SelectMany(x=>x.Missing));bool verified=false;
            using(var output=new FileStream(partial,resume?FileMode.Open:FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read))
            using(var journal=new FileStream(journalPath,resume?FileMode.Open:FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read)){
                RejectAlias(fileSource,output);RejectAlias(fileSource,journal);
                if(resume){
                    if(output.Length<head.CompletedBytes)throw Error("Рабочая копия короче подтверждённой части.");
                    foreach(var chunk in chunks.Values){cancel.ThrowIfCancellationRequested();if(head.Pending!=null&&head.Pending.Next!=null&&chunk.Offset==head.Pending.Next.Offset)continue;if(Hash(Bytes(output,chunk,cancel))!=chunk.Sha256)throw Error("Подтверждённый блок рабочей копии изменён. Возобновление остановлено.");}
                    // Uncommitted trailing data is never treated as completed.
                    journal.SetLength(head.JournalBytes);output.SetLength(head.CompletedBytes);RestorePending(source,output,journal,head,chunks,patch,checkpoint,map,cancel,available);
                    if(head.Pending==null&&File.Exists(patch))File.Delete(patch);
                    gaps=Merge(chunks.Values.SelectMany(x=>x.Missing));
                }
                verified=true;head.Status="copying";Persist(checkpoint,map,head,gaps);
                try{
                    if(progress!=null)progress(head.CompletedBytes,size);
                    while(head.CompletedBytes<size){
                        cancel.ThrowIfCancellationRequested();long at=head.CompletedBytes;int count=(int)Math.Min(ChunkBytes,size-at);byte[] buffer=new byte[count];var missing=new List<ResumableRange>();
                        if(!Read(source,at,buffer,0,count,sector,cancel)){
                            Available(immediateAvailable);if(!tolerateErrors)throw Error("Ошибка чтения. Копия и контрольная точка сохранены для возобновления.");
                            for(int p=0;p<count;p+=65536){cancel.ThrowIfCancellationRequested();int n=Math.Min(65536,count-p);if(Read(source,at+p,buffer,p,n,sector,cancel))continue;Available(available);Array.Clear(buffer,p,n);missing.Add(new ResumableRange{Offset=at+p,Length=n});}
                        }
                        var chunk=new Chunk{Kind="copy",Offset=at,Length=count,Sha256=Hash(buffer),Missing=Merge(missing)};var newGaps=Merge(gaps.Concat(chunk.Missing));
                        CheckCapturedSamples(head,chunk,buffer);Write(output,at,buffer);Commit(journal,head,chunk);chunks[at]=chunk;gaps=newGaps;Persist(checkpoint,map,head,gaps);if(progress!=null)progress(head.CompletedBytes,size);
                    }
                    if(tolerateErrors&&retryUnread&&gaps.Count>0){
                        head.Status="retrying";Persist(checkpoint,map,head,gaps);int attempts=0;
                        foreach(var old in chunks.Values.Where(x=>x.Missing.Count>0).ToList()){
                            cancel.ThrowIfCancellationRequested();if(attempts>=MaximumRetrySectors)break;Available(immediateAvailable);byte[] buffer=Bytes(output,old,cancel);var missing=new List<ResumableRange>();bool changed=false;
                            foreach(var gap in old.Missing)for(long at=gap.Offset;at<gap.Offset+gap.Length;at+=sector){
                                cancel.ThrowIfCancellationRequested();if(attempts>=MaximumRetrySectors){missing.Add(new ResumableRange{Offset=at,Length=gap.Offset+gap.Length-at});break;}
                                attempts++;var data=new byte[sector];if(Read(source,at,data,0,sector,sector,cancel)){Buffer.BlockCopy(data,0,buffer,(int)(at-old.Offset),sector);changed=true;}
                                else{Available(available);missing.Add(new ResumableRange{Offset=at,Length=sector});}
                            }
                            if(!changed)continue;
                            var next=new Chunk{Kind="repair",Offset=old.Offset,Length=old.Length,Sha256=Hash(buffer),Missing=Merge(missing)};var nextGaps=Merge(chunks.Values.Where(x=>x.Offset!=old.Offset).SelectMany(x=>x.Missing).Concat(next.Missing));
                            CheckCapturedSamples(head,next,buffer);using(var staged=new FileStream(patch,FileMode.CreateNew,FileAccess.Write,FileShare.None)){staged.Write(buffer,0,buffer.Length);staged.Flush(true);}
                            head.Pending=new Pending{OldSha256=old.Sha256,Next=next};SaveHead(checkpoint,head);Write(output,old.Offset,buffer);Commit(journal,head,next);chunks[old.Offset]=next;gaps=nextGaps;head.Pending=null;Persist(checkpoint,map,head,gaps);File.Delete(patch);if(progress!=null)progress(size,size);
                        }
                    }
                    cancel.ThrowIfCancellationRequested();output.Position=0;string digest;using(var sha=SHA256.Create()){
                        byte[] block=new byte[ChunkBytes];long total=0;int n;while((n=output.Read(block,0,block.Length))>0){cancel.ThrowIfCancellationRequested();sha.TransformBlock(block,0,n,null,0);total+=n;}if(total!=size)throw Error("Размер рабочей копии изменился.");sha.TransformFinalBlock(new byte[0],0,0);digest=Hex(sha.Hash);
                    }
                    Available(immediateAvailable);head.Status=gaps.Count==0?"complete":"complete_with_read_errors";Persist(checkpoint,map,head,gaps);return new ResumableCaptureResult{Sha256=digest,UnreadBytes=gaps.Sum(x=>x.Length),ResumedBytes=resumed,CopiedBytes=head.CompletedBytes,Ranges=gaps};
                }catch(OperationCanceledException){head.Status="cancelled";if(verified)Persist(checkpoint,map,head,gaps);throw;}catch{head.Status="incomplete";if(verified)Persist(checkpoint,map,head,gaps);throw;}
            }
        }
    }
}
