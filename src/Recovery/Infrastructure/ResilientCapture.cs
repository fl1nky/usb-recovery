using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace UsbRecovery
{
    public sealed class UnreadRange { public long Offset, Length; }
    public sealed class RescueCopyResult { public string Sha256; public long UnreadBytes; public List<UnreadRange> Ranges = new List<UnreadRange>(); }
    // A bounded best-effort copier, not a replacement for GNU ddrescue.
    // Never writes the source. Each failed sector is retried once, with an
    // explicit zero-filled-range map; disconnect/EOF is a hard failure.
    public static class ResilientCapture
    {
        public static RescueCopyResult Copy(Stream source,string partial,long size,int sector,string map,CancellationToken cancel,Action<long,long> progress,Func<bool> available)
        {
            cancel.ThrowIfCancellationRequested();
            if(!source.CanSeek || size<=0 || sector<512 || sector>4096 || size%sector!=0 || RecoveryCore.ChunkSize%sector!=0)throw new IOException("Некорректная геометрия для чтения с пропуском ошибок.");
            var result=new RescueCopyResult();long done=0;int failures=0;string status="running";byte[] buffer=new byte[RecoveryCore.ChunkSize];
            Action save=()=>RecoveryCore.SaveJson(map,new{status=status,size=size,copied=done,unreadBytes=result.UnreadBytes,ranges=result.Ranges,note="Unread ranges are zero-filled placeholders, not recovered original bytes. No source writes. No resume from this map."});
            using(var output=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
            using(var hash=SHA256.Create()) {
                try {
                    while(done<size) {
                        cancel.ThrowIfCancellationRequested();int count=(int)Math.Min(buffer.Length,size-done);
                        bool ok=Read(source,done,buffer,0,count,sector,cancel);
                        if(!ok) {
                            if(available!=null && !available())throw new IOException("Флешка отключилась или изменилась. Неполная копия сохранена.");
                            for(int small=0;small<count;small+=65536) {
                                int smallCount=Math.Min(65536,count-small);
                                if(Read(source,done+small,buffer,small,smallCount,sector,cancel))continue;
                                for(int at=small;at<small+smallCount;at+=sector) {
                                    cancel.ThrowIfCancellationRequested();if(++failures>4096)throw new IOException("Достигнут предел секторных проб. Сохранены неполная копия и карта; для дальнейшего съёма используй GNU ddrescue.");
                                    if(Read(source,done+at,buffer,at,sector,sector,cancel) || Read(source,done+at,buffer,at,sector,sector,cancel))continue;
                                    if(available!=null && !available())throw new IOException("Флешка отключилась. Поиск по неполной копии не запущен.");
                                    Array.Clear(buffer,at,sector);result.UnreadBytes+=sector;
                                    var last=result.Ranges.Count==0?null:result.Ranges[result.Ranges.Count-1];
                                    if(last!=null && last.Offset+last.Length==done+at)last.Length+=sector;else result.Ranges.Add(new UnreadRange{Offset=done+at,Length=sector});
                                }
                            }
                        }
                        output.Write(buffer,0,count);hash.TransformBlock(buffer,0,count,null,0);done+=count;save();if(progress!=null)progress(done,size);
                    }
                    cancel.ThrowIfCancellationRequested();output.Flush(true);hash.TransformFinalBlock(new byte[0],0,0);result.Sha256=BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
                    status=result.UnreadBytes>0?"complete_with_read_errors":"complete";save();return result;
                } catch(OperationCanceledException){status="cancelled";save();throw;} catch{status="incomplete";save();throw;}
            }
        }
        static bool Read(Stream source,long position,byte[] buffer,int at,int count,int sector,CancellationToken cancel)
        {
            try {
                source.Position=position;int done=0;
                while(done<count){cancel.ThrowIfCancellationRequested();int n=source.Read(buffer,at+done,count-done);if(n==0)throw new EndOfStreamException("Источник перестал отдавать данные.");if(n%sector!=0)throw new EndOfStreamException("Неполный сектор.");done+=n;}
                return true;
            } catch(EndOfStreamException){throw;} catch(IOException){return false;}
        }
    }
}
