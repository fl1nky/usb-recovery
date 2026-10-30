using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    public sealed class ContentVerification
    {
        public string Code="unverified",Label="Не проверено",Detail="Для этого формата полная проверка содержимого не выполнялась.";
    }
    // Bounded content checks. CRC verification authenticates neither origin
    // nor original completeness: a valid ZIP can contain an incomplete document.
    public static class ContentVerifier
    {
        const long MaximumFile=512L*1024*1024,MaximumExpanded=256L*1024*1024;
        static readonly uint[] Crc=Table();
        static uint[] Table(){var t=new uint[256];for(uint n=0;n<256;n++){uint x=n;for(int b=0;b<8;b++)x=(x&1)==0?x>>1:(x>>1)^0xedb88320;t[n]=x;}return t;}
        static byte[] Read(Stream stream,long offset,int length){if(offset<0||length<0||offset>stream.Length-length)return null;stream.Position=offset;var bytes=new byte[length];int at=0,n;while(at<length&&(n=stream.Read(bytes,at,length-at))>0)at+=n;return at==length?bytes:null;}
        static bool Is(byte[] b,int at,string value){if(b==null||at<0||at>b.Length-value.Length)return false;for(int i=0;i<value.Length;i++)if(b[at+i]!=(byte)value[i])return false;return true;}
        static ContentVerification State(string code,string label,string detail){return new ContentVerification{Code=code,Label=label,Detail=detail};}
        public static ContentVerification Verify(string path,CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();var file=new FileInfo(path);
            if(file.Length>MaximumFile)return State("unverified","Проверка отложена","Размер превышает 512 МиБ — предел дополнительной проверки. Файл сохранён без утверждения целостности.");
            using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                byte[] head=Read(input,0,(int)Math.Min(16,input.Length));
                if(Is(head,0,"PK\x03\x04")||Is(head,0,"PK\x05\x06"))return Zip(input,cancel);
                string ext=Path.GetExtension(path).ToLowerInvariant();
                if(new[]{".zip",".docx",".xlsx",".pptx",".odt",".ods",".epub"}.Contains(ext))return State("unverified","Начало ZIP не подтверждено","Расширение предполагает ZIP, но файл может иметь дополнительный префикс, другую структуру или повреждение. По одному расширению целостность не определяется.");
                if(Is(head,0,"%PDF-")){
                    var tail=Read(input,Math.Max(0,input.Length-4096),(int)Math.Min(4096,input.Length));bool end=Encoding.ASCII.GetString(tail??new byte[0]).Contains("%%EOF");
                    return end?State("structure","Есть начало и окончание PDF","Найдены заголовок и %%EOF. Объекты, страницы и сжатые потоки PDF полностью не проверены."):State("partial","Возможно, часть PDF","Есть заголовок PDF, но в конце файла не найден %%EOF. Открытие документа не гарантируется.");
                }
                if(Is(head,0,"RIFF"))return Riff(input,head,cancel);
            }
            return new ContentVerification();
        }
        sealed class Segment:Stream
        {
            readonly Stream source;readonly long begin,length;long at;
            public Segment(Stream s,long start,long count){source=s;begin=start;length=count;}
            public override bool CanRead{get{return true;}}public override bool CanSeek{get{return false;}}public override bool CanWrite{get{return false;}}public override long Length{get{return length;}}public override long Position{get{return at;}set{throw new NotSupportedException();}}
            public override int Read(byte[] b,int p,int n){if(at>=length)return 0;source.Position=begin+at;int read=source.Read(b,p,(int)Math.Min(n,length-at));at+=read;return read;}
            public override void Flush(){}public override long Seek(long p,SeekOrigin o){throw new NotSupportedException();}public override void SetLength(long n){throw new NotSupportedException();}public override void Write(byte[] b,int p,int n){throw new NotSupportedException();}
        }
        static ContentVerification Zip(FileStream input,CancellationToken cancel)
        {
            int count=(int)Math.Min(65557,input.Length);byte[] tail=Read(input,input.Length-count,count);int end=-1;
            for(int i=count-22;i>=0;i--)if(Is(tail,i,"PK\x05\x06")&&i+22+BitConverter.ToUInt16(tail,i+20)==count){end=i;break;}
            if(end<0)return State("partial","Нет каталога ZIP","Локальные записи есть, но завершающий каталог ZIP не подтверждён. Режим извлечения частей может сохранить отдельные исправные файлы.");
            int entries=BitConverter.ToUInt16(tail,end+10);long central=BitConverter.ToUInt32(tail,end+16),centralBytes=BitConverter.ToUInt32(tail,end+12),endOffset=input.Length-count+end;
            if(entries==65535||central==UInt32.MaxValue||centralBytes==UInt32.MaxValue)return State("unverified","ZIP64 не проверен","ZIP64 сохранён. Эта дополнительная проверка CRC ограничена ZIP32.");
            if(entries>10000)return State("unverified","Слишком много записей ZIP","Каталог превышает предел 10 000 записей проверки. Результат не объявляется повреждённым только из-за лимита.");
            if(BitConverter.ToUInt16(tail,end+4)!=0||BitConverter.ToUInt16(tail,end+6)!=0)return State("unverified","Многотомный ZIP","Для проверки многотомного ZIP нужны все части; эта проверка их не собирает.");
            if(BitConverter.ToUInt16(tail,end+8)!=entries||central<0||centralBytes<0||central>input.Length-centralBytes||central+centralBytes!=endOffset)return State("damaged","Каталог ZIP повреждён","Границы центрального каталога не согласованы с размером файла.");
            var dataRanges=new List<Tuple<long,long>>();long at=central,expanded=0;int validated=0;
            try {
                for(int entry=0;entry<entries;entry++){
                    cancel.ThrowIfCancellationRequested();byte[] h=Read(input,at,46);if(!Is(h,0,"PK\x01\x02"))return State("damaged","Запись ZIP повреждена","Ожидаемая запись центрального каталога не найдена.");
                    int flags=BitConverter.ToUInt16(h,8),method=BitConverter.ToUInt16(h,10),name=BitConverter.ToUInt16(h,28),extra=BitConverter.ToUInt16(h,30),comment=BitConverter.ToUInt16(h,32);uint expectedCrc=BitConverter.ToUInt32(h,16);long packed=BitConverter.ToUInt32(h,20),unpacked=BitConverter.ToUInt32(h,24),local=BitConverter.ToUInt32(h,42);
                    if(packed==UInt32.MaxValue||unpacked==UInt32.MaxValue||local==UInt32.MaxValue)return State("unverified","ZIP64 не проверен","В записи обнаружены поля ZIP64.");
                    if(BitConverter.ToUInt16(h,34)!=0)return State("unverified","Многотомный ZIP","Запись ссылается на другую часть архива.");
                    if((flags&1)!=0||(flags&64)!=0)return State("encrypted","Зашифрованный архив","Проверка содержимого требует пароля. Файл сохранён; успешная расшифровка не заявляется.");
                    if(method!=0&&method!=8)return State("unverified","Другой метод сжатия","Проверка поддерживает stored и deflate. Неподдерживаемый метод не считается повреждением.");
                    if(at+46L+name+extra+comment>central+centralBytes)return State("damaged","Запись ZIP обрезана","Имя или дополнительные поля выходят за границы каталога.");
                    byte[] lh=Read(input,local,30),centralName=Read(input,at+46,name);if(!Is(lh,0,"PK\x03\x04"))return State("damaged","Нет локальной записи ZIP","Каталог ссылается на неподтверждённый локальный заголовок.");
                    int localName=BitConverter.ToUInt16(lh,26),localExtra=BitConverter.ToUInt16(lh,28);long start=local+30L+localName+localExtra;
                    if(BitConverter.ToUInt32(lh,18)==UInt32.MaxValue||BitConverter.ToUInt32(lh,22)==UInt32.MaxValue)return State("unverified","ZIP64 не проверен","Локальная запись использует ZIP64, даже если центральный каталог содержит обычные размеры.");
                    byte[] localNameBytes=Read(input,local+30,localName);
                    if(BitConverter.ToUInt16(lh,6)!=flags||BitConverter.ToUInt16(lh,8)!=method||localNameBytes==null||!localNameBytes.SequenceEqual(centralName??new byte[0])||start>central-packed)return State("damaged","ZIP-записи расходятся","Локальный и центральный заголовки не согласованы либо содержимое выходит за каталог.");
                    if((flags&8)==0&&(BitConverter.ToUInt32(lh,14)!=expectedCrc||BitConverter.ToUInt32(lh,18)!=packed||BitConverter.ToUInt32(lh,22)!=unpacked))return State("damaged","Размеры ZIP расходятся","Размеры/CRC локального и центрального заголовков не совпадают.");
                    if(dataRanges.Any(x=>start<x.Item1+x.Item2&&x.Item1<start+packed))return State("damaged","Перекрывающиеся записи ZIP","Разные записи используют пересекающиеся области содержимого.");
                    dataRanges.Add(Tuple.Create(start,packed));
                    if(unpacked>64L*1024*1024||expanded>MaximumExpanded-unpacked||packed==0&&unpacked!=0||packed>0&&unpacked/Math.Max(1,packed)>1000)return State("unverified","Лимит распаковки","Превышен безопасный бюджет проверки: 64 МиБ на запись, 256 МиБ всего, степень сжатия до 1000. Содержимое не распаковывается на диск.");
                    uint crc=0xffffffff;long bytes=0;byte[] block=new byte[65536];
                    using(var segment=new Segment(input,start,packed))
                    using(Stream decoded=method==0?(Stream)segment:new DeflateStream(segment,CompressionMode.Decompress,true)){
                        int n;while((n=decoded.Read(block,0,block.Length))>0){cancel.ThrowIfCancellationRequested();bytes+=n;if(bytes>unpacked||bytes>64L*1024*1024)return State("damaged","Размер содержимого ZIP неверен","Декодированный поток длиннее заявленного размера.");for(int i=0;i<n;i++)crc=Crc[(crc^block[i])&255]^(crc>>8);}
                    }
                    if(bytes!=unpacked||~crc!=expectedCrc)return State("damaged","Ошибка CRC ZIP","Хотя бы одна запись не прошла проверку размера/CRC. Не следует считать архив исправным.");
                    expanded+=bytes;validated++;at+=46L+name+extra+comment;
                }
            }catch(InvalidDataException){return State("damaged","Поток ZIP повреждён","Deflate не декодируется. Отдельные другие записи могут сохраняться режимом извлечения частей.");}
            if(at!=central+centralBytes){byte[] signature=Read(input,at,6);if(Is(signature,0,"PK\x05\x05")&&at+6+BitConverter.ToUInt16(signature,4)==central+centralBytes)return State("unverified","Подпись ZIP не проверена","CRC записей проверены, но подлинность цифровой подписи каталога не проверяется.");return State("unverified","Дополнительные данные каталога ZIP","CRC записей проверены, дополнительные структуры каталога не распознаны.");}
            return State("container_crc","CRC контейнера проверены","Проверены размеры и CRC всех "+validated+" записей ZIP по центральному каталогу. Дополнительные структуры ZIP, семантика документа, исходная полнота и происхождение этим не подтверждаются.");
        }
        static ContentVerification Riff(FileStream input,byte[] head,CancellationToken cancel)
        {
            if(head.Length<12)return State("partial","Обрезанный RIFF","Не хватает заголовка контейнера.");
            long length=BitConverter.ToUInt32(head,4)+8L;if(length!=input.Length)return State("partial","Размер RIFF расходится","Размер контейнера отличается от сохранённого файла; возможны пропуски или лишние байты.");
            long at=12;int chunks=0;while(at<input.Length&&++chunks<=100000){cancel.ThrowIfCancellationRequested();byte[] chunk=Read(input,at,8);if(chunk==null)return State("partial","Обрезан блок RIFF","Заголовок последнего блока обрезан.");long n=BitConverter.ToUInt32(chunk,4);if(n>input.Length-at-8)return State("partial","Обрезано содержимое RIFF","Размер блока выходит за файл.");at+=8+n+(n&1);}
            return at==input.Length?State("structure","Структура RIFF проверена","Размеры контейнера и блоков согласованы. Полное декодирование изображения/аудио/видео здесь не выполнялось."):State("unverified","Лимит блоков RIFF","Контейнер сохранён, проверка остановлена по лимиту.");
        }
    }
}
