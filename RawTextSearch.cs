using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace UsbRecovery
{
    // String carving from an image, not document reconstruction. All offsets
    // are file byte offsets. Strictly validated byte runs keep offsets exact.
    public static class RawTextSearch
    {
        const int Chunk=1024*1024,Overlap=65536,MaximumResults=5000;
        static readonly Encoding Binary=Encoding.GetEncoding(28591),Utf8=new UTF8Encoding(false,true),Le=new UnicodeEncoding(false,false,true),Be=new UnicodeEncoding(true,false,true);
        static Regex Bytes(string pattern){return new Regex(pattern,RegexOptions.CultureInvariant,TimeSpan.FromSeconds(2));}
        static readonly Regex Utf8Runs=Bytes(@"(?:[\x09\x0a\x0d\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee-\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2}){8,8192}");
        static readonly Regex LeRuns=Bytes(@"(?:[\x09\x0a\x0d\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x01-\x05]){8,8192}");
        static readonly Regex BeRuns=Bytes(@"(?:\x00[\x09\x0a\x0d\x20-\x7e\xa0-\xff]|[\x01-\x05][\x00-\xff]){8,8192}");
        public static int Recover(string image,string directory,string query,CancellationToken cancel,Action<long,long> progress)
        {
            if(!File.Exists(image)||image.StartsWith(@"\\",StringComparison.Ordinal)||Path.GetFullPath(image).IndexOf(':',2)>=0)throw new IOException("Текст ищется только в обычном локальном образе.");
            var terms=(query??"").Split((char[])null,StringSplitOptions.RemoveEmptyEntries);
            if(terms.Length==0||terms.Length>8||query.Length>256)throw new IOException("Укажи до 8 ключевых слов для текстового поиска.");
            cancel.ThrowIfCancellationRequested();string output=Path.Combine(directory,"text-fragments");Directory.CreateDirectory(output);var records=new List<object>();long position=0;int carry=0;string status="incomplete";var lastEnd=new long[]{-1,-1,-1};
            var patterns=new[]{Utf8Runs,LeRuns,BeRuns};var encodings=new[]{Utf8,Le,Be};var names=new[]{"utf-8","utf-16-le","utf-16-be"};
            try {
                using(var source=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read,Chunk)) {
                    byte[] block=new byte[Chunk+2*Overlap];
                    while(true){
                        cancel.ThrowIfCancellationRequested();int read=source.Read(block,carry,Chunk),length=read+carry;bool final=read==0;int safe=final?length:Math.Max(0,length-Overlap);long start=position-carry;string binary=Binary.GetString(block,0,length);
                        for(int kind=0;kind<3;kind++)foreach(Match match in patterns[kind].Matches(binary)){
                            cancel.ThrowIfCancellationRequested();long at=start+match.Index,end=at+match.Length;
                            if(match.Index>=safe||at<lastEnd[kind]||(!final&&match.Index+match.Length>safe))continue;lastEnd[kind]=end;
                            string text;try{text=encodings[kind].GetString(block,match.Index,match.Length);}catch(DecoderFallbackException){continue;}
                            int letters=text.Count(Char.IsLetter);if(letters<5||letters*100<text.Length*40||text.Any(c=>Char.IsControl(c)&&c!='\r'&&c!='\n'&&c!='\t'))continue;
                            if(!terms.All(term=>text.IndexOf(term,StringComparison.OrdinalIgnoreCase)>=0))continue;
                            string relative="text-fragments/offset-"+at.ToString("D16")+"-"+names[kind]+".txt",target=Path.Combine(directory,relative.Replace('/',Path.DirectorySeparatorChar));
                            File.WriteAllText(target,text,new UTF8Encoding(true));records.Add(new{path=relative,offset=at,sourceBytes=match.Length,encoding=names[kind],status="text_fragment",deletedState="unknown",note="Text only. Original document boundaries, author and date unknown. Stored TXT is UTF-8; source encoding is recorded separately."});
                            if(records.Count>=MaximumResults){status="limited";throw new IOException("Текстовый поиск достиг 5000 фрагментов. Найденное сохранено; сузь ключевые слова.");}
                        }
                        if(final)break;position+=read;carry=Math.Min(length,2*Overlap);Buffer.BlockCopy(block,length-carry,block,0,carry);if(progress!=null)progress(position,source.Length);
                    }
                }
                status="complete";return records.Count;
            }catch(RegexMatchTimeoutException){status="limited";throw new IOException("Сложный участок данных: текстовый проход остановлен по времени. Уже найденное сохранено.");}catch(OperationCanceledException){status="cancelled";throw;}finally{RecoveryCore.SaveJson(Path.Combine(directory,"text-search.json"),new{status=status,image=Path.GetFullPath(image),query=query,files=records,maximumFragments=MaximumResults,note="No full-file or deletion-state claim. Image digest is retained in usb.dd.sha256 or source-image.sha256."});}
        }
    }
}
