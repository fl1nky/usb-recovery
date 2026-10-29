using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    // Independent byte-offset pass for contiguous containers. Structure is not
    // proof of intact payload; no source archive/script is executed or unpacked.
    public static class ContainerCarver
    {
        const long Maximum = 512L * 1024 * 1024;
        static byte[] Read(FileStream s, long at, int count) { if (at < 0 || count < 0 || at > s.Length-count) return null; byte[] b=new byte[count]; s.Position=at; int done=0,n; while(done<count && (n=s.Read(b,done,count-done))>0) done+=n; return done==count?b:null; }
        static uint BE(byte[] b,int p) { return ((uint)b[p]<<24)|((uint)b[p+1]<<16)|((uint)b[p+2]<<8)|b[p+3]; }
        static bool Is(byte[] b,int p,string value) { if(b==null || p<0 || p>b.Length-value.Length)return false; for(int j=0;j<value.Length;j++)if(b[p+j]!=(byte)value[j])return false;return true; }
        static long ZipEnd(FileStream stream,long start,CancellationToken cancel,out string extension)
        {
            extension=".zip"; long limit=Math.Min(stream.Length,start+Maximum); byte[] block=new byte[1024*1024+21]; long position=start; int carry=0;
            while(position<limit) {
                cancel.ThrowIfCancellationRequested(); stream.Position=position;int n=stream.Read(block,carry,(int)Math.Min(block.Length-carry,limit-position));if(n==0)break;int size=carry+n;long baseOffset=position-carry;
                for(int i=0;i+22<=size;i++)if(Is(block,i,"PK\x05\x06")) {
                    long end=baseOffset+i+22+BitConverter.ToUInt16(block,i+20);int entries=BitConverter.ToUInt16(block,i+10);uint centralSize=BitConverter.ToUInt32(block,i+12),centralOffset=BitConverter.ToUInt32(block,i+16);
                    if(entries==0 || entries>10000 || BitConverter.ToUInt16(block,i+4)!=0 || BitConverter.ToUInt16(block,i+6)!=0 || entries!=BitConverter.ToUInt16(block,i+8) || end>limit || start+centralOffset+centralSize!=baseOffset+i)continue;
                    long at=start+centralOffset;bool valid=true;string detected=".zip";
                    for(int entry=0;entry<entries;entry++) {
                        cancel.ThrowIfCancellationRequested();byte[] h=Read(stream,at,46);if(!Is(h,0,"PK\x01\x02")){valid=false;break;}
                        int name=BitConverter.ToUInt16(h,28),extra=BitConverter.ToUInt16(h,30),comment=BitConverter.ToUInt16(h,32);uint local=BitConverter.ToUInt32(h,42);byte[] localHeader=Read(stream,start+local,30);
                        if(local>=centralOffset || !Is(localHeader,0,"PK\x03\x04") || start+local+30L+BitConverter.ToUInt16(localHeader,26)+BitConverter.ToUInt16(localHeader,28)+BitConverter.ToUInt32(h,20)>start+centralOffset || at+46L+name+extra+comment>start+centralOffset+centralSize){valid=false;break;}
                        byte[] path=Read(stream,at+46,name);string text=Encoding.UTF8.GetString(path??new byte[0]);
                        if(text=="word/document.xml")detected=".docx";else if(text=="xl/workbook.xml")detected=".xlsx";else if(text=="ppt/presentation.xml")detected=".pptx";
                        at+=46L+name+extra+comment;
                    }
                    if(valid && at==start+centralOffset+centralSize){extension=detected;return end;}
                }
                position+=n;carry=Math.Min(21,size);Buffer.BlockCopy(block,size-carry,block,0,carry);
            }
            return -1;
        }
        static long PdfEnd(FileStream stream,long start,CancellationToken cancel)
        {
            byte[] header=Read(stream,start,8);if(!Is(header,0,"%PDF-") || header[5]<'1' || header[5]>'2' || header[6]!='.')return -1;
            byte[] block=new byte[1024*1024+5];int carry=0;long at=start,limit=Math.Min(stream.Length,start+128L*1024*1024);bool objectFound=false;
            while(at<limit) {
                cancel.ThrowIfCancellationRequested();stream.Position=at;int n=stream.Read(block,carry,(int)Math.Min(block.Length-carry,limit-at));if(n==0)break;int size=n+carry;long baseOffset=at-carry;
                for(int i=0;i+5<=size;i++){if(Is(block,i," obj"))objectFound=true;if(objectFound && Is(block,i,"%%EOF"))return baseOffset+i+5;}
                at+=n;carry=Math.Min(5,size);Buffer.BlockCopy(block,size-carry,block,0,carry);
            }
            return -1;
        }
        static long RiffEnd(FileStream stream,long start,out string extension)
        {
            extension=null;byte[] h=Read(stream,start,12);if(!Is(h,0,"RIFF"))return -1;long length=BitConverter.ToUInt32(h,4)+8L;
            if(length<20 || length>Maximum || start>stream.Length-length)return -1;
            if(Is(h,8,"WEBP"))extension=".webp";else if(Is(h,8,"AVI "))extension=".avi";else if(Is(h,8,"WAVE"))extension=".wav";else return -1;
            long at=start+12;bool payload=false;int chunks=0;
            while(at<start+length && ++chunks<100000) {
                byte[] chunk=Read(stream,at,8);if(chunk==null)return -1;long size=BitConverter.ToUInt32(chunk,4);long end=at+8+size+(size&1);
                if(end>start+length)return -1;
                if(extension==".webp" && (Is(chunk,0,"VP8 ")||Is(chunk,0,"VP8L")||Is(chunk,0,"ANMF")))payload=true;
                if(extension==".avi" && Is(chunk,0,"LIST"))payload=true;if(extension==".wav" && Is(chunk,0,"data"))payload=true;
                at=end;
            }
            return payload && at==start+length ? at : -1;
        }
        static long BmffEnd(FileStream stream,long start,CancellationToken cancel,out string extension)
        {
            extension=".mp4";byte[] first=Read(stream,start,16);if(!Is(first,4,"ftyp"))return -1;
            string brand=Encoding.ASCII.GetString(first,8,4);bool photo=new[]{"heic","heix","hevc","hevx","mif1","msf1","avif","avis"}.Contains(brand);
            if(photo)extension=brand.StartsWith("avi",StringComparison.Ordinal)?".avif":".heic";else if(brand=="qt  ")extension=".mov";else if(brand.StartsWith("M4A",StringComparison.Ordinal))extension=".m4a";
            long at=start,limit=Math.Min(stream.Length,start+Maximum);bool media=false,metadata=false;int boxes=0;
            while(at+8<=limit && ++boxes<=100000) {
                cancel.ThrowIfCancellationRequested();byte[] box=Read(stream,at,8);if(box==null)break;long size=BE(box,0);int header=8;
                if(size==1){box=Read(stream,at,16);if(box==null)break;ulong wide=((ulong)BE(box,8)<<32)|BE(box,12);if(wide>Int64.MaxValue)break;size=(long)wide;header=16;}
                if(size==0 || size<header || size>limit-at)break;
                string kind=Encoding.ASCII.GetString(box,4,4);if(!new[]{"ftyp","moov","mdat","free","skip","wide","meta","uuid","pdin","moof","mfra","sidx","styp","emsg","prft"}.Contains(kind))break;
                if(kind=="mdat")media=true;if(kind==(photo?"meta":"moov"))metadata=true;at+=size;
            }
            return media && metadata ? at : -1;
        }
        public static int Recover(string image,string directory,RecoveryOptions options,CancellationToken cancel,Action<long,long> progress)
        {
            if(!File.Exists(image)||image.StartsWith(@"\\",StringComparison.Ordinal)||Path.GetFullPath(image).IndexOf(':',2)>=0)throw new IOException("Контейнеры ищутся только в обычном локальном файле образа.");
            string root=Path.Combine(directory,"containers");Directory.CreateDirectory(root);var records=new List<object>();int candidates=0,probes=0;long position=0,skipUntil=0;int carry=0;
            using(var scan=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read,4*1024*1024))
            using(var parse=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                byte[] block=new byte[4*1024*1024+16];int read;
                while((read=scan.Read(block,carry,block.Length-carry))>0){
                    cancel.ThrowIfCancellationRequested();int length=carry+read,limit=scan.Position==scan.Length?length:Math.Max(0,length-15);long baseOffset=position-carry;
                    for(int i=0;i<limit;i++){
                        if((i&65535)==0)cancel.ThrowIfCancellationRequested();
                        if(baseOffset+i<skipUntil)continue;
                        bool zip=(options.Archives||options.Documents||options.Other)&&Is(block,i,"PK\x03\x04"),pdf=(options.Documents||options.Other)&&Is(block,i,"%PDF-"),riff=Is(block,i,"RIFF"),bmff=Is(block,i+4,"ftyp");if(!zip&&!pdf&&!riff&&!bmff)continue;
                        if(++probes>10000)throw new IOException("Достигнут предел 10 000 контейнеров-кандидатов. Найденное сохранено.");
                        string ext=null;long start=baseOffset+i,end=-1;
                        if(zip)end=ZipEnd(parse,start,cancel,out ext);else if(pdf){ext=".pdf";end=PdfEnd(parse,start,cancel);}else if(riff)end=RiffEnd(parse,start,out ext);else if(bmff)end=BmffEnd(parse,start,cancel,out ext);
                        if(end<=start)continue;
                        bool include=options.Other || (new[]{".webp",".heic",".avif"}.Contains(ext)?options.Photos:new[]{".mp4",".mov",".avi"}.Contains(ext)?options.Video:new[]{".wav",".m4a"}.Contains(ext)?options.Audio:ext==".zip"?options.Archives:options.Documents);
                        if(!include)continue;
                        string name="offset-"+start.ToString("D16")+ext,target=Path.Combine(root,name);if(File.Exists(target))continue;
                        string partial=target+".partial";parse.Position=start;
                        using(var output=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){byte[] data=new byte[1024*1024];long left=end-start;while(left>0){cancel.ThrowIfCancellationRequested();int n=parse.Read(data,0,(int)Math.Min(left,data.Length));if(n==0)throw new IOException("Неполный контейнер.");output.Write(data,0,n);left-=n;}}
                        File.Move(partial,target);skipUntil=end;candidates++;records.Add(new{path="containers/"+name,offset=start,bytes=end-start,method="byte-offset-container",status="structure_only",note="Payload integrity, deletion state and original name unknown; ZIP64 and fragmented containers not reconstructed."});
                    }
                    position+=read;carry=length-limit;Buffer.BlockCopy(block,limit,block,0,carry);if(progress!=null)progress(scan.Position,scan.Length);
                    RecoveryCore.SaveJson(Path.Combine(directory,"container-search.json"),new{status="running",files=records});
                }
            }
            RecoveryCore.SaveJson(Path.Combine(directory,"container-search.json"),new{status="complete",files=records});return candidates;
        }
    }
}
