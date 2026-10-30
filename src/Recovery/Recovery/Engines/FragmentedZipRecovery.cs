using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // ZIP APPNOTE 6.3.10, sections 4.3.7 / 4.3.12 / 4.3.16:
    // https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
    // Only fragmentation BETWEEN complete local-member records is supported.
    // Compressed bodies and central-directory+EOCD must each be contiguous.
    public static class FragmentedZipRecovery
    {
        public const int MaximumHeaders=30000,MaximumLocals=20000,MaximumDirectories=5000,MaximumEntries=1024,MaximumArchives=100;
        public const long MaximumMemberBytes=64L*1024*1024,MaximumArchiveBytes=128L*1024*1024,MaximumWorkBytes=512L*1024*1024,MaximumOutputBytes=512L*1024*1024;
        const int BlockBytes=4*1024*1024,MaximumDirectoryBytes=2*1024*1024;
        static readonly Encoding StrictUtf8=new UTF8Encoding(false,true),Legacy=Encoding.GetEncoding(437);
        static readonly uint[] Crc=MakeCrc();

        public sealed class Extent { public long ImageOffset,LogicalOffset,Length; }
        public sealed class Member
        {
            public string Name,Crc32,RecordSha256;
            public long LogicalOffset,ImageOffset,CompressedBytes,Bytes;
            public List<long> EquivalentRecordOffsets=new List<long>();
        }
        public sealed class Result
        {
            public string Path,Sha256,Status="zip_crc_reassembled";
            public long Bytes,CentralOffset,EocdOffset;
            public int Members;
            public List<Extent> Extents=new List<Extent>();
            public List<Member> MemberSources=new List<Member>();
            public string Note="ZIP32 reconstructed from CRC-verified complete member records and a surviving central directory. Original archive name, deletion state and physical continuity unknown; CRC does not authenticate origin.";
        }
        public sealed class Report
        {
            public string Status="incomplete";
            public int Schema=1,Headers,LocalRecords,Directories,Recovered;
            public long InputBytes,ExpandedWorkBytes,OutputBytes;
            public Dictionary<string,int> Skipped=new Dictionary<string,int>(StringComparer.Ordinal);
            public List<Result> Files=new List<Result>();
            public string Scope="Only between-member fragmentation. ZIP32 stored/deflate, known local sizes, no encryption, ZIP64, descriptors, SFX/padding or signed central directories. All members must pass CRC and length checks; ambiguous distinct raw records are not joined.";
        }
        sealed class Reject:Exception { public readonly string Code;public Reject(string code){Code=code;} }
        sealed class Local
        {
            public long Offset,DataOffset,Packed,Unpacked,RecordBytes;
            public ushort Flags,Method,Version,Time,Date;
            public uint ExpectedCrc;
            public byte[] RawName;
            public string Name,Key,RawSha;
            public bool Checked,Valid;
        }
        sealed class Entry
        {
            public long LogicalOffset,Packed,Unpacked;
            public ushort Flags,Method,Version,Time,Date;
            public uint ExpectedCrc;
            public byte[] RawName;
            public string Name,Key;
        }
        sealed class DirectoryRecord
        {
            public long Offset,EocdOffset,LogicalOffset,Bytes,EocdBytes;
            public List<Entry> Entries=new List<Entry>();
        }
        sealed class Slice:Stream
        {
            readonly FileStream input;readonly long start,length;long position;
            public Slice(FileStream file,long offset,long count){input=file;start=offset;length=count;}
            public override bool CanRead{get{return true;}}public override bool CanSeek{get{return false;}}public override bool CanWrite{get{return false;}}
            public override long Length{get{return length;}}public override long Position{get{return position;}set{throw new NotSupportedException();}}
            public override int Read(byte[] b,int at,int count){if(position>=length)return 0;input.Position=start+position;int n=input.Read(b,at,(int)Math.Min(count,length-position));if(n==0)throw new Reject("member_truncated");position+=n;return n;}
            public override void Flush(){}public override long Seek(long n,SeekOrigin o){throw new NotSupportedException();}public override void SetLength(long n){throw new NotSupportedException();}public override void Write(byte[] b,int at,int n){throw new NotSupportedException();}
        }

        static void NoLinks(string path)
        {
            string full=Path.GetFullPath(path);if(File.Exists(full)&&(File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new IOException("Файл-ссылка не подходит для поиска ZIP.");
            for(var item=new DirectoryInfo(Directory.Exists(full)?full:Path.GetDirectoryName(full));item!=null;item=item.Parent)if(item.Exists&&(item.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Путь поиска ZIP содержит перенаправление.");
        }
        static string FullPath(string path)
        {
            try{return Path.GetFullPath(path);}catch(ArgumentException){throw new IOException("Для сборки ZIP нужен обычный локальный путь.");}catch(NotSupportedException){throw new IOException("Для сборки ZIP нужен обычный локальный путь.");}
        }
        static byte[] Read(FileStream input,long offset,int length)
        {
            if(offset<0||length<0||offset>input.Length-length)throw new Reject("structure_bounds");input.Position=offset;byte[] bytes=new byte[length];int done=0,n;while(done<length&&(n=input.Read(bytes,done,length-done))>0)done+=n;if(done!=length)throw new Reject("structure_truncated");return bytes;
        }
        static ushort U16(byte[] b,int at){return BitConverter.ToUInt16(b,at);}static uint U32(byte[] b,int at){return BitConverter.ToUInt32(b,at);}
        static bool Signature(byte[] b,uint value){return b.Length>=4&&U32(b,0)==value;}
        static void Flags(ushort flags,ushort method,ushort version)
        {
            if((flags&9)!=0||(flags&~0x806)!=0)throw new Reject("flags_or_descriptor_unsupported");
            if(method!=0&&method!=8)throw new Reject("compression_unsupported");if(version>20)throw new Reject("version_unsupported");if(method==0&&(flags&6)!=0)throw new Reject("stored_flags_unsupported");
        }
        static void Extra(byte[] bytes)
        {
            for(int at=0;at<bytes.Length;){if(bytes.Length-at<4)throw new Reject("extra_truncated");int type=U16(bytes,at),n=U16(bytes,at+2);if(n>bytes.Length-at-4)throw new Reject("extra_truncated");if(type==1)throw new Reject("zip64_unsupported");at+=4+n;}
        }
        static string Name(byte[] bytes,ushort flags)
        {
            if(bytes.Length==0||bytes.Length>1024)throw new Reject("name_limit");string name;
            try{name=((flags&0x800)!=0?StrictUtf8:Legacy).GetString(bytes);}catch(DecoderFallbackException){throw new Reject("name_encoding");}
            if(name.Any(Char.IsControl)||name.IndexOf('\0')>=0)throw new Reject("name_invalid");return name;
        }
        static string Key(ushort version,ushort flags,ushort method,ushort time,ushort date,uint crc,long packed,long unpacked,byte[] name)
        {return version+":"+flags+":"+method+":"+time+":"+date+":"+crc+":"+packed+":"+unpacked+":"+Convert.ToBase64String(name);}
        static Local LocalAt(FileStream input,long offset)
        {
            byte[] h=Read(input,offset,30);if(!Signature(h,0x04034b50))throw new Reject("local_signature");
            var item=new Local{Offset=offset,Version=U16(h,4),Flags=U16(h,6),Method=U16(h,8),Time=U16(h,10),Date=U16(h,12),ExpectedCrc=U32(h,14),Packed=U32(h,18),Unpacked=U32(h,22)};
            Flags(item.Flags,item.Method,item.Version);if(item.Packed==UInt32.MaxValue||item.Unpacked==UInt32.MaxValue)throw new Reject("zip64_unsupported");if(item.Packed>MaximumMemberBytes||item.Unpacked>MaximumMemberBytes)throw new Reject("member_limit");
            int names=U16(h,26),extras=U16(h,28);if(extras>32768)throw new Reject("extra_limit");item.RawName=Read(input,offset+30,names);item.Name=Name(item.RawName,item.Flags);Extra(Read(input,offset+30+names,extras));
            item.DataOffset=offset+30+names+extras;item.RecordBytes=30L+names+extras+item.Packed;if(item.DataOffset>input.Length-item.Packed)throw new Reject("member_truncated");
            if(item.Method==0&&item.Packed!=item.Unpacked||item.Packed==0&&item.Unpacked!=0||item.Packed>0&&item.Unpacked/Math.Max(1,item.Packed)>1000)throw new Reject("member_sizes");
            item.Key=Key(item.Version,item.Flags,item.Method,item.Time,item.Date,item.ExpectedCrc,item.Packed,item.Unpacked,item.RawName);return item;
        }
        static DirectoryRecord DirectoryAt(FileStream input,long eocd)
        {
            byte[] h=Read(input,eocd,22);if(!Signature(h,0x06054b50))throw new Reject("eocd_signature");int count=U16(h,10),comment=U16(h,20);long size=U32(h,12),logical=U32(h,16);
            if(U16(h,4)!=0||U16(h,6)!=0||U16(h,8)!=count)throw new Reject("multivolume_unsupported");if(count==65535||size==UInt32.MaxValue||logical==UInt32.MaxValue)throw new Reject("zip64_unsupported");
            if(count<1||count>MaximumEntries||size<46||size>MaximumDirectoryBytes)throw new Reject("directory_limit");if(eocd<size||eocd>input.Length-22-comment||logical>MaximumArchiveBytes-size-22-comment)throw new Reject("directory_bounds");
            var record=new DirectoryRecord{Offset=eocd-size,EocdOffset=eocd,LogicalOffset=logical,Bytes=size,EocdBytes=22+comment};long at=record.Offset;
            for(int n=0;n<count;n++){
                byte[] c=Read(input,at,46);if(!Signature(c,0x02014b50))throw new Reject("central_signature");int names=U16(c,28),extras=U16(c,30),comments=U16(c,32);if(at+46L+names+extras+comments>eocd||extras>32768)throw new Reject("central_bounds");
                var entry=new Entry{Version=U16(c,6),Flags=U16(c,8),Method=U16(c,10),Time=U16(c,12),Date=U16(c,14),ExpectedCrc=U32(c,16),Packed=U32(c,20),Unpacked=U32(c,24),LogicalOffset=U32(c,42)};
                Flags(entry.Flags,entry.Method,entry.Version);if(U16(c,34)!=0)throw new Reject("multivolume_unsupported");if(entry.Packed==UInt32.MaxValue||entry.Unpacked==UInt32.MaxValue||entry.LogicalOffset==UInt32.MaxValue)throw new Reject("zip64_unsupported");if(entry.Packed>MaximumMemberBytes||entry.Unpacked>MaximumMemberBytes)throw new Reject("member_limit");
                entry.RawName=Read(input,at+46,names);entry.Name=Name(entry.RawName,entry.Flags);Extra(Read(input,at+46+names,extras));entry.Key=Key(entry.Version,entry.Flags,entry.Method,entry.Time,entry.Date,entry.ExpectedCrc,entry.Packed,entry.Unpacked,entry.RawName);record.Entries.Add(entry);at+=46L+names+extras+comments;
            }
            if(at!=eocd)throw new Reject("central_extra_or_signature_unsupported");if(record.Entries.All(e=>e.Unpacked==0))throw new Reject("empty_archive");return record;
        }
        static string HashRange(FileStream input,long offset,long length,CancellationToken cancel)
        {
            using(var sha=SHA256.Create()){byte[] block=new byte[65536];input.Position=offset;while(length>0){cancel.ThrowIfCancellationRequested();int n=input.Read(block,0,(int)Math.Min(length,block.Length));if(n==0)throw new Reject("range_truncated");sha.TransformBlock(block,0,n,null,0);length-=n;}sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();}
        }
        static bool Verify(FileStream input,Local local,Report report,CancellationToken cancel)
        {
            if(local.Checked)return local.Valid;local.Checked=true;uint crc=0xffffffff;long done=0;byte[] block=new byte[65536];
            try{
                using(var slice=new Slice(input,local.DataOffset,local.Packed))
                using(Stream stream=local.Method==0?(Stream)slice:new DeflateStream(slice,CompressionMode.Decompress,true)){
                    int n;while((n=stream.Read(block,0,block.Length))>0){cancel.ThrowIfCancellationRequested();if(n>MaximumWorkBytes-report.ExpandedWorkBytes){report.Status="limited";throw new IOException("Поиск ZIP достиг общего предела проверки распаковки.");}report.ExpandedWorkBytes+=n;done+=n;if(done>local.Unpacked||done>MaximumMemberBytes)return false;for(int i=0;i<n;i++)crc=Crc[(crc^block[i])&255]^(crc>>8);}
                }
                if(done!=local.Unpacked||~crc!=local.ExpectedCrc)return false;local.RawSha=HashRange(input,local.Offset,local.RecordBytes,cancel);local.Valid=true;return true;
            }catch(InvalidDataException){return false;}catch(Reject){return false;}
        }
        static string Extension(IEnumerable<Entry> entries)
        {
            var names=new HashSet<string>(entries.Select(e=>e.Name.Replace('\\','/')),StringComparer.Ordinal);if(names.Contains("[Content_Types].xml")){if(names.Contains("word/document.xml"))return ".docx";if(names.Contains("xl/workbook.xml"))return ".xlsx";if(names.Contains("ppt/presentation.xml"))return ".pptx";}return ".zip";
        }
        static void Copy(FileStream input,FileStream output,SHA256 sha,long offset,long length,CancellationToken cancel)
        {
            input.Position=offset;byte[] b=new byte[65536];while(length>0){cancel.ThrowIfCancellationRequested();int n=input.Read(b,0,(int)Math.Min(b.Length,length));if(n==0)throw new Reject("range_truncated");output.Write(b,0,n);sha.TransformBlock(b,0,n,null,0);length-=n;}
        }
        static void Skip(Report report,string code){int n;report.Skipped.TryGetValue(code,out n);report.Skipped[code]=n+1;}
        static void PublishReport(string path,Report report)
        {
            string temporary=Path.Combine(Path.GetDirectoryName(path),".fz-"+Guid.NewGuid().ToString("N").Substring(0,8)+".partial");
            try{byte[] bytes=new UTF8Encoding(false).GetBytes(new JavaScriptSerializer{MaxJsonLength=32*1024*1024}.Serialize(report));using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){file.Write(bytes,0,bytes.Length);file.Flush(true);}File.Move(temporary,path);}finally{if(File.Exists(temporary))File.Delete(temporary);}
        }
        public static int Recover(string image,string runDirectory,CancellationToken cancel,Action<long,long> progress)
        {
            cancel.ThrowIfCancellationRequested();string source=FullPath(image),run=FullPath(runDirectory),folder=Path.Combine(run,"fragmented-archives"),reportPath=Path.Combine(run,"fragmented-zip.json");
            if(source.StartsWith("\\\\",StringComparison.Ordinal)||source.IndexOf(':',2)>=0||run.StartsWith("\\\\",StringComparison.Ordinal)||run.IndexOf(':',2)>=0||!File.Exists(source)||(File.GetAttributes(source)&FileAttributes.Directory)!=0)throw new IOException("Для сборки ZIP нужен обычный локальный образ и локальная папка.");NoLinks(source);NoLinks(run);NoLinks(folder);NoLinks(reportPath);
            if(source.Equals(reportPath,StringComparison.OrdinalIgnoreCase)||source.Equals(folder,StringComparison.OrdinalIgnoreCase)||source.StartsWith(folder+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||File.Exists(reportPath)||File.Exists(folder)||Directory.Exists(folder))throw new IOException("Нужна новая папка результата сборки ZIP, отдельно от исходного образа.");
            Directory.CreateDirectory(run);Directory.CreateDirectory(folder);var report=new Report();
            try{
                using(var input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read,BlockBytes)){
                    report.InputBytes=input.Length;var locals=new Dictionary<string,List<Local>>(StringComparer.Ordinal);var ends=new List<long>();byte[] block=new byte[BlockBytes+3];int carry=0;long position=0;
                    while(position<input.Length){
                        cancel.ThrowIfCancellationRequested();input.Position=position;int expected=(int)Math.Min(BlockBytes,input.Length-position),count=0,n;while(count<expected&&(n=input.Read(block,carry+count,expected-count))>0)count+=n;if(count!=expected)throw new IOException("Образ изменился или обрезан во время поиска ZIP.");int total=carry+count;long start=position-carry;
                        for(int at=0;at+3<total;at++){
                            if(block[at]!=80||block[at+1]!=75)continue;int type=block[at+2]|block[at+3]<<8;if(type!=0x0403&&type!=0x0605)continue;
                            if(++report.Headers>MaximumHeaders){report.Status="limited";throw new IOException("Достигнут предел проверяемых ZIP-заголовков.");}
                            long offset=start+at;if(type==0x0605){if(ends.Count>=MaximumDirectories){report.Status="limited";throw new IOException("Достигнут предел каталогов ZIP.");}ends.Add(offset);continue;}
                            try{Local item=LocalAt(input,offset);if(++report.LocalRecords>MaximumLocals){report.Status="limited";throw new IOException("Достигнут предел локальных ZIP-записей.");}List<Local> list;if(!locals.TryGetValue(item.Key,out list)){list=new List<Local>();locals.Add(item.Key,list);}list.Add(item);}catch(Reject error){Skip(report,error.Code);}
                        }
                        carry=Math.Min(3,total);Buffer.BlockCopy(block,total-carry,block,0,carry);position+=count;if(progress!=null)progress(position,input.Length);
                    }
                    var outputHashes=new HashSet<string>(StringComparer.Ordinal);
                    foreach(long end in ends){
                        cancel.ThrowIfCancellationRequested();DirectoryRecord central;
                        try{central=DirectoryAt(input,end);}catch(Reject error){Skip(report,error.Code);continue;}report.Directories++;
                        try{
                            var ordered=central.Entries.OrderBy(e=>e.LogicalOffset).ToArray();var chosen=new List<Local>();var alternatives=new List<List<Local>>();long logical=0;
                            for(int index=0;index<ordered.Length;index++){
                                Entry entry=ordered[index];if(entry.LogicalOffset!=logical)throw new Reject("logical_gaps_or_overlap_unsupported");long next=index+1<ordered.Length?ordered[index+1].LogicalOffset:central.LogicalOffset,recordBytes=next-logical;if(recordBytes<30+entry.RawName.Length+entry.Packed||recordBytes>30+entry.RawName.Length+32768L+entry.Packed)throw new Reject("logical_record_bounds");
                                List<Local> candidates;if(!locals.TryGetValue(entry.Key,out candidates))throw new Reject("member_missing");if(candidates.Count>256)throw new Reject("member_ambiguity_limit");var valid=new List<Local>();
                                foreach(var item in candidates)if(item.RecordBytes==recordBytes&&Verify(input,item,report,cancel))valid.Add(item);
                                if(valid.Count==0)throw new Reject("member_crc_or_length");if(valid.Select(x=>x.RawSha).Distinct(StringComparer.Ordinal).Take(2).Count()!=1)throw new Reject("member_ambiguous_raw_versions");
                                Local selected=valid.OrderBy(x=>x.Offset).FirstOrDefault(v=>!chosen.Any(x=>v.Offset<x.Offset+x.RecordBytes&&x.Offset<v.Offset+v.RecordBytes)&&!(v.Offset<central.Offset+central.Bytes+central.EocdBytes&&central.Offset<v.Offset+v.RecordBytes));if(selected==null)throw new Reject("physical_overlap");
                                chosen.Add(selected);alternatives.Add(valid);logical=next;
                            }
                            if(logical!=central.LogicalOffset)throw new Reject("logical_directory_offset");long length=logical+central.Bytes+central.EocdBytes;if(length>MaximumArchiveBytes)throw new Reject("archive_limit");
                            bool contiguous=true;long physical=chosen[0].Offset;for(int i=0;i<chosen.Count;i++){if(chosen[i].Offset!=physical)contiguous=false;physical=chosen[i].Offset+chosen[i].RecordBytes;}if(physical!=central.Offset)contiguous=false;if(contiguous)throw new Reject("already_contiguous");
                            if(report.Recovered>=MaximumArchives||length>MaximumOutputBytes-report.OutputBytes){report.Status="limited";throw new IOException("Достигнут предел вывода собранных ZIP.");}
                            string name="reassembled-"+end.ToString("D16")+Extension(central.Entries),path=Path.Combine(folder,name),partial=path+".partial";string digest;
                            try{
                                using(var output=new FileStream(partial,FileMode.CreateNew,FileAccess.Write,FileShare.Read))using(var hash=SHA256.Create()){
                                    foreach(var item in chosen)Copy(input,output,hash,item.Offset,item.RecordBytes,cancel);Copy(input,output,hash,central.Offset,central.Bytes+central.EocdBytes,cancel);hash.TransformFinalBlock(new byte[0],0,0);digest=BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();output.Flush(true);
                                }
                                cancel.ThrowIfCancellationRequested();if(!outputHashes.Add(digest)){Skip(report,"duplicate_archive_bytes");File.Delete(partial);continue;}File.Move(partial,path);
                            }catch{if(File.Exists(partial))File.Delete(partial);throw;}
                            var result=new Result{Path="fragmented-archives/"+name,Sha256=digest,Bytes=length,CentralOffset=central.Offset,EocdOffset=central.EocdOffset,Members=chosen.Count};logical=0;
                            for(int i=0;i<chosen.Count;i++){Local item=chosen[i];result.Extents.Add(new Extent{ImageOffset=item.Offset,LogicalOffset=logical,Length=item.RecordBytes});result.MemberSources.Add(new Member{Name=item.Name,Crc32=item.ExpectedCrc.ToString("x8"),RecordSha256=item.RawSha,LogicalOffset=logical,ImageOffset=item.Offset,CompressedBytes=item.Packed,Bytes=item.Unpacked,EquivalentRecordOffsets=alternatives[i].Select(x=>x.Offset).ToList()});logical+=item.RecordBytes;}
                            result.Extents.Add(new Extent{ImageOffset=central.Offset,LogicalOffset=logical,Length=central.Bytes+central.EocdBytes});report.Files.Add(result);report.Recovered++;report.OutputBytes+=length;
                        }catch(Reject error){Skip(report,error.Code);}
                    }
                }
                report.Status="complete";return report.Recovered;
            }catch(OperationCanceledException){report.Status="cancelled";throw;}catch(IOException){if(report.Status!="limited")report.Status="incomplete";throw;}finally{PublishReport(reportPath,report);}
        }
        static uint[] MakeCrc(){var table=new uint[256];for(uint n=0;n<256;n++){uint x=n;for(int b=0;b<8;b++)x=(x&1)==0?x>>1:(x>>1)^0xedb88320;table[n]=x;}return table;}
    }
}
