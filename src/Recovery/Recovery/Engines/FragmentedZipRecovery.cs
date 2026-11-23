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
    public static partial class FragmentedZipRecovery
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
            public long InputBytes,ExpandedWorkBytes,OutputBytes,ChargedWorkBytes;
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
            public override int Read(byte[] b,int at,int count){if(count==0||position>=length)return 0;input.Position=start+position;int n=input.Read(b,at,(int)Math.Min(count,length-position));if(n==0)throw new IOException("FRAGMENTED_ZIP_SOURCE_TRUNCATED");position+=n;return n;}
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
            if(offset<0||length<0||offset>input.Length-length)throw new Reject("structure_bounds");input.Position=offset;byte[] bytes=new byte[length];int done=0,n;while(done<length&&(n=input.Read(bytes,done,length-done))>0)done+=n;if(done!=length)throw new IOException("FRAGMENTED_ZIP_SOURCE_TRUNCATED");return bytes;
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
            using(var sha=SHA256.Create()){byte[] block=new byte[65536];input.Position=offset;while(length>0){cancel.ThrowIfCancellationRequested();int n=input.Read(block,0,(int)Math.Min(length,block.Length));if(n==0)throw new IOException("FRAGMENTED_ZIP_SOURCE_TRUNCATED");sha.TransformBlock(block,0,n,null,0);length-=n;}sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();}
        }
        static bool Verify(FileStream input,Local local,Report report,CancellationToken cancel,long allowance)
        {
            if(local.Checked)return local.Valid;local.Checked=true;uint crc=0xffffffff;long done=0;byte[] block=new byte[65536];
            try{
                using(var slice=new Slice(input,local.DataOffset,local.Packed))
                using(Stream stream=local.Method==0?(Stream)slice:new DeflateStream(slice,CompressionMode.Decompress,true)){
                    int n;while((n=stream.Read(block,0,block.Length))>0){cancel.ThrowIfCancellationRequested();if(n>allowance-done){report.Status="limited";throw new IOException("Поиск ZIP достиг общего предела проверки распаковки.");}report.ExpandedWorkBytes+=n;done+=n;if(done>local.Unpacked||done>MaximumMemberBytes)return false;for(int i=0;i<n;i++)crc=Crc[(crc^block[i])&255]^(crc>>8);}
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
            input.Position=offset;byte[] b=new byte[65536];while(length>0){cancel.ThrowIfCancellationRequested();int n=input.Read(b,0,(int)Math.Min(b.Length,length));if(n==0)throw new IOException("FRAGMENTED_ZIP_SOURCE_TRUNCATED");output.Write(b,0,n);sha.TransformBlock(b,0,n,null,0);length-=n;}
        }
        static void Skip(Report report,string code){int n;report.Skipped.TryGetValue(code,out n);report.Skipped[code]=n+1;}
        public static int Recover(string image, string runDirectory, CancellationToken cancel, Action<long, long> progress)
        {
            return Recover(image, runDirectory, cancel, progress, null);
        }

        internal static int Recover(string image, string runDirectory, CancellationToken cancel,
            Action<long, long> progress, RecoveryCheckpointContext checkpoint)
        {
            return RecoverWithCheckpoints(image, runDirectory, cancel, progress, checkpoint);
        }

        static uint[] MakeCrc(){var table=new uint[256];for(uint n=0;n<256;n++){uint x=n;for(int b=0;b<8;b++)x=(x&1)==0?x>>1:(x>>1)^0xedb88320;table[n]=x;}return table;}
    }
}
