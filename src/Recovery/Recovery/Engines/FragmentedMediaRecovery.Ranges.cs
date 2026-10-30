using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace UsbRecovery
{
    public static partial class FragmentedMediaRecovery
    {
        sealed class UnitAnchor {public int Cell;public UnitSample Sample;}
        static void RecordZeroRanges(Context c,long start,byte[] raw)
        {
            for(int at=0;at<raw.Length;at+=4096){int length=Math.Min(4096,raw.Length-at);bool zero=true;for(int n=0;n<length;n++)if(raw[at+n]!=0){zero=false;break;}if(!zero)continue;
                var previous=c.ZeroRanges.LastOrDefault();if(previous!=null&&previous.Offset+previous.Bytes==start+at)previous.Bytes+=length;
                else if(c.ZeroRanges.Count<c.Limits.MaxCandidates)c.ZeroRanges.Add(new Payload{Offset=start+at,Bytes=length});
            }
        }
        static bool SourceZeroRange(Context c,long at,int length)
        {
            int low=0,high=c.ZeroRanges.Count;while(low<high){int middle=low+(high-low)/2;if(c.ZeroRanges[middle].Offset<=at)low=middle+1;else high=middle;}if(low==0)return false;var range=c.ZeroRanges[low-1];return at>=range.Offset&&at+length<=range.Offset+range.Bytes;
        }
        static void EnsurePayloadIndex(Context c,Chunk chunk)
        {
            bool jpeg=chunk.Codec=="jpeg"||chunk.Codec=="mjpg",hevc=chunk.Hevc!=null;int length=hevc?chunk.Hevc.NalLengthBytes:0;
            if(jpeg?c.JpegIndexed:hevc?(c.HevcIndexed&(1<<length))!=0:c.AvcIndexed)return;
            var found=jpeg?c.Jpeg:hevc?c.Hevc:c.Avc;var seen=new HashSet<long>(found);byte[] block=new byte[BlockBytes+16];int carry=0;
            for(long position=0;position<c.Input.Length;){
                c.Cancel.ThrowIfCancellationRequested();int count=(int)Math.Min(BlockBytes,c.Input.Length-position);byte[] raw=c.Read(position,count);Buffer.BlockCopy(raw,0,block,carry,count);int total=carry+count;long start=position-carry;
                for(int p=0;p+8<=total;p++){
                    bool possible=false;
                    if(jpeg)possible=block[p]==255&&block[p+1]==216&&block[p+2]==255;
                    else if(hevc)possible=PossibleHevcStart(block,p,total-p,length);
                    else if(block[p]==0){uint n=U32(block,p);int nal=block[p+4]&31;possible=n>0&&n<MaximumSampleBytes&&(block[p+4]&128)==0&&(nal==1||nal==5||nal==6||nal==7||nal==8||nal==9);}
                    long at=start+p;if(possible&&seen.Add(at)){if(found.Count>=c.Limits.MaxCandidates)throw new Budget();found.Add(at);if(!jpeg&&!hevc&&c.AvcHeaders.Count<c.Limits.MaxCandidates*2)c.AvcHeaders[at]=new AvcHeader{Length=U32(block,p),Kind=block[p+4]&31,Valid=(block[p+4]&128)==0&&(block[p+4]&31)>0&&(block[p+4]&31)<24};}
                }
                carry=Math.Min(7,total);Buffer.BlockCopy(block,total-carry,block,0,carry);position+=count;
            }
            found.Sort();if(jpeg)c.JpegIndexed=true;else if(hevc)c.HevcIndexed|=1<<length;else c.AvcIndexed=true;
        }
        static AvcHeader PhysicalAvcHeader(Context c,long at)
        {
            c.Cancel.ThrowIfCancellationRequested();AvcHeader header;
            if(c.AvcHeaders.TryGetValue(at,out header)){
                if(!header.Charged){if(5>c.Limits.MaxVerifiedBytes-c.Report.VerifiedBytes)throw new Budget();c.Report.VerifiedBytes+=5;header.Charged=true;}return header;
            }
            byte[] raw=c.Read(at,5,true);int kind=raw[4]&31;header=new AvcHeader{Length=U32(raw,0),Kind=kind,Valid=(raw[4]&128)==0&&kind>0&&kind<24,Charged=true};if(c.AvcHeaders.Count<c.Limits.MaxCandidates*2)c.AvcHeaders.Add(at,header);return header;
        }
        static bool AvcPhysicalValid(Context c,long at,int bytes)
        {
            int position=0,nals=0;bool slice=false;while(position<bytes){
                if(bytes-position<5||++nals>MaximumHeaders)return false;var header=PhysicalAvcHeader(c,at+position);
                if(!header.Valid||header.Length<1||header.Length>bytes-position-4)return false;if(header.Kind==1||header.Kind==5)slice=true;position+=4+(int)header.Length;
            }return slice;
        }
        // The accessor addresses logical file bytes. It may cross any number
        // of selected source extents; it never supplies absent bytes or padding.
        static bool UnitRangeSampleValid(UnitSample sample,Func<long,int,byte[]> read)
        {
            var chunk=sample.Chunk;
            if(chunk.Codec=="mp4a"){
                if(sample.Bytes>AacLcValidator.MaximumSampleBytes||sample.Bytes<2)return false;
                byte[] tail=read(sample.Logical+sample.Bytes-2,2);if(!UnitAudioEnd(tail,0,tail.Length))return false;
                byte[] first=read(sample.Logical,2);if(!AacLcValidator.IsPossibleStart(first,0))return false;
                return UnitSampleValid(read(sample.Logical,sample.Bytes),chunk);
            }
            if(chunk.Hevc!=null||chunk.Codec=="jpeg"||chunk.Codec=="mjpg")return UnitSampleValid(read(sample.Logical,sample.Bytes),chunk);
            int position=0,nals=0;bool slice=false;
            while(position<sample.Bytes){
                if(sample.Bytes-position<5||++nals>MaximumHeaders)return false;byte[] header=read(sample.Logical+position,5);uint length=U32(header,0);int kind=header[4]&31;
                if(length<1||length>sample.Bytes-position-4||(header[4]&128)!=0||kind==0||kind>=24)return false;
                if(kind==1||kind==5)slice=true;position+=4+(int)length;
            }
            return slice;
        }
        static bool UnitCellRangeValid(Context c,long physical,long logical,int length,List<UnitFixed> known,List<UnitSample> samples)
        {
            long end=logical+length;
            foreach(var fixedBytes in known){long left=Math.Max(logical,fixedBytes.Logical),right=Math.Min(end,fixedBytes.Logical+fixedBytes.Raw.Length);if(left>=right)continue;byte[] raw=c.Read(physical+left-logical,(int)(right-left),true);for(int n=0;n<raw.Length;n++)if(raw[n]!=fixedBytes.Raw[(int)(left-fixedBytes.Logical)+n])return false;}
            Func<long,int,byte[]> read=(at,count)=>c.Read(physical+at-logical,count,true);
            foreach(var sample in samples.Where(x=>x.Chunk.Codec!="mp4a"))if(sample.Logical>=logical&&sample.Logical+sample.Bytes<=end&&!UnitRangeSampleValid(sample,read))return false;
            foreach(var sample in samples.Where(x=>x.Chunk.Codec=="mp4a"))if(sample.Logical>=logical&&sample.Logical+sample.Bytes<=end&&!UnitRangeSampleValid(sample,read))return false;
            return true;
        }
        static byte[] ReadUnitMap(Context c,UnitCopy[] assigned,long[] positions,int unit,int length,long at,int count)
        {
            if(at<0||count<0||at>length-count)throw new Reject("unit_logical_bounds");byte[] raw=new byte[count];int done=0;
            while(done<count){long logical=at+done;int cell=(int)(logical/unit),within=(int)(logical%unit);var copy=assigned[cell];if(copy==null)throw new Reject("unit_unmapped_range");int n=Math.Min(count-done,copy.Length-within);if(n<1)throw new Reject("unit_logical_bounds");byte[] part=c.Read(positions[cell]+within,n,true);Buffer.BlockCopy(part,0,raw,done,n);done+=n;}
            return raw;
        }
        static string HashUnitMap(Context c,UnitCopy[] assigned,long[] positions)
        {
            using(var hash=SHA256.Create()){
                for(int cell=0;cell<assigned.Length;cell++){int done=0;while(done<assigned[cell].Length){c.Cancel.ThrowIfCancellationRequested();int n=Math.Min(65536,assigned[cell].Length-done);byte[] raw=c.Read(positions[cell]+done,n,true);hash.TransformBlock(raw,0,n,null,0);done+=n;}}
                hash.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        static bool RangeVideoHeader(byte[] raw,int at,int available,UnitSample sample)
        {
            if(sample.Chunk.Codec=="jpeg"||sample.Chunk.Codec=="mjpg")return available>=3&&raw[at]==255&&raw[at+1]==216&&raw[at+2]==255;
            int prefix=sample.Chunk.Hevc==null?4:sample.Chunk.Hevc.NalLengthBytes;if(available<prefix+(sample.Chunk.Hevc==null?1:2))return false;long size=0;for(int n=0;n<prefix;n++)size=(size<<8)|raw[at+n];if(size<1||size>sample.Bytes-prefix)return false;
            if(sample.Chunk.Hevc!=null){int first=raw[at+prefix],second=raw[at+prefix+1],hevcKind=(first>>1)&63;return size>=3&&(first&128)==0&&((first&1)<<5|(second>>3))==0&&(second&7)!=0&&(hevcKind<=9||hevcKind>=16&&hevcKind<=21||hevcKind>=32&&hevcKind<=35||hevcKind==39);}
            int kind=raw[at+4]&31;return (raw[at+4]&128)==0&&kind>0&&kind<24;
        }
        static bool MetadataLeafPrefix(byte[] raw,int at,int header,int bytes,int available,string type)
        {
            if(type!="stsz"&&type!="stsc"&&type!="stts"&&type!="stss"&&type!="ctts"&&type!="stco"&&type!="co64"&&type!="stsd"&&type!="dref")return true;
            int data=at+header,end=at+bytes,seen=Math.Min(available,end);if(bytes<header+8)return false;
            if(seen>=data+4&&(type=="ctts"?(U32(raw,data)!=0&&U32(raw,data)!=0x01000000):U32(raw,data)!=0))return false;
            if(type=="stsz"){
                if(bytes<header+12)return false;if(seen<data+12)return true;uint fixedSize=U32(raw,data+4),samples=U32(raw,data+8);if(samples<1||samples>MaximumSamples||fixedSize>MaximumSampleBytes)return false;
                if(bytes-header!=(fixedSize==0?12L+samples*4:12))return false;
                if(fixedSize==0)for(int p=data+12;p+4<=seen;p+=4){uint size=U32(raw,p);if(size<1||size>MaximumSampleBytes)return false;}return true;
            }
            if(seen<data+8)return true;uint count=U32(raw,data+4);if(type=="stsd"||type=="dref")return count==1;
            if(type=="stss"&&count==0)return bytes-header==8;
            int stride=type=="stsc"?12:type=="stts"||type=="ctts"||type=="co64"?8:4;int maximum=type=="stts"||type=="ctts"||type=="stss"?MaximumSamples:MaximumChunks;if(count<1||count>maximum||bytes-header!=8L+count*stride)return false;
            uint previous=0;long timed=0;
            for(int p=data+8;p+stride<=seen;p+=stride){uint first=U32(raw,p);
                if(type=="stsc"){uint per=U32(raw,p+4);if(first<1||first>MaximumChunks||p==data+8&&first!=1||p>data+8&&first<=previous||per<1||per>MaximumSamples||U32(raw,p+8)!=1)return false;previous=first;}
                else if(type=="stts"){if(first==0||U32(raw,p+4)==0||(timed+=first)>MaximumSamples)return false;}
                else if(type=="ctts"){if(first==0||(timed+=first)>MaximumSamples)return false;}
                else if(type=="stss"){if(first<1||first>MaximumSamples||p>data+8&&first<=previous)return false;previous=first;}
                else {long offset=type=="co64"?U64(raw,p):first;if(offset<8||offset>MaximumFileBytes)return false;}
            }
            return true;
        }
        static HashSet<long>[] RangeUnitSeeds(Context c,int unit,int length,List<UnitFixed> known,List<UnitSample> samples,List<Extent> metadata,int phase)
        {
            int count=(length+unit-1)/unit;var seeds=Enumerable.Range(0,count).Select(x=>new HashSet<long>()).ToArray();var video=Enumerable.Range(0,512).Select(x=>new List<UnitAnchor>()).ToArray();var audio=Enumerable.Range(0,512).Select(x=>new List<UnitAnchor>()).ToArray();var byCell=new List<UnitSample>[count];
            for(int cell=0;cell<count;cell++){
                long left=(long)cell*unit,right=Math.Min(length,left+unit);byCell[cell]=samples.Where(x=>x.Logical>=left&&x.Logical<right).ToList();
                var picture=byCell[cell].Where(x=>x.Chunk.Codec!="mp4a"&&x.Logical+(x.Chunk.Codec=="jpeg"||x.Chunk.Codec=="mjpg"?3:x.Chunk.Hevc==null?5:x.Chunk.Hevc.NalLengthBytes+2)<=right).OrderBy(x=>x.Logical+x.Bytes<=right?0:1).ThenBy(x=>x.Bytes).FirstOrDefault();
                if(picture!=null){video[Mod(picture.Logical+phase,512)].Add(new UnitAnchor{Cell=cell,Sample=picture});continue;}
                bool fixedAnchor=metadata.Any(x=>x.LogicalOffset<right&&left<x.LogicalOffset+x.Length);
                if(fixedAnchor)continue;
                var sound=byCell[cell].Where(x=>x.Chunk.Codec=="mp4a"&&x.Logical+x.Bytes<=right).OrderByDescending(x=>x.Bytes).FirstOrDefault();if(sound==null)return null;
                audio[Mod(sound.Logical+sound.Bytes-1+phase,512)].Add(new UnitAnchor{Cell=cell,Sample=sound});
            }
            foreach(var e in metadata)for(long p=e.LogicalOffset;p<e.LogicalOffset+e.Length;p=(p/unit+1)*unit)UnitSeed(c,seeds,unit,length,phase,p,e.ImageOffset+p-e.LogicalOffset);
            var attempted=Enumerable.Range(0,count).Select(x=>new HashSet<long>()).ToArray();int probes=0;
            Action<UnitAnchor,long> consider=(anchor,at)=>{
                long physical=at-anchor.Sample.Logical%unit;int cell=anchor.Cell,bytes=Math.Min(unit,length-cell*unit);if(physical<0||physical>c.Input.Length-bytes||Mod(physical,512)!=phase||!attempted[cell].Add(physical))return;
                if(++probes>c.Limits.MaxCandidates*8L||(long)probes*64>UnitMemoryLimit)throw new Budget();if(UnitCellRangeValid(c,physical,(long)cell*unit,bytes,known,byCell[cell]))UnitSeed(c,seeds,unit,length,phase,anchor.Sample.Logical,at);
            };
            bool anyAudio=audio.Any(x=>x.Count>0),anyVideo=video.Any(x=>x.Count>0);int before=anyAudio?AacLcValidator.MaximumSampleBytes:0;
            if(anyAudio||anyVideo)for(long position=0;position<c.Input.Length;position+=BlockBytes){
                c.Cancel.ThrowIfCancellationRequested();long start=Math.Max(0,position-before);int prefix=(int)(position-start),countHere=(int)Math.Min(BlockBytes,c.Input.Length-position);byte[] raw=c.Read(start,(int)Math.Min(prefix+countHere+8L,c.Input.Length-start));
                for(int p=prefix;p<prefix+countHere;p++){
                    if((p&65535)==0)c.Cancel.ThrowIfCancellationRequested();long absolute=start+p;int residue=Mod(absolute,512);
                    if(anyVideo)foreach(var anchor in video[residue])if(RangeVideoHeader(raw,p,raw.Length-p,anchor.Sample))consider(anchor,absolute);
                    if(anyAudio&&p>=1&&raw[p]!=0){int last=raw[p],zero=0;while((last&(1<<zero))==0)zero++;if((((raw[p-1]<<8)|last)>>zero&7)!=7)continue;
                        foreach(var anchor in audio[residue]){int at=p-anchor.Sample.Bytes+1;if(at<0||!AacLcValidator.IsPossibleStart(raw,at))continue;byte[] candidate=new byte[anchor.Sample.Bytes];Buffer.BlockCopy(raw,at,candidate,0,candidate.Length);if(candidate.Length>c.Limits.MaxVerifiedBytes-c.Report.VerifiedBytes)throw new Budget();c.Report.VerifiedBytes+=candidate.Length;if(UnitSampleValid(candidate,anchor.Sample.Chunk))consider(anchor,absolute-anchor.Sample.Bytes+1);}
                    }
                }
            }
            return seeds.Any(x=>x.Count==0)?null:seeds;
        }
    }
}
