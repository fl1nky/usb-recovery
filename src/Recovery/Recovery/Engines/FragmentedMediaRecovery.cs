using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace UsbRecovery
{
    // Apple QTFF: stco/co64 contain FILE offsets, stsc maps samples to chunks.
    // https://developer.apple.com/documentation/quicktime-file-format/chunk_offset_atom
    // A sample table has no payload hashes. Even unique syntactically matching
    // chunks remain candidates; neither ownership nor deletion is authenticated.
    public static partial class FragmentedMediaRecovery
    {
        public const int MaximumHeaders=100000,MaximumSampleBytes=8*1024*1024,MaximumMetadataBytes=16*1024*1024;
        public const int MaximumChunks=20000,MaximumSamples=100000,MaximumMovies=64;
        public const long MaximumFileBytes=512L*1024*1024,MaximumOutputBytes=1024L*1024*1024,MaximumVerifiedBytes=512L*1024*1024;
        const int BlockBytes=1024*1024,MaximumRetainedMetadataBytes=32*1024*1024;
        public sealed class Limits
        {
            public int MaxCandidates=MaximumHeaders,MaxFiles=32;
            public long MaxOutputBytes=MaximumOutputBytes,MaxVerifiedBytes=MaximumVerifiedBytes;
            internal void Validate(){if(MaxCandidates<1||MaxCandidates>MaximumHeaders||MaxFiles<1||MaxFiles>MaximumMovies||MaxOutputBytes<1||MaxOutputBytes>MaximumOutputBytes||MaxVerifiedBytes<1||MaxVerifiedBytes>MaximumVerifiedBytes)throw new ArgumentException("MEDIA_LIMITS_INVALID");}
        }
        public sealed class Extent
        {
            public long ImageOffset,LogicalOffset,Length;
            public string Kind;
            public List<long> EquivalentOffsets=new List<long>();
        }
        public sealed class Result
        {
            public string Path,Sha256,Status="iso_bmff_structural_candidate";
            public long Bytes,MoovOffset;
            public int Tracks,Chunks;
            public int AudioChunks;
            public bool AudioGeometryInferred;
            public bool AudioSyntaxChecked;
            public string AudioSearch;
            public bool PayloadAuthenticated=false,DeletionConfirmed=false;
            public List<Extent> Extents=new List<Extent>();
            public string Note="Surviving sample tables and unique syntax-valid chunk bytes agree. This is not a decoded-video or ownership/authenticity guarantee. Original name and deletion state are unknown; inspect the candidate.";
        }
        public sealed class Report
        {
            public int Schema=1,Headers,Movies,Candidates,Recovered;
            public int SourceRangeCount,SourceAlternativeCount;
            public int PayloadProbes;
            public long InputBytes,OutputBytes,VerifiedBytes,SourceReadBytes;
            public string Status="incomplete";
            public Dictionary<string,int> Skipped=new Dictionary<string,int>(StringComparer.Ordinal);
            public List<Result> Files=new List<Result>();
            public string Scope="Classic self-contained MP4/MOV, one mdat, densely packed non-overlapping chunks; surviving ftyp/moov, optional one free/wide. AVC four-byte NAL lengths, single-layer Main/Main10 HEVC with supplied parameter sets and 1/2/4-byte lengths, or JPEG video, plus AAC-LC mono/stereo. HEVC parameter/slice headers are checked; AVC checks NAL framing/types. Entropy, reference pictures and PCM are not decoded/authenticated. Whole-chunk search uses bracketing geometry or strict AAC syntax at sector/video/container offsets. A separate fallback joins sample-internal splits only in 512..65536-byte logical allocation-unit hypotheses, each unit independently anchored by metadata/sample structure, physical origins sector-congruent with ftyp. It requires complete cross-join syntax, full non-overlapping source coverage and one byte result across all bounded assignments. Source-backed unit descriptors and streamed assignment hashes/output avoid a whole-file buffer; AVC validation range-reads NAL headers, AAC and supported HEVC/JPEG reads remain sample-bounded. Unit capacity <=256MiB from 4096 cells/65536-byte units, with 8192 samples and 8192 assignment states, estimated32MiB mapping metadata and the shared512MiB verification budget; whole-chunk recovery remains a fallback up to its existing file bound. Codec indexes are built lazily; bounded AVC header reuse avoids repeated source reads, legacy payload probes are capped at16 times MaxCandidates, and source-read bytes are separately reported. Metadata repair <=64KiB/eight fragments/64 variants/one million probes. Metadata alternatives undergo whole-file checks before publication. Unanchored opaque interiors, arbitrary nonaligned permutations, HE-AAC/other audio, moof, invented padding/missing bytes are unsupported. Distinct valid complete byte results are ambiguous. Exhausted search reports limited, never successful uniqueness.";
        }
        sealed class Reject:Exception {public string Code;public bool VideoOnly;public Reject(string code){Code=code;}}
        sealed class Budget:Exception {}
        sealed class Atom {public long Offset,Bytes;public int Header;public string Type;public byte[] Raw;public List<Extent> Parts;}
        sealed class Chunk {public long Logical,Bytes;public string Codec;public int[] Samples;public int Width,Height,Channels,AudioFrequency;public HevcSampleValidator.Configuration Hevc;}
        sealed class Movie {public Atom Moov;public List<Chunk> Chunks=new List<Chunk>();public int Tracks;}
        sealed class Box {public int At,Bytes,Header;public string Type;public int Data{get{return At+Header;}}public int End{get{return At+Bytes;}}}
        sealed class Payload {public long Offset,Bytes;public string Sha;}
        sealed class AvcHeader {public uint Length;public int Kind;public bool Valid,Charged;}
        sealed class Context
        {
            public FileStream Input;public Report Report;public Limits Limits;public CancellationToken Cancel;
            public List<Atom> Ftyp=new List<Atom>(),Moov=new List<Atom>(),Mdat=new List<Atom>(),Free=new List<Atom>();
            public List<long> Jpeg=new List<long>(),Avc=new List<long>(),Hevc=new List<long>();
            public List<long> AacStarts;
            public Dictionary<string,List<Payload>> Cache=new Dictionary<string,List<Payload>>(StringComparer.Ordinal);
            public long RetainedMetadataBytes;
            public int LayoutAttempts;
            public UnitIndex Units;
            public bool AvcIndexed,JpegIndexed;
            public int HevcIndexed;
            public Dictionary<long,AvcHeader> AvcHeaders=new Dictionary<long,AvcHeader>();
            public List<Payload> ZeroRanges=new List<Payload>();
            public byte[] Read(long at,int count,bool charge=false){
                Cancel.ThrowIfCancellationRequested();if(at<0||count<0||at>Input.Length-count)throw new Reject("source_bounds");
                if(charge){if(count>Limits.MaxVerifiedBytes-Report.VerifiedBytes)throw new Budget();Report.VerifiedBytes+=count;}
                Input.Position=at;byte[] b=new byte[count];int done=0,n;while(done<count&&(n=Input.Read(b,done,count-done))>0){done+=n;Report.SourceReadBytes+=n;}if(done!=count)throw new IOException("MEDIA_SOURCE_TRUNCATED");return b;
            }
        }
        static uint U32(byte[] b,int at){return (uint)b[at]<<24|(uint)b[at+1]<<16|(uint)b[at+2]<<8|b[at+3];}
        static long U64(byte[] b,int at){ulong n=(ulong)U32(b,at)<<32|U32(b,at+4);if(n>Int64.MaxValue)throw new Reject("integer_bounds");return (long)n;}
        static string Type(byte[] b,int at){return Encoding.ASCII.GetString(b,at,4);}
        static string Sha(byte[] b){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
        static void Skip(Report report,string code){int n;report.Skipped.TryGetValue(code,out n);report.Skipped[code]=n+1;}
        static void NoLinks(string path){for(var d=new DirectoryInfo(File.Exists(path)?Path.GetDirectoryName(path):path);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("MEDIA_LINKED_PATH");if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("MEDIA_LINKED_PATH");}
        static void Local(string path){if(path.StartsWith("\\\\",StringComparison.Ordinal)||path.IndexOf(':',2)>=0)throw new IOException("MEDIA_LOCAL_FILE_REQUIRED");NoLinks(path);}
        static string FullPath(string path){try{return Path.GetFullPath(path);}catch(ArgumentException){throw new IOException("MEDIA_LOCAL_FILE_REQUIRED");}catch(NotSupportedException){throw new IOException("MEDIA_LOCAL_FILE_REQUIRED");}}
        static Atom AtomAt(Context c,long at)
        {
            byte[] head=c.Read(at,8);uint shortSize=U32(head,0);int header=shortSize==1?16:8;long bytes=shortSize==1?U64(c.Read(at+8,8),0):shortSize;
            if(bytes<header||bytes>MaximumFileBytes)throw new Reject("atom_size");string type=Type(head,4);
            var a=new Atom{Offset=at,Bytes=bytes,Header=header,Type=type};
            if(type!="mdat"){
                if(bytes>MaximumMetadataBytes||bytes>c.Input.Length-at)throw new Reject("metadata_bounds");if(bytes>MaximumRetainedMetadataBytes-c.RetainedMetadataBytes)throw new Budget();a.Raw=c.Read(at,(int)bytes);c.RetainedMetadataBytes+=bytes;
                if(type=="ftyp"){
                    if(bytes<header+8||(bytes-header)%4!=0||bytes>4096)throw new Reject("ftyp_invalid");
                    var brands=new HashSet<string>{"isom","iso2","avc1","mp41","mp42","qt  ","M4V ","MSNV"};bool allowed=brands.Contains(Type(a.Raw,header));
                    for(int p=header+8;p<a.Raw.Length;p+=4)allowed|=brands.Contains(Type(a.Raw,p));if(!allowed)throw new Reject("brand_unsupported");
                }
            }
            return a;
        }
        static List<Box> Boxes(byte[] raw,int start,int end)
        {
            var list=new List<Box>();for(int p=start;p<end;){if(end-p<8||list.Count>=10000)throw new Reject("box_table_bounds");uint small=U32(raw,p);int header=small==1?16:8;if(end-p<header)throw new Reject("box_header");long size=small==1?U64(raw,p+8):small;if(size<header||size>end-p)throw new Reject("box_size");list.Add(new Box{At=p,Bytes=(int)size,Header=header,Type=Type(raw,p+4)});p+=(int)size;}return list;
        }
        static Box One(IEnumerable<Box> boxes,string type){var found=boxes.Where(x=>x.Type==type).ToArray();if(found.Length!=1)throw new Reject("required_box_"+type);return found[0];}
        static List<Box> Children(byte[] raw,Box b){return Boxes(raw,b.Data,b.End);}
        static void FullBox(byte[] raw,Box b,int payload){if(b.End-b.Data<payload+4||U32(raw,b.Data)!=0)throw new Reject("full_box_version_or_size");}
        static int Count(uint n,int maximum){if(n<1||n>maximum)throw new Reject("table_count_limit");return (int)n;}
        static void Exact(Box b,int dataBytes){if(b.End-b.Data!=dataBytes)throw new Reject("table_length");}
        static Movie ParseMovie(Atom a)
        {
            byte[] raw=a.Raw;var top=Boxes(raw,a.Header,raw.Length);One(top,"mvhd");if(top.Any(b=>b.Type=="mvex"))throw new Reject("fragmented_mp4_unsupported");
            var movie=new Movie{Moov=a};var tracks=top.Where(b=>b.Type=="trak").ToArray();if(tracks.Length<1||tracks.Length>8)throw new Reject("track_count");
            foreach(var track in tracks){
                var t=Children(raw,track);One(t,"tkhd");var mdia=Children(raw,One(t,"mdia"));One(mdia,"mdhd");Box hdlr=One(mdia,"hdlr");FullBox(raw,hdlr,8);string handler=Type(raw,hdlr.Data+8);if(handler!="vide"&&handler!="soun")throw new Reject("track_type_unsupported");
                var minf=Children(raw,One(mdia,"minf"));var dinf=Children(raw,One(minf,"dinf"));Box dref=One(dinf,"dref");FullBox(raw,dref,4);if(U32(raw,dref.Data+4)!=1)throw new Reject("data_references_unsupported");
                var refs=Boxes(raw,dref.Data+8,dref.End);Box reference=One(refs,"url ");if(refs.Count!=1||reference.End-reference.Data!=4||U32(raw,reference.Data)!=1)throw new Reject("external_media_unsupported");
                var stbl=Children(raw,One(minf,"stbl"));Box stsd=One(stbl,"stsd"),stsc=One(stbl,"stsc"),stsz=One(stbl,"stsz"),stts=One(stbl,"stts");
                if(stbl.Any(b=>b.Type=="stz2"))throw new Reject("compact_sample_sizes_unsupported");
                FullBox(raw,stsd,4);if(U32(raw,stsd.Data+4)!=1)throw new Reject("sample_descriptions_unsupported");var descriptions=Boxes(raw,stsd.Data+8,stsd.End);if(descriptions.Count!=1)throw new Reject("sample_descriptions_unsupported");Box description=descriptions[0];string codec=description.Type;
                if(handler=="vide"&&codec!="avc1"&&codec!="avc3"&&codec!="hvc1"&&codec!="hev1"&&codec!="jpeg"&&codec!="mjpg"||handler=="soun"&&codec!="mp4a")throw new Reject("codec_unsupported");
                int channels=0,audioFrequency=0;if(codec=="mp4a")channels=AudioConfig(raw,description,out audioFrequency);else if(description.End-description.Data<78||raw[description.Data+6]!=0||raw[description.Data+7]!=1)throw new Reject("sample_description_invalid");
                HevcSampleValidator.Configuration hevc=null;
                if(codec=="avc1"||codec=="avc3"){
                    var extensions=Boxes(raw,description.Data+78,description.End);Box avcc=One(extensions,"avcC");if(avcc.End-avcc.Data<7||raw[avcc.Data]!=1||(raw[avcc.Data+4]&3)!=3)throw new Reject("avc_configuration_unsupported");ValidateAvcc(raw,avcc);
                }
                if(codec=="hvc1"||codec=="hev1"){
                    var extensions=Boxes(raw,description.Data+78,description.End);Box hvcc=One(extensions,"hvcC");byte[] config=new byte[hvcc.End-hvcc.Data];Buffer.BlockCopy(raw,hvcc.Data,config,0,config.Length);
                    string code;if(!HevcSampleValidator.TryParseConfiguration(config,codec,raw[description.Data+24]<<8|raw[description.Data+25],raw[description.Data+26]<<8|raw[description.Data+27],out hevc,out code))throw new Reject(code??"hevc_configuration_invalid");
                }
                FullBox(raw,stsz,8);int sampleCount=Count(U32(raw,stsz.Data+8),MaximumSamples);if(hevc!=null&&hevc.SinglePictureOnly&&sampleCount!=1)throw new Reject("hevc_single_picture_sample_count");uint fixedSize=U32(raw,stsz.Data+4);Exact(stsz,fixedSize==0?12+sampleCount*4:12);var sizes=new int[sampleCount];for(int n=0;n<sampleCount;n++){uint size=fixedSize==0?U32(raw,stsz.Data+12+n*4):fixedSize;if(size<1||size>MaximumSampleBytes)throw new Reject("sample_size_limit");sizes[n]=(int)size;}
                FullBox(raw,stts,4);int times=Count(U32(raw,stts.Data+4),MaximumSamples);Exact(stts,8+times*8);long timed=0;for(int n=0;n<times;n++){uint count=U32(raw,stts.Data+8+n*8),delta=U32(raw,stts.Data+12+n*8);if(count==0||delta==0)throw new Reject("timing_invalid");timed+=count;}if(timed!=sampleCount)throw new Reject("timing_sample_count");
                var offsets=stbl.Where(b=>b.Type=="stco"||b.Type=="co64").ToArray();if(offsets.Length!=1)throw new Reject("chunk_offsets_missing_or_duplicate");Box stco=offsets[0];FullBox(raw,stco,4);int chunks=Count(U32(raw,stco.Data+4),MaximumChunks);int width=stco.Type=="co64"?8:4;Exact(stco,8+chunks*width);
                FullBox(raw,stsc,4);int runs=Count(U32(raw,stsc.Data+4),MaximumChunks);Exact(stsc,8+runs*12);var first=new int[runs];var per=new int[runs];
                for(int n=0;n<runs;n++){first[n]=Count(U32(raw,stsc.Data+8+n*12),chunks);per[n]=Count(U32(raw,stsc.Data+12+n*12),MaximumSamples);if(U32(raw,stsc.Data+16+n*12)!=1||n==0&&first[n]!=1||n>0&&first[n]<=first[n-1])throw new Reject("sample_chunk_table_invalid");}
                int run=0,sample=0;for(int n=0;n<chunks;n++){
                    if(run+1<runs&&n+1>=first[run+1])run++;if(per[run]>sampleCount-sample)throw new Reject("sample_chunk_count");var chunk=new Chunk{Logical=width==8?U64(raw,stco.Data+8+n*8):U32(raw,stco.Data+8+n*4),Codec=codec,Samples=new int[per[run]],Width=codec=="mp4a"?0:raw[description.Data+24]<<8|raw[description.Data+25],Height=codec=="mp4a"?0:raw[description.Data+26]<<8|raw[description.Data+27],Channels=channels,AudioFrequency=audioFrequency,Hevc=hevc};
                    for(int j=0;j<chunk.Samples.Length;j++){chunk.Samples[j]=sizes[sample++];chunk.Bytes+=chunk.Samples[j];}if(chunk.Logical<8||chunk.Bytes>MaximumFileBytes||chunk.Logical>MaximumFileBytes-chunk.Bytes)throw new Reject("chunk_bounds");movie.Chunks.Add(chunk);
                }
                if(sample!=sampleCount||movie.Chunks.Count>MaximumChunks)throw new Reject("sample_chunk_count");movie.Tracks++;
            }
            movie.Chunks=movie.Chunks.OrderBy(c=>c.Logical).ToList();long next=movie.Chunks[0].Logical;
            foreach(var chunk in movie.Chunks){if(chunk.Logical!=next)throw new Reject("chunk_gaps_or_overlap_unsupported");next+=chunk.Bytes;}
            return movie;
        }
        sealed class Descriptor {public int Tag,Data,End;}
        static Descriptor DescriptorAt(byte[] raw,ref int at,int end)
        {
            if(at>=end)throw new Reject("aac_descriptor_bounds");int tag=raw[at++],length=0;bool terminated=false;
            for(int n=0;n<4;n++){if(at>=end)throw new Reject("aac_descriptor_bounds");int part=raw[at++];length=checked(length*128+(part&127));if((part&128)==0){terminated=true;break;}}
            if(!terminated||length>end-at)throw new Reject("aac_descriptor_bounds");var result=new Descriptor{Tag=tag,Data=at,End=at+length};at+=length;return result;
        }
        static int AudioConfig(byte[] raw,Box description,out int samplingIndex)
        {
            samplingIndex=0;
            if(description.End-description.Data<28||raw[description.Data+6]!=0||raw[description.Data+7]!=1||raw[description.Data+8]!=0||raw[description.Data+9]!=0)throw new Reject("audio_sample_entry_unsupported");
            var extensions=Boxes(raw,description.Data+28,description.End);Box esds=One(extensions,"esds");FullBox(raw,esds,2);int at=esds.Data+4;var es=DescriptorAt(raw,ref at,esds.End);if(es.Tag!=3||at!=esds.End||es.End-es.Data<3)throw new Reject("aac_es_descriptor");
            int p=es.Data+2,flags=raw[p++];if((flags&128)!=0)p+=2;if((flags&64)!=0){if(p>=es.End)throw new Reject("aac_es_descriptor");p+=1+raw[p];}if((flags&32)!=0)p+=2;if(p>es.End)throw new Reject("aac_es_descriptor");
            Descriptor decoder=null;while(p<es.End){var item=DescriptorAt(raw,ref p,es.End);if(item.Tag==4){if(decoder!=null)throw new Reject("aac_decoder_descriptor");decoder=item;}}
            if(decoder==null||decoder.End-decoder.Data<13||raw[decoder.Data]!=0x40||(raw[decoder.Data+1]>>2)!=5||(raw[decoder.Data+1]&1)==0)throw new Reject("aac_decoder_unsupported");p=decoder.Data+13;Descriptor config=null;
            while(p<decoder.End){var item=DescriptorAt(raw,ref p,decoder.End);if(item.Tag==5){if(config!=null)throw new Reject("aac_config_unsupported");config=item;}}
            if(config==null||config.End-config.Data<2||config.End-config.Data>64)throw new Reject("aac_config_unsupported");
            var asc=new byte[config.End-config.Data];Buffer.BlockCopy(raw,config.Data,asc,0,asc.Length);var bits=new AudioBits{Raw=asc};
            int objectType=bits.Get(5),frequency=bits.Get(4),channels=bits.Get(4);
            if(objectType!=2||frequency>12||(channels!=1&&channels!=2)||bits.Get(3)!=0)throw new Reject("aac_profile_unsupported");
            // DecoderSpecificInfo may carry the backwards-compatible sync
            // extension even when its first AOT is LC. Do not mislabel HE-AAC
            // as LC merely because the initial sixteen bits look familiar.
            if(bits.Raw.Length*8-bits.At>7){
                if(bits.Raw.Length*8-bits.At<17||bits.Get(11)!=0x2b7||bits.Get(5)!=5)throw new Reject("aac_config_extension_unsupported");
                if(bits.Get(1)!=0)throw new Reject("aac_sbr_extension_unsupported");
                if(bits.Raw.Length*8-bits.At>7){
                    if(bits.Raw.Length*8-bits.At<12||bits.Get(11)!=0x548)throw new Reject("aac_config_extension_unsupported");
                    if(bits.Get(1)!=0)throw new Reject("aac_ps_extension_unsupported");
                }
            }
            int padding=bits.Raw.Length*8-bits.At;if(padding>7||bits.Get(padding)!=0)throw new Reject("aac_config_padding_invalid");
            samplingIndex=frequency;return channels;
        }
        static void ValidateAvcc(byte[] raw,Box b)
        {
            int p=b.Data+6,sps=raw[b.Data+5]&31;if(sps<1)throw new Reject("avc_configuration_invalid");
            for(int i=0;i<sps;i++)AvccNal(raw,b.End,ref p,7);if(p>=b.End)throw new Reject("avc_configuration_invalid");int pps=raw[p++];if(pps<1)throw new Reject("avc_configuration_invalid");for(int i=0;i<pps;i++)AvccNal(raw,b.End,ref p,8);
            // High-profile AVC configuration extensions may follow SPS/PPS.
        }
        static void AvccNal(byte[] raw,int end,ref int p,int type){if(end-p<2)throw new Reject("avc_configuration_invalid");int n=raw[p]<<8|raw[p+1];p+=2;if(n<1||n>end-p||(raw[p]&128)!=0||(raw[p]&31)!=type)throw new Reject("avc_configuration_invalid");p+=n;}
        static bool JpegValid(byte[] b,int width,int height)
        {
            if(b.Length<16||b[0]!=255||b[1]!=216||b[b.Length-2]!=255||b[b.Length-1]!=217)return false;int p=2;bool sof=false,sos=false,entropy=false;
            while(p<b.Length){
                if(entropy){while(p<b.Length&&b[p]!=255)p++;if(p>=b.Length)return false;int at=p++;while(p<b.Length&&b[p]==255)p++;if(p>=b.Length)return false;int m=b[p++];if(m==0||m>=208&&m<=215)continue;if(m==217)return sof&&sos&&p==b.Length;if(m==216)return false;p=at;entropy=false;continue;}
                if(b[p++]!=255)return false;while(p<b.Length&&b[p]==255)p++;if(p>=b.Length)return false;int marker=b[p++];if(marker==217)return sof&&sos&&p==b.Length;if(marker==216||marker==0||marker>=208&&marker<=215||b.Length-p<2)return false;
                int bytes=b[p]<<8|b[p+1];if(bytes<2||bytes>b.Length-p)return false;
                if(marker==192||marker==193||marker==194){if(bytes<8||b[p+2]!=8)return false;int h=b[p+3]<<8|b[p+4],w=b[p+5]<<8|b[p+6],components=b[p+7];if(w<1||h<1||w!=width||h!=height||(long)w*h>64000000||components<1||components>4||bytes!=8+3*components)return false;sof=true;}
                if(marker==218){if(!sof||bytes<6)return false;sos=true;entropy=true;}p+=bytes;
            }
            return false;
        }
        static bool AvcValid(byte[] b)
        {
            int p=0;bool slice=false;while(p<b.Length){if(b.Length-p<5)return false;uint n=U32(b,p);p+=4;if(n<1||n>b.Length-p)return false;int kind=b[p]&31;if((b[p]&128)!=0||kind==0||kind>=24)return false;if(kind==1||kind==5)slice=true;p+=(int)n;}return slice;
        }
        static bool SamplesValid(Context c,long at,Chunk chunk)
        {
            long p=at;foreach(int length in chunk.Samples){if(p<0||p>c.Input.Length-length)return false;
                if(chunk.Codec=="avc1"||chunk.Codec=="avc3"){if(!AvcPhysicalValid(c,p,length))return false;}
                else {var sample=new UnitSample{Logical=0,Bytes=length,Chunk=chunk};if(!UnitRangeSampleValid(sample,(logical,bytes)=>c.Read(p+logical,bytes,true)))return false;}p+=length;
            }return true;
        }
        static string HashRange(Context c,long at,long bytes)
        {
            if(bytes>c.Limits.MaxVerifiedBytes-c.Report.VerifiedBytes)throw new Budget();c.Report.VerifiedBytes+=bytes;
            using(var sha=SHA256.Create()){byte[] buffer=new byte[65536];c.Input.Position=at;while(bytes>0){c.Cancel.ThrowIfCancellationRequested();int n=c.Input.Read(buffer,0,(int)Math.Min(bytes,buffer.Length));if(n==0)throw new IOException("MEDIA_SOURCE_TRUNCATED");c.Report.SourceReadBytes+=n;sha.TransformBlock(buffer,0,n,null,0);bytes-=n;}sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();}
        }
        static List<Payload> FindPayload(Context c,Chunk chunk)
        {
            EnsurePayloadIndex(c,chunk);
            string key=chunk.Codec+":"+chunk.Width+"x"+chunk.Height+":"+(chunk.Hevc==null?"":chunk.Hevc.Fingerprint)+":"+String.Join(",",chunk.Samples.Select(x=>x.ToString(System.Globalization.CultureInfo.InvariantCulture)));List<Payload> found;if(c.Cache.TryGetValue(key,out found))return found;found=new List<Payload>();
            foreach(long at in chunk.Codec=="jpeg"||chunk.Codec=="mjpg"?c.Jpeg:chunk.Hevc!=null?c.Hevc:c.Avc){
                if(at>c.Input.Length-chunk.Bytes)continue;
                // Cheap last-byte/length checks precede any charged payload read.
                if(chunk.Codec=="jpeg"||chunk.Codec=="mjpg"){byte[] tail=c.Read(at+chunk.Samples[0]-2,2);if(tail[0]!=255||tail[1]!=217)continue;}
                else if(chunk.Hevc!=null){int bytes=chunk.Hevc.NalLengthBytes;byte[] prefix=c.Read(at,Math.Min(bytes+3,chunk.Samples[0]));if(!HevcSampleValidator.IsPossibleSampleStart(prefix,0,prefix.Length,bytes))continue;long first=0;for(int i=0;i<bytes;i++)first=(first<<8)|prefix[i];if(first>chunk.Samples[0]-bytes)continue;}
                else {AvcHeader prefix;long first=c.AvcHeaders.TryGetValue(at,out prefix)?prefix.Length:U32(c.Read(at,4),0);if(first<1||first>chunk.Samples[0]-4)continue;}
                if(++c.Report.PayloadProbes>c.Limits.MaxCandidates*16L)throw new Budget();if(SamplesValid(c,at,chunk))found.Add(new Payload{Offset=at,Bytes=chunk.Bytes,Sha=HashRange(c,at,chunk.Bytes)});
                if(found.Count>256)throw new Reject("chunk_candidate_limit");
            }
            c.Cache.Add(key,found);return found;
        }
        static bool PossibleHevcStart(byte[] buffer,int at,int available,int lengthBytes)
        {
            if(available<lengthBytes+3)return false;int first=buffer[at+lengthBytes],second=buffer[at+lengthBytes+1];
            if((first&129)!=0||(second&248)!=0||(second&7)==0)return false;
            if(lengthBytes==4&&(buffer[at]!=0||buffer[at+1]>128))return false;
            return HevcSampleValidator.IsPossibleSampleStart(buffer,at,available,lengthBytes);
        }
        static void Scan(Context c,Action<long,long> progress)
        {
            byte[] block=new byte[BlockBytes+16];int carry=0;long position=0;var atomOffsets=new HashSet<long>();
            while(position<c.Input.Length){
                c.Cancel.ThrowIfCancellationRequested();int count=(int)Math.Min(BlockBytes,c.Input.Length-position);byte[] next=c.Read(position,count);RecordZeroRanges(c,position,next);Buffer.BlockCopy(next,0,block,carry,count);int total=carry+count;long start=position-carry;
                for(int p=0;p+8<=total;p++){
                    long at=start+p;if(at<position-carry)continue;
                    bool atom=(block[p+4]==102&&block[p+5]==116&&block[p+6]==121&&block[p+7]==112)||(block[p+4]==109&&block[p+5]==111&&block[p+6]==111&&block[p+7]==118)||(block[p+4]==109&&block[p+5]==100&&block[p+6]==97&&block[p+7]==116)||(block[p+4]==102&&block[p+5]==114&&block[p+6]==101&&block[p+7]==101)||(block[p+4]==119&&block[p+5]==105&&block[p+6]==100&&block[p+7]==101);
                    if(atom&&atomOffsets.Add(at)){
                        if(++c.Report.Headers>c.Limits.MaxCandidates)throw new Budget();try{var a=AtomAt(c,at);if(a.Type=="ftyp")c.Ftyp.Add(a);else if(a.Type=="moov"){if(c.Moov.Count>=MaximumMovies)throw new Budget();c.Moov.Add(a);}else if(a.Type=="mdat")c.Mdat.Add(a);else c.Free.Add(a);}catch(Reject error){Skip(c.Report,error.Code);}
                    }
                }
                // Positions with fewer than eight remaining bytes are deferred.
                carry=Math.Min(7,total);Buffer.BlockCopy(block,total-carry,block,0,carry);position+=count;if(progress!=null)progress(position,c.Input.Length);
            }
        }
        static bool Overlaps(Extent a,Extent b){return a.ImageOffset<b.ImageOffset+b.Length&&b.ImageOffset<a.ImageOffset+a.Length;}
        static Extent Ext(long logical,Atom a,string kind){return new Extent{LogicalOffset=logical,ImageOffset=a.Offset,Length=a.Bytes,Kind=kind,EquivalentOffsets=new List<long>{a.Offset}};}
        static Atom UniqueAtom(IEnumerable<Atom> atoms){var groups=atoms.GroupBy(a=>Sha(a.Raw??new byte[0]),StringComparer.Ordinal).ToArray();if(groups.Length==0)throw new Reject("layout_atom_missing");if(groups.Length>1)throw new Reject("layout_atom_ambiguous");return groups[0].OrderBy(a=>a.Offset).First();}
        static List<Extent> Layout(Context c,Movie movie)
        {
            long first=movie.Chunks[0].Logical,mediaBytes=movie.Chunks.Sum(x=>x.Bytes);var layouts=new List<List<Extent>>();
            foreach(var ftyp in c.Ftyp){foreach(var mdat in c.Mdat.Where(x=>x.Bytes-x.Header==mediaBytes)){
                foreach(bool front in new[]{false,true}){
                    if(++c.LayoutAttempts>4096)throw new Budget();c.Cancel.ThrowIfCancellationRequested();
                    long gap=first-ftyp.Bytes-mdat.Header-(front?movie.Moov.Bytes:0);if(gap<0||gap>1024*1024)continue;
                    Atom free=null;if(gap>0){var matches=c.Free.Where(x=>x.Bytes==gap).ToArray();if(matches.Length==0)continue;free=UniqueAtom(matches);}
                    var ext=new List<Extent>{Ext(0,ftyp,"ftyp")};long logical=ftyp.Bytes;if(front){ext.AddRange(MetadataExtents(logical,movie.Moov));logical+=movie.Moov.Bytes;}
                    if(free!=null){ext.Add(Ext(logical,free,free.Type));logical+=free.Bytes;}
                    ext.Add(new Extent{ImageOffset=mdat.Offset,LogicalOffset=logical,Length=mdat.Header,Kind="mdat_header",EquivalentOffsets=new List<long>{mdat.Offset}});logical+=mdat.Header+mediaBytes;
                    if(!front)ext.AddRange(MetadataExtents(logical,movie.Moov));
                    if(ext.Any(a=>ext.Any(b=>!Object.ReferenceEquals(a,b)&&Overlaps(a,b))))continue;layouts.Add(ext);
                }
            }}
            if(layouts.Count==0)throw new Reject("surviving_box_layout_missing");
            // Equal bytes at duplicate source locations do not create a new file.
            var unique=layouts.GroupBy(x=>String.Join("|",x.OrderBy(e=>e.LogicalOffset).Select(e=>e.LogicalOffset+":"+e.Length+":"+HashRange(c,e.ImageOffset,e.Length))),StringComparer.Ordinal).ToArray();if(unique.Length!=1)throw new Reject("metadata_layout_ambiguous");return unique[0].First();
        }
        static Result Assemble(Context c,Movie movie,string folder)
        {
            var extents=Layout(c,movie);var videos=movie.Chunks.Where(x=>x.Codec!="mp4a").ToList();if(videos.Count==0)throw new Reject("video_anchor_missing");var matches=videos.Select(chunk=>FindPayload(c,chunk)).ToArray();if(matches.Any(x=>x.Count==0))throw new Reject("chunk_missing_or_invalid");
            Payload[] selected;try{selected=SelectPayloads(c,videos,matches,extents);}catch(Reject error){if(error.Code=="chunk_payload_ambiguous")error.VideoOnly=true;throw;}
            for(int i=0;i<videos.Count;i++){var chunk=videos[i];var item=selected[i];extents.Add(new Extent{ImageOffset=item.Offset,LogicalOffset=chunk.Logical,Length=chunk.Bytes,Kind="sample_chunk",EquivalentOffsets=matches[i].Where(x=>x.Sha==item.Sha).Select(x=>x.Offset).ToList()});}
            var audio=movie.Chunks.Where(x=>x.Codec=="mp4a").ToArray();bool audioSyntax=false;
            try { extents.AddRange(GeometryAudio(c,movie,extents,audio)); }
            catch(Reject error) {
                if(error.Code!="audio_geometry_unavailable")throw;
                // A single anchor cannot authenticate adjacent AAC. A separate
                // bounded search instead walks every AAC-LC Huffman/section/
                // spectral boundary and rejects distinct complete assignments.
                extents.AddRange(SyntaxAudio(c,extents,audio));audioSyntax=true;
            }
            return WriteCandidate(c,movie,folder,extents,audioSyntax);
        }
        static Result WriteCandidate(Context c,Movie movie,string folder,List<Extent> extents,bool audioSyntax,string expectedSha=null)
        {
            var audio=movie.Chunks.Where(x=>x.Codec=="mp4a").ToArray();extents=extents.OrderBy(e=>e.LogicalOffset).ToList();long length=0;foreach(var e in extents){if(e.LogicalOffset!=length)throw new Reject("output_gaps_or_overlap");length+=e.Length;}if(length>MaximumFileBytes)throw new Reject("file_size_limit");
            long alternatives=extents.Sum(e=>(long)e.EquivalentOffsets.Count);if(extents.Count>MaximumHeaders-c.Report.SourceRangeCount||alternatives>4L*MaximumHeaders-c.Report.SourceAlternativeCount)throw new Budget();
            if(length>c.Limits.MaxOutputBytes-c.Report.OutputBytes||c.Report.Files.Count>=c.Limits.MaxFiles)throw new Budget();
            bool contiguous=true;long physical=extents[0].ImageOffset;foreach(var e in extents){if(e.ImageOffset!=physical)contiguous=false;physical=e.ImageOffset+e.Length;}if(contiguous)throw new Reject("already_contiguous");
            string temporary=Path.Combine(folder,".media-"+Guid.NewGuid().ToString("N")+".partial");bool owned=false;
            try{
                string digest;using(var sha=SHA256.Create())using(var output=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
                    owned=true;byte[] b=new byte[65536];foreach(var e in extents){c.Input.Position=e.ImageOffset;long left=e.Length;while(left>0){c.Cancel.ThrowIfCancellationRequested();int n=c.Input.Read(b,0,(int)Math.Min(left,b.Length));if(n==0)throw new IOException("MEDIA_SOURCE_TRUNCATED");c.Report.SourceReadBytes+=n;output.Write(b,0,n);sha.TransformBlock(b,0,n,null,0);left-=n;}}sha.TransformFinalBlock(new byte[0],0,0);digest=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();output.Flush(true);
                }
                if(expectedSha!=null&&digest!=expectedSha)throw new IOException("MEDIA_SOURCE_CHANGED");
                string name="candidate-"+digest+".mp4",target=Path.Combine(folder,name);if(File.Exists(target)){File.Delete(temporary);owned=false;throw new Reject("duplicate_output");}File.Move(temporary,target);owned=false;
                var result=new Result{Path="fragmented-media/"+name,Sha256=digest,Bytes=length,MoovOffset=movie.Moov.Offset,Tracks=movie.Tracks,Chunks=movie.Chunks.Count,AudioChunks=audio.Length,AudioGeometryInferred=audio.Length>0,AudioSyntaxChecked=audioSyntax,AudioSearch=audio.Length==0?null:audioSyntax?"sector_and_video_delta_syntax":"two_anchor_geometry",Extents=extents};
                if(audio.Length>0)result.Note+=audioSyntax?" AAC-LC sample syntax was walked completely without PCM synthesis. Only 512-byte aligned starts and surviving video/container affine offsets were searched; a unique non-overlapping byte assignment was found within that scope. This is not an audio checksum or proof of original ownership.":" AAC-LC bytes were copied only between agreeing surviving video/container anchors. AAC element boundaries were checked, not full AAC decoding; audio identity and original integrity remain unverified.";return result;
            }finally{if(owned&&File.Exists(temporary))File.Delete(temporary);}
        }
        static List<Extent> GeometryAudio(Context c,Movie movie,List<Extent> extents,Chunk[] audio)
        {
            var found=new List<Extent>();if(audio.Length==0)return found;
            var anchorList=new List<Extent>(extents);var mediaHeader=extents.Single(x=>x.Kind=="mdat_header");long delta=mediaHeader.ImageOffset-mediaHeader.LogicalOffset,totalMediaBytes=movie.Chunks.Sum(x=>x.Bytes);
            if(extents.Where(x=>x.Kind=="sample_chunk").All(x=>x.ImageOffset-x.LogicalOffset==delta)&&mediaHeader.ImageOffset<=c.Input.Length-mediaHeader.Length-totalMediaBytes)
                anchorList.Add(new Extent{ImageOffset=mediaHeader.ImageOffset+mediaHeader.Length+totalMediaBytes,LogicalOffset=mediaHeader.LogicalOffset+mediaHeader.Length+totalMediaBytes,Length=0,Kind="declared_mdat_end"});
            var anchors=anchorList.OrderBy(x=>x.LogicalOffset).ThenBy(x=>x.Kind=="declared_mdat_end"?0:1).ToArray();
            foreach(var chunk in audio){
                Extent left=anchors.LastOrDefault(x=>x.LogicalOffset+x.Length<=chunk.Logical),right=anchors.FirstOrDefault(x=>x.LogicalOffset>=chunk.Logical+chunk.Bytes);
                if(left==null||right==null||left.ImageOffset-left.LogicalOffset!=right.ImageOffset-right.LogicalOffset)throw new Reject("audio_geometry_unavailable");
                long physical=chunk.Logical+(left.ImageOffset-left.LogicalOffset);
                if(physical<0||physical>c.Input.Length-chunk.Bytes||extents.Concat(found).Any(e=>physical<e.ImageOffset+e.Length&&e.ImageOffset<physical+chunk.Bytes))throw new Reject("audio_geometry_overlap_or_bounds");
                long current=physical;foreach(int bytes in chunk.Samples){byte[] sample=c.Read(current,bytes,true);if(!AacBoundary(sample,chunk.Channels))throw new Reject("aac_boundary_invalid");current+=bytes;}
                found.Add(new Extent{ImageOffset=physical,LogicalOffset=chunk.Logical,Length=chunk.Bytes,Kind="aac_geometry_chunk",EquivalentOffsets=new List<long>{physical}});
            }
            return found;
        }
        static List<long> AudioStarts(Context c)
        {
            if(c.AacStarts!=null)return c.AacStarts;var found=new List<long>();
            for(long at=0;at<c.Input.Length;at+=BlockBytes){byte[] block=c.Read(at,(int)Math.Min(BlockBytes,c.Input.Length-at));
                for(int p=0;p+2<=block.Length;p+=512)if(AacLcValidator.IsPossibleStart(block,p)){if(found.Count>=c.Limits.MaxCandidates)throw new Budget();found.Add(at+p);}}
            c.AacStarts=found;return found;
        }
        static bool AudioSamplesValid(Context c,long physical,Chunk chunk)
        {
            foreach(int size in chunk.Samples){if(size>AacLcValidator.MaximumSampleBytes||physical<0||physical>c.Input.Length-size)return false;
                string code;byte[] sample=c.Read(physical,size,true);if(!AacLcValidator.TryValidate(sample,chunk.Channels,chunk.AudioFrequency,out code))return false;physical+=size;}
            return true;
        }
        static List<Extent> SyntaxAudio(Context c,List<Extent> anchors,Chunk[] audio)
        {
            var matches=new List<Payload>[audio.Length];var deltas=anchors.Select(e=>e.ImageOffset-e.LogicalOffset).Distinct().ToArray();
            string anchorKey=Sha(Encoding.UTF8.GetBytes(String.Join("|",anchors.Select(e=>e.LogicalOffset+":"+e.ImageOffset+":"+e.Length))));
            for(int i=0;i<audio.Length;i++){
                c.Cancel.ThrowIfCancellationRequested();Chunk chunk=audio[i];if(chunk.Samples.Any(x=>x>AacLcValidator.MaximumSampleBytes))throw new Reject("aac_syntax_sample_size_unsupported");
                string key="aac-lc:"+anchorKey+":"+chunk.Logical+":"+chunk.Channels+":"+chunk.AudioFrequency+":"+String.Join(",",chunk.Samples);
                List<Payload> found;if(!c.Cache.TryGetValue(key,out found)){
                    found=new List<Payload>();var positions=new HashSet<long>(AudioStarts(c));foreach(long delta in deltas){long at=chunk.Logical+delta;if(at>=0&&at<=c.Input.Length-chunk.Bytes)positions.Add(at);}
                    foreach(long physical in positions.OrderBy(x=>x)){
                        if(physical<0||physical>c.Input.Length-chunk.Bytes||anchors.Any(e=>physical<e.ImageOffset+e.Length&&e.ImageOffset<physical+chunk.Bytes))continue;
                        if(AudioSamplesValid(c,physical,chunk))found.Add(new Payload{Offset=physical,Bytes=chunk.Bytes,Sha=HashRange(c,physical,chunk.Bytes)});
                        if(found.Count>256)throw new Reject("aac_chunk_candidate_limit");
                    }
                    c.Cache.Add(key,found);
                }
                if(found.Count==0)throw new Reject("aac_chunk_missing_or_invalid");matches[i]=found;
            }
            var selected=SelectPayloads(c,audio.ToList(),matches,anchors);var result=new List<Extent>();
            for(int i=0;i<audio.Length;i++)result.Add(new Extent{ImageOffset=selected[i].Offset,LogicalOffset=audio[i].Logical,Length=audio[i].Bytes,Kind="aac_syntax_chunk",EquivalentOffsets=matches[i].Where(x=>x.Sha==selected[i].Sha).Select(x=>x.Offset).ToList()});
            return result;
        }
        sealed class AudioBits
        {
            public byte[] Raw;public int At;
            public int Get(int count){if(count<0||count>24||count>Raw.Length*8-At)throw new Reject("aac_bit_bounds");int value=0;for(int n=0;n<count;n++){value=(value<<1)|((Raw[At/8]>>(7-At%8))&1);At++;}return value;}
            public void Skip(int count){if(count<0||count>Raw.Length*8-At)throw new Reject("aac_bit_bounds");At+=count;}
        }
        static bool AacBoundary(byte[] sample,int channels)
        {
            if(sample.Length<3)return false;try{
                var bits=new AudioBits{Raw=sample};int element=-1;for(int n=0;n<8;n++){
                    element=bits.Get(3);if(element==6){int count=bits.Get(4);if(count==15)count=14+bits.Get(8);bits.Skip(count*8);continue;}
                    if(element==4){bits.Get(4);int align=bits.Get(1),count=bits.Get(8);if(count==255)count+=bits.Get(8);if(align!=0)bits.At=(bits.At+7)/8*8;bits.Skip(count*8);continue;}break;
                }
                if(element!=(channels==1?0:1))return false;bits.Get(4);
                int tail=sample[sample.Length-2]<<8|sample[sample.Length-1];for(int pad=0;pad<8;pad++)if((tail&((1<<pad)-1))==0&&((tail>>pad)&7)==7)return true;return false;
            }catch(Reject){return false;}
        }
        static bool Fits(Payload candidate,List<Extent> metadata,Payload[] chosen)
        {
            return !metadata.Any(e=>candidate.Offset<e.ImageOffset+e.Length&&e.ImageOffset<candidate.Offset+candidate.Bytes)&&!chosen.Any(x=>x!=null&&candidate.Offset<x.Offset+x.Bytes&&x.Offset<candidate.Offset+candidate.Bytes);
        }
        static Payload[] SelectPayloads(Context c,List<Chunk> chunks,List<Payload>[] matches,List<Extent> metadata)
        {
            var chosen=new Payload[chunks.Count];bool ambiguous=matches.Any(list=>list.Select(x=>x.Sha).Distinct(StringComparer.Ordinal).Take(2).Count()>1);
            if(!ambiguous){foreach(int i in Enumerable.Range(0,chunks.Count).OrderByDescending(i=>chunks[i].Bytes)){chosen[i]=matches[i].FirstOrDefault(x=>Fits(x,metadata,chosen));if(chosen[i]==null)throw new Reject("chunk_physical_overlap");}return chosen;}
            // Global assignment can resolve local equal-size collisions when
            // another chunk consumes an overlapping source interval. Branching
            // has strict depth/work bounds; distinct resulting bytes still fail.
            if(chunks.Count>64)throw new Reject("chunk_ambiguity_search_limit");int states=0;string identity=null;Payload[] answer=null;
            Action<int> visit=null;visit=delegate(int depth){
                c.Cancel.ThrowIfCancellationRequested();if(++states>8192)throw new Reject("chunk_ambiguity_search_limit");
                if(depth==chunks.Count){string key=String.Join("|",chosen.Select(x=>x.Sha));if(identity!=null&&identity!=key)throw new Reject("chunk_payload_ambiguous");identity=key;if(answer==null)answer=(Payload[])chosen.Clone();return;}
                int next=-1;List<Payload> available=null;for(int i=0;i<chunks.Count;i++)if(chosen[i]==null){var options=matches[i].Where(x=>Fits(x,metadata,chosen)).ToList();if(options.Count==0)return;if(available==null||options.Count<available.Count){available=options;next=i;}}
                foreach(var item in available){chosen[next]=item;visit(depth+1);chosen[next]=null;}
            };
            visit(0);if(answer==null)throw new Reject("chunk_physical_overlap");return answer;
        }
        static void Publish(string path,Report report)
        {
            string temporary=Path.Combine(Path.GetDirectoryName(path),".media-report-"+Guid.NewGuid().ToString("N")+".partial");bool owned=false;
            try{byte[] b=new UTF8Encoding(false).GetBytes(new JavaScriptSerializer{MaxJsonLength=32*1024*1024}.Serialize(report));using(var output=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){owned=true;output.Write(b,0,b.Length);output.Flush(true);}File.Move(temporary,path);owned=false;}finally{if(owned&&File.Exists(temporary))File.Delete(temporary);}
        }
        public static int Recover(string image,string runDirectory,CancellationToken cancel,Action<long,long> progress){return Recover(image,runDirectory,cancel,progress,new Limits());}
        public static int Recover(string image,string runDirectory,CancellationToken cancel,Action<long,long> progress,Limits limits)
        {
            cancel.ThrowIfCancellationRequested();if(limits==null)throw new ArgumentNullException("limits");limits.Validate();string source=FullPath(image),run=FullPath(runDirectory),folder=Path.Combine(run,"fragmented-media"),reportPath=Path.Combine(run,"fragmented-media.json");Local(source);Local(run);Local(folder);Local(reportPath);
            if(!File.Exists(source)||Directory.Exists(source)||source.Equals(reportPath,StringComparison.OrdinalIgnoreCase)||source.Equals(folder,StringComparison.OrdinalIgnoreCase)||source.StartsWith(folder+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||File.Exists(reportPath)||Directory.Exists(folder)||File.Exists(folder))throw new IOException("MEDIA_FRESH_OUTPUT_REQUIRED");
            Directory.CreateDirectory(run);Directory.CreateDirectory(folder);var report=new Report();
            try{
                using(var input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read,BlockBytes)){
                    report.InputBytes=input.Length;var c=new Context{Input=input,Report=report,Limits=limits,Cancel=cancel};Scan(c,progress);
                    foreach(var atom in c.Moov){cancel.ThrowIfCancellationRequested();try{
                        Movie movie=null;Reject parseError=null;try{movie=ParseMovie(atom);}catch(Reject error){parseError=error;}
                        report.Movies++;Result result;
                        if(movie==null){try{result=AssembleRepairedUnits(c,atom,folder);}catch(Reject repair){if(repair.Code=="moov_unit_missing"||repair.Code=="moov_unit_limit"||repair.Code=="unit_mapping_missing")throw parseError;throw;}}
                        else if(movie.Chunks.Last().Logical+movie.Chunks.Last().Bytes>16*1024*1024){try{result=AssembleUnits(c,movie,folder);}catch(Reject unit){if(unit.Code!="unit_mapping_missing"&&unit.Code!="unit_file_limit"&&unit.Code!="unit_sample_limit")throw;result=Assemble(c,movie,folder);}}
                        else try{result=Assemble(c,movie,folder);}catch(Reject error){if(!UnitFallbackCode(error.Code)&&!error.VideoOnly)throw;try{result=AssembleUnits(c,movie,folder);}catch(Reject unit){if(unit.Code=="unit_mapping_missing"||unit.Code=="unit_file_limit"||unit.Code=="unit_sample_limit")throw error;throw;}}
                        report.Files.Add(result);report.OutputBytes+=result.Bytes;report.SourceRangeCount+=result.Extents.Count;report.SourceAlternativeCount+=(int)result.Extents.Sum(e=>(long)e.EquivalentOffsets.Count);report.Candidates++;report.Recovered++;
                    }catch(Reject error){Skip(report,error.Code);}}
                }
                report.Status="complete";return report.Candidates;
            }catch(OperationCanceledException){report.Status="cancelled";throw;}catch(Budget){report.Status="limited";throw new IOException("MEDIA_SEARCH_LIMIT_REACHED");}catch{report.Status="failed";throw;}finally{Publish(reportPath,report);}
        }
    }
}
