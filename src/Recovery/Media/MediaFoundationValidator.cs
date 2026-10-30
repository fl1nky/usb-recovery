using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace UsbRecovery
{
    // Worker core ONLY: never call native decoders on a Windows Forms thread.
    // Synchronous native calls need the enclosing worker's hard timeout/job cap.
    // Microsoft source-reader contract / canonical SDK interface method order:
    // https://learn.microsoft.com/windows/win32/medfound/processing-media-data-with-the-source-reader
    // https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders/um
    public static class MediaFoundationValidator
    {
        public sealed class DecodeLimits
        {
            public long MaxInputBytes=512L*1024*1024,MaxDecodedBytes=64L*1024*1024*1024;
            public int MaxVideoFrames=10000,MaxDecodedSamples=100000,MaxMilliseconds=30000,MaxPixels=16000000;
            internal void Validate(){if(MaxInputBytes<1||MaxInputBytes>512L*1024*1024||MaxDecodedBytes<1||MaxDecodedBytes>256L*1024*1024*1024||MaxVideoFrames<1||MaxVideoFrames>100000||MaxDecodedSamples<1||MaxDecodedSamples>1000000||MaxMilliseconds<1||MaxMilliseconds>120000||MaxPixels<1||MaxPixels>16000000)throw new ArgumentException("MF_LIMITS_INVALID");}
        }
        public sealed class DecodeProgress {public string Phase;public int StreamIndex;public long Samples,Bytes;}
        public sealed class DecodedStream
        {
            public int Index,Width,Height,Stride,Channels,SampleRate,BitsPerSample,BlockAlign;
            public string Kind,NativeSubtype,OutputSubtype,DecodedSha256,CompressedSha256,PartialSha256,DecodedHashLayout;
            public long MetadataPackets,CompressedPacketsRead,CompressedBytes,DecodedSamples,VideoFrames,PcmFrames,DecodedBytes,FirstTimestamp,LastTimestamp;
            public bool EndOfStream,CompressedEndOfStream;
            public int CorruptionSignals,UnknownCorruptionFlags,StreamTicks,NullSamples,Discontinuities;
        }
        public sealed class DecodeReport
        {
            public int Schema=1;
            public string Status="error",Code="MF_NOT_STARTED",NativeCode,SourceSha256;
            public long SourceBytes,DecodedBytes,ElapsedMilliseconds;
            public bool SourceUnchanged,AllStreamsEnded,StrictIntegrityEstablished=false,OwnershipAuthenticated=false;
            public bool LimitsAreCooperative=true;
            public List<DecodedStream> Streams=new List<DecodedStream>();
            public string Note="Full local-stream decoding is soft evidence. Media Foundation can conceal damaged samples; EOS, hashes and a zero/absent corruption flag do not authenticate the original bytes, ownership or deletion. Hard native-call time/memory limits require an isolated worker process.";
        }
        sealed class Failure:Exception {public string Code,State;public int Native;public Failure(string code,string state="error",int native=0){Code=code;State=state;Native=native;}}
        sealed class PacketTrack {public string Kind;public long Count;}
        sealed class Box {public long At,Bytes;public int Header;public string Type;public long Data{get{return At+Header;}}public long End{get{return At+Bytes;}}}
        sealed class Context
        {
            public DecodeLimits Limits;public CancellationToken Cancel;public DecodeReport Report;public Action<DecodeProgress> Progress;public Stopwatch Clock=Stopwatch.StartNew();
            public void Check(){Cancel.ThrowIfCancellationRequested();if(Clock.ElapsedMilliseconds>Limits.MaxMilliseconds)throw new Failure("MF_TIME_LIMIT","limited");}
            public void Update(string phase,int stream,long samples,long bytes){if(Progress!=null)Progress(new DecodeProgress{Phase=phase,StreamIndex=stream,Samples=samples,Bytes=bytes});Check();}
        }
        static readonly Guid Major=new Guid("48eba18e-f8c9-4687-bf11-0a74c9f96a8f"),Subtype=new Guid("f7e34c9a-42e8-4714-b74b-cb29d72c35e5");
        static readonly Guid Video=new Guid("73646976-0000-0010-8000-00aa00389b71"),Audio=new Guid("73647561-0000-0010-8000-00aa00389b71");
        static readonly Guid Rgb32=new Guid("00000016-0000-0010-8000-00aa00389b71"),Pcm=new Guid("00000001-0000-0010-8000-00aa00389b71");
        static readonly Guid VideoProcessing=new Guid("fb394f3d-ccf1-42ee-bbb3-f9b845d5681d"),DisableDxva=new Guid("aa456cfd-3943-4a1e-a77d-1838c0ea2e35");
        static readonly Guid FrameSize=new Guid("1652c33d-d6b2-4012-b834-72030849a37d"),DefaultStride=new Guid("644b4e48-1e02-4516-b0eb-c01ca9d49ac6");
        static readonly Guid Channels=new Guid("37e48bf5-645e-4c5b-89de-ada9e29b696a"),SampleRate=new Guid("5faeeae7-0290-4c31-9e8a-c534f68d9dba");
        static readonly Guid BitsPerSample=new Guid("f2deb57f-40fa-4764-aa33-ed4f2d1ff669"),BlockAlignment=new Guid("322de230-9eeb-43bd-ab7a-ff412251541d");
        static readonly Guid FrameCorruption=new Guid("b4dd4a8c-0beb-44c4-8b75-b02b913b04f0"),Discontinuity=new Guid("9cdf01d9-a0f0-43ba-b077-eaa06cbd728a");
        const uint AllStreams=0xfffffffe;
        const int InvalidStream=unchecked((int)0xc00d36b3),CodecMissing=unchecked((int)0xc00d5212),InvalidMediaType=unchecked((int)0xc00d36b4),InvalidFile=unchecked((int)0xc00d36be),UnsupportedByteStream=unchecked((int)0xc00d36c4);
        static void Hr(int value,string operation){if(value>=0)return;bool unsupported=value==CodecMissing||value==InvalidMediaType||value==UnsupportedByteStream;throw new Failure(unsupported?"MF_CODEC_UNAVAILABLE":"MF_"+operation,unsupported?"unsupported":"corrupt",value);}
        [DllImport("ole32.dll")]static extern int CoInitializeEx(IntPtr reserved,uint flags);
        [DllImport("ole32.dll")]static extern void CoUninitialize();
        [DllImport("mfplat.dll")]static extern int MFStartup(uint version,uint flags);
        [DllImport("mfplat.dll")]static extern int MFShutdown();
        [DllImport("mfplat.dll")]static extern int MFCreateAttributes(out IntPtr attributes,uint initialSize);
        [DllImport("mfplat.dll")]static extern int MFCreateMediaType(out IntPtr mediaType);
        [DllImport("mfreadwrite.dll",CharSet=CharSet.Unicode)]static extern int MFCreateSourceReaderFromURL(string url,IntPtr attributes,out IntPtr reader);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Set32(IntPtr self,ref Guid key,uint value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Get32(IntPtr self,ref Guid key,out uint value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Get64(IntPtr self,ref Guid key,out ulong value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GuidGet(IntPtr self,ref Guid key,out Guid value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int GuidSet(IntPtr self,ref Guid key,ref Guid value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Selection(IntPtr self,uint index,int selected);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int NativeType(IntPtr self,uint stream,uint type,out IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int CurrentType(IntPtr self,uint stream,out IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int SetType(IntPtr self,uint stream,IntPtr reserved,IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int ReadSample(IntPtr self,uint stream,uint control,out uint actual,out uint flags,out long timestamp,out IntPtr sample);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int BufferFromSample(IntPtr self,out IntPtr buffer);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int BufferLock(IntPtr self,out IntPtr bytes,out uint maximum,out uint current);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Simple(IntPtr self);
        static T Method<T>(IntPtr pointer,int slot) where T:class {return (T)(object)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(pointer),slot*IntPtr.Size),typeof(T));}
        static void Release(ref IntPtr pointer){if(pointer!=IntPtr.Zero){Marshal.Release(pointer);pointer=IntPtr.Zero;}}
        static uint UInt32(IntPtr pointer,Guid key){uint value;Hr(Method<Get32>(pointer,7)(pointer,ref key,out value),"FORMAT_ATTRIBUTE");return value;}
        static Guid GuidValue(IntPtr pointer,Guid key){Guid value;Hr(Method<GuidGet>(pointer,10)(pointer,ref key,out value),"FORMAT_ATTRIBUTE");return value;}
        static void SetGuid(IntPtr pointer,Guid key,Guid value){Hr(Method<GuidSet>(pointer,24)(pointer,ref key,ref value),"SET_ATTRIBUTE");}
        static void SetUInt32(IntPtr pointer,Guid key,uint value){Hr(Method<Set32>(pointer,21)(pointer,ref key,value),"SET_ATTRIBUTE");}
        static string Digest(byte[] bytes){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
        static string Digest(FileStream stream,Context c){using(var sha=SHA256.Create()){stream.Position=0;byte[] b=new byte[65536];int n;while((n=stream.Read(b,0,b.Length))>0){c.Check();sha.TransformBlock(b,0,n,null,0);}sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();}}
        static byte[] Read(FileStream input,long at,int count){if(at<0||count<0||at>input.Length-count)throw new Failure("MF_CONTAINER_BOUNDS","corrupt");input.Position=at;byte[] b=new byte[count];int done=0,n;while(done<count&&(n=input.Read(b,done,count-done))>0)done+=n;if(done!=count)throw new Failure("MF_CONTAINER_TRUNCATED","corrupt");return b;}
        static uint U32(byte[] b,int p){return (uint)b[p]<<24|(uint)b[p+1]<<16|(uint)b[p+2]<<8|b[p+3];}
        static long U64(byte[] b,int p){ulong n=(ulong)U32(b,p)<<32|U32(b,p+4);if(n>Int64.MaxValue)throw new Failure("MF_CONTAINER_BOUNDS","corrupt");return (long)n;}
        static List<Box> Boxes(byte[] b,long start,long end)
        {
            var result=new List<Box>();for(long at=start;at<end;){if(end-at<8||result.Count>=10000)throw new Failure("MF_CONTAINER_BOUNDS","corrupt");uint small=U32(b,(int)at);int header=small==1?16:8;if(end-at<header)throw new Failure("MF_CONTAINER_BOUNDS","corrupt");long size=small==1?U64(b,(int)at+8):small;if(size<header||size>end-at)throw new Failure("MF_CONTAINER_BOUNDS","corrupt");result.Add(new Box{At=at,Header=header,Bytes=size,Type=Encoding.ASCII.GetString(b,(int)at+4,4)});at+=size;}return result;
        }
        static Box One(IEnumerable<Box> boxes,string type){var found=boxes.Where(b=>b.Type==type).ToArray();if(found.Length!=1)throw new Failure("MF_REQUIRED_"+type.ToUpperInvariant(),"corrupt");return found[0];}
        static List<Box> Child(byte[] b,Box box){return Boxes(b,box.Data,box.End);}
        static List<PacketTrack> Preflight(FileStream input,Context c)
        {
            long at=0;byte[] moov=null;int moovHeader=0;bool ftyp=false,mdat=false;int boxes=0;
            while(at<input.Length){c.Check();if(++boxes>10000)throw new Failure("MF_BOX_LIMIT","limited");byte[] h=Read(input,at,8);uint small=U32(h,0);int header=small==1?16:8;long size=small==1?U64(Read(input,at+8,8),0):small;string kind=Encoding.ASCII.GetString(h,4,4);if(size<header||size>input.Length-at)throw new Failure("MF_CONTAINER_BOUNDS","corrupt");
                if(kind=="ftyp"){if(ftyp||size>4096||size<header+8)throw new Failure("MF_FTYP_INVALID","corrupt");ftyp=true;}
                else if(kind=="moov"){if(moov!=null||size>16*1024*1024)throw new Failure("MF_METADATA_LIMIT","limited");moov=Read(input,at,(int)size);moovHeader=header;}
                else if(kind=="mdat")mdat=true;
                else if(kind!="free"&&kind!="wide"&&kind!="skip")throw new Failure("MF_CONTAINER_FEATURE_UNSUPPORTED","unsupported");at+=size;
            }
            if(!ftyp||!mdat||moov==null)throw new Failure("MF_MP4_REQUIRED","unsupported");var top=Boxes(moov,moovHeader,moov.Length);if(top.Any(x=>x.Type=="mvex"||x.Type=="rmra"||x.Type=="rmda"||x.Type=="rdrf"||x.Type=="uuid"))throw new Failure("MF_REFERENCE_OR_FRAGMENTED_MOVIE_UNSUPPORTED","unsupported");var tracks=top.Where(x=>x.Type=="trak").ToArray();if(tracks.Length<1||tracks.Length>8)throw new Failure("MF_STREAM_LIMIT","limited");var result=new List<PacketTrack>();
            foreach(var track in tracks){
                var trackChildren=Child(moov,track);if(trackChildren.Any(x=>x.Type=="tref"))throw new Failure("MF_TRACK_REFERENCE_UNSUPPORTED","unsupported");var mdia=Child(moov,One(trackChildren,"mdia"));Box handler=One(mdia,"hdlr");if(handler.End-handler.Data<12)throw new Failure("MF_HANDLER_INVALID","corrupt");string kind=Encoding.ASCII.GetString(moov,(int)handler.Data+8,4);if(kind!="vide"&&kind!="soun")throw new Failure("MF_STREAM_KIND_UNSUPPORTED","unsupported");var minf=Child(moov,One(mdia,"minf"));var dinf=Child(moov,One(minf,"dinf"));Box dref=One(dinf,"dref");if(dref.End-dref.Data<8||U32(moov,(int)dref.Data)!=0||U32(moov,(int)dref.Data+4)!=1)throw new Failure("MF_DATA_REFERENCE_UNSUPPORTED","unsupported");var refs=Boxes(moov,dref.Data+8,dref.End);Box reference=One(refs,"url ");if(refs.Count!=1||reference.End-reference.Data!=4||U32(moov,(int)reference.Data)!=1)throw new Failure("MF_EXTERNAL_DATA_REFERENCE","unsupported");
                var stbl=Child(moov,One(minf,"stbl"));Box stsd=One(stbl,"stsd"),stsz=One(stbl,"stsz");if(stsd.End-stsd.Data<8||U32(moov,(int)stsd.Data)!=0||U32(moov,(int)stsd.Data+4)!=1)throw new Failure("MF_SAMPLE_DESCRIPTION_UNSUPPORTED","unsupported");var descriptions=Boxes(moov,stsd.Data+8,stsd.End);if(descriptions.Count!=1||descriptions[0].End-descriptions[0].Data<8||moov[descriptions[0].Data+6]!=0||moov[descriptions[0].Data+7]!=1)throw new Failure("MF_EXTERNAL_SAMPLE_DESCRIPTION","unsupported");if(descriptions[0].Type=="enca"||descriptions[0].Type=="encv")throw new Failure("MF_ENCRYPTED_MEDIA_UNSUPPORTED","unsupported");
                if(stsz.End-stsz.Data<12||U32(moov,(int)stsz.Data)!=0)throw new Failure("MF_SAMPLE_COUNT_INVALID","corrupt");long count=U32(moov,(int)stsz.Data+8),fixedSize=U32(moov,(int)stsz.Data+4);if(count<1||count>1000000||stsz.End-stsz.Data!=(fixedSize==0?12+count*4:12))throw new Failure("MF_SAMPLE_COUNT_INVALID","corrupt");result.Add(new PacketTrack{Kind=kind=="vide"?"video":"audio",Count=count});
            }
            return result;
        }
        static string SafeSource(string path)
        {
            string full;try{if(String.IsNullOrWhiteSpace(path)||path.StartsWith("\\\\",StringComparison.Ordinal)||path.IndexOf(':',2)>=0)throw new Failure("MF_LOCAL_FILE_REQUIRED","unsupported");full=Path.GetFullPath(path);}catch(ArgumentException){throw new Failure("MF_LOCAL_FILE_REQUIRED","unsupported");}catch(NotSupportedException){throw new Failure("MF_LOCAL_FILE_REQUIRED","unsupported");}
            // Normalize before any existence/attribute probes: //server paths
            // become UNC only after GetFullPath. Mapped network drives are also
            // rejected using the local drive-type query, without touching files.
            if(full.StartsWith("\\\\",StringComparison.Ordinal)||full.StartsWith("//",StringComparison.Ordinal))throw new Failure("MF_LOCAL_FILE_REQUIRED","unsupported");
            DriveType drive;try{drive=new DriveInfo(Path.GetPathRoot(full)).DriveType;}catch(ArgumentException){throw new Failure("MF_LOCAL_DRIVE_REQUIRED","unsupported");}catch(IOException){throw new Failure("MF_LOCAL_DRIVE_REQUIRED","unsupported");}
            if(drive!=DriveType.Fixed&&drive!=DriveType.Removable&&drive!=DriveType.Ram)throw new Failure("MF_LOCAL_DRIVE_REQUIRED","unsupported");
            if(!new[]{".mp4",".mov"}.Contains(Path.GetExtension(full).ToLowerInvariant()))throw new Failure("MF_CONTAINER_EXTENSION_UNSUPPORTED","unsupported");
            // Inspect the root first. A deepest-first existence probe could
            // traverse an unchecked ancestor junction into a network share.
            var parents=new List<DirectoryInfo>();for(var d=new DirectoryInfo(Path.GetDirectoryName(full));d!=null;d=d.Parent)parents.Add(d);parents.Reverse();
            try{
                foreach(var parent in parents){var attributes=File.GetAttributes(parent.FullName);if((attributes&FileAttributes.ReparsePoint)!=0)throw new Failure("MF_LINKED_SOURCE","unsupported");if((attributes&FileAttributes.Directory)==0)throw new Failure("MF_SOURCE_UNAVAILABLE");}
                var leafAttributes=File.GetAttributes(full);if((leafAttributes&FileAttributes.ReparsePoint)!=0)throw new Failure("MF_LINKED_SOURCE","unsupported");if((leafAttributes&FileAttributes.Directory)!=0)throw new Failure("MF_SOURCE_UNAVAILABLE");
            }catch(FileNotFoundException){throw new Failure("MF_SOURCE_UNAVAILABLE");}catch(DirectoryNotFoundException){throw new Failure("MF_SOURCE_UNAVAILABLE");}return full;
        }
        static IntPtr Reader(string source)
        {
            IntPtr attributes=IntPtr.Zero,reader=IntPtr.Zero;try{Hr(MFCreateAttributes(out attributes,2),"CREATE_ATTRIBUTES");SetUInt32(attributes,VideoProcessing,1);SetUInt32(attributes,DisableDxva,1);Hr(MFCreateSourceReaderFromURL(source,attributes,out reader),"OPEN_SOURCE");return reader;}catch{Release(ref reader);throw;}finally{Release(ref attributes);}
        }
        static List<DecodedStream> Streams(IntPtr reader,List<PacketTrack> tracks,Context c)
        {
            var result=new List<DecodedStream>();for(uint index=0;index<9;index++){
                c.Check();IntPtr native=IntPtr.Zero;int hr=Method<NativeType>(reader,5)(reader,index,0,out native);if(hr==InvalidStream)break;Hr(hr,"ENUM_STREAM");try{
                    if(index>=8)throw new Failure("MF_STREAM_LIMIT","limited");Guid kind=GuidValue(native,Major);if(kind!=Video&&kind!=Audio)throw new Failure("MF_STREAM_KIND_UNSUPPORTED","unsupported");var stream=new DecodedStream{Index=(int)index,Kind=kind==Video?"video":"audio",NativeSubtype=GuidValue(native,Subtype).ToString()};
                    var metadata=tracks.Where(x=>x.Kind==stream.Kind).ToList();int ordinal=result.Count(x=>x.Kind==stream.Kind);if(ordinal>=metadata.Count)throw new Failure("MF_STREAM_METADATA_MISMATCH","corrupt");stream.MetadataPackets=metadata[ordinal].Count;CheckFormat(native,stream,c,false);result.Add(stream);
                }finally{Release(ref native);}
            }
            if(result.Count!=tracks.Count)throw new Failure("MF_STREAM_METADATA_MISMATCH","corrupt");return result;
        }
        static void CheckFormat(IntPtr type,DecodedStream stream,Context c,bool output)
        {
            if(stream.Kind=="video"){
                ulong packed;Guid key=FrameSize;Hr(Method<Get64>(type,8)(type,ref key,out packed),"FRAME_SIZE");long width=(long)(packed>>32),height=(long)(packed&0xffffffff);if(width<1||height<1||width>Int32.MaxValue||height>Int32.MaxValue||width>c.Limits.MaxPixels/height)throw new Failure("MF_PIXEL_LIMIT","limited");stream.Width=(int)width;stream.Height=(int)height;
                if(output){uint stride;key=DefaultStride;int hr=Method<Get32>(type,7)(type,ref key,out stride);stream.Stride=hr>=0?unchecked((int)stride):checked(stream.Width*4);if(Math.Abs((long)stream.Stride)<stream.Width*4L||Math.Abs((long)stream.Stride)*stream.Height>64L*1024*1024)throw new Failure("MF_FRAME_BUFFER_LIMIT","limited");}
            }else{
                stream.Channels=(int)UInt32(type,Channels);stream.SampleRate=(int)UInt32(type,SampleRate);if(stream.Channels<1||stream.Channels>8||stream.SampleRate<8000||stream.SampleRate>192000)throw new Failure("MF_AUDIO_FORMAT_UNSUPPORTED","unsupported");
                if(output){stream.BitsPerSample=(int)UInt32(type,BitsPerSample);stream.BlockAlign=(int)UInt32(type,BlockAlignment);if(stream.BitsPerSample!=16||stream.BlockAlign!=stream.Channels*2)throw new Failure("MF_PCM_FORMAT_UNSUPPORTED","unsupported");}
            }
        }
        static void Configure(IntPtr reader,DecodedStream stream,Context c,bool compressed)
        {
            Hr(Method<Selection>(reader,4)(reader,AllStreams,0),"SELECT_STREAM");Hr(Method<Selection>(reader,4)(reader,(uint)stream.Index,1),"SELECT_STREAM");if(compressed)return;IntPtr type=IntPtr.Zero,current=IntPtr.Zero;
            try{Hr(MFCreateMediaType(out type),"CREATE_TYPE");SetGuid(type,Major,stream.Kind=="video"?Video:Audio);SetGuid(type,Subtype,stream.Kind=="video"?Rgb32:Pcm);if(stream.Kind=="audio"){SetUInt32(type,BitsPerSample,16);SetUInt32(type,Channels,(uint)stream.Channels);SetUInt32(type,SampleRate,(uint)stream.SampleRate);}Hr(Method<SetType>(reader,7)(reader,(uint)stream.Index,IntPtr.Zero,type),"CONFIGURE_DECODER");Hr(Method<CurrentType>(reader,6)(reader,(uint)stream.Index,out current),"CURRENT_FORMAT");stream.OutputSubtype=GuidValue(current,Subtype).ToString();if(GuidValue(current,Subtype)!=(stream.Kind=="video"?Rgb32:Pcm))throw new Failure("MF_OUTPUT_TYPE_MISMATCH","unsupported");CheckFormat(current,stream,c,true);}finally{Release(ref current);Release(ref type);}
        }
        static void HashSample(IntPtr sample,DecodedStream stream,Context c,SHA256 sha,bool compressed)
        {
            IntPtr buffer=IntPtr.Zero,bytes=IntPtr.Zero;bool locked=false;try{
                Hr(Method<BufferFromSample>(sample,41)(sample,out buffer),"SAMPLE_BUFFER");uint maximum,current;Hr(Method<BufferLock>(buffer,3)(buffer,out bytes,out maximum,out current),"BUFFER_LOCK");locked=true;if(current>maximum||current>64*1024*1024)throw new Failure("MF_SAMPLE_BUFFER_LIMIT","limited");
                if(compressed){if(current>c.Limits.MaxInputBytes-stream.CompressedBytes)throw new Failure("MF_PACKET_BYTES_LIMIT","limited");stream.CompressedBytes+=current;}
                else if(current>c.Limits.MaxDecodedBytes-c.Report.DecodedBytes)throw new Failure("MF_OUTPUT_BYTES_LIMIT","limited");
                byte[] raw=new byte[(int)current];if(current>0)Marshal.Copy(bytes,raw,0,raw.Length);
                if(!compressed&&stream.Kind=="video"){
                    long pitch=Math.Abs((long)stream.Stride),needed=pitch*(stream.Height-1)+stream.Width*4L;if(needed>raw.Length)throw new Failure("MF_FRAME_LENGTH_INVALID","corrupt");
                    // Canonical RGB24 excludes undefined RGB32 X bytes and stride
                    // padding. Orientation is recorded through the signed stride.
                    byte[] rgb=new byte[checked(stream.Width*3)];for(int y=0;y<stream.Height;y++){int at=(int)((stream.Stride<0?stream.Height-1-y:y)*pitch);for(int x=0;x<stream.Width;x++){rgb[x*3]=raw[at+x*4+2];rgb[x*3+1]=raw[at+x*4+1];rgb[x*3+2]=raw[at+x*4];}sha.TransformBlock(rgb,0,rgb.Length,null,0);}
                    stream.VideoFrames++;if(stream.VideoFrames>c.Limits.MaxVideoFrames)throw new Failure("MF_FRAME_COUNT_LIMIT","limited");
                }else {sha.TransformBlock(raw,0,raw.Length,null,0);if(!compressed&&stream.Kind=="audio"){if(raw.Length%stream.BlockAlign!=0)throw new Failure("MF_PCM_ALIGNMENT_INVALID","corrupt");stream.PcmFrames+=raw.Length/stream.BlockAlign;}}
                if(!compressed){stream.DecodedBytes+=current;c.Report.DecodedBytes+=current;}
            }finally{if(locked)Method<Simple>(buffer,4)(buffer);Release(ref buffer);}
        }
        static void DecodeStream(string source,DecodedStream stream,Context c,bool compressed)
        {
            IntPtr reader=IntPtr.Zero;using(var sha=SHA256.Create())try{
                reader=Reader(source);Configure(reader,stream,c,compressed);int noProgress=0;while(true){
                    c.Check();uint actual,flags;long timestamp;IntPtr sample=IntPtr.Zero;int hr=Method<ReadSample>(reader,9)(reader,(uint)stream.Index,0,out actual,out flags,out timestamp,out sample);
                    try{Hr(hr,"READ_SAMPLE");if((flags&1)!=0)throw new Failure("MF_DECODER_ERROR_FLAG","corrupt");if((flags&0x34)!=0)throw new Failure("MF_DYNAMIC_STREAM_UNSUPPORTED","unsupported");if(actual!=(uint)stream.Index)throw new Failure("MF_STREAM_INDEX_MISMATCH","corrupt");if((flags&0x100)!=0)stream.StreamTicks++;
                        if(sample!=IntPtr.Zero){noProgress=0;if(compressed){stream.CompressedPacketsRead++;if(stream.CompressedPacketsRead>c.Limits.MaxDecodedSamples)throw new Failure("MF_PACKET_COUNT_LIMIT","limited");}else{
                                stream.DecodedSamples++;if(stream.DecodedSamples>c.Limits.MaxDecodedSamples)throw new Failure("MF_SAMPLE_COUNT_LIMIT","limited");if(stream.DecodedSamples==1)stream.FirstTimestamp=timestamp;stream.LastTimestamp=timestamp;uint corrupt;Guid key=FrameCorruption;int present=Method<Get32>(sample,7)(sample,ref key,out corrupt);if(present<0||corrupt==0)stream.UnknownCorruptionFlags++;else stream.CorruptionSignals++;key=Discontinuity;uint discontinuity;if(Method<Get32>(sample,7)(sample,ref key,out discontinuity)>=0&&discontinuity!=0)stream.Discontinuities++;
                            }HashSample(sample,stream,c,sha,compressed);
                        }else {stream.NullSamples++;if(++noProgress>128)throw new Failure("MF_NO_DECODE_PROGRESS","corrupt");}
                        c.Update(compressed?"packets":"decode",stream.Index,compressed?stream.CompressedPacketsRead:stream.DecodedSamples,compressed?stream.CompressedBytes:stream.DecodedBytes);
                        if((flags&2)!=0){if(compressed)stream.CompressedEndOfStream=true;else stream.EndOfStream=true;break;}
                    }finally{Release(ref sample);}
                }
                sha.TransformFinalBlock(new byte[0],0,0);string digest=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();if(compressed){stream.CompressedSha256=digest;if(stream.CompressedPacketsRead!=stream.MetadataPackets)throw new Failure("MF_PACKET_COUNT_MISMATCH","corrupt");}else{stream.DecodedSha256=digest;stream.DecodedHashLayout=stream.Kind=="video"?"MF RGB32 memory rows normalized to RGB24 using recorded stride, X bytes/padding omitted":"MF PCM S16LE timeline, OS priming/padding retained";if(stream.DecodedSamples==0||stream.Kind=="video"&&stream.VideoFrames!=stream.MetadataPackets)throw new Failure("MF_DECODED_FRAME_COUNT_MISMATCH","corrupt");if(stream.Kind=="audio"&&stream.PcmFrames==0)throw new Failure("MF_DECODED_AUDIO_EMPTY","corrupt");}
            }finally{Release(ref reader);}
        }
        public static DecodeReport Validate(string path,DecodeLimits limits,CancellationToken cancel,Action<DecodeProgress> progress=null)
        {
            if(limits==null)throw new ArgumentNullException("limits");limits.Validate();var report=new DecodeReport();var c=new Context{Limits=limits,Cancel=cancel,Report=report,Progress=progress};bool com=false,mf=false;
            try{
                c.Check();string source=SafeSource(path);using(var input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read,65536)){
                    report.SourceBytes=input.Length;if(input.Length<24||input.Length>limits.MaxInputBytes)throw new Failure("MF_INPUT_BYTES_LIMIT","limited");report.SourceSha256=Digest(input,c);var tracks=Preflight(input,c);c.Update("preflight",-1,0,0);
                    int init=CoInitializeEx(IntPtr.Zero,0);if(init<0)throw new Failure("MF_MTA_WORKER_REQUIRED","unsupported",init);com=true;Hr(MFStartup(0x00020070,0),"STARTUP");mf=true;IntPtr reader=IntPtr.Zero;try{reader=Reader(source);report.Streams=Streams(reader,tracks,c);}finally{Release(ref reader);}
                    foreach(var stream in report.Streams){DecodeStream(source,stream,c,true);DecodeStream(source,stream,c,false);}
                    report.SourceUnchanged=Digest(input,c)==report.SourceSha256;if(!report.SourceUnchanged)throw new Failure("MF_SOURCE_CHANGED");report.AllStreamsEnded=report.Streams.Count>0&&report.Streams.All(s=>s.EndOfStream&&s.CompressedEndOfStream);
                    if(!report.AllStreamsEnded)throw new Failure("MF_EOS_MISSING","corrupt");if(report.Streams.Any(s=>s.CorruptionSignals>0))throw new Failure("MF_SAMPLE_CORRUPTION_REPORTED","corrupt");report.Status="decoded_soft";report.Code="MF_ALL_STREAMS_DECODED_SOFT";
                }
            }catch(OperationCanceledException){report.Status="cancelled";report.Code="MF_CANCELLED";}catch(Failure error){report.Status=error.State;report.Code=error.Code;if(error.Native!=0)report.NativeCode="0x"+unchecked((uint)error.Native).ToString("x8");}
            catch(DllNotFoundException){report.Status="unsupported";report.Code="MF_OS_COMPONENT_UNAVAILABLE";}catch(EntryPointNotFoundException){report.Status="unsupported";report.Code="MF_OS_COMPONENT_UNAVAILABLE";}catch(UnauthorizedAccessException){report.Status="error";report.Code="MF_SOURCE_ACCESS_DENIED";}catch(IOException){report.Status="error";report.Code="MF_SOURCE_IO_FAILED";}
            finally{if(mf)MFShutdown();if(com)CoUninitialize();report.ElapsedMilliseconds=c.Clock.ElapsedMilliseconds;}
            return report;
        }
    }
}
